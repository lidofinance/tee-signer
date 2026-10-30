//go:build !verifierselect

// Command share-import is the dealer side of the sealed share import: it
// asks a runner for its attested identity, checks it, encrypts one share to
// the runner's import key (HPKE, ML-KEM-768-X25519) and sends it. The share
// is read from a file or stdin, never from the command line.
//
//	share-import -addr tcp:127.0.0.1:7100 -pubkey 0x... -index 9 -share-file share.hex -verifier dev
//
// The identity is checked with the verifier of package runnerclient, the
// one the signing client uses:
//
//	-verifier dev        the dev platform's unsigned document (local runners)
//	-verifier azure-maa  an Azure MAA token: -maa-host, -cce-policy-sha256
//	                     and, if not the ACI default, -compliance-status
//	-verifier aws-nitro  an AWS Nitro NSM document: -nitro-pcr INDEX=HEX,
//	                     repeated, with PCR0, PCR1 and PCR2 required, and
//	                     optionally -nitro-root-sha256
//	-verifier gcp-cs     a Confidential Space token: -gcp-image-digest,
//	                     -gcp-audience and -gcp-hwmodel (repeated), and
//	                     optionally -gcp-issuer, -gcp-jwks-file and
//	                     -gcp-service-account
//
// -verifier has no default and there is no way to skip the check. A setting
// of one verifier is refused with another. With -tls-cert and -tls-key the
// tool also connects over mutual TLS and binds the connection to the
// verified identity; -tls-key-pin adds a pin of the runner's TLS key.
// A runner with a setup takes a share only under an import order that k
// of its approvers signed (package importorder): -order names the file
// with the signed order (binary, as signer-config writes it), and
// -commitments the file with the validator's t public commitments of the
// split, one 0x-hex G1 point per line, commitment 0 first (the validator
// key). t, n and the share index come from the order.
//
// Without them it checks the identity only, which suits a local runner
// without TLS. Every cloud runner serves mutual TLS, so use them there. A
// Nitro runner listens on vsock with TLS that ends inside the enclave, so
// the address is the TCP port of the forwarder on the parent instance
// (-addr tcp:HOST:7100). The share leaves the tool sealed to the key in the
// verified identity, so the forwarder and the parent see ciphertext only.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/importorder"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "share-import:", err)
		os.Exit(1)
	}
}

func readSecret(path string) ([32]byte, error) {
	var sk [32]byte
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return sk, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return sk, err
	}
	defer clear(b)
	s := strings.TrimPrefix(strings.TrimSpace(string(b)), "0x")
	if len(s) != 64 {
		return sk, errors.New("share file: want 32 bytes as hex")
	}
	if _, err := hex.Decode(sk[:], []byte(s)); err != nil {
		return sk, errors.New("share file: not hex")
	}
	return sk, nil
}

func run() error {
	var (
		addr      = flag.String("addr", "", "runner address (tcp:, unix:, vsock:)")
		pubkeyHex = flag.String("pubkey", "", "validator public key (0x...)")
		index     = flag.Int64("index", -1, "validator index; -1 = unbound")
		shareFile = flag.String("share-file", "", "file with the share secret as hex, or - for stdin")
		certFile  = flag.String("tls-cert", "", "client certificate (PEM) for a runner with mutual TLS")
		keyFile   = flag.String("tls-key", "", "client key (PEM)")
		keyPin    = flag.String("tls-key-pin", "", "sha256 of the runner's TLS key as hex, checked in addition to the attested identity (needs -tls-cert)")
		orderFile = flag.String("order", "", "signed import order (binary); a runner with a setup needs one")
		commFile  = flag.String("commitments", "", "the validator's public commitments, one 0x-hex point per line (with -order)")
		testnet   = flag.Bool("allow-testnet-build", false, "accept a runner of a testnet build (governance time locks in minutes, devnets and test networks only; needs -tls-cert)")
	)
	att := runnerclient.Flags(flag.CommandLine)
	flag.Parse()
	if *addr == "" || *pubkeyHex == "" || *shareFile == "" {
		return errors.New("-addr, -pubkey and -share-file are required")
	}
	var pk backend.Pubkey
	if err := pk.UnmarshalText([]byte(*pubkeyHex)); err != nil {
		return fmt.Errorf("-pubkey: %w", err)
	}
	extra := &backend.SealedImportRequest{}
	if *orderFile != "" {
		raw, err := os.ReadFile(*orderFile)
		if err != nil {
			return err
		}
		o, err := importorder.Decode(raw)
		if err != nil {
			return fmt.Errorf("-order: %w", err)
		}
		if *commFile == "" {
			return errors.New("-order needs -commitments")
		}
		b, err := os.ReadFile(*commFile)
		if err != nil {
			return err
		}
		for _, line := range strings.Fields(string(b)) {
			var c backend.Pubkey
			if err := c.UnmarshalText([]byte(line)); err != nil {
				return fmt.Errorf("-commitments: %w", err)
			}
			extra.Commitments = append(extra.Commitments, c)
		}
		if len(extra.Commitments) != int(o.Body.T) {
			return fmt.Errorf("-commitments: %d points, the order's threshold is %d", len(extra.Commitments), o.Body.T)
		}
		extra.Order, extra.T, extra.N, extra.ShareIndex = raw, o.Body.T, o.Body.N, o.Body.ShareIndex
	}

	// The verifier and the client come first: a wrong setting stops the tool
	// before it reads the share.
	verify, err := att.NewVerifier()
	if err != nil {
		return err
	}
	var c *remote.Client
	if *certFile != "" || *keyFile != "" {
		conn := runnerclient.Connection{Address: *addr, ClientCert: *certFile, ClientKey: *keyFile, TLSKeyPin: *keyPin, Attestation: *att,
			AllowTestnetBuild: *testnet}
		rc, err := conn.New()
		if err != nil {
			return err
		}
		c, verify = rc.Client, rc.Verify
	} else {
		if *keyPin != "" {
			return errors.New("-tls-key-pin needs -tls-cert and -tls-key")
		}
		if c, err = remote.New(*addr); err != nil {
			return err
		}
	}
	defer c.Close()

	sk, err := readSecret(*shareFile)
	if err != nil {
		return err
	}
	defer clear(sk[:])
	sharePk, err := core.PubkeyOf(sk)
	if err != nil {
		return errors.New("share is not a valid BLS secret key")
	}
	idx := backend.IndexUnknown
	if *index >= 0 {
		idx = uint64(*index)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	k, err := remoteadmin.Wrap(c).ImportShareSealedWith(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: idx}, sharePk, verify, extra)
	if err != nil {
		return err
	}
	fmt.Printf("imported pubkey=%s share_pubkey=%s index=%d (sealed to the runner's attested ML-KEM-768-X25519 key, identity checked with the %s verifier)\n",
		k.Pubkey, k.SharePubkey, k.Index, att.Verifier)
	return nil
}
