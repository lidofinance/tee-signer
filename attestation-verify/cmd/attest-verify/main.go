//go:build !peerselect

// Command attest-verify checks one attestation document from the cloud
// runner and prints the verified fields as JSON.
//
//	attest-verify -platform nitro -in doc.cbor -pcr 0=<hex> -pcr 1=<hex> -pcr 2=<hex> -nonce <hex>
//	attest-verify -platform gcp -in token.jwt -jwks keys.json -aud signer-runner-identity -image-digest sha256:... -max-age 5m
//	attest-verify -platform azure -in token.jwt -issuer https://P.R.attest.azure.net -compliance azure-compliant-uvm -hostdata <hex> -skr-policy policy.json -max-age 5m
//
// Without -jwks, gcp and azure read the issuer's OpenID configuration and
// fetch its key set over HTTPS. Exit status: 0 verified, 1 refused, 2 usage.
package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		platform   = fs.String("platform", "", "nitro, gcp or azure")
		in         = fs.String("in", "-", "document or token file, - for stdin")
		at         = fs.String("at", "", "verification time, RFC 3339 (default: now)")
		maxAge     = fs.Duration("max-age", 0, "maximum age of the document or token")
		allowDebug = fs.Bool("allow-debug", false, "accept debug-mode TEEs (never in production)")
		// nitro
		root     = fs.String("root", "", "nitro: root certificate PEM (default: pinned AWS root)")
		pcrs     list
		anyPCRs  = fs.Bool("any-pcrs", false, "nitro: skip the PCR comparison (inspection only)")
		nonceHex = fs.String("nonce", "", "nitro: expected nonce, hex; gcp: expected eat_nonce entry")
		udHex    = fs.String("user-data", "", "nitro: expected user data, hex")
		// jwt
		jwks     = fs.String("jwks", "", "gcp, azure: key set file or https URL (default: OIDC discovery)")
		issuer   = fs.String("issuer", "", "gcp: token issuer (default Google's); azure: attestation provider URL")
		aud      = fs.String("aud", "", "gcp: expected audience")
		digests  list
		anyImage = fs.Bool("any-image", false, "gcp: accept any image digest (inspection only)")
		support  list
		hwmodels list
		sa       = fs.String("service-account", "", "gcp: required entry in google_service_accounts")
		// azure
		compliance  = fs.String("compliance", attest.ComplianceACI, "azure: x-ms-compliance-status")
		hostdata    list
		launch      list
		vmid        = fs.String("vmid", "", "azure: expected VM id")
		runtimeHex  = fs.String("runtime-data", "", "azure: runtime data the runner sent to MAA, hex")
		policyFile  = fs.String("skr-policy", "", "azure: Key Vault release policy JSON to evaluate too")
		anyWorkload = fs.Bool("any-workload", false, "azure: no host data, launch measurement or VM id (inspection only)")
	)
	fs.Var(&pcrs, "pcr", "nitro: expected PCR as index=hex (repeatable)")
	fs.Var(&digests, "image-digest", "gcp: accepted image digest (repeatable)")
	fs.Var(&support, "support-attr", "gcp: required support attribute (repeatable, default STABLE)")
	fs.Var(&hwmodels, "hwmodel", "gcp: accepted hwmodel (repeatable)")
	fs.Var(&hostdata, "hostdata", "azure: accepted x-ms-sevsnpvm-hostdata, hex (repeatable)")
	fs.Var(&launch, "launch-measurement", "azure: accepted launch measurement, hex (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(f string, a ...any) int {
		fmt.Fprintf(stderr, "attest-verify: "+f+"\n", a...)
		return 2
	}
	now := time.Now()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return usage("-at: %v", err)
		}
		now = t
	}
	doc, err := readInput(*in)
	if err != nil {
		return usage("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var out any
	switch *platform {
	case "nitro":
		o := attest.NitroOptions{Now: now, MaxAge: *maxAge, AllowDebug: *allowDebug, AcceptAnyPCRs: *anyPCRs, PCRs: map[int][]byte{}}
		if *root != "" {
			c, err := readCert(*root)
			if err != nil {
				return usage("-root: %v", err)
			}
			o.Roots = []*x509.Certificate{c}
		}
		for _, p := range pcrs {
			i, h, ok := strings.Cut(p, "=")
			idx, err1 := strconv.Atoi(i)
			v, err2 := hex.DecodeString(h)
			if !ok || err1 != nil || err2 != nil {
				return usage("-pcr %q: want index=hex", p)
			}
			o.PCRs[idx] = v
		}
		if o.Nonce, err = optHex(*nonceHex); err != nil {
			return usage("-nonce: %v", err)
		}
		if o.UserData, err = optHex(*udHex); err != nil {
			return usage("-user-data: %v", err)
		}
		d, err := attest.VerifyNitro(decodeBinary(doc), o)
		if err != nil {
			return refuse(stderr, err)
		}
		pcrOut := map[string]string{}
		for i, v := range d.PCRs {
			pcrOut[fmt.Sprintf("pcr%d", i)] = hex.EncodeToString(v)
		}
		out = map[string]any{
			"platform": "nitro", "module_id": d.ModuleID, "timestamp": d.Timestamp, "debug": d.Debug,
			"pcrs": pcrOut, "nonce": hex.EncodeToString(d.Nonce), "user_data": hex.EncodeToString(d.UserData),
			"public_key": hex.EncodeToString(d.PublicKey), "certificate_subject": d.Certificate.Subject.String(),
		}
	case "gcp":
		iss := *issuer
		if iss == "" {
			iss = attest.ConfidentialSpaceIssuer
		}
		ks, err := loadKeys(ctx, *jwks, iss, stderr)
		if err != nil {
			return usage("keys: %v", err)
		}
		o := attest.ConfidentialSpaceOptions{Issuer: iss, Keys: ks, Audience: *aud, Now: now, MaxAge: *maxAge,
			ImageDigests: digests, AcceptAnyImage: *anyImage, HWModels: hwmodels, ServiceAccount: *sa, AllowDebug: *allowDebug}
		if len(support) > 0 {
			o.SupportAttributes = support
		}
		if *nonceHex != "" {
			o.Nonces = []string{*nonceHex}
		}
		tok, err := attest.VerifyConfidentialSpace(strings.TrimSpace(string(doc)), o)
		if err != nil {
			return refuse(stderr, err)
		}
		out = map[string]any{"platform": "gcp", "claims": tok.Claims}
	case "azure":
		if *issuer == "" {
			return usage("-issuer is required for azure")
		}
		ks, err := loadKeys(ctx, *jwks, *issuer, stderr)
		if err != nil {
			return usage("keys: %v", err)
		}
		o := attest.MAAOptions{Issuer: *issuer, Keys: ks, Now: now, MaxAge: *maxAge, ComplianceStatus: *compliance,
			HostData: hostdata, LaunchMeasurements: launch, VMID: *vmid, AcceptAnyWorkload: *anyWorkload, AllowDebug: *allowDebug}
		if o.RuntimeData, err = optHex(*runtimeHex); err != nil {
			return usage("-runtime-data: %v", err)
		}
		if *policyFile != "" {
			b, err := os.ReadFile(*policyFile)
			if err != nil {
				return usage("-skr-policy: %v", err)
			}
			if o.Policy, err = attest.ParseReleasePolicy(b); err != nil {
				return usage("-skr-policy: %v", err)
			}
		}
		tok, err := attest.VerifyMAA(strings.TrimSpace(string(doc)), o)
		if err != nil {
			return refuse(stderr, err)
		}
		out = map[string]any{"platform": "azure", "claims": tok.Claims}
	default:
		return usage("-platform must be nitro, gcp or azure")
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return 0
}

func refuse(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "attest-verify: REFUSED: %v\n", err)
	return 1
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	}
	return os.ReadFile(path)
}

// decodeBinary accepts raw CBOR, or base64 or hex text of it.
func decodeBinary(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	if v, err := hex.DecodeString(s); err == nil && len(v) > 0 {
		return v
	}
	if v, err := base64.StdEncoding.DecodeString(s); err == nil && len(v) > 0 {
		return v
	}
	return b
}

func optHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func loadKeys(ctx context.Context, src, issuer string, stderr io.Writer) (*attest.KeySet, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	switch {
	case src == "":
		fmt.Fprintf(stderr, "attest-verify: fetching keys through %s/.well-known/openid-configuration\n", strings.TrimSuffix(issuer, "/"))
		return attest.DiscoverJWKS(ctx, client, issuer)
	case strings.HasPrefix(src, "https://"):
		fmt.Fprintf(stderr, "attest-verify: fetching keys from %s\n", src)
		return attest.FetchJWKS(ctx, client, src)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	return attest.ParseJWKS(b)
}
