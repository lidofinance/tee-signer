// Command charon-node-sign adds this Charon node's signature to a lock that
// dkg-coordinator charon-lock made. Run it on each node with that node's
// charon-enr-private-key; the key never leaves the node and is never an
// argument (only its file path).
//
//	charon-node-sign -lock cluster-lock.json -key .charon/charon-enr-private-key
//
// It checks the lock first: the hashes recompute, the public shares give
// each validator key, the deposits, builder registrations and
// signature_aggregate verify. Once every node has signed, it checks every
// node signature too and says the lock is complete. -verify only checks.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lidofinance/tee-signer/signer-admin/charonnode"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "charon-node-sign:", err)
		os.Exit(1)
	}
}

func run() error {
	lockPath := flag.String("lock", "cluster-lock.json", "the lock")
	keyPath := flag.String("key", ".charon/charon-enr-private-key", "this node's ENR private key file")
	outPath := flag.String("out", "", "where to write the lock (default: -lock)")
	verify := flag.Bool("verify", false, "only check the lock and every node signature")
	flag.Parse()
	raw, err := os.ReadFile(*lockPath)
	if err != nil {
		return err
	}
	l, err := charonlock.Parse(raw)
	if err != nil {
		return err
	}
	if *verify {
		if err := l.VerifyHashes(); err != nil {
			return err
		}
		if err := l.VerifyBLS(); err != nil {
			return err
		}
		if err := charonnode.VerifyNodeSignatures(l); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "lock %x complete: hashes, shares, deposits, registrations, signature_aggregate and %d node signatures verify\n",
			[]byte(l.LockHash), len(l.NodeSignatures))
		return nil
	}
	k, err := charonnode.LoadKey(*keyPath)
	if err != nil {
		return err
	}
	idx, err := charonnode.AddSignature(l, k)
	if err != nil {
		return err
	}
	out, err := l.Marshal()
	if err != nil {
		return err
	}
	if *outPath == "" {
		*outPath = *lockPath
	}
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		return err
	}
	if charonnode.VerifyNodeSignatures(l) == nil {
		fmt.Fprintf(os.Stderr, "operator %d signed; every node has signed and every signature verifies: the lock is complete\n", idx)
		return nil
	}
	fmt.Fprintf(os.Stderr, "operator %d signed lock %x; other nodes still to sign\n", idx, []byte(l.LockHash))
	return nil
}
