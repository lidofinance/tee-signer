package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
)

// cmdApproverKey prints an approver's public key as the setup file's
// approvers line wants it. Neither source needs the card: -key
// openpgp:KEYGRIP reads the public key gpg-agent keeps in the card key's
// stub, -openpgp reads an exported public key (gpg --export).
//
//	signer-admin approver-key -key FILE|openpgp:KEYGRIP
//	signer-admin approver-key -openpgp FILE [-fingerprint HEX]
func cmdApproverKey(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("approver-key", flag.ContinueOnError)
	keyURI := fs.String("key", "", "the approver's key: a seed file or openpgp:KEYGRIP (reads the public key only)")
	pgpPath := fs.String("openpgp", "", "an exported OpenPGP public key, armored or binary (gpg --export FINGERPRINT)")
	fpr := fs.String("fingerprint", "", "with -openpgp: the fingerprint or key ID (16 hex digits or more) of the Ed25519 key; default: the one Ed25519 signing subkey")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*keyURI == "") == (*pgpPath == "") || fs.NArg() != 0 || *fpr != "" && *pgpPath == "" {
		return errors.New("usage: signer-admin approver-key -key FILE|openpgp:KEYGRIP | -openpgp FILE [-fingerprint HEX]")
	}
	var pub ed25519.PublicKey
	if *keyURI != "" {
		s, err := adminapprover.Open(*keyURI)
		if err != nil {
			return err
		}
		pub = s.Public()
		fprintf(out, "approver key of %s\n", *keyURI)
	} else {
		data, err := os.ReadFile(*pgpPath)
		if err != nil {
			return err
		}
		keys, err := adminapprover.OpenPGPEd25519Keys(data)
		if err != nil {
			return fmt.Errorf("%s: %w", *pgpPath, err)
		}
		for _, k := range keys {
			fprintf(out, "%s Ed25519 key %X, sign flag %v\n", map[bool]string{true: "subkey ", false: "primary"}[k.Subkey], k.Fingerprint, k.CanSign)
		}
		k, err := adminapprover.SelectOpenPGPKey(keys, *fpr)
		if err != nil {
			return fmt.Errorf("%s: %w", *pgpPath, err)
		}
		pub = k.Public
		fprintf(out, "approver key of %s, OpenPGP key %X\n", *pgpPath, k.Fingerprint)
	}
	fprintf(out, "approvers = 0x%x\n", []byte(pub))
	return nil
}
