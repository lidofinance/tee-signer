package main

// assemble: collects approver signature files into a signed update.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
)

func parseSigFile(path string) (*sigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vals := map[string][]byte{}
	want := map[string]int{"body_sha256": 32, "public_key": 32, "signature": 64}
	for i, l := range strings.Split(string(data), "\n") {
		text, _, _ := strings.Cut(l, "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		k, v, ok := strings.Cut(text, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if ok && k == "form" {
			// Informational: assemble tries both forms.
			if v != "direct" && v != "hashed" {
				return nil, fmt.Errorf("%s:%d: form: direct or hashed", path, i+1)
			}
			continue
		}
		n, known := want[k]
		switch {
		case !ok:
			return nil, fmt.Errorf("%s:%d: want key = value", path, i+1)
		case !known:
			return nil, fmt.Errorf("%s:%d: unknown key %q", path, i+1, k)
		case vals[k] != nil:
			return nil, fmt.Errorf("%s:%d: %s set again", path, i+1, k)
		}
		b, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err != nil || len(b) != n {
			return nil, fmt.Errorf("%s:%d: %s: want %d bytes of hex", path, i+1, k, n)
		}
		vals[k] = b
	}
	for k := range want {
		if vals[k] == nil {
			return nil, fmt.Errorf("%s: %s is missing", path, k)
		}
	}
	return &sigFile{bodyHash: [32]byte(vals["body_sha256"]), key: [32]byte(vals["public_key"]), sig: [64]byte(vals["signature"])}, nil
}

// readKey reads an approver key: a path or file:PATH of a hex Ed25519
// seed file, mode 0600 (admin/approver).
func readKey(uri string) (ed25519.PrivateKey, error) {
	return adminapprover.ReadKeyFile(strings.TrimPrefix(uri, "file:"))
}

func cmdAssemble(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	activePath := fs.String("active", "", "the active values (default: BODY.active)")
	outPath := fs.String("out", "", "the signed update (default update.signed)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("usage: signer-admin assemble [-active FILE] [-out update.signed] update.bin SIG...")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if *activePath == "" {
		*activePath = fs.Arg(0) + ".active"
	}
	if isImportFile(raw) {
		return assembleKind(out, fs.Arg(0), raw, *activePath, fs.Args()[1:], *outPath)
	}
	*outPath = cmpOr(*outPath, "update.signed")
	body, err := setupwire.DecodeUpdateBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	a, err := loadActive(*activePath, body)
	if err != nil {
		return err
	}
	set := &a.locked.Approvers
	hash, err := body.Hash()
	if err != nil {
		return err
	}
	header, err := body.Header()
	if err != nil {
		return err
	}
	rotation := body.IsRotation(set)
	approvals := map[int][64]byte{}
	newSet := map[int][64]byte{}
	for _, p := range fs.Args()[1:] {
		s, err := parseSigFile(p)
		if err != nil {
			return err
		}
		if s.bodyHash != hash {
			return fmt.Errorf("%s signs body %s, not this one (%s)", p, hex8(s.bodyHash), hex8(hash))
		}
		if !setupwire.VerifyApproval(s.key, setupwire.CtxConfigUpdate, s.sig, header) {
			return fmt.Errorf("%s: the signature does not verify", p)
		}
		pa := position(set.Keys, s.key)
		pn := -1
		if rotation {
			pn = position(body.Locked.Approvers.Keys, s.key)
		}
		if pa < 0 && pn < 0 {
			return fmt.Errorf("%s: key %s is not an active approver%s", p, hex.EncodeToString(s.key[:]),
				map[bool]string{true: " and not in the new set", false: ""}[rotation])
		}
		if pa >= 0 {
			approvals[pa] = s.sig
		}
		if pn >= 0 {
			newSet[pn] = s.sig
		}
	}
	u := &setupwire.Update{Body: *body}
	for p := range len(set.Keys) {
		if sig, ok := approvals[p]; ok {
			u.Approvals = append(u.Approvals, setupwire.Approval{Position: uint8(p), Signature: sig})
		}
	}
	if len(u.Approvals) < int(set.ApprovalsNeeded) {
		return fmt.Errorf("%d of the active approvers signed, approvals_needed is %d: %d more needed", len(u.Approvals), set.ApprovalsNeeded, int(set.ApprovalsNeeded)-len(u.Approvals))
	}
	if rotation {
		var missing []string
		for p := range body.Locked.Approvers.Keys {
			sig, ok := newSet[p]
			if !ok {
				missing = append(missing, fmt.Sprint(p))
				continue
			}
			u.NewSet = append(u.NewSet, setupwire.Approval{Position: uint8(p), Signature: sig})
		}
		if len(missing) > 0 {
			return fmt.Errorf("a rotation needs every new key to sign; the new keys at positions %s have not", strings.Join(missing, ", "))
		}
	}
	signed, err := u.Encode()
	if err != nil {
		return err
	}
	if err := u.Verify(set); err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, signed, 0o644); err != nil {
		return err
	}
	var pos []string
	for _, ap := range u.Approvals {
		pos = append(pos, fmt.Sprint(ap.Position))
	}
	fprintf(out, "%s version %d, body_sha256 %s: approvers %s of %d (k %d)", body.Group, body.Version, fullHex(hash), strings.Join(pos, ","), len(set.Keys), set.ApprovalsNeeded)
	if rotation {
		fprintf(out, ", and all %d new keys", len(u.NewSet))
	}
	fprintf(out, "\nwrote %s\n", *outPath)
	return nil
}
