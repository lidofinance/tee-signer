package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/lidofinance/tee-signer/governance/exitapproval"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// testnetWait is what an offline view adds when a testnet build waits
// another time than the default build (backend/flavor): the body does not
// say which build its signers run.
func testnetWait(def, testnet uint64) string {
	if def == testnet {
		return ""
	}
	return fmt.Sprintf("; %d s on signers of a testnet build", testnet)
}

// decodeBodyOrUpdate decodes a draft body ('B') or a signed update ('U'),
// read from path, with the strict decoders.
func decodeBodyOrUpdate(path string, raw []byte) (*setupwire.UpdateBody, []byte, *setupwire.Update, error) {
	if len(raw) > 0 && raw[0] == 'U' {
		u, err := setupwire.DecodeUpdate(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		body, err := u.Body.Encode()
		if err != nil {
			return nil, nil, nil, err
		}
		return &u.Body, body, u, nil
	}
	b, err := setupwire.DecodeUpdateBody(raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, raw, nil, nil
}

// optionalActive loads the active file at path. With def set, a missing
// file is no error: the result is nil.
func optionalActive(path string, def bool, body *setupwire.UpdateBody) (*active, error) {
	if def {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	return loadActive(path, body)
}

// position is the index of key in keys, or -1.
func position(keys [][32]byte, key [32]byte) int {
	return slices.Index(keys, key)
}

func cmdShow(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	activePath := fs.String("active", "", "the active values the update replaces (default: FILE.active when it exists)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: signer-admin show [-active FILE] FILE")
	}
	// The draft is read once: the values, the hashes and the signing
	// digests all come from these bytes, so a draft changed during the
	// review cannot show one body and sign another (SG-REVIEW-01).
	head, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	defer printSigning(out, head)
	switch {
	case isExitFile(head):
		return showExit(out, fs.Arg(0), head, *activePath)
	case isImportFile(head):
		return showImport(out, fs.Arg(0), head, *activePath)
	case handoverorder.IsBody(head) || handoverorder.IsOrder(head):
		return showHandover(out, fs.Arg(0), head, *activePath)
	}
	body, _, signed, err := decodeBodyOrUpdate(fs.Arg(0), head)
	if err != nil {
		return err
	}
	text, err := body.Format()
	if err != nil {
		return err
	}
	if _, err := out.Write(text); err != nil {
		return err
	}
	h, err := body.Hash()
	if err != nil {
		return err
	}
	fprintf(out, "\nbody_sha256 %s\n", fullHex(h))
	path, def := *activePath, false
	if path == "" {
		path, def = fs.Arg(0)+".active", true
	}
	a, err := optionalActive(path, def, body)
	if err != nil {
		return err
	}
	if a == nil {
		fprintf(out, "no active values (%s): no diff and no signature check\n", path)
	} else {
		fprintf(out, "active values from %s: %s version %d, bound by prev_hash\n", path, body.Group, a.refs[body.Group].version)
		if err := diffAgainst(out, a, body); err != nil {
			return err
		}
		set := &a.locked.Approvers
		if body.IsRotation(set) {
			fprintf(out, "rotation: the approver set changes from %s to %s; every new key must sign\n", hex8(set.Hash()), hex8(body.Locked.Approvers.Hash()))
		}
		if body.Group == setupwire.GroupLocked {
			fprintf(out, "wait: at least %d s after arrival (the active time lock%s)%s\n", flavor.Default.Limits().Wait(a.locked, body),
				map[bool]string{true: ", or the images minimum: the allowed list gains an image", false: ""}[setupwire.GainsImage(a.locked.AllowedImageMeasurements, body.Locked.AllowedImageMeasurements)],
				testnetWait(flavor.Default.Limits().Wait(a.locked, body), flavor.Testnet.Limits().Wait(a.locked, body)))
		}
	}
	if signed != nil {
		for _, ap := range signed.Approvals {
			fprintf(out, "approver_signature position %d\n", ap.Position)
		}
		for _, ap := range signed.NewSet {
			fprintf(out, "new_key_signature position %d\n", ap.Position)
		}
		if a != nil {
			if err := signed.Verify(&a.locked.Approvers); err != nil {
				return fmt.Errorf("signatures: %w", err)
			}
			fprintf(out, "signatures: complete and valid against the active approver set %s\n", hex8(a.locked.Approvers.Hash()))
		}
	}
	return nil
}

// A signature file is one approver's signature over a body, in the
// "key = value" form:
//
//	body_sha256 = 0x...   the hash of the update it signs (setupwire.UpdateHash: over the
//	                       header, which names the root of the new group's salted leaves)
//	public_key = 0x...    the approver's Ed25519 key
//	signature = 0x...     over signer-config-update-v1 and the body
//
// a handover order's likewise, over signer-handover-order-v1.
type sigFile struct {
	bodyHash [32]byte
	key      [32]byte
	sig      [64]byte
	// context names what the signature is over, for the comment line
	// (default signer-config-update-v1).
	context string
	// hashed: the signature is over the hashed form (setupwire.ApprovalMessage).
	hashed bool
}

func (s *sigFile) format() []byte {
	ctx := s.context
	if ctx == "" {
		ctx = setupwire.CtxConfigUpdate.String()
	}
	if s.hashed {
		hc, _ := setupwire.HashedContext(contextNamed(ctx))
		return fmt.Appendf(nil, "# signer-admin approver signature, hashed form: over SHA-256 of %s and SHA-256 of %s and the body\nform = hashed\nbody_sha256 = 0x%x\npublic_key = 0x%x\nsignature = 0x%x\n",
			hc, ctx, s.bodyHash, s.key, s.sig)
	}
	return fmt.Appendf(nil, "# signer-admin approver signature over %s and the body\nbody_sha256 = 0x%x\npublic_key = 0x%x\nsignature = 0x%x\n",
		ctx, s.bodyHash, s.key, s.sig)
}

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

func cmdSign(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "the approver's key: a path or file:PATH of a hex Ed25519 seed file, mode 0600, or openpgp:KEYGRIP of an Ed25519 key in gpg-agent (a YubiKey)")
	hashed := fs.Bool("hashed", false, "sign the hash-then-sign form: 32 bytes, SHA-256 of the kind's hash context and SHA-256 of the direct message (OpenPGP cards sign only this form)")
	outPath := fs.String("out", "", "signature file (default: BODY.<first 8 hex digits of the public key>.sig)")
	expect := fs.String("expect-sha256", "", "the sha256 of the direct signing message that show printed for the draft reviewed; another draft is refused")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || fs.NArg() != 1 {
		return errors.New("usage: signer-admin sign -key FILE|openpgp:KEYGRIP [-hashed] [-expect-sha256 HEX] [-out FILE] update.bin|order.bin|handover.bin|import.bin|exit.bin")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if *expect != "" {
		if err := checkExpected(raw, *expect); err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(0), err)
		}
	}
	if len(raw) > 0 && (raw[0] == 'U' || raw[0] == 'J' || handoverorder.IsOrder(raw) || isExitFile(raw) && len(raw) > exitapproval.Len) {
		return fmt.Errorf("%s is signed already; sign the body that draft, handover-draft, import-draft or exit-draft wrote", fs.Arg(0))
	}
	var body *setupwire.UpdateBody
	if !isExitFile(raw) && !isImportFile(raw) && !handoverorder.IsBody(raw) {
		if body, err = setupwire.DecodeUpdateBody(raw); err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(0), err)
		}
	}
	key, err := adminapprover.Open(*keyPath)
	if err != nil {
		return err
	}
	if adminapprover.HashedOnly(key) && !*hashed {
		*hashed = true
		fprintf(out, "an OpenPGP key signs the hashed form only: signing that form\n")
	}
	switch {
	case isExitFile(raw) || isImportFile(raw):
		return signKind(out, fs.Arg(0), raw, key, *hashed, *outPath)
	case handoverorder.IsBody(raw):
		return signHandover(out, fs.Arg(0), raw, key, *hashed, *outPath)
	}
	h, err := body.Hash()
	if err != nil {
		return err
	}
	header, err := body.Header()
	if err != nil {
		return err
	}
	sig, err := adminapprover.Sign(key, setupwire.CtxConfigUpdate, *hashed, header)
	if err != nil {
		return err
	}
	s := &sigFile{bodyHash: h, key: adminapprover.Key(key), sig: sig, hashed: *hashed}
	if *outPath == "" {
		*outPath = fmt.Sprintf("%s.%s.sig", fs.Arg(0), hex.EncodeToString(s.key[:4]))
	}
	if err := os.WriteFile(*outPath, s.format(), 0o644); err != nil {
		return err
	}
	fprintf(out, "signed %s version %d, body_sha256 %s, activate_at %s, with key %s\n", body.Group, body.Version, fullHex(s.bodyHash), when(body.ActivateAt), hex.EncodeToString(s.key[:]))
	if a, err := optionalActive(fs.Arg(0)+".active", true, body); err == nil && a != nil {
		if p := position(a.locked.Approvers.Keys, s.key); p >= 0 {
			fprintf(out, "the key is active approver %d\n", p)
		}
		if body.Group == setupwire.GroupLocked && body.IsRotation(&a.locked.Approvers) {
			if p := position(body.Locked.Approvers.Keys, s.key); p >= 0 {
				fprintf(out, "the key is new approver %d of the rotation\n", p)
			}
		}
	}
	fprintf(out, "wrote %s\n", *outPath)
	return nil
}

func cmdAssemble(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	activePath := fs.String("active", "", "the active values (default: BODY.active)")
	outPath := fs.String("out", "", "the signed update (default update.signed, handover.signed for a handover order)")
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
	if handoverorder.IsBody(raw) {
		return assembleHandover(out, fs.Arg(0), raw, *activePath, fs.Args()[1:], cmpOr(*outPath, "handover.signed"))
	}
	if isExitFile(raw) || isImportFile(raw) {
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

// checkExpected checks that the direct signing message of raw has the
// sha256 want (64 hex digits), the one show printed for the draft the
// approver reviewed.
func checkExpected(raw []byte, want string) error {
	w, err := hex.DecodeString(strings.TrimPrefix(want, "0x"))
	if err != nil || len(w) != sha256.Size {
		return errors.New("-expect-sha256: want 64 hex digits, the direct form's sha256 that show printed")
	}
	ctx, body, ok := signingInput(raw)
	if !ok {
		return errors.New("not a draft that show and sign know")
	}
	got := sha256.Sum256(setupwire.ApprovalMessage(ctx, false, body))
	if !bytes.Equal(got[:], w) {
		return fmt.Errorf("signing message sha256 %s is not the one reviewed (%s); show the draft again", fullHex(got), hex.EncodeToString(w))
	}
	return nil
}

// contextNamed is the registry entry of a context name.
func contextNamed(name string) setupwire.Context {
	for _, c := range setupwire.Contexts {
		if c.String() == name {
			return c
		}
	}
	return setupwire.Context{}
}
