package main

// What an approver runs: show, which prints a draft, its diff against the
// active values and the signing message hashes, and sign, which signs only
// the draft whose hash the approver passes with -expect-sha256. The
// helpers they call are here too, also those draft and assemble share,
// except the small ones in cluster.go (hex8, fullHex, when, fprintf).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
)

// nonProdWait is what an offline view adds when a non-prod build waits
// another time than the mainnet build (governance/runnerchain): the body
// does not say which build its signers run.
func nonProdWait(long, short uint64) string {
	if long == short {
		return ""
	}
	return fmt.Sprintf("; %d s on signers of a non-prod build (hoodi, devnet, ci-test)", short)
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
	case isImportFile(head):
		return showImport(out, fs.Arg(0), head, *activePath)
	}
	body, _, signed, err := decodeBodyOrUpdate(fs.Arg(0), head)
	if err != nil {
		return err
	}
	text, err := setuptext.FormatUpdateBody(body)
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
			gfv := a.setup.Chain.GenesisForkVersion
			fprintf(out, "wait: at least %d s after arrival (the active time lock%s)%s\n", runnerchain.Mainnet.Limits().Wait(gfv, a.locked, body),
				map[bool]string{true: ", or the images minimum: the allowed list gains an image", false: ""}[setupwire.GainsImage(a.locked.AllowedImageMeasurements, body.Locked.AllowedImageMeasurements)],
				nonProdWait(runnerchain.Mainnet.Limits().Wait(gfv, a.locked, body), runnerchain.Devnet.Limits().Wait(gfv, a.locked, body)))
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
		return errors.New("usage: signer-admin sign -key FILE|openpgp:KEYGRIP [-hashed] -expect-sha256 HEX [-out FILE] update.bin|import.bin")
	}
	if *expect == "" {
		return errors.New("sign needs -expect-sha256: the direct form's sha256 that signer-admin show printed for the draft you reviewed")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := checkExpected(raw, *expect); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if len(raw) > 0 && (raw[0] == 'U' || raw[0] == 'J') {
		return fmt.Errorf("%s is signed already; sign the body that draft or import-draft wrote", fs.Arg(0))
	}
	var body *setupwire.UpdateBody
	if !isImportFile(raw) {
		if body, err = setupwire.DecodeUpdateBody(raw); err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(0), err)
		}
	}
	// draft checks the image list against every signer of the cluster;
	// the active file holds one signer's setup, so sign checks that one.
	if body != nil && body.Locked != nil {
		if a, err := optionalActive(fs.Arg(0)+".active", true, body); err == nil && a != nil {
			if err := checkOwnImages([]*member{{name: a.setup.SignerName, setup: a.setup}}, body.Locked); err != nil {
				return fmt.Errorf("%s: %w; nothing signed", fs.Arg(0), err)
			}
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
	case isImportFile(raw):
		return signKind(out, fs.Arg(0), raw, key, *hashed, *outPath)
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

// loadSetupActive reads an active file of a setup and its locked group in
// force, as import-draft writes it.
func loadSetupActive(path string) (*orderActive, error) {
	var f activeFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(f.Setup)
	if err != nil {
		return nil, fmt.Errorf("%s: setup: not hex", path)
	}
	a := &orderActive{}
	if a.setup, err = setupwire.DecodeSetup(raw); err != nil {
		return nil, fmt.Errorf("%s: setup: %w", path, err)
	}
	a.locked = &a.setup.Locked
	h, _ := a.setup.GroupHash(setupwire.GroupLocked)
	a.ref = ref{0, h}
	if f.Locked != "" {
		lb, err := hex.DecodeString(f.Locked)
		if err != nil {
			return nil, fmt.Errorf("%s: locked: not hex", path)
		}
		u, err := setupwire.DecodeUpdateBody(lb)
		if err != nil {
			return nil, fmt.Errorf("%s: locked: %w", path, err)
		}
		if u.Group != setupwire.GroupLocked || u.Matches(a.setup) != nil {
			return nil, fmt.Errorf("%s: locked: an update of another group or cluster", path)
		}
		uh, err := setupwire.UpdateHash(lb)
		if err != nil {
			return nil, err
		}
		a.locked, a.ref = u.Locked, ref{u.Version, uh}
	}
	return a, nil
}

// isImportFile reports whether raw starts like an import order body or a
// signed one.
func isImportFile(raw []byte) bool { return len(raw) > 0 && (raw[0] == 'I' || raw[0] == 'J') }

// readImport reads an import order body or a signed one.
func readImport(raw []byte) (*importorder.Body, []byte, *importorder.Order, error) {
	if raw[0] == 'J' {
		o, err := importorder.Decode(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		body, err := o.Body.Encode()
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Body, body, o, nil
	}
	b, err := importorder.DecodeBody(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	return b, raw, nil, nil
}

func showImport(out io.Writer, path string, raw []byte, activePath string) error {
	b, body, signed, err := readImport(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	fprintf(out, "import order\ncluster_id = 0x%x\nchain_hash = 0x%x\ntarget_setup_sha256 = 0x%x\nnot_after = %s\nt = %d\nn = %d\nshare_index = %d\n",
		b.ClusterID, b.ChainHash, b.Target, when(b.NotAfter), b.T, b.N, b.ShareIndex)
	for _, v := range b.Validators {
		fprintf(out, "validator = %s commitments_sha256 0x%x\n", v.Pubkey, v.CommitmentsHash)
	}
	fprintf(out, "\norder_sha256 %s\n", fullHex(importorder.Hash(body)))
	a, err := optionalSetupActive(path, activePath)
	if err != nil {
		return err
	}
	single := b.T == 1 && b.N == 1
	if a == nil && single {
		fprintf(out, "1 of 1: the target holds the whole key; show with its active values (-active, or %s.active) says whether it is a GCP signer, where that is UNSAFE\n", path)
	}
	if a != nil {
		if h, _ := a.setup.Hash(); h != b.Target || a.setup.ClusterID != b.ClusterID {
			fprintf(out, "target: the active values are not of this order's target\n")
		} else {
			fprintf(out, "target: %s, the setup of the active values; approvers of its locked version %d\n", a.setup.SignerName, a.ref.version)
			fprintf(out, "target signing_mode = %s\n", a.setup.SigningMode)
			if err := setupwire.CheckThresholdOn(a.setup, int(b.T), int(b.N)); err != nil {
				fprintf(out, "WARNING %s: its runner refuses this order: %v\n", a.setup.SignerName, err)
			}
			// What import-draft printed to the drafter, for each approver
			// before sign.
			if single && a.setup.Platform.Platform == setupwire.PlatformGCP {
				fprintf(out, "WARNING %s: 1 of 1 on GCP: %s\n", a.setup.SignerName, setupwire.UnsafeSingleKeyWarning)
			}
		}
	}
	if signed != nil {
		for _, ap := range signed.Approvals {
			fprintf(out, "approver_signature position %d\n", ap.Position)
		}
		if a != nil {
			if err := signed.Verify(&a.locked.Approvers); err != nil {
				return fmt.Errorf("signatures: %w", err)
			}
			fprintf(out, "signatures: complete and valid against the approver set %s in force\n", hex8(a.locked.Approvers.Hash()))
		}
	}
	return nil
}

// optionalSetupActive loads activePath, or path.active when it exists.
func optionalSetupActive(path, activePath string) (*orderActive, error) {
	p := activePath
	if p == "" {
		p = path + ".active"
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	return loadSetupActive(p)
}

// signKind signs an import order body.
func signKind(out io.Writer, path string, raw []byte, key adminapprover.Signer, hashed bool, outPath string) error {
	b, err := importorder.DecodeBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	ctx, hash := setupwire.CtxImportOrder, importorder.Hash(raw)
	what := fmt.Sprintf("import order of %d validators for setup %s", len(b.Validators), hex8(b.Target))
	sig, err := adminapprover.Sign(key, ctx, hashed, raw)
	if err != nil {
		return err
	}
	s := &sigFile{bodyHash: hash, key: adminapprover.Key(key), sig: sig, context: ctx.String(), hashed: hashed}
	if outPath == "" {
		outPath = fmt.Sprintf("%s.%s.sig", path, hex.EncodeToString(s.key[:4]))
	}
	if err := os.WriteFile(outPath, s.format(), 0o644); err != nil {
		return err
	}
	fprintf(out, "signed %s, sha256 %s, %s form, with key %s\nwrote %s\n", what, fullHex(hash), adminapprover.Form(hashed), hex.EncodeToString(s.key[:]), outPath)
	return nil
}

// printSigning names both messages an approver may sign for raw, so an
// approver can compare them over a second channel: the direct form and
// the hashed form.
func printSigning(out io.Writer, raw []byte) {
	ctx, body, ok := signingInput(raw)
	if !ok {
		return
	}
	direct := setupwire.ApprovalMessage(ctx, false, body)
	d := sha256.Sum256(direct)
	hc, _ := setupwire.HashedContext(ctx)
	fprintf(out, "signing message, direct form: %s and the body, %d bytes, sha256 %s\n", ctx, len(direct), fullHex(d))
	fprintf(out, "signing message, hashed form (sign -hashed): sha256 of %s and sha256 %s, the 32 bytes %s\n", hc, fullHex(d),
		fullHex([32]byte(setupwire.ApprovalMessage(ctx, true, body))))
}

// signingInput is the approver context and the signed body of any file
// show reads.
func signingInput(raw []byte) (setupwire.Context, []byte, bool) {
	if len(raw) == 0 {
		return setupwire.Context{}, nil, false
	}
	switch {
	case isImportFile(raw):
		if _, body, _, err := readImport(raw); err == nil {
			return setupwire.CtxImportOrder, body, true
		}
	case raw[0] == 'U':
		if u, err := setupwire.DecodeUpdate(raw); err == nil {
			if h, err := u.Body.Header(); err == nil {
				return setupwire.CtxConfigUpdate, h, true
			}
		}
	default:
		if b, err := setupwire.DecodeUpdateBody(raw); err == nil {
			if h, err := b.Header(); err == nil {
				return setupwire.CtxConfigUpdate, h, true
			}
		}
	}
	return setupwire.Context{}, nil, false
}

// activeFile is the file next to a draft (update.bin.active): the active
// values the draft replaces, so that show prints the diff and assemble
// checks signatures on a machine without access to the signers. setup is
// one signer's setup (cluster_id, chain and version 0 of both groups);
// locked and open are the bodies of the active updates above version 0.
// Every value is hex of the binary form.
type activeFile struct {
	Setup  string `json:"setup"`
	Locked string `json:"locked,omitempty"`
	Open   string `json:"open,omitempty"`
}

// active is the active config that a body replaces.
type active struct {
	setup  *setupwire.Setup
	locked *setupwire.Locked
	open   *setupwire.Open
	refs   map[setupwire.Group]ref
	// bodies are the active update bodies above version 0, by group.
	bodies map[setupwire.Group][]byte
}

// loadActive reads an active file and checks it against body: same
// cluster_id and chain, and prev_hash names the active values of the
// body's group (the setup's group at version 0, else the body in the file).
// The active locked values of an open update come from the file unchecked:
// prev_hash binds the open group only.
func loadActive(path string, body *setupwire.UpdateBody) (*active, error) {
	var f activeFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, err
	}
	dec := func(what, s string) ([]byte, error) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: not hex", path, what)
		}
		return b, nil
	}
	raw, err := dec("setup", f.Setup)
	if err != nil {
		return nil, err
	}
	a := &active{refs: map[setupwire.Group]ref{}, bodies: map[setupwire.Group][]byte{}}
	if a.setup, err = setupwire.DecodeSetup(raw); err != nil {
		return nil, fmt.Errorf("%s: setup: %w", path, err)
	}
	if err := body.Matches(a.setup); err != nil {
		return nil, fmt.Errorf("%s: the active values are not of this update's cluster: %w", path, err)
	}
	a.locked, a.open = &a.setup.Locked, &a.setup.Open
	for _, g := range groups {
		h, _ := a.setup.GroupHash(g)
		a.refs[g] = ref{0, h}
		s := f.Locked
		if g == setupwire.GroupOpen {
			s = f.Open
		}
		if s == "" {
			continue
		}
		raw, err := dec(g.String(), s)
		if err != nil {
			return nil, err
		}
		b, err := setupwire.DecodeUpdateBody(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, g, err)
		}
		if b.Group != g || b.Matches(a.setup) != nil {
			return nil, fmt.Errorf("%s: %s: an update of another group or cluster", path, g)
		}
		uh, err := b.Hash()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, g, err)
		}
		a.refs[g] = ref{b.Version, uh}
		a.bodies[g] = raw
		if g == setupwire.GroupLocked {
			a.locked = b.Locked
		} else {
			a.open = b.Open
		}
	}
	if r := a.refs[body.Group]; r.hash != body.PrevHash {
		return nil, fmt.Errorf("prev_hash %s is not the active %s values of %s (version %d, %s): the file belongs to another draft or was changed",
			hex8(body.PrevHash), body.Group, path, r.version, hex8(r.hash))
	}
	if r := a.refs[body.Group]; r.version >= body.Version {
		return nil, fmt.Errorf("version %d is not above the active %s version %d", body.Version, body.Group, r.version)
	}
	return a, nil
}

// lines are the "key = value" lines of a group's human form, without
// comments.
func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func groupLines(g setupwire.Group, l *setupwire.Locked, o *setupwire.Open) ([]string, error) {
	var b []byte
	var err error
	if g == setupwire.GroupLocked {
		b, err = setuptext.FormatLocked(l)
	} else {
		b, err = setuptext.FormatOpen(o)
	}
	return lines(b), err
}

// diffLines is a line diff (longest common subsequence): lines only in a
// get "- ", lines only in b "+ ", in file order.
func diffLines(a, b []string) []string {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "- "+a[i])
			i++
		default:
			out = append(out, "+ "+b[j])
			j++
		}
	}
	return out
}

// diffAgainst prints the diff of body's group against the active values.
func diffAgainst(out io.Writer, a *active, body *setupwire.UpdateBody) error {
	old, err := groupLines(body.Group, a.locked, a.open)
	if err != nil {
		return err
	}
	next, err := groupLines(body.Group, body.Locked, body.Open)
	if err != nil {
		return err
	}
	d := diffLines(old, next)
	if len(d) == 0 {
		fprintf(out, "no change against the active %s values (version %d); as a pending update's successor it cancels that update\n", body.Group, a.refs[body.Group].version)
		return nil
	}
	fprintf(out, "changes against the active %s values (version %d):\n", body.Group, a.refs[body.Group].version)
	for _, l := range d {
		fprintf(out, "  %s\n", l)
	}
	return nil
}

// checkOwnImages refuses locked values whose allowed_image_measurements
// list no image of a member's platform: once in force, that signer's
// runner would refuse every import and signature, and only another locked
// update, which its approvers sign, could list its image again
// (setupwire.Setup.CheckOwnImageListed, the same rule for a setup).
func checkOwnImages(members []*member, l *setupwire.Locked) error {
	for _, m := range members {
		p := m.setup.Platform.Platform
		if p.ImageListed(l.AllowedImageMeasurements) {
			continue
		}
		k, _ := p.ImageKind()
		return fmt.Errorf("signer %s: platform is %s, but the new allowed_image_measurements lists no %s image: its runner would refuse every import and signature once the update is in force; keep a line allowed_image_measurements = %s ...",
			m.name, p, k, k)
	}
	return nil
}
