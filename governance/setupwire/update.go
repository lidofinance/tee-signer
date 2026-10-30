package setupwire

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
)

// CONFIG_UPDATE. The body carries the full new group, its values and a
// salt for each of its leaves. The approvers sign the header under
// CtxConfigUpdate; the header names the root of the new group's salted
// leaves (policy.go) in place of the values, so a signature, and the
// update's hash, can be checked against published leaves while other
// leaves stay withheld. The signatures follow the body.
//
//	body   = 'B' version:u8(1) cluster_id[32] chain_hash[32] group:u8
//	         config_version:u64 prev_hash[32] activate_at:u64 locked|open
//	         group_salts (one salt[32] per leaf of the group)
//	header = cluster_id[32] chain_hash[32] group:u8 config_version:u64
//	         prev_hash[32] activate_at:u64 group_root[32]
//	update = 'U' version:u8(1) body_len:u32 body
//	         sig_count:u8 {position:u8 signature[64]}
//	         new_count:u8 {position:u8 signature[64]}
//
// A signature is Ed25519 over CtxConfigUpdate.Message(header), the update's
// hash CtxConfigUpdate.Hash(header). sig_count is 1 to MaxApprovers
// signatures by the active approvers, positions ascending. new_count is 0,
// or for a rotation the size of the new set with positions 0 to n-1: every
// new key signs the same header (section 8).
const (
	UpdateVersion = 1
	// HeaderLen is the size of the header the approvers sign.
	HeaderLen = 32 + 32 + 1 + 8 + 32 + 8 + 32
	// MaxUpdate bounds a body and a signed update. A locked group at
	// every cap is about 16 KB.
	MaxUpdate = 64 << 10
)

// UpdateBody is the update the approvers sign the header of. Locked or Open
// holds the full new group, as Group says, and Salts the salts of its
// leaves.
type UpdateBody struct {
	ClusterID  [32]byte
	ChainHash  [32]byte // Chain.Hash of the setup
	Group      Group
	Version    uint64 // per group; the setup is version 0
	PrevHash   [32]byte
	ActivateAt uint64 // Unix seconds
	Locked     *Locked
	Open       *Open
	// Salts has one salt per leaf of the group (NumLockedLeaves or
	// NumOpenLeaves). signer-config draft draws them for each update.
	Salts Salts
}

// Approval is one signature, naming its approver by position.
type Approval struct {
	Position  uint8
	Signature [64]byte
}

// Update is a signed CONFIG_UPDATE.
type Update struct {
	Body      UpdateBody
	Approvals []Approval // by the active approvers
	NewSet    []Approval // a rotation only: by every key of the new set
}

// CheckValues applies the body's value rules, without the salts: a body
// that signer-config read from a human file before it drew them.
func (u *UpdateBody) CheckValues() error {
	if u.ClusterID == ([32]byte{}) {
		return errors.New("update: cluster_id is zero")
	}
	if u.Version == 0 {
		return errors.New("update: version 0 is the setup's, an update starts at 1")
	}
	switch u.Group {
	case GroupLocked:
		if u.Locked == nil || u.Open != nil {
			return errors.New("update: a locked update carries the locked group only")
		}
		return u.Locked.Check()
	case GroupOpen:
		if u.Open == nil || u.Locked != nil {
			return errors.New("update: an open update carries the open group only")
		}
		return u.Open.Check()
	}
	return fmt.Errorf("update: group %d, want locked or open", u.Group)
}

// Check applies the body's value rules and checks its salts.
func (u *UpdateBody) Check() error {
	if err := u.CheckValues(); err != nil {
		return err
	}
	return checkSalts("update", u.Salts, u.leafCount())
}

func (u *UpdateBody) leafCount() int {
	if u.Group == GroupLocked {
		return NumLockedLeaves
	}
	return NumOpenLeaves
}

// DrawSalts gives the body fresh salts from r (crypto/rand.Reader outside
// tests). Call it after the group is set.
func (u *UpdateBody) DrawSalts(r io.Reader) error {
	if u.Group != GroupLocked && u.Group != GroupOpen {
		return fmt.Errorf("update: group %d, want locked or open", u.Group)
	}
	s, err := NewSalts(r, u.leafCount())
	if err != nil {
		return err
	}
	u.Salts = s
	return nil
}

// Encode checks the body and returns its bytes.
func (u *UpdateBody) Encode() ([]byte, error) {
	if err := u.Check(); err != nil {
		return nil, err
	}
	w := &writer{}
	u.write(w)
	return w.b, nil
}

func (u *UpdateBody) write(w *writer) {
	w.u8(kindBody)
	w.u8(UpdateVersion)
	w.raw(u.ClusterID[:])
	w.raw(u.ChainHash[:])
	w.u8(uint8(u.Group))
	w.u64(u.Version)
	w.raw(u.PrevHash[:])
	w.u64(u.ActivateAt)
	if u.Group == GroupLocked {
		writeFields(w, u.Locked.fields())
	} else {
		writeFields(w, u.Open.fields())
	}
	writeSalts(w, u.Salts)
}

// GroupRoot is the root of the new group's salted leaves.
func (u *UpdateBody) GroupRoot() ([32]byte, error) {
	if err := u.Check(); err != nil {
		return [32]byte{}, err
	}
	if u.Group == GroupLocked {
		return u.Locked.Root(u.Salts)
	}
	return u.Open.Root(u.Salts)
}

// Header is what the approvers sign.
func (u *UpdateBody) Header() ([]byte, error) {
	root, err := u.GroupRoot()
	if err != nil {
		return nil, err
	}
	return HeaderOf(u.ClusterID, u.ChainHash, u.Group, u.Version, u.PrevHash, u.ActivateAt, root), nil
}

// HeaderOf is the header of an update with these fields and group root: a
// verifier that has the header fields and the root, but not every leaf,
// rebuilds it with this.
func HeaderOf(clusterID, chainHash [32]byte, g Group, version uint64, prevHash [32]byte, activateAt uint64, groupRoot [32]byte) []byte {
	w := &writer{}
	w.raw(clusterID[:])
	w.raw(chainHash[:])
	w.u8(uint8(g))
	w.u64(version)
	w.raw(prevHash[:])
	w.u64(activateAt)
	w.raw(groupRoot[:])
	return w.b
}

func readBody(r *reader) *UpdateBody {
	r.header(kindBody, "config update body", UpdateVersion)
	u := &UpdateBody{}
	r.fixed(u.ClusterID[:])
	r.fixed(u.ChainHash[:])
	u.Group = Group(r.u8())
	u.Version = r.u64()
	r.fixed(u.PrevHash[:])
	u.ActivateAt = r.u64()
	switch u.Group {
	case GroupLocked:
		u.Locked = &Locked{}
		readLocked(r, u.Locked)
		u.Salts = r.salts(NumLockedLeaves)
	case GroupOpen:
		u.Open = &Open{}
		readOpen(r, u.Open)
		u.Salts = r.salts(NumOpenLeaves)
	default:
		r.fail(fmt.Errorf("setupwire: unknown group %d", u.Group))
	}
	return u
}

// DecodeUpdateBody reads a body as strictly as DecodeSetup reads a setup.
func DecodeUpdateBody(b []byte) (*UpdateBody, error) {
	if len(b) > MaxUpdate {
		return nil, fmt.Errorf("setupwire: update body is %d bytes, at most %d", len(b), MaxUpdate)
	}
	r := &reader{b: b}
	u := readBody(r)
	if err := r.done(); err != nil {
		return nil, err
	}
	again, err := u.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, errors.New("setupwire: update body does not encode back to the same bytes")
	}
	return u, nil
}

// HeaderHash is the hash of an update with this header. The next update
// of the group names it as prev_hash.
func HeaderHash(header []byte) [32]byte { return CtxConfigUpdate.Hash(header) }

// Hash is the update's hash: HeaderHash of its header.
func (u *UpdateBody) Hash() ([32]byte, error) {
	h, err := u.Header()
	if err != nil {
		return [32]byte{}, err
	}
	return HeaderHash(h), nil
}

// UpdateHash decodes an encoded body strictly and returns its hash.
func UpdateHash(body []byte) ([32]byte, error) {
	u, err := DecodeUpdateBody(body)
	if err != nil {
		return [32]byte{}, err
	}
	return u.Hash()
}

// Matches is step 2 of section 6: the update is for this cluster and
// chain, and its slot time changes fit the chain.
func (u *UpdateBody) Matches(s *Setup) error {
	if u.ClusterID != s.ClusterID {
		return errors.New("update: for another cluster_id")
	}
	if u.ChainHash != s.Chain.Hash() {
		return errors.New("update: for another chain")
	}
	if u.Group == GroupLocked && u.Locked != nil {
		if err := CheckSlotTimes(&s.Chain, u.Locked.SlotTimeChanges); err != nil {
			return fmt.Errorf("update: locked: %w", err)
		}
	}
	return nil
}

// IsRotation reports whether u gives the approvers another set (other keys,
// another order or another approvals_needed). Every key of that set must
// sign it.
func (u *UpdateBody) IsRotation(active *ApproverSet) bool {
	return u.Group == GroupLocked && u.Locked != nil && !u.Locked.Approvers.Equal(active)
}

// Sign is one approver's signature over the body's header.
func (u *UpdateBody) Sign(key ed25519.PrivateKey) ([64]byte, error) {
	h, err := u.Header()
	if err != nil {
		return [64]byte{}, err
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(key, CtxConfigUpdate.Message(h)))
	return sig, nil
}

// SignHashed is Sign in the hash-then-sign form (CtxConfigUpdateHash).
func (u *UpdateBody) SignHashed(key ed25519.PrivateKey) ([64]byte, error) {
	h, err := u.Header()
	if err != nil {
		return [64]byte{}, err
	}
	return SignApproval(key, CtxConfigUpdate, true, h), nil
}

// SignBody decodes an encoded body strictly and signs its header.
func SignBody(key ed25519.PrivateKey, body []byte) ([64]byte, error) {
	u, err := DecodeUpdateBody(body)
	if err != nil {
		return [64]byte{}, err
	}
	return u.Sign(key)
}

func (u *Update) check() error {
	if err := u.Body.Check(); err != nil {
		return err
	}
	if n := len(u.Approvals); n < 1 || n > MaxApprovers {
		return fmt.Errorf("update: %d approver signatures, want 1 to %d", n, MaxApprovers)
	}
	for i, a := range u.Approvals {
		if a.Position >= MaxApprovers {
			return fmt.Errorf("update: signature by position %d, at most %d", a.Position, MaxApprovers-1)
		}
		if i > 0 && a.Position <= u.Approvals[i-1].Position {
			return errors.New("update: approver signatures must be in ascending position order, one per approver")
		}
	}
	if len(u.NewSet) == 0 {
		return nil
	}
	if u.Body.Group != GroupLocked {
		return errors.New("update: new-set signatures on an open update")
	}
	if len(u.NewSet) != len(u.Body.Locked.Approvers.Keys) {
		return fmt.Errorf("update: %d new-set signatures for %d new keys, want one by every key", len(u.NewSet), len(u.Body.Locked.Approvers.Keys))
	}
	for i, a := range u.NewSet {
		if int(a.Position) != i {
			return errors.New("update: new-set signatures must name positions 0 to n-1 in order")
		}
	}
	return nil
}

// Encode returns the signed update.
func (u *Update) Encode() ([]byte, error) {
	if err := u.check(); err != nil {
		return nil, err
	}
	w := &writer{}
	u.write(w)
	if len(w.b) > MaxUpdate {
		return nil, fmt.Errorf("update: %d bytes, at most %d", len(w.b), MaxUpdate)
	}
	return w.b, nil
}

func (u *Update) write(w *writer) {
	body := &writer{}
	u.Body.write(body)
	w.u8(kindUpdate)
	w.u8(UpdateVersion)
	w.u32(uint32(len(body.b)))
	w.raw(body.b)
	for _, list := range [][]Approval{u.Approvals, u.NewSet} {
		w.u8(uint8(len(list)))
		for _, a := range list {
			w.u8(a.Position)
			w.raw(a.Signature[:])
		}
	}
}

// DecodeUpdate reads a signed update strictly. It checks the layout and
// the values, not the signatures: Verify does that against the active set.
func DecodeUpdate(b []byte) (*Update, error) {
	if len(b) > MaxUpdate {
		return nil, fmt.Errorf("setupwire: update is %d bytes, at most %d", len(b), MaxUpdate)
	}
	r := &reader{b: b}
	r.header(kindUpdate, "config update", UpdateVersion)
	n := r.u32()
	if r.err == nil && n > MaxUpdate {
		return nil, fmt.Errorf("setupwire: update body of %d bytes, at most %d", n, MaxUpdate)
	}
	raw := r.take(int(n))
	if r.err != nil {
		return nil, r.err
	}
	body, err := DecodeUpdateBody(raw)
	if err != nil {
		return nil, err
	}
	u := &Update{Body: *body}
	read := func(what string) []Approval {
		var out []Approval
		for range r.count(what, MaxApprovers, false) {
			a := Approval{Position: r.u8()}
			r.fixed(a.Signature[:])
			out = append(out, a)
		}
		return out
	}
	u.Approvals = read("approver signatures")
	u.NewSet = read("new-set signatures")
	if err := r.done(); err != nil {
		return nil, err
	}
	again, err := u.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, errors.New("setupwire: update does not encode back to the same bytes")
	}
	return u, nil
}

// Verify checks the signatures against the active approver set (section 6,
// step 5, and section 8): every signature verifies, at least
// approvals_needed distinct active approvers signed, and for a rotation
// every key of the new set signed too. The pending set never counts.
func (u *Update) Verify(active *ApproverSet) error {
	if err := u.check(); err != nil {
		return err
	}
	header, err := u.Body.Header()
	if err != nil {
		return err
	}
	for _, a := range u.Approvals {
		if int(a.Position) >= len(active.Keys) {
			return fmt.Errorf("update: signature by approver %d, the active set has %d", a.Position, len(active.Keys))
		}
		if !VerifyApproval(active.Keys[a.Position], CtxConfigUpdate, a.Signature, header) {
			return fmt.Errorf("update: the signature of approver %d does not verify", a.Position)
		}
	}
	if len(u.Approvals) < int(active.ApprovalsNeeded) {
		return fmt.Errorf("update: %d approver signatures, approvals_needed is %d", len(u.Approvals), active.ApprovalsNeeded)
	}
	rotation := u.Body.IsRotation(active)
	switch {
	case rotation && len(u.NewSet) == 0:
		return errors.New("update: a rotation needs a signature by every key of the new set")
	case !rotation && len(u.NewSet) != 0:
		return errors.New("update: new-set signatures on an update that keeps the approver set")
	}
	for _, a := range u.NewSet {
		if !VerifyApproval(u.Body.Locked.Approvers.Keys[a.Position], CtxConfigUpdate, a.Signature, header) {
			return fmt.Errorf("update: the signature of new key %d does not verify", a.Position)
		}
	}
	return nil
}
