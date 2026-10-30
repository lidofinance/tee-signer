// Package handoverorder is the handover order (signer-protocol
// docs/protocol.md, "Handover"): k approvers in force sign it under
// setupwire.CtxHandoverOrder, it reaches the source runner over the wire
// (HANDOVER_ORDER), and it names the one target the source may hand its
// shares to.
//
// It follows the rules of package setupwire (fixed binary form, strict
// decoder, a human form for people). A runner's settings (runner.go) are
// the verifier, the image and what that verifier needs.
//
//	body   = 'H' version:u8(1) cluster_id[32] chain_hash[32] not_after:u64
//	         source target
//	runner = name:str setup_hash[32] settings
//	settings = verifier:u8 image:
//	           aws-nitro: pcr0..pcr2[144] pcr3[48] has:u8 [pcr8[48]]
//	           | azure-maa: cce_policy_sha256[32] maa_host:str compliance:u8
//	           | gcp-cs: image_digest[32] audience:str hwmodel_count:u8 {hwmodel:str}
//	                     issuer:str service_account:str project_id:str
//	           | dev: (nothing)
//	order  = 'T' version:u8(1) body_len:u32 body
//	         sig_count:u8 {position:u8 signature[64]}
//
// Integers are big endian, str is len:u8 and 1 to 255 bytes of printable
// ASCII without space or '#'.
//
// The source is the runner that holds the shares now: its setup_hash, and
// the image and settings a verifier of its attestation needs. The source
// runner checks only that the setup_hash is its own. The image and
// settings are for the target, which may check the source's proof of key
// origin with them (handover, package handover).
//
// The target is the runner the shares go to: its setup_hash and image, and
// the settings the source checks its attestation with. The target's image
// must be on the source's allowed-images list in force.
//
// The order's hash is SHA-256 over CtxHandoverOrder and the body, so it
// names what the approvers signed; the signatures are not in it.
package handoverorder

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

const (
	Version = 1
	// MaxSize bounds a body and a signed order. Two runners at every cap
	// and eight signatures take under 3 KB.
	MaxSize = 8 << 10

	kindBody  = 'H'
	kindOrder = 'T'
)

// Body is what the approvers sign.
type Body struct {
	ClusterID [32]byte
	ChainHash [32]byte // setupwire.Chain.Hash of the source's setup
	// NotAfter, Unix seconds: from then on no handover starts under the
	// order. A source that wrote its tombstone answers its target again
	// after it.
	NotAfter uint64
	Source   Runner
	Target   Runner
}

// Order is a signed handover order.
type Order struct {
	Body      Body
	Approvals []setupwire.Approval // by the approvers in force, ascending positions
}

func checkRunner(what string, r *Runner) error {
	if err := r.CheckSettings(); err != nil {
		return fmt.Errorf("handover order: %s: %w", what, err)
	}
	if r.SetupHash == ([32]byte{}) {
		return fmt.Errorf("handover order: %s: setup_sha256 is zero", what)
	}
	return nil
}

// Check applies the body's value rules.
func (b *Body) Check() error {
	if b.ClusterID == ([32]byte{}) {
		return errors.New("handover order: cluster_id is zero")
	}
	if b.NotAfter == 0 {
		return errors.New("handover order: not_after is 0")
	}
	if err := checkRunner("source", &b.Source); err != nil {
		return err
	}
	if err := checkRunner("target", &b.Target); err != nil {
		return err
	}
	if b.Source.SetupHash == b.Target.SetupHash {
		return errors.New("handover order: source and target have the same setup_sha256")
	}
	return nil
}

func appendRunner(p []byte, r *Runner) []byte {
	p = append(p, uint8(len(r.Name)))
	p = append(p, r.Name...)
	p = append(p, r.SetupHash[:]...)
	return appendSettings(p, r)
}

// Encode checks the body and returns the bytes the approvers sign.
func (b *Body) Encode() ([]byte, error) {
	if err := b.Check(); err != nil {
		return nil, err
	}
	p := []byte{kindBody, Version}
	p = append(p, b.ClusterID[:]...)
	p = append(p, b.ChainHash[:]...)
	p = binary.BigEndian.AppendUint64(p, b.NotAfter)
	p = appendRunner(p, &b.Source)
	p = appendRunner(p, &b.Target)
	if len(p) > MaxSize {
		return nil, fmt.Errorf("handover order: body of %d bytes, at most %d", len(p), MaxSize)
	}
	return p, nil
}

var errShort = errors.New("handoverorder: message too short")

func take(p []byte, n int) ([]byte, []byte, error) {
	if n < 0 || n > len(p) {
		return nil, nil, errShort
	}
	return p[:n], p[n:], nil
}

func header(p []byte, kind byte, what string) ([]byte, error) {
	if len(p) < 2 {
		return nil, errShort
	}
	if p[0] != kind {
		return nil, fmt.Errorf("handoverorder: not a %s (kind byte %#02x, want %#02x)", what, p[0], kind)
	}
	if p[1] != Version {
		return nil, fmt.Errorf("handoverorder: %s version %d, want %d", what, p[1], Version)
	}
	return p[2:], nil
}

func readRunner(p []byte, r *Runner) ([]byte, error) {
	if len(p) < 1 {
		return nil, errShort
	}
	name, p, err := take(p[1:], int(p[0]))
	if err != nil {
		return nil, err
	}
	r.Name = string(name)
	h, p, err := take(p, 32)
	if err != nil {
		return nil, err
	}
	copy(r.SetupHash[:], h)
	return readSettings(p, r)
}

// DecodeBody reads a body strictly: it refuses input above MaxSize, a kind
// or version it does not know, values Check refuses, trailing bytes, and
// anything that does not encode back to the same bytes.
func DecodeBody(raw []byte) (*Body, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("handoverorder: body is %d bytes, at most %d", len(raw), MaxSize)
	}
	p, err := header(raw, kindBody, "handover order body")
	if err != nil {
		return nil, err
	}
	if len(p) < 32+32+8 {
		return nil, errShort
	}
	b := &Body{}
	copy(b.ClusterID[:], p)
	copy(b.ChainHash[:], p[32:])
	b.NotAfter = binary.BigEndian.Uint64(p[64:])
	p = p[72:]
	if p, err = readRunner(p, &b.Source); err != nil {
		return nil, err
	}
	if p, err = readRunner(p, &b.Target); err != nil {
		return nil, err
	}
	if len(p) != 0 {
		return nil, fmt.Errorf("handoverorder: %d trailing bytes", len(p))
	}
	again, err := b.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, errors.New("handoverorder: body does not encode back to the same bytes")
	}
	return b, nil
}

// Hash is the hash of an order: SHA-256 over CtxHandoverOrder and its body.
func Hash(body []byte) [32]byte { return setupwire.CtxHandoverOrder.Hash(body) }

// Hash encodes the body and returns its order hash.
func (b *Body) Hash() ([32]byte, error) {
	enc, err := b.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return Hash(enc), nil
}

// SignBodyHashed is SignBody in the hash-then-sign form (CtxHandoverOrderHash).
func SignBodyHashed(key ed25519.PrivateKey, body []byte) [64]byte {
	return setupwire.SignApproval(key, setupwire.CtxHandoverOrder, true, body)
}

// SignBody is one approver's signature over an encoded body.
func SignBody(key ed25519.PrivateKey, body []byte) [64]byte {
	var sig [64]byte
	copy(sig[:], ed25519.Sign(key, setupwire.CtxHandoverOrder.Message(body)))
	return sig
}

// Matches says whether the order is for this setup's cluster and chain
// and names it as the source.
func (b *Body) Matches(s *setupwire.Setup, setupHash [32]byte) error {
	if b.ClusterID != s.ClusterID {
		return errors.New("handover order: for another cluster_id")
	}
	if b.ChainHash != s.Chain.Hash() {
		return errors.New("handover order: for another chain")
	}
	if b.Source.SetupHash != setupHash {
		return fmt.Errorf("handover order: its source is setup %x, this signer's is %x", b.Source.SetupHash[:8], setupHash[:8])
	}
	return nil
}

// CheckImage refuses an order whose target image is not on the
// allowed-images list. The dev verifier has no image; devOK says whether
// that is accepted (a dev runner only).
func (b *Body) CheckImage(allowed []setupwire.Image, devOK bool) error {
	im, ok := b.Target.AllowedImage()
	if !ok {
		if !devOK {
			return fmt.Errorf("handover order: target %s has the dev verifier, which only a dev runner takes", b.Target.Name)
		}
		return nil
	}
	if !slices.ContainsFunc(allowed, func(a setupwire.Image) bool {
		return a.Kind == im.Kind && bytes.Equal(a.Measurement, im.Measurement)
	}) {
		return fmt.Errorf("handover order: target %s: its %s image is not on the allowed-images list in force", b.Target.Name, im.Kind)
	}
	return nil
}

// Wait is how long an order waits from its arrival before it acts: the
// change delay in force, and at least the images minimum, because it decides which code holds the shares next. dev is
// the dev platform, which protects nothing and waits its change delay only.
func Wait(active *setupwire.Locked, dev bool) uint64 {
	if dev {
		return active.ChangeDelay()
	}
	return max(active.ChangeDelay(), setupwire.ImagesMinTimeLock)
}

func (o *Order) check() error {
	if err := o.Body.Check(); err != nil {
		return err
	}
	if n := len(o.Approvals); n < 1 || n > setupwire.MaxApprovers {
		return fmt.Errorf("handover order: %d approver signatures, want 1 to %d", n, setupwire.MaxApprovers)
	}
	for i, a := range o.Approvals {
		if a.Position >= setupwire.MaxApprovers {
			return fmt.Errorf("handover order: signature by position %d, at most %d", a.Position, setupwire.MaxApprovers-1)
		}
		if i > 0 && a.Position <= o.Approvals[i-1].Position {
			return errors.New("handover order: approver signatures must be in ascending position order, one per approver")
		}
	}
	return nil
}

// Encode returns the signed order.
func (o *Order) Encode() ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	body, err := o.Body.Encode()
	if err != nil {
		return nil, err
	}
	p := []byte{kindOrder, Version}
	p = binary.BigEndian.AppendUint32(p, uint32(len(body)))
	p = append(p, body...)
	p = append(p, uint8(len(o.Approvals)))
	for _, a := range o.Approvals {
		p = append(p, a.Position)
		p = append(p, a.Signature[:]...)
	}
	if len(p) > MaxSize {
		return nil, fmt.Errorf("handover order: %d bytes, at most %d", len(p), MaxSize)
	}
	return p, nil
}

// Decode reads a signed order strictly. It checks the layout and the
// values, not the signatures: Verify does that against the set in force.
func Decode(raw []byte) (*Order, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("handoverorder: order is %d bytes, at most %d", len(raw), MaxSize)
	}
	p, err := header(raw, kindOrder, "handover order")
	if err != nil {
		return nil, err
	}
	if len(p) < 4 {
		return nil, errShort
	}
	n := binary.BigEndian.Uint32(p)
	if n > MaxSize {
		return nil, fmt.Errorf("handoverorder: body of %d bytes, at most %d", n, MaxSize)
	}
	bodyRaw, p, err := take(p[4:], int(n))
	if err != nil {
		return nil, err
	}
	body, err := DecodeBody(bodyRaw)
	if err != nil {
		return nil, err
	}
	o := &Order{Body: *body}
	if len(p) < 1 {
		return nil, errShort
	}
	count := int(p[0])
	if count > setupwire.MaxApprovers {
		return nil, fmt.Errorf("handoverorder: %d approver signatures, at most %d", count, setupwire.MaxApprovers)
	}
	p = p[1:]
	for range count {
		var e []byte
		if e, p, err = take(p, 1+64); err != nil {
			return nil, err
		}
		a := setupwire.Approval{Position: e[0]}
		copy(a.Signature[:], e[1:])
		o.Approvals = append(o.Approvals, a)
	}
	if len(p) != 0 {
		return nil, fmt.Errorf("handoverorder: %d trailing bytes", len(p))
	}
	again, err := o.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, errors.New("handoverorder: order does not encode back to the same bytes")
	}
	return o, nil
}

// Verify checks the signatures against the approver set in force: every
// signature verifies and at least k distinct approvers of the set signed.
// The positions are distinct (check), and the set's keys are (setupwire).
func (o *Order) Verify(active *setupwire.ApproverSet) error {
	if err := o.check(); err != nil {
		return err
	}
	body, err := o.Body.Encode()
	if err != nil {
		return err
	}
	for _, a := range o.Approvals {
		if int(a.Position) >= len(active.Keys) {
			return fmt.Errorf("handover order: signature by approver %d, the set in force has %d", a.Position, len(active.Keys))
		}
		if !setupwire.VerifyApproval(active.Keys[a.Position], setupwire.CtxHandoverOrder, a.Signature, body) {
			return fmt.Errorf("handover order: the signature of approver %d does not verify under the set in force", a.Position)
		}
	}
	if len(o.Approvals) < int(active.ApprovalsNeeded) {
		return fmt.Errorf("handover order: %d approver signatures, approvals_needed is %d", len(o.Approvals), active.ApprovalsNeeded)
	}
	return nil
}

// IsBody reports whether raw starts like an order body, for tools that
// read several kinds of files.
func IsBody(raw []byte) bool { return len(raw) > 0 && raw[0] == kindBody }

// IsOrder reports whether raw starts like a signed order.
func IsOrder(raw []byte) bool { return len(raw) > 0 && raw[0] == kindOrder }
