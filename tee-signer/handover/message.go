package handover

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// HANDOVER. A runner with a setup hands its shares over only under an
// approver-signed handover order (package handoverorder) that names the
// target's setup_hash, and only to a target whose attested identity
// carries it. The request carries the target's identity and its published
// setup as bytes, which the source decodes and checks.
//
//	request  = version:u8(1) nonce_len:u16 nonce identity_len:u32 identity
//	           policy_len:u32 policy order_len:u32 order start:u32
//	response = version:u8(1) mark[26] total:u32 origin_proof
//	           count:u16 {share_len:u16 share} carry_len:u32 carry
//	origin_proof = origin_key[32] nonce_len:u16 nonce attestation_len:u32
//	           attestation (wire.EncodeAttestation)
//	share    = header sealed_len:u16 sealed origin_sig[64]
//	header   = pubkey[48] share_pubkey[48] index:u64 interchange[25]
//	           origin:u8 reserved[32]
//
// identity is the target's IDENTITY answer for nonce, policy its published
// setup, order the signed handover order. start pages through the shares;
// every request is checked in full again.
//
// Each share is a sealed import (IMPORT_SHARE_SEALED's header, the mark
// as interchange maxima) with the share's key origin added. The origin is
// always 1 (imported) and the 32 reserved bytes after it are zero: the
// layout is that of earlier builds, which also handed over keys made in
// key generation (origin 2, with that order's hash). DecodeShare refuses
// any other origin and reserved bytes that are not zero, so such a share
// never counts as an imported one. The carry (carry.go) holds the key set
// the source hands over and the day's exits of its mark log. The HPKE
// associated data is CtxHandoverShare over the header and the carry's
// hash, so neither the mark, the origin nor the carry changes without the
// open failing, and a handed-over share does not open as a plain sealed
// import.
//
// HPKE does not say who sealed: anyone can seal a share of their own to
// the target's attested import key. So the header is signed. The source
// makes an Ed25519 origin key per process, signs each header with it under
// CtxHandoverOrigin, and proves the key with its own attestation: the
// origin proof is a platform document over CtxHandoverOriginKey(order_hash,
// origin_key) for the request's nonce. A target that verifies the proof
// with the order's source settings (its image and verifier) and each
// header's signature knows the header, with its mark, came from that
// image.

// Type is HANDOVER.
const Type wire.MsgType = 0x32

// Version is the version byte of the request and response.
const Version = 1

// Caps of the request's parts.
const (
	MaxIdentity = wire.MaxFrame / 4
	MaxPolicy   = 64 << 10 // setupwire.MaxPublished
	MaxOrder    = 8 << 10  // handoverorder.MaxSize
)

// OriginImported is the key origin of every handed-over share.
const OriginImported uint8 = 1

// Request asks a source to hand its shares to the target of an order.
type Request struct {
	Nonce    []byte
	Identity []byte // the target's IDENTITY answer for Nonce
	Policy   []byte // the target's published setup
	Order    []byte // the signed handover order
	Start    uint32
}

// Encode is the request.
func (q *Request) Encode() ([]byte, error) {
	if len(q.Nonce) > wire.MaxNonce || len(q.Identity) > MaxIdentity || len(q.Policy) > MaxPolicy || len(q.Order) > MaxOrder {
		return nil, errors.New("handover: request part too long")
	}
	p := []byte{Version}
	p = binary.BigEndian.AppendUint16(p, uint16(len(q.Nonce)))
	p = append(p, q.Nonce...)
	for _, part := range [][]byte{q.Identity, q.Policy, q.Order} {
		p = binary.BigEndian.AppendUint32(p, uint32(len(part)))
		p = append(p, part...)
	}
	return binary.BigEndian.AppendUint32(p, q.Start), nil
}

// cursor takes fields off a byte slice; the first short read sets err.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.b) {
		c.err = errShort
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}

func (c *cursor) u8() uint8 {
	if v := c.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (c *cursor) u16() uint16 {
	if v := c.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (c *cursor) u32() uint32 {
	if v := c.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (c *cursor) u64() uint64 {
	if v := c.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

// part reads len:u32 and that many bytes, at most max.
func (c *cursor) part(what string, max int) []byte {
	n := c.u32()
	if c.err == nil && int64(n) > int64(max) {
		c.err = fmt.Errorf("handover: %s of %d bytes, at most %d", what, n, max)
		return nil
	}
	return bytes.Clone(c.take(int(n)))
}

func (c *cursor) done() error {
	if c.err == nil && len(c.b) != 0 {
		c.err = errors.New("handover: trailing bytes")
	}
	return c.err
}

// DecodeRequest reads a request: the layout and the caps. The parts
// are checked by their own decoders.
func DecodeRequest(p []byte) (*Request, error) {
	c := &cursor{b: p}
	if v := c.u8(); c.err == nil && v != Version {
		return nil, fmt.Errorf("handover: request version %d, want %d", v, Version)
	}
	q := &Request{}
	n := int(c.u16())
	if c.err == nil && n > wire.MaxNonce {
		return nil, fmt.Errorf("handover: nonce of %d bytes, at most %d", n, wire.MaxNonce)
	}
	q.Nonce = bytes.Clone(c.take(n))
	q.Identity = c.part("identity", MaxIdentity)
	q.Policy = c.part("policy", MaxPolicy)
	q.Order = c.part("order", MaxOrder)
	q.Start = c.u32()
	if err := c.done(); err != nil {
		return nil, err
	}
	return q, nil
}

// Share is one handed-over share.
type Share struct {
	backend.SealedImportRequest
	Origin    uint8    // OriginImported
	OriginSig [64]byte // by the source's origin key over the header
}

// HeaderLen is the length of a handed-over share's header.
const HeaderLen = wireadmin.SealedHeaderLen + 1 + 32

// Header is the share's header: IMPORT_SHARE_SEALED's header, origin:u8
// and 32 reserved zero bytes.
func (s *Share) Header() []byte {
	h := wireadmin.SealedHeader(&s.SealedImportRequest)
	h = append(h, s.Origin)
	return append(h, make([]byte, 32)...)
}

// CarriesMark reports whether the share's interchange maxima are mark. A
// mark of a log that never signed has neither part, and its shares carry
// no maxima (the header's flags are 0).
func (s *Share) CarriesMark(mark backend.Watermark) bool {
	if !mark.HasBlock && !mark.HasAttestation {
		return s.Interchange == nil
	}
	return s.Interchange != nil && *s.Interchange == mark
}

// CheckOrigin refuses a key origin other than OriginImported. Origin 2
// was a key made in key generation inside the source, in earlier builds.
func (s *Share) CheckOrigin() error {
	if s.Origin != OriginImported {
		return fmt.Errorf("handover: key origin %d, want 1 (imported)", s.Origin)
	}
	return nil
}

// SignOrigin signs the share's header with the origin key.
func (s *Share) SignOrigin(key ed25519.PrivateKey) {
	copy(s.OriginSig[:], ed25519.Sign(key, setupwire.CtxHandoverOrigin.Message(s.Header())))
}

// VerifyOrigin checks the share's origin signature under the origin key.
func (s *Share) VerifyOrigin(key [32]byte) error {
	if !ed25519.Verify(ed25519.PublicKey(key[:]), setupwire.CtxHandoverOrigin.Message(s.Header()), s.OriginSig[:]) {
		return errors.New("handover: the origin signature does not verify under the source's origin key")
	}
	return nil
}

// Encode is header sealed_len:u16 sealed origin_sig[64].
func (s *Share) Encode() ([]byte, error) {
	if len(s.Sealed) > wireadmin.MaxSealed {
		return nil, errors.New("handover: sealed share too long")
	}
	if err := s.CheckOrigin(); err != nil {
		return nil, err
	}
	p := s.Header()
	p = binary.BigEndian.AppendUint16(p, uint16(len(s.Sealed)))
	p = append(p, s.Sealed...)
	return append(p, s.OriginSig[:]...), nil
}

// DecodeShare reads a handed-over share strictly.
func DecodeShare(p []byte) (*Share, error) {
	if len(p) < HeaderLen+2+64 {
		return nil, errShort
	}
	// The sealed import's header and length, as IMPORT_SHARE_SEALED has
	// them, with origin and the reserved bytes between.
	n := int(binary.BigEndian.Uint16(p[HeaderLen:]))
	if n > wireadmin.MaxSealed || len(p) != HeaderLen+2+n+64 {
		return nil, errors.New("handover: share of the wrong length")
	}
	plain := append(bytes.Clone(p[:wireadmin.SealedHeaderLen]), p[HeaderLen:HeaderLen+2+n]...)
	req, err := wireadmin.DecodeImportSealed(plain)
	if err != nil {
		return nil, err
	}
	s := &Share{SealedImportRequest: req, Origin: p[wireadmin.SealedHeaderLen]}
	if !bytes.Equal(p[wireadmin.SealedHeaderLen+1:HeaderLen], make([]byte, 32)) {
		return nil, errors.New("handover: the reserved bytes after the key origin are not zero")
	}
	copy(s.OriginSig[:], p[HeaderLen+2+n:])
	if err := s.CheckOrigin(); err != nil {
		return nil, err
	}
	return s, nil
}

// OriginProof is the source's attestation of its origin key.
type OriginProof struct {
	Key         [32]byte // Ed25519
	Nonce       []byte   // the request's nonce
	Attestation *backend.Attestation
}

// OriginUserData is the user data the origin proof's attestation binds:
// CtxHandoverOriginKey over the order hash and the origin key.
func OriginUserData(orderHash, key [32]byte) []byte {
	h := setupwire.CtxHandoverOriginKey.Hash(orderHash[:], key[:])
	return h[:]
}

func (o *OriginProof) encode(p []byte) ([]byte, error) {
	if o.Attestation == nil || len(o.Nonce) > wire.MaxNonce {
		return nil, errors.New("handover: bad origin proof")
	}
	a, err := wire.EncodeAttestation(o.Attestation)
	if err != nil {
		return nil, err
	}
	p = append(p, o.Key[:]...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(o.Nonce)))
	p = append(p, o.Nonce...)
	p = binary.BigEndian.AppendUint32(p, uint32(len(a)))
	return append(p, a...), nil
}

// Response is one page of a handover.
type Response struct {
	Mark   backend.Watermark
	Total  uint32
	Origin OriginProof
	Shares []Share
	// Carry is the source's carry. Every share of the response is sealed
	// under its hash (Share.AAD).
	Carry Carry
}

// Encode is the response.
func (r *Response) Encode() ([]byte, error) {
	if len(r.Shares) > MaxPerResponse {
		return nil, errors.New("handover: too many shares in one response")
	}
	p := appendMark([]byte{Version}, r.Mark)
	p = binary.BigEndian.AppendUint32(p, r.Total)
	p, err := r.Origin.encode(p)
	if err != nil {
		return nil, err
	}
	p = binary.BigEndian.AppendUint16(p, uint16(len(r.Shares)))
	for i := range r.Shares {
		s, err := r.Shares[i].Encode()
		if err != nil {
			return nil, err
		}
		p = binary.BigEndian.AppendUint16(p, uint16(len(s)))
		p = append(p, s...)
	}
	c, err := r.Carry.Encode()
	if err != nil {
		return nil, err
	}
	p = binary.BigEndian.AppendUint32(p, uint32(len(c)))
	return append(p, c...), nil
}

// DecodeResponse reads a response. Every share must carry the page's
// mark as its interchange maxima.
func DecodeResponse(p []byte) (*Response, error) {
	c := &cursor{b: p}
	if v := c.u8(); c.err == nil && v != Version {
		return nil, fmt.Errorf("handover: response version %d, want %d", v, Version)
	}
	m := c.take(markLen)
	if c.err != nil {
		return nil, c.err
	}
	if m[0] > 1 || m[9] > 1 {
		return nil, errors.New("handover: bad mark flags")
	}
	r := &Response{Mark: backend.Watermark{
		HasBlock: m[0] == 1, BlockSlot: binary.BigEndian.Uint64(m[1:]),
		HasAttestation: m[9] == 1, SourceEpoch: binary.BigEndian.Uint64(m[10:]), TargetEpoch: binary.BigEndian.Uint64(m[18:]),
	}}
	r.Total = c.u32()
	copy(r.Origin.Key[:], c.take(32))
	n := int(c.u16())
	if c.err == nil && n > wire.MaxNonce {
		return nil, errors.New("handover: origin proof nonce too long")
	}
	r.Origin.Nonce = bytes.Clone(c.take(n))
	if a := c.part("origin attestation", wire.MaxFrame); c.err == nil {
		var err error
		if r.Origin.Attestation, err = wire.DecodeAttestation(a); err != nil {
			return nil, err
		}
	}
	count := int(c.u16())
	if c.err == nil && count > MaxPerResponse {
		return nil, errors.New("handover: too many shares in one response")
	}
	seen := map[backend.Pubkey]bool{}
	for range count {
		l := int(c.u16())
		b := c.take(l)
		if c.err != nil {
			break
		}
		s, err := DecodeShare(b)
		if err != nil {
			return nil, err
		}
		if !s.CarriesMark(r.Mark) {
			return nil, errors.New("handover: a share does not carry the handed-over mark")
		}
		// One share per validator in a page (APSTATE-02).
		if seen[s.Pubkey] {
			return nil, fmt.Errorf("handover: validator %s twice in one page", s.Pubkey.String()[:18])
		}
		seen[s.Pubkey] = true
		r.Shares = append(r.Shares, *s)
	}
	if b := c.part("carry", MaxCarry); c.err == nil {
		carry, err := DecodeCarry(b)
		if err != nil {
			return nil, err
		}
		if carry.Set.Total != r.Total {
			return nil, fmt.Errorf("handover: the page's total is %d, its carry's key set has %d", r.Total, carry.Set.Total)
		}
		r.Carry = *carry
	}
	if err := c.done(); err != nil {
		return nil, err
	}
	return r, nil
}
