// Package dkgmsg holds the messages of the runners' distributed key
// generation (docs/dkg.md) and their binary encoding. The runner (package
// runner/keygen) and the untrusted relay that carries the messages between
// runners both use it.
//
// Integers are big endian. A list of blobs is count:u16 then, per blob,
// len:u32 and the bytes.
package dkgmsg

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

const (
	Version = 1
	// MaxParticipants bounds n. With MaxValidators it keeps a FINISH
	// request (n deals) under wire.MaxFrame.
	MaxParticipants = 10
	// MaxValidators is the number of validator keys one session makes.
	MaxValidators = 64
	// MinNonce and MaxNonce bound the relay's session nonce.
	MinNonce = 16
	MaxNonce = 64
	// MaxSealed bounds one recipient's sealed shares (enc_len, HPKE enc of
	// 1120 bytes, MaxValidators shares, tag).
	MaxSealed = 2 + 1120 + 32*MaxValidators + 16
)

// Domain separation prefixes. Each hash or signature in the protocol starts
// with its own.
const (
	ctxHello      = "signer-dkg-hello-v1"
	ctxSession    = "signer-dkg-session-v1"
	ctxDeal       = "signer-dkg-deal-v1"
	ctxShareAAD   = "signer-dkg-share-aad-v1"
	ctxTranscript = "signer-dkg-transcript-v1"
	ctxResult     = "signer-dkg-result-v1"
	ctxConfirm    = "signer-dkg-confirm-v1"
	// ShareInfo is the HPKE info string of sealed shares.
	ShareInfo = "signer-dkg-share-v1"
)

var errShort = errors.New("dkgmsg: message too short")

// reader takes fields off a byte slice. After the first error every read
// returns zero values and err keeps that error.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (r *reader) fixed(dst []byte) { copy(dst, r.take(len(dst))) }

// done fails if bytes are left over.
func (r *reader) done() error {
	if r.err == nil && len(r.b) != 0 {
		r.err = errors.New("dkgmsg: trailing bytes")
	}
	return r.err
}

// EncodeList encodes blobs as count:u16 (len:u32 blob)*.
func EncodeList(blobs [][]byte) []byte {
	n := 2
	for _, b := range blobs {
		n += 4 + len(b)
	}
	p := binary.BigEndian.AppendUint16(make([]byte, 0, n), uint16(len(blobs)))
	for _, b := range blobs {
		p = binary.BigEndian.AppendUint32(p, uint32(len(b)))
		p = append(p, b...)
	}
	return p
}

// DecodeList decodes EncodeList's format with 1 to max blobs.
func DecodeList(b []byte, max int) ([][]byte, error) {
	r := &reader{b: b}
	n := int(r.u16())
	if r.err == nil && (n == 0 || n > max) {
		return nil, fmt.Errorf("dkgmsg: %d items, want 1 to %d", n, max)
	}
	out := make([][]byte, 0, n)
	for range n {
		v := r.take(int(r.u32()))
		if r.err != nil {
			break
		}
		out = append(out, append([]byte(nil), v...))
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- HELLO -------------------------------------------------------------

// HelloRequest starts a session: the relay's nonce and the number of
// validator keys to make.
type HelloRequest struct {
	Nonce []byte
	Count uint16
}

// Encode: nonce_len:u8 nonce count:u16.
func (q *HelloRequest) Encode() ([]byte, error) {
	if len(q.Nonce) < MinNonce || len(q.Nonce) > MaxNonce || q.Count == 0 || q.Count > MaxValidators {
		return nil, fmt.Errorf("dkgmsg: hello request needs a nonce of %d to %d bytes and 1 to %d validators",
			MinNonce, MaxNonce, MaxValidators)
	}
	p := append([]byte{byte(len(q.Nonce))}, q.Nonce...)
	return binary.BigEndian.AppendUint16(p, q.Count), nil
}

func DecodeHelloRequest(b []byte) (*HelloRequest, error) {
	r := &reader{b: b}
	q := &HelloRequest{}
	q.Nonce = append([]byte(nil), r.take(int(r.u8()))...)
	q.Count = r.u16()
	if err := r.done(); err != nil {
		return nil, err
	}
	if _, err := q.Encode(); err != nil {
		return nil, err
	}
	return q, nil
}

// Hello is a runner's attested entry into a session. Identity.ImportKey is
// the session's HPKE key that peers seal shares to; SignKey is the session's
// Ed25519 key that signs the runner's deal and confirmation. The attestation
// in Identity binds backend.DKGHelloUserData(AttestNonce(), Identity), so a
// verifier of the identity with that nonce also covers every field here.
type Hello struct {
	PolicyHash [32]byte
	Nonce      []byte
	Count      uint16
	Random     [32]byte
	SignKey    [32]byte
	// OperatorKey is the runner's operator key (DKG_OPERATOR); the policy
	// pins one per position.
	OperatorKey [32]byte
	Identity    *backend.Identity
}

// AttestNonce is the nonce the runner attests the hello's identity with.
func (h *Hello) AttestNonce() []byte {
	d := sha256.New()
	d.Write([]byte(ctxHello))
	d.Write(h.PolicyHash[:])
	d.Write([]byte{byte(len(h.Nonce))})
	d.Write(h.Nonce)
	d.Write(binary.BigEndian.AppendUint16(nil, h.Count))
	d.Write(h.Random[:])
	d.Write(h.SignKey[:])
	d.Write(h.OperatorKey[:])
	return d.Sum(nil)
}

// Encode: version:u8 policy_hash[32] nonce_len:u8 nonce count:u16
// random[32] sign_key[32] operator_key[32] identity (wire.EncodeIdentity).
func (h *Hello) Encode() ([]byte, error) {
	if len(h.Nonce) > MaxNonce || h.Identity == nil {
		return nil, errors.New("dkgmsg: bad hello")
	}
	id, err := wire.EncodeIdentity(h.Identity)
	if err != nil {
		return nil, err
	}
	p := append([]byte{Version}, h.PolicyHash[:]...)
	p = append(p, byte(len(h.Nonce)))
	p = append(p, h.Nonce...)
	p = binary.BigEndian.AppendUint16(p, h.Count)
	p = append(p, h.Random[:]...)
	p = append(p, h.SignKey[:]...)
	p = append(p, h.OperatorKey[:]...)
	return append(p, id...), nil
}

func DecodeHello(b []byte) (*Hello, error) {
	r := &reader{b: b}
	if v := r.u8(); r.err == nil && v != Version {
		return nil, fmt.Errorf("dkgmsg: hello version %d", v)
	}
	h := &Hello{}
	r.fixed(h.PolicyHash[:])
	h.Nonce = append([]byte(nil), r.take(int(r.u8()))...)
	h.Count = r.u16()
	r.fixed(h.Random[:])
	r.fixed(h.SignKey[:])
	r.fixed(h.OperatorKey[:])
	if r.err != nil {
		return nil, r.err
	}
	id, err := wire.DecodeIdentity(r.b)
	if err != nil {
		return nil, err
	}
	h.Identity = id
	return h, nil
}

// SessionID names a session: the policy and the hello of every participant
// in order. Each runner computes it from the hellos it is given.
func SessionID(policyHash [32]byte, hellos [][]byte) [32]byte {
	d := sha256.New()
	d.Write([]byte(ctxSession))
	d.Write(policyHash[:])
	d.Write(binary.BigEndian.AppendUint16(nil, uint16(len(hellos))))
	for _, h := range hellos {
		s := sha256.Sum256(h)
		d.Write(s[:])
	}
	var out [32]byte
	d.Sum(out[:0])
	return out
}

// ---- DEAL --------------------------------------------------------------

// SealedShares is one recipient's shares from one dealer: HPKE to the
// recipient's session key (enc_len:u16 enc ciphertext), with one 32-byte
// share per validator inside.
type SealedShares struct {
	Recipient uint16
	Sealed    []byte
}

// Deal is one dealer's message: Feldman commitments of one polynomial per
// validator, and the shares for every other participant, sealed to each.
type Deal struct {
	Session   [32]byte
	Dealer    uint16 // share ID x of the dealer, 1..n
	Threshold uint16
	// Commitments[v][k] = a_{v,k} * G1 for validator v and coefficient k.
	Commitments [][]backend.Pubkey
	Shares      []SealedShares
	Signature   [64]byte // Ed25519 by the dealer's hello SignKey over SignedBytes
}

func (d *Deal) body() []byte {
	p := append([]byte{Version}, d.Session[:]...)
	p = binary.BigEndian.AppendUint16(p, d.Dealer)
	p = binary.BigEndian.AppendUint16(p, d.Threshold)
	p = binary.BigEndian.AppendUint16(p, uint16(len(d.Commitments)))
	for _, cs := range d.Commitments {
		for _, c := range cs {
			p = append(p, c[:]...)
		}
	}
	p = binary.BigEndian.AppendUint16(p, uint16(len(d.Shares)))
	for _, s := range d.Shares {
		p = binary.BigEndian.AppendUint16(p, s.Recipient)
		p = binary.BigEndian.AppendUint16(p, uint16(len(s.Sealed)))
		p = append(p, s.Sealed...)
	}
	return p
}

// SignedBytes is what the dealer signs.
func (d *Deal) SignedBytes() []byte { return append([]byte(ctxDeal), d.body()...) }

// CommitmentsHash goes into each sealed share's associated data.
func (d *Deal) CommitmentsHash() [32]byte {
	h := sha256.New()
	for _, cs := range d.Commitments {
		for _, c := range cs {
			h.Write(c[:])
		}
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Encode: version:u8 session[32] dealer:u16 threshold:u16 count:u16
// commitments[count*threshold*48] shares:u16 (recipient:u16 len:u16
// sealed)* signature[64].
func (d *Deal) Encode() ([]byte, error) {
	if len(d.Commitments) == 0 || len(d.Commitments) > MaxValidators || len(d.Shares) >= MaxParticipants {
		return nil, errors.New("dkgmsg: bad deal")
	}
	for _, cs := range d.Commitments {
		if len(cs) != int(d.Threshold) {
			return nil, errors.New("dkgmsg: deal commitments do not match the threshold")
		}
	}
	for _, s := range d.Shares {
		if len(s.Sealed) > MaxSealed {
			return nil, errors.New("dkgmsg: sealed shares too long")
		}
	}
	return append(d.body(), d.Signature[:]...), nil
}

func DecodeDeal(b []byte) (*Deal, error) {
	r := &reader{b: b}
	if v := r.u8(); r.err == nil && v != Version {
		return nil, fmt.Errorf("dkgmsg: deal version %d", v)
	}
	d := &Deal{}
	r.fixed(d.Session[:])
	d.Dealer = r.u16()
	d.Threshold = r.u16()
	count := int(r.u16())
	if r.err == nil && (count == 0 || count > MaxValidators || d.Threshold == 0 || d.Threshold > MaxParticipants) {
		return nil, errors.New("dkgmsg: deal count or threshold out of range")
	}
	d.Commitments = make([][]backend.Pubkey, count)
	for v := range d.Commitments {
		d.Commitments[v] = make([]backend.Pubkey, d.Threshold)
		for k := range d.Commitments[v] {
			r.fixed(d.Commitments[v][k][:])
		}
	}
	ns := int(r.u16())
	if r.err == nil && ns >= MaxParticipants {
		return nil, errors.New("dkgmsg: too many sealed shares")
	}
	for range ns {
		s := SealedShares{Recipient: r.u16()}
		l := int(r.u16())
		if r.err == nil && l > MaxSealed {
			return nil, errors.New("dkgmsg: sealed shares too long")
		}
		s.Sealed = append([]byte(nil), r.take(l)...)
		if r.err != nil {
			break
		}
		d.Shares = append(d.Shares, s)
	}
	r.fixed(d.Signature[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	return d, nil
}

// ShareAAD is the HPKE associated data of the shares a dealer seals for a
// recipient: the session, both IDs and the dealer's commitments.
func ShareAAD(session [32]byte, dealer, recipient uint16, commitments [32]byte) []byte {
	p := append([]byte(ctxShareAAD), session[:]...)
	p = binary.BigEndian.AppendUint16(p, dealer)
	p = binary.BigEndian.AppendUint16(p, recipient)
	return append(p, commitments[:]...)
}

// TranscriptHash covers every deal of the session byte for byte. Runners
// that saw the same deals compute the same value.
func TranscriptHash(session [32]byte, deals [][]byte) [32]byte {
	d := sha256.New()
	d.Write([]byte(ctxTranscript))
	d.Write(session[:])
	d.Write(binary.BigEndian.AppendUint16(nil, uint16(len(deals))))
	for _, b := range deals {
		s := sha256.Sum256(b)
		d.Write(s[:])
	}
	var out [32]byte
	d.Sum(out[:0])
	return out
}

// ---- FINISH ------------------------------------------------------------

// Result is the public outcome of a session as one runner computed it.
type Result struct {
	Session    [32]byte
	Transcript [32]byte
	Self       uint16 // share ID of the runner that wrote it
	Threshold  uint16
	// GroupKeys[v] is validator v's key; PublicShares[v][i] the public key of
	// its share at x = i+1.
	GroupKeys    []backend.Pubkey
	PublicShares [][]backend.Pubkey
}

func (res *Result) body() []byte {
	p := append([]byte{Version}, res.Session[:]...)
	p = append(p, res.Transcript[:]...)
	p = binary.BigEndian.AppendUint16(p, res.Self)
	p = binary.BigEndian.AppendUint16(p, res.Threshold)
	n := 0
	if len(res.PublicShares) > 0 {
		n = len(res.PublicShares[0])
	}
	p = binary.BigEndian.AppendUint16(p, uint16(n))
	p = binary.BigEndian.AppendUint16(p, uint16(len(res.GroupKeys)))
	for v, k := range res.GroupKeys {
		p = append(p, k[:]...)
		for _, s := range res.PublicShares[v] {
			p = append(p, s[:]...)
		}
	}
	return p
}

// Hash covers everything but Self, so the results of all runners of one
// session hash the same.
func (res *Result) Hash() [32]byte {
	c := *res
	c.Self = 0
	return sha256.Sum256(append([]byte(ctxResult), c.body()...))
}

// Encode: version:u8 session[32] transcript[32] self:u16 threshold:u16 n:u16
// count:u16, then per validator group_key[48] and n public shares[48].
func (res *Result) Encode() ([]byte, error) {
	if len(res.GroupKeys) != len(res.PublicShares) || len(res.GroupKeys) == 0 {
		return nil, errors.New("dkgmsg: bad result")
	}
	for _, s := range res.PublicShares {
		if len(s) != len(res.PublicShares[0]) {
			return nil, errors.New("dkgmsg: bad result")
		}
	}
	return res.body(), nil
}

func DecodeResult(b []byte) (*Result, error) {
	r := &reader{b: b}
	if v := r.u8(); r.err == nil && v != Version {
		return nil, fmt.Errorf("dkgmsg: result version %d", v)
	}
	res := &Result{}
	r.fixed(res.Session[:])
	r.fixed(res.Transcript[:])
	res.Self = r.u16()
	res.Threshold = r.u16()
	n := int(r.u16())
	count := int(r.u16())
	if r.err == nil && (n == 0 || n > MaxParticipants || count == 0 || count > MaxValidators) {
		return nil, errors.New("dkgmsg: result size out of range")
	}
	if r.err != nil {
		return nil, r.err
	}
	res.GroupKeys = make([]backend.Pubkey, count)
	res.PublicShares = make([][]backend.Pubkey, count)
	for v := range count {
		r.fixed(res.GroupKeys[v][:])
		res.PublicShares[v] = make([]backend.Pubkey, n)
		for i := range n {
			r.fixed(res.PublicShares[v][i][:])
		}
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return res, nil
}

// Confirm is a runner's signed statement that it finished a session with
// this transcript and result. A runner keeps its new shares only once it
// holds a valid Confirm with the same values from every participant.
type Confirm struct {
	Session    [32]byte
	Transcript [32]byte
	ResultHash [32]byte
	Signer     uint16
	Signature  [64]byte // Ed25519 by the signer's hello SignKey over SignedBytes
}

// ConfirmLen is the encoded size of a Confirm.
const ConfirmLen = 32*3 + 2 + 64

func (c *Confirm) SignedBytes() []byte {
	p := append([]byte(ctxConfirm), c.Session[:]...)
	p = append(p, c.Transcript[:]...)
	p = append(p, c.ResultHash[:]...)
	return binary.BigEndian.AppendUint16(p, c.Signer)
}

// Encode: session[32] transcript[32] result_hash[32] signer:u16 signature[64].
func (c *Confirm) Encode() []byte {
	p := make([]byte, 0, ConfirmLen)
	p = append(append(append(p, c.Session[:]...), c.Transcript[:]...), c.ResultHash[:]...)
	p = binary.BigEndian.AppendUint16(p, c.Signer)
	return append(p, c.Signature[:]...)
}

func DecodeConfirm(b []byte) (*Confirm, error) {
	if len(b) != ConfirmLen {
		return nil, fmt.Errorf("dkgmsg: confirm: want %d bytes, got %d", ConfirmLen, len(b))
	}
	c := &Confirm{}
	r := &reader{b: b}
	r.fixed(c.Session[:])
	r.fixed(c.Transcript[:])
	r.fixed(c.ResultHash[:])
	c.Signer = r.u16()
	r.fixed(c.Signature[:])
	return c, r.done()
}

// Finished is the FINISH response: the result and the runner's confirmation.
type Finished struct {
	Result  *Result
	Confirm *Confirm
}

// Encode: a list of two blobs, the result and the confirmation.
func (f *Finished) Encode() ([]byte, error) {
	rb, err := f.Result.Encode()
	if err != nil {
		return nil, err
	}
	return EncodeList([][]byte{rb, f.Confirm.Encode()}), nil
}

func DecodeFinished(b []byte) (*Finished, error) {
	l, err := DecodeList(b, 2)
	if err != nil || len(l) != 2 {
		return nil, errors.New("dkgmsg: bad finish response")
	}
	res, err := DecodeResult(l[0])
	if err != nil {
		return nil, err
	}
	c, err := DecodeConfirm(l[1])
	if err != nil {
		return nil, err
	}
	return &Finished{Result: res, Confirm: c}, nil
}

// ---- COMMIT ------------------------------------------------------------

// CommitRequest carries every participant's confirmation of a session.
type CommitRequest struct {
	Session  [32]byte
	Confirms []*Confirm
}

// Encode: session[32] then the confirmations as a list.
func (q *CommitRequest) Encode() []byte {
	blobs := make([][]byte, len(q.Confirms))
	for i, c := range q.Confirms {
		blobs[i] = c.Encode()
	}
	return append(append([]byte(nil), q.Session[:]...), EncodeList(blobs)...)
}

func DecodeCommitRequest(b []byte) (*CommitRequest, error) {
	if len(b) < 32 {
		return nil, errShort
	}
	q := &CommitRequest{}
	copy(q.Session[:], b)
	l, err := DecodeList(b[32:], MaxParticipants)
	if err != nil {
		return nil, err
	}
	for _, cb := range l {
		c, err := DecodeConfirm(cb)
		if err != nil {
			return nil, err
		}
		q.Confirms = append(q.Confirms, c)
	}
	return q, nil
}
