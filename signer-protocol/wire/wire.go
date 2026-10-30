// Package wire is the length-prefixed protocol between the remote backend
// (in the client process) and the enclave runner. docs/protocol.md is the
// spec; this file is the reference implementation.
//
//	frame   = length:u32 body                  length = len(body)
//	body    = version:u8 type:u8 id:u32 payload
//
// Protocol integers are big endian. SSZ containers inside payloads keep
// SSZ little-endian encoding. One request is in flight per connection; a
// response carries the request's id and type|0x80.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	Version      = 1
	MaxFrame     = 1 << 20 // body bytes
	MaxNonce     = 1024
	MaxDetail    = 1024
	headerLen    = 6 // version, type, id
	ResponseFlag = 0x80
)

type MsgType uint8

// The signing and attestation message types. The admin types (imports,
// config updates, exit approvals) are in package wire/admin, the key
// handover types in tee-signer/handover.
const (
	TypeHealth     MsgType = 0x01
	TypePublicKeys MsgType = 0x02
	TypeSign       MsgType = 0x03
	TypeAttest     MsgType = 0x04
	TypeIdentity   MsgType = 0x06
)

// typeNames names every message type of the protocol, those of wire/admin
// and handover too, so logs stay readable without those packages.
var typeNames = map[MsgType]string{
	0x01: "HEALTH", 0x02: "PUBLIC_KEYS", 0x03: "SIGN", 0x04: "ATTEST", 0x05: "IMPORT_SHARE",
	0x06: "IDENTITY", 0x07: "IMPORT_SHARE_SEALED", 0x08: "CONFIG_UPDATE", 0x09: "APPROVE_EXIT",
	0x31: "HANDOVER_ORDER", 0x32: "HANDOVER", 0x33: "IMPORT_HANDOVER",
}

func (t MsgType) String() string {
	if n, ok := typeNames[t&^ResponseFlag]; ok {
		if t&ResponseFlag != 0 {
			return n + "_RESPONSE"
		}
		return n
	}
	return fmt.Sprintf("TYPE_0x%02x", uint8(t))
}

// Frame is one decoded message.
type Frame struct {
	Type    MsgType
	ID      uint32
	Payload []byte
}

var ErrFrameTooLarge = errors.New("wire: frame too large")

// WriteFrame writes f as one frame.
func WriteFrame(w io.Writer, f Frame) error {
	n := headerLen + len(f.Payload)
	if n > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+n)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	buf[4] = Version
	buf[5] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[6:], f.ID)
	copy(buf[10:], f.Payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame. It returns io.EOF only on a clean close
// between frames.
func ReadFrame(r io.Reader) (Frame, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxFrame {
		return Frame{}, ErrFrameTooLarge
	}
	if n < headerLen {
		return Frame{}, fmt.Errorf("wire: frame body of %d bytes is shorter than the header", n)
	}
	body, err := readBody(r, int(n))
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	if body[0] != Version {
		return Frame{}, fmt.Errorf("wire: unsupported version %d", body[0])
	}
	return Frame{Type: MsgType(body[1]), ID: binary.BigEndian.Uint32(body[2:]), Payload: body[6:]}, nil
}

// bodyChunk is the most ReadFrame allocates ahead of the bytes it has.
const bodyChunk = 16 << 10

// readBody reads n bytes, growing the buffer as they arrive: a peer that
// declares MaxFrame and stalls holds no more memory than it sent
// (ATTEST-BUDGET-01).
func readBody(r io.Reader, n int) ([]byte, error) {
	body := make([]byte, 0, min(n, bodyChunk))
	for len(body) < n {
		k := min(n-len(body), bodyChunk)
		body = slices.Grow(body, k)
		m, err := io.ReadFull(r, body[len(body):len(body)+k])
		body = body[:len(body)+m]
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

// ---- SIGN ----------------------------------------------------------------

// RootMessage payload size: type:u8 epoch:u64 object_root[32] domain[32].
const rootMsgLen = 1 + 8 + 32 + 32

// EncodeSign: pubkey[48] kind:u8, then for a root message (kind 5) its
// type:u8 epoch:u64 object_root[32] domain[32], and for every other kind
// domain[32] (SignRequest.Domain, the caller's) and the message. The runner
// refuses a typed request whose domain differs from its own.
func EncodeSign(req backend.SignRequest) ([]byte, error) {
	if req.Message == nil {
		return nil, errors.New("wire: sign request without message")
	}
	p := append(make([]byte, 0, 48+1+32+128), req.Pubkey[:]...)
	p = append(p, byte(req.Message.Kind()))
	if m, ok := req.Message.(*backend.RootMessage); ok {
		p = append(p, byte(m.Type))
		p = binary.BigEndian.AppendUint64(p, m.Epoch)
		p = append(p, m.ObjectRoot[:]...)
		p = append(p, m.Domain[:]...)
		return p, nil
	}
	body, err := backend.EncodeSSZ(req.Message)
	if err != nil {
		return nil, err
	}
	p = append(p, req.Domain[:]...)
	return append(p, body...), nil
}

func DecodeSign(p []byte) (backend.SignRequest, error) {
	var req backend.SignRequest
	if len(p) < 49 {
		return req, errors.New("wire: short SIGN payload")
	}
	copy(req.Pubkey[:], p[:48])
	kind := backend.Kind(p[48])
	body := p[49:]
	if kind == backend.KindRoot {
		if len(body) != rootMsgLen {
			return req, fmt.Errorf("wire: root message: want %d bytes, got %d", rootMsgLen, len(body))
		}
		m := &backend.RootMessage{Type: backend.RootType(body[0]), Epoch: binary.BigEndian.Uint64(body[1:])}
		copy(m.ObjectRoot[:], body[9:41])
		copy(m.Domain[:], body[41:73])
		req.Message = m
		return req, nil
	}
	if len(body) < len(req.Domain) {
		return req, fmt.Errorf("wire: %v: no domain", kind)
	}
	copy(req.Domain[:], body)
	m, err := backend.DecodeSSZ(kind, body[len(req.Domain):])
	if err != nil {
		return req, fmt.Errorf("wire: %w", err)
	}
	req.Message = m
	return req, nil
}

// ---- ATTEST --------------------------------------------------------------

// IdentityVersion is the version of the IDENTITY and ATTEST messages. The
// request ends with it and the answer starts with it. A runner refuses a
// request of another version with UNSUPPORTED (ErrRequestVersion).
const IdentityVersion = 1

// ErrRequestVersion: an ATTEST or IDENTITY request of another version than
// IdentityVersion.
var ErrRequestVersion = errors.New("wire: ATTEST or IDENTITY request of another version")

// EncodeAttest is the request of ATTEST and IDENTITY: nonce_len:u16 nonce
// version:u8 (IdentityVersion).
func EncodeAttest(nonce []byte) ([]byte, error) {
	if len(nonce) > MaxNonce {
		return nil, fmt.Errorf("wire: nonce longer than %d bytes", MaxNonce)
	}
	p := binary.BigEndian.AppendUint16(nil, uint16(len(nonce)))
	p = append(p, nonce...)
	return append(p, IdentityVersion), nil
}

// DecodeAttest reads the request of ATTEST and IDENTITY and returns the
// nonce. A request of another version gives ErrRequestVersion.
func DecodeAttest(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, errors.New("wire: bad ATTEST payload")
	}
	n := int(binary.BigEndian.Uint16(p))
	switch {
	case n != len(p)-3 || n > MaxNonce:
		return nil, errors.New("wire: bad ATTEST payload")
	case p[len(p)-1] != IdentityVersion:
		return nil, fmt.Errorf("%w: version %d, this runner answers version %d", ErrRequestVersion, p[len(p)-1], IdentityVersion)
	}
	return append([]byte(nil), p[2:2+n]...), nil
}

// readVersion checks the version byte an ATTEST or IDENTITY answer starts
// with and returns the rest.
func readVersion(b []byte, what string) ([]byte, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("wire: empty %s", what)
	}
	if b[0] != IdentityVersion {
		return nil, fmt.Errorf("wire: %s of version %d, want %d", what, b[0], IdentityVersion)
	}
	return b[1:], nil
}

// EncodeAttestResponse is the ATTEST answer: version:u8 (IdentityVersion)
// setup_state attestation. The document binds backend.AttestUserData of
// the nonce, the state and the loaded keys.
func EncodeAttestResponse(s *backend.SetupState, a *backend.Attestation) ([]byte, error) {
	at, err := EncodeAttestation(a)
	if err != nil {
		return nil, err
	}
	p := backend.AppendSetupState([]byte{IdentityVersion}, s)
	return append(p, at...), nil
}

// DecodeAttestResponse reads an ATTEST answer.
func DecodeAttestResponse(b []byte) (*backend.SetupState, *backend.Attestation, error) {
	b, err := readVersion(b, "ATTEST answer")
	if err != nil {
		return nil, nil, err
	}
	if len(b) < backend.SetupStateLen {
		return nil, nil, errors.New("wire: short ATTEST answer")
	}
	s, err := backend.ParseSetupState(b[:backend.SetupStateLen])
	if err != nil {
		return nil, nil, fmt.Errorf("wire: %w", err)
	}
	a, err := DecodeAttestation(b[backend.SetupStateLen:])
	if err != nil {
		return nil, nil, err
	}
	return &s, a, nil
}

// ---- IDENTITY ------------------------------------------------------------

// The request is the same as ATTEST: nonce_len:u16 nonce version:u8.

// MaxImportKey bounds the HPKE public key (ML-KEM-768-X25519: 1216 bytes).
const MaxImportKey = 4096

// EncodeIdentity: version:u8 (IdentityVersion) setup_state (see
// backend.AppendSetupState) kem:u16 kdf:u16 aead:u16 import_key_len:u16
// import_key tls_key_hash_len:u8 tls_key_hash attestation (as in ATTEST).
// The handover messages carry an identity in this form too.
func EncodeIdentity(id *backend.Identity) ([]byte, error) {
	if len(id.ImportKey) > MaxImportKey || len(id.TLSKeyHash) > 255 || id.Attestation == nil {
		return nil, errors.New("wire: bad identity")
	}
	p := backend.AppendSetupState([]byte{IdentityVersion}, &id.State)
	p = binary.BigEndian.AppendUint16(p, id.ImportKEM)
	p = binary.BigEndian.AppendUint16(p, id.ImportKDF)
	p = binary.BigEndian.AppendUint16(p, id.ImportAEAD)
	p = binary.BigEndian.AppendUint16(p, uint16(len(id.ImportKey)))
	p = append(p, id.ImportKey...)
	p = append(p, byte(len(id.TLSKeyHash)))
	p = append(p, id.TLSKeyHash...)
	a, err := EncodeAttestation(id.Attestation)
	if err != nil {
		return nil, err
	}
	return append(p, a...), nil
}

// DecodeIdentity reads an identity. It refuses another version than
// IdentityVersion.
func DecodeIdentity(b []byte) (*backend.Identity, error) {
	b, err := readVersion(b, "identity")
	if err != nil {
		return nil, err
	}
	bad := errors.New("wire: malformed identity")
	const fixed = backend.SetupStateLen + 8
	if len(b) < fixed {
		return nil, bad
	}
	var id backend.Identity
	if id.State, err = backend.ParseSetupState(b[:backend.SetupStateLen]); err != nil {
		return nil, fmt.Errorf("wire: identity: %w", err)
	}
	b = b[backend.SetupStateLen:]
	id.ImportKEM = binary.BigEndian.Uint16(b[0:])
	id.ImportKDF = binary.BigEndian.Uint16(b[2:])
	id.ImportAEAD = binary.BigEndian.Uint16(b[4:])
	n := int(binary.BigEndian.Uint16(b[6:]))
	b = b[8:]
	if n > len(b) || n > MaxImportKey {
		return nil, bad
	}
	id.ImportKey = append([]byte(nil), b[:n]...)
	b = b[n:]
	if len(b) < 1 || int(b[0]) > len(b)-1 {
		return nil, bad
	}
	id.TLSKeyHash = append([]byte(nil), b[1:1+int(b[0])]...)
	a, err := DecodeAttestation(b[1+int(b[0]):])
	if err != nil {
		return nil, err
	}
	id.Attestation = a
	return &id, nil
}

// ---- responses -----------------------------------------------------------

// EncodeOK: status:u16 = 0, then the type-specific body.
func EncodeOK(body []byte) []byte {
	return append([]byte{0, 0}, body...)
}

// EncodeError: status:u16 detail_len:u16 detail (UTF-8, at most MaxDetail bytes).
func EncodeError(err error) []byte {
	st := backend.StatusOf(err)
	if st == backend.StatusOK {
		st = backend.StatusInternal
	}
	detail := err.Error()
	var r *backend.RefusedError
	if errors.As(err, &r) {
		detail = r.Detail
	}
	if len(detail) > MaxDetail {
		detail = detail[:MaxDetail]
	}
	p := binary.BigEndian.AppendUint16(nil, uint16(st))
	p = binary.BigEndian.AppendUint16(p, uint16(len(detail)))
	return append(p, detail...)
}

// DecodeResponse returns the body of an OK response, or a *backend.RefusedError.
func DecodeResponse(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, errors.New("wire: short response")
	}
	st := backend.Status(binary.BigEndian.Uint16(p))
	if st == backend.StatusOK {
		return p[2:], nil
	}
	if len(p) < 4 || int(binary.BigEndian.Uint16(p[2:])) != len(p)-4 {
		return nil, fmt.Errorf("wire: malformed error response (status %v)", st)
	}
	return nil, &backend.RefusedError{Code: st, Detail: string(p[4:])}
}

// Signature body: signature[96].
func DecodeSignature(b []byte) (backend.Signature, error) {
	var s backend.Signature
	if len(b) != len(s) {
		return s, fmt.Errorf("wire: signature: want 96 bytes, got %d", len(b))
	}
	copy(s[:], b)
	return s, nil
}

// Key body: pubkey[48] share_pubkey[48] index:u64.
const keyLen = 48 + 48 + 8

func AppendKey(p []byte, k backend.ValidatorKey) []byte {
	p = append(p, k.Pubkey[:]...)
	p = append(p, k.SharePubkey[:]...)
	return binary.BigEndian.AppendUint64(p, k.Index)
}

func DecodeKey(b []byte) (backend.ValidatorKey, error) {
	var k backend.ValidatorKey
	if len(b) != keyLen {
		return k, fmt.Errorf("wire: key: want %d bytes, got %d", keyLen, len(b))
	}
	copy(k.Pubkey[:], b[0:48])
	copy(k.SharePubkey[:], b[48:96])
	k.Index = binary.BigEndian.Uint64(b[96:])
	return k, nil
}

// Keys body: count:u32 then count keys.
func EncodeKeys(keys []backend.ValidatorKey) []byte {
	p := binary.BigEndian.AppendUint32(make([]byte, 0, 4+keyLen*len(keys)), uint32(len(keys)))
	for _, k := range keys {
		p = AppendKey(p, k)
	}
	return p
}

func DecodeKeys(b []byte) ([]backend.ValidatorKey, error) {
	if len(b) < 4 {
		return nil, errors.New("wire: short key list")
	}
	n := int(binary.BigEndian.Uint32(b))
	if len(b) != 4+n*keyLen {
		return nil, errors.New("wire: key list length mismatch")
	}
	keys := make([]backend.ValidatorKey, n)
	for i := range keys {
		keys[i], _ = DecodeKey(b[4+i*keyLen : 4+(i+1)*keyLen])
	}
	return keys, nil
}

// Attestation body: platform_len:u8 platform format_len:u8 format
// user_data_len:u16 user_data doc_len:u32 document.
func EncodeAttestation(a *backend.Attestation) ([]byte, error) {
	if len(a.Platform) > 255 || len(a.Format) > 255 || len(a.UserData) > 0xffff {
		return nil, errors.New("wire: attestation field too long")
	}
	p := append([]byte{byte(len(a.Platform))}, a.Platform...)
	p = append(p, byte(len(a.Format)))
	p = append(p, a.Format...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(a.UserData)))
	p = append(p, a.UserData...)
	p = binary.BigEndian.AppendUint32(p, uint32(len(a.Document)))
	return append(p, a.Document...), nil
}

func DecodeAttestation(b []byte) (*backend.Attestation, error) {
	bad := errors.New("wire: malformed attestation")
	take := func(n int) ([]byte, error) {
		if n > len(b) {
			return nil, bad
		}
		v := b[:n]
		b = b[n:]
		return v, nil
	}
	var a backend.Attestation
	for _, dst := range []*string{&a.Platform, &a.Format} {
		l, err := take(1)
		if err != nil {
			return nil, err
		}
		v, err := take(int(l[0]))
		if err != nil {
			return nil, err
		}
		*dst = string(v)
	}
	l, err := take(2)
	if err != nil {
		return nil, err
	}
	ud, err := take(int(binary.BigEndian.Uint16(l)))
	if err != nil {
		return nil, err
	}
	a.UserData = append([]byte(nil), ud...)
	l, err = take(4)
	if err != nil {
		return nil, err
	}
	doc, err := take(int(binary.BigEndian.Uint32(l)))
	if err != nil || len(b) != 0 {
		return nil, bad
	}
	a.Document = append([]byte(nil), doc...)
	return &a, nil
}

// Health body: JSON of backend.Health. Not security relevant, so JSON keeps
// it easy to extend.
func EncodeHealth(h *backend.Health) ([]byte, error) { return json.Marshal(h) }

func DecodeHealth(b []byte) (*backend.Health, error) {
	var h backend.Health
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("wire: health: %w", err)
	}
	return &h, nil
}
