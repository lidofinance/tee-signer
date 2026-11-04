// Package admin holds the wire codecs of the admin messages: plaintext
// and sealed share import and config updates (docs/protocol.md). Only clients of the admin role may send them
// (runner/server/roles.go). Package wire keeps the frames, the errors and
// the signing and attestation messages, so a signing client
// builds without this package.
package admin

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// The admin message types.
const (
	// TypeImportShare loads a share in plain text (debug builds only).
	TypeImportShare wire.MsgType = 0x05
	// TypeImportSealed loads a share encrypted to the import key.
	TypeImportSealed wire.MsgType = 0x07
	// TypeConfigUpdate carries an approver-signed config update
	// (CONFIG_UPDATE) and answers with the runner's setup state.
	TypeConfigUpdate wire.MsgType = 0x08
	// 0x09 was APPROVE_EXIT, the exit approvals; it is not reused.
	// TypeImportBatch loads many shares encrypted to the import key under
	// one import order (IMPORT_SHARES_SEALED).
	TypeImportBatch wire.MsgType = 0x0a
)

// readVersion checks the version byte an answer starts with and returns
// the rest.
func readVersion(b []byte, what string) ([]byte, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("wire: empty %s", what)
	}
	if b[0] != wire.IdentityVersion {
		return nil, fmt.Errorf("wire: %s of version %d, want %d", what, b[0], wire.IdentityVersion)
	}
	return b[1:], nil
}

// ---- IMPORT_SHARE --------------------------------------------------------

const importLen = 48 + 32 + 8 + 1 + 24

// EncodeImport: pubkey[48] secret[32] index:u64 flags:u8 block_slot:u64
// source_epoch:u64 target_epoch:u64. flags bit 0: has block, bit 1: has
// attestation (interchange maxima present).
func EncodeImport(req backend.ImportShareRequest) []byte {
	p := make([]byte, 0, importLen)
	p = append(p, req.Pubkey[:]...)
	p = append(p, req.Secret[:]...)
	p = binary.BigEndian.AppendUint64(p, req.Index)
	return AppendInterchange(p, req.Interchange)
}

// interchangeLen is flags:u8 block_slot:u64 source_epoch:u64 target_epoch:u64.
const interchangeLen = 1 + 24

// AppendInterchange appends the optional EIP-3076 maxima as flags and
// three u64 values (zero when absent).
func AppendInterchange(p []byte, w *backend.Watermark) []byte {
	var wm backend.Watermark
	if w != nil {
		wm = *w
	}
	var flags byte
	if wm.HasBlock {
		flags |= 1
	}
	if wm.HasAttestation {
		flags |= 2
	}
	p = append(p, flags)
	p = binary.BigEndian.AppendUint64(p, wm.BlockSlot)
	p = binary.BigEndian.AppendUint64(p, wm.SourceEpoch)
	return binary.BigEndian.AppendUint64(p, wm.TargetEpoch)
}

func decodeInterchange(p []byte) (*backend.Watermark, error) {
	flags := p[0]
	if flags&^3 != 0 {
		return nil, errors.New("unknown flags")
	}
	if flags == 0 {
		return nil, nil
	}
	return &backend.Watermark{
		HasBlock:       flags&1 != 0,
		HasAttestation: flags&2 != 0,
		BlockSlot:      binary.BigEndian.Uint64(p[1:]),
		SourceEpoch:    binary.BigEndian.Uint64(p[9:]),
		TargetEpoch:    binary.BigEndian.Uint64(p[17:]),
	}, nil
}

func DecodeImport(p []byte) (backend.ImportShareRequest, error) {
	var req backend.ImportShareRequest
	if len(p) != importLen {
		return req, fmt.Errorf("wire: IMPORT_SHARE: want %d bytes, got %d", importLen, len(p))
	}
	copy(req.Pubkey[:], p[0:48])
	copy(req.Secret[:], p[48:80])
	req.Index = binary.BigEndian.Uint64(p[80:])
	wm, err := decodeInterchange(p[88:])
	if err != nil {
		return req, fmt.Errorf("wire: IMPORT_SHARE: %w", err)
	}
	req.Interchange = wm
	return req, nil
}

// ---- IMPORT_SHARE_SEALED -------------------------------------------------

// SealedHeaderLen is the fixed part of IMPORT_SHARE_SEALED.
const SealedHeaderLen = 48 + 48 + 8 + interchangeLen

// MaxSealed bounds the sealed share (enc of ML-KEM-768-X25519 is 1120
// bytes, plus a 48-byte ciphertext).
const MaxSealed = 4096

// SealedHeader is pubkey[48] share_pubkey[48] index:u64 flags:u8
// block_slot:u64 source_epoch:u64 target_epoch:u64. It is also the HPKE
// associated data (package sealedimport).
func SealedHeader(req *backend.SealedImportRequest) []byte {
	p := make([]byte, 0, SealedHeaderLen)
	p = append(p, req.Pubkey[:]...)
	p = append(p, req.SharePubkey[:]...)
	p = binary.BigEndian.AppendUint64(p, req.Index)
	return AppendInterchange(p, req.Interchange)
}

// MaxImportOrder bounds the import order of IMPORT_SHARE_SEALED.
const MaxImportOrder = 128 << 10

// EncodeImportSealed: header sealed_len:u16 sealed, then, if the request
// has an import order, order_len:u32 order and, if it names the split,
// t:u8 n:u8 share_index:u8 commitments[48*t]. A request without an order
// is for a runner without a setup; a runner with a setup refuses it.
func EncodeImportSealed(req *backend.SealedImportRequest) ([]byte, error) {
	if len(req.Sealed) > MaxSealed {
		return nil, errors.New("wire: sealed share too long")
	}
	if len(req.Order) > MaxImportOrder {
		return nil, errors.New("wire: import order too long")
	}
	p := SealedHeader(req)
	p = binary.BigEndian.AppendUint16(p, uint16(len(req.Sealed)))
	p = append(p, req.Sealed...)
	if len(req.Order) > 0 {
		p = binary.BigEndian.AppendUint32(p, uint32(len(req.Order)))
		p = append(p, req.Order...)
		if req.T > 0 {
			if len(req.Commitments) != int(req.T) {
				return nil, errors.New("wire: import split: want t commitments")
			}
			p = append(p, req.T, req.N, req.ShareIndex)
			for _, c := range req.Commitments {
				p = append(p, c[:]...)
			}
		}
	} else if req.T > 0 {
		return nil, errors.New("wire: import split without an import order")
	}
	return p, nil
}

// decodeSealedShare reads the header and the sealed share, the start of
// IMPORT_SHARE_SEALED and of each share of IMPORT_SHARES_SEALED, and
// returns the bytes after them.
func decodeSealedShare(p []byte, req *backend.SealedImportRequest) ([]byte, error) {
	if len(p) < SealedHeaderLen+2 {
		return nil, errors.New("short payload")
	}
	copy(req.Pubkey[:], p[0:48])
	copy(req.SharePubkey[:], p[48:96])
	req.Index = binary.BigEndian.Uint64(p[96:])
	wm, err := decodeInterchange(p[104:])
	if err != nil {
		return nil, err
	}
	req.Interchange = wm
	n := int(binary.BigEndian.Uint16(p[SealedHeaderLen:]))
	rest := p[SealedHeaderLen+2:]
	if n > len(rest) || n > MaxSealed {
		return nil, errors.New("sealed length mismatch")
	}
	req.Sealed = append([]byte(nil), rest[:n]...)
	return rest[n:], nil
}

func DecodeImportSealed(p []byte) (backend.SealedImportRequest, error) {
	var req backend.SealedImportRequest
	rest, err := decodeSealedShare(p, &req)
	if err != nil {
		return req, fmt.Errorf("wire: IMPORT_SHARE_SEALED: %w", err)
	}
	if len(rest) == 0 {
		return req, nil
	}
	if len(rest) < 4 {
		return req, errors.New("wire: IMPORT_SHARE_SEALED: short import order")
	}
	m := int(binary.BigEndian.Uint32(rest))
	if m == 0 || m > MaxImportOrder || m > len(rest)-4 {
		return req, errors.New("wire: IMPORT_SHARE_SEALED: import order length mismatch")
	}
	req.Order = append([]byte(nil), rest[4:4+m]...)
	rest = rest[4+m:]
	if len(rest) == 0 {
		return req, nil
	}
	if len(rest) < 3 || rest[0] == 0 || len(rest) != 3+48*int(rest[0]) {
		return req, errors.New("wire: IMPORT_SHARE_SEALED: import split length mismatch")
	}
	req.T, req.N, req.ShareIndex = rest[0], rest[1], rest[2]
	for i := range int(req.T) {
		var c backend.Pubkey
		copy(c[:], rest[3+48*i:])
		req.Commitments = append(req.Commitments, c)
	}
	return req, nil
}

// ---- IMPORT_SHARES_SEALED ------------------------------------------------

// BatchVersion is the version byte IMPORT_SHARES_SEALED starts with.
const BatchVersion = 1

// MaxBatch bounds the shares of one IMPORT_SHARES_SEALED. The frame
// (wire.MaxFrame) bounds its bytes too: BatchLen and BatchShareLen size it.
const MaxBatch = 1024

// BatchLen is the length of IMPORT_SHARES_SEALED with order and no share.
func BatchLen(order []byte) int { return 1 + 4 + len(order) + 2 }

// BatchShareLen is what req adds to IMPORT_SHARES_SEALED.
func BatchShareLen(req *backend.SealedImportRequest) int {
	n := SealedHeaderLen + 2 + len(req.Sealed) + 1
	if req.T > 0 {
		n += 2 + 48*int(req.T)
	}
	return n
}

// EncodeImportBatch is IMPORT_SHARES_SEALED: version:u8 order_len:u32
// order count:u16, then per share its header, sealed_len:u16 sealed and
// t:u8, and if t > 0 n:u8 share_index:u8 commitments[48*t]. Every share
// goes under the one order; each request's Order is ignored. An empty
// order is for a runner without a setup.
func EncodeImportBatch(order []byte, reqs []backend.SealedImportRequest) ([]byte, error) {
	if len(reqs) > MaxBatch || len(order) > MaxImportOrder {
		return nil, errors.New("wire: import batch too long")
	}
	p := append([]byte{BatchVersion}, binary.BigEndian.AppendUint32(nil, uint32(len(order)))...)
	p = append(p, order...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(reqs)))
	for i := range reqs {
		r := &reqs[i]
		if len(r.Sealed) > MaxSealed || len(r.Commitments) != int(r.T) || r.T > 0 && len(order) == 0 {
			return nil, fmt.Errorf("wire: import batch: share %d: bad sealed share or split", i)
		}
		p = append(p, SealedHeader(r)...)
		p = binary.BigEndian.AppendUint16(p, uint16(len(r.Sealed)))
		p = append(append(p, r.Sealed...), r.T)
		if r.T > 0 {
			p = append(p, r.N, r.ShareIndex)
			for _, c := range r.Commitments {
				p = append(p, c[:]...)
			}
		}
	}
	return p, nil
}

// DecodeImportBatch reads IMPORT_SHARES_SEALED. Each request it returns
// carries the batch's order.
func DecodeImportBatch(p []byte) ([]backend.SealedImportRequest, error) {
	bad := func(what string) error { return fmt.Errorf("wire: IMPORT_SHARES_SEALED: %s", what) }
	if len(p) < 5 || p[0] != BatchVersion {
		return nil, bad(fmt.Sprintf("short payload or version other than %d", BatchVersion))
	}
	m := int(binary.BigEndian.Uint32(p[1:]))
	if m > MaxImportOrder || m+2 > len(p)-5 {
		return nil, bad("import order length mismatch")
	}
	var order []byte
	if m > 0 {
		order = append([]byte(nil), p[5:5+m]...)
	}
	n, rest := int(binary.BigEndian.Uint16(p[5+m:])), p[7+m:]
	if n > MaxBatch {
		return nil, bad("too many shares")
	}
	reqs := make([]backend.SealedImportRequest, n)
	for i := range reqs {
		r := &reqs[i]
		var err error
		if rest, err = decodeSealedShare(rest, r); err == nil && len(rest) < 1 {
			err = errors.New("short payload")
		}
		if err != nil {
			return nil, bad(fmt.Sprintf("share %d: %v", i, err))
		}
		t := int(rest[0])
		if t > 0 && (order == nil || len(rest) < 3+48*t) {
			return nil, bad(fmt.Sprintf("share %d: split length mismatch or split without an import order", i))
		}
		if t > 0 {
			r.T, r.N, r.ShareIndex = rest[0], rest[1], rest[2]
			for j := range t {
				r.Commitments = append(r.Commitments, backend.Pubkey(rest[3+48*j:3+48*(j+1)]))
			}
			rest = rest[2+48*t:]
		}
		r.Order, rest = order, rest[1:]
	}
	if len(rest) != 0 {
		return nil, bad("trailing bytes")
	}
	return reqs, nil
}

// ---- CONFIG_UPDATE -------------------------------------------------------

// MaxConfigUpdate bounds a signed config update: setupwire.MaxUpdate.
const MaxConfigUpdate = 64 << 10

// The outcome byte of a CONFIG_UPDATE answer.
const (
	// ConfigAccepted: the runner took the update as its group's pending
	// update. With no wait it may be in force already.
	ConfigAccepted uint8 = 1
	// ConfigKnown: the same update was the group's pending or active update
	// already. The runner wrote its body again if no readable copy was left.
	ConfigKnown uint8 = 2
)

// EncodeConfigUpdate is the CONFIG_UPDATE request: the signed update as
// approvers and signer-config make it (backend/setupwire, the 'U' layout),
// 1 to MaxConfigUpdate bytes. The runner decodes it strictly.
func EncodeConfigUpdate(update []byte) ([]byte, error) {
	if len(update) == 0 || len(update) > MaxConfigUpdate {
		return nil, fmt.Errorf("wire: config update of %d bytes, want 1 to %d", len(update), MaxConfigUpdate)
	}
	return append([]byte(nil), update...), nil
}

// DecodeConfigUpdate reads a CONFIG_UPDATE request and returns the signed
// update's bytes.
func DecodeConfigUpdate(p []byte) ([]byte, error) {
	if len(p) == 0 || len(p) > MaxConfigUpdate {
		return nil, fmt.Errorf("wire: CONFIG_UPDATE of %d bytes, want 1 to %d", len(p), MaxConfigUpdate)
	}
	return append([]byte(nil), p...), nil
}

// EncodeConfigUpdateResponse is the CONFIG_UPDATE answer: version:u8
// (wire.IdentityVersion, the setup state's version) outcome:u8 setup_state. The
// state is the runner's effective state after the update, unattested;
// IDENTITY attests the same values.
func EncodeConfigUpdateResponse(outcome uint8, s *backend.SetupState) []byte {
	return backend.AppendSetupState([]byte{wire.IdentityVersion, outcome}, s)
}

// DecodeConfigUpdateResponse reads a CONFIG_UPDATE answer.
func DecodeConfigUpdateResponse(b []byte) (uint8, *backend.SetupState, error) {
	b, err := readVersion(b, "CONFIG_UPDATE answer")
	if err != nil {
		return 0, nil, err
	}
	if len(b) != 1+backend.SetupStateLen {
		return 0, nil, fmt.Errorf("wire: CONFIG_UPDATE answer of %d bytes, want %d", len(b)+1, 2+backend.SetupStateLen)
	}
	if b[0] != ConfigAccepted && b[0] != ConfigKnown {
		return 0, nil, fmt.Errorf("wire: CONFIG_UPDATE outcome %d", b[0])
	}
	s, err := backend.ParseSetupState(b[1:])
	if err != nil {
		return 0, nil, fmt.Errorf("wire: %w", err)
	}
	return b[0], &s, nil
}
