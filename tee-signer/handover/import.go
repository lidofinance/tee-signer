package handover

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// IMPORT_HANDOVER: the target's side of HANDOVER (server/
// handover_import.go). The operator's tool (signer-admin cmd/handover-target)
// passes the pages the source sealed to this target on, with the signed
// handover order:
//
//	request  = version:u8(1) flags:u8 order_len:u32 order page_len:u32 page
//	response = version:u8(1) count:u16 {outcome:u8} held:u32 total:u32
//	           done:u8 generated:u32 imported:u32
//
// page is a HANDOVER response (Response's encoding): the mark, the
// source's total, its origin proof, some or all of one page's shares and
// the carry.
// The tool may split a page into smaller requests; every request carries
// the order and the origin proof again, and the target checks them again
// (it keeps the results of the expensive checks per process).
//
// The response has one outcome per share of the request, in order, then
// how many keys the target holds of the total, whether the import is done,
// and the target's key origin counts.

// TypeImport is IMPORT_HANDOVER.
const TypeImport wire.MsgType = 0x33

// ImportVersion is the version byte of the request and the response.
const ImportVersion = 1

// Request flags.
const (
	// ImportAsImported skips the origin checks (the source's origin proof
	// and each header's signature): for a target built without the
	// verifier of the source's platform, by the operator's choice.
	ImportAsImported uint8 = 1
)

// Outcomes of one share.
const (
	// Stored: the share was stored and loaded by this request.
	Stored uint8 = 1
	// Held: the target held this share already (an earlier request).
	Held uint8 = 2
)

// ImportRequest passes handed-over shares to the target.
type ImportRequest struct {
	Flags uint8
	Order []byte    // the signed handover order (package handoverorder)
	Page  *Response // the source's page, or part of one
}

// Encode is the IMPORT_HANDOVER request.
func (q *ImportRequest) Encode() ([]byte, error) {
	if q.Page == nil || len(q.Order) > MaxOrder {
		return nil, errors.New("handover import: bad request")
	}
	if q.Flags&^ImportAsImported != 0 {
		return nil, fmt.Errorf("handover import: unknown flags %#02x", q.Flags)
	}
	page, err := q.Page.Encode()
	if err != nil {
		return nil, err
	}
	p := []byte{ImportVersion, q.Flags}
	p = binary.BigEndian.AppendUint32(p, uint32(len(q.Order)))
	p = append(p, q.Order...)
	p = binary.BigEndian.AppendUint32(p, uint32(len(page)))
	p = append(p, page...)
	if len(p) > wire.MaxFrame {
		return nil, fmt.Errorf("handover import: request of %d bytes, at most %d", len(p), wire.MaxFrame)
	}
	return p, nil
}

// DecodeImportRequest reads a request strictly. The page decodes as a
// HANDOVER response: every share carries the page's mark.
func DecodeImportRequest(p []byte) (*ImportRequest, error) {
	c := &cursor{b: p}
	if v := c.u8(); c.err == nil && v != ImportVersion {
		return nil, fmt.Errorf("handover import: request version %d, want %d", v, ImportVersion)
	}
	q := &ImportRequest{Flags: c.u8()}
	if c.err == nil && q.Flags&^ImportAsImported != 0 {
		return nil, fmt.Errorf("handover import: unknown flags %#02x", q.Flags)
	}
	q.Order = c.part("order", MaxOrder)
	page := c.part("page", wire.MaxFrame)
	if err := c.done(); err != nil {
		return nil, err
	}
	var err error
	if q.Page, err = DecodeResponse(page); err != nil {
		return nil, err
	}
	return q, nil
}

// ImportResponse is the target's answer.
type ImportResponse struct {
	Outcomes []uint8 // one per share of the request
	Held     uint32  // keys the target holds now
	Total    uint32  // the source's total
	Done     bool    // every share is in; the target signs again
	Imported uint32  // the loaded keys (backend.KeyOrigin)
}

// Encode is the IMPORT_HANDOVER response.
func (r *ImportResponse) Encode() ([]byte, error) {
	if len(r.Outcomes) > MaxPerResponse {
		return nil, errors.New("handover import: too many outcomes")
	}
	p := []byte{ImportVersion}
	p = binary.BigEndian.AppendUint16(p, uint16(len(r.Outcomes)))
	p = append(p, r.Outcomes...)
	p = binary.BigEndian.AppendUint32(p, r.Held)
	p = binary.BigEndian.AppendUint32(p, r.Total)
	done := byte(0)
	if r.Done {
		done = 1
	}
	p = append(p, done)
	// Four reserved zero bytes: earlier builds counted keys made in key
	// generation here.
	p = binary.BigEndian.AppendUint32(p, 0)
	return binary.BigEndian.AppendUint32(p, r.Imported), nil
}

// DecodeImportResponse reads a response strictly.
func DecodeImportResponse(p []byte) (*ImportResponse, error) {
	c := &cursor{b: p}
	if v := c.u8(); c.err == nil && v != ImportVersion {
		return nil, fmt.Errorf("handover import: response version %d, want %d", v, ImportVersion)
	}
	n := int(c.u16())
	if c.err == nil && n > MaxPerResponse {
		return nil, errors.New("handover import: too many outcomes")
	}
	r := &ImportResponse{}
	for _, o := range c.take(n) {
		if o != Stored && o != Held {
			return nil, fmt.Errorf("handover import: outcome %d", o)
		}
		r.Outcomes = append(r.Outcomes, o)
	}
	r.Held, r.Total = c.u32(), c.u32()
	switch d := c.u8(); {
	case c.err != nil:
	case d > 1:
		return nil, errors.New("handover import: bad done flag")
	default:
		r.Done = d == 1
	}
	reserved := c.u32()
	r.Imported = c.u32()
	if err := c.done(); err != nil {
		return nil, err
	}
	if reserved != 0 {
		return nil, errors.New("handover import: the reserved count is not zero")
	}
	return r, nil
}
