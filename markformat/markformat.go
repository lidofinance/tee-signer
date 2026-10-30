// Package markformat binds the portable C codec for SCW1 watermark records.
package markformat

/*
#include "markformat.h"
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// WatermarkEncodedLen is the length of the fixed SCW1 storage record.
const WatermarkEncodedLen = C.MARKFORMAT_ENCODED_LEN

// EncodeWatermark uses the shared C codec to encode a durable watermark.
func EncodeWatermark(w backend.Watermark) []byte {
	cw := C.markformat_watermark{block_slot: C.uint64_t(w.BlockSlot), source_epoch: C.uint64_t(w.SourceEpoch), target_epoch: C.uint64_t(w.TargetEpoch)}
	if w.HasBlock {
		cw.flags |= C.MARKFORMAT_HAS_BLOCK
	}
	if w.HasAttestation {
		cw.flags |= C.MARKFORMAT_HAS_ATTESTATION
	}
	out := make([]byte, WatermarkEncodedLen)
	C.markformat_encode(&cw, (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// DecodeWatermark checks the record header and decodes its counter values.
func DecodeWatermark(b []byte) (backend.Watermark, error) {
	var cw C.markformat_watermark
	var p *C.uint8_t
	if len(b) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&b[0]))
	}
	if C.markformat_decode(p, C.size_t(len(b)), &cw) != C.MARKFORMAT_OK {
		return backend.Watermark{}, errors.New("markformat: invalid watermark record")
	}
	return backend.Watermark{BlockSlot: uint64(cw.block_slot), SourceEpoch: uint64(cw.source_epoch), TargetEpoch: uint64(cw.target_epoch), HasBlock: cw.flags&C.MARKFORMAT_HAS_BLOCK != 0, HasAttestation: cw.flags&C.MARKFORMAT_HAS_ATTESTATION != 0}, nil
}
