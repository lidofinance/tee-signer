package backend

import (
	"encoding/binary"
	"errors"
)

// WatermarkEncodedLen is the length of an SCW1 storage record.
const WatermarkEncodedLen = 32

// EncodeWatermark encodes the fixed storage format used by the C signer.
func EncodeWatermark(w Watermark) []byte {
	b := make([]byte, WatermarkEncodedLen)
	copy(b, "SCW1")
	if w.HasBlock {
		b[4] |= 1
	}
	if w.HasAttestation {
		b[4] |= 2
	}
	binary.LittleEndian.PutUint64(b[8:16], w.BlockSlot)
	binary.LittleEndian.PutUint64(b[16:24], w.SourceEpoch)
	binary.LittleEndian.PutUint64(b[24:32], w.TargetEpoch)
	return b
}

// DecodeWatermark rejects records with an unknown format, flags or reserved bytes.
func DecodeWatermark(b []byte) (Watermark, error) {
	if len(b) != WatermarkEncodedLen || string(b[:4]) != "SCW1" ||
		b[4]&^byte(3) != 0 || b[5] != 0 || b[6] != 0 || b[7] != 0 {
		return Watermark{}, errors.New("protocol: invalid watermark record")
	}
	return Watermark{
		BlockSlot:      binary.LittleEndian.Uint64(b[8:16]),
		SourceEpoch:    binary.LittleEndian.Uint64(b[16:24]),
		TargetEpoch:    binary.LittleEndian.Uint64(b[24:32]),
		HasBlock:       b[4]&1 != 0,
		HasAttestation: b[4]&2 != 0,
	}, nil
}
