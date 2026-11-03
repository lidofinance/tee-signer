// Package handover is the handover between two runners with a setup:
// HANDOVER under an approver-signed order (message.go), the target's
// IMPORT_HANDOVER (import.go) and the source's carried state (carry.go).
package handover

import (
	"encoding/binary"
	"errors"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// TypeOrder is the message type of HANDOVER_ORDER, whose codec is
// governance/handoverorder (handoverorder.TypeOrder names the same value;
// that package does not import this one, and
// TestTypeOrderMatchesHandoverOrder keeps the two equal).
const TypeOrder wire.MsgType = 0x31

// MaxPerResponse bounds the shares of one response (about 1.3 KB each).
const MaxPerResponse = 256

var errShort = errors.New("handover: short message")

// markLen is the size of a mark on the wire: has_block, block_slot,
// has_attestation, source_epoch, target_epoch.
const markLen = 1 + 8 + 1 + 8 + 8

func appendMark(p []byte, wm backend.Watermark) []byte {
	b := func(v bool) byte {
		if v {
			return 1
		}
		return 0
	}
	p = append(p, b(wm.HasBlock))
	p = binary.BigEndian.AppendUint64(p, wm.BlockSlot)
	p = append(p, b(wm.HasAttestation))
	p = binary.BigEndian.AppendUint64(p, wm.SourceEpoch)
	return binary.BigEndian.AppendUint64(p, wm.TargetEpoch)
}
