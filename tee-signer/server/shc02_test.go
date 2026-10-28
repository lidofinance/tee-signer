//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// SHC-02: a handover import, ImportAsImported included, takes the page's
// mark and each share's maxima only within the clock horizon, and never the
// tombstone. Before, a far-future mark raised the locked log and stopped
// the runner until real time passed it. The refusal comes before any
// write: the log keeps its mark and no import slot is set.
func TestSHC02HandoverMarkAboveTheHorizonRefused(t *testing.T) {
	far := backend.Watermark{HasAttestation: true, SourceEpoch: startEpoch + 500, TargetEpoch: startEpoch + 501,
		HasBlock: true, BlockSlot: (startEpoch+501)*8 + 7}
	for name, mark := range map[string]backend.Watermark{"far future": far, "tombstone": markstore.Tombstone} {
		t.Run(name, func(t *testing.T) {
			e := newTgtEnv(t, "dev", nil)
			before, v := e.marks.Mark()
			src := newSource(t, 0, 2, [][32]byte{{0xd1}}, mark)
			order, hash := e.order([]byte{1, 2}, nil)
			page := src.pages(e.sealTo(), hash, 8)[0]
			if _, err := e.imp(order, page, handover.ImportAsImported); err == nil {
				t.Fatal("the import took the mark")
			} else if backend.StatusOf(err) != backend.StatusBadRequest {
				t.Logf("refused: %v", err)
			}
			if after, v2 := e.marks.Mark(); after != before || v2 != v {
				t.Errorf("the log went from %+v (version %d) to %+v (version %d)", before, v, after, v2)
			}
			if o := e.srv.importing(); o != nil {
				t.Errorf("an import slot is set: %x", o.Hash[:8])
			}
		})
	}
}
