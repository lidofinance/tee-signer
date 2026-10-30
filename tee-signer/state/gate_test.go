package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// gateLog is a MarkLog that holds only what the source gate reads and
// sets.
type gateLog struct {
	gate   *uint64
	raised []backend.Watermark
}

func (l *gateLog) Append(context.Context, backend.Watermark) error { return nil }
func (l *gateLog) Raise(_ context.Context, wm backend.Watermark) error {
	l.raised = append(l.raised, wm)
	return nil
}
func (l *gateLog) HandOver(context.Context) (backend.Watermark, error) {
	return backend.Watermark{}, nil
}
func (l *gateLog) HandedOver() (backend.Watermark, bool) { return backend.Watermark{}, false }
func (l *gateLog) HandOverTo(context.Context, [32]byte) (backend.Watermark, error) {
	return backend.Watermark{}, nil
}
func (l *gateLog) HandedOverTo() ([32]byte, bool)                        { return [32]byte{}, false }
func (l *gateLog) Exits() *markstore.ExitDay                             { return nil }
func (l *gateLog) RecordExits(context.Context, *markstore.ExitDay) error { return nil }
func (l *gateLog) Lost() error                                           { return nil }
func (l *gateLog) Status() string                                        { return "gate log" }
func (l *gateLog) SourceGate() (uint64, bool) {
	if l.gate == nil {
		return 0, false
	}
	return *l.gate, true
}
func (l *gateLog) ShareSet() *markstore.ShareSet                             { return nil }
func (l *gateLog) SetShareSet(*markstore.ShareSet)                           {}
func (l *gateLog) RecordShareSet(context.Context, *markstore.ShareSet) error { return nil }
func (l *gateLog) SetSourceGate(f uint64, on bool) {
	l.gate = nil
	if on {
		l.gate = &f
	}
}

// The source gate as a restart decides it from the claimed log: the gate a
// record carries until the log's source reaches its floor, and a new gate
// for a log without a vote (RBRLOG-02).
func TestSourceGateAtRestart(t *testing.T) {
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.DeviceMark = true
	margin := DefaultFloorMargin(cfg)
	const epoch = 50
	fresh := epoch + margin
	ten := uint64(10)
	att := func(source uint64) backend.Watermark {
		return backend.Watermark{HasAttestation: true, SourceEpoch: source, TargetEpoch: 40, HasBlock: true, BlockSlot: 40 * 32}
	}
	for _, c := range []struct {
		name     string
		gate     *uint64
		mark     backend.Watermark
		on       bool
		floor    uint64
		recorded bool // the next record carries a gate
	}{
		{"no vote in the log: a new gate", nil, backend.Watermark{}, true, fresh, true},
		{"cover write only, gate in the record: kept", &ten, att(0), true, 10, true},
		{"vote below the gate's floor: kept", &ten, att(9), true, 10, true},
		{"vote at the gate's floor: dropped", &ten, att(10), false, 0, false},
		{"vote, no gate: none", nil, att(0), false, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			clk := &fakeClock{t: at(epoch, 5)}
			h, err := New(cfg, Mode{Floor: true, FloorMargin: margin, MarkLog: true}, clk, nil, nil, quiet)
			if err != nil {
				t.Fatal(err)
			}
			l := &gateLog{gate: c.gate}
			h.UseMarkLog(l, c.mark, c.mark.HasAttestation)
			if _, _, err := h.LoadDeviceMark(); err != nil {
				t.Fatal(err)
			}
			var pk backend.Pubkey
			f, on := h.SourceFloor(pk)
			if on != c.on || on && f != c.floor {
				t.Errorf("gate %v at %d, want %v at %d", on, f, c.on, c.floor)
			}
			if _, rec := l.SourceGate(); rec != c.recorded {
				t.Errorf("next record carries a gate: %v, want %v", rec, c.recorded)
			}
			h.NoteHistory(pk)
			if _, on := h.SourceFloor(pk); on {
				t.Error("a key with its own history is still gated")
			}
		})
	}
}

// The gate is set before an import's raise, so the raise's record carries
// it: a restart right after the raise must not read the raised source as
// history of every validator.
func TestSourceGateBeforeTheFirstRaise(t *testing.T) {
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.DeviceMark = true
	clk := &fakeClock{t: at(50, 5)}
	h, err := New(cfg, Mode{Floor: true, FloorMargin: DefaultFloorMargin(cfg), MarkLog: true}, clk, nil, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	l := &gateLog{}
	h.UseMarkLog(l, backend.Watermark{}, false)
	if err := h.RaiseMark(context.Background(), backend.Watermark{HasAttestation: true, SourceEpoch: 45, TargetEpoch: 46}); err != nil {
		t.Fatal(err)
	}
	if f, on := l.SourceGate(); !on || f != 50+DefaultFloorMargin(cfg) {
		t.Errorf("gate at the raise: %d %v", f, on)
	}
}

// errClock fails every reading.
type errClock struct{}

func (errClock) Now() (time.Time, error) { return time.Time{}, errors.New("no clock") }
func (errClock) Source() string          { return "broken" }
func (errClock) Trusted() bool           { return false }

// ImportFloor is on only with the restart floor and a mark log in use, and
// fails closed when the clock cannot be read.
func TestImportFloorModes(t *testing.T) {
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.DeviceMark = true
	margin := DefaultFloorMargin(cfg)
	ok := &fakeClock{t: at(50, 5)}
	for _, c := range []struct {
		name    string
		mode    Mode
		clock   platform.Clock
		useLog  bool
		on      bool
		wantErr bool
	}{
		{"floor and mark log: on", Mode{Floor: true, FloorMargin: margin, MarkLog: true}, ok, true, true, false},
		{"no restart floor: off", Mode{MarkLog: true}, ok, true, false, false},
		{"no mark log mode: off", Mode{Floor: true, FloorMargin: margin}, ok, true, false, false},
		{"mark log not in use yet: off", Mode{Floor: true, FloorMargin: margin, MarkLog: true}, ok, false, false, false},
		{"clock error", Mode{Floor: true, FloorMargin: margin, MarkLog: true}, errClock{}, true, false, true},
		{"clock before 1970", Mode{Floor: true, FloorMargin: margin, MarkLog: true}, &fakeClock{t: time.Unix(-1, 0)}, true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, err := New(cfg, c.mode, c.clock, nil, nil, quiet)
			if err != nil {
				t.Fatal(err)
			}
			if c.useLog {
				h.UseMarkLog(&gateLog{}, backend.Watermark{}, false)
			}
			f, on, err := h.ImportFloor()
			if (err != nil) != c.wantErr {
				t.Fatalf("error %v, want one: %v", err, c.wantErr)
			}
			if on != c.on || on && f != 50+margin {
				t.Errorf("floor %v at %d, want %v at %d", on, f, c.on, 50+margin)
			}
		})
	}
}
