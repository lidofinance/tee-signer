package handoverorder

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// TypeOrder is HANDOVER_ORDER: the signed order in, its State out. Any
// client with a client certificate may send it; the approvers' signatures
// carry the authority. Pushing it again does no harm and reads the state.
// It must equal handover.TypeOrder (tee-signer/handover, which this
// module cannot import); TestTypeOrderMatchesHandoverOrder there checks
// that.
const TypeOrder wire.MsgType = 0x31

// Outcomes of HANDOVER_ORDER.
const (
	Accepted uint8 = 1 // new on this runner
	Known    uint8 = 2 // the runner holds it already; its arrival stays
)

// Status is where an order stands on its source runner.
type Status uint8

const (
	// Pending: it waits out its time from the arrival.
	Pending Status = 1
	// Active: HANDOVER to its target may start.
	Active Status = 2
	// Expired: past not_after, and no handover started under it.
	Expired Status = 3
	// Void: its signatures do not verify under the approver set in force,
	// or its target image left the allowed list.
	Void Status = 4
	// Done: the source wrote the tombstone that names its target; the
	// source answers HANDOVER to that target only, for good.
	Done Status = 5
)

func (s Status) String() string {
	switch s {
	case Pending:
		return "pending"
	case Active:
		return "active"
	case Expired:
		return "expired"
	case Void:
		return "void"
	case Done:
		return "done"
	}
	return fmt.Sprintf("status %d", s)
}

// State is the HANDOVER_ORDER answer.
type State struct {
	Outcome  uint8
	Status   Status
	Hash     [32]byte
	Arrived  uint64 // Unix seconds, on the runner's trusted clock
	ActAt    uint64 // arrival plus the wait
	NotAfter uint64
	// Why says what makes the order void, or is empty.
	Why string
}

// StateLen is the length of an encoded State without Why.
const StateLen = 1 + 1 + 32 + 8 + 8 + 8 + 2

// MaxWhy bounds the reason text.
const MaxWhy = 512

// Encode: outcome:u8 status:u8 hash[32] arrived:u64 act_at:u64
// not_after:u64 why_len:u16 why.
func (s *State) Encode() []byte {
	why := s.Why
	if len(why) > MaxWhy {
		why = why[:MaxWhy]
	}
	b := make([]byte, 0, StateLen+len(why))
	b = append(b, s.Outcome, byte(s.Status))
	b = append(b, s.Hash[:]...)
	b = binary.BigEndian.AppendUint64(b, s.Arrived)
	b = binary.BigEndian.AppendUint64(b, s.ActAt)
	b = binary.BigEndian.AppendUint64(b, s.NotAfter)
	b = binary.BigEndian.AppendUint16(b, uint16(len(why)))
	return append(b, why...)
}

// DecodeState reads an encoded State strictly.
func DecodeState(b []byte) (*State, error) {
	if len(b) < StateLen {
		return nil, errShort
	}
	s := &State{Outcome: b[0], Status: Status(b[1])}
	copy(s.Hash[:], b[2:34])
	s.Arrived = binary.BigEndian.Uint64(b[34:])
	s.ActAt = binary.BigEndian.Uint64(b[42:])
	s.NotAfter = binary.BigEndian.Uint64(b[50:])
	n := int(binary.BigEndian.Uint16(b[58:]))
	if n > MaxWhy || len(b) != StateLen+n {
		return nil, errors.New("handoverorder: state of the wrong length")
	}
	s.Why = string(b[StateLen:])
	if s.Outcome != Accepted && s.Outcome != Known || s.Status < Pending || s.Status > Done {
		return nil, errors.New("handoverorder: state with an unknown outcome or status")
	}
	return s, nil
}

func hexOf(b []byte) string { return "0x" + hex.EncodeToString(b) }

func unixNote(t uint64) string {
	if t > 253402300799 {
		return "far future"
	}
	return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
}

func formatBody(w *strings.Builder, b *Body) {
	kv := func(k string, v any) { fmt.Fprintf(w, "%s = %v\n", k, v) }
	note := func(format string, args ...any) { fmt.Fprintf(w, "# %s\n", fmt.Sprintf(format, args...)) }
	note("Handover order (setup-phase.md, section 10). Approvers sign the binary form.")
	note("The source hands its shares to the target only, at least the images minimum time lock after it arrives.")
	kv("cluster_id", hexOf(b.ClusterID[:]))
	kv("chain_hash", hexOf(b.ChainHash[:]))
	note("not_after %s: no handover starts under the order from then on", unixNote(b.NotAfter))
	kv("not_after", b.NotAfter)
	for _, r := range []struct {
		pre, note string
		r         *Runner
	}{{"source.", "the runner that holds the shares now", &b.Source}, {"target.", "the runner the shares go to; its image must be on the source's allowed list", &b.Target}} {
		w.WriteString("\n")
		note("%s", r.note)
		kv(r.pre+"name", r.r.Name)
		kv(r.pre+"setup_sha256", hexOf(r.r.SetupHash[:]))
		w.WriteString(FormatSettings(r.pre, r.r))
	}
}

// Format checks the body and writes its human form.
func (b *Body) Format() ([]byte, error) {
	if err := b.Check(); err != nil {
		return nil, err
	}
	var w strings.Builder
	formatBody(&w, b)
	return []byte(w.String()), nil
}

// Format checks the signed order and writes its human form.
func (o *Order) Format() ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	var w strings.Builder
	formatBody(&w, &o.Body)
	w.WriteString("\n# signatures over signer-handover-order-v1 and the body, by position\n")
	for _, a := range o.Approvals {
		fmt.Fprintf(&w, "approver_signature = %d %s\n", a.Position, hexOf(a.Signature[:]))
	}
	return []byte(w.String()), nil
}
