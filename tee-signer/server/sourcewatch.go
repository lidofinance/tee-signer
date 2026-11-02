package server

import (
	"fmt"
	"sync"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// sourceWatch is the device source alarm. With one mark for every key
// (core.Config.DeviceMark) the source bound is the highest source signed
// by any key, and a restart applies it to every key. A vote whose source is
// above what the chain justified (a signing client can send one) therefore
// stops the honest votes of every other key after a restart, until the
// chain justifies that epoch. Nothing shows it before the restart, since
// the RAM rules are per key.
//
// The rule: a signed vote with target T and source S raises the alarm when
// this runner signed a vote with target T-1 and S is more than one epoch
// above the highest source of those votes. An honest chain moves the
// source by at most one epoch per epoch while it finalizes, and keeps it
// while it does not. The end of a long non-finality period can move it
// further at once; the alarm then fires too, and the operator checks that
// the chain justified epoch S.
//
// The alarm logs at error level and shows in HEALTH as
// device_source_alarm until the runner restarts. A new alarm replaces it
// only with a higher source, so a flood of such votes logs once per new
// source.
type sourceWatch struct {
	mu sync.Mutex
	// highest is the highest source signed per target epoch, for the
	// newest targets only (keepTargets).
	highest map[uint64]uint64
	newest  uint64
	alarm   string
	alarmAt uint64 // the source of the alarm in force
}

// keepTargets is how many target epochs below the newest one the watch
// keeps. Late votes for older targets still arrive; four epochs covers
// them.
const keepTargets = 4

// note records a signed vote and returns the alarm text when this vote
// raises a new alarm, "" otherwise.
func (w *sourceWatch) note(pk backend.Pubkey, source, target uint64) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.highest == nil {
		w.highest = map[uint64]uint64{}
	}
	var alarm string
	if target > 0 {
		if prev, ok := w.highest[target-1]; ok && source > prev+1 && source > w.alarmAt {
			w.alarm = fmt.Sprintf("vote of key %s with source %d (target %d) is %d epochs above source %d of the votes for target %d: "+
				"after a restart every key refuses votes with a source below %d until the chain justifies it",
				pk.String()[:18], source, target, source-prev, prev, target-1, source)
			w.alarmAt = source
			alarm = w.alarm
		}
	}
	if s, ok := w.highest[target]; !ok || source > s {
		w.highest[target] = source
	}
	if target > w.newest {
		w.newest = target
		for t := range w.highest {
			if t+keepTargets < w.newest {
				delete(w.highest, t)
			}
		}
	}
	return alarm
}

// status is the alarm in force, "" without one.
func (w *sourceWatch) status() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.alarm
}
