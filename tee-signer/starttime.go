package main

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// The NTS clock starts on the setup's time values, since the config log
// that says which updates are in force is read only after the clock has a
// quorum. A setup whose time_policy or time_servers were loosened by an
// update (NTS to NTP, higher bounds, more servers) may get no quorum on
// version 0. The clock then tries once more on logTimeValues: the newest
// values that a chain of signed updates from the setup reaches, read from
// the config log's update bodies before the mark log is claimed. The
// signatures need no time to check. The records are not read here: an
// update counts only once the coarse clock's time (the HTTPS-date quorum)
// has passed its activate_at plus its wait, the wait its signatures allow
// (setupwire Decide, without the history the records hold). So a pending
// update in its change delay, an NTS to NTP one say, does not run the
// clock early, which would let a host that blocks NTS-KE at a restart get
// the weaker values before they are in force (rv-pb4.1). An update whose
// activate_at lies before its arrival can still count up to that much
// early, as the arrival time is in the records only. StartConfig switches
// the clock to the values really in force, and nothing is signed before
// it has.

// logTimeValuesWait bounds the reads of logTimeValues.
const logTimeValuesWait = time.Minute

// logTimeValues opens the mark log's store of spec and returns
// signedTimeValues of its update bodies.
func logTimeValues(ctx context.Context, p *platform.Platform, platformName, spec string, st *setup.Setup, now time.Time, log *slog.Logger) (*platform.TimeValues, error) {
	l, err := markstore.Open(spec, markLogEnv(p, platformName, st))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, logTimeValuesWait)
	defer cancel()
	return signedTimeValues(ctx, l, st.Wire, st.SHA256, unixSeconds(now), log)
}

// signedTimeValues follows each config group from the setup's version 0
// along the update bodies in l: the next update is the highest version
// whose prev_hash is the hash of the current one and whose signatures
// verify against the approvers of the current locked values (for an open
// update: of the last locked values of the chain, so an open chain signed
// by a set a rotation replaced stops where that set signed), and that is
// in force by now
// (inForceBy). It returns the time values at the end of both chains, or
// nil when neither changes them. A body that does not decode, is for
// another setup or does not verify is skipped.
func signedTimeValues(ctx context.Context, l markstore.Log, s *setupwire.Setup, hash [32]byte, now uint64, log *slog.Logger) (*platform.TimeValues, error) {
	bodies := map[setupwire.Group][]*setupwire.Update{}
	for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
		prefix := path.Dir(strings.TrimSuffix(markstore.BodyPrefix(hash, g, 0), "/")) + "/"
		es, err := l.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("config log: list %s: %w", prefix, err)
		}
		for _, e := range es {
			raw, err := l.Get(ctx, e)
			if err != nil {
				continue
			}
			u, err := setupwire.DecodeUpdate(raw)
			if err != nil || u.Body.Group != g || u.Body.Matches(s) != nil {
				continue
			}
			bodies[g] = append(bodies[g], u)
		}
	}
	// next is the highest version after version v with prev_hash prev that
	// one of sets verifies and that is in force by now under the locked
	// values cur, and its hash.
	next := func(g setupwire.Group, v uint64, prev [32]byte, sets []*setupwire.ApproverSet, cur *setupwire.Locked) (*setupwire.Update, [32]byte) {
		var best *setupwire.Update
		var bestHash [32]byte
		for _, u := range bodies[g] {
			b := &u.Body
			if b.Version <= v || b.PrevHash != prev || (best != nil && b.Version <= best.Body.Version) || !inForceBy(u, &s.Chain, cur, now) {
				continue
			}
			h, err := b.Hash()
			if err != nil {
				continue
			}
			for _, set := range sets {
				if u.Verify(set) == nil {
					best, bestHash = u, h
					break
				}
			}
		}
		return best, bestHash
	}
	locked, open := &s.Locked, &s.Open
	var lv, ov uint64
	lh, err := s.GroupHash(setupwire.GroupLocked)
	if err != nil {
		return nil, err
	}
	sets := []*setupwire.ApproverSet{&s.Locked.Approvers}
	for {
		u, h := next(setupwire.GroupLocked, lv, lh, sets[len(sets)-1:], locked)
		if u == nil {
			break
		}
		locked, lv, lh = u.Body.Locked, u.Body.Version, h
		sets = append(sets, &locked.Approvers)
	}
	oh, err := s.GroupHash(setupwire.GroupOpen)
	if err != nil {
		return nil, err
	}
	for {
		// Only the last approver set: a rotation replaced the ones before,
		// maybe because their keys leaked.
		u, h := next(setupwire.GroupOpen, ov, oh, sets[len(sets)-1:], locked)
		if u == nil {
			break
		}
		open, ov, oh = u.Body.Open, u.Body.Version, h
	}
	if locked.TimePolicy == s.Locked.TimePolicy && slices.Equal(open.TimeServers, s.Open.TimeServers) {
		return nil, nil
	}
	v := timeValuesOf(locked.TimePolicy, open.TimeServers)
	v.From = fmt.Sprintf("the config log (signed locked version %d, open version %d)", lv, ov)
	if log != nil {
		log.Info("config log: newest signed time values", "from", v.From, "protocol", v.Protocol, "max_bound", v.MaxBound,
			"max_sample_bound", v.MaxSampleBound, "servers", strings.Join(v.Servers, ","))
	}
	return v, nil
}

// inForceBy reports whether update u, under the locked values cur, is in
// force by now at the latest: its activate_at plus the wait its signatures
// allow (Decide; Wait when Decide refuses it) has passed. Arrival plus the
// wait may be later; the records hold the arrival, and they are not read
// before the clock runs.
func inForceBy(u *setupwire.Update, c *setupwire.Chain, cur *setupwire.Locked, now uint64) bool {
	var w uint64
	if u.Body.Group == setupwire.GroupLocked {
		w = setupwire.Wait(c, cur, &u.Body)
		if d, err := u.Decide(c, cur, nil, setupwire.History{Now: now}); err == nil {
			w = d.Wait
		}
	}
	return setupwire.SatAdd(u.Body.ActivateAt, w) <= now
}

// unixSeconds is t in unix seconds, 0 before 1970.
func unixSeconds(t time.Time) uint64 { return uint64(max(t.Unix(), 0)) }

// timePolicyOf is the setupwire form of v's protocol and bounds.
func timePolicyOf(v *platform.TimeValues) setupwire.TimePolicy {
	p := setupwire.TimePolicy{Protocol: setupwire.ClockNTS, MaxBoundMs: uint16(v.MaxBound / time.Millisecond),
		MaxSampleBoundMs: uint16(v.MaxSampleBound / time.Millisecond)}
	if v.Protocol == "ntp" {
		p.Protocol = setupwire.ClockNTP
	}
	return p
}
