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
// signatures need no time to check. Effective times and the records are
// not read here, so these values can be ahead of those in force (a pending
// update); StartConfig switches the clock to the values really in force,
// and nothing is signed before it has.

// logTimeValuesWait bounds the reads of logTimeValues.
const logTimeValuesWait = time.Minute

// logTimeValues opens the mark log's store of spec and returns
// signedTimeValues of its update bodies.
func logTimeValues(ctx context.Context, p *platform.Platform, platformName, spec string, st *setup.Setup, log *slog.Logger) (*platform.TimeValues, error) {
	l, err := markstore.Open(spec, markLogEnv(p, platformName, st))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, logTimeValuesWait)
	defer cancel()
	return signedTimeValues(ctx, l, st.Wire, st.SHA256, log)
}

// signedTimeValues follows each config group from the setup's version 0
// along the update bodies in l: the next update is the highest version
// whose prev_hash is the hash of the current one and whose signatures
// verify against the approvers of the current locked values (for an open
// update: of any locked values on the chain). It returns the time values
// at the end of both chains, or nil when neither changes them. A body that
// does not decode, is for another setup or does not verify is skipped.
func signedTimeValues(ctx context.Context, l markstore.Log, s *setupwire.Setup, hash [32]byte, log *slog.Logger) (*platform.TimeValues, error) {
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
	// one of sets verifies, and its hash.
	next := func(g setupwire.Group, v uint64, prev [32]byte, sets []*setupwire.ApproverSet) (*setupwire.Update, [32]byte) {
		var best *setupwire.Update
		var bestHash [32]byte
		for _, u := range bodies[g] {
			b := &u.Body
			if b.Version <= v || b.PrevHash != prev || (best != nil && b.Version <= best.Body.Version) {
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
		u, h := next(setupwire.GroupLocked, lv, lh, sets[len(sets)-1:])
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
		u, h := next(setupwire.GroupOpen, ov, oh, sets)
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

// timePolicyOf is the setupwire form of v's protocol and bounds.
func timePolicyOf(v *platform.TimeValues) setupwire.TimePolicy {
	p := setupwire.TimePolicy{Protocol: setupwire.ClockNTS, MaxBoundMs: uint16(v.MaxBound / time.Millisecond),
		MaxSampleBoundMs: uint16(v.MaxSampleBound / time.Millisecond)}
	if v.Protocol == "ntp" {
		p.Protocol = setupwire.ClockNTP
	}
	return p
}
