package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

// The time values of the config groups: time_servers of the open group and
// time_policy of the locked group. The NTS clock starts with the setup's
// (version 0 of each group), since the clock is needed before the mark log
// can be read. StartConfig then switches it once to the values in force,
// and after that each update that comes into force switches it again: a
// time_servers update through NTS.SetServers, a time_policy update through
// NTS.SetPolicy. Accept refuses a time_servers list the clock would refuse,
// so an update comes into force only with a list the clock takes. If the
// clock still refuses values in force (an image whose catalog withdrew an
// entry), the runner signs nothing until values it takes are in force, and
// keeps taking config updates meanwhile.

// TimeSink is the runner's clock as the config updates drive it: the NTS
// clock of a runner built with -tags nts. nil: the clock takes no time
// values (another clock, or the NTS clock off).
type TimeSink interface {
	// SetServers dials the image's default set plus the catalog entries
	// specs names (time_servers).
	SetServers(specs []string) error
	// SetPolicy sets the protocol and the bounds (time_policy).
	SetPolicy(p setupwire.TimePolicy) error
}

// MinTimeServers is the fewest servers the clock runs on, the image's
// default set and time_servers together. At least 3 fresh samples must
// agree, so with 3 servers one slow server would stop signing.
const MinTimeServers = 4

// CheckTimeServers refuses a time_servers list that names an entry the
// image's catalog does not have, has withdrawn or cannot route (an alt host
// without a Nitro port), or that leaves fewer than MinTimeServers servers
// with the default set (trusted-time/ntscatalog, WithConfirmed).
func CheckTimeServers(specs []string) error {
	eps, err := ntscatalog.Builtin.WithConfirmed(specs)
	if err != nil {
		return fmt.Errorf("time_servers: %w", err)
	}
	if len(eps) < MinTimeServers {
		return fmt.Errorf("time_servers: %d servers with the image's default set, at least %d", len(eps), MinTimeServers)
	}
	return nil
}

// applyTimeLocked gives the clock the time values in force, if they differ
// from those it runs on. Call it with writeMu held. The clock calls run
// outside mu: a swap waits for a Refresh in flight, up to about 10 s, and
// signing must not wait for it.
func (u *Updates) applyTimeLocked() {
	sink := u.opt.Time
	if sink == nil {
		return
	}
	u.mu.Lock()
	var servers []string
	var policy *setupwire.TimePolicy
	var sv, pv uint64
	if o := u.view.open; o != nil && !slices.Equal(o.TimeServers, u.clockServers) {
		servers, sv = slices.Clone(o.TimeServers), u.view.state.Open.Version
		if servers == nil {
			servers = []string{}
		}
	}
	if l := u.view.locked; l != nil && l.TimePolicy != u.clockPolicy {
		p := l.TimePolicy
		policy, pv = &p, u.view.state.Locked.Version
	}
	u.mu.Unlock()
	var errs []error
	if servers != nil {
		if err := sink.SetServers(servers); err != nil {
			errs = append(errs, fmt.Errorf("the clock refused time_servers %v of open version %d: %w", servers, sv, err))
		} else {
			u.clockServers = servers
			u.opt.Logger.Info("config: time_servers in force", "open_version", sv, "servers", servers)
		}
	}
	if policy != nil {
		if err := sink.SetPolicy(*policy); err != nil {
			errs = append(errs, fmt.Errorf("the clock refused time_policy of locked version %d: %w", pv, err))
		} else {
			level, msg := slog.LevelInfo, "config: time_policy in force"
			if policy.Protocol != u.clockPolicy.Protocol {
				level, msg = slog.LevelWarn, "config: time_policy in force with another protocol; the clock gives no time until a quorum forms on it"
			}
			u.clockPolicy = *policy
			u.opt.Logger.Log(context.Background(), level, msg, "locked_version", pv, "protocol", policy.Protocol.String(),
				"max_bound_ms", policy.MaxBoundMs, "max_sample_bound_ms", policy.MaxSampleBoundMs)
		}
	}
	err := errors.Join(errs...)
	u.mu.Lock()
	changed := fmt.Sprint(err) != fmt.Sprint(u.timeErr)
	u.timeErr = err
	u.mu.Unlock()
	if err != nil && changed {
		u.opt.Logger.Error("config: "+err.Error()+"; nothing is signed until time values the clock takes are in force", "err", err)
	}
}

// applyTime is applyTimeLocked with writeMu taken.
func (u *Updates) applyTime() {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	u.applyTimeLocked()
}

// notePathsLocked records, for HEALTH and the log, how an update that came
// into force in the view got there, when Accept took it in this run.
func (u *Updates) notePathsLocked() {
	for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
		gs, _ := u.view.state.Group(g)
		r := refOf(*gs)
		if u.seen[g] == r {
			continue
		}
		u.seen[g] = r
		p, ok := u.paths[bodyID{g, r}]
		if !ok {
			continue
		}
		u.lastPath = &backend.UpdatePath{Group: g.String(), Version: r.version, Path: p.String()}
		if p != setupwire.PathNormal {
			u.opt.Logger.Warn("config: update in force by "+p.String()+", with no change delay", "group", g.String(), "version", r.version,
				"hash", fmt.Sprintf("%x", r.hash[:8]))
		}
	}
}

// lastUpdatePath is HEALTH's last_update_path.
func (u *Updates) lastUpdatePath() *backend.UpdatePath {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.lastPath == nil {
		return nil
	}
	p := *u.lastPath
	return &p
}
