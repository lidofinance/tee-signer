//go:build nts

package nts

import (
	"context"
	"errors"
	"fmt"
	"time"

	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
)

// Config is what a Client is made of. The servers and their roots are the
// core's configuration and must come by a trusted path (the image, the
// sealed setup). Durations left zero take the defaults of clock.NTS.
type Config struct {
	Servers          []Server
	Interval         time.Duration // between two queries to one server
	MinPoll          time.Duration // the shortest poll interval
	MaxPoll          time.Duration // the longest, after Kiss-o'-Death backoff
	MaxBound         time.Duration // Bounded refuses over it
	MaxAge           time.Duration // Bounded refuses once the quorum's oldest sample is older
	JoinAge          time.Duration // the oldest a sample may be to enter a quorum; 0: MaxAge
	MaxCoarseDiff    time.Duration // a quorum further from the coarse time is refused
	CoarseResolution time.Duration // of the coarse readings
	ExchangeTimeout  time.Duration // 0: ExchangeTimeout
	// Protocol is NTS or plain NTP (unauthenticated). MaxSampleBound caps
	// one sample's bound (0: MaxBound). QueryTimeout bounds one NTP query
	// (0: the shorter of ExchangeTimeout and Interval / 2). StartWait is
	// how long the start state lasts after SetServers or SetPolicy left no
	// quorum (0: no start state then). Capacity is the most servers
	// SetServers may set later (0: len(Servers)). All of it is the core's
	// configuration, like the servers.
	Protocol       Protocol
	MaxSampleBound time.Duration
	QueryTimeout   time.Duration
	StartWait      time.Duration
	Capacity       int
	// ResolveNTP looks the NTP host up once per key exchange (with plain
	// NTP once, until ForgetAddr), an IPv4 address first, and dials that
	// address for every query after it, so a short QueryTimeout does not
	// include a DNS lookup. For the default dialer: a platform dialer (the
	// Nitro UDP relay) resolves on its side.
	ResolveNTP bool
	// Warn, if set, gets what the host operations have to say (a name
	// that did not resolve).
	Warn func(msg string, args ...any)
	// Dial opens the connections. Nil: net.Dialer.
	Dial DialFunc
	// Local is the monotonic clock in ns. Nil: Monotonic. A test moves it
	// ahead to age the bound.
	Local func() int64
	// Ops replaces the host operations of this package (then Dial, Local,
	// ResolveNTP and Warn are unused): tests pass a virtual world
	// (ntstest.World). If it has a SetContext(peer, ctx) method, Poll
	// calls it like the real operations' own.
	Ops ntscore.HostOps
}

// contexter is the part of the host operations that binds a peer's
// operations to the context of its poll.
type contexter interface {
	SetContext(peer int, ctx context.Context)
}

// Client is the NTS client: the C core of ntscore with the host operations
// of this package. clock.NTS drives it: Due, Poll per due server, Combine,
// then Bounded for the time.
type Client struct {
	core  *ntscore.Core
	ops   ntscore.HostOps
	ctxs  contexter // nil if the operations take no context
	hooks *hooks    // nil with Config.Ops
}

// NewClient allocates the core. Close frees it.
func NewClient(cfg Config) (*Client, error) {
	c := &Client{ops: cfg.Ops}
	if cfg.Ops == nil {
		c.hooks = newHooks(cfg.Dial, cfg.Local)
		c.hooks.resolve, c.hooks.warn = cfg.ResolveNTP, cfg.Warn
		c.ops = c.hooks
	}
	c.ctxs, _ = c.ops.(contexter)
	core, err := ntscore.New(ntscore.Config{
		Servers: cfg.Servers, Interval: cfg.Interval, MinPoll: cfg.MinPoll, MaxPoll: cfg.MaxPoll, MaxBound: cfg.MaxBound, MaxAge: cfg.MaxAge,
		JoinAge: cfg.JoinAge, MaxCoarseDiff: cfg.MaxCoarseDiff, CoarseResolution: cfg.CoarseResolution,
		ExchangeTimeout: cmpOr(cfg.ExchangeTimeout, ExchangeTimeout), KissGrace: KissGrace,
		DriftBaselinePolls: DriftBaselinePolls, FloorUnix: FloorTime,
		Protocol: cfg.Protocol, MaxSampleBound: cfg.MaxSampleBound, QueryTimeout: cfg.QueryTimeout, StartWait: cfg.StartWait, Capacity: cfg.Capacity,
	}, c.ops)
	if err != nil {
		return nil, fmt.Errorf("nts: %w", err)
	}
	c.core = core
	return c, nil
}

// SetServers replaces the server list of a running client
// (ntscore.Core.SetServers): a server that is as before in every field
// keeps its state, a removed one leaves the quorum at once, and a list the
// core refuses changes nothing. coarse (read at the monotonic time
// coarseLocal) checks the quorum that forms again, as in Combine.
//
// This and SetPolicy are configuration of the core, like NewClient's: the
// caller must be the trusted side (the setup, a signed config update whose
// signatures it has checked), never anything driven by the network.
// During a poll the call is refused with ntscore.ErrBusy and changes
// nothing, and no poll starts while it is at work: the core and its
// binding both keep that exclusion (nts_core.h).
func (c *Client) SetServers(servers []Server, coarse time.Time, coarseLocal int64) error {
	if err := c.core.SetServers(servers, coarse, coarseLocal); err != nil {
		return err
	}
	if c.hooks != nil {
		// The addresses kept were of the old list's positions.
		c.hooks.forgetAll()
	}
	return nil
}

// SetPolicy sets the protocol and the two bounds of a running client
// (ntscore.Core.SetPolicy). A new protocol starts the core over; no time
// is served until a quorum forms on it. See SetServers for who may call.
func (c *Client) SetPolicy(p Protocol, maxBound, maxSampleBound time.Duration, coarse time.Time, coarseLocal int64) error {
	if err := c.core.SetPolicy(p, maxBound, maxSampleBound, coarse, coarseLocal); err != nil {
		return err
	}
	if c.hooks != nil {
		c.hooks.forgetAll()
	}
	return nil
}

// ForgetAddr drops the resolved NTP address of server i (ResolveNTP), so
// its next query looks the name up again: for plain NTP, which has no key
// exchange to do it, after a streak of lost queries. Not during that
// server's poll.
func (c *Client) ForgetAddr(i int) {
	if c.hooks != nil {
		c.hooks.forget(i)
	}
}

func cmpOr(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

// Close wipes the keys and the cookies and frees the core.
func (c *Client) Close() { c.core.Close() }

// Local is the monotonic clock the client runs on.
func (c *Client) Local() int64 { return c.ops.Monotonic() }

// Due is the servers due for a poll now.
func (c *Client) Due() []int { return c.core.Due(c.Local()) }

// Poll polls server i under ctx: NTS-KE if needed, then one query.
// coarse is the coarse time read at the monotonic time coarseLocal; it
// dates the certificate before the first quorum. A Kiss-o'-Death is a
// *KissError; a refusal of the records, the response, the measurement or
// the request is an *Error with its code; a failure of a connection is
// the connection's error. If ctx ended and cut an exchange short, the
// error is ntscore.ErrHostCancelled (errors.Is): the core counts no loss
// and no failure then, and the server stays due. Polls of different
// servers may run at once.
func (c *Client) Poll(ctx context.Context, i int, coarse time.Time, coarseLocal int64) (ntscore.PeerStatus, error) {
	if c.ctxs != nil {
		c.ctxs.SetContext(i, ctx)
		defer c.ctxs.SetContext(i, nil)
	}
	ps, err := c.core.Poll(i, coarse, coarseLocal)
	return ps, wrap(err)
}

// wrap turns the core's refusal into this package's errors.
func wrap(err error) error {
	var e *ntscore.Error
	if !errors.As(err, &e) {
		return err
	}
	switch {
	case errors.Is(e, ntscore.ErrKiss):
		return &KissError{Code: e.Kiss, Authentic: e.KissAuthentic}
	case errors.Is(e, ntscore.ErrNoCookie):
		return &Error{Code: CodeNoCookie, Err: e}
	}
	switch e.Class() {
	case ntscore.ClassKE:
		return &Error{Code: CodeKE, Err: e}
	case ntscore.ClassNTP:
		return &Error{Code: CodeNTP, Err: e}
	case ntscore.ClassSample:
		return &Error{Code: CodeSample, Err: e}
	case ntscore.ClassQuorum:
		return &Error{Code: CodeQuorum, Err: e}
	}
	return err
}

// Peer is server i's state; it may be read while that server's poll is
// not running.
func (c *Client) Peer(i int) ntscore.PeerStatus { return c.core.Peer(i) }

// Combine forms the quorum of the fresh samples, checks it against the
// coarse time (read at coarseLocal) and the earlier quorums, and serves
// it. No poll may run meanwhile.
func (c *Client) Combine(coarse time.Time, coarseLocal int64) error {
	return wrap(c.core.Combine(coarse, coarseLocal))
}

// Bounded is the time now and its error bound, or a refusal: no quorum,
// the bound over the limit (the bound comes back with it), or the
// quorum's samples over the age limit.
func (c *Client) Bounded() (time.Time, time.Duration, error) { return c.core.Bounded() }

// Status is a full snapshot; no poll may run meanwhile. Summary is the
// part of it that may be read during polls.
func (c *Client) Status() ntscore.Status  { return c.core.Status() }
func (c *Client) Summary() ntscore.Status { return c.core.Summary() }
