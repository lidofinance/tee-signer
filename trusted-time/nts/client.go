//go:build nts

package nts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/ntscore"
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
	MaxCoarseDiff    time.Duration // a quorum further from the coarse time is refused
	CoarseResolution time.Duration // of the coarse readings
	ExchangeTimeout  time.Duration // 0: ExchangeTimeout
	// Dial opens the connections. Nil: net.Dialer.
	Dial DialFunc
	// Local is the monotonic clock in ns. Nil: Monotonic. A test moves it
	// ahead to age the bound.
	Local func() int64
}

// Client is the NTS client: the C core of ntscore with the host operations
// of this package. clock.NTS drives it: Due, Poll per due server, Combine,
// then Bounded for the time.
type Client struct {
	core  *ntscore.Core
	hooks *hooks
}

// NewClient allocates the core. Close frees it.
func NewClient(cfg Config) (*Client, error) {
	h := newHooks(cfg.Dial, cfg.Local)
	core, err := ntscore.New(ntscore.Config{
		Servers: cfg.Servers, Interval: cfg.Interval, MinPoll: cfg.MinPoll, MaxPoll: cfg.MaxPoll, MaxBound: cfg.MaxBound,
		MaxCoarseDiff: cfg.MaxCoarseDiff, CoarseResolution: cfg.CoarseResolution,
		ExchangeTimeout: cmpOr(cfg.ExchangeTimeout, ExchangeTimeout), KissGrace: KissGrace,
		DriftBaselinePolls: DriftBaselinePolls, FloorUnix: FloorTime,
	}, h)
	if err != nil {
		return nil, fmt.Errorf("nts: %w", err)
	}
	return &Client{core: core, hooks: h}, nil
}

func cmpOr(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

// Close wipes the keys and the cookies and frees the core.
func (c *Client) Close() { c.core.Close() }

// Servers is the configuration, by index.
func (c *Client) Servers() []Server { return c.core.Servers() }

// Local is the monotonic clock the client runs on.
func (c *Client) Local() int64 { return c.hooks.Monotonic() }

// Due is the servers due for a poll now.
func (c *Client) Due() []int { return c.core.Due(c.Local()) }

// Poll polls server i under ctx: NTS-KE if needed, then one query.
// coarse is the coarse time read at the monotonic time coarseLocal; it
// dates the certificate before the first quorum. A Kiss-o'-Death is a
// *KissError; a refusal of the records, the response, the measurement or
// the request is an *Error with its code; a failure of a connection is
// the connection's error. Polls of different servers may run at once.
func (c *Client) Poll(ctx context.Context, i int, coarse time.Time, coarseLocal int64) (ntscore.PeerStatus, error) {
	c.hooks.setContext(ctx)
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
// or the bound over the limit (the bound comes back with it).
func (c *Client) Bounded() (time.Time, time.Duration, error) { return c.core.Bounded() }

// Status is a full snapshot; no poll may run meanwhile. Summary is the
// part of it that may be read during polls.
func (c *Client) Status() ntscore.Status  { return c.core.Status() }
func (c *Client) Summary() ntscore.Status { return c.core.Summary() }
