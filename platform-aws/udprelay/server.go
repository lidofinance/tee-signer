package udprelay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Server is the relay. It reads a destination, checks it against Allow,
// and copies datagrams between the stream and a connected UDP socket.
//
// Limits (the defaults suit four NTS servers polled every 16 s or more):
//
//   - MaxSessions connections at once (16); one over it is refused.
//   - A session ends after Idle without a datagram either way (10 s) and
//     after MaxLife in any case (30 s). Each NTP query is one session.
//   - PerSession datagrams out per session (8).
//   - Rate datagrams out per second over all sessions, Burst at once (10, 20).
//   - DestRate datagrams out per second to one address, DestBurst at once
//     (0.5, 4).
//
// A datagram over a limit is dropped and counted, as a network would drop
// it. The client's NTS code sees a timeout and retries at its next poll.
type Server struct {
	Allow       *Allowlist
	Log         *slog.Logger // nil: no logs
	MaxSessions int
	Idle        time.Duration
	MaxLife     time.Duration
	PerSession  int
	Rate        float64
	Burst       float64
	DestRate    float64
	DestBurst   float64
	// DialUDP opens the connected UDP socket. Nil: net.DialUDP.
	DialUDP func(ap netip.AddrPort) (net.Conn, error)

	once    sync.Once
	slots   chan struct{}
	global  *bucket
	destMu  sync.Mutex
	dests   map[netip.Addr]*bucket
	Counter Counters
}

// Counters count what the relay did since it started.
type Counters struct {
	Sessions, Refused, Busy     atomic.Int64
	Out, In                     atomic.Int64 // datagrams sent to and received from destinations
	DroppedRate, DroppedSession atomic.Int64 // datagrams out dropped by a limit
	DroppedLarge, BadFrames     atomic.Int64
	OctetsOut, OctetsIn         atomic.Int64
	sessionsNow                 atomic.Int64
}

// Snapshot is Counters as plain numbers, for logs.
func (c *Counters) Snapshot() map[string]int64 {
	return map[string]int64{
		"sessions": c.Sessions.Load(), "refused": c.Refused.Load(), "busy": c.Busy.Load(),
		"out": c.Out.Load(), "in": c.In.Load(), "dropped_rate": c.DroppedRate.Load(),
		"dropped_session": c.DroppedSession.Load(), "dropped_large": c.DroppedLarge.Load(),
		"bad_frames": c.BadFrames.Load(), "octets_out": c.OctetsOut.Load(), "octets_in": c.OctetsIn.Load(),
		"sessions_now": c.sessionsNow.Load(),
	}
}

func orInt(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func orDur(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func orF(v, d float64) float64 {
	if v > 0 {
		return v
	}
	return d
}

func (s *Server) init() {
	s.once.Do(func() {
		s.slots = make(chan struct{}, orInt(s.MaxSessions, 16))
		s.global = newBucket(orF(s.Rate, 10), orF(s.Burst, 20))
		s.dests = map[netip.Addr]*bucket{}
	})
}

func (s *Server) logf(level slog.Level, msg string, args ...any) {
	if s.Log != nil {
		s.Log.Log(context.Background(), level, msg, args...)
	}
}

// Serve accepts connections on l until ctx ends or l fails.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.init()
	if s.Allow == nil {
		return errors.New("udprelay: no allowlist")
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() { <-s.slots }()
				s.handle(ctx, c)
			}()
		default:
			s.Counter.Busy.Add(1)
			go func() {
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_ = writeFrame(c, append([]byte{1}, "busy"...))
				c.Close()
			}()
			s.logf(slog.LevelWarn, "udprelay: busy, session refused", "max", cap(s.slots))
		}
	}
}

// destBucket is the rate limit of one address. Buckets that are full again
// are dropped from the map, so it stays small.
func (s *Server) destAllow(ip netip.Addr) bool {
	s.destMu.Lock()
	defer s.destMu.Unlock()
	now := time.Now()
	for k, b := range s.dests {
		if b.full(now) {
			delete(s.dests, k)
		}
	}
	b, ok := s.dests[ip]
	if !ok {
		b = newBucket(orF(s.DestRate, 0.5), orF(s.DestBurst, 4))
		s.dests[ip] = b
	}
	return b.take(now)
}

func (s *Server) dialUDP(ap netip.AddrPort) (net.Conn, error) {
	if s.DialUDP != nil {
		return s.DialUDP(ap)
	}
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	s.Counter.Sessions.Add(1)
	s.Counter.sessionsNow.Add(1)
	defer s.Counter.sessionsNow.Add(-1)
	start := time.Now()
	end := start.Add(orDur(s.MaxLife, 30*time.Second))
	idle := orDur(s.Idle, 10*time.Second)
	deadline := func() time.Time {
		if d := time.Now().Add(idle); d.Before(end) {
			return d
		}
		return end
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, MaxDatagram)
	d, err := readFrame(c, buf, MaxDest)
	if err != nil {
		s.Counter.BadFrames.Add(1)
		s.logf(slog.LevelWarn, "udprelay: no destination", "err", err)
		return
	}
	dest := printable(d, MaxDest)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ap, err := s.Allow.Check(cctx, string(d))
	cancel()
	if err == nil && dest != string(d) {
		err = refusal{"destination is not printable ASCII"}
	}
	if err != nil {
		s.Counter.Refused.Add(1)
		reason := err.Error()
		if len(reason) > maxReason {
			reason = reason[:maxReason]
		}
		_ = writeFrame(c, append([]byte{1}, reason...))
		s.logf(slog.LevelWarn, "udprelay: destination refused", "dest", dest, "reason", reason)
		return
	}
	u, err := s.dialUDP(ap)
	if err != nil {
		s.Counter.Refused.Add(1)
		_ = writeFrame(c, append([]byte{1}, "cannot open UDP"...))
		s.logf(slog.LevelWarn, "udprelay: UDP", "dest", dest, "addr", ap, "err", err)
		return
	}
	defer u.Close()
	if err := writeFrame(c, []byte{0}); err != nil {
		return
	}
	var out, in, dropped atomic.Int64
	done := make(chan struct{})
	// Answers: UDP to the stream. The socket is connected, so the kernel
	// passes only datagrams from ap.
	go func() {
		defer close(done)
		rb := make([]byte, MaxDatagram+1)
		for {
			_ = u.SetReadDeadline(deadline())
			n, err := u.Read(rb)
			if err != nil {
				var ne net.Error
				if !errors.Is(err, net.ErrClosed) && !(errors.As(err, &ne) && ne.Timeout()) && time.Now().Before(end) {
					// ICMP port unreachable and the like: keep waiting
					// for the real answer.
					continue
				}
				c.Close()
				return
			}
			if n > MaxDatagram {
				s.Counter.DroppedLarge.Add(1)
				continue
			}
			in.Add(1)
			s.Counter.In.Add(1)
			s.Counter.OctetsIn.Add(int64(n))
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := writeFrame(c, rb[:n]); err != nil {
				return
			}
		}
	}()
	perSession := int64(orInt(s.PerSession, 8))
	for {
		_ = c.SetReadDeadline(deadline())
		p, err := readFrame(c, buf, MaxDatagram)
		if err != nil {
			if errors.Is(err, errFrame) {
				s.Counter.BadFrames.Add(1)
				s.logf(slog.LevelWarn, "udprelay: bad frame, session closed", "dest", dest, "err", err)
			}
			break
		}
		switch {
		case out.Load()+dropped.Load() >= perSession:
			s.Counter.DroppedSession.Add(1)
			dropped.Add(1)
			continue
		case !s.global.take(time.Now()) || !s.destAllow(ap.Addr()):
			s.Counter.DroppedRate.Add(1)
			dropped.Add(1)
			continue
		}
		if _, err := u.Write(p); err != nil {
			s.logf(slog.LevelWarn, "udprelay: UDP write", "dest", dest, "err", err)
			continue
		}
		out.Add(1)
		s.Counter.Out.Add(1)
		s.Counter.OctetsOut.Add(int64(len(p)))
	}
	u.Close()
	<-done
	level := slog.LevelDebug
	if dropped.Load() > 0 {
		level = slog.LevelWarn
	}
	s.logf(level, "udprelay: session", "dest", dest, "addr", ap, "out", out.Load(), "in", in.Load(),
		"dropped", dropped.Load(), "took", time.Since(start).Round(time.Millisecond))
}

// bucket is a token bucket: rate tokens per second, at most burst.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	at     time.Time
}

func newBucket(rate, burst float64) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, at: time.Now()}
}

func (b *bucket) fill(now time.Time) {
	if dt := now.Sub(b.at).Seconds(); dt > 0 {
		b.tokens = min(b.burst, b.tokens+dt*b.rate)
	}
	b.at = now
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *bucket) full(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fill(now)
	return b.tokens >= b.burst
}
