//go:build nts

package ntscore

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The client's rules through an honest host: the hostile harness's host
// with an empty decision stream (every choice honest), and the knobs of
// hostileWorld set by each test. The harness's own checks run on every
// operation: requests that verify, a Unique Identifier and a cookie never
// sent before, the NTP address the key exchange named.

const (
	honestInterval = 2 * time.Second
	honestMaxPoll  = 64 * time.Second
)

func newHonestCore(t *testing.T, n int, edit func(*Config)) (*hostileWorld, *Core) {
	t.Helper()
	w := &hostileWorld{t: t, d: &decisions{}, rng: testRng(0x636c69656e74 + uint64(n)), live: map[int]*clientRequest{}, honest: map[int]bool{},
		uids: map[[UniqueIDLen]byte]bool{}, issued: map[string]*hostileServer{}, named: map[int]string{}, sent: map[string]bool{}}
	w.now = int64(time.Hour)
	w.trueOffset = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).UnixNano() - w.now
	var servers []Server
	for i := 0; i < n; i++ {
		s := &hostileServer{op: string(rune('a' + i)), c2s: w.rng.bytes(32), s2c: w.rng.bytes(32)}
		w.servers = append(w.servers, s)
		servers = append(servers, Server{Operator: s.op, Host: fmt.Sprintf("nts-%s.test", s.op), Roots: []byte("-----BEGIN CERTIFICATE-----\n")})
	}
	cfg := Config{
		Servers: servers, Interval: honestInterval, MinPoll: time.Second, MaxPoll: honestMaxPoll, MaxBound: 100 * time.Millisecond, MaxAge: time.Minute,
		MaxCoarseDiff: 30 * time.Second, CoarseResolution: time.Second, ExchangeTimeout: time.Second, KissGrace: 100 * time.Millisecond,
		DriftBaselinePolls: 4, FloorUnix: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}
	if edit != nil {
		edit(&cfg)
	}
	w.cookieLen = 100
	core, err := New(cfg, w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	w.core = core
	return w, core
}

// coarseNow is the true time as the host's coarse reading, now.
func (w *hostileWorld) coarseNow() time.Time {
	w.coarse, w.coarseLocal = w.trueNow(), w.now
	return time.Unix(0, w.coarse)
}

func (w *hostileWorld) poll(core *Core, i int) (PeerStatus, error) {
	w.t.Helper()
	ps, err := core.Poll(i, w.coarseNow(), w.now)
	if w.failed != nil {
		w.t.Fatalf("peer %d: %v", i, w.failed)
	}
	return ps, err
}

// round polls the servers that are due and combines, as clock.NTS.Refresh.
func (w *hostileWorld) round(core *Core) error {
	w.t.Helper()
	for _, i := range core.Due(w.now) {
		w.poll(core, i)
	}
	return core.Combine(w.coarseNow(), w.now)
}

// The baseline of the drift check stays about DriftBaselinePolls
// intervals old however often Combine runs. clock.NTS combines four times
// an interval; with the production ratio (64 polls of baseline, a combine
// every quarter interval: 256 quorums a baseline, more than the 64 the
// core keeps) the baseline once stayed the first quorum for good, its
// pair ever longer.
func TestDriftBaselineMovesOn(t *testing.T) {
	const polls = 64
	w, core := newHonestCore(t, 3, func(c *Config) { c.DriftBaselinePolls = polls })
	baseline := polls * honestInterval
	// At most one spacing (baseline/60) and one step (a quarter interval,
	// and the polls' own time) older than the baseline.
	most := baseline + baseline/60 + honestInterval/2
	for step := 1; step <= 3000; step++ {
		w.now += int64(honestInterval / 4)
		if err := w.round(core); err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		st := core.Summary()
		if step > 1 && !st.HaveDrift {
			t.Fatalf("step %d: no drift reading", step)
		}
		if time.Duration(step)*honestInterval/4 > baseline+honestInterval && (st.DriftDT < baseline || st.DriftDT > most) {
			t.Fatalf("step %d: baseline %v old, want %v to %v", step, st.DriftDT, baseline, most)
		}
	}
}

// After a drift refusal the refused quorum's samples do not form a quorum
// again: only new samples bring the time back.
func TestRefusedSamplesDoNotFormAQuorumAgain(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	// The local clock jumps; the true time does not.
	w.now += int64(10 * time.Second)
	w.trueOffset -= int64(10 * time.Second)
	if err := w.round(core); !errors.Is(err, ErrDrift) {
		t.Fatalf("after a jump of the local clock: %v", err)
	}
	if err := core.Combine(w.coarseNow(), w.now); err == nil || errors.Is(err, ErrDrift) {
		t.Fatalf("the refused samples again: %v", err)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("time after the refusal: %v", err)
	}
	w.now += int64(honestInterval)
	if err := w.round(core); err != nil {
		t.Fatalf("new samples: %v", err)
	}
	if _, _, err := core.Bounded(); err != nil {
		t.Fatal(err)
	}
}

// The quorum's samples age on the local clock: the time is refused once
// the oldest is over MaxAge, even with the bound within MaxBound, and
// samples that old form no quorum.
func TestSamplesOverMaxAge(t *testing.T) {
	w, core := newHonestCore(t, 3, func(c *Config) { c.MaxAge, c.MaxBound = 5*time.Second, time.Second })
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	w.now += int64(4 * time.Second)
	if _, _, err := core.Bounded(); err != nil {
		t.Fatalf("4 s: %v", err)
	}
	w.now += int64(2 * time.Second)
	_, b, err := core.Bounded()
	if !errors.Is(err, ErrSamplesTooOld) || b <= 0 || b > time.Second {
		t.Fatalf("6 s: bound %v, %v", b, err)
	}
	if st := core.Summary(); !errors.Is(st.Refusal, ErrSamplesTooOld) || st.SampleAge < 6*time.Second || st.Refusals != 1 {
		t.Fatalf("summary %+v", st)
	}
	if err := core.Combine(w.coarseNow(), w.now); !errors.Is(err, ErrQuorumTooFew) {
		t.Fatalf("a quorum of 6 s old samples: %v", err)
	}
}

// The time that dates an NTS-KE certificate follows the rules of the time
// served: the core's own while its quorum would be served, the coarse
// reading moved forward once that quorum has aged out. A stale quorum on a
// counter run ahead once dated certificates ahead of real time.
func TestCertificateTimeFollowsTheServedTime(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	// Eight lost requests use up the cookies: the next poll runs NTS-KE.
	w.drop = MaxCookies
	for k := 0; k < MaxCookies; k++ {
		w.now += int64(honestInterval)
		if _, err := w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
			t.Fatalf("lost request %d: %v", k, err)
		}
	}
	// The counter jumps two minutes ahead of real time: the quorum in force
	// is past MaxAge, the time is refused, and the certificate is dated by
	// the coarse reading (honest here), not by the quorum's time.
	w.now += int64(2 * time.Minute)
	w.trueOffset -= int64(2 * time.Minute)
	if _, _, err := core.Bounded(); !errors.Is(err, ErrSamplesTooOld) {
		t.Fatalf("time with the quorum aged out: %v", err)
	}
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	if ps := core.Peer(0); ps.Stats.KEOK != 2 {
		t.Fatalf("no second key exchange: %+v", ps.Stats)
	}
	// The coarse reading, moved forward: within the world's own advances
	// of the true time, never the two minutes of the stale quorum.
	if lead := w.keValidity - w.trueNow(); lead < -int64(time.Second) || lead > int64(time.Second) {
		t.Fatalf("certificate dated %v from the true time", time.Duration(lead))
	}
}

// A monotonic counter that went back between two quorums is a broken
// clock: the quorum is refused as drift, not checked as if no time had
// passed since the earlier one.
func TestCounterThatWentBackIsDrift(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	w.now += int64(honestInterval)
	if err := core.Combine(w.coarseNow(), w.now); err != nil {
		t.Fatalf("the same samples again: %v", err)
	}
	w.now -= int64(honestInterval / 2)
	if err := core.Combine(w.coarseNow(), w.now); !errors.Is(err, ErrDrift) {
		t.Fatalf("the counter went back by half an interval: %v", err)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("time after the refusal: %v", err)
	}
}

// Close frees the core between polls and refuses every call after it.
func TestCloseRefusesLaterCalls(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	core.Close()
	if _, err := core.Poll(0, w.coarseNow(), w.now); !errors.Is(err, ErrClosed) {
		t.Fatalf("poll after Close: %v", err)
	}
	if err := core.Combine(w.coarseNow(), w.now); !errors.Is(err, ErrClosed) {
		t.Fatalf("combine after Close: %v", err)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrClosed) {
		t.Fatalf("time after Close: %v", err)
	}
	if core.Due(w.now) != nil || core.Peer(0).Sample != nil || core.Status().HaveResult || core.Summary().HaveResult {
		t.Fatal("a closed core still answers")
	}
	core.Close() // a second Close, and the one of Cleanup, do nothing
}

// Keys or a response of the wrong length from the host's key exchange
// are refused as a failed host operation: no association, no socket, no
// sample (the Rust FFI's assoc_new_refusals: a 31-octet key).
func TestKeyExchangeOfTheWrongLength(t *testing.T) {
	for bad, what := range map[int]string{1: "a C2S key of 31 octets", 2: "an S2C key of 33 octets", 3: "a response longer than the buffer"} {
		w, core := newHonestCore(t, 3, nil)
		w.keBad = bad
		ps, err := w.poll(core, 0)
		if !errors.Is(err, ErrHost) || ps.Sample != nil || ps.Cookies != 0 || ps.Stats.KEFail != 1 || w.opens != 0 {
			t.Fatalf("%s: %v, %+v, %d sockets", what, err, ps, w.opens)
		}
	}
}

// Requests lost on the way cost their cookies; the next request asks for
// as many placeholders as the jar lacks, and the answer fills it again
// (the Rust FFI's placeholders_refill_the_jar).
func TestPlaceholdersRefillTheJar(t *testing.T) {
	for _, lost := range []int{1, 3, 5, 7} {
		w, core := newHonestCore(t, 3, nil)
		if ps, err := w.poll(core, 0); err != nil || ps.Cookies != MaxCookies {
			t.Fatalf("first poll: %+v, %v", ps, err)
		}
		w.drop = lost
		for k := 0; k < lost; k++ {
			w.now += int64(honestInterval)
			if _, err := w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
				t.Fatalf("lost request %d: %v", k, err)
			}
		}
		if ps := core.Peer(0); ps.Cookies != MaxCookies-lost {
			t.Fatalf("%d lost: %d cookies", lost, ps.Cookies)
		}
		w.now += int64(honestInterval)
		ps, err := w.poll(core, 0)
		if err != nil || ps.Sample == nil || ps.Sample.CookiesReceived != lost+1 || ps.Cookies != MaxCookies || ps.Sample.CookiesHeld != MaxCookies {
			t.Fatalf("%d lost, then an answer: %+v, %v", lost, ps, err)
		}
		if got := w.live[0].placeholders; got != lost {
			t.Fatalf("%d lost: %d placeholders", lost, got)
		}
	}
}

// A send the host reports failed may have gone out: its cookie is not
// used again (the harness fails on a cookie sent twice).
func TestFailedSendSpendsTheCookie(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.sendFail = true
	w.now += int64(honestInterval)
	if _, err := w.poll(core, 0); !errors.Is(err, ErrHost) {
		t.Fatalf("failed send: %v", err)
	}
	if ps := core.Peer(0); ps.Cookies != MaxCookies-1 {
		t.Fatalf("after a failed send: %d cookies", ps.Cookies)
	}
	w.sendFail = false
	w.now += int64(honestInterval)
	if ps, err := w.poll(core, 0); err != nil || ps.Sample == nil {
		t.Fatalf("next poll: %+v, %v", ps, err)
	}
}

// An authenticated DENY or RSTR stops the server for MaxPoll and drops its
// association: the cookies go, the sample goes, and the next poll after
// MaxPoll starts with a key exchange. RATE doubles the poll up to MaxPoll.
func TestAuthenticKissCodes(t *testing.T) {
	for _, code := range []string{"DENY", "RSTR"} {
		w, core := newHonestCore(t, 3, nil)
		if _, err := w.poll(core, 0); err != nil {
			t.Fatal(err)
		}
		w.kiss = code
		w.now += int64(honestInterval)
		ps, err := w.poll(core, 0)
		var e *Error
		if !errors.As(err, &e) || !errors.Is(err, ErrKiss) || e.Kiss != code || !e.KissAuthentic {
			t.Fatalf("%s: %v", code, err)
		}
		if ps.Disabled != code || ps.Poll != honestMaxPoll || ps.Sample != nil || ps.Cookies != 0 {
			t.Fatalf("%s: %+v", code, ps)
		}
		w.kiss = ""
		w.now += int64(honestMaxPoll - time.Second)
		for _, i := range core.Due(w.now) {
			if i == 0 {
				t.Fatalf("%s: due again before MaxPoll", code)
			}
		}
		w.now += int64(2 * time.Second)
		ps, err = w.poll(core, 0)
		if err != nil || ps.Disabled != "" || ps.Stats.KEOK != 2 || ps.Sample == nil {
			t.Fatalf("%s, after MaxPoll: %+v, %v", code, ps, err)
		}
	}
	w, core := newHonestCore(t, 3, nil)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.kiss = "RATE"
	for _, want := range []time.Duration{4, 8, 16, 32, 64, 64} {
		w.now += int64(honestMaxPoll)
		ps, _ := w.poll(core, 0)
		if ps.Poll != want*time.Second || ps.Disabled != "" || ps.Cookies == 0 {
			t.Fatalf("RATE: poll %v, want %v (%+v)", ps.Poll, want*time.Second, ps)
		}
	}
}

// Without Server and Port records the NTP server is the key exchange's
// host on port 123 (RFC 8915 sections 4.1.7, 4.1.8); a named IPv6 address
// is dialed in brackets. The harness checks the address dialed.
func TestNTPAddressDefaults(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	w.keNoServerPort = true
	if ps, err := w.poll(core, 0); err != nil || ps.NTPAddr != "nts-a.test:123" {
		t.Fatalf("no Server or Port record: %+v, %v", ps, err)
	}
	w, core = newHonestCore(t, 3, nil)
	w.keServer = "2001:db8::1"
	if ps, err := w.poll(core, 0); err != nil || ps.NTPAddr != "[2001:db8::1]:1234" {
		t.Fatalf("an IPv6 server: %+v, %v", ps, err)
	}
}

// Cores are independent: several, each on its own goroutine and host,
// poll and serve at the same time (the Rust FFI's associations on many
// threads; the race detector watches).
func TestCoresOnManyGoroutines(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			w, core := newHonestCore(t, 3+g%3, nil)
			for r := 0; r < 20; r++ {
				w.now += int64(honestInterval)
				for _, i := range core.Due(w.now) {
					if _, err := core.Poll(i, w.coarseNow(), w.now); err != nil {
						errs <- fmt.Errorf("core %d round %d peer %d: %w", g, r, i, err)
						return
					}
				}
				if err := core.Combine(w.coarseNow(), w.now); err != nil {
					errs <- fmt.Errorf("core %d round %d: %w", g, r, err)
					return
				}
				if _, _, err := core.Bounded(); err != nil {
					errs <- fmt.Errorf("core %d round %d: %w", g, r, err)
					return
				}
			}
			if w.failed != nil {
				errs <- fmt.Errorf("core %d: %w", g, w.failed)
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Every code of the core has its own error and text (the Rust FFI's
// every_kind_has_its_own_text); the numbers are the header's (lowlevel.go
// defines them from it).
func TestErrorCodesAndTexts(t *testing.T) {
	seen := map[string]int{}
	for code, err := range byCode {
		if err == nil || err.Error() == "" {
			t.Fatalf("code %d has no text", code)
		}
		if other, ok := seen[err.Error()]; ok {
			t.Fatalf("codes %d and %d share the text %q", code, other, err.Error())
		}
		seen[err.Error()] = code
		if got := CodeError(code, 0); !errors.Is(got, err) {
			t.Fatalf("CodeError(%d) = %v, not %v", code, got, err)
		}
	}
	if err := CodeError(9999, 0); !errors.Is(err, errUnknownCode) || !strings.Contains(err.Error(), "9999") {
		t.Fatalf("unknown code: %v", err)
	}
	if CodeError(codeOK, 0) != nil {
		t.Fatal("code 0 is an error")
	}
}

// Until the first quorum, a failed key exchange is tried again after the
// interval, not after a doubling wait: a relay that comes up late must not
// push the first quorum past the runner's start wait. From the first
// quorum on, a failure backs off: the interval, then twice that, up to
// MaxPoll; the polls in between do nothing (ErrNotDue); a key exchange
// that works resets the wait, and the next failure starts again at the
// interval. Without the backoff a hostile network could make the client
// hammer NTS-KE; without the reset a failure would keep an operator out
// for MaxPoll.
func TestKeyExchangeBackoff(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	w.keFail = 100
	for n := 0; n < 4; n++ {
		if ps, err := w.poll(core, 0); !errors.Is(err, ErrHost) || ps.Stats.KEFail != n+1 || ps.Cookies != 0 {
			t.Fatalf("failure %d before the first quorum: %v, %+v", n, err, ps)
		}
		w.now += int64(honestInterval - time.Second)
		if _, err := w.poll(core, 0); !errors.Is(err, ErrNotDue) {
			t.Fatalf("failure %d, before the interval: %v", n, err)
		}
		w.now += int64(time.Second)
	}
	w.keFail = 0
	if err := w.round(core); err != nil {
		t.Fatalf("the first quorum: %v", err)
	}
	// Eight lost requests spend the cookies; from here a failed key
	// exchange backs off.
	spend := func() {
		w.drop = MaxCookies
		for k := 0; k < MaxCookies; k++ {
			w.now += int64(honestInterval)
			if _, err := w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
				t.Fatalf("lost request %d: %v", k, err)
			}
		}
	}
	spend()
	w.keFail = 100
	fails := core.Peer(0).Stats.KEFail
	for n, wait := range []time.Duration{2, 4, 8, 16, 32, 64, 64} {
		wait *= time.Second
		if ps, err := w.poll(core, 0); !errors.Is(err, ErrHost) || ps.Stats.KEFail != fails+n+1 || ps.Cookies != 0 {
			t.Fatalf("failure %d after the first quorum: %v, %+v", n, err, ps)
		}
		w.now += int64(wait - time.Second)
		if _, err := w.poll(core, 0); !errors.Is(err, ErrNotDue) {
			t.Fatalf("failure %d, %v before the wait of %v ends: %v", n, time.Second, wait, err)
		}
		w.now += int64(time.Second)
	}
	w.keFail = 0
	ps, err := w.poll(core, 0)
	if err != nil || ps.Sample == nil || ps.Stats.KEOK != 2 {
		t.Fatalf("after the backoff: %v, %+v", err, ps)
	}
	// A failure after a success waits the interval again, not the 64 s the
	// backoff had reached.
	spend()
	w.keFail = 1
	w.now += int64(honestInterval)
	if _, err := w.poll(core, 0); !errors.Is(err, ErrHost) {
		t.Fatalf("the failure after a success: %v", err)
	}
	w.now += int64(honestInterval - time.Second)
	if _, err := w.poll(core, 0); !errors.Is(err, ErrNotDue) {
		t.Fatalf("before the interval: %v", err)
	}
	w.now += int64(time.Second)
	if ps, err := w.poll(core, 0); err != nil || ps.Sample == nil || ps.Stats.KEOK != 3 {
		t.Fatalf("at the interval: %v, %+v", err, ps)
	}
}

// A quorum that fails the coarse check stops the time: Bounded refuses
// until a quorum passes, as after a drift refusal, instead of serving the
// earlier quorum until its samples age out.
func TestCoarseRefusalStopsServing(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.Bounded(); err != nil {
		t.Fatal(err)
	}
	w.now += int64(honestInterval)
	for _, i := range core.Due(w.now) {
		w.poll(core, i)
	}
	// The coarse clock 40 s behind the servers: refused, and no time.
	if err := core.Combine(time.Unix(0, w.trueNow()-40*int64(time.Second)), w.now); !errors.Is(err, ErrCoarseCheck) {
		t.Fatalf("the coarse clock 40 s behind: %v", err)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("time after the coarse refusal: %v", err)
	}
	if st := core.Summary(); st.HaveResult || !errors.Is(st.LastErr, ErrCoarseCheck) {
		t.Fatalf("summary after the coarse refusal: %+v", st)
	}
	// Agreement again: the next quorum, of the same fresh samples, serves.
	if err := core.Combine(w.coarseNow(), w.now); err != nil {
		t.Fatalf("the coarse clock agrees again: %v", err)
	}
	if _, _, err := core.Bounded(); err != nil {
		t.Fatalf("time after the coarse clock agrees again: %v", err)
	}
}

// While the quorum in force would be served, the certificate is dated by
// the core's own time, not by the coarse reading: a host that moves the
// coarse clock within the coarse check's 30 s must not move the time the
// certificates are checked at.
func TestCertificateTimeIsTheCoresWhileItServes(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	w.drop = MaxCookies
	for k := 0; k < MaxCookies; k++ {
		w.now += int64(honestInterval)
		if _, err := w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
			t.Fatalf("lost request %d: %v", k, err)
		}
	}
	if _, _, err := core.Bounded(); err != nil {
		t.Fatalf("the quorum is 16 s old and still served: %v", err)
	}
	w.now += int64(honestInterval)
	w.coarse, w.coarseLocal = w.trueNow()+20*int64(time.Second), w.now
	ps, err := core.Poll(0, time.Unix(0, w.coarse), w.coarseLocal)
	if w.failed != nil {
		t.Fatal(w.failed)
	}
	if err != nil || ps.Stats.KEOK != 2 {
		t.Fatalf("no second key exchange: %v, %+v", err, ps)
	}
	if off := w.keValidity - w.trueNow(); off > int64(time.Second) || -off > int64(time.Second) {
		t.Fatalf("certificate dated %v from the true time with the coarse clock 20 s ahead", time.Duration(off))
	}
}

// A CSPRNG that fails costs nothing: no cookie leaves the jar, no socket
// opens, the poll is an error, and the next one works.
func TestRandomFailureCostsNothing(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.randomFail = true
	w.now += int64(honestInterval)
	opens := w.opens
	ps, err := w.poll(core, 0)
	if !errors.Is(err, ErrHostRandom) || ps.Cookies != MaxCookies || ps.Stats.Errors != 1 || w.opens != opens {
		t.Fatalf("random failed: %v, %+v, %d sockets", err, ps, w.opens-opens)
	}
	w.randomFail = false
	w.now += int64(honestInterval)
	if ps, err := w.poll(core, 0); err != nil || ps.Sample == nil {
		t.Fatalf("next poll: %v, %+v", err, ps)
	}
}

// The Server and Port records of NTS-KE, each alone: the server named on
// port 123, the KE host on the port named; and a KE host that is an IPv6
// literal goes in brackets.
func TestServerAndPortRecordsAlone(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	w.keNoPort = true
	if ps, err := w.poll(core, 0); err != nil || ps.NTPAddr != "ntp-a.test:123" {
		t.Fatalf("a Server record alone: %+v, %v", ps, err)
	}
	w, core = newHonestCore(t, 3, nil)
	w.keNoServer, w.kePort = true, 4123
	if ps, err := w.poll(core, 0); err != nil || ps.NTPAddr != "nts-a.test:4123" {
		t.Fatalf("a Port record alone: %+v, %v", ps, err)
	}
	w, core = newHonestCore(t, 3, func(c *Config) { c.Servers[0].Host = "2001:db8::2" })
	w.keNoServer = true
	if ps, err := w.poll(core, 0); err != nil || ps.NTPAddr != "[2001:db8::2]:1234" {
		t.Fatalf("an IPv6 KE host: %+v, %v", ps, err)
	}
}

// An authentic Kiss-o'-Death followed by the real answer within the grace:
// the answer wins, the poll interval does not change, and the KoD is not
// counted (the query ended with a sample). An authentic KoD of a code the
// core does not know is only counted: the poll and the cookies stay.
func TestKissOfDeathEdges(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.kissThenAnswer = "RATE"
	w.now += int64(honestInterval)
	if ps, err := w.poll(core, 0); err != nil || ps.Sample == nil || ps.Poll != honestInterval || len(ps.Stats.Kisses) != 0 || ps.Cookies != MaxCookies {
		t.Fatalf("RATE then the answer: %v, %+v", err, ps)
	}
	w.kissThenAnswer, w.kiss = "", "STEP"
	w.now += int64(honestInterval)
	ps, err := w.poll(core, 0)
	var e *Error
	if !errors.As(err, &e) || e.Kiss != "STEP" || !e.KissAuthentic || ps.Stats.Kisses["OTHER"] != 1 || ps.Poll != honestInterval || ps.Cookies != MaxCookies-1 || ps.Disabled != "" {
		t.Fatalf("an authentic STEP: %v, %+v", err, ps)
	}
}

// Every code lands in the class its range in nts_core.h says, and the
// texts of the host class name the host's error.
func TestErrorClasses(t *testing.T) {
	want := func(code int) CodeClass {
		switch {
		case code < 40:
			return ClassNTP
		case code < 60:
			return ClassSample
		case code < 70:
			return ClassQuorum
		case code < 90:
			return ClassKE
		case code < 100:
			return ClassHost
		}
		return ClassClient
	}
	for code := range byCode {
		if got := ClassOf(code); got != want(code) {
			t.Fatalf("code %d: class %v, want %v", code, got, want(code))
		}
	}
	if ClassOf(codeOK) != ClassNone {
		t.Fatal("code 0 has a class")
	}
	host := errors.New("ntp 127.0.0.1:123: i/o timeout")
	e := &Error{Code: codeHostTimeout, Detail: codeNotAuthentic, Host: host}
	if s := e.Error(); !strings.Contains(s, host.Error()) || !strings.Contains(s, ErrNotAuthentic.Error()) || !errors.Is(e, ErrHostTimeout) {
		t.Fatalf("a timeout after a refusal: %q, is ErrHostTimeout %v", s, errors.Is(e, ErrHostTimeout))
	}
	if s := (&Error{Code: codeKiss, Kiss: "RATE"}).Error(); !strings.Contains(s, "RATE") || !strings.Contains(s, "not authenticated") {
		t.Fatalf("an unauthenticated KoD: %q", s)
	}
}

// The time never goes back: when every server's clock moves back a little
// (within what the drift check allows over an interval, about 1 ms; no
// liar to outvote) and the quorum follows, a reading that would fall
// behind the highest one served stays at it, until real time passes it.
func TestTimeNeverGoesBack(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	w.now += int64(honestInterval)
	highest, _, err := core.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range w.servers {
		s.offset = -500 * int64(time.Microsecond)
	}
	// The polls move the counter by a few milliseconds; the highest reading
	// is taken after them, so the new quorum, 500 us behind, falls behind it.
	for _, i := range core.Due(w.now) {
		w.poll(core, i)
	}
	if highest, _, err = core.Bounded(); err != nil {
		t.Fatal(err)
	}
	if err := core.Combine(w.coarseNow(), w.now); err != nil {
		t.Fatalf("the quorum after the servers moved back 500 us: %v", err)
	}
	st := core.Summary()
	if raw := time.Unix(0, w.now+st.Offset); !raw.Before(highest) {
		t.Fatalf("the new quorum reads %v, not behind the highest reading %v", raw, highest)
	}
	served, _, err := core.Bounded()
	if err != nil || !served.Equal(highest) {
		t.Fatalf("served %v, the highest reading was %v (%v)", served, highest, err)
	}
	w.now += int64(time.Millisecond)
	later, _, err := core.Bounded()
	if err != nil || !later.After(highest) || later.Sub(highest) > time.Millisecond {
		t.Fatalf("1 ms on: served %v, the highest reading was %v (%v)", later, highest, err)
	}
}

// The drift check at its limit, at the production interval: a local
// counter that runs within rho (500 ppm) of real time is accepted, one
// well over it is refused on the first pair that shows it. The two
// quorums' bounds (about half a millisecond each here, from the harness's
// one-millisecond answers) add about 60 ppm of slack over 16 s, so 490
// ppm is accepted and 600 refused; nothing else pins the rho term.
func TestDriftCheckAtTheLimit(t *testing.T) {
	for _, tc := range []struct {
		ppm     int64
		refused bool
	}{{400, false}, {490, false}, {-490, false}, {600, true}, {-600, true}, {1000, true}} {
		t.Run(fmt.Sprintf("%dppm", tc.ppm), func(t *testing.T) {
			const interval = 16 * time.Second
			w, core := newHonestCore(t, 3, func(c *Config) { c.Interval, c.MinPoll = interval, interval })
			if err := w.round(core); err != nil {
				t.Fatal(err)
			}
			refusals := 0
			for r := 0; r < 8; r++ {
				// The counter counts an interval while real time moves an
				// interval less ppm of it.
				w.now += int64(interval)
				w.trueOffset -= int64(interval) * tc.ppm / 1_000_000
				switch err := w.round(core); {
				case errors.Is(err, ErrDrift):
					refusals++
				case err != nil:
					t.Fatalf("round %d: %v", r, err)
				}
			}
			if (refusals > 0) != tc.refused {
				t.Fatalf("%d ppm: %d drift refusals in 8 rounds, refused %v", tc.ppm, refusals, tc.refused)
			}
		})
	}
}

// FloorUnix is the pivot of the NTP era: with a floor past the 2036
// rollover and servers in 2040 (era 1 on the wire, the seconds wrapped),
// the timestamps are read in era 1 and the quorum serves 2040.
func TestFloorPastTheEraRollover(t *testing.T) {
	for _, floor := range []time.Time{time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)} {
		w, core := newHonestCore(t, 3, func(c *Config) { c.FloorUnix = floor })
		w.trueOffset = time.Date(2040, 5, 5, 0, 0, 0, 0, time.UTC).UnixNano() - w.now
		if err := w.round(core); err != nil {
			t.Fatalf("floor %v: %v", floor, err)
		}
		tm, bound, err := core.Bounded()
		if err != nil || tm.Year() != 2040 || tm.Sub(time.Unix(0, w.trueNow())) > bound || time.Unix(0, w.trueNow()).Sub(tm) > bound {
			t.Fatalf("floor %v: served %v with bound %v, true %v (%v)", floor, tm, bound, time.Unix(0, w.trueNow()), err)
		}
	}
}
