//go:build nts

package ntscore

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// A configuration call and a poll exclude each other: no call is taken
// while a poll is under way, and no poll runs on a peer that a call wipes
// or gives to another server. One goroutine polls server 0, another makes
// configuration calls that touch it, as fast as they go.
//
// Each case runs twice: through the binding (SetServers, SetPolicy), and
// through setServers and setPolicy, which leave out the binding's lock, so
// that the core's own exclusion (nts_core.h: the atomic gate of client.c)
// is all that keeps the two apart, as in a trusted application.
//
// What is checked: a call that was taken never lies wholly inside a poll
// (from the poll's socket open to its close, both by the core, both inside
// the poll); the cookie jar keeps its size; the world's own checks of
// every request hold; and, under -asan, the core's memory. A poll that
// starts inside a call cannot be told from outside by its timing; it shows
// in the last three (with the check the core had before, which was no
// lock, SetServers/core fails here within some tens of polls), and
// TestPollDuringAConfigurationCallIsBusy has that order without a race.
func TestConfigurationCallsExcludePolls(t *testing.T) {
	for _, c := range []struct {
		name    string
		binding bool
		policy  bool
	}{
		{"SetServers", true, false},
		{"SetServers/core", false, false},
		{"SetPolicy", true, true},
		{"SetPolicy/core", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, core := newHonestCore(t, 4, func(cfg *Config) { cfg.Capacity = 4 })
			if c.binding && !c.policy {
				// With a quorum in force every swap forms it again (the core
				// reads the clock for that). Without the binding's lock the
				// calls must not enter the world: only the poll may.
				if err := w.round(core); err != nil {
					t.Fatal(err)
				}
			}
			coarse, local := w.coarseNow(), w.now
			// The servers answer nothing in the policy cases: the protocol
			// changes under the world, which could not tell an NTS request
			// from a plain one in time. Every poll still runs NTS-KE when it
			// must, spends a cookie and waits its time out.
			w.silent = c.policy
			// The same list under two host names for server 0: every swap
			// that is taken wipes its peer and puts a new server in the slot.
			lists := [2][]Server{}
			for k, host := range []string{"x1.test", "x2.test"} {
				for i, s := range w.servers {
					sv := honestServer(s)
					if i == 0 {
						sv.Host = host
					}
					lists[k] = append(lists[k], sv)
				}
			}
			protos := []Protocol{ProtocolNTS, ProtocolNTS}
			if PlainSupported() {
				protos[1] = ProtocolNTP
			}
			call := func(k int) error {
				switch {
				case c.policy && c.binding:
					return core.SetPolicy(protos[k%2], 100*time.Millisecond, time.Duration(100+k%2)*time.Millisecond, coarse, local)
				case c.policy:
					return core.setPolicy(protos[k%2], 100*time.Millisecond, time.Duration(100+k%2)*time.Millisecond, coarse, local)
				case c.binding:
					return core.SetServers(lists[k%2], coarse, local)
				}
				return core.setServers(lists[k%2], coarse, local)
			}

			// One count for both goroutines: a poll is open from opened to
			// closed, a call lasts from before to after.
			var seq, opened, closed atomic.Int64
			w.onOpen = func() {
				opened.Store(seq.Add(1))
				time.Sleep(20 * time.Microsecond) // room for a call to come in, if one could
			}
			w.onClose = func() { closed.Store(seq.Add(1)) }
			var stop atomic.Bool
			var taken, busy, during atomic.Int64
			var unexpected atomic.Pointer[string]
			done := make(chan struct{})
			go func() {
				defer close(done)
				for k := 0; !stop.Load(); k++ {
					before := seq.Add(1)
					err := call(k)
					after := seq.Add(1)
					switch {
					case err == nil:
						taken.Add(1)
						// The poll that was open before the call began: still
						// open (its close not yet counted), or closed only
						// after the call returned.
						if po, pc := opened.Load(), closed.Load(); po != 0 && po < before && (pc < po || pc > after) {
							during.Add(1)
						}
					case errors.Is(err, ErrBusy):
						busy.Add(1)
					default:
						s := err.Error()
						unexpected.CompareAndSwap(nil, &s)
					}
				}
			}()
			polls, refused := 0, 0
			most := 2000
			if testing.Short() {
				most = 300
			}
			deadline := time.Now().Add(20 * time.Second)
			// At least `most` polls that ran, and on until both outcomes of a
			// call were seen (a slow machine, one CPU), or the time is up.
			for (polls-refused < most || taken.Load() == 0 || busy.Load() == 0) && time.Now().Before(deadline) && during.Load() == 0 {
				ps, err := core.Poll(0, coarse, local)
				polls++
				if ps.Cookies < 0 || ps.Cookies > MaxCookies {
					t.Errorf("poll %d: %d cookies in the jar", polls, ps.Cookies)
					break
				}
				if errors.Is(err, ErrBusy) {
					// The core's gate was held by a call: nothing was done.
					refused++
					if c.binding {
						t.Errorf("poll %d: refused as busy through the binding, which makes a poll wait", polls)
						break
					}
				}
				if w.failed != nil {
					t.Errorf("poll %d: %v", polls, w.failed)
					break
				}
				runtime.Gosched()
			}
			stop.Store(true)
			<-done
			t.Logf("%d polls (%d refused as busy); calls: %d taken, %d refused as busy, %d taken during a poll", polls, refused, taken.Load(), busy.Load(), during.Load())
			if s := unexpected.Load(); s != nil {
				t.Fatalf("a configuration call failed: %s", *s)
			}
			if during.Load() != 0 {
				t.Fatalf("%d configuration calls were taken while a poll was under way", during.Load())
			}
			if taken.Load() == 0 || busy.Load() == 0 {
				t.Fatalf("the two never met: %d calls taken, %d refused as busy", taken.Load(), busy.Load())
			}
			// The core is whole: a round forms a quorum again.
			w.onOpen, w.onClose, w.silent = nil, nil, false
			if c.policy {
				if err := core.SetPolicy(ProtocolNTS, 100*time.Millisecond, 100*time.Millisecond, coarse, local); err != nil {
					t.Fatal(err)
				}
			}
			w.list = nil
			if err := core.SetServers(lists[0], w.coarseNow(), w.now); err != nil {
				t.Fatal(err)
			}
			w.now += int64(honestMaxPoll)
			for i := range w.servers {
				if _, err := w.poll(core, i); err != nil {
					t.Fatalf("after the race, peer %d: %v", i, err)
				}
			}
			if err := core.Combine(w.coarseNow(), w.now); err != nil {
				t.Fatalf("after the race: %v", err)
			}
			if tm, bound, err := core.Bounded(); err != nil || !within(tm, bound, w.trueNow()) {
				t.Fatalf("after the race: %v %v %v", tm, bound, err)
			}
		})
	}
}

// The other order, without a race: a poll that comes in while a
// configuration call is at work (here from the clock reading the call
// takes after it has wiped what goes, the binding's own lock left out) is
// refused as busy and touches nothing.
func TestPollDuringAConfigurationCallIsBusy(t *testing.T) {
	w, core := newHonestCore(t, 4, func(c *Config) { c.StartWait, c.Capacity = time.Minute, 4 })
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	was := core.Peer(1)
	var inner []error
	during := func() {
		w.onMono = nil
		_, err := core.Poll(1, time.Unix(0, w.coarse), w.coarseLocal)
		inner = append(inner, err)
	}
	// Server 0 leaves: it was a member, so the quorum forms again.
	w.onMono = during
	var list []Server
	for _, s := range w.servers[1:] {
		list = append(list, honestServer(s))
	}
	if err := core.setServers(list, w.coarseNow(), w.now); err != nil {
		t.Fatal(err)
	}
	// Bounds under every sample: all of them leave, and the quorum with them.
	w.onMono = during
	if err := core.setPolicy(ProtocolNTS, 500*time.Microsecond, 500*time.Microsecond, w.coarseNow(), w.now); err != nil {
		t.Fatal(err)
	}
	if len(inner) != 2 || !errors.Is(inner[0], ErrBusy) || !errors.Is(inner[1], ErrBusy) {
		t.Fatalf("polls during SetServers and SetPolicy: %v", inner)
	}
	// Peer 0 of the new list is the server that was peer 1; the refused
	// polls sent nothing and spent no cookie.
	if ps := core.Peer(0); ps.Stats.Queries != was.Stats.Queries || ps.Cookies != was.Cookies || ps.Stats.KEOK != was.Stats.KEOK {
		t.Fatalf("a refused poll did something: %+v, was %+v", ps, was)
	}
	if st := core.Status(); st.HaveResult || st.Busy || len(st.Peers) != 3 {
		t.Fatalf("after the calls: %+v", st)
	}
}

// Two polls of one server exclude each other too: the second is refused
// as busy and does nothing. Other servers' polls are not held up.
func TestSecondPollOfAPeerIsBusy(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	var inner error
	var was, after PeerStatus
	w.onOpen = func() {
		w.onOpen = nil
		was = core.Peer(0)
		_, inner = core.Poll(0, time.Unix(0, w.coarse), w.coarseLocal)
		after = core.Peer(0)
	}
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(inner, ErrBusy) {
		t.Fatalf("a poll of a peer during its poll: %v", inner)
	}
	if was.Cookies != after.Cookies || was.Stats.Queries != after.Stats.Queries || was.Stats.KEOK != after.Stats.KEOK {
		t.Fatalf("the refused poll did something: %+v, was %+v", after, was)
	}
	if ps := core.Peer(0); ps.Sample == nil || ps.LastErr != nil || ps.Stats.Queries != 1 {
		t.Fatalf("the poll that ran: %+v", ps)
	}
	if _, err := w.poll(core, 0); err != nil {
		t.Fatalf("the next poll: %v", err)
	}
}

// A certificate is never dated before the era pivot. After a configuration
// call left no quorum (as after a refusal, or samples aged out), the core
// dates NTS-KE by the host's coarse reading; one that lies far below the
// time the core has served is raised to that time. A coarse reading above
// it is used as it is, and no coarse reading at all is still no time.
func TestCertificateNeverDatedBeforeThePivot(t *testing.T) {
	w, core := newHonestCore(t, 3, func(c *Config) { c.StartWait = time.Minute })
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	highest, _, err := core.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range w.servers {
		s.rename("other-" + s.op + ".test")
	}
	if err := w.swap(core, w.servers...); err != nil {
		t.Fatal(err)
	}
	st := core.Status()
	if st.HaveResult || st.EraPivot < highest.UnixNano() {
		t.Fatalf("after the swap: %+v, highest %v", st, highest)
	}
	floor := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// A month below the time served, two seconds above the floor.
	w.coarse, w.coarseLocal = floor.Add(2*time.Second).UnixNano(), w.now
	ps, err := core.Poll(0, time.Unix(0, w.coarse), w.coarseLocal)
	if err != nil || w.failed != nil || ps.Stats.KEOK != 1 {
		t.Fatalf("poll with a low coarse reading: %v, %v, %+v", err, w.failed, ps)
	}
	if w.keValidity != st.EraPivot || w.keValidity < highest.UnixNano() {
		t.Fatalf("certificate dated %v; the era pivot is %v, the highest time served %v", time.Unix(0, w.keValidity).UTC(), time.Unix(0, st.EraPivot).UTC(), highest.UTC())
	}
	// Above the pivot the coarse reading dates it, moved to the poll's time.
	w.coarse, w.coarseLocal = st.EraPivot+int64(time.Hour), w.now
	if _, err := core.Poll(1, time.Unix(0, w.coarse), w.coarseLocal); err != nil || w.failed != nil {
		t.Fatalf("poll with a coarse reading above the pivot: %v, %v", err, w.failed)
	}
	if d := w.keValidity - (st.EraPivot + int64(time.Hour)); d < 0 || d > int64(time.Second) {
		t.Fatalf("certificate dated %v with a coarse reading an hour above the pivot %v", time.Unix(0, w.keValidity).UTC(), time.Unix(0, st.EraPivot).UTC())
	}
	// No coarse reading: no key exchange, though the pivot is a time.
	kes := w.kes
	if _, err := core.Poll(2, time.Time{}, w.now); !errors.Is(err, ErrNoTrustedTime) || w.kes != kes {
		t.Fatalf("poll without a coarse reading: %v, %d key exchanges", err, w.kes-kes)
	}
	w.now += int64(honestMaxPoll) // past the wait after the failure
	// (The core moves the reading on to its own clock reading, a microsecond later.)
	if _, err := core.Poll(2, floor, w.now+int64(time.Microsecond)); !errors.Is(err, ErrNoTrustedTime) || w.kes != kes {
		t.Fatalf("poll with the coarse reading at the floor: %v, %d key exchanges", err, w.kes-kes)
	}
}

// A host operation that returns a code the core does not expect of it (a
// host written in C can: the Go binding's own hosts cannot) fails as a
// host operation and nothing else. The core's own codes do not pass for
// its findings: "wide answer" without an answer does not end a loss
// streak or clear a DENY, "Kiss-o'-Death" counts no kiss.
func TestHostCodesTheCoreDoesNotExpect(t *testing.T) {
	ops := map[int]string{1: "key exchange", 2: "open", 3: "send", 4: "receive"}
	for _, code := range []int{codeSampleWide, codeKiss, codeBusy, codeNotDue, codeNoQuorum, codeHostRandom, 9999, -3} {
		for op := 1; op <= 4; op++ {
			what := fmt.Sprintf("code %d from the %s", code, ops[op])
			w, core := newHonestCore(t, 3, nil)
			if op != 1 {
				// A sample, then two lost queries: a streak of two.
				if _, err := w.poll(core, 0); err != nil {
					t.Fatal(err)
				}
				w.drop = 2
				for k := 0; k < 2; k++ {
					w.now += int64(honestInterval)
					w.poll(core, 0)
				}
			}
			was := core.Peer(0)
			w.rawCode[op] = code
			w.now += int64(honestInterval)
			ps, err := w.poll(core, 0)
			var e *Error
			if !errors.As(err, &e) || e.Code != codeHost || !errors.Is(err, ErrHost) || e.Kiss != "" {
				t.Fatalf("%s: the poll gave %v", what, err)
			}
			if ps.Stats.Wide != 0 || len(ps.Stats.Kisses) != 0 || ps.Stats.Samples != was.Stats.Samples || !errors.Is(ps.LastErr, ErrHost) {
				t.Fatalf("%s: %+v", what, ps)
			}
			if op == 1 {
				if ps.Stats.KEFail != 1 || ps.Stats.KEOK != 0 || ps.Stats.Queries != 0 || !ps.NeedKE {
					t.Fatalf("%s: %+v", what, ps)
				}
				continue
			}
			if ps.LostInRow != was.LostInRow+1 || ps.Stats.Errors != was.Stats.Errors+1 || ps.Sample == nil || *ps.Sample != *was.Sample {
				t.Fatalf("%s: the streak or the sample changed: %+v, was %+v", what, ps, was)
			}
		}
	}
	// A DENY obeyed stays until a real answer: the code of a wide answer
	// from the socket does not clear it.
	w, core := newHonestCore(t, 3, nil)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.kiss = "DENY"
	w.now += int64(honestInterval)
	if ps, _ := w.poll(core, 0); ps.Disabled != "DENY" {
		t.Fatalf("after an authentic DENY: %+v", ps)
	}
	w.kiss = ""
	w.rawCode[4] = codeSampleWide
	w.now += int64(honestMaxPoll)
	ps, err := w.poll(core, 0)
	if !errors.Is(err, ErrHost) || ps.Disabled != "DENY" || ps.Stats.Wide != 0 || ps.LostInRow != 1 {
		t.Fatalf("a wide answer's code from the socket after a DENY: %v, %+v", err, ps)
	}
	// The real answer clears it.
	w.rawCode[4] = 0
	w.now += int64(honestMaxPoll)
	if ps, err := w.poll(core, 0); err != nil || ps.Disabled != "" || ps.LostInRow != 0 {
		t.Fatalf("the answer after it: %v, %+v", err, ps)
	}
}
