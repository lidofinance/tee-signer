//go:build nts

package clock

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// newPlainServers starts one plain NTP server per operator (no NTS-KE).
func newPlainServers(t *testing.T, opts map[string]ntstest.NTPOptions, order ...string) ([]NTSServer, []*ntstest.NTPServer) {
	t.Helper()
	var srvs []NTSServer
	var ntps []*ntstest.NTPServer
	for _, op := range order {
		s, err := ntstest.StartPlainNTP(opt(opts[op]))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		// Host has no NTS-KE server behind it: a key exchange would fail.
		srvs = append(srvs, NTSServer{Host: "nts-" + op + ".invalid", Operator: op, NTPAddr: s.Addr})
		ntps = append(ntps, s)
	}
	return srvs, ntps
}

func newPlainNTS(srvs []NTSServer, coarse *coarseClock) *NTS {
	return &NTS{Protocol: ProtocolNTP, Servers: srvs, Coarse: coarse, Interval: 50 * time.Millisecond, minPoll: 10 * time.Millisecond, StartDelay: -1}
}

func TestPlainNTPClockQuorum(t *testing.T) {
	srvs, ntps := newPlainServers(t, map[string]ntstest.NTPOptions{"liar": {Offset: 5 * time.Second}}, "a", "b", "c", "liar")
	var logs bytes.Buffer
	n := newPlainNTS(srvs, &coarseClock{})
	n.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, bound, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	if d := testClock().Sub(got); d.Abs() > bound+5*time.Millisecond || bound > NTSMaxBound {
		t.Fatalf("one server 5 s ahead moved the time by %v (bound %v)", d, bound)
	}
	if n.Source() != "ntp(a,b,c,liar)" || !n.Trusted() {
		t.Fatalf("source %s", n.Source())
	}
	st := n.Status()
	if st.Protocol != ProtocolNTP || len(st.Members) != 4 {
		t.Fatalf("status %+v", st)
	}
	sum := n.NTSSummary()
	if sum.Protocol != ProtocolNTP || !sum.Quorum {
		t.Fatalf("summary %+v", sum)
	}
	for i, p := range sum.Peers {
		if p.KEOK != 0 || p.KEFail != 0 || p.Queries != 1 || p.Answers != 1 {
			t.Fatalf("peer %+v: plain NTP runs no NTS-KE", p)
		}
		if st.Peers[p.Operator].NTPAddr != ntps[i].Addr {
			t.Fatalf("peer %s asked %s, want %s", p.Operator, st.Peers[p.Operator].NTPAddr, ntps[i].Addr)
		}
	}
	// Every log line says the clock is plain NTP.
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if !strings.Contains(l, "protocol=ntp-unauthenticated") {
			t.Fatalf("log line without the protocol: %s", l)
		}
	}
	if logs.Len() == 0 {
		t.Fatal("no log line")
	}
}

// Two of three wrong give no time; the quorum rule is the same as for NTS.
func TestPlainNTPClockQuorumRule(t *testing.T) {
	srvs, _ := newPlainServers(t, map[string]ntstest.NTPOptions{"b": {Offset: 5 * time.Second}, "c": {Offset: 10 * time.Second}}, "a", "b", "c")
	n := newPlainNTS(srvs, &coarseClock{})
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("got %v", err)
	}
	// Two answers are too few: at least 3 must agree.
	srvs, _ = newPlainServers(t, map[string]ntstest.NTPOptions{"c": {Drop: true}}, "a", "b", "c")
	n = newPlainNTS(srvs, &coarseClock{})
	n.queryTimeout = 200 * time.Millisecond
	if err := refresh(t, n); err == nil {
		t.Fatal("a quorum of two")
	}
}

// The coarse check bounds what forged answers can do: servers that all
// agree on a time 40 s ahead are refused.
func TestPlainNTPClockCoarseCheck(t *testing.T) {
	ahead := ntstest.NTPOptions{Offset: 40 * time.Second}
	srvs, _ := newPlainServers(t, map[string]ntstest.NTPOptions{"a": ahead, "b": ahead, "c": ahead}, "a", "b", "c")
	n := newPlainNTS(srvs, &coarseClock{})
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "coarse clock") {
		t.Fatalf("got %v", err)
	}
	if _, err := n.Now(); err == nil {
		t.Fatal("time 40 s off the coarse clock")
	}
}

// RATE backs off and DENY stops a server, as with NTS.
func TestPlainNTPClockKiss(t *testing.T) {
	srvs, _ := newPlainServers(t, map[string]ntstest.NTPOptions{"rate": {Kiss: "RATE"}, "deny": {Kiss: "DENY"}}, "a", "b", "c", "rate", "deny")
	n := newPlainNTS(srvs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	st := n.Status()
	if st.Peers["rate"].Stats.Kisses["RATE"] != 1 || st.Peers["rate"].Poll <= n.interval() || st.Peers["deny"].Disabled != "DENY" {
		t.Fatalf("status %+v", st.Peers)
	}
}

// An unknown protocol is refused, and NTS stays the default.
func TestNTSClockProtocol(t *testing.T) {
	n := &NTS{Protocol: "sntp", Coarse: &coarseClock{}}
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), `protocol "sntp"`) {
		t.Fatalf("got %v", err)
	}
	d := &NTS{Coarse: &coarseClock{}, Servers: []NTSServer{{Operator: "a"}}}
	if d.Source() != "nts(a)" || d.NTSSummary().Protocol != ProtocolNTS {
		t.Fatalf("default: %s %v", d.Source(), d.NTSSummary().Protocol)
	}
	for in, want := range map[string]Protocol{"": ProtocolNTS, "nts": ProtocolNTS, "ntp": ProtocolNTP} {
		if p, err := ParseProtocol(in); err != nil || p != want {
			t.Fatalf("ParseProtocol(%q) = %v, %v", in, p, err)
		}
	}
	for _, in := range []string{"NTP", "sntp", " ntp"} {
		if _, err := ParseProtocol(in); err == nil {
			t.Fatalf("ParseProtocol(%q) accepted", in)
		}
	}
}
