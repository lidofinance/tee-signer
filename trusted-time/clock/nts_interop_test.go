//go:build nts

package clock

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// TestNTSInteropPublicServers runs the NTS clock against the four public
// operators: one NTS-KE and three queries per server, 33 s apart (RFC 5905
// MINPOLL is 16 s), so about 70 s and 4 x (1 TLS session + 3 UDP queries).
// It runs only with NTS_INTEROP=1 (from trusted-time: NTS_INTEROP=1 go test
// -tags nts -run TestNTSInteropPublicServers ./clock): it needs the network
// and is not part of the offline tests.
//
// The coarse clock is the host clock here: the HTTPS-date sources would be
// other hosts, which this test does not contact. So the 2 s check compares
// with the host clock.
func TestNTSInteropPublicServers(t *testing.T) {
	if os.Getenv("NTS_INTEROP") != "1" {
		t.Skip("NTS_INTEROP is not 1")
	}
	n := &NTS{Coarse: &coarseClock{}, Interval: 33 * time.Second}
	for _, s := range nts.PublicServers {
		pool, err := nts.RootPool(s.Roots)
		if err != nil {
			t.Fatal(err)
		}
		n.Servers = append(n.Servers, NTSServer{Host: s.Host, Operator: s.Operator, Roots: pool})
	}

	type sampleRow struct {
		Round          int
		Operator       string
		Error          string  `json:",omitempty"`
		DelayMs        float64 `json:",omitempty"`
		BoundMs        float64 `json:",omitempty"`
		OffsetHostMs   float64 `json:",omitempty"`
		RootDelayMs    float64 `json:",omitempty"`
		RootDispMs     float64 `json:",omitempty"`
		Stratum        int     `json:",omitempty"`
		Precision      int     `json:",omitempty"`
		CookiesHeld    int     `json:",omitempty"`
		CookiesInReply int     `json:",omitempty"`
		// RawDriftPPM: this server's offset to CLOCK_MONOTONIC_RAW since its
		// previous sample, per elapsed time: the local clock's rate error.
		RawDriftPPM float64 `json:",omitempty"`
	}
	type roundRow struct {
		Round         int
		Error         string `json:",omitempty"`
		Members       []string
		QuorumBoundMs float64
		NowBoundMs    float64
		NowFromHostMs float64
		QuorumWidthMs float64
		DriftPPM      float64 // from the clock's own check, over its baseline
		// GoMonoVsRawPPM: Go's monotonic clock (CLOCK_MONOTONIC) against
		// CLOCK_MONOTONIC_RAW since the previous round.
		GoMonoVsRawPPM float64
	}
	var samples []sampleRow
	var rounds []roundRow
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	prev := map[string]*nts.Sample{}
	var prevRaw int64
	var prevGo time.Time

	start := time.Now()
	for round := 1; round <= 3; round++ {
		if round > 1 {
			time.Sleep(time.Until(start.Add(time.Duration(round-1) * 34 * time.Second)))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := n.Refresh(ctx)
		cancel()
		st := n.Status()
		ops := make([]string, 0, len(st.Peers))
		for op := range st.Peers {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			p := st.Peers[op]
			row := sampleRow{Round: round, Operator: op, Error: p.LastErr}
			if p.Sample != nil && p.LastErr == "" {
				s := p.Sample
				row.DelayMs, row.BoundMs, row.OffsetHostMs = ms(s.Delay), ms(s.Bound), ms(p.Stats.LastOffsetFromHost)
				row.RootDelayMs, row.RootDispMs = ms(s.RootDelay), ms(s.RootDispersion)
				row.Stratum, row.Precision, row.CookiesHeld, row.CookiesInReply = s.Stratum, s.Precision, s.CookiesHeld, s.CookiesReceived
				if q := prev[op]; q != nil && s.T4 > q.T4 {
					row.RawDriftPPM = float64(s.Offset-q.Offset) / float64(s.T4-q.T4) * 1e6
				}
				prev[op] = s
			}
			samples = append(samples, row)
			t.Logf("round %d %-10s %-20s KE ok %d fail %d (%v, %d cookies) | delay %.3f ms bound %.3f ms offset-vs-host %+.3f ms stratum %d prec %d rootdelay %.3f rootdisp %.3f | cookies %d (+%d) | raw clock drift %+.1f ppm %s",
				round, op, p.Host, p.Stats.KEOK, p.Stats.KEFail, p.Stats.LastKE.Round(time.Millisecond), p.Stats.CookiesAfterKE,
				row.DelayMs, row.BoundMs, row.OffsetHostMs, row.Stratum, row.Precision, row.RootDelayMs, row.RootDispMs,
				row.CookiesHeld, row.CookiesInReply, row.RawDriftPPM, p.LastErr)
		}
		rr := roundRow{Round: round, Members: st.Members, QuorumBoundMs: ms(st.Bound), QuorumWidthMs: ms(time.Duration(st.Hi - st.Lo)), DriftPPM: st.DriftPPM}
		raw, goNow := nts.Monotonic(), time.Now()
		if round > 1 {
			rawD, goD := float64(raw-prevRaw), float64(goNow.Sub(prevGo))
			rr.GoMonoVsRawPPM = (goD - rawD) / rawD * 1e6
		}
		prevRaw, prevGo = raw, goNow
		if err != nil {
			rr.Error = err.Error()
		}
		if now, b, berr := n.Bounded(); berr == nil {
			rr.NowBoundMs, rr.NowFromHostMs = ms(b), ms(time.Until(now))
		} else if rr.Error == "" {
			rr.Error = berr.Error()
		}
		rounds = append(rounds, rr)
		t.Logf("round %d quorum: members %v bound %.3f ms (width %.3f ms), Now bound %.3f ms, Now - host %+.3f ms, quorum drift %+.1f ppm, CLOCK_MONOTONIC vs RAW %+.0f ppm, err %v",
			round, rr.Members, rr.QuorumBoundMs, rr.QuorumWidthMs, rr.NowBoundMs, rr.NowFromHostMs, rr.DriftPPM, rr.GoMonoVsRawPPM, rr.Error)
	}
	if out := os.Getenv("NTS_INTEROP_OUT"); out != "" {
		b, _ := json.MarshalIndent(map[string]any{"samples": samples, "rounds": rounds, "library": nts.Version()}, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st := n.Status()
	for op, p := range st.Peers {
		if p.Stats.KEOK == 0 {
			t.Errorf("%s (%s): no NTS-KE: %s", op, p.Host, p.LastErr)
		} else if p.Stats.Samples == 0 {
			t.Errorf("%s (%s): no sample: %s", op, p.Host, p.LastErr)
		}
	}
	if last := rounds[len(rounds)-1]; last.Error != "" {
		t.Errorf("last round: %s", last.Error)
	}
	fmt.Fprintf(os.Stderr, "interop took %v\n", time.Since(start).Round(time.Second))
}
