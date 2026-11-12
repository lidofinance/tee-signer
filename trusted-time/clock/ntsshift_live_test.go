//go:build nts

package clock

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// TestNTSShiftLive runs the shift schedule against public NTS servers,
// the catalog's and candidates for it, for NTS_SHIFT_LIVE (a duration, for
// example 15m). It needs the network, and it is a test only:
//   - the coarse clock is the host clock, as in TestNTSInteropPublicServers;
//   - operators whose roots trusted-time/nts does not pin (BEV, FER, Meta,
//     Paris Observatory) use the system roots of the machine;
//   - any.time.nl is left out: it is TimeNL, the operator of
//     ntppool1.time.nl, and the quorum takes one server per operator.
//
// It sets the seed 3 minutes in (SetScheduleSeed), and resolves the NTP
// host at NTS-KE although it dials through its own Dial.
//
// It logs every contact (each dial, by operator), the counts of the
// schedule, and every second Now failed; it fails if an operator is
// contacted twice within NTSShiftMinGap.
func TestNTSShiftLive(t *testing.T) {
	dur, err := time.ParseDuration(os.Getenv("NTS_SHIFT_LIVE"))
	if err != nil {
		t.Skip("NTS_SHIFT_LIVE is not a duration")
	}
	pinned := func(files ...string) *x509.CertPool {
		p, err := nts.RootPool(files)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	isrg := pinned("isrg-root-x1.pem", "isrg-root-x2.pem")
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	servers := []NTSServer{
		{Host: "nts.netnod.se", Operator: "netnod", Roots: isrg},
		{Host: "ptbtime1.ptb.de", Operator: "ptb", Roots: isrg},
		{Host: "bevtime1.metrologie.at", Operator: "bev", Roots: system},
		{Host: "ntppool1.time.nl", Operator: "time.nl", Roots: isrg},
		{Host: "nts1.ntp.hr", Operator: "fer", Roots: system},
		{Host: "nts.meta.com", Operator: "meta", Roots: system},
		{Host: "ntp.obspm.fr", Operator: "obspm", Roots: system},
		{Host: "time.cloudflare.com", Operator: "cloudflare", Roots: pinned("sslcom-root-ecc.pem")},
	}

	// Every dial, by address. NTS-KE dials host:4460; NTP dials the address
	// NTS-KE named, which Status gives per operator at the end.
	type dial struct {
		at        time.Time
		net, addr string
	}
	var mu sync.Mutex
	var dials []dial
	var d net.Dialer
	record := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, dial{time.Now(), network, addr})
		mu.Unlock()
		return d.DialContext(ctx, network, addr)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// No seed at start, as when the key comes later: every operator is
	// active until SetScheduleSeed, 3 minutes in.
	n := &NTS{Servers: servers, Coarse: &coarseClock{}, Dial: record, Log: log, Shifts: true, resolveAnyDial: true}
	n.init()
	t.Logf("start delay %v, grid phase %d ticks (no seed yet)", n.shifts.startDelay, n.shifts.phase)
	seedAt := 3 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	start := time.Now()
	// As the runner does: Refresh until the first quorum, then Run.
	for n.Refresh(ctx) != nil && ctx.Err() == nil {
		time.Sleep(5 * time.Second)
	}
	t.Logf("first quorum after %v: %v", time.Since(start).Round(time.Millisecond), n.NTSSummary().Members)
	go n.Run(ctx)
	var failed []string
	var prevActives []string
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		<-tick.C
		if seedAt > 0 && time.Since(start) >= seedAt {
			seedAt = 0
			n.SetScheduleSeed(fmt.Appendf(nil, "live-%d", time.Now().UnixNano()))
			n.shifts.mu.Lock()
			order := make([]string, len(n.shifts.order))
			for i, op := range n.shifts.order {
				order[i] = servers[op].Operator
			}
			phase, next := n.shifts.phase, n.shifts.shiftLen-(n.shifts.q+n.shifts.shift0)%n.shifts.shiftLen
			n.shifts.mu.Unlock()
			t.Logf("%v: seed set; order %v, grid phase %d ticks, next handover in %d ticks", time.Since(start).Round(time.Second), order, phase, next)
		}
		if _, err := n.Now(); err != nil {
			failed = append(failed, fmt.Sprintf("%v: %v", time.Since(start).Round(time.Second), err))
		}
		if a := n.NTSSummary().Actives; !slices.Equal(a, prevActives) {
			t.Logf("%v: actives %v", time.Since(start).Round(time.Second), a)
			prevActives = a
		}
	}
	cancel()
	st := n.Status()
	sum := n.NTSSummary()
	hours := time.Since(start).Hours()

	// Dials to contacts per operator: a KE dial and the NTP dial right after
	// it are one contact.
	byAddr := map[string]string{}
	for _, s := range servers {
		byAddr[net.JoinHostPort(s.Host, "4460")] = s.Operator
		if p, ok := st.Peers[s.Operator]; ok && p.NTPAddr != "" {
			byAddr[p.NTPAddr] = s.Operator
		}
	}
	contacts := map[string][]time.Time{}
	for _, x := range dials {
		op, ok := byAddr[x.addr]
		if !ok {
			op = "?" + x.addr
		}
		cs := contacts[op]
		if len(cs) > 0 && x.at.Sub(cs[len(cs)-1]) < 10*time.Second {
			continue
		}
		contacts[op] = append(cs, x.at)
	}
	var lines []string
	minGap := time.Duration(1 << 62)
	for _, s := range servers {
		cs := contacts[s.Operator]
		gap := time.Duration(0)
		for i := 1; i < len(cs); i++ {
			g := cs[i].Sub(cs[i-1])
			if gap == 0 || g < gap {
				gap = g
			}
		}
		if gap > 0 {
			minGap = min(minGap, gap)
		}
		c := sum.Operators[s.Operator]
		ps := st.Peers[s.Operator]
		lines = append(lines, fmt.Sprintf("| %s | %d | %.1f | %d | %d | %d | %d | %d | %d | %d | %v | %d/%d | %v |", s.Operator, len(cs),
			float64(len(cs))/hours, c.Queries, c.Answers, c.Losses, c.Fallbacks, c.Bursts, c.Handovers, c.FailedHandovers,
			gap.Round(time.Millisecond), ps.Stats.KEOK, ps.Stats.KEFail, ps.LastErr))
	}
	t.Logf("\n| Operator | Contacts | Contacts/h | Queries | Answers | Losses | Fallbacks | Bursts | Handovers | Failed handovers | Min gap | KE ok/fail | Last error |\n"+
		"| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n%s", strings.Join(lines, "\n"))
	for op := range contacts {
		if strings.HasPrefix(op, "?") {
			t.Logf("dials to an address of no operator: %s (%d)", op, len(contacts[op]))
		}
	}
	t.Logf("ran %v; Now failed %d s of %d; actives at the end %v; quorum %v bound %v", time.Since(start).Round(time.Second), len(failed),
		int(time.Since(start).Seconds()), sum.Actives, sum.Members, sum.BoundNow)
	for _, f := range failed {
		t.Log("Now failed at " + f)
	}
	if minGap < NTSShiftMinGap {
		t.Errorf("an operator was contacted twice %v apart", minGap)
	}
}
