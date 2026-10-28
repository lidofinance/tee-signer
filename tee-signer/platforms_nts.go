//go:build nts

package main

// The NTS clock in a runner built with -tags nts. main.go is not changed, so
// the default runners stay byte for byte the same. This file's name sorts
// after platform_*.go, so its init runs after theirs and can wrap the
// platforms they registered. With -nts-clock (or RUNNER_NTS_CLOCK=1) every
// platform gets the NTS clock (runner/clock.NTS) in place of its own. The
// cloud images set the flags in their measured command (the enclave image,
// the CCE policy, the Confidential Space image), so the host cannot turn the
// clock off; the variables are for local runs. A
// flag that is set wins over its variable.
//
//	-nts-clock                 RUNNER_NTS_CLOCK=1            turn it on
//	-nts-coarse-urls a,b,c     RUNNER_NTS_COARSE_URLS=a,b,c  HTTPS-date URLs of the coarse check (required, 3 or more);
//	                                                         {region} stands for the platform option region (Nitro,
//	                                                         from the setup), so one image serves every region
//	-nts-wait 90s              RUNNER_NTS_WAIT=90s           how long start-up waits for the first quorum
//	-nts-max-bound 100ms       RUNNER_NTS_MAX_BOUND=100ms    Now fails above this error bound
//	                           RUNNER_NTS_STATUS_EVERY=60s   period of the "nts: status" log line
//
// The clock dials through the platform (platform.Platform.Dial): on Nitro,
// NTS-KE goes through vsock-proxy routes and NTP through the parent's UDP
// relay. With the NTS clock on, -clock must be platform (the default): the
// runner refuses -clock https-date, which would replace the NTS clock.
//
// If no quorum forms in the wait the runner starts anyway and every signing
// request is refused until one forms (the clock's Now fails).

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

var (
	ntsClockFlag    = flag.Bool("nts-clock", false, "use the NTS clock (RFC 8915, four public operators) on every platform; also RUNNER_NTS_CLOCK=1")
	ntsCoarseFlag   = flag.String("nts-coarse-urls", "", "comma-separated https URLs (3 or more) of the NTS clock's coarse check; default RUNNER_NTS_COARSE_URLS")
	ntsWaitFlag     = flag.Duration("nts-wait", 0, "how long start-up waits for the first NTS quorum; 0 = RUNNER_NTS_WAIT or 90s")
	ntsMaxBoundFlag = flag.Duration("nts-max-bound", 0, "signing fails above this NTS error bound; 0 = RUNNER_NTS_MAX_BOUND or 100ms")
)

func init() {
	for name, f := range platforms {
		platforms[name] = ntsSwitch(f)
	}
}

// ntsOn: the flag or the variable asks for the NTS clock.
func ntsOn() bool { return *ntsClockFlag || os.Getenv("RUNNER_NTS_CLOCK") == "1" }

// ntsSwitch runs f, and adds the NTS clock when it is on. The flags are
// parsed by then: main calls the platform after flag.Parse.
func ntsSwitch(f platformFunc) platformFunc {
	return func(o platform.Options) (*platform.Platform, error) {
		if !ntsOn() {
			return f(o)
		}
		if c := flag.Lookup("clock"); c != nil && c.Value.String() != "platform" {
			return nil, fmt.Errorf("nts clock: -clock %s would replace it; leave -clock out (platform) with -nts-clock", c.Value.String())
		}
		return withNTSClock(f)(o)
	}
}

// ntsDuration is the flag's value if set, else the variable's, else def.
func ntsDuration(f time.Duration, name string, def time.Duration) (time.Duration, error) {
	if f < 0 {
		return 0, fmt.Errorf("-%s: want a positive duration", strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(name, "RUNNER_"), "_", "-")))
	}
	if f > 0 {
		return f, nil
	}
	return envDuration(name, def)
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s=%q: want a positive duration", name, v)
	}
	return d, nil
}

func withNTSClock(f platformFunc) platformFunc {
	return func(o platform.Options) (*platform.Platform, error) {
		p, err := f(o)
		if err != nil {
			return nil, err
		}
		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		var dial nts.DialFunc
		if p.Dial != nil {
			dial = p.Dial
		}
		n, err := startNTSClock(context.Background(), p.HTTPClient, dial, o.Param("region", ""), log)
		if err != nil {
			if p.Close != nil {
				_ = p.Close()
			}
			return nil, err
		}
		p.Clock = n
		return p, nil
	}
}

// newNTSClock builds the NTS clock over nts.PublicServers (a debug build
// can name test servers, nts_servers_debug.go) with an HTTPS-date quorum
// (majority of the URLs) as its coarse clock. dial nil: the default dialer.
// region replaces {region} in the URLs.
func newNTSClock(client *http.Client, dial nts.DialFunc, region string, log *slog.Logger) (*clock.NTS, *clock.Anchored, error) {
	urls, err := ntsCoarseURLs(region)
	if err != nil {
		return nil, nil, err
	}
	q := &clock.Quorum{Min: len(urls)/2 + 1}
	for _, u := range urls {
		q.Sources = append(q.Sources, &clock.HTTPSDate{URL: u, Client: client})
	}
	// The coarse clock ages its reading on CLOCK_MONOTONIC_RAW, the NTS
	// clock's local time, so the coarse check compares two times aged on
	// the same counter. Go's monotonic clock (CLOCK_MONOTONIC) is slewed
	// by timesyncd in WSL, 39,000 to 56,000 ppm slow: 15 to 40 s between
	// readings put the coarse time up to 2.2 s behind. Only this coarse
	// clock changes; -clock https-date in main.go stays as in the default
	// build.
	coarse := &clock.Anchored{Src: q, Interval: clock.DefaultInterval, TrustedSrc: true, Local: rawLocal}
	maxBound, err := ntsDuration(*ntsMaxBoundFlag, "RUNNER_NTS_MAX_BOUND", clock.NTSMaxBound)
	if err != nil {
		return nil, nil, err
	}
	n := &clock.NTS{Coarse: coarse, MaxBound: maxBound, Log: log, Dial: dial}
	if n.Servers, err = ntsServers(); err != nil {
		return nil, nil, err
	}
	return n, coarse, nil
}

// ntsCoarseURLs reads -nts-coarse-urls (or RUNNER_NTS_COARSE_URLS) and puts
// region in place of {region}. The Nitro image names its coarse-time hosts
// kms.{region}.amazonaws.com and sts.{region}.amazonaws.com: the runner
// fills in the region of the setup and nothing else.
func ntsCoarseURLs(region string) ([]string, error) {
	list := *ntsCoarseFlag
	if list == "" {
		list = os.Getenv("RUNNER_NTS_COARSE_URLS")
	}
	var urls []string
	for _, u := range strings.Split(list, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		if strings.Contains(u, "{region}") {
			if region == "" {
				return nil, fmt.Errorf("nts clock: coarse URL %s names {region}, and the platform has no region option", u)
			}
			u = strings.ReplaceAll(u, "{region}", region)
		}
		urls = append(urls, u)
	}
	if len(urls) < 3 {
		return nil, errors.New("nts clock: -nts-coarse-urls (RUNNER_NTS_COARSE_URLS) needs 3 or more https URLs for the coarse check")
	}
	return urls, nil
}

// publicNTSServers are nts.PublicServers with their pinned roots.
func publicNTSServers() ([]clock.NTSServer, error) {
	var out []clock.NTSServer
	for _, s := range nts.PublicServers {
		pool, err := nts.RootPool(s.Roots)
		if err != nil {
			return nil, err
		}
		out = append(out, clock.NTSServer{Host: s.Host, Operator: s.Operator, Roots: pool})
	}
	return out, nil
}

// rawLocal is nts.Monotonic as a time.Time for Anchored.Local. Anchored only
// subtracts two such values, so the epoch does not matter.
func rawLocal() time.Time { return time.Unix(0, nts.Monotonic()) }

// startNTSClock takes the first coarse reading and the first quorum (up to
// -nts-wait), then keeps both running and logs a status line.
func startNTSClock(ctx context.Context, client *http.Client, dial nts.DialFunc, region string, log *slog.Logger) (*clock.NTS, error) {
	wait, err := ntsDuration(*ntsWaitFlag, "RUNNER_NTS_WAIT", 90*time.Second)
	if err != nil {
		return nil, err
	}
	every, err := envDuration("RUNNER_NTS_STATUS_EVERY", time.Minute)
	if err != nil {
		return nil, err
	}
	n, coarse, err := newNTSClock(client, dial, region, log)
	if err != nil {
		return nil, err
	}
	log.Info("nts: clock starting", "library", nts.Version(), "servers", n.Source(), "max_bound", n.MaxBound, "wait", wait)
	deadline := time.Now().Add(wait)
	for {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = coarse.Refresh(rctx)
		cancel()
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Error("nts: no coarse (HTTPS-date) reading at start", "err", err)
	}
	go coarse.Run(ctx)
	for n.Refresh(ctx) != nil {
		if time.Now().After(deadline) {
			log.Error("nts: no quorum at start; signing is refused until one forms", "waited", wait, "status", statusLine(n.Status()))
			break
		}
		time.Sleep(5 * time.Second)
	}
	go n.Run(ctx)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			st := n.Status()
			log.Info("nts: status", statusAttrs(st)...)
		}
	}()
	log.Info("nts: status", statusAttrs(n.Status())...)
	return n, nil
}

// statusAttrs are the fields of the "nts: status" line. drift_ppm,
// drift_err_ppm and drift_baseline are clock.NTSStatus's DriftPPM,
// DriftErrPPM and DriftBaseline: a quorum is refused, and rho_violations
// counts it, when |drift_ppm| > 500 + drift_err_ppm. coarse_diff is the NTS
// time minus the coarse (HTTPS-date) clock at the last quorum.
func statusAttrs(st clock.NTSStatus) []any {
	return []any{
		"bound_now", st.BoundNow, "bound_at_quorum", st.Bound, "quorum_age", st.AgeOfQuorum.Round(time.Millisecond),
		"offset_from_host", st.OffsetFromHost, "members", strings.Join(st.Members, ","), "refusals", st.Refusals,
		"drift_ppm", int64(math.Round(st.DriftPPM)), "drift_err_ppm", int64(math.Ceil(st.DriftErrPPM)),
		"drift_baseline", st.DriftBaseline.Round(time.Second), "rho_violations", st.RhoViolations,
		"coarse_diff", st.CoarseDiff.Round(time.Millisecond),
		"peers", statusLine(st), "last_error", st.LastError,
	}
}

// statusLine is one word per server: operator:samples/queries/ke,
// the poll interval and the kiss codes seen, and "off" when disabled.
func statusLine(st clock.NTSStatus) string {
	ops := make([]string, 0, len(st.Peers))
	for op := range st.Peers {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	var parts []string
	for _, op := range ops {
		p := st.Peers[op]
		s := fmt.Sprintf("%s:%d/%d/ke%d,poll=%v", op, p.Stats.Samples, p.Stats.Queries, p.Stats.KEOK, p.Poll)
		if p.Sample != nil {
			s += fmt.Sprintf(",delay=%v,bound=%v", p.Sample.Delay.Round(time.Microsecond), p.Sample.Bound.Round(time.Microsecond))
		}
		for code, k := range p.Stats.Kisses {
			s += fmt.Sprintf(",%s=%d", code, k)
		}
		if p.Disabled != "" {
			s += ",off=" + p.Disabled
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}
