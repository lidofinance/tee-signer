//go:build nts

package main

// The NTS clock in a runner built with -tags nts. main.go is not changed, so
// the default runners stay byte for byte the same. This file's name sorts
// after platform_*.go, so its init runs after theirs and can wrap the
// platforms they registered. With -nts-clock (or RUNNER_NTS_CLOCK=1) every
// platform gets the NTS clock (trusted-time/clock.NTS) in place of its own. The
// cloud images set the flags in their measured command (the enclave image,
// the CCE policy, the Confidential Space image), so the host cannot turn the
// clock off; the variables are for local runs. A flag that is set wins
// over its variable.
//
//	-nts-clock                 RUNNER_NTS_CLOCK=1            turn it on
//	-nts-coarse-urls a,b,c     RUNNER_NTS_COARSE_URLS=a,b,c  HTTPS-date URLs of the coarse check (required, 3 or more);
//	                                                         {region} stands for the platform option region (Nitro,
//	                                                         from the setup), so one image serves every region; each
//	                                                         must be in the coarse catalog (ntscatalog), whose roots
//	                                                         its source trusts
//	-nts-wait 90s              RUNNER_NTS_WAIT=90s           how long start-up waits for the first quorum
//	-nts-max-bound 100ms       RUNNER_NTS_MAX_BOUND=100ms    Now fails above this error bound; at most 250ms
//	-nts-max-sample-bound 100ms RUNNER_NTS_MAX_SAMPLE_BOUND   a sample with a wider bound joins no quorum; from
//	                                                         -nts-max-bound (the default) to 1s (no cap)
//	-nts-terms-confirmed a,b   RUNNER_NTS_TERMS_CONFIRMED    catalog entries (trusted-time/ntscatalog) dialed next to
//	                                                         the default set, whose operators' terms the deployment's
//	                                                         writer confirmed; id@host picks an alt host with a Nitro
//	                                                         port (time.nl@any.time.nl)
//	-clock-protocol nts|ntp    RUNNER_CLOCK_PROTOCOL=ntp     how the clock asks its servers: nts (the default) or
//	                                                         plain NTP, unauthenticated: the host can forge every
//	                                                         answer, and the time is only as good as the coarse check
//	                                                         (trusted-time/docs/nts.md, "Plain NTP"); the variable
//	                                                         only on the dev platform and in debug builds
//	                           RUNNER_NTS_STATUS_EVERY=60s   period of the "nts: status" log line
//
// -nts-clock turns the network clock on; -clock-protocol picks the protocol
// of every server. Plain NTP asks port 123 of each catalog entry's
// plain_ntp_host, else its first ntp_names entry, else its host. The image
// command carries the choice for now.
//
// The clock dials through the platform (platform.Platform.Dial): on Nitro,
// NTS-KE goes through vsock-proxy routes and NTP through the parent's UDP
// relay.
//
// If no quorum forms in the wait the start fails and the runner exits, as
// for any other start failure: the supervisor (ACI and Confidential Space
// restart on failure; on Nitro the operator or the parent's service
// manager) starts it again. A runner that went on without a quorum would
// load no share, since each share's restart floor reads the clock, and it
// would not load them when the quorum formed later.

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/cloudroots"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

var (
	ntsClockFlag    = flag.Bool("nts-clock", false, "use the NTS clock (RFC 8915, the catalog's default public servers plus -nts-terms-confirmed) on every platform; also RUNNER_NTS_CLOCK=1")
	ntsCoarseFlag   = flag.String("nts-coarse-urls", "", "comma-separated https URLs (3 or more) of the NTS clock's coarse check; default RUNNER_NTS_COARSE_URLS")
	ntsWaitFlag     = flag.Duration("nts-wait", 0, "how long start-up waits for the first NTS quorum; 0 = RUNNER_NTS_WAIT or 90s")
	ntsMaxBoundFlag = flag.Duration("nts-max-bound", 0, "signing fails above this NTS error bound, at most 250ms; 0 = RUNNER_NTS_MAX_BOUND or 100ms")
	// ntsMaxSampleFlag: see ntsMaxSampleBoundCap.
	ntsMaxSampleFlag = flag.Duration("nts-max-sample-bound", 0, "an NTS sample with a wider bound joins no quorum, from -nts-max-bound to 1s; 0 = RUNNER_NTS_MAX_SAMPLE_BOUND or -nts-max-bound")
	ntsConfirmFlag   = flag.String("nts-terms-confirmed", "", "comma-separated NTS catalog IDs (id or id@alt-host) whose operators' terms the deployment confirmed, dialed next to the default set; default RUNNER_NTS_TERMS_CONFIRMED")
	clockProtoFlag   = flag.String("clock-protocol", "", "protocol of the -nts-clock servers: nts (default) or ntp (plain NTP, unauthenticated: only as good as the coarse check); default RUNNER_CLOCK_PROTOCOL")
)

// plainNTPWarning is logged at start when the clock runs plain NTP. The
// numbers are worked out in trusted-time/docs/nts.md, "Plain NTP".
const plainNTPWarning = "plain NTP: the host can forge every answer; the time is only as good as the coarse check " +
	"(up to about 46 s behind and 31 s ahead of real time; where the host sets the local counter, 196 s ahead and behind without a limit)"

// clockProtocol is -clock-protocol, or RUNNER_CLOCK_PROTOCOL: nts (also
// when neither is set) or ntp. Any other value is an error. The variable
// counts only with envOK (the dev platform, the -nts-clock-check
// pre-flight) or in a debug build (clockProtocolEnvAllowed): a release
// runner on a cloud takes the protocol from its measured command alone, so
// the host cannot switch it to plain NTP.
func clockProtocol(envOK bool) (clock.Protocol, error) {
	v := *clockProtoFlag
	if v == "" {
		if e := os.Getenv("RUNNER_CLOCK_PROTOCOL"); e != "" {
			if !envOK && !clockProtocolEnvAllowed {
				return "", fmt.Errorf("RUNNER_CLOCK_PROTOCOL=%q: a release build takes the clock protocol only from -clock-protocol; set the flag in the image command", e)
			}
			v = e
		}
	}
	p, err := clock.ParseProtocol(v)
	if err != nil {
		return "", fmt.Errorf("-clock-protocol (RUNNER_CLOCK_PROTOCOL) %q: want nts or ntp", v)
	}
	return p, nil
}

// ntsConfirmed is -nts-terms-confirmed, or RUNNER_NTS_TERMS_CONFIRMED.
func ntsConfirmed() []string {
	list := *ntsConfirmFlag
	if list == "" {
		list = os.Getenv("RUNNER_NTS_TERMS_CONFIRMED")
	}
	var out []string
	for _, s := range strings.Split(list, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ntsMaxBoundCap is the largest -nts-max-bound the runner accepts. A
// sample's bound is about half its round trip, so 250 ms leaves room for
// servers up to about 400 ms away. A larger limit lets the runner sign on a
// time it can vouch for only that loosely.
const ntsMaxBoundCap = 250 * time.Millisecond

// ntsMaxSampleBoundCap is the largest -nts-max-sample-bound: 1 s, the
// widest sample the NTS core takes at all (RFC 5905 MAXDIST), so 1s turns
// the cap off. Its default is -nts-max-bound, and it may not be smaller.
// A host that widens the one honest sample of a small fresh set lets two
// wrong servers shift the time by up to about twice the cap (the bound is
// a half-width), not about 1 s each way. An image that raises it above
// -nts-max-bound gives part of that back.
const ntsMaxSampleBoundCap = time.Second

func init() {
	for name, f := range platforms {
		platforms[name] = ntsSwitch(name, f)
	}
}

// ntsOn: the flag or the variable asks for the NTS clock.
func ntsOn() bool { return *ntsClockFlag || os.Getenv("RUNNER_NTS_CLOCK") == "1" }

// ntsSwitch runs f, and adds the NTS clock when it is on. The flags are
// parsed by then: main calls the platform after flag.Parse. A bad
// -clock-protocol is refused also with the clock off. name is the
// platform's: only dev takes RUNNER_CLOCK_PROTOCOL in a release build.
func ntsSwitch(name string, f platformFunc) platformFunc {
	return func(o platform.Options) (*platform.Platform, error) {
		protocol, err := clockProtocol(name == "dev")
		if err != nil {
			return nil, err
		}
		if !ntsOn() {
			return f(o)
		}
		return withNTSClock(f, protocol)(o)
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

func withNTSClock(f platformFunc, protocol clock.Protocol) platformFunc {
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
		n, err := startNTSClock(context.Background(), p.HTTPClient, dial, o.Param("region", ""), p.NTSScheduleSeed, protocol, log)
		if err != nil {
			// main never gets this platform, so it cannot report the
			// error to the host (Nitro: the enclave has no console).
			if p.ReportExit != nil {
				p.ReportExit("runner: " + err.Error())
			}
			if p.Close != nil {
				_ = p.Close()
			}
			return nil, err
		}
		p.Clock = n
		return p, nil
	}
}

// newNTSClock builds the NTS clock over publicNTSServers (a debug build
// can name test servers, nts_servers_debug.go) with an HTTPS-date quorum
// (majority of the URLs) as its coarse clock. dial nil: the default dialer.
// region replaces {region} in the URLs. protocol is clock.ProtocolNTS or
// clock.ProtocolNTP (clockProtocol).
func newNTSClock(client *http.Client, dial nts.DialFunc, region string, protocol clock.Protocol, log *slog.Logger) (*clock.NTS, *clock.Anchored, error) {
	urls, err := ntsCoarseURLs(region)
	if err != nil {
		return nil, nil, err
	}
	q := &clock.Quorum{Min: len(urls)/2 + 1}
	for _, u := range urls {
		c, err := coarseClient(client, u)
		if err != nil {
			return nil, nil, err
		}
		q.Sources = append(q.Sources, &clock.HTTPSDate{URL: u.url, Client: c})
	}
	// The coarse clock ages its reading on CLOCK_MONOTONIC_RAW, the NTS
	// clock's local time, so the coarse check compares two times aged on
	// the same counter. Go's monotonic clock (CLOCK_MONOTONIC) is slewed
	// by timesyncd in WSL, 39,000 to 56,000 ppm slow: 15 to 40 s between
	// readings put the coarse time up to 2.2 s behind.
	coarse := &clock.Anchored{Src: q, Interval: clock.DefaultInterval, TrustedSrc: true, Local: rawLocal}
	maxBound, err := ntsDuration(*ntsMaxBoundFlag, "RUNNER_NTS_MAX_BOUND", clock.NTSMaxBound)
	if err != nil {
		return nil, nil, err
	}
	if maxBound > ntsMaxBoundCap {
		return nil, nil, fmt.Errorf("nts clock: -nts-max-bound (RUNNER_NTS_MAX_BOUND) %v: at most %v", maxBound, ntsMaxBoundCap)
	}
	maxSample, err := ntsDuration(*ntsMaxSampleFlag, "RUNNER_NTS_MAX_SAMPLE_BOUND", maxBound)
	if err != nil {
		return nil, nil, err
	}
	if maxSample < maxBound || maxSample > ntsMaxSampleBoundCap {
		return nil, nil, fmt.Errorf("nts clock: -nts-max-sample-bound (RUNNER_NTS_MAX_SAMPLE_BOUND) %v: from -nts-max-bound (%v) to %v", maxSample, maxBound, ntsMaxSampleBoundCap)
	}
	n := &clock.NTS{Protocol: protocol, Coarse: coarse, MaxBound: maxBound, MaxSampleBound: maxSample, Log: log, Dial: dial}
	if n.Servers, err = ntsServers(); err != nil {
		return nil, nil, err
	}
	return n, coarse, nil
}

// coarseURL is one URL of the coarse check: as the image names it, with
// {region} filled in, and its catalog entry (ok false: none).
type coarseURL struct {
	named, url string
	entry      ntscatalog.Coarse
	ok         bool
}

// coarseClient is the client of one coarse source. On a platform with
// pinned roots it trusts the roots of the URL's catalog entry and no
// others: a certificate for the KMS host from Cloudflare's CA, or for
// www.cloudflare.com from a cloud's CA, is refused. A URL with no entry is
// refused there, except in a debug build, whose tests name test servers;
// it then gets the platform's roots plus the NTS operators', as before the
// coarse catalog. A client without pinned roots (the dev platform) is
// returned as it is.
func coarseClient(c *http.Client, u coarseURL) (*http.Client, error) {
	if c == nil {
		return nil, nil
	}
	t, ok := c.Transport.(*http.Transport)
	if !ok || t.TLSClientConfig == nil || t.TLSClientConfig.RootCAs == nil {
		return c, nil
	}
	var pool *x509.CertPool
	switch {
	case u.ok:
		pool = cloudroots.Pool()
		if u.entry.CloudRoots != "" {
			p, err := cloudRootSet(u.entry.CloudRoots)
			if err != nil {
				return nil, err
			}
			pool = cloudroots.Pool(p)
		}
		if err := nts.AddRoots(pool, u.entry.Roots); err != nil {
			return nil, err
		}
	case coarseTestURLs:
		pool = t.TLSClientConfig.RootCAs.Clone()
		for _, s := range nts.PublicServers {
			if err := nts.AddRoots(pool, s.Roots); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("nts clock: coarse URL %s is not in the coarse catalog (trusted-time/ntscatalog)", u.named)
	}
	t = t.Clone()
	t.TLSClientConfig = t.TLSClientConfig.Clone()
	t.TLSClientConfig.RootCAs = pool
	cc := *c
	cc.Transport = t
	return &cc, nil
}

// validRegion: 1 to 32 of a-z, 0-9 and '-', as cloud region names are.
func validRegion(r string) bool {
	if r == "" || len(r) > 32 {
		return false
	}
	for _, c := range []byte(r) {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// cloudRootSet maps a catalog cloud_roots value to its cloudroots set.
func cloudRootSet(name string) (cloudroots.Provider, error) {
	switch name {
	case "aws":
		return cloudroots.AWS, nil
	case "google":
		return cloudroots.Google, nil
	case "azure":
		return cloudroots.Azure, nil
	}
	return 0, fmt.Errorf("nts clock: cloud roots %q unknown", name)
}

// ntsCoarseURLs reads -nts-coarse-urls (or RUNNER_NTS_COARSE_URLS), looks
// each up in the coarse catalog, and puts region in place of {region}. The
// Nitro image names its coarse-time hosts kms.{region}.amazonaws.com and
// sts.{region}.amazonaws.com: the runner fills in the region of the setup
// and nothing else.
func ntsCoarseURLs(region string) ([]coarseURL, error) {
	list := *ntsCoarseFlag
	if list == "" {
		list = os.Getenv("RUNNER_NTS_COARSE_URLS")
	}
	var urls []coarseURL
	seen := map[string]bool{}
	for _, u := range strings.Split(list, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		// One host named twice would count twice in the coarse quorum.
		if seen[u] {
			return nil, fmt.Errorf("nts clock: coarse URL %s named twice", u)
		}
		seen[u] = true
		c := coarseURL{named: u, url: u}
		c.entry, c.ok = ntscatalog.Builtin.CoarseFor(u)
		if strings.Contains(u, "{region}") {
			// The catalog entry is looked up before the region goes in, so
			// the region must not change the host: a cloud region name
			// only (no '/', '?', '#', '@', ':' or '.').
			if !validRegion(region) {
				return nil, fmt.Errorf("nts clock: coarse URL %s names {region}, and the platform's region option %q is not a region name (a-z, 0-9, '-')", u, region)
			}
			c.url = strings.ReplaceAll(u, "{region}", region)
		}
		urls = append(urls, c)
	}
	if len(urls) < 3 {
		return nil, errors.New("nts clock: -nts-coarse-urls (RUNNER_NTS_COARSE_URLS) needs 3 or more https URLs for the coarse check")
	}
	return urls, nil
}

// publicNTSServers are the catalog's default set plus the entries named in
// -nts-terms-confirmed (ntscatalog WithConfirmed), with their pinned roots.
// The plain NTP address is the entry's plain_ntp_host (Netnod: ntp.se),
// else its first NTP name (Meta's NTS-KE names time.meta.com), else its
// host, on port 123 (ntscatalog Endpoint.PlainNTPName). The Nitro relay
// allows all of these names and port 123.
func publicNTSServers() ([]clock.NTSServer, error) {
	eps, err := ntscatalog.Builtin.WithConfirmed(ntsConfirmed())
	if err != nil {
		return nil, fmt.Errorf("nts clock: -nts-terms-confirmed (RUNNER_NTS_TERMS_CONFIRMED): %w", err)
	}
	var out []clock.NTSServer
	for _, e := range eps {
		pool, err := nts.RootPool(e.Roots)
		if err != nil {
			return nil, err
		}
		out = append(out, clock.NTSServer{Host: e.Host, Operator: e.Operator, Roots: pool, NTPAddr: net.JoinHostPort(e.PlainNTPName(), "123")})
	}
	return out, nil
}

// rawLocal is nts.Monotonic as a time.Time for Anchored.Local. Anchored only
// subtracts two such values, so the epoch does not matter.
func rawLocal() time.Time { return time.Unix(0, nts.Monotonic()) }

// ntsShiftMinServers is the fewest servers the schedule hands over on:
// clock.NTSShiftMinServers, 4 actives and 3 others for fallbacks and
// bursts (5 actives from 8 servers, clock.ShiftActives).
const ntsShiftMinServers = clock.NTSShiftMinServers

// ntsMinServers is the fewest servers the runner starts the NTS clock
// with. At least 3 fresh samples must agree (nts.QuorumWrong), so with 3
// servers one slow server would stop signing.
const ntsMinServers = 4

// ntsSchedule turns the seeded schedule on, with seed. From
// ntsShiftMinServers servers it runs shifts; with fewer, every server is
// active, each asked once per 60 s on the same grid, so a small set is not
// asked more often than a large one. Fewer than ntsMinServers is an error.
func ntsSchedule(n *clock.NTS, seed []byte) error {
	if err := ntsEnoughServers(n); err != nil {
		return err
	}
	n.Shifts, n.ScheduleSeed = true, seed
	return nil
}

// ntsEnoughServers refuses fewer than ntsMinServers servers.
func ntsEnoughServers(n *clock.NTS) error {
	if len(n.Servers) < ntsMinServers {
		return fmt.Errorf("nts clock: %d servers, at least %d", len(n.Servers), ntsMinServers)
	}
	return nil
}

// startNTSClock takes the first coarse reading and the first quorum (up to
// -nts-wait), then keeps both running and logs a status line. No quorum in
// the wait is an error: the runner does not start without the clock. The
// clock runs the 60 s schedule (ntsSchedule) with seed
// (platform.Platform.NTSScheduleSeed; nil: every server active, with a
// random phase). protocol is clockProtocol's.
func startNTSClock(ctx context.Context, client *http.Client, dial nts.DialFunc, region string, seed []byte, protocol clock.Protocol, log *slog.Logger) (*clock.NTS, error) {
	wait, err := ntsDuration(*ntsWaitFlag, "RUNNER_NTS_WAIT", 90*time.Second)
	if err != nil {
		return nil, err
	}
	every, err := envDuration("RUNNER_NTS_STATUS_EVERY", time.Minute)
	if err != nil {
		return nil, err
	}
	n, coarse, err := newNTSClock(client, dial, region, protocol, log)
	if err != nil {
		return nil, err
	}
	if err := ntsSchedule(n, seed); err != nil {
		return nil, err
	}
	if protocol == clock.ProtocolNTP {
		log.Warn(plainNTPWarning, "servers", n.Source(), "max_coarse_diff", clock.NTSMaxCoarseDiff)
	}
	log.Info("nts: clock starting", "library", nts.Version(), "protocol", protocol, "servers", n.Source(), "shifts", n.Shifts, "max_bound", n.MaxBound, "wait", wait)
	deadline := time.Now().Add(wait)
	for {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = coarse.Refresh(rctx)
		cancel()
		if err == nil || time.Now().Add(2*time.Second).After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Error("nts: no coarse (HTTPS-date) reading at start", "err", err)
	}
	go coarse.Run(ctx)
	for {
		if err = n.Refresh(ctx); err == nil {
			break
		}
		if time.Now().Add(5 * time.Second).After(deadline) {
			return nil, fmt.Errorf("nts clock: no quorum after %v (peers %s): %w", wait, statusLine(n.Status()), err)
		}
		time.Sleep(5 * time.Second)
	}
	go n.Run(ctx)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Info("nts: status", statusAttrs(n.Status())...)
			}
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
		"protocol", st.Protocol,
		"bound_now", st.BoundNow, "bound_at_quorum", st.Bound, "quorum_age", st.AgeOfQuorum.Round(time.Millisecond),
		"sample_age", st.SampleAge.Round(time.Millisecond),
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
		if p.Stats.Wide > 0 {
			s += fmt.Sprintf(",wide=%d", p.Stats.Wide)
		}
		if p.Disabled != "" {
			s += ",off=" + p.Disabled
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}
