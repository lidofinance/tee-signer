// Command health-exporter polls the HEALTH of tee-signer runners over their
// attested mutual TLS and serves the result as Prometheus metrics.
//
// Each runner is a connection file in the format signer-admin reads
// (address, client_cert, client_key, attestation pins). Use a client
// certificate of the attest-only role: HEALTH needs no more.
//
//	health-exporter -listen 127.0.0.1:9478 -every 30s name=conn.json [name=conn.json ...]
//
// Every new connection checks the runner's attestation and setup pins first.
// A runner that fails the check, or does not answer, shows as
// tee_signer_up 0, with the error in the log.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	admincluster "github.com/lidofinance/tee-signer/signer-admin/cluster"
	backend "github.com/lidofinance/tee-signer/signer-protocol"
)

type runner struct {
	name string
	cl   *runnerclient.Client

	mu       sync.Mutex
	h        *backend.Health // nil after a failed call
	rtt      time.Duration   // of the call that gave h, on an open connection
	skew     time.Duration   // runner clock minus local clock, at the middle of that call
	skewOK   bool            // that call's answer had the clock in ms
	errs     uint64
	verified uint64
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9478", "address of the /metrics endpoint")
	every := flag.Duration("every", 30*time.Second, "poll interval")
	timeout := flag.Duration("timeout", 20*time.Second, "timeout of one HEALTH call")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: health-exporter [-listen ADDR] [-every 30s] [-timeout 20s] name=conn.json ...")
		os.Exit(2)
	}
	var rs []*runner
	seen := map[string]bool{}
	for _, arg := range flag.Args() {
		name, path, ok := strings.Cut(arg, "=")
		if !ok || name == "" || path == "" {
			log.Fatalf("%q: want name=conn.json", arg)
		}
		if seen[name] {
			log.Fatalf("%s: named twice", name)
		}
		seen[name] = true
		r, err := newRunner(name, path, *timeout)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].name < rs[j].name })
	for _, r := range rs {
		go func() {
			for {
				r.poll(*timeout)
				time.Sleep(*every)
			}
		}()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		render(w, rs)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("serving /metrics on %s for %d runners", *listen, len(rs))
	log.Fatal(srv.ListenAndServe())
}

// newRunner reads the connection file at path. It does not connect.
func newRunner(name, path string, timeout time.Duration) (*runner, error) {
	conn, err := admincluster.LoadConn(path)
	if err != nil {
		return nil, err
	}
	r := &runner{name: name}
	r.cl, err = conn.New(runnerclient.WithTimeout(timeout), runnerclient.WithVerified(func(*backend.Identity) {
		r.mu.Lock()
		r.verified++
		r.mu.Unlock()
	}))
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *runner) poll(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r.mu.Lock()
	v0 := r.verified
	r.mu.Unlock()
	t0 := time.Now()
	h, err := r.cl.Health(ctx)
	t1 := time.Now()
	r.mu.Lock()
	dialed := r.verified != v0
	r.mu.Unlock()
	if err == nil && dialed {
		// The call opened a new connection, so it also timed the dial and
		// the attestation check. Time a second call on that connection.
		t0 = time.Now()
		h, err = r.cl.Health(ctx)
		t1 = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.errs++
		r.h, r.skewOK = nil, false
		log.Printf("%s: health: %v", r.name, err)
		return
	}
	r.h, r.rtt, r.skewOK = h, t1.Sub(t0), h.ClockUnixMS != 0
	if r.skewOK {
		mid := t0.Add(t1.Sub(t0) / 2)
		r.skew = time.UnixMilli(int64(h.ClockUnixMS)).Sub(mid)
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// render writes the Prometheus text format: every metric carries the label
// runner, with HELP and TYPE once per metric. A runner without an answer
// has only tee_signer_up and the two counters of this exporter.
func render(w io.Writer, rs []*runner) {
	type sample struct {
		labels string
		v      float64
	}
	type metric struct {
		name, help, typ string
		s               []sample
	}
	var order []string
	ms := map[string]*metric{}
	add := func(name, typ, help, labels string, v float64) {
		m := ms[name]
		if m == nil {
			m = &metric{name: name, help: help, typ: typ}
			ms[name] = m
			order = append(order, name)
		}
		m.s = append(m.s, sample{labels, v})
	}
	gauge := func(name, help, labels string, v float64) { add(name, "gauge", help, labels, v) }
	counter := func(name, help, labels string, v float64) { add(name, "counter", help, labels, v) }
	q := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace
	for _, r := range rs {
		r.mu.Lock()
		h, rtt, skew, skewOK, errs, verified := r.h, r.rtt, r.skew, r.skewOK, r.errs, r.verified
		r.mu.Unlock()
		l := fmt.Sprintf(`runner="%s"`, q(r.name))
		one := "{" + l + "}"
		with := func(k, v string) string { return fmt.Sprintf(`{%s,%s="%s"}`, l, k, q(v)) }
		gauge("tee_signer_up", "1 if the last HEALTH call passed the attestation check and answered.", one, b2f(h != nil))
		counter("tee_signer_health_errors_total", "HEALTH calls that failed (connection, attestation or timeout).", one, float64(errs))
		counter("tee_signer_attestations_verified_total", "Runner identities this exporter verified, one per new connection.", one, float64(verified))
		if h == nil {
			continue
		}
		gauge("tee_signer_info", "Runner build and settings; always 1.",
			fmt.Sprintf(`{%s,platform="%s",version="%s",signing_mode="%s",single_key="%s",clock_source="%s",key_lock="%s",restart_mode="%s"}`,
				l, q(h.Platform), q(h.Version), q(h.SigningMode), q(h.SingleKey), q(h.ClockSource), q(h.KeyLock), q(h.RestartMode)), 1)
		gauge("tee_signer_ready", "1 if the runner reports it can sign.", one, b2f(h.Ready))
		for _, nr := range []struct{ reason, why string }{
			{"load_failed", h.LoadFailed}, {"state_copy_failed", h.StateCopyFailed},
			{"mark_log_lost", h.MarkLogLost}, {"request_panic", h.RequestPanic},
		} {
			gauge("tee_signer_not_ready_reason", "1 while the runner reports this reason.", with("reason", nr.reason), b2f(nr.why != ""))
		}
		if h.Image != nil {
			gauge("tee_signer_image_check", "1 for the state of the runner's check of its own image.", with("state", h.Image.State), 1)
		}
		if s := h.Setup; s != nil {
			for _, g := range []struct {
				name string
				c    backend.ConfigGroup
			}{{"locked", s.Locked}, {"open", s.Open}} {
				gauge("tee_signer_config_version", "Active version of the config group.", with("group", g.name), float64(g.c.Version))
				gauge("tee_signer_config_pending_effective_timestamp_seconds", "When the pending update of the config group takes effect, unix seconds; 0 if none.",
					with("group", g.name), float64(g.c.Pending.EffectiveAt))
			}
		}
		gauge("tee_signer_validators", "Validator keys or shares loaded.", one, float64(h.Validators))
		gauge("tee_signer_started_timestamp_seconds", "Runner start time, unix seconds.", one, float64(h.StartedUnix))
		gauge("tee_signer_health_rtt_seconds", "Duration of the last HEALTH call on an open connection.", one, rtt.Seconds())
		if skewOK {
			gauge("tee_signer_clock_skew_seconds", "Runner clock minus this host's clock.", one, skew.Seconds())
		}
		gauge("tee_signer_clock_trusted", "1 if the runner's clock is a trusted source.", one, b2f(h.ClockTrusted))
		gauge("tee_signer_allow_unverified_nonslashable", "1 if the runner signs bare roots it cannot check.", one, b2f(h.AllowUnverifiedNonslashable))
		counter("tee_signer_unverified_signatures_total", "Bare-root signatures the runner could not check.", one, float64(h.UnverifiedSignatures))
		if s := h.Stats; s != nil {
			counter("tee_signer_signatures_total", "Signatures made since start.", one, float64(s.Signatures))
			counter("tee_signer_watermark_writes_total", "Slashing mark writes since start.", one, float64(s.WatermarkWrites))
			counter("tee_signer_exact_repeats_total", "Exact repeats signed again since start.", one, float64(s.ExactRepeats))
			counter("tee_signer_hash_cache_hits_total", "Signing root cache hits since start.", one, float64(s.HashCacheHits))
			counter("tee_signer_hash_cache_misses_total", "Signing root cache misses since start.", one, float64(s.HashCacheMisses))
		}
		if n := h.NTS; n != nil {
			gauge("tee_signer_nts_quorum", "1 if the NTS clock answers.", one, b2f(n.Quorum))
			gauge("tee_signer_nts_bound_seconds", "Current NTS error bound.", one, n.BoundNowMS/1000)
			gauge("tee_signer_nts_max_bound_seconds", "Error bound above which the runner signs nothing.", one, n.MaxBoundMS/1000)
			gauge("tee_signer_nts_offset_from_host_seconds", "NTS time minus the host-set system clock inside the TEE.", one, n.OffsetFromHostMS/1000)
			gauge("tee_signer_nts_quorum_age_seconds", "Time since the last NTS quorum.", one, n.QuorumAgeMS/1000)
			gauge("tee_signer_nts_sample_age_seconds", "Age of the oldest NTS sample in the quorum.", one, n.SampleAgeMS/1000)
			gauge("tee_signer_nts_max_sample_age_seconds", "Sample age above which the runner signs nothing.", one, n.MaxSampleAgeMS/1000)
			gauge("tee_signer_nts_members", "NTS servers in the quorum.", one, float64(len(n.Members)))
			counter("tee_signer_nts_refusals_total", "Times the NTS clock refused to give a time.", one, float64(n.Refusals))
			counter("tee_signer_nts_rho_violations_total", "Quorums the drift check refused.", one, float64(n.RhoViolations))
			gauge("tee_signer_nts_drift_ppm", "Measured drift of the local clock, parts per million.", one, n.DriftPPM)
			gauge("tee_signer_nts_coarse_diff_seconds", "NTS time minus the HTTPS-date time at the last quorum.", one, n.CoarseDiffMS/1000)
		}
	}
	for _, name := range order {
		m := ms[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.typ)
		sort.SliceStable(m.s, func(i, j int) bool { return m.s[i].labels < m.s[j].labels })
		for _, s := range m.s {
			fmt.Fprintf(w, "%s%s %g\n", m.name, s.labels, s.v)
		}
	}
}
