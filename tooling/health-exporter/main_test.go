package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	backend "github.com/lidofinance/tee-signer/signer-protocol"
)

func rendered(rs ...*runner) string {
	var b strings.Builder
	render(&b, rs)
	return b.String()
}

func wantLine(t *testing.T, out, line string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return
		}
	}
	t.Errorf("no line %q in:\n%s", line, out)
}

func TestRenderHelpTypeOnce(t *testing.T) {
	h := &backend.Health{Platform: "dev", Ready: true, Validators: 3, Stats: &backend.SignerStats{Signatures: 7},
		NTS: &backend.ClockNTS{Quorum: true, Members: []string{"a", "b"}}}
	out := rendered(&runner{name: "b", h: h}, &runner{name: "a", h: h})
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "# HELP ") {
			continue
		}
		name := strings.Fields(l)[2]
		if n := strings.Count(out, "# HELP "+name+" "); n != 1 {
			t.Errorf("%s: %d HELP lines", name, n)
		}
		if n := strings.Count(out, "# TYPE "+name+" "); n != 1 {
			t.Errorf("%s: %d TYPE lines", name, n)
		}
	}
	// Samples of one metric follow its TYPE line, sorted by labels.
	i := strings.Index(out, "# TYPE tee_signer_validators gauge\n")
	if i < 0 || !strings.HasPrefix(out[i:], "# TYPE tee_signer_validators gauge\n"+
		"tee_signer_validators{runner=\"a\"} 3\ntee_signer_validators{runner=\"b\"} 3\n") {
		t.Errorf("validators block:\n%s", out)
	}
	wantLine(t, out, `tee_signer_nts_members{runner="a"} 2`)
	wantLine(t, out, `tee_signer_not_ready_reason{runner="a",reason="mark_log_lost"} 0`)
}

func TestRenderEscapesLabels(t *testing.T) {
	h := &backend.Health{Version: "1\"2\\3\n4"}
	out := rendered(&runner{name: `x"y\z`, h: h})
	wantLine(t, out, `tee_signer_up{runner="x\"y\\z"} 1`)
	if !strings.Contains(out, `version="1\"2\\3\n4"`) {
		t.Errorf("version label not escaped:\n%s", out)
	}
}

func TestRenderRunnerDown(t *testing.T) {
	out := rendered(&runner{name: "a", errs: 4, verified: 2})
	var samples []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(l, "#") {
			samples = append(samples, l)
		}
	}
	want := []string{
		`tee_signer_up{runner="a"} 0`,
		`tee_signer_health_errors_total{runner="a"} 4`,
		`tee_signer_attestations_verified_total{runner="a"} 2`,
	}
	if strings.Join(samples, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(samples, "\n"), strings.Join(want, "\n"))
	}
	wantLine(t, out, "# TYPE tee_signer_health_errors_total counter")
	wantLine(t, out, "# TYPE tee_signer_attestations_verified_total counter")
}

func TestRenderCountersAndConfig(t *testing.T) {
	h := &backend.Health{
		UnverifiedSignatures: 5,
		Stats:                &backend.SignerStats{Signatures: 10, WatermarkWrites: 4, ExactRepeats: 1, HashCacheHits: 8, HashCacheMisses: 2},
		NTS:                  &backend.ClockNTS{Refusals: 3, RhoViolations: 1, BoundNowMS: 250},
		Image:                &backend.ImageCheck{State: backend.ImageAllowed},
		Setup: &backend.SetupState{Locked: backend.ConfigGroup{Version: 2},
			Open: backend.ConfigGroup{Version: 1, Pending: backend.PendingUpdate{Version: 2, EffectiveAt: 1800000000}}},
	}
	out := rendered(&runner{name: "a", h: h})
	for _, l := range []string{
		"# TYPE tee_signer_signatures_total counter",
		`tee_signer_signatures_total{runner="a"} 10`,
		`tee_signer_watermark_writes_total{runner="a"} 4`,
		`tee_signer_exact_repeats_total{runner="a"} 1`,
		`tee_signer_hash_cache_hits_total{runner="a"} 8`,
		`tee_signer_hash_cache_misses_total{runner="a"} 2`,
		`tee_signer_unverified_signatures_total{runner="a"} 5`,
		"# TYPE tee_signer_nts_refusals_total counter",
		`tee_signer_nts_refusals_total{runner="a"} 3`,
		`tee_signer_nts_rho_violations_total{runner="a"} 1`,
		`tee_signer_nts_bound_seconds{runner="a"} 0.25`,
		`tee_signer_image_check{runner="a",state="allowed"} 1`,
		`tee_signer_config_version{runner="a",group="locked"} 2`,
		`tee_signer_config_pending_effective_timestamp_seconds{runner="a",group="open"} 1.8e+09`,
		`tee_signer_config_pending_effective_timestamp_seconds{runner="a",group="locked"} 0`,
	} {
		wantLine(t, out, l)
	}
	// No clock reading in ms: no skew.
	if strings.Contains(out, "tee_signer_clock_skew_seconds") {
		t.Errorf("skew without a clock reading:\n%s", out)
	}
}

// writeConn writes a connection file for r with the dev verifier and, if
// pin is set, a setup pin.
func writeConn(t *testing.T, addr string, r *fakerunner.Runner, pin string) string {
	t.Helper()
	dir := t.TempDir()
	cert, key := r.ClientFiles(t, dir)
	att := map[string]any{"verifier": "dev"}
	if pin != "" {
		att["setup_sha256"] = pin
	}
	b, err := json.Marshal(map[string]any{
		"address": addr, "client_cert": cert, "client_key": key, "attestation": att,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "conn.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPollFakeRunner(t *testing.T) {
	fr := fakerunner.Start(t, backend.SetupState{})
	r, err := newRunner("s1", writeConn(t, fr.Addr(), fr, ""), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer r.cl.Close()
	r.poll(10 * time.Second)
	r.poll(10 * time.Second)
	out := rendered(r)
	wantLine(t, out, `tee_signer_up{runner="s1"} 1`)
	wantLine(t, out, `tee_signer_ready{runner="s1"} 1`)
	wantLine(t, out, `tee_signer_health_errors_total{runner="s1"} 0`)
	// Two calls on one connection: one attestation check.
	wantLine(t, out, `tee_signer_attestations_verified_total{runner="s1"} 1`)
	if !strings.Contains(out, `platform="dev"`) {
		t.Errorf("no platform label:\n%s", out)
	}
}

func TestPollRunnerDown(t *testing.T) {
	fr := fakerunner.Start(t, backend.SetupState{})
	// A port with no listener: take one, then close it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := "tcp:" + ln.Addr().String()
	ln.Close()
	r, err := newRunner("s1", writeConn(t, addr, fr, ""), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer r.cl.Close()
	r.poll(2 * time.Second)
	out := rendered(r)
	wantLine(t, out, `tee_signer_up{runner="s1"} 0`)
	wantLine(t, out, `tee_signer_health_errors_total{runner="s1"} 1`)
	if strings.Contains(out, "tee_signer_ready") {
		t.Errorf("ready of a runner that did not answer:\n%s", out)
	}
}

func TestPollWrongSetupPin(t *testing.T) {
	fr := fakerunner.Start(t, backend.SetupState{})
	r, err := newRunner("s1", writeConn(t, fr.Addr(), fr, strings.Repeat("ab", 32)), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer r.cl.Close()
	r.poll(10 * time.Second)
	out := rendered(r)
	wantLine(t, out, `tee_signer_up{runner="s1"} 0`)
	wantLine(t, out, `tee_signer_health_errors_total{runner="s1"} 1`)
	wantLine(t, out, `tee_signer_attestations_verified_total{runner="s1"} 0`)
}

// slowDial forwards to addr, but holds each new connection for d before it
// forwards a byte, so the TLS handshake of every new connection is slow.
func slowDial(t *testing.T, addr string, d time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				time.Sleep(d)
				up, err := net.Dial("tcp", strings.TrimPrefix(addr, "tcp:"))
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// A poll that opens a new connection times the dial and the attestation
// check too, so it must not set rtt or skew.
func TestPollRTTSkipsNewConnection(t *testing.T) {
	fr := fakerunner.Start(t, backend.SetupState{})
	const dial = 500 * time.Millisecond
	r, err := newRunner("s1", writeConn(t, slowDial(t, fr.Addr(), dial), fr, ""), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer r.cl.Close()
	r.poll(10 * time.Second)
	out := rendered(r)
	wantLine(t, out, `tee_signer_up{runner="s1"} 1`)
	if strings.Contains(out, "tee_signer_health_rtt_seconds{") || strings.Contains(out, "tee_signer_clock_skew_seconds{") {
		t.Errorf("rtt or skew from a poll that dialed:\n%s", out)
	}
	r.poll(10 * time.Second)
	if r.rtt <= 0 || r.rtt >= dial/2 {
		t.Errorf("rtt on an open connection %v, want above 0 and below %v", r.rtt, dial/2)
	}
}
