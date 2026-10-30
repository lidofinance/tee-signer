package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// fakeRunner answers HEALTH with the JSON health(now) returns and IDENTITY
// with an identity whose user data matches, on a unix socket, over the
// wire protocol. health gets the time of the request, so a test can play a
// signer clock ahead of this machine's.
func fakeRunner(t *testing.T, health func(now time.Time) string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "runner.sock")
	ln, err := net.Listen("unix", sock)
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
			go serveFake(c, health)
		}
	}()
	return "unix:" + sock
}

func serveFake(c net.Conn, health func(time.Time) string) {
	defer c.Close()
	for {
		f, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		var body []byte
		switch f.Type {
		case wire.TypeHealth:
			body = []byte(health(time.Now()))
		case wire.TypeIdentity:
			nonce, err := wire.DecodeAttest(f.Payload)
			if err != nil {
				return
			}
			id := &cloud.Identity{State: cloud.SetupState{SetupHash: cloud.Root{0xc0, 0xff, 0xee, 0x01}}, ImportKEM: 0x20, ImportKDF: 1, ImportAEAD: 3,
				ImportKey: make([]byte, 32), TLSKeyHash: []byte{0xab, 0xcd, 0xef, 0x12, 0x34}}
			id.Attestation = &cloud.Attestation{Platform: "dev", Format: "dev", UserData: cloud.IdentityUserData(nonce, id), Document: []byte("doc")}
			if body, err = wire.EncodeIdentity(id); err != nil {
				return
			}
		default:
			return
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: wire.EncodeOK(body)}); err != nil {
			return
		}
	}
}

func probeFake(t *testing.T, health func(time.Time) string, verify remote.VerifyFunc) result {
	t.Helper()
	cl, err := remote.New(fakeRunner(t, health), remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if verify == nil {
		verify = func(context.Context, []byte, *cloud.Identity) error { return nil }
	}
	return probe(ctx, cl, verify, &runnerclient.Attestation{Verifier: runnerclient.VerifierDev}, result{Name: "aws-2", Enabled: true})
}

// A new runner with the NTS clock: the NTS figures pass through as the
// runner sent them, and the figure against this machine has millisecond
// resolution (the fake clock is 1500 ms ahead of this machine).
func TestProbeNewRunnerWithNTS(t *testing.T) {
	r := probeFake(t, func(now time.Time) string {
		ms := now.Add(1500 * time.Millisecond).UnixMilli()
		return fmt.Sprintf(`{"platform":"nitro","ready":true,"clock_source":"nts(a,b,c,d)","clock_trusted":true,"clock_unix":%d,"clock_unix_ms":%d,`+
			`"clock_nts":{"quorum":true,"bound_now_ms":17.25,"max_bound_ms":100,"offset_from_host_ms":-2210.5,"members":["a","b","c"],`+
			`"quorum_age_ms":9000,"refusals":4,"drift_ppm":1.5,"drift_err_ppm":30,"drift_baseline_s":960,"rho_violations":0,"coarse_diff_ms":380}}`,
			ms/1000, ms)
	}, nil)
	if !r.OK || r.Error != "" || !r.Ready || r.TLSKey != "abcdef12" || r.Config != "c0ffee01" {
		t.Fatalf("result %+v", r)
	}
	// The fake runner is on the flag path: setup_hash only.
	if r.Setup == nil || *r.Setup != (setupView{SetupHash: "c0ffee01", FlagPath: true}) || setupLine(r) != "setup=flag-path" {
		t.Fatalf("setup %+v", r.Setup)
	}
	if r.ClockSource != "nts(a,b,c,d)" || !r.ClockTrusted || r.ClockUnixMS == 0 || r.ClockUnix != r.ClockUnixMS/1000 {
		t.Fatalf("clock %+v", r)
	}
	if math.Abs(r.ClockVsCheckerMS-1500) > 50 || r.ClockVsCheckerErrMS > 50 {
		t.Fatalf("vs checker %.1f +- %.1f ms, want 1500 +- a few", r.ClockVsCheckerMS, r.ClockVsCheckerErrMS)
	}
	want := cloud.ClockNTS{Quorum: true, BoundNowMS: 17.25, MaxBoundMS: 100, OffsetFromHostMS: -2210.5, Members: []string{"a", "b", "c"},
		QuorumAgeMS: 9000, Refusals: 4, DriftPPM: 1.5, DriftErrPPM: 30, DriftBaselineS: 960, CoarseDiffMS: 380}
	if r.NTS == nil || r.NTS.BoundNowMS != want.BoundNowMS || r.NTS.OffsetFromHostMS != want.OffsetFromHostMS ||
		strings.Join(r.NTS.Members, ",") != "a,b,c" || r.NTS.Refusals != 4 || r.NTS.CoarseDiffMS != 380 || r.NTS.DriftBaselineS != 960 {
		t.Fatalf("nts %+v, want %+v", r.NTS, want)
	}
	// The output file names the fields the exporter reads.
	b, _ := json.Marshal(r)
	for _, k := range []string{`"clock_vs_checker_ms":`, `"clock_vs_checker_err_ms":`, `"clock_unix_ms":`, `"nts":{"quorum":true,"bound_now_ms":17.25`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("output lacks %s: %s", k, b)
		}
	}
	if strings.Contains(string(b), "clock_offset_s") {
		t.Errorf("output still has clock_offset_s: %s", b)
	}
	if l := clockLine(r); !strings.Contains(l, "nts_bound=17.2ms") && !strings.Contains(l, "nts_bound=17.3ms") {
		t.Errorf("log line %q", l)
	}
}

// An old runner: whole seconds only, no clock_unix_ms and no clock_nts. The
// check passes; the figure against this machine has the extra half second
// of error; no NTS figures.
func TestProbeOldRunner(t *testing.T) {
	r := probeFake(t, func(now time.Time) string {
		return fmt.Sprintf(`{"platform":"azure","ready":true,"clock_source":"anchored(https-date x3)","clock_trusted":true,"clock_unix":%d}`, now.Unix())
	}, nil)
	if !r.OK || r.NTS != nil || r.ClockUnixMS != 0 || r.ClockUnix == 0 {
		t.Fatalf("result %+v", r)
	}
	if math.Abs(r.ClockVsCheckerMS) > 600 || r.ClockVsCheckerErrMS < 500 || r.ClockVsCheckerErrMS > 550 {
		t.Fatalf("vs checker %.1f +- %.1f ms", r.ClockVsCheckerMS, r.ClockVsCheckerErrMS)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), `"nts"`) || strings.Contains(string(b), "clock_unix_ms") {
		t.Fatalf("old runner output %s", b)
	}
}

// A runner whose clock refuses (NTS bound over the limit): not ready, no
// time, the NTS figures say why.
func TestProbeRunnerWithoutTime(t *testing.T) {
	r := probeFake(t, func(time.Time) string {
		return `{"platform":"gcp","ready":false,"clock_source":"nts(a,b,c,d)","clock_trusted":true,"clock_unix":0,` +
			`"clock_nts":{"quorum":false,"bound_now_ms":131,"max_bound_ms":100,"members":["a","b"],"refusals":12}}`
	}, nil)
	if !r.OK || r.Ready || r.ClockUnix != 0 || r.ClockVsCheckerMS != 0 || r.NTS == nil || r.NTS.Quorum || r.NTS.BoundNowMS != 131 {
		t.Fatalf("result %+v nts %+v", r, r.NTS)
	}
	if l := clockLine(r); !strings.Contains(l, "signer_clock=none") {
		t.Errorf("log line %q", l)
	}
}

// A failed attestation fails the check; the clock figures of the HEALTH
// before it stay in the result.
func TestProbeVerifyFails(t *testing.T) {
	r := probeFake(t, func(now time.Time) string {
		return fmt.Sprintf(`{"platform":"dev","ready":true,"clock_unix":%d,"clock_unix_ms":%d}`, now.Unix(), now.UnixMilli())
	}, func(context.Context, []byte, *cloud.Identity) error {
		return errors.New("document from 10.0.0.4 rejected")
	})
	if r.OK || !strings.Contains(r.Error, "identity not verified") || strings.Contains(r.Error, "10.0.0.4") || r.ClockUnixMS == 0 || r.Setup != nil {
		t.Fatalf("result %+v", r)
	}
}

// The share count and the signer core's counters of HEALTH pass through; a runner without counters has no stats field.
func TestProbeCoreCounters(t *testing.T) {
	r := probeFake(t, func(now time.Time) string {
		return fmt.Sprintf(`{"platform":"dev","ready":true,"validators":100,"clock_unix":%d,"clock_unix_ms":%d,`+
			`"stats":{"signatures":5120,"hash_cache_hits":4000,"hash_cache_misses":1120,"watermark_writes":300,"exact_repeats":7}}`,
			now.Unix(), now.UnixMilli())
	}, nil)
	if !r.OK || r.Validators != 100 || r.Stats == nil || r.Stats.Signatures != 5120 || r.Stats.HashCacheMisses != 1120 || r.Stats.ExactRepeats != 7 {
		t.Fatalf("result %+v stats %+v", r, r.Stats)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"validators":100`) || !strings.Contains(string(b), `"stats":{"signatures":5120,"hash_cache_hits":4000`) {
		t.Errorf("output %s", b)
	}
	old := probeFake(t, func(now time.Time) string {
		return fmt.Sprintf(`{"platform":"dev","ready":true,"clock_unix":%d}`, now.Unix())
	}, nil)
	if b, _ := json.Marshal(old); strings.Contains(string(b), `"stats"`) || strings.Contains(string(b), `"mark"`) {
		t.Errorf("a runner without counters or mark log got their fields: %s", b)
	}
}

// A runner with the mark log reports its newest record in HEALTH record.
// The file keeps the numbers and the state, never the log's bucket name.
func TestProbeMarkLog(t *testing.T) {
	r := probeFake(t, func(now time.Time) string {
		return fmt.Sprintf(`{"platform":"nitro","ready":true,"clock_unix":%d,`+
			`"record":"marklog s3://signer-marks-7f3a signer=aws-2 owner=0a1b2c3d version=412 writes=37 target=96 source=94 block=3071"}`, now.Unix())
	}, nil)
	want := mark{Record: 412, Writes: 37, TargetEpoch: 96, SourceEpoch: 94, BlockSlot: 3071, State: "ok"}
	if !r.OK || r.Mark == nil || *r.Mark != want {
		t.Fatalf("mark %+v, want %+v", r.Mark, want)
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), "signer-marks") || strings.Contains(string(b), "owner") {
		t.Errorf("the log's name or owner reached the file: %s", b)
	}
	for record, state := range map[string]string{
		"marklog gs://b signer=gcp-3 owner=00 version=9 writes=0 target=5 source=4 block=0 skipped=2 LOST": "lost",
		"marklog azblob://a/c signer=azure-1 owner=00 version=3 HANDED-OVER":                               "handed-over",
	} {
		if m := markOf(record); m == nil || m.State != state {
			t.Errorf("%q: %+v, want state %s", record, m, state)
		}
	}
	for _, record := range []string{"", "none", "guard s3://x seq=4"} {
		if m := markOf(record); m != nil {
			t.Errorf("%q gave a mark %+v", record, m)
		}
	}
}

// The image fingerprint is the measurement the verifier pins, per cloud.
func TestImageOf(t *testing.T) {
	h64 := "AB12CD34" + strings.Repeat("0", 56)
	for _, c := range []struct {
		a    runnerclient.Attestation
		want string
	}{
		{runnerclient.Attestation{Verifier: "azure-maa", CCEPolicySHA256: h64}, "ab12cd34"},
		{runnerclient.Attestation{Verifier: "aws-nitro", NitroPCRs: map[string]string{"0": "9f8e7d6c" + strings.Repeat("1", 88), "1": "aa"}}, "9f8e7d6c"},
		{runnerclient.Attestation{Verifier: "gcp-cs", GCPImageDigest: "sha256:" + h64}, "ab12cd34"},
		{runnerclient.Attestation{Verifier: "dev"}, ""},
	} {
		if got := imageOf(c.a); got != c.want {
			t.Errorf("%s: %q, want %q", c.a.Verifier, got, c.want)
		}
	}
}
