package e2e

// A restart with lost local state, on each platform build that can run
// here: the runner finds its state directory empty (no sealed shares, no
// hint, no sealing key blob) and must still read its mark log, continue
// with the newest mark and sign again once its share is imported again.
// The record keys come from the platform's key release (platform.Keys), so
// the same image and position open them; another image, another key
// release or another position cannot add records that count.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// lostState drives one runner through the scenario. r is set up but not
// started; connect returns a client for it; load imports the share.
type lostState struct {
	c       chain
	r       *runner
	connect func() *remote.Client
	load    func(cl *remote.Client)
	records func() int // records in the log, for the report
	// restored: the runner keeps a durable copy of its state (-state-store),
	// so the share comes back with the restart and needs no new import.
	restored bool
}

var (
	claimRE  = regexp.MustCompile(`mark log: claimed.*version=(\d+)`)
	newestRE = regexp.MustCompile(`mark log: newest record.* target=(\d+)`)
)

// newestTarget is the target of the last "newest record" line, 0 if none.
func newestTarget(text string) uint64 {
	m := newestRE.FindAllStringSubmatch(text, -1)
	if len(m) == 0 {
		return 0
	}
	var t uint64
	fmt.Sscanf(m[len(m)-1][1], "%d", &t)
	return t
}

func lastClaim(t *testing.T, text string) string {
	t.Helper()
	m := claimRE.FindAllStringSubmatch(text, -1)
	if len(m) == 0 {
		t.Fatal("no claim line in the runner log")
	}
	return m[len(m)-1][1]
}

// run signs three epochs with source s0, stops, wipes the state directory,
// starts again and checks: the claim continues the log, the share is gone,
// after a new import a vote with a source below s0 (a surround of the
// votes before) is refused at every epoch while one with source s0 signs.
// It returns s0 and the last target signed before the restart.
func (ls lostState) run(t *testing.T, pk backend.Pubkey) (uint64, uint64) {
	t.Helper()
	c, r := ls.c, ls.r
	sign := func(cl *remote.Client, m backend.Message) error {
		_, err := cl.Sign(ctx, c.req(pk, m))
		return err
	}
	r.start()
	cl := ls.connect()
	waitReady(t, cl)
	ls.load(cl)
	e0 := c.stableEpoch(t) + 3
	s0 := e0 - 1
	var last uint64
	for e := e0; e < e0+3; e++ {
		c.waitEpoch(t, e)
		if err := sign(cl, att(s0, e, 0x10)); err != nil {
			t.Fatalf("before the restart, target %d: %v", e, err)
		}
		last = e
	}
	firstClaim := lastClaim(t, r.logText())
	r.stop()
	before := ls.records()
	if err := os.RemoveAll(r.stateDir); err != nil {
		t.Fatal(err)
	}

	r.start()
	cl = ls.connect()
	h := waitReady(t, cl)
	switch {
	case ls.restored && h.Validators != 1:
		t.Fatalf("%d validators after the state was wiped, want the share back from the state copy", h.Validators)
	case !ls.restored && h.Validators != 0:
		t.Fatalf("%d validators after the state was wiped", h.Validators)
	}
	// The newest record holds the last target signed, or the next epoch
	// if the raise at three quarters of the epoch ran before the stop.
	text := r.logText()
	if nt := newestTarget(text); nt != last && nt != last+1 {
		t.Fatalf("the restarted runner read target %d, want the newest record (target %d or %d)", nt, last, last+1)
	}
	claim := lastClaim(t, text)
	t.Logf("state wiped: %d records in the log, first claim at version %s, the new claim at version %s, newest target %d, health %q, validators %d",
		before, firstClaim, claim, last, h.Record, h.Validators)
	if !ls.restored {
		ls.load(cl)
	}
	start := c.stableEpoch(t)
	surround, signed := 0, 0
	for e := start; e < start+6; e++ {
		c.waitEpoch(t, e)
		errS := sign(cl, att(s0-2, e, 0x30))
		errN := sign(cl, att(s0, e, 0x20))
		t.Logf("after the restart, target %d: source %d (below the log's) %s | source %d %s", e, s0-2, short(errS), s0, short(errN))
		if errS == nil {
			surround++
		}
		if errN == nil {
			signed++
		}
	}
	if surround != 0 || signed == 0 {
		t.Fatalf("after the restart: %d votes with a lower source signed, %d with the log's source", surround, signed)
	}
	return s0, last
}

// surroundControl: a runner on an empty log, which is what a restart with
// lost state was before (a new mark key, no record it could read). With a
// share imported without history it refuses the lower source too: the
// restart floor bounds sources until an import carries vote history (issue
// #5 R2). A second runner whose import carries history with a lower source
// signs it: the carried history, not the floor, sets the bound.
func surroundControl(t *testing.T, c chain, sk [32]byte, pk backend.Pubkey, s0 uint64) {
	t.Helper()
	try := func(name string, interchange *backend.Watermark, tag byte) (signedAt uint64, ok bool) {
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r := newRunner(t, name, c, addr, "-mark-store", "file:"+t.TempDir(), "-mark-signer", "s1")
		r.start()
		defer r.stop()
		cl := client(t, addr)
		waitReady(t, cl)
		if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7, Interchange: interchange}); err != nil {
			t.Fatal(err)
		}
		start := c.stableEpoch(t)
		for e := start; e < start+6; e++ {
			c.waitEpoch(t, e)
			if _, err := cl.Sign(ctx, c.req(pk, att(s0-2, e, tag))); err == nil {
				return e, true
			}
		}
		return 0, false
	}
	if e, ok := try("empty-log", nil, 0x31); ok {
		t.Fatalf("control, empty log, import without history: source %d signed at target %d below the restart floor", s0-2, e)
	}
	t.Logf("control, empty log, import without history: source %d refused (restart floor)", s0-2)
	carried := &backend.Watermark{HasAttestation: true, SourceEpoch: s0 - 3, TargetEpoch: s0 - 2}
	e, ok := try("empty-log-history", carried, 0x32)
	if !ok {
		t.Fatalf("control, empty log, import with history (source %d): source %d refused", s0-3, s0-2)
	}
	t.Logf("control, empty log, import with history (source %d): source %d signed at target %d", s0-3, s0-2, e)
}

func plainImport(t *testing.T, sk [32]byte, pk backend.Pubkey) func(*remote.Client) {
	return func(cl *remote.Client) {
		t.Helper()
		if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
			t.Fatal(err)
		}
	}
}

// The dev platform with a file log: lost state, then another image
// (-platform-opt measurement, the dev stand-in for the measurement) and
// another position (-mark-signer s2) try the log.
func TestE2EMarkLogLostState(t *testing.T) {
	c := newChain(t)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	logDir := t.TempDir()
	flags := []string{"-mark-store", "file:" + logDir, "-mark-signer", "s1"}
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunner(t, "s1", c, addr, flags...)
	ls := lostState{c: c, r: r, connect: func() *remote.Client { return client(t, addr) }, load: plainImport(t, sk, pk),
		records: func() int { return len(logRecords(t, logDir, "s1")) }}
	s0, _ := ls.run(t, pk)
	surroundControl(t, c, sk, pk, s0)
	r.stop()

	// Another image: its key release does not open the records' keys.
	other := newRunner(t, "other-image", c, fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)),
		append(flags, "-platform-opt", "measurement=another-image")...)
	other.start()
	if !waitExit(t, other, 20*time.Second) || !strings.Contains(other.logText(), "none is a valid record") {
		t.Fatal("a runner of another image started on the log")
	}
	t.Logf("another image: %s", lastLine(other.logText(), "runner:"))

	// Another position: its own log works; its record copied under this
	// signer's next name does not count.
	addr2 := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	pos2 := newRunner(t, "s2", c, addr2, "-mark-store", "file:"+logDir, "-mark-signer", "s2")
	pos2.start()
	waitReady(t, client(t, addr2))
	pos2.stop()
	recs1, recs2 := logRecords(t, logDir, "s1"), logRecords(t, logDir, "s2")
	var next uint64
	fmt.Sscanf(recs1[len(recs1)-1], "%d", &next)
	next++
	b, err := os.ReadFile(filepath.Join(logDir, "marks", "s2", recs2[len(recs2)-1]))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(logDir, "marks", "s1", fmt.Sprintf("%020d", next))
	if err := os.WriteFile(copied, b, 0o400); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(r.stateDir)
	r.start()
	waitReady(t, client(t, addr))
	text := r.logText()
	if !strings.Contains(text, "not a valid record") || lastClaim(t, text) != fmt.Sprint(next+1) {
		t.Fatalf("the record of position s2 under the name of s1 version %d: claim at %s", next, lastClaim(t, text))
	}
	t.Logf("position s2's record copied to s1 version %d: skipped, s1 claims version %d with its own mark", next, next+1)
}

func lastLine(text, prefix string) string {
	out := ""
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, prefix) {
			out = l
		}
	}
	return out
}

// The same on a WORM fake of S3: the AWS debug build, dev platform, the S3
// client against wormfake with Object Lock.
func TestE2EMarkLogLostStateS3(t *testing.T) {
	c := newChain(t)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	srv := wormfake.New(wormfake.S3, "signer-marks")
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	flags := []string{"-allow-import", "-mark-store", "s3:bucket=signer-marks,region=eu-central-1,endpoint=" + srv.URL, "-mark-signer", "signer-2"}
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunnerOn(t, runnerBinary(t, "aws-debug"), "s3", c, addr, flags...)
	ls := lostState{c: c, r: r, connect: func() *remote.Client { return client(t, addr) }, load: plainImport(t, sk, pk),
		records: func() int { return len(srv.Names()) }}
	ls.run(t, pk)
	r.stop()
	other := newRunnerOn(t, runnerBinary(t, "aws-debug"), "s3-other-image", c, fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)),
		append(flags, "-platform-opt", "measurement=another-image")...)
	other.start()
	if !waitExit(t, other, 20*time.Second) || !strings.Contains(other.logText(), "none is a valid record") {
		t.Fatal("a runner of another image started on the S3 log")
	}
	t.Logf("S3 WORM fake: %d objects, another image refused: %s", len(srv.Names()), lastLine(other.logText(), "runner:"))
}

// ---- GCP: fake launcher, STS and Cloud KMS ----------------------------------

func fakeJWT(claims map[string]any) string {
	p, _ := json.Marshal(claims)
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

// fakeLauncher is the Confidential Space launcher of a VM that runs the
// image digest: its tokens carry it, as the image_digest claim does.
func fakeLauncher(t *testing.T, digest string) string {
	sock := filepath.Join(t.TempDir(), "teeserver.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Audience string   `json:"audience"`
			Nonces   []string `json:"nonces"`
		}
		if r.URL.Path != "/v1/token" || json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		w.Write([]byte(fakeJWT(map[string]any{"aud": req.Audience, "iat": time.Now().Unix(), "eat_nonce": req.Nonces,
			"swname": "CONFIDENTIAL_SPACE", "submods": map[string]any{"container": map[string]any{"image_digest": digest}}})))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// fakeGoogle is STS with the WIF provider's condition (the image digest
// must be the allowed one) and Cloud KMS (AES-GCM per key name with the
// request's additional authenticated data; 400 for a ciphertext that does
// not open).
func fakeGoogle(t *testing.T, allowed string) *httptest.Server {
	aeadFor := func(name string) cipher.AEAD {
		k := sha256.Sum256([]byte("fake kms|" + name))
		b, _ := aes.NewCipher(k[:])
		g, _ := cipher.NewGCM(b)
		return g
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/token":
			r.ParseForm()
			parts := strings.Split(r.Form.Get("subject_token"), ".")
			var c struct {
				Aud     string
				Submods struct {
					Container struct {
						ImageDigest string `json:"image_digest"`
					}
				}
			}
			if len(parts) != 3 {
				http.Error(w, "bad token", 400)
				return
			}
			p, _ := base64.RawURLEncoding.DecodeString(parts[1])
			json.Unmarshal(p, &c)
			if c.Aud != "https://sts.googleapis.com" || c.Submods.Container.ImageDigest != allowed {
				http.Error(w, `{"error":"unauthorized_client","error_description":"The given credential is rejected by the attribute condition."}`, 403)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "federated"})
		case strings.HasSuffix(r.URL.Path, ":encrypt"), strings.HasSuffix(r.URL.Path, ":decrypt"):
			if r.Header.Get("Authorization") != "Bearer federated" {
				http.Error(w, "unauthorized", 401)
				return
			}
			name, op, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), ":")
			g := aeadFor(name)
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			aad, _ := base64.StdEncoding.DecodeString(in["additionalAuthenticatedData"])
			if op == "encrypt" {
				b, _ := base64.StdEncoding.DecodeString(in["plaintext"])
				nonce := make([]byte, g.NonceSize())
				rand.Read(nonce)
				json.NewEncoder(w).Encode(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, b, aad))})
				return
			}
			b, _ := base64.StdEncoding.DecodeString(in["ciphertext"])
			var p []byte
			var err error = fmt.Errorf("short")
			if len(b) >= g.NonceSize() {
				p, err = g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], aad)
			}
			if err != nil {
				http.Error(w, `{"error":{"code":400,"message":"Decryption failed: the ciphertext is invalid.","status":"INVALID_ARGUMENT"}}`, 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(p), "usedPrimary": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// acceptAny stands in for the gcp-cs verifier: the fake launcher's tokens
// are not signed. The sealed import itself is the real one.
func acceptAny(context.Context, []byte, *backend.Identity) error { return nil }

// The GCP debug build: Confidential Space launcher, STS and KMS faked,
// the Cloud Storage client against wormfake with a locked retention policy.
// Then another image (STS refuses its token) and another KMS key (a key
// release that does not open the records' keys) try the log.
func TestE2EMarkLogLostStateGCP(t *testing.T) {
	c := newChain(t)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	const image = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	g := fakeGoogle(t, image)
	srv := wormfake.New(wormfake.GCS, "signer-marks")
	t.Cleanup(srv.Close)
	gcp := func(name, launcher, kmsKey string) (*runner, string) {
		sock := filepath.Join(t.TempDir(), name+".sock")
		r := newRunnerOn(t, runnerBinary(t, "gcp-debug"), name, c, "unix:"+sock, "-platform", "gcp",
			"-mark-store", "gcs:bucket=signer-marks,endpoint="+srv.URL, "-mark-signer", "signer-3",
			"-platform-opt", "socket="+launcher,
			"-platform-opt", "wif_provider=//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"-platform-opt", "kms_key=projects/p/locations/l/keyRings/r/cryptoKeys/"+kmsKey,
			"-platform-opt", "test_google_url="+g.URL)
		return r, "unix:" + sock
	}
	r, addr := gcp("gcp", fakeLauncher(t, image), "sealing")
	load := func(cl *remote.Client) {
		t.Helper()
		if _, err := adminOf(cl).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}, pk, acceptAny); err != nil {
			t.Fatal(err)
		}
	}
	ls := lostState{c: c, r: r, connect: func() *remote.Client { return client(t, addr) }, load: load,
		records: func() int { return len(srv.Names()) }}
	ls.run(t, pk)
	r.stop()

	otherImage, _ := gcp("gcp-other-image", fakeLauncher(t, "sha256:2222222222222222222222222222222222222222222222222222222222222222"), "sealing")
	otherImage.start()
	if !waitExit(t, otherImage, 20*time.Second) || !strings.Contains(otherImage.logText(), "attribute condition") {
		t.Fatal("a runner of another image started")
	}
	t.Logf("another image: %s", lastLine(otherImage.logText(), "runner:"))

	otherKey, _ := gcp("gcp-other-key", fakeLauncher(t, image), "another-key")
	otherKey.start()
	if !waitExit(t, otherKey, 20*time.Second) || !strings.Contains(otherKey.logText(), "none is a valid record") {
		t.Fatal("a runner with another KMS key started on the log")
	}
	t.Logf("another KMS key: %s", lastLine(otherKey.logText(), "runner:"))
}
