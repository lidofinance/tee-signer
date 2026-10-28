package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/jwtclaims"
)

type maaFixture struct {
	maa     *fakeMAA
	reports *testReports
	col     *fakeCollateral
	client  *MAAClient
}

func newMAAFixture(t *testing.T) *maaFixture {
	t.Helper()
	fx := newTLSFixture(t)
	col := &fakeCollateral{col: testCollateral()}
	m := newFakeMAA(t, fx, col.col)
	reports := &testReports{}
	copy(reports.hostData[:], bytes.Repeat([]byte{0x5a}, 32))
	return &maaFixture{maa: m, reports: reports, col: col,
		client: &MAAClient{Endpoint: m.host(), HTTP: m.srv.Client(), Reports: reports, Collateral: col}}
}

// TestMAARequestShape pins the request the runner sends for an identity and
// for the clock: the URL, the encodings, the report data, the runtime data
// bytes. The fake MAA refuses anything else. It also checks that the token
// the runner gets binds the runtime data the way a verifier recomputes it.
func TestMAARequestShape(t *testing.T) {
	f := newMAAFixture(t)
	ctx := context.Background()

	// Identity: user data is a SHA-256 (backend.IdentityUserData).
	ud := bytes.Repeat([]byte{0xab}, 32)
	a, err := (&Attester{MAA: f.client}).Attest(ctx, nil, ud)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.UserData, ud) || a.Platform != "azure" || a.Format != "azure-maa-jwt" {
		t.Fatalf("attestation %+v", a)
	}
	seen := f.maa.seen()
	if len(seen) != 1 {
		t.Fatalf("%d requests", len(seen))
	}
	wantRuntime := `{"signer-runner-identity":"` + strings.Repeat("ab", 32) + `"}`
	s := seen[0]
	if string(s.runtime) != wantRuntime {
		t.Fatalf("runtime data %q, want %q", s.runtime, wantRuntime)
	}
	if s.path != "/attest/SevSnpVM" || s.query != "api-version=2020-10-01" || s.contentType != "application/json" {
		t.Fatalf("request %s?%s (%s)", s.path, s.query, s.contentType)
	}
	if !bytes.Equal(s.certChain, f.col.col.CertChain) || !bytes.Equal(s.endorsement, f.col.col.UVMReferenceInfo) {
		t.Fatal("collateral not sent")
	}
	if len(f.col.tcb) != 1 || f.col.tcb[0] != testTCB {
		t.Fatalf("collateral asked for TCB %x", f.col.tcb)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(s.rawBody, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"report", "runtimeData", "initTimeData", "nonce"} {
		if _, ok := top[k]; !ok {
			t.Errorf("request has no %q", k)
		}
	}
	c, err := jwtclaims.Claims(string(a.Document))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(wantRuntime))
	if c["x-ms-sevsnpvm-reportdata"] != hex.EncodeToString(sum[:])+strings.Repeat("00", 32) {
		t.Fatalf("report data %v", c["x-ms-sevsnpvm-reportdata"])
	}
	if rt, _ := c["x-ms-runtime"].(map[string]any); rt["signer-runner-identity"] != strings.Repeat("ab", 32) || len(rt) != 1 {
		t.Fatalf("x-ms-runtime %v", c["x-ms-runtime"])
	}
	if c["x-ms-sevsnpvm-hostdata"] != strings.Repeat("5a", 32) {
		t.Fatalf("hostdata %v", c["x-ms-sevsnpvm-hostdata"])
	}

	// Clock: one key, a 32-byte nonce in hex.
	if _, err := (MAATime{MAA: f.client}).Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	seen = f.maa.seen()
	if len(seen) != 2 {
		t.Fatalf("%d requests", len(seen))
	}
	var obj map[string]string
	rt := seen[1].runtime
	if json.Unmarshal(rt, &obj) != nil || len(obj) != 1 || len(obj["signer-runner-clock"]) != 64 ||
		string(rt) != `{"signer-runner-clock":"`+obj["signer-runner-clock"]+`"}` {
		t.Fatalf("clock runtime data %q", rt)
	}
	if seen[0].nonce == seen[1].nonce {
		t.Error("the MAA nonce repeats")
	}

	// Runtime data that is not a JSON object never reaches the hardware or MAA.
	calls := f.reports.callCount()
	for _, bad := range [][]byte{ud, []byte("null"), []byte(`["a"]`), []byte(`"text"`), nil} {
		if _, err := f.client.Token(ctx, bad); err == nil {
			t.Errorf("runtime data %q accepted", bad)
		}
	}
	if f.reports.callCount() != calls || len(f.maa.seen()) != 2 {
		t.Fatal("a request went out for bad runtime data")
	}
}

func TestMAAClockToken(t *testing.T) {
	f := newMAAFixture(t)
	tm, err := MAATime{MAA: f.client}.Fetch(context.Background())
	if err != nil || tm.Unix() != f.maa.iat {
		t.Fatal(tm, err)
	}
	// A token that does not state the report data of this request is refused.
	f.maa.reportDataClaim = strings.Repeat("00", 64)
	if _, err := (MAATime{MAA: f.client}).Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "report data") {
		t.Fatalf("got %v", err)
	}
}

func TestMAAFailures(t *testing.T) {
	ctx := context.Background()
	rt := []byte(`{"k":"v"}`)

	t.Run("hardware error", func(t *testing.T) {
		f := newMAAFixture(t)
		f.reports.err = errors.New("no device")
		if _, err := f.client.Token(ctx, rt); err == nil || !strings.Contains(err.Error(), "no device") {
			t.Fatal(err)
		}
		if len(f.maa.seen()) != 0 {
			t.Fatal("MAA was called")
		}
	})
	t.Run("report without the requested report data", func(t *testing.T) {
		f := newMAAFixture(t)
		f.reports.tamper = func(r []byte) { r[reportDataOffset] ^= 1 }
		if _, err := f.client.Token(ctx, rt); err == nil || !strings.Contains(err.Error(), "report data") {
			t.Fatal(err)
		}
		if len(f.maa.seen()) != 0 {
			t.Fatal("MAA was called")
		}
	})
	t.Run("report of the wrong size", func(t *testing.T) {
		f := newMAAFixture(t)
		f.client.Reports = shortReports{}
		if _, err := f.client.Token(ctx, rt); err == nil || !strings.Contains(err.Error(), "1184") {
			t.Fatal(err)
		}
	})
	t.Run("collateral error", func(t *testing.T) {
		f := newMAAFixture(t)
		f.col.err = errors.New("no endorsements")
		if _, err := f.client.Token(ctx, rt); err == nil || !strings.Contains(err.Error(), "no endorsements") {
			t.Fatal(err)
		}
	})
	t.Run("MAA refuses: the answer is in the error, no retry", func(t *testing.T) {
		f := newMAAFixture(t)
		f.col.col = &Collateral{CertChain: []byte("other"), UVMReferenceInfo: []byte("other")}
		_, err := f.client.Token(ctx, rt)
		if err == nil || !strings.Contains(err.Error(), "collateral differs") || !strings.Contains(err.Error(), "400") {
			t.Fatal(err)
		}
	})
	t.Run("server errors are retried", func(t *testing.T) {
		f := newMAAFixture(t)
		f.maa.statuses = []int{503, 429}
		tok, err := f.client.Token(ctx, rt)
		if err != nil || tok == "" {
			t.Fatal(tok, err)
		}
		if len(f.maa.seen()) != 1 {
			t.Fatalf("%d accepted requests", len(f.maa.seen()))
		}
	})
	t.Run("server errors that go on", func(t *testing.T) {
		f := newMAAFixture(t)
		f.maa.statuses = []int{500, 500, 500, 500, 500}
		if _, err := f.client.Token(ctx, rt); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatal(err)
		}
	})
	t.Run("nil runtime data", func(t *testing.T) {
		if _, err := (&MAAClient{}).Token(ctx, nil); err == nil {
			t.Fatal("nil runtime data accepted")
		}
	})
	t.Run("context", func(t *testing.T) {
		f := newMAAFixture(t)
		f.maa.statuses = []int{500, 500, 500, 500}
		c, cancel := context.WithTimeout(ctx, time.Nanosecond)
		defer cancel()
		time.Sleep(time.Millisecond)
		if _, err := f.client.Token(c, rt); err == nil {
			t.Fatal("expired context accepted")
		}
	})
}

type shortReports struct{}

func (shortReports) Report([reportDataSize]byte) ([]byte, error) { return make([]byte, 100), nil }
