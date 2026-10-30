//go:build nts

package ntscore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// The binding's constants and functions as the wrapper and the tests use
// them, and the core's AES-SIV against the test server's independent copy.

func TestKEValues(t *testing.T) {
	if ALPN != "ntske/1" || ExporterLabel != "EXPORTER-network-time-security" || KEPort != 4460 || KeyLen != 32 {
		t.Fatalf("ALPN %q, label %q, port %d, key %d", ALPN, ExporterLabel, KEPort, KeyLen)
	}
	if c := ExporterContext(false); !bytes.Equal(c, []byte{0, 0, 0, 15, 0}) {
		t.Fatalf("C2S context %x", c)
	}
	if c := ExporterContext(true); !bytes.Equal(c, []byte{0, 0, 0, 15, 1}) {
		t.Fatalf("S2C context %x", c)
	}
	if r := hex.EncodeToString(KERequest()); r != "80010002000080040002000f80000000" {
		t.Fatalf("KE request %s", r)
	}
	if _, done, err := KEComplete([]byte{0x80, 0x01}); done || err != nil {
		t.Fatalf("2 octets: done %v err %v", done, err)
	}
	if _, _, err := KEComplete([]byte{0x00, 0x05, 0x04, 0x01}); err == nil || !strings.Contains(err.Error(), "at most 1024") {
		t.Fatalf("over-long record: %v", err)
	}
	// The record rules: each refused response, and the reason.
	rec := func(critical bool, typ uint16, body ...byte) []byte {
		if critical {
			typ |= 0x8000
		}
		r := []byte{byte(typ >> 8), byte(typ), byte(len(body) >> 8), byte(len(body))}
		return append(r, body...)
	}
	eom := rec(true, 0)
	proto := rec(true, 1, 0, 0)
	aead := rec(true, 4, 0, 15)
	cookie := rec(false, 5, 1, 2, 3)
	join := func(rs ...[]byte) []byte {
		var out []byte
		for _, r := range rs {
			out = append(out, r...)
		}
		return out
	}
	if r, err := ParseKEResponse(join(proto, aead, cookie, rec(false, 6, 'h', 'o', 's', 't'), rec(false, 7, 0x10, 0x7b), eom)); err != nil || r.Server != "host" || r.Port != 4219 || len(r.Cookies) != 1 {
		t.Fatalf("good response: %+v %v", r, err)
	}
	for _, c := range []struct {
		name string
		resp []byte
		want string
	}{
		{"no cookie", join(proto, aead, eom), "no cookie"},
		{"no protocol", join(aead, cookie, eom), "no Next Protocol"},
		{"no aead", join(proto, cookie, eom), "no AEAD"},
		{"other aead", join(proto, rec(true, 4, 0, 30), cookie, eom), "AEAD_AES_SIV_CMAC_256"},
		{"other protocol", join(rec(true, 1, 0, 1), aead, cookie, eom), "NTPv4"},
		{"repeated protocol", join(proto, proto, aead, cookie, eom), "repeated"},
		{"error record", join(rec(true, 2, 0, 1), eom), "server error 1"},
		{"warning record", join(proto, aead, cookie, rec(true, 3, 0, 0), eom), "server warning 0"},
		{"unknown critical", join(proto, aead, cookie, rec(true, 99), eom), "unknown critical record 99"},
		{"trailing bytes", join(proto, aead, cookie, eom, []byte{1}), "after End of Message"},
		{"no eom", join(proto, aead, cookie), "before End of Message"},
		{"empty cookie", join(proto, aead, rec(false, 5), eom), "cookie of 0 octets"},
	} {
		if _, err := ParseKEResponse(c.resp); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// An unknown non-critical record is ignored; cookies past 8 are dropped.
	many := join(proto, aead)
	for i := 0; i < 12; i++ {
		many = append(many, cookie...)
	}
	if r, err := ParseKEResponse(join(many, rec(false, 99, 1, 2), eom)); err != nil || len(r.Cookies) != 8 {
		t.Fatalf("12 cookies and an unknown record: %+v %v", r, err)
	}
}

// The AES-SIV of the core against the test server's independent one, on
// random inputs.
func TestSIVMatchesTestServer(t *testing.T) {
	for i := 0; i < 200; i++ {
		key := make([]byte, 32)
		ad := make([]byte, i%40)
		nonce := make([]byte, 1+i%20)
		pt := make([]byte, i)
		for _, b := range [][]byte{key, ad, nonce, pt} {
			rand.Read(b)
		}
		k, err := NewSIVKey(key)
		if err != nil {
			t.Fatal(err)
		}
		ours := k.Seal([][]byte{ad, nonce}, pt)
		theirs := ntstest.Seal(key, ad, nonce, pt)
		if !bytes.Equal(ours, theirs) {
			t.Fatalf("%d: seal differs", i)
		}
		if p, ok := k.Open([][]byte{ad, nonce}, theirs); !ok || !bytes.Equal(p, pt) {
			t.Fatalf("%d: open of the server's ciphertext", i)
		}
		if _, ok := ntstest.Open(key, ad, nonce, ours); !ok {
			t.Fatalf("%d: the server does not open ours", i)
		}
	}
}

// The test server's AES-SIV against RFC 5297 appendix A.1, so the cross
// check above means something.
func TestTestServerSIVMatchesRFC5297(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	key := h("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := h("101112131415161718191a1b1c1d1e1f2021222324252627")
	pt := h("112233445566778899aabbccddee")
	want := h("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
	if got := ntstest.SealVector(key, [][]byte{ad}, pt); !bytes.Equal(got, want) {
		t.Fatalf("A.1: got %x, want %x", got, want)
	}
	ct := ntstest.Seal(key, ad, []byte("nonce"), pt)
	if p, ok := ntstest.Open(key, ad, []byte("nonce"), ct); !ok || !bytes.Equal(p, pt) {
		t.Fatal("open after seal failed")
	}
	ct[3] ^= 1
	if _, ok := ntstest.Open(key, ad, []byte("nonce"), ct); ok {
		t.Fatal("tampered ciphertext opened")
	}
}

// The core's functions are safe to call from many goroutines at once: the
// tables are set up once, and nothing else is shared.
func TestCallsFromManyGoroutines(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	key := make([]byte, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k, err := NewSIVKey(key)
				if err != nil {
					errs <- err
					return
				}
				ct := k.Seal([][]byte{{byte(i)}}, []byte{byte(j)})
				if p, ok := k.Open([][]byte{{byte(i)}}, ct); !ok || len(p) != 1 || p[0] != byte(j) {
					errs <- ErrNotAuthentic
					return
				}
				if _, err := Quorum([]Interval{{Operator: "a", Offset: 1, Bound: 1}, {Operator: "b", Offset: 1, Bound: 1}, {Operator: "c", Offset: 1, Bound: 1}}, 0); err != nil {
					errs <- err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestQuorumBinding(t *testing.T) {
	const ms = int64(time.Millisecond)
	in := []Interval{
		{Operator: "cloudflare", Offset: 100 * ms, Bound: 10 * time.Millisecond},
		{Operator: "netnod", Offset: 110 * ms, Bound: 15 * time.Millisecond},
		{Operator: "ptb", Offset: 102 * ms, Bound: 2 * time.Millisecond},
	}
	q, err := Quorum(in, 0)
	if err != nil || q.Lo != 95*ms || q.Hi != 110*ms || q.Offset != 102_500_000 || q.Bound != 7_500_000 {
		t.Fatalf("%+v %v", q, err)
	}
	in[2].Operator = "netnod"
	if _, err := Quorum(in, 0); err == nil || !strings.Contains(err.Error(), "two servers of one operator") {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := Quorum(in[:2], 0); err == nil {
		t.Fatal("two servers accepted")
	}
	if d := Drift(32 * time.Second); d != 16*time.Millisecond {
		t.Fatalf("Drift(32 s) = %v", d)
	}
	if AddBound(1, 2) != 3 || AddBound(-1, 2) != 1<<63-1 || AddBound(1<<62, 1<<62) != 1<<63-1 {
		t.Fatal("AddBound")
	}
}

func TestCoarseRefused(t *testing.T) {
	const limit, res = 30 * time.Second, time.Second
	if !CoarseRefused(31*time.Second, limit, res) || CoarseRefused(30999*time.Millisecond, limit, res) ||
		!CoarseRefused(-30001*time.Millisecond, limit, res) || CoarseRefused(-30*time.Second, limit, res) {
		t.Fatal("limits of the coarse check")
	}
}
