package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/gateway/internal/backend"
	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// countingSigner counts the calls that reach it. With a gate, each call
// waits until the gate closes. It is safe for concurrent requests.
type countingSigner struct {
	keys    map[phase0.BLSPubKey]bool
	started chan struct{}

	mu    sync.Mutex
	calls int
	gate  chan struct{}
	err   error
}

func (f *countingSigner) PublicKeys(context.Context) []phase0.BLSPubKey { return nil }

func (f *countingSigner) HasKey(_ context.Context, k phase0.BLSPubKey) bool { return f.keys[k] }

func (f *countingSigner) do() (phase0.BLSSignature, error) {
	f.mu.Lock()
	f.calls++
	gate, err := f.gate, f.err
	f.mu.Unlock()
	f.started <- struct{}{}
	if gate != nil {
		<-gate
	}

	return (&fakeSigner{}).sig(), err
}

func (f *countingSigner) Sign(context.Context, phase0.BLSPubKey, *signing.Job) (phase0.BLSSignature, error) {
	return f.do()
}

func (f *countingSigner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

func (f *countingSigner) set(gate chan struct{}, err error) {
	f.mu.Lock()
	f.gate, f.err = gate, err
	f.mu.Unlock()
}

// lockedBuffer is a log sink that tests may read while handlers write.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) lines(msg string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, l := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(l, " msg="+msg+" ") || strings.Contains(l, ` msg="`+msg+`" `) {
			out = append(out, l)
		}
	}

	return out
}

const otherPubHex = "0x" + "a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9e0e1e2e3e4e5e6e7e8"

// newSharingServer is a test server with coalescing that keeps results for
// keep (no coalescing when keep is negative), over a countingSigner that
// holds pubHex and otherPubHex.
func newSharingServer(t *testing.T, keep time.Duration) (*httptest.Server, *countingSigner, *lockedBuffer) {
	t.Helper()
	pk, _ := parsePubkey(pubHex)
	other, _ := parsePubkey(otherPubHex)
	f := &countingSigner{keys: map[phase0.BLSPubKey]bool{pk: true, other: true}, started: make(chan struct{}, 64)}
	pol, err := policy.New([]string{allowedFeeRecipient})
	if err != nil {
		t.Fatal(err)
	}
	h, err := eth2.NewHasher("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	chain := signing.Chain{Hasher: h, SlotsPerEpoch: 32, GenesisForkVersion: phase0.Version{}}
	s := New(f, pol, chain, slog.New(slog.NewTextHandler(logs, nil)), 0)
	if keep >= 0 {
		s = s.WithCoalescing(keep)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	return srv, f, logs
}

type reply struct {
	code int
	body string
	err  error
}

// postAsync sends one request on its own goroutine.
func postAsync(srv *httptest.Server, key, body string) <-chan reply {
	out := make(chan reply, 1)
	go func() {
		resp, err := http.Post(srv.URL+"/api/v1/eth2/sign/"+key, "application/json", strings.NewReader(body))
		if err != nil {
			out <- reply{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		out <- reply{code: resp.StatusCode, body: string(b)}
	}()

	return out
}

func waitStarted(t *testing.T, f *countingSigner, n int) {
	t.Helper()
	for i := range n {
		select {
		case <-f.started:
		case <-time.After(2 * time.Second):
			t.Fatalf("%d of %d calls reached the signer", i, n)
		}
	}
}

func selectionProofBody(subcommittee int) string {
	return `{"type":"SYNC_COMMITTEE_SELECTION_PROOF",` + forkInfo +
		`,"sync_aggregator_selection_data":{"slot":"13164545","subcommittee_index":"` + string(rune('0'+subcommittee)) + `"}}`
}

const syncMessageBody = `{"type":"SYNC_COMMITTEE_MESSAGE",` + forkInfo + `,"sync_committee_message":{"beacon_block_root":"0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464","slot":"13164545"}}`

const blockBody = `{"type":"BLOCK_V2",` + forkInfo + `,"beacon_block":{"version":"FULU","block_header":{"slot":"13164545","proposer_index":"7",
	"parent_root":"0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
	"state_root":"0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
	"body_root":"0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"}}}`

// Five identical selection proofs at once (Grandine's repeats) make one
// call to the signers. The first request's line has signer_ms; the others say they
// shared (coalesced=true, or cache_hit=true if one arrived after the call
// ended). Every line keeps total_ms, the client's wait.
func TestServerCoalescesDuplicates(t *testing.T) {
	srv, f, logs := newSharingServer(t, time.Hour)
	gate := make(chan struct{})
	f.set(gate, nil)

	replies := []<-chan reply{postAsync(srv, pubHex, selectionProofBody(1))}
	waitStarted(t, f, 1)
	for range 4 {
		replies = append(replies, postAsync(srv, pubHex, selectionProofBody(1)))
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	var first string
	for i, ch := range replies {
		r := <-ch
		if r.err != nil || r.code != 200 {
			t.Fatalf("request %d: %+v", i, r)
		}
		if i == 0 {
			first = r.body
		} else if r.body != first {
			t.Fatalf("request %d got %s, the first got %s", i, r.body, first)
		}
	}
	if n := f.count(); n != 1 {
		t.Fatalf("%d calls reached the signer, want 1", n)
	}
	lines := logs.lines("signed")
	if len(lines) != 5 {
		t.Fatalf("%d signed lines, want 5:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	own, shared := 0, 0
	for _, l := range lines {
		if !strings.Contains(l, " total_ms=") {
			t.Errorf("no total_ms: %s", l)
		}
		switch {
		case strings.Contains(l, " signer_ms="):
			own++
		case strings.Contains(l, " coalesced=true ") || strings.Contains(l, " cache_hit=true "):
			shared++
		}
	}
	if own != 1 || shared != 4 {
		t.Fatalf("%d lines with signer_ms and %d shared, want 1 and 4:\n%s", own, shared, strings.Join(lines, "\n"))
	}
}

// A repeat after the call ended gets the stored signature until keep runs
// out, then makes a new call.
func TestServerCachesUntilKeepRunsOut(t *testing.T) {
	srv, f, logs := newSharingServer(t, 300*time.Millisecond)
	for i, want := range []int{1, 1} {
		if r := <-postAsync(srv, pubHex, syncMessageBody); r.code != 200 {
			t.Fatalf("request %d: %+v", i, r)
		}
		if n := f.count(); n != want {
			t.Fatalf("request %d: %d calls, want %d", i, n, want)
		}
	}
	if l := logs.lines("signed"); len(l) != 2 || !strings.Contains(l[1], " cache_hit=true ") || strings.Contains(l[1], "signer_ms") {
		t.Fatalf("second line should be a cache hit without signer_ms:\n%s", strings.Join(l, "\n"))
	}
	time.Sleep(400 * time.Millisecond)
	if r := <-postAsync(srv, pubHex, syncMessageBody); r.code != 200 || f.count() != 2 {
		t.Fatalf("after keep: %+v, %d calls, want a new call", r, f.count())
	}
}

// Attestations, blocks and registrations always make their own call, even
// when identical requests are in flight at the same moment.
func TestServerNeverSharesSlashableTypes(t *testing.T) {
	for name, body := range map[string]string{
		"attestation":  attestationBody(411400),
		"block":        blockBody,
		"registration": registrationBody(allowedFeeRecipient, pubHex),
	} {
		t.Run(name, func(t *testing.T) {
			srv, f, logs := newSharingServer(t, time.Hour)
			gate := make(chan struct{})
			f.set(gate, nil)
			var replies []<-chan reply
			for range 3 {
				replies = append(replies, postAsync(srv, pubHex, body))
			}
			// All three are at the signer together: none waited for another.
			waitStarted(t, f, 3)
			close(gate)
			for i, ch := range replies {
				if r := <-ch; r.code != 200 {
					t.Fatalf("request %d: %+v", i, r)
				}
			}
			if r := <-postAsync(srv, pubHex, body); r.code != 200 {
				t.Fatalf("repeat: %+v", r)
			}
			if n := f.count(); n != 4 {
				t.Fatalf("%d calls, want 4", n)
			}
			for _, l := range logs.lines("signed") {
				if strings.Contains(l, "coalesced") || strings.Contains(l, "cache_hit") || !strings.Contains(l, " signer_ms=") {
					t.Fatalf("line of a %s: %s", name, l)
				}
			}
		})
	}
}

// A refusal is not stored: the repeat calls again. Requests that waited for
// the refused call get the refusal too.
func TestServerDoesNotStoreErrors(t *testing.T) {
	srv, f, logs := newSharingServer(t, time.Hour)
	gate := make(chan struct{})
	f.set(gate, &backend.DeniedError{Detail: "not enough signatures: 0 signed, 3 denied, 0 failed, 0 errored"})
	a := postAsync(srv, pubHex, selectionProofBody(2))
	waitStarted(t, f, 1)
	b := postAsync(srv, pubHex, selectionProofBody(2))
	time.Sleep(100 * time.Millisecond)
	close(gate)
	for i, ch := range []<-chan reply{a, b} {
		if r := <-ch; r.code != 412 {
			t.Fatalf("request %d: %+v, want 412", i, r)
		}
	}
	if n := f.count(); n != 1 {
		t.Fatalf("%d calls, want 1", n)
	}
	if l := logs.lines("denied by signers"); len(l) != 2 || !strings.Contains(strings.Join(l, "\n"), " coalesced=true") {
		t.Fatalf("denied lines:\n%s", strings.Join(l, "\n"))
	}

	f.set(nil, nil)
	for i, want := range []int{2, 2} {
		if r := <-postAsync(srv, pubHex, selectionProofBody(2)); r.code != 200 || f.count() != want {
			t.Fatalf("after the refusal, request %d: %+v, %d calls, want %d", i, r, f.count(), want)
		}
	}
}

// Another validator, another signing root or another type is another
// signature and another call.
func TestServerSharesOnlySameKeyRootAndType(t *testing.T) {
	srv, f, _ := newSharingServer(t, time.Hour)
	for i, req := range []struct{ key, body string }{
		{pubHex, selectionProofBody(1)},
		{otherPubHex, selectionProofBody(1)},
		{pubHex, selectionProofBody(3)},
		{pubHex, syncMessageBody},
	} {
		if r := <-postAsync(srv, req.key, req.body); r.code != 200 || f.count() != i+1 {
			t.Fatalf("request %d: %+v, %d calls, want %d", i, r, f.count(), i+1)
		}
	}
}

// Without WithCoalescing every request makes its own call.
func TestServerWithoutCoalescing(t *testing.T) {
	srv, f, logs := newSharingServer(t, -1)
	for range 2 {
		if r := <-postAsync(srv, pubHex, selectionProofBody(1)); r.code != 200 {
			t.Fatalf("%+v", r)
		}
	}
	if n := f.count(); n != 2 {
		t.Fatalf("%d calls, want 2", n)
	}
	for _, l := range logs.lines("signed") {
		if !strings.Contains(l, " signer_ms=") || strings.Contains(l, "coalesced") || strings.Contains(l, "cache_hit") {
			t.Fatalf("line: %s", l)
		}
	}
}
