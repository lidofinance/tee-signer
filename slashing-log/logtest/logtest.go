// Package logtest is the shared test suite of the mark log stores: the
// write-once API of each client against its fake, and the mark log on top
// with the admin's rollback attempts and the store's faults. Each client
// package runs it from a test file behind its platform build tag.
package logtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/statestore"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// NewLog returns a client for the fake.
type NewLog func(t *testing.T, srv *wormfake.Server) markstore.Log

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// key is the key release of image n: runners of one image open each
// other's key blobs, runners of another image do not.
func key(n byte) platform.Keys { return dev.NewDevKeys(fmt.Sprintf("image-%d", n)) }

// downKeys is a key release that cannot be reached.
type downKeys struct{ platform.Keys }

func (downKeys) OpenKey(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("key service unreachable")
}

// Setup is setup n of signer-1 with a retention of days: its own
// setup_hash, version 0 of both groups.
func Setup(n byte, days uint32) *markstore.Setup {
	var h [32]byte
	h[0], h[31] = n, 0x5e
	return &markstore.Setup{Hash: h, Signer: "signer-1", RetentionDays: days,
		First: markstore.ConfigState{Locked: markstore.GroupState{Hash: [32]byte{0x10, n}}, Open: markstore.GroupState{Hash: [32]byte{0x20, n}}}}
}

// Update is a signed CONFIG_UPDATE of group g at version v; tag varies its
// content. The mark log checks its layout and hash only, not the
// signatures, so made-up ones do.
func Update(t testing.TB, g setupwire.Group, v uint64, tag byte) []byte {
	t.Helper()
	body := setupwire.UpdateBody{ClusterID: [32]byte{0xc1}, ChainHash: [32]byte{0xc2}, Group: g, Version: v,
		PrevHash: [32]byte{tag}, ActivateAt: 1_800_000_000 + uint64(tag)}
	n := setupwire.NumOpenLeaves
	switch g {
	case setupwire.GroupOpen:
		body.Open = &setupwire.Open{ForkSchedule: []setupwire.Fork{{Epoch: 100 + uint64(tag), Version: backend.Version{6, 0, 0, tag}}}}
	case setupwire.GroupLocked:
		n = setupwire.NumLockedLeaves
		pub := func(i byte) [32]byte {
			return [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32)).Public().(ed25519.PublicKey))
		}
		var wc backend.Root
		wc[0], wc[31] = 0x01, 0x42
		body.Locked = &setupwire.Locked{Approvers: setupwire.ApproverSet{Keys: [][32]byte{pub(1), pub(2), pub(3)}, ApprovalsNeeded: 2},
			BuilderGasLimitMin: 30_000_000, BuilderGasLimitMax: 30_000_000 + uint64(tag),
			ExitApprovalsNeeded: 2, MinActivationBalance: 32e9, MaxEffectiveBalance: 2048e9, WithdrawalCredentials: wc}
	}
	for i := range n {
		body.Salts = append(body.Salts, [32]byte{tag, byte(i + 1), byte(g)})
	}
	u := setupwire.Update{Body: body, Approvals: []setupwire.Approval{{Position: 0, Signature: [64]byte{tag}}, {Position: 1, Signature: [64]byte{tag, 1}}}}
	b, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// forge writes a record for signer-1 of setup s at version v under its
// name, signed with a key of release keys wrapped for the setup aadSetup
// and the position aadSigner: what a runner of another image (another
// release), of another setup or of another position (the same release,
// another signer) could write.
func forge(t *testing.T, srv *wormfake.Server, keys platform.Keys, s *markstore.Setup, aadSetup [32]byte, aadSigner string, v, prev uint64, mark backend.Watermark) {
	t.Helper()
	seed, blob, err := keys.NewKey(context.Background(), markstore.KeyAAD(aadSetup, aadSigner))
	if err != nil {
		t.Fatal(err)
	}
	r := markstore.Record{Setup: s.Hash, Signer: "signer-1", Version: v, PrevVersion: prev, LogID: [32]byte{9}, KeyBlob: blob,
		Mark: mark, State: s.First}
	srv.AdminCreate(markstore.Name(s.Hash, "signer-1", v), r.Sign(ed25519.NewKeyFromSeed(seed)))
}

// memStore is a platform.Store in memory, for the hint and the state copy.
type memStore map[string][]byte

func (m memStore) Get(k string) ([]byte, error) {
	if v, ok := m[k]; ok {
		return append([]byte(nil), v...), nil
	}
	return nil, platform.ErrNotFound
}
func (m memStore) Put(k string, v []byte) error { m[k] = append([]byte(nil), v...); return nil }
func (m memStore) List(prefix string) ([]string, error) {
	var out []string
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

// plainSealer binds the AAD but does not encrypt: enough for the hint's
// tests, which roll the store back, not forge it, and for the share AAD.
type plainSealer struct{}

func (plainSealer) Seal(p, aad []byte) ([]byte, error) {
	return append(append([]byte(nil), aad...), p...), nil
}
func (plainSealer) Unseal(b, aad []byte) ([]byte, error) {
	if len(b) < len(aad) || string(b[:len(aad)]) != string(aad) {
		return nil, errors.New("aad")
	}
	return b[len(aad):], nil
}

func wm(source, target, slot uint64) backend.Watermark {
	return backend.Watermark{HasAttestation: true, SourceEpoch: source, TargetEpoch: target, HasBlock: true, BlockSlot: slot}
}

const day = 24 * time.Hour

// Run is the whole suite for one kind of store.
func Run(t *testing.T, kind wormfake.Kind, newLog NewLog) {
	ctx := context.Background()
	fresh := func(t *testing.T) (*wormfake.Server, markstore.Log) {
		srv := wormfake.New(kind, "signer-marks")
		t.Cleanup(srv.Close)
		return srv, newLog(t, srv)
	}
	clockOf := func(srv *wormfake.Server) func() (time.Time, error) {
		return func() (time.Time, error) { return srv.Now(), nil }
	}
	// openSetup opens signer-1's log of setup s, on the fake's clock.
	openSetup := func(t *testing.T, srv *wormfake.Server, l markstore.Log, hint memStore, k platform.Keys, s *markstore.Setup) *markstore.MarkLog {
		t.Helper()
		opt := markstore.Options{Setup: s, Clock: clockOf(srv), Log: quiet}
		if hint != nil {
			opt.HintStore, opt.HintSealer = hint, plainSealer{}
		}
		m, err := markstore.New(l, "signer-1", k, opt)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	s1 := Setup(1, 30)
	open := func(t *testing.T, srv *wormfake.Server, l markstore.Log, hint memStore, k platform.Keys) *markstore.MarkLog {
		t.Helper()
		return openSetup(t, srv, l, hint, k, s1)
	}
	name := func(v uint64) string { return markstore.Name(s1.Hash, "signer-1", v) }

	t.Run("write-once API", func(t *testing.T) {
		srv, l := fresh(t)
		if err := l.Create(ctx, "a/1", []byte("one")); err != nil {
			t.Fatal(err)
		}
		if err := l.Create(ctx, "a/1", []byte("two")); !errors.Is(err, markstore.ErrExists) {
			t.Fatalf("second create: %v, want ErrExists", err)
		}
		for i := 2; i <= 8; i++ {
			if err := l.Create(ctx, "a/"+string(rune('0'+i)), []byte{byte(i)}); err != nil {
				t.Fatal(err)
			}
		}
		es, err := l.List(ctx, "a/")
		if err != nil || len(es) != 8 { // pages of 3
			t.Fatalf("list: %d entries, %v", len(es), err)
		}
		b, err := l.Get(ctx, es[0])
		if err != nil || string(b) != "one" {
			t.Fatalf("get: %q %v", b, err)
		}
		if _, err := l.Get(ctx, markstore.Entry{Name: "a/none"}); !errors.Is(err, markstore.ErrNotFound) {
			t.Fatalf("get missing: %v", err)
		}
		srv.SetHidden("a/2")
		if es, _ := l.List(ctx, "a/"); len(es) != 7 {
			t.Fatalf("hidden listing: %d entries, want 7", len(es))
		}
		srv.SetHidden("")
		srv.SetDown(true)
		if err := l.Create(ctx, "a/9", nil); err == nil {
			t.Fatal("create succeeded on a store that is down")
		}
		if _, err := l.List(ctx, "a/"); err == nil {
			t.Fatal("list succeeded on a store that is down")
		}
	})

	t.Run("fault plan: a dropped reply, then a failed write", func(t *testing.T) {
		// A create that landed but whose reply the host dropped: the retry
		// finds this runner's own record and goes on (issue #5 R7). A
		// create that failed before it landed: Append fails, the log stays
		// at the old version, and the next Append writes.
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		_, v := m.Mark()
		// Twice on S3: its client sends a request once more after a reset.
		create, times := http.MethodPut, 1
		switch kind {
		case wormfake.GCS:
			create = http.MethodPost
		case wormfake.S3:
			times = 2
		}
		srv.AddFault(wormfake.Fault{Method: create, Match: name(v + 1), Action: wormfake.ApplyThenDropReply, Times: times})
		if err := m.Append(ctx, wm(4, 5, 160)); err == nil {
			t.Fatal("the dropped reply did not reach Append")
		}
		srv.Advance(time.Second)
		if err := m.Append(ctx, wm(4, 5, 160)); err != nil || m.Lost() != nil {
			t.Fatalf("retry after a dropped reply: %v, lost %v", err, m.Lost())
		}
		if _, got := m.Mark(); got != v+1 {
			t.Fatalf("after the retry at version %d, want %d", got, v+1)
		}
		srv.AddFault(wormfake.Fault{Match: name(v + 2), Action: wormfake.FailBeforeApply})
		if err := m.Append(ctx, wm(5, 6, 192)); err == nil {
			t.Fatal("a write that failed was reported durable")
		}
		if err := m.Append(ctx, wm(5, 6, 192)); err != nil {
			t.Fatal(err)
		}
		if got, v2 := m.Mark(); v2 != v+2 || got.TargetEpoch != 6 {
			t.Fatalf("mark %+v at version %d, want target 6 at %d", got, v2, v+2)
		}
		if srv.Hits() != times+1 {
			t.Fatalf("fault plan hit %d requests, want %d", srv.Hits(), times+1)
		}
	})

	t.Run("claim, append, restart", func(t *testing.T) {
		srv, l := fresh(t)
		hint := memStore{}
		m := open(t, srv, l, hint, key(1))
		got, found, err := m.Claim(ctx, false)
		if err != nil || found || got != (backend.Watermark{}) {
			t.Fatalf("first claim: %+v %v %v", got, found, err)
		}
		id := m.LogID()
		if id == ([32]byte{}) || !m.State().Equal(s1.First) {
			t.Fatalf("first start: log_id %x, state %+v", id, m.State())
		}
		if names := srv.Names(); len(names) != 1 || names[0] != name(1) {
			t.Fatalf("record 1 under %v, want %s", names, name(1))
		}
		for e := uint64(10); e < 15; e++ {
			if err := m.Append(ctx, wm(e-1, e, e*32+31)); err != nil {
				t.Fatal(err)
			}
		}
		// A restart: a new process, same key release, same hint store.
		m2 := open(t, srv, l, hint, key(1))
		got, found, err = m2.Claim(ctx, true)
		if err != nil || !found || got != wm(13, 14, 14*32+31) {
			t.Fatalf("restart claim: %+v %v %v", got, found, err)
		}
		if m2.LogID() != id {
			t.Fatalf("restart: log_id %x, want %x", m2.LogID(), id)
		}
		// The old process is a clone now: its next write conflicts.
		if err := m.Append(ctx, wm(14, 15, 15*32+31)); !errors.Is(err, markstore.ErrLost) {
			t.Fatalf("old instance after a takeover: %v, want ErrLost", err)
		}
		if err := m.Append(ctx, wm(14, 16, 0)); !errors.Is(err, markstore.ErrLost) {
			t.Fatal("a lost instance wrote again")
		}
		if err := m2.Append(ctx, wm(14, 15, 15*32+31)); err != nil {
			t.Fatalf("new owner: %v", err)
		}
		// Another setup on the same bucket and signer name has a log of its
		// own: a first start, another log_id.
		m3 := openSetup(t, srv, l, nil, key(1), Setup(2, 30))
		if _, found, err := m3.Claim(ctx, false); err != nil || found || m3.LogID() == id {
			t.Fatalf("another setup: found %v, %v, log_id %x", found, err, m3.LogID())
		}
	})

	t.Run("fail closed: store down at start, empty log for a node with shares", func(t *testing.T) {
		srv, l := fresh(t)
		srv.SetDown(true)
		if _, _, err := open(t, srv, l, nil, key(1)).Claim(ctx, false); err == nil {
			t.Fatal("claim with the store down")
		}
		srv.SetDown(false)
		if _, _, err := open(t, srv, l, nil, key(1)).Claim(ctx, true); err == nil {
			t.Fatal("claim of an empty log by a node that holds shares")
		}
		m := markstore.Options{Setup: s1, Clock: clockOf(srv), AllowCreate: true, Log: quiet}
		ml, _ := markstore.New(l, "signer-1", key(1), m)
		if _, _, err := ml.Claim(ctx, true); err != nil {
			t.Fatalf("operator override: %v", err)
		}
		bad := markstore.Options{Setup: s1, Clock: func() (time.Time, error) { return time.Time{}, errors.New("no quorum") }, Log: quiet}
		ml, _ = markstore.New(l, "signer-1", key(1), bad)
		if _, _, err := ml.Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "no quorum") {
			t.Fatalf("claim without a trusted clock: %v", err)
		}
		if _, err := markstore.New(l, "signer-1", key(1), markstore.Options{Setup: s1}); err == nil {
			t.Fatal("a log with a setup and no trusted clock")
		}
	})

	t.Run("outage while running, then recovery", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := m.Append(ctx, wm(1, 2, 95)); err != nil {
			t.Fatal(err)
		}
		srv.SetDown(true)
		if err := m.Append(ctx, wm(2, 3, 127)); err == nil {
			t.Fatal("append with the store down")
		}
		if got, _ := m.Mark(); got != wm(1, 2, 95) {
			t.Fatalf("the mark moved without a write: %+v", got)
		}
		srv.SetDown(false)
		if err := m.Append(ctx, wm(2, 3, 127)); err != nil {
			t.Fatalf("after recovery: %v", err)
		}
	})

	t.Run("slow store: the caller's deadline holds", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		srv.SetDelay(2 * time.Second)
		c, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		if err := m.Append(c, wm(1, 2, 95)); err == nil || time.Since(start) > time.Second {
			t.Fatalf("slow append: %v after %v", err, time.Since(start))
		}
		srv.SetDelay(0)
	})

	t.Run("admin cannot roll back", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		for e := uint64(10); e < 14; e++ {
			if err := m.Append(ctx, wm(e-1, e, e*32)); err != nil {
				t.Fatal(err)
			}
		}
		_, v := m.Mark()
		newest := name(v)
		old, _ := srv.Current(name(2))
		// Delete: refused by the lock everywhere.
		if srv.AdminDelete(newest) {
			t.Fatal("locked record deleted")
		}
		// Overwrite: refused on GCS and Azure; on S3 a new version that
		// is not a valid record (it holds an older record's bytes).
		srv.AdminOverwrite(newest, old)
		// Hide behind a delete marker (S3 only; refused elsewhere).
		srv.AdminDeleteMarker(newest)
		// Replay an old record under the next name.
		srv.AdminCreate(name(v+1), old)
		got, _, err := open(t, srv, l, nil, key(1)).Claim(ctx, true)
		if err != nil || got != wm(12, 13, 13*32) {
			t.Fatalf("after the admin's attempts: %+v %v (want the newest mark)", got, err)
		}
		if kind != wormfake.S3 && len(srv.Refused) < 3 {
			t.Fatalf("the lock refused only %v", srv.Refused)
		}
	})

	t.Run("records under another key release, setup or signer do not count", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := m.Append(ctx, wm(4, 5, 160)); err != nil {
			t.Fatal(err)
		}
		_, v := m.Mark()
		// Another image (another key release) writes the next versions
		// with a lower mark, a runner of another setup and one of another
		// position write under this signer's name: none counts.
		forge(t, srv, key(2), s1, s1.Hash, "signer-1", v+1, v, wm(0, 1, 1))
		forge(t, srv, key(1), s1, s1.Hash, "signer-2", v+2, v, wm(0, 1, 1))
		forge(t, srv, key(1), s1, Setup(2, 30).Hash, "signer-1", v+3, v, wm(0, 1, 1))
		m2 := open(t, srv, l, nil, key(1))
		got, _, err := m2.Claim(ctx, true)
		if err != nil || got != wm(4, 5, 160) {
			t.Fatalf("with foreign records on top: %+v %v", got, err)
		}
		if _, v2 := m2.Mark(); v2 != v+4 {
			t.Fatalf("claim at version %d, want %d (past the three foreign objects)", v2, v+4)
		}
	})

	t.Run("restart with lost local state", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, memStore{}, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		for e := uint64(20); e < 40; e++ { // more than maxSkips records
			if err := m.Append(ctx, wm(e-1, e, e*32)); err != nil {
				t.Fatal(err)
			}
		}
		_, v := m.Mark()
		// A new process with an empty state directory: no hint, no shares,
		// the same image (key release).
		m2 := open(t, srv, l, memStore{}, key(1))
		got, found, err := m2.Claim(ctx, false)
		if err != nil || !found || got != wm(38, 39, 39*32) {
			t.Fatalf("after losing the state: %+v %v %v", got, found, err)
		}
		if _, v2 := m2.Mark(); v2 != v+1 {
			t.Fatalf("claimed version %d, want %d", v2, v+1)
		}
		if err := m2.Append(ctx, wm(39, 40, 40*32)); err != nil {
			t.Fatal(err)
		}
		// The old process (a clone now) loses its next write.
		if err := m.Append(ctx, wm(39, 40, 40*32+1)); !errors.Is(err, markstore.ErrLost) {
			t.Fatalf("old instance: %v, want ErrLost", err)
		}
		// Another image with an empty state finds records it cannot open
		// and does not start; nor does a runner whose key release is down.
		if _, _, err := open(t, srv, l, memStore{}, key(2)).Claim(ctx, false); err == nil {
			t.Fatal("another image claimed the log")
		}
		if _, _, err := open(t, srv, l, memStore{}, downKeys{key(1)}).Claim(ctx, false); err == nil || !strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("key release down: %v", err)
		}
	})

	t.Run("stale listing is caught by the hint", func(t *testing.T) {
		srv, l := fresh(t)
		hint := memStore{}
		m := open(t, srv, l, hint, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		for e := uint64(1); e < 5; e++ {
			if err := m.Append(ctx, wm(e-1, e, e*32)); err != nil {
				t.Fatal(err)
			}
		}
		srv.SetStale(2) // the listing misses the last two records
		_, _, err := open(t, srv, l, hint, key(1)).Claim(ctx, true)
		if err == nil || !strings.Contains(err.Error(), "listing stale") {
			t.Fatalf("stale listing: %v", err)
		}
		srv.SetStale(0)
		if _, _, err := open(t, srv, l, hint, key(1)).Claim(ctx, true); err != nil {
			t.Fatalf("fresh listing: %v", err)
		}
	})

	t.Run("lock self-check", func(t *testing.T) {
		srv, l := fresh(t)
		if err := markstore.CheckLock(ctx, l, 30); err != nil {
			t.Fatalf("compliance, 30 days: %v", err)
		}
		for _, c := range []struct {
			lock    wormfake.Lock
			minDays uint32
			why     string
		}{
			{wormfake.DefaultLock, 31, "retention shorter than slashing_log_min_lock_days"},
			{wormfake.Lock{Compliance: false, Days: 30}, 30, "governance mode or an unlocked policy"},
			{wormfake.Lock{None: true}, 1, "no lock"},
		} {
			srv.SetLock(c.lock)
			if err := markstore.CheckLock(ctx, l, c.minDays); !errors.Is(err, markstore.ErrNoLock) {
				t.Errorf("%s: %v, want ErrNoLock", c.why, err)
			}
		}
		srv.SetLock(wormfake.DefaultLock)
		srv.SetDown(true)
		if err := markstore.CheckLock(ctx, l, 30); err == nil {
			t.Fatal("lock check with the store down")
		}
		srv.SetDown(false)
		fl, _ := markstore.NewFileLog(t.TempDir())
		if err := markstore.CheckLock(ctx, fl, 1); !errors.Is(err, markstore.ErrNoLock) {
			t.Fatalf("file log: %v", err)
		}
	})

	t.Run("config state and update bodies", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := m.Append(ctx, wm(4, 5, 160)); err != nil {
			t.Fatal(err)
		}
		lu, ou := Update(t, setupwire.GroupLocked, 1, 1), Update(t, setupwire.GroupOpen, 3, 2)
		// An admin squats the open body's first copy name.
		srv.AdminCreate(markstore.BodyName(s1.Hash, setupwire.GroupOpen, 3, 1), []byte("not the update"))
		_, _, lh, err := m.PutBody(ctx, lu)
		if err != nil {
			t.Fatal(err)
		}
		g, v, oh, err := m.PutBody(ctx, ou)
		if err != nil || g != setupwire.GroupOpen || v != 3 {
			t.Fatalf("put open body: %v %d %v", g, v, err)
		}
		before := len(srv.Names())
		if _, _, _, err := m.PutBody(ctx, ou); err != nil || len(srv.Names()) != before {
			t.Fatalf("the same update again: %v, %d objects, want %d", err, len(srv.Names()), before)
		}
		// A state naming a body that is not in the log, or going back.
		missing := s1.First.Clone()
		missing.Open.Pending = &markstore.Pending{Version: 4, Hash: [32]byte{4}, EffectiveAt: 1}
		if err := m.SetState(ctx, missing); err == nil {
			t.Fatal("a state naming a body that is not in the log")
		}
		st := s1.First.Clone()
		st.Locked.Pending = &markstore.Pending{Version: 1, Hash: lh, EffectiveAt: 2_000_000_000}
		st.Open = markstore.GroupState{Version: 3, Hash: oh}
		if err := m.SetState(ctx, st); err != nil {
			t.Fatal(err)
		}
		back := st.Clone()
		back.Open = s1.First.Open
		if err := m.SetState(ctx, back); err == nil {
			t.Fatal("open went back to version 0")
		}
		if err := m.Append(ctx, wm(5, 6, 192)); err != nil {
			t.Fatal(err)
		}
		// A restart reads the newest state, which every record carries, and
		// the bodies it names (the open one from copy 2, past the squatter).
		m2 := open(t, srv, l, nil, key(1))
		if got, _, err := m2.Claim(ctx, true); err != nil || got != wm(5, 6, 192) {
			t.Fatalf("restart: %+v %v", got, err)
		}
		if !m2.State().Equal(st) {
			t.Fatalf("restart read state %+v, want %+v", m2.State(), st)
		}
		for _, c := range []struct {
			g    setupwire.Group
			v    uint64
			want []byte
		}{{setupwire.GroupLocked, 1, lu}, {setupwire.GroupOpen, 3, ou}} {
			if b, _, err := m2.Body(c.g, c.v); err != nil || !bytes.Equal(b, c.want) {
				t.Fatalf("restart: body of %s %d: %v", c.g, c.v, err)
			}
		}
		// The pending update becomes active.
		act := st.Clone()
		act.Locked = markstore.GroupState{Version: 1, Hash: lh}
		if err := m2.SetState(ctx, act); err != nil {
			t.Fatal(err)
		}
		m3 := open(t, srv, l, nil, key(1))
		if _, _, err := m3.Claim(ctx, true); err != nil || !m3.State().Equal(act) {
			t.Fatalf("after activation: %+v %v", m3.State(), err)
		}
		// A clone (the process before the restart) writes nothing more.
		if err := m2.SetState(ctx, act); !errors.Is(err, markstore.ErrLost) {
			t.Fatalf("lost instance, config state: %v", err)
		}
		if _, _, _, err := m2.PutBody(ctx, Update(t, setupwire.GroupOpen, 4, 3)); !errors.Is(err, markstore.ErrLost) {
			t.Fatalf("lost instance, body: %v", err)
		}
	})

	t.Run("body refresh keeps bodies and the log past the retention", func(t *testing.T) {
		srv, l := fresh(t)
		ret := time.Duration(s1.RetentionDays) * day
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		id := m.LogID()
		ou := Update(t, setupwire.GroupOpen, 1, 7)
		_, _, oh, err := m.PutBody(ctx, ou)
		if err != nil {
			t.Fatal(err)
		}
		st := s1.First.Clone()
		st.Open.Pending = &markstore.Pending{Version: 1, Hash: oh, EffectiveAt: uint64(srv.Now().Add(400 * day).Unix())}
		if err := m.SetState(ctx, st); err != nil {
			t.Fatal(err)
		}
		_, v0 := m.Mark()
		if err := m.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, v := m.Mark(); v != v0 {
			t.Fatal("refresh wrote with nothing to do")
		}
		// A day later, nothing else written: a keep-alive record.
		srv.Advance(day + time.Minute)
		if err := m.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, v := m.Mark(); v != v0+1 {
			t.Fatalf("no keep-alive record (version %d)", v)
		}
		// Past half the retention: copy 2 of the body, then a record that
		// names it.
		srv.Advance(ret/2 - day)
		if err := m.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := srv.Current(markstore.BodyName(s1.Hash, setupwire.GroupOpen, 1, 2)); !ok {
			t.Fatal("no second copy of the body")
		}
		// Past the retention of copy 1 and of the first records. The admin
		// deletes them.
		srv.Advance(ret/2 - day + time.Hour)
		for i := 0; i < 3; i++ {
			srv.Advance(day)
			if err := m.Refresh(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if n := srv.AdminDeleteExpired(); n == 0 {
			t.Fatal("nothing expired")
		}
		if _, ok := srv.Current(name(1)); ok {
			t.Fatal("record 1 did not expire")
		}
		m2 := open(t, srv, l, nil, key(1))
		if _, _, err := m2.Claim(ctx, true); err != nil {
			t.Fatalf("restart after record 1 and copy 1 expired: %v", err)
		}
		if m2.LogID() != id || !m2.State().Equal(st) {
			t.Fatalf("restart: log_id %x (want %x), state %+v", m2.LogID(), id, m2.State())
		}
		if b, _, err := m2.Body(setupwire.GroupOpen, 1); err != nil || !bytes.Equal(b, ou) {
			t.Fatalf("body after copy 1 expired: %v", err)
		}
	})

	t.Run("age check: newest record older than half the retention", func(t *testing.T) {
		srv, l := fresh(t)
		ret := time.Duration(s1.RetentionDays) * day
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		srv.Advance(ret/2 - time.Hour)
		if _, _, err := open(t, srv, l, nil, key(1)).Claim(ctx, true); err != nil {
			t.Fatalf("restart within half the retention: %v", err)
		}
		srv.Advance(ret/2 + time.Hour)
		if _, _, err := open(t, srv, l, nil, key(1)).Claim(ctx, true); !errors.Is(err, markstore.ErrTooOld) {
			t.Fatalf("restart past half the retention: %v, want ErrTooOld", err)
		}
	})

	t.Run("log made again after expiry: new log_id, old shares do not open", func(t *testing.T) {
		srv, l := fresh(t)
		ret := time.Duration(s1.RetentionDays) * day
		pk := backend.Pubkey{0xaa, 0x01}
		// First life: the log, a state copy in the same bucket, and a share
		// sealed under the log's log_id.
		local := memStore{}
		sc, err := statestore.Open(ctx, local, l, "signer-1", key(1), statestore.Options{SetupHash: s1.Hash, Now: srv.Now, Log: quiet})
		if err != nil {
			t.Fatal(err)
		}
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := m.Append(ctx, wm(9, 10, 320)); err != nil {
			t.Fatal(err)
		}
		old := m.LogID()
		blob, _ := plainSealer{}.Seal([]byte("share"), markstore.ShareAAD(s1.Hash, old, pk))
		srv.Advance(2 * day)
		if err := sc.Put("shares/aa01", blob); err != nil {
			t.Fatal(err)
		}
		// The host keeps the signer stopped until its records expired (the
		// newer commit has not), the admin deletes what expired, and the
		// listing hides the state copy's objects, so the shares are gone
		// at List.
		srv.Advance(ret - day)
		srv.AdminDeleteExpired()
		if _, ok := srv.Current(statestore.Name(s1.Hash, "signer-1", 1)); !ok {
			t.Fatal("the commit expired too; the test wants it hidden")
		}
		srv.SetHidden(statestore.Prefix(s1.Hash, "signer-1"))
		local2 := memStore{}
		if _, err := statestore.Open(ctx, local2, l, "signer-1", key(1), statestore.Options{SetupHash: s1.Hash, Now: srv.Now, Log: quiet}); err != nil {
			t.Fatal(err)
		}
		listed, _ := local2.List("shares/")
		if len(listed) != 0 {
			t.Fatalf("hidden commits restored %v", listed)
		}
		// A node that still lists its shares refuses the empty log.
		if _, _, err := open(t, srv, l, nil, key(1)).Claim(ctx, true); err == nil {
			t.Fatal("claim of an expired log by a node that lists shares")
		}
		m2 := open(t, srv, l, nil, key(1))
		if _, found, err := m2.Claim(ctx, len(listed) > 0); err != nil || found {
			t.Fatalf("first start after expiry: %v %v", found, err)
		}
		if m2.LogID() == old || !m2.State().Equal(s1.First) {
			t.Fatalf("log made again: log_id %x (old %x), state %+v", m2.LogID(), old, m2.State())
		}
		// Shares from before do not open under the new log_id.
		if _, err := (plainSealer{}).Unseal(blob, markstore.ShareAAD(s1.Hash, m2.LogID(), pk)); err == nil {
			t.Fatal("a share from before the expiry opened in the new log")
		}
		if _, err := (plainSealer{}).Unseal(blob, markstore.ShareAAD(s1.Hash, old, pk)); err != nil {
			t.Fatal("the share does not open under its own log_id either")
		}
	})

	t.Run("tombstone names the target setup", func(t *testing.T) {
		srv, l := fresh(t)
		m := open(t, srv, l, nil, key(1))
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := m.Append(ctx, wm(9, 10, 320)); err != nil {
			t.Fatal(err)
		}
		target := Setup(3, 30).Hash
		before, err := m.HandOverTo(ctx, target)
		if err != nil || before != wm(9, 10, 320) {
			t.Fatalf("handover: %+v %v", before, err)
		}
		if _, err := m.HandOverTo(ctx, Setup(4, 30).Hash); err == nil {
			t.Fatal("a second target for one tombstone")
		}
		m2 := open(t, srv, l, nil, key(1))
		if got, _, err := m2.Claim(ctx, true); err != nil || !markstore.IsTombstone(got) {
			t.Fatalf("restart after the handover: %+v %v", got, err)
		}
		if got, ok := m2.HandedOverTo(); !ok || got != target {
			t.Fatalf("restart: target %x %v", got, ok)
		}
		if again, err := m2.HandOverTo(ctx, target); err != nil || again != before {
			t.Fatalf("handover repeated to the same target: %+v %v", again, err)
		}
	})

	t.Run("flag path without a setup: names marks/<signer>/", func(t *testing.T) {
		srv, l := fresh(t)
		m, err := markstore.New(l, "signer-1", key(1), markstore.Options{Log: quiet})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		if names := srv.Names(); len(names) != 1 || names[0] != "marks/signer-1/00000000000000000001" {
			t.Fatalf("names %v", names)
		}
		if _, _, _, err := m.PutBody(ctx, Update(t, setupwire.GroupOpen, 1, 1)); err == nil {
			t.Fatal("a body without a setup")
		}
		m2, _ := markstore.New(l, "signer-1", key(1), markstore.Options{Log: quiet})
		if _, _, err := m2.Claim(ctx, false); err != nil || m2.LogID() != m.LogID() {
			t.Fatalf("restart: %v", err)
		}
	})
}
