package server

import (
	"io"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/state"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// keyServer is a server whose core holds n validators and has room for
// one more.
func keyServer(t *testing.T, n int) *Server {
	t.Helper()
	cfg := software.DevConfig(uint64(time.Now().Unix())-3600, 12, 32)
	store, sealer := &shareStore{m: map[string][]byte{}}, dev.NewDevSealer()
	hooks, err := state.New(cfg, state.Mode{Floor: true, FloorMargin: state.DefaultFloorMargin(cfg)}, clock.System{}, store, sealer, quiet)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := core.NewSigner(cfg, uint32(n+1), 0, hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	for i := range n {
		addKey(t, signer, uint64(i))
	}
	return &Server{Signer: signer, Hooks: hooks, Platform: &platform.Platform{Name: "dev", Store: store, Sealer: sealer}, Log: quiet}
}

func addKey(t *testing.T, s *core.Signer, index uint64) {
	t.Helper()
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddValidator(pk, sk, index, nil); err != nil {
		t.Fatal(err)
	}
}

// publicKeys asks for PUBLIC_KEYS on a new connection and decodes the
// answer.
func publicKeys(t *testing.T, s *Server) []byte {
	t.Helper()
	peer, done := serveOne(s)
	defer func() { peer.Close(); <-done }()
	peer.SetDeadline(time.Now().Add(10 * time.Second))
	if err := wire.WriteFrame(peer, wire.Frame{Type: wire.TypePublicKeys, ID: 1}); err != nil {
		t.Fatal(err)
	}
	f, err := wire.ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := wire.DecodeResponse(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Peers that ask for PUBLIC_KEYS and stop reading the answer hold no copy
// of the key list each: their stalled writes share one answer. Before,
// each held its own frame buffer of 104 bytes per key: 256 such peers at
// 8192 keys held 221 MB of heap, now about 1 MB.
func TestStalledPublicKeysAnswersShareOneBuffer(t *testing.T) {
	const keys, conns = 1024, 64
	s := keyServer(t, keys)
	size := len(publicKeys(t, s))

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peers []net.Conn
	var dones []chan struct{}
	t.Cleanup(func() {
		for i, p := range peers {
			p.Close()
			<-dones[i]
		}
	})
	for range conns {
		peer, done := serveOne(s)
		peers, dones = append(peers, peer), append(dones, done)
		peer.SetDeadline(time.Now().Add(10 * time.Second))
		if err := wire.WriteFrame(peer, wire.Frame{Type: wire.TypePublicKeys, ID: 1}); err != nil {
			t.Fatal(err)
		}
		// One byte of the answer: the server is in its write, and stays
		// there, as this peer reads no more.
		if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d stalled answers of %d bytes hold %d heap bytes", conns, size, held)
	if held > int64(8*size) {
		t.Fatalf("%d stalled answers of %d bytes hold %d heap bytes, %d each: each holds its own copy of the key list",
			conns, size, held, held/conns)
	}
}

// The shared answer follows the key set: a key added after an answer is
// in the next one.
func TestPublicKeysAnswerFollowsKeySet(t *testing.T) {
	s := keyServer(t, 2)
	first, err := wire.DecodeKeys(publicKeys(t, s))
	if err != nil || len(first) != 2 {
		t.Fatalf("first answer %d keys, %v", len(first), err)
	}
	addKey(t, s.Signer, 9)
	got, err := wire.DecodeKeys(publicKeys(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if want := s.Signer.Keys(); !reflect.DeepEqual(got, want) {
		t.Fatalf("answer after a new key: %d keys, want %d", len(got), len(want))
	}
}
