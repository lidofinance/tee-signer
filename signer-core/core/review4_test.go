package core_test

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Tests that reproduce findings of the security reviews in issues #4 and #5
// on lidofinance/threshold-signer-poc. Each asserts the behaviour the
// finding asks for, so each fails until its fix lands.

// deviceHooks are MemHooks with one device mark, kept across a restart
// when a test hands the same hooks to a second Signer.
type deviceHooks struct {
	*software.MemHooks
	mu    sync.Mutex
	mark  backend.Watermark
	found bool
}

func (h *deviceHooks) LoadDeviceMark() (backend.Watermark, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mark, h.found, nil
}

func (h *deviceHooks) StoreDeviceMark(wm backend.Watermark) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mark, h.found = wm, true
	return nil
}

// Issue #4 F2: the core raises the device source bound to the source of
// any vote it signs. A vote with source >= target, or with a source at or
// above the clock epoch, can only be hostile, yet it is signed and pins the
// source bound; after a restart every key starts from that bound and
// refuses honest votes until the chain justifies the pinned epoch. Such a
// vote must be refused and must not raise the bound.
func TestReview4F2HostileVotePinsSourceBound(t *testing.T) {
	for _, tc := range []struct {
		name           string
		hostile        *backend.AttestationData
		honestAfter    *backend.AttestationData // at clock epoch 23, justification lagging
		boundWithClock uint64                   // highest source an honest vote has at clock epoch 20
	}{
		{"source equals target", att(21, 21), att(20, 23), 19},
		{"source at the clock epoch", att(20, 21), att(19, 23), 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			epoch := uint64(20)
			h := &deviceHooks{MemHooks: software.NewMemHooks()}
			h.Clock = func() (uint64, error) { return clockAtEpoch(epoch)() }
			cfg := software.DevConfig(genesis, 12, 32)
			cfg.DeviceMark = true
			ska, _ := software.NewSecret()
			pka, _ := core.PubkeyOf(ska)
			skb, _ := software.NewSecret()
			pkb, _ := core.PubkeyOf(skb)
			start := func() *core.Signer {
				s, err := core.NewSigner(cfg, 4, 0, h)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Close)
				if _, err := s.AddValidator(pka, ska, 7, nil); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AddValidator(pkb, skb, 8, nil); err != nil {
					t.Fatal(err)
				}
				return s
			}
			s := start()
			if _, err := s.Sign(signReq(s, pka, tc.hostile)); err == nil {
				t.Errorf("hostile vote (source %d, target %d) at clock epoch %d signed", tc.hostile.Source.Epoch, tc.hostile.Target.Epoch, epoch)
			}
			if h.found && h.mark.SourceEpoch > tc.boundWithClock {
				t.Errorf("device source bound raised to %d at clock epoch %d", h.mark.SourceEpoch, epoch)
			}
			s.Close()

			// Restart while the chain justifies slowly: the other key's
			// honest vote must sign.
			epoch = 23
			s = start()
			if _, err := s.Sign(signReq(s, pkb, tc.honestAfter)); err != nil {
				t.Errorf("after a restart, honest vote (source %d, target %d) of another key refused: %v",
					tc.honestAfter.Source.Epoch, tc.honestAfter.Target.Epoch, err)
			}
		})
	}
}

// Issue #5 R11: with allow_unverified_nonslashable off, the runner signs
// bare roots of type 2 (aggregation slot, the selection proof), 4 (sync
// committee message) and 5 (sync committee selection proof) for any root.
// Design rule 2 lists them under the switch, and the TA refuses them. With
// the switch off they must be refused.
func TestReview5R11BareRootsWithSwitchOff(t *testing.T) {
	s, pk, cfg := newTestSigner(t, software.NewMemHooks())
	if cfg.AllowUnverifiedNonslashable {
		t.Fatal("DevConfig turns the switch on")
	}
	for name, m := range map[string]*backend.RootMessage{
		"type 2, aggregation slot (selection proof)": {Type: backend.RootAggregationSlot, Epoch: 20, ObjectRoot: backend.Root{0x42}, Domain: cfg.Domain(backend.DomainSelectionProof, 20)},
		"type 4, sync committee message":             {Type: backend.RootSyncCommitteeMessage, Epoch: 20, ObjectRoot: backend.Root{0x42}, Domain: cfg.Domain(backend.DomainSyncCommittee, 20)},
		"type 5, sync committee selection proof":     {Type: backend.RootSyncCommitteeSelectionProof, Epoch: 20, ObjectRoot: backend.Root{0x42}, Domain: cfg.Domain(backend.DomainSyncCommitteeSelectionProof, 20)},
	} {
		if _, err := s.Sign(signReq(s, pk, m)); err == nil {
			t.Errorf("%s: an arbitrary root signed with allow_unverified_nonslashable off", name)
		}
	}
}

// sha is SHA-256 of a and b concatenated.
func sha(a, b [32]byte) [32]byte { return sha256.Sum256(append(a[:], b[:]...)) }

// plainBuilderRequestAuthRoot is hash_tree_root of
//
//	class BuilderRequestAuth(Container):
//	    data: ByteList[MAX_BUILDER_AUTH_DATA_SIZE]  # 4096
//	    slot: Slot
//
// (builder-specs, specs/gloas/validator.md) by the SSZ rules for a plain
// Container, written out here without the backend's helpers.
func plainBuilderRequestAuthRoot(data []byte, slot uint64) [32]byte {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:], slot)
	// Two fields: merkleize([data_root, slot_root]), no active-fields mixin.
	return sha(byteListRoot(data), s)
}

// byteListRoot is hash_tree_root of data as ByteList[4096]: 128 chunks, a
// tree of depth 7, then the length mixed in.
func byteListRoot(data []byte) [32]byte {
	layer := make([][32]byte, 128)
	for i := 0; i*32 < len(data); i++ {
		copy(layer[i][:], data[i*32:])
	}
	for len(layer) > 1 {
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = sha(layer[2*i], layer[2*i+1])
		}
		layer = next
	}
	var n [32]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(data)))
	return sha(layer[0], n)
}

// BuilderRequestAuth is a plain Container in builder-specs. The core (and
// the backend's Go root) hash it as a ProgressiveContainer, as go-eth2-client
// v0.30.1 does, so a builder that follows the spec gets a signature over
// another root. The input is the Web3Signer 26.9.0 example (data
// "builder.example.org", slot 32); no Web3Signer signing root for it is in
// the repo, so the test checks the spec root only.
func TestReview4BuilderRequestAuthPlainContainerRoot(t *testing.T) {
	data := []byte("builder.example.org")
	m := &backend.BuilderRequestAuth{Data: data, Slot: 20*32 + 1}
	want := plainBuilderRequestAuthRoot(m.Data, m.Slot)
	// The field roots agree with the backend; only the container differs.
	if byteListRoot(data) != backend.BuilderRequestAuthDataRoot(data) {
		t.Fatal("the test's ByteList[4096] root disagrees with the backend's: the test is wrong")
	}

	// The Go root the backend publishes.
	if got, err := backend.HashTreeRoot(m); err != nil || got != backend.Root(want) {
		t.Errorf("backend hash_tree_root %x, plain Container root %x (%v)", got[:], want[:], err)
	}
	ex := &backend.BuilderRequestAuth{Data: data, Slot: 32}
	if got, _ := backend.HashTreeRoot(ex); got != backend.Root(plainBuilderRequestAuthRoot(ex.Data, ex.Slot)) {
		t.Errorf("Web3Signer example input: backend root %x, plain Container root %x", got[:], plainBuilderRequestAuthRoot(ex.Data, ex.Slot))
	}

	// The C core: its signature must verify over the spec signing root.
	s, pk, cfg, _ := gloasSigner(t, software.NewMemHooks())
	c0 := s.Config()
	p := c0.Policy()
	p.BuilderRequestAuthRoots = []backend.Root{backend.BuilderRequestAuthDataRoot(data)}
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(signReq(s, pk, m))
	if err != nil {
		t.Fatal(err)
	}
	d := backend.ComputeDomain(backend.DomainBuilderRequestAuth, cfg.GenesisForkVersion, backend.Root{})
	signing := sha(want, d)
	if !core.Verify(pk, backend.Root(signing), sig) {
		t.Errorf("the core's BuilderRequestAuth signature does not verify over the plain Container signing root %x", signing[:])
	}
}
