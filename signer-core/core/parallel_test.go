package core_test

import (
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// signAll sends msg(i) for i in [0, n) from n goroutines at once and
// returns each one's signature, repeat flag and error.
func signAll(s *core.Signer, pk backend.Pubkey, n int, msg func(i int) backend.Message) ([]backend.Signature, []bool, []error) {
	sigs := make([]backend.Signature, n)
	reps := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sigs[i], reps[i], errs[i] = s.SignDetailed(signReq(s, pk, msg(i)))
		}(i)
	}
	wg.Wait()
	return sigs, reps, errs
}

// oneSigns checks that exactly one of errs is nil and every other one is
// the refusal want.
func oneSigns(t *testing.T, what string, errs []error, want backend.Status) {
	t.Helper()
	ok := 0
	for i, err := range errs {
		if err == nil {
			ok++
		} else if got := backend.StatusOf(err); got != want {
			t.Errorf("%s: request %d: %v, want %v", what, i, err, want)
		}
	}
	if ok != 1 {
		t.Errorf("%s: %d of %d signed, want exactly 1", what, ok, len(errs))
	}
}

// Requests for one key from many goroutines at once. The signer's lock
// serializes them, so conflicting attestations (one target, different
// beacon block roots) and conflicting blocks (one slot, different body
// roots) get exactly one signature each and slashing refusals for the
// rest; identical requests all sign, one as the first and the others as
// exact repeats with the same signature; and a second key signing at the
// same time is not held back. Run under -race.
func TestParallelSigningOneKey(t *testing.T) {
	const n = 16
	h := software.NewMemHooks()
	h.Clock = clockAtEpoch(60)
	s, pk, _ := newTestSigner(t, h)

	_, _, errs := signAll(s, pk, n, func(i int) backend.Message {
		a := att(18, 19)
		a.BeaconBlockRoot = backend.Root{byte(i + 1)}
		return a
	})
	oneSigns(t, "attestations at one target", errs, backend.StatusSlashTarget)

	_, _, errs = signAll(s, pk, n, func(i int) backend.Message {
		return &backend.BeaconBlockHeader{Slot: 20 * 32, ProposerIndex: 7, BodyRoot: backend.Root{byte(i + 1)}}
	})
	oneSigns(t, "blocks at one slot", errs, backend.StatusSlashBlock)

	before := s.Stats()
	sigs, reps, errs := signAll(s, pk, n, func(int) backend.Message { return att(19, 20) })
	firsts := 0
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("identical attestation %d: %v", i, errs[i])
		}
		if sigs[i] != sigs[0] {
			t.Fatalf("identical attestation %d: another signature", i)
		}
		if !reps[i] {
			firsts++
		}
	}
	if firsts != 1 {
		t.Fatalf("%d of %d identical requests signed as the first, want 1", firsts, n)
	}
	// Target 20 sits inside the window the vote at 19 booked: no write.
	if after := s.Stats(); after.ExactRepeats != before.ExactRepeats+n-1 || after.WatermarkWrites != before.WatermarkWrites {
		t.Fatalf("stats before %+v, after %+v: want %d repeats and no write", before, after, n-1)
	}
	sigs, reps, errs = signAll(s, pk, n, func(int) backend.Message {
		return &backend.BeaconBlockHeader{Slot: 21 * 32, ProposerIndex: 7, BodyRoot: backend.Root{9}}
	})
	firsts = 0
	for i := range errs {
		if errs[i] != nil || sigs[i] != sigs[0] {
			t.Fatalf("identical block %d: %v, same signature %v", i, errs[i], sigs[i] == sigs[0])
		}
		if !reps[i] {
			firsts++
		}
	}
	if firsts != 1 {
		t.Fatalf("%d of %d identical blocks signed as the first, want 1", firsts, n)
	}

	// Two keys at once, each voting every epoch from 21 to 60: both finish
	// with every vote signed. A third goroutine keeps sending the first
	// key's conflicting votes, which never get through.
	sk2, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := core.PubkeyOf(sk2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddValidator(pk2, sk2, 8, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	votes := func(pk backend.Pubkey, out *[]error) {
		defer wg.Done()
		for e := uint64(21); e <= 60; e++ {
			_, err := s.Sign(signReq(s, pk, att(e-1, e)))
			*out = append(*out, err)
		}
	}
	var errs1, errs2, hostile []error
	wg.Add(3)
	go votes(pk, &errs1)
	go votes(pk2, &errs2)
	go func() {
		defer wg.Done()
		for e := uint64(21); e <= 60; e++ {
			a := att(e-1, e)
			a.BeaconBlockRoot = backend.Root{0xcc}
			_, err := s.Sign(signReq(s, pk, a))
			hostile = append(hostile, err)
		}
	}()
	wg.Wait()
	for i, err := range errs2 {
		if err != nil {
			t.Errorf("key 2, vote %d: %v", i, err)
		}
	}
	// The hostile vote at target e lands before or after the honest one:
	// after it, the marks refuse it (a double vote, or a surround once the
	// honest key moved on); before it, it signs and the honest one is
	// refused instead. One signature per target either way.
	first := 0
	for i := range hostile {
		honest, other := errs1[i], hostile[i]
		switch {
		case honest == nil && backend.StatusOf(other).IsSlashing():
		case other == nil && backend.StatusOf(honest).IsSlashing():
			first++
		default:
			t.Errorf("target %d: honest %v, hostile %v: want one signature and one slashing refusal", 21+i, honest, other)
		}
	}
	t.Logf("hostile votes that came first: %d of %d", first, len(hostile))
	st1, _ := s.State(pk)
	st2, _ := s.State(pk2)
	if st1.RAM.TargetEpoch != 60 || st2.RAM.TargetEpoch != 60 {
		t.Fatalf("targets reached: key 1 %d, key 2 %d, want 60", st1.RAM.TargetEpoch, st2.RAM.TargetEpoch)
	}
}
