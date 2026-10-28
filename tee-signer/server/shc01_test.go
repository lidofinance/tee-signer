//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// shc01Env is a source with 4 keys past its order's wait, its
// target, the order and the one page of all 4 shares.
func shc01Env(t *testing.T) (src, tgt *tgtEnv, order []byte, page *handover.Response) {
	t.Helper()
	src = newSrcEnv(t, nil)
	src.addKeys(4, 0, [32]byte{}, &srcMark)
	tgt = newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	order, _ = srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	page, err := handOver(t, src, tgt, order, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Shares) != 4 || page.Total != 4 {
		t.Fatalf("page of %d shares, total %d", len(page.Shares), page.Total)
	}
	return src, tgt, order, page
}

// part is page with the shares [from, to), its total and its carry as
// given.
func part(page *handover.Response, from, to int, total uint32, carry handover.Carry) *handover.Response {
	p := *page
	p.Shares = page.Shares[from:to]
	p.Total, p.Carry = total, carry
	return &p
}

// SHC-01: the target ends a handover import only when it holds every share
// the source hands over. A tool that lowered the page's total, or sent held
// shares again under a smaller key set, would end the import with shares
// missing; the slot would clear, the rest would be refused for good, and
// the source has written its tombstone. So the total and the key set
// travel in the carry, which every share's associated data binds, and only
// a request whose carry opened a share ends the import.
func TestSHC01ImportEndsOnlyWithEveryShare(t *testing.T) {
	cases := map[string]func(t *testing.T, tgt *tgtEnv, order []byte, page *handover.Response){
		"lowered total": func(t *testing.T, tgt *tgtEnv, order []byte, page *handover.Response) {
			// Refused, or taken without ending the import.
			if r, err := tgt.imp(order, part(page, 0, 2, 2, page.Carry), 0); err == nil && r.Done {
				t.Errorf("2 of 4 shares with total 2 ended the import: %+v", r)
			}
		},
		"held shares, smaller key set": func(t *testing.T, tgt *tgtEnv, order []byte, page *handover.Response) {
			if r := tgt.mustImp(order, part(page, 0, 2, 4, page.Carry), 0); r.Done || r.Held != 2 {
				t.Fatalf("2 of 4: %+v", r)
			}
			keys := tgt.signer.Keys()
			forged := handover.Carry{Set: handover.SetOf(keys)}
			if r, err := tgt.imp(order, part(page, 0, 2, 2, forged), 0); err == nil && r.Done {
				t.Errorf("held shares under a key set of 2 ended the import: %+v", r)
			}
		},
	}
	for name, attack := range cases {
		t.Run(name, func(t *testing.T) {
			_, tgt, order, page := shc01Env(t)
			attack(t, tgt, order, page)
			if n := len(tgt.signer.Keys()); tgt.srv.importing() == nil && n > 0 {
				t.Errorf("the import ended with %d of 4 shares", n)
			}
			r, err := tgt.imp(order, page, 0)
			if err != nil || !r.Done || r.Held != 4 {
				t.Fatalf("the whole page after: %+v %v", r, err)
			}
			if o := tgt.srv.importing(); o != nil {
				t.Fatalf("the import did not end: %x", o.Hash[:8])
			}
		})
	}
}

// A carried exit keeps its validator key: a repeat of it on the
// target matches the carried entry.
func TestCarriedExitKeepsItsKey(t *testing.T) {
	src := newSrcEnv(t, nil)
	keys := src.addKeys(2, 0, [32]byte{}, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	day := &markstore.ExitDay{Day: src.now() / daySeconds, Stake: 32_000_000_000,
		Exits: []markstore.ExitEntry{{Pubkey: keys[0], ValidatorIndex: 7, ExitEpoch: startEpoch, Stake: 32_000_000_000, Nonce: [32]byte{0xe1}}}}
	if err := src.hooks.RecordExits(ctx, day); err != nil {
		t.Fatal(err)
	}
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	d, _ := tgt.hooks.Exits()
	if d == nil || len(d.Exits) != 1 || d.Exits[0].Pubkey != keys[0] {
		t.Fatalf("the target's exits %+v", d)
	}
}
