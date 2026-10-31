//go:build !debugimport

package server

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A share record that is gone for good: the source holds fewer shares than
// its mark log vouched for. A handover order without left_behind is
// refused; one whose left_behind names exactly the missing key hands over
// the rest. left_behind that names a stored key, more keys than are
// missing, or any key when none is missing is refused, and the source
// does not hand over.
func TestHandoverLeftBehind(t *testing.T) {
	_, other := newKey(t)
	cases := []struct {
		name string
		hide bool
		// left returns the keys of left_behind from the source's keys
		// (pks[0] is the hidden one when hide is set).
		left func(pks []backend.Pubkey) []backend.Pubkey
		want string // "" for a handover of the stored shares
	}{
		{"no left_behind", true, func([]backend.Pubkey) []backend.Pubkey { return nil }, "a share record is missing"},
		{"the missing key", true, func(p []backend.Pubkey) []backend.Pubkey { return p[:1] }, ""},
		{"a stored key", true, func(p []backend.Pubkey) []backend.Pubkey { return p[1:2] }, "whose share is stored here"},
		{"the missing key and a stored one", true, func(p []backend.Pubkey) []backend.Pubkey { return []backend.Pubkey{p[0], p[2]} }, "whose share is stored here"},
		{"one key too many", true, func(p []backend.Pubkey) []backend.Pubkey { return []backend.Pubkey{p[0], other} }, "exactly the 1 missing"},
		{"nothing missing", false, func(p []backend.Pubkey) []backend.Pubkey { return []backend.Pubkey{other} }, "no share record is missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := newSrcEnv(t, nil)
			pks := src.addKeys(3, nil)
			tgt := newTargetOf(t, src, nil, nil, nil)
			if c.hide {
				src.deleteShare(pks[0])
				src.restart()
			}
			var left [][48]byte
			for _, pk := range c.left(pks) {
				left = append(left, [48]byte(pk))
			}
			slices.SortFunc(left, func(a, b [48]byte) int { return bytes.Compare(a[:], b[:]) })
			order, _ := srcOrder(t, src, tgt, []byte{1, 2}, func(b *handoverorder.Body) { b.LeftBehind = left })
			if _, err := src.push(order); err != nil {
				t.Fatal(err)
			}
			src.clock.add(srcDelay)
			if c.want != "" {
				if _, err := handOver(t, src, tgt, order, 0); err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("handover: %v, want %q", err, c.want)
				}
				if src.srv.HandedOver() {
					t.Fatal("the source handed over")
				}
				return
			}
			_, imp := handOverAll(t, src, tgt, order)
			if !imp.Done || imp.Total != 2 {
				t.Fatalf("handover with the missing key left behind: %+v", imp)
			}
			if !src.srv.HandedOver() {
				t.Fatal("the source did not hand over")
			}
		})
	}
}
