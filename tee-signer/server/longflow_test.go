package server

import (
	"crypto/rand"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// A handover import sends its pages as large frames on one admin
// connection, and may run for most of an hour. The per-frame certificate
// check (ATTEST-ROLES-01) and the in-flight byte cap (ATTEST-BUDGET-01)
// must not cut it while the certificate is valid: every page counts
// against the cap only until its answer, and the check reads the trusted
// clock, not the time since the handshake. Ten pages of 900 KiB through a
// cap of 2 MiB over 50 minutes all reach the import, and the connection
// closes only once the certificate expires.
func TestLongImportKeepsItsConnection(t *testing.T) {
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, admin)
	cert := adminCA.leaf(t, clientAuth, admin, adminCA) // NotAfter: now + 1 h

	s := roleServer(t)
	s.Limits = Limits{MaxInflight: 2 << 20}
	clk := &movingClock{t: time.Now()}
	s.Platform.Clock = clk
	c := dialClock(t, s, root.pem(), cert, clk)

	page := make([]byte, 900<<10)
	rand.Read(page)
	start := time.Now()
	for i := range 10 {
		clk.set(start.Add(time.Duration(i) * 5 * time.Minute))
		_ = c.c.SetDeadline(time.Now().Add(10 * time.Second))
		_, err := c.call(handover.TypeImport, page)
		// A refusal of the import itself is an answer: the role check and
		// the cap let the page through. FORBIDDEN or no answer is a cut.
		if st := refusedWith(err); st == backend.StatusOK || st == backend.StatusForbidden {
			t.Fatalf("page %d at +%v: %v, want the import's own answer", i, time.Duration(i)*5*time.Minute, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for s.inflight.n.Load() != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("page %d: %d bytes still held after its answer", i, s.inflight.n.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	clk.set(start.Add(61 * time.Minute))
	_ = c.c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.call(handover.TypeImport, page); refusedWith(err) != backend.StatusForbidden {
		t.Fatalf("page after the certificate expired: %v, want FORBIDDEN", err)
	}
}
