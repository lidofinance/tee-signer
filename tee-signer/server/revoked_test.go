package server

import (
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// A revocation that comes while a connection is open closes it at its
// next frame, HEALTH too.
func TestRevokedCertificateLosesItsOpenConnection(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	s.Revoked = &attls.Revoked{}
	clk := &movingClock{t: time.Now()}
	s.Platform.Clock = clk
	cert := root.leaf(t, clientAuth, nil)
	c := dialClock(t, s, root.pem(), cert, clk)
	if _, err := c.call(wire.TypeHealth, nil); err != nil {
		t.Fatalf("HEALTH before the revocation: %v", err)
	}
	s.Revoked.Set([][32]byte{sha256.Sum256(cert.Certificate[0])})
	if _, err := c.call(wire.TypeHealth, nil); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("HEALTH after the revocation: %v, want FORBIDDEN for the revocation", err)
	}
	if _, err := c.call(wire.TypeHealth, nil); err == nil {
		t.Fatal("the connection stays open after its certificate was revoked")
	}
}

// The set in force is the union of the setup's list, the active open
// update's and the pending one's.
func TestRevokedOfIsTheUnion(t *testing.T) {
	st := &setupwire.Setup{Open: setupwire.Open{RevokedClientCerts: [][32]byte{{1}}}}
	v := &view{
		open:   &setupwire.Open{RevokedClientCerts: [][32]byte{{1}, {2}}},
		newest: &setupwire.Open{RevokedClientCerts: [][32]byte{{1}, {2}, {3}}},
	}
	r := &attls.Revoked{}
	r.Set(revokedOf(st, v))
	if r.Len() != 3 {
		t.Fatalf("union: %d entries, want 3", r.Len())
	}
	// Unreadable bodies (nil values) leave the setup's list.
	if got := revokedOf(st, &view{}); !slices.Equal(got, st.Open.RevokedClientCerts) {
		t.Fatalf("without readable bodies: %x, want the setup's list", got)
	}
	var s Server
	s.RefreshRevokedClientCerts() // no Updates, no Revoked: nothing to do
}
