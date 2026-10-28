package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

var (
	errNoQuorum = errors.New("test clock: no quorum")
	adminMark   = []asn1.ObjectIdentifier{backend.AdminClientOID}
)

// wantNoClock checks a HEALTH answer of a runner without trusted time: no
// clock reading and not ready.
func wantNoClock(t *testing.T, b []byte) {
	t.Helper()
	h, err := wire.DecodeHealth(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.ClockUnix != 0 || h.ClockUnixMS != 0 || h.Ready {
		t.Fatalf("HEALTH without trusted time: clock_unix %d, clock_unix_ms %d, ready %v; want 0, 0, false",
			h.ClockUnix, h.ClockUnixMS, h.Ready)
	}
}

// A connection opened while the trusted clock has no reading gets HEALTH,
// so a watchdog or a client sees the clock state, as often as it asks.
func TestNewConnectionWithoutTrustedTimeGetsHealth(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	clk := &movingClock{t: time.Now()}
	clk.fail(errNoQuorum)
	s.Platform.Clock = clk
	c := dialClock(t, s, root.pem(), root.leaf(t, clientAuth, nil), clk)
	for i := 0; i < 2; i++ {
		b, err := c.call(wire.TypeHealth, nil)
		if err != nil {
			t.Fatalf("HEALTH %d on a connection opened without trusted time: %v", i, err)
		}
		wantNoClock(t, b)
	}
}

// Without trusted time every request but HEALTH gets FORBIDDEN and the
// connection closes, for every role, on a connection opened before the
// clock failed and on one opened after.
func TestNoTrustedTimeAnswersOnlyHealth(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, adminMark)
	certs := map[string]tls.Certificate{
		"signing":     root.leaf(t, clientAuth, nil),
		"attest-only": root.leaf(t, clientAuth, attestOnly),
		"admin":       adminCA.leaf(t, clientAuth, adminMark, adminCA),
	}
	nonce := make([]byte, 32)
	cases := []struct {
		role string
		typ  wire.MsgType
		body []byte
	}{
		{"signing", wire.TypeSign, nil},
		{"signing", wire.TypePublicKeys, nil},
		{"signing", wire.TypeIdentity, nonce},
		{"attest-only", wire.TypeAttest, nonce},
		{"admin", wireadmin.TypeConfigUpdate, nil},
		{"admin", wireadmin.TypeApproveExit, nil},
		{"admin", wireadmin.TypeImportSealed, nil},
		{"admin", wire.TypePublicKeys, nil},
		{"admin", 0x7e, nil}, // a type no runner serves
	}
	for _, tc := range cases {
		for _, opened := range []string{"before", "after"} {
			t.Run(tc.role+" "+tc.typ.String()+", opened "+opened+" the clock failed", func(t *testing.T) {
				s := roleServer(t)
				clk := &movingClock{t: time.Now()}
				s.Platform.Clock = clk
				if opened == "after" {
					clk.fail(errNoQuorum)
				}
				c := dialClock(t, s, root.pem(), certs[tc.role], clk)
				if opened == "before" {
					// The server's handshake ends at the first read.
					if _, err := c.call(wire.TypeHealth, nil); err != nil {
						t.Fatalf("HEALTH with trusted time: %v", err)
					}
				}
				clk.fail(errNoQuorum)
				if _, err := c.call(wire.TypeHealth, nil); err != nil {
					t.Fatalf("HEALTH: %v", err)
				}
				if _, err := c.call(tc.typ, tc.body); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "no trusted time") {
					t.Fatalf("%v without trusted time: %v, want FORBIDDEN for the clock", tc.typ, err)
				}
				if _, err := c.call(wire.TypeHealth, nil); err == nil {
					t.Fatal("the connection stays open after the refusal")
				}
			})
		}
	}
}

// Without trusted time the handshake still verifies the chain: a
// certificate of another CA, or one without clientAuth, gets nothing.
// With trusted time a chain outside its dates gets nothing, as before.
func TestChainChecksStayWithoutTrustedTime(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	other := newTestCA(t, nil, nil, nil)
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for name, tc := range map[string]struct {
		cert   tls.Certificate
		failed bool
		at     time.Time
	}{
		"other CA, no trusted time":         {other.leaf(t, clientAuth, nil), true, time.Now()},
		"serverAuth only, no trusted time":  {root.leaf(t, serverAuth, nil), true, time.Now()},
		"expired at the trusted time":       {root.leaf(t, clientAuth, nil), false, time.Now().Add(2 * time.Hour)},
		"not yet valid at the trusted time": {root.leaf(t, clientAuth, nil), false, time.Now().Add(-2 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			s := roleServer(t)
			clk := &movingClock{t: tc.at}
			if tc.failed {
				clk.fail(errNoQuorum)
			}
			s.Platform.Clock = clk
			c, err := dialClockErr(t, s, root.pem(), tc.cert, clk)
			if err == nil {
				_, err = c.call(wire.TypeHealth, nil)
			}
			if err == nil {
				t.Fatal("HEALTH answered")
			}
		})
	}
}

// When trusted time comes back, a connection opened without it is checked
// at its next request with the chain's dates: a valid chain gets its role,
// an expired one gets FORBIDDEN and the connection closes.
func TestTrustedTimeBackChecksConnectionOpenedWithoutIt(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, adminMark)
	open := func(t *testing.T, cert tls.Certificate) (*movingClock, *conn) {
		t.Helper()
		s := roleServer(t)
		clk := &movingClock{t: time.Now()}
		clk.fail(errNoQuorum)
		s.Platform.Clock = clk
		c := dialClock(t, s, root.pem(), cert, clk)
		if _, err := c.call(wire.TypeHealth, nil); err != nil {
			t.Fatalf("HEALTH without trusted time: %v", err)
		}
		return clk, c
	}

	t.Run("signing", func(t *testing.T) {
		clk, c := open(t, root.leaf(t, clientAuth, nil))
		clk.set(time.Now())
		if _, err := c.call(wire.TypePublicKeys, nil); err != nil {
			t.Fatalf("PUBLIC_KEYS once trusted time is back: %v", err)
		}
		if _, err := c.call(wireadmin.TypeConfigUpdate, nil); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "signing role") {
			t.Fatalf("CONFIG_UPDATE of a signing client: %v, want FORBIDDEN for the role", err)
		}
		// The clock fails again: HEALTH only, as for any connection.
		clk.fail(errNoQuorum)
		if _, err := c.call(wire.TypeHealth, nil); err != nil {
			t.Fatalf("HEALTH: %v", err)
		}
		if _, err := c.call(wire.TypePublicKeys, nil); refusedWith(err) != backend.StatusForbidden {
			t.Fatalf("PUBLIC_KEYS after the clock failed again: %v, want FORBIDDEN", err)
		}
	})

	t.Run("admin", func(t *testing.T) {
		clk, c := open(t, adminCA.leaf(t, clientAuth, adminMark, adminCA))
		clk.set(time.Now())
		if _, err := c.call(wireadmin.TypeConfigUpdate, nil); err == nil || refusedWith(err) == backend.StatusForbidden {
			t.Fatalf("CONFIG_UPDATE of an admin client once trusted time is back: %v, want a refusal other than FORBIDDEN", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		clk, c := open(t, root.leaf(t, clientAuth, nil)) // NotAfter: now + 1 h
		clk.set(time.Now().Add(2 * time.Hour))
		if _, err := c.call(wire.TypePublicKeys, nil); refusedWith(err) != backend.StatusForbidden {
			t.Fatalf("PUBLIC_KEYS with a chain expired at the trusted time: %v, want FORBIDDEN", err)
		}
		if _, err := c.call(wire.TypeHealth, nil); err == nil {
			t.Fatal("the connection stays open after its chain failed the check at trusted time")
		}
	})
}
