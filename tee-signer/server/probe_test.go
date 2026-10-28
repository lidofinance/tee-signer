package server

import (
	"encoding/asn1"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// The role probe of signer-admin (docs/protocol.md, "Client roles"):
// CONFIG_UPDATE with an empty payload. On a runner with a setup the role
// check answers FORBIDDEN to a certificate without the admin role; with it
// the check passes and the empty payload fails to decode (BAD_REQUEST). A
// runner without a setup answers UNSUPPORTED before decoding. These tests
// pin the answers probe relies on.
func TestAdminProbe(t *testing.T) {
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, admin)
	signCA := newTestCA(t, root, clientAuth, nil)
	probe := func(cert func() *conn) error {
		_, err := cert().call(wireadmin.TypeConfigUpdate, nil)
		return err
	}
	conns := func(s *Server) map[string]func() *conn {
		mk := func(c *testCA, marks []asn1.ObjectIdentifier, chain ...*testCA) func() *conn {
			return func() *conn {
				cn, err := dial(t, s, root.pem(), c.leaf(t, clientAuth, marks, chain...))
				if err != nil {
					t.Fatal(err)
				}
				return cn
			}
		}
		return map[string]func() *conn{
			"admin":                     mk(adminCA, admin, adminCA),
			"signing":                   mk(signCA, nil, signCA),
			"attest-only":               mk(signCA, attestOnly, signCA),
			"admin mark under the root": mk(root, admin),
		}
	}

	e := newEnv(t, nil)
	for name, c := range conns(e.srv) {
		want := backend.StatusForbidden
		if name == "admin" {
			want = backend.StatusBadRequest
		}
		if err := probe(c); refusedWith(err) != want {
			t.Errorf("runner with a setup, %s: %v, want %v", name, err, want)
		}
	}

	bare := roleServer(t)
	for name, c := range conns(bare) {
		want := backend.StatusForbidden
		if name == "admin" {
			want = backend.StatusUnsupported
		}
		if err := probe(c); refusedWith(err) != want {
			t.Errorf("runner without a setup, %s: %v, want %v", name, err, want)
		}
	}
}
