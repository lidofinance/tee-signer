package server

import (
	"context"
	"encoding/asn1"
	"testing"

	"github.com/lidofinance/tee-signer/signer-admin/cluster"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// connRT gives a test connection the RoundTripper of admin/cluster.
type connRT struct{ c *conn }

func (r connRT) RoundTrip(_ context.Context, t wire.MsgType, p []byte) ([]byte, error) {
	return r.c.call(t, p)
}

// signer-admin's Probe against an in-process runner, over mutual TLS with
// an admin leaf and a signing leaf, on a runner with a setup and on one
// without.
func TestAdminProbeInProcess(t *testing.T) {
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, admin)
	signCA := newTestCA(t, root, clientAuth, nil)
	ctx := context.Background()
	probe := func(s *Server, c *testCA, marks []asn1.ObjectIdentifier) cluster.ProbeResult {
		t.Helper()
		cn, err := dial(t, s, root.pem(), c.leaf(t, clientAuth, marks, c))
		if err != nil {
			t.Fatal(err)
		}
		r, err := cluster.Probe(ctx, connRT{cn})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	withSetup := newEnv(t, nil).srv
	if r := probe(withSetup, adminCA, admin); !r.Admin || !r.Setup || !r.OK() {
		t.Errorf("admin leaf, runner with a setup: %+v", r)
	}
	if r := probe(withSetup, signCA, nil); r.Admin || r.OK() {
		t.Errorf("signing leaf, runner with a setup: %+v", r)
	}
	bare := roleServer(t)
	if r := probe(bare, adminCA, admin); !r.Admin || r.Setup {
		t.Errorf("admin leaf, runner without a setup: %+v", r)
	}
	if r := probe(bare, signCA, nil); r.Admin || r.OK() {
		t.Errorf("signing leaf, runner without a setup: %+v", r)
	}
}
