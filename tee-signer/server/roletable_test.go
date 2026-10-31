package server

import (
	"context"
	"encoding/asn1"
	"net"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// pipeCall sends one request over c, a connection without TLS, and
// returns the body or the refusal.
func pipeCall(t *testing.T, c net.Conn, id uint32, typ wire.MsgType, payload []byte) ([]byte, error) {
	t.Helper()
	if err := wire.WriteFrame(c, wire.Frame{Type: typ, ID: id, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	f, err := wire.ReadFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	return wire.DecodeResponse(f.Payload)
}

// Every message type of wire, wire/admin and handover, and some unknown ones,
// against each client role: FORBIDDEN exactly where the role table of
// docs/protocol.md says no. The unknown ones include 0x20 to 0x28, the
// message numbers of the removed key generation: they stay refused for
// every role.
func TestRoleTable(t *testing.T) {
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, admin)
	signCA := newTestCA(t, root, clientAuth, nil)
	s := roleServer(t)

	types := []wire.MsgType{
		wire.TypeHealth, wire.TypePublicKeys, wire.TypeSign, wire.TypeAttest, wireadmin.TypeImportShare, wire.TypeIdentity,
		wireadmin.TypeImportSealed, wireadmin.TypeConfigUpdate, wireadmin.TypeApproveExit,
		handover.TypeOrder, handover.Type, handover.TypeImport,
		0x00, 0x0a, 0x1f, 0x29, 0x30, 0x34, 0x7f,
	}
	for typ := wire.MsgType(0x20); typ <= 0x28; typ++ {
		types = append(types, typ)
	}
	// The types each role may send; the rest must be FORBIDDEN.
	signing := map[wire.MsgType]bool{wire.TypeHealth: true, wire.TypePublicKeys: true, wire.TypeSign: true, wire.TypeIdentity: true}
	attest := map[wire.MsgType]bool{wire.TypeHealth: true, wire.TypePublicKeys: true, wire.TypeAttest: true, wire.TypeIdentity: true}
	adminOK := map[wire.MsgType]bool{}
	for _, typ := range types {
		adminOK[typ] = typ != wire.TypeSign && (typ < 0x0a || typ >= 0x31 && typ <= 0x33) && typ != 0
	}

	// An admin leaf straight under the root: admin rights in a testnet build
	// only. Run under both tags.
	rootDirect := signing
	if buildflavor.AdminRootDirect {
		rootDirect = adminOK
	}

	nonce := make([]byte, 32)
	nonce[0] = 7
	attestReq, _ := wire.EncodeAttest(nonce)
	payload := func(typ wire.MsgType) []byte {
		if typ == wire.TypeAttest || typ == wire.TypeIdentity {
			return attestReq
		}
		return make([]byte, 64)
	}
	check := func(name string, ok map[wire.MsgType]bool, call func(wire.MsgType, []byte) ([]byte, error)) {
		for _, typ := range types {
			_, err := call(typ, payload(typ))
			if forbidden := refusedWith(err) == backend.StatusForbidden; forbidden == ok[typ] {
				t.Errorf("%s, type %v: %v (allowed: %v)", name, typ, err, ok[typ])
			}
		}
	}

	for name, tc := range map[string]struct {
		leaf func() (*conn, error)
		ok   map[wire.MsgType]bool
	}{
		"signing":                         {func() (*conn, error) { return dial(t, s, root.pem(), signCA.leaf(t, clientAuth, nil, signCA)) }, signing},
		"TLS without mark under the root": {func() (*conn, error) { return dial(t, s, root.pem(), root.leaf(t, clientAuth, nil)) }, signing},
		"attest-only": {func() (*conn, error) {
			return dial(t, s, root.pem(), signCA.leaf(t, clientAuth, attestOnly, signCA))
		}, attest},
		"admin":                     {func() (*conn, error) { return dial(t, s, root.pem(), adminCA.leaf(t, clientAuth, admin, adminCA)) }, adminOK},
		"admin mark under the root": {func() (*conn, error) { return dial(t, s, root.pem(), root.leaf(t, clientAuth, admin)) }, rootDirect},
		"both marks": {func() (*conn, error) {
			return dial(t, s, root.pem(), adminCA.leaf(t, clientAuth, append(attestOnly, admin...), adminCA))
		}, attest},
	} {
		c, err := tc.leaf()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		check(name, tc.ok, c.call)
	}

	// No TLS (a unix socket): a local client, the admin row and SIGN.
	local := map[wire.MsgType]bool{wire.TypeSign: true}
	for typ, ok := range adminOK {
		local[typ] = local[typ] || ok
	}
	srvSide, cliSide := net.Pipe()
	defer cliSide.Close()
	go s.handleConn(context.Background(), srvSide)
	id := uint32(0)
	check("unix", local, func(typ wire.MsgType, p []byte) ([]byte, error) {
		id++
		return pipeCall(t, cliSide, id, typ, p)
	})
}

// A nil client and a client of no role get nothing.
func TestRoleNoneIsDenied(t *testing.T) {
	s := roleServer(t)
	for _, cl := range []*client{nil, {}} {
		if _, err := s.dispatchFor(context.Background(), wire.Frame{Type: wire.TypeHealth}, cl); refusedWith(err) != backend.StatusForbidden {
			t.Errorf("client %+v: HEALTH %v, want FORBIDDEN", cl, err)
		}
	}
}

// A refused IMPORT_SHARE payload is wiped for every role that may not send
// it.
func TestRefusedImportPayloadCleared(t *testing.T) {
	s := roleServer(t)
	for _, cl := range []*client{{role: attls.RoleSigning}, {role: attls.RoleAttestOnly}, nil} {
		p := []byte{1, 2, 3, 4}
		if _, err := s.dispatchFor(context.Background(), wire.Frame{Type: wireadmin.TypeImportShare, Payload: p}, cl); refusedWith(err) != backend.StatusForbidden {
			t.Fatalf("client %+v: %v, want FORBIDDEN", cl, err)
		}
		if p[0]|p[1]|p[2]|p[3] != 0 {
			t.Errorf("client %+v: payload %x not cleared", cl, p)
		}
	}
}
