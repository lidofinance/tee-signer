package server

import (
	"context"
	"encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
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

// Every message type of wire and wire/admin, and some unknown ones,
// against each client role: FORBIDDEN exactly where the role table of
// docs/protocol.md says no. The unknown ones include 0x20 to 0x28, the
// message numbers of the removed key generation, 0x09, that of the exit
// approvals, and 0x31 to 0x33, those of the handover: they stay refused
// for every role.
func TestRoleTable(t *testing.T) {
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, admin)
	signCA := newTestCA(t, root, clientAuth, nil)
	s := roleServer(t)

	types := []wire.MsgType{
		wire.TypeHealth, wire.TypePublicKeys, wire.TypeSign, wire.TypeAttest, wireadmin.TypeImportShare, wire.TypeIdentity,
		wireadmin.TypeImportSealed, wireadmin.TypeConfigUpdate, 0x09,
		0x00, 0x0a, 0x1f, 0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x7f,
	}
	for typ := wire.MsgType(0x20); typ <= 0x28; typ++ {
		types = append(types, typ)
	}
	// The types each role may send; the rest must be FORBIDDEN.
	signing := map[wire.MsgType]bool{wire.TypeHealth: true, wire.TypePublicKeys: true, wire.TypeSign: true, wire.TypeIdentity: true}
	attest := map[wire.MsgType]bool{wire.TypeHealth: true, wire.TypePublicKeys: true, wire.TypeAttest: true, wire.TypeIdentity: true}
	adminOK := map[wire.MsgType]bool{}
	for _, typ := range types {
		adminOK[typ] = typ != wire.TypeSign && typ < 0x09 && typ != 0
	}

	// An admin leaf straight under the root: admin rights in a non-prod build
	// only, no rights in a mainnet build. Run under each build's tags.
	rootDirect := map[wire.MsgType]bool{}
	if buildchain.AdminRootDirect {
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

// A voluntary exit is the admin role's SIGN: a signing certificate gets
// FORBIDDEN for it and still signs other kinds; an admin certificate signs
// the exit and gets FORBIDDEN for any other kind.
func TestExitAdminOnly(t *testing.T) {
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	root := newTestCA(t, nil, nil, nil)
	adminCA := newTestCA(t, root, clientAuth, admin)
	signCA := newTestCA(t, root, clientAuth, nil)
	s := roleServer(t)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := s.addShare(pk, &sk, 5, nil, "test"); err != nil {
		t.Fatal(err)
	}
	cfg := s.Signer.Config()
	req := func(m backend.Message) []byte {
		d, err := cfg.MessageDomain(m)
		if err != nil {
			t.Fatal(err)
		}
		p, err := wire.EncodeSign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	epoch := (uint64(time.Now().Unix()) - cfg.GenesisTime) / cfg.SecondsPerSlot / cfg.SlotsPerEpoch
	exit := req(&backend.VoluntaryExit{Epoch: 1, ValidatorIndex: 5})
	rd, _ := cfg.MessageDomain(&backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: epoch})
	randao := req(&backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: epoch, ObjectRoot: backend.HashTreeRootUint64(epoch), Domain: rd})
	vote := req(&backend.AttestationData{Slot: (epoch + 1) * cfg.SlotsPerEpoch,
		Source: backend.Checkpoint{Epoch: epoch}, Target: backend.Checkpoint{Epoch: epoch + 1}})

	sc, err := dial(t, s, root.pem(), signCA.leaf(t, clientAuth, nil, signCA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.call(wire.TypeSign, exit); refusedWith(err) != backend.StatusForbidden {
		t.Errorf("signing certificate, exit: %v, want FORBIDDEN", err)
	}
	if _, err := sc.call(wire.TypeSign, randao); err != nil {
		t.Errorf("signing certificate, RANDAO: %v", err)
	}
	// The vote reaches the signer, which may refuse it for its own reasons.
	if _, err := sc.call(wire.TypeSign, vote); refusedWith(err) == backend.StatusForbidden {
		t.Errorf("signing certificate, attestation: %v", err)
	}

	ac, err := dial(t, s, root.pem(), adminCA.leaf(t, clientAuth, admin, adminCA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.call(wire.TypeSign, exit); err != nil {
		t.Errorf("admin certificate, exit: %v", err)
	}
	for name, p := range map[string][]byte{"RANDAO": randao, "attestation": vote} {
		if _, err := ac.call(wire.TypeSign, p); refusedWith(err) != backend.StatusForbidden {
			t.Errorf("admin certificate, %s: %v, want FORBIDDEN", name, err)
		}
	}
}
