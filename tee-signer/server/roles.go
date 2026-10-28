package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// Client roles (docs/protocol.md, "Client roles"). Every connection has a
// client with a role, and the table allows is the only grant: a message
// type that is not in the role's row gets FORBIDDEN before anything of its
// payload is read. A TLS client's role comes from its verified certificate
// chain (attls.RoleOf). A connection without TLS (a unix socket, or a dev
// runner without a client CA; release builds allow neither off dev) is a
// local client: the admin role's messages and SIGN. An admin certificate
// cannot SIGN, so a stolen one makes no signature; a local client has no
// certificate to steal, and the dev runners and their tests sign over it.

// client is what the server knows about the peer of a connection.
type client struct {
	role attls.Role
	// local: a connection without TLS, which has no certificate.
	local bool
	// cert is the SHA-256 of the leaf certificate's DER.
	cert [32]byte
	// notAfter is the earliest NotAfter of the verified chains: from then
	// on the client has no valid certificate, and its connection serves
	// nothing more (ATTEST-ROLES-01). Zero for a local client.
	notAfter time.Time
	// undated: the handshake had no trusted time, so attls checked the
	// chain without its dates and the connection has no verified chain.
	// The client may send HEALTH only, until a trusted reading checks the
	// chain with its dates (stillValid). peer holds its certificates for
	// that check.
	undated bool
	peer    []*x509.Certificate
}

// localAdmin is the client of a connection without TLS.
var localAdmin = &client{role: attls.RoleAdmin, local: true}

// localAllows is what a local client may send: the admin row and SIGN.
var localAllows = func() map[wire.MsgType]grant {
	m := map[wire.MsgType]grant{wire.TypeSign: allow}
	for t, g := range allows[attls.RoleAdmin] {
		m[t] = g
	}
	return m
}()

// clientOf is the client of a TLS connection after its handshake.
func clientOf(cs *tls.ConnectionState) *client {
	cl := &client{role: attls.RoleOf(cs), notAfter: attls.NotAfter(cs)}
	if len(cs.PeerCertificates) > 0 {
		cl.cert = sha256.Sum256(cs.PeerCertificates[0].Raw)
		if len(cs.VerifiedChains) == 0 {
			cl.undated, cl.peer = true, cs.PeerCertificates
		}
	}
	return cl
}

// stillValid refuses a request of type t of a TLS client whose
// certificate chain has expired by the trusted clock, or, unless t is
// HEALTH, when there is no trusted reading to check it against. The
// handshake checked the chain once; a connection may stay open for days,
// so every frame checks the dates again (ATTEST-ROLES-01). HEALTH goes
// through without a reading so a watchdog or a client can see the clock
// state; it carries no secret and changes nothing. A connection whose
// handshake had no trusted time has its chain checked with its dates at
// the first request that has a reading (checkUndated). A local client has
// no certificate.
func (s *Server) stillValid(cl *client, t wire.MsgType) error {
	if cl == nil || cl.local {
		return nil
	}
	now, err := s.certNow()
	if err != nil {
		if t == wire.TypeHealth {
			return nil
		}
		return backend.Refused(backend.StatusForbidden, "no trusted time to check the client certificate: %v", err)
	}
	if cl.undated {
		if err := s.checkUndated(cl, now); err != nil {
			return err
		}
	}
	if cl.notAfter.IsZero() || now.After(cl.notAfter) {
		return backend.Refused(backend.StatusForbidden, "the client certificate chain expired at %s (trusted time %s); connect again with a valid certificate",
			cl.notAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkUndated checks the chain of a connection whose handshake had no
// trusted time at the trusted reading now, as a handshake would. A chain
// that holds gives the client its role and NotAfter; one that does not is
// refused.
func (s *Server) checkUndated(cl *client, now time.Time) error {
	chains, err := attls.VerifyAt(s.ClientCAs, cl.peer, now)
	if err != nil {
		return backend.Refused(backend.StatusForbidden,
			"the client certificate chain, taken without trusted time at the handshake, fails at the trusted time: %v; connect again with a valid certificate", err)
	}
	cs := &tls.ConnectionState{PeerCertificates: cl.peer, VerifiedChains: chains}
	cl.role, cl.notAfter, cl.undated, cl.peer = attls.RoleOf(cs), attls.NotAfter(cs), false, nil
	s.Log.Info("client certificate checked at trusted time", "role", cl.role.String(), "cert_sha256", hex.EncodeToString(cl.cert[:8]))
	return nil
}

// certNow is the trusted clock that checks client certificates: the
// platform's clock, the one attls.ServerConfig gets. A server without a
// platform clock (tests) uses the system clock.
func (s *Server) certNow() (time.Time, error) {
	if s.Platform != nil && s.Platform.Clock != nil {
		return s.Platform.Clock.Now()
	}
	return time.Now(), nil
}

// grant is what a role may do with one message type.
type grant uint8

const (
	deny grant = iota
	allow
	// limited: ATTEST and IDENTITY under the fresh attestation limit of
	// limit.go.
	limited
)

// adminTypes are the message types only the admin role may send.
var adminTypes = []wire.MsgType{
	wireadmin.TypeImportShare, wireadmin.TypeImportSealed, wireadmin.TypeConfigUpdate, wireadmin.TypeApproveExit,
	handover.TypeOrder, handover.Type, handover.TypeImport,
}

// allows is the role table. A role or a type missing here is denied.
var allows = func() map[attls.Role]map[wire.MsgType]grant {
	admin := map[wire.MsgType]grant{
		wire.TypeHealth: allow, wire.TypePublicKeys: allow, wire.TypeAttest: allow, wire.TypeIdentity: allow,
	}
	for _, t := range adminTypes {
		admin[t] = allow
	}
	t := map[attls.Role]map[wire.MsgType]grant{
		// The Dirk fork: keys, signatures, health and its identity on each
		// new connection. It never sends ATTEST.
		attls.RoleSigning: {wire.TypeHealth: allow, wire.TypePublicKeys: allow, wire.TypeSign: allow, wire.TypeIdentity: limited},
		// PUBLIC_KEYS is in: a verifier of an ATTEST answer needs the keys
		// to recompute keys_hash.
		attls.RoleAttestOnly: {wire.TypeHealth: allow, wire.TypePublicKeys: allow, wire.TypeAttest: limited, wire.TypeIdentity: limited},
		attls.RoleAdmin:      admin,
	}
	// Testnet builds only. A default build has no row for this role, so
	// it gets nothing even if RoleOf ever returned it.
	if buildflavor.AdminRootDirect {
		t[attls.RoleAdminRootDirect] = admin
	}
	return t
}()

// grantFor is what cl may do with t.
func grantFor(cl *client, t wire.MsgType) grant {
	if cl == nil {
		return deny
	}
	if cl.local {
		return localAllows[t]
	}
	if cl.undated {
		// No chain checked with its dates yet (stillValid): HEALTH only.
		if t == wire.TypeHealth {
			return allow
		}
		return deny
	}
	return allows[cl.role][t]
}

// dispatchFor serves f for cl. A type the role table does not grant cl's
// role gets FORBIDDEN before the handed-over check and before anything of
// the payload is read; a refused import's payload is wiped. Limited types
// count against the certificate's attestation limit (limit.go).
func (s *Server) dispatchFor(ctx context.Context, f wire.Frame, cl *client) ([]byte, error) {
	switch grantFor(cl, f.Type) {
	case allow:
		return s.dispatch(ctx, f)
	case limited:
		return s.limitedAttestation(ctx, f, cl)
	}
	if f.Type == wireadmin.TypeImportShare || f.Type == wireadmin.TypeImportSealed {
		clear(f.Payload)
	}
	role := attls.RoleNone
	var cert []byte
	if cl != nil {
		role, cert = cl.role, cl.cert[:8]
	}
	s.Log.Warn("refused: client role", "type", f.Type.String(), "role", role.String(), "cert_sha256", hex.EncodeToString(cert))
	return nil, backend.Refused(backend.StatusForbidden,
		"%v: a client certificate of the %v role may not send this message (docs/protocol.md, \"Client roles\"; admin messages need extended key usage %v on the leaf and on its issuing intermediate, which has pathlen:0 and is signed by the root)",
		f.Type, role, backend.AdminClientOID)
}
