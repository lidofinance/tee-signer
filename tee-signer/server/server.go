// Package server serves the wire protocol on top of a core.Signer and a
// platform. It owns share import, share sealing and attestation.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
	"github.com/lidofinance/tee-signer/tee-signer/state"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

const Version = "0.1.0" + buildflavor.VersionSuffix // HEALTH's version; "+testnet" in a testnet build

// handshakeTimeout is how long a TLS peer has to finish the handshake. A
// variable so a test can shorten it.
var handshakeTimeout = 10 * time.Second

// Server handles connections. Requests on one connection run in order;
// connections run concurrently, and the core serializes signing.
type Server struct {
	Signer   *core.Signer
	Hooks    *state.Hooks
	Platform *platform.Platform
	// State returns the setup and config state that IDENTITY, ATTEST and
	// HEALTH carry. nil: all zero.
	State func() backend.SetupState
	// SetupHash and LogID bind the stored shares to the setup and to the mark
	// log (markstore.ShareAAD). Both zero: the flag path without a setup.
	// With a setup the runner sets LogID once the mark log is claimed; until
	// then the server stores and loads no share.
	SetupHash [32]byte
	LogID     [32]byte
	// KeyReleaseHash is the key_release_hash the platform read at start
	// (platform.Platform.KeyRule). The setup state of a runner with a
	// setup carries it; zero when the platform has no self-check or the
	// read failed.
	KeyReleaseHash [32]byte
	// KeyLock is the lock of the same key rule. HEALTH of a runner with a
	// setup carries it; the setup state does not, its layout is the
	// circuits' statement.
	KeyLock backend.KeyLock
	// KeyLockWhy says what KeyLock rests on; HEALTH carries it.
	KeyLockWhy string
	// DebugImport holds the plaintext import setting of debug builds
	// (-tags debugimport); it is empty in release builds.
	DebugImport
	// ImportKey, if set, accepts IMPORT_SHARE_SEALED encrypted to it.
	ImportKey *sealedimport.Key
	// TLSKeyHash is sha256 of the TLS certificate's SPKI, if TLS is on.
	TLSKeyHash []byte
	// ClientCAs is the ClientCAs pool of the TLS configuration
	// (attls.ServerConfig). A connection whose handshake had no trusted
	// time has its chain checked against it once the clock has a reading
	// (roles.go). nil: such a connection gets HEALTH only.
	ClientCAs *x509.CertPool
	Log       *slog.Logger
	// Updates, if set, takes CONFIG_UPDATE and keeps the core at the config
	// in force (config.go): a runner with a setup. nil: CONFIG_UPDATE is
	// UNSUPPORTED.
	Updates *Updates
	// OnWedged, if set, runs when a lock of the server is still held long
	// after a request panicked (recover.go): every later request would
	// hang on it.
	OnWedged func(error)
	// Image, if set, is the image check (imagegate.go) of a runner with a
	// setup: a request that signs, hands over or imports goes through only
	// while it passes. nil: no check (the flag path, and tests).
	Image *ImageGate

	// handoverSrc serves HANDOVER_ORDER and HANDOVER as a source
	// (handover_source.go, release builds with a setup and the mark log);
	// nil: UNSUPPORTED.
	handoverSrc handoverSource
	// imp serves IMPORT_HANDOVER, the target's side of HANDOVER
	// (handover_import.go, release builds with a setup and the mark log);
	// nil: UNSUPPORTED.
	imp handoverImporter

	started time.Time
	wg      sync.WaitGroup
	// panics counts the requests that panicked (recover.go).
	panics atomic.Uint64
	// panicked is why a state-changing request's panic stopped the
	// runner's state changes until a restart (recover.go); nil before.
	panicked atomic.Pointer[string]
	// panicHook, tests only, runs before each request is served.
	panicHook func(wire.Frame)
	// handedOver: this runner handed its shares over and signs nothing.
	handedOver atomic.Bool
	// lostLogged: the loss of the mark log is in the log (lostRefusal).
	lostLogged atomic.Bool
	// sharesMu orders share additions (read) against the handover's read
	// of every share and its tombstone (write): no share is added between
	// the two, so none is left behind.
	sharesMu namedRWMutex[sharesMuName]
	// blocked holds validators whose import raised the mark log but whose
	// interchange maxima the core did not take: they sign nothing until a
	// restart, which reads the raised mark.
	blockedMu sync.Mutex
	blocked   map[backend.Pubkey]bool
	// admitting holds the validators whose share addShareOf is adding now:
	// one share per validator at a time (SSI-STORAGE-01).
	admitMu   sync.Mutex
	admitting map[backend.Pubkey]bool
	// attestLimit counts the fresh attestations of attest-only clients
	// (limit.go); limitNow, if set, is its clock (tests).
	attestLimit attestLimit
	limitNow    func() time.Time
	// exits holds exit approvals and the day's exits (exits.go).
	exits exitState

	// Limits bounds connections, handshakes and large frame bytes
	// (limits.go); the zero value has the defaults.
	Limits Limits
	// conns, handshakes and inflight count what the limits bound, over
	// every listener of the server.
	conns, handshakes, inflight gauge
	// connsNote, handshakesNote and inflightNote count refusals for the
	// log (limits.go).
	connsNote, handshakesNote, inflightNote limitNote
}

// shareRecord is the sealed form of a stored share. parseShareRecord
// reads it and refuses a field it does not have (keyorigin.go).
type shareRecord struct {
	Pubkey backend.Pubkey `json:"pubkey"`
	Secret []byte         `json:"secret"`
	Index  uint64         `json:"index"`
	// History: the import that stored the share carried attestation
	// maxima, which raised the mark log first. A restart exempts the key
	// from the source gate (state.Hooks.NoteHistory). The host can roll
	// the record back to one without it, which only gates the key again.
	History bool `json:"history,omitempty"`
}

func shareKey(pk backend.Pubkey) string { return "shares/" + hex.EncodeToString(pk[:]) }

// shareAAD is the AAD of pk's stored share (markstore.ShareAAD).
func (s *Server) shareAAD(pk backend.Pubkey) []byte {
	return markstore.ShareAAD(s.SetupHash, s.LogID, pk)
}

// checkLogID refuses shares on a runner with a setup whose mark log has no
// log_id yet: the share would be bound to no log.
func (s *Server) checkLogID() error {
	if s.SetupHash != ([32]byte{}) && s.LogID == ([32]byte{}) {
		return errors.New("the mark log is not claimed yet (no log_id), and shares are bound to it")
	}
	return nil
}

// ListShares lists the stored shares. A runner with a setup lists them
// once, before the mark log's claim: the claim
// learns from that list whether the node holds shares, and the runner loads
// only that list (LoadListedShares). A share that shows up in a later
// listing is never loaded.
func ListShares(st platform.Store) ([]string, error) { return st.List("shares/") }

// LoadShares lists the stored shares and loads them: the flag path without
// a setup. A runner with a setup calls LoadListedShares with the list it
// took before the claim.
func (s *Server) LoadShares() (int, error) {
	keys, err := ListShares(s.Platform.Store)
	if err != nil {
		return 0, err
	}
	return s.LoadListedShares(keys)
}

// LoadListedShares unseals the shares of names (from ListShares) and loads
// them into the signer. It returns how many loaded; a share that fails
// stays unloaded and is logged. A share sealed under another setup or
// another log_id does not unseal.
func (s *Server) LoadListedShares(keys []string) (int, error) {
	if err := s.checkLogID(); err != nil {
		return 0, err
	}
	loaded := 0
	var errs []error
	for _, k := range keys {
		if !strings.HasPrefix(k, "shares/") {
			errs = append(errs, fmt.Errorf("%s: not a share name", k))
			continue
		}
		blob, err := s.Platform.Store.Get(k)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue
		}
		pkHex := strings.TrimPrefix(k, "shares/")
		var pk backend.Pubkey
		if b, err := hex.DecodeString(pkHex); err != nil || len(b) != len(pk) {
			errs = append(errs, fmt.Errorf("%s: bad key name", k))
			continue
		} else {
			copy(pk[:], b)
		}
		plain, err := s.Platform.Sealer.Unseal(blob, s.shareAAD(pk))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: unseal: %w", k, err))
			continue
		}
		rec, err := parseShareRecord(plain)
		clear(plain)
		if err != nil || rec.Pubkey != pk || len(rec.Secret) != 32 {
			clear(rec.Secret)
			errs = append(errs, fmt.Errorf("%s: bad record", k))
			continue
		}
		var sec [32]byte
		copy(sec[:], rec.Secret)
		clear(rec.Secret)
		s.Hooks.ExpectRecord(pk)
		_, err = s.Signer.AddValidator(pk, sec, rec.Index, nil)
		clear(sec[:])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue
		}
		if rec.History {
			s.Hooks.NoteHistory(pk)
		}
		loaded++
	}
	return loaded, errors.Join(errs...)
}

// Serve accepts connections until ctx ends or the listener fails.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s.started.IsZero() {
		s.started = time.Now()
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return err
		}
		// Over the connection cap the connection closes before the
		// handshake: no goroutine, no TLS state (ATTEST-BUDGET-01).
		if !s.conns.take(1, s.Limits.maxConns()) {
			if n := s.connsNote.note(); n > 0 {
				s.Log.Warn("refused: connection cap", "max_conns", s.Limits.maxConns(), "refused_since_start", n)
			}
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.conns.give(1)
			s.handleConn(ctx, c)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	// A TLS listener hands out the connection before the handshake. Do it
	// here with a time limit, so a peer that connects and says nothing (on
	// vsock that can be the parent instance) does not hold a goroutine
	// for good, and log why a handshake failed. The verified client
	// certificate gives the connection's role (roles.go); a connection
	// without TLS is a local admin client.
	cl := localAdmin
	if tc, ok := c.(*tls.Conn); ok {
		// The handshake budget: a peer that has not shown a client
		// certificate yet holds one of a few slots (ATTEST-BUDGET-01).
		if !s.handshakes.take(1, s.Limits.maxHandshakes()) {
			if n := s.handshakesNote.note(); n > 0 {
				s.Log.Warn("refused: handshake budget", "max_handshakes", s.Limits.maxHandshakes(), "refused_since_start", n)
			}
			return
		}
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		s.handshakes.give(1)
		if err != nil {
			if ctx.Err() == nil {
				s.Log.Warn("tls handshake", "remote", c.RemoteAddr().String(), "err", err)
			}
			return
		}
		cs := tc.ConnectionState()
		cl = clientOf(&cs)
		if cl.undated {
			s.Log.Warn("tls handshake without trusted time: HEALTH only until the clock has a reading", "remote", c.RemoteAddr().String(),
				"cert_sha256", hex.EncodeToString(cl.cert[:8]))
		}
	}
	fc := &frameConn{Conn: c, timeout: frameTimeout, idle: s.Limits.IdleTimeout,
		inflight: &s.inflight, maxInflight: s.Limits.maxInflight()}
	defer fc.release()
	for {
		fc.next()
		f, err := wire.ReadFrame(fc)
		if err != nil {
			switch {
			case errors.Is(err, errInflight):
				if n := s.inflightNote.note(); n > 0 {
					s.Log.Warn("refused: in-flight byte cap", "max_inflight_bytes", s.Limits.maxInflight(), "refused_since_start", n)
				}
			case !errors.Is(err, io.EOF) && ctx.Err() == nil && !errors.Is(err, net.ErrClosed):
				s.Log.Warn("read", "remote", c.RemoteAddr().String(), "err", err)
			}
			return
		}
		if err := s.stillValid(cl, f.Type); err != nil {
			if f.Type == wireadmin.TypeImportShare || f.Type == wireadmin.TypeImportSealed {
				clear(f.Payload)
			}
			s.Log.Warn("refused and closed: client certificate", "remote", c.RemoteAddr().String(), "type", f.Type.String(),
				"cert_sha256", hex.EncodeToString(cl.cert[:8]), "err", err)
			_ = wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: wire.EncodeError(err)})
			return
		}
		payload, ok := s.answer(ctx, f, cl)
		if !ok {
			return
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: payload}); err != nil {
			s.Log.Warn("write", "err", err)
			return
		}
	}
}

func (s *Server) dispatch(ctx context.Context, f wire.Frame) ([]byte, error) {
	switch f.Type {
	case wire.TypeHealth, wire.TypePublicKeys, wire.TypeAttest, wire.TypeIdentity, handover.Type, handover.TypeOrder:
	default:
		// After a handover the runner answers status, keys and attestation
		// only, and the handover again; nothing that signs or imports.
		if s.HandedOver() {
			if f.Type == wireadmin.TypeImportShare {
				clear(f.Payload)
			}
			return nil, backend.Refused(backend.StatusStorage, "handed over to another image: this runner signs and imports nothing")
		}
	}
	switch f.Type {
	case wire.TypeHealth, wire.TypePublicKeys, wire.TypeAttest, wire.TypeIdentity:
	default:
		// Another runner instance took the mark log over (RBRLOG-03), or a
		// state-changing request panicked (recover.go): this one signs,
		// imports and hands over nothing, also messages that write no
		// record, and answers status, keys and attestation only.
		err := s.panicRefusal()
		if err == nil {
			err = s.lostRefusal()
		}
		if err != nil {
			if f.Type == wireadmin.TypeImportShare {
				clear(f.Payload)
			}
			return nil, err
		}
	}
	switch f.Type {
	case wire.TypeHealth, wire.TypePublicKeys, wire.TypeAttest, wire.TypeIdentity, wireadmin.TypeConfigUpdate:
	default:
		// An image the allowed list in force does not name answers status,
		// keys, attestation and config updates only (imagegate.go).
		if s.Image != nil {
			if err := s.Image.Check(s.Updates); err != nil {
				if f.Type == wireadmin.TypeImportShare {
					clear(f.Payload)
				}
				return nil, err
			}
		}
	}
	switch f.Type {
	case handover.Type, handover.TypeOrder:
		if s.handoverSrc == nil {
			return nil, backend.Refused(backend.StatusUnsupported,
				"this runner hands over to no one: HANDOVER needs a release build with a setup and the mark log, whose verifier checks the target's attestation")
		}
		if f.Type == handover.TypeOrder {
			return s.handoverSrc.order(ctx, f.Payload)
		}
		return s.handoverSrc.handover(ctx, f.Payload)
	case handover.TypeImport:
		if s.imp == nil {
			return nil, backend.Refused(backend.StatusUnsupported,
				"this runner takes no handed-over shares: IMPORT_HANDOVER needs a release build with a setup and the mark log, whose verifier checks the source's origin proof")
		}
		return s.imp.importShares(ctx, f.Payload)
	case wire.TypeHealth:
		h, err := s.health()
		if err != nil {
			return nil, err
		}
		return wire.EncodeHealth(h)
	case wire.TypePublicKeys:
		return wire.EncodeKeys(s.Signer.Keys()), nil
	case wire.TypeSign:
		req, err := wire.DecodeSign(f.Payload)
		if err != nil {
			return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
		}
		sig, err := s.sign(req)
		if err != nil {
			return nil, err
		}
		return sig[:], nil
	case wire.TypeAttest, wire.TypeIdentity:
		nonce, err := decodeNonce(f.Payload)
		if err != nil {
			return nil, err
		}
		return s.attestationFor(f.Type, nonce).answer(ctx)
	case wireadmin.TypeImportSealed:
		if s.ImportKey == nil {
			return nil, backend.Refused(backend.StatusUnsupported, "sealed share import is disabled (-sealed-import=false)")
		}
		if o := s.importing(); o != nil {
			return nil, backend.Refused(backend.StatusNotReady, "a handover import (order %x) is in progress: this runner takes the handed-over shares only until it ends", o.Hash[:8])
		}
		req, err := wireadmin.DecodeImportSealed(f.Payload)
		if err != nil {
			return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
		}
		if err := s.checkMaxima(req.Interchange); err != nil {
			return nil, err
		}
		if s.Updates != nil {
			b, e, err := s.checkImportOrder(&req)
			if err != nil {
				return nil, err
			}
			if err := s.checkSplit(&req, b, e); err != nil {
				return nil, err
			}
		}
		secret, err := s.ImportKey.Open(&req)
		if err != nil {
			return nil, backend.Refused(backend.StatusBadKey, "%v", err)
		}
		defer clear(secret[:])
		got, err := core.PubkeyOf(secret)
		if err != nil || got != req.SharePubkey {
			return nil, backend.Refused(backend.StatusBadKey, "decrypted share does not match share_pubkey")
		}
		k, err := s.addShare(req.Pubkey, &secret, req.Index, req.Interchange, "sealed")
		if err != nil {
			return nil, err
		}
		return wire.AppendKey(nil, k), nil
	case wireadmin.TypeConfigUpdate:
		return s.configUpdate(ctx, f.Payload)
	case wireadmin.TypeApproveExit:
		return s.approveExit(f.Payload)
	}
	// IMPORT_SHARE is served only by debug builds (plainimport.go); a
	// release build answers it as an unknown type (noplainimport.go).
	return s.otherMessage(f)
}

// lostRefusal is the refusal of a runner whose mark log latched
// markstore.ErrLost, nil while it holds the log. The first refusal logs
// why; the runner stays up so HEALTH can say it.
func (s *Server) lostRefusal() error {
	if s.Hooks == nil {
		return nil
	}
	lost := s.Hooks.MarkLogLost()
	if lost == nil {
		return nil
	}
	if s.lostLogged.CompareAndSwap(false, true) {
		s.Log.Error("mark log lost to another runner instance: this runner signs, imports and hands over nothing until it is replaced",
			"err", lost, "record", s.Hooks.GuardStatus())
	}
	return backend.Refused(backend.StatusNotReady, "mark log: %v", lost)
}

// unknownType is the answer to a message type this runner does not serve.
func unknownType(f wire.Frame) error {
	return backend.Refused(backend.StatusUnsupported, "message type %v", f.Type)
}

// decodeNonce reads an ATTEST or IDENTITY request. A request of another
// version gets UNSUPPORTED.
func decodeNonce(p []byte) ([]byte, error) {
	nonce, err := wire.DecodeAttest(p)
	if errors.Is(err, wire.ErrRequestVersion) {
		return nil, backend.Refused(backend.StatusUnsupported, "%v", err)
	}
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	return nonce, nil
}

// configUpdate answers CONFIG_UPDATE: the update's outcome and the setup
// state in force after it. Only an admin client gets here (roles.go); the
// approvers' signatures carry the authority over what changes.
func (s *Server) configUpdate(ctx context.Context, p []byte) ([]byte, error) {
	if s.Updates == nil {
		return nil, backend.Refused(backend.StatusUnsupported, "this runner has no setup, so it takes no config update")
	}
	raw, err := wireadmin.DecodeConfigUpdate(p)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	outcome, st, err := s.Updates.Accept(ctx, raw)
	if err != nil {
		s.Log.Warn("config update refused", "err", err)
		return nil, err
	}
	return wireadmin.EncodeConfigUpdateResponse(outcome, &st), nil
}

// SetupState is the setup and config state this runner reports now, with
// the key origin of the loaded keys (keyorigin.go).
func (s *Server) SetupState() backend.SetupState {
	st, _ := s.stateWithKeys()
	return st
}

// identity is this boot's identity without the attestation.
func (s *Server) identity() *backend.Identity {
	id := &backend.Identity{State: s.SetupState(), TLSKeyHash: s.TLSKeyHash}
	if s.ImportKey != nil {
		s.ImportKey.Fill(id)
	}
	return id
}

func (s *Server) sign(req backend.SignRequest) (backend.Signature, error) {
	s.blockedMu.Lock()
	blocked := s.blocked[req.Pubkey]
	s.blockedMu.Unlock()
	if blocked {
		return backend.Signature{}, backend.Refused(backend.StatusStorage, "the import's interchange maxima did not reach the core; restart the runner")
	}
	kind := req.Message.Kind().String()
	if o := s.importing(); o != nil {
		// A handover target signs nothing before every share is in, also
		// after a restart mid-import: the slot is in the mark log.
		return backend.Signature{}, backend.Refused(backend.StatusNotReady,
			"a handover import (order %x) is in progress: nothing is signed until every handed-over share is in", o.Hash[:8])
	}
	if a, ok := req.Message.(*backend.AttestationData); ok && s.Hooks != nil {
		if f, on := s.Hooks.SourceFloor(req.Pubkey); on && a.Source.Epoch < f {
			err := backend.Refused(backend.StatusSlashSource,
				"attestation source %d below the source gate's floor epoch %d: the mark log held no vote when this runner started on it, and no import carried this validator's vote history", a.Source.Epoch, f)
			s.Log.Info("refused", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message), "err", err)
			return backend.Signature{}, err
		}
	}
	if _, ok := req.Message.(*backend.VoluntaryExit); ok && s.Updates == nil && s.Platform.Name != "dev" {
		// The approval and daily cap gate below needs a setup. Without one,
		// a signing client could exit any validator on the allowlist.
		err := backend.Refused(backend.StatusPolicyExit,
			"this runner has no setup, so it has no exit approvals and no daily stake cap: it signs no voluntary exit off the dev platform")
		s.Log.Info("refused", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message), "err", err)
		return backend.Signature{}, err
	}
	var (
		sig    backend.Signature
		repeat bool
		err    error
	)
	if s.Updates == nil {
		sig, repeat, err = s.Signer.SignDetailed(req)
	}
	// The config in force now goes into the core first; without the values
	// in force nothing is signed. A request that reached the core after the
	// config moved on is checked again under the new values.
	for attempt := 0; s.Updates != nil; attempt++ {
		g, gerr := s.Updates.beforeSign()
		if gerr != nil {
			s.Log.Warn("refused", "kind", kind, "pubkey", req.Pubkey.String()[:18], "err", gerr)
			return backend.Signature{}, gerr
		}
		if e, ok := req.Message.(*backend.VoluntaryExit); ok {
			if err := s.exitAllowed(req.Pubkey, e); err != nil {
				s.Log.Info("refused", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message), "err", err)
				return backend.Signature{}, err
			}
		}
		sig, repeat, err = s.Signer.SignGuarded(req, g)
		if !errors.Is(err, core.ErrConfigMoved) {
			break
		}
		if attempt == 2 {
			err = backend.Refused(backend.StatusNotReady, "the config changed three times while this request waited; send it again")
			break
		}
	}
	if err != nil {
		var r *backend.RefusedError
		if errors.As(err, &r) && r.Code.IsSlashing() {
			if f, ok := s.Hooks.Floor(req.Pubkey); ok && atOrBelowFloor(req.Message, f, s.Signer.Config().SlotsPerEpoch) {
				r.Detail += fmt.Sprintf(" (at or below restart floor epoch %d)", f)
			}
		}
		s.Log.Info("refused", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message), "err", err)
		return sig, err
	}
	if repeat {
		s.Log.Info("signed (exact repeat, same signature)", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message))
		return sig, nil
	}
	if m, ok := req.Message.(*backend.RootMessage); ok && m.Type.Unverified() {
		s.Log.Warn("signed unverified (allow_unverified_nonslashable)", "root_type", m.Type, "epoch", m.Epoch,
			"pubkey", req.Pubkey.String()[:18], "count", s.Signer.Stats().UnverifiedSignatures)
		return sig, nil
	}
	s.Log.Info("signed", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message))
	return sig, nil
}

func atOrBelowFloor(m backend.Message, floor, slotsPerEpoch uint64) bool {
	switch v := m.(type) {
	case *backend.AttestationData:
		return v.Target.Epoch <= floor || v.Source.Epoch < floor
	case *backend.BeaconBlockHeader:
		return v.Slot/slotsPerEpoch <= floor
	case *backend.PayloadAttestationData:
		return v.Slot/slotsPerEpoch <= floor
	case *backend.PayloadEnvelope:
		return v.Payload.SlotNumber/slotsPerEpoch <= floor
	}
	return false
}

func describe(m backend.Message) string {
	switch v := m.(type) {
	case *backend.AttestationData:
		return fmt.Sprintf("slot=%d source=%d target=%d", v.Slot, v.Source.Epoch, v.Target.Epoch)
	case *backend.BeaconBlockHeader:
		return fmt.Sprintf("slot=%d proposer=%d", v.Slot, v.ProposerIndex)
	case *backend.VoluntaryExit:
		return fmt.Sprintf("epoch=%d validator=%d", v.Epoch, v.ValidatorIndex)
	case *backend.ValidatorRegistration:
		return fmt.Sprintf("gas_limit=%d timestamp=%d", v.GasLimit, v.Timestamp)
	case *backend.RootMessage:
		return fmt.Sprintf("type=%d epoch=%d", v.Type, v.Epoch)
	case *backend.PayloadAttestationData:
		return fmt.Sprintf("slot=%d payload_present=%t blob_data_available=%t", v.Slot, v.PayloadPresent, v.BlobDataAvailable)
	case *backend.PayloadEnvelope:
		return fmt.Sprintf("slot=%d self_build=%t", v.Payload.SlotNumber, v.BuilderIndex == backend.BuilderIndexSelfBuild)
	case *backend.ProposerPreferences:
		return fmt.Sprintf("proposal_slot=%d validator=%d gas_limit=%d", v.ProposalSlot, v.ValidatorIndex, v.TargetGasLimit)
	case *backend.SelectionProof:
		return fmt.Sprintf("slot=%d", v.Slot)
	case *backend.AggregateAndProof:
		return fmt.Sprintf("form=%d bytes=%d", v.Form, len(v.SSZ))
	case *backend.SyncCommitteeMessage:
		return fmt.Sprintf("slot=%d", v.Slot)
	case *backend.SyncSelectionProof:
		return fmt.Sprintf("slot=%d subcommittee=%d", v.Slot, v.SubcommitteeIndex)
	case *backend.ContributionAndProof:
		return fmt.Sprintf("bytes=%d", len(v.SSZ))
	case *backend.BuilderRequestAuth:
		return fmt.Sprintf("slot=%d data_root=%s", v.Slot, backend.BuilderRequestAuthDataRoot(v.Data).String()[:18])
	}
	return ""
}

// addShare seals and stores an imported share and loads it into the
// signer. how is "plaintext" or "sealed", for the log.
func (s *Server) addShare(pk backend.Pubkey, secret *[32]byte, index uint64, interchange *backend.Watermark, how string) (backend.ValidatorKey, error) {
	return s.addShareOf(pk, secret, index, interchange, how, nil)
}

// addShareOf is addShare with keys, the signer's list the duplicate check
// uses (a handover import takes it once per request); nil reads it now.
//
// One share per validator is added at a time, and the duplicate check
// looks at the core after the caller's list: keys may be older than a
// share of pk that another request loaded since. A second share of a
// validator is refused before it is stored, so it never replaces the
// stored record of the share that loaded (SSI-STORAGE-01).
func (s *Server) addShareOf(pk backend.Pubkey, secret *[32]byte, index uint64, interchange *backend.Watermark, how string,
	keys []backend.ValidatorKey) (backend.ValidatorKey, error) {
	if !s.reserve(pk) {
		return backend.ValidatorKey{}, &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "another request is adding this validator"}
	}
	defer s.release(pk)
	s.sharesMu.RLock()
	defer s.sharesMu.RUnlock()
	if s.HandedOver() {
		return backend.ValidatorKey{}, backend.Refused(backend.StatusStorage, "handed over to another image: this runner imports nothing")
	}
	if o := s.importing(); o != nil && how != "handover" {
		// Checked under the share lock, which the import's start holds while
		// it writes the slot (handover_import.go).
		return backend.ValidatorKey{}, backend.Refused(backend.StatusNotReady,
			"a handover import (order %x) is in progress: this runner takes the handed-over shares only until it ends", o.Hash[:8])
	}
	if keys == nil {
		keys = s.Signer.Keys()
	}
	if err := s.checkShare(pk, secret, keys); err != nil {
		return backend.ValidatorKey{}, err
	}
	if _, err := s.Signer.State(pk); err == nil {
		return backend.ValidatorKey{}, &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "validator already loaded"}
	}
	// Interchange maxima (an EIP-3076 import, or the handover's mark) raise
	// the mark log first: once the share is stored, a restart must read
	// them from the log.
	if interchange != nil && s.Hooks != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.Hooks.RaiseMark(ctx, *interchange)
		cancel()
		if err != nil {
			return backend.ValidatorKey{}, backend.Refused(backend.StatusStorage, "raise the mark log to the interchange maxima: %v", err)
		}
	}
	blob, err := s.sealRecord(shareRecord{Pubkey: pk, Secret: secret[:], Index: index,
		History: interchange != nil && interchange.HasAttestation})
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	if err := s.Platform.Store.Put(shareKey(pk), blob); err != nil {
		return backend.ValidatorKey{}, backend.Refused(backend.StatusPlatform, "store share: %v", err)
	}
	return s.loadShare(pk, secret, index, interchange, how)
}

// reserve marks pk as being added; false if it is already.
func (s *Server) reserve(pk backend.Pubkey) bool {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	if s.admitting[pk] {
		return false
	}
	if s.admitting == nil {
		s.admitting = map[backend.Pubkey]bool{}
	}
	s.admitting[pk] = true
	return true
}

func (s *Server) release(pk backend.Pubkey) {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	delete(s.admitting, pk)
}

// importing is the handover order whose import is in progress here, nil
// when none is (Updates.ImportOrder).
func (s *Server) importing() *markstore.Order {
	if s.Updates == nil {
		return nil
	}
	return s.Updates.ImportOrder()
}

// checkMaxima refuses interchange maxima above the clock epoch plus the
// restart floor's margin (max_epochs_ahead + 1). No honest signer signed
// past that, and maxima above it raise the mark log and stop every key of
// this runner from signing until the clock gets there (2^64-1 is the
// handover tombstone).
func (s *Server) checkMaxima(wm *backend.Watermark) error {
	return s.checkMaximaAhead(wm, 0)
}

// checkHandoverMark is checkMaxima for a handover's mark (SHC-02): the
// source's device mark, whose target and block bounds run up to the
// commit-ahead window past what it signed, so the horizon is that much
// later (this runner's commit_ahead target_epochs).
func (s *Server) checkHandoverMark(wm *backend.Watermark) error {
	return s.checkMaximaAhead(wm, s.Signer.Config().CommitAhead.TargetEpochs)
}

func (s *Server) checkMaximaAhead(wm *backend.Watermark, window uint64) error {
	if wm == nil {
		return nil
	}
	t, err := s.Platform.Clock.Now()
	if err != nil {
		return backend.Refused(backend.StatusPlatform, "the interchange maxima check needs the clock: %v", err)
	}
	cfg := s.Signer.Config()
	now := s.Signer.EpochAt(uint64(t.Unix()))
	horizon := now + state.DefaultFloorMargin(cfg) + window
	if horizon < now {
		horizon = ^uint64(0)
	}
	if wm.HasAttestation && max(wm.SourceEpoch, wm.TargetEpoch) > horizon || wm.HasBlock && wm.BlockSlot/cfg.SlotsPerEpoch > horizon {
		return backend.Refused(backend.StatusBadRequest,
			"interchange maxima (source %d, target %d, block slot %d) above the clock horizon, epoch %d (clock epoch %d)",
			wm.SourceEpoch, wm.TargetEpoch, wm.BlockSlot, horizon, now)
	}
	return nil
}

// checkShare refuses a share that cannot be stored: no log_id yet, a
// validator already loaded (keys is the signer's list), a runner at its
// setup's max_keys or a bad secret.
func (s *Server) checkShare(pk backend.Pubkey, secret *[32]byte, keys []backend.ValidatorKey) error {
	if err := s.checkLogID(); err != nil {
		return backend.Refused(backend.StatusStorage, "%v", err)
	}
	if s.Updates != nil {
		if n := s.Updates.opt.Setup.MaxKeys; uint64(len(keys)) >= uint64(n) {
			return backend.Refused(backend.StatusNoMem, "this runner holds %d keys, its setup's max_keys is %d", len(keys), n)
		}
	}
	for _, k := range keys {
		if k.Pubkey == pk {
			return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "validator already loaded"}
		}
	}
	if _, err := core.PubkeyOf(*secret); err != nil {
		return &backend.RefusedError{Code: backend.StatusBadKey, Detail: "share secret"}
	}
	return nil
}

// sealRecord seals a share record for the store.
func (s *Server) sealRecord(rec shareRecord) ([]byte, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	blob, err := s.Platform.Sealer.Seal(plain, s.shareAAD(rec.Pubkey))
	clear(plain)
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "seal share: %v", err)
	}
	return blob, nil
}

// loadShare loads a stored share into the signer.
func (s *Server) loadShare(pk backend.Pubkey, secret *[32]byte, index uint64, interchange *backend.Watermark, how string) (backend.ValidatorKey, error) {
	k, err := s.Signer.AddValidator(pk, *secret, index, interchange)
	if err != nil {
		// A duplicate loaded nothing: the validator keeps its share and
		// its bounds (APSTATE-02).
		if interchange != nil && s.Hooks.Mode().MarkLog && backend.StatusOf(err) != backend.StatusDuplicate {
			// The validator may be loaded under the core's older device
			// mark; the log holds the raised one. Keep it from signing.
			s.blockedMu.Lock()
			if s.blocked == nil {
				s.blocked = map[backend.Pubkey]bool{}
			}
			s.blocked[pk] = true
			s.blockedMu.Unlock()
			s.Log.Error("imported share blocked until a restart: the core did not take the interchange maxima", "pubkey", pk.String()[:18], "err", err)
		}
		return k, err
	}
	if interchange != nil && interchange.HasAttestation {
		// Only now is the key's vote history in the core (SSI-HISTORY-01).
		s.Hooks.NoteHistory(pk)
	}
	// With persisted marks, write the first record now: after a restart a
	// stored share without a record is treated as tampering.
	if s.Hooks.Mode().Persist {
		st, err := s.Signer.State(pk)
		if err == nil {
			err = s.Hooks.StoreWatermark(pk, st.Committed)
		}
		if err != nil {
			return k, backend.Refused(backend.StatusStorage, "initial watermark record: %v", err)
		}
	}
	s.Log.Info("imported share", "how", how, "pubkey", pk.String()[:18], "share_pubkey", k.SharePubkey.String()[:18], "index", index)
	return k, nil
}

// UserData is what ATTEST binds into the platform document:
// backend.AttestUserData over the nonce, the setup state st and the hash of
// the loaded keys.
func (s *Server) UserData(nonce []byte, st *backend.SetupState) []byte {
	return backend.AttestUserData(nonce, st, backend.KeysHash(s.Signer.Keys()))
}

func (s *Server) health() (*backend.Health, error) {
	setup := s.SetupState()
	h := &backend.Health{
		Platform:     s.Platform.Name,
		Version:      Version,
		Ready:        true,
		Validators:   len(s.Signer.Keys()),
		ConfigHash:   setup.SetupHash,
		Setup:        &setup,
		ClockSource:  s.Platform.Clock.Source(),
		ClockTrusted: s.Platform.Clock.Trusted(),
		RestartMode:  s.Hooks.Mode().String(),
		StartedUnix:  uint64(s.started.Unix()),
		Record:       s.Hooks.GuardStatus(),

		AllowUnverifiedNonslashable: s.Signer.Config().AllowUnverifiedNonslashable,
		UnverifiedSignatures:        s.Signer.Stats().UnverifiedSignatures,
	}
	if s.SetupHash != ([32]byte{}) {
		h.KeyLock, h.KeyLockWhy = s.KeyLock.String(), s.KeyLockWhy
	}
	if s.Updates != nil {
		w := s.Updates.SetupWire()
		h.SingleKey, h.SigningMode = singleKey(&w.Platform), w.SigningMode.String()
	}
	st := s.Signer.Stats()
	h.Stats = &backend.SignerStats{
		Signatures: st.Signatures, HashCacheHits: st.HashCacheHits, HashCacheMisses: st.HashCacheMisses,
		WatermarkWrites: st.WatermarkWrites, ExactRepeats: st.ExactRepeats,
	}
	if t, err := s.Platform.Clock.Now(); err == nil {
		h.ClockUnix = uint64(t.Unix())
		h.ClockUnixMS = uint64(t.UnixMilli())
	} else {
		h.Ready = false
	}
	if r, ok := s.Platform.Clock.(clock.NTSReporter); ok {
		h.NTS = healthNTS(r.NTSSummary())
	}
	if s.HandedOver() || s.importing() != nil {
		h.Ready = false
	}
	if s.lostRefusal() != nil {
		h.Ready, h.MarkLogLost = false, s.Hooks.MarkLogLost().Error()
	}
	if why := s.panicked.Load(); why != nil {
		h.Ready, h.RequestPanic = false, *why
	}
	if s.Image != nil {
		var refused bool
		if h.Image, refused = s.Image.Status(s.Updates); refused {
			h.Ready = false
		}
	}
	if s.Updates != nil && s.Updates.signErr() != nil {
		// A body the config in force needs is unreadable, or the core
		// refused it: the runner signs nothing.
		h.Ready = false
	}
	return h, nil
}

func healthNTS(s clock.NTSSummary) *backend.ClockNTS {
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	return &backend.ClockNTS{
		Quorum: s.Quorum, BoundNowMS: ms(s.BoundNow), MaxBoundMS: ms(s.MaxBound), OffsetFromHostMS: ms(s.OffsetFromHost),
		Members: s.Members, QuorumAgeMS: ms(s.AgeOfQuorum), Refusals: s.Refusals,
		DriftPPM: s.DriftPPM, DriftErrPPM: s.DriftErrPPM, DriftBaselineS: s.DriftBaseline.Seconds(), RhoViolations: s.RhoViolations,
		CoarseDiffMS: ms(s.CoarseDiff),
	}
}
