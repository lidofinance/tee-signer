//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

// Key generation (runner/keygen) is a build-time plugin, like the platforms:
// only a runner built with peer_* tags has this file. It replaces
// noplainimport.go, whose otherMessage it extends with the DKG_* messages,
// so a runner built without peer tags is byte for byte the one without key
// generation. Debug builds (plaintext import) never get key generation
// (runner/dkg_guard.go).

package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// DebugImport is empty in a release build.
type DebugImport struct{}

// dkg is the key generation of this process, set by main when -dkg-policy
// is given. One server runs per process.
var dkg *keygen.Manager

// dkgOrders is the key generation of a runner with a setup: DKG orders
// pushed over the wire (DKG_ORDER), each message of one order in a
// DKG_IN_ORDER envelope. Set by main; nil on the flag path.
var dkgOrders *keygen.Orders

// operatorKeys answers DKG_OPERATOR, with or without a policy.
var operatorKeys *keygen.OperatorKeys

// SetDKG turns key generation on.
func (s *Server) SetDKG(m *keygen.Manager) { dkg = m }

// SetDKGOrders turns key generation under DKG orders on.
func (s *Server) SetDKGOrders(o *keygen.Orders) { dkgOrders = o }

// SignSetupMessage signs a setup message of a generated key (a builder
// registration) as SIGN does: with the config in force, and not while the
// runner signs nothing (config.go).
func (s *Server) SignSetupMessage(req backend.SignRequest) (backend.Signature, error) {
	return s.sign(req)
}

// ConfigInForce is the core's config with the values in force now.
func (s *Server) ConfigInForce() core.Config {
	if s.Updates != nil {
		s.Updates.reconcile()
	}
	return s.Signer.Config()
}

// TrustedTime is the time a DKG order is checked against, as a config
// update is: the NTS clock with a quorum (any clock on the dev platform).
func (u *Updates) TrustedTime() (uint64, error) {
	now, err := u.trustedNow()
	if err != nil {
		return 0, backend.Refused(backend.StatusClock, "dkg order: %v", err)
	}
	return now, nil
}

// SetOperatorKeys serves DKG_OPERATOR.
func (s *Server) SetOperatorKeys(k *keygen.OperatorKeys) { operatorKeys = k }

// AddGeneratedShares seals the shares a key generation commit made inside
// this runner, hands them to store (which writes them with their key
// records in one store change) and loads them once that succeeded
// (keygen.Env.AddShares). The validator index is unknown until the deposit.
// The share records say generated, with the order, so the key origin
// counts these keys as generated after a restart too.
func (s *Server) AddGeneratedShares(shares []keygen.NewShare, store func(sealed map[string][]byte) error) ([]backend.ValidatorKey, error) {
	// The write lock: no other share is added between the capacity check
	// and the load, by another commit or an import (TKGSTATE-01).
	s.sharesMu.Lock()
	defer s.sharesMu.Unlock()
	if s.HandedOver() {
		return nil, backend.Refused(backend.StatusStorage, "handed over to another image: this runner stores no new share")
	}
	if o := s.importing(); o != nil {
		return nil, backend.Refused(backend.StatusNotReady, "a handover import (order %x) is in progress: this runner stores no generated share until it ends", o.Hash[:8])
	}
	loaded := s.Signer.Keys()
	if err := s.checkBatch(shares, loaded); err != nil {
		return nil, err
	}
	sealed := map[string][]byte{}
	for _, sh := range shares {
		if err := s.checkShare(sh.Pubkey, sh.Secret, loaded); err != nil {
			return nil, err
		}
		if sh.Order != nil && len(sh.Order) != 32 {
			return nil, backend.Refused(backend.StatusInternal, "dkg: order hash of %d bytes", len(sh.Order))
		}
		blob, err := s.sealShare(sh.Pubkey, sh.Secret, backend.IndexUnknown, true, sh.Order)
		if err != nil {
			return nil, err
		}
		sealed[shareKey(sh.Pubkey)] = blob
	}
	if err := store(sealed); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "store shares: %v", err)
	}
	var keys []backend.ValidatorKey
	for _, sh := range shares {
		// Noted before the load: a load that fails after the core took the
		// key leaves it loaded, and the key origin counts loaded keys only.
		s.noteGenerated(sh.Pubkey, sh.Order)
		k, err := s.loadShare(sh.Pubkey, sh.Secret, backend.IndexUnknown, nil, "generated")
		if err != nil {
			return keys, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// checkBatch refuses a key generation batch that would leave more shares
// in the store than the setup's max_keys, or that names a key twice or a
// key held here. It counts every stored share, loaded or not: a restart
// loads them all, so a batch that overfills the store can push a funded
// key out of the loaded set (TKGSTATE-01). Callers hold sharesMu.
func (s *Server) checkBatch(shares []keygen.NewShare, loaded []backend.ValidatorKey) error {
	held := map[string]bool{}
	for _, k := range loaded {
		held[shareKey(k.Pubkey)] = true
	}
	names, err := ListShares(s.Platform.Store)
	if err != nil {
		return backend.Refused(backend.StatusPlatform, "list shares: %v", err)
	}
	for _, n := range names {
		held[n] = true
	}
	batch := map[string]bool{}
	for _, sh := range shares {
		k := shareKey(sh.Pubkey)
		if held[k] || batch[k] {
			return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "dkg: validator " + sh.Pubkey.String() + " is held here or twice in the batch"}
		}
		batch[k] = true
	}
	if s.Updates == nil {
		return nil
	}
	if n := s.Updates.opt.Setup.MaxKeys; uint64(len(held))+uint64(len(batch)) > uint64(n) {
		return backend.Refused(backend.StatusNoMem, "dkg: this runner holds %d keys and the batch adds %d, its setup's max_keys is %d", len(held), len(batch), n)
	}
	return nil
}

// WithShare unseals the stored share of pk and gives it to f; it is wiped
// after. Setup signing (keygen) uses it for the messages the signer core
// does not sign: deposits and the Charon lock hash.
func (s *Server) WithShare(pk backend.Pubkey, f func(secret *[32]byte) error) error {
	blob, err := s.Platform.Store.Get(shareKey(pk))
	if err != nil {
		return err
	}
	plain, err := s.Platform.Sealer.Unseal(blob, s.shareAAD(pk))
	if err != nil {
		return fmt.Errorf("unseal share: %w", err)
	}
	var rec shareRecord
	err = json.Unmarshal(plain, &rec)
	clear(plain)
	if err != nil || rec.Pubkey != pk || len(rec.Secret) != 32 {
		clear(rec.Secret)
		return fmt.Errorf("bad share record")
	}
	var sec [32]byte
	copy(sec[:], rec.Secret)
	clear(rec.Secret)
	defer clear(sec[:])
	return f(&sec)
}

// otherMessage serves the key generation messages and answers every other
// remaining type as unknown. An IMPORT_SHARE payload carries a share in
// plain text, so it is wiped first.
func (s *Server) otherMessage(f wire.Frame) ([]byte, error) {
	if f.Type == wireadmin.TypeImportShare {
		clear(f.Payload)
		return nil, unknownType(f)
	}
	// otherMessage gets no context; the verifiers' key set fetches have
	// their own time limits.
	if body, ok, err := s.dkgMessage(context.Background(), f); ok {
		return body, err
	}
	return nil, unknownType(f)
}

// dkgMessage serves the key generation messages. ok is false for any other
// message type.
func (s *Server) dkgMessage(ctx context.Context, f wire.Frame) (body []byte, ok bool, err error) {
	bad := func(err error) ([]byte, bool, error) {
		return nil, true, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	switch f.Type {
	case dkgmsg.TypeOperator:
		if operatorKeys == nil {
			return nil, true, backend.Refused(backend.StatusNotReady, "operator key not loaded")
		}
		q, err := dkgmsg.DecodeOperatorRequest(f.Payload)
		if err != nil {
			return bad(err)
		}
		body, err = operatorKeys.Answer(ctx, q, s.SetupState(), s.TLSKeyHash)
		return body, true, err
	case dkgmsg.TypeOrder, dkgmsg.TypeInOrder:
		if dkgOrders == nil {
			return nil, true, backend.Refused(backend.StatusUnsupported, "DKG orders are for a runner with a setup; this one takes -dkg-policy")
		}
		body, err = s.orderMessage(ctx, f)
		return body, true, err
	case dkgmsg.TypeHello, dkgmsg.TypeDeal, dkgmsg.TypeFinish, dkgmsg.TypeCommit, dkgmsg.TypeAbort, dkgmsg.TypeSetupSign:
	default:
		return nil, false, nil
	}
	if dkgOrders != nil {
		return nil, true, backend.Refused(backend.StatusUnsupported,
			"this runner makes keys under DKG orders: push the order (DKG_ORDER), then send each message of it in DKG_IN_ORDER")
	}
	if dkg == nil {
		return nil, true, backend.Refused(backend.StatusUnsupported, "key generation is off (no -dkg-policy)")
	}
	body, err = managerMessage(ctx, dkg, f)
	return body, true, err
}

// orderMessage serves DKG_ORDER and DKG_IN_ORDER. While a handover import
// is in progress it takes no new order and starts no session
// (importslot.go): the import ends when the runner holds the source's
// total, so every key it holds until then must be the order's.
func (s *Server) orderMessage(ctx context.Context, f wire.Frame) ([]byte, error) {
	busy := func(what string) error {
		if o := s.importing(); o != nil {
			return backend.Refused(backend.StatusNotReady, "a handover import (order %x) is in progress: no %s until every handed-over share is in", o.Hash[:8], what)
		}
		return nil
	}
	if f.Type == dkgmsg.TypeOrder {
		if err := busy("DKG order"); err != nil {
			return nil, err
		}
		st, err := dkgOrders.Push(ctx, f.Payload)
		if err != nil {
			return nil, err
		}
		return st.Encode(), nil
	}
	m, err := dkgmsg.DecodeInOrder(f.Payload)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	if m.Type == dkgmsg.TypeAbort {
		dkgOrders.Abort(m.Order)
		return nil, nil
	}
	if m.Type == dkgmsg.TypeHello {
		if err := busy("key generation session"); err != nil {
			return nil, err
		}
	}
	mgr, err := dkgOrders.Manager(m.Order, m.Type == dkgmsg.TypeHello)
	if err != nil {
		return nil, err
	}
	return managerMessage(ctx, mgr, wire.Frame{Type: m.Type, ID: f.ID, Payload: m.Payload})
}

// managerMessage serves one key generation message with a manager.
func managerMessage(ctx context.Context, dkg *keygen.Manager, f wire.Frame) (body []byte, err error) {
	bad := func(err error) ([]byte, error) {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	switch f.Type {
	case dkgmsg.TypeHello:
		q, err := dkgmsg.DecodeHelloRequest(f.Payload)
		if err != nil {
			return bad(err)
		}
		return dkg.Hello(ctx, q)
	case dkgmsg.TypeDeal:
		l, err := dkgmsg.DecodeList(f.Payload, dkgmsg.MaxParticipants)
		if err != nil {
			return bad(err)
		}
		return dkg.Deal(ctx, l)
	case dkgmsg.TypeFinish:
		l, err := dkgmsg.DecodeList(f.Payload, dkgmsg.MaxParticipants)
		if err != nil {
			return bad(err)
		}
		fin, err := dkg.Finish(ctx, l)
		if err != nil {
			return nil, err
		}
		return fin.Encode()
	case dkgmsg.TypeCommit:
		q, err := dkgmsg.DecodeCommitRequest(f.Payload)
		if err != nil {
			return bad(err)
		}
		keys, err := dkg.Commit(ctx, q)
		if err != nil {
			return nil, err
		}
		return wire.EncodeKeys(keys), nil
	case dkgmsg.TypeAbort:
		dkg.Abort()
		return nil, nil
	case dkgmsg.TypeSetupSign:
		return dkg.SetupSign(ctx, f.Payload)
	}
	return nil, backend.Refused(backend.StatusInternal, "dkg: unhandled message")
}
