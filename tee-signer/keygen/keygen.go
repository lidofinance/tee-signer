// Package keygen is the runner's side of a distributed key generation among
// runners (docs/dkg.md): a Joint-Feldman DKG like the OP-TEE trusted app's
// (F7 in threshold-signer-poc), with attested session keys in place of the device
// CA and an all-or-nothing commit at the end.
//
// Rounds, each one request from the untrusted relay to every runner:
//
//	HELLO   fresh session keys (HPKE for shares, Ed25519 for signatures),
//	        attested with the policy hash and the relay's nonce
//	DEAL    check every peer's hello with the policy's verifier, then deal
//	        one polynomial per validator and seal each peer's shares to it
//	FINISH  check every deal (signature, commitments, own shares), add up
//	        the shares, store them sealed as pending, sign a confirmation
//	COMMIT  check every participant's confirmation of the same transcript,
//	        then load the shares and keep them
//
// Any bad message ends the session with nothing kept. No share leaves the
// runner except sealed to an attested peer, and none is logged.
package keygen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/devkit/lockorder"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// SessionTTL is how long a session may take from HELLO to FINISH.
const SessionTTL = 10 * time.Minute

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// Env is what the manager needs from the runner.
type Env struct {
	Platform string
	Sealer   platform.Sealer
	Store    platform.Store
	Attester platform.Attester
	// State is the runner's setup state, for the identity of its hello.
	// StateNow, if set, replaces it with the state at each hello (a runner
	// with a setup, whose config state changes).
	State    backend.SetupState
	StateNow func() backend.SetupState
	// TLSKeyHash returns the hash of the runner's TLS key (set after start).
	TLSKeyHash func() []byte
	// OperatorKey is this runner's operator key (operator.go).
	OperatorKey [32]byte
	// Verifiers[i] checks participant i's hello identity (policy order):
	// runnerclient's NewDKGHelloVerifier.
	Verifiers []remote.VerifyFunc
	// Chain is the runner's chain and policy config (genesis fork version,
	// fee recipient allowlist, gas limits) for the setup signatures.
	// ChainNow, if set, replaces it with the config in force at each
	// signature (a runner with config updates).
	Chain    core.Config
	ChainNow func() core.Config
	// AddShares seals the shares as an import does and hands their store
	// entries to store, which writes them in one store change with the key
	// records (platform.Apply). Only if store succeeds are they loaded.
	AddShares func(shares []NewShare, store func(sealed map[string][]byte) error) ([]backend.ValidatorKey, error)
	// WithShare gives f the loaded share of a validator, from sealed
	// storage, and wipes it after.
	WithShare func(pk backend.Pubkey, f func(secret *[32]byte) error) error
	// Sign signs a typed message through the signer core, with its policy.
	Sign func(req backend.SignRequest) (backend.Signature, error)
	// Keys lists the loaded keys.
	Keys func() []backend.ValidatorKey
	Now  func() time.Time
	Log  *slog.Logger
}

// NewShare is a share a commit adds (Env.AddShares).
type NewShare struct {
	Pubkey backend.Pubkey
	Secret *[32]byte
	// Order is the hash of the DKG order the share was made under; nil for
	// a share made under a -dkg-policy file.
	Order []byte
}

// Manager runs at most one session at a time.
type Manager struct {
	mu         lockorder.Mutex[managerMuName]
	env        Env
	policy     *Policy
	policyHash [32]byte
	sess       *session

	// tamperShare, if set, changes the share this runner deals to a
	// recipient. Only this package's tests set it, to play a rogue dealer.
	tamperShare func(recipient uint16, v int, share *[32]byte)
}

// New returns a manager for the policy. env.Verifiers must hold one
// verifier per participant.
func New(p *Policy, policyHash [32]byte, env Env) (*Manager, error) {
	if len(env.Verifiers) != len(p.Participants) {
		return nil, errors.New("keygen: one verifier per participant needed")
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Log == nil {
		env.Log = slog.New(slog.DiscardHandler)
	}
	if env.TLSKeyHash == nil {
		env.TLSKeyHash = func() []byte { return nil }
	}
	return &Manager{env: env, policy: p, policyHash: policyHash}, nil
}

// PolicyHash is the hash every hello of this runner carries.
func (m *Manager) PolicyHash() [32]byte { return m.policyHash }

// session is the state between HELLO and FINISH. It lives in memory only,
// so a restart ends it.
type session struct {
	created  time.Time
	nonce    []byte
	count    int
	signKey  ed25519.PrivateKey
	hpkeKey  hpke.PrivateKey
	hello    []byte
	dealt    bool
	id       [32]byte
	self     uint16 // own share ID
	hellos   []*dkgmsg.Hello
	ownShare [][32]byte // own polynomials evaluated at self, per validator
	ownDeal  [32]byte   // sha256 of the deal this runner sent
}

func (s *session) wipe() {
	if s == nil {
		return
	}
	for i := range s.ownShare {
		clear(s.ownShare[i][:])
	}
	clear(s.signKey)
	s.hpkeKey = nil
	s.ownShare = nil
}

func (m *Manager) n() int { return len(m.policy.Participants) }

func (m *Manager) state() backend.SetupState {
	if m.env.StateNow != nil {
		return m.env.StateNow()
	}
	return m.env.State
}

func (m *Manager) chain() core.Config {
	if m.env.ChainNow != nil {
		return m.env.ChainNow()
	}
	return m.env.Chain
}
func (m *Manager) t() int { return m.policy.Threshold }

// end wipes the session in progress. Callers hold mu.
func (m *Manager) end(why string) {
	if m.sess != nil {
		m.env.Log.Info("dkg session ended", "session", short(m.sess.id), "why", why)
	}
	m.sess.wipe()
	m.sess = nil
}

// refuse ends the session and returns a refusal.
func (m *Manager) refuse(code backend.Status, format string, args ...any) error {
	err := backend.Refused(code, "dkg: "+format, args...)
	m.end(err.Error())
	return err
}

func short(id [32]byte) string { return hex.EncodeToString(id[:6]) }

// Abort ends the session in progress, if any.
func (m *Manager) Abort() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.end("aborted by request")
}

// Hello starts a new session (ending any other) and returns this runner's
// encoded hello.
func (m *Manager) Hello(ctx context.Context, q *dkgmsg.HelloRequest) ([]byte, error) {
	// The setup state shows the order slot, which takes Orders.mu: read it
	// before mu, never under it (TKGORDER-02).
	state := m.state()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.end("new session")
	s := &session{created: m.env.Now(), nonce: append([]byte(nil), q.Nonce...), count: int(q.Count)}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.signKey = priv
	if s.hpkeKey, err = kem.GenerateKey(); err != nil {
		return nil, err
	}
	h := &dkgmsg.Hello{PolicyHash: m.policyHash, Nonce: s.nonce, Count: q.Count, OperatorKey: m.env.OperatorKey}
	copy(h.SignKey[:], pub)
	if _, err := rand.Read(h.Random[:]); err != nil {
		return nil, err
	}
	h.Identity = &backend.Identity{
		State: state, TLSKeyHash: m.env.TLSKeyHash(),
		ImportKEM: kem.ID(), ImportKDF: kdf.ID(), ImportAEAD: aead.ID(),
		ImportKey: s.hpkeKey.PublicKey().Bytes(),
	}
	nonce := h.AttestNonce()
	h.Identity.Attestation, err = m.env.Attester.Attest(ctx, nonce, backend.DKGHelloUserData(nonce, h.Identity))
	if err != nil {
		s.wipe()
		return nil, backend.Refused(backend.StatusPlatform, "dkg: attest: %v", err)
	}
	if s.hello, err = h.Encode(); err != nil {
		s.wipe()
		return nil, err
	}
	m.sess = s
	m.env.Log.Info("dkg hello", "validators", q.Count, "participants", m.n(), "threshold", m.t(),
		"policy", hex.EncodeToString(m.policyHash[:6]))
	return s.hello, nil
}

// live returns the session if it exists, is in the wanted round and has not
// expired. Callers hold mu.
func (m *Manager) live(dealt bool) (*session, error) {
	s := m.sess
	if s == nil {
		return nil, backend.Refused(backend.StatusNotReady, "dkg: no session in progress")
	}
	if m.env.Now().Sub(s.created) > SessionTTL {
		return nil, m.refuse(backend.StatusNotReady, "session older than %v", SessionTTL)
	}
	if s.dealt != dealt {
		return nil, m.refuse(backend.StatusBadRequest, "message out of order")
	}
	return s, nil
}

// Deal checks every hello and returns this runner's encoded deal.
func (m *Manager) Deal(ctx context.Context, raw [][]byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.live(false)
	if err != nil {
		return nil, err
	}
	if len(raw) != m.n() {
		return nil, m.refuse(backend.StatusBadRequest, "%d hellos for %d participants", len(raw), m.n())
	}
	s.hellos = make([]*dkgmsg.Hello, m.n())
	signKeys := map[[32]byte]bool{}
	hpkeKeys := map[string]bool{}
	for i, b := range raw {
		x := uint16(i + 1)
		h, err := dkgmsg.DecodeHello(b)
		if err != nil {
			return nil, m.refuse(backend.StatusBadRequest, "participant %d: %v", x, err)
		}
		if bytes.Equal(b, s.hello) {
			if s.self != 0 {
				return nil, m.refuse(backend.StatusBadRequest, "own hello appears twice")
			}
			if h.OperatorKey != m.policy.Participants[i].operatorKey {
				return nil, m.refuse(backend.StatusBadKey, "this runner's operator key is not the one the policy names for participant %d (%s)",
					x, m.policy.Participants[i].Name)
			}
			if pt := &m.policy.Participants[i]; pt.pinned && h.Identity.State.SetupHash != pt.setupHash {
				return nil, m.refuse(backend.StatusBadKey, "this runner's setup_hash is not the one the order names for participant %d (%s)",
					x, pt.Name)
			}
			s.self = x
		} else if err := m.checkPeerHello(ctx, i, h, s); err != nil {
			return nil, m.refuse(backend.StatusBadKey, "participant %d (%s): %v", x, m.policy.Participants[i].Name, err)
		}
		if signKeys[h.SignKey] || hpkeKeys[string(h.Identity.ImportKey)] {
			return nil, m.refuse(backend.StatusBadKey, "participant %d: session key repeats", x)
		}
		signKeys[h.SignKey], hpkeKeys[string(h.Identity.ImportKey)] = true, true
		s.hellos[i] = h
	}
	if s.self == 0 {
		return nil, m.refuse(backend.StatusBadRequest, "own hello is missing")
	}
	s.id = dkgmsg.SessionID(m.policyHash, raw)
	d, err := m.deal(s)
	if err != nil {
		return nil, m.refuse(backend.StatusInternal, "deal: %v", err)
	}
	out, err := d.Encode()
	if err != nil {
		return nil, m.refuse(backend.StatusInternal, "deal: %v", err)
	}
	s.ownDeal = sha256.Sum256(out)
	s.dealt = true
	m.env.Log.Info("dkg deal", "session", short(s.id), "self", s.self)
	return out, nil
}

// checkPeerHello checks that a peer's hello is for this session and that
// its identity passes the policy's verifier for its position.
func (m *Manager) checkPeerHello(ctx context.Context, i int, h *dkgmsg.Hello, s *session) error {
	if h.PolicyHash != m.policyHash {
		return errors.New("another policy")
	}
	if h.OperatorKey != m.policy.Participants[i].operatorKey {
		return errors.New("operator key is not the one the policy names for this position")
	}
	// The order pins each position's setup. The verifier checks the pin
	// too (setup_sha256 in its settings); this check stands on its own, so
	// a hello of another setup is refused whatever verifier runs.
	if pt := &m.policy.Participants[i]; pt.pinned && h.Identity != nil && h.Identity.State.SetupHash != pt.setupHash {
		return fmt.Errorf("setup_hash %x is not the setup_sha256 %x the order names for this position", h.Identity.State.SetupHash[:8], pt.setupHash[:8])
	}
	if !bytes.Equal(h.Nonce, s.nonce) || int(h.Count) != s.count {
		return errors.New("another session (nonce or validator count)")
	}
	id := h.Identity
	if id.ImportKEM != kem.ID() || id.ImportKDF != kdf.ID() || id.ImportAEAD != aead.ID() {
		return errors.New("session key of another HPKE suite")
	}
	if _, err := kem.NewPublicKey(id.ImportKey); err != nil {
		return fmt.Errorf("session key: %w", err)
	}
	// The verifier checks the document and that it carries this user data;
	// the dev verifier does not recompute the user data itself, so check
	// the binding to the hello's fields here for every verifier. The user
	// data is the hello's own (backend.DKGHelloUserData): an IDENTITY
	// answer for the same nonce does not pass (TKGPEER-01).
	nonce := h.AttestNonce()
	if id.Attestation == nil || !bytes.Equal(id.Attestation.UserData, backend.DKGHelloUserData(nonce, id)) {
		return errors.New("attestation does not bind this hello")
	}
	if err := m.env.Verifiers[i](ctx, nonce, id); err != nil {
		return fmt.Errorf("attestation: %w", err)
	}
	return nil
}

// deal draws one polynomial of degree t-1 per validator, keeps its value
// at the runner's own ID and seals every other participant's values to
// that participant. The coefficients are wiped before it returns.
func (m *Manager) deal(s *session) (*dkgmsg.Deal, error) {
	n, t := m.n(), m.t()
	d := &dkgmsg.Deal{Session: s.id, Dealer: s.self, Threshold: uint16(t), Commitments: make([][]backend.Pubkey, s.count)}
	coeffs := make([][32]byte, t)
	defer func() {
		for i := range coeffs {
			clear(coeffs[i][:])
		}
	}()
	// plain[j] collects participant j's shares, one per validator.
	plain := make([][]byte, n)
	defer func() {
		for _, p := range plain {
			clear(p)
		}
	}()
	s.ownShare = make([][32]byte, s.count)
	for v := range s.count {
		d.Commitments[v] = make([]backend.Pubkey, t)
		for k := range coeffs {
			var err error
			if coeffs[k], err = dkgmath.RandomScalar(); err != nil {
				return nil, err
			}
			if d.Commitments[v][k], err = core.PubkeyOf(coeffs[k]); err != nil {
				return nil, err
			}
		}
		for j := range n {
			x := uint16(j + 1)
			share, err := dkgmath.PolyEval(coeffs, uint64(x))
			if err != nil {
				return nil, err
			}
			if x == s.self {
				s.ownShare[v] = share
			} else {
				if m.tamperShare != nil {
					m.tamperShare(x, v, &share)
				}
				plain[j] = append(plain[j], share[:]...)
			}
			clear(share[:])
		}
	}
	ch := d.CommitmentsHash()
	for j := range n {
		x := uint16(j + 1)
		if x == s.self {
			continue
		}
		pub, err := kem.NewPublicKey(s.hellos[j].Identity.ImportKey)
		if err != nil {
			return nil, err
		}
		enc, snd, err := hpke.NewSender(pub, kdf, aead, []byte(dkgmsg.ShareInfo))
		if err != nil {
			return nil, err
		}
		ct, err := snd.Seal(dkgmsg.ShareAAD(s.id, s.self, x, ch), plain[j])
		if err != nil {
			return nil, err
		}
		sealed := append([]byte{byte(len(enc) >> 8), byte(len(enc))}, enc...)
		d.Shares = append(d.Shares, dkgmsg.SealedShares{Recipient: x, Sealed: append(sealed, ct...)})
	}
	copy(d.Signature[:], ed25519.Sign(s.signKey, d.SignedBytes()))
	return d, nil
}

// pending is the sealed record of a finished session that waits for every
// confirmation. It holds this runner's new shares. Once the session is
// committed or aborted the record shrinks to the session's state and, if
// committed, its keys (finished), and after FinishedKeep it is deleted
// (expired).
type pending struct {
	State      string    `json:"state"` // "pending", "committed" or "aborted"
	Session    []byte    `json:"session"`
	Transcript []byte    `json:"transcript"`
	ResultHash []byte    `json:"result_hash"`
	Result     []byte    `json:"result"`    // dkgmsg.Result encoding
	SignKeys   [][]byte  `json:"sign_keys"` // participants' Ed25519 keys, in order
	Shares     [][]byte  `json:"shares,omitempty"`
	PolicyHash []byte    `json:"policy_hash"`
	Updated    time.Time `json:"updated"`
	// Keys are a committed session's validator keys; records written before
	// they existed have the result instead.
	Keys []backend.Pubkey `json:"keys,omitempty"`
}

// FinishedKeep is how long the record of a committed or aborted session
// stays: a COMMIT repeated within it answers as the first one did.
const FinishedKeep = 24 * time.Hour

// finished is the short record of a session that ended in state.
func (p *pending) finished(state string, keys []backend.Pubkey, now time.Time) *pending {
	return &pending{State: state, Session: p.Session, Transcript: p.Transcript, ResultHash: p.ResultHash,
		PolicyHash: p.PolicyHash, Keys: keys, Updated: now}
}

// groupKeys are the validator keys of a committed session.
func (p *pending) groupKeys() ([]backend.Pubkey, error) {
	if len(p.Keys) > 0 || len(p.Result) == 0 {
		return p.Keys, nil
	}
	res, err := dkgmsg.DecodeResult(p.Result)
	if err != nil {
		return nil, err
	}
	return res.GroupKeys, nil
}

func pendingKey(id [32]byte) string { return "dkg/pending/" + hex.EncodeToString(id[:]) }
func pendingAAD(id [32]byte) []byte { return append([]byte("signer-dkg-pending-v1|"), id[:]...) }

func (m *Manager) putPending(id [32]byte, p *pending) error {
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer clear(plain)
	blob, err := m.env.Sealer.Seal(plain, pendingAAD(id))
	if err != nil {
		return err
	}
	return m.env.Store.Put(pendingKey(id), blob)
}

func (m *Manager) getPending(id [32]byte) (*pending, error) {
	blob, err := m.env.Store.Get(pendingKey(id))
	if err != nil {
		return nil, err
	}
	plain, err := m.env.Sealer.Unseal(blob, pendingAAD(id))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var p pending
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, err
	}
	if !bytes.Equal(p.Session, id[:]) {
		return nil, errors.New("record of another session")
	}
	return &p, nil
}

func (p *pending) wipe() {
	for _, s := range p.Shares {
		clear(s)
	}
	p.Shares = nil
}

// Finish checks every deal, computes the result and stores the new shares
// sealed as pending. The session ends either way.
func (m *Manager) Finish(_ context.Context, raw [][]byte) (*dkgmsg.Finished, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.live(true)
	if err != nil {
		return nil, err
	}
	n, t := m.n(), m.t()
	if len(raw) != n {
		return nil, m.refuse(backend.StatusBadRequest, "%d deals for %d participants", len(raw), n)
	}
	sum := make([][32]byte, s.count)
	defer func() {
		for i := range sum {
			clear(sum[i][:])
		}
	}()
	copy(sum, s.ownShare)
	// agg[v][k] collects coefficient k's commitments of every dealer.
	agg := make([][][]backend.Pubkey, s.count)
	for v := range agg {
		agg[v] = make([][]backend.Pubkey, t)
	}
	for j, b := range raw {
		x := uint16(j + 1)
		d, err := dkgmsg.DecodeDeal(b)
		if err != nil {
			return nil, m.refuse(backend.StatusBadRequest, "dealer %d: %v", x, err)
		}
		if err := m.checkDeal(s, x, b, d, sum); err != nil {
			return nil, m.refuse(backend.StatusBadKey, "dealer %d (%s): %v", x, m.policy.Participants[j].Name, err)
		}
		for v := range s.count {
			for k := range t {
				agg[v][k] = append(agg[v][k], d.Commitments[v][k])
			}
		}
	}
	res := &dkgmsg.Result{Session: s.id, Transcript: dkgmsg.TranscriptHash(s.id, raw), Self: s.self, Threshold: uint16(t),
		GroupKeys: make([]backend.Pubkey, s.count), PublicShares: make([][]backend.Pubkey, s.count)}
	ones := make([]*big.Int, n)
	for i := range ones {
		ones[i] = big.NewInt(1)
	}
	seen := map[backend.Pubkey]bool{}
	for v := range s.count {
		// Commitments of the summed polynomial: sum over dealers.
		total := make([]backend.Pubkey, t)
		for k := range t {
			if total[k], err = dkgmath.G1LinComb(agg[v][k], ones); err != nil {
				return nil, m.refuse(backend.StatusInternal, "commitments: %v", err)
			}
		}
		res.GroupKeys[v] = total[0]
		if !dkgmath.G1Valid(total[0]) || seen[total[0]] {
			return nil, m.refuse(backend.StatusBadKey, "validator %d: key is the identity or repeats", v)
		}
		seen[total[0]] = true
		res.PublicShares[v] = make([]backend.Pubkey, n)
		shareSeen := map[backend.Pubkey]bool{}
		for i := range n {
			ps, err := dkgmath.FeldmanEval(total, uint64(i+1))
			if err != nil || !dkgmath.G1Valid(ps) || shareSeen[ps] {
				return nil, m.refuse(backend.StatusBadKey, "validator %d: public share %d is invalid or repeats", v, i+1)
			}
			shareSeen[ps] = true
			res.PublicShares[v][i] = ps
		}
		own, err := core.PubkeyOf(sum[v])
		if err != nil || own != res.PublicShares[v][s.self-1] {
			return nil, m.refuse(backend.StatusBadKey, "validator %d: own share does not match the commitments", v)
		}
	}
	c := &dkgmsg.Confirm{Session: s.id, Transcript: res.Transcript, ResultHash: res.Hash(), Signer: s.self}
	copy(c.Signature[:], ed25519.Sign(s.signKey, c.SignedBytes()))
	rb, err := res.Encode()
	if err != nil {
		return nil, m.refuse(backend.StatusInternal, "%v", err)
	}
	p := &pending{State: "pending", Session: s.id[:], Transcript: res.Transcript[:], ResultHash: c.ResultHash[:],
		Result: rb, PolicyHash: m.policyHash[:], Updated: m.env.Now().UTC()}
	for _, h := range s.hellos {
		p.SignKeys = append(p.SignKeys, append([]byte(nil), h.SignKey[:]...))
	}
	for v := range sum {
		p.Shares = append(p.Shares, append([]byte(nil), sum[v][:]...))
	}
	err = m.putPending(s.id, p)
	p.wipe()
	if err != nil {
		return nil, m.refuse(backend.StatusPlatform, "store pending result: %v", err)
	}
	m.env.Log.Info("dkg finished, waiting for every confirmation", "session", short(s.id), "self", s.self,
		"transcript", hex.EncodeToString(res.Transcript[:6]))
	m.end("finished")
	return &dkgmsg.Finished{Result: res, Confirm: c}, nil
}

// checkDeal checks dealer x's deal and adds the shares it holds for this
// runner to sum.
func (m *Manager) checkDeal(s *session, x uint16, raw []byte, d *dkgmsg.Deal, sum [][32]byte) error {
	t := m.t()
	if d.Session != s.id || d.Dealer != x || int(d.Threshold) != t || len(d.Commitments) != s.count {
		return errors.New("deal of another session, position, threshold or validator count")
	}
	if x == s.self {
		if sha256.Sum256(raw) != s.ownDeal {
			return errors.New("own deal came back changed")
		}
		return nil
	}
	if !ed25519.Verify(s.hellos[x-1].SignKey[:], d.SignedBytes(), d.Signature[:]) {
		return errors.New("signature does not verify under the dealer's session key")
	}
	for v := range d.Commitments {
		for k := range d.Commitments[v] {
			if !dkgmath.G1Valid(d.Commitments[v][k]) {
				return fmt.Errorf("validator %d: commitment %d is not a G1 point", v, k)
			}
		}
	}
	// One sealed entry per other participant, in ID order.
	if len(d.Shares) != m.n()-1 {
		return errors.New("wrong number of sealed shares")
	}
	var mine []byte
	next := uint16(1)
	for _, e := range d.Shares {
		if next == x {
			next++
		}
		if e.Recipient != next {
			return errors.New("sealed shares out of order")
		}
		if e.Recipient == s.self {
			mine = e.Sealed
		}
		next++
	}
	plain, err := open(s.hpkeKey, mine, dkgmsg.ShareAAD(s.id, x, s.self, d.CommitmentsHash()))
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain) != 32*s.count {
		return errors.New("sealed shares have the wrong length")
	}
	for v := range s.count {
		var share [32]byte
		copy(share[:], plain[32*v:])
		pk, err := core.PubkeyOf(share)
		want, ferr := dkgmath.FeldmanEval(d.Commitments[v], uint64(s.self))
		if err != nil || ferr != nil || pk != want {
			clear(share[:])
			return fmt.Errorf("validator %d: share does not match the commitments", v)
		}
		sum[v], err = dkgmath.ScalarAdd(sum[v], share)
		clear(share[:])
		if err != nil {
			return fmt.Errorf("validator %d: share sum: %v", v, err)
		}
	}
	return nil
}

func open(key hpke.PrivateKey, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 2 {
		return nil, errors.New("sealed shares too short")
	}
	n := int(sealed[0])<<8 | int(sealed[1])
	if len(sealed) < 2+n {
		return nil, errors.New("sealed shares too short")
	}
	r, err := hpke.NewRecipient(sealed[2:2+n], key, kdf, aead, []byte(dkgmsg.ShareInfo))
	if err != nil {
		return nil, fmt.Errorf("sealed shares: %w", err)
	}
	plain, err := r.Open(aad, sealed[2+n:])
	if err != nil {
		return nil, errors.New("sealed shares do not open (sealed to another key, or changed)")
	}
	return plain, nil
}

// Commit checks every participant's confirmation against the stored
// pending result and, if all match, stores and loads the new shares. A
// confirmation whose signature fails changes nothing. A validly signed one
// with another transcript or result means the participants disagree: the
// pending result is dropped for good.
//
// The shares and their key records go to the store as one change
// (platform.Apply): with the state copy all of them land or none, so a
// restart never finds a share without its key record or the reverse. A
// store that takes them one by one gets each key record before the
// shares, so a crash can leave records without shares (refused by setup
// signing, written again by the next COMMIT) but no share without a
// record. The session's record changes to committed after that, in a
// second write: a crash in between leaves the session pending, and the
// next COMMIT finds the shares stored and writes only the record.
func (m *Manager) Commit(_ context.Context, q *dkgmsg.CommitRequest) ([]backend.ValidatorKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.getPending(q.Session)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, backend.Refused(backend.StatusNotReady, "dkg: no finished session %s", short(q.Session))
	}
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "dkg: pending result: %v", err)
	}
	defer p.wipe()
	// The server picks this manager from the order hash around the
	// request, and the session names no order: a session of another order
	// is refused here, or its shares would load under this one (TKGRESULT-01).
	if !bytes.Equal(p.PolicyHash, m.policyHash[:]) {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "dkg: session %s was made under another order or policy", short(q.Session))
	}
	switch p.State {
	case "aborted":
		return nil, backend.Refused(backend.StatusBadRequest, "dkg: session %s was aborted", short(q.Session))
	case "committed":
		keys, err := p.groupKeys()
		if err != nil {
			return nil, backend.Refused(backend.StatusInternal, "dkg: stored result: %v", err)
		}
		return m.keysOf(keys), nil
	}
	res, err := dkgmsg.DecodeResult(p.Result)
	if err != nil {
		return nil, backend.Refused(backend.StatusInternal, "dkg: stored result: %v", err)
	}
	if len(q.Confirms) != len(p.SignKeys) {
		return nil, backend.Refused(backend.StatusBadRequest, "dkg: %d confirmations for %d participants", len(q.Confirms), len(p.SignKeys))
	}
	for i, c := range q.Confirms {
		if c.Signer != uint16(i+1) || c.Session != q.Session ||
			!ed25519.Verify(p.SignKeys[i], c.SignedBytes(), c.Signature[:]) {
			return nil, backend.Refused(backend.StatusBadKey, "dkg: confirmation %d does not verify", i+1)
		}
	}
	for i, c := range q.Confirms {
		if !bytes.Equal(c.Transcript[:], p.Transcript) || !bytes.Equal(c.ResultHash[:], p.ResultHash) {
			if err := m.putPending(q.Session, p.finished("aborted", nil, m.env.Now().UTC())); err != nil {
				return nil, backend.Refused(backend.StatusPlatform, "dkg: store abort: %v", err)
			}
			m.env.Log.Warn("dkg participants disagree, result dropped", "session", short(q.Session), "participant", i+1)
			return nil, backend.Refused(backend.StatusBadKey, "dkg: participant %d confirmed another transcript or result; result dropped", i+1)
		}
	}
	have := map[backend.Pubkey]backend.ValidatorKey{}
	for _, k := range m.env.Keys() {
		have[k.Pubkey] = k
	}
	ch := &platform.Change{}
	var add []NewShare
	defer func() {
		for _, a := range add {
			clear(a.Secret[:])
		}
	}()
	// The key origin of IDENTITY counts the new shares as generated, under
	// this order.
	var order []byte
	if m.policy.order {
		order = p.PolicyHash
	}
	for v, gk := range res.GroupKeys {
		if k, ok := have[gk]; ok {
			// Loaded by an earlier commit that stopped before its last
			// write. Its key record is written again only if it is missing:
			// setup signing may have changed it since.
			if k.SharePubkey != res.PublicShares[v][res.Self-1] {
				return nil, backend.Refused(backend.StatusDuplicate, "dkg: validator %d is loaded with another share", v)
			}
			if _, err := LoadKeyRecord(m.env.Sealer, m.env.Store, gk); !errors.Is(err, platform.ErrNotFound) {
				if err != nil {
					return nil, backend.Refused(backend.StatusPlatform, "dkg: key record: %v", err)
				}
				continue
			}
		} else {
			sec := new([32]byte)
			copy(sec[:], p.Shares[v])
			add = append(add, NewShare{Pubkey: gk, Secret: sec, Order: order})
		}
		blob, err := m.sealKeyRecord(m.keyRecord(gk, res, v, p.PolicyHash))
		if err != nil {
			return nil, backend.Refused(backend.StatusPlatform, "dkg: key record: %v", err)
		}
		ch.Put(keyRecordKey(gk), blob)
	}
	if len(ch.Ops()) > 0 {
		_, err := m.env.AddShares(add, func(sealed map[string][]byte) error {
			names := make([]string, 0, len(sealed))
			for k := range sealed {
				names = append(names, k)
			}
			slices.Sort(names)
			for _, k := range names {
				ch.Put(k, sealed[k])
			}
			return platform.Apply(m.env.Store, ch)
		})
		if err != nil {
			return nil, err
		}
	}
	now := m.env.Now().UTC()
	if err := m.putPending(q.Session, p.finished("committed", res.GroupKeys, now)); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "dkg: store commit: %v", err)
	}
	m.env.Log.Info("dkg committed", "session", short(q.Session), "self", res.Self, "validators", len(res.GroupKeys))
	m.dropExpired(q.Session, now)
	return m.keysOf(res.GroupKeys), nil
}

// dropExpired deletes the records of sessions that were committed or
// aborted more than FinishedKeep ago, on a store that can delete. A pending
// record stays until its COMMIT, however old: it holds this runner's shares
// of a session the other runners may have committed, and the coordinator
// can send that COMMIT again (dkg-result.json keeps the confirmations).
func (m *Manager) dropExpired(current [32]byte, now time.Time) {
	if _, ok := m.env.Store.(platform.Deleter); !ok {
		return
	}
	names, err := m.env.Store.List("dkg/pending/")
	if err != nil {
		m.env.Log.Warn("dkg: listing session records failed", "err", err)
		return
	}
	ch := &platform.Change{}
	for _, name := range names {
		var id [32]byte
		b, err := hex.DecodeString(strings.TrimPrefix(name, "dkg/pending/"))
		if err != nil || len(b) != len(id) {
			continue
		}
		copy(id[:], b)
		if id == current {
			continue
		}
		p, err := m.getPending(id)
		if err != nil {
			continue
		}
		p.wipe()
		if (p.State == "committed" || p.State == "aborted") && now.Sub(p.Updated) > FinishedKeep {
			ch.Delete(name)
		}
	}
	if len(ch.Ops()) == 0 {
		return
	}
	if err := platform.Apply(m.env.Store, ch); err != nil {
		m.env.Log.Warn("dkg: deleting finished session records failed; the next commit tries again", "records", len(ch.Ops()), "err", err)
		return
	}
	m.env.Log.Info("dkg: finished session records deleted", "records", len(ch.Ops()))
}

func (m *Manager) keysOf(keys []backend.Pubkey) []backend.ValidatorKey {
	want := map[backend.Pubkey]bool{}
	for _, gk := range keys {
		want[gk] = true
	}
	var out []backend.ValidatorKey
	for _, k := range m.env.Keys() {
		if want[k.Pubkey] {
			out = append(out, k)
		}
	}
	return out
}

// KeyRecord is the sealed public record of a generated key: what the lock
// check (milestone 3) compares the lock with.
type KeyRecord struct {
	Pubkey     backend.Pubkey `json:"pubkey"`
	Session    []byte         `json:"session"`
	Transcript []byte         `json:"transcript"`
	PolicyHash []byte         `json:"policy_hash"`
	// Order and Path label a key made under a DKG order: the order's hash
	// (also in PolicyHash) and its path, dirk or charon. Empty on the
	// policy file path.
	Order        []byte           `json:"order,omitempty"`
	Path         string           `json:"path,omitempty"`
	Threshold    uint16           `json:"threshold"`
	Self         uint16           `json:"self"`
	PublicShares []backend.Pubkey `json:"public_shares"`
	// Setup state (setup.go). The host can roll the record back, so this
	// limits setup signing in normal operation; it is not a rollback-proof
	// guarantee.
	DepositsSigned []uint64 `json:"deposits_signed,omitempty"`
	// Credentials are the withdrawal credentials of the key's first
	// deposit or lock signature (TKGSETUP-01). Setup signing for the key
	// then refuses other credentials, also after a locked update changes
	// the ones in force. Empty until then.
	Credentials        []byte `json:"withdrawal_credentials,omitempty"`
	RegistrationSigned bool   `json:"registration_signed,omitempty"`
	LockSigned         bool   `json:"lock_signed,omitempty"`
	SetupClosed        bool   `json:"setup_closed,omitempty"`
}

func keyRecordKey(pk backend.Pubkey) string { return "dkg/keys/" + hex.EncodeToString(pk[:]) }
func keyRecordAAD(pk backend.Pubkey) []byte { return append([]byte("signer-dkg-key-v1|"), pk[:]...) }

// keyRecord is the record of a commit's validator v. A key made under a
// DKG order carries the order's hash and path.
func (m *Manager) keyRecord(pk backend.Pubkey, res *dkgmsg.Result, v int, policyHash []byte) *KeyRecord {
	rec := &KeyRecord{Pubkey: pk, Session: res.Session[:], Transcript: res.Transcript[:], PolicyHash: policyHash,
		Threshold: res.Threshold, Self: res.Self, PublicShares: res.PublicShares[v]}
	if m.policy.order {
		rec.Order, rec.Path = policyHash, m.policy.path
	}
	return rec
}

func (m *Manager) sealKeyRecord(rec *KeyRecord) ([]byte, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return m.env.Sealer.Seal(plain, keyRecordAAD(rec.Pubkey))
}

func (m *Manager) storeKeyRecord(rec *KeyRecord) error {
	blob, err := m.sealKeyRecord(rec)
	if err != nil {
		return err
	}
	return m.env.Store.Put(keyRecordKey(rec.Pubkey), blob)
}

// LoadKeyRecord reads the sealed record of a generated key.
func LoadKeyRecord(sealer platform.Sealer, store platform.Store, pk backend.Pubkey) (*KeyRecord, error) {
	blob, err := store.Get(keyRecordKey(pk))
	if err != nil {
		return nil, err
	}
	plain, err := sealer.Unseal(blob, keyRecordAAD(pk))
	if err != nil {
		return nil, err
	}
	var rec KeyRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		return nil, err
	}
	if rec.Pubkey != pk {
		return nil, errors.New("keygen: record of another key")
	}
	return &rec, nil
}
