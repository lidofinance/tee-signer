package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// keysMaxAge is how old the key list may be when a request reads it: GET
// publicKeys and a sign request for a key the list lacks load it from the
// signers again first.
const keysMaxAge = 30 * time.Second

// SignerConfig is one TEE signer.
type SignerConfig struct {
	// Name names the signer in the log.
	Name string
	// Connection is its address, the client certificate and what its
	// attestation must show.
	Connection runnerclient.Connection
}

// Config says how to reach the signers.
type Config struct {
	Signers []SignerConfig
	// Connections is the number of connections to each signer (1 to 16).
	Connections int
	// Timeout bounds each PUBLIC_KEYS call, and a SIGN whose request has
	// no deadline.
	Timeout time.Duration
	// DialTimeout bounds each new connection, from TCP to the end of the
	// attestation check.
	DialTimeout time.Duration
	// MaxShareIndex is the highest share index deriveGroup tries (0: the
	// number of signers).
	MaxShareIndex int
	// Certs, if set, is the client certificate in force. The connections
	// move to each new one, and requests fail once it expired. Without
	// it the connections present the files of each Connection, read once.
	Certs *certreload.Watcher
}

// Signers signs through the TEE signers. A request goes to every signer
// that holds a share of the key, at once. Each partial signature must
// verify under the share key that signer listed, over the signing root the
// gateway computed; the first threshold that do are combined with their
// share indices, and the result must verify under the validator key.
type Signers struct {
	nodes    []runner
	names    []string
	maxIndex int
	timeout  time.Duration
	log      *slog.Logger
	keys     *keyList
	// certs is the client certificate in force, nil without reload.
	certs certSource

	mu sync.Mutex
	// listed is each signer's last PUBLIC_KEYS answer, nil before the
	// first one. A signer that does not answer keeps its last answer, so
	// its shares stay in the groups and the others still sign.
	listed [][]proto.ValidatorKey
	// derived caches deriveGroup by validator key and share keys.
	derived map[string]derivedGroup
}

type derivedGroup struct {
	g   group
	err error
}

var _ Signer = (*Signers)(nil)

// New makes the connections to the signers. It does not connect; Refresh
// does.
func New(cfg Config, log *slog.Logger) (*Signers, error) {
	if len(cfg.Signers) == 0 {
		return nil, errors.New("no signer")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 30 * time.Second
	}
	pc := poolConfig{size: max(cfg.Connections, 1), warm: dialTimeout + timeout, log: log}
	if cfg.Certs != nil {
		pc.certs = cfg.Certs
	}
	var nodes []runner
	var names []string
	closeAll := func() {
		for _, n := range nodes {
			_ = n.Close()
		}
	}
	for _, sc := range cfg.Signers {
		name := sc.Name
		verified := func(id *proto.Identity) {
			log.Info("signer attested", append([]any{"signer", name, "address", sc.Connection.Address},
				runnerclient.SetupLog(&id.State, time.Now())...)...)
		}
		n, err := newNode(sc.Connection, pc, runnerclient.WithTimeout(dialTimeout), runnerclient.WithVerified(verified))
		if err != nil {
			closeAll()

			return nil, fmt.Errorf("signer %s: %w", name, err)
		}
		nodes = append(nodes, n)
		names = append(names, name)
	}

	s := newSigners(names, nodes, cfg.MaxShareIndex, timeout, log)
	s.certs = pc.certs

	return s, nil
}

func newSigners(names []string, nodes []runner, maxIndex int, timeout time.Duration, log *slog.Logger) *Signers {
	if maxIndex == 0 {
		maxIndex = len(nodes)
	}
	s := &Signers{nodes: nodes, names: names, maxIndex: min(maxIndex, maxShareIndex), timeout: timeout, log: log,
		listed: make([][]proto.ValidatorKey, len(nodes)), derived: map[string]derivedGroup{}}
	s.keys = newKeyList(s.loadKeys, keysMaxAge, log)

	return s
}

// Refresh asks every signer for its keys now and returns the number of
// validator keys the gateway can sign for.
func (s *Signers) Refresh(ctx context.Context) (int, error) { return s.keys.reload(ctx) }

// PublicKeys implements Signer.
func (s *Signers) PublicKeys(ctx context.Context) []phase0.BLSPubKey { return s.keys.list(ctx) }

// HasKey implements Signer.
func (s *Signers) HasKey(ctx context.Context, pubkey phase0.BLSPubKey) bool {
	_, ok := s.keys.get(ctx, pubkey)

	return ok
}

// Close closes every connection.
func (s *Signers) Close() error {
	var errs []error
	for _, n := range s.nodes {
		errs = append(errs, n.Close())
	}

	return errors.Join(errs...)
}

// loadKeys asks every signer for PUBLIC_KEYS at once and builds the
// groups: for each validator key the shares the signers hold, their
// indices and the threshold (deriveGroup). A key whose shares do not fit
// is left out and logged once.
func (s *Signers) loadKeys(ctx context.Context) (map[phase0.BLSPubKey]group, error) {
	type answer struct {
		keys []proto.ValidatorKey
		err  error
	}
	answers := make([]answer, len(s.nodes))
	var wg sync.WaitGroup
	for i, n := range s.nodes {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			keys, err := n.PublicKeys(cctx)
			answers[i] = answer{keys, err}
		})
	}
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for i, a := range answers {
		if a.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.names[i], a.err))
			s.log.Warn("signer key list failed", "signer", s.names[i], "err", a.err.Error())

			continue
		}
		s.listed[i] = a.keys
	}
	shares := map[phase0.BLSPubKey][]share{}
	answered := false
	for i, keys := range s.listed {
		answered = answered || keys != nil
		for _, k := range keys {
			pk := phase0.BLSPubKey(k.Pubkey)
			shares[pk] = append(shares[pk], share{node: i, pub: phase0.BLSPubKey(k.SharePubkey)})
		}
	}
	if !answered {
		return nil, fmt.Errorf("no signer answered: %w", errors.Join(errs...))
	}
	groups := make(map[phase0.BLSPubKey]group, len(shares))
	derived := make(map[string]derivedGroup, len(shares))
	for pk, sh := range shares {
		id := groupID(pk, sh)
		d, ok := s.derived[id]
		if !ok {
			d.g, d.err = deriveGroup(pk, sh, s.maxIndex)
			if d.err != nil {
				s.log.Warn("key refused", "pubkey", fmt.Sprintf("%#x", pk), "shares", len(sh), "err", d.err.Error())
			}
		}
		derived[id] = d
		if d.err == nil {
			groups[pk] = d.g
		}
	}
	s.derived = derived
	if len(groups) == 0 {
		return nil, errors.New("the signers hold no key the gateway can sign for")
	}

	return groups, nil
}

func groupID(pk phase0.BLSPubKey, shares []share) string {
	var b strings.Builder
	b.Write(pk[:])
	for _, s := range shares {
		fmt.Fprintf(&b, "|%d:", s.node)
		b.Write(s.pub[:])
	}

	return b.String()
}

// Sign implements Signer.
func (s *Signers) Sign(ctx context.Context, pubkey phase0.BLSPubKey, job *signing.Job) (phase0.BLSSignature, error) {
	if s.certs != nil {
		if err := s.certs.Usable(); err != nil {
			return phase0.BLSSignature{}, err
		}
	}
	g, ok := s.keys.get(ctx, pubkey)
	if !ok {
		return phase0.BLSSignature{}, ErrUnknownKey
	}
	msg, err := Message(job)
	if err != nil {
		return phase0.BLSSignature{}, err
	}
	req := proto.SignRequest{Pubkey: proto.Pubkey(pubkey), Message: msg, Domain: proto.Root(job.Domain)}

	return s.fanOut(ctx, pubkey, g, req, job.SigningRoot)
}

// partial is one signer's answer.
type partial struct {
	share share
	sig   phase0.BLSSignature
	err   error
}

// fanOut sends req to every signer of g at once and combines the first
// g.threshold partial signatures that verify over root. It returns as soon
// as they are in, or as soon as the answers so far leave too few to reach
// the threshold. The calls to the other signers go on until the deadline
// of ctx: those signers still see the request, and their slashing
// protection with it.
func (s *Signers) fanOut(ctx context.Context, pubkey phase0.BLSPubKey, g group, req proto.SignRequest, root phase0.Root) (phase0.BLSSignature, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.timeout)
	}
	callCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	results := make(chan partial, len(g.shares))
	var wg sync.WaitGroup
	for _, sh := range g.shares {
		wg.Go(func() {
			sig, err := s.nodes[sh.node].Sign(callCtx, req)
			p := partial{share: sh, sig: phase0.BLSSignature(sig), err: err}
			if err == nil {
				if verr := VerifyBLS(sh.pub, root, p.sig); verr != nil {
					p.err = fmt.Errorf("partial signature does not verify under the share key: %w", verr)
					s.log.Warn("bad partial signature", "signer", s.names[sh.node], "pubkey", fmt.Sprintf("%#x", pubkey),
						"kind", req.Message.Kind().String(), "signing_root", fmt.Sprintf("%#x", root))
				}
			}
			results <- p
		})
	}
	go func() {
		wg.Wait()
		cancel()
	}()

	var good []partial
	var denied, failed []string
	for got := 0; got < len(g.shares); {
		select {
		case p := <-results:
			got++
			switch {
			case p.err == nil:
				good = append(good, p)
			case isDenial(p.err):
				denied = append(denied, s.names[p.share.node]+": "+p.err.Error())
			default:
				failed = append(failed, s.names[p.share.node]+": "+p.err.Error())
			}
			if len(good) == g.threshold {
				return s.combineVerified(pubkey, root, good)
			}
			if len(good)+len(g.shares)-got < g.threshold {
				return phase0.BLSSignature{}, notEnough(g, len(good), denied, failed)
			}
		case <-ctx.Done():
			return phase0.BLSSignature{}, fmt.Errorf("%d of %d partial signatures (threshold %d) before the deadline: %w",
				len(good), len(g.shares), g.threshold, ctx.Err())
		}
	}

	return phase0.BLSSignature{}, notEnough(g, len(good), denied, failed)
}

func (s *Signers) combineVerified(pubkey phase0.BLSPubKey, root phase0.Root, parts []partial) (phase0.BLSSignature, error) {
	indices := make([]uint64, len(parts))
	sigs := make([]phase0.BLSSignature, len(parts))
	for i, p := range parts {
		indices[i], sigs[i] = p.share.index, p.sig
	}
	sig, err := combine(indices, sigs)
	if err != nil {
		return phase0.BLSSignature{}, fmt.Errorf("combine: %w", err)
	}
	if err := VerifyBLS(pubkey, root, sig); err != nil {
		return phase0.BLSSignature{}, fmt.Errorf("combined signature: %w", err)
	}

	return sig, nil
}

// notEnough is the error when too few partial signatures came: a
// DeniedError (HTTP 412) when a signer refused, a plain error (HTTP 500)
// when they failed, timed out or sent a partial that does not verify.
func notEnough(g group, good int, denied, failed []string) error {
	detail := fmt.Sprintf("not enough signatures: %d signed, %d denied, %d failed of %d signers, threshold %d",
		good, len(denied), len(failed), len(g.shares), g.threshold)
	if why := strings.Join(append(append([]string(nil), denied...), failed...), "; "); why != "" {
		detail += ": " + why
	}
	if len(denied) > 0 {
		return &DeniedError{Detail: detail}
	}

	return errors.New(detail)
}

// isDenial reports whether a signer refused the request on its rules:
// slashing protection, policy, domain, or a request it would not take.
// Anything else (not ready, a platform failure, an unknown key, the
// connection) is a failure.
func isDenial(err error) bool {
	var r *proto.RefusedError
	if !errors.As(err, &r) {
		return false
	}
	switch c := r.Code; {
	case c.IsSlashing(), c.IsPolicy(), c == proto.StatusPolicyBuilderAuth:
		return true
	case c == proto.StatusArg, c == proto.StatusDecode, c == proto.StatusBadRequest, c == proto.StatusUnsupported:
		return true
	}

	return false
}
