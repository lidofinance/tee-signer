package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
	"github.com/lidofinance/tee-signer/gateway/internal/metrics"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// keysMaxAge is how old the key list may be when a request reads it: GET
// publicKeys and a sign request for a key the list lacks load it from the
// signers again first; a sign request for a key it has starts that load in
// the background.
const keysMaxAge = 30 * time.Second

// modeMaxRefreshes is how many key refreshes (keysMaxAge each) a signer's
// signing_mode stays good for a whole key without a new HEALTH answer.
const modeMaxRefreshes = 3

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
	// Metrics, if set, receives the metrics of the signers, the keys and
	// the signing.
	Metrics *metrics.Gateway
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
	m     *metrics.Gateway
	// warns limits the lines about a signer that did not sign.
	warns *warnLimit

	mu sync.Mutex
	// listed is each signer's last PUBLIC_KEYS answer, nil before the
	// first one. A signer that does not answer keeps its last answer, so
	// its shares stay in the groups and the others still sign.
	listed [][]proto.ValidatorKey
	// modes is the signing_mode each signer's HEALTH last reported, ""
	// before the first. Only a signer that lists a whole key is asked.
	modes []string
	// modesAt is when each signer's HEALTH last gave its mode. A failed
	// HEALTH keeps the mode but not the time, so the mode ages out.
	modesAt []time.Time
	// modeMaxAge is how old a mode may be for a whole key:
	// modeMaxRefreshes key refreshes.
	modeMaxAge time.Duration
	// newerLevel is the protocol level above proto.ProtocolLevel each
	// signer's HEALTH last reported and the gateway warned about, 0 before
	// one. A level is warned about once per signer.
	newerLevel []int
	// derived caches deriveGroup by validator key and share keys. Only
	// the load that holds the key-load token writes it.
	derived map[string]derivedGroup
	// deferred is the keys, by groupID, that fit no guess at the last load
	// and wait for the full search in a load of their own. Only the load
	// that holds the key-load token writes it.
	deferred map[string]bool
	// followAt is when the last follow-up load for deferred keys started,
	// and followPending is set while one is due: at most one runs per
	// keysMaxAge, and a follow-up load defers no key.
	followAt      time.Time
	followPending bool
	// listedTwice is the signers, by validator key, that list the key more
	// than once, as last logged.
	listedTwice map[phase0.BLSPubKey]string
	// ctx ends at Close; the load for deferred keys runs under it.
	ctx  context.Context
	stop context.CancelFunc

	// guesses are the thresholds and share indices of the groups derived
	// so far, for deriveGroup to try first.
	guesses guessList
	// derive is deriveGroup; tests replace it.
	derive func(pk phase0.BLSPubKey, shares []share, maxIndex int, guesses ...guess) (group, error)
}

type derivedGroup struct {
	g   group
	err error
	// refused is the last checkWhole error, logged when it changes.
	refused string
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
	m := cfg.Metrics
	if m == nil {
		m = metrics.New()
	}
	pc := poolConfig{size: max(cfg.Connections, 1), warm: dialTimeout + timeout, log: log, m: m}
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
				verify.SetupLog(&id.State, time.Now())...)...)
		}
		npc := pc
		npc.name = name
		n, err := newNode(sc.Connection, npc, runnerclient.WithTimeout(dialTimeout), runnerclient.WithVerified(verified))
		if err != nil {
			closeAll()

			return nil, fmt.Errorf("signer %s: %w", name, err)
		}
		nodes = append(nodes, n)
		names = append(names, name)
	}

	s := newSigners(names, nodes, cfg.MaxShareIndex, timeout, log)
	s.certs = pc.certs
	s.m = m

	return s, nil
}

func newSigners(names []string, nodes []runner, maxIndex int, timeout time.Duration, log *slog.Logger) *Signers {
	if maxIndex == 0 {
		maxIndex = len(nodes)
	}
	s := &Signers{nodes: nodes, names: names, maxIndex: min(maxIndex, maxShareIndex), timeout: timeout, log: log,
		listed: make([][]proto.ValidatorKey, len(nodes)), modes: make([]string, len(nodes)), modesAt: make([]time.Time, len(nodes)),
		newerLevel: make([]int, len(nodes)), derived: map[string]derivedGroup{}, m: metrics.New(),
		warns: newWarnLimit(warnEvery), derive: deriveGroup, deferred: map[string]bool{},
		listedTwice: map[phase0.BLSPubKey]string{}}
	s.ctx, s.stop = context.WithCancel(context.Background())
	s.keys = newKeyList(s.loadKeys, keysMaxAge, log)
	s.modeMaxAge = modeMaxRefreshes * s.keys.maxAge
	s.keys.check = s.wholeOK

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

// DVShare implements Signer. It reads the key list as HasKey left it: a
// dv_share key is a whole key (threshold 1) of a signer whose last HEALTH
// said signing_mode = dv_share.
func (s *Signers) DVShare(_ context.Context, pubkey phase0.BLSPubKey) bool {
	g, ok := s.keys.lookup(pubkey)
	if !ok || g.threshold != 1 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.modes[g.shares[0].node] == setupwire.SigningModeDVShare.String()
}

// Close closes every connection.
func (s *Signers) Close() error {
	s.stop()
	var errs []error
	for _, n := range s.nodes {
		errs = append(errs, n.Close())
	}

	return errors.Join(errs...)
}

// loadKeys asks every signer for PUBLIC_KEYS at once and builds the
// groups: for each validator key the shares the signers hold, their
// indices and the threshold (deriveGroup). A key whose shares do not fit
// is left out and logged once. Every signer that answered is also asked
// for HEALTH: its protocol level, and for a signer that lists a whole key
// its signing_mode (a whole key is served only from a signer that reported
// signing_mode = single or dv_share within modeMaxAge, checkWhole).
//
// The groups of keys not seen before are derived without s.mu, so whole
// keys sign meanwhile, on one goroutine per CPU (deriveAll). A key that
// fits no guess of the groups found so far waits: the load serves the
// others and starts a follow-up load, which runs the full search for every
// key that fits no guess. A follow-up starts at most once per keysMaxAge,
// later if the last one was sooner, and starts no other: a signer that
// lists a new share key at every answer keeps its key waiting, but not
// the loads looping. A load whose ctx ends first fails and keeps the
// groups derived by then for the next.
//
// A key that one signer lists more than once is refused: that signer
// would count as several.
func (s *Signers) loadKeys(ctx context.Context) (map[phase0.BLSPubKey]group, error) {
	followUp := ctx.Value(followUpKey{}) != nil
	type answer struct {
		keys    []proto.ValidatorKey
		err     error
		asked   bool // HEALTH was asked: the signer answered PUBLIC_KEYS
		whole   bool // the signer lists a whole key: its signing_mode counts
		mode    string
		level   int // HEALTH's EffectiveProtocol
		modeErr error
	}
	answers := make([]answer, len(s.nodes))
	var wg sync.WaitGroup
	for i, n := range s.nodes {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, s.timeout)
			keys, err := n.PublicKeys(cctx)
			cancel()
			answers[i] = answer{keys: keys, err: capDetail(err)}
			if err != nil {
				return
			}
			// HEALTH of every signer: its protocol level, and for a signer
			// that lists a whole key its signing mode (rv-93s.1: a threshold
			// cluster was never asked, so a newer level went unseen).
			answers[i].asked, answers[i].whole = true, listsWholeKey(keys)
			cctx, cancel = context.WithTimeout(ctx, s.timeout)
			defer cancel()
			h, err := n.Health(cctx)
			switch {
			case err != nil:
				answers[i].modeErr = capDetail(err)
			case h == nil:
				answers[i].modeErr = errors.New("no HEALTH answer")
			default:
				answers[i].mode, answers[i].level = h.SigningMode, h.EffectiveProtocol()
			}
		})
	}
	wg.Wait()

	s.mu.Lock()
	if followUp {
		s.followPending, s.followAt = false, time.Now()
	}
	now := s.keys.now()
	var errs []error
	for i, a := range answers {
		if a.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.names[i], a.err))
			s.log.Warn("signer key list failed", "signer", s.names[i], "err", a.err.Error())

			continue
		}
		s.listed[i] = a.keys
		s.m.SignerKeysRefreshed.Set(float64(time.Now().UnixMilli())/1000, s.names[i])
		switch {
		case a.modeErr != nil:
			// Keep the last mode and its time: a whole key it served stays
			// served until the mode is modeMaxAge old.
			s.log.Warn("signer health failed", "signer", s.names[i], "err", a.modeErr.Error())
		case a.asked:
			if a.whole {
				s.modes[i], s.modesAt[i] = a.mode, now
			}
			// A runner newer than this gateway may answer in ways it reads
			// wrongly (signer-protocol/docs/protocol.md, "Protocol level").
			if a.level > proto.ProtocolLevel && a.level != s.newerLevel[i] {
				s.newerLevel[i] = a.level
				s.log.Warn("signer reports a newer protocol level; update the gateway", "signer", s.names[i],
					"protocol", a.level, "gateway_protocol", proto.ProtocolLevel)
			}
		}
	}
	shares := map[phase0.BLSPubKey][]share{}
	twice := map[phase0.BLSPubKey][]string{}
	answered := false
	for i, keys := range s.listed {
		answered = answered || keys != nil
		for _, k := range keys {
			pk := phase0.BLSPubKey(k.Pubkey)
			if sh := shares[pk]; len(sh) > 0 && sh[len(sh)-1].node == i {
				if names := twice[pk]; len(names) == 0 || names[len(names)-1] != s.names[i] {
					twice[pk] = append(names, s.names[i])
				}

				continue
			}
			shares[pk] = append(shares[pk], share{node: i, pub: phase0.BLSPubKey(k.SharePubkey)})
		}
	}
	listedTwice := make(map[phase0.BLSPubKey]string, len(twice))
	for pk, names := range twice {
		delete(shares, pk)
		listedTwice[pk] = strings.Join(names, ",")
		if s.listedTwice[pk] != listedTwice[pk] {
			s.log.Warn("key refused", "pubkey", fmt.Sprintf("%#x", pk), "signer", listedTwice[pk],
				"err", "the signer lists the key more than once")
		}
	}
	s.listedTwice = listedTwice
	if !answered {
		s.mu.Unlock()

		return nil, fmt.Errorf("no signer answered: %w", errors.Join(errs...))
	}
	var todo []deriveJob
	for pk, sh := range shares {
		id := groupID(pk, sh)
		if _, ok := s.derived[id]; !ok {
			todo = append(todo, deriveJob{pk: pk, shares: sh, id: id})
		}
	}
	s.mu.Unlock()

	fresh, later, err := s.deriveAll(ctx, todo, followUp)

	s.mu.Lock()
	defer s.mu.Unlock()
	now = s.keys.now()
	waiting := make(map[string]bool, len(later))
	for _, j := range later {
		waiting[j.id] = true
	}
	for _, j := range todo {
		if d, ok := fresh[j.id]; ok && d.err != nil {
			s.log.Warn("key refused", "pubkey", fmt.Sprintf("%#x", j.pk), "shares", len(j.shares), "err", d.err.Error())
		}
	}
	if err != nil {
		maps.Copy(s.derived, fresh)
		maps.Copy(s.deferred, waiting)

		return nil, fmt.Errorf("share groups of %d of %d new keys derived: %w", len(fresh), len(todo), err)
	}
	groups := make(map[phase0.BLSPubKey]group, len(shares))
	derived := make(map[string]derivedGroup, len(shares))
	for pk, sh := range shares {
		id := groupID(pk, sh)
		d, ok := s.derived[id]
		if !ok {
			if d, ok = fresh[id]; !ok {
				continue // deferred
			}
		}
		if d.err == nil {
			// A mode ages without a new answer, so checkWhole runs at every
			// load, not from the cache.
			refused := ""
			if err := s.checkWhole(d.g, now); err != nil {
				refused = err.Error()
			} else {
				groups[pk] = d.g
			}
			if refused != "" && refused != d.refused {
				s.log.Warn("key refused", "pubkey", fmt.Sprintf("%#x", pk), "shares", len(sh), "err", refused)
			}
			d.refused = refused
		}
		derived[id] = d
	}
	s.derived = derived
	s.deferred = waiting
	if len(later) > 0 && !s.followPending {
		s.log.Info("keys that fit no guess wait for the next load", "keys", len(later))
		s.followPending = true
		go s.followUp(time.Until(s.followAt.Add(s.keys.maxAge)))
	}
	if len(groups) == 0 {
		return nil, errors.New("the signers hold no key the gateway can sign for")
	}
	s.m.Keys.Set(float64(len(groups)))

	return groups, nil
}

// followUpKey marks the ctx of a follow-up load.
type followUpKey struct{}

// followUp runs a follow-up load after wait, unless Close comes first.
func (s *Signers) followUp(wait time.Duration) {
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-s.ctx.Done():
			return
		}
	}
	if _, err := s.keys.reload(context.WithValue(s.ctx, followUpKey{}, true)); err != nil && s.ctx.Err() == nil {
		s.log.Warn("key load failed", "err", err.Error())
	}
}

// deriveJob is a key whose group loadKeys derives.
type deriveJob struct {
	pk     phase0.BLSPubKey
	shares []share
	id     string // groupID
}

// deriveAll derives the groups of the jobs on one goroutine per CPU, by
// groupID. Each tries the thresholds and indices of the groups derived so
// far first. A job that fits none of them runs the full search when there
// is no guess for its signers yet, it waited at the last load
// (s.deferred), or searchAll is set; otherwise deriveAll returns it in
// later. Once ctx ends it starts no more and returns the groups derived
// by then with the error of ctx.
func (s *Signers) deriveAll(ctx context.Context, todo []deriveJob, searchAll bool) (out map[string]derivedGroup, later []deriveJob, err error) {
	out = make(map[string]derivedGroup, len(todo))
	var mu sync.Mutex
	jobs := make(chan deriveJob)
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), len(todo)) {
		wg.Go(func() {
			for j := range jobs {
				var d derivedGroup
				guesses := s.guesses.of(j.shares)
				g, done, gerr := guessGroup(j.pk, j.shares, s.maxIndex, guesses)
				switch {
				case done:
					d.g, d.err = g, gerr
				case len(guesses) > 0 && !s.deferred[j.id] && !searchAll:
					mu.Lock()
					later = append(later, j)
					mu.Unlock()

					continue
				default:
					d.g, d.err = s.derive(j.pk, j.shares, s.maxIndex, guesses...)
				}
				if d.err == nil {
					s.guesses.add(len(s.nodes), d.g)
				}
				mu.Lock()
				out[j.id] = d
				mu.Unlock()
			}
		})
	}
feed:
	for _, j := range todo {
		if err = ctx.Err(); err != nil {
			break
		}
		select {
		case jobs <- j:
		case <-ctx.Done():
			err = ctx.Err()

			break feed
		}
	}
	close(jobs)
	wg.Wait()

	return out, later, err
}

// maxGuesses bounds the guesses kept.
const maxGuesses = 8

// guessList is the threshold and the index of each signer of the groups
// derived so far, the most recent first. The signers of a threshold split
// usually hold the same index for every key, so deriveGroup tries these
// first.
type guessList struct {
	mu   sync.Mutex
	list []nodeGuess
}

// nodeGuess is a threshold and the share index of each signer, 0 for a
// signer without a share.
type nodeGuess struct {
	threshold int
	index     []uint64
}

// add puts the threshold and the indices of g first.
func (l *guessList) add(nodes int, g group) {
	if g.threshold < 2 {
		return
	}
	n := nodeGuess{threshold: g.threshold, index: make([]uint64, nodes)}
	for _, sh := range g.shares {
		n.index[sh.node] = sh.index
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = slices.DeleteFunc(l.list, func(o nodeGuess) bool {
		return o.threshold == n.threshold && slices.Equal(o.index, n.index)
	})
	l.list = slices.Insert(l.list, 0, n)
	l.list = l.list[:min(len(l.list), maxGuesses)]
}

// of returns the guesses that give an index to every share.
func (l *guessList) of(shares []share) []guess {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []guess
next:
	for _, n := range l.list {
		idx := make([]uint64, len(shares))
		for i, sh := range shares {
			if idx[i] = n.index[sh.node]; idx[i] == 0 {
				continue next
			}
		}
		out = append(out, guess{threshold: n.threshold, index: idx})
	}

	return out
}

// groupID is the key of the deriveGroup cache: the validator key, and the
// signer and the share key of each share.
func groupID(pk phase0.BLSPubKey, shares []share) string {
	var b strings.Builder
	b.Write(pk[:])
	for _, s := range shares {
		fmt.Fprintf(&b, "|%d:", s.node)
		b.Write(s.pub[:])
	}

	return b.String()
}

// listsWholeKey reports whether a PUBLIC_KEYS answer has a share key equal
// to its validator key.
func listsWholeKey(keys []proto.ValidatorKey) bool {
	for _, k := range keys {
		if k.SharePubkey == k.Pubkey {
			return true
		}
	}

	return false
}

// checkWhole refuses a whole key (threshold 1) unless its signer's HEALTH
// said signing_mode = single or dv_share at most modeMaxAge before now; s.mu
// is held.
// Share keys equal to the validator key are not enough: the runner of a
// threshold setup refuses a whole key at import, so one that lists it is
// not following its setup, and an old runner or one without a setup does
// not say. The age limit stops the mode of a HEALTH that no longer answers
// from passing the key for good. HEALTH is not attested, so this catches a
// wrong configuration, not a runner that lies. deriveGroup has already
// refused a whole key on more than one signer.
func (s *Signers) checkWhole(g group, now time.Time) error {
	if g.threshold != 1 {
		return nil
	}
	n := g.shares[0].node
	if m := s.modes[n]; !wholeKeyMode(m) {
		return fmt.Errorf("the whole key is on signer %s, whose HEALTH says signing_mode = %q; a whole key needs signing_mode = single or dv_share", s.names[n], m)
	}
	if now.Sub(s.modesAt[n]) > s.modeMaxAge {
		return fmt.Errorf("the whole key is on signer %s, whose last signing_mode from HEALTH is older than %s (%d key refreshes); a whole key needs a recent signing_mode = single or dv_share",
			s.names[n], s.modeMaxAge, modeMaxRefreshes)
	}

	return nil
}

// wholeKeyMode reports whether a signer of signing_mode m serves whole
// keys: single, or dv_share, whose runner lists each Charon share under its
// own key and signs alone for it (the Charon cluster combines the shares).
func wholeKeyMode(m string) bool {
	return m == setupwire.SigningModeSingle.String() || m == setupwire.SigningModeDVShare.String()
}

// wholeOK is checkWhole at the key list's clock. A threshold key passes
// without the lock, so a sign request does not wait for a key load.
func (s *Signers) wholeOK(g group) error {
	if g.threshold != 1 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.checkWhole(g, s.keys.now())
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
	if s.wholeOK(g) != nil {
		// The signing_mode this whole key was served on aged out since the
		// last load: wait for a new load and look again.
		s.keys.fresh(ctx)
		if g, ok = s.keys.lookup(pubkey); !ok {
			return phase0.BLSSignature{}, ErrUnknownKey
		}
		if err := s.wholeOK(g); err != nil {
			return phase0.BLSSignature{}, fmt.Errorf("%w: %w", ErrUnknownKey, err)
		}
	}
	msg, err := Message(job)
	if err != nil {
		return phase0.BLSSignature{}, err
	}
	req := proto.SignRequest{Pubkey: proto.Pubkey(pubkey), Message: msg, Domain: proto.Root(job.Domain)}
	t0 := time.Now()
	sig, err := s.fanOut(ctx, pubkey, g, req, job.SigningRoot, job.Type)
	if err == nil {
		s.m.SignDuration.Observe(time.Since(t0).Seconds(), job.Type)
	}

	return sig, err
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
//
// An error is a *SignError with the outcome at every configured signer.
// When the request signs, each signer that failed or refused, before or
// after the return, is logged by warnSigner. duty is the request type.
func (s *Signers) fanOut(ctx context.Context, pubkey phase0.BLSPubKey, g group, req proto.SignRequest, root phase0.Root, duty string) (phase0.BLSSignature, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.timeout)
	}
	callCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	results := make(chan partial, len(g.shares))
	// end is set once fanOut has its result. A failed answer before that
	// goes to results; after it, the call logs it itself if the request
	// signed. A good answer always goes to results, without the lock.
	var end struct {
		sync.Mutex
		done, signed bool
	}
	var wg sync.WaitGroup
	for _, sh := range g.shares {
		wg.Go(func() {
			sig, err := s.nodes[sh.node].Sign(callCtx, req)
			err = capDetail(err)
			p := partial{share: sh, sig: phase0.BLSSignature(sig), err: err}
			if err == nil {
				if verr := VerifyBLS(sh.pub, root, p.sig); verr != nil {
					p.err = fmt.Errorf("%w: %w", errBadPartial, verr)
					s.m.CombineFailures.Inc("bad_partial")
					s.log.Warn("bad partial signature", "signer", s.names[sh.node], "pubkey", fmt.Sprintf("%#x", pubkey),
						"kind", req.Message.Kind().String(), "signing_root", fmt.Sprintf("%#x", root))
				}
			}
			if p.err == nil {
				results <- p

				return
			}
			end.Lock()
			done, signed := end.done, end.signed
			if !done {
				// The buffer holds an answer from every share: no block.
				results <- p
			}
			end.Unlock()
			if done && signed {
				s.warnSigner(duty, pubkey, p)
			}
		})
	}
	go func() {
		wg.Wait()
		cancel()
	}()

	// finish sets end and returns the answers that came in but were not
	// read yet.
	finish := func(signed bool) []partial {
		end.Lock()
		end.done, end.signed = true, signed
		end.Unlock()
		var rest []partial
		for {
			select {
			case p := <-results:
				rest = append(rest, p)
			default:
				return rest
			}
		}
	}
	fail := func(good, bad []partial, err error) (phase0.BLSSignature, error) {
		parts := append(append(append([]partial(nil), good...), bad...), finish(false)...)

		return phase0.BLSSignature{}, &SignError{Err: err, Outcomes: s.outcomes(g, parts)}
	}

	var good, bad []partial
	var denied, failed []string
	for got := 0; got < len(g.shares); {
		select {
		case p := <-results:
			got++
			switch {
			case p.err == nil:
				good = append(good, p)
			case isDenial(p.err):
				bad = append(bad, p)
				denied = append(denied, s.names[p.share.node]+": "+p.err.Error())
			default:
				bad = append(bad, p)
				failed = append(failed, s.names[p.share.node]+": "+p.err.Error())
			}
			if len(good) == g.threshold {
				sig, err := s.combineVerified(pubkey, root, good)
				if err != nil {
					return fail(good, bad, err)
				}
				for _, p := range append(bad, finish(true)...) {
					if p.err != nil {
						s.warnSigner(duty, pubkey, p)
					}
				}

				return sig, nil
			}
			if len(good)+len(g.shares)-got < g.threshold {
				s.m.CombineFailures.Inc("below_threshold")

				return fail(good, bad, notEnough(g, len(good), denied, failed))
			}
		case <-ctx.Done():
			return fail(good, bad, fmt.Errorf("%d of %d partial signatures (threshold %d) before the deadline: %w",
				len(good), len(g.shares), g.threshold, ctx.Err()))
		}
	}
	s.m.CombineFailures.Inc("below_threshold")

	return fail(good, bad, notEnough(g, len(good), denied, failed))
}

func (s *Signers) combineVerified(pubkey phase0.BLSPubKey, root phase0.Root, parts []partial) (phase0.BLSSignature, error) {
	indices := make([]uint64, len(parts))
	sigs := make([]phase0.BLSSignature, len(parts))
	for i, p := range parts {
		indices[i], sigs[i] = p.share.index, p.sig
	}
	sig, err := combine(indices, sigs)
	if err != nil {
		s.m.CombineFailures.Inc("verify")

		return phase0.BLSSignature{}, fmt.Errorf("combine: %w", err)
	}
	if err := VerifyBLS(pubkey, root, sig); err != nil {
		s.m.CombineFailures.Inc("verify")

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
// slashing protection or its floor, policy, domain, or a request it would
// not take. Anything else (not ready, a platform failure, an unknown key,
// the connection, a refusal inside a failed dial) is a failure.
func isDenial(err error) bool {
	r, ok := signerRefusal(err)
	if !ok {
		return false
	}
	switch c := r.Code; {
	case c.IsSlashing(), c.IsPolicy(), c == proto.StatusPolicyBuilderAuth, c == proto.StatusFloor, c == proto.StatusFloorUnproven:
		return true
	case c == proto.StatusArg, c == proto.StatusDecode, c == proto.StatusBadRequest, c == proto.StatusUnsupported:
		return true
	}

	return false
}
