//go:build !debugimport

// IMPORT_HANDOVER, the target side of HANDOVER. The source
// (handover_source.go) checked this runner's attested identity and published setup against an
// approver-signed handover order, wrote the tombstone that names this
// runner's setup_hash and sealed its shares to this boot's import key. The
// operator's tool (signer-admin/cmd/handover-target) passes the sealed pages
// on with the order. Every release build with a setup serves it: the
// verifier of the source's origin proof is the one of this runner's own
// platform (attestation-verify/runnerclient, tag verifierselect).
//
// Each request is checked in full, and refused with nothing stored when a
// check fails:
//
//   - the order names this runner's setup_hash as its target, this
//     cluster_id and chain, and k approvers in force here signed it (this
//     runner's version 0 is the source's config in force, so its approvers
//     are the source's). Its not_after does not apply: the source answers
//     its target after it, and an import that a restart cut must go on;
//   - the first request of an import finds this runner empty: no key, both
//     groups at version 0, nothing pending, handover_generation 2 or more,
//     max_keys at least the source's total. It writes the order into the
//     order slot of the mark log's state (importslot.go): from then on the
//     runner signs nothing, takes no other share and no config update
//     until the import ends, also after a restart. Later requests
//     must name the same order, and need no approvals in force again;
//   - every request of this process carries the same mark;
//   - the source's origin proof verifies with the verifier and image the
//     order names for the source, over the order hash and the origin key,
//     and every share's header verifies under that key. Then a share the
//     source holds as generated (made inside a runner of an earlier build)
//     keeps that origin and its order hash; any other counts as imported. A
//     build without the source's verifier, or the dev
//     verifier off the dev platform, refuses, unless the request asks to
//     count every share as imported (ImportAsImported);
//   - every share opens with this boot's import key under its header and,
//     the hash of the page's carry (the mark, the origin, the key set and
//     the day's exits are in the associated data), and is the share of its
//     share_pubkey.
//
// Each new share then goes through the sealed import's path: the mark log
// is raised to the mark first (its interchange maxima; a log that never
// signed hands over no maxima), then the share is stored with its key
// origin and loaded. A validator already held with the same share counts
// as held, so a resumed import skips what is in. When the runner holds the
// carry's key set, a record clears the order slot and the runner signs
// again, above the handed-over mark. The day's exits the source carried go
// into the mark log before that (takeExits).

package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// HandoverImportOptions configure EnableHandoverImport.
type HandoverImportOptions struct {
	// VerifierOptions go to the source's verifier (the platform's HTTP
	// client for the key sets).
	VerifierOptions []runnerclient.Option
	// LimitedEgress and PeerEndpoints: on a runner that reaches only its
	// setup's peer hosts (setup.AttestationEgress), every host the source's
	// verifier fetches a key set from must be one of them.
	LimitedEgress bool
	PeerEndpoints []string
}

// EnableHandoverImport turns IMPORT_HANDOVER on. It needs a setup with its
// config updates and the mark log.
func (s *Server) EnableHandoverImport(o HandoverImportOptions) error {
	switch {
	case s.Updates == nil || s.SetupHash == ([32]byte{}):
		return errors.New("handover import needs a runner with a setup")
	case s.Hooks == nil || !s.Hooks.Mode().MarkLog:
		return errors.New("handover import needs the mark log")
	}
	s.imp = &importer{s: s, opt: o, verifiers: map[[32]byte]runnerclient.DocumentVerifier{}, proven: map[[64]byte]bool{}}
	if cur := s.importing(); cur != nil {
		s.Log.Warn("handover import in progress: nothing is signed until every handed-over share is in",
			"order", hex.EncodeToString(cur.Hash[:6]), "keys_held", len(s.Signer.Keys()))
	}
	return nil
}

type importer struct {
	s   *Server
	opt HandoverImportOptions

	// slotMu orders the writes of the order slot: the start and the end of
	// an import.
	slotMu namedMutex[importSlotMuName]

	mu namedMutex[importMuName]
	// mark is the handed-over mark of this process's import; every request
	// carries it.
	mark *backend.Watermark
	// verifiers are the source verifiers by order hash, so a key set is
	// fetched once.
	verifiers map[[32]byte]runnerclient.DocumentVerifier
	// proven holds the origin keys whose proof verified: order hash, then
	// the key.
	proven map[[64]byte]bool
}

func (im *importer) dev() bool { return im.s.Platform.Name == "dev" }

// refuse logs and returns a BAD_REQUEST refusal.
func (im *importer) refuse(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	im.s.Log.Warn("handover import refused", "err", err)
	return backend.Refused(backend.StatusBadRequest, "handover import: %v", err)
}

// checkOrder checks that the order hands over to this runner and that k
// approvers in force here signed it. An order whose import is in progress
// passed that check when its first request wrote the slot, and the slot is
// in the locked log, so later requests need only name it: a set that came
// into force since (which no CONFIG_UPDATE of this runner can bring, see
// importslot.go) does not strand shares that left their source.
func (im *importer) checkOrder(o *handoverorder.Order, hash [32]byte) error {
	s, b := im.s, &o.Body
	setup := s.Updates.SetupWire()
	switch {
	case b.Target.SetupHash != s.SetupHash:
		return im.refuse("the order hands over to setup %x, this runner's is %x", b.Target.SetupHash[:8], s.SetupHash[:8])
	case b.ClusterID != setup.ClusterID:
		return im.refuse("the order is for another cluster_id")
	case b.ChainHash != setup.Chain.Hash():
		return im.refuse("the order is for another chain")
	}
	if cur := s.importing(); cur != nil && cur.Hash == hash {
		return nil
	}
	locked, err := s.Updates.LockedInForce()
	if err != nil {
		return err
	}
	if err := o.Verify(&locked.Approvers); err != nil {
		return im.refuse("%v", err)
	}
	return nil
}

// sourceVerifier is the verifier of the order's source: the settings the
// order names, a verifier built into this runner, the dev verifier on the
// dev platform only, and key set hosts this runner reaches.
func (im *importer) sourceVerifier(b *handoverorder.Body, hash [32]byte) (runnerclient.DocumentVerifier, error) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if v, ok := im.verifiers[hash]; ok {
		return v, nil
	}
	p := b.Source
	a := runnerclient.RunnerAttestation(&p)
	switch {
	case !runnerclient.Available(a.Verifier):
		return nil, fmt.Errorf("the source's verifier %q is not built into this runner", a.Verifier)
	case a.Verifier == runnerclient.VerifierDev && !im.dev():
		return nil, fmt.Errorf("the source has the dev verifier, which accepts unsigned documents; refused on platform %s", im.s.Platform.Name)
	}
	if im.opt.LimitedEgress {
		var missing []string
		for _, e := range a.Endpoints() {
			if !slices.Contains(im.opt.PeerEndpoints, e) {
				missing = append(missing, e)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("the source's verifier fetches its key set from %s, which this runner does not reach (its setup's peer hosts: %s)",
				strings.Join(missing, " and "), strings.Join(im.opt.PeerEndpoints, ", "))
		}
	}
	v, err := a.NewDocumentVerifier(im.opt.VerifierOptions...)
	if err != nil {
		return nil, fmt.Errorf("the source's settings: %w", err)
	}
	im.verifiers[hash] = v
	return v, nil
}

// checkOrigin verifies the page's origin proof (once per order and key)
// and the origin signature of each share in fresh.
func (im *importer) checkOrigin(ctx context.Context, b *handoverorder.Body, hash [32]byte, page *handover.Response, fresh []int) error {
	const hint = " (a target that cannot check the origin may skip the origin checks: handover-target import -as-imported)"
	var id [64]byte
	copy(id[:32], hash[:])
	copy(id[32:], page.Origin.Key[:])
	im.mu.Lock()
	proven := im.proven[id]
	im.mu.Unlock()
	if !proven {
		verify, err := im.sourceVerifier(b, hash)
		if err != nil {
			im.s.Log.Warn("handover import refused: origin proof", "err", err)
			return backend.Refused(backend.StatusBadKey, "handover import: origin proof: %v%s", err, hint)
		}
		if err := verify(ctx, page.Origin.Nonce, handover.OriginUserData(hash, page.Origin.Key), page.Origin.Attestation); err != nil {
			im.s.Log.Warn("handover import refused: origin proof", "err", err)
			return backend.Refused(backend.StatusBadKey, "handover import: origin proof: %v%s", err, hint)
		}
		im.mu.Lock()
		im.proven[id] = true
		im.mu.Unlock()
		im.s.Log.Info("handover import: the source's origin proof verified", "order", hex.EncodeToString(hash[:6]),
			"origin_key", hex.EncodeToString(page.Origin.Key[:8]), "verifier", b.Source.Verifier.String())
	}
	for _, i := range fresh {
		if err := page.Shares[i].VerifyOrigin(page.Origin.Key); err != nil {
			return im.refuse("share %d (%s): %v", i, page.Shares[i].Pubkey.String()[:18], err)
		}
	}
	return nil
}

// checkStart checks that an import may start here: an empty runner (the
// caller checked that it holds no key) at version 0 of a handover target's
// setup, with room for the total.
func (im *importer) checkStart(total uint32) error {
	s := im.s
	setup := s.Updates.SetupWire()
	st := s.SetupState()
	switch {
	case setup.HandoverGeneration < 2:
		return im.refuse("this runner's setup has handover_generation %d; a handover target has 2 or more", setup.HandoverGeneration)
	case st.Locked.Version != 0 || st.Open.Version != 0:
		return im.refuse("this runner is past version 0 of its groups (locked %d, open %d); a handover target starts at version 0", st.Locked.Version, st.Open.Version)
	case st.Locked.Pending.Version != 0 || st.Open.Pending.Version != 0:
		return im.refuse("a config update is pending here")
	case st.Order.Kind != 0:
		return im.refuse("an order (kind %d, %x) is pending here", st.Order.Kind, st.Order.Hash[:8])
	case uint64(total) > uint64(setup.MaxKeys):
		return im.refuse("the source hands over %d shares, this runner's max_keys is %d", total, setup.MaxKeys)
	}
	return nil
}

// start writes the order into the order slot: from here on the runner
// signs nothing until the import ends. The caller holds slotMu. It holds
// the share lock while it writes, so a share that another path (a sealed
// import) stores either comes first and stops the start,
// or finds the slot set and is refused (addShareOf):
// the end of the import counts the runner's keys, which must all be the
// order's.
func (im *importer) start(ctx context.Context, hash [32]byte, total uint32) error {
	s := im.s
	t, err := s.Platform.Clock.Now()
	if err != nil {
		return backend.Refused(backend.StatusClock, "handover import: clock: %v", err)
	}
	s.sharesMu.Lock()
	defer s.sharesMu.Unlock()
	if n := len(s.Signer.Keys()); n > 0 {
		return im.refuse("this runner took %d keys since the first checks; an import starts on an empty runner only", n)
	}
	if err := s.Updates.setImportOrder(ctx, &markstore.Order{Kind: markstore.OrderHandover, Hash: hash, ActAt: unix(t)}); err != nil {
		return err
	}
	s.Log.Warn("handover import started: nothing is signed until every share is in", "order", hex.EncodeToString(hash[:6]), "total", total)
	return nil
}

// reserve serves HANDOVER_ORDER for an order that names this runner as
// its target (SHR-01). A source checks the target's IDENTITY answer, which
// the operator's tool read for its own nonce, so the answer may be older
// than a config update the target took since: the source would write its
// tombstone for a target that refuses the import. reserve checks the
// order as the first import request does and writes it into the import
// slot of an empty runner. From then on the runner takes no config update,
// no other order and no other share, and its IDENTITY shows the order: a
// source of this tree hands over only to a target reserved for its order.
// The same order again reports it reserved. A reservation lasts until the
// import ends, as an import does: a target whose order is abandoned is
// replaced, not reused.
func (im *importer) reserve(ctx context.Context, o *handoverorder.Order, hash [32]byte) ([]byte, error) {
	s := im.s
	if err := im.checkOrder(o, hash); err != nil {
		return nil, err
	}
	im.slotMu.Lock()
	defer im.slotMu.Unlock()
	outcome := handoverorder.Accepted
	switch cur := s.importing(); {
	case cur != nil && cur.Hash == hash:
		outcome = handoverorder.Known
	case cur != nil:
		return nil, im.refuse("the import under handover order %x is in progress; it takes no other order", cur.Hash[:8])
	case len(s.Signer.Keys()) > 0:
		return nil, im.refuse("this runner holds %d keys; a handover target starts empty", len(s.Signer.Keys()))
	default:
		if err := im.checkStart(0); err != nil {
			return nil, err
		}
		if err := im.start(ctx, hash, 0); err != nil {
			return nil, err
		}
	}
	st := &handoverorder.State{Outcome: outcome, Status: handoverorder.Active, Hash: hash, NotAfter: o.Body.NotAfter}
	return st.Encode(), nil
}

// checkMark wants mark to be this process's import mark. keep makes it
// that mark when there is none yet (a request that passed every check).
func (im *importer) checkMark(mark backend.Watermark, keep bool) error {
	im.mu.Lock()
	defer im.mu.Unlock()
	switch {
	case im.mark == nil && keep:
		im.mark = &mark
	case im.mark != nil && *im.mark != mark:
		return im.refuse("the page carries mark (block %d, source %d, target %d), this import has (block %d, source %d, target %d)",
			mark.BlockSlot, mark.SourceEpoch, mark.TargetEpoch, im.mark.BlockSlot, im.mark.SourceEpoch, im.mark.TargetEpoch)
	}
	return nil
}

// importShares serves IMPORT_HANDOVER.
func (im *importer) importShares(ctx context.Context, payload []byte) ([]byte, error) {
	s := im.s
	if s.ImportKey == nil {
		return nil, backend.Refused(backend.StatusUnsupported, "handover import: sealed share import is disabled (-sealed-import=false)")
	}
	q, err := handover.DecodeImportRequest(payload)
	if err != nil {
		return nil, im.refuse("%v", err)
	}
	o, err := handoverorder.Decode(q.Order)
	if err != nil {
		return nil, im.refuse("%v", err)
	}
	b := &o.Body
	hash, _ := b.Hash()
	if err := im.checkOrder(o, hash); err != nil {
		return nil, err
	}
	page := q.Page
	// The page's mark and every share's maxima within the clock horizon
	// before anything is written (SHC-02), also under ImportAsImported,
	// which skips the origin checks: a far-future mark would raise the
	// locked log and stop this runner until real time passed it.
	if markstore.IsTombstone(page.Mark) {
		return nil, im.refuse("the page carries the handover tombstone as its mark")
	}
	if err := s.checkHandoverMark(&page.Mark); err != nil {
		return nil, err
	}
	for i := range page.Shares {
		if err := s.checkHandoverMark(page.Shares[i].Interchange); err != nil {
			return nil, err
		}
		if err := s.checkSourceFloor(page.Shares[i].SourceFloor); err != nil {
			return nil, err
		}
	}

	// Which shares this runner holds already. A validator held with
	// another share is a conflict.
	keys := s.Signer.Keys()
	held := make(map[backend.Pubkey]backend.Pubkey, len(keys))
	for _, k := range keys {
		held[k.Pubkey] = k.SharePubkey
	}
	outcomes := make([]uint8, len(page.Shares))
	var fresh []int
	for i := range page.Shares {
		sh := &page.Shares[i]
		sp, ok := held[sh.Pubkey]
		switch {
		case ok && sp != sh.SharePubkey:
			return nil, im.refuse("share %d: this runner holds another share of validator %s", i, sh.Pubkey.String()[:18])
		case ok:
			outcomes[i] = handover.Held
		default:
			fresh = append(fresh, i)
		}
	}

	// The order slot: an import to start, one to go on with, or one that
	// ended (every share held). The slot is written only once every check
	// of the request passed.
	im.slotMu.Lock()
	cur := s.importing()
	starting := false
	switch {
	case cur == nil && len(keys) == 0:
		starting, err = true, im.checkStart(page.Total)
	case cur == nil && len(fresh) > 0:
		err = im.refuse("this runner holds %d keys and no handover import is in progress; an import starts on an empty runner only", len(keys))
	case cur != nil && cur.Hash != hash:
		err = im.refuse("the import under handover order %x is in progress; it takes no other order", cur.Hash[:8])
	case len(keys) == 0 && uint64(page.Total) > uint64(s.Updates.SetupWire().MaxKeys):
		// A reserved target: the start's room check.
		err = im.refuse("the source hands over %d shares, this runner's max_keys is %d", page.Total, s.Updates.SetupWire().MaxKeys)
	}
	im.slotMu.Unlock()
	if err != nil {
		return nil, err
	}
	if cur == nil && len(fresh) == 0 && len(keys) > 0 {
		// An import that ended: nothing to store.
		return im.answer(ctx, hash, page, outcomes, false)
	}
	if err := im.checkMark(page.Mark, false); err != nil {
		return nil, err
	}

	asImported := q.Flags&handover.ImportAsImported != 0
	if len(fresh) > 0 && !asImported {
		if err := im.checkOrigin(ctx, b, hash, page, fresh); err != nil {
			return nil, err
		}
	}
	carryHash, err := page.CarryHash()
	if err != nil {
		return nil, im.refuse("%v", err)
	}
	secrets := make([][32]byte, len(page.Shares))
	defer clear(secrets)
	for _, i := range fresh {
		sh := &page.Shares[i]
		sec, err := s.ImportKey.OpenAAD(sh.Sealed, sh.AAD(carryHash))
		if err != nil {
			s.Log.Warn("handover import refused: share does not open", "share", i, "err", err)
			return nil, backend.Refused(backend.StatusBadKey,
				"handover import: share %d (%s): %v (a share sealed for an earlier boot of this runner: read its identity again and have the source seal again)",
				i, sh.Pubkey.String()[:18], err)
		}
		secrets[i] = sec
		clear(sec[:])
		if sp, err := core.PubkeyOf(secrets[i]); err != nil || sp != sh.SharePubkey {
			return nil, backend.Refused(backend.StatusBadKey, "handover import: share %d (%s): the share is not its share_pubkey's", i, sh.Pubkey.String()[:18])
		}
	}
	// The carry, and with it the page's total and key set, is the source's
	// only if a share of this request opened under it (SHC-01): a fresh one
	// above, or else one held already.
	authed := len(fresh) > 0
	if !authed && cur != nil && cur.Hash == hash {
		authed = im.carryOpens(ctx, b, hash, page, carryHash, asImported)
	}

	if starting && len(fresh) == 0 {
		// Nothing to store, so no import starts: a request without a share
		// cannot end one (answer), and a source with no share hands over
		// nothing.
		return im.answer(ctx, hash, page, outcomes, false)
	}
	if starting {
		im.slotMu.Lock()
		switch cur := s.importing(); {
		case cur == nil:
			err = im.start(ctx, hash, page.Total)
		case cur.Hash != hash:
			err = im.refuse("the import under handover order %x is in progress; it takes no other order", cur.Hash[:8])
		}
		im.slotMu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	if err := im.checkMark(page.Mark, true); err != nil {
		return nil, err
	}
	// The carry opened with the shares above (it is in their associated
	// data), so it came from the source with them.
	if len(fresh) > 0 {
		if err := im.takeExits(ctx, &page.Carry); err != nil {
			return nil, err
		}
	}

	start := time.Now()
	stored := 0
	for _, i := range fresh {
		sh := &page.Shares[i]
		// The mark is the source's device mark: the page says whether this
		// key had its own history there (HSH-01).
		handed := &handedState{history: sh.History, floor: sh.SourceFloor}
		k, err := s.addShareOf(sh.Pubkey, &secrets[i], sh.Index, sh.Interchange, "handover", handed, keys)
		var r *backend.RefusedError
		switch {
		case errors.As(err, &r) && r.Code == backend.StatusDuplicate:
			// Another request stored it meanwhile: held only if that is
			// this share.
			switch sp, ok := s.loadedShare(sh.Pubkey); {
			case !ok:
				return nil, backend.Refused(backend.StatusNotReady, "handover import: share %d (%s): another request is storing this validator; send the request again",
					i, sh.Pubkey.String()[:18])
			case sp != sh.SharePubkey:
				return nil, im.refuse("share %d: this runner holds another share of validator %s", i, sh.Pubkey.String()[:18])
			}
			outcomes[i] = handover.Held
			continue
		case err != nil:
			s.Log.Warn("handover import: share not stored", "share", i, "pubkey", sh.Pubkey.String()[:18], "stored_before", stored, "err", err)
			return nil, err
		case k.SharePubkey != sh.SharePubkey:
			return nil, backend.Refused(backend.StatusInternal, "handover import: share %d loaded with another share key", i)
		}
		outcomes[i] = handover.Stored
		stored++
	}
	s.Log.Info("handover import: request", "order", hex.EncodeToString(hash[:6]), "shares", len(page.Shares), "stored", stored,
		"held_before", len(page.Shares)-len(fresh), "as_imported", asImported, "ms", time.Since(start).Milliseconds())
	return im.answer(ctx, hash, page, outcomes, authed)
}

// loadedShare is the share key of the loaded validator pk.
func (s *Server) loadedShare(pk backend.Pubkey) (backend.Pubkey, bool) {
	for _, k := range s.Signer.Keys() {
		if k.Pubkey == pk {
			return k.SharePubkey, true
		}
	}
	return backend.Pubkey{}, false
}

// carryOpens reports whether a share of page that this runner holds
// already opens under the page's carry, with its origin checked unless
// asImported: then the carry came from the source with it. A request of
// held shares only can end the import only so.
func (im *importer) carryOpens(ctx context.Context, b *handoverorder.Body, hash [32]byte, page *handover.Response, carryHash [32]byte, asImported bool) bool {
	for i := range page.Shares {
		sh := &page.Shares[i]
		if !asImported && im.checkOrigin(ctx, b, hash, page, []int{i}) != nil {
			continue
		}
		sec, err := im.s.ImportKey.OpenAAD(sh.Sealed, sh.AAD(carryHash))
		if err != nil {
			continue
		}
		sp, err := core.PubkeyOf(sec)
		clear(sec[:])
		if err == nil && sp == sh.SharePubkey {
			return true
		}
	}
	return false
}

// takeExits writes the day's exits the source carried into this
// runner's mark log, before the import ends and the runner signs again: an
// exit the source signed today counts against this runner's cap too, and
// its approval's nonce stays used. A carry of an earlier day frees nothing
// and is not written; a log that holds that day already merges the two.
func (im *importer) takeExits(ctx context.Context, c *handover.Carry) error {
	if c.Exits == nil {
		return nil
	}
	s := im.s
	t, err := s.Platform.Clock.Now()
	if err != nil {
		return backend.Refused(backend.StatusClock, "handover import: clock: %v", err)
	}
	if c.Exits.Day < unix(t)/daySeconds {
		return nil
	}
	cur, err := s.Hooks.Exits()
	if err != nil {
		return backend.Refused(backend.StatusStorage, "handover import: the carried exits need the mark log: %v", err)
	}
	if cur != nil && cur.Day > c.Exits.Day {
		return nil
	}
	// The same day: both ledgers count, each approval nonce once (SHH-01).
	// The carry names each exit's validator key, so a repeat of a carried
	// exit matches here.
	d := &markstore.ExitDay{Day: c.Exits.Day}
	if cur != nil && cur.Day == c.Exits.Day {
		d = cur.Clone()
	}
	seen := map[[32]byte]bool{}
	for _, e := range d.Exits {
		seen[e.Nonce] = true
	}
	added := 0
	for _, e := range c.Exits.Entries {
		if seen[e.Nonce] {
			continue
		}
		seen[e.Nonce] = true
		if d.Stake+e.Stake < d.Stake {
			return backend.Refused(backend.StatusBadRequest, "handover import: the carried exits' stake overflows")
		}
		d.Exits = append(d.Exits, markstore.ExitEntry{Pubkey: e.Pubkey, ValidatorIndex: e.ValidatorIndex, ExitEpoch: e.ExitEpoch, Stake: e.Stake, Nonce: e.Nonce})
		d.Stake += e.Stake
		added++
	}
	if added == 0 {
		return nil
	}
	if len(d.Exits) > markstore.MaxExitsPerDay {
		return backend.Refused(backend.StatusNoMem, "handover import: %d exits today with the carried ones, at most %d", len(d.Exits), markstore.MaxExitsPerDay)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.Hooks.RecordExits(wctx, d); err != nil {
		return backend.Refused(backend.StatusStorage, "handover import: the carried exits were not written to the mark log: %v", err)
	}
	s.Log.Warn("handover import: the source's exits of the day are in the mark log", "day", d.Day, "exits", len(d.Exits), "stake_gwei", d.Stake)
	return nil
}

// answer ends the import once the runner holds what the source hands over
// (a record clears the order slot) and returns the response. Only a
// request whose carry authed (a share of it opened under the carry) ends
// it, and only when the runner holds exactly the carry's key set.
func (im *importer) answer(ctx context.Context, hash [32]byte, page *handover.Response, outcomes []uint8, authed bool) ([]byte, error) {
	s := im.s
	keys := s.Signer.Keys()
	total := page.Total
	set := page.Carry.Set
	holds := set.Holds(keys)
	if !holds && uint64(len(keys)) >= uint64(set.Total) {
		s.Log.Error("handover import: this runner holds as many keys as the source hands over, but not the source's set", "order", hex.EncodeToString(hash[:6]),
			"keys", len(keys), "total", set.Total)
	}
	if holds && authed {
		im.slotMu.Lock()
		var err error
		if cur := s.importing(); cur != nil && cur.Hash == hash {
			if err = s.Updates.setImportOrder(ctx, nil); err == nil {
				mark := backend.Watermark{}
				im.mu.Lock()
				if im.mark != nil {
					mark = *im.mark
				}
				im.mu.Unlock()
				s.Log.Warn("handover import done: every share is in; signing above the handed-over mark", "order", hex.EncodeToString(hash[:6]),
					"keys", len(keys),
					"target", mark.TargetEpoch, "source", mark.SourceEpoch, "block", mark.BlockSlot)
			}
		}
		im.slotMu.Unlock()
		if err != nil {
			return nil, backend.Refused(backend.StatusStorage, "handover import: every share is in, but the record that ends the import was not written (%v); send the request again", err)
		}
	}
	r := &handover.ImportResponse{Outcomes: outcomes, Held: uint32(len(keys)), Total: total,
		Done: s.importing() == nil && holds, Imported: keyOrigin(keys).Imported}
	out, err := r.Encode()
	if err != nil {
		return nil, backend.Refused(backend.StatusInternal, "%v", err)
	}
	return out, nil
}

// lockers are its locks, for the check after a panic (recover.go).
func (im *importer) lockers() []sync.Locker { return []sync.Locker{&im.slotMu, &im.mu} }
