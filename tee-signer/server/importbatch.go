package server

// IMPORT_SHARES_SEALED: many sealed shares under one import order, stored
// all or none under one mark log record.
//
// The runner checks every share before it writes anything. Then one log
// record vouches for the set before the batch and the set after it, and
// the records go to the store, shareWriters at once. Each record carries
// the batch's tag (shareRecord.Batch). If a write fails and the read back
// does not find it, the batch fails: a log record at once vouches for the
// set before only.
//
// The records of a batch that did not complete (a write failed, or the
// runner stopped halfway) may stay in the store. A start whose stored
// records are not a set the newest log record vouches for leaves out the
// records of one tag (findCut); if the rest is vouched, it loads the rest
// as it is and none of the batch's keys. Later log records vouch for sets
// without those records, so later starts leave them out too. A later
// batch must hold every key of that batch and takes its tag, so the store
// never holds records of two batches that did not complete. A key of it
// imported on its own leaves it.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

// shareWriters is how many share records a batch writes at once.
const shareWriters = 16

// batchCut is a batch that did not complete: its tag and the keys whose
// records of it may be stored.
type batchCut struct {
	tag  []byte
	keys map[backend.Pubkey]bool
}

// drop takes pk out of c once a record of pk outside the batch is stored.
func (c *batchCut) drop(pk backend.Pubkey) {
	if c != nil {
		delete(c.keys, pk)
	}
}

// findCut returns the batch whose records, left out of the stored records
// (recs, and their hashes), leave a set that set vouches for; nil if none.
func findCut(set *markstore.ShareSet, recs map[backend.Pubkey]*shareRecord, hashes map[backend.Pubkey][32]byte) *batchCut {
	tags := map[string]bool{}
	for _, r := range recs {
		if len(r.Batch) > 0 {
			tags[string(r.Batch)] = true
		}
	}
	for _, tag := range slices.Sorted(maps.Keys(tags)) {
		cut := &batchCut{tag: []byte(tag), keys: map[backend.Pubkey]bool{}}
		rest := map[backend.Pubkey][32]byte{}
		for pk, h := range hashes {
			if string(recs[pk].Batch) == tag {
				cut.keys[pk] = true
			} else {
				rest[pk] = h
			}
		}
		if set.Vouches(markstore.ShareSetRoot(rest)) {
			return cut
		}
	}
	return nil
}

// importBatch serves IMPORT_SHARES_SEALED. An empty batch writes nothing
// and answers an empty key list: a sender learns that the runner knows
// the message.
func (s *Server) importBatch(p []byte) ([]byte, error) {
	defer clear(p)
	if s.ImportKey == nil {
		return nil, backend.Refused(backend.StatusUnsupported, "sealed share import is disabled (-sealed-import=false)")
	}
	reqs, err := wireadmin.DecodeImportBatch(p)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	if len(reqs) == 0 {
		return wire.EncodeKeys(nil), nil
	}
	var (
		order *importorder.Order
		now   uint64
	)
	if s.Updates != nil {
		if order, now, err = s.verifyImportOrder(reqs[0].Order); err != nil {
			return nil, err
		}
	}
	// The keys the shares are filed under, and their group keys (importKey).
	pks, groups := make([]backend.Pubkey, len(reqs)), make([]*backend.Pubkey, len(reqs))
	for i := range reqs {
		pks[i], groups[i] = s.importKey(&reqs[i])
	}
	if err := s.reserveAll(pks); err != nil {
		return nil, err
	}
	defer s.releaseAll(pks)
	secrets := make([][32]byte, len(reqs))
	defer clear(secrets)
	keys, seen := s.Signer.Keys(), map[backend.Pubkey]bool{}
	for i := range reqs {
		if err := s.checkBatchShare(&reqs[i], pks[i], groups[i], order, now, &secrets[i], keys, seen); err != nil {
			detail := err.Error()
			if re := (*backend.RefusedError)(nil); errors.As(err, &re) {
				detail = re.Detail
			}
			return nil, backend.Refused(backend.StatusOf(err), "share %d, validator %s: %s", i, pks[i].String()[:18], detail)
		}
	}
	floor, floorOn, err := s.Hooks.ImportFloor()
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "%v", err)
	}
	if err := s.storeBatch(reqs, pks, groups, secrets, floor, floorOn); err != nil {
		return nil, err
	}
	out := make([]backend.ValidatorKey, 0, len(reqs))
	var failed []error
	for i := range reqs {
		r := &reqs[i]
		var loadFloor uint64
		if floorOn {
			loadFloor = floor
			if r.Interchange == nil || !r.Interchange.HasAttestation {
				s.Hooks.NoteImportFloor(pks[i], floor)
			}
		}
		k, err := s.loadShare(pks[i], &secrets[i], r.Index, r.Interchange, groups[i], loadFloor, "sealed batch")
		if err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", pks[i].String()[:18], err))
			continue
		}
		out = append(out, k)
	}
	if len(failed) > 0 {
		return nil, backend.Refused(backend.StatusOf(failed[0]), "the batch is stored, %d of its %d keys did not load: %v", len(failed), len(reqs), failed[0])
	}
	return wire.EncodeKeys(out), nil
}

// checkBatchShare checks one share of a batch as the sealed import checks
// it, against the import order o verified at now, and opens it into
// secret. seen holds the share keys of the batch so far. pk and group are
// the key the share is filed under and its group key (importKey).
func (s *Server) checkBatchShare(req *backend.SealedImportRequest, pk backend.Pubkey, group *backend.Pubkey, o *importorder.Order, now uint64, secret *[32]byte,
	keys []backend.ValidatorKey, seen map[backend.Pubkey]bool) error {
	if err := s.checkMaxima(req.Interchange); err != nil {
		return err
	}
	if err := s.checkGroupKey(pk, group); err != nil {
		return err
	}
	if o != nil {
		e, err := o.Body.Matches(s.Updates.SetupWire(), s.SetupHash, now, req.Pubkey)
		if err != nil {
			return backend.Refused(backend.StatusForbidden, "%v", err)
		}
		if err := s.checkSplit(req, &o.Body, e); err != nil {
			return err
		}
	}
	var err error
	if *secret, err = s.ImportKey.Open(req); err != nil {
		return backend.Refused(backend.StatusBadKey, "%v", err)
	}
	if got, err := core.PubkeyOf(*secret); err != nil || got != req.SharePubkey {
		return backend.Refused(backend.StatusBadKey, "decrypted share does not match share_pubkey")
	}
	if seen[req.SharePubkey] {
		return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "the batch holds this share twice"}
	}
	seen[req.SharePubkey] = true
	if err := s.checkShare(pk, secret, keys); err != nil {
		return err
	}
	if _, err := s.Signer.State(pk); err == nil {
		return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "validator already loaded"}
	}
	return nil
}

// storeBatch raises the mark log to the batch's interchange maxima, seals
// its records and stores them (putShares). A batch adds keys only: a key
// whose record is in the set is refused, so the set before holds no
// record of a batch key.
func (s *Server) storeBatch(reqs []backend.SealedImportRequest, pks []backend.Pubkey, groups []*backend.Pubkey, secrets [][32]byte, floor uint64, floorOn bool) error {
	s.shareSetMu.Lock()
	defer s.shareSetMu.Unlock()
	batch := map[backend.Pubkey]bool{}
	for i := range reqs {
		pk := pks[i]
		if _, held := s.shareHash[pk]; held {
			return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: fmt.Sprintf(
				"validator %s: its share record is stored already; a batch adds keys only, import it with IMPORT_SHARE_SEALED", pk.String()[:18])}
		}
		batch[pk] = true
	}
	// A start that loaded no key for a share set reason: only a batch of
	// every share it listed is taken.
	if err := s.batchLoadRefusal(batch); err != nil {
		return err
	}
	tag := []byte(rand.Text())
	if s.cut != nil {
		for pk := range s.cut.keys {
			if !batch[pk] {
				return backend.Refused(backend.StatusBadRequest,
					"%d keys of an earlier batch that did not complete may have records stored; send a batch that holds all of them (%s is missing), or import them one at a time",
					len(s.cut.keys), pk.String()[:18])
			}
		}
		tag = s.cut.tag
	}
	var raise *backend.Watermark
	for i := range reqs {
		if w := reqs[i].Interchange; w != nil {
			m := *w
			if raise != nil {
				m = state.Merge(*raise, m)
			}
			raise = &m
		}
	}
	if raise != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.Hooks.RaiseMark(ctx, *raise)
		cancel()
		if err != nil {
			return backend.Refused(backend.StatusStorage, "raise the mark log to the interchange maxima: %v", err)
		}
	}
	blobs := make(map[backend.Pubkey][]byte, len(reqs))
	for i := range reqs {
		r := &reqs[i]
		rec := shareRecord{Pubkey: pks[i], Secret: secrets[i][:], Index: r.Index,
			History: r.Interchange != nil && r.Interchange.HasAttestation, Batch: tag, GroupPubkey: groups[i]}
		if !rec.History && floorOn {
			rec.SourceFloor = floor
		}
		blob, err := s.sealRecord(rec)
		if err != nil {
			return err
		}
		blobs[pks[i]] = blob
	}
	if err := s.imageRefusal(); err != nil {
		return err
	}
	if err := s.putShares(blobs, tag); err != nil {
		return backend.Refused(backend.StatusPlatform, "store shares: %v", err)
	}
	return nil
}

// putShares stores a batch's sealed records, all or none. With a mark log
// it first writes one log record that vouches for the set before and the
// set after, then the records. If one does not land, it writes a log
// record at once that vouches for the set before only, and the batch
// becomes the cut batch; if that record fails too, share writes stop until
// a restart, as in putShare. The caller holds shareSetMu and checked
// batchLoadRefusal.
func (s *Server) putShares(blobs map[backend.Pubkey][]byte, tag []byte) error {
	if _, committed := s.Hooks.ShareSet(); !committed {
		return s.putAll(blobs)
	}
	if s.shareWritesStopped {
		return errors.New("a failed share write is still vouched in the mark log: no share write until a restart")
	}
	next := maps.Clone(s.shareHash)
	if next == nil {
		next = map[backend.Pubkey][32]byte{}
	}
	for pk, b := range blobs {
		next[pk] = sha256.Sum256(b)
	}
	before, after := markstore.ShareSetRoot(s.shareHash), markstore.ShareSetRoot(next)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := s.Hooks.RecordShareSet(ctx, &markstore.ShareSet{Current: before, Pending: &after})
	cancel()
	if err != nil {
		return fmt.Errorf("mark log share set: %w", err)
	}
	if err := s.putAll(blobs); err != nil {
		// Drop the set after from the log at once: the host keeps the
		// blobs and could store them later.
		s.Hooks.SetShareSet(&markstore.ShareSet{Current: before})
		s.cut = &batchCut{tag: tag, keys: map[backend.Pubkey]bool{}}
		for pk := range blobs {
			s.cut.keys[pk] = true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if rerr := s.Hooks.RecordShareSet(ctx, &markstore.ShareSet{Current: before}); rerr != nil {
			s.shareWritesStopped = true
			err = fmt.Errorf("%w; the mark log record that drops it failed too, no share write until a restart: %v", err, rerr)
		}
		cancel()
		return err
	}
	s.shareHash, s.cut = next, nil
	s.Hooks.SetShareSet(&markstore.ShareSet{Current: after})
	// As in putShare: a start with no record listed is ready after this.
	// So is one that listed records it did not load: this batch held
	// every one of them (batchLoadRefusal) and replaced their records.
	s.noShares.Store(nil)
	s.loadFailed.Store(nil)
	s.noSharesListed.Store(false)
	s.listedShares = nil
	return nil
}

// putAll writes blobs, shareWriters at once. A write that fails is read
// back (landed); the error counts the records that did not land.
func (s *Server) putAll(blobs map[backend.Pubkey][]byte) error {
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed int
		first  error
	)
	sem := make(chan struct{}, shareWriters)
	for pk, blob := range blobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			if err := s.Platform.Store.Put(shareKey(pk), blob); err != nil && !s.landed(pk, sha256.Sum256(blob)) {
				mu.Lock()
				failed++
				if first == nil {
					first = fmt.Errorf("%s: %w", shareKey(pk), err)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if failed > 0 {
		return fmt.Errorf("%d of %d records did not land, the batch is not stored: %w", failed, len(blobs), first)
	}
	return nil
}

// reserveAll is reserve for every key of a batch, with one max_keys check.
func (s *Server) reserveAll(pks []backend.Pubkey) error {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	batch := map[backend.Pubkey]bool{}
	for _, pk := range pks {
		if s.admitting[pk] || batch[pk] {
			return &backend.RefusedError{Code: backend.StatusDuplicate,
				Detail: fmt.Sprintf("validator %s: another request or share of the batch is adding it", pk.String()[:18])}
		}
		batch[pk] = true
	}
	if s.Updates != nil {
		if err := s.checkSlots(pks...); err != nil {
			return err
		}
	}
	if s.admitting == nil {
		s.admitting = map[backend.Pubkey]bool{}
	}
	for _, pk := range pks {
		s.admitting[pk] = true
	}
	return nil
}

func (s *Server) releaseAll(pks []backend.Pubkey) {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	for _, pk := range pks {
		delete(s.admitting, pk)
	}
}
