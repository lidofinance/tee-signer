// Package server serves the wire protocol on top of a core.Signer and a
// platform. It owns share import, share sealing and attestation.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/state"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

const Version = "0.1.0" + buildchain.VersionSuffix // HEALTH's version; "+<chain>" in a non-prod build

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
	// setup carries it; zero when the platform has no self-check, the
	// read failed or the rule is not locked (keyRule).
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
	// setup: a request that signs or imports goes through only
	// while it passes. nil: no check (the flag path, and tests).
	Image *ImageGate
	// SealingKeyUnproven: the platform's sealing key came from a stored
	// blob (platform.Platform.SealingKeyStored) and no check of the stored
	// shares has passed yet (ProveSealingKey). While it holds, the server
	// seals no share. Set before Serve and changed only by
	// ProveSealingKey, also before Serve.
	SealingKeyUnproven bool

	started   time.Time
	startOnce sync.Once
	wg        sync.WaitGroup
	// panics counts the requests that panicked (recover.go).
	panics atomic.Uint64
	// panicked is why a state-changing request's panic stopped the
	// runner's state changes until a restart (recover.go); nil before.
	panicked atomic.Pointer[string]
	// loadFailed is why LoadListedShares loaded no key because of a mark
	// log error; nil otherwise. HEALTH then reports not ready, and imports
	// are refused (loadRefusal), until a restart.
	loadFailed atomic.Pointer[string]
	// noShares is why LoadListedShares found no readable share record
	// although the store lists some, or the mark log vouches for a set
	// that is not empty; nil otherwise. HEALTH then reports not ready.
	// With no record listed, an import clears it: it records a new set.
	// With records listed (noSharesListed), imports are refused
	// (loadRefusal) until a restart.
	noShares atomic.Pointer[string]
	// noSharesListed: the start that latched noShares saw share records
	// listed that it did not load. An import then would write a set
	// without them, so imports are refused (loadRefusal) until a restart.
	noSharesListed atomic.Bool
	// listedShares is the keys of the share names the start listed, when
	// it latched loadFailed or noSharesListed for a share set reason; nil
	// otherwise. A batch that imports every one of them replaces the
	// stored set and is taken (batchLoadRefusal). Set before Serve, read
	// under shareSetMu.
	listedShares map[backend.Pubkey]bool
	// copyFailed is why the last state copy refresh failed; nil after one
	// that succeeded (SetStateCopyFailed).
	copyFailed atomic.Pointer[string]
	// panicHook, tests only, runs before each request is served.
	panicHook func(wire.Frame)
	// lostLogged: the loss of the mark log is in the log (lostRefusal).
	lostLogged atomic.Bool
	// blocked holds validators whose import raised the mark log but whose
	// interchange maxima the core did not take: they sign nothing until a
	// restart, which reads the raised mark.
	blockedMu sync.Mutex
	blocked   map[backend.Pubkey]bool
	// admitting holds the validators whose share addShareOf is adding now:
	// one share per validator at a time (SSI-STORAGE-01). Each also holds a
	// max_keys slot until its import ends (SIAC-01, checkSlots).
	admitMu   sync.Mutex
	admitting map[backend.Pubkey]bool
	// shareHash is the sha256 of each stored share record this runner
	// loaded or wrote, nil without a mark log (putShare). shareSetMu
	// orders share writes.
	shareSetMu sync.Mutex
	shareHash  map[backend.Pubkey][32]byte
	// shareWritesStopped: a share write failed and so did the log record
	// that drops its set. Share writes stop until a restart.
	shareWritesStopped bool
	// cut is a batch import that did not complete and whose records may
	// be stored (importbatch.go); nil if none. shareSetMu guards it.
	cut *batchCut
	// attestOnlyLimit and signingLimit count the fresh attestations of
	// attest-only and of signing clients, each role on its own (limit.go);
	// limitNow, if set, is their clock (tests).
	attestOnlyLimit, signingLimit attestLimit
	limitNow                      func() time.Time

	// Limits bounds connections, handshakes and large frame bytes
	// (limits.go); the zero value has the defaults.
	Limits Limits
	// conns, handshakes and inflight count what the limits bound, over
	// every listener of the server.
	conns, handshakes, inflight gauge
	// addrHandshakes counts handshakes per source IP address.
	addrHandshakes addrGauge
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
	// SourceFloor: the import came without vote history, and the key signs
	// no vote with a source below this epoch, the restart floor epoch at the
	// import (state.Hooks.ImportFloor, SLBOUND-01). A restart sets it again.
	// The host stores the record; the mark log's share set vouches for it
	// (LoadListedShares), so an older record with a lower floor or none
	// loads every key with a fresh floor instead.
	SourceFloor uint64 `json:"source_floor,omitempty"`
	// Batch tags the records of one batch import (importbatch.go), so a
	// start can leave out the records of a batch that did not complete.
	Batch []byte `json:"batch,omitempty"`
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

// ProveSealingKey checks a sealing key that came from a stored blob
// (platform.Platform.SealingKeyStored, AWS-KMS-02) against the stored
// shares of names (from ListShares): it needs at least one, and every one
// must unseal under the key. The host can put any object under shares/
// next to the blob, and a share that does not open means the blob or the
// share is not this runner's, so the start stops rather than seal new
// shares under a key someone else may know. That includes a share of
// this signer that does not open for another reason: one left from an
// earlier life of the mark log (sealed under an older log_id) or restored
// from another signer by mistake. LoadListedShares would log and skip it;
// here it stops the start, the error names it, and the operator removes
// it from shares/ before the restart. On success SealingKeyUnproven is
// cleared. Call it before Serve, and only when the image check lets the
// shares load.
//
// The check has a limit. A key admin who made the blob before the key
// policy was locked knows the key, can seal a share under it and, before
// the lock, a mark log record too: such a blob passes, and every later
// share is sealed under a key the admin holds. Only the deploy rule
// prevents that (create the key with its final, locked policy,
// platform-aws/deploy/README.md); the runner cannot check it.
func (s *Server) ProveSealingKey(keys []string) error {
	if err := s.checkLogID(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("the sealing key came from the store, but no share is listed now: " +
			"restart, and the platform makes a new key for an empty store")
	}
	var bad []string
	for _, k := range keys {
		pk, err := sharePubkey(k)
		if err != nil {
			bad = append(bad, k)
			continue
		}
		blob, err := s.Platform.Store.Get(k)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		plain, err := s.Platform.Sealer.Unseal(blob, s.shareAAD(pk))
		clear(plain)
		if err != nil {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("the stored sealing key opens %d of %d stored shares; %s did not open. "+
			"A sealing key that does not open every stored share may be one the key admin made before the key policy was locked (AWS-KMS-02), "+
			"so this runner seals nothing under it. Remove what does not belong under shares/ on the host, or, if no share opens, "+
			"move the sealing blob aside too, and restart", len(keys)-len(bad), len(keys), strings.Join(bad, ", "))
	}
	s.SealingKeyUnproven = false
	return nil
}

// SetStateCopyFailed records the result of a state copy refresh: an error
// makes HEALTH report not ready with it, nil clears it.
func (s *Server) SetStateCopyFailed(err error) {
	if err == nil {
		s.copyFailed.Store(nil)
		return
	}
	why := "state copy refresh failed: " + err.Error()
	s.copyFailed.Store(&why)
}

// shareNames lists the store names of pks for an error, at most 16.
func shareNames(pks []backend.Pubkey) string {
	var names []string
	for i, pk := range pks {
		if i == 16 {
			names = append(names, fmt.Sprintf("and %d more", len(pks)-i))
			break
		}
		names = append(names, shareKey(pk))
	}
	return strings.Join(names, ", ")
}

// failLoad latches err as the reason no key loaded and returns it.
func (s *Server) failLoad(err error) error {
	why := "no key loaded: " + err.Error()
	s.loadFailed.Store(&why)
	return err
}

// sharePubkey reads the public key from a share's store name. Only the
// name shareKey gives counts: lowercase hex, so one key has one name.
func sharePubkey(k string) (backend.Pubkey, error) {
	var pk backend.Pubkey
	b, err := hex.DecodeString(strings.TrimPrefix(k, "shares/"))
	if err != nil || len(b) != len(pk) {
		return pk, fmt.Errorf("%s: not a share name", k)
	}
	copy(pk[:], b)
	if shareKey(pk) != k {
		return pk, fmt.Errorf("%s: not a share name", k)
	}
	return pk, nil
}

// LoadListedShares unseals the shares of names (from ListShares) and loads
// them into the signer. It returns how many loaded; a share that fails
// stays unloaded and is logged. A share sealed under another setup or
// another log_id does not unseal.
//
// With a mark log the stored records must be a set the log vouches for
// (markstore.ShareSet): the root of the records that unseal and parse is
// the newest record's current or pending root. Before that check it leaves
// out the records of a batch import that did not complete, if the rest is
// vouched (findCut, importbatch.go). Else the host replayed, hid,
// changed or added a record, and the runner cannot tell which: it loads no
// key, writes nothing and names the stored records, so the operator
// removes what should not be there. A store that holds no readable record
// of a set that is not empty loads no key and reports not ready; the log
// keeps vouching for the set it had, so the records put back load at the
// next start. If that store lists no record at all (the state is lost, or
// the operator removed every share), an import goes through and records
// a new set over the old one. A log with no share set yet (written by an image without
// share sets) resets once: every key loads without history and with a
// source floor of at least the restart floor epoch now, the bounds of an
// import without history, the log vouches for the rewritten records, then
// the runner writes them. If that log record fails, no key loads. Such a
// log with no readable record commits nothing: a store that lists no
// record is a new signer, ready for its first import; one that lists
// records it does not give reports not ready, and the records put back
// take the reset at the next start. A replayed record never gives a key
// history.
//
// A start that loads no key for one of these reasons latches load_failed
// in HEALTH, and HEALTH reports not ready. While the store listed records
// the start did not load, the runner refuses imports (loadRefusal) until
// a restart: an import would record a set without the stored records,
// and the log would never vouch for them again. One import is taken: a
// batch that holds every share the start listed (batchLoadRefusal). It
// replaces the stored records, so none is left out of the new set. The
// decision is the start's listing, not a later one.
func (s *Server) LoadListedShares(keys []string) (int, error) {
	if err := s.checkLogID(); err != nil {
		return 0, s.failLoad(err)
	}
	var errs []error
	// The records that unseal and parse, and their blobs: the share set is
	// the set of records this runner can read. A blob that does not unseal
	// never loads and counts on neither side of the vouch check.
	recs := map[backend.Pubkey]*shareRecord{}
	hashes := map[backend.Pubkey][32]byte{}
	var pks []backend.Pubkey
	// listed: the keys of every share name, readable or not. A batch that
	// imports all of them replaces the stored set (batchLoadRefusal).
	listed := map[backend.Pubkey]bool{}
	defer func() {
		for _, r := range recs {
			clear(r.Secret)
		}
	}()
	// In name order, as the file store lists them: with more shares stored
	// than the core holds, every start loads the same ones.
	for _, k := range slices.Sorted(slices.Values(keys)) {
		pk, err := sharePubkey(k)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, seen := recs[pk]; seen {
			continue
		}
		listed[pk] = true
		blob, err := s.Platform.Store.Get(k)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue
		}
		plain, err := s.Platform.Sealer.Unseal(blob, s.shareAAD(pk))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: unseal: %w (it never loads under this setup and log; remove the object)", k, err))
			continue
		}
		rec, err := parseShareRecord(plain)
		clear(plain)
		if err != nil || rec.Pubkey != pk || len(rec.Secret) != 32 {
			clear(rec.Secret)
			errs = append(errs, fmt.Errorf("%s: bad record (it never loads; remove the object)", k))
			continue
		}
		recs[pk], hashes[pk] = &rec, sha256.Sum256(blob)
		pks = append(pks, pk)
	}
	set, committed := s.Hooks.ShareSet()
	var cut *batchCut
	if committed && !set.Vouches(markstore.ShareSetRoot(hashes)) {
		// A batch that did not complete: its records leave the set.
		if cut = findCut(set, recs, hashes); cut != nil {
			for pk := range cut.keys {
				clear(recs[pk].Secret)
				delete(recs, pk)
				delete(hashes, pk)
			}
			pks = slices.DeleteFunc(pks, func(pk backend.Pubkey) bool { return cut.keys[pk] })
			s.Log.Warn("stored share records of a batch import that did not complete: they stay out and their keys do not load; import them again",
				"records", len(cut.keys))
		}
	}
	reset := committed && !set.Vouches(markstore.ShareSetRoot(hashes))
	// hidden: the store holds no readable record, and the log vouches for
	// a set that is not empty, or has no share set yet. The commitment
	// stays as the log has it.
	hidden := false
	if reset && set != nil {
		if len(pks) > 0 {
			s.listedShares = listed
			return 0, errors.Join(append(errs, s.failLoad(fmt.Errorf("the stored share records are not the set the mark log vouches for, so a record was replaced, hidden or added "+
				"(such as the share of an import that failed). Stored: %s. Remove the objects that should not be there, or put back the ones that are missing, and restart; "+
				"or import every listed share again in one batch, which replaces the stored records; or remove every share record and restart, then import the shares again. "+
				"Other imports are refused until then",
				shareNames(pks))))...)
		}
		why := "no key loaded: the mark log vouches for a share set that is not empty, and the store lists no share record. " +
			"Put the records back and restart, or import the shares again"
		if len(keys) > 0 {
			why = "no key loaded: the mark log vouches for a share set that is not empty, and the store lists share records but holds no readable share record. " +
				"Put the records back and restart, or import every listed share again in one batch, or remove every share record and restart, then import the shares again; other imports are refused until then"
			s.noSharesListed.Store(true)
			s.listedShares = listed
		}
		s.noShares.Store(&why)
		s.Log.Warn(why)
		reset, hidden = false, true
	}
	if committed && set == nil && len(hashes) == 0 {
		// A log with no share set and no readable record: the commitment
		// stays nil, which vouches for the empty set already, so records
		// that show up later take the one-time reset rather than failing
		// against a committed empty set. A store that lists no record is
		// a new signer. One that lists records it does not give is not:
		// the records are hidden, or the objects are not records of this
		// signer.
		hidden = true
		if len(keys) > 0 {
			why := "no key loaded: the mark log holds no share set yet, and the store lists share records but holds no readable share record. " +
				"Put the records back and restart, or import every listed share again in one batch, or remove every share record and restart, then import the shares again; other imports are refused until then"
			s.noSharesListed.Store(true)
			s.listedShares = listed
			s.noShares.Store(&why)
			s.Log.Warn(why)
		}
	}
	blobs := map[backend.Pubkey][]byte{}
	if reset {
		var resetFloor uint64
		f, on, err := s.Hooks.ImportFloor()
		if err != nil {
			return 0, s.failLoad(fmt.Errorf("stored share records the mark log does not vouch for: %w", err))
		}
		if on {
			resetFloor = f
		}
		// Expected once: the log was written by an image without share
		// sets.
		s.Log.Warn("the mark log holds no share set yet (first start of this image on it): every key loads without history, with a fresh source floor, once",
			"records", len(recs), "floor_epoch", resetFloor)
		// The log vouches only for the rewritten records. One the reset
		// could not seal stays out, so the next start finds it outside
		// the vouched set and loads no key until it is removed.
		hashes = map[backend.Pubkey][32]byte{}
		for _, pk := range pks {
			rec := recs[pk]
			rec.History, rec.SourceFloor = false, max(rec.SourceFloor, resetFloor)
			blob, err := s.sealRecord(*rec)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", shareKey(pk), err))
				continue
			}
			blobs[pk], hashes[pk] = blob, sha256.Sum256(blob)
		}
	}
	if committed {
		cur := &markstore.ShareSet{Current: markstore.ShareSetRoot(hashes)}
		if reset {
			// Before the rewrites: if this record fails, the log still
			// vouches for the old set, so no key loads, and a start cut
			// after it finds records the log does not vouch for and
			// resets again.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := s.Hooks.RecordShareSet(ctx, cur)
			cancel()
			if err != nil {
				return 0, errors.Join(append(errs, s.failLoad(fmt.Errorf("the mark log does not vouch for the reset share records, no key loaded: %w", err)))...)
			}
		} else if !hidden {
			s.Hooks.SetShareSet(cur)
		}
		// hidden: the log keeps the set it vouches for. The next record of
		// any kind (a keep-alive, a config activation) carries that set on,
		// so the records put back load at the next start. With records
		// listed, imports are refused (loadRefusal) but a batch of every
		// listed share (batchLoadRefusal); with none listed, an import
		// records a new set over it (putShare, putShares).
		s.shareSetMu.Lock()
		s.shareHash, s.cut = hashes, cut
		s.shareSetMu.Unlock()
	}
	loaded := 0
	for _, pk := range pks {
		k, rec := shareKey(pk), recs[pk]
		if blob, ok := blobs[pk]; ok {
			if err := s.Platform.Store.Put(k, blob); err != nil {
				s.Log.Warn("share record not written back: the key loads with the fresh floor, and the next start loads no key and names it (the mark log vouches for the rewritten record only); then import every listed share again in one batch, or remove every share record, restart and import the shares again",
					"pubkey", pk.String()[:18], "err", err)
			}
		}
		var sec [32]byte
		copy(sec[:], rec.Secret)
		if err := s.checkWholeKey(pk, &sec); err != nil {
			clear(sec[:])
			errs = append(errs, fmt.Errorf("%s: %w; the record stays in the store and is not loaded: remove it", k, err))
			continue
		}
		s.Hooks.ExpectRecord(pk)
		if rec.SourceFloor != 0 && !rec.History {
			s.Hooks.NoteImportFloor(pk, rec.SourceFloor)
		}
		_, err := s.Signer.AddValidator(pk, sec, rec.Index, nil)
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

// putShare stores pk's sealed record blob. With a mark log the write goes
// under the share set commitment: first a log record that vouches for the
// set before the write and the set after it (current and pending root),
// then the store write. A start after a cut between the two finds one of
// the two sets and loads it; the set before holds no record of the key,
// so nothing with more history than the set after. Share writes go one at
// a time.
func (s *Server) putShare(pk backend.Pubkey, blob []byte) error {
	if _, committed := s.Hooks.ShareSet(); !committed {
		return s.Platform.Store.Put(shareKey(pk), blob)
	}
	s.shareSetMu.Lock()
	defer s.shareSetMu.Unlock()
	if s.shareWritesStopped {
		return errors.New("a failed share write is still vouched in the mark log: no share write until a restart")
	}
	if err := s.loadRefusal(); err != nil {
		return err
	}
	// The set before. It leaves out the key's old record, which this
	// runner did not load and which may say the key has history: a write
	// that fails then leaves no set the log vouches for with it, and the
	// next start loads no key.
	prev := make(map[backend.Pubkey][32]byte, len(s.shareHash))
	for k, v := range s.shareHash {
		prev[k] = v
	}
	delete(prev, pk)
	next := make(map[backend.Pubkey][32]byte, len(prev)+1)
	for k, v := range prev {
		next[k] = v
	}
	next[pk] = sha256.Sum256(blob)
	before, pending := markstore.ShareSetRoot(prev), markstore.ShareSetRoot(next)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := s.Hooks.RecordShareSet(ctx, &markstore.ShareSet{Current: before, Pending: &pending})
	cancel()
	if err != nil {
		return fmt.Errorf("mark log share set: %w", err)
	}
	if err := s.Platform.Store.Put(shareKey(pk), blob); err != nil {
		// The write may have landed with its reply lost. Then the stored
		// set is the one after: keep it, so the next write names the set
		// the store holds and a start finds it vouched.
		if !s.landed(pk, next[pk]) {
			// Drop the set after from the log at once: the host keeps
			// the blob and could store it later. If that record fails
			// too, the log still vouches for the set after, so no share
			// write goes on until a restart.
			s.shareHash = prev
			s.Hooks.SetShareSet(&markstore.ShareSet{Current: before})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if rerr := s.Hooks.RecordShareSet(ctx, &markstore.ShareSet{Current: before}); rerr != nil {
				s.shareWritesStopped = true
				err = fmt.Errorf("%w; the mark log record that drops it failed too, no share write until a restart: %v", err, rerr)
			}
			cancel()
			return err
		}
	}
	s.shareHash = next
	s.Hooks.SetShareSet(&markstore.ShareSet{Current: pending})
	// A start with no record listed under a vouched set: this write
	// recorded the new set, the runner is ready.
	s.noShares.Store(nil)
	s.cut.drop(pk)
	return nil
}

// landed reports whether pk's stored record has hash h, reading it up to
// three times: a store that just failed a write may fail a read as well.
func (s *Server) landed(pk backend.Pubkey, h [32]byte) bool {
	for try := range 3 {
		if try > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		cur, err := s.Platform.Store.Get(shareKey(pk))
		if err == nil {
			return sha256.Sum256(cur) == h
		}
	}
	return false
}

// Serve accepts connections until ctx ends or the listener fails.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	// The first Serve sets the start time; the others run at the same time.
	s.startOnce.Do(func() { s.started = time.Now() })
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
		// certificate yet holds one of its slots (ATTEST-BUDGET-01).
		// One IP address holds at most a part of them.
		addr, perAddr := addrOf(c), s.Limits.maxHandshakesPerAddr()
		if !s.addrHandshakes.take(addr, perAddr) {
			if n := s.handshakesNote.note(); n > 0 {
				s.Log.Warn("refused: handshake budget of one address", "max_handshakes_per_addr", perAddr, "refused_since_start", n)
			}
			return
		}
		if !s.handshakes.take(1, s.Limits.maxHandshakes()) {
			s.addrHandshakes.give(addr, perAddr)
			if n := s.handshakesNote.note(); n > 0 {
				s.Log.Warn("refused: handshake budget", "max_handshakes", s.Limits.maxHandshakes(), "refused_since_start", n)
			}
			return
		}
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		s.handshakes.give(1)
		s.addrHandshakes.give(addr, perAddr)
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
			if f.Type == wireadmin.TypeImportShare || f.Type == wireadmin.TypeImportSealed || f.Type == wireadmin.TypeImportBatch {
				clear(f.Payload)
			}
			s.Log.Warn("refused and closed: client certificate", "remote", c.RemoteAddr().String(), "type", f.Type.String(),
				"cert_sha256", hex.EncodeToString(cl.cert[:8]), "err", err)
			_ = c.SetWriteDeadline(time.Now().Add(frameTimeout))
			_ = wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: wire.EncodeError(err)})
			return
		}
		payload, ok := s.answer(ctx, f, cl)
		if !ok {
			return
		}
		// A peer that stops reading loses the connection after
		// frameTimeout, not holds the frame's bytes and its slot
		// (TEE-BUDGET-02).
		_ = c.SetWriteDeadline(time.Now().Add(frameTimeout))
		if err := wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: payload}); err != nil {
			s.Log.Warn("write", "err", err)
			return
		}
	}
}

func (s *Server) dispatch(ctx context.Context, f wire.Frame) ([]byte, error) {
	switch f.Type {
	case wire.TypeHealth, wire.TypePublicKeys, wire.TypeAttest, wire.TypeIdentity:
	default:
		// Another runner instance took the mark log over (RBRLOG-03), or a
		// state-changing request panicked (recover.go): this one signs,
		// and imports nothing, also messages that write no
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
	case wireadmin.TypeImportShare, wireadmin.TypeImportSealed:
		// A start that loaded no key for a share set reason: an import
		// would record a set without the stored records (loadRefusal). A
		// batch is checked against its keys (storeBatch).
		if err := s.loadRefusal(); err != nil {
			clear(f.Payload)
			return nil, err
		}
	}
	switch f.Type {
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
	case wireadmin.TypeImportBatch:
		return s.importBatch(f.Payload)
	case wireadmin.TypeConfigUpdate:
		return s.configUpdate(ctx, f.Payload)
	}
	// IMPORT_SHARE is served only by debug builds (plainimport.go); a
	// release build answers it as an unknown type (noplainimport.go).
	return s.otherMessage(f)
}

// loadRefusal is the refusal of an import while a start that loaded no
// key is latched with share records listed that it did not load
// (loadFailed, or noShares with noSharesListed), nil otherwise. An import
// then would write a share set without the stored records, and the log
// would never vouch for them again (marklog.md, "Share set"). A start
// that listed no record takes imports: the import records a new set.
func (s *Server) loadRefusal() error {
	if why := s.loadWhy(); why != nil {
		return backend.Refused(backend.StatusNotReady, "%s", *why)
	}
	return nil
}

// imageRefusal is the image check (imagegate.go) now, nil without a
// gate. A request that signs or stores a share runs it again after its
// waits, as dispatch's check may predate an update that drops this image
// (SETUP-IMAGE-01).
func (s *Server) imageRefusal() error {
	if s.Image == nil {
		return nil
	}
	return s.Image.Check(s.Updates)
}

// loadWhy is the latched reason of loadRefusal, nil without one.
func (s *Server) loadWhy() *string {
	why := s.loadFailed.Load()
	if why == nil && s.noSharesListed.Load() {
		why = s.noShares.Load()
	}
	return why
}

// batchLoadRefusal is loadRefusal for a batch of keys. A batch that holds
// the key of every share name the start listed (listedShares) is taken:
// it writes a record for each of them, so the new set leaves no stored
// record out, which is what the refusal is for. The set before is the
// empty root: a start that latched the refusal set no share hash. The
// caller holds shareSetMu.
func (s *Server) batchLoadRefusal(batch map[backend.Pubkey]bool) error {
	why := s.loadWhy()
	if why == nil {
		return nil
	}
	if s.listedShares == nil {
		return backend.Refused(backend.StatusNotReady, "%s", *why)
	}
	var missing []string
	for pk := range s.listedShares {
		if !batch[pk] {
			missing = append(missing, shareKey(pk))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return backend.Refused(backend.StatusNotReady, "a batch that imports every share the start listed replaces the stored records and is taken; this one leaves out %d of %d (%s). %s",
		len(missing), len(s.listedShares), missing[0], *why)
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
		s.Log.Error("mark log lost to another runner instance: this runner signs and imports nothing until it is replaced",
			"err", lost, "record", s.Hooks.MarkLogStatus())
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
		return backend.Signature{}, backend.Refused(backend.StatusStorage, "the import's bounds (interchange maxima or import floor) did not reach the core; restart the runner")
	}
	kind := req.Message.Kind().String()
	if a, ok := req.Message.(*backend.AttestationData); ok && s.Hooks != nil {
		if f, on := s.Hooks.SourceFloor(req.Pubkey); on && a.Source.Epoch < f {
			err := backend.Refused(backend.StatusSlashSource,
				"attestation source %d below the source floor epoch %d: no import carried this validator's vote history, and the mark log held no vote when this runner started on it or the share came in later", a.Source.Epoch, f)
			s.Log.Info("refused", "kind", kind, "pubkey", req.Pubkey.String()[:18], "msg", describe(req.Message), "err", err)
			return backend.Signature{}, err
		}
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
		// The request may have waited past an update that drops this
		// image since dispatch checked it; g covers the time from here.
		if err := s.imageRefusal(); err != nil {
			return backend.Signature{}, err
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
				kind := "restart"
				if lf, ok := s.Hooks.LoadFloor(req.Pubkey); ok && lf == f {
					kind = "import"
				}
				r.Detail += fmt.Sprintf(" (at or below %s floor epoch %d)", kind, f)
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
//
// One share per validator is added at a time, and the duplicate check
// looks at the core after the signer's list: the list may be older than a
// share of pk that another request loaded since. A second share of a
// validator is refused before it is stored, so it never replaces the
// stored record of the share that loaded (SSI-STORAGE-01).
func (s *Server) addShare(pk backend.Pubkey, secret *[32]byte, index uint64, interchange *backend.Watermark, how string) (backend.ValidatorKey, error) {
	if err := s.reserve(pk); err != nil {
		return backend.ValidatorKey{}, err
	}
	defer s.release(pk)
	if err := s.checkShare(pk, secret, s.Signer.Keys()); err != nil {
		return backend.ValidatorKey{}, err
	}
	if _, err := s.Signer.State(pk); err == nil {
		return backend.ValidatorKey{}, &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "validator already loaded"}
	}
	// Interchange maxima (an EIP-3076 import) raise
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
	rec := shareRecord{Pubkey: pk, Secret: secret[:], Index: index,
		History: interchange != nil && interchange.HasAttestation}
	if !rec.History && s.Hooks != nil {
		// No vote history: the key may have voted elsewhere up to now, past
		// the log's gate (SLBOUND-01). Gate it from now on, before it can
		// sign; the record keeps the floor for a restart.
		f, on, err := s.Hooks.ImportFloor()
		if err != nil {
			return backend.ValidatorKey{}, backend.Refused(backend.StatusPlatform, "%v", err)
		}
		if on {
			rec.SourceFloor = f
			s.Hooks.NoteImportFloor(pk, f)
		}
	}
	// Every key added now, with history or not, gets the floor's block and
	// target bounds in its own mark (loadShare): it may have proposed
	// elsewhere after its interchange was exported.
	loadFloor := rec.SourceFloor
	if loadFloor == 0 && s.Hooks != nil {
		f, on, err := s.Hooks.ImportFloor()
		if err != nil {
			return backend.ValidatorKey{}, backend.Refused(backend.StatusPlatform, "%v", err)
		}
		if on {
			loadFloor = f
		}
	}
	blob, err := s.sealRecord(rec)
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	if err := s.imageRefusal(); err != nil {
		return backend.ValidatorKey{}, err
	}
	if err := s.putShare(pk, blob); err != nil {
		return backend.ValidatorKey{}, backend.Refused(backend.StatusPlatform, "store share: %v", err)
	}
	return s.loadShare(pk, secret, index, interchange, loadFloor, how)
}

// reserve marks pk as being added. Under a setup it also holds a max_keys
// slot for pk until release: the validators stored, loaded and being
// added stay within max_keys together, so two imports cannot both take
// the last slot and every stored share loads at the next start (SIAC-01).
// A stored share that failed to load keeps its slot.
func (s *Server) reserve(pk backend.Pubkey) error {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	if s.admitting[pk] {
		return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "another request is adding this validator"}
	}
	if s.Updates != nil {
		if err := s.checkSlots(pk); err != nil {
			return err
		}
	}
	if s.admitting == nil {
		s.admitting = map[backend.Pubkey]bool{}
	}
	s.admitting[pk] = true
	return nil
}

// checkSlots refuses pks when the validators stored, loaded or being added,
// with pks, are more than the setup's max_keys. The caller holds admitMu.
func (s *Server) checkSlots(pks ...backend.Pubkey) error {
	names, err := ListShares(s.Platform.Store)
	if err != nil {
		return backend.Refused(backend.StatusStorage, "stored shares: %v", err)
	}
	held := map[string]bool{}
	for _, pk := range pks {
		held[shareKey(pk)] = true
	}
	for _, n := range names {
		held[n] = true
	}
	for _, k := range s.Signer.Keys() {
		held[shareKey(k.Pubkey)] = true
	}
	for a := range s.admitting {
		held[shareKey(a)] = true
	}
	if n := s.Updates.opt.Setup.MaxKeys; uint64(len(held)) > uint64(n) {
		return backend.Refused(backend.StatusNoMem, "this runner stores, holds or is adding %d keys with this one, its setup's max_keys is %d", len(held), n)
	}
	return nil
}

func (s *Server) release(pk backend.Pubkey) {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	delete(s.admitting, pk)
}

// checkMaxima refuses interchange maxima above the clock epoch plus the
// restart floor's margin (max_epochs_ahead + 1). No honest signer signed
// past that, and maxima above it raise the mark log and stop every key of
// this runner from signing until the clock gets there.
func (s *Server) checkMaxima(wm *backend.Watermark) error {
	if wm == nil {
		return nil
	}
	t, err := s.Platform.Clock.Now()
	if err != nil {
		return backend.Refused(backend.StatusPlatform, "the interchange maxima check needs the clock: %v", err)
	}
	cfg := s.Signer.Config()
	now := s.Signer.EpochAt(uint64(t.Unix()))
	horizon := now + state.DefaultFloorMargin(cfg)
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
// validator or share already loaded (keys is the signer's list), a runner at its
// setup's max_keys, a bad secret or a key that does not fit the setup's
// signing_mode (checkWholeKeyOf).
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
	got, err := core.PubkeyOf(*secret)
	if err != nil {
		return &backend.RefusedError{Code: backend.StatusBadKey, Detail: "share secret"}
	}
	for _, k := range keys {
		if k.SharePubkey == got {
			return &backend.RefusedError{Code: backend.StatusDuplicate, Detail: "this share is loaded under another pubkey"}
		}
	}
	return s.checkWholeKeyOf(pk, got)
}

// checkWholeKey checks a key against the setup's signing_mode. Under
// signing_mode = single it refuses a key whose public key is not the
// validator key pk: such a signer holds whole keys only. Under
// signing_mode = threshold it refuses a key whose public key is pk: such
// a signer holds shares of splits only, and a share equal to the whole
// key comes from a degenerate split (for an honest one the chance is
// about 1 in r). It runs wherever a key is stored or loaded: the sealed
// import, the debug plain import and a restart.
func (s *Server) checkWholeKey(pk backend.Pubkey, secret *[32]byte) error {
	if s.Updates == nil {
		return nil
	}
	got, err := core.PubkeyOf(*secret)
	if err != nil {
		return backend.Refused(backend.StatusBadKey, "share secret")
	}
	return s.checkWholeKeyOf(pk, got)
}

// checkWholeKeyOf is checkWholeKey for a key whose public key got is
// known already. It refuses every key under a signing_mode it does not
// know.
func (s *Server) checkWholeKeyOf(pk, got backend.Pubkey) error {
	if s.Updates == nil {
		return nil
	}
	switch mode := s.Updates.SetupWire().SigningMode; mode {
	case setupwire.SigningModeSingle:
		if got != pk {
			return backend.Refused(backend.StatusBadKey, "the setup says signing_mode = single, so this signer holds whole keys only: the key is not the validator key %s",
				pk.String()[:18])
		}
	case setupwire.SigningModeThreshold:
		if got == pk {
			return backend.Refused(backend.StatusBadKey, "the setup says signing_mode = threshold, so this signer holds shares of splits only: the key is the whole validator key %s",
				pk.String()[:18])
		}
	default:
		return backend.Refused(backend.StatusBadKey, "signing_mode %d: unknown, this signer takes no key", mode)
	}
	return nil
}

// sealRecord seals a share record for the store.
func (s *Server) sealRecord(rec shareRecord) ([]byte, error) {
	if s.SealingKeyUnproven {
		return nil, backend.Refused(backend.StatusPlatform,
			"seal share: the sealing key came from the store and the stored shares were not checked at this start (the image check held them); restart once it passes")
	}
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
//
// floor is the restart floor epoch at the import. With the device mark the
// core starts a key added now from the device's bounds, which hold only
// what keys here signed, and the key may have proposed elsewhere up to
// that epoch. The floor's block and target bounds (source 0: the source
// bound is SourceFloor's, and the device's stays as it is) go into the
// watermark the core imports with the key, under the same lock hold, so
// the key never signs without them: blocks, PTC votes and envelopes up to
// the last slot of that epoch, and targets up to it.
func (s *Server) loadShare(pk backend.Pubkey, secret *[32]byte, index uint64, interchange *backend.Watermark, floor uint64, how string) (backend.ValidatorKey, error) {
	imp := interchange
	if floor != 0 {
		fw := state.FloorWatermark(s.Signer.Config(), floor)
		fw.SourceEpoch = 0
		if interchange != nil {
			fw = state.Merge(*interchange, fw)
		}
		imp = &fw
		s.Hooks.NoteLoadFloor(pk, floor)
	}
	k, err := s.Signer.AddValidator(pk, *secret, index, imp)
	if err != nil {
		// A duplicate loaded nothing: the validator keeps its share and
		// its bounds (APSTATE-02).
		if imp != nil && s.Hooks.Mode().MarkLog && backend.StatusOf(err) != backend.StatusDuplicate {
			// The validator may be loaded under the core's older device
			// mark (the core refuses it as unready); the log holds the
			// raised one. Keep it from signing until a restart.
			s.blockedMu.Lock()
			if s.blocked == nil {
				s.blocked = map[backend.Pubkey]bool{}
			}
			s.blocked[pk] = true
			s.blockedMu.Unlock()
			s.Log.Error("imported share blocked until a restart: the core did not take the import's bounds", "pubkey", pk.String()[:18], "err", err)
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
		Record:       s.Hooks.MarkLogStatus(),

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
	if s.lostRefusal() != nil {
		h.Ready, h.MarkLogLost = false, s.Hooks.MarkLogLost().Error()
	} else if err := s.Hooks.MarkLogStopped(); err != nil {
		h.Ready, h.MarkLogLost = false, "mark log stopped: store lock lost: "+err.Error()
	} else if err := s.Hooks.MarkLogUnchecked(); err != nil {
		h.Ready, h.MarkLogLost = false, "mark log paused: store lock unchecked: "+err.Error()
	}
	if why := s.panicked.Load(); why != nil {
		h.Ready, h.RequestPanic = false, *why
	}
	if why := s.loadFailed.Load(); why != nil {
		h.Ready, h.LoadFailed = false, *why
	} else if why := s.noShares.Load(); why != nil {
		h.Ready, h.LoadFailed = false, *why
	}
	if why := s.copyFailed.Load(); why != nil {
		h.Ready, h.StateCopyFailed = false, *why
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
	out := &backend.ClockNTS{
		Protocol: string(s.Protocol),
		Quorum:   s.Quorum, Refused: s.Refused, BoundNowMS: ms(s.BoundNow), MaxBoundMS: ms(s.MaxBound), OffsetFromHostMS: ms(s.OffsetFromHost),
		Members: s.Members, QuorumAgeMS: ms(s.AgeOfQuorum), SampleAgeMS: ms(s.SampleAge), MaxSampleAgeMS: ms(s.MaxSampleAge),
		Refusals: s.Refusals,
		DriftPPM: s.DriftPPM, DriftErrPPM: s.DriftErrPPM, DriftBaselineS: s.DriftBaseline.Seconds(), RhoViolations: s.RhoViolations,
		CoarseDiffMS: ms(s.CoarseDiff), FallbacksCapped: s.FallbacksCapped,
	}
	for _, p := range s.Peers {
		age := -1.0
		if p.LastAnswerAge >= 0 {
			age = ms(p.LastAnswerAge)
		}
		c := s.Operators[p.Operator]
		out.Operators = append(out.Operators, backend.ClockNTSOperator{
			Operator: p.Operator, Host: p.Host, Active: p.Active, Queries: p.Queries, Answers: p.Answers, Losses: p.Losses, Wide: p.Wide,
			KEOK: p.KEOK, KEFail: p.KEFail, LastAnswerAgeMS: age, Off: p.Off, LastError: p.LastError,
			Fallbacks: c.Fallbacks, Bursts: c.Bursts, Rates: c.Rates, Handovers: c.Handovers, FailedHandovers: c.FailedHandovers,
			FallbackKE: c.FallbackKE,
		})
	}
	for _, c := range s.Coarse {
		age := -1.0
		if c.LastAnswerAge >= 0 {
			age = ms(c.LastAnswerAge)
		}
		out.Coarse = append(out.Coarse, backend.ClockNTSCoarse{Source: c.Name, Queries: c.Queries, Answers: c.Answers,
			Failures: c.Failures, LastAnswerAgeMS: age, LastDiffMS: ms(c.LastDiff), LastError: c.LastError})
	}
	return out
}
