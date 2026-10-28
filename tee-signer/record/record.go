// Package record is the clone guard: an external single-writer record per
// node that a runner must advance before it signs into a new epoch.
//
// The threat: a host starts two runners from the
// same measured image and feeds both the same sealed share. Both unseal it,
// both read the same clock, and each keeps its own slashing state, so
// together they can sign two different votes for one target. A local store
// cannot stop that, and neither can the restart floor.
//
// The record lives outside the host's reach (DynamoDB on AWS; a file for
// local tests) and only moves forward through conditional writes on a
// version number:
//
//   - Claim, at start: read the record, then write version+1 with a fresh
//     random owner ID. The epoch in the record is the highest epoch the
//     previous owner may have signed for; this runner refuses everything at
//     or below it (a third restart floor).
//   - Cover, before the core raises a commit-ahead watermark past the
//     epoch the record covers: write version+1 with the new epoch. If the
//     write fails because the version moved, another instance claimed the
//     record; this runner then refuses every new slashable signature.
//
// So for any epoch at most one instance signs: the old owner only up to
// what it covered before the claim, the new owner only above it.
//
// The record value is sealed with the platform sealer, bound to the key and
// the version, so a writer without the sealing key cannot forge one. It can
// still delete or replay old values; the deployment must make the record
// writable by the enclave alone (cloud/aws/README.md).
package record

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
)

var (
	// ErrNotFound: the record does not exist.
	ErrNotFound = errors.New("record: not found")
	// ErrConflict: a conditional write failed because the stored version
	// was not the expected one.
	ErrConflict = errors.New("record: conditional write failed (version changed)")
)

// Store is the external record. Implementations must be linearizable for a
// single key: a Put that returns nil happened after every Put it saw.
type Store interface {
	// Get returns the stored version and value, or ErrNotFound.
	Get(ctx context.Context, key string) (version uint64, value []byte, err error)
	// Put stores (next, value) if the stored version is prev, where prev 0
	// means the record must not exist yet. Otherwise it returns ErrConflict.
	Put(ctx context.Context, key string, prev, next uint64, value []byte) error
	String() string
}

// Sealer is platform.Sealer.
type Sealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Unseal(blob, aad []byte) ([]byte, error)
}

// Entry is the plaintext of one record value.
type Entry struct {
	Owner [16]byte // random per runner process
	Epoch uint64   // highest epoch the owner may have signed for
}

const magic = "SREC1"

func aad(key string, version uint64) []byte {
	b := []byte("signer-record-v1|" + key + "|")
	return binary.BigEndian.AppendUint64(b, version)
}

func encode(e Entry) []byte {
	b := append([]byte(magic), e.Owner[:]...)
	return binary.BigEndian.AppendUint64(b, e.Epoch)
}

func decode(b []byte) (Entry, error) {
	var e Entry
	if len(b) != len(magic)+16+8 || string(b[:len(magic)]) != magic {
		return e, errors.New("record: bad entry")
	}
	copy(e.Owner[:], b[len(magic):])
	e.Epoch = binary.BigEndian.Uint64(b[len(magic)+16:])
	return e, nil
}

// Guard holds the record for one runner process.
type Guard struct {
	store  Store
	key    string
	sealer Sealer
	ahead  uint64
	log    *slog.Logger

	// AllowCreate lets Claim create a missing record even when the node
	// already holds shares (operator override after losing the record).
	AllowCreate bool

	mu       sync.Mutex
	owner    [16]byte
	version  uint64 // version this process last wrote; 0 before Claim
	epoch    uint64 // highest epoch covered by the record
	prior    uint64
	hasPrior bool
	lost     error
}

// New returns a guard for key. ahead is added to each covered epoch, so a
// write is needed only every ahead+1 epochs (a clone then refuses that many
// more epochs).
func New(store Store, key string, sealer Sealer, ahead uint64, log *slog.Logger) (*Guard, error) {
	if store == nil || sealer == nil || key == "" {
		return nil, errors.New("record: store, sealer and key are required")
	}
	if log == nil {
		log = slog.Default()
	}
	g := &Guard{store: store, key: key, sealer: sealer, ahead: ahead, log: log}
	if _, err := rand.Read(g.owner[:]); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Guard) open(version uint64, value []byte) (Entry, error) {
	plain, err := g.sealer.Unseal(value, aad(g.key, version))
	if err != nil {
		return Entry{}, fmt.Errorf("record %s version %d does not unseal (forged or tampered): %w", g.key, version, err)
	}
	return decode(plain)
}

func (g *Guard) seal(version uint64, e Entry) ([]byte, error) {
	return g.sealer.Seal(encode(e), aad(g.key, version))
}

// Claim takes the record over for this process. Call it once at start,
// before any validator is loaded. expect says the node already holds
// shares, so a missing record means someone deleted it: Claim then fails
// unless AllowCreate is set.
func (g *Guard) Claim(ctx context.Context, expect bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.version != 0 {
		return errors.New("record: already claimed")
	}
	ver, val, err := g.store.Get(ctx, g.key)
	switch {
	case errors.Is(err, ErrNotFound):
		if expect && !g.AllowCreate {
			return fmt.Errorf("record %s is missing but this node holds shares: deleted? (refusing to start)", g.key)
		}
		ver = 0
	case err != nil:
		return fmt.Errorf("record %s: %w", g.key, err)
	default:
		e, err := g.open(ver, val)
		if err != nil {
			return err
		}
		g.prior, g.hasPrior, g.epoch = e.Epoch, true, e.Epoch
		g.log.Info("clone guard: previous record", "key", g.key, "version", ver,
			"previous_owner", hex.EncodeToString(e.Owner[:4]), "epoch", e.Epoch)
	}
	next := ver + 1
	blob, err := g.seal(next, Entry{Owner: g.owner, Epoch: g.epoch})
	if err != nil {
		return err
	}
	if err := g.store.Put(ctx, g.key, ver, next, blob); err != nil {
		return fmt.Errorf("record %s: claim: %w", g.key, err)
	}
	g.version = next
	g.log.Info("clone guard: claimed record", "store", g.store.String(), "key", g.key, "version", next,
		"owner", hex.EncodeToString(g.owner[:4]), "floor_epoch", g.epoch, "had_record", g.hasPrior)
	return nil
}

// Floor returns the epoch the previous owner may have signed up to, if a
// record existed at Claim. Everything at or below it must be refused.
func (g *Guard) Floor() (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.prior, g.hasPrior
}

// Cover makes the record cover epoch e before anything for e is signed.
// It writes only when e is past the covered epoch. It fails, and keeps
// failing, once another instance has claimed the record.
func (g *Guard) Cover(ctx context.Context, e uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lost != nil {
		return g.lost
	}
	if g.version == 0 {
		return errors.New("record: not claimed")
	}
	if e <= g.epoch {
		return nil
	}
	target := e
	if target <= math.MaxUint64-g.ahead {
		target += g.ahead
	}
	next := g.version + 1
	blob, err := g.seal(next, Entry{Owner: g.owner, Epoch: target})
	if err != nil {
		return err
	}
	err = g.store.Put(ctx, g.key, g.version, next, blob)
	if errors.Is(err, ErrConflict) {
		// A write whose reply was lost may have landed: then the record
		// is still ours with exactly what we tried to write.
		if v, val, gerr := g.store.Get(ctx, g.key); gerr == nil && v == next {
			if cur, oerr := g.open(v, val); oerr == nil && cur.Owner == g.owner && cur.Epoch == target {
				err = nil
			}
		}
	}
	switch {
	case errors.Is(err, ErrConflict):
		g.lost = fmt.Errorf("clone guard: record %s was claimed by another runner instance; this one signs nothing new", g.key)
		g.log.Error("clone guard: record taken over by another instance; refusing new slashable signatures",
			"key", g.key, "my_version", g.version, "owner", hex.EncodeToString(g.owner[:4]))
		return g.lost
	case err != nil:
		return fmt.Errorf("clone guard: cannot advance record %s: %w", g.key, err)
	}
	g.version, g.epoch = next, target
	return nil
}

// Status describes the guard for HEALTH and logs.
func (g *Guard) Status() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := fmt.Sprintf("%s key=%s owner=%s version=%d epoch=%d", g.store, g.key, hex.EncodeToString(g.owner[:4]), g.version, g.epoch)
	if g.lost != nil {
		s += " LOST"
	}
	return s
}

func (g *Guard) String() string { return g.Status() }
