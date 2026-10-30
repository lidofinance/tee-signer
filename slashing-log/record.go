package markstore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/markformat"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Record is one entry of a signer's mark log, magic SMARK1. Every record
// carries the full config state, so no record needs an earlier one for the
// config.
type Record struct {
	Setup       [32]byte          // setup_hash; zero on the flag path without a setup
	Signer      string            // the signer's name (its object name part)
	Version     uint64            // the version its object name carries
	PrevVersion uint64            // the record before it; 0 for the first
	PrevHash    [32]byte          // sha256 of the record before it
	LogID       [32]byte          // sha256 of the log's first record; zero in the first record itself
	Owner       [16]byte          // random per runner process
	KeyBlob     []byte            // the signing key's seed, wrapped by the platform's key release (platform.Keys)
	Mark        backend.Watermark // the device mark: nothing at or below it may be signed again
	Time        uint64            // unix seconds when written, from the runner's clock (the age check reads it)
	State       ConfigState       // the config state per group, and the pending order
	Copies      [4]BodyCopy       // the newest copy of each update body State names (bodyIndex)
	Target      *[32]byte         // a tombstone only: the setup_hash of the handover's target
	Exits       *ExitDay          // the day's exits; nil before the first
	// SourceGate is the source floor epoch of a log that held no vote when
	// the runner started on it (state.Hooks): a validator without imported
	// history of its own signs no vote with a source below it. nil: no
	// gate (RBRLOG-02).
	SourceGate *uint64
	Sig        [ed25519.SignatureSize]byte

	body []byte // the signed bytes, as read (Parse)
}

// ConfigState is the config state a record carries (section 6): per group
// the active version and the hash of the update that set it, and the
// pending update; and the pending order (phase 2).
type ConfigState struct {
	Locked GroupState
	Open   GroupState
	Order  *Order // nil: none
}

// GroupState is one config group's state.
type GroupState struct {
	Version uint64   // active version; 0 is the setup's
	Hash    [32]byte // the update that set it; for version 0 the setup's group hash
	Pending *Pending // nil: none
}

// Pending is an update that waits for its effective activation time.
type Pending struct {
	Version     uint64
	Hash        [32]byte
	EffectiveAt uint64 // unix seconds: the later of activate_at and arrival + wait
}

// OrderKind is the kind of a pending order (section 10, phase 2). The
// handover order is the only kind: Parse and SetState refuse every other,
// so a record of an earlier build with a key generation order (kind 2)
// does not read.
type OrderKind uint8

const OrderHandover OrderKind = 1

// Order is a pending handover order (phase 2).
type Order struct {
	Kind  OrderKind
	Hash  [32]byte
	ActAt uint64 // unix seconds
}

// ExitDay is the day's voluntary exits the runner signed under exit
// approvals (issue #4 F4), carried by every record from the first exit on,
// so a rollback of the host's local state cannot free the day's stake cap.
type ExitDay struct {
	Day   uint64 // unix seconds / 86400, trusted clock
	Stake uint64 // Gwei counted against exit_stake_cap_per_day
	Exits []ExitEntry
}

// ExitEntry is one exit of the day, keyed by validator key, index and exit
// epoch (OPTEE-EXIT-01).
type ExitEntry struct {
	Pubkey         backend.Pubkey
	ValidatorIndex uint64
	ExitEpoch      uint64
	Stake          uint64
	Nonce          [32]byte // the approval's
}

// MaxExitsPerDay bounds ExitDay.Exits so a record stays under MaxRecord.
const MaxExitsPerDay = 200

// Clone returns a deep copy.
func (d *ExitDay) Clone() *ExitDay {
	if d == nil {
		return nil
	}
	c := *d
	c.Exits = append([]ExitEntry(nil), d.Exits...)
	return &c
}

func exitsEqual(a, b *ExitDay) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Day != b.Day || a.Stake != b.Stake || len(a.Exits) != len(b.Exits) {
		return false
	}
	for i := range a.Exits {
		if a.Exits[i] != b.Exits[i] {
			return false
		}
	}
	return true
}

// BodyCopy is the newest copy of an update body that the runner wrote: its
// copy number in the body's object name and when it wrote it. The runner
// writes copy n+1 when copy n is older than half the retention.
type BodyCopy struct {
	N  uint32 // 0: no body (version 0, or no pending update)
	At uint64 // unix seconds
}

// Group returns the state of group g.
func (s *ConfigState) Group(g setupwire.Group) (*GroupState, error) {
	switch g {
	case setupwire.GroupLocked:
		return &s.Locked, nil
	case setupwire.GroupOpen:
		return &s.Open, nil
	}
	return nil, fmt.Errorf("markstore: unknown config group %d", g)
}

// Clone returns a deep copy.
func (s ConfigState) Clone() ConfigState {
	c := s
	for _, g := range []*GroupState{&c.Locked, &c.Open} {
		if g.Pending != nil {
			p := *g.Pending
			g.Pending = &p
		}
	}
	if c.Order != nil {
		o := *c.Order
		c.Order = &o
	}
	return c
}

// Equal reports whether two states name the same versions, hashes, times
// and order.
func (s ConfigState) Equal(o ConfigState) bool {
	pendEq := func(a, b *Pending) bool { return a == b || a != nil && b != nil && *a == *b }
	grpEq := func(a, b GroupState) bool {
		return a.Version == b.Version && a.Hash == b.Hash && pendEq(a.Pending, b.Pending)
	}
	ordEq := s.Order == o.Order || s.Order != nil && o.Order != nil && *s.Order == *o.Order
	return grpEq(s.Locked, o.Locked) && grpEq(s.Open, o.Open) && ordEq
}

// bodyIndex is the position in Record.Copies of a group's active (pending
// false) or pending update.
func bodyIndex(g setupwire.Group, pending bool) int {
	i := 0
	if g == setupwire.GroupOpen {
		i = 2
	}
	if pending {
		i++
	}
	return i
}

const (
	// recordMagic is "SMARK" and the format version digit, 1. A record
	// with a higher digit is from a newer image (RecordHeader).
	recordMagic  = "SMARK1"
	versionWidth = 20
	maxSignerLen = 128
	maxKeyBlob   = 1024
	// MaxRecord bounds an encoded record: the store clients read at most
	// 1 MiB of an object, a record is about 700 bytes, 21 KB more with
	// MaxExitsPerDay exits.
	MaxRecord = 32768
)

// KeyAAD is what the key blobs of a signer's log are bound to: a blob made
// for one setup or signer does not open as another's.
func KeyAAD(setup [32]byte, signer string) []byte {
	return setupwire.CtxMarkKey.Message(setup[:], []byte(signer))
}

// ShareAAD is the AAD a stored share is sealed under (section 5): bound to
// the setup and to the log. A log made again after its records expired
// has another log_id, so no share sealed before opens in it.
func ShareAAD(setup, logID [32]byte, pk backend.Pubkey) []byte {
	return setupwire.CtxShare.Message(setup[:], logID[:], pk[:])
}

// Prefix is the object name prefix of a signer's log:
// marks/<setup_hash hex>/<signer>/. A new setup never meets an old log. A
// zero setup is the flag path without a setup: marks/<signer>/.
func Prefix(setup [32]byte, signer string) string {
	if setup == ([32]byte{}) {
		return "marks/" + signer + "/"
	}
	return "marks/" + hex.EncodeToString(setup[:]) + "/" + signer + "/"
}

// Name is the object name of version v of a signer's log: zero-padded, so
// names sort as versions do.
func Name(setup [32]byte, signer string, v uint64) string {
	return fmt.Sprintf("%s%0*d", Prefix(setup, signer), versionWidth, v)
}

// versionOf parses a name under prefix.
func versionOf(prefix, name string) (uint64, bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || len(rest) != versionWidth {
		return 0, false
	}
	v, err := strconv.ParseUint(rest, 10, 64)
	return v, err == nil && v > 0
}

// BodyPrefix is the object name prefix of the copies of an update body:
// config/<setup_hash hex>/<group>/<version, 20 digits>/.
func BodyPrefix(setup [32]byte, g setupwire.Group, version uint64) string {
	return fmt.Sprintf("config/%s/%s/%0*d/", hex.EncodeToString(setup[:]), g, versionWidth, version)
}

// BodyName is the object name of copy n of an update body.
func BodyName(setup [32]byte, g setupwire.Group, version uint64, n uint32) string {
	return BodyPrefix(setup, g, version) + strconv.FormatUint(uint64(n), 10)
}

// CheckSigner refuses names that would not make plain object names.
func CheckSigner(s string) error {
	if s == "" || len(s) > maxSignerLen {
		return fmt.Errorf("markstore: signer ID must be 1 to %d characters", maxSignerLen)
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("markstore: signer ID %q: use a-z, 0-9, '-', '_', '.'", s)
		}
	}
	return nil
}

func putFlag(b []byte, on bool) []byte {
	if on {
		return append(b, 1)
	}
	return append(b, 0)
}

func (r *Record) encodeBody() []byte {
	be := binary.BigEndian
	b := append([]byte(recordMagic), r.Setup[:]...)
	b = append(b, byte(len(r.Signer)))
	b = append(b, r.Signer...)
	b = be.AppendUint64(b, r.Version)
	b = be.AppendUint64(b, r.PrevVersion)
	b = append(b, r.PrevHash[:]...)
	b = append(b, r.LogID[:]...)
	b = append(b, r.Owner[:]...)
	b = be.AppendUint16(b, uint16(len(r.KeyBlob)))
	b = append(b, r.KeyBlob...)
	b = append(b, markformat.EncodeWatermark(r.Mark)...)
	b = be.AppendUint64(b, r.Time)
	for gi, g := range []*GroupState{&r.State.Locked, &r.State.Open} {
		active, pending := r.Copies[2*gi], r.Copies[2*gi+1]
		b = be.AppendUint64(b, g.Version)
		b = append(b, g.Hash[:]...)
		b = be.AppendUint32(b, active.N)
		b = be.AppendUint64(b, active.At)
		b = putFlag(b, g.Pending != nil)
		if g.Pending != nil {
			b = be.AppendUint64(b, g.Pending.Version)
			b = append(b, g.Pending.Hash[:]...)
			b = be.AppendUint64(b, g.Pending.EffectiveAt)
			b = be.AppendUint32(b, pending.N)
			b = be.AppendUint64(b, pending.At)
		}
	}
	b = putFlag(b, r.State.Order != nil)
	if o := r.State.Order; o != nil {
		b = append(b, byte(o.Kind))
		b = append(b, o.Hash[:]...)
		b = be.AppendUint64(b, o.ActAt)
	}
	b = putFlag(b, r.Target != nil)
	if r.Target != nil {
		b = append(b, r.Target[:]...)
	}
	b = putFlag(b, r.Exits != nil)
	if d := r.Exits; d != nil {
		b = be.AppendUint64(b, d.Day)
		b = be.AppendUint64(b, d.Stake)
		b = be.AppendUint16(b, uint16(len(d.Exits)))
		for _, e := range d.Exits {
			b = append(b, e.Pubkey[:]...)
			b = be.AppendUint64(b, e.ValidatorIndex)
			b = be.AppendUint64(b, e.ExitEpoch)
			b = be.AppendUint64(b, e.Stake)
			b = append(b, e.Nonce[:]...)
		}
	}
	b = putFlag(b, r.SourceGate != nil)
	if r.SourceGate != nil {
		b = be.AppendUint64(b, *r.SourceGate)
	}
	return b
}

func signedMessage(body []byte) []byte { return setupwire.CtxMark.Message(body) }

// Sign fills Sig and returns the encoding. key is the private key of the
// seed that KeyBlob wraps.
func (r *Record) Sign(key ed25519.PrivateKey) []byte {
	body := r.encodeBody()
	r.body = body
	copy(r.Sig[:], ed25519.Sign(key, signedMessage(body)))
	return append(body, r.Sig[:]...)
}

// Hash is sha256 of a record's encoding: what the next record links to,
// and for the first record of a log its log_id.
func Hash(enc []byte) [32]byte { return sha256.Sum256(enc) }

var errRecord = errors.New("markstore: not a valid mark record")

// recReader reads fields; the first short read sets bad and every later
// read returns zeros.
type recReader struct {
	b   []byte
	bad bool
}

func (r *recReader) take(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad = true
		return make([]byte, n)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *recReader) u8() uint8          { return r.take(1)[0] }
func (r *recReader) u16() uint16        { return binary.BigEndian.Uint16(r.take(2)) }
func (r *recReader) u32() uint32        { return binary.BigEndian.Uint32(r.take(4)) }
func (r *recReader) u64() uint64        { return binary.BigEndian.Uint64(r.take(8)) }
func (r *recReader) fixed(dst []byte)   { copy(dst, r.take(len(dst))) }
func (r *recReader) flag() (bool, bool) { v := r.u8(); return v == 1, v <= 1 }

// Parse reads a record's fields without checking its signature: the key
// that checks it is in KeyBlob, which only the platform's key release
// opens (Verify). It reads SMARK1 only, and refuses any encoding that does
// not read back to the same bytes and any state the format does not allow.
func Parse(enc []byte) (*Record, error) {
	if len(enc) > MaxRecord || len(enc) < len(recordMagic)+ed25519.SignatureSize || string(enc[:len(recordMagic)]) != recordMagic {
		return nil, errors.New("markstore: not a mark record")
	}
	body := enc[:len(enc)-ed25519.SignatureSize]
	rd := &recReader{b: body[len(recordMagic):]}
	r := &Record{}
	rd.fixed(r.Setup[:])
	r.Signer = string(rd.take(int(rd.u8())))
	r.Version, r.PrevVersion = rd.u64(), rd.u64()
	rd.fixed(r.PrevHash[:])
	rd.fixed(r.LogID[:])
	rd.fixed(r.Owner[:])
	kb := int(rd.u16())
	if kb == 0 || kb > maxKeyBlob {
		return nil, fmt.Errorf("%w: key blob of %d bytes", errRecord, kb)
	}
	r.KeyBlob = append([]byte(nil), rd.take(kb)...)
	wm, err := markformat.DecodeWatermark(rd.take(markformat.WatermarkEncodedLen))
	if err != nil && !rd.bad {
		return nil, err
	}
	r.Mark = wm
	r.Time = rd.u64()
	ok := true
	for gi, g := range []*GroupState{&r.State.Locked, &r.State.Open} {
		g.Version = rd.u64()
		rd.fixed(g.Hash[:])
		r.Copies[2*gi] = BodyCopy{N: rd.u32(), At: rd.u64()}
		has, valid := rd.flag()
		ok = ok && valid
		if has {
			g.Pending = &Pending{Version: rd.u64()}
			rd.fixed(g.Pending.Hash[:])
			g.Pending.EffectiveAt = rd.u64()
			r.Copies[2*gi+1] = BodyCopy{N: rd.u32(), At: rd.u64()}
		}
	}
	has, valid := rd.flag()
	ok = ok && valid
	if has {
		o := &Order{Kind: OrderKind(rd.u8())}
		rd.fixed(o.Hash[:])
		o.ActAt = rd.u64()
		r.State.Order = o
	}
	has, valid = rd.flag()
	ok = ok && valid
	if has {
		var t [32]byte
		rd.fixed(t[:])
		r.Target = &t
	}
	exits, valid := rd.flag()
	ok = ok && valid
	if exits {
		d := &ExitDay{Day: rd.u64(), Stake: rd.u64()}
		n := int(rd.u16())
		if n > MaxExitsPerDay {
			return nil, fmt.Errorf("%w: %d exits", errRecord, n)
		}
		// The entries must be there before they are allocated: a short
		// record claiming 200 keyed exits would otherwise grow the slice
		// to about 64 KiB from a few hundred bytes.
		size := len(backend.Pubkey{}) + 8 + 8 + 8 + 32
		if len(rd.b) < n*size {
			return nil, fmt.Errorf("%w: %d exits in %d bytes", errRecord, n, len(rd.b))
		}
		if n > 0 {
			d.Exits = make([]ExitEntry, 0, n)
		}
		for range n {
			var e ExitEntry
			rd.fixed(e.Pubkey[:])
			e.ValidatorIndex, e.ExitEpoch, e.Stake = rd.u64(), rd.u64(), rd.u64()
			rd.fixed(e.Nonce[:])
			d.Exits = append(d.Exits, e)
		}
		r.Exits = d
	}
	has, valid = rd.flag()
	ok = ok && valid
	if has {
		f := rd.u64()
		r.SourceGate = &f
	}
	if rd.bad || len(rd.b) != 0 || !ok {
		return nil, fmt.Errorf("%w: length or presence byte", errRecord)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	r.body = append([]byte(nil), body...)
	copy(r.Sig[:], enc[len(body):])
	return r, nil
}

// Header is the start of a record that every record version keeps, so a
// runner can tell a record it cannot parse from an object that is no
// record of its signer (the fail-closed reader rule, MarkLog.validAt):
//
//	magic[6] ("SMARK" and a version digit, 1 or higher) setup_hash[32]
//	signer_len:u8 signer version:u64 prev_version:u64 prev_hash[32]
//	log_id[32] owner[16] key_blob_len:u16 key_blob
//
// A later record format may change anything after the key blob, and must
// keep this start and the magic's form.
type Header struct {
	Magic   string
	Setup   [32]byte
	Signer  string
	Version uint64
	KeyBlob []byte
}

// RecordHeader reads a record's Header; false when enc does not start
// like a record of any version.
func RecordHeader(enc []byte) (*Header, bool) {
	const magicLen = len(recordMagic)
	if len(enc) > MaxRecord || len(enc) < magicLen || string(enc[:magicLen-1]) != recordMagic[:magicLen-1] ||
		enc[magicLen-1] < recordMagic[magicLen-1] || enc[magicLen-1] > '9' {
		return nil, false
	}
	rd := &recReader{b: enc[magicLen:]}
	h := &Header{Magic: string(enc[:magicLen])}
	rd.fixed(h.Setup[:])
	h.Signer = string(rd.take(int(rd.u8())))
	h.Version = rd.u64()
	rd.take(8 + 32 + 32 + 16)
	kb := int(rd.u16())
	if rd.bad || kb == 0 || kb > maxKeyBlob {
		return nil, false
	}
	h.KeyBlob = append([]byte(nil), rd.take(kb)...)
	if rd.bad {
		return nil, false
	}
	return h, true
}

// check holds the rules a record's fields follow.
func (r *Record) check() error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", errRecord, why) }
	if err := CheckSigner(r.Signer); err != nil {
		return err
	}
	switch {
	case r.Version == 0 || r.PrevVersion >= r.Version:
		return bad("versions")
	case (r.PrevVersion == 0) != (r.LogID == [32]byte{}):
		return bad("log_id is zero in a log's first record and set in every later one")
	case r.Target != nil && r.Mark != Tombstone:
		return bad("a target on a record that is not a tombstone")
	}
	for gi, g := range []*GroupState{&r.State.Locked, &r.State.Open} {
		active, pending := r.Copies[2*gi], r.Copies[2*gi+1]
		if (g.Version == 0) != (active.N == 0) {
			return bad("an active update past version 0 has a body copy, version 0 none")
		}
		if active.N == 0 && active.At != 0 {
			return bad("time of a body copy that does not exist")
		}
		if g.Pending == nil {
			if pending != (BodyCopy{}) {
				return bad("a body copy for no pending update")
			}
			continue
		}
		if g.Pending.Version <= g.Version || pending.N == 0 {
			return bad("pending update at or below the active version, or without a body copy")
		}
	}
	if o := r.State.Order; o != nil && o.Kind != OrderHandover {
		return bad(fmt.Sprintf("order kind %d", o.Kind))
	}
	if d := r.Exits; d != nil {
		var sum uint64
		for _, e := range d.Exits {
			if sum+e.Stake < sum {
				return bad("exit stake overflows")
			}
			sum += e.Stake
		}
		if len(d.Exits) == 0 || len(d.Exits) > MaxExitsPerDay || sum != d.Stake {
			return bad("exits: none, too many, or a stake that is not their sum")
		}
	}
	return nil
}

// Verify checks a parsed record: its signature under pub (the key its
// KeyBlob opens to), the expected setup and signer, and the version its name
// gives.
func (r *Record) Verify(pub ed25519.PublicKey, setup [32]byte, signer string, version uint64) error {
	if !ed25519.Verify(pub, signedMessage(r.body), r.Sig[:]) {
		return errors.New("markstore: signature does not verify under the key of its key blob")
	}
	switch {
	case r.Setup != setup:
		return errors.New("markstore: record of another setup")
	case r.Signer != signer:
		return fmt.Errorf("markstore: record of signer %q in the log of %q", r.Signer, signer)
	case r.Version != version:
		return fmt.Errorf("markstore: record version %d under the name of version %d (replayed)", r.Version, version)
	}
	return nil
}

// logIDOf is the log_id of the log a record belongs to: its own hash for a
// first record, the field for every later one.
func logIDOf(r *Record, enc []byte) [32]byte {
	if r.PrevVersion == 0 {
		return Hash(enc)
	}
	return r.LogID
}
