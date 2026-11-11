package markstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/markformat"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Record is one entry of a signer's mark log, magic SMARK3 (SMARK1 reads
// as a record without Shares, SMARK1 and SMARK2 without the config history,
// ConfigState.RemovedAt and Carried). Every record carries the full config state, so no record needs an earlier one for the
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
	// SourceGate is the source floor epoch of a log that held no vote when
	// the runner started on it (state.Hooks): a validator without imported
	// history of its own signs no vote with a source below it. nil: no
	// gate (RBRLOG-02).
	SourceGate *uint64
	// Shares is the share set commitment (ShareSetRoot): the runner loads
	// a set of stored share records only if its root is Current or
	// Pending. nil (and every SMARK1 record): the empty set.
	Shares *ShareSet
	Sig    [ed25519.SignatureSize]byte

	body []byte // the signed bytes, as read (Parse)
	// ver is the format digit Parse read, 1 or 2 for an older record, which
	// encodes back as it was read; 0 for the newest, recordVersion.
	ver byte
}

// ConfigState is the config state a record carries (section 6): per group
// the active version and the hash of the update that set it, and the
// pending update; and the pending order (phase 2).
type ConfigState struct {
	Locked GroupState
	Open   GroupState
	Order  *Order // nil: none
	// RemovedAt is the effective time of the newest locked update in force
	// that removed one approver (setupwire.EmergencyRemoval), 0 for none. A
	// break-glass change waits one change delay after it
	// (setupwire.History).
	RemovedAt uint64
	// Carried are the revoked_client_certs entries of a pending open
	// update that a rotation dropped, which the runner keeps refusing until
	// the next open update comes into force (leaving one out of it needed
	// every approver). Sorted, without repeats, at most MaxCarried.
	Carried [][32]byte
	// Paths is the path each update the state names came by
	// (setupwire.Path; 0 unknown, as for version 0 and an update of an
	// older record), in bodyIndex order: locked active, locked pending,
	// open active, open pending. HEALTH reports it after a restart too.
	Paths [4]setupwire.Path
}

// Path is the path of group g's active (pending false) or pending update.
func (s *ConfigState) Path(g setupwire.Group, pending bool) setupwire.Path {
	return s.Paths[bodyIndex(g, pending)]
}

// SetPath sets the path of group g's active (pending false) or pending
// update.
func (s *ConfigState) SetPath(g setupwire.Group, pending bool, p setupwire.Path) {
	s.Paths[bodyIndex(g, pending)] = p
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
// handover order is the only kind: Parse refuses every other, so a record
// of an earlier build with a key generation order (kind 2) does not read.
// SetState refuses every order, as no handover writes one.
type OrderKind uint8

const OrderHandover OrderKind = 1

// Order is a pending handover order (phase 2).
type Order struct {
	Kind  OrderKind
	Hash  [32]byte
	ActAt uint64 // unix seconds
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
	c.Carried = slices.Clone(c.Carried)
	return c
}

// Equal reports whether two states name the same versions, hashes, times,
// order and config history.
func (s ConfigState) Equal(o ConfigState) bool {
	pendEq := func(a, b *Pending) bool { return a == b || a != nil && b != nil && *a == *b }
	grpEq := func(a, b GroupState) bool {
		return a.Version == b.Version && a.Hash == b.Hash && pendEq(a.Pending, b.Pending)
	}
	ordEq := s.Order == o.Order || s.Order != nil && o.Order != nil && *s.Order == *o.Order
	return grpEq(s.Locked, o.Locked) && grpEq(s.Open, o.Open) && ordEq && s.RemovedAt == o.RemovedAt && slices.Equal(s.Carried, o.Carried) && s.Paths == o.Paths
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
	// recordMagic is "SMARK" and the format version digit, 3, the one
	// this image writes; it reads 2 (recordMagicV2, without the config
	// history) and 1 (recordMagicV1, without the share set either). A
	// record with a higher digit is from a newer image (RecordHeader).
	recordMagic   = "SMARK3"
	recordMagicV2 = "SMARK2"
	recordMagicV1 = "SMARK1"
	// MaxCarried bounds ConfigState.Carried: one open update's
	// revoked_client_certs.
	MaxCarried   = setupwire.MaxRevokedClientCerts
	versionWidth = 20
	maxSignerLen = 128
	maxKeyBlob   = 1024
	// MaxRecord bounds an encoded record: the store clients read at most
	// 1 MiB of an object, a record is about 700 bytes.
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
	magic := recordMagic
	switch r.ver {
	case 1:
		magic = recordMagicV1
	case 2:
		magic = recordMagicV2
	}
	b := append([]byte(magic), r.Setup[:]...)
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
	// The exits block of an image with exit approvals: its presence byte
	// stays, always 0.
	b = putFlag(b, false)
	b = putFlag(b, r.SourceGate != nil)
	if r.SourceGate != nil {
		b = be.AppendUint64(b, *r.SourceGate)
	}
	if r.ver == 1 {
		return b
	}
	b = putFlag(b, r.Shares != nil)
	if s := r.Shares; s != nil {
		b = append(b, s.Current[:]...)
		b = putFlag(b, s.Pending != nil)
		if s.Pending != nil {
			b = append(b, s.Pending[:]...)
		}
	}
	if r.ver == 2 {
		return b
	}
	b = putFlag(b, r.State.RemovedAt != 0)
	if r.State.RemovedAt != 0 {
		b = be.AppendUint64(b, r.State.RemovedAt)
	}
	b = append(b, byte(len(r.State.Carried)))
	for _, h := range r.State.Carried {
		b = append(b, h[:]...)
	}
	for _, p := range r.State.Paths {
		b = append(b, byte(p))
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
// opens (Verify). It reads SMARK1, SMARK2 and SMARK3, and refuses any encoding
// that does not read back to the same bytes under its own magic and any
// state the format does not allow.
func Parse(enc []byte) (*Record, error) {
	if len(enc) > MaxRecord || len(enc) < len(recordMagic)+ed25519.SignatureSize {
		return nil, errors.New("markstore: not a mark record")
	}
	var ver byte
	switch string(enc[:len(recordMagic)]) {
	case recordMagic:
	case recordMagicV2:
		ver = 2
	case recordMagicV1:
		ver = 1
	default:
		return nil, errors.New("markstore: not a mark record")
	}
	body := enc[:len(enc)-ed25519.SignatureSize]
	rd := &recReader{b: body[len(recordMagic):]}
	r := &Record{ver: ver}
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
	if exits, valid := rd.flag(); exits || !valid {
		// An image with exit approvals wrote the day's exits here; this
		// one signs exits without them and reads no such record.
		return nil, fmt.Errorf("%w: an exits block (written by an image with exit approvals)", errRecord)
	}
	has, valid = rd.flag()
	ok = ok && valid
	if has {
		f := rd.u64()
		r.SourceGate = &f
	}
	if ver != 1 {
		has, valid = rd.flag()
		ok = ok && valid
		if has {
			s := &ShareSet{}
			rd.fixed(s.Current[:])
			has, valid = rd.flag()
			ok = ok && valid
			if has {
				var p [32]byte
				rd.fixed(p[:])
				s.Pending = &p
			}
			r.Shares = s
		}
	}
	if ver == 0 {
		has, valid = rd.flag()
		ok = ok && valid
		if has {
			// Presence with 0 would encode back without it.
			r.State.RemovedAt = rd.u64()
			ok = ok && r.State.RemovedAt != 0
		}
		if n := int(rd.u8()); n > 0 {
			r.State.Carried = make([][32]byte, n)
			for i := range r.State.Carried {
				rd.fixed(r.State.Carried[i][:])
			}
		}
		for i := range r.State.Paths {
			r.State.Paths[i] = setupwire.Path(rd.u8())
		}
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
// and every record ends with a 64-byte Ed25519 signature, under the key
// its key blob opens to, over the context signer-mark-v1 and every byte
// before the signature. A later record format may change anything between
// the key blob and the signature, and must keep this start, the magic's
// form and the signed tail. The tail lets the reader tell a record that a
// runner under its key release wrote from an object that copies a real
// record's key blob, which is a public field.
type Header struct {
	Magic   string
	Setup   [32]byte
	Signer  string
	Version uint64
	Owner   [16]byte // the process that wrote it
	KeyBlob []byte
	Signed  []byte                      // the bytes before the signature
	Sig     [ed25519.SignatureSize]byte // the last 64 bytes
}

// Verify reports whether h's signature holds under pub over the bytes
// before it, as every record version signs them.
func (h *Header) Verify(pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, signedMessage(h.Signed), h.Sig[:])
}

// RecordHeader reads a record's Header; false when enc does not start
// like a record of any version, or its start does not fit before the
// signature.
func RecordHeader(enc []byte) (*Header, bool) {
	const magicLen = len(recordMagic)
	if len(enc) > MaxRecord || len(enc) < magicLen+ed25519.SignatureSize || string(enc[:magicLen-1]) != recordMagic[:magicLen-1] ||
		enc[magicLen-1] < recordMagicV1[magicLen-1] || enc[magicLen-1] > '9' {
		return nil, false
	}
	signed := enc[:len(enc)-ed25519.SignatureSize]
	rd := &recReader{b: signed[magicLen:]}
	h := &Header{Magic: string(enc[:magicLen])}
	rd.fixed(h.Setup[:])
	h.Signer = string(rd.take(int(rd.u8())))
	h.Version = rd.u64()
	rd.take(8 + 32 + 32) // prev_version, prev_hash, log_id
	rd.fixed(h.Owner[:])
	kb := int(rd.u16())
	if rd.bad || kb == 0 || kb > maxKeyBlob {
		return nil, false
	}
	h.KeyBlob = append([]byte(nil), rd.take(kb)...)
	if rd.bad {
		return nil, false
	}
	h.Signed = append([]byte(nil), signed...)
	copy(h.Sig[:], enc[len(signed):])
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
	if err := r.State.checkCarried(); err != nil {
		return bad(err.Error())
	}
	if err := r.State.checkPaths(); err != nil {
		return bad(err.Error())
	}
	return nil
}

// checkPaths: each path is 0 or a known one (up to
// setupwire.PathEmergencyRemoval), and 0 where the state names no update
// (version 0, no pending update).
func (s *ConfigState) checkPaths() error {
	for gi, g := range []*GroupState{&s.Locked, &s.Open} {
		active, pending := s.Paths[2*gi], s.Paths[2*gi+1]
		if active > setupwire.PathEmergencyRemoval || pending > setupwire.PathEmergencyRemoval {
			return fmt.Errorf("update path %d or %d", active, pending)
		}
		if g.Version == 0 && active != 0 || g.Pending == nil && pending != 0 {
			return errors.New("an update path where the state names no update")
		}
	}
	return nil
}

// checkCarried: at most MaxCarried carried revocations, sorted, without
// repeats, none zero.
func (s *ConfigState) checkCarried() error {
	if len(s.Carried) > MaxCarried {
		return fmt.Errorf("%d carried revocations, at most %d", len(s.Carried), MaxCarried)
	}
	for i, h := range s.Carried {
		if h == ([32]byte{}) || i > 0 && bytes.Compare(s.Carried[i-1][:], h[:]) >= 0 {
			return errors.New("carried revocations not sorted, repeated or zero")
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
