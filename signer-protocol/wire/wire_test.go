package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Frame{Type: TypeSign, ID: 42, Payload: []byte("hello")}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	if got := binary.BigEndian.Uint32(raw); got != 6+5 {
		t.Fatalf("length prefix %d", got)
	}
	out, err := ReadFrame(&buf)
	if err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("%+v %v", out, err)
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("want clean EOF, got %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(raw[:len(raw)-1])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame: %v", err)
	}
	bad := append([]byte(nil), raw...)
	bad[4] = 9
	if _, err := ReadFrame(bytes.NewReader(bad)); err == nil {
		t.Fatal("bad version accepted")
	}
	big := binary.BigEndian.AppendUint32(nil, MaxFrame+1)
	if _, err := ReadFrame(bytes.NewReader(big)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame: %v", err)
	}
	if err := WriteFrame(io.Discard, Frame{Payload: make([]byte, MaxFrame)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal("oversized write accepted")
	}
}

func TestSignRoundTrip(t *testing.T) {
	pk := backend.Pubkey{1, 2, 3}
	msgs := []backend.Message{
		&backend.AttestationData{Slot: 1, Index: 2, BeaconBlockRoot: backend.Root{3}, Source: backend.Checkpoint{Epoch: 4, Root: backend.Root{5}}, Target: backend.Checkpoint{Epoch: 6, Root: backend.Root{7}}},
		&backend.BeaconBlockHeader{Slot: 1, ProposerIndex: 2, ParentRoot: backend.Root{3}, StateRoot: backend.Root{4}, BodyRoot: backend.Root{5}},
		&backend.VoluntaryExit{Epoch: 1, ValidatorIndex: 2},
		&backend.ValidatorRegistration{FeeRecipient: backend.Address{1}, GasLimit: 2, Timestamp: 3, Pubkey: backend.Pubkey{4}},
		&backend.RootMessage{Type: backend.RootSyncCommitteeMessage, Epoch: 1 << 40, ObjectRoot: backend.Root{1}, Domain: backend.Root{2}},
		// Gloas kinds 6 to 8.
		&backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{1}, Slot: 2, PayloadPresent: true},
		&backend.PayloadEnvelope{Payload: backend.ExecutionPayloadSummary{ParentHash: backend.Root{1}, FeeRecipient: backend.Address{2},
			GasLimit: 3, BaseFeePerGas: backend.Root{4}, BlockAccessListRoot: backend.Root{5}, SlotNumber: 6},
			ExecutionRequestsRoot: backend.Root{7}, BuilderIndex: backend.BuilderIndexSelfBuild, BeaconBlockRoot: backend.Root{8}, ParentBeaconBlockRoot: backend.Root{9}},
		&backend.ProposerPreferences{DependentRoot: backend.Root{1}, ProposalSlot: 2, ValidatorIndex: 3, FeeRecipient: backend.Address{4}, TargetGasLimit: 5},
		// Fixed-size kinds of aggregates.go.
		&backend.SelectionProof{Slot: 3},
		&backend.SyncCommitteeMessage{Slot: 4, BeaconBlockRoot: backend.Root{5}},
		&backend.SyncSelectionProof{Slot: 6, SubcommitteeIndex: 1},
	}
	domain := backend.Root{0x01, 0, 0, 0, 0xd0, 0x4a}
	for _, m := range msgs {
		p, err := EncodeSign(backend.SignRequest{Pubkey: pk, Message: m, Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeSign(p)
		if err != nil {
			t.Fatal(err)
		}
		if got.Pubkey != pk || !reflect.DeepEqual(got.Message, m) {
			t.Fatalf("%v: %+v != %+v", m.Kind(), got.Message, m)
		}
		// Typed kinds carry the caller's domain after the kind; a root
		// message carries its own inside the message.
		if _, root := m.(*backend.RootMessage); root {
			if got.Domain != (backend.Root{}) {
				t.Fatalf("root message: request domain %v, want none", got.Domain)
			}
		} else if got.Domain != domain || !bytes.Equal(p[49:81], domain[:]) {
			t.Fatalf("%v: domain %v, want %v at bytes 49 to 80", m.Kind(), got.Domain, domain)
		}
		if _, err := DecodeSign(p[:len(p)-1]); err == nil {
			t.Fatalf("%v: truncated payload accepted", m.Kind())
		}
	}
	if _, err := DecodeSign(append(make([]byte, 48), 77)); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

// A typed SIGN without the domain does not parse, for every fixed-size kind; the variable
// kinds 9 and 10 parse into a domain the runner's check refuses.
func TestSignWithoutDomainRefused(t *testing.T) {
	for _, m := range []backend.Message{
		&backend.AttestationData{Slot: 1}, &backend.BeaconBlockHeader{Slot: 1}, &backend.VoluntaryExit{Epoch: 1},
		&backend.ValidatorRegistration{GasLimit: 1}, &backend.PayloadAttestationData{Slot: 1},
		&backend.PayloadEnvelope{BuilderIndex: 1}, &backend.ProposerPreferences{ProposalSlot: 1},
		&backend.SelectionProof{Slot: 1}, &backend.SyncCommitteeMessage{Slot: 1}, &backend.SyncSelectionProof{Slot: 1},
	} {
		body, err := backend.EncodeSSZ(m)
		if err != nil {
			t.Fatal(err)
		}
		old := append(append(make([]byte, 48), byte(m.Kind())), body...)
		if _, err := DecodeSign(old); err == nil {
			t.Errorf("%v without a domain accepted", m.Kind())
		}
	}
	short := append(make([]byte, 48), byte(backend.KindAttestation))
	if _, err := DecodeSign(append(short, make([]byte, 31)...)); err == nil {
		t.Error("31-byte domain accepted")
	}
}

func TestOtherPayloads(t *testing.T) {
	keys := []backend.ValidatorKey{{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3}, {Index: backend.IndexUnknown}}
	gotKeys, err := DecodeKeys(EncodeKeys(keys))
	if err != nil || !reflect.DeepEqual(gotKeys, keys) {
		t.Fatalf("%+v %v", gotKeys, err)
	}

	a := &backend.Attestation{Platform: "nitro", Format: "aws-nitro-cose-sign1", UserData: []byte{1, 2}, Document: []byte("doc")}
	p, _ := EncodeAttestation(a)
	gotA, err := DecodeAttestation(p)
	if err != nil || !reflect.DeepEqual(gotA, a) {
		t.Fatalf("%+v %v", gotA, err)
	}
	if _, err := DecodeAttestation(append(p, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}

	n, _ := EncodeAttest([]byte("nonce"))
	if gotN, err := DecodeAttest(n); err != nil || string(gotN) != "nonce" {
		t.Fatal(gotN, err)
	}
	if !bytes.Equal(n, []byte("\x00\x05nonce\x01")) {
		t.Fatalf("request layout %q, want nonce_len nonce version", n)
	}
	if _, err := EncodeAttest(make([]byte, MaxNonce+1)); err == nil {
		t.Fatal("long nonce accepted")
	}

	// ATTEST answer: version, setup state, attestation.
	st := testState()
	ar, err := EncodeAttestResponse(&st, a)
	if err != nil {
		t.Fatal(err)
	}
	gotS, gotA, err := DecodeAttestResponse(ar)
	if err != nil || *gotS != st || !reflect.DeepEqual(gotA, a) {
		t.Fatalf("attest answer: %+v %+v %v", gotS, gotA, err)
	}
	for _, bad := range [][]byte{ar[:len(ar)-1], append(ar, 0), append([]byte{0}, ar[1:]...), append([]byte{2}, ar[1:]...), ar[:1+backend.SetupStateLen-1]} {
		if _, _, err := DecodeAttestResponse(bad); err == nil {
			t.Fatalf("bad attest answer of %d bytes accepted", len(bad))
		}
	}
}

// testState is a setup state with every field set.
func testState() backend.SetupState {
	return backend.SetupState{
		SetupHash:       backend.Root{0x5e},
		Locked:          backend.ConfigGroup{Version: 4, Hash: backend.Root{1}, Pending: backend.PendingUpdate{Version: 6, Hash: backend.Root{2}, EffectiveAt: 1_800_000_000}},
		Open:            backend.ConfigGroup{Version: 1, Hash: backend.Root{3}},
		ApproverSetHash: backend.Root{4},
		Order:           backend.Order{Kind: 1, Hash: backend.Root{5}, ActAt: 1_900_000_000},
		KeyReleaseHash:  backend.Root{6},
		KeyOrigin:       backend.KeyOrigin{Generated: 7, Imported: 1, OrdersHash: backend.Root{8}},
	}
}

// An ATTEST or IDENTITY request of another version is refused with
// ErrRequestVersion, which the runner answers with UNSUPPORTED. A request
// without the version byte is malformed.
func TestIdentityRequestVersion(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 32)
	bare := append([]byte{0, 32}, nonce...)
	if _, err := DecodeAttest(bare); err == nil || errors.Is(err, ErrRequestVersion) {
		t.Fatalf("request without a version byte: %v", err)
	}
	for _, v := range []byte{0, 2} {
		if _, err := DecodeAttest(append(append([]byte{}, bare...), v)); !errors.Is(err, ErrRequestVersion) {
			t.Fatalf("request of version %d: %v", v, err)
		}
	}
	if _, err := DecodeAttest(append(append([]byte{}, bare...), IdentityVersion, IdentityVersion)); err == nil || errors.Is(err, ErrRequestVersion) {
		t.Fatalf("request with a trailing byte: %v", err)
	}
	if got, err := DecodeAttest(append(append([]byte{}, bare...), IdentityVersion)); err != nil || !bytes.Equal(got, nonce) {
		t.Fatalf("request of version %d: %v", IdentityVersion, err)
	}
}

// A setup state with an impossible pending update or order does not parse.
func TestSetupStateStrict(t *testing.T) {
	st := testState()
	b := backend.AppendSetupState(nil, &st)
	if len(b) != backend.SetupStateLen {
		t.Fatalf("%d bytes, want %d", len(b), backend.SetupStateLen)
	}
	if got, err := backend.ParseSetupState(b); err != nil || got != st {
		t.Fatalf("%+v %v", got, err)
	}
	for name, mod := range map[string]func(*backend.SetupState){
		"pending at the active version": func(s *backend.SetupState) { s.Locked.Pending.Version = s.Locked.Version },
		"empty pending with a hash":     func(s *backend.SetupState) { s.Open.Pending.Hash = backend.Root{1} },
		"empty pending with a time":     func(s *backend.SetupState) { s.Open.Pending.EffectiveAt = 1 },
		"order of kind 3":               func(s *backend.SetupState) { s.Order.Kind = 3 },
		"no order with an act time":     func(s *backend.SetupState) { s.Order = backend.Order{ActAt: 1} },
	} {
		s := testState()
		mod(&s)
		if _, err := backend.ParseSetupState(backend.AppendSetupState(nil, &s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := backend.ParseSetupState(b[1:]); err == nil {
		t.Error("short state accepted")
	}
}

func TestIdentity(t *testing.T) {
	id := &backend.Identity{State: testState(), ImportKEM: 0x647a, ImportKDF: 1, ImportAEAD: 2,
		ImportKey: bytes.Repeat([]byte{5}, 1216), TLSKeyHash: bytes.Repeat([]byte{6}, 32),
		Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}
	b, err := EncodeIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	gotID, err := DecodeIdentity(b)
	if err != nil || !reflect.DeepEqual(gotID, id) {
		t.Fatalf("%+v %v", gotID, err)
	}
	if b[0] != IdentityVersion || !bytes.Equal(b[1:1+backend.SetupStateLen], backend.AppendSetupState(nil, &id.State)) {
		t.Fatal("identity layout: version, then the setup state")
	}
	fixed := 1 + backend.SetupStateLen + 8
	for _, cut := range []int{0, 1, fixed - 1, fixed, fixed + 1216, len(b) - 1} {
		if _, err := DecodeIdentity(b[:cut]); err == nil {
			t.Fatalf("identity cut at %d accepted", cut)
		}
	}
	// An identity of another version does not read.
	for _, v := range []byte{0, 2} {
		if _, err := DecodeIdentity(append([]byte{v}, b[1:]...)); err == nil {
			t.Fatalf("identity of version %d accepted", v)
		}
	}

	// The user data covers every field: change one, get another hash.
	nonce := []byte("n")
	base := backend.IdentityUserData(nonce, id)
	mod := *id
	mod.TLSKeyHash = bytes.Repeat([]byte{7}, 32)
	if bytes.Equal(base, backend.IdentityUserData(nonce, &mod)) {
		t.Fatal("TLS key hash not bound")
	}
	mod = *id
	mod.ImportKey = append([]byte{9}, id.ImportKey[1:]...)
	if bytes.Equal(base, backend.IdentityUserData(nonce, &mod)) {
		t.Fatal("import key not bound")
	}
	if bytes.Equal(base, backend.IdentityUserData([]byte("m"), id)) {
		t.Fatal("nonce not bound")
	}
	for name, change := range map[string]func(*backend.SetupState){
		"setup_hash":        func(s *backend.SetupState) { s.SetupHash[0] ^= 1 },
		"locked version":    func(s *backend.SetupState) { s.Locked.Version++ },
		"locked hash":       func(s *backend.SetupState) { s.Locked.Hash[0] ^= 1 },
		"pending version":   func(s *backend.SetupState) { s.Locked.Pending.Version++ },
		"pending hash":      func(s *backend.SetupState) { s.Locked.Pending.Hash[0] ^= 1 },
		"pending time":      func(s *backend.SetupState) { s.Locked.Pending.EffectiveAt++ },
		"open version":      func(s *backend.SetupState) { s.Open.Version++ },
		"open hash":         func(s *backend.SetupState) { s.Open.Hash[0] ^= 1 },
		"approver set hash": func(s *backend.SetupState) { s.ApproverSetHash[0] ^= 1 },
		"order kind":        func(s *backend.SetupState) { s.Order.Kind = 2 },
		"order hash":        func(s *backend.SetupState) { s.Order.Hash[0] ^= 1 },
		"order time":        func(s *backend.SetupState) { s.Order.ActAt++ },
		"key_release_hash":  func(s *backend.SetupState) { s.KeyReleaseHash[0] ^= 1 },
	} {
		mod = *id
		change(&mod.State)
		if bytes.Equal(base, backend.IdentityUserData(nonce, &mod)) {
			t.Errorf("%s not bound", name)
		}
	}
	// The identity and the ATTEST user data are apart even over the same
	// nonce and state.
	if bytes.Equal(backend.IdentityUserData(nonce, &backend.Identity{}), backend.AttestUserData(nonce, &backend.SetupState{}, backend.KeysHash(nil))) {
		t.Fatal("IDENTITY and ATTEST user data agree")
	}
}

func TestResponses(t *testing.T) {
	body, err := DecodeResponse(EncodeOK([]byte{1, 2}))
	if err != nil || !bytes.Equal(body, []byte{1, 2}) {
		t.Fatal(body, err)
	}
	_, err = DecodeResponse(EncodeError(backend.Refused(backend.StatusSlashTarget, "target 5 <= 6")))
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != backend.StatusSlashTarget || r.Detail != "target 5 <= 6" {
		t.Fatalf("%v", err)
	}
	if !r.Code.IsSlashing() || r.Code.IsPolicy() {
		t.Fatal("classification")
	}
	_, err = DecodeResponse(EncodeError(errors.New("boom")))
	if backend.StatusOf(err) != backend.StatusInternal {
		t.Fatal(err)
	}
}

// HEALTH carries the core's counters when the runner has them, and an answer
// without them (a backend without counters) still decodes, with no stats.
func TestHealthStatsRoundTrip(t *testing.T) {
	in := &backend.Health{Platform: "dev", Validators: 3, Stats: &backend.SignerStats{
		Signatures: 10, HashCacheHits: 7, HashCacheMisses: 3, WatermarkWrites: 2, ExactRepeats: 4,
	}}
	b, err := EncodeHealth(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeHealth(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stats == nil || *out.Stats != *in.Stats {
		t.Fatalf("stats %+v, want %+v", out.Stats, in.Stats)
	}
	old, err := DecodeHealth([]byte(`{"platform":"dev","ready":true,"validators":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if old.Stats != nil {
		t.Fatalf("an answer without stats decoded with stats %+v", old.Stats)
	}
}

// HEALTH with the millisecond clock and the NTS state round-trips; an
// answer without them (a runner before them, or one without the NTS clock)
// decodes with zero and nil; and a client built before them (oldHealth
// stands for its struct) still decodes a new answer, with the fields it
// knows.
func TestHealthClockRoundTrip(t *testing.T) {
	in := &backend.Health{Platform: "nitro", Ready: true, ClockSource: "nts(a,b,c,d)", ClockTrusted: true,
		ClockUnix: 1_760_000_000, ClockUnixMS: 1_760_000_000_123,
		NTS: &backend.ClockNTS{Quorum: true, BoundNowMS: 12.5, MaxBoundMS: 100, OffsetFromHostMS: -2345.678,
			Members: []string{"a", "b", "c"}, QuorumAgeMS: 4100, Refusals: 2, DriftPPM: 3.25, DriftErrPPM: 40,
			DriftBaselineS: 990, RhoViolations: 1, CoarseDiffMS: 420}}
	b, err := EncodeHealth(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeHealth(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("decoded %+v (nts %+v), want %+v", out, out.NTS, in)
	}

	old, err := DecodeHealth([]byte(`{"platform":"azure","ready":true,"clock_source":"anchored(https-date x3)","clock_trusted":true,"clock_unix":1760000000}`))
	if err != nil {
		t.Fatal(err)
	}
	if old.ClockUnixMS != 0 || old.NTS != nil || old.ClockUnix != 1_760_000_000 || !old.ClockTrusted {
		t.Fatalf("old answer decoded as %+v", old)
	}
	noNTS, err := EncodeHealth(&backend.Health{Platform: "dev", ClockSource: "system", ClockUnix: 5, ClockUnixMS: 5_250})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(noNTS), "clock_nts") {
		t.Fatalf("a runner without the NTS clock sends clock_nts: %s", noNTS)
	}

	type oldHealth struct {
		Platform     string `json:"platform"`
		Ready        bool   `json:"ready"`
		ClockSource  string `json:"clock_source"`
		ClockTrusted bool   `json:"clock_trusted"`
		ClockUnix    uint64 `json:"clock_unix"`
	}
	var oh oldHealth
	if err := json.Unmarshal(b, &oh); err != nil {
		t.Fatalf("a client before the new fields cannot read the answer: %v", err)
	}
	if oh.ClockUnix != in.ClockUnix || oh.ClockSource != in.ClockSource || !oh.ClockTrusted || !oh.Ready {
		t.Fatalf("old client read %+v", oh)
	}
}

// CONFIG_UPDATE carries the signed update as it is, within setupwire's cap,
// and answers with an outcome and the setup state.
// Every message type has a name, the admin and handover ones too.
func TestTypeNames(t *testing.T) {
	if MsgType(0x08).String() != "CONFIG_UPDATE" || (MsgType(0x08)|ResponseFlag).String() != "CONFIG_UPDATE_RESPONSE" {
		t.Fatalf("names %v %v", MsgType(0x08), MsgType(0x08)|ResponseFlag)
	}
	for _, typ := range []MsgType{0x05, 0x07, 0x09, 0x31, 0x33} {
		if strings.HasPrefix(typ.String(), "TYPE_") {
			t.Errorf("type 0x%02x has no name", uint8(typ))
		}
	}
	if MsgType(0x7f).String() != "TYPE_0x7f" {
		t.Fatal(MsgType(0x7f).String())
	}
}

// Package wire builds without the admin codecs: none of its files imports
// wire/admin (that package imports this one).
func TestNoAdminImport(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			if strings.Contains(imp.Path.Value, "wire/admin") {
				t.Errorf("%s imports %s", f, imp.Path.Value)
			}
		}
	}
}
