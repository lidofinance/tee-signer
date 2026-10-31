package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Fuzz targets for the decoders of this package. Seeds come from the
// vectors of the unit tests. Every target checks that nothing panics and
// that what decodes encodes back to the same bytes, where the format has
// one encoding per value; the comments name the exceptions.

func seedState() backend.SetupState { return testState() }

func seedAttestation() *backend.Attestation {
	return &backend.Attestation{Platform: "nitro", Format: "aws-nitro-cose-sign1", UserData: []byte{1, 2}, Document: []byte("doc")}
}

func seedIdentity() *backend.Identity {
	return &backend.Identity{State: seedState(), ImportKEM: 0x647a, ImportKDF: 1, ImportAEAD: 2,
		ImportKey: bytes.Repeat([]byte{5}, 64), TLSKeyHash: bytes.Repeat([]byte{6}, 32), Attestation: seedAttestation()}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 6, 1, 1, 0, 0, 0, 1}) // HEALTH, id 1 (docs/protocol.md)
	var buf bytes.Buffer
	_ = WriteFrame(&buf, Frame{Type: TypeSign, ID: 42, Payload: []byte("hello")})
	f.Add(buf.Bytes())
	// A length of MaxFrame with no body (ATTEST-BUDGET-01).
	f.Add([]byte{0, 0x10, 0, 0, 1, 1, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		var fr Frame
		var err error
		// The body is allocated as its bytes arrive, not at the declared
		// length: a stalled peer holds no more memory than it sent.
		fuzzcheck.Bounded(t, len(b), func() { fr, err = ReadFrame(bytes.NewReader(b)) })
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := WriteFrame(&out, fr); err != nil {
			t.Fatalf("decoded frame does not encode: %v", err)
		}
		if n := out.Len(); n > len(b) || !bytes.Equal(out.Bytes(), b[:n]) {
			t.Fatalf("frame does not encode back:\n%x\n%x", out.Bytes(), b)
		}
	})
}

func FuzzDecodeSign(f *testing.F) {
	domain := backend.Root{0x01, 0, 0, 0, 0xd0, 0x4a}
	for _, m := range []backend.Message{
		&backend.AttestationData{Slot: 1, Index: 2, BeaconBlockRoot: backend.Root{3}, Source: backend.Checkpoint{Epoch: 4, Root: backend.Root{5}}, Target: backend.Checkpoint{Epoch: 6, Root: backend.Root{7}}},
		&backend.BeaconBlockHeader{Slot: 1, ProposerIndex: 2, ParentRoot: backend.Root{3}, StateRoot: backend.Root{4}, BodyRoot: backend.Root{5}},
		&backend.VoluntaryExit{Epoch: 1, ValidatorIndex: 2},
		&backend.ValidatorRegistration{FeeRecipient: backend.Address{1}, GasLimit: 2, Timestamp: 3, Pubkey: backend.Pubkey{4}},
		&backend.RootMessage{Type: backend.RootSyncCommitteeMessage, Epoch: 1 << 40, ObjectRoot: backend.Root{1}, Domain: backend.Root{2}},
		&backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{1}, Slot: 2, PayloadPresent: true},
		&backend.PayloadEnvelope{Payload: backend.ExecutionPayloadSummary{ParentHash: backend.Root{1}, FeeRecipient: backend.Address{2},
			GasLimit: 3, BaseFeePerGas: backend.Root{4}, BlockAccessListRoot: backend.Root{5}, SlotNumber: 6},
			ExecutionRequestsRoot: backend.Root{7}, BuilderIndex: backend.BuilderIndexSelfBuild, BeaconBlockRoot: backend.Root{8}, ParentBeaconBlockRoot: backend.Root{9}},
		&backend.ProposerPreferences{DependentRoot: backend.Root{1}, ProposalSlot: 2, ValidatorIndex: 3, FeeRecipient: backend.Address{4}, TargetGasLimit: 5},
		&backend.SelectionProof{Slot: 3},
		&backend.SyncCommitteeMessage{Slot: 4, BeaconBlockRoot: backend.Root{5}},
		&backend.SyncSelectionProof{Slot: 6, SubcommitteeIndex: 1},
		&backend.BuilderRequestAuth{Data: bytes.Repeat([]byte{0x5a}, 19), Slot: 32},
	} {
		f.Add(must(EncodeSign(backend.SignRequest{Pubkey: backend.Pubkey{1, 2, 3}, Message: m, Domain: domain})))
	}
	// Kinds 9 and 10 with a short body, and kinds the runner does not know.
	for _, k := range []byte{9, 10, 0, 15, 77} {
		f.Add(append(append(make([]byte, 48), k), make([]byte, 40)...))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		req, err := DecodeSign(b)
		if err != nil {
			return
		}
		again, err := EncodeSign(req)
		if err != nil {
			t.Fatalf("decoded %v does not encode: %v", req.Message.Kind(), err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("%v does not encode back:\n%x\n%x", req.Message.Kind(), again, b)
		}
	})
}

func FuzzDecodeAttest(f *testing.F) {
	f.Add(must(EncodeAttest([]byte("nonce"))))
	f.Add(must(EncodeAttest(bytes.Repeat([]byte{7}, 32))))
	f.Add(append([]byte{0, 32}, bytes.Repeat([]byte{7}, 32)...)) // no version byte
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		nonce, err := DecodeAttest(b)
		if err != nil {
			if errors.Is(err, ErrRequestVersion) && len(b) < 2 {
				t.Fatal("short request reported as another version")
			}
			return
		}
		if again := must(EncodeAttest(nonce)); !bytes.Equal(again, b) {
			t.Fatalf("request does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeAttestResponse(f *testing.F) {
	st := seedState()
	f.Add(must(EncodeAttestResponse(&st, seedAttestation())))
	var zero backend.SetupState
	f.Add(must(EncodeAttestResponse(&zero, &backend.Attestation{})))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		s, a, err := DecodeAttestResponse(b)
		if err != nil {
			return
		}
		again, err := EncodeAttestResponse(s, a)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("ATTEST answer does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

func FuzzDecodeIdentity(f *testing.F) {
	f.Add(must(EncodeIdentity(seedIdentity())))
	f.Add(must(EncodeIdentity(&backend.Identity{Attestation: &backend.Attestation{}})))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		id, err := DecodeIdentity(b)
		if err != nil {
			return
		}
		again, err := EncodeIdentity(id)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("identity does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

// A response: an OK body comes back as it is; an error with a detail of at
// most MaxDetail bytes encodes back (EncodeError cuts a longer one).
func FuzzDecodeResponse(f *testing.F) {
	f.Add(EncodeOK([]byte{1, 2}))
	f.Add(EncodeError(backend.Refused(backend.StatusSlashTarget, "target 5 <= 6")))
	f.Add(EncodeError(errors.New("boom")))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		body, err := DecodeResponse(b)
		if err == nil {
			if again := EncodeOK(body); !bytes.Equal(again, b) {
				t.Fatalf("OK response does not encode back:\n%x\n%x", again, b)
			}
			return
		}
		var r *backend.RefusedError
		if !errors.As(err, &r) || len(r.Detail) > MaxDetail {
			return
		}
		if r.Code == backend.StatusOK {
			t.Fatal("error response with status 0")
		}
		if again := EncodeError(r); !bytes.Equal(again, b) {
			t.Fatalf("error response does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeKeys(f *testing.F) {
	f.Add(EncodeKeys([]backend.ValidatorKey{{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3}, {Index: backend.IndexUnknown}}))
	f.Add(EncodeKeys(nil))
	f.Add(binary.BigEndian.AppendUint32(nil, 0xffffffff))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		keys, err := DecodeKeys(b)
		if err != nil {
			return
		}
		if again := EncodeKeys(keys); !bytes.Equal(again, b) {
			t.Fatalf("key list does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeAttestation(f *testing.F) {
	f.Add(must(EncodeAttestation(seedAttestation())))
	f.Add(must(EncodeAttestation(&backend.Attestation{})))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		a, err := DecodeAttestation(b)
		if err != nil {
			return
		}
		again, err := EncodeAttestation(a)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("attestation does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

// HEALTH is JSON: only "no panic" and "what decodes encodes".
func FuzzDecodeHealth(f *testing.F) {
	st := seedState()
	f.Add(must(EncodeHealth(&backend.Health{Platform: "dev", Version: "0.1.0", Ready: true, Validators: 2, Setup: &st})))
	f.Add([]byte(`{"platform":"nitro","ready":false}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		h, err := DecodeHealth(b)
		if err != nil {
			return
		}
		if _, err := EncodeHealth(h); err != nil {
			t.Fatalf("decoded health does not encode: %v", err)
		}
	})
}
