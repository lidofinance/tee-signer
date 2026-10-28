package admin

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

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

func seedState() backend.SetupState { return testState() }

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestImport(t *testing.T) {
	imp := backend.ImportShareRequest{Pubkey: backend.Pubkey{9}, Secret: [32]byte{8}, Index: 7,
		Interchange: &backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}}
	got, err := DecodeImport(EncodeImport(imp))
	if err != nil || !reflect.DeepEqual(got, imp) {
		t.Fatalf("%+v %v", got, err)
	}
	imp.Interchange = nil
	if got, _ := DecodeImport(EncodeImport(imp)); got.Interchange != nil {
		t.Fatal("empty interchange should decode as nil")
	}

}

func TestSealedImport(t *testing.T) {
	req := backend.SealedImportRequest{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3,
		Interchange: &backend.Watermark{HasBlock: true, BlockSlot: 99}, Sealed: []byte("enc-and-ciphertext")}
	p, err := EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[:SealedHeaderLen], SealedHeader(&req)) {
		t.Fatal("header prefix")
	}
	got, err := DecodeImportSealed(p)
	if err != nil || !reflect.DeepEqual(got, req) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeImportSealed(p[:len(p)-1]); err == nil {
		t.Fatal("truncated sealed share accepted")
	}
	if _, err := DecodeImportSealed(append(p, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}

}

func TestConfigUpdate(t *testing.T) {
	if MaxConfigUpdate != setupwire.MaxUpdate {
		t.Fatalf("MaxConfigUpdate %d, setupwire.MaxUpdate %d", MaxConfigUpdate, setupwire.MaxUpdate)
	}
	if TypeConfigUpdate.String() != "CONFIG_UPDATE" || (TypeConfigUpdate|wire.ResponseFlag).String() != "CONFIG_UPDATE_RESPONSE" {
		t.Fatalf("names %v %v", TypeConfigUpdate, TypeConfigUpdate|wire.ResponseFlag)
	}
	update := bytes.Repeat([]byte{'U'}, 300)
	p, err := EncodeConfigUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeConfigUpdate(p); err != nil || !bytes.Equal(got, update) {
		t.Fatalf("%x %v", got, err)
	}
	for _, n := range []int{0, MaxConfigUpdate + 1} {
		if _, err := EncodeConfigUpdate(make([]byte, n)); err == nil {
			t.Errorf("encoded an update of %d bytes", n)
		}
		if _, err := DecodeConfigUpdate(make([]byte, n)); err == nil {
			t.Errorf("decoded an update of %d bytes", n)
		}
	}

	st := testState()
	for _, outcome := range []uint8{ConfigAccepted, ConfigKnown} {
		b := EncodeConfigUpdateResponse(outcome, &st)
		if len(b) != 2+backend.SetupStateLen {
			t.Fatalf("answer of %d bytes", len(b))
		}
		got, s, err := DecodeConfigUpdateResponse(b)
		if err != nil || got != outcome || *s != st {
			t.Fatalf("outcome %d state %+v %v", got, s, err)
		}
	}
	good := EncodeConfigUpdateResponse(ConfigAccepted, &st)
	for name, b := range map[string][]byte{
		"empty":         nil,
		"version 2":     append([]byte{2}, good[1:]...),
		"outcome 0":     append([]byte{good[0], 0}, good[2:]...),
		"outcome 3":     append([]byte{good[0], 3}, good[2:]...),
		"short":         good[:len(good)-1],
		"trailing byte": append(append([]byte{}, good...), 0),
		"bad state":     append(append([]byte{}, good[:2]...), make([]byte, backend.SetupStateLen)...),
	} {
		if name == "bad state" {
			// Locked: active version 2, pending version 1.
			b[2+32+7], b[2+32+8+32+7] = 2, 1
		}
		if _, _, err := DecodeConfigUpdateResponse(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// IMPORT_SHARE and IMPORT_SHARE_SEALED: with flags 0 the decoder drops the
// three maxima, whatever they hold, so only a value round trip holds there.
func interchangeCanonical(flags byte, maxima []byte) bool {
	return flags != 0 || bytes.Equal(maxima, make([]byte, 24))
}

func FuzzDecodeImport(f *testing.F) {
	imp := backend.ImportShareRequest{Pubkey: backend.Pubkey{9}, Secret: [32]byte{8}, Index: 7,
		Interchange: &backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}}
	f.Add(EncodeImport(imp))
	imp.Interchange = nil
	f.Add(EncodeImport(imp))
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := DecodeImport(b)
		if err != nil {
			return
		}
		again := EncodeImport(req)
		if interchangeCanonical(b[88], b[89:]) && !bytes.Equal(again, b) {
			t.Fatalf("IMPORT_SHARE does not encode back:\n%x\n%x", again, b)
		}
		if req2, err := DecodeImport(again); err != nil || !reflect.DeepEqual(req2, req) {
			t.Fatalf("IMPORT_SHARE value round trip: %+v %v", req2, err)
		}
	})
}

func FuzzDecodeImportSealed(f *testing.F) {
	req := backend.SealedImportRequest{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3,
		Interchange: &backend.Watermark{HasBlock: true, BlockSlot: 99}, Sealed: []byte("enc-and-ciphertext")}
	f.Add(must(EncodeImportSealed(&req)))
	req.Interchange, req.Sealed = nil, nil
	f.Add(must(EncodeImportSealed(&req)))
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := DecodeImportSealed(b)
		if err != nil {
			return
		}
		again, err := EncodeImportSealed(&req)
		if err != nil {
			t.Fatalf("decoded sealed import does not encode: %v", err)
		}
		if interchangeCanonical(b[104], b[105:SealedHeaderLen]) && !bytes.Equal(again, b) {
			t.Fatalf("IMPORT_SHARE_SEALED does not encode back:\n%x\n%x", again, b)
		}
		if req2, err := DecodeImportSealed(again); err != nil || !reflect.DeepEqual(req2, req) {
			t.Fatalf("IMPORT_SHARE_SEALED value round trip: %+v %v", req2, err)
		}
	})
}

func FuzzDecodeConfigUpdateResponse(f *testing.F) {
	st := seedState()
	f.Add(EncodeConfigUpdateResponse(ConfigAccepted, &st))
	f.Add(EncodeConfigUpdateResponse(ConfigKnown, &backend.SetupState{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		outcome, s, err := DecodeConfigUpdateResponse(b)
		if err != nil {
			return
		}
		if again := EncodeConfigUpdateResponse(outcome, s); !bytes.Equal(again, b) {
			t.Fatalf("CONFIG_UPDATE answer does not encode back:\n%x\n%x", again, b)
		}
	})
}
