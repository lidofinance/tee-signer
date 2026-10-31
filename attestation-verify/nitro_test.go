//go:build !verifierselect

package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNitroRootPinned(t *testing.T) {
	r := NitroRoot()
	if r.Subject.CommonName != "aws.nitro-enclaves" || !r.IsCA {
		t.Fatalf("root subject %v", r.Subject)
	}
}

// Real documents from public repositories, see testdata/nitro/*/SOURCE.
// They chain to the real AWS root; their leaf certificates expired years
// ago, so they verify only at their own timestamp.
type realNitro struct {
	file  string
	b64   bool
	debug bool
	at    time.Time // the document's timestamp
	pcrs  map[int]string
}

var realNitroDocs = []realNitro{
	{file: "testdata/nitro/blocky-nitrite/nitro_attestation.b64", b64: true,
		at: time.Date(2024, 9, 7, 14, 37, 39, 545e6, time.UTC),
		pcrs: map[int]string{
			0: "e72a46ca80a260fb044a125442f0c7e331813bcbaf9724d9f3857758992766f2d65710a27aa94ae3949dd54e7c9fe86a",
			1: "0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa",
			2: "d5dcbdea0aa39c802f9d55ced2ea6e4d74ecec5f08fe40c508882639c9090642669106a062a3e24ee2805a3024b9b75c",
		}},
	{file: "testdata/nitro/blocky-nitrite/nitro_attestation_debug.b64", b64: true, debug: true,
		at: time.Date(2024, 9, 7, 14, 38, 6, 508e6, time.UTC)},
	{file: "testdata/nitro/evervault/valid-attestation-doc-bytes",
		at: time.Date(2022, 10, 13, 8, 58, 2, 136e6, time.UTC),
		pcrs: map[int]string{
			0: "f4d48b81a460c9916d1e685119074bf24660afd3e34fae9fca0a0d28d9d5599936332687e6f66fc890ac8cf150142d8b",
			1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
			2: "d8f114da658de5481f8d9ec73907feb553560787522f705c92d7d96beed8e15e2aa611984e098c576832c292e8dc469a",
			8: "8790eb3cce6c83d07e84b126dc61ca923333d6f66615c4a79157de48c5ab2418bdc60746ea7b7afbff03a1c6210201cb",
		}},
	{file: "testdata/nitro/evervault/valid-attestation-doc-base64", b64: true, debug: true,
		at: time.Date(2023, 9, 18, 15, 3, 30, 860e6, time.UTC)},
	{file: "testdata/nitro/evervault/debug-mode-attestation-doc-bytes", debug: true,
		at: time.Date(2022, 10, 12, 13, 50, 6, 81e6, time.UTC)},
}

func (r realNitro) load(t *testing.T) []byte {
	if r.b64 {
		return readB64(t, r.file)
	}
	return readFile(t, r.file)
}

func (r realNitro) opts(t *testing.T) NitroOptions {
	o := NitroOptions{Now: r.at, MaxAge: time.Minute, AllowDebug: r.debug, AcceptAnyPCRs: r.debug}
	if len(r.pcrs) > 0 {
		o.PCRs = map[int][]byte{}
		for i, h := range r.pcrs {
			o.PCRs[i] = mustHex(t, h)
		}
	}
	return o
}

func TestNitroRealDocuments(t *testing.T) {
	for _, r := range realNitroDocs {
		t.Run(r.file, func(t *testing.T) {
			doc := r.load(t)
			d, err := VerifyNitro(doc, r.opts(t))
			if err != nil {
				t.Fatalf("real document does not verify: %v", err)
			}
			if d.Debug != r.debug || !d.Timestamp.Equal(r.at) {
				t.Fatalf("debug %v ts %s", d.Debug, d.Timestamp)
			}
			for i := 0; i <= 8; i++ {
				if len(d.PCR(i)) != 48 {
					t.Fatalf("pcr%d missing", i)
				}
			}

			// The leaf certificate has expired by now.
			o := r.opts(t)
			o.Now = time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
			o.MaxAge = 0
			o.Nonce = d.Nonce
			if o.Nonce == nil {
				o.Nonce = []byte{}
			}
			_, err = VerifyNitro(doc, o)
			wantErr(t, err, ErrChain)

			// A local test CA is not the AWS root.
			o = r.opts(t)
			o.Roots = []*x509.Certificate{newTestCA(t, r.at).Root}
			_, err = VerifyNitro(doc, o)
			wantErr(t, err, ErrChain)

			// One flipped bit in the signature.
			bad := bytes.Clone(doc)
			bad[len(bad)-5] ^= 1
			_, err = VerifyNitro(bad, r.opts(t))
			wantErr(t, err, ErrSignature)

			// One flipped bit inside PCR1 in the signed payload.
			pcr1 := d.PCR(1)
			i := bytes.Index(doc, pcr1)
			if i < 0 {
				t.Fatal("pcr1 not found in the raw document")
			}
			bad = bytes.Clone(doc)
			bad[i+47] ^= 1
			_, err = VerifyNitro(bad, r.opts(t))
			wantErr(t, err, ErrSignature)

			// Stale: same document checked two minutes later with MaxAge 1m.
			o = r.opts(t)
			o.Now = r.at.Add(2 * time.Minute)
			_, err = VerifyNitro(doc, o)
			wantErr(t, err, ErrStale)

			// Wrong nonce.
			o = r.opts(t)
			o.Nonce = []byte("another nonce")
			_, err = VerifyNitro(doc, o)
			wantErr(t, err, ErrNonce)

			if r.debug {
				o = r.opts(t)
				o.AllowDebug = false
				_, err = VerifyNitro(doc, o)
				wantErr(t, err, ErrDebug)
			} else {
				o = r.opts(t)
				o.PCRs[0] = bytes.Clone(o.PCRs[0])
				o.PCRs[0][0] ^= 1
				_, err = VerifyNitro(doc, o)
				wantErr(t, err, ErrMeasurement)
			}
		})
	}
}

// The document of the runner in a real Nitro enclave (Graviton),
// testdata/nitro/aws-signer-2/SOURCE. It chains to the pinned
// AWS root. Its payload map has an indefinite length.
func TestNitroRealRunnerDocument(t *testing.T) {
	doc := readFile(t, "testdata/nitro/aws-signer-2/attestation-doc-bytes")
	at := time.UnixMilli(1792169007353).UTC()
	if !bytes.Contains(doc, []byte{0xbf, 0x69, 'm', 'o', 'd', 'u', 'l', 'e', '_', 'i', 'd'}) {
		t.Fatal("the payload map is not indefinite-length any more: this sample no longer covers that case")
	}
	pcrs := map[int]string{
		0: "34da454a0ed6db9276ffdb53eebe73c4f4cacd08f88f12fe3ccb0e88f6d3b37168cca5a4a0029bc1c5546d41c84e29b6",
		1: "745004eab9a0fb4a67973b261c6e7fa5418dc870292927591574385649338e54686cdeb659f3c6c2e72ba11aba2158a8",
		2: "614e21b3378d13214bafd07296d7d1278962832d70a90a6261a361e85abd14fc331f0054cf4f6fef5c1c9b578a85fc78",
		3: "da47f8977ae52f67364b9e1833d9b794ac6492cd9ac4cd90724e7d031b05946dd343f319b409b00f36aa8ff8c46df620",
	}
	opts := func() NitroOptions {
		o := NitroOptions{Now: at, MaxAge: time.Minute, PCRs: map[int][]byte{}}
		for i, h := range pcrs {
			o.PCRs[i] = mustHex(t, h)
		}
		return o
	}
	d, err := VerifyNitro(doc, opts())
	if err != nil {
		t.Fatalf("real document of the runner does not verify: %v", err)
	}
	if d.Debug || !d.Timestamp.Equal(at) || d.ModuleID != "i-048d4ea8214906fb3-enc01a1459504d38712" {
		t.Fatalf("debug %v ts %s module %s", d.Debug, d.Timestamp, d.ModuleID)
	}
	if len(d.UserData) != 32 || len(d.Nonce) != 32 || len(d.PCR(4)) != 48 {
		t.Fatalf("user data %d, nonce %d, pcr4 %d", len(d.UserData), len(d.Nonce), len(d.PCR(4)))
	}

	o := opts()
	o.PCRs[2] = bytes.Clone(o.PCRs[2])
	o.PCRs[2][0] ^= 1
	_, err = VerifyNitro(doc, o)
	wantErr(t, err, ErrMeasurement)

	o = opts()
	o.Roots = []*x509.Certificate{newTestCA(t, at).Root}
	_, err = VerifyNitro(doc, o)
	wantErr(t, err, ErrChain)

	bad := bytes.Clone(doc)
	bad[len(bad)-5] ^= 1
	_, err = VerifyNitro(bad, opts())
	wantErr(t, err, ErrSignature)

	o = opts()
	o.Now = at.Add(5 * time.Minute)
	_, err = VerifyNitro(doc, o)
	wantErr(t, err, ErrStale)
}

func TestNitroSynthetic(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t, now)
	roots := []*x509.Certificate{ca.Root}
	nonce := []byte("fresh nonce from the verifier 01")
	ud := []byte("identity user data")
	pk := []byte("DER public key placeholder")
	good := ca.NitroDoc(t, testgen.NitroSpec{TS: now.Add(-10 * time.Second), Nonce: nonce, UserData: ud, PublicKey: pk})
	opts := func() NitroOptions {
		return NitroOptions{Roots: roots, Now: now, PCRs: expectPCRs(0, 1, 2, 3, 8), Nonce: nonce, UserData: ud, MaxAge: time.Minute}
	}

	t.Run("good", func(t *testing.T) {
		d, err := VerifyNitro(good, opts())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(d.Nonce, nonce) || !bytes.Equal(d.UserData, ud) || !bytes.Equal(d.PublicKey, pk) || d.Debug {
			t.Fatalf("fields %+v", d)
		}
		for i := 0; i <= 8; i++ {
			if !bytes.Equal(d.PCR(i), defaultPCRs()[uint64(i)]) {
				t.Fatalf("pcr%d", i)
			}
		}
	})
	t.Run("indefinite-length payload map", func(t *testing.T) {
		// The NSM of a real enclave writes the payload map as 0xbf ... 0xff.
		p, err := cbor.Marshal(map[string]any{
			"module_id": "i-test-enc0000000000000000", "digest": "SHA384",
			"timestamp": uint64(now.UnixMilli()), "pcrs": testgen.DefaultPCRs(),
			"certificate": ca.Leaf.Raw, "cabundle": [][]byte{ca.Root.Raw, ca.Inter.Raw},
			"public_key": nil, "user_data": ud, "nonce": nonce,
		})
		if err != nil {
			t.Fatal(err)
		}
		if p[0] != 0xa9 {
			t.Fatalf("map header %#x, want 0xa9 (9 entries)", p[0])
		}
		indef := append(append([]byte{0xbf}, p[1:]...), 0xff)
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Payload: indef})
		d, err := VerifyNitro(doc, opts())
		if err != nil {
			t.Fatalf("indefinite-length payload map refused: %v", err)
		}
		if !bytes.Equal(d.Nonce, nonce) || !bytes.Equal(d.UserData, ud) {
			t.Fatalf("fields %+v", d)
		}
		// A changed byte in it still fails the signature.
		bad := bytes.Clone(doc)
		i := bytes.Index(bad, defaultPCRs()[0])
		bad[i] ^= 1
		_, err = VerifyNitro(bad, opts())
		wantErr(t, err, ErrSignature)
		// Duplicate keys stay refused in the indefinite form.
		dup := append(append([]byte{0xbf}, p[1:]...), 0x69)
		dup = append(dup, []byte("module_id")...)
		dup = append(dup, 0x61, 'x', 0xff)
		_, err = VerifyNitro(ca.NitroDoc(t, testgen.NitroSpec{TS: now, Payload: dup}), opts())
		if err == nil {
			t.Fatal("duplicate key accepted")
		}
	})
	t.Run("tagged form", func(t *testing.T) {
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud, Tagged: true})
		if _, err := VerifyNitro(doc, opts()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		bad := bytes.Clone(good)
		bad[len(bad)-1] ^= 1
		_, err := VerifyNitro(bad, opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("tampered payload", func(t *testing.T) {
		bad := bytes.Clone(good)
		i := bytes.Index(bad, ud)
		bad[i] ^= 1
		_, err := VerifyNitro(bad, opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("wrong root: pinned AWS root", func(t *testing.T) {
		o := opts()
		o.Roots = nil
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrChain)
	})
	t.Run("wrong root: other test CA", func(t *testing.T) {
		o := opts()
		o.Roots = []*x509.Certificate{newTestCA(t, now).Root}
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrChain)
	})
	t.Run("bundle names the root but chain does not reach it", func(t *testing.T) {
		other := newTestCA(t, now)
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud, Bundle: [][]byte{other.Root.Raw, ca.Inter.Raw}})
		o := opts()
		o.Roots = []*x509.Certificate{other.Root}
		_, err := VerifyNitro(doc, o)
		wantErr(t, err, ErrChain)
	})
	t.Run("expired leaf", func(t *testing.T) {
		o := opts()
		o.Now = now.Add(3 * time.Hour)
		o.MaxAge = 0
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrChain)
	})
	t.Run("wrong PCR", func(t *testing.T) {
		o := opts()
		o.PCRs[2] = pcrValue(0xff)
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrMeasurement)
	})
	t.Run("expected PCR missing from doc", func(t *testing.T) {
		o := opts()
		o.PCRs[20] = pcrValue(0x01)
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrMeasurement)
	})
	t.Run("stale nonce", func(t *testing.T) {
		o := opts()
		o.Nonce = []byte("fresh nonce from the verifier 02")
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrNonce)
	})
	t.Run("no nonce in doc", func(t *testing.T) {
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, UserData: ud})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrNonce)
	})
	t.Run("wrong user data", func(t *testing.T) {
		o := opts()
		o.UserData = []byte("other")
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrUserData)
	})
	t.Run("old timestamp", func(t *testing.T) {
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now.Add(-2 * time.Minute), Nonce: nonce, UserData: ud})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrStale)
	})
	t.Run("future timestamp", func(t *testing.T) {
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now.Add(5 * time.Minute), Nonce: nonce, UserData: ud})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrStale)
	})
	t.Run("debug mode", func(t *testing.T) {
		pcrs := defaultPCRs()
		for i := range pcrs {
			pcrs[i] = make([]byte, 48)
		}
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud, PCRs: pcrs})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrDebug)
		o := opts()
		o.AllowDebug, o.PCRs, o.AcceptAnyPCRs = true, nil, true
		d, err := VerifyNitro(doc, o)
		if err != nil || !d.Debug {
			t.Fatalf("AllowDebug: %v", err)
		}
	})
	t.Run("alg ES256 refused", func(t *testing.T) {
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud, Alg: -7})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrFormat)
	})
	t.Run("pcr8 missing", func(t *testing.T) {
		pcrs := defaultPCRs()
		delete(pcrs, 8)
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud, PCRs: pcrs})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrFormat)
	})
	t.Run("pcr of 32 bytes", func(t *testing.T) {
		pcrs := defaultPCRs()
		pcrs[5] = make([]byte, 32)
		doc := ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud, PCRs: pcrs})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrFormat)
	})
	t.Run("duplicate payload key", func(t *testing.T) {
		// A map with "nonce" twice: hand-built CBOR after a valid map.
		inner, _ := cbor.Marshal(map[string]any{"module_id": "x"})
		dup := append([]byte{0xa2}, inner[1:]...) // map of 2 pairs
		dup = append(dup, inner[1:]...)           // same key again
		doc := ca.NitroDoc(t, testgen.NitroSpec{Payload: dup})
		_, err := VerifyNitro(doc, opts())
		wantErr(t, err, ErrFormat)
	})
	t.Run("trailing bytes", func(t *testing.T) {
		_, err := VerifyNitro(append(bytes.Clone(good), 0x00), opts())
		wantErr(t, err, ErrFormat)
	})
	t.Run("config needs PCRs and freshness", func(t *testing.T) {
		o := opts()
		o.PCRs = nil
		_, err := VerifyNitro(good, o)
		wantErr(t, err, ErrConfig)
		o = opts()
		o.Nonce, o.MaxAge = nil, 0
		_, err = VerifyNitro(good, o)
		wantErr(t, err, ErrConfig)
	})
}

// An expected PCR must be 48 bytes, and the document must have that index.
// An empty expected value for an index the document lacks is refused, not
// taken as a match.
func TestNitroExpectedPCRMustBeComplete(t *testing.T) {
	r := realNitroDocs[2] // evervault, PCR0 to PCR8 and no PCR31
	doc := r.load(t)
	o := r.opts(t)
	o.PCRs[31] = []byte{}
	_, err := VerifyNitro(doc, o)
	wantErr(t, err, ErrConfig)

	o = r.opts(t)
	o.PCRs[31] = bytes.Repeat([]byte{1}, 48)
	_, err = VerifyNitro(doc, o)
	wantErr(t, err, ErrMeasurement)

	o = r.opts(t)
	o.PCRs[0] = o.PCRs[0][:32]
	_, err = VerifyNitro(doc, o)
	wantErr(t, err, ErrConfig)
}
