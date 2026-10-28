package nitro

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
)

// syntheticDocument is a COSE_Sign1 document in the documented shape with
// these PCRs (TestParseDocumentSynthetic's form).
func syntheticDocument(t *testing.T, pcrs map[int][]byte) []byte {
	t.Helper()
	payload, err := cbor.Marshal(map[string]any{"module_id": "i-0123-enc0123", "digest": "SHA384", "timestamp": uint64(1), "pcrs": pcrs})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := cbor.Marshal([]any{[]byte{0xa1, 0x01, 0x38, 0x22}, map[any]any{}, payload, make([]byte, 96)})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// The runner's own image is PCR0, PCR1 and PCR2 of the NSM document KMS
// takes as recipient, in that order; PCR3 and up are not part of it. A
// document short of one of them, or with a PCR of another size, gives no
// image.
func TestDocumentImage(t *testing.T) {
	pcr := func(b byte) []byte { return bytes.Repeat([]byte{b}, 48) }
	im, err := documentImage(syntheticDocument(t, map[int][]byte{0: pcr(0xa0), 1: pcr(0xa1), 2: pcr(0xa2), 3: pcr(0xa3), 8: pcr(0xa8)}))
	want := append(append(pcr(0xa0), pcr(0xa1)...), pcr(0xa2)...)
	if err != nil || im.Kind != setupwire.ImageNitro || !bytes.Equal(im.Measurement, want) {
		t.Fatalf("image %s %x, %v", im.Kind, im.Measurement, err)
	}
	for _, c := range []struct {
		name string
		pcrs map[int][]byte
		want string
	}{
		{"no PCR2", map[int][]byte{0: pcr(1), 1: pcr(1)}, "no PCR2"},
		{"PCR1 of 32 bytes", map[int][]byte{0: pcr(1), 1: make([]byte, 32), 2: pcr(1)}, "PCR1 is 32 bytes"},
	} {
		if _, err := documentImage(syntheticDocument(t, c.pcrs)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	if _, err := documentImage([]byte("nsm document")); err == nil {
		t.Fatal("a document that does not parse")
	}

	// Recorded per key release: the same document twice is one image,
	// another one makes the image unknown.
	seen := &platform.ImageSeen{}
	doc := syntheticDocument(t, map[int][]byte{0: pcr(1), 1: pcr(2), 2: pcr(3)})
	seen.Record(documentImage(doc))
	seen.Record(documentImage(doc))
	if _, err := seen.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen.Record(documentImage(syntheticDocument(t, map[int][]byte{0: pcr(1), 1: pcr(2), 2: pcr(4)})))
	if _, err := seen.Get(context.Background()); err == nil {
		t.Fatal("two images, one answer")
	}
}
