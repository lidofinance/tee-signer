package markformat

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

func TestWatermarkStorageFormat(t *testing.T) {
	w := backend.Watermark{
		BlockSlot: 0x0807060504030201, SourceEpoch: 0x1817161514131211,
		TargetEpoch: 0x2827262524232221, HasBlock: true, HasAttestation: true,
	}
	const record = "5343573103000000010203040506070811121314151617182122232425262728"
	b, err := hex.DecodeString(record)
	if err != nil {
		t.Fatal(err)
	}
	if got := EncodeWatermark(w); !bytes.Equal(got, b) {
		t.Fatalf("storage format changed: %x", got)
	}
	if got, err := DecodeWatermark(b); err != nil || got != w {
		t.Fatalf("decode: %+v, %v", got, err)
	}
	for flags := byte(0); flags < 4; flags++ {
		b[4] = flags
		w.HasBlock, w.HasAttestation = flags&1 != 0, flags&2 != 0
		got, err := DecodeWatermark(b)
		if err != nil || got != w {
			t.Fatalf("flags %d: %+v, %v", flags, got, err)
		}
	}
}

func TestWatermarkRejectsMalformedRecords(t *testing.T) {
	b := EncodeWatermark(backend.Watermark{})
	for n := 0; n <= WatermarkEncodedLen+1; n++ {
		if n == WatermarkEncodedLen {
			continue
		}
		if _, err := DecodeWatermark(make([]byte, n)); err == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
	for i := range 8 {
		for bit := byte(1); bit != 0; bit <<= 1 {
			if i == 4 && bit <= 2 {
				continue
			}
			bad := bytes.Clone(b)
			bad[i] ^= bit
			if _, err := DecodeWatermark(bad); err == nil {
				t.Fatalf("accepted changed header byte %d, bit %x", i, bit)
			}
		}
	}
}

func FuzzWatermarkStorageRecord(f *testing.F) {
	f.Add(EncodeWatermark(backend.Watermark{}))
	f.Add(EncodeWatermark(backend.Watermark{BlockSlot: ^uint64(0), SourceEpoch: 2, TargetEpoch: 1, HasAttestation: true}))
	f.Add([]byte("SCW1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		w, err := DecodeWatermark(b)
		if err == nil && !bytes.Equal(EncodeWatermark(w), b) {
			t.Fatalf("accepted record does not preserve its bytes: %x", b)
		}
	})
}
