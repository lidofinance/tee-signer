package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// keysFile writes an interchange file of one validator whose entry is item
// (without the pubkey) and returns its path.
func keysFile(t testing.TB, dir, item string) string {
	p := filepath.Join(dir, "ic.json")
	body := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + strings.Repeat("11", 32) + `"},` +
		`"data":[{"pubkey":"0x` + strings.Repeat("a1", 48) + `",` + item + `}]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A key twice in one object, two keys that differ only in case, or a key
// that differs only in case from a field of the format refuses the file.
// encoding/json keeps the last of repeated keys and matches field names
// without case, so each of these files would carry lower maxima than the
// first key says (true maxima: slot 100, target 40).
func TestInterchangeRepeatedKeys(t *testing.T) {
	const (
		blocks = `"signed_blocks":[{"slot":"100"}]`
		atts   = `"signed_attestations":[{"source_epoch":"3","target_epoch":"40"}]`
	)
	cases := map[string]string{
		"signed_blocks twice":           blocks + `,"signed_blocks":[],` + atts,
		"slot and Slot":                 `"signed_blocks":[{"slot":"100","Slot":"1"}],` + atts,
		"target_epoch and Target_epoch": blocks + `,"signed_attestations":[{"source_epoch":"3","target_epoch":"40","Target_epoch":"4"}]`,
		"signed_attestations twice":     blocks + `,` + atts + `,"signed_attestations":[{"source_epoch":"1","target_epoch":"2"}]`,
		"slot twice, one escaped":       `"signed_blocks":[{"slot":"100","\u0073lot":"1"}],` + atts,
		"Slot alone":                    `"signed_blocks":[{"slot":"100"},{"Slot":"1"}],` + atts,
		"slot with a long s":            `"signed_blocks":[{"slot":"100"},{"ſlot":"1"}],` + atts,
		"Signed_Blocks alone":           `"Signed_Blocks":[{"slot":"100"}],` + atts,
		"an unknown key twice":          blocks + `,` + atts + `,"x":1,"x":2`,
	}
	for name, item := range cases {
		ic, err := loadInterchange(keysFile(t, t.TempDir(), item))
		if err == nil {
			t.Errorf("%s: accepted with maxima %+v", name, ic.marks)
		}
	}
	// The data array twice: the second hides the first.
	p := filepath.Join(t.TempDir(), "ic.json")
	body := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + strings.Repeat("11", 32) + `"},` +
		`"data":[{"pubkey":"0x` + strings.Repeat("a1", 48) + `",` + blocks + `}],"data":[]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if ic, err := loadInterchange(p); err == nil {
		t.Errorf("data twice: accepted with maxima %+v", ic.marks)
	}
	// Keys that differ in more than case, and distinct unknown keys, stay.
	if _, err := loadInterchange(keysFile(t, t.TempDir(), blocks+`,`+atts+`,"slots":1,"x":1,"y":{"x":1}`)); err != nil {
		t.Errorf("distinct keys refused: %v", err)
	}
}

// Any bytes as an interchange file: when the parser accepts one, no object
// repeats a key, and the maxima are what a reader that matches each key
// exactly finds. The check reads the file with its own code: a generic
// decode and a count of the colons outside strings.
func FuzzInterchangeKeys(f *testing.F) {
	pk := "0x" + strings.Repeat("a1", 48)
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + strings.Repeat("11", 32) + `"},"data":[` +
		`{"pubkey":"` + pk + `","signed_blocks":[{"slot":"100","signing_root":"0x01"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"40"}]}]}`))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + strings.Repeat("11", 32) + `"},"data":[` +
		`{"pubkey":"` + pk + `","signed_blocks":[{"slot":"100","Slot":"1"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"40","target_epoch":"4"}]}]}`))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + strings.Repeat("11", 32) + `","Metadata":{}},"data":[],"Data":[]}`))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		path := filepath.Join(dir, "ic.json")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		ic, err := loadInterchange(path)
		if err != nil {
			return
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("accepted a file that is not JSON: %v", err)
		}
		if got, want := countKeys(v), colons(b); got != want {
			t.Fatalf("accepted a file with a repeated key: %d keys after decoding, %d in the text", got, want)
		}
		want, err := exactMaxima(v)
		if err != nil {
			t.Fatalf("accepted a file an exact reader refuses: %v", err)
		}
		if !reflect.DeepEqual(ic.marks, want) {
			t.Fatalf("maxima %+v, an exact reader finds %+v", ic.marks, want)
		}
	})
}

// countKeys is the number of keys in all objects of v.
func countKeys(v any) int {
	n := 0
	switch v := v.(type) {
	case map[string]any:
		n += len(v)
		for _, e := range v {
			n += countKeys(e)
		}
	case []any:
		for _, e := range v {
			n += countKeys(e)
		}
	}
	return n
}

// colons is the number of colons outside strings in valid JSON b, which is
// the number of keys it writes.
func colons(b []byte) int {
	n, in, esc := 0, false, false
	for _, c := range b {
		switch {
		case esc:
			esc = false
		case in && c == '\\':
			esc = true
		case c == '"':
			in = !in
		case !in && c == ':':
			n++
		}
	}
	return n
}

// exactMaxima reads the maxima of each validator from a generic decode,
// matching keys exactly.
func exactMaxima(v any) (map[cloud.Pubkey]cloud.Watermark, error) {
	top, _ := v.(map[string]any)
	data, _ := top["data"].([]any)
	num := func(o map[string]any, k string) (uint64, error) {
		s, _ := o[k].(string)
		return strconv.ParseUint(s, 10, 64)
	}
	out := map[cloud.Pubkey]cloud.Watermark{}
	for _, d := range data {
		e, _ := d.(map[string]any)
		s, _ := e["pubkey"].(string)
		raw, err := decodeHexN(s, 48)
		if err != nil {
			return nil, err
		}
		pk := cloud.Pubkey(raw)
		w := out[pk]
		bs, _ := e["signed_blocks"].([]any)
		for _, x := range bs {
			o, _ := x.(map[string]any)
			slot, err := num(o, "slot")
			if err != nil {
				return nil, err
			}
			w.BlockSlot, w.HasBlock = max(w.BlockSlot, slot), true
		}
		as, _ := e["signed_attestations"].([]any)
		for _, x := range as {
			o, _ := x.(map[string]any)
			src, err := num(o, "source_epoch")
			if err != nil {
				return nil, err
			}
			tgt, err := num(o, "target_epoch")
			if err != nil {
				return nil, err
			}
			w.SourceEpoch, w.TargetEpoch, w.HasAttestation = max(w.SourceEpoch, src), max(w.TargetEpoch, tgt), true
		}
		out[pk] = w
	}
	return out, nil
}
