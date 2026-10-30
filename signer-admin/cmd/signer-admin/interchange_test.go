package main

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// An EIP-3076 file reduces to each validator's maxima, entries of one
// validator merged; a validator without history carries none, one the file
// does not list is an error, and so is a source above its target.
func TestInterchange(t *testing.T) {
	pk1, pk2 := "0x"+strings.Repeat("a1", 48), "0x"+strings.Repeat("b2", 48)
	file := func(body string) string {
		p := filepath.Join(t.TempDir(), "ic.json")
		if err := os.WriteFile(p, []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x`+
			strings.Repeat("11", 32)+`"},"data":[`+body+`]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ic, err := loadInterchange(file(`{"pubkey":"` + pk1 + `","signed_blocks":[{"slot":"100"},{"slot":"90"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]},` +
		`{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"4","target_epoch":"5"}]},` +
		`{"pubkey":"` + pk2 + `","signed_blocks":[],"signed_attestations":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var p1, p2, p3 cloud.Pubkey
	_ = p1.UnmarshalText([]byte(pk1))
	_ = p2.UnmarshalText([]byte(pk2))
	p3[0] = 1
	w, err := ic.markOf(p1)
	if err != nil || w == nil || *w != (cloud.Watermark{HasBlock: true, BlockSlot: 100, HasAttestation: true, SourceEpoch: 4, TargetEpoch: 5}) {
		t.Fatalf("validator 1: %+v %v", w, err)
	}
	if w, err := ic.markOf(p2); err != nil || w != nil {
		t.Fatalf("validator 2: %+v %v", w, err)
	}
	if _, err := ic.markOf(p3); err == nil {
		t.Fatal("a validator the file does not list")
	}
	if _, err := loadInterchange(file(`{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"6","target_epoch":"5"}]}`)); err == nil {
		t.Fatal("a source above its target")
	}
}

const (
	icGVR = "0x1111111111111111111111111111111111111111111111111111111111111111"
	icPK1 = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	icPK2 = "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

// icFile writes an EIP-3076 file with version 5, icGVR and the given data
// items, and returns its path.
func icFile(t *testing.T, items ...string) string {
	t.Helper()
	return icRaw(t, icFileBody(items...))
}

func icFileBody(items ...string) string {
	return `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"},"data":[` + strings.Join(items, ",") + `]}`
}

func icRaw(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ic.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func icPubkey(t *testing.T, hex string) cloud.Pubkey {
	t.Helper()
	var pk cloud.Pubkey
	if err := pk.UnmarshalText([]byte(hex)); err != nil {
		t.Fatal(err)
	}
	return pk
}

// The numbers of an interchange file are decimal strings, as the format
// says, and nothing else: a number the parser cannot read refuses the file
// rather than becoming 0 and lowering a maximum. The same rule applies to
// a slot, a source epoch and a target epoch.
func TestInterchangeNumbers(t *testing.T) {
	const max = "18446744073709551615"
	cases := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"0", 0, true},
		{"42", 42, true},
		{"007", 7, true}, // leading zeros read as decimal
		{max, math.MaxUint64, true},
		{"18446744073709551616", 0, false}, // one above uint64
		{"-1", 0, false},
		{"1.5", 0, false},
		{"1e3", 0, false},
		{"0x10", 0, false},
		{"12abc", 0, false},
		{" 1", 0, false},
		{"1 ", 0, false},
		{"", 0, false},
		{"+1", 0, false},
		{"１", 0, false}, // a full-width digit one
	}
	for _, c := range cases {
		// The value as a slot, as a source (with the highest target, so
		// it is never above it) and as a target (with source 0).
		files := map[string]string{
			"slot":   icFile(t, `{"pubkey":"`+icPK1+`","signed_blocks":[{"slot":"`+c.in+`"}],"signed_attestations":[]}`),
			"source": icFile(t, `{"pubkey":"`+icPK1+`","signed_blocks":[],"signed_attestations":[{"source_epoch":"`+c.in+`","target_epoch":"`+max+`"}]}`),
			"target": icFile(t, `{"pubkey":"`+icPK1+`","signed_blocks":[],"signed_attestations":[{"source_epoch":"0","target_epoch":"`+c.in+`"}]}`),
		}
		for field, path := range files {
			ic, err := loadInterchange(path)
			if !c.ok {
				if err == nil || !strings.Contains(err.Error(), "not a decimal number") {
					t.Errorf("%s %q: accepted (%v), want a refusal", field, c.in, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s %q: %v", field, c.in, err)
				continue
			}
			w := ic.marks[icPubkey(t, icPK1)]
			got := map[string]uint64{"slot": w.BlockSlot, "source": w.SourceEpoch, "target": w.TargetEpoch}[field]
			if got != c.want {
				t.Errorf("%s %q: read as %d, want %d", field, c.in, got, c.want)
			}
		}
	}
	// A JSON number where the format wants a string is refused too.
	for _, body := range []string{
		`{"pubkey":"` + icPK1 + `","signed_blocks":[{"slot":100}],"signed_attestations":[]}`,
		`{"pubkey":"` + icPK1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":1,"target_epoch":"2"}]}`,
		`{"pubkey":"` + icPK1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"1","target_epoch":2}]}`,
	} {
		if _, err := loadInterchange(icFile(t, body)); err == nil {
			t.Errorf("a JSON number accepted: %s", body)
		}
	}
}

// The file's shape: metadata, the data array, pubkeys, optional and
// unknown fields, and what refuses the whole file.
func TestInterchangeShape(t *testing.T) {
	meta := func(version, gvr string) string {
		return `{"metadata":{"interchange_format_version":` + version + `,"genesis_validators_root":` + gvr + `},"data":[]}`
	}
	entry := func(pubkey, blocks, attestations string) string {
		return `{"pubkey":` + pubkey + `,"signed_blocks":` + blocks + `,"signed_attestations":` + attestations + `}`
	}
	pk1 := icPubkey(t, icPK1)
	none := map[cloud.Pubkey]cloud.Watermark{}
	one := map[cloud.Pubkey]cloud.Watermark{
		pk1: {HasBlock: true, BlockSlot: 10, HasAttestation: true, SourceEpoch: 1, TargetEpoch: 2},
	}
	empty := map[cloud.Pubkey]cloud.Watermark{pk1: {}}
	cases := []struct {
		name string
		body string
		err  string                           // a part of the error, or "" for success
		want map[cloud.Pubkey]cloud.Watermark // on success
	}{
		{"version 4", meta(`"4"`, `"`+icGVR+`"`), "interchange_format_version", nil},
		{"version 6", meta(`"6"`, `"`+icGVR+`"`), "interchange_format_version", nil},
		{"version as a number", meta(`5`, `"`+icGVR+`"`), "cannot unmarshal number", nil},
		{"version missing", `{"metadata":{"genesis_validators_root":"` + icGVR + `"},"data":[]}`, "interchange_format_version", nil},
		{"metadata missing", `{"data":[]}`, "interchange_format_version", nil},
		{"metadata not an object", `{"metadata":[],"data":[]}`, "cannot unmarshal", nil},
		{"gvr missing", `{"metadata":{"interchange_format_version":"5"},"data":[]}`, "genesis_validators_root", nil},
		{"gvr null", meta(`"5"`, `null`), "genesis_validators_root", nil},
		{"gvr short", meta(`"5"`, `"0x1111"`), "genesis_validators_root", nil},
		{"gvr long", meta(`"5"`, `"`+icGVR+`11"`), "genesis_validators_root", nil},
		{"gvr not hex", meta(`"5"`, `"0x`+strings.Repeat("zz", 32)+`"`), "genesis_validators_root", nil},
		{"gvr without 0x", meta(`"5"`, `"`+strings.TrimPrefix(icGVR, "0x")+`"`), "", none},
		{"not JSON", `{"metadata":`, "unexpected end", nil},
		{"data missing", `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"}}`, "", none},
		{"data null", `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"},"data":null}`, "", none},
		{"data empty", icFileBody(), "", none},
		{"data an object", `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"},"data":{}}`, "cannot unmarshal object", nil},
		{"data a string", `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"},"data":"x"}`, "cannot unmarshal string", nil},
		{"pubkey 47 bytes", icFileBody(entry(`"`+icPK1[:len(icPK1)-2]+`"`, `[]`, `[]`)), "pubkey", nil},
		{"pubkey 49 bytes", icFileBody(entry(`"`+icPK1+`ff"`, `[]`, `[]`)), "pubkey", nil},
		{"pubkey not hex", icFileBody(entry(`"0x`+strings.Repeat("zz", 48)+`"`, `[]`, `[]`)), "pubkey", nil},
		{"pubkey missing", icFileBody(`{"signed_blocks":[],"signed_attestations":[]}`), "pubkey", nil},
		{"pubkey null", icFileBody(entry(`null`, `[]`, `[]`)), "pubkey", nil},
		{"pubkey a number", icFileBody(entry(`1`, `[]`, `[]`)), "cannot unmarshal number", nil},
		{"pubkey upper case", icFileBody(entry(`"`+strings.ToUpper(icPK1[2:])+`"`, `[{"slot":"10"}]`, `[{"source_epoch":"1","target_epoch":"2"}]`)), "", one},
		{"signing_root absent", icFileBody(entry(`"`+icPK1+`"`, `[{"slot":"10"}]`, `[{"source_epoch":"1","target_epoch":"2"}]`)), "", one},
		{"signing_root null", icFileBody(entry(`"`+icPK1+`"`, `[{"slot":"10","signing_root":null}]`, `[{"source_epoch":"1","target_epoch":"2","signing_root":null}]`)), "", one},
		{"signing_root malformed", icFileBody(entry(`"`+icPK1+`"`, `[{"slot":"10","signing_root":"zz"}]`, `[{"source_epoch":"1","target_epoch":"2","signing_root":7}]`)), "", one},
		{"unknown fields", `{"extra":1,"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `","extra":[]},"data":[{"extra":{},"pubkey":"` + icPK1 + `","signed_blocks":[{"slot":"10","extra":"x"}],"signed_attestations":[{"source_epoch":"1","target_epoch":"2","extra":null}]}]}`, "", one},
		{"both lists empty", icFileBody(entry(`"`+icPK1+`"`, `[]`, `[]`)), "", empty},
		{"both lists null", icFileBody(entry(`"`+icPK1+`"`, `null`, `null`)), "", empty},
		{"both lists missing", icFileBody(`{"pubkey":"` + icPK1 + `"}`), "", empty},
		{"blocks an object", icFileBody(entry(`"`+icPK1+`"`, `{}`, `[]`)), "cannot unmarshal object", nil},
		{"a block without a slot", icFileBody(entry(`"`+icPK1+`"`, `[{}]`, `[]`)), "not a decimal number", nil},
		{"an attestation without a target", icFileBody(entry(`"`+icPK1+`"`, `[]`, `[{"source_epoch":"1"}]`)), "not a decimal number", nil},
		{"source above target in one of three entries", icFileBody(
			entry(`"`+icPK1+`"`, `[]`, `[{"source_epoch":"1","target_epoch":"2"}]`),
			entry(`"`+icPK2+`"`, `[]`, `[{"source_epoch":"3","target_epoch":"2"}]`),
			entry(`"`+icPK1+`"`, `[]`, `[{"source_epoch":"4","target_epoch":"5"}]`)), "source epoch 3 above target epoch 2", nil},
		{"source equal to target", icFileBody(entry(`"`+icPK1+`"`, `[]`, `[{"source_epoch":"2","target_epoch":"2"}]`)), "",
			map[cloud.Pubkey]cloud.Watermark{pk1: {HasAttestation: true, SourceEpoch: 2, TargetEpoch: 2}}},
	}
	for _, c := range cases {
		ic, err := loadInterchange(icRaw(t, c.body))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: got %v, want an error with %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(ic.marks, c.want) {
			t.Errorf("%s: marks %+v, want %+v", c.name, ic.marks, c.want)
		}
	}
	// A file with no entry for a validator: markOf refuses it; an entry
	// that holds nothing carries nothing.
	ic, err := loadInterchange(icFile(t, entry(`"`+icPK1+`"`, `[]`, `[]`)))
	if err != nil {
		t.Fatal(err)
	}
	if w, err := ic.markOf(pk1); err != nil || w != nil {
		t.Errorf("an entry with nothing: %+v %v", w, err)
	}
	if _, err := ic.markOf(icPubkey(t, icPK2)); err == nil {
		t.Error("a validator the file does not list was accepted")
	}
}

// One validator's entries, wherever they are in the file and in whatever
// order, reduce to the same maxima: the highest slot, source and target,
// each on its own.
func TestInterchangeOrderIndependent(t *testing.T) {
	entries := []string{
		`{"pubkey":"` + icPK1 + `","signed_blocks":[{"slot":"100"}],"signed_attestations":[]}`,
		`{"pubkey":"` + icPK2 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]}`,
		`{"pubkey":"` + icPK1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"1","target_epoch":"9"}]}`,
		`{"pubkey":"` + icPK1 + `","signed_blocks":[{"slot":"50"}],"signed_attestations":[{"source_epoch":"5","target_epoch":"6"}]}`,
	}
	want := map[cloud.Pubkey]cloud.Watermark{
		icPubkey(t, icPK1): {HasBlock: true, BlockSlot: 100, HasAttestation: true, SourceEpoch: 5, TargetEpoch: 9},
		icPubkey(t, icPK2): {HasAttestation: true, SourceEpoch: 3, TargetEpoch: 4},
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 24; i++ {
		order := append([]string(nil), entries...)
		r.Shuffle(len(order), func(a, b int) { order[a], order[b] = order[b], order[a] })
		ic, err := loadInterchange(icFile(t, order...))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ic.marks, want) {
			t.Fatalf("order %d: marks %+v, want %+v", i, ic.marks, want)
		}
	}
}

// Any bytes as an interchange file: the parser never panics; when it
// accepts the file, every validator's maxima are exactly the highest slot,
// source and target of its entries (so no entry sits above them), and the
// entries in another order give the same maxima.
func FuzzLoadInterchange(f *testing.F) {
	f.Add([]byte(icFileBody(
		`{"pubkey":"`+icPK1+`","signed_blocks":[{"slot":"100","signing_root":"0x01"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]}`,
		`{"pubkey":"`+icPK2+`","signed_blocks":[],"signed_attestations":[{"source_epoch":"4","target_epoch":"5"},{"source_epoch":"1","target_epoch":"9"}]}`,
		`{"pubkey":"`+icPK1+`","signed_blocks":[{"slot":"18446744073709551615"}],"signed_attestations":[]}`)))
	f.Add([]byte(icFileBody()))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"}}`))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"4","genesis_validators_root":"` + icGVR + `"},"data":[]}`))
	f.Add([]byte(icFileBody(`{"pubkey":"` + icPK1 + `","signed_blocks":[{"slot":"-1"}],"signed_attestations":[]}`)))
	f.Add([]byte(icFileBody(`{"pubkey":"` + icPK1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"5","target_epoch":"4"}]}`)))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + icGVR + `"},"data":[1]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, b []byte) {
		path := filepath.Join(dir, "ic.json")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		ic, err := loadInterchange(path)
		if err != nil {
			return
		}
		// The maxima against the entries, read once more with the same
		// struct and the same number rule.
		var file interchangeFile
		if err := json.Unmarshal(b, &file); err != nil {
			t.Fatalf("accepted a file that does not decode: %v", err)
		}
		want := map[cloud.Pubkey]cloud.Watermark{}
		for _, d := range file.Data {
			raw, err := decodeHexN(d.Pubkey, 48)
			if err != nil {
				t.Fatalf("accepted pubkey %q: %v", d.Pubkey, err)
			}
			w := want[cloud.Pubkey(raw)]
			for _, sb := range d.SignedBlocks {
				slot, err := strconv.ParseUint(sb.Slot, 10, 64)
				if err != nil {
					t.Fatalf("accepted slot %q: %v", sb.Slot, err)
				}
				w.BlockSlot = max(w.BlockSlot, slot)
				w.HasBlock = true
			}
			for _, sa := range d.SignedAttestations {
				src, err := strconv.ParseUint(sa.SourceEpoch, 10, 64)
				if err != nil {
					t.Fatalf("accepted source %q: %v", sa.SourceEpoch, err)
				}
				tgt, err := strconv.ParseUint(sa.TargetEpoch, 10, 64)
				if err != nil {
					t.Fatalf("accepted target %q: %v", sa.TargetEpoch, err)
				}
				if src > tgt {
					t.Fatalf("accepted source %d above target %d", src, tgt)
				}
				w.SourceEpoch = max(w.SourceEpoch, src)
				w.TargetEpoch = max(w.TargetEpoch, tgt)
				w.HasAttestation = true
			}
			want[cloud.Pubkey(raw)] = w
		}
		if !reflect.DeepEqual(ic.marks, want) {
			t.Fatalf("marks %+v, want the maxima of the entries %+v", ic.marks, want)
		}
		// The entries in another order.
		var loose struct {
			Metadata json.RawMessage   `json:"metadata"`
			Data     []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(b, &loose); err != nil {
			t.Fatalf("accepted a file whose data is not an array: %v", err)
		}
		r := rand.New(rand.NewPCG(uint64(len(b)), uint64(len(loose.Data))))
		r.Shuffle(len(loose.Data), func(a, b int) { loose.Data[a], loose.Data[b] = loose.Data[b], loose.Data[a] })
		again, err := json.Marshal(loose)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, again, 0o644); err != nil {
			t.Fatal(err)
		}
		ic2, err := loadInterchange(path)
		if err != nil {
			t.Fatalf("the entries in another order refused: %v\n%s", err, again)
		}
		if !reflect.DeepEqual(ic2.marks, ic.marks) {
			t.Fatalf("the entries in another order give %+v, the original %+v", ic2.marks, ic.marks)
		}
	})
}
