package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// interchangeFile is the part of an EIP-3076 slashing protection file
// (format version 5) that signer-admin import needs.
type interchangeFile struct {
	Metadata struct {
		FormatVersion         string `json:"interchange_format_version"`
		GenesisValidatorsRoot string `json:"genesis_validators_root"`
	} `json:"metadata"`
	Data []struct {
		Pubkey       string `json:"pubkey"`
		SignedBlocks []struct {
			Slot string `json:"slot"`
		} `json:"signed_blocks"`
		SignedAttestations []struct {
			SourceEpoch string `json:"source_epoch"`
			TargetEpoch string `json:"target_epoch"`
		} `json:"signed_attestations"`
	} `json:"data"`
}

// interchange holds the maxima of each validator of one EIP-3076 file.
type interchange struct {
	gvr   cloud.Root
	marks map[cloud.Pubkey]cloud.Watermark
}

func decodeHexN(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("want %d bytes of hex", n)
	}
	return b, nil
}

// loadInterchange reads an EIP-3076 file and reduces each validator's
// history to its maxima (the minimal strategy): the highest block slot, the
// highest source and the highest target epoch. Entries of one validator in
// several data items are merged.
func loadInterchange(path string) (*interchange, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := checkKeys(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var f interchangeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Metadata.FormatVersion != "5" {
		return nil, fmt.Errorf("%s: interchange_format_version %q, want \"5\"", path, f.Metadata.FormatVersion)
	}
	g, err := decodeHexN(f.Metadata.GenesisValidatorsRoot, 32)
	if err != nil {
		return nil, fmt.Errorf("%s: genesis_validators_root: %w", path, err)
	}
	ic := &interchange{gvr: cloud.Root(g), marks: map[cloud.Pubkey]cloud.Watermark{}}
	num := func(s, what string, pk cloud.Pubkey) (uint64, error) {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %v: %s %q is not a decimal number", path, pk, what, s)
		}
		return v, nil
	}
	for _, d := range f.Data {
		raw, err := decodeHexN(d.Pubkey, 48)
		if err != nil {
			return nil, fmt.Errorf("%s: pubkey %q: %w", path, d.Pubkey, err)
		}
		pk := cloud.Pubkey(raw)
		w := ic.marks[pk]
		for _, sb := range d.SignedBlocks {
			slot, err := num(sb.Slot, "slot", pk)
			if err != nil {
				return nil, err
			}
			if !w.HasBlock || slot > w.BlockSlot {
				w.BlockSlot = slot
			}
			w.HasBlock = true
		}
		for _, sa := range d.SignedAttestations {
			src, err := num(sa.SourceEpoch, "source_epoch", pk)
			if err != nil {
				return nil, err
			}
			tgt, err := num(sa.TargetEpoch, "target_epoch", pk)
			if err != nil {
				return nil, err
			}
			if src > tgt {
				return nil, fmt.Errorf("%s: %v: source epoch %d above target epoch %d", path, pk, src, tgt)
			}
			if !w.HasAttestation || src > w.SourceEpoch {
				w.SourceEpoch = src
			}
			if !w.HasAttestation || tgt > w.TargetEpoch {
				w.TargetEpoch = tgt
			}
			w.HasAttestation = true
		}
		ic.marks[pk] = w
	}
	return ic, nil
}

// interchangeKeys are the keys of interchangeFile.
var interchangeKeys = []string{"metadata", "interchange_format_version", "genesis_validators_root", "data",
	"pubkey", "signed_blocks", "slot", "signed_attestations", "source_epoch", "target_epoch"}

// checkKeys refuses JSON in which one object has a key twice, or two keys
// that differ only in case, or which has a key that differs only in case
// from a key of interchangeFile. encoding/json keeps the last of repeated
// keys and matches keys to fields without regard to case, so such a file
// could carry lower maxima than its first keys show to a person or to
// another tool. It checks keys only; json.Unmarshal checks the rest.
func checkKeys(b []byte) error {
	known := map[string]string{}
	for _, k := range interchangeKeys {
		known[foldKey(k)] = k
	}
	// One frame per open object or array; keys is nil for an array.
	type frame struct {
		keys    map[string]string // folded key to the key as written
		wantKey bool
	}
	var stack []*frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].keys != nil {
			stack[n-1].wantKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n := len(stack); n > 0 && stack[n-1].wantKey {
			top := stack[n-1]
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			k, _ := tok.(string)
			f := foldKey(k)
			switch prev, ok := top.keys[f]; {
			case ok && prev == k:
				return fmt.Errorf("key %q twice in one object", k)
			case ok:
				return fmt.Errorf("keys %q and %q in one object differ only in case", prev, k)
			}
			if want, ok := known[f]; ok && want != k {
				return fmt.Errorf("key %q: the format's key is %q", k, want)
			}
			top.keys[f] = k
			top.wantKey = false
			continue
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{keys: map[string]string{}, wantKey: true})
		case json.Delim('['):
			stack = append(stack, &frame{})
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

// foldKey maps s to one string for all strings strings.EqualFold holds
// equal: each rune becomes the smallest rune of its case folding orbit.
func foldKey(s string) string {
	var sb strings.Builder
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			m = min(m, f)
		}
		sb.WriteRune(m)
	}
	return sb.String()
}

// markOf returns the maxima of validator pk, or nil when its entry holds no
// signed block and no signed attestation (nothing to carry). A validator the
// file does not list is an error: the import was asked to carry its history.
func (ic *interchange) markOf(pk cloud.Pubkey) (*cloud.Watermark, error) {
	w, ok := ic.marks[pk]
	if !ok {
		return nil, fmt.Errorf("the interchange file has no entry for validator %v", pk)
	}
	if !w.HasBlock && !w.HasAttestation {
		return nil, nil
	}
	return &w, nil
}
