package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// interchangeFile is the part of an EIP-3076 slashing protection file
// (format version 5) that import needs. Ported from the signing client's
// cloud-import.
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
