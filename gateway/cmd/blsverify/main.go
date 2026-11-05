// Command blsverify checks a gateway signature on a Web3Signer request without
// reusing any gateway or signer code: the signing root comes from SSZ hashing
// written out by hand on crypto/sha256, and the BLS check uses blst (the
// gateway combines with herumi).
//
// Supported request types: ATTESTATION, BLOCK_V2 (block_header versions),
// RANDAO_REVEAL, AGGREGATION_SLOT, SYNC_COMMITTEE_MESSAGE, VALIDATOR_REGISTRATION.
// Mainnet preset (32 slots per epoch).
//
// Usage:
//
//	blsverify -request req.json -root-only
//	blsverify -request req.json -pubkey 0x.. -signature 0x..
//
// Exit status 0 means the signature verifies.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	blst "github.com/supranational/blst/bindings/go"
)

// Ethereum consensus BLS ciphersuite (proof-of-possession scheme, min-pk).
var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

const slotsPerEpoch = 32

type chunk = [32]byte

type checkpoint struct {
	Epoch string `json:"epoch"`
	Root  string `json:"root"`
}

type request struct {
	Type     string `json:"type"`
	ForkInfo struct {
		Fork struct {
			PreviousVersion string `json:"previous_version"`
			CurrentVersion  string `json:"current_version"`
			Epoch           string `json:"epoch"`
		} `json:"fork"`
		GenesisValidatorsRoot string `json:"genesis_validators_root"`
	} `json:"fork_info"`
	Attestation *struct {
		Slot            string     `json:"slot"`
		Index           string     `json:"index"`
		BeaconBlockRoot string     `json:"beacon_block_root"`
		Source          checkpoint `json:"source"`
		Target          checkpoint `json:"target"`
	} `json:"attestation"`
	BeaconBlock *struct {
		Version     string `json:"version"`
		BlockHeader *struct {
			Slot          string `json:"slot"`
			ProposerIndex string `json:"proposer_index"`
			ParentRoot    string `json:"parent_root"`
			StateRoot     string `json:"state_root"`
			BodyRoot      string `json:"body_root"`
		} `json:"block_header"`
	} `json:"beacon_block"`
	RandaoReveal *struct {
		Epoch string `json:"epoch"`
	} `json:"randao_reveal"`
	AggregationSlot *struct {
		Slot string `json:"slot"`
	} `json:"aggregation_slot"`
	SyncCommitteeMessage *struct {
		BeaconBlockRoot string `json:"beacon_block_root"`
		Slot            string `json:"slot"`
	} `json:"sync_committee_message"`
	ValidatorRegistration *struct {
		FeeRecipient string `json:"fee_recipient"`
		GasLimit     string `json:"gas_limit"`
		Timestamp    string `json:"timestamp"`
		Pubkey       string `json:"pubkey"`
	} `json:"validator_registration"`
}

var genesisForkVersion = flag.String("genesis-fork-version", "0x00000000", "for VALIDATOR_REGISTRATION")

func main() {
	reqPath := flag.String("request", "", "Web3Signer request body (JSON file)")
	pubHex := flag.String("pubkey", "", "BLS public key, 0x hex (48 bytes)")
	sigHex := flag.String("signature", "", "BLS signature, 0x hex (96 bytes)")
	rootOnly := flag.Bool("root-only", false, "print the signing root and exit")
	flag.Parse()

	b, err := os.ReadFile(*reqPath)
	if err != nil {
		fail(err)
	}
	var req request
	if err := json.Unmarshal(b, &req); err != nil {
		fail(err)
	}
	root, err := signingRoot(&req)
	if err != nil {
		fail(err)
	}
	if *rootOnly {
		fmt.Printf("%#x\n", root)
		return
	}
	fmt.Printf("type: %s\nsigning_root (independent): %#x\n", req.Type, root)

	pub, err := decodeHex(*pubHex, 48)
	if err != nil {
		fail(fmt.Errorf("pubkey: %w", err))
	}
	sig, err := decodeHex(*sigHex, 96)
	if err != nil {
		fail(fmt.Errorf("signature: %w", err))
	}
	pk := new(blst.P1Affine).Uncompress(pub)
	if pk == nil {
		fail(errors.New("pubkey is not a valid compressed G1 point"))
	}
	s := new(blst.P2Affine).Uncompress(sig)
	if s == nil {
		fail(errors.New("signature is not a valid compressed G2 point"))
	}
	if !s.Verify(true, pk, true, root[:], dst) {
		fmt.Println("blst verify: FAIL")
		os.Exit(1)
	}
	fmt.Println("blst verify: OK")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "blsverify:", err)
	os.Exit(2)
}

// signingRoot returns compute_signing_root(object, domain) for the request.
func signingRoot(req *request) (chunk, error) {
	var (
		object     chunk
		domainType [4]byte
		epoch      uint64
		err        error
	)
	switch req.Type {
	case "ATTESTATION":
		a := req.Attestation
		if a == nil {
			return object, errors.New("no attestation")
		}
		var l [5]chunk
		if l[0], err = uintChunk(a.Slot); err != nil {
			return object, err
		}
		if l[1], err = uintChunk(a.Index); err != nil {
			return object, err
		}
		if l[2], err = root32(a.BeaconBlockRoot); err != nil {
			return object, err
		}
		if l[3], err = checkpointRoot(a.Source); err != nil {
			return object, err
		}
		if l[4], err = checkpointRoot(a.Target); err != nil {
			return object, err
		}
		object = merkleize(l[:])
		domainType = [4]byte{0x01}
		epoch, err = strconv.ParseUint(a.Target.Epoch, 10, 64)
	case "BLOCK_V2":
		if req.BeaconBlock == nil || req.BeaconBlock.BlockHeader == nil {
			return object, errors.New("only block_header requests are supported")
		}
		h := req.BeaconBlock.BlockHeader
		var l [5]chunk
		if l[0], err = uintChunk(h.Slot); err != nil {
			return object, err
		}
		if l[1], err = uintChunk(h.ProposerIndex); err != nil {
			return object, err
		}
		if l[2], err = root32(h.ParentRoot); err != nil {
			return object, err
		}
		if l[3], err = root32(h.StateRoot); err != nil {
			return object, err
		}
		if l[4], err = root32(h.BodyRoot); err != nil {
			return object, err
		}
		object = merkleize(l[:])
		domainType = [4]byte{0x00}
		epoch, err = epochOfSlot(h.Slot)
	case "RANDAO_REVEAL":
		if req.RandaoReveal == nil {
			return object, errors.New("no randao_reveal")
		}
		object, err = uintChunk(req.RandaoReveal.Epoch)
		domainType = [4]byte{0x02}
		if err == nil {
			epoch, err = strconv.ParseUint(req.RandaoReveal.Epoch, 10, 64)
		}
	case "AGGREGATION_SLOT":
		if req.AggregationSlot == nil {
			return object, errors.New("no aggregation_slot")
		}
		object, err = uintChunk(req.AggregationSlot.Slot)
		domainType = [4]byte{0x05}
		if err == nil {
			epoch, err = epochOfSlot(req.AggregationSlot.Slot)
		}
	case "SYNC_COMMITTEE_MESSAGE":
		m := req.SyncCommitteeMessage
		if m == nil {
			return object, errors.New("no sync_committee_message")
		}
		object, err = root32(m.BeaconBlockRoot)
		domainType = [4]byte{0x07}
		if err == nil {
			epoch, err = epochOfSlot(m.Slot)
		}
	case "VALIDATOR_REGISTRATION":
		return registrationRoot(req)
	default:
		return object, fmt.Errorf("unsupported type %q", req.Type)
	}
	if err != nil {
		return object, err
	}

	forkEpoch, err := strconv.ParseUint(req.ForkInfo.Fork.Epoch, 10, 64)
	if err != nil {
		return object, fmt.Errorf("fork epoch: %w", err)
	}
	versionHex := req.ForkInfo.Fork.CurrentVersion
	if epoch < forkEpoch {
		versionHex = req.ForkInfo.Fork.PreviousVersion
	}
	gvr, err := root32(req.ForkInfo.GenesisValidatorsRoot)
	if err != nil {
		return object, err
	}
	domain, err := computeDomain(domainType, versionHex, gvr)
	if err != nil {
		return object, err
	}

	return hash(object, domain), nil
}

// registrationRoot: ValidatorRegistrationV1 under DOMAIN_APPLICATION_BUILDER,
// genesis fork version, zero genesis_validators_root.
func registrationRoot(req *request) (chunk, error) {
	var zero chunk
	r := req.ValidatorRegistration
	if r == nil {
		return zero, errors.New("no validator_registration")
	}
	fee, err := decodeHex(r.FeeRecipient, 20)
	if err != nil {
		return zero, err
	}
	pub, err := decodeHex(r.Pubkey, 48)
	if err != nil {
		return zero, err
	}
	var l [4]chunk
	copy(l[0][:], fee)
	if l[1], err = uintChunk(r.GasLimit); err != nil {
		return zero, err
	}
	if l[2], err = uintChunk(r.Timestamp); err != nil {
		return zero, err
	}
	var p0, p1 chunk // Bytes48 is two chunks, the second zero-padded.
	copy(p0[:], pub[:32])
	copy(p1[:], pub[32:])
	l[3] = hash(p0, p1)
	domain, err := computeDomain([4]byte{0x00, 0x00, 0x00, 0x01}, *genesisForkVersion, zero)
	if err != nil {
		return zero, err
	}

	return hash(merkleize(l[:]), domain), nil
}

// computeDomain: domain_type ++ hash_tree_root(ForkData(version, gvr))[:28].
func computeDomain(domainType [4]byte, versionHex string, gvr chunk) (chunk, error) {
	var domain chunk
	version, err := decodeHex(versionHex, 4)
	if err != nil {
		return domain, fmt.Errorf("fork version: %w", err)
	}
	var versionChunk chunk
	copy(versionChunk[:], version)
	forkDataRoot := hash(versionChunk, gvr)
	copy(domain[:4], domainType[:])
	copy(domain[4:], forkDataRoot[:28])

	return domain, nil
}

func checkpointRoot(c checkpoint) (chunk, error) {
	epoch, err := uintChunk(c.Epoch)
	if err != nil {
		return epoch, err
	}
	root, err := root32(c.Root)
	if err != nil {
		return root, err
	}

	return hash(epoch, root), nil
}

// merkleize pads leaves with zero chunks to a power of two and hashes pairwise.
func merkleize(leaves []chunk) chunk {
	n := 1
	for n < len(leaves) {
		n *= 2
	}
	layer := make([]chunk, n)
	copy(layer, leaves)
	for len(layer) > 1 {
		next := make([]chunk, len(layer)/2)
		for i := range next {
			next[i] = hash(layer[2*i], layer[2*i+1])
		}
		layer = next
	}

	return layer[0]
}

func hash(a, b chunk) chunk {
	return sha256.Sum256(append(a[:], b[:]...))
}

func epochOfSlot(s string) (uint64, error) {
	slot, err := strconv.ParseUint(s, 10, 64)

	return slot / slotsPerEpoch, err
}

func uintChunk(s string) (chunk, error) {
	var c chunk
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return c, err
	}
	binary.LittleEndian.PutUint64(c[:8], v)

	return c, nil
}

func root32(s string) (chunk, error) {
	var r chunk
	b, err := decodeHex(s, 32)
	if err != nil {
		return r, err
	}
	copy(r[:], b)

	return r, nil
}

func decodeHex(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("want %d bytes, got %d", n, len(b))
	}

	return b, nil
}
