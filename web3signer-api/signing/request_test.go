package signing

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
)

// The vectors are the request examples from Web3Signer 26.9.0
// openapi-specs/eth2/signing/paths/sign.yaml (Apache-2.0), converted to JSON by
// tools/specvectors. Each carries the signingRoot Web3Signer computes.
const vectorsFile = "testdata/web3signer-26.9.0-sign-examples.json"

var testChain = mustChain("minimal")

func loadVectors(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}

	return v
}

// Some examples in the spec still use camelCase fork keys, which Web3Signer's
// own parser (schema/Fork.java) does not accept. Rename them.
func fixForkKeys(b []byte) []byte {
	s := strings.NewReplacer(`"previousVersion"`, `"previous_version"`, `"currentVersion"`, `"current_version"`).Replace(string(b))

	return []byte(s)
}

func TestWeb3SignerExampleSigningRoots(t *testing.T) {
	vectors := loadVectors(t)
	names := make([]string, 0, len(vectors))
	for n := range vectors {
		names = append(names, n)
	}
	sort.Strings(names)

	// Types the gateway does not handle; Parse must return a bad request.
	// The EXECUTION_PAYLOAD_ENVELOPE example has a 262-byte logs_bloom (256
	// in the spec), so it is a bad request too.
	unsupported := map[string]bool{"BLOCK": true, "DEPOSIT": true, "EXECUTION_PAYLOAD_ENVELOPE": true}
	// Gloas types: the examples carry no signingRoot. The test chain has no
	// Gloas fork, so each parses to a job policy refuses (gloas_test.go
	// covers them with one).
	gloasOnly := map[string]bool{
		"EXECUTION_PAYLOAD_BID": true, "PAYLOAD_ATTESTATION_MESSAGE": true,
		"PROPOSER_PREFERENCES": true, "BUILDER_REQUEST_AUTH": true,
	}
	// The Electra-format aggregate examples mix presets: committee_bits has the
	// mainnet size (8 bytes) while the other examples use minimal. Neither
	// preset reproduces their signingRoot (mainnet gives 0x1180bcb4..., minimal
	// rejects the committee_bits length). TestElectraAggregateAndProof covers
	// the Electra path with mainnet sizes.
	const mixed = "example mixes mainnet committee_bits with minimal preset"
	knownBad := map[string]string{
		"AGGREGATE_AND_PROOF_V2 (ELECTRA)": mixed,
		"AGGREGATE_AND_PROOF_V2 (FULU)":    mixed,
		"AGGREGATE_AND_PROOF_V2 (GLOAS)":   mixed,
	}

	checked := 0
	for _, name := range names {
		raw := fixForkKeys(vectors[name])
		var head struct {
			Type        string `json:"type"`
			SigningRoot string `json:"signingRoot"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Run(name, func(t *testing.T) {
			job, err := Parse(raw, testChain)
			switch {
			case unsupported[head.Type]:
				if !IsBadRequest(err) {
					t.Fatalf("want bad request for unsupported type, got job=%v err=%v", job, err)
				}
				return
			case gloasOnly[head.Type]:
				if err != nil || job.Method != MethodNone || job.Refusal == "" {
					t.Fatalf("want a refused job without Gloas in the chain, got job=%v err=%v", job, err)
				}
				return
			case knownBad[name] != "":
				if err == nil {
					t.Fatalf("expected failure (%s) but parsed", knownBad[name])
				}
				t.Skipf("%s: %v", knownBad[name], err)
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if job.Method == MethodNone {
				return // voluntary exit: no root computed
			}
			if head.SigningRoot == "" {
				t.Fatalf("example has no signingRoot")
			}
			if got := fmt.Sprintf("%#x", job.SigningRoot); got != head.SigningRoot {
				t.Fatalf("signing root %s, Web3Signer example says %s", got, head.SigningRoot)
			}
			checked++
		})
	}
	if checked < 15 {
		t.Fatalf("only %d examples checked", checked)
	}
	t.Logf("%d signing roots match Web3Signer", checked)
}

func TestMethodPerType(t *testing.T) {
	vectors := loadVectors(t)
	want := map[string]Method{
		"ATTESTATION":                      MethodAttestation,
		"BLOCK_V2 (PHASE 0)":               MethodProposal,
		"BLOCK_V2 (ALTAIR)":                MethodProposal,
		"BLOCK_V2 (ELECTRA)":               MethodProposal,
		"RANDAO_REVEAL":                    MethodGeneric,
		"AGGREGATION_SLOT":                 MethodGeneric,
		"AGGREGATE_AND_PROOF (DEPRECATED)": MethodGeneric,
		"AGGREGATE_AND_PROOF_V2 (DENEB)":   MethodGeneric,
		"SYNC_COMMITTEE_MESSAGE":           MethodGeneric,
		"SYNC_COMMITTEE_SELECTION_PROOF":   MethodGeneric,
		"VALIDATOR_REGISTRATION":           MethodGeneric,
		"VOLUNTARY_EXIT":                   MethodNone,
	}
	for name, m := range want {
		job, err := Parse(fixForkKeys(vectors[name]), testChain)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if job.Method != m {
			t.Errorf("%s: method %v, want %v", name, job.Method, m)
		}
	}
}

func TestDomainTypes(t *testing.T) {
	vectors := loadVectors(t)
	want := map[string]phase0.DomainType{
		"ATTESTATION":                      eth2.DomainBeaconAttester,
		"BLOCK_V2 (ELECTRA)":               eth2.DomainBeaconProposer,
		"RANDAO_REVEAL":                    eth2.DomainRandao,
		"AGGREGATION_SLOT":                 eth2.DomainSelectionProof,
		"AGGREGATE_AND_PROOF_V2 (PHASE 0)": eth2.DomainAggregateAndProof,
		"SYNC_COMMITTEE_MESSAGE":           eth2.DomainSyncCommittee,
		"SYNC_COMMITTEE_SELECTION_PROOF":   eth2.DomainSyncCommitteeSelectionProof,
		"VALIDATOR_REGISTRATION":           eth2.DomainApplicationBuilder,
	}
	for name, dt := range want {
		job, err := Parse(fixForkKeys(vectors[name]), testChain)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if [4]byte(job.Domain[:4]) != dt {
			t.Errorf("%s: domain type %#x, want %#x", name, job.Domain[:4], dt)
		}
	}
}

// The ALTAIR block example has a 4-byte sync_committee_bits (minimal preset).
// Hashing it with mainnet sizes must not silently produce Web3Signer's root:
// the preset is part of the gateway config for a reason.
func TestPresetMatters(t *testing.T) {
	raw := fixForkKeys(loadVectors(t)["BLOCK_V2 (ALTAIR)"])
	if _, err := Parse(raw, testChain); err != nil {
		t.Fatalf("minimal: %v", err)
	}
	if _, err := Parse(raw, mustChain("mainnet")); err == nil {
		t.Fatal("mainnet preset accepted a minimal-preset block with the minimal signing root")
	}
}

// Electra-format AggregateAndProof with mainnet sizes (8-byte committee_bits).
func TestElectraAggregateAndProof(t *testing.T) {
	body := `{"type":"AGGREGATE_AND_PROOF_V2",
	"fork_info":{"fork":{"previous_version":"0x05000000","current_version":"0x06000000","epoch":"411392"},
	  "genesis_validators_root":"0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"},
	"aggregate_and_proof":{"version":"ELECTRA","data":{"aggregator_index":"1",
	  "aggregate":{"aggregation_bits":"0x0000000000000000000000000000000000000000000101",
	    "data":{"slot":"13164544","index":"0","beacon_block_root":"0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
	      "source":{"epoch":"411391","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},
	      "target":{"epoch":"411392","root":"0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"}},
	    "signature":"0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
	    "committee_bits":"0x0000000000000001"},
	  "selection_proof":"0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"}}}`
	job, err := Parse([]byte(body), mustChain("mainnet"))
	if err != nil {
		t.Fatal(err)
	}
	if job.Method != MethodGeneric || [4]byte(job.Domain[:4]) != eth2.DomainAggregateAndProof {
		t.Fatalf("method %v domain %#x", job.Method, job.Domain)
	}
	// Slot 13164544 is epoch 411392 = fork epoch: current version 0x06000000.
	gvr := phase0.Root{}
	copy(gvr[:], mustHex(t, "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"))
	want, err := eth2.ComputeDomain(eth2.DomainAggregateAndProof, phase0.Version{0x06, 0, 0, 0}, gvr)
	if err != nil {
		t.Fatal(err)
	}
	if job.Domain != want {
		t.Fatalf("domain %#x, want %#x", job.Domain, want)
	}
}

// With a 16-byte aggregation_bits (mainnet) the contribution parses and uses the
// contribution-and-proof domain at the contribution's epoch.
func TestContributionAndProofRoot(t *testing.T) {
	body := `{"type":"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
	"fork_info":{"fork":{"previous_version":"0x00000001","current_version":"0x00000002","epoch":"1"},
	  "genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"},
	"contribution_and_proof":{"aggregator_index":"11",
	  "selection_proof":"0x8f5c34de9e22ceaa7e8d165fc0553b32f02188539e89e2cc91e2eb9077645986550d872ee3403204ae5d554eae3cac12124e18d2324bccc814775316aaef352abc0450812b3ca9fde96ecafa911b3b8bfddca8db4027f08e29c22a9c370ad933",
	  "contribution":{"slot":"40","beacon_block_root":"0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
	    "subcommittee_index":"1","aggregation_bits":"0x24000000000000000000000000000000",
	    "signature":"0x9005ed0936f527d416609285b355fe6b9610d730c18b9d2f4942ba7d0eb95ba304ff46b6a2fb86f0c756bf09274db8e11399b7642f9fc5ae50b5bd9c1d87654277a19bfc3df78d36da16f44a48630d9550774a4ca9f3a5b55bbf33345ad2ec71"}}}`
	job, err := Parse([]byte(body), mustChain("mainnet"))
	if err != nil {
		t.Fatal(err)
	}
	if job.Method != MethodGeneric || [4]byte(job.Domain[:4]) != eth2.DomainContributionAndProof {
		t.Fatalf("method %v domain %#x", job.Method, job.Domain)
	}
	// Slot 40 is epoch 1 >= fork epoch 1: the current version (0x00000002) applies.
	gvr := phase0.Root{}
	copy(gvr[:], mustHex(t, "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"))
	want, err := eth2.ComputeDomain(eth2.DomainContributionAndProof, phase0.Version{0, 0, 0, 2}, gvr)
	if err != nil {
		t.Fatal(err)
	}
	if job.Domain != want {
		t.Fatalf("domain %#x, want %#x", job.Domain, want)
	}
}

func TestForkVersionSelection(t *testing.T) {
	mk := func(target string) []byte {
		return []byte(`{"type":"ATTESTATION","fork_info":{"fork":{"previous_version":"0x00000001","current_version":"0x00000002","epoch":"10"},
		"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"},
		"attestation":{"slot":"1","index":"0","beacon_block_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
		"source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},
		"target":{"epoch":"` + target + `","root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89"}}}`)
	}
	before, err := Parse(mk("9"), testChain)
	if err != nil {
		t.Fatal(err)
	}
	at, err := Parse(mk("10"), testChain)
	if err != nil {
		t.Fatal(err)
	}
	gvr := phase0.Root{}
	copy(gvr[:], mustHex(t, "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"))
	prev, _ := eth2.ComputeDomain(eth2.DomainBeaconAttester, phase0.Version{0, 0, 0, 1}, gvr)
	cur, _ := eth2.ComputeDomain(eth2.DomainBeaconAttester, phase0.Version{0, 0, 0, 2}, gvr)
	if before.Domain != prev {
		t.Errorf("target epoch 9 < fork epoch 10 should use previous_version")
	}
	if at.Domain != cur {
		t.Errorf("target epoch 10 >= fork epoch 10 should use current_version")
	}
}

func TestBadRequests(t *testing.T) {
	vectors := loadVectors(t)
	att := string(vectors["ATTESTATION"])
	cases := map[string]string{
		"not json":           `{`,
		"no type":            `{}`,
		"unknown type":       `{"type":"NOPE"}`,
		"missing payload":    `{"type":"ATTESTATION","fork_info":{"fork":{"previous_version":"0x00000001","current_version":"0x00000001","epoch":"1"},"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"}}`,
		"missing fork_info":  strings.Replace(att, `"fork_info"`, `"fork_info_x"`, 1),
		"wrong signing root": strings.Replace(att, "0x548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0", "0x"+strings.Repeat("00", 32), 1),
		"bad epoch":          `{"type":"RANDAO_REVEAL","fork_info":{"fork":{"previous_version":"0x00000001","current_version":"0x00000001","epoch":"1"},"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"},"randao_reveal":{"epoch":"-1"}}`,
		"bad block version":  `{"type":"BLOCK_V2","fork_info":{"fork":{"previous_version":"0x00000001","current_version":"0x00000001","epoch":"1"},"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"},"beacon_block":{"version":"NOPE"}}`,
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body), testChain); !IsBadRequest(err) {
			t.Errorf("%s: want bad request, got %v", name, err)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	r, err := parseRoot("0x" + s)
	if err != nil {
		t.Fatal(err)
	}

	return r[:]
}

// mustChain builds a chain for preset with genesis fork version 0x00000001,
// the value the Web3Signer examples were computed with.
func mustChain(preset string) Chain {
	h, err := eth2.NewHasher(preset)
	if err != nil {
		panic(err)
	}

	return Chain{Hasher: h, SlotsPerEpoch: h.SlotsPerEpoch(), GenesisForkVersion: phase0.Version{0x00, 0x00, 0x00, 0x01}}
}

// The subcommittee index must survive parsing: each index has its own root.
func TestSyncSelectionProofKeepsSubcommitteeIndex(t *testing.T) {
	chain := testChain
	const forkInfo = `{"fork":{"previous_version":"0x00000001","current_version":"0x00000001","epoch":"1"},"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"}`
	roots := map[string]bool{}
	for _, idx := range []string{"0", "1", "2", "3"} {
		body := []byte(`{"type":"SYNC_COMMITTEE_SELECTION_PROOF","fork_info":` + forkInfo +
			`,"sync_aggregator_selection_data":{"slot":"64","subcommittee_index":"` + idx + `"}}`)
		job, err := Parse(body, chain)
		if err != nil {
			t.Fatalf("index %s: %v", idx, err)
		}
		data, ok := job.Typed.(*altair.SyncAggregatorSelectionData)
		if !ok {
			t.Fatalf("index %s: typed is %T", idx, job.Typed)
		}
		if got := fmt.Sprint(data.SubcommitteeIndex); got != idx || data.Slot != 64 {
			t.Fatalf("index %s: parsed slot %d index %s", idx, data.Slot, got)
		}
		roots[fmt.Sprintf("%x", job.SigningRoot)] = true
	}
	if len(roots) != 4 {
		t.Fatalf("want 4 distinct signing roots, got %d", len(roots))
	}
	bad := []byte(`{"type":"SYNC_COMMITTEE_SELECTION_PROOF","fork_info":` + forkInfo +
		`,"sync_aggregator_selection_data":{"slot":"64"}}`)
	if _, err := Parse(bad, chain); err == nil {
		t.Fatal("missing subcommittee_index accepted")
	}
}

// The Web3Signer Gloas examples parse with Gloas at genesis: the PTC vote,
// the preferences and builder authentication as typed jobs; the bid is
// refused. The envelope example has a malformed logs_bloom (262 bytes); with
// that fixed it is the envelope of builder 1, not a self-build, so refused.
func TestWeb3SignerGloasExamples(t *testing.T) {
	vectors := loadVectors(t)
	chain := mustChain("minimal")
	zero := phase0.Epoch(0)
	chain.GloasForkEpoch = &zero
	want := map[string]Method{
		"PAYLOAD_ATTESTATION_MESSAGE (GLOAS)": MethodTyped, "PROPOSER_PREFERENCES (GLOAS)": MethodTyped,
		"EXECUTION_PAYLOAD_BID (GLOAS)": MethodNone,
		"BUILDER_REQUEST_AUTH (GLOAS)":  MethodTyped,
	}
	for name, method := range want {
		job, err := Parse(fixForkKeys(vectors[name]), chain)
		if err != nil || job.Method != method {
			t.Errorf("%s: job %v, err %v; want method %v", name, job, err, method)
		}
	}
	// The builder authentication example (data "builder.example.org", slot
	// 32) has the plain Container root go-eth2-client v0.30.3 gives (the
	// Dirk fork's builder auth vectors) and the builder domain with
	// the genesis fork version 0x00000001 and a zero root.
	job, err := Parse(fixForkKeys(vectors["BUILDER_REQUEST_AUTH (GLOAS)"]), chain)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", job.ObjectRoot); got != "a41492397cdff5d90327742c39f1432e34dc4b08ad473638417b218cef9533e1" {
		t.Errorf("builder request auth example root %s", got)
	}
	domain, _ := eth2.ComputeDomain(eth2.DomainBuilderRequestAuth, phase0.Version{0, 0, 0, 1}, phase0.Root{})
	if job.Domain != domain {
		t.Errorf("builder request auth example domain %#x, want %#x", job.Domain, domain)
	}
	if want, _ := eth2.SigningRoot(job.ObjectRoot, domain); job.SigningRoot != want {
		t.Errorf("builder request auth example signing root %#x, want %#x", job.SigningRoot, want)
	}
	env := string(fixForkKeys(vectors["EXECUTION_PAYLOAD_ENVELOPE (GLOAS)"]))
	if _, err := Parse([]byte(env), chain); !IsBadRequest(err) {
		t.Errorf("envelope example with a 262-byte logs_bloom: %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(env), &req); err != nil {
		t.Fatal(err)
	}
	payload := req["execution_payload_envelope"].(map[string]any)["data"].(map[string]any)["payload"].(map[string]any)
	payload["logs_bloom"] = "0x" + strings.Repeat("00", 256)
	fixed, _ := json.Marshal(req)
	if job, err := Parse(fixed, chain); err != nil || job.Method != MethodNone || !strings.Contains(job.Refusal, "self-built") {
		t.Errorf("envelope example, logs_bloom fixed: job %v, err %v", job, err)
	}
}
