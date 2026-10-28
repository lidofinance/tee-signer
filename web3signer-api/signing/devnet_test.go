package signing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// devnetPin is the chain of a local devnet (devnet/network_params.yaml): genesis
// fork 0x10000038, then Altair to Fulu, all at epoch 0.
func devnetPin(t *testing.T) *Pin {
	t.Helper()
	gvr, err := parseRoot("0xd1ec305b97bf6336571c2348e4a8bf173684b0cdb7e55f7e6554d51f8478b5a3")
	if err != nil {
		t.Fatal(err)
	}
	p := &Pin{GenesisValidatorsRoot: gvr, Forks: []ForkEpoch{{0, phase0.Version{0x10, 0, 0, 0x38}}}}
	for v := byte(0x20); v <= 0x70; v += 0x10 {
		p.Forks = append(p.Forks, ForkEpoch{0, phase0.Version{v, 0, 0, 0x38}})
	}

	return p
}

// lighthouseAggregate is a request Lighthouse v8.2.3 sent through the gateway on
// a local test chain (F6): type AGGREGATE_AND_PROOF without a
// version, and the Electra form of the object (committee_bits). signingRoot is
// Lighthouse's own.
const lighthouseAggregate = `{"type":"AGGREGATE_AND_PROOF","fork_info":{"fork":{"previous_version":"0x70000038","current_version":"0x70000038","epoch":"0"},"genesis_validators_root":"0xd1ec305b97bf6336571c2348e4a8bf173684b0cdb7e55f7e6554d51f8478b5a3"},"signingRoot":"0xedcf3bbc9d1f6351f311fad97971472f70f886f0120b9777d7373d9d6c560494","aggregate_and_proof":{"aggregator_index":"128","aggregate":{"aggregation_bits":"0x1e","data":{"slot":"473","index":"0","beacon_block_root":"0x2e08c8977572bcf17ae30bef7a25f4ce4583e73dc3f02370fd6016fdb73b0501","source":{"epoch":"13","root":"0x17ff3634cdf7c7a76d49deef249a3256eda38ac4887b5f01cb9b32b9c0ffa1cf"},"target":{"epoch":"14","root":"0xbbbc9b5f945833a994654f920fd9450fae27662e2ca0c3a7fdf84a2cb5b7774b"}},"signature":"0xa10fdd66993b10b6db575f42f600d082eac5b6fa622a9dba0cf4c10a2dd17b30c0242481c0ab71010078b70b8108007418db68fcefacca35c3ebe0a46a3cfe2f2eed9d344843a953ca58bb5152d2e46fbb3a73bb4b328765f0dfb81685b8031c","committee_bits":"0x0100000000000000"},"selection_proof":"0xa60e1f371e3990ae158456d096b37d1549c6e27476d9882dcfa6e86b9e4ae9bc2952dd6b5f1ccd078360c43b77b1e9bb03dda6c6bb149674abe34b605043576d02679b06dbc00b92bc91157c86dcfa1701c2e89a7a5d6051f4b184df4b444251"}}`

// tekuAggregate is the same kind of request from Teku 26.9.0 on the same
// devnet. Teku names the fork with Electra as previous_version.
const tekuAggregate = `{"signingRoot":"0xb8844f055b6d835f4b91895b90a7a90118e693a71effb74d25b8fccf1aa9a07d","type":"AGGREGATE_AND_PROOF","fork_info":{"fork":{"previous_version":"0x60000038","current_version":"0x70000038","epoch":"0"},"genesis_validators_root":"0xd1ec305b97bf6336571c2348e4a8bf173684b0cdb7e55f7e6554d51f8478b5a3"},"aggregate_and_proof":{"aggregator_index":"128","aggregate":{"aggregation_bits":"0x19","data":{"slot":"571","index":"0","beacon_block_root":"0xa6efeb4c6782b701070d8d2d3afec3e8695dd16527976689085ecec4ac7d5c99","source":{"epoch":"16","root":"0x375168c0fba0f89f5eb12a190128850af437c2254d7ac4e4fdd01d1641fe8126"},"target":{"epoch":"17","root":"0x6b044e5cbcbac92d8f225876db5718333358b1b0ff225993735296cf6c74f496"}},"signature":"0xb26d0274a1f2dbf29aa606c5dcd71ede7c15ed81ba5e5f3bec41f4b253dd955421c380e26830d952ea22dea57e6d078c0bed061a312abf5f32d4ce98b602215772a612770c8f076b2ce5eec75a183f23716a8e9f12255b01dbec012fbfd7692d","committee_bits":"0x0100000000000000"},"selection_proof":"0x8b8cbf06e1393307e257c358cf3d2f29f40d98bfd6d67e0bfc8a3566ad1a9cd770d2744e063b7a0cf714e545d73257051516b9c559a743dff2f53454d7c475f981d980a4b3f55dc4cdef086036b78798a195ec1fbba4ebcbf3d079e4d9e9338d"}}`

func TestUnversionedElectraAggregate(t *testing.T) {
	chain := mustChain("mainnet")
	chain.Pin = devnetPin(t)
	for name, c := range map[string]struct{ body, root string }{
		"Lighthouse": {lighthouseAggregate, "0xedcf3bbc9d1f6351f311fad97971472f70f886f0120b9777d7373d9d6c560494"},
		"Teku":       {tekuAggregate, "0xb8844f055b6d835f4b91895b90a7a90118e693a71effb74d25b8fccf1aa9a07d"},
	} {
		job, err := Parse([]byte(c.body), chain)
		if err != nil {
			t.Fatalf("%s's aggregate: %v", name, err)
		}
		if got := fmt.Sprintf("%#x", job.SigningRoot); got != c.root {
			t.Fatalf("%s: signing root %s, the client computed %s", name, got, c.root)
		}
		if _, ok := job.Typed.(*electra.AggregateAndProof); !ok {
			t.Fatalf("%s: typed data %T, want the Electra AggregateAndProof", name, job.Typed)
		}
	}

	// Without committee_bits the object is the phase0 form, whose root is not
	// the one Lighthouse signed.
	phase0Body := strings.Replace(lighthouseAggregate, `,"committee_bits":"0x0100000000000000"`, "", 1)
	if _, err := Parse([]byte(phase0Body), chain); !IsBadRequest(err) || !strings.Contains(err.Error(), "must match signing root") {
		t.Fatalf("phase0 form with Lighthouse's Electra signing root: want a signing root mismatch, got %v", err)
	}
}
