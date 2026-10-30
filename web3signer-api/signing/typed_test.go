package signing

import (
	"fmt"
	"testing"

	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
)

// Every job without a stock typed signer call carries its request data, and
// that data hashes to the job's object root, so a signer that sends the
// data (the signing client) signs the same root the gateway verifies.
func TestTypedDataPerType(t *testing.T) {
	vectors := loadVectors(t)
	want := map[string]string{
		"RANDAO_REVEAL":                         "*signing.RandaoReveal",
		"AGGREGATION_SLOT":                      "*signing.AggregationSlot",
		"AGGREGATE_AND_PROOF (DEPRECATED)":      "*phase0.AggregateAndProof",
		"AGGREGATE_AND_PROOF_V2 (DENEB)":        "*phase0.AggregateAndProof",
		"SYNC_COMMITTEE_MESSAGE":                "*signing.SyncCommitteeMessage",
		"SYNC_COMMITTEE_SELECTION_PROOF":        "*altair.SyncAggregatorSelectionData",
		"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": "*altair.ContributionAndProof",
		"VALIDATOR_REGISTRATION":                "*v1.ValidatorRegistration",
		"VOLUNTARY_EXIT":                        "*phase0.VoluntaryExit",
		"ATTESTATION":                           "<nil>",
		"BLOCK_V2 (ELECTRA)":                    "<nil>",
	}
	for name, typ := range want {
		job, err := Parse(fixForkKeys(vectors[name]), testChain)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := fmt.Sprintf("%T", job.Typed); got != typ {
			t.Errorf("%s: typed data %s, want %s", name, got, typ)
		}
		var root [32]byte
		switch d := job.Typed.(type) {
		case nil:
			continue
		case *RandaoReveal:
			root = eth2.Uint64Root(uint64(d.Epoch))
		case *AggregationSlot:
			root = eth2.Uint64Root(uint64(d.Slot))
		case *SyncCommitteeMessage:
			root = d.BeaconBlockRoot
		default:
			if root, err = testChain.Hasher.Root(d); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if job.Method != MethodNone && root != job.ObjectRoot {
			t.Errorf("%s: typed data hashes to %#x, job object root %#x", name, root, job.ObjectRoot)
		}
	}
}
