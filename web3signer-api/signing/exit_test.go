package signing

import (
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

const devnetExit = `{"type":"VOLUNTARY_EXIT","fork_info":{"fork":{"previous_version":"0x70000038","current_version":"0x70000038","epoch":"0"},` +
	`"genesis_validators_root":"0xd1ec305b97bf6336571c2348e4a8bf173684b0cdb7e55f7e6554d51f8478b5a3"},` +
	`"voluntary_exit":{"epoch":"40","validator_index":"128"}}`

// Without an exit fork version (the gateway) an exit gets no domain and
// policy refuses it. With one (the signer shim) it is signed under the
// EIP-7044 domain: the Capella fork version whatever the epoch.
func TestVoluntaryExitDomain(t *testing.T) {
	chain := mustChain("mainnet")
	chain.Pin = devnetPin(t)
	job, err := Parse([]byte(devnetExit), chain)
	if err != nil {
		t.Fatal(err)
	}
	if job.Method != MethodNone {
		t.Fatalf("without an exit fork version: method %s, want none", job.Method)
	}

	capella := phase0.Version{0x40, 0, 0, 0x38}
	chain.VoluntaryExitForkVersion = &capella
	job, err = Parse([]byte(devnetExit), chain)
	if err != nil {
		t.Fatal(err)
	}
	exit := &phase0.VoluntaryExit{Epoch: 40, ValidatorIndex: 128}
	objectRoot, err := exit.HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	forkDataRoot, err := (&phase0.ForkData{CurrentVersion: capella, GenesisValidatorsRoot: chain.Pin.GenesisValidatorsRoot}).HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	var domain phase0.Domain
	copy(domain[:], []byte{0x04, 0, 0, 0})
	copy(domain[4:], forkDataRoot[:28])
	want, err := (&phase0.SigningData{ObjectRoot: objectRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if job.Method != MethodGeneric || job.Domain != domain || job.SigningRoot != want {
		t.Fatalf("exit: method %s domain %#x root %#x, want generic, %#x, %#x", job.Method, job.Domain, job.SigningRoot, domain, phase0.Root(want))
	}
	if _, ok := job.Typed.(*phase0.VoluntaryExit); !ok {
		t.Fatalf("typed data %T, want *phase0.VoluntaryExit", job.Typed)
	}

	// The client's signing root must match; another chain's fork_info is refused.
	bad := strings.Replace(devnetExit, `"type"`, `"signingRoot":"0x`+strings.Repeat("00", 32)+`","type"`, 1)
	if _, err := Parse([]byte(bad), chain); !IsBadRequest(err) {
		t.Fatalf("wrong signingRoot: err %v, want bad request", err)
	}
	other := strings.Replace(devnetExit, "0xd1ec", "0xd1ed", 1)
	if _, err := Parse([]byte(other), chain); !IsBadRequest(err) {
		t.Fatalf("other genesis_validators_root: err %v, want bad request", err)
	}

	// Lighthouse 8.2.3 sends the EIP-7044 fork for exits: Capella as previous
	// and current version, the exit epoch as fork epoch. Same domain and root.
	lh := strings.Replace(devnetExit, `"previous_version":"0x70000038","current_version":"0x70000038","epoch":"0"`,
		`"previous_version":"0x40000038","current_version":"0x40000038","epoch":"35"`, 1)
	job, err = Parse([]byte(lh), chain)
	if err != nil {
		t.Fatalf("EIP-7044 fork_info: %v", err)
	}
	if job.Domain != domain || job.SigningRoot != want {
		t.Fatalf("EIP-7044 fork_info: domain %#x root %#x, want %#x, %#x", job.Domain, job.SigningRoot, domain, phase0.Root(want))
	}
	// The same fork from another chain, and a fork that is neither the
	// schedule's nor EIP-7044's, stay refused.
	if _, err := Parse([]byte(strings.Replace(lh, "0xd1ec", "0xd1ed", 1)), chain); !IsBadRequest(err) {
		t.Fatalf("EIP-7044 fork_info, other genesis_validators_root: err %v, want bad request", err)
	}
	odd := strings.Replace(lh, `"previous_version":"0x40000038"`, `"previous_version":"0x30000038"`, 1)
	if _, err := Parse([]byte(odd), chain); !IsBadRequest(err) {
		t.Fatalf("fork 0x30000038 -> 0x40000038 at epoch 35: err %v, want bad request", err)
	}
}
