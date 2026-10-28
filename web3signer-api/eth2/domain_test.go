package eth2

import (
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Mainnet deposit domain, as used by the deposit CLI and every launchpad:
// compute_domain(DOMAIN_DEPOSIT, 0x00000000, zero root).
func TestComputeDomainMainnetDeposit(t *testing.T) {
	d, err := ComputeDomain(DomainDeposit, phase0.Version{}, phase0.Root{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"
	if got := fmt.Sprintf("%#x", d); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestForkDomainPicksVersionByEpoch(t *testing.T) {
	fork := &phase0.Fork{PreviousVersion: phase0.Version{0, 0, 0, 1}, CurrentVersion: phase0.Version{0, 0, 0, 2}, Epoch: 10}
	before, _ := ForkDomain(DomainRandao, fork, phase0.Root{}, 9)
	at, _ := ForkDomain(DomainRandao, fork, phase0.Root{}, 10)
	prev, _ := ComputeDomain(DomainRandao, fork.PreviousVersion, phase0.Root{})
	cur, _ := ComputeDomain(DomainRandao, fork.CurrentVersion, phase0.Root{})
	if before != prev || at != cur {
		t.Fatal("wrong fork version chosen")
	}
}

func TestUint64Root(t *testing.T) {
	r := Uint64Root(0x0102)
	if r[0] != 0x02 || r[1] != 0x01 || r[2] != 0 || r[31] != 0 {
		t.Fatalf("got %#x", r)
	}
}
