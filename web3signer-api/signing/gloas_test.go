package signing

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"

	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
)

const gloasEpoch = 430000

// gloasChain is mainnetPin plus a Gloas fork (version 0x07000000) at epoch 430000.
func gloasChain(t *testing.T) Chain {
	t.Helper()
	chain := mustChain("mainnet")
	chain.Pin = mainnetPin(t)
	chain.Pin.Forks = append(chain.Pin.Forks, ForkEpoch{Epoch: gloasEpoch, Version: phase0.Version{7, 0, 0, 0}})
	e := phase0.Epoch(gloasEpoch)
	chain.GloasForkEpoch = &e

	return chain
}

var (
	gloasForkInfo = pinForkInfo("0x06000000", "0x07000000", gloasEpoch, mainnetGVR)
	fuluForkInfo  = pinForkInfo("0x05000000", "0x06000000", 411392, mainnetGVR)
)

func gloasBody(typ, key, forkInfo string, data any) string {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	fi := ""
	if forkInfo != "" {
		fi = `"fork_info":` + forkInfo + `,`
	}

	return fmt.Sprintf(`{"type":"%s",%s"%s":{"version":"GLOAS","data":%s}}`, typ, fi, key, b)
}

func gloasDomain(t *testing.T, chain Chain, dt phase0.DomainType, version byte) phase0.Domain {
	t.Helper()
	d, err := eth2.ComputeDomain(dt, phase0.Version{version, 0, 0, 0}, chain.Pin.GenesisValidatorsRoot)
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func TestGloasPayloadAttestation(t *testing.T) {
	chain := gloasChain(t)
	data := &gloas.PayloadAttestationData{BeaconBlockRoot: phase0.Root{1}, Slot: gloasEpoch*32 + 5, PayloadPresent: true}
	job, err := Parse([]byte(gloasBody(TypePayloadAttestationMessage, "payload_attestation_message", gloasForkInfo, data)), chain)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := data.HashTreeRoot()
	if job.Method != MethodTyped || job.ObjectRoot != root || job.Domain != gloasDomain(t, chain, eth2.DomainPTCAttester, 7) {
		t.Fatalf("job %+v", job)
	}
	if _, ok := job.Typed.(*gloas.PayloadAttestationData); !ok {
		t.Fatalf("typed %T", job.Typed)
	}

	// Before the fork, and without Gloas in the config: refused by policy.
	data.Slot = gloasEpoch*32 - 1
	job, err = Parse([]byte(gloasBody(TypePayloadAttestationMessage, "payload_attestation_message", gloasForkInfo, data)), chain)
	if err != nil || job.Method != MethodNone || !strings.Contains(job.Refusal, "before the Gloas fork") {
		t.Fatalf("before the fork: %+v %v", job, err)
	}
	chain.GloasForkEpoch = nil
	data.Slot = gloasEpoch*32 + 5
	job, err = Parse([]byte(gloasBody(TypePayloadAttestationMessage, "payload_attestation_message", gloasForkInfo, data)), chain)
	if err != nil || job.Method != MethodNone || !strings.Contains(job.Refusal, "not in the configured chain") {
		t.Fatalf("no Gloas: %+v %v", job, err)
	}

	// Another version, or a claimed signing root that differs: 400.
	chain = gloasChain(t)
	body := strings.Replace(gloasBody(TypePayloadAttestationMessage, "payload_attestation_message", gloasForkInfo, data), `"GLOAS"`, `"FULU"`, 1)
	if _, err := Parse([]byte(body), chain); !IsBadRequest(err) {
		t.Fatalf("FULU version: %v", err)
	}
	body = strings.Replace(gloasBody(TypePayloadAttestationMessage, "payload_attestation_message", gloasForkInfo, data), `{"type"`,
		fmt.Sprintf(`{"signing_root":"0x%064x","type"`, 5), 1)
	if _, err := Parse([]byte(body), chain); !IsBadRequest(err) {
		t.Fatalf("wrong signing root: %v", err)
	}
}

func testEnvelope(slot uint64) *gloas.ExecutionPayloadEnvelope {
	p := &gloas.ExecutionPayload{
		ParentHash: phase0.Hash32{1}, FeeRecipient: bellatrix.ExecutionAddress{2}, GasLimit: 45_000_000, Timestamp: 1_800_000_000,
		ExtraData: []byte("gloas"), BaseFeePerGas: uint256.NewInt(7), BlockHash: phase0.Hash32{3},
		Transactions:    []bellatrix.Transaction{{1, 2, 3}, make([]byte, 300)},
		Withdrawals:     []*capella.Withdrawal{{Index: 1, ValidatorIndex: 2, Address: bellatrix.ExecutionAddress{4}, Amount: 5}},
		BlockAccessList: make([]byte, 70), SlotNumber: slot,
	}

	return &gloas.ExecutionPayloadEnvelope{Payload: p, ExecutionRequests: &gloas.ExecutionRequests{
		Deposits: []*electra.DepositRequest{{Amount: 32, WithdrawalCredentials: make([]byte, 32)}},
	}, BuilderIndex: gloas.BuilderIndexSelfBuild, BeaconBlockRoot: phase0.Root{8}, ParentBeaconBlockRoot: phase0.Root{9}}
}

func TestGloasPayloadEnvelope(t *testing.T) {
	chain := gloasChain(t)
	env := testEnvelope(gloasEpoch*32 + 3)
	job, err := Parse([]byte(gloasBody(TypeExecutionPayloadEnvelope, "execution_payload_envelope", gloasForkInfo, env)), chain)
	if err != nil {
		t.Fatal(err)
	}
	root, err := env.HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	s, ok := job.Typed.(*PayloadEnvelope)
	if job.Method != MethodTyped || !ok || job.ObjectRoot != root || s.Root() != root {
		t.Fatalf("job %+v", job)
	}
	if s.Payload.SlotNumber != env.Payload.SlotNumber || s.Payload.BaseFeePerGas[0] != 7 || job.Domain != gloasDomain(t, chain, eth2.DomainBeaconBuilder, 7) {
		t.Fatalf("summary %+v", s)
	}

	env.BuilderIndex = 4
	job, err = Parse([]byte(gloasBody(TypeExecutionPayloadEnvelope, "execution_payload_envelope", gloasForkInfo, env)), chain)
	if err != nil || job.Method != MethodNone || !strings.Contains(job.Refusal, "self-built") {
		t.Fatalf("builder envelope: %+v %v", job, err)
	}
	env = testEnvelope(gloasEpoch*32 - 3)
	job, err = Parse([]byte(gloasBody(TypeExecutionPayloadEnvelope, "execution_payload_envelope", gloasForkInfo, env)), chain)
	if err != nil || job.Method != MethodNone {
		t.Fatalf("envelope before the fork: %+v %v", job, err)
	}
}

// Preferences for the first Gloas epoch, signed while fork_info still
// names Fulu, use the Gloas fork version (validator.md).
func TestGloasProposerPreferences(t *testing.T) {
	chain := gloasChain(t)
	pref := &gloas.ProposerPreferences{DependentRoot: phase0.Root{1}, ProposalSlot: gloasEpoch*32 + 1, ValidatorIndex: 9,
		FeeRecipient: bellatrix.ExecutionAddress{5}, TargetGasLimit: 60_000_000}
	job, err := Parse([]byte(gloasBody(TypeProposerPreferences, "proposer_preferences", fuluForkInfo, pref)), chain)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := pref.HashTreeRoot()
	if job.Method != MethodTyped || job.ObjectRoot != root || job.Domain != gloasDomain(t, chain, eth2.DomainProposerPreferences, 7) {
		t.Fatalf("job %+v", job)
	}
	other := pinForkInfo("0x05000000", "0x06000000", 411392, "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
	if _, err := Parse([]byte(gloasBody(TypeProposerPreferences, "proposer_preferences", other, pref)), chain); !IsBadRequest(err) {
		t.Fatalf("another chain: %v", err)
	}
	pref.ProposalSlot = gloasEpoch*32 - 1
	job, err = Parse([]byte(gloasBody(TypeProposerPreferences, "proposer_preferences", fuluForkInfo, pref)), chain)
	if err != nil || job.Method != MethodNone {
		t.Fatalf("pre-Gloas proposal slot: %+v %v", job, err)
	}
}

func TestGloasBidRefused(t *testing.T) {
	chain := gloasChain(t)
	body := `{"type":"EXECUTION_PAYLOAD_BID","fork_info":` + gloasForkInfo + `,"execution_payload_bid":{"version":"GLOAS","data":{}}}`
	job, err := Parse([]byte(body), chain)
	if err != nil || job.Method != MethodNone || job.Refusal == "" {
		t.Fatalf("%+v %v", job, err)
	}
}

func authBody(data string, slot uint64) string {
	return fmt.Sprintf(`{"type":"BUILDER_REQUEST_AUTH","builder_request_auth":{"version":"GLOAS","data":{"data":"0x%s","slot":"%d"}}}`, data, slot)
}

// Builder API authentication: a typed job under DOMAIN_BUILDER_REQUEST_AUTH
// with the genesis fork version and a zero root, no fork_info.
func TestGloasBuilderRequestAuth(t *testing.T) {
	chain := gloasChain(t)
	data := []byte("builder.example.org")
	job, err := Parse([]byte(authBody(fmt.Sprintf("%x", data), gloasEpoch*32+2)), chain)
	if err != nil {
		t.Fatal(err)
	}
	auth, ok := job.Typed.(*gloas.BuilderRequestAuth)
	if job.Method != MethodTyped || !ok || string(auth.Data) != string(data) || auth.Slot != gloasEpoch*32+2 {
		t.Fatalf("job %+v", job)
	}
	root, _ := auth.HashTreeRoot()
	domain, _ := eth2.ComputeDomain(phase0.DomainType{0x0b, 0, 0, 1}, chain.GenesisForkVersion, phase0.Root{})
	if job.ObjectRoot != root || job.Domain != domain {
		t.Fatalf("root %#x domain %#x, want %#x %#x", job.ObjectRoot, job.Domain, root, domain)
	}
	// The root is the plain Container (builder-specs) go-eth2-client v0.30.3
	// hashes: hash(data root, slot chunk), data as ByteList[4096].
	chunks := make([][32]byte, (len(data)+31)/32)
	for i := range chunks {
		copy(chunks[i][:], data[i*32:])
	}
	dataRoot := hashPair(merkleize(chunks, MaxBuilderRequestAuthData/32), u64Chunk(uint64(len(data))))
	if hashPair(dataRoot, u64Chunk(uint64(auth.Slot))) != root {
		t.Fatal("root differs from the container of data and slot")
	}

	// fork_info is not needed and does not change the domain.
	withFork := strings.Replace(authBody(fmt.Sprintf("%x", data), gloasEpoch*32+2), `{"type"`, `{"fork_info":`+fuluForkInfo+`,"type"`, 1)
	if j, err := Parse([]byte(withFork), chain); err != nil || j.SigningRoot != job.SigningRoot {
		t.Fatalf("with fork_info: %+v %v", j, err)
	}
	// The claimed signing root must match.
	claimed := strings.Replace(authBody("01", gloasEpoch*32), `{"type"`, fmt.Sprintf(`{"signing_root":"0x%064x","type"`, 5), 1)
	if _, err := Parse([]byte(claimed), chain); !IsBadRequest(err) {
		t.Fatalf("wrong signing root: %v", err)
	}

	// 4096 data bytes sign; 4097, empty data or another version are bad requests.
	if j, err := Parse([]byte(authBody(strings.Repeat("ab", 4096), gloasEpoch*32)), chain); err != nil || j.Method != MethodTyped {
		t.Fatalf("4096 bytes: %+v %v", j, err)
	}
	for name, body := range map[string]string{
		"4097 bytes": authBody(strings.Repeat("ab", 4097), gloasEpoch*32),
		"empty data": authBody("", gloasEpoch*32),
		"FULU":       strings.Replace(authBody("01", gloasEpoch*32), `"GLOAS"`, `"FULU"`, 1),
		"no data":    `{"type":"BUILDER_REQUEST_AUTH"}`,
	} {
		if _, err := Parse([]byte(body), chain); !IsBadRequest(err) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Before the fork, and without Gloas in the config: refused by policy.
	j, err := Parse([]byte(authBody("01", gloasEpoch*32-1)), chain)
	if err != nil || j.Method != MethodNone || !strings.Contains(j.Refusal, "before the Gloas fork") {
		t.Fatalf("before the fork: %+v %v", j, err)
	}
	chain.GloasForkEpoch = nil
	j, err = Parse([]byte(authBody("01", gloasEpoch*32)), chain)
	if err != nil || j.Method != MethodNone || !strings.Contains(j.Refusal, "not in the configured chain") {
		t.Fatalf("no Gloas: %+v %v", j, err)
	}
}

// From the Gloas fork on, aggregates hash as Gloas aggregates.
func TestGloasAggregate(t *testing.T) {
	chain := gloasChain(t)
	bits := bitfield.NewBitlist(10)
	bits.SetBitAt(3, true)
	cb := bitfield.NewBitvector64()
	cb.SetBitAt(2, true)
	agg := func(slot uint64) *electra.AggregateAndProof {
		return &electra.AggregateAndProof{AggregatorIndex: 4, Aggregate: &electra.Attestation{AggregationBits: bits,
			Data:          &phase0.AttestationData{Slot: phase0.Slot(slot), Source: &phase0.Checkpoint{}, Target: &phase0.Checkpoint{Epoch: phase0.Epoch(slot / 32)}},
			CommitteeBits: cb}}
	}
	body := func(version string, a any) string {
		b, _ := json.Marshal(a)
		if version == "" {
			return `{"type":"AGGREGATE_AND_PROOF","fork_info":` + gloasForkInfo + `,"aggregate_and_proof":` + string(b) + `}`
		}

		return `{"type":"AGGREGATE_AND_PROOF_V2","fork_info":` + gloasForkInfo + `,"aggregate_and_proof":{"version":"` + version + `","data":` + string(b) + `}}`
	}
	a := agg(gloasEpoch*32 + 1)
	g := &gloas.AggregateAndProof{AggregatorIndex: 4, Aggregate: &gloas.Attestation{AggregationBits: bits, Data: a.Aggregate.Data, CommitteeBits: cb}}
	want, err := chain.Hasher.Root(g)
	if err != nil {
		t.Fatal(err)
	}
	electraRoot, _ := chain.Hasher.Root(a)
	if want == electraRoot {
		t.Fatal("Gloas and Electra roots should differ")
	}
	for _, version := range []string{"GLOAS", ""} {
		job, err := Parse([]byte(body(version, a)), chain)
		if err != nil {
			t.Fatalf("%q: %v", version, err)
		}
		if _, ok := job.Typed.(*GloasAggregateAndProof); !ok || job.ObjectRoot != want {
			t.Fatalf("%q: typed %T, root %#x want %#x", version, job.Typed, job.ObjectRoot, want)
		}
	}
	if _, err := Parse([]byte(body("ELECTRA", a)), chain); !IsBadRequest(err) {
		t.Fatalf("ELECTRA after the fork: %v", err)
	}
	if _, err := Parse([]byte(body("GLOAS", agg(gloasEpoch*32-1))), chain); !IsBadRequest(err) {
		t.Fatalf("GLOAS before the fork: %v", err)
	}
	job, err := Parse([]byte(body("ELECTRA", agg(gloasEpoch*32-1))), chain)
	if err != nil || job.ObjectRoot == want {
		t.Fatalf("ELECTRA before the fork: %v", err)
	}
}

// grandineBody is a request as Grandine 3.0.0-rc.1 sends it: camelCase
// signingRoot and the bare data object, no {"version","data"} wrapper.
func grandineBody(typ, key, forkInfo string, root phase0.Root, data any) string {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf(`{"type":"%s","fork_info":%s,"signingRoot":"%#x","%s":%s}`, typ, forkInfo, root, key, b)
}

// Grandine's shapes give the same jobs as the wrapped ones.
func TestGloasGrandineShapes(t *testing.T) {
	chain := gloasChain(t)
	ptc := &gloas.PayloadAttestationData{BeaconBlockRoot: phase0.Root{1}, Slot: gloasEpoch*32 + 5, PayloadPresent: true, BlobDataAvailable: true}
	pref := &gloas.ProposerPreferences{DependentRoot: phase0.Root{1}, ProposalSlot: gloasEpoch*32 + 1, ValidatorIndex: 9,
		FeeRecipient: bellatrix.ExecutionAddress{5}, TargetGasLimit: 60_000_000}
	for _, c := range []struct {
		wrappedType, grandineType, wrappedKey, grandineKey, forkInfo string
		data                                                         any
	}{
		{TypePayloadAttestationMessage, TypePayloadAttestation, "payload_attestation_message", "payload_attestation", gloasForkInfo, ptc},
		{TypeProposerPreferences, TypeProposerPreferences, "proposer_preferences", "proposer_preferences", fuluForkInfo, pref},
		{TypeExecutionPayloadEnvelope, TypeExecutionPayloadEnvelope, "execution_payload_envelope", "execution_payload_envelope", gloasForkInfo, testEnvelope(gloasEpoch*32 + 3)},
	} {
		want, err := Parse([]byte(gloasBody(c.wrappedType, c.wrappedKey, c.forkInfo, c.data)), chain)
		if err != nil || want.Method != MethodTyped {
			t.Fatalf("%s wrapped: %+v %v", c.wrappedType, want, err)
		}
		got, err := Parse([]byte(grandineBody(c.grandineType, c.grandineKey, c.forkInfo, want.SigningRoot, c.data)), chain)
		if err != nil {
			t.Fatalf("%s: %v", c.grandineType, err)
		}
		if got.Type != c.wrappedType || got.Method != MethodTyped || got.SigningRoot != want.SigningRoot ||
			got.Domain != want.Domain || fmt.Sprintf("%T", got.Typed) != fmt.Sprintf("%T", want.Typed) {
			t.Fatalf("%s: job %+v, want %+v", c.grandineType, got, want)
		}
		// A claimed root that differs is still a 400.
		if _, err := Parse([]byte(grandineBody(c.grandineType, c.grandineKey, c.forkInfo, phase0.Root{5}, c.data)), chain); !IsBadRequest(err) {
			t.Fatalf("%s wrong root: %v", c.grandineType, err)
		}
	}

	// PAYLOAD_ATTESTATION reads payload_attestation, not payload_attestation_message.
	body := gloasBody(TypePayloadAttestation, "payload_attestation_message", gloasForkInfo, ptc)
	if _, err := Parse([]byte(body), chain); !IsBadRequest(err) {
		t.Fatalf("PAYLOAD_ATTESTATION without payload_attestation: %v", err)
	}
}
