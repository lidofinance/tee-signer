// Command xcheck-gloas writes Gloas test vectors computed by
// attestantio/go-eth2-client v0.30.3 (its gloas package and dynamic-ssz).
// The C unit test compares the core's hash_tree_root of each container
// against them: consensus-spec-tests has no release with the current Gloas
// containers yet (v1.6.0-beta.0 predates the progressive containers).
//
// Output, one case per line, hex without 0x:
//
//	ptc  <PayloadAttestationData SSZ, 42 bytes> <hash_tree_root>
//	pref <ProposerPreferences SSZ, 76 bytes> <hash_tree_root>
//	env  <sc_payload_envelope fixed layout, 532 bytes> <hash_tree_root of the full envelope>
//	agg  <gloas AggregateAndProof SSZ, mainnet> <hash_tree_root>
//
// For env the generator builds a full ExecutionPayloadEnvelope (transactions,
// withdrawals, block access list, execution requests), hashes it whole, and
// writes the summary the signer gets: fixed fields as values, the variable
// fields as their roots.
package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	dynssz "github.com/pk910/dynamic-ssz"
)

// xorshift64 so the vectors are the same on every run.
type rng uint64

func (r *rng) next() uint64 {
	x := uint64(*r)
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	*r = rng(x)
	return x
}

func (r *rng) fill(b []byte) {
	for i := range b {
		b[i] = byte(r.next())
	}
}

func (r *rng) bytes(n int) []byte {
	b := make([]byte, n)
	r.fill(b)
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var ds = dynssz.NewDynSsz(map[string]any{
	"MAX_VALIDATORS_PER_COMMITTEE": uint64(2048),
	"MAX_COMMITTEES_PER_SLOT":      uint64(64),
})

func root(v any) [32]byte {
	r, err := ds.HashTreeRoot(v)
	must(err)
	return r
}

// A plain container with one field has the field's root as its own
// (merkleize of a single chunk), so these wrappers give the root of one
// payload field with the field's own SSZ type.
type (
	logsBloomField struct{ V [256]byte }
	extraDataField struct {
		V []byte `ssz-max:"32"`
	}
	transactionsField struct {
		V []bellatrix.Transaction `ssz-type:"progressive-list,progressive-list"`
	}
	withdrawalsField struct {
		V []*capella.Withdrawal `ssz-type:"progressive-list"`
	}
	balField struct {
		V gloas.BlockAccessList `ssz-type:"progressive-list"`
	}
)

func payload(r *rng, i int) *gloas.ExecutionPayload {
	p := &gloas.ExecutionPayload{
		BlockNumber: r.next(), GasLimit: r.next() % 200_000_000, GasUsed: r.next() % 60_000_000,
		Timestamp: r.next(), BlobGasUsed: r.next() % 1_000_000, ExcessBlobGas: r.next(),
		SlotNumber: r.next() % 10_000_000,
	}
	r.fill(p.ParentHash[:])
	r.fill(p.FeeRecipient[:])
	r.fill(p.StateRoot[:])
	r.fill(p.ReceiptsRoot[:])
	r.fill(p.LogsBloom[:])
	r.fill(p.PrevRandao[:])
	r.fill(p.BlockHash[:])
	p.ExtraData = r.bytes(int(r.next() % 33))
	var fee [32]byte
	r.fill(fee[:])
	p.BaseFeePerGas = new(uint256.Int).SetBytes(fee[:])
	ntx := []int{0, 1, 3, 17, 70}[i%5]
	for t := 0; t < ntx; t++ {
		p.Transactions = append(p.Transactions, r.bytes(int(r.next()%400)))
	}
	nw := []int{0, 1, 5, 16}[i%4]
	for w := 0; w < nw; w++ {
		wd := &capella.Withdrawal{Index: capella.WithdrawalIndex(r.next()), ValidatorIndex: phase0.ValidatorIndex(r.next()), Amount: phase0.Gwei(r.next())}
		r.fill(wd.Address[:])
		p.Withdrawals = append(p.Withdrawals, wd)
	}
	p.BlockAccessList = r.bytes([]int{0, 1, 31, 32, 33, 700}[i%6])
	return p
}

func requests(r *rng, i int) *gloas.ExecutionRequests {
	q := &gloas.ExecutionRequests{}
	for k := 0; k < i%3; k++ {
		d := &electra.DepositRequest{Amount: phase0.Gwei(r.next()), Index: r.next()}
		r.fill(d.Pubkey[:])
		d.WithdrawalCredentials = r.bytes(32)
		r.fill(d.Signature[:])
		q.Deposits = append(q.Deposits, d)
		e := &gloas.BuilderExitRequest{}
		r.fill(e.SourceAddress[:])
		r.fill(e.Pubkey[:])
		q.BuilderExits = append(q.BuilderExits, e)
	}
	return q
}

func le64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }

// summary is the core's sc_payload_envelope fixed layout.
func summary(e *gloas.ExecutionPayloadEnvelope) []byte {
	p := e.Payload
	b := append([]byte(nil), p.ParentHash[:]...)
	b = append(b, p.FeeRecipient[:]...)
	b = append(b, p.StateRoot[:]...)
	b = append(b, p.ReceiptsRoot[:]...)
	lb := root(&logsBloomField{V: p.LogsBloom})
	b = append(b, lb[:]...)
	b = append(b, p.PrevRandao[:]...)
	b = le64(b, p.BlockNumber)
	b = le64(b, p.GasLimit)
	b = le64(b, p.GasUsed)
	b = le64(b, p.Timestamp)
	ed := root(&extraDataField{V: p.ExtraData})
	b = append(b, ed[:]...)
	fee := p.BaseFeePerGas.Bytes32() // big endian
	for i := 31; i >= 0; i-- {
		b = append(b, fee[i])
	}
	b = append(b, p.BlockHash[:]...)
	tx := root(&transactionsField{V: p.Transactions})
	b = append(b, tx[:]...)
	wd := root(&withdrawalsField{V: p.Withdrawals})
	b = append(b, wd[:]...)
	b = le64(b, p.BlobGasUsed)
	b = le64(b, p.ExcessBlobGas)
	bal := root(&balField{V: p.BlockAccessList})
	b = append(b, bal[:]...)
	b = le64(b, p.SlotNumber)
	rq := root(e.ExecutionRequests)
	b = append(b, rq[:]...)
	b = le64(b, uint64(e.BuilderIndex))
	b = append(b, e.BeaconBlockRoot[:]...)
	return append(b, e.ParentBeaconBlockRoot[:]...)
}

// authData wraps the data of a BuilderRequestAuth: its root is the root of
// the ByteList[4096] alone.
type authData struct {
	Data []byte `ssz-max:"4096"`
}

// builderAuth writes the BuilderRequestAuth vectors (-bra):
//
//	bra <SSZ> <hash_tree_root of data as ByteList[4096]> <hash_tree_root>
func builderAuth() {
	r := rng(0x2545f4914f6cdd1d)
	fmt.Println("# generated by tools/xcheck-gloas -bra with go-eth2-client v0.30.3 (spec/gloas BuilderRequestAuth)")
	lens := []int{0, 1, 19, 31, 32, 33, 63, 64, 65, 100, 1000, 2047, 2048, 2049, 4064, 4095, 4096}
	for i, n := range lens {
		a := &gloas.BuilderRequestAuth{Data: r.bytes(n), Slot: phase0.Slot(r.next())}
		if i == 2 {
			a = &gloas.BuilderRequestAuth{Data: []byte("builder.example.org"), Slot: 32}
		}
		ssz, err := a.MarshalSSZ()
		must(err)
		d := root(&authData{Data: a.Data})
		h := root(a)
		fmt.Printf("bra %x %x %x\n", ssz, d[:], h[:])
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-bra" {
		builderAuth()
		return
	}
	r := rng(0x9e3779b97f4a7c15)
	fmt.Println("# generated by tools/xcheck-gloas with go-eth2-client v0.30.3 (spec/gloas)")
	for i := 0; i < 16; i++ {
		d := &gloas.PayloadAttestationData{Slot: phase0.Slot(r.next()), PayloadPresent: i&1 == 1, BlobDataAvailable: i&2 == 2}
		r.fill(d.BeaconBlockRoot[:])
		ssz, err := ds.MarshalSSZ(d)
		must(err)
		h := root(d)
		fmt.Printf("ptc %x %x\n", ssz, h[:])
	}
	for i := 0; i < 16; i++ {
		p := &gloas.ProposerPreferences{ProposalSlot: phase0.Slot(r.next()), ValidatorIndex: phase0.ValidatorIndex(r.next()), TargetGasLimit: r.next()}
		r.fill(p.DependentRoot[:])
		r.fill(p.FeeRecipient[:])
		ssz, err := ds.MarshalSSZ(p)
		must(err)
		h := root(p)
		fmt.Printf("pref %x %x\n", ssz, h[:])
	}
	for i := 0; i < 24; i++ {
		e := &gloas.ExecutionPayloadEnvelope{Payload: payload(&r, i), ExecutionRequests: requests(&r, i), BuilderIndex: gloas.BuilderIndex(r.next())}
		if i%2 == 0 {
			e.BuilderIndex = gloas.BuilderIndexSelfBuild
		}
		r.fill(e.BeaconBlockRoot[:])
		r.fill(e.ParentBeaconBlockRoot[:])
		h := root(e)
		fmt.Printf("env %x %x\n", summary(e), h[:])
	}
	for i := 0; i < 16; i++ {
		nbits := []uint64{1, 2, 7, 8, 9, 64, 300, 2048, 131072}[i%9]
		bits := bitfield.NewBitlist(nbits)
		for k := uint64(0); k < nbits; k++ {
			if r.next()%3 == 0 {
				bits.SetBitAt(k, true)
			}
		}
		att := &gloas.Attestation{AggregationBits: bits, Data: &phase0.AttestationData{
			Slot: phase0.Slot(r.next()), Source: &phase0.Checkpoint{Epoch: phase0.Epoch(r.next())},
			Target: &phase0.Checkpoint{Epoch: phase0.Epoch(r.next())},
		}, CommitteeBits: bitfield.NewBitvector64()}
		r.fill(att.Data.BeaconBlockRoot[:])
		r.fill(att.Signature[:])
		att.CommitteeBits.SetBitAt(r.next()%64, true)
		a := &gloas.AggregateAndProof{AggregatorIndex: phase0.ValidatorIndex(r.next()), Aggregate: att}
		r.fill(a.SelectionProof[:])
		ssz, err := ds.MarshalSSZ(a)
		must(err)
		h := root(a)
		fmt.Printf("agg %x %x\n", ssz, h[:])
	}
}
