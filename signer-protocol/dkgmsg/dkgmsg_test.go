package dkgmsg

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

func sampleHello() *Hello {
	return &Hello{
		PolicyHash: [32]byte{1}, Nonce: bytes.Repeat([]byte{2}, 32), Count: 3, Random: [32]byte{3}, SignKey: [32]byte{4}, OperatorKey: [32]byte{10},
		Identity: &backend.Identity{State: backend.SetupState{SetupHash: backend.Root{5}}, ImportKEM: 1, ImportKDF: 2, ImportAEAD: 3,
			ImportKey: []byte{6, 7}, TLSKeyHash: []byte{8},
			Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{9}, Document: []byte("{}")}},
	}
}

func sampleDeal() *Deal {
	return &Deal{Session: [32]byte{1}, Dealer: 2, Threshold: 2,
		Commitments: [][]backend.Pubkey{{{1}, {2}}, {{3}, {4}}},
		Shares:      []SealedShares{{Recipient: 1, Sealed: []byte{1, 2, 3}}, {Recipient: 3, Sealed: []byte{4}}},
		Signature:   [64]byte{9}}
}

func sampleResult() *Result {
	return &Result{Session: [32]byte{1}, Transcript: [32]byte{2}, Self: 2, Threshold: 2,
		GroupKeys:    []backend.Pubkey{{1}, {2}},
		PublicShares: [][]backend.Pubkey{{{3}, {4}, {5}}, {{6}, {7}, {8}}}}
}

// Every message survives a round trip, and every shorter prefix and every
// longer form is refused without a panic.
func TestRoundTripsAndTruncation(t *testing.T) {
	h := sampleHello()
	hb, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d := sampleDeal()
	db, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	res := sampleResult()
	c := &Confirm{Session: [32]byte{1}, Transcript: [32]byte{2}, ResultHash: res.Hash(), Signer: 3, Signature: [64]byte{4}}
	fb, err := (&Finished{Result: res, Confirm: c}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cq := (&CommitRequest{Session: [32]byte{7}, Confirms: []*Confirm{c, c}}).Encode()
	hq, err := (&HelloRequest{Nonce: bytes.Repeat([]byte{1}, 16), Count: 2}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		b      []byte
		decode func([]byte) (any, error)
		want   any
	}{
		{"hello", hb, func(b []byte) (any, error) { return DecodeHello(b) }, h},
		{"deal", db, func(b []byte) (any, error) { return DecodeDeal(b) }, d},
		{"finished", fb, func(b []byte) (any, error) { return DecodeFinished(b) }, &Finished{Result: res, Confirm: c}},
		{"commit", cq, func(b []byte) (any, error) { return DecodeCommitRequest(b) }, &CommitRequest{Session: [32]byte{7}, Confirms: []*Confirm{c, c}}},
		{"hello request", hq, func(b []byte) (any, error) { return DecodeHelloRequest(b) }, &HelloRequest{Nonce: bytes.Repeat([]byte{1}, 16), Count: 2}},
	}
	for _, tc := range cases {
		got, err := tc.decode(tc.b)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: round trip differs:\n%+v\n%+v", tc.name, got, tc.want)
		}
		for n := range len(tc.b) {
			if _, err := tc.decode(tc.b[:n]); err == nil {
				t.Fatalf("%s: prefix of %d bytes accepted", tc.name, n)
			}
		}
		if _, err := tc.decode(append(append([]byte(nil), tc.b...), 0)); err == nil {
			t.Fatalf("%s: trailing byte accepted", tc.name)
		}
	}
}

func TestLimits(t *testing.T) {
	if _, err := (&HelloRequest{Nonce: make([]byte, 15), Count: 1}).Encode(); err == nil {
		t.Fatal("short nonce accepted")
	}
	if _, err := (&HelloRequest{Nonce: make([]byte, 16), Count: MaxValidators + 1}).Encode(); err == nil {
		t.Fatal("too many validators accepted")
	}
	d := sampleDeal()
	d.Commitments[1] = d.Commitments[1][:1]
	if _, err := d.Encode(); err == nil {
		t.Fatal("deal with a short commitment row accepted")
	}
	if _, err := DecodeList(EncodeList(nil), 3); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := DecodeList(EncodeList([][]byte{{1}, {2}}), 1); err == nil {
		t.Fatal("list over the limit accepted")
	}
}

// The largest FINISH request (MaxParticipants deals of MaxValidators keys at
// threshold MaxParticipants) fits in one frame.
func TestLargestFinishFitsAFrame(t *testing.T) {
	n, cnt := MaxParticipants, MaxValidators
	d := &Deal{Threshold: uint16(n), Commitments: make([][]backend.Pubkey, cnt)}
	for v := range d.Commitments {
		d.Commitments[v] = make([]backend.Pubkey, n)
	}
	for j := 1; j < n; j++ {
		d.Shares = append(d.Shares, SealedShares{Recipient: uint16(j), Sealed: make([]byte, MaxSealed)})
	}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	deals := make([][]byte, n)
	for i := range deals {
		deals[i] = b
	}
	if size := len(EncodeList(deals)) + 6; size > wire.MaxFrame {
		t.Fatalf("largest FINISH request is %d bytes, frame limit %d", size, wire.MaxFrame)
	}
}

// Result.Hash ignores Self, so all runners' results compare equal.
func TestResultHashIgnoresSelf(t *testing.T) {
	a, b := sampleResult(), sampleResult()
	b.Self = 3
	if a.Hash() != b.Hash() {
		t.Fatal("hash depends on Self")
	}
	b.PublicShares[1][2][0] ^= 1
	if a.Hash() == b.Hash() {
		t.Fatal("hash ignores a public share")
	}
}
