package dkgmsg

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Fuzz targets for the decoders of this package. Seeds come from the
// vectors of the unit tests. Every target checks that nothing panics and
// that what decodes encodes back to the same bytes; the comments name the
// exceptions.

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func seedConfirm() *Confirm {
	return &Confirm{Session: [32]byte{1}, Transcript: [32]byte{2}, ResultHash: sampleResult().Hash(), Signer: 3, Signature: [64]byte{4}}
}

func FuzzDecodeList(f *testing.F) {
	f.Add(EncodeList([][]byte{{1}, {2, 3}, {}}))
	f.Add(EncodeList(nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := DecodeList(b, MaxParticipants)
		if err != nil {
			return
		}
		if again := EncodeList(l); !bytes.Equal(again, b) {
			t.Fatalf("list does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeHelloRequest(f *testing.F) {
	f.Add(must((&HelloRequest{Nonce: bytes.Repeat([]byte{1}, 16), Count: 2}).Encode()))
	f.Add(must((&HelloRequest{Nonce: bytes.Repeat([]byte{1}, MaxNonce), Count: MaxValidators}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := DecodeHelloRequest(b)
		if err != nil {
			return
		}
		if again := must(q.Encode()); !bytes.Equal(again, b) {
			t.Fatalf("hello request does not encode back:\n%x\n%x", again, b)
		}
	})
}

// DecodeHello takes a nonce of up to 255 bytes, Encode only up to MaxNonce;
// the keygen manager compares the nonce with its own request's. The round
// trip is checked where Encode takes the value.
func FuzzDecodeHello(f *testing.F) {
	f.Add(must(sampleHello().Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHello(b)
		if err != nil {
			return
		}
		again, err := h.Encode()
		if err != nil {
			if len(h.Nonce) <= MaxNonce {
				t.Fatalf("decoded hello does not encode: %v", err)
			}
			return
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("hello does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeDeal(f *testing.F) {
	f.Add(must(sampleDeal().Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeDeal(b)
		if err != nil {
			return
		}
		again, err := d.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("deal does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

func FuzzDecodeResult(f *testing.F) {
	f.Add(must(sampleResult().Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := DecodeResult(b)
		if err != nil {
			return
		}
		again, err := res.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("result does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

func FuzzDecodeConfirm(f *testing.F) {
	f.Add(seedConfirm().Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeConfirm(b)
		if err != nil {
			return
		}
		if again := c.Encode(); !bytes.Equal(again, b) {
			t.Fatalf("confirm does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeFinished(f *testing.F) {
	f.Add(must((&Finished{Result: sampleResult(), Confirm: seedConfirm()}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		fin, err := DecodeFinished(b)
		if err != nil {
			return
		}
		again, err := fin.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("finish answer does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

func FuzzDecodeCommitRequest(f *testing.F) {
	c := seedConfirm()
	f.Add((&CommitRequest{Session: [32]byte{7}, Confirms: []*Confirm{c, c}}).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := DecodeCommitRequest(b)
		if err != nil {
			return
		}
		if again := q.Encode(); !bytes.Equal(again, b) {
			t.Fatalf("commit request does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeOperatorRequest(f *testing.F) {
	f.Add(must((&OperatorRequest{Nonce: bytes.Repeat([]byte{3}, 32)}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := DecodeOperatorRequest(b)
		if err != nil {
			return
		}
		if again := must(q.Encode()); !bytes.Equal(again, b) {
			t.Fatalf("operator request does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeOperatorInfo(f *testing.F) {
	h := sampleHello()
	f.Add(must((&OperatorInfo{Nonce: bytes.Repeat([]byte{3}, 32), Key: [32]byte{4}, Identity: h.Identity}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := DecodeOperatorInfo(b)
		if err != nil {
			return
		}
		again, err := o.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("operator answer does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

func FuzzDecodeSetupRequest(f *testing.F) {
	f.Add(must((&SetupRequest{Kind: SetupDeposit, Deposit: &Deposit{Pubkey: backend.Pubkey{1}, WithdrawalCredentials: backend.Root{2}, Amount: 32e9}}).Encode()))
	f.Add(must((&SetupRequest{Kind: SetupRegistration, Registration: &backend.ValidatorRegistration{FeeRecipient: backend.Address{1}, GasLimit: 2, Timestamp: 3, Pubkey: backend.Pubkey{4}}}).Encode()))
	f.Add(must((&SetupRequest{Kind: SetupCharonLock, Lock: []byte(`{"lock_hash":"0x00"}`)}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := DecodeSetupRequest(b)
		if err != nil {
			return
		}
		again, err := q.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("setup request does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}

func FuzzDecodeLockSigned(f *testing.F) {
	f.Add((&LockSigned{LockHash: backend.Root{1}, Signatures: []LockSignature{{Pubkey: backend.Pubkey{2}}, {Signature: backend.Signature{3}}}}).Encode())
	f.Add((&LockSigned{}).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := DecodeLockSigned(b)
		if err != nil {
			return
		}
		if again := l.Encode(); !bytes.Equal(again, b) {
			t.Fatalf("lock answer does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeOrderState(f *testing.F) {
	f.Add((&OrderState{Outcome: OrderKnown, Status: OrderVoid, Hash: [32]byte{1, 2}, Position: 2, Arrived: 10, ActAt: 20,
		NotAfter: 30, Why: "dkg order: the signature of approver 0 does not verify"}).Encode())
	f.Add((&OrderState{Outcome: OrderAccepted, Status: OrderPending}).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeOrderState(b)
		if err != nil {
			return
		}
		if again := s.Encode(); !bytes.Equal(again, b) {
			t.Fatalf("order state does not encode back:\n%x\n%x", again, b)
		}
	})
}

func FuzzDecodeInOrder(f *testing.F) {
	for _, typ := range []byte{byte(TypeHello), byte(TypeCommit), byte(TypeAbort), byte(TypeSetupSign), byte(TypeOperator), 0x01} {
		f.Add(append(append(bytes.Repeat([]byte{7}, 32), typ), 1, 2, 3))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeInOrder(b)
		if err != nil {
			return
		}
		again, err := m.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("order envelope does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}
