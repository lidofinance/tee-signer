// Package charonnode is the part of a Charon lock that each Charon node
// makes itself: its signature over the lock hash with the key of its ENR
// (charon-enr-private-key). That key stays on the node, outside any TEE: it
// authenticates the node to its Charon peers and cannot sign a duty.
package charonnode

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// LoadKey reads a charon-enr-private-key file: 32 bytes as hex.
func LoadKey(path string) (*secp256k1.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(b) != 32 {
		return nil, errors.New("charonnode: the key file is not 32 bytes of hex")
	}
	k := secp256k1.PrivKeyFromBytes(b)
	clear(b)
	return k, nil
}

// Sign returns the 65-byte signature Charon wants in node_signatures: r, s
// and the recovery id (0 or 1), over the raw 32-byte lock hash.
func Sign(k *secp256k1.PrivateKey, lockHash backend.Root) []byte {
	c := ecdsa.SignCompact(k, lockHash[:], true) // [27+4+recid] r s
	out := append(append([]byte(nil), c[1:]...), (c[0]-27)&3)
	return out
}

// Recover returns the compressed key that made sig over lockHash.
func Recover(sig []byte, lockHash backend.Root) ([]byte, error) {
	if len(sig) != 65 {
		return nil, errors.New("charonnode: node signature is not 65 bytes")
	}
	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	if v > 1 {
		return nil, errors.New("charonnode: bad recovery id")
	}
	compact := append([]byte{27 + 4 + v}, sig[:64]...)
	pk, _, err := ecdsa.RecoverCompact(compact, lockHash[:])
	if err != nil {
		return nil, err
	}
	return pk.SerializeCompressed(), nil
}

// AddSignature checks the lock (hashes, shares, deposits, registrations,
// signature_aggregate), finds the operator whose ENR is k's, and puts k's
// signature over the lock hash at its place. It returns the operator index.
func AddSignature(l *charonlock.Lock, k *secp256k1.PrivateKey) (int, error) {
	if err := l.VerifyHashes(); err != nil {
		return 0, err
	}
	if err := l.VerifyBLS(); err != nil {
		return 0, err
	}
	pub := k.PubKey().SerializeCompressed()
	idx := -1
	for i, o := range l.Definition.Operators {
		ek, err := ENRKey(o.ENR)
		if err != nil {
			return 0, fmt.Errorf("operator %d: %w", i, err)
		}
		if bytes.Equal(ek, pub) {
			idx = i
		}
	}
	if idx < 0 {
		return 0, errors.New("charonnode: this key is not the key of any operator's ENR")
	}
	n := len(l.Definition.Operators)
	if len(l.NodeSignatures) != n {
		l.NodeSignatures = make([]charonlock.Hex, n)
	}
	var lh backend.Root
	copy(lh[:], l.LockHash)
	l.NodeSignatures[idx] = Sign(k, lh)
	return idx, nil
}

// VerifyNodeSignatures checks that every operator signed the lock hash with
// its ENR key, as charon run does.
func VerifyNodeSignatures(l *charonlock.Lock) error {
	if len(l.NodeSignatures) != len(l.Definition.Operators) {
		return fmt.Errorf("charonnode: %d node signatures for %d operators", len(l.NodeSignatures), len(l.Definition.Operators))
	}
	var lh backend.Root
	copy(lh[:], l.LockHash)
	for i, o := range l.Definition.Operators {
		ek, err := ENRKey(o.ENR)
		if err != nil {
			return fmt.Errorf("operator %d: %w", i, err)
		}
		if len(l.NodeSignatures[i]) == 0 {
			return fmt.Errorf("charonnode: operator %d has not signed", i)
		}
		got, err := Recover(l.NodeSignatures[i], lh)
		if err != nil || !bytes.Equal(got, ek) {
			return fmt.Errorf("charonnode: operator %d's signature is not by its ENR key", i)
		}
	}
	return nil
}
