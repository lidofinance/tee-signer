package setupwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"
)

// msg is len:u16 ctx and the parts, written out by hand so the test does
// not lean on Context.Message.
func msg(ctx string, parts ...[]byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(ctx)))
	b = append(b, ctx...)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func sum(ctx string, parts ...[]byte) [32]byte { return sha256.Sum256(msg(ctx, parts...)) }

// The layouts of docs/attestation-statement.md: a leaf, a node, the
// padding, the roots and setup_hash.
func TestPolicyLayout(t *testing.T) {
	l := Leaf{Name: "genesis_time", Value: []byte{0, 0, 0, 0, 0x68, 0xe7, 0x30, 0x00}, Salt: [32]byte{9}}
	want := sum("signer-policy-leaf-v1", []byte{12}, []byte("genesis_time"), []byte{0, 0, 0, 8}, l.Value, l.Salt[:])
	if l.Hash() != want {
		t.Fatal("leaf layout")
	}
	h := func(b byte) [32]byte { return sha256.Sum256([]byte{b}) }
	node := func(a, b [32]byte) [32]byte { return sum("signer-policy-node-v1", a[:], b[:]) }
	var zero [32]byte
	if MerkleRoot([][32]byte{h(1)}) != h(1) {
		t.Fatal("one leaf is its own root")
	}
	if MerkleRoot([][32]byte{h(1), h(2), h(3)}) != node(node(h(1), h(2)), node(h(3), zero)) {
		t.Fatal("three leaves pad to four with a zero hash")
	}
	if MerkleRoot([][32]byte{h(1), h(2), h(3), h(4), h(5)}) != node(node(node(h(1), h(2)), node(h(3), h(4))), node(node(h(5), zero), node(zero, zero))) {
		t.Fatal("five leaves pad to eight")
	}

	for name, s := range samples(t) {
		b := must(s.Encode())
		// The setup is 'S', then the leaf values of each group followed by
		// its salts, the platform salt and the private part.
		pub := must1(s.PublicLeaves())
		lk := must1(s.Locked.Leaves(s.PolicySalts.Locked))
		op := must1(s.Open.Leaves(s.PolicySalts.Open))
		if len(pub) != NumPublicLeaves || len(lk) != NumLockedLeaves || len(op) != NumOpenLeaves {
			t.Fatalf("%s: leaf counts %d %d %d", name, len(pub), len(lk), len(op))
		}
		var rebuilt []byte
		rebuilt = append(rebuilt, 'S')
		roots := make([][32]byte, 3)
		for i, ls := range [][]Leaf{pub, lk, op} {
			var hs [][32]byte
			for _, l := range ls {
				rebuilt = append(rebuilt, l.Value...)
				hs = append(hs, sum("signer-policy-leaf-v1", []byte{byte(len(l.Name))}, []byte(l.Name),
					binary.BigEndian.AppendUint32(nil, uint32(len(l.Value))), l.Value, l.Salt[:]))
			}
			for _, l := range ls {
				rebuilt = append(rebuilt, l.Salt[:]...)
			}
			roots[i] = MerkleRoot(hs)
		}
		priv := must(s.PrivateBytes())
		rebuilt = append(rebuilt, s.PlatformSalt[:]...)
		rebuilt = append(rebuilt, priv...)
		if !bytes.Equal(rebuilt, b) {
			t.Fatalf("%s: the setup is not its leaf values, salts and private part in order", name)
		}
		pr := sum("signer-policy-root-v1", roots[0][:], roots[1][:], roots[2][:])
		pc := sum("signer-platform-commitment-v1", s.PlatformSalt[:], priv)
		if got, _ := s.PolicyRoot(); got != pr {
			t.Fatalf("%s: policy_root", name)
		}
		if got, _ := s.PlatformCommitment(); got != pc {
			t.Fatalf("%s: platform_commitment", name)
		}
		if got, _ := s.Hash(); got != sum("signer-setup-v1", pr[:], pc[:]) {
			t.Fatalf("%s: setup_hash", name)
		}
		if lh, _ := s.GroupHash(GroupLocked); lh != roots[1] {
			t.Fatalf("%s: locked hash at version 0 is not the root of its leaves", name)
		}
		names := []string{}
		for _, l := range pub {
			names = append(names, l.Name)
		}
		pn, _, _ := LeafNames()
		if !slices.Equal(names, pn) {
			t.Fatalf("%s: leaf names", name)
		}
	}
}

func must1[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Every value and every salt of the public part moves policy_root and not
// platform_commitment; every private value moves platform_commitment and
// not policy_root.
func TestPolicySplit(t *testing.T) {
	base := samples(t)["setup-gcp"]
	pr0, _ := base.PolicyRoot()
	pc0, _ := base.PlatformCommitment()
	h0, _ := base.Hash()
	check := func(what string, s *Setup, policy bool) {
		t.Helper()
		pr, err := s.PolicyRoot()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		pc, _ := s.PlatformCommitment()
		h, _ := s.Hash()
		if (pr != pr0) != policy || (pc != pc0) == policy || h == h0 {
			t.Errorf("%s: policy_root moved %v, platform_commitment moved %v, want the %v side", what, pr != pr0, pc != pc0, map[bool]string{true: "policy", false: "platform"}[policy])
		}
	}
	for _, f := range []struct {
		what   string
		policy bool
		mutate func(s *Setup)
	}{
		{"cluster_id", true, func(s *Setup) { s.ClusterID[5]++ }},
		{"handover_generation", true, func(s *Setup) { s.HandoverGeneration++ }},
		{"genesis_time", true, func(s *Setup) { s.Chain.GenesisTime++ }},
		{"max_keys", true, func(s *Setup) { s.MaxKeys++ }},
		{"slashing_log_min_lock_days", true, func(s *Setup) { s.SlashingLogMinLockDays++ }},
		{"builder_gas_limit_max", true, func(s *Setup) { s.Locked.BuilderGasLimitMax++ }},
		{"slot_time_changes", true, func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{Epoch: 9, SecondsPerSlot: 4}} }},
		{"allowed_builder_request_auth_data_roots", true, func(s *Setup) {
			s.Locked.AllowedBuilderRequestAuthDataRoots = append(s.Locked.AllowedBuilderRequestAuthDataRoots, [32]byte{0x61})
		}},
		{"gloas_fork_epoch", true, func(s *Setup) { s.Open = sampleOpen() }},
		{"a public salt", true, func(s *Setup) { s.PolicySalts.Public[15][0]++ }},
		{"a locked salt", true, func(s *Setup) { s.PolicySalts.Locked[18][0]++ }},
		{"an open salt", true, func(s *Setup) { s.PolicySalts.Open[1][0]++ }},
		{"signer_name", false, func(s *Setup) { s.SignerName = "signer-9" }},
		{"slashing_log_store", false, func(s *Setup) { s.Platform.SlashingLogStore.Bucket = "other-bucket" }},
		{"allowed_client_ca", false, func(s *Setup) { s.Platform.AllowedClientCA = [][]byte{makeCA(t, 2, "second CA", true)} }},
		{"sealing_key_release", false, func(s *Setup) { s.Platform.SealingKeyRelease.AttestAudience = "other" }},
		{"platform_salt", false, func(s *Setup) { s.PlatformSalt[0]++ }},
	} {
		s := samples(t)["setup-gcp"]
		f.mutate(s)
		check(f.what, s, f.policy)
	}
	// Two signers of a cluster: the same public part and salts, another
	// private part. They share policy_root.
	a, b := samples(t)["setup-nitro"], samples(t)["setup-nitro-peers"]
	pa, _ := a.PolicyRoot()
	pb, _ := b.PolicyRoot()
	ca, _ := a.PlatformCommitment()
	cb, _ := b.PlatformCommitment()
	if pa != pb || ca == cb {
		t.Fatal("signers of one cluster do not share policy_root")
	}
}

// NewPolicySalts draws one salt per leaf and refuses a source that runs
// dry or gives zero bytes.
func TestNewSalts(t *testing.T) {
	src := bytes.NewReader(bytes.Repeat([]byte{7}, 32*(NumPublicLeaves+NumLockedLeaves+NumOpenLeaves)))
	p, err := NewPolicySalts(src)
	if err != nil || p.check() != nil {
		t.Fatalf("%v", err)
	}
	if _, err := NewPolicySalts(bytes.NewReader(make([]byte, 64))); err == nil {
		t.Fatal("a short source gave salts")
	}
	if _, err := NewSalts(bytes.NewReader(make([]byte, 32)), 1); err == nil {
		t.Fatal("a zero salt was drawn")
	}
}
