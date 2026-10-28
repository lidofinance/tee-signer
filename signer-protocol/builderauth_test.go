package backend

import (
	"encoding/hex"
	"testing"
)

// Vectors from signer-core/tests/data/builder_auth_go.txt (go-eth2-client
// v0.30.1): SSZ, root of the data, root of the container. The second is the
// Web3Signer 26.9.0 example (data "builder.example.org", slot 32).
// go-eth2-client hashes the container as a ProgressiveContainer; builder-specs
// has a plain Container, so the backend's root is hash(data root, slot
// chunk) and differs from the third column.
var builderAuthVectors = [][3]string{
	{"0c000000e7e3a8ea0b286c7f", "96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57", "0ba5ec021c2bd42fa551bc350618857965ccc1548d27f32ed0aaf8d1a81bd171"},
	{"0c00000020000000000000006275696c6465722e6578616d706c652e6f7267", "72e371dc05200f6a51999de982af676ee79ce1dc03fdcc12da106db214d15d4e", "94c3e97c0ac42592fb40c9ffebca61179467592bac42b02d13c74fa695b963a5"},
	{"0c000000fd203b4a938d9013dfa88bec89389897d64f6f09193997e80bd3a86ddf249ef5c679af10a8d73a74ec", "6d8d839335f67402858fc3f65d735e10d760946c0856e2c4739be33f22e19101", "e1f1057871ce047f722f1b3aac3fac8b0a70f3b57c7bfb742072ab5344c2915b"},
}

func TestBuilderRequestAuthVectors(t *testing.T) {
	for _, v := range builderAuthVectors {
		b, _ := hex.DecodeString(v[0])
		m, err := DecodeSSZ(KindBuilderRequestAuth, b)
		if err != nil {
			t.Fatal(err)
		}
		a := m.(*BuilderRequestAuth)
		if r := BuilderRequestAuthDataRoot(a.Data); hex.EncodeToString(r[:]) != v[1] {
			t.Fatalf("data root %x, want %s", r, v[1])
		}
		r, _ := HashTreeRoot(m)
		if want := hashPair(BuilderRequestAuthDataRoot(a.Data), u64Root(a.Slot)); r != want {
			t.Fatalf("root %x, want the plain Container root %x", r[:], want[:])
		}
		if hex.EncodeToString(r[:]) == v[2] {
			t.Fatalf("root %x is go-eth2-client's ProgressiveContainer root", r[:])
		}
		if enc, _ := EncodeSSZ(m); hex.EncodeToString(enc) != v[0] {
			t.Fatal("SSZ does not round trip")
		}
	}
	if string(mustDecode(t, builderAuthVectors[1][0]).Data) != "builder.example.org" {
		t.Fatal("example data")
	}
}

func mustDecode(t *testing.T, h string) *BuilderRequestAuth {
	b, _ := hex.DecodeString(h)
	m, err := DecodeSSZ(KindBuilderRequestAuth, b)
	if err != nil {
		t.Fatal(err)
	}
	return m.(*BuilderRequestAuth)
}

func TestBuilderRequestAuthStrict(t *testing.T) {
	ok := append([]byte{12, 0, 0, 0}, make([]byte, 8+MaxBuilderRequestAuthData)...)
	if _, err := DecodeSSZ(KindBuilderRequestAuth, ok); err != nil {
		t.Fatalf("4096 data bytes: %v", err)
	}
	for name, b := range map[string][]byte{
		"short":       {12, 0, 0, 0, 1, 2, 3},
		"offset 13":   append([]byte{13, 0, 0, 0}, make([]byte, 9)...),
		"4097 bytes":  append(append([]byte{}, ok...), 0),
		"high offset": append([]byte{12, 0, 0, 1}, make([]byte, 8)...),
	} {
		if _, err := DecodeSSZ(KindBuilderRequestAuth, b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if KindBuilderRequestAuth.String() != "builder_request_auth" || StatusPolicyBuilderAuth.String() != "SC_ERR_POLICY_BUILDER_AUTH" {
		t.Fatal("names")
	}
}
