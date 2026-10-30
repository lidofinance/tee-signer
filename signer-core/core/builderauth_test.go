package core_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The core signs a BuilderRequestAuth whose data root is on the list, under
// DOMAIN_BUILDER_REQUEST_AUTH with the genesis fork version and a zero
// root; it refuses other data, an empty list, a pre-Gloas slot and another
// domain, and a policy update changes the list.
func TestBuilderRequestAuth(t *testing.T) {
	host := []byte("builder.example.org")
	hooks := software.NewMemHooks()
	s, pk, cfg, _ := gloasSigner(t, hooks)
	m := &backend.BuilderRequestAuth{Data: host, Slot: 20*32 + 1}

	_, err := s.Sign(signReq(s, pk, m))
	wantStatus(t, err, backend.StatusPolicyBuilderAuth) // empty list

	c0 := s.Config()
	p := c0.Policy()
	p.BuilderRequestAuthRoots = []backend.Root{backend.BuilderRequestAuthDataRoot(host)}
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(signReq(s, pk, m))
	if err != nil {
		t.Fatal(err)
	}
	root, err := c0.SigningRoot(m)
	if err != nil {
		t.Fatal(err)
	}
	obj, _ := backend.HashTreeRoot(m)
	d := backend.ComputeDomain(backend.DomainBuilderRequestAuth, cfg.GenesisForkVersion, backend.Root{})
	if root != backend.SigningRoot(obj, d) {
		t.Fatal("signing root: not the genesis fork version with a zero root")
	}
	if !core.Verify(pk, root, sig) { // gloasSigner loads the whole key
		t.Fatal("signature does not verify")
	}

	_, err = s.Sign(signReq(s, pk, &backend.BuilderRequestAuth{Data: []byte("other.example.org"), Slot: m.Slot}))
	wantStatus(t, err, backend.StatusPolicyBuilderAuth)
	_, err = s.Sign(signReq(s, pk, &backend.BuilderRequestAuth{Data: host, Slot: (gloasEpoch-1)*32 + 31}))
	wantStatus(t, err, backend.StatusPolicyFork)
	req := signReq(s, pk, m)
	req.Domain = backend.ComputeDomain(backend.DomainBuilderRequestAuth, cfg.ForkVersionAt(20), cfg.GenesisValidatorsRoot)
	_, err = s.Sign(req)
	wantStatus(t, err, backend.StatusDomainMismatch)

	p.BuilderRequestAuthRoots = make([]backend.Root, core.MaxBuilderAuthRootsForTest+1)
	if err := s.SetPolicy(p); err == nil {
		t.Fatal("17 roots accepted")
	}
	p.BuilderRequestAuthRoots = nil
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	_, err = s.Sign(signReq(s, pk, m))
	wantStatus(t, err, backend.StatusPolicyBuilderAuth)
}
