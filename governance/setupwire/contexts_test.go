package setupwire

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The names are distinct, so with the length prefix no input under one
// context equals an input under another.
func TestContexts(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Contexts {
		name := c.String()
		if name == "" || len(name) > 255 || seen[name] {
			t.Fatalf("context %q: empty, too long or listed twice", name)
		}
		for i := 0; i < len(name); i++ {
			if name[i] < 0x20 || name[i] > 0x7e {
				t.Fatalf("context %q is not printable ASCII", name)
			}
		}
		seen[name] = true
	}
	// The TA header lists the same names except the import order, the
	// hash-then-sign and the handover carry contexts, which are the
	// runner's only.
	if len(Contexts) != 38 {
		t.Fatalf("%d contexts; add a new one to Contexts and to the TA header", len(Contexts))
	}
	// Package backend cannot import this one, so it holds the names of the
	// user data, key origin and key release contexts itself.
	if backend.IdentityContext != CtxRunnerIdentity.String() || backend.AttestContext != CtxRunnerAttest.String() {
		t.Fatalf("backend's contexts %q and %q are not the registry's", backend.IdentityContext, backend.AttestContext)
	}
	if backend.KeygenOrdersContext != CtxKeygenOrders.String() || backend.KeyReleaseContext != CtxKeyRelease.String() {
		t.Fatalf("backend's contexts %q and %q are not the registry's", backend.KeygenOrdersContext, backend.KeyReleaseContext)
	}

	m := CtxSetup.Message([]byte("ab"), []byte("c"))
	if !bytes.Equal(m, []byte("\x00\x0fsigner-setup-v1abc")) {
		t.Fatalf("message layout %q", m)
	}
	if CtxSetup.Hash([]byte("abc")) != sha256.Sum256(m) {
		t.Fatal("hash is not SHA-256 of the message")
	}
	// No context's header (length and name) starts another's, so no body
	// can make an input under one context equal an input under another.
	for _, a := range Contexts {
		for _, b := range Contexts {
			if a != b && bytes.HasPrefix(b.Message(), a.Message()) {
				t.Fatalf("%q poses as %q", a, b)
			}
		}
	}
}

// The four approver contexts have a hashed form: its message is the 32
// bytes SHA-256 of the hashed context and SHA-256 of the direct message.
// No other context has one.
func TestHashedContexts(t *testing.T) {
	approverCtx := []Context{CtxConfigUpdate, CtxHandoverOrder, CtxImportOrder, CtxTAExitApproval}
	for _, c := range approverCtx {
		h, ok := HashedContext(c)
		name := c.String()
		if !ok || h.String() != name[:len(name)-3]+"-hash"+name[len(name)-3:] {
			t.Errorf("%s: hashed context %q %v", c, h, ok)
		}
		d := sha256.Sum256(c.Message([]byte("body")))
		m := sha256.Sum256(h.Message(d[:]))
		if !bytes.Equal(ApprovalMessage(c, true, []byte("body")), m[:]) || !bytes.Equal(ApprovalMessage(c, false, []byte("body")), c.Message([]byte("body"))) {
			t.Errorf("%s: approval messages", c)
		}
	}
	for _, c := range Contexts {
		if _, ok := HashedContext(c); ok != slices.Contains(approverCtx, c) {
			t.Errorf("%s: has a hashed form: %v", c, ok)
		}
	}
}
