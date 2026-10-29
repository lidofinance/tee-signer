package setupwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
)

// Context is one entry of the registry of signing contexts
// (setup-phase.md, section 2). Every input that approvers sign, or that the
// runner hashes or derives a key with, is
//
//	len:u16 context body
//
// so no context can pose as another and no two message types can share a
// signature. Build one only from the variables below.
type Context struct{ name string }

// The registry. The names are fixed: changing one changes every hash and
// signature made under it. testdata/contexts.txt holds the same list for
// the C copy (the TA's header) to compare against.
var (
	// setup_hash, over policy_root and platform_commitment (policy.go).
	CtxSetup = Context{"signer-setup-v1"}
	// Approvers: CONFIG_UPDATE, over the update header (update.go), which
	// names the root of the new group. Also the update's hash (prev_hash
	// and the state in IDENTITY) is SHA-256 over this input, so it names
	// exactly what the approvers signed.
	CtxConfigUpdate = Context{"signer-config-update-v1"}
	// Approvers: handover order.
	CtxHandoverOrder = Context{"signer-handover-order-v1"}
	// One approver: PAUSE.
	CtxPause = Context{"signer-pause-v1"}
	// IdentityUserData (IDENTITY, with the key origin).
	CtxRunnerIdentity = Context{"signer-runner-identity-v1"}
	// Mark log: record signature, mark key AAD, hint AAD, share AAD.
	CtxMark     = Context{"signer-mark-v1"}
	CtxMarkKey  = Context{"signer-mark-key-v1"}
	CtxMarkHint = Context{"signer-mark-hint-v1"}
	CtxShare    = Context{"signer-share-v1"}
	// Azure HKDF info strings.
	CtxAzureSealing = Context{"signer-runner azure sealing v1"}
	CtxAzureKeyWrap = Context{"signer-runner azure key wrap v1"}
	// Approvers on boards (the TA).
	CtxTAPolicy       = Context{"signer-ta-policy-v1"}
	CtxTAExitApproval = Context{"signer-ta-exit-approval-v1"}
	CtxTAPause        = Context{"signer-ta-pause-v1"}
	CtxTAResume       = Context{"signer-ta-resume-v1"}

	// Hashes the design names without a context. Its rule puts every
	// hash the runner makes in the registry, so they get one here.
	//
	// The chain hash in an update body: over the setup's chain part.
	CtxChain = Context{"signer-chain-v1"}
	// The approver set hash in IDENTITY: over approvals_needed:u8 n:u8 and the keys.
	CtxApproverSet = Context{"signer-approver-set-v1"}

	// State copy (runner/statestore): the snapshot's AES-GCM AAD and the
	// snapshot key's key-release AAD, both over setup_hash.
	CtxState    = Context{"signer-state-v1"}
	CtxStateKey = Context{"signer-state-key-v1"}

	// The ATTEST user data (backend.AttestUserData), next to the
	// identity's, with the key origin.
	CtxRunnerAttest = Context{"signer-runner-attest-v1"}
	// GCP Cloud KMS additional authenticated data: of the sealing data key
	// (over setup_hash), and of the keys of platform.Keys (over setup_hash
	// and the caller's AAD).
	CtxGCPSealing = Context{"signer-runner gcp sealing v1"}
	CtxGCPKeyWrap = Context{"signer-runner gcp key wrap v1"}

	// The policy tree (policy.go): a leaf and a node, policy_root over the
	// three group roots, and platform_commitment over the platform salt and
	// the private part.
	CtxPolicyLeaf         = Context{"signer-policy-leaf-v1"}
	CtxPolicyNode         = Context{"signer-policy-node-v1"}
	CtxPolicyRoot         = Context{"signer-policy-root-v1"}
	CtxPlatformCommitment = Context{"signer-platform-commitment-v1"}

	// The key origin: the hash of the DKG orders the runner's generated
	// keys came from (backend.KeygenOrdersHash).
	CtxKeygenOrders = Context{"signer-keygen-orders-v1"}
	// key_release_hash in the setup state: over what the AWS and Azure
	// runners read at start about the key that releases their sealing key
	// (backend.KeyReleaseHash).
	CtxKeyRelease = Context{"signer-key-release-v1"}

	// Handover (package handover).
	//
	// The HPKE associated data of a handed-over share: over its header,
	// which carries the mark and the share's key origin.
	CtxHandoverShare = Context{"signer-handover-share-v1"}
	// The source's origin key signs each handed-over share's header with
	// it, so the key origin a target counts comes from the source.
	CtxHandoverOrigin = Context{"signer-handover-origin-v1"}
	// The user data of the source's attestation of its origin key: over
	// the order hash and the origin key.
	CtxHandoverOriginKey = Context{"signer-handover-origin-key-v1"}

	// The import order (package importorder). k approvers in force sign an
	// import order under CtxImportOrder; CtxImportCommitments hashes a
	// validator's public commitments (Feldman), which the order names.
	CtxImportOrder       = Context{"signer-import-order-v1"}
	CtxImportCommitments = Context{"signer-import-commitments-v1"}

	// Hash-then-sign: the second form of each approver signature. An
	// approver signs the 32 bytes CtxXHash.Hash(SHA-256(CtxX.Message(body))),
	// so an OpenPGP card can sign any body: gpg's scdaemon passes the card a
	// message of 20, 28, 32, 48 or 64 bytes only (docs/protocol.md,
	// "Hardware approver keys"). The verifiers take either form per
	// signature (VerifyApproval).
	CtxConfigUpdateHash   = Context{"signer-config-update-hash-v1"}
	CtxHandoverOrderHash  = Context{"signer-handover-order-hash-v1"}
	CtxImportOrderHash    = Context{"signer-import-order-hash-v1"}
	CtxTAExitApprovalHash = Context{"signer-ta-exit-approval-hash-v1"}

	// The hash of what a handover source carries to its target besides
	// the shares (package handover, carry.go). Each share's HPKE associated
	// data takes it after the header, so nobody can drop or change the
	// carried part without every share failing to open.
	CtxHandoverCarry = Context{"signer-handover-carry-v1"}
)

// hashedForm maps each approver context to its hash-then-sign context.
var hashedForm = map[Context]Context{
	CtxConfigUpdate:   CtxConfigUpdateHash,
	CtxHandoverOrder:  CtxHandoverOrderHash,
	CtxImportOrder:    CtxImportOrderHash,
	CtxTAExitApproval: CtxTAExitApprovalHash,
}

// HashedContext is the hash-then-sign context of the approver context c;
// false if c is not one of the four approver contexts.
func HashedContext(c Context) (Context, bool) {
	h, ok := hashedForm[c]
	return h, ok
}

// ApprovalMessage is what an approver signs for body under the approver
// context c: c.Message(body) in the direct form, and in the hashed form the
// 32 bytes HashedContext(c).Hash(SHA-256(c.Message(body))). It panics if c
// is not an approver context, a programming error.
func ApprovalMessage(c Context, hashed bool, body ...[]byte) []byte {
	direct := c.Message(body...)
	if !hashed {
		return direct
	}
	h, ok := hashedForm[c]
	if !ok {
		panic("setupwire: " + c.name + " has no hashed form")
	}
	d := sha256.Sum256(direct)
	m := h.Hash(d[:])
	return m[:]
}

// SignApproval is key's signature over body under the approver context c,
// in the direct or the hashed form.
func SignApproval(key ed25519.PrivateKey, c Context, hashed bool, body ...[]byte) [64]byte {
	var sig [64]byte
	copy(sig[:], ed25519.Sign(key, ApprovalMessage(c, hashed, body...)))
	return sig
}

// VerifyApproval reports whether sig is the signature of the approver key
// k over body under c, in the direct or the hashed form. The direct
// message starts with its context; the hashed one is SHA-256 over an input
// that starts with its hash context. A signature of one form or kind
// passes for another only through a SHA-256 collision or preimage.
func VerifyApproval(k [32]byte, c Context, sig [64]byte, body ...[]byte) bool {
	pub := ed25519.PublicKey(k[:])
	return ed25519.Verify(pub, ApprovalMessage(c, false, body...), sig[:]) ||
		ed25519.Verify(pub, ApprovalMessage(c, true, body...), sig[:])
}

// Contexts lists the registry in a fixed order.
var Contexts = []Context{
	CtxSetup, CtxConfigUpdate, CtxHandoverOrder, CtxPause,
	CtxRunnerIdentity, CtxMark, CtxMarkKey, CtxMarkHint, CtxShare,
	CtxAzureSealing, CtxAzureKeyWrap,
	CtxTAPolicy, CtxTAExitApproval, CtxTAPause, CtxTAResume,
	CtxChain, CtxApproverSet,
	CtxState, CtxStateKey,
	CtxRunnerAttest, CtxGCPSealing, CtxGCPKeyWrap,
	CtxPolicyLeaf, CtxPolicyNode, CtxPolicyRoot, CtxPlatformCommitment,
	CtxKeygenOrders, CtxKeyRelease,
	CtxHandoverShare, CtxHandoverOrigin, CtxHandoverOriginKey,
	CtxImportOrder, CtxImportCommitments,
	CtxConfigUpdateHash, CtxHandoverOrderHash, CtxImportOrderHash, CtxTAExitApprovalHash,
	CtxHandoverCarry,
}

func (c Context) String() string { return c.name }

// Message is the input to sign, hash or derive with: len:u16, the context,
// then the parts of the body in order.
func (c Context) Message(body ...[]byte) []byte {
	n := 2 + len(c.name)
	for _, b := range body {
		n += len(b)
	}
	m := make([]byte, 0, n)
	m = binary.BigEndian.AppendUint16(m, uint16(len(c.name)))
	m = append(m, c.name...)
	for _, b := range body {
		m = append(m, b...)
	}
	return m
}

// Hash is SHA-256 over Message(body...).
func (c Context) Hash(body ...[]byte) [32]byte { return sha256.Sum256(c.Message(body...)) }
