package nitro

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// lockActions are the KMS actions no principal of a locked key policy may
// have (research/admin-proof-key-release.md in the PoC repo, section 2.1):
// with any of them someone can change the policy, hand out the key by a
// grant, put in key material they know, or copy the key to another
// region. A wildcard that covers one of them (kms:*, *, kms:Put*) counts
// too.
var lockActions = []string{"kms:PutKeyPolicy", "kms:CreateGrant", "kms:ImportKeyMaterial", "kms:ReplicateKey"}

// keyActions are the KMS actions that give out key material or move it
// under another key (RBRNIT-01). A locked policy allows them only to a
// Nitro enclave of a named image: an Allow of one of them needs a
// kms:RecipientAttestation condition (enclaveBound). GenerateDataKey*
// without plaintext is not here: its answer holds no plaintext.
var keyActions = []string{"kms:Decrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyPair", "kms:ReEncryptFrom", "kms:ReEncryptTo"}

// encryptAction makes a blob of a key the caller knows. A locked policy
// allows it only to the enclave, or only under the record credentials'
// encryption context (recordCredsOnly): a blob under the sealing or mark
// log context would plant a key the caller knows (nitro.go, "contexts").
const encryptAction = "kms:Encrypt"

// policyLock decides whether a KMS key is locked from what KeyRule read:
// the key policy text, the key's Origin and MultiRegion. The key is locked
// when its material was made inside KMS (Origin AWS_KMS), it has no
// replicas in other regions, no Allow statement of the policy grants any
// principal one of lockActions, every Allow of one of keyActions is bound
// to an enclave (enclaveBound), and every other Allow of Encrypt holds to
// the record credentials' context (recordCredsOnly). Conditions do not count for
// lockActions: a grant under a condition is still a grant. Deny statements only take away, so they
// are skipped. A policy that does not parse is not locked. Grants that
// already exist on the key are not in the policy and not read; a locked
// policy that never allowed CreateGrant has none from after it was set.
func policyLock(policy, origin string, multiRegion bool) (backend.KeyLock, string) {
	switch {
	case origin != "AWS_KMS":
		return backend.KeyLockNotLocked, fmt.Sprintf("key origin %s, not AWS_KMS: the key material may be known outside KMS", origin)
	case multiRegion:
		return backend.KeyLockNotLocked, "the key is a multi-Region key: replicas in other regions have their own policies"
	}
	var doc struct {
		Statement json.RawMessage
	}
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return backend.KeyLockNotLocked, fmt.Sprintf("the key policy does not parse: %v", err)
	}
	var stmts []keyPolicyStatement
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var one keyPolicyStatement
		if err := json.Unmarshal(doc.Statement, &one); err != nil {
			return backend.KeyLockNotLocked, fmt.Sprintf("the key policy's Statement does not parse: %v", err)
		}
		stmts = []keyPolicyStatement{one}
	}
	for i, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		name := s.Sid
		if name == "" {
			name = fmt.Sprintf("number %d", i+1)
		}
		for _, a := range lockActions {
			if s.grants(a) {
				return backend.KeyLockNotLocked, fmt.Sprintf("statement %s allows %s", name, a)
			}
		}
		if s.enclaveBound() {
			continue
		}
		for _, a := range keyActions {
			if s.grants(a) {
				return backend.KeyLockNotLocked, fmt.Sprintf("statement %s allows %s without a kms:RecipientAttestation condition: a principal outside the enclave gets the key", name, a)
			}
		}
		if s.grants(encryptAction) && !s.recordCredsOnly() {
			return backend.KeyLockNotLocked, fmt.Sprintf("statement %s allows %s under other encryption contexts than {%s: %s}: a principal outside the enclave can plant a sealing or mark log key",
				name, encryptAction, ctxPurpose, purposeRecordCreds)
		}
	}
	return backend.KeyLockLocked, ""
}

// keyPolicyStatement is the part of an IAM policy statement policyLock reads.
type keyPolicyStatement struct {
	Sid       string
	Effect    string
	Action    stringOrList
	NotAction stringOrList
	Condition map[string]map[string]json.RawMessage
}

// recordCredsOnly reports whether the statement's condition fixes the
// encryption context's purpose to record-creds: a StringEquals test of
// kms:EncryptionContext:purpose with that one value.
func (s keyPolicyStatement) recordCredsOnly() bool {
	for op, keys := range s.Condition {
		if !strings.EqualFold(op, "StringEquals") {
			continue
		}
		for k, raw := range keys {
			if !strings.EqualFold(k, "kms:EncryptionContext:"+ctxPurpose) {
				continue
			}
			var vals stringOrList
			if json.Unmarshal(raw, &vals) == nil && len(vals) == 1 && vals[0] == purposeRecordCreds {
				return true
			}
		}
	}
	return false
}

// enclaveBound reports whether the statement's condition ties it to a
// Nitro enclave image: a StringEquals or StringEqualsIgnoreCase test of a
// kms:RecipientAttestation key against values that are all non-empty
// strings. KMS checks such a key only on a request with an attestation
// document (the Recipient parameter), so a request without one does not
// match. IfExists, StringLike and set operators do not count.
func (s keyPolicyStatement) enclaveBound() bool {
	for op, keys := range s.Condition {
		if !strings.EqualFold(op, "StringEquals") && !strings.EqualFold(op, "StringEqualsIgnoreCase") {
			continue
		}
		for k, raw := range keys {
			if !strings.HasPrefix(strings.ToLower(k), "kms:recipientattestation:") {
				continue
			}
			var vals stringOrList
			if json.Unmarshal(raw, &vals) != nil || len(vals) == 0 {
				continue
			}
			if !slices.Contains(vals, "") {
				return true
			}
		}
	}
	return false
}

// grants reports whether an Allow statement covers action: Action names it
// (by a pattern), or NotAction is present and does not name it.
func (s keyPolicyStatement) grants(action string) bool {
	if s.NotAction != nil {
		return !matchAny(s.NotAction, action)
	}
	return matchAny(s.Action, action)
}

// matchAny matches action against IAM action patterns: case-insensitive,
// with * and ? as wildcards.
func matchAny(patterns []string, action string) bool {
	for _, p := range patterns {
		// path.Match gives * and ? their IAM meaning here: action names
		// have no slash. A pattern with [ or \ matches nothing in IAM;
		// path.Match may read it as a class, so those count as literals.
		lp, la := strings.ToLower(p), strings.ToLower(action)
		if strings.ContainsAny(lp, `[\`) {
			if lp == la {
				return true
			}
			continue
		}
		if ok, err := path.Match(lp, la); err == nil && ok {
			return true
		}
	}
	return false
}

// stringOrList is an IAM field that holds one string or a list.
type stringOrList []string

func (l *stringOrList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}
