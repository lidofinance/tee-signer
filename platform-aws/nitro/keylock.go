package nitro

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

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
// Nitro enclave of a named image: an Allow of one of them needs literal
// kms:RecipientAttestation:PCR0, PCR1 and PCR2 conditions (enclaveBinding). GenerateDataKey*
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
// to an enclave (enclaveBinding), and every other Allow of Encrypt holds to
// the record credentials' context (recordCredsOnly). Conditions do not count for
// lockActions: a grant under a condition is still a grant. Deny statements only take away, so they
// are skipped. A policy that does not parse is not locked. Grants that
// already exist on the key are not in the policy: KeyRule reads them and
// grantLock decides on them (AWS-KMS-01).
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
		bound, bad := s.enclaveBinding()
		if bad != "" {
			return backend.KeyLockNotLocked, fmt.Sprintf("statement %s: %s", name, bad)
		}
		if bound {
			continue
		}
		for _, a := range keyActions {
			if s.grants(a) {
				return backend.KeyLockNotLocked, fmt.Sprintf("statement %s allows %s without literal kms:RecipientAttestation:PCR0, PCR1 and PCR2 conditions: "+
					"a principal outside the enclave, or an enclave of another image, gets the key", name, a)
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

// recipientPrefix starts the Nitro attestation condition keys of KMS.
const recipientPrefix = "kms:recipientattestation:"

// imagePCRs are the PCRs that name one enclave image (NREL-01): PCR0 the
// whole image, PCR1 the kernel and boot ramfs, PCR2 the application. PCR3
// (the parent's IAM role) and PCR8 (the signing certificate) do not: any
// image that role starts, or that certificate signs, matches them.
var imagePCRs = []string{"pcr0", "pcr1", "pcr2"}

// sha384Hex is a literal PCR or ImageSha384 value.
var sha384Hex = regexp.MustCompile(`^[0-9a-fA-F]{96}$`)

// enclaveBinding reports whether the statement's condition ties it to one
// Nitro enclave image: StringEquals or StringEqualsIgnoreCase tests of
// kms:RecipientAttestation:PCR0, PCR1 and PCR2 (NREL-01). KMS checks such
// a key only on a request with an attestation document (the Recipient
// parameter), so a request without one does not match. IfExists,
// StringLike and set operators do not count.
//
// bad is set when a kms:RecipientAttestation condition of the statement,
// under any operator, has a key other than PCR0 to PCR31 or ImageSha384,
// or a value that is not 96 hex digits. A policy variable such as
// ${aws:PrincipalTag/pcr0} is not 96 hex digits: IAM fills it in per
// request from state outside the key policy, so it fixes no image.
func (s keyPolicyStatement) enclaveBinding() (bound bool, bad string) {
	fixed := map[string]bool{}
	for op, keys := range s.Condition {
		exact := strings.EqualFold(op, "StringEquals") || strings.EqualFold(op, "StringEqualsIgnoreCase")
		for k, raw := range keys {
			lk := strings.ToLower(k)
			name, ok := strings.CutPrefix(lk, recipientPrefix)
			if !ok {
				continue
			}
			if !knownRecipientKey(name) {
				return false, fmt.Sprintf("condition key %s is not a Nitro PCR or ImageSha384", k)
			}
			var vals stringOrList
			if json.Unmarshal(raw, &vals) != nil || len(vals) == 0 {
				return false, fmt.Sprintf("condition %s on %s has no string values", op, k)
			}
			for _, v := range vals {
				if !sha384Hex.MatchString(v) {
					return false, fmt.Sprintf("condition %s on %s has the value %q, not 96 hex digits", op, k, v)
				}
			}
			if exact {
				fixed[name] = true
			}
		}
	}
	for _, p := range imagePCRs {
		if !fixed[p] {
			return false, ""
		}
	}
	return true, ""
}

// knownRecipientKey reports whether name (lower case, after the
// kms:RecipientAttestation: prefix) is a key KMS fills from a Nitro
// attestation document: imagesha384, or pcr0 to pcr31.
func knownRecipientKey(name string) bool {
	if name == "imagesha384" {
		return true
	}
	n, ok := strings.CutPrefix(name, "pcr")
	if !ok || n == "" || len(n) > 2 || (len(n) == 2 && n[0] == '0') {
		return false
	}
	i, err := strconv.Atoi(n)
	return err == nil && i >= 0 && i <= 31
}

// grantLock decides on the grants of a key whose policy is locked
// (AWS-KMS-01). A grant gives its grantee key use that the key policy does
// not show, and it stays in force after the policy is locked. KMS grant
// constraints cover the encryption context only, never the recipient's
// attestation, so a grant of Decrypt or GenerateDataKey hands the key to a
// principal outside the enclave, and a grant of Encrypt lets one plant a
// sealing key. A locked key therefore has no grants at all.
func grantLock(grants []types.GrantListEntry) (backend.KeyLock, string) {
	if len(grants) == 0 {
		return backend.KeyLockLocked, ""
	}
	g := grants[0]
	ops := make([]string, len(g.Operations))
	for i, o := range g.Operations {
		ops[i] = string(o)
	}
	return backend.KeyLockNotLocked, fmt.Sprintf("the key has %d grant(s), for example %s to %s for %s: a grant is outside the key policy and cannot require the enclave as recipient",
		len(grants), aws.ToString(g.GrantId), aws.ToString(g.GranteePrincipal), strings.Join(ops, ","))
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
