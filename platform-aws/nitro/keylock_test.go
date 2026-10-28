package nitro

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// lockedPolicy is a key policy locked as research/admin-proof-key-release.md
// section 2.1 describes: the enclave's data keys and reads, nothing that
// changes the policy, grants, imports or replicates.
const lockedPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "EnclaveOnlyDataKeys", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::111122223333:role/parent"},
     "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
     "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": "00"}}},
    {"Sid": "EnclaveReadsItsKeyPolicy", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::111122223333:role/parent"},
     "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"], "Resource": "*"},
    {"Sid": "AdminReads", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::111122223333:role/admin"},
     "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:ScheduleKeyDeletion"], "Resource": "*"},
    {"Sid": "NoOneElse", "Effect": "Deny", "Principal": "*", "Action": "kms:*", "Resource": "*"}
  ]
}`

// The lock rule per policy: locked only when no Allow statement covers
// PutKeyPolicy, CreateGrant, ImportKeyMaterial or ReplicateKey, by name or
// wildcard or NotAction, and the key is an AWS_KMS key in one region.
func TestPolicyLock(t *testing.T) {
	allow := func(action string) string {
		return `{"Statement":[{"Sid":"S","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"},"Action":` + action + `,"Resource":"*"}]}`
	}
	for _, c := range []struct {
		name, policy, origin string
		multi                bool
		want                 backend.KeyLock
		why                  string
	}{
		{"locked", lockedPolicy, "AWS_KMS", false, backend.KeyLockLocked, ""},
		{"one statement, not a list", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"kms:DescribeKey"}}`, "AWS_KMS", false, backend.KeyLockLocked, ""},
		{"PutKeyPolicy", allow(`["kms:Decrypt","kms:PutKeyPolicy"]`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:PutKeyPolicy"},
		{"CreateGrant", allow(`"kms:CreateGrant"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:CreateGrant"},
		{"ImportKeyMaterial", allow(`"kms:ImportKeyMaterial"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:ImportKeyMaterial"},
		{"ReplicateKey", allow(`"kms:ReplicateKey"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:ReplicateKey"},
		{"kms:*", allow(`"kms:*"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:PutKeyPolicy"},
		{"*", allow(`"*"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows"},
		{"prefix wildcard", allow(`"kms:Put*"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:PutKeyPolicy"},
		{"other case", allow(`"KMS:createGRANT"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:CreateGrant"},
		{"question mark", allow(`"kms:Replicate?ey"`), "AWS_KMS", false, backend.KeyLockNotLocked, "allows kms:ReplicateKey"},
		{"NotAction", `{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":["kms:Decrypt"]}]}`, "AWS_KMS", false, backend.KeyLockNotLocked, "number 1 allows kms:PutKeyPolicy"},
		{"NotAction covering all four", `{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":["kms:PutKeyPolicy","kms:CreateGrant","kms:ImportKeyMaterial","kms:ReplicateKey"]}]}`, "AWS_KMS", false, backend.KeyLockNotLocked, "number 1 allows kms:Decrypt"},
		{"Deny only takes away", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"kms:*"}]}`, "AWS_KMS", false, backend.KeyLockLocked, ""},
		{"imported key", lockedPolicy, "EXTERNAL", false, backend.KeyLockNotLocked, "origin EXTERNAL"},
		{"custom key store", lockedPolicy, "AWS_CLOUDHSM", false, backend.KeyLockNotLocked, "origin AWS_CLOUDHSM"},
		{"multi-Region", lockedPolicy, "AWS_KMS", true, backend.KeyLockNotLocked, "multi-Region"},
		{"not JSON", `{"Statement":`, "AWS_KMS", false, backend.KeyLockNotLocked, "does not parse"},
		{"no statements", `{"Version":"2012-10-17"}`, "AWS_KMS", false, backend.KeyLockNotLocked, "does not parse"},
	} {
		got, why := policyLock(c.policy, c.origin, c.multi)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, got, why, c.want, c.why)
		}
	}
}

// The repository's key policy template lets the key admin call
// PutKeyPolicy, so a key made from it is not locked: on mainnet a runner
// refuses it until the policy is locked.
func TestPolicyTemplateNotLocked(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "deploy", "kms-key-policy.json.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	if got, why := policyLock(string(b), "AWS_KMS", false); got != backend.KeyLockNotLocked || !strings.Contains(why, "KeyAdministration allows kms:PutKeyPolicy") {
		t.Fatalf("template: %s %q", got, why)
	}
}

// KeyRule carries the lock of the policy KMS answered next to the hash.
func TestKeyRuleLock(t *testing.T) {
	f := &keyPolicyKMS{arn: "arn:aws:kms:eu-west-1:111122223333:key/k1", origin: "AWS_KMS", policy: lockedPolicy}
	srv := httptest.NewServer(f)
	defer srv.Close()
	keys := Keys{Client: kms.New(kms.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), Credentials: staticCreds,
		HTTPClient: srv.Client(), RetryMaxAttempts: 1}), KeyID: "k1"}
	r, err := keys.KeyRule(context.Background())
	if err != nil || r.Lock != backend.KeyLockLocked || r.Hash == ([32]byte{}) {
		t.Fatalf("locked policy: %+v %v", r, err)
	}
	f.policy = strings.Replace(lockedPolicy, `"kms:ScheduleKeyDeletion"`, `"kms:ScheduleKeyDeletion", "kms:PutKeyPolicy"`, 1)
	if r, err = keys.KeyRule(context.Background()); err != nil || r.Lock != backend.KeyLockNotLocked || !strings.Contains(r.Why, "AdminReads allows kms:PutKeyPolicy") {
		t.Fatalf("policy with PutKeyPolicy: %+v %v", r, err)
	}
}

// RBRNIT-01: a policy that lets anyone outside the enclave get the key's
// plaintext is not locked, even when nobody can change it. Every Allow of
// Decrypt, GenerateDataKey* or ReEncrypt* needs a kms:RecipientAttestation
// condition with StringEquals or StringEqualsIgnoreCase.
func TestPolicyLockWhoMayDecrypt(t *testing.T) {
	withStmt := func(stmt string) string {
		return strings.Replace(lockedPolicy, `{"Sid": "NoOneElse"`, stmt+`,
    {"Sid": "NoOneElse"`, 1)
	}
	const admin = `"Principal": {"AWS": "arn:aws:iam::111122223333:role/admin"}, "Resource": "*"`
	for _, c := range []struct {
		name, policy string
		want         backend.KeyLock
		why          string
	}{
		{"enclave only", lockedPolicy, backend.KeyLockLocked, ""},
		{"admin Decrypt", withStmt(`{"Sid": "AdminDecrypt", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt"}`), backend.KeyLockNotLocked, "AdminDecrypt allows kms:Decrypt"},
		{"admin GenerateDataKey", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": ["kms:GenerateDataKey"]}`), backend.KeyLockNotLocked, "A allows kms:GenerateDataKey"},
		{"admin GenerateDataKeyPair", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:GenerateDataKey*"}`), backend.KeyLockNotLocked, "A allows kms:GenerateDataKey"},
		{"admin ReEncryptFrom", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:ReEncrypt*"}`), backend.KeyLockNotLocked, "A allows kms:ReEncryptFrom"},
		{"admin Decrypt under another condition", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringEquals": {"kms:EncryptionContext:purpose": "x"}}}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"IfExists does not bind", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringEqualsIfExists": {"kms:RecipientAttestation:PCR0": "00"}}}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"StringLike does not bind", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringLike": {"kms:RecipientAttestation:PCR0": "*"}}}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"empty value does not bind", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringEquals": {"kms:RecipientAttestation:ImageSha384": ""}}}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"second enclave statement", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringEquals": {"kms:RecipientAttestation:ImageSha384": "ab"}}}`), backend.KeyLockLocked, ""},
		{"NotAction", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "NotAction": ["kms:PutKeyPolicy", "kms:CreateGrant", "kms:ImportKeyMaterial", "kms:ReplicateKey"]}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"one statement, not a list", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt"}}`, backend.KeyLockNotLocked, "number 1 allows kms:Decrypt"},
	} {
		got, why := policyLock(c.policy, "AWS_KMS", false)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, got, why, c.want, c.why)
		}
	}
}

// The repository's template with PutKeyPolicy taken out is locked: its only
// Decrypt and GenerateDataKey statement is bound to the enclave's PCRs.
// With an extra unconditional admin Decrypt it is not.
func TestPolicyTemplateWithoutPutKeyPolicyLocked(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "deploy", "kms-key-policy.json.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	locked := strings.Replace(string(b), `"kms:List*", "kms:PutKeyPolicy",`, `"kms:List*",`, 1)
	if locked == string(b) {
		t.Fatal("template changed: no PutKeyPolicy to take out")
	}
	if got, why := policyLock(locked, "AWS_KMS", false); got != backend.KeyLockLocked {
		t.Fatalf("template without PutKeyPolicy: %s %q", got, why)
	}
	open := strings.Replace(locked, `"kms:List*",`, `"kms:List*", "kms:Decrypt",`, 1)
	if got, why := policyLock(open, "AWS_KMS", false); got != backend.KeyLockNotLocked || !strings.Contains(why, "KeyAdministration allows kms:Decrypt") {
		t.Fatalf("template with admin Decrypt: %s %q", got, why)
	}
}

// RBRNIT-01, planting: the runner's sealing and mark log keys come from
// GenerateDataKey with the enclave as recipient. A principal that may call
// Encrypt under another encryption context could make a blob of a key it
// knows that the runner decrypts as its sealing key. A locked policy lets
// Encrypt only to the enclave, or only under {purpose: record-creds}.
func TestPolicyLockEncrypt(t *testing.T) {
	withStmt := func(stmt string) string {
		return strings.Replace(lockedPolicy, `{"Sid": "NoOneElse"`, stmt+`,
    {"Sid": "NoOneElse"`, 1)
	}
	const admin = `"Principal": {"AWS": "arn:aws:iam::111122223333:role/admin"}, "Resource": "*"`
	for _, c := range []struct {
		name, policy string
		want         backend.KeyLock
		why          string
	}{
		{"record-creds only", withStmt(`{"Sid": "Rec", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt",
     "Condition": {"StringEquals": {"kms:EncryptionContext:purpose": "record-creds"}}}`), backend.KeyLockLocked, ""},
		{"unconditional", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt"}`), backend.KeyLockNotLocked, "Enc allows kms:Encrypt"},
		{"wildcard", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Enc*"}`), backend.KeyLockNotLocked, "Enc allows kms:Encrypt"},
		{"sealing purpose", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt",
     "Condition": {"StringEquals": {"kms:EncryptionContext:purpose": "sealing"}}}`), backend.KeyLockNotLocked, "Enc allows kms:Encrypt"},
		{"two purposes", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt",
     "Condition": {"StringEquals": {"kms:EncryptionContext:purpose": ["record-creds", "sealing"]}}}`), backend.KeyLockNotLocked, "Enc allows kms:Encrypt"},
		{"IfExists", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt",
     "Condition": {"StringEqualsIfExists": {"kms:EncryptionContext:purpose": "record-creds"}}}`), backend.KeyLockNotLocked, "Enc allows kms:Encrypt"},
		{"enclave", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt",
     "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": "00"}}}`), backend.KeyLockLocked, ""},
	} {
		got, why := policyLock(c.policy, "AWS_KMS", false)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, got, why, c.want, c.why)
		}
	}
}
