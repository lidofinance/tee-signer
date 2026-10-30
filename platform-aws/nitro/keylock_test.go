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
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Literal PCR values, 96 hex digits as KMS compares them.
const (
	pcrA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pcrB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pcrC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	pcrD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// enclaveCond is a condition that binds a statement to one image: literal
// PCR0, PCR1 and PCR2.
const enclaveCond = `{"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": "` + pcrA +
	`", "kms:RecipientAttestation:PCR1": "` + pcrB + `", "kms:RecipientAttestation:PCR2": "` + pcrC + `"}}`

// lockedPolicy is a key policy locked as research/admin-proof-key-release.md
// section 2.1 describes: the enclave's data keys and reads, nothing that
// changes the policy, grants, imports or replicates.
const lockedPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "EnclaveOnlyDataKeys", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::111122223333:role/parent"},
     "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
     "Condition": ` + enclaveCond + `},
    {"Sid": "EnclaveReadsItsKeyPolicy", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::111122223333:role/parent"},
     "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"], "Resource": "*"},
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
     "Condition": {"StringEqualsIfExists": {"kms:RecipientAttestation:PCR0": "` + pcrA + `", "kms:RecipientAttestation:PCR1": "` + pcrB + `",
     "kms:RecipientAttestation:PCR2": "` + pcrC + `"}}}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"StringLike does not bind", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringLike": {"kms:RecipientAttestation:PCR0": "*"}}}`), backend.KeyLockNotLocked, `statement A: condition StringLike on kms:RecipientAttestation:PCR0 has the value "*"`},
		{"empty value does not bind", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": {"StringEquals": {"kms:RecipientAttestation:ImageSha384": ""}}}`), backend.KeyLockNotLocked, "not 96 hex digits"},
		{"second enclave statement", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "Action": "kms:Decrypt",
     "Condition": ` + enclaveCond + `}`), backend.KeyLockLocked, ""},
		{"NotAction", withStmt(`{"Sid": "A", "Effect": "Allow", ` + admin + `, "NotAction": ["kms:PutKeyPolicy", "kms:CreateGrant", "kms:ImportKeyMaterial", "kms:ReplicateKey"]}`), backend.KeyLockNotLocked, "A allows kms:Decrypt"},
		{"one statement, not a list", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt"}}`, backend.KeyLockNotLocked, "number 1 allows kms:Decrypt"},
	} {
		got, why := policyLock(c.policy, "AWS_KMS", false)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, got, why, c.want, c.why)
		}
	}
}

// The repository's template with PutKeyPolicy taken out and its PCRs
// filled in is locked: its only Decrypt and GenerateDataKey statement is
// bound to the enclave's PCRs.
// With an extra unconditional admin Decrypt it is not.
func TestPolicyTemplateWithoutPutKeyPolicyLocked(t *testing.T) {
	b := renderedTemplate(t)
	locked := strings.Replace(b, `"kms:List*", "kms:PutKeyPolicy",`, `"kms:List*",`, 1)
	if locked == b {
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

// renderedTemplate is kms-key-policy.json.tmpl with its PCRs filled in, as
// scripts/kms-policy.sh render writes it. The other variables stay: they
// are in principals, which the lock check does not read.
func renderedTemplate(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "deploy", "kms-key-policy.json.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReplacer("${PCR0}", pcrA, "${PCR1}", pcrB, "${PCR2}", pcrC, "${PCR3}", pcrD).Replace(string(b))
}

// NREL-01: only literal PCR0, PCR1 and PCR2 values name one image. A
// policy variable resolves per request from IAM state outside the key
// policy; PCR3 alone admits any image the parent role starts, PCR8 alone
// any image the certificate signs; an unknown key is refused outright.
func TestPolicyLockImageBinding(t *testing.T) {
	stmt := func(cond string) string {
		return strings.Replace(lockedPolicy, `"Condition": `+enclaveCond, `"Condition": `+cond, 1)
	}
	pcrs := func(op string, kv ...string) string {
		var b strings.Builder
		for i := 0; i < len(kv); i += 2 {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(`"kms:RecipientAttestation:` + kv[i] + `": ` + kv[i+1])
		}
		return `{"` + op + `": {` + b.String() + `}}`
	}
	q := func(s string) string { return `"` + s + `"` }
	const tagVar = `"${aws:PrincipalTag/pcr0}"`
	for _, c := range []struct {
		name, cond string
		want       backend.KeyLock
		why        string
	}{
		{"PCR0 to PCR2, ignore case", pcrs("StringEqualsIgnoreCase", "PCR0", q(pcrA), "PCR1", q(pcrB), "PCR2", q(pcrC)), backend.KeyLockLocked, ""},
		{"PCR0 to PCR2, exact", pcrs("StringEquals", "PCR0", q(pcrA), "PCR1", q(pcrB), "PCR2", q(pcrC)), backend.KeyLockLocked, ""},
		{"PCR0 to PCR3", pcrs("StringEqualsIgnoreCase", "PCR0", q(pcrA), "PCR1", q(pcrB), "PCR2", q(pcrC), "PCR3", q(pcrD)), backend.KeyLockLocked, ""},
		{"two images", pcrs("StringEquals", "PCR0", `["`+pcrA+`","`+pcrD+`"]`, "PCR1", q(pcrB), "PCR2", q(pcrC)), backend.KeyLockLocked, ""},
		{"key in lower case", pcrs("StringEquals", "pcr0", q(pcrA), "pcr1", q(pcrB), "pcr2", q(pcrC)), backend.KeyLockLocked, ""},
		{"principal tag in PCR0", pcrs("StringEqualsIgnoreCase", "PCR0", tagVar, "PCR1", q(pcrB), "PCR2", q(pcrC)), backend.KeyLockNotLocked,
			`condition StringEqualsIgnoreCase on kms:RecipientAttestation:PCR0 has the value "${aws:PrincipalTag/pcr0}", not 96 hex digits`},
		{"principal tag alone", pcrs("StringEquals", "PCR0", tagVar), backend.KeyLockNotLocked, "not 96 hex digits"},
		{"principal tag in PCR3", pcrs("StringEquals", "PCR0", q(pcrA), "PCR1", q(pcrB), "PCR2", q(pcrC), "PCR3", `"${aws:PrincipalTag/r}"`), backend.KeyLockNotLocked, "not 96 hex digits"},
		{"PCR3 only", pcrs("StringEquals", "PCR3", q(pcrD)), backend.KeyLockNotLocked, "EnclaveOnlyDataKeys allows kms:Decrypt without literal"},
		{"PCR8 only", pcrs("StringEquals", "PCR8", q(pcrD)), backend.KeyLockNotLocked, "EnclaveOnlyDataKeys allows kms:Decrypt without literal"},
		{"ImageSha384 only", pcrs("StringEquals", "ImageSha384", q(pcrA)), backend.KeyLockNotLocked, "EnclaveOnlyDataKeys allows kms:Decrypt without literal"},
		{"PCR0 only", pcrs("StringEquals", "PCR0", q(pcrA)), backend.KeyLockNotLocked, "EnclaveOnlyDataKeys allows kms:Decrypt without literal"},
		{"PCR0 and PCR1", pcrs("StringEquals", "PCR0", q(pcrA), "PCR1", q(pcrB)), backend.KeyLockNotLocked, "without literal"},
		{"made-up key alone", pcrs("StringEquals", "Nonsense", q(pcrA)), backend.KeyLockNotLocked,
			"condition key kms:RecipientAttestation:Nonsense is not a Nitro PCR or ImageSha384"},
		{"made-up key next to PCR0 to PCR2", pcrs("StringEquals", "PCR0", q(pcrA), "PCR1", q(pcrB), "PCR2", q(pcrC), "Nonsense", q(pcrD)), backend.KeyLockNotLocked,
			"is not a Nitro PCR"},
		{"PCR32", pcrs("StringEquals", "PCR0", q(pcrA), "PCR1", q(pcrB), "PCR2", q(pcrC), "PCR32", q(pcrD)), backend.KeyLockNotLocked, "is not a Nitro PCR"},
		{"short value", pcrs("StringEquals", "PCR0", q("00"), "PCR1", q(pcrB), "PCR2", q(pcrC)), backend.KeyLockNotLocked, "not 96 hex digits"},
		{"PCRs split over two operators", `{"StringEquals": {"kms:RecipientAttestation:PCR0": "` + pcrA + `"},
		  "StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR1": "` + pcrB + `", "kms:RecipientAttestation:PCR2": "` + pcrC + `"}}`, backend.KeyLockLocked, ""},
		{"PCR2 only under IfExists", `{"StringEquals": {"kms:RecipientAttestation:PCR0": "` + pcrA + `", "kms:RecipientAttestation:PCR1": "` + pcrB + `"},
		  "StringEqualsIfExists": {"kms:RecipientAttestation:PCR2": "` + pcrC + `"}}`, backend.KeyLockNotLocked, "without literal"},
	} {
		got, why := policyLock(stmt(c.cond), "AWS_KMS", false)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, got, why, c.want, c.why)
		}
	}
}

// The unrendered template holds ${PCR0} and the like: not a locked policy.
func TestPolicyTemplateUnrenderedNotLocked(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "deploy", "kms-key-policy.json.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	locked := strings.Replace(string(b), `"kms:List*", "kms:PutKeyPolicy",`, `"kms:List*",`, 1)
	if got, why := policyLock(locked, "AWS_KMS", false); got != backend.KeyLockNotLocked || !strings.Contains(why, `has the value "${PCR`) {
		t.Fatalf("unrendered template: %s %q", got, why)
	}
}

func TestKnownRecipientKey(t *testing.T) {
	for name, want := range map[string]bool{"pcr0": true, "pcr2": true, "pcr8": true, "pcr31": true, "imagesha384": true,
		"pcr32": false, "pcr01": false, "pcr": false, "pcr-1": false, "pcr100": false, "nonsense": false, "": false} {
		if got := knownRecipientKey(name); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
}

// AWS-KMS-01: a grant made before the policy was locked stays in force,
// and no grant can require the enclave as recipient. KeyRule reads every
// page of ListGrants; a locked policy with any grant is not locked, and a
// grant list it cannot read leaves the lock unread.
func TestKeyRuleGrants(t *testing.T) {
	f := &keyPolicyKMS{arn: "arn:aws:kms:eu-west-1:111122223333:key/k1", origin: "AWS_KMS", policy: lockedPolicy}
	srv := httptest.NewServer(f)
	defer srv.Close()
	keys := Keys{Client: kms.New(kms.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), Credentials: staticCreds,
		HTTPClient: srv.Client(), RetryMaxAttempts: 1}), KeyID: "k1"}
	ctx := context.Background()
	clean, err := keys.KeyRule(ctx)
	if err != nil || clean.Lock != backend.KeyLockLocked {
		t.Fatalf("no grants: %+v %v", clean, err)
	}
	if f.grantCalls == 0 {
		t.Fatal("KeyRule did not call ListGrants")
	}

	// A setup may name the key by alias; ListGrants gets the key's ARN.
	f.grantKeyIDs = nil
	byAlias := keys
	byAlias.KeyID = "alias/signer"
	if r, err := byAlias.KeyRule(ctx); err != nil || r.Lock != backend.KeyLockLocked || len(f.grantKeyIDs) != 1 || f.grantKeyIDs[0] != f.arn {
		t.Fatalf("key by alias: %+v %v, ListGrants on %q", r, err, f.grantKeyIDs)
	}

	adminDecrypt := map[string]any{"GrantId": "g-admin", "GranteePrincipal": "arn:aws:iam::111122223333:role/admin",
		"Operations": []string{"Decrypt", "GenerateDataKey"}}
	f.grants = []map[string]any{adminDecrypt}
	r, err := keys.KeyRule(ctx)
	if err != nil || r.Lock != backend.KeyLockNotLocked || !strings.Contains(r.Why, "1 grant(s), for example g-admin to arn:aws:iam::111122223333:role/admin for Decrypt,GenerateDataKey") {
		t.Fatalf("admin Decrypt grant: %+v %v", r, err)
	}

	// A grant on the third page, one grant per page.
	f.grants = []map[string]any{
		{"GrantId": "g-1", "GranteePrincipal": "arn:aws:iam::111122223333:role/parent", "Operations": []string{"DescribeKey"}},
		{"GrantId": "g-2", "GranteePrincipal": "arn:aws:iam::111122223333:role/parent", "Operations": []string{"DescribeKey"}},
		{"GrantId": "g-3", "GranteePrincipal": "arn:aws:iam::111122223333:role/admin", "Operations": []string{"Encrypt"}},
	}
	f.pageSize = 1
	f.grantCalls = 0
	if r, err = keys.KeyRule(ctx); err != nil || r.Lock != backend.KeyLockNotLocked || !strings.Contains(r.Why, "3 grant(s)") || f.grantCalls != 3 {
		t.Fatalf("paged grants: %+v %v, %d ListGrants calls", r, err, f.grantCalls)
	}

	f.grants, f.denyGrants = nil, true
	r, err = keys.KeyRule(ctx)
	if err != nil || r.Lock != backend.KeyLockUnread || !strings.Contains(r.Why, "ListGrants") || r.Hash != clean.Hash {
		t.Fatalf("ListGrants refused: %+v %v", r, err)
	}

	// A policy that is not locked says why; the grants are not read.
	f.grantCalls = 0
	f.policy = strings.Replace(lockedPolicy, `"kms:ScheduleKeyDeletion"`, `"kms:ScheduleKeyDeletion", "kms:PutKeyPolicy"`, 1)
	if r, err = keys.KeyRule(ctx); err != nil || r.Lock != backend.KeyLockNotLocked || !strings.Contains(r.Why, "PutKeyPolicy") || f.grantCalls != 0 {
		t.Fatalf("open policy: %+v %v, %d ListGrants calls", r, err, f.grantCalls)
	}
}

func TestGrantLock(t *testing.T) {
	if got, why := grantLock(nil); got != backend.KeyLockLocked || why != "" {
		t.Fatalf("no grants: %s %q", got, why)
	}
	g := []types.GrantListEntry{{GrantId: aws.String("g1"), GranteePrincipal: aws.String("p"),
		Operations: []types.GrantOperation{types.GrantOperationDecrypt}}}
	if got, why := grantLock(g); got != backend.KeyLockNotLocked || !strings.Contains(why, "g1 to p for Decrypt") {
		t.Fatalf("one grant: %s %q", got, why)
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
     "Condition": ` + enclaveCond + `}`), backend.KeyLockLocked, ""},
		{"PCR3 only", withStmt(`{"Sid": "Enc", "Effect": "Allow", ` + admin + `, "Action": "kms:Encrypt",
     "Condition": {"StringEquals": {"kms:RecipientAttestation:PCR3": "` + pcrD + `"}}}`), backend.KeyLockNotLocked, "Enc allows kms:Encrypt"},
	} {
		got, why := policyLock(c.policy, "AWS_KMS", false)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, got, why, c.want, c.why)
		}
	}
}
