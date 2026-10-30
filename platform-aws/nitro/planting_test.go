package nitro

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

// policyStatement is one statement of cloud/aws/kms-key-policy.json.tmpl.
type policyStatement struct {
	Sid       string
	Effect    string
	Principal struct{ AWS string }
	Action    []string
	Condition map[string]map[string]json.RawMessage
}

func loadKeyPolicy(t *testing.T) []policyStatement {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "deploy", "kms-key-policy.json.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ Statement []policyStatement }
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p.Statement
}

// grants reports whether an action pattern of a statement covers action.
func grants(patterns []string, action string) bool {
	for _, p := range patterns {
		if p == "*" || p == action || strings.HasSuffix(p, "*") && strings.HasPrefix(action, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

// conditionValues reads a condition value: a string or a list of strings.
func conditionValues(raw json.RawMessage) ([]string, error) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	return many, json.Unmarshal(raw, &many)
}

// allows evaluates a statement's conditions for a request with encryption
// context ctx, for the operators the key policy uses. Another operator or
// key fails the test, so a change of the policy cannot pass unread.
func allows(t *testing.T, st policyStatement, ctx map[string]string) bool {
	t.Helper()
	for op, conds := range st.Condition {
		for key, raw := range conds {
			vals, err := conditionValues(raw)
			if err != nil {
				t.Fatalf("%s: condition %s %s: %v", st.Sid, op, key, err)
			}
			name, isCtx := strings.CutPrefix(key, "kms:EncryptionContext:")
			switch {
			case op == "StringEquals" && isCtx:
				if v, ok := ctx[name]; !ok || !slices.Contains(vals, v) {
					return false
				}
			case op == "ForAllValues:StringEquals" && key == "kms:EncryptionContextKeys":
				for k := range ctx {
					if !slices.Contains(vals, k) {
						return false
					}
				}
			case op == "Null" && isCtx && len(vals) == 1:
				if _, ok := ctx[name]; ok == (vals[0] == "true") {
					return false
				}
			default:
				t.Fatalf("%s: condition %s on %s: this test does not evaluate it", st.Sid, op, key)
			}
		}
	}
	return true
}

// adminEncrypt is the key policy's rule for the key admin's kms:Encrypt:
// the one statement that grants it.
func adminEncrypt(t *testing.T) func(map[string]string) bool {
	t.Helper()
	var enc []policyStatement
	for _, st := range loadKeyPolicy(t) {
		if st.Effect == "Allow" && grants(st.Action, "kms:Encrypt") {
			enc = append(enc, st)
		}
	}
	if len(enc) != 1 || !strings.Contains(enc[0].Principal.AWS, "${ADMIN_ROLE}") {
		t.Fatalf("%d statements grant kms:Encrypt, want one, to the key admin", len(enc))
	}
	return func(ctx map[string]string) bool { return allows(t, enc[0], ctx) }
}

// The key policy lets the key admin encrypt with exactly {purpose:
// record-creds}: no context of the runner's own keys, and no context with
// one key more. No statement grants a way around it (ReEncrypt, grants,
// data keys without a recipient). main.tf has the same conditions.
func TestKeyPolicyAdminEncrypt(t *testing.T) {
	may := adminEncrypt(t)
	setup := strings.Repeat("ab", 32)
	for _, c := range []struct {
		ctx  map[string]string
		want bool
	}{
		{recordCredsContext(), true},
		{nil, false},
		{map[string]string{ctxPurpose: purposeSealing, ctxSetup: setup}, false},
		{map[string]string{ctxPurpose: purposeRecordCreds, ctxSetup: setup}, false},
		{map[string]string{keyContext: "00", ctxSetup: setup}, false},
		{map[string]string{ctxPurpose: "record-creds-2"}, false},
		{Keys{Setup: [32]byte{1}}.sealingContext(), false},
		{Keys{Setup: [32]byte{1}}.keyContext([]byte("aad")), false},
	} {
		if got := may(c.ctx); got != c.want {
			t.Errorf("admin Encrypt with %v: allowed %v, want %v", c.ctx, got, c.want)
		}
	}
	for _, st := range loadKeyPolicy(t) {
		for _, a := range []string{"kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant", "kms:GenerateDataKeyWithoutPlaintext",
			"kms:GenerateDataKeyPair", "kms:ImportKeyMaterial"} {
			if st.Effect == "Allow" && grants(st.Action, a) {
				t.Errorf("%s grants %s", st.Sid, a)
			}
		}
		if grants(st.Action, "kms:GenerateDataKey") || grants(st.Action, "kms:Decrypt") {
			if _, ok := st.Condition["StringEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"]; !ok {
				t.Errorf("%s grants GenerateDataKey or Decrypt without the enclave's attestation as recipient", st.Sid)
			}
		}
	}
	tf, err := os.ReadFile(filepath.Join("..", "deploy", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kms:EncryptionContext:purpose" = "record-creds"`, `"ForAllValues:StringEquals" = { "kms:EncryptionContextKeys" = ["purpose"] }`} {
		if !strings.Contains(string(tf), want) {
			t.Errorf("main.tf lacks %s", want)
		}
	}
	if strings.Contains(string(tf), "kms:EncryptionContext:signer-key") {
		t.Error("main.tf still has the old condition on signer-key")
	}
}

// kmsFixture is the fake KMS with the key policy's admin rule, the
// enclave's client and recipient, and the admin's client.
type kmsFixture struct {
	f         *fakeKMS
	enclave   *kms.Client
	admin     *kms.Client
	recipient func() (*rsa.PrivateKey, *types.RecipientInfo, error)
}

func newKMSFixture(t *testing.T) *kmsFixture {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "enclave"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SubjectKeyId: []byte{1, 2, 3, 4}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	f := &fakeKMS{t: t, certPath: certPath, adminMay: adminEncrypt(t)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := func() *kms.Client {
		return kms.New(kms.Options{Region: "eu-central-1", BaseEndpoint: aws.String(srv.URL), Credentials: staticCreds,
			HTTPClient: srv.Client(), RetryMaxAttempts: 1})
	}
	return &kmsFixture{f: f, enclave: client(), admin: client(),
		recipient: func() (*rsa.PrivateKey, *types.RecipientInfo, error) {
			return rsaKey, &types.RecipientInfo{AttestationDocument: []byte("nsm document"),
				KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256}, nil
		}}
}

func (x *kmsFixture) keys(setup [32]byte) Keys {
	return Keys{Client: x.enclave, KeyID: "key-1", Recipient: x.recipient, Setup: setup}
}

// encrypt is the key admin's `aws kms encrypt` with context ctx.
func (x *kmsFixture) encrypt(plain []byte, ctx map[string]string) ([]byte, error) {
	out, err := x.admin.Encrypt(context.Background(), &kms.EncryptInput{KeyId: aws.String("key-1"), Plaintext: plain, EncryptionContext: ctx})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

// A second setup on the same KMS key and the same parent store opens
// nothing of the first: the stored sealing key does not decrypt (the start
// stops), and no key the first wrapped opens through platform.Keys.
func TestAnotherSetupOpensNothing(t *testing.T) {
	x := newKMSFixture(t)
	ctx := context.Background()
	store, _ := filestore.New(t.TempDir())
	one, other := [32]byte{1}, [32]byte{2}
	k1, err := x.keys(one).dataKey(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	// The first setup sealed a share: from now on the blob counts.
	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	again, err := x.keys(one).dataKey(ctx, store)
	if err != nil || !bytes.Equal(again, k1) {
		t.Fatalf("restart with the same setup: %v", err)
	}
	if _, err := x.keys(other).dataKey(ctx, store); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
		t.Fatalf("another setup on the same store: %v", err)
	}
	_, blob, err := x.keys(one).NewKey(ctx, []byte("mark key aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.keys(other).OpenKey(ctx, blob, []byte("mark key aad")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another setup opened a wrapped key: %v", err)
	}
	// A key of platform.Keys does not pass for the sealing key either.
	store.Put(dataKeyBlob, blob)
	if _, err := x.keys(one).dataKey(ctx, store); err == nil {
		t.Fatal("a wrapped key passed for the sealing key")
	}
}

// The planting attack of review A: the key admin makes a ciphertext of a
// key it knows and puts it on the parent before a fresh start. Under the
// key policy the admin can encrypt with {purpose: record-creds} only, and
// such a blob opens neither as the sealing key nor as a key of
// platform.Keys. The record credentials, which the admin is meant to make,
// still open.
func TestPlantedSealingKeyRefused(t *testing.T) {
	x := newKMSFixture(t)
	ctx := context.Background()
	setup := [32]byte{7}
	known := bytes.Repeat([]byte{0x42}, 32)

	for name, c := range map[string]map[string]string{
		"no context (the sealing key before the fix)": nil,
		"the sealing context":                         x.keys(setup).sealingContext(),
		"a key context":                               x.keys(setup).keyContext([]byte("mark key aad")),
	} {
		if _, err := x.encrypt(known, c); err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
			t.Fatalf("admin Encrypt with %s: %v, want AccessDeniedException", name, err)
		}
	}
	planted, err := x.encrypt(known, recordCredsContext())
	if err != nil {
		t.Fatal(err)
	}
	store, _ := filestore.New(t.TempDir())
	store.Put(dataKeyBlob, planted)
	// With a share stored the runner takes the blob as its own: it does not
	// decrypt, and the start stops.
	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	if dek, err := x.keys(setup).dataKey(ctx, store); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
		t.Fatalf("planted sealing key: %x %v", dek, err)
	}
	if _, err := x.keys(setup).OpenKey(ctx, planted, []byte("mark key aad")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("planted mark log key: %v", err)
	}

	creds, _ := json.Marshal(map[string]string{"access_key_id": "AKIDWRITER", "secret_access_key": "writer-secret"})
	blob, err := x.encrypt(creds, recordCredsContext())
	if err != nil {
		t.Fatal(err)
	}
	store.Put("record/writer-credentials.kms", blob)
	got, err := x.keys(setup).recordCredentials(ctx, store, "record/writer-credentials.kms")
	if err != nil || got.AccessKeyID != "AKIDWRITER" || got.SecretAccessKey != "writer-secret" {
		t.Fatalf("record credentials: %+v %v", got, err)
	}
}

// A store whose listing shows no shares, though shares sealed under the
// stored key exist (a partial restore, a late mount), must not lose that
// key: the ignored blob stays under another name, and putting it back
// with the shares opens the old key again.
func TestIgnoredSealingKeyKept(t *testing.T) {
	x := newKMSFixture(t)
	ctx := context.Background()
	setup := [32]byte{7}
	store, _ := filestore.New(t.TempDir())
	k1, err := x.keys(setup).dataKey(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := store.Get(dataKeyBlob)

	// The shares are missing from the store at this start.
	k2, err := x.keys(setup).dataKey(ctx, store)
	if err != nil || bytes.Equal(k2, k1) {
		t.Fatalf("start without shares: %v", err)
	}
	names, err := store.List("sealing/")
	if err != nil {
		t.Fatal(err)
	}
	var kept []byte
	for _, n := range names {
		if strings.HasPrefix(n, dataKeyBlob+".ignored-") {
			kept, _ = store.Get(n)
		}
	}
	if !bytes.Equal(kept, original) {
		t.Fatalf("the original blob is gone: %q", names)
	}

	// The operator puts the old blob back next to the restored shares.
	store.Put(dataKeyBlob, kept)
	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	if k3, err := x.keys(setup).dataKey(ctx, store); err != nil || !bytes.Equal(k3, k1) {
		t.Fatalf("restored blob: %v", err)
	}
}

// AWS-KMS-02: before the key policy is locked, the key admin holds
// PutKeyPolicy and can allow itself Encrypt under the sealing context. It
// plants a blob of a key it knows; the blob still decrypts after the lock.
// On a store without shares the runner ignores the blob and makes a new
// key, which it then keeps across restarts once a share is sealed.
func TestSealingKeyPlantedBeforeLock(t *testing.T) {
	x := newKMSFixture(t)
	x.f.adminMay = func(map[string]string) bool { return true } // the policy before the lock
	ctx := context.Background()
	setup := [32]byte{7}
	known := bytes.Repeat([]byte{0x42}, 32)
	planted, err := x.encrypt(known, x.keys(setup).sealingContext())
	if err != nil {
		t.Fatal(err)
	}
	store, _ := filestore.New(t.TempDir())
	store.Put(dataKeyBlob, planted)
	store.Put("record/writer-credentials.kms", []byte("not a share"))
	store.Put("wm/aa01", []byte("not a share either"))

	dek, err := x.keys(setup).dataKey(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dek, known) {
		t.Fatal("the runner took the planted sealing key")
	}
	stored, err := store.Get(dataKeyBlob)
	if err != nil || bytes.Equal(stored, planted) {
		t.Fatalf("the planted blob is still stored: %v", err)
	}
	// The ignored blob is kept under another name, not destroyed.
	sum := sha256.Sum256(planted)
	if kept, err := store.Get(fmt.Sprintf("%s.ignored-%x", dataKeyBlob, sum[:8])); err != nil || !bytes.Equal(kept, planted) {
		t.Fatalf("the ignored blob was not kept: %v", err)
	}

	// The runner seals a share; the next start opens its own blob.
	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	again, err := x.keys(setup).dataKey(ctx, store)
	if err != nil || !bytes.Equal(again, dek) {
		t.Fatalf("restart with a share stored: %v", err)
	}
}
