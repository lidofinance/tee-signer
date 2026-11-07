package nitro

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// keyPolicyKMS answers DescribeKey, GetKeyPolicy and ListGrants for one
// key, as KMS does in the JSON 1.1 protocol.
type keyPolicyKMS struct {
	arn, origin, policy string
	multiRegion         bool
	denyPolicy          bool
	grants              []map[string]any
	pageSize            int // grants per ListGrants page; 0: all on one
	denyGrants          bool
	grantCalls          int
	grantKeyIDs         []string // the KeyId of each ListGrants call
	policyKeyIDs        []string // the KeyId of each GetKeyPolicy call
	dropMarker          bool     // a truncated page without NextMarker
	created             float64  // CreationDate, epoch seconds; 0: left out
	describeFail        bool     // DescribeKey answers a 500
	noARN               bool     // DescribeKey answers without Arn
}

// isAlias reports whether a KeyId names an alias: GetKeyPolicy and
// ListGrants take a key ID or key ARN only.
func isAlias(id string) bool {
	return strings.HasPrefix(id, "alias/") || strings.Contains(id, ":alias/")
}

// refuseAlias answers as KMS does to an alias where it takes none.
func refuseAlias(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"__type": "NotFoundException", "message": "alias not accepted"})
}

func (f *keyPolicyKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct{ KeyId, PolicyName, Marker string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.DescribeKey":
		if f.describeFail {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"__type": "KMSInternalException", "message": "internal"})
			return
		}
		m := map[string]any{"Arn": f.arn, "KeyId": in.KeyId,
			"Origin": f.origin, "KeyManager": "CUSTOMER", "MultiRegion": f.multiRegion, "KeyState": "Enabled"}
		if f.noARN {
			delete(m, "Arn")
		}
		if f.created != 0 {
			m["CreationDate"] = f.created
		}
		json.NewEncoder(w).Encode(map[string]any{"KeyMetadata": m})
	case "TrentService.GetKeyPolicy":
		f.policyKeyIDs = append(f.policyKeyIDs, in.KeyId)
		if isAlias(in.KeyId) {
			refuseAlias(w)
			return
		}
		if f.denyPolicy || in.PolicyName != "default" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": "AccessDeniedException", "message": "not allowed"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"Policy": f.policy, "PolicyName": "default"})
	case "TrentService.ListGrants":
		f.grantCalls++
		f.grantKeyIDs = append(f.grantKeyIDs, in.KeyId)
		if isAlias(in.KeyId) {
			refuseAlias(w)
			return
		}
		if f.denyGrants {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": "AccessDeniedException", "message": "not allowed"})
			return
		}
		from, _ := strconv.Atoi(in.Marker)
		to := len(f.grants)
		if f.pageSize > 0 {
			to = min(from+f.pageSize, to)
		}
		out := map[string]any{"Grants": f.grants[from:to], "Truncated": to < len(f.grants)}
		if to < len(f.grants) && !f.dropMarker {
			out["NextMarker"] = strconv.Itoa(to)
		}
		json.NewEncoder(w).Encode(out)
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"__type": "UnknownOperationException"})
	}
}

// key_release_hash is over the key's metadata and its policy in canonical
// form. The same policy with members in another order or other whitespace
// gives the same hash (KMS answers it so). Another policy, origin or
// replica setting gives another hash. A read the key policy refuses, or a
// policy that does not parse, is an error, not a hash.
func TestKeyRuleHash(t *testing.T) {
	f := &keyPolicyKMS{arn: "arn:aws:kms:eu-west-1:111122223333:key/k1", origin: "AWS_KMS",
		policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Condition":{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":"a","kms:RecipientAttestation:PCR1":"b"}}}]}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	keys := Keys{Client: kms.New(kms.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), Credentials: staticCreds,
		HTTPClient: srv.Client(), RetryMaxAttempts: 1}), KeyID: f.arn}
	ctx := context.Background()
	r, _, err := keys.KeyRule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	canon := `{"Statement":[{"Condition":{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":"a","kms:RecipientAttestation:PCR1":"b"}},"Effect":"Allow"}],"Version":"2012-10-17"}`
	want := backend.KeyReleaseHash(backend.KeyReleaseNitro, []byte(f.arn), []byte("AWS_KMS"), []byte("CUSTOMER"), []byte{0}, []byte(canon))
	if h := r.Hash; h != want {
		t.Fatalf("key_release_hash %x, want %x", h, want)
	}
	saved := f.policy
	f.policy = `{ "Statement": [ { "Condition": { "StringEqualsIgnoreCase": {
		"kms:RecipientAttestation:PCR1": "b",
		"kms:RecipientAttestation:PCR0": "a" } },
	  "Effect": "Allow" } ],
"Version": "2012-10-17" }`
	if got, _, err := keys.KeyRule(ctx); err != nil || got.Hash != want {
		t.Errorf("reordered policy: %x %v, want %x", got.Hash, err, want)
	}
	f.policy = `{"Version":"2012-10-17",`
	if _, _, err := keys.KeyRule(ctx); err == nil || !strings.Contains(err.Error(), "GetKeyPolicy answer") {
		t.Errorf("policy that does not parse: %v, want an error", err)
	}
	f.policy = saved
	for name, change := range map[string]func(){
		"another policy":   func() { f.policy = `{"Version":"2012-10-17","Statement":[]}` },
		"another PCR0":     func() { f.policy = strings.Replace(f.policy, `PCR0":"a"`, `PCR0":"c"`, 1) },
		"imported key":     func() { f.origin = "EXTERNAL" },
		"multi-region key": func() { f.multiRegion = true },
	} {
		saved := *f
		change()
		if got, _, err := keys.KeyRule(ctx); err != nil || got.Hash == r.Hash {
			t.Errorf("%s: %x %v, want another hash", name, got.Hash, err)
		}
		*f = saved
	}
	f.denyPolicy = true
	if _, _, err := keys.KeyRule(ctx); err == nil || !strings.Contains(err.Error(), "GetKeyPolicy") {
		t.Fatalf("refused read: %v", err)
	}
}
