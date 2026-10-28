package nitro

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// keyPolicyKMS answers DescribeKey and GetKeyPolicy for one key, as KMS
// does in the JSON 1.1 protocol.
type keyPolicyKMS struct {
	arn, origin, policy string
	multiRegion         bool
	denyPolicy          bool
}

func (f *keyPolicyKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct{ KeyId, PolicyName string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.DescribeKey":
		json.NewEncoder(w).Encode(map[string]any{"KeyMetadata": map[string]any{"Arn": f.arn, "KeyId": in.KeyId,
			"Origin": f.origin, "KeyManager": "CUSTOMER", "MultiRegion": f.multiRegion, "KeyState": "Enabled"}})
	case "TrentService.GetKeyPolicy":
		if f.denyPolicy || in.PolicyName != "default" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": "AccessDeniedException", "message": "not allowed"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"Policy": f.policy, "PolicyName": "default"})
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"__type": "UnknownOperationException"})
	}
}

// key_release_hash is over the key's metadata and policy as KMS answers
// them; another policy, origin or replica setting gives another hash, and
// a read the key policy refuses is an error, not a hash.
func TestKeyRuleHash(t *testing.T) {
	f := &keyPolicyKMS{arn: "arn:aws:kms:eu-west-1:111122223333:key/k1", origin: "AWS_KMS", policy: `{"Version":"2012-10-17"}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	keys := Keys{Client: kms.New(kms.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), Credentials: staticCreds,
		HTTPClient: srv.Client(), RetryMaxAttempts: 1}), KeyID: "k1"}
	ctx := context.Background()
	r, err := keys.KeyRule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := backend.KeyReleaseHash(backend.KeyReleaseNitro, []byte(f.arn), []byte("AWS_KMS"), []byte("CUSTOMER"), []byte{0}, []byte(f.policy))
	if h := r.Hash; h != want {
		t.Fatalf("key_release_hash %x, want %x", h, want)
	}
	for name, change := range map[string]func(){
		"another policy":   func() { f.policy = `{"Version":"2012-10-17","Statement":[]}` },
		"imported key":     func() { f.origin = "EXTERNAL" },
		"multi-region key": func() { f.multiRegion = true },
	} {
		saved := *f
		change()
		if got, err := keys.KeyRule(ctx); err != nil || got.Hash == r.Hash {
			t.Errorf("%s: %x %v, want another hash", name, got.Hash, err)
		}
		*f = saved
	}
	f.denyPolicy = true
	if _, err := keys.KeyRule(ctx); err == nil || !strings.Contains(err.Error(), "GetKeyPolicy") {
		t.Fatalf("refused read: %v", err)
	}
}
