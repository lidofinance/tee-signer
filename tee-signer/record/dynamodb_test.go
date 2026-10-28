//go:build platform_aws

package record

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// fakeDynamo implements GetItem and PutItem of the DynamoDB JSON API the
// way the AWS API reference describes them, for one table.
type fakeDynamo struct {
	mu    sync.Mutex
	items map[string]map[string]ddbAttr
	t     *testing.T
	calls int
}

func (f *fakeDynamo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	fail := func(code int, typ, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"__type": "com.amazonaws.dynamodb.v20120810#" + typ, "message": msg})
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !strings.Contains(auth, "/eu-west-1/dynamodb/aws4_request") ||
		r.Header.Get("X-Amz-Date") == "" || r.Header.Get("Content-Type") != "application/x-amz-json-1.0" {
		fail(400, "MissingAuthenticationTokenException", "bad signature headers: "+auth)
		return
	}
	var in struct {
		TableName                 string
		Key, Item                 map[string]ddbAttr
		ConsistentRead            bool
		ConditionExpression       string
		ExpressionAttributeNames  map[string]string
		ExpressionAttributeValues map[string]ddbAttr
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.TableName != "signer-records" {
		fail(400, "ValidationException", "bad body")
		return
	}
	switch r.Header.Get("X-Amz-Target") {
	case "DynamoDB_20120810.GetItem":
		if !in.ConsistentRead {
			fail(400, "ValidationException", "test wants strongly consistent reads")
			return
		}
		item := f.items[*in.Key["node"].S]
		json.NewEncoder(w).Encode(map[string]any{"Item": item})
	case "DynamoDB_20120810.PutItem":
		key := *in.Item["node"].S
		cur, exists := f.items[key]
		ok := false
		switch in.ConditionExpression {
		case "attribute_not_exists(#k)":
			ok = in.ExpressionAttributeNames["#k"] == "node" && !exists
		case "#v = :prev":
			ok = in.ExpressionAttributeNames["#v"] == "version" && exists &&
				*cur["version"].N == *in.ExpressionAttributeValues[":prev"].N
		default:
			fail(400, "ValidationException", "unexpected condition "+in.ConditionExpression)
			return
		}
		if !ok {
			fail(400, "ConditionalCheckFailedException", "The conditional request failed")
			return
		}
		if _, err := strconv.ParseUint(*in.Item["version"].N, 10, 64); err != nil {
			fail(400, "ValidationException", "version")
			return
		}
		f.items[key] = in.Item
		w.Write([]byte("{}"))
	default:
		fail(400, "UnknownOperationException", r.Header.Get("X-Amz-Target"))
	}
}

func TestDynamoStoreAgainstFake(t *testing.T) {
	fake := &fakeDynamo{items: map[string]map[string]ddbAttr{}, t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	creds := func(context.Context) (platform.Credentials, error) {
		return platform.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "test-secret"}, nil
	}
	s, err := Open("dynamodb:table=signer-records,region=eu-west-1,endpoint="+srv.URL, Env{Creds: creds})
	if err != nil {
		t.Fatal(err)
	}
	storeContract(t, s)
	t.Logf("fake DynamoDB served %d signed GetItem/PutItem calls", fake.calls)

	// Without credentials Open refuses, and a store made by hand sends nothing.
	if _, err := Open("dynamodb:table=signer-records,region=eu-west-1,endpoint="+srv.URL, Env{}); err == nil {
		t.Fatal("Open gave a dynamodb store without credentials")
	}
	bad := &DynamoStore{Table: "signer-records", Region: "eu-west-1", Endpoint: srv.URL}
	if err := bad.Put(ctx, "x", 0, 1, nil); err == nil {
		t.Fatal("unsigned request accepted")
	}
}

// Malformed dynamodb: specs are refused.
func TestOpenDynamoSpecs(t *testing.T) {
	creds := func(context.Context) (platform.Credentials, error) { return platform.Credentials{}, nil }
	for _, s := range []string{"dynamodb:table=x", "dynamodb:region=y", "dynamodb:table=x,region=y,colour=red", "dynamodb:bogus"} {
		if _, err := Open(s, Env{Creds: creds}); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}
