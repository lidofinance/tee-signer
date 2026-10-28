//go:build platform_aws

package record

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/lidofinance/tee-signer/platform"
)

func init() { openDynamo = openDynamoStore }

// openDynamoStore parses the part of a -record value after "dynamodb:".
// Without credentials it refuses, so a runner never signs with the host's.
func openDynamoStore(rest string, env Env) (Store, error) {
	if env.Creds == nil {
		return nil, errors.New("record: dynamodb needs credentials only the TEE holds (nitro: -platform-opt record_creds=...); refusing to use the host's")
	}
	d := &DynamoStore{HTTP: env.HTTP, Creds: env.Creds}
	for _, kv := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return nil, fmt.Errorf("record: dynamodb: want key=value, got %q", kv)
		}
		switch k {
		case "table":
			d.Table = v
		case "region":
			d.Region = v
		case "endpoint":
			d.Endpoint = v
		default:
			return nil, fmt.Errorf("record: dynamodb: unknown option %q", k)
		}
	}
	if d.Table == "" || d.Region == "" {
		return nil, errors.New("record: dynamodb needs table= and region=")
	}
	return d, nil
}

// DynamoStore keeps records in a DynamoDB table with a string partition key
// "node" and the attributes "version" (number) and "value" (binary). Writes
// are PutItem with a ConditionExpression on the version, which DynamoDB
// applies atomically per item; reads are strongly consistent GetItem.
//
// DRAFT: tested against a local fake of the DynamoDB JSON API
// (dynamodb_test.go), not against DynamoDB or DynamoDB Local. Requests use
// the JSON 1.0 protocol (X-Amz-Target DynamoDB_20120810.*) signed with
// SigV4 from aws-sdk-go-v2, so the module needs no DynamoDB SDK package.
// SigV4 uses the local clock; a host that moves it can only make AWS refuse
// the request (the runner then refuses to sign).
type DynamoStore struct {
	Table    string
	Region   string
	Endpoint string // default https://dynamodb.<region>.amazonaws.com
	HTTP     *http.Client
	Creds    func(ctx context.Context) (platform.Credentials, error)
}

func (d *DynamoStore) String() string { return "dynamodb:" + d.Table + "@" + d.Region }

func (d *DynamoStore) endpoint() string {
	if d.Endpoint != "" {
		return strings.TrimSuffix(d.Endpoint, "/")
	}
	return "https://dynamodb." + d.Region + ".amazonaws.com"
}

type ddbAttr struct {
	S *string `json:"S,omitempty"`
	N *string `json:"N,omitempty"`
	B []byte  `json:"B,omitempty"` // encoding/json writes base64, as DynamoDB wants
}

type ddbError struct {
	Type     string `json:"__type"`
	Message  string `json:"message"`
	Message2 string `json:"Message"`
}

func (d *DynamoStore) call(ctx context.Context, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint()+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810."+op)
	if d.Creds == nil {
		return errors.New("dynamodb: no credentials")
	}
	c, err := d.Creds(ctx)
	if err != nil {
		return fmt.Errorf("dynamodb: credentials: %w", err)
	}
	creds := aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken,
		CanExpire: !c.Expires.IsZero(), Expires: c.Expires, Source: "platform"}
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "dynamodb", d.Region, time.Now()); err != nil {
		return err
	}
	hc := d.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("dynamodb %s: %w", op, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e ddbError
		_ = json.Unmarshal(b, &e)
		if strings.HasSuffix(e.Type, "#ConditionalCheckFailedException") {
			return ErrConflict
		}
		msg := e.Message
		if msg == "" {
			msg = e.Message2
		}
		return fmt.Errorf("dynamodb %s: %s: %s %s", op, resp.Status, e.Type, msg)
	}
	return json.Unmarshal(b, out)
}

func (d *DynamoStore) Get(ctx context.Context, key string) (uint64, []byte, error) {
	in := map[string]any{
		"TableName":      d.Table,
		"Key":            map[string]ddbAttr{"node": {S: &key}},
		"ConsistentRead": true,
	}
	var out struct {
		Item map[string]ddbAttr `json:"Item"`
	}
	if err := d.call(ctx, "GetItem", in, &out); err != nil {
		return 0, nil, err
	}
	if len(out.Item) == 0 {
		return 0, nil, ErrNotFound
	}
	v, val := out.Item["version"], out.Item["value"]
	if v.N == nil {
		return 0, nil, errors.New("dynamodb: item without a version")
	}
	ver, err := strconv.ParseUint(*v.N, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("dynamodb: version: %w", err)
	}
	return ver, val.B, nil
}

func (d *DynamoStore) Put(ctx context.Context, key string, prev, next uint64, value []byte) error {
	nextS, prevS := strconv.FormatUint(next, 10), strconv.FormatUint(prev, 10)
	in := map[string]any{
		"TableName": d.Table,
		"Item": map[string]ddbAttr{
			"node":    {S: &key},
			"version": {N: &nextS},
			"value":   {B: value},
		},
	}
	if prev == 0 {
		in["ConditionExpression"] = "attribute_not_exists(#k)"
		in["ExpressionAttributeNames"] = map[string]string{"#k": "node"}
	} else {
		in["ConditionExpression"] = "#v = :prev"
		in["ExpressionAttributeNames"] = map[string]string{"#v": "version"}
		in["ExpressionAttributeValues"] = map[string]ddbAttr{":prev": {N: &prevS}}
	}
	var out map[string]any
	return d.call(ctx, "PutItem", in, &out)
}
