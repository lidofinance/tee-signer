package record

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/lidofinance/tee-signer/platform"
)

// Env is what Open needs from the platform.
type Env struct {
	HTTP *http.Client
	// Creds signs the requests of a store that needs credentials (DynamoDB
	// on AWS). On Nitro they must be credentials only the enclave holds
	// (cloud/aws/README.md), never the parent's role.
	Creds func(ctx context.Context) (platform.Credentials, error)
}

// openDynamo opens a dynamodb: store. dynamodb.go sets it (build tag
// platform_aws): only the AWS build has the DynamoDB store, and with it the
// AWS SDK's request signer.
var openDynamo func(spec string, env Env) (Store, error)

// Open parses a -record value:
//
//	none
//	file:DIR
//	dynamodb:table=NAME,region=REGION[,endpoint=URL]   (AWS build only)
//
// It returns nil for "none" and "".
func Open(spec string, env Env) (Store, error) {
	kind, rest, _ := strings.Cut(spec, ":")
	switch kind {
	case "", "none":
		return nil, nil
	case "file":
		if rest == "" {
			return nil, errors.New("record: file: needs a directory")
		}
		return &FileStore{Dir: rest}, nil
	case "dynamodb":
		if openDynamo == nil {
			return nil, errors.New("record: dynamodb is not built into this binary (only the AWS build has it)")
		}
		return openDynamo(rest, env)
	}
	return nil, fmt.Errorf("record: unknown store %q (want none, file:DIR or dynamodb:table=...,region=...)", spec)
}

// EnvCredentials reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
// AWS_SESSION_TOKEN. For the dev platform (DynamoDB Local or a fake) only.
func EnvCredentials() func(context.Context) (platform.Credentials, error) {
	return func(context.Context) (platform.Credentials, error) {
		c := platform.Credentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN")}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return c, errors.New("record: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")
		}
		return c, nil
	}
}
