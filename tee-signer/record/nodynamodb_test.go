//go:build !platform_aws

package record

import (
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// Without the AWS build there is no DynamoDB store, and Open says so.
func TestNoDynamoStoreOutsideTheAWSBuild(t *testing.T) {
	creds := func(context.Context) (platform.Credentials, error) { return platform.Credentials{}, nil }
	_, err := Open("dynamodb:table=signer-records,region=eu-west-1", Env{Creds: creds})
	if err == nil || !strings.Contains(err.Error(), "not built into this binary") {
		t.Fatalf("dynamodb in a build without it: %v", err)
	}
}
