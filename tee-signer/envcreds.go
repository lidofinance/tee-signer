package main

import (
	"context"
	"errors"
	"os"

	"github.com/lidofinance/tee-signer/platform"
)

// envCredentials reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
// AWS_SESSION_TOKEN: the S3 credentials of the mark log and the state copy
// on the dev platform (a local S3 or a fake). Other platforms bring their
// own (platform.Platform RecordCredentials).
func envCredentials() func(context.Context) (platform.Credentials, error) {
	return func(context.Context) (platform.Credentials, error) {
		c := platform.Credentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN")}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return c, errors.New("dev S3 credentials: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")
		}
		return c, nil
	}
}
