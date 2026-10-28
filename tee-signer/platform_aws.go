//go:build platform_aws

package main

import (
	"github.com/lidofinance/tee-signer/platform-aws/hostagent"
	"github.com/lidofinance/tee-signer/platform-aws/nitro"
	_ "github.com/lidofinance/tee-signer/platform-aws/s3log" // the S3 mark log
	"github.com/lidofinance/tee-signer/platform/setup"
)

// AWS Nitro Enclaves. The command line calls the platform nitro. This tag
// also brings the AWS SDK (KMS), the NSM and CBOR code, vsock and the
// DynamoDB record store. The setup comes from the host agent at the fixed
// vsock address of the image, before any KMS call.
func init() {
	register("nitro", nitro.New)
	registerSetup("nitro", func() setup.Channel { return &hostagent.SetupChannel{Addr: setup.NitroAgent} })
}
