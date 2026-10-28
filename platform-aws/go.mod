module github.com/lidofinance/tee-signer/platform-aws

go 1.27.3

require (
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.4
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/hf/nsm v0.0.0-20220930140112-cd181bd646b9
	github.com/lidofinance/tee-signer/attestation-verify v0.0.0
	github.com/lidofinance/tee-signer/governance v0.0.0
	github.com/lidofinance/tee-signer/platform v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
	github.com/lidofinance/tee-signer/slashing-log v0.0.0
	github.com/lidofinance/tee-signer/tee-signer v0.0.0
	github.com/lidofinance/tee-signer/trusted-time v0.0.0
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/lidofinance/tee-signer/devkit v0.0.0 // indirect
	github.com/lidofinance/tee-signer/signer-core v0.0.0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/mdlayher/vsock v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/lidofinance/tee-signer/attestation-verify => ../attestation-verify
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
	github.com/lidofinance/tee-signer/platform => ../platform
	github.com/lidofinance/tee-signer/platform-azure => ../platform-azure
	github.com/lidofinance/tee-signer/platform-gcp => ../platform-gcp
	github.com/lidofinance/tee-signer/signer-admin => ../signer-admin
	github.com/lidofinance/tee-signer/signer-core => ../signer-core
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
	github.com/lidofinance/tee-signer/slashing-log => ../slashing-log
	github.com/lidofinance/tee-signer/tee-signer => ../tee-signer
	github.com/lidofinance/tee-signer/trusted-time => ../trusted-time
)
