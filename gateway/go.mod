module github.com/lidofinance/tee-signer/gateway

go 1.26.0

require (
	github.com/attestantio/go-eth2-client v0.30.3
	github.com/herumi/bls-eth-go-binary v1.36.1
	github.com/supranational/blst v0.3.17
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/lidofinance/tee-signer/attestation-verify v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
	github.com/lidofinance/tee-signer/web3signer-api v0.0.0
)

require (
	github.com/OffchainLabs/go-bitfield v0.0.0-20251031151322-f427d04d8506 // indirect
	github.com/fatih/color v1.10.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.6 // indirect
	github.com/goccy/go-yaml v1.9.2 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/lidofinance/tee-signer/governance v0.0.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/mdlayher/vsock v1.3.0 // indirect
	github.com/pk910/dynamic-ssz v1.4.0 // indirect
	github.com/pk910/hashtree-bindings v0.2.6 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace (
	github.com/lidofinance/tee-signer/attestation-verify => ../attestation-verify
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
	github.com/lidofinance/tee-signer/platform => ../platform
	github.com/lidofinance/tee-signer/platform-aws => ../platform-aws
	github.com/lidofinance/tee-signer/platform-azure => ../platform-azure
	github.com/lidofinance/tee-signer/platform-gcp => ../platform-gcp
	github.com/lidofinance/tee-signer/signer-admin => ../signer-admin
	github.com/lidofinance/tee-signer/signer-core => ../signer-core
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
	github.com/lidofinance/tee-signer/slashing-log => ../slashing-log
	github.com/lidofinance/tee-signer/tee-signer => ../tee-signer
	github.com/lidofinance/tee-signer/trusted-time => ../trusted-time
	github.com/lidofinance/tee-signer/web3signer-api => ../web3signer-api
)
