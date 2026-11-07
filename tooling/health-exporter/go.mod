module github.com/lidofinance/tee-signer/tooling/health-exporter

go 1.26.0

require (
	github.com/lidofinance/tee-signer/attestation-verify v0.0.0
	github.com/lidofinance/tee-signer/signer-admin v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
)

require (
	github.com/fxamacker/cbor/v2 v2.9.6 // indirect
	github.com/lidofinance/tee-signer/governance v0.0.0 // indirect
	github.com/lidofinance/tee-signer/platform v0.0.0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/mdlayher/vsock v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace (
	github.com/lidofinance/tee-signer/attestation-verify => ../../attestation-verify
	github.com/lidofinance/tee-signer/governance => ../../governance
	github.com/lidofinance/tee-signer/platform => ../../platform
	github.com/lidofinance/tee-signer/signer-admin => ../../signer-admin
	github.com/lidofinance/tee-signer/signer-protocol => ../../signer-protocol
	github.com/lidofinance/tee-signer/trusted-time => ../../trusted-time
)
