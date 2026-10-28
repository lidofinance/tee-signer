module github.com/lidofinance/tee-signer/signer-protocol

go 1.26.0

toolchain go1.27.3

require (
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/mdlayher/vsock v1.3.0
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

require (
	github.com/lidofinance/tee-signer/devkit v0.0.0
	github.com/lidofinance/tee-signer/governance v0.0.0
)

replace (
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
)
