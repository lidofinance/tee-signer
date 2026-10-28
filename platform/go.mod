module github.com/lidofinance/tee-signer/platform

go 1.26.0

toolchain go1.27.3

require (
	github.com/lidofinance/tee-signer/governance v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
	github.com/lidofinance/tee-signer/trusted-time v0.0.0
)

require (
	github.com/beevik/ntp v1.6.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
	github.com/lidofinance/tee-signer/trusted-time => ../trusted-time
)
