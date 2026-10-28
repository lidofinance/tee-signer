module github.com/lidofinance/tee-signer/governance

go 1.26.0

require (
	github.com/lidofinance/tee-signer/devkit v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
)

replace (
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
)
