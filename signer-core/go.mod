module github.com/lidofinance/tee-signer/signer-core

go 1.27.3

require (
	github.com/lidofinance/tee-signer/governance v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
)

replace (
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
)
