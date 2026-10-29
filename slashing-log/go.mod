module github.com/lidofinance/tee-signer/slashing-log

go 1.26.0

require (
	github.com/lidofinance/tee-signer/devkit v0.0.0
	github.com/lidofinance/tee-signer/governance v0.0.0
	github.com/lidofinance/tee-signer/platform v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
)

require github.com/lidofinance/tee-signer/trusted-time v0.0.0 // indirect

replace (
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
	github.com/lidofinance/tee-signer/platform => ../platform
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
	github.com/lidofinance/tee-signer/trusted-time => ../trusted-time
)
