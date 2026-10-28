module github.com/lidofinance/tee-signer/platform-gcp

go 1.26.0

require (
	github.com/lidofinance/tee-signer/governance v0.0.0
	github.com/lidofinance/tee-signer/platform v0.0.0
	github.com/lidofinance/tee-signer/signer-protocol v0.0.0
	github.com/lidofinance/tee-signer/slashing-log v0.0.0
	github.com/lidofinance/tee-signer/trusted-time v0.0.0
)

require (
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1 // indirect
	github.com/beevik/ntp v1.6.0 // indirect
	github.com/beevik/nts v0.3.3 // indirect
	github.com/lidofinance/tee-signer/devkit v0.0.0 // indirect
	github.com/lidofinance/tee-signer/signer-core v0.0.0 // indirect
	github.com/secure-io/siv-go v0.0.0-20180922214919-5ff40651e2c4 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/lidofinance/tee-signer/devkit => ../devkit
	github.com/lidofinance/tee-signer/governance => ../governance
	github.com/lidofinance/tee-signer/platform => ../platform
	github.com/lidofinance/tee-signer/signer-core => ../signer-core
	github.com/lidofinance/tee-signer/signer-protocol => ../signer-protocol
	github.com/lidofinance/tee-signer/slashing-log => ../slashing-log
	github.com/lidofinance/tee-signer/trusted-time => ../trusted-time
)
