// Package buildchain holds the constants of the chain a runner is built
// for. The build tags pick it:
//
//   - no tag: mainnet, a prod build with the design's governance times.
//     Every image for real keys is this build.
//   - nonprod and one chain tag (chain_hoodi, chain_devnet or
//     chain_ci_test): the same code with one minute for each day of the
//     mainnet build, so research on a test network or a devnet can change
//     images in minutes. Such a runner names its chain (HEALTH's version,
//     its TLS certificate's subject), starts on that chain only
//     (governance/runnerchain), and clients refuse it unless their
//     connection settings name that chain.
//
// nonprod is the tag the code tests; the chain tag only names the chain.
// A chain tag without nonprod, nonprod without a chain tag, or two chain
// tags do not compile: Name is then declared twice or not at all.
//
// Prod must match the chain's row in the chain table
// (governance/setupwire chains.go); a test checks it. mainnet.go and
// nonprod.go give this build's values; setupwire takes its DefaultTimeLock,
// MaxTimeLock, ActivationHorizon and ImagesMinTimeLock from them, and the
// runner its version suffix and certificate name. governance/runnerchain
// gives clients the values of every chain, by the chain a runner reports.
//
// The package holds constants only, and must stay so: a package without
// code adds nothing to a binary, so the mainnet build of every program
// that imports it stays byte for byte what it was before the chain builds.
// Constants in a new file of a package with code would change the binary
// (the file joins the package's file table), and so would any code here.
package buildchain

// The chains a runner is built for. The name shows in the version suffix
// and the certificate name of a non-prod build.
const (
	Mainnet = "mainnet"
	Hoodi   = "hoodi"
	Devnet  = "devnet"
	CITest  = "ci-test" // governance/chains/chain.ci-test.json, a test chain no network runs
)

// The governance times, in seconds: the prod build's, and the short waits
// of the non-prod builds.
const (
	MainnetTimeLock          = 48 * 3600  // 2 days, when the setup names none
	MainnetMaxTimeLock       = 30 * 86400 // 30 days
	MainnetActivationHorizon = 30 * 86400 // 30 days past the required wait
	MainnetImagesMinTimeLock = 7 * 86400  // 7 days

	ShortTimeLock          = 2 * 60  // 2 minutes
	ShortMaxTimeLock       = 30 * 60 // 30 minutes
	ShortActivationHorizon = 30 * 60 // 30 minutes
	ShortImagesMinTimeLock = 7 * 60  // 7 minutes
)

// MainnetCertName is the subject common name of the TLS certificate of a
// mainnet runner. A non-prod build of chain c has CertName
// MainnetCertName + " " + c and VersionSuffix "+" + c (semver build
// metadata, so "+ci-test" is valid).
const MainnetCertName = "signer-runner"
