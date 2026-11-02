// Package buildflavor holds the constants of the runner's two build
// flavours:
//
//   - default: the design's governance times. Every image for real
//     keys is this build.
//   - testnet (go build -tags testnet): the same code with one minute for
//     each day of the default, so research on a devnet or a test network can
//     change images and run handover orders in minutes. A testnet runner reports
//     its flavour (HEALTH's version, its TLS certificate's subject), starts
//     on devnets and the test networks of backend/flavor only, and clients
//     refuse it unless their connection settings allow it.
//
// default.go and testnet.go give this build's values; setupwire takes its
// DefaultTimeLock, MaxTimeLock, ActivationHorizon and ImagesMinTimeLock from
// them, and the runner its version suffix and certificate name.
// backend/flavor gives clients both sets, by the flavour a runner reports.
//
// The package holds constants only, and must stay so: a package without
// code adds nothing to a binary, so the default build of every program
// that imports it stays byte for byte what it was before the flavours.
// Constants in a new file of a package with code would change the binary
// (the file joins the package's file table), and so would any code here.
package buildflavor

// The governance times of each flavour, in seconds.
const (
	DefaultFlavorTimeLock          = 48 * 3600  // 2 days, when the setup names none
	DefaultFlavorMaxTimeLock       = 30 * 86400 // 30 days
	DefaultFlavorActivationHorizon = 30 * 86400 // 30 days past the required wait
	DefaultFlavorImagesMinTimeLock = 7 * 86400  // 7 days

	TestnetFlavorTimeLock          = 2 * 60  // 2 minutes
	TestnetFlavorMaxTimeLock       = 30 * 60 // 30 minutes
	TestnetFlavorActivationHorizon = 30 * 60 // 30 minutes
	TestnetFlavorImagesMinTimeLock = 7 * 60  // 7 minutes
)

// The marks of each flavour: the subject common name of the runner's TLS
// certificate, and the suffix of its version in HEALTH.
const (
	DefaultCertName      = "signer-runner"
	TestnetCertName      = "signer-runner testnet"
	TestnetVersionSuffix = "+testnet"
)
