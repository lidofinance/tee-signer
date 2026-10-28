//go:build !testnet

package buildflavor

// This build is the default flavour.
const (
	Name = "default"

	TimeLock          = DefaultFlavorTimeLock
	MaxTimeLock       = DefaultFlavorMaxTimeLock
	ActivationHorizon = DefaultFlavorActivationHorizon
	ImagesMinTimeLock = DefaultFlavorImagesMinTimeLock

	CertName      = DefaultCertName
	VersionSuffix = ""

	// AdminRootDirect: no admin role for a leaf signed straight by the root.
	AdminRootDirect = false
	// AdminRootDirectRole names that role in logs; empty in a default
	// build, which must not hold the name.
	AdminRootDirectRole = ""
)
