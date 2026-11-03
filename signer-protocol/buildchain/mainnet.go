//go:build !nonprod

package buildchain

// This build is the mainnet build, the prod one.
const (
	Name = Mainnet
	Prod = true

	TimeLock          = MainnetTimeLock
	MaxTimeLock       = MainnetMaxTimeLock
	ActivationHorizon = MainnetActivationHorizon
	ImagesMinTimeLock = MainnetImagesMinTimeLock

	CertName      = MainnetCertName
	VersionSuffix = ""

	// AdminRootDirect: no admin role for a leaf signed straight by the root.
	AdminRootDirect = false
	// AdminRootDirectRole names that role in logs; empty in a mainnet
	// build, which must not hold the name.
	AdminRootDirectRole = ""
)
