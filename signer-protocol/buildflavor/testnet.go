//go:build testnet

package buildflavor

// This build is the testnet flavour.
const (
	Name = "testnet"

	TimeLock          = TestnetFlavorTimeLock
	MaxTimeLock       = TestnetFlavorMaxTimeLock
	ActivationHorizon = TestnetFlavorActivationHorizon
	ImagesMinTimeLock = TestnetFlavorImagesMinTimeLock

	CertName      = TestnetCertName
	VersionSuffix = TestnetVersionSuffix

	// AdminRootDirect: a leaf with the admin mark signed straight by a pinned
	// root is admin. The devnet's pinned client root has pathlen:0, so it can
	// have no admin intermediate below it.
	AdminRootDirect = true
	// AdminRootDirectRole names that role in logs; empty in a default
	// build, which must not hold the name.
	AdminRootDirectRole = "admin-root-direct"
)
