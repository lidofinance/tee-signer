//go:build nonprod

package buildchain

// This build is a non-prod build. Name comes from the chain tag
// (hoodi.go, devnet.go, citest.go).
const (
	Prod = false

	TimeLock          = ShortTimeLock
	MaxTimeLock       = ShortMaxTimeLock
	ActivationHorizon = ShortActivationHorizon
	ImagesMinTimeLock = ShortImagesMinTimeLock

	CertName      = MainnetCertName + " " + Name
	VersionSuffix = "+" + Name

	// AdminRootDirect: a leaf with the admin mark signed straight by a pinned
	// root is admin. The devnet's pinned client root has pathlen:0, so it can
	// have no admin intermediate below it.
	AdminRootDirect = true
	// AdminRootDirectRole names that role in logs; empty in a mainnet
	// build, which must not hold the name.
	AdminRootDirectRole = "admin-root-direct"
)
