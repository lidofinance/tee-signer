package backend

// The states of ImageCheck.
const (
	// ImageAllowed: the image is on allowed_image_measurements in force.
	ImageAllowed = "allowed"
	// ImageNotAllowed: it is not; the runner signs, hands over and imports
	// nothing.
	ImageNotAllowed = "not_allowed"
	// ImageRestartNeeded: the image was not allowed when the runner
	// started, so it loaded no share; the list in force names it now, and a
	// restart loads the shares. Until then the runner serves as for
	// ImageNotAllowed.
	ImageRestartNeeded = "restart_needed"
	// ImageUnknown: the runner cannot tell its own image, or cannot read the
	// list in force; it serves as for ImageNotAllowed.
	ImageUnknown = "unknown"
	// ImageOverride: not on the list, served anyway under the testnet
	// build's -allow-unlisted-image.
	ImageOverride = "override"
	// ImageNotApplicable: the dev platform, which has no image kind.
	ImageNotApplicable = "not_applicable"
)

// ImageCheck is what HEALTH reports of the runner's image check.
type ImageCheck struct {
	// State is one of the Image* states above.
	State string `json:"state"`
	// Kind and Measurement are the runner's own image as its key release
	// evidence named it: the setupwire.ImageKind name (nitro, azure, gcp)
	// and the measurement in hex (PCR0, PCR1 and PCR2 for nitro). Empty
	// when unknown.
	Kind        string `json:"kind,omitempty"`
	Measurement string `json:"measurement,omitempty"`
	// LockedVersion is the version of the locked group in force whose list
	// the check read.
	LockedVersion uint64 `json:"locked_version"`
	// Why says what the state rests on.
	Why string `json:"why,omitempty"`
}
