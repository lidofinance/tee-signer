package core

// Expose the C limits to external tests without adding them to the public API.
const (
	MaxSlotTimesForTest        = maxSlotTimes
	MaxFeeRecipientsForTest    = maxFeeRecipients
	MaxBuilderAuthRootsForTest = maxBuilderAuthRoots
)

func (s *Signer) CoreEpochAtForTest(t uint64) uint64 { return s.coreEpochAt(t) }
