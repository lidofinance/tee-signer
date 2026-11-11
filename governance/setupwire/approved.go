package setupwire

import (
	"fmt"
	"math"
)

// PushSlack is how far, in seconds, signer-admin push lets a locked update
// arrive after its activate_at minus the wait. A runner then brings it into
// force at most this long after activate_at.
const PushSlack = 300

// UpdateFile is a signed update and the name of the file it came from.
type UpdateFile struct {
	Name string
	Raw  []byte
}

// Approved is the allowed_image_measurements list of a cluster as
// ApprovedImages finds it.
type Approved struct {
	Images []Image
	// Version is the locked version the walk reached; 0 is the setup.
	Version uint64
	// Pending are the images of the last list that do not count yet.
	Pending []Image
	// Warnings name the files that do not decode or do not chain.
	Warnings []string
}

// ApprovedImages walks the locked chain from the setup s through the
// signed updates in files and returns the images that count at now (Unix
// seconds). Each step takes the locked update of this cluster and chain
// whose prev_hash is the current hash, whose version is higher, and that
// the current approver set signed. Copies of one update are one step; two
// different updates for one step are an error.
//
// A runner brings an update into force at the later of activate_at and
// its arrival plus the wait (Wait). signer-admin push refuses an update
// whose activate_at plus PushSlack is earlier than now plus the wait, so a
// pushed update comes into force between activate_at and activate_at +
// PushSlack. An image that an update of the walk adds counts from that
// update's activate_at + PushSlack on, and never when the update has no
// activate_at. An image that the last update drops counts until its
// activate_at, and not at all when it has none; one that an earlier
// update dropped does not count. So the tools are never ahead of the
// runners, and at most PushSlack behind.
func ApprovedImages(s *Setup, files []UpdateFile, now uint64) (*Approved, error) {
	hash, err := s.GroupHash(GroupLocked)
	if err != nil {
		return nil, err
	}
	a := &Approved{}
	type candidate struct {
		name string
		u    *Update
		hash [32]byte
		used bool
	}
	var cs []*candidate
	for _, f := range files {
		u, err := DecodeUpdate(f.Raw)
		if err != nil {
			a.Warnings = append(a.Warnings, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}
		if u.Body.Group != GroupLocked {
			continue
		}
		if err := u.Body.Matches(s); err != nil {
			a.Warnings = append(a.Warnings, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}
		h, err := u.Body.Hash()
		if err != nil {
			a.Warnings = append(a.Warnings, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}
		cs = append(cs, &candidate{name: f.Name, u: u, hash: h})
	}
	key := func(im Image) string { return fmt.Sprintf("%d:%x", im.Kind, im.Measurement) }
	// from is the earliest time each image of the current list counts.
	from := map[string]uint64{}
	for _, im := range s.Locked.AllowedImageMeasurements {
		from[key(im)] = 0
	}
	cur := &s.Locked
	var dropped []Image // by the last step, counting until until
	var until uint64
	for {
		var next *candidate
		for _, c := range cs {
			b := &c.u.Body
			if b.PrevHash != hash || b.Version <= a.Version || c.u.Verify(&cur.Approvers) != nil {
				continue
			}
			if next != nil && next.hash != c.hash {
				return nil, fmt.Errorf("%s and %s both replace locked version %d; remove the one that was not pushed", next.name, c.name, a.Version)
			}
			if next == nil {
				next = c
			}
			c.used = true
		}
		if next == nil {
			break
		}
		b := &next.u.Body
		// With no activate_at an added image never counts and a dropped one
		// is off at once.
		added := uint64(math.MaxUint64)
		if b.ActivateAt != 0 {
			added = SatAdd(b.ActivateAt, PushSlack)
		}
		nextFrom := map[string]uint64{}
		for _, im := range b.Locked.AllowedImageMeasurements {
			t, ok := from[key(im)]
			if !ok {
				t = added
			}
			nextFrom[key(im)] = t
		}
		dropped, until = nil, b.ActivateAt
		for _, im := range cur.AllowedImageMeasurements {
			if _, ok := nextFrom[key(im)]; !ok && from[key(im)] <= now {
				dropped = append(dropped, im)
			}
		}
		hash, cur, a.Version, from = next.hash, b.Locked, b.Version, nextFrom
	}
	for _, c := range cs {
		if !c.used {
			a.Warnings = append(a.Warnings, fmt.Sprintf("%s: locked version %d does not chain to the setup: its prev_hash names no update of the chain, or the approvers of that one did not sign it", c.name, c.u.Body.Version))
		}
	}
	for _, im := range cur.AllowedImageMeasurements {
		if from[key(im)] <= now {
			a.Images = append(a.Images, im)
		} else {
			a.Pending = append(a.Pending, im)
		}
	}
	if now < until {
		a.Images = append(a.Images, dropped...)
	}
	return a, nil
}
