package setupwire

import "fmt"

// UpdateFile is a signed update and the name of the file it came from.
type UpdateFile struct {
	Name string
	Raw  []byte
}

// Approved is the allowed_image_measurements list of a cluster as
// ApprovedImages finds it.
type Approved struct {
	Images []Image
	// Version is the locked version the list comes from; 0 is the setup.
	Version uint64
	// Pending are the images the last update adds that do not count yet.
	Pending []Image
	// Warnings name the files that do not decode or do not chain.
	Warnings []string
}

// ApprovedImages walks the locked chain from the setup s through the
// signed updates in files and returns the list of the last update it
// reaches. Each step takes the one locked update of this cluster and
// chain whose prev_hash is the current hash, whose version is higher, and
// that the current approver set signed. Two such updates for one step are
// an error. An image that only the last update adds counts once now (Unix
// seconds) has reached that update's activate_at; with no activate_at it
// does not count. The tool cannot see when the update came into force on
// a runner, so activate_at is the earliest time it can have.
func ApprovedImages(s *Setup, files []UpdateFile, now uint64) (*Approved, error) {
	hash, err := s.GroupHash(GroupLocked)
	if err != nil {
		return nil, err
	}
	a := &Approved{}
	type candidate struct {
		name string
		u    *Update
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
		cs = append(cs, &candidate{name: f.Name, u: u})
	}
	cur, prev := &s.Locked, s.Locked.AllowedImageMeasurements
	var last *UpdateBody
	for {
		var next *candidate
		for _, c := range cs {
			b := &c.u.Body
			if b.PrevHash != hash || b.Version <= a.Version || c.u.Verify(&cur.Approvers) != nil {
				continue
			}
			if next != nil {
				return nil, fmt.Errorf("%s and %s both replace locked version %d; remove the one that was not pushed", next.name, c.name, a.Version)
			}
			next = c
		}
		if next == nil {
			break
		}
		next.used = true
		last = &next.u.Body
		if hash, err = last.Hash(); err != nil {
			return nil, fmt.Errorf("%s: %w", next.name, err)
		}
		prev, cur, a.Version = cur.AllowedImageMeasurements, last.Locked, last.Version
	}
	for _, c := range cs {
		if !c.used {
			a.Warnings = append(a.Warnings, fmt.Sprintf("%s: locked version %d does not chain to the setup: its prev_hash names no update of the chain, or the approvers of that one did not sign it", c.name, c.u.Body.Version))
		}
	}
	for _, im := range cur.AllowedImageMeasurements {
		if last != nil && !im.Listed(prev) && (last.ActivateAt == 0 || now < last.ActivateAt) {
			a.Pending = append(a.Pending, im)
			continue
		}
		a.Images = append(a.Images, im)
	}
	return a, nil
}
