package setupwire

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func nitroImage(b byte) Image {
	return Image{Kind: ImageNitro, Measurement: bytes.Repeat([]byte{b}, 144)}
}

// imageUpdate is a locked update after prev (nil: the setup) with images
// and, if set, the approver set, signed by the given keys at the given
// positions of the set prev has in force.
func imageUpdate(t *testing.T, s *Setup, prev *Update, version, activateAt uint64, images []Image, set *ApproverSet, keys []byte, newKeys []byte) *Update {
	t.Helper()
	l := s.Locked
	prevHash, err := s.GroupHash(GroupLocked)
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		l = *prev.Body.Locked
		if prevHash, err = prev.Body.Hash(); err != nil {
			t.Fatal(err)
		}
	}
	l.AllowedImageMeasurements = slices.SortedFunc(slices.Values(images), compareImages)
	if set != nil {
		l.Approvers = *set
	}
	u := signedUpdate(t, s, UpdateBody{Group: GroupLocked, Version: version, PrevHash: prevHash, ActivateAt: activateAt, Locked: &l}, nil, newKeys)
	for pos, k := range keys {
		sig, err := u.Body.Sign(approverKey(k))
		if err != nil {
			t.Fatal(err)
		}
		u.Approvals = append(u.Approvals, Approval{Position: uint8(pos), Signature: sig})
	}
	return u
}

func files(t *testing.T, us ...*Update) []UpdateFile {
	t.Helper()
	var out []UpdateFile
	for i, u := range us {
		raw, err := u.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, UpdateFile{Name: string(rune('a'+i)) + ".signed", Raw: raw})
	}
	return out
}

func wantImages(t *testing.T, what string, got []Image, want ...Image) {
	t.Helper()
	if !slices.EqualFunc(got, want, func(a, b Image) bool { return compareImages(a, b) == 0 }) {
		t.Fatalf("%s: images %v, want %v", what, got, want)
	}
}

func TestApprovedImages(t *testing.T) {
	s := samples(t)["setup-nitro"]
	az := s.Locked.AllowedImageMeasurements[1]
	const past, now, future = 1_700_000_000, 1_750_000_000, 1_800_000_000

	// The setup alone.
	a, err := ApprovedImages(s, nil, now)
	if err != nil || a.Version != 0 || len(a.Warnings) != 0 {
		t.Fatalf("setup: %+v, %v", a, err)
	}
	wantImages(t, "setup", a.Images, nitroImage(0x11), az)

	// A linear chain: v1 adds 0x22, v3 drops 0x11. The last list counts.
	v1 := imageUpdate(t, s, nil, 1, past, []Image{nitroImage(0x11), nitroImage(0x22), az}, nil, []byte{1, 2}, nil)
	v3 := imageUpdate(t, s, v1, 3, past, []Image{nitroImage(0x22), az}, nil, []byte{1, 2}, nil)
	a, err = ApprovedImages(s, files(t, v3, v1), now)
	if err != nil || a.Version != 3 || len(a.Warnings) != 0 {
		t.Fatalf("chain: %+v, %v", a, err)
	}
	wantImages(t, "chain", a.Images, nitroImage(0x22), az)

	// A rotation to keys 2, 3, 4: the next step needs the new set.
	set := &ApproverSet{Keys: [][32]byte{approverPub(2), approverPub(3), approverPub(4)}, ApprovalsNeeded: 2}
	rot := imageUpdate(t, s, nil, 1, past, []Image{nitroImage(0x11), az}, set, []byte{1, 2}, []byte{2, 3, 4})
	byOld := imageUpdate(t, s, rot, 2, past, []Image{nitroImage(0x11), nitroImage(0x22), az}, set, []byte{1, 2}, nil)
	a, err = ApprovedImages(s, files(t, rot, byOld), now)
	if err != nil || a.Version != 1 || len(a.Warnings) != 1 || !strings.Contains(a.Warnings[0], "does not chain") {
		t.Fatalf("rotation, signed by the old set: %+v, %v", a, err)
	}
	byNew := imageUpdate(t, s, rot, 2, past, []Image{nitroImage(0x11), nitroImage(0x22), az}, set, []byte{2, 3}, nil)
	a, err = ApprovedImages(s, files(t, rot, byNew), now)
	if err != nil || a.Version != 2 {
		t.Fatalf("rotation, signed by the new set: %+v, %v", a, err)
	}
	wantImages(t, "rotation", a.Images, nitroImage(0x11), nitroImage(0x22), az)

	// An update of another cluster does not count.
	other := *s
	other.ClusterID[0]++
	foreign := imageUpdate(t, &other, nil, 1, past, []Image{nitroImage(0x22), az}, nil, []byte{1, 2}, nil)
	a, err = ApprovedImages(s, files(t, foreign), now)
	if err != nil || a.Version != 0 || len(a.Warnings) != 1 || !strings.Contains(a.Warnings[0], "another cluster_id") {
		t.Fatalf("another cluster: %+v, %v", a, err)
	}

	// Without v1 the chain stops at the setup, with a warning for v3.
	a, err = ApprovedImages(s, append(files(t, v3), UpdateFile{Name: "junk.signed", Raw: []byte("junk")}), now)
	if err != nil || a.Version != 0 || len(a.Warnings) != 2 {
		t.Fatalf("missing predecessor: %+v, %v", a, err)
	}
	wantImages(t, "missing predecessor", a.Images, nitroImage(0x11), az)

	// Two updates for one step.
	v1b := imageUpdate(t, s, nil, 1, past, []Image{nitroImage(0x33), az}, nil, []byte{1, 2}, nil)
	if _, err := ApprovedImages(s, files(t, v1, v1b), now); err == nil || !strings.Contains(err.Error(), "a.signed and b.signed both replace locked version 0") {
		t.Fatalf("two candidates: %v", err)
	}

	// Copies of one update, with other signatures, are one step.
	v1c := imageUpdate(t, s, nil, 1, past, []Image{nitroImage(0x11), nitroImage(0x22), az}, nil, []byte{1, 2, 3}, nil)
	a, err = ApprovedImages(s, files(t, v1, v1c), now)
	if err != nil || a.Version != 1 || len(a.Warnings) != 0 {
		t.Fatalf("two copies: %+v, %v", a, err)
	}

	// An image an update adds counts from its activate_at plus the push
	// slack on, and the image it drops until its activate_at. With no
	// activate_at the added image never counts and the dropped one is off
	// at once.
	pend := imageUpdate(t, s, nil, 1, future, []Image{nitroImage(0x11), nitroImage(0x22)}, nil, []byte{1, 2}, nil)
	for _, tc := range []struct {
		at     uint64
		images []Image
	}{
		{future - 1, []Image{nitroImage(0x11), az}},
		{future, []Image{nitroImage(0x11)}},
		{future + PushSlack - 1, []Image{nitroImage(0x11)}},
		{future + PushSlack, []Image{nitroImage(0x11), nitroImage(0x22)}},
	} {
		a, err = ApprovedImages(s, files(t, pend), tc.at)
		if err != nil || a.Version != 1 {
			t.Fatalf("at %d: %+v, %v", tc.at, a, err)
		}
		wantImages(t, fmt.Sprintf("at activate_at %+d", int64(tc.at)-future), a.Images, tc.images...)
	}
	noTime := imageUpdate(t, s, nil, 1, 0, []Image{nitroImage(0x11), nitroImage(0x22)}, nil, []byte{1, 2}, nil)
	a, err = ApprovedImages(s, files(t, noTime), now)
	if err != nil || a.Version != 1 {
		t.Fatalf("no activate_at: %+v, %v", a, err)
	}
	wantImages(t, "no activate_at", a.Images, nitroImage(0x11))
	wantImages(t, "no activate_at", a.Pending, nitroImage(0x22))

	// An image an earlier update adds waits for that update's time, though
	// a later update with a past activate_at lists it too.
	early := imageUpdate(t, s, nil, 1, future, []Image{nitroImage(0x11), nitroImage(0x22), az}, nil, []byte{1, 2}, nil)
	late := imageUpdate(t, s, early, 2, past, []Image{nitroImage(0x11), nitroImage(0x22), nitroImage(0x33), az}, nil, []byte{1, 2}, nil)
	a, err = ApprovedImages(s, files(t, early, late), now)
	if err != nil || a.Version != 2 {
		t.Fatalf("earlier pending: %+v, %v", a, err)
	}
	wantImages(t, "earlier pending", a.Images, nitroImage(0x11), nitroImage(0x33), az)
	wantImages(t, "earlier pending", a.Pending, nitroImage(0x22))
}
