package setupwire

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// withFeatures is the Nitro sample with required_features fs.
func withFeatures(t testing.TB, fs ...string) *Setup {
	t.Helper()
	s := samples(t)["setup-nitro"]
	s.Locked.RequiredFeatures = fs
	return s
}

// required_features is always leaf 15 of locked, with a salt of its own;
// an empty list is version 1 and count 0, so each list has one encoding.
func TestRequiredFeaturesLayout(t *testing.T) {
	s := samples(t)["setup-nitro"]
	ls := val(s.Locked.Leaves(s.PolicySalts.Locked))
	if len(ls) != NumLockedLeaves || NumLockedLeaves != 16 {
		t.Fatalf("%d locked leaves", len(ls))
	}
	last := ls[NumLockedLeaves-1]
	if last.Name != RequiredFeaturesLeaf || !bytes.Equal(last.Value, []byte{RequiredFeaturesVersion, 0}) {
		t.Fatalf("leaf 15: %s %x", last.Name, last.Value)
	}
	if v := val(s.Locked.Encode()); !bytes.HasSuffix(v, []byte{RequiredFeaturesVersion, 0}) {
		t.Fatal("the empty list is not written as version 1, count 0")
	}
	if d := val(DecodeSetup(must(s.Encode()))); d.Locked.RequiredFeatures != nil {
		t.Fatalf("empty list decoded as %#v", d.Locked.RequiredFeatures)
	}
	// nil and an empty slice are one list.
	e := samples(t)["setup-nitro"]
	e.Locked.RequiredFeatures = []string{}
	if !bytes.Equal(must(e.Encode()), must(s.Encode())) {
		t.Fatal("[]string{} and nil encode differently")
	}
	// 15 locked salts are refused.
	short := samples(t)["setup-nitro"]
	short.PolicySalts.Locked = short.PolicySalts.Locked[:15]
	if _, err := short.Encode(); err == nil {
		t.Fatal("15 locked salts encoded")
	}
}

// required_features joined the locked group as its 16th leaf while
// UpdateVersion stayed 2. What
// keeps a locked body of the 15-leaf layout out is the layout itself: with
// the leaf's two bytes and its salt removed, the 16-leaf reader refuses it,
// whatever the salts hold, including salts that start with the bytes of an
// empty leaf. A later leaf change must keep this, or move UpdateVersion.
func TestFifteenLeafLockedBodyRefused(t *testing.T) {
	s := samples(t)["setup-nitro"]
	body := signedUpdate(t, s, lockedBody(s), []byte{0, 2}, nil).Body
	body.Locked.RequiredFeatures = nil
	b := val(body.Encode())
	if _, err := DecodeUpdateBody(b); err != nil {
		t.Fatalf("the 16-leaf body does not decode: %v", err)
	}
	// The body ends in the empty leaf (version, count 0) and 16 salts.
	at := len(b) - NumLockedLeaves*32 - 2
	if b[at] != RequiredFeaturesVersion || b[at+1] != 0 {
		t.Fatalf("bytes %d, %d are %#x %#x, want the empty required_features leaf", at, at+1, b[at], b[at+1])
	}
	old := slices.Concat(b[:at], b[at+2:len(b)-32])
	if _, err := DecodeUpdateBody(old); err == nil {
		t.Fatal("a locked body of the 15-leaf layout decodes")
	}
	r := rand.New(rand.NewSource(7))
	salts := old[at:]
	for i := range 2000 {
		r.Read(salts)
		if i%2 == 0 {
			// What the 16-leaf reader takes as the leaf's version and count.
			salts[0], salts[1] = RequiredFeaturesVersion, 0
		}
		if _, err := DecodeUpdateBody(old); err == nil {
			t.Fatalf("trial %d: a locked body of the 15-leaf layout decodes", i)
		}
	}
}

// A list with entries round-trips in a setup and in a locked update, and
// changes the locked root, policy_root and setup_hash, not the open group
// or the platform commitment.
func TestRequiredFeaturesRoundTrip(t *testing.T) {
	base := samples(t)["setup-nitro"]
	s := withFeatures(t, "a_1", "dv_shares")
	b := must(s.Encode())
	d, err := DecodeSetup(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, s) {
		t.Fatalf("decoded %+v, want %+v", d.Locked, s.Locked)
	}
	if len(b) != len(must(base.Encode()))+(1+3)+(1+9) {
		t.Fatal("the list does not add exactly its entries")
	}
	if val(base.Hash()) == val(s.Hash()) || val(base.PolicyRoot()) == val(s.PolicyRoot()) ||
		val(base.GroupHash(GroupLocked)) == val(s.GroupHash(GroupLocked)) {
		t.Fatal("a required feature does not change the hashes")
	}
	if val(base.GroupHash(GroupOpen)) != val(s.GroupHash(GroupOpen)) || val(base.PlatformCommitment()) != val(s.PlatformCommitment()) {
		t.Fatal("a required feature changes the open group or the platform commitment")
	}
	ls := val(s.Locked.Leaves(s.PolicySalts.Locked))
	if !bytes.Equal(ls[NumLockedLeaves-1].Value, append([]byte{RequiredFeaturesVersion, 2, 3}, "a_1\x09dv_shares"...)) {
		t.Fatalf("leaf value %x", ls[NumLockedLeaves-1].Value)
	}
	if val(withFeatures(t, "dv_shares").Hash()) == val(s.Hash()) {
		t.Fatal("two lists, one hash")
	}

	body := lockedBody(base)
	body.Locked.RequiredFeatures = []string{"dv_shares"}
	u := signedUpdate(t, base, body, []byte{0, 1}, nil)
	du, err := DecodeUpdate(must(u.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(du, u) {
		t.Fatalf("update decoded %+v", du.Body.Locked)
	}
	if val(signedUpdate(t, base, lockedBody(base), []byte{0, 1}, nil).Body.Hash()) == val(u.Body.Hash()) {
		t.Fatal("a required feature does not change the update hash")
	}
}

// The decoder refuses a bad leaf: another version, a count above the cap,
// an empty or unsorted entry, and trailing bytes after the setup.
func TestRequiredFeaturesWire(t *testing.T) {
	b := must(withFeatures(t, "zzfeat").Encode())
	leaf := []byte("\x01\x01\x06zzfeat")
	at := bytes.Index(b, leaf)
	if at < 0 || bytes.Count(b, leaf) != 1 {
		t.Fatal("leaf value not found once")
	}
	edit := func(f func(c []byte) []byte) []byte { return f(slices.Clone(b)) }
	for name, bad := range map[string][]byte{
		"version 2": edit(func(c []byte) []byte { c[at] = 2; return c }),
		"count 17": edit(func(c []byte) []byte {
			return slices.Concat(c[:at], []byte{1, 17}, bytes.Repeat([]byte{1, 'a'}, 17), c[at+len(leaf):])
		}),
		"empty name":        edit(func(c []byte) []byte { return slices.Concat(c[:at], []byte{1, 1, 0}, c[at+len(leaf):]) }),
		"no entry, count 1": edit(func(c []byte) []byte { return slices.Concat(c[:at], []byte{1, 1}, c[at+len(leaf):]) }),
		"trailing byte":     append(slices.Clone(b), 0),
		"unsorted":          rawSetup(withFeatures(t, "b", "a")),
		"repeat":            rawSetup(withFeatures(t, "a", "a")),
		"upper case":        rawSetup(withFeatures(t, "A")),
	} {
		if _, err := DecodeSetup(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestRequiredFeaturesCheck(t *testing.T) {
	many := make([]string, MaxRequiredFeatures+1)
	for i := range many {
		many[i] = fmt.Sprintf("f%02d", i)
	}
	for name, fs := range map[string][]string{
		"unsorted":     {"b", "a"},
		"duplicate":    {"a", "a"},
		"too long":     {strings.Repeat("a", MaxFeatureName+1)},
		"empty name":   {""},
		"upper case":   {"Dv_shares"},
		"dash":         {"dv-shares"},
		"space":        {"dv shares"},
		"more than 16": many,
	} {
		s := withFeatures(t, fs...)
		if err := s.Locked.Check(); err == nil || !strings.Contains(err.Error(), "required_features") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := s.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	ok := withFeatures(t, many[:MaxRequiredFeatures]...)
	ok.Locked.RequiredFeatures[0] = strings.Repeat("0", MaxFeatureName)
	if _, err := DecodeSetup(must(ok.Encode())); err != nil {
		t.Fatalf("16 features, one of 32 characters: %v", err)
	}
}

// Any change of required_features takes the normal path and waits the
// change delay, whoever signs: adding one, dropping one, with a removal.
func TestRequiredFeaturesDecide(t *testing.T) {
	s := samples(t)["setup-nitro"]
	wait := s.Locked.ChangeDelayOn(&s.Chain)
	if wait == 0 {
		t.Fatal("the sample has no change delay")
	}
	prev, _ := s.GroupHash(GroupLocked)
	all := make([]byte, len(s.Locked.Approvers.Keys))
	for i := range all {
		all[i] = byte(i)
	}
	want := []FieldChange{{RequiredFeaturesLeaf, ChangeLoosen}}
	add := s.Locked
	add.RequiredFeatures = []string{"dv_shares"}
	u := signedUpdate(t, s, UpdateBody{Group: GroupLocked, Version: 1, PrevHash: prev, ActivateAt: 1_800_000_000, Locked: &add}, all, nil)
	d, err := u.Decide(&s.Chain, &s.Locked, &s.Open, History{})
	if err != nil || d.Path != PathNormal || d.Wait != wait || !reflect.DeepEqual(d.Changes, want) {
		t.Fatalf("feature added: %+v, %v", d, err)
	}
	plain := s.Locked
	u = signedUpdate(t, s, UpdateBody{Group: GroupLocked, Version: 2, PrevHash: prev, ActivateAt: 1_800_000_000, Locked: &plain}, all, nil)
	d, err = u.Decide(&s.Chain, &add, &s.Open, History{})
	if err != nil || d.Path != PathNormal || d.Wait != wait || !reflect.DeepEqual(d.Changes, want) {
		t.Fatalf("feature dropped: %+v, %v", d, err)
	}
	rm := add
	rm.Approvers.Keys = slices.Clone(s.Locked.Approvers.Keys[1:])
	if _, ok := EmergencyRemoval(&s.Locked, &rm, ClassifyLocked(&s.Locked, &rm)); ok {
		t.Fatal("a removal that adds a feature counts as an emergency removal")
	}
}

func TestUnknownFeatures(t *testing.T) {
	l := &Locked{RequiredFeatures: []string{"a", "b", "c"}}
	if got := l.UnknownFeatures([]string{"b"}); !slices.Equal(got, []string{"a", "c"}) {
		t.Fatalf("%v", got)
	}
	if got := (&Locked{}).UnknownFeatures(nil); got != nil {
		t.Fatalf("%v", got)
	}
	if err := l.CheckFeatures([]string{"b"}); err == nil || !strings.Contains(err.Error(), "required_features a, c") {
		t.Fatalf("%v", err)
	}
	if err := (&Locked{}).CheckFeatures(nil); err != nil {
		t.Fatal(err)
	}
}

// val is must for any type.
func val[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
