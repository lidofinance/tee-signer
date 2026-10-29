package setupwire

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func lockedBody(s *Setup) UpdateBody {
	l := s.Locked
	l.AllowedFeeRecipients = append(slices.Clone(l.AllowedFeeRecipients), [20]byte{0x45})
	l.AllowedBuilderRequestAuthDataRoots = append(slices.Clone(l.AllowedBuilderRequestAuthDataRoots), [32]byte{0x53})
	prev, _ := s.GroupHash(GroupLocked)
	return UpdateBody{Group: GroupLocked, Version: 1, PrevHash: prev, ActivateAt: 1_800_000_000, Locked: &l}
}

func openBody(s *Setup) UpdateBody {
	o := s.Open
	o.ForkSchedule = append(slices.Clone(o.ForkSchedule), Fork{Epoch: 30, Version: [4]byte{5, 0, 0, 0x10}})
	prev, _ := s.GroupHash(GroupOpen)
	return UpdateBody{Group: GroupOpen, Version: 1, PrevHash: prev, ActivateAt: 1_800_000_000, Open: &o}
}

// rotation moves the set to keys 2, 3, 4 with k = 2.
func rotationBody(s *Setup) UpdateBody {
	b := lockedBody(s)
	b.Locked.Approvers = ApproverSet{Keys: [][32]byte{approverPub(2), approverPub(3), approverPub(4)}, ApprovalsNeeded: 2}
	return b
}

func TestUpdateRoundTrip(t *testing.T) {
	s := samples(t)["setup-nitro"]
	active := &s.Locked.Approvers
	for name, u := range map[string]*Update{
		"locked":   signedUpdate(t, s, lockedBody(s), []byte{0, 2}, nil),
		"open":     signedUpdate(t, s, openBody(s), []byte{0, 1, 2}, nil),
		"rotation": signedUpdate(t, s, rotationBody(s), []byte{1, 2}, []byte{2, 3, 4}),
	} {
		b, err := u.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := DecodeUpdate(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !reflect.DeepEqual(got, u) {
			t.Fatalf("%s: decoded %+v, want %+v", name, got, u)
		}
		if err := got.Verify(active); err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if err := got.Body.Matches(s); err != nil {
			t.Fatal(err)
		}
		text, err := u.Format()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseUpdate(name, text)
		if err != nil {
			t.Fatalf("%s: parse: %v\n%s", name, err, text)
		}
		if !reflect.DeepEqual(parsed, u) {
			t.Fatalf("%s: parsed %+v, want %+v", name, parsed, u)
		}
		body := must(u.Body.Encode())
		gotBody, err := DecodeUpdateBody(body)
		if err != nil || !reflect.DeepEqual(*gotBody, u.Body) {
			t.Fatalf("%s: body: %v", name, err)
		}
		btext := must(u.Body.Format())
		pb, err := ParseUpdateBody(name, btext)
		if err != nil || !reflect.DeepEqual(*pb, u.Body) {
			t.Fatalf("%s: body text: %v", name, err)
		}
		h, _ := u.Body.Hash()
		header := must(u.Body.Header())
		root, _ := u.Body.GroupRoot()
		uh, err := UpdateHash(body)
		if err != nil || h != uh || h != CtxConfigUpdate.Hash(header) || len(header) != HeaderLen ||
			!bytes.Equal(header, HeaderOf(u.Body.ClusterID, u.Body.ChainHash, u.Body.Group, u.Body.Version, u.Body.PrevHash, u.Body.ActivateAt, root)) {
			t.Fatalf("%s: update hash: %v", name, err)
		}
	}
}

func TestUpdateRefusals(t *testing.T) {
	s := samples(t)["setup-nitro"]
	active := &s.Locked.Approvers
	other := samples(t)["setup-azure"]
	other.ClusterID[0]++
	cases := []struct {
		name string
		u    func() *Update
		want string
	}{
		{"one signature, k is 2", func() *Update { return signedUpdate(t, s, lockedBody(s), []byte{1}, nil) }, "1 approver signatures, approvals_needed is 2"},
		{"bad signature", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Approvals[1].Signature[5] ^= 1
			return u
		}, "approver 1 does not verify"},
		{"signature by a key not in the set", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Approvals[1].Signature = signedUpdate(t, s, lockedBody(s), []byte{6}, nil).Approvals[0].Signature
			return u
		}, "approver 1 does not verify"},
		{"position outside the active set", func() *Update { return signedUpdate(t, s, lockedBody(s), []byte{0, 5}, nil) }, "approver 5, the active set has 3"},
		{"position above 7", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Approvals[1].Position = 8
			return u
		}, "position 8"},
		{"same approver twice", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 0}, nil)
			return u
		}, "ascending position order"},
		{"positions descending", func() *Update { return signedUpdate(t, s, lockedBody(s), []byte{1, 0}, nil) }, "ascending position order"},
		{"no signatures", func() *Update { return signedUpdate(t, s, lockedBody(s), nil, nil) }, "0 approver signatures"},
		{"9 signatures", func() *Update { return signedUpdate(t, s, lockedBody(s), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, nil) }, "9 approver signatures"},
		{"rotation without the new set", func() *Update { return signedUpdate(t, s, rotationBody(s), []byte{0, 1}, nil) }, "every key of the new set"},
		{"rotation with part of the new set", func() *Update { return signedUpdate(t, s, rotationBody(s), []byte{0, 1}, []byte{2, 3}) }, "2 new-set signatures for 3 new keys"},
		{"rotation with a wrong new key", func() *Update { return signedUpdate(t, s, rotationBody(s), []byte{0, 1}, []byte{2, 3, 5}) }, "new key 2 does not verify"},
		{"rotation signed by the new set only", func() *Update {
			// Keys 2, 3 and 4 sign as positions 0 and 1 of the active set:
			// position 0 is key 1, so the signature by key 2 fails.
			u := signedUpdate(t, s, rotationBody(s), nil, []byte{2, 3, 4})
			u.Approvals = []Approval{u.NewSet[0], u.NewSet[1]}
			return u
		}, "approver 0 does not verify"},
		{"approvals_needed change is a rotation", func() *Update {
			b := lockedBody(s)
			b.Locked.Approvers.ApprovalsNeeded = 3
			return signedUpdate(t, s, b, []byte{0, 1}, nil)
		}, "every key of the new set"},
		{"new set on a plain update", func() *Update { return signedUpdate(t, s, lockedBody(s), []byte{0, 1}, []byte{1, 2, 3}) }, "keeps the approver set"},
		{"new set on an open update", func() *Update {
			u := signedUpdate(t, s, openBody(s), []byte{0, 1}, nil)
			u.NewSet = []Approval{{Position: 0}}
			return u
		}, "new-set signatures on an open update"},
		{"new set out of order", func() *Update {
			u := signedUpdate(t, s, rotationBody(s), []byte{0, 1}, []byte{2, 3, 4})
			u.NewSet[0], u.NewSet[1] = u.NewSet[1], u.NewSet[0]
			return u
		}, "positions 0 to n-1"},
		{"version 0", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.Version = 0
			return u
		}, "version 0"},
		{"cluster id zero", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.ClusterID = [32]byte{}
			return u
		}, "cluster_id is zero"},
		{"body changed after signing", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.ActivateAt++
			return u
		}, "approver 0 does not verify"},
		{"group 3", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.Group = 3
			return u
		}, "group 3"},
		{"both groups", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			o := sampleOpen()
			u.Body.Open = &o
			return u
		}, "locked group only"},
		{"bad group value", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.Locked.Approvers.ApprovalsNeeded = 1
			return u
		}, "approvals_needed is 1"},
		{"salt changed after signing", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.Salts = slices.Clone(u.Body.Salts)
			u.Body.Salts[7][0] ^= 1
			return u
		}, "approver 0 does not verify"},
		{"value changed after signing", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.Locked.BuilderGasLimitMax++
			return u
		}, "approver 0 does not verify"},
		{"salt missing", func() *Update {
			u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
			u.Body.Salts = u.Body.Salts[:18]
			return u
		}, "update: 18 salts"},
	}
	for _, c := range cases {
		u := c.u()
		if err := u.Verify(active); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: verify: got %v, want %q", c.name, err, c.want)
		}
	}

	u := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
	if err := u.Body.Matches(other); err == nil || !strings.Contains(err.Error(), "cluster_id") {
		t.Fatalf("other cluster: %v", err)
	}
	other.ClusterID = s.ClusterID
	other.Chain.GenesisTime++
	if err := u.Body.Matches(other); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("other chain: %v", err)
	}
	// A signature under another context does not verify.
	h := must(u.Body.Header())
	u.Approvals[0].Signature = [64]byte(ed25519.Sign(approverKey(1), CtxHandoverOrder.Message(h)))
	if err := u.Verify(active); err == nil {
		t.Fatal("a signature under the handover context verified")
	}
}

// Every shorter prefix and every longer form of a signed update is refused,
// and the decoder refuses what the encoder would.
func TestDecodeUpdateBytes(t *testing.T) {
	s := samples(t)["setup-nitro"]
	u := signedUpdate(t, s, rotationBody(s), []byte{0, 1}, []byte{2, 3, 4})
	b := must(u.Encode())
	for i := range len(b) {
		if _, err := DecodeUpdate(b[:i]); err == nil {
			t.Fatalf("%d-byte prefix accepted", i)
		}
	}
	body := must(u.Body.Encode())
	for i := range len(body) {
		if _, err := DecodeUpdateBody(body[:i]); err == nil {
			t.Fatalf("%d-byte body prefix accepted", i)
		}
	}
	set := func(src []byte, off int, v byte) []byte {
		c := slices.Clone(src)
		c[off] = v
		return c
	}
	sigsAt := 2 + 4 + len(body)
	raw := func(u *Update) []byte {
		w := &writer{}
		u.write(w)
		return w.b
	}
	dup := signedUpdate(t, s, lockedBody(s), []byte{0, 1}, nil)
	dup.Approvals[1].Position = 0
	ob := must(signedUpdate(t, s, openBody(s), []byte{0, 1}, nil).Body.Encode())
	cases := []struct {
		name string
		b    []byte
		body bool
		want string
	}{
		{"trailing", append(slices.Clone(b), 0), false, "trailing"},
		{"body trailing", append(slices.Clone(body), 0), true, "trailing"},
		{"kind", set(b, 0, 'B'), false, "not a config update"},
		{"version", set(b, 1, 2), false, "version 2"},
		{"body kind", set(body, 0, 'U'), true, "not a config update body"},
		{"body version", set(body, 1, 2), true, "version 2"},
		{"body zero salt", append(slices.Clone(body[:len(body)-32]), make([]byte, 32)...), true, "update: salt 18 is zero"},
		{"body length too large", set(b, 2, 0x7f), false, "at most 65536"},
		{"oversize", make([]byte, MaxUpdate+1), false, "at most 65536"},
		{"group 0", set(body, 66, 0), true, "unknown group 0"},
		{"group 3", set(body, 66, 3), true, "unknown group 3"},
		{"approver count 9", set(body, 115, 9), true, "9 approvers, at most 8"},
		{"fork count 17", set(ob, 115, 17), true, "17 fork_schedule entries, at most 16"},
		{"sig count 9", set(b, sigsAt, 9), false, "9 approver signatures, at most 8"},
		{"sig count 0", append(set(b[:sigsAt+1], sigsAt, 0), 0), false, "0 approver signatures"},
		{"repeated position", raw(dup), false, "ascending position order"},
	}
	for _, c := range cases {
		var err error
		if c.body {
			_, err = DecodeUpdateBody(c.b)
		} else {
			_, err = DecodeUpdate(c.b)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	got, err := DecodeUpdate(b)
	if err != nil || !bytes.Equal(must(got.Encode()), b) {
		t.Fatalf("re-encode: %v", err)
	}
}

// A hash-then-sign signature counts like a direct one, for the active set
// and for the new set of a rotation; one made under another kind's hashed
// context does not.
func TestUpdateHashedSignature(t *testing.T) {
	s := samples(t)["setup-nitro"]
	u := signedUpdate(t, s, lockedBody(s), []byte{0, 2}, nil)
	var err error
	if u.Approvals[1].Signature, err = u.Body.SignHashed(approverKey(3)); err != nil {
		t.Fatal(err)
	}
	if err := u.Verify(&s.Locked.Approvers); err != nil {
		t.Fatalf("direct and hashed: %v", err)
	}
	header, _ := u.Body.Header()
	u.Approvals[1].Signature = SignApproval(approverKey(3), CtxImportOrder, true, header)
	if err := u.Verify(&s.Locked.Approvers); err == nil {
		t.Fatal("a signature under the DKG order's hashed context verified")
	}
	r := signedUpdate(t, s, rotationBody(s), []byte{0, 1}, []byte{2, 3, 4})
	if r.NewSet[0].Signature, err = r.Body.SignHashed(approverKey(2)); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(&s.Locked.Approvers); err != nil {
		t.Fatalf("rotation with a hashed new-set signature: %v", err)
	}
}
