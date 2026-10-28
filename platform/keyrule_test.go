package platform

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// ReadKeyRule: on mainnet only a locked rule or an accepted platform
// without a lock passes, never the dev platform (no real attestation); a rule that is not locked or not readable stops the start. Off
// mainnet every rule passes and a failed read gives unread, as before.
// Without a setup nothing is read.
func TestReadKeyRule(t *testing.T) {
	setup := [32]byte{1}
	read := func(r KeyRule, err error) func(context.Context) (KeyRule, error) {
		return func(ctx context.Context) (KeyRule, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("the read runs without a deadline")
			}
			return r, err
		}
	}
	locked := KeyRule{Hash: [32]byte{7}, Lock: backend.KeyLockLocked}
	open := KeyRule{Hash: [32]byte{8}, Lock: backend.KeyLockNotLocked, Why: "statement Admin allows kms:PutKeyPolicy"}
	none := KeyRule{Lock: backend.KeyLockNone, Why: "gcp"}
	denied := errors.New("AccessDeniedException")
	devNone := KeyRule{Lock: backend.KeyLockNone, Why: "dev", NoService: true}
	for _, c := range []struct {
		name    string
		mainnet bool
		accept  bool
		r       KeyRule
		err     error
		want    backend.KeyLock
		refuse  string
	}{
		{"mainnet locked", true, false, locked, nil, backend.KeyLockLocked, ""},
		{"mainnet no lock possible", true, false, none, nil, 0, "has no lock on the rule of the key"},
		{"mainnet no lock possible, accepted", true, true, none, nil, backend.KeyLockNone, ""},
		{"mainnet dev", true, false, devNone, nil, 0, "the dev platform has no real attestation"},
		{"mainnet dev, no_lock_accepted", true, true, devNone, nil, 0, "the dev platform has no real attestation"},
		{"testnet dev", false, false, devNone, nil, backend.KeyLockNone, ""},
		{"mainnet not locked, no_lock_accepted", true, true, open, nil, 0, "is not locked"},
		{"mainnet not locked", true, false, open, nil, 0, "is not locked, and the runner does not start: statement Admin allows kms:PutKeyPolicy"},
		{"mainnet unread", true, false, KeyRule{}, denied, 0, "cannot read the rule of the key that releases its sealing key"},
		{"testnet locked", false, false, locked, nil, backend.KeyLockLocked, ""},
		{"testnet no lock possible", false, false, none, nil, backend.KeyLockNone, ""},
		{"testnet not locked", false, false, open, nil, backend.KeyLockNotLocked, ""},
		{"testnet unread", false, false, KeyRule{Hash: [32]byte{9}}, denied, backend.KeyLockUnread, ""},
	} {
		o := Options{SetupHash: setup, Mainnet: c.mainnet, NoLockAccepted: c.accept}
		got, err := o.ReadKeyRule(context.Background(), read(c.r, c.err))
		if c.refuse != "" {
			if err == nil || !strings.Contains(err.Error(), c.refuse) || !strings.HasPrefix(err.Error(), "mainnet: ") {
				t.Errorf("%s: %+v %v, want a refusal with %q", c.name, got, err, c.refuse)
			}
			continue
		}
		if err != nil || got == nil || got.Lock != c.want {
			t.Errorf("%s: %+v %v, want %s", c.name, got, err, c.want)
			continue
		}
		if c.err != nil && (got.Hash != [32]byte{} || got.Why != c.err.Error()) {
			t.Errorf("%s: a failed read gave %+v", c.name, got)
		}
	}
	calls := 0
	got, err := Options{Mainnet: true}.ReadKeyRule(context.Background(), func(context.Context) (KeyRule, error) { calls++; return open, nil })
	if got != nil || err != nil || calls != 0 {
		t.Fatalf("flag path: %+v %v after %d reads", got, err, calls)
	}
}

// CheckKeyRule counts a platform that read nothing as unread.
func TestCheckKeyRuleNil(t *testing.T) {
	if err := (Options{Mainnet: true}).CheckKeyRule(nil); err == nil || !strings.Contains(err.Error(), "read no key rule") {
		t.Fatalf("mainnet, nothing read: %v", err)
	}
	if err := (Options{}).CheckKeyRule(nil); err != nil {
		t.Fatalf("testnet, nothing read: %v", err)
	}
}
