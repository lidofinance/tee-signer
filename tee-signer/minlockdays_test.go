//go:build !nonprod

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// withLockDays is raw with slashing_log_min_lock_days set to days.
func withLockDays(t *testing.T, raw []byte, days uint32) []byte {
	t.Helper()
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.SlashingLogMinLockDays = days
	out, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The tools refuse a new prod-chain setup with slashing_log_min_lock_days
// below 7; the runner does not. A mainnet setup with 1 day, encoded before
// that rule, still starts, and the start log warns.
func TestProdSetupBelowMinLockDaysStartsWithAWarning(t *testing.T) {
	const (
		mainnetFork = "00000000"
		mainnetRoot = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
	)
	var events []string
	var opts platform.Options
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))
	fake := &fakeChannel{raw: withLockDays(t, nitroSetupOn(t, mainnetFork, mainnetRoot), 1), events: &events}
	withChannel("nitro", mainnetChannel(func() setup.Channel { return fake })(), func() {
		a := &startArgs{platformName: "nitro", setupSrc: "platform", given: map[string]string{"setup": "platform"},
			params: map[string]string{"clock": "nsm"}, stateDir: "/tmp/unused"}
		s, _, _, err := startPlatform(context.Background(), a, recordingPlatform("nitro", &events, &opts), log)
		if err != nil || !s.prod {
			t.Fatalf("start %+v: %v", s, err)
		}
	})
	if !strings.Contains(logged.String(), "level=WARN") || !strings.Contains(logged.String(), "slashing_log_min_lock_days 1 on a prod chain") {
		t.Fatalf("start log without the lock days warning:\n%s", logged.String())
	}
}

// A Hoodi setup with 1 day starts with no lock days warning: the floor of
// 7 is for prod chains only.
func TestHoodiSetupWithOneLockDayStartsWithoutAWarning(t *testing.T) {
	s, err := setupwire.DecodeSetup(sampleSetup(t, "dev-single"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisForkVersion[:], []byte("10000910")); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisValidatorsRoot[:], []byte("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")); err != nil {
		t.Fatal(err)
	}
	s.SlashingLogMinLockDays = 1
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "setup.bin")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var events []string
	var opts platform.Options
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))
	a := &startArgs{platformName: "dev", setupSrc: "file:" + path}
	st, _, _, err := startPlatform(context.Background(), a, recordingPlatform("dev", &events, &opts), log)
	if err != nil || st.prod {
		t.Fatalf("start %+v: %v", st, err)
	}
	if strings.Contains(logged.String(), "slashing_log_min_lock_days") {
		t.Fatalf("a Hoodi setup with 1 day warns:\n%s", logged.String())
	}
}
