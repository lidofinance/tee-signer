// Package dev is the development platform: a file store, AES-GCM sealing
// under a public key (fixed, or made from setup_hash), the system clock
// (optionally offset to play a host that moves time), and an unsigned JSON
// attestation. It protects nothing and exists so the runner can be tested
// on any Linux box.
package dev

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// devKey is public on purpose: anyone with the state directory can unseal.
var devKey = sha256.Sum256([]byte("tee-signer dev sealing key v1 (NOT SECRET)"))

// NewDevKeys is the dev platform's key release: AES-GCM under a public key
// made from measurement, which stands in for the image measurement. Runners
// with the same value open each other's keys, as two runners of one image
// would; with another value they do not, as another image gets no key
// release. Like the sealer it protects nothing.
func NewDevKeys(measurement string) platform.SealerKeys {
	k := sha256.Sum256([]byte("tee-signer dev key release v1 (NOT SECRET)|" + measurement))
	s, _ := platform.NewGCMSealer(k[:])
	return platform.SealerKeys{Sealer: s}
}

// NewDevSealer uses the fixed dev key.
func NewDevSealer() *platform.GCMSealer {
	s, _ := platform.NewGCMSealer(devKey[:])
	return s
}

// NewSetupSealer is the sealer of a dev runner with a setup: a public key
// made from setup_hash, so that a runner with another setup over the same
// state directory opens nothing this one sealed, as on the cloud platforms.
// A zero setup (the flag path) gets the fixed dev key.
func NewSetupSealer(setup [32]byte) *platform.GCMSealer {
	if setup == ([32]byte{}) {
		return NewDevSealer()
	}
	k := sha256.Sum256(append([]byte("tee-signer dev setup sealing key v1 (NOT SECRET)|"), setup[:]...))
	s, _ := platform.NewGCMSealer(k[:])
	return s
}

// NewSetupKeys is the dev key release of a runner with a setup: as
// NewDevKeys, with setup_hash in the key. A zero setup gets NewDevKeys.
func NewSetupKeys(measurement string, setup [32]byte) platform.SealerKeys {
	if setup == ([32]byte{}) {
		return NewDevKeys(measurement)
	}
	k := sha256.Sum256(append([]byte("tee-signer dev setup key release v1 (NOT SECRET)|"+measurement+"|"), setup[:]...))
	s, _ := platform.NewGCMSealer(k[:])
	return platform.SealerKeys{Sealer: s}
}

// Attester returns an unsigned JSON document. Measurement is the
// measurement option, the dev stand-in for the image measurement.
type Attester struct{ Measurement string }

func (a Attester) Attest(_ context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	exe := ""
	if b, err := os.ReadFile("/proc/self/exe"); err == nil {
		exe = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	doc, err := json.Marshal(map[string]any{
		"platform":      "dev",
		"warning":       "unsigned; proves nothing",
		"nonce":         nonce,
		"user_data":     userData,
		"binary_sha256": exe,
		"measurement":   a.Measurement,
		"time":          time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	return &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: userData, Document: doc}, nil
}

// New builds the dev platform. Params: clock_offset (Go duration, e.g.
// "-30m"; simulates a host that moves the system clock), measurement (a
// stand-in for the image measurement in the key release, see NewDevKeys),
// egress (host:port list, from a setup's peer_attestation_hosts: the HTTP client
// reaches only these, see EgressClient).
// The sealer and the key release take o.SetupHash (NewSetupSealer,
// NewSetupKeys).
func New(o platform.Options) (*platform.Platform, error) {
	store, err := filestore.New(o.StateDir)
	if err != nil {
		return nil, err
	}
	var off time.Duration
	if s := o.Param("clock_offset", ""); s != "" {
		if off, err = time.ParseDuration(s); err != nil {
			return nil, fmt.Errorf("dev: clock_offset: %w", err)
		}
	}
	p := &platform.Platform{
		Name:     "dev",
		Store:    store,
		Clock:    clock.System{Offset: off},
		Attester: Attester{Measurement: o.Param("measurement", "")},
		Keys:     NewSetupKeys(o.Param("measurement", ""), o.SetupHash),
	}
	if s := o.Param("egress", ""); s != "" {
		p.HTTPClient = EgressClient(strings.Split(s, ","))
	}
	// No key release service, so no rule to lock.
	if p.KeyRule, err = o.ReadKeyRule(context.Background(), platform.NoKeyRelease("the dev platform has no key release service and no real attestation; refused on mainnet")); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if p.Store, err = o.UseDurable(ctx, p); err != nil {
		return nil, err
	}
	p.Sealer = NewSetupSealer(o.SetupHash)
	return p, nil
}
