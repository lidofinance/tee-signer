// Package software is an in-process backend for development. It runs the
// same C signer core as the enclave runner, but keys and slashing state
// live in this process's memory and Attest returns an unsigned document.
// Never use it for real keys.
package software

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Backend implements backend.Backend in process.
type Backend struct {
	signer  *core.Signer
	cfgHash backend.Root
	started time.Time
}

var _ backend.Backend = (*Backend)(nil)

// New creates a software backend with in-memory watermarks. hooks may be
// nil for NewMemHooks().
func New(cfg core.Config, maxValidators uint32, hooks core.Hooks) (*Backend, error) {
	if hooks == nil {
		hooks = NewMemHooks()
	}
	s, err := core.NewSigner(cfg, maxValidators, 64, hooks)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(cfg)
	return &Backend{signer: s, cfgHash: sha256.Sum256(raw), started: time.Now()}, nil
}

func (b *Backend) PublicKeys(context.Context) ([]backend.ValidatorKey, error) {
	return b.signer.Keys(), nil
}

func (b *Backend) Sign(_ context.Context, req backend.SignRequest) (backend.Signature, error) {
	return b.signer.Sign(req)
}

// Attest returns a JSON document with the nonce. It proves nothing.
func (b *Backend) Attest(_ context.Context, nonce []byte) (*backend.Attestation, error) {
	doc, _ := json.Marshal(map[string]any{"platform": "software", "nonce": nonce, "config_hash": b.cfgHash})
	return &backend.Attestation{Platform: "software", Format: "software-json", UserData: nonce, Document: doc}, nil
}

func (b *Backend) Health(context.Context) (*backend.Health, error) {
	now := time.Now()
	return &backend.Health{
		Platform:    "software",
		Version:     "dev",
		Ready:       true,
		Validators:  len(b.signer.Keys()),
		ConfigHash:  b.cfgHash,
		ClockSource: "system",
		ClockUnix:   uint64(now.Unix()),
		ClockUnixMS: uint64(now.UnixMilli()),
		RestartMode: "none",
		StartedUnix: uint64(b.started.Unix()),
	}, nil
}

func (b *Backend) ImportShare(_ context.Context, req backend.ImportShareRequest) (backend.ValidatorKey, error) {
	return b.signer.AddValidator(req.Pubkey, req.Secret, req.Index, req.Interchange)
}

func (b *Backend) Close() error {
	b.signer.Close()
	return nil
}
