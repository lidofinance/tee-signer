package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// HandedOver reports that this runner handed its shares over (HANDOVER,
// handover_source.go), or read the tombstone of a handover at start (see
// ReadHandover), and signs nothing.
func (s *Server) HandedOver() bool { return s.handedOver.Load() }

// ReadHandover takes over what the mark log's claim found: a log that ends
// with a handover's tombstone. Call it once before serving.
func (s *Server) ReadHandover() {
	if s.Hooks != nil && s.Hooks.HandedOver() {
		s.handedOver.Store(true)
	}
}

// readShare unseals the stored share of pk and gives it to f; it is wiped
// after.
func (s *Server) readShare(pk backend.Pubkey, f func(rec *shareRecord, secret *[32]byte) error) error {
	blob, err := s.Platform.Store.Get(shareKey(pk))
	if err != nil {
		return err
	}
	plain, err := s.Platform.Sealer.Unseal(blob, s.shareAAD(pk))
	if err != nil {
		return fmt.Errorf("unseal share: %w", err)
	}
	var rec shareRecord
	err = json.Unmarshal(plain, &rec)
	clear(plain)
	if err != nil || rec.Pubkey != pk || len(rec.Secret) != 32 {
		clear(rec.Secret)
		return errors.New("bad share record")
	}
	var sec [32]byte
	copy(sec[:], rec.Secret)
	clear(rec.Secret)
	defer clear(sec[:])
	return f(&rec, &sec)
}

// handoverSource serves HANDOVER_ORDER and HANDOVER as a source
// (handover_source.go). A release build with a setup and the mark log has
// one (tee-signer/handover_wire.go), so every image can hand its shares
// to the next one; a debug build, or a runner without a setup, has
// neither side, and Server.handoverSrc stays nil there (both messages are
// UNSUPPORTED).
type handoverSource interface {
	order(ctx context.Context, payload []byte) ([]byte, error)
	handover(ctx context.Context, payload []byte) ([]byte, error)
}

// handoverImporter serves IMPORT_HANDOVER, the target side of HANDOVER
// (handover_import.go).
type handoverImporter interface {
	importShares(ctx context.Context, payload []byte) ([]byte, error)
}
