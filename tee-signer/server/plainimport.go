//go:build debugimport

// Plaintext share import (IMPORT_SHARE) exists only in debug builds
// (go build -tags debugimport), the way the signer TA keeps IMPORT_KEY to
// its debug build (DESIGN-INVARIANTS.md, 9). Release builds, and every
// cloud image, do not compile this file; see noplainimport.go.

package server

import (
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// DebugImport is the plaintext import setting of a debug build.
type DebugImport struct {
	// AllowImport accepts plaintext IMPORT_SHARE. main allows it only on
	// the dev platform.
	AllowImport bool
}

// otherMessage serves IMPORT_SHARE when AllowImport is set.
func (s *Server) otherMessage(f wire.Frame) ([]byte, error) {
	if f.Type != wireadmin.TypeImportShare {
		return nil, unknownType(f)
	}
	if !s.AllowImport {
		clear(f.Payload)
		return nil, backend.Refused(backend.StatusUnsupported, "plaintext share import is disabled (debug build, dev platform with -allow-import only; use IMPORT_SHARE_SEALED)")
	}
	req, err := wireadmin.DecodeImport(f.Payload)
	clear(f.Payload)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	k, err := s.addShare(req.Pubkey, &req.Secret, req.Index, req.Interchange, "plaintext")
	clear(req.Secret[:])
	if err != nil {
		return nil, err
	}
	return wire.AppendKey(nil, k), nil
}
