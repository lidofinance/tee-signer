//go:build !debugimport

// Release build: no plaintext share import. IMPORT_SHARE gets the same
// answer as any message type the runner does not know. Shares arrive only
// as IMPORT_SHARE_SEALED. plainimport.go is the debug-build counterpart.

package server

import (
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// DebugImport is empty in a release build.
type DebugImport struct{}

// otherMessage answers every remaining type as unknown. An IMPORT_SHARE
// payload carries a share in plain text, so it is wiped first.
func (s *Server) otherMessage(f wire.Frame) ([]byte, error) {
	if f.Type == wireadmin.TypeImportShare {
		clear(f.Payload)
	}
	return nil, unknownType(f)
}
