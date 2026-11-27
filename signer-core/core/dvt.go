//go:build dvt

package core

// The DVT build of the binding: the core built with -DSC_DVT
// (libsigner_core_dvt.a, scripts/build-core.sh with DVT=1) and
// AddValidatorGroup. This file is the only Go code that declares
// sc_signer_add_validator_group (SC_DVT in signer_core.h), so a dvt build
// linked against the default core fails at link time.

/*
#cgo CFLAGS: -DSC_DVT
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lsigner_core_dvt -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lsigner_core_dvt -lblst
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lsigner_core_dvt -lblst
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lsigner_core_dvt -lblst
#include <stdlib.h>
#include <string.h>
#include "signer_core.h"
*/
import "C"

import (
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// AddValidatorGroup is AddValidator for a share of a distributed validator
// (sc_signer_add_validator_group): pubkey is the share's own key, the key
// requests name, and group the validator's on-chain key. Aggregates and
// contributions must carry a selection proof by group, and a registration
// may name group. A group key that is not a G1 point is refused
// (StatusBadKey) and nothing loads. The steps after the C call are those
// of AddValidator in core.go; a change to one belongs in both, and
// TestAddValidatorGroupMatchesAddValidator fails when they part.
func (s *Signer) AddValidatorGroup(pubkey backend.Pubkey, secret [32]byte, index uint64,
	interchange *backend.Watermark, group backend.Pubkey) (backend.ValidatorKey, error) {
	defer clear(secret[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return backend.ValidatorKey{}, ErrClosed
	}
	s.state.lastErr = nil
	sec := (*[32]byte)(C.malloc(32))
	defer func() {
		C.memset(unsafe.Pointer(sec), 0, 32)
		C.free(unsafe.Pointer(sec))
	}()
	*sec = secret
	var share [48]byte
	rc := C.sc_signer_add_validator_group(s.s, u8(pubkey[:]), (*C.uint8_t)(unsafe.Pointer(sec)), C.uint64_t(index), u8(group[:]), u8(share[:]))
	what := "add validator"
	if rc == C.SC_ERR_DUPLICATE && !s.hasKey(pubkey) {
		what = "add validator: this share is loaded under another pubkey"
	}
	if err := s.refusal(rc, what); err != nil {
		return backend.ValidatorKey{}, err
	}
	k := backend.ValidatorKey{Pubkey: pubkey, SharePubkey: share, Index: index}
	s.keys = append(s.keys, k)
	if interchange != nil {
		cw := toC(*interchange)
		gvr := s.cfg.GenesisValidatorsRoot
		if err := s.refusal(C.sc_signer_import(s.s, u8(pubkey[:]), u8(gvr[:]), &cw), "import"); err != nil {
			if s.unready == nil {
				s.unready = map[backend.Pubkey]error{}
			}
			s.unready[pubkey] = err
			return k, err
		}
	}
	return k, nil
}
