package core

/*
#include "signer_core.h"
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The C trampolines in core_cb.c call these with the cgo.Handle stored in
// sc_host_ops.ctx. They run on the goroutine that called into the core,
// which holds Signer.mu, so they must not call back into the Signer.

func stateOf(h C.uintptr_t) *hookState { return cgo.Handle(h).Value().(*hookState) }

func pubkeyOf(p *C.uint8_t) backend.Pubkey {
	var pk backend.Pubkey
	copy(pk[:], unsafe.Slice((*byte)(unsafe.Pointer(p)), len(pk)))
	return pk
}

//export scgoLoadWatermark
func scgoLoadWatermark(h C.uintptr_t, pubkey *C.uint8_t, out *C.sc_watermark) C.int {
	st := stateOf(h)
	wm, found, err := st.hooks.LoadWatermark(pubkeyOf(pubkey))
	if err != nil {
		st.lastErr = err
		return C.SC_ERR_STORAGE
	}
	if !found {
		return C.SC_ERR_UNKNOWN_VALIDATOR
	}
	*out = toC(wm)
	return C.SC_OK
}

//export scgoStoreWatermark
func scgoStoreWatermark(h C.uintptr_t, pubkey *C.uint8_t, wm *C.sc_watermark) C.int {
	st := stateOf(h)
	if err := st.hooks.StoreWatermark(pubkeyOf(pubkey), fromC(*wm)); err != nil {
		st.lastErr = err
		return C.SC_ERR_STORAGE
	}
	return C.SC_OK
}

//export scgoNow
func scgoNow(h C.uintptr_t, out *C.uint64_t) C.int {
	st := stateOf(h)
	t, err := st.hooks.Now()
	if err != nil {
		st.lastErr = err
		return C.SC_ERR_CLOCK
	}
	if t == 0 {
		st.lastErr = errors.New("clock returned 0")
		return C.SC_ERR_CLOCK
	}
	*out = C.uint64_t(t)
	return C.SC_OK
}

//export scgoLoadDeviceMark
func scgoLoadDeviceMark(h C.uintptr_t, out *C.sc_watermark) C.int {
	st := stateOf(h)
	dh, ok := st.hooks.(DeviceMarkHooks)
	if !ok {
		st.lastErr = errors.New("hooks do not keep a device mark")
		return C.SC_ERR_STORAGE
	}
	wm, found, err := dh.LoadDeviceMark()
	if err != nil {
		st.lastErr = err
		return C.SC_ERR_STORAGE
	}
	if !found {
		return C.SC_ERR_UNKNOWN_VALIDATOR
	}
	*out = toC(wm)
	return C.SC_OK
}

//export scgoStoreDeviceMark
func scgoStoreDeviceMark(h C.uintptr_t, wm *C.sc_watermark) C.int {
	st := stateOf(h)
	dh, ok := st.hooks.(DeviceMarkHooks)
	if !ok {
		st.lastErr = errors.New("hooks do not keep a device mark")
		return C.SC_ERR_STORAGE
	}
	if err := dh.StoreDeviceMark(fromC(*wm)); err != nil {
		st.lastErr = err
		return C.SC_ERR_STORAGE
	}
	return C.SC_OK
}
