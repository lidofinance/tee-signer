//go:build linux && (amd64 || arm64)

package azure

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/lidofinance/tee-signer/platform"
)

// The ioctl structs must have the layout of the kernel's, byte for byte,
// because the driver reads them from raw memory. The sizes and the ioctl
// numbers are those in the sidecar (PAYLOAD_SIZE 40 and 32,
// SNP_GET_REPORT_IOCTL_REQ_CODE_5 3223868161 and _6 3223343872).
func TestSNPIoctlLayout(t *testing.T) {
	var o guestRequestOld
	if s := unsafe.Sizeof(o); s != 40 {
		t.Errorf("old request is %d bytes, want 40", s)
	}
	for _, f := range []struct {
		name      string
		got, want uintptr
	}{
		{"request_len", unsafe.Offsetof(o.requestLen), 4},
		{"request_uaddr", unsafe.Offsetof(o.requestAddr), 8},
		{"response_len", unsafe.Offsetof(o.responseLen), 16},
		{"response_uaddr", unsafe.Offsetof(o.responseAddr), 24},
		{"error", unsafe.Offsetof(o.fwErr), 32},
	} {
		if f.got != f.want {
			t.Errorf("old request: %s at %d, want %d", f.name, f.got, f.want)
		}
	}
	var n guestRequestNew
	if s := unsafe.Sizeof(n); s != 32 {
		t.Errorf("new request is %d bytes, want 32", s)
	}
	for _, f := range []struct {
		name      string
		got, want uintptr
	}{
		{"req_data", unsafe.Offsetof(n.reqData), 8},
		{"resp_data", unsafe.Offsetof(n.respData), 16},
		{"fw_err", unsafe.Offsetof(n.fwErr), 24},
	} {
		if f.got != f.want {
			t.Errorf("new request: %s at %d, want %d", f.name, f.got, f.want)
		}
	}
	if ioctlReportOld != 3223868161 {
		t.Errorf("old ioctl %d, want 3223868161", uint64(ioctlReportOld))
	}
	if ioctlReportNew != 3223343872 {
		t.Errorf("new ioctl %d, want 3223343872", uint64(ioctlReportNew))
	}
}

func TestSNPDeviceMissing(t *testing.T) {
	if exists(snpDeviceOld) || exists(snpDeviceNew) {
		t.Skip("this machine has an SNP guest device")
	}
	_, err := newDeviceReports().Report([reportDataSize]byte{})
	if err == nil || !strings.Contains(err.Error(), "no SEV-SNP guest device") {
		t.Fatalf("got %v", err)
	}
}

// A runner outside an SNP VM stops at the first report it needs, before any
// network call, and says why.
func TestNewWithoutHardware(t *testing.T) {
	if exists(snpDeviceOld) || exists(snpDeviceNew) {
		t.Skip("this machine has an SNP guest device")
	}
	if len(debugOptions) > 0 {
		t.Skip("the debug build can fake the hardware")
	}
	_, err := New(platform.Options{StateDir: t.TempDir(), Params: map[string]string{
		"maa_endpoint": "127.0.0.1:1", "akv_endpoint": "127.0.0.1:2", "kid": "signer-kek-1"}})
	if err == nil || !strings.Contains(err.Error(), "no SEV-SNP guest device") {
		t.Fatalf("got %v", err)
	}
}
