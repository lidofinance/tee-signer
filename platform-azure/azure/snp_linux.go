//go:build linux && (amd64 || arm64)

package azure

// The guest device of an SEV-SNP VM. ACI puts it into every non-privileged
// workload container of a confidential group: hcsshim's Host.CreateContainer
// calls AddDevSev (internal/guest/spec/spec.go), which adds /dev/sev if it
// exists and /dev/sev-guest otherwise, when the group has a CCE policy.
// UNVERIFIED on Azure: nothing here ran in an ACI confidential group.
//
// Two driver generations answer differently, and the sidecar handles both
// (pkg/attest/attestation_report_fetcher.go):
//
//   - kernel 5.x, /dev/sev: ioctl SEV_SNP_GUEST_MSG_REPORT, _IOWR('S', 1, ...)
//     with a 40-byte struct that names the message types and a 1280-byte
//     response buffer;
//   - kernel 6.x, /dev/sev-guest: ioctl SNP_GET_REPORT, _IOWR('S', 0, ...)
//     with a 32-byte struct and a 4000-byte response buffer.
//
// Both take a 96-byte MSG_REPORT_REQ (64 bytes of report data, then VMPL 0
// and zeros) and fill a MSG_REPORT_RSP: status (u32), report size (u32),
// 24 reserved bytes, then the 1184-byte report. The structs hold their
// buffer addresses as unsafe.Pointer so the garbage collector sees them.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const (
	snpDeviceOld = "/dev/sev"
	snpDeviceNew = "/dev/sev-guest"

	msgReportReq     = 5
	msgReportRsp     = 6
	reportReqSize    = 96   // MSG_REPORT_REQ
	reportRspSize    = 1280 // MSG_REPORT_RSP
	reportRspSizeNew = 4000 // snp_report_resp.data of the 6.x driver
	reportRspHeader  = 32   // status, report size, reserved
)

// guestRequestOld is struct sev_snp_guest_request of the 5.x driver.
type guestRequestOld struct {
	reqMsgType   uint8
	rspMsgType   uint8
	msgVersion   uint8
	_            uint8
	requestLen   uint16
	_            uint16
	requestAddr  unsafe.Pointer
	responseLen  uint16
	_            [3]uint16
	responseAddr unsafe.Pointer
	fwErr        uint32
	_            uint32
}

// guestRequestNew is struct snp_guest_request_ioctl of the 6.x driver.
type guestRequestNew struct {
	msgVersion uint8
	_          [7]uint8
	reqData    unsafe.Pointer
	respData   unsafe.Pointer
	fwErr      uint64
}

// Linux ioctl numbers: _IOWR(type, nr, size) is direction 3 in bits 30-31,
// the size in bits 16-29, the type in bits 8-15 and nr in bits 0-7. They
// equal the constants in the sidecar (3223868161 and 3223343872).
const (
	ioctlReportOld = 3<<30 | unsafe.Sizeof(guestRequestOld{})<<16 | 'S'<<8 | 1
	ioctlReportNew = 3<<30 | unsafe.Sizeof(guestRequestNew{})<<16 | 'S'<<8 | 0
)

// deviceReports reads reports from the guest device.
type deviceReports struct{ mu sync.Mutex }

func newDeviceReports() ReportSource { return &deviceReports{} }

func (d *deviceReports) Report(reportData [reportDataSize]byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var path string
	var old bool
	switch {
	case exists(snpDeviceOld):
		path, old = snpDeviceOld, true
	case exists(snpDeviceNew):
		path = snpDeviceNew
	default:
		return nil, fmt.Errorf("azure: no SEV-SNP guest device (%s or %s): this is not an SEV-SNP VM, or the platform gave the container no device", snpDeviceOld, snpDeviceNew)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("azure: open %s: %w", path, err)
	}
	defer syscall.Close(fd)

	req := make([]byte, reportReqSize)
	copy(req, reportData[:])
	var rsp []byte
	var errno syscall.Errno
	var fwErr uint64
	if old {
		rsp = make([]byte, reportRspSize)
		p := guestRequestOld{reqMsgType: msgReportReq, rspMsgType: msgReportRsp, msgVersion: 1,
			requestLen: reportReqSize, requestAddr: unsafe.Pointer(&req[0]),
			responseLen: reportRspSize, responseAddr: unsafe.Pointer(&rsp[0])}
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlReportOld, uintptr(unsafe.Pointer(&p)))
		fwErr = uint64(p.fwErr)
	} else {
		rsp = make([]byte, reportRspSizeNew)
		p := guestRequestNew{msgVersion: 1, reqData: unsafe.Pointer(&req[0]), respData: unsafe.Pointer(&rsp[0])}
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlReportNew, uintptr(unsafe.Pointer(&p)))
		fwErr = p.fwErr
	}
	runtime.KeepAlive(req)
	runtime.KeepAlive(rsp)
	if errno != 0 {
		return nil, fmt.Errorf("azure: SNP report ioctl on %s: %w (firmware error %#x)", path, errno, fwErr)
	}
	if status := binary.LittleEndian.Uint32(rsp[0:4]); status != 0 {
		return nil, fmt.Errorf("azure: SNP report request failed, status %d", status)
	}
	if n := binary.LittleEndian.Uint32(rsp[4:8]); n != reportSize {
		return nil, fmt.Errorf("azure: SNP report size %d, want %d", n, reportSize)
	}
	return append([]byte(nil), rsp[reportRspHeader:reportRspHeader+reportSize]...), nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}
