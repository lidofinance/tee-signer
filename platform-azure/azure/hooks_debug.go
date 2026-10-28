//go:build debugimport

package azure

// Debug build only (-tags platform_azure,debugimport, the
// runner-azure-debugimport binary): two options that let a test run the
// whole Azure flow on a machine without SEV-SNP hardware and without the
// Azure metadata service.
// Release builds have neither (hooks_release.go), so a measured command
// line of the real image cannot carry them.
//
//	test_snp_hostdata=<64 hex>  a fake SNP report with this HOST_DATA, the
//	                            runtime-data hash in REPORT_DATA and the
//	                            TCB version debugFakeTCB
//	test_imds_url=<URL>         the token endpoint instead of the
//	                            instance metadata service
//
// attest/runnerclient/azure_e2e_test.go uses both.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/lidofinance/tee-signer/platform"
)

// debugFakeTCB is the TCB version of the fake report. The host certificate JSON
// of the e2e test carries it as the hex string tcbm "1c01000000000004".
const debugFakeTCB = 0x1c01000000000004

var debugOptions = []string{"test_snp_hostdata", "test_imds_url"}

type fakeReports struct{ hostData []byte }

func (f fakeReports) Report(rd [reportDataSize]byte) ([]byte, error) {
	r := make([]byte, reportSize)
	binary.LittleEndian.PutUint32(r[0:], 2) // report version
	copy(r[reportDataOffset:], rd[:])
	copy(r[hostDataOffset:], f.hostData)
	binary.LittleEndian.PutUint64(r[reportedTCBOffset:], debugFakeTCB)
	return r, nil
}

func hardwareFor(o platform.Options) (ReportSource, string, error) {
	rs := newDeviceReports()
	if hd := o.Param("test_snp_hostdata", ""); hd != "" {
		b, err := hex.DecodeString(hd)
		if err != nil || len(b) != 32 {
			return nil, "", errors.New("azure: test_snp_hostdata must be 64 hex digits")
		}
		rs = fakeReports{hostData: b}
	}
	return rs, o.Param("test_imds_url", ""), nil
}
