package azure

// The SEV-SNP attestation report and the hardware behind it.
//
// Sources, all from microsoft/confidential-sidecar-containers (MIT):
//   - pkg/attest/attestation_report_fetcher.go: report layout constants,
//     the two driver generations and their ioctl structs;
//   - pkg/attest/snp_device.go: the device paths /dev/sev (kernel 5.x
//     driver) and /dev/sev-guest (kernel 6.x driver);
//   - pkg/attest/attest.go (GenerateMAAReportData): report data is the
//     SHA-256 of the runtime data, padded with zeros to 64 bytes.
//
// Microsoft's page "Secure Key Release with Azure Key Vault and
// Confidential Containers on Azure Container Instance" says a custom
// application fetches the raw report "by doing a IOCTL Linux Socket call"
// and needs no guest attestation library. The code here is our own.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Layout of ATTESTATION_REPORT (AMD SEV-SNP firmware ABI specification,
// table 21), as far as the runner reads it.
const (
	reportSize        = 1184
	reportDataSize    = 64
	reportDataOffset  = 80
	hostDataOffset    = 192
	reportedTCBOffset = 384
)

// ReportSource gives the raw SEV-SNP attestation report of this VM. The
// hardware implementation talks to the guest device; tests use a fake.
type ReportSource interface {
	// Report returns the report (reportSize bytes) whose REPORT_DATA field
	// holds reportData.
	Report(reportData [reportDataSize]byte) ([]byte, error)
}

// runtimeReportData is the REPORT_DATA that binds runtime data: its
// SHA-256 in the first 32 bytes, zeros after. MAA and the verifier in
// attest/azureid compute the same value.
func runtimeReportData(runtimeData []byte) [reportDataSize]byte {
	var rd [reportDataSize]byte
	sum := sha256.Sum256(runtimeData)
	copy(rd[:], sum[:])
	return rd
}

// checkReport makes sure a report is what the runner asked for before it
// goes anywhere: the right size and its REPORT_DATA equal to the one
// requested. It returns the TCB version the report states, which selects
// the VCEK certificate.
func checkReport(report []byte, want [reportDataSize]byte) (reportedTCB uint64, err error) {
	if len(report) != reportSize {
		return 0, fmt.Errorf("azure: SNP report has %d bytes, want %d", len(report), reportSize)
	}
	if !bytes.Equal(report[reportDataOffset:reportDataOffset+reportDataSize], want[:]) {
		return 0, fmt.Errorf("azure: the SNP report does not carry the report data that was asked for")
	}
	return binary.LittleEndian.Uint64(report[reportedTCBOffset:]), nil
}
