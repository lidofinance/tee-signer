//go:build !(linux && (amd64 || arm64))

package azure

import "errors"

// The guest device exists in an x86-64 SEV-SNP VM. Other targets build for
// tests and tools only.
type noReports struct{}

func newDeviceReports() ReportSource { return noReports{} }

func (noReports) Report([reportDataSize]byte) ([]byte, error) {
	return nil, errors.New("azure: SEV-SNP reports need Linux on amd64")
}
