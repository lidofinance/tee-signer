package azure

// The Microsoft Azure Attestation (MAA) request for an SEV-SNP VM.
//
// Source: the sidecar's pkg/common/maa.go (the request structs and their
// encodings), internal/httpginendpoints/httpginendpoints.go (the endpoint
// type "SevSnpVM" and the API version), and pkg/attest/attest.go (what goes
// into each field). Microsoft's REST reference
// (https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm)
// documents the same operation as POST {instance}/attest/SevSnpVm and the
// fields report, runtimeData, initTimeData and nonce; the layout inside
// "report" is not in the reference, only in the sidecar and in the
// reference's sample request.
//
// The request, as the sidecar sends it:
//
//	POST https://<maa host>/attest/SevSnpVM?api-version=2020-10-01
//	{"report":      base64url(JSON{"SnpReport":     base64url(raw report),
//	                               "VcekCertChain": base64url(PEM chain),
//	                               "Endorsements":  base64url(JSON{"Uvm":[base64url(UVM reference info)]})}),
//	 "runtimeData": {"data": base64url(runtime data), "dataType": "JSON"},
//	 "initTimeData": {"data": "", "dataType": ""},
//	 "nonce": <random uint64>}
//
// All base64url here is the padded alphabet (Go's base64.URLEncoding), as
// in the sidecar. The answer is {"token": "<JWT>"}.
//
// The runtime data must be a JSON object: with dataType JSON, MAA puts it
// into the token as the claim x-ms-runtime. The report data in the SNP
// report is SHA-256(runtime data) and 32 zero bytes, so a verifier can tie
// the token to the exact bytes. Key Vault reads the wrapping key for a
// released key from x-ms-runtime.keys (keyvault.go).
//
// UNVERIFIED on Azure: nothing here talked to a real MAA provider. The
// API version is the one the sidecar uses (2020-10-01); Microsoft's current
// reference page is for 2022-08-01 and 2025-06-01, which this code does not
// use.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	maaTEEType     = "SevSnpVM"
	maaAPIVersion  = "api-version=2020-10-01"
	maaPathPattern = "https://%s/attest/%s?%s"
)

// MAAClient asks MAA for a token over a fresh SNP report.
type MAAClient struct {
	Endpoint   string // host of the provider, e.g. sharedweu.weu.attest.azure.net
	HTTP       *http.Client
	Reports    ReportSource
	Collateral CollateralSource
}

type maaReport struct {
	SNPReport     string `json:"SnpReport"`
	VCEKCertChain string `json:"VcekCertChain"`
	Endorsements  string `json:"Endorsements,omitempty"`
}

type maaEndorsements struct {
	Uvm []string `json:"Uvm"`
}

type maaData struct {
	Data     string `json:"data"`
	DataType string `json:"dataType"`
}

type maaRequest struct {
	Report       string  `json:"report"`
	RuntimeData  maaData `json:"runtimeData"`
	InitTimeData maaData `json:"initTimeData"`
	Nonce        uint64  `json:"nonce"`
}

// Token returns an MAA token over the runtime data, which must be a JSON
// object. It fetches a report that carries SHA-256(runtimeData), and the
// collateral for it, and sends both.
func (c *MAAClient) Token(ctx context.Context, runtimeData []byte) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal(runtimeData, &obj); err != nil || obj == nil {
		return "", fmt.Errorf("azure: runtime data must be a JSON object (%v)", err)
	}
	rd := runtimeReportData(runtimeData)
	report, err := c.Reports.Report(rd)
	if err != nil {
		return "", err
	}
	tcb, err := checkReport(report, rd)
	if err != nil {
		return "", err
	}
	col, err := c.Collateral.Collateral(ctx, tcb)
	if err != nil {
		return "", err
	}
	body, err := maaRequestBody(report, col, runtimeData)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf(maaPathPattern, c.Endpoint, maaTEEType, maaAPIVersion)
	resp, err := httpDo(ctx, c.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure: MAA: %w", err)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", fmt.Errorf("azure: MAA answer: %w", err)
	}
	if out.Token == "" {
		return "", errors.New("azure: MAA answered without a token")
	}
	return out.Token, nil
}

func maaRequestBody(report []byte, col *Collateral, runtimeData []byte) ([]byte, error) {
	b64 := base64.URLEncoding.EncodeToString
	rep := maaReport{SNPReport: b64(report), VCEKCertChain: b64(col.CertChain)}
	if len(col.UVMReferenceInfo) > 0 {
		e, err := json.Marshal(maaEndorsements{Uvm: []string{b64(col.UVMReferenceInfo)}})
		if err != nil {
			return nil, err
		}
		rep.Endorsements = b64(e)
	}
	repJSON, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	var n [8]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, err
	}
	return json.Marshal(maaRequest{
		Report:      b64(repJSON),
		RuntimeData: maaData{Data: b64(runtimeData), DataType: "JSON"},
		// The sidecar sends an empty init time data object, and so do we.
		InitTimeData: maaData{},
		Nonce:        binary.BigEndian.Uint64(n[:]),
	})
}

// reportDataClaim is what MAA states as x-ms-sevsnpvm-reportdata for
// runtime data: 64 bytes in hex.
func reportDataClaim(runtimeData []byte) string {
	rd := runtimeReportData(runtimeData)
	return hex.EncodeToString(rd[:])
}

func sameHex(a, b string) bool { return strings.EqualFold(a, b) }
