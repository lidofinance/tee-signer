package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func thimJSON(vcek, tcbm, chain string) string {
	b, _ := json.Marshal(map[string]string{"vcekCert": vcek, "tcbm": tcbm, "certificateChain": chain, "cacheControl": "{}"})
	return string(b)
}

func b64std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// writeContextDir makes a security context directory as hcsshim does.
func writeContextDir(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, c := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCollateralFromSecurityContextDir(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		fileReferenceInfo:        b64std("uvm reference info") + "\n",
		fileHostAMDCert:          b64std(thimJSON(testVCEK, testTCBM, testChain)),
		"security-policy-base64": b64std("package policy"),
	}
	dir := writeContextDir(t, root, "security-context-123456", files)

	// UVM_SECURITY_CONTEXT_DIR names the directory.
	h := &HostCollateral{Getenv: env(map[string]string{envSecurityContextDir: dir})}
	col, err := h.Collateral(context.Background(), testTCB)
	if err != nil {
		t.Fatal(err)
	}
	if string(col.UVMReferenceInfo) != "uvm reference info" || string(col.CertChain) != testVCEK+testChain {
		t.Fatalf("collateral %q, %q", col.UVMReferenceInfo, col.CertChain)
	}

	// Without the variable the runner finds security-context-* under the root.
	h = &HostCollateral{Getenv: env(nil), Root: root}
	col2, err := h.Collateral(context.Background(), testTCB)
	if err != nil || string(col2.CertChain) != string(col.CertChain) {
		t.Fatalf("scan: %v", err)
	}
}

func TestCollateralFromVariables(t *testing.T) {
	h := &HostCollateral{Root: t.TempDir(), Getenv: env(map[string]string{
		envReferenceInfo: b64std("from the environment"),
		envHostAMDCert:   b64std(thimJSON(testVCEK, testTCBM, testChain)),
	})}
	col, err := h.Collateral(context.Background(), testTCB)
	if err != nil || string(col.UVMReferenceInfo) != "from the environment" {
		t.Fatalf("%v, %+v", err, col)
	}
}

func TestCollateralNeedsReferenceInfo(t *testing.T) {
	dir := writeContextDir(t, t.TempDir(), "security-context-1", map[string]string{
		fileHostAMDCert: b64std(thimJSON(testVCEK, testTCBM, testChain)),
	})
	h := &HostCollateral{Getenv: env(map[string]string{envSecurityContextDir: dir})}
	_, err := h.Collateral(context.Background(), testTCB)
	if err == nil || !strings.Contains(err.Error(), "azure-compliant-uvm") {
		t.Fatalf("got %v", err)
	}
	h = &HostCollateral{Getenv: env(map[string]string{envSecurityContextDir: dir, envReferenceInfo: "!!not base64!!"})}
	if _, err := h.Collateral(context.Background(), testTCB); err == nil || !strings.Contains(err.Error(), "not base64") {
		t.Fatalf("bad base64: %v", err)
	}
}

// A host certificate for another TCB version, or none, makes the runner ask
// the host's certificate endpoint, as the sidecar does.
func TestCollateralHostEndpoint(t *testing.T) {
	var hits atomic.Int32
	var header atomic.Value
	thim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		header.Store(r.Header.Get("Metadata"))
		if r.URL.Path != "/metadata/THIM/amd/certification" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(thimJSON(testVCEK, testTCBM, testChain)))
	}))
	defer thim.Close()
	url := thim.URL + "/metadata/THIM/amd/certification"
	ref := b64std("uvm reference info")

	stale := b64std(thimJSON("old vcek\n", "0000000000000001", "old chain\n"))
	for name, certVar := range map[string]string{"stale certificate": stale, "no certificate": ""} {
		hits.Store(0)
		h := &HostCollateral{Root: t.TempDir(), THIMURL: url, HTTP: thim.Client(),
			Getenv: env(map[string]string{envReferenceInfo: ref, envHostAMDCert: certVar})}
		col, err := h.Collateral(context.Background(), testTCB)
		if err != nil || string(col.CertChain) != testVCEK+testChain {
			t.Fatalf("%s: %v", name, err)
		}
		if hits.Load() != 1 || header.Load() != "true" {
			t.Fatalf("%s: %d requests, Metadata header %v", name, hits.Load(), header.Load())
		}
	}

	// A matching certificate in the files means no request at all.
	hits.Store(0)
	h := &HostCollateral{Root: t.TempDir(), THIMURL: url, HTTP: thim.Client(),
		Getenv: env(map[string]string{envReferenceInfo: ref, envHostAMDCert: b64std(thimJSON(testVCEK, testTCBM, testChain))})}
	if _, err := h.Collateral(context.Background(), testTCB); err != nil || hits.Load() != 0 {
		t.Fatalf("matching certificate: %v, %d requests", err, hits.Load())
	}

	// The report states a TCB version that even the endpoint does not have.
	if _, err := h.Collateral(context.Background(), testTCB+1); err == nil || !strings.Contains(err.Error(), "for TCB version") {
		t.Fatalf("other TCB: %v", err)
	}
}

func TestCollateralHostEndpointFails(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 400) }))
	defer down.Close()
	h := &HostCollateral{Root: t.TempDir(), THIMURL: down.URL, HTTP: down.Client(),
		Getenv: env(map[string]string{envReferenceInfo: b64std("ref")})}
	if _, err := h.Collateral(context.Background(), testTCB); err == nil || !strings.Contains(err.Error(), "host endpoint failed") {
		t.Fatalf("got %v", err)
	}
}

func TestJoinPEMAddsNewline(t *testing.T) {
	if got := joinPEM("a", "b\n"); got != "a\nb\n" {
		t.Fatalf("%q", got)
	}
	if got := joinPEM("a\n", "b\n"); got != "a\nb\n" {
		t.Fatalf("%q", got)
	}
}
