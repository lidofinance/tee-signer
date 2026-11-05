package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform-aws/cmd/internal/metrics"
	"github.com/lidofinance/tee-signer/platform-aws/hostagent"
)

const described = `[
  {
    "EnclaveName": "runner",
    "EnclaveID": "i-0abc-enc0123",
    "ProcessID": 4242,
    "EnclaveCID": 16,
    "NumberOfCPUs": 2,
    "CPUIDs": [1, 3],
    "MemoryMiB": 512,
    "State": "RUNNING",
    "Flags": "NONE",
    "Measurements": {"HashAlgorithm": "Sha384 { ... }", "PCR0": "aa11", "PCR1": "bb", "PCR2": "cc"}
  }
]`

// The enclave state comes from describe-enclaves and the start time of
// its process from /proc; a failed run counts as an error and leaves the
// state out.
func TestEnclaveMetrics(t *testing.T) {
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	// starttime (field 22) is 12345 ticks: 123 s after boot.
	os.WriteFile(filepath.Join(proc, "4242", "stat"), []byte("4242 (nitro-cli (x)) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu 1 2 3\nbtime 1700000000\n"), 0o644)
	var out string
	var err error
	e := &enclaveState{procDir: proc, run: func(context.Context) ([]byte, error) { return []byte(out), err }}

	out = described
	var w metrics.Writer
	e.write(&w)
	want := `# HELP signer_enclave_describe_errors_total nitro-cli describe-enclaves runs that failed.
# TYPE signer_enclave_describe_errors_total counter
signer_enclave_describe_errors_total 0
# HELP signer_enclave_running 1 if describe-enclaves lists an enclave in state RUNNING.
# TYPE signer_enclave_running gauge
signer_enclave_running 1
# HELP signer_enclave_info Each enclave describe-enclaves lists.
# TYPE signer_enclave_info gauge
signer_enclave_info{enclave_id="i-0abc-enc0123",name="runner",cid="16",state="RUNNING",pcr0="aa11"} 1
# HELP signer_enclave_cpus vCPUs of the enclave.
# TYPE signer_enclave_cpus gauge
signer_enclave_cpus{enclave_id="i-0abc-enc0123"} 2
# HELP signer_enclave_memory_bytes Memory of the enclave.
# TYPE signer_enclave_memory_bytes gauge
signer_enclave_memory_bytes{enclave_id="i-0abc-enc0123"} 536870912
# HELP signer_enclave_start_time_seconds Start time of the process that runs the enclave, Unix seconds.
# TYPE signer_enclave_start_time_seconds gauge
signer_enclave_start_time_seconds{enclave_id="i-0abc-enc0123"} 1700000123
`
	if got := w.String(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}

	out = "[]"
	w = metrics.Writer{}
	e.write(&w)
	if got := w.String(); !strings.Contains(got, "\nsigner_enclave_running 0\n") || strings.Contains(got, "signer_enclave_info") {
		t.Fatalf("no enclave:\n%s", got)
	}

	err = errors.New("no nitro device")
	w = metrics.Writer{}
	e.write(&w)
	if got := w.String(); !strings.Contains(got, "\nsigner_enclave_describe_errors_total 1\n") || strings.Contains(got, "signer_enclave_running") {
		t.Fatalf("failed run:\n%s", got)
	}
}

func TestAgentMetrics(t *testing.T) {
	var w metrics.Writer
	writeAgentMetrics(&w, hostagent.Stats{
		Connections: 3, Open: 1,
		Requests:    map[[2]string]uint64{{"setup", "ok"}: 1, {"creds", "ok"}: 4, {"creds", "error"}: 2},
		CredsExpiry: time.Unix(1700003600, 0),
	}, time.Unix(1700000000, 0))
	for _, line := range []string{
		"signer_hostagent_start_time_seconds 1700000000",
		"signer_hostagent_connections_total 3",
		"signer_hostagent_connections_open 1",
		`signer_hostagent_requests_total{kind="creds",result="error"} 2`,
		`signer_hostagent_requests_total{kind="creds",result="ok"} 4`,
		`signer_hostagent_requests_total{kind="setup",result="ok"} 1`,
		"signer_hostagent_credentials_expiry_timestamp_seconds 1700003600",
	} {
		if !strings.Contains(w.String(), "\n"+line+"\n") {
			t.Errorf("missing %q in\n%s", line, w.String())
		}
	}
}
