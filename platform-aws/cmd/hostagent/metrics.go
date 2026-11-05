package main

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/platform-aws/cmd/internal/metrics"
	"github.com/lidofinance/tee-signer/platform-aws/hostagent"
)

func writeAgentMetrics(w *metrics.Writer, s hostagent.Stats, start time.Time) {
	w.Gauge("signer_hostagent_start_time_seconds", "Start time of the host agent, Unix seconds.", float64(start.Unix()))
	w.Counter("signer_hostagent_connections_total", "Connections from the enclave accepted.", float64(s.Connections))
	w.Gauge("signer_hostagent_connections_open", "Connections from the enclave open now.", float64(s.Open))
	w.Counter("signer_hostagent_read_errors_total", "Connections ended by a frame that did not read.", float64(s.ReadErrors))
	keys := slices.SortedFunc(maps.Keys(s.Requests), func(a, b [2]string) int {
		return strings.Compare(a[0]+" "+a[1], b[0]+" "+b[1])
	})
	for _, k := range keys {
		w.Counter("signer_hostagent_requests_total", "Requests from the enclave by kind and result (ok, refused, error).", float64(s.Requests[k]), "kind", k[0], "result", k[1])
	}
	if !s.CredsExpiry.IsZero() {
		w.Gauge("signer_hostagent_credentials_expiry_timestamp_seconds", "Expiry of the last credentials handed to the enclave, Unix seconds.", float64(s.CredsExpiry.Unix()))
	}
}

// enclaveState reads the enclave state with nitro-cli describe-enclaves at
// each scrape, one scrape at a time.
type enclaveState struct {
	mu      sync.Mutex
	run     func(ctx context.Context) ([]byte, error) // the JSON of describe-enclaves
	procDir string                                    // "/proc": the start time of the enclave process
	errors  uint64
}

func nitroCLI(path string) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		return exec.CommandContext(ctx, path, "describe-enclaves").Output()
	}
}

type describedEnclave struct {
	EnclaveName  string
	EnclaveID    string
	ProcessID    int
	EnclaveCID   uint64
	NumberOfCPUs int
	MemoryMiB    uint64
	State        string
	Measurements struct{ PCR0 string }
}

func (e *enclaveState) write(w *metrics.Writer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var list []describedEnclave
	out, err := e.run(ctx)
	if err == nil {
		err = json.Unmarshal(out, &list)
	}
	if err != nil {
		e.errors++
	}
	w.Counter("signer_enclave_describe_errors_total", "nitro-cli describe-enclaves runs that failed.", float64(e.errors))
	if err != nil {
		return
	}
	running := 0
	for _, x := range list {
		if x.State == "RUNNING" {
			running = 1
		}
	}
	w.Gauge("signer_enclave_running", "1 if describe-enclaves lists an enclave in state RUNNING.", float64(running))
	for _, x := range list {
		w.Info("signer_enclave_info", "Each enclave describe-enclaves lists.", "enclave_id", x.EnclaveID, "name", x.EnclaveName,
			"cid", strconv.FormatUint(x.EnclaveCID, 10), "state", x.State, "pcr0", x.Measurements.PCR0)
	}
	for _, x := range list {
		w.Gauge("signer_enclave_cpus", "vCPUs of the enclave.", float64(x.NumberOfCPUs), "enclave_id", x.EnclaveID)
	}
	for _, x := range list {
		w.Gauge("signer_enclave_memory_bytes", "Memory of the enclave.", float64(x.MemoryMiB<<20), "enclave_id", x.EnclaveID)
	}
	for _, x := range list {
		if t, ok := procStart(e.procDir, x.ProcessID); ok {
			w.Gauge("signer_enclave_start_time_seconds", "Start time of the process that runs the enclave, Unix seconds.", float64(t), "enclave_id", x.EnclaveID)
		}
	}
}

// procStart is the start time of process pid in Unix seconds, from its
// stat (field 22, clock ticks since boot, USER_HZ 100) and the boot time.
func procStart(procDir string, pid int) (int64, bool) {
	stat, err1 := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "stat"))
	sys, err2 := os.ReadFile(filepath.Join(procDir, "stat"))
	i := bytes.LastIndexByte(stat, ')')
	if err1 != nil || err2 != nil || pid <= 0 || i < 0 {
		return 0, false
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return 0, false
	}
	for line := range strings.Lines(string(sys)) {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			boot, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return boot + ticks/100, err == nil
		}
	}
	return 0, false
}
