//go:build unix && !aix && !solaris

package cluster

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Two runs edit the same cloud.json at once, each many times. With the
// lock no edit is lost.
func TestEditCloudJSONConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.json")
	if err := os.WriteFile(path, []byte(`{"address":"a","attestation":{"n":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const runs, edits = 2, 50
	var wg sync.WaitGroup
	errs := make(chan error, runs*edits)
	for range runs {
		wg.Go(func() {
			for range edits {
				errs <- EditCloudJSON(path, func(att map[string]json.RawMessage) error {
					n, err := strconv.Atoi(string(att["n"]))
					if err != nil {
						return err
					}
					time.Sleep(time.Millisecond) // widen the window between read and write
					att["n"] = json.RawMessage(strconv.Itoa(n + 1))
					return nil
				})
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var top struct{ Attestation struct{ N int } }
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &top); err != nil || top.Attestation.N != runs*edits {
		t.Fatalf("n = %d after %d edits (%v)", top.Attestation.N, runs*edits, err)
	}
}

// A run that cannot get the lock in lockWait fails with a clear error and
// leaves the file alone.
func TestEditCloudJSONLockTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.json")
	if err := os.WriteFile(path, []byte(`{"attestation":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	old := lockWait
	lockWait = 200 * time.Millisecond
	defer func() { lockWait = old }()
	err = EditCloudJSON(path, func(map[string]json.RawMessage) error {
		t.Error("edit ran without the lock")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "another signer-admin is editing cloud.json") {
		t.Fatalf("got %v", err)
	}
}

// Temp files an interrupted run left next to cloud.json go at the next edit.
func TestEditCloudJSONRemovesStaleTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloud.json")
	stale := filepath.Join(dir, ".cloud.json.tmp-123")
	other := filepath.Join(dir, ".other.json.tmp-123")
	for _, p := range []string{path, stale, other} {
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := EditCloudJSON(path, func(map[string]json.RawMessage) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temp still there: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another file's temp removed: %v", err)
	}
}
