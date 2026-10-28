package record

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
)

var keyRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// FileStore keeps each record in DIR/<key>.rec and serializes writers with
// flock on DIR/<key>.lock. It is the local test implementation: it works
// for processes on one host (two runners sharing a directory), and the host
// can edit it, so it protects nothing in production.
type FileStore struct{ Dir string }

func (f *FileStore) String() string { return "file:" + f.Dir }

type fileRecord struct {
	Version uint64 `json:"version"`
	Value   []byte `json:"value"`
}

func (f *FileStore) paths(key string) (string, string, error) {
	if !keyRE.MatchString(key) {
		return "", "", fmt.Errorf("record: bad key %q", key)
	}
	return filepath.Join(f.Dir, key+".rec"), filepath.Join(f.Dir, key+".lock"), nil
}

func (f *FileStore) locked(key string, how int, fn func(path string) error) error {
	path, lockPath, err := f.paths(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), how); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	return fn(path)
}

func readRecord(path string) (fileRecord, error) {
	var r fileRecord
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

func (f *FileStore) Get(_ context.Context, key string) (uint64, []byte, error) {
	var r fileRecord
	err := f.locked(key, syscall.LOCK_SH, func(path string) error {
		var err error
		r, err = readRecord(path)
		return err
	})
	return r.Version, r.Value, err
}

func (f *FileStore) Put(_ context.Context, key string, prev, next uint64, value []byte) error {
	return f.locked(key, syscall.LOCK_EX, func(path string) error {
		cur, err := readRecord(path)
		switch {
		case errors.Is(err, ErrNotFound):
			cur.Version = 0
		case err != nil:
			return err
		}
		if cur.Version != prev {
			return ErrConflict
		}
		b, err := json.Marshal(fileRecord{Version: next, Value: value})
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		t, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := t.Write(b); err != nil {
			t.Close()
			return err
		}
		if err := t.Sync(); err != nil {
			t.Close()
			return err
		}
		if err := t.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		d, err := os.Open(f.Dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	})
}

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu   sync.Mutex
	m    map[string]fileRecord
	Fail error // returned by every call when set
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]fileRecord{}} }

func (m *MemStore) String() string { return "mem" }

func (m *MemStore) Get(_ context.Context, key string) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, nil, m.Fail
	}
	r, ok := m.m[key]
	if !ok {
		return 0, nil, ErrNotFound
	}
	return r.Version, append([]byte(nil), r.Value...), nil
}

func (m *MemStore) Put(_ context.Context, key string, prev, next uint64, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if m.m[key].Version != prev {
		return ErrConflict
	}
	m.m[key] = fileRecord{Version: next, Value: append([]byte(nil), value...)}
	return nil
}

// Delete removes a record (tests: a host or admin deleting it).
func (m *MemStore) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, key)
}
