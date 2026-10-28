// Package filestore is a platform.Store on a local directory. Keys map to
// file paths; writes go to a temp file, fsync, rename, fsync of the
// directory. The host owns the directory, so it can roll it back.
package filestore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lidofinance/tee-signer/platform"
)

type Store struct{ dir string }

// New creates dir if needed.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("filestore: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(key string) (string, error) {
	if key == "" || strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("filestore: bad key %q", key)
	}
	return filepath.Join(s.dir, filepath.FromSlash(key)), nil
}

func (s *Store) Get(key string) ([]byte, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, platform.ErrNotFound
	}
	return b, err
}

func (s *Store) Put(key string, val []byte) error {
	dir, err := s.write(key, val, true)
	if err != nil {
		return err
	}
	return syncDir(dir)
}

// write puts val in a temp file, fsyncs it if sync is set and renames it to
// key's path. It returns the directory.
func (s *Store) write(key string, val []byte, sync bool) (string, error) {
	p, err := s.path(key)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(val); err != nil {
		f.Close()
		return "", err
	}
	if sync {
		if err := f.Sync(); err != nil {
			f.Close()
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return dir, os.Rename(tmp, p)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// PutMany writes every entry and then syncs the file system once, in
// place of a sync per entry. It is not atomic: after a crash some entries
// may be missing or empty. For writes whose durable copy lives elsewhere
// (runner/statestore puts them back at the next start).
func (s *Store) PutMany(entries map[string][]byte) error {
	for k, v := range entries {
		if _, err := s.write(k, v, false); err != nil {
			return err
		}
	}
	return syncFS(s.dir)
}

// Delete removes key. A missing key is no error.
func (s *Store) Delete(key string) error {
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(filepath.Dir(p))
}

// List returns the keys that start with prefix, sorted. It walks only the
// folder of prefix's last "/", not the whole store.
func (s *Store) List(prefix string) ([]string, error) {
	var keys []string
	root := s.dir
	if i := strings.LastIndex(prefix, "/"); i > 0 && !strings.Contains(prefix, "..") {
		root = filepath.Join(s.dir, filepath.FromSlash(prefix[:i]))
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".tmp-") {
			return nil
		}
		rel, err := filepath.Rel(s.dir, p)
		if err != nil {
			return err
		}
		if k := filepath.ToSlash(rel); strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
		return nil
	})
	sort.Strings(keys)
	return keys, err
}
