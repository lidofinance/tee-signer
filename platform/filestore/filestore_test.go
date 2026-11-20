package filestore

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

func TestPutManyDeleteList(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("shares/aa", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMany(map[string][]byte{"orders/keys/aa": []byte("2"), "orders/pending/01": []byte("3"), "shares/bb": []byte("4")}); err != nil {
		t.Fatal(err)
	}
	for prefix, want := range map[string][]string{
		"":                {"orders/keys/aa", "orders/pending/01", "shares/aa", "shares/bb"},
		"orders/":         {"orders/keys/aa", "orders/pending/01"},
		"orders/pending/": {"orders/pending/01"},
		"shares/b":        {"shares/bb"},
		"sh":              {"shares/aa", "shares/bb"},
		"wm/":             nil,
	} {
		got, err := s.List(prefix)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("List(%q) = %v, %v; want %v", prefix, got, err, want)
		}
	}
	if err := s.Delete("orders/pending/01"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("orders/pending/01"); err != nil {
		t.Fatalf("a missing key: %v", err)
	}
	if _, err := s.Get("orders/pending/01"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if v, err := s.Get("shares/bb"); err != nil || string(v) != "4" {
		t.Fatalf("PutMany entry: %q %v", v, err)
	}
}

// A key is refused unless it is its own
// clean form. "." and "x/." name a directory, so Put makes its temp file
// one level up, in the parent of the store for "."; "a/./b", "./b", "a//b"
// and "b/" alias another key. Keys that leave the store ("..", a leading
// "/") are refused already and must stay refused.
func TestKeysOutsideTheirCleanFormRefused(t *testing.T) {
	parent := t.TempDir()
	s, err := New(filepath.Join(parent, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("shares/aa", []byte("1")); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"", "..", "../x", "shares/../../x", "/etc/x",
		".", "./", "shares/.", "a/./b", "./b", "a//b", "b/"} {
		t.Run(k, func(t *testing.T) {
			if p, err := s.path(k); err == nil {
				t.Errorf("key %q accepted as %s; a key must be its own clean form inside the store", k, p)
			}
			if err := s.Put(k, []byte("planted")); err == nil {
				t.Errorf("Put(%q) wrote", k)
			}
		})
	}
	if got, err := s.List(""); err != nil || !slices.Equal(got, []string{"shares/aa"}) {
		t.Errorf("store holds %v (%v); want only shares/aa", got, err)
	}
	if ents, err := os.ReadDir(parent); err != nil || len(ents) != 1 {
		t.Errorf("parent of the store holds %d entries (%v); want only the store", len(ents), err)
	}
}
