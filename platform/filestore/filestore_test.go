package filestore

import (
	"errors"
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
