package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// import with the shares file of another signer under this signer's
// order: the shares are share 1 of each validator, the order is for share
// index 2. import refuses the file before it dials the runner, so no
// share is sealed and no frame reaches the runner.
func TestImportWrongSharesFileRefused(t *testing.T) {
	e := newSplitEnv(t, "scrypt", "pbkdf2")
	mustTool(t, e.args("-t", "3", "-n", "4", "-signers", "s1,s2,s3,s4")...)
	splitPath := filepath.Join(e.out, "split.json")

	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	body := fc.path("import.bin")
	mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s2", "-split", splitPath, "-out", body)
	signed := fc.path("import.signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, fc.signAll(t, body, 0, 1)...)...)

	wrong := filepath.Join(e.out, "shares", "s1", "shares.txt")
	out := failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-shares", wrong, "-commitments", splitPath)
	wantIn(t, out, wrong+":1 is share 1 of validator "+e.pks[0].String(), "the order is for share index 2", "nothing sent")
	r := fc.runners["s2"]
	for _, typ := range []wire.MsgType{wireadmin.TypeImportShare, wireadmin.TypeImportSealed, wireadmin.TypeImportBatch} {
		if n := r.Seen(typ); n != 0 {
			t.Fatalf("the runner saw %d frames of type 0x%02x; the tool sent shares", n, uint8(typ))
		}
	}
	if k := r.Keys(); len(k) != 0 {
		t.Fatalf("the runner holds %d keys", len(k))
	}
	// The right file goes through.
	mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed,
		"-shares", filepath.Join(e.out, "shares", "s2", "shares.txt"), "-commitments", splitPath)
	if k := r.Keys(); len(k) != 2 {
		t.Fatalf("the runner holds %d keys, want 2", len(k))
	}
}

// split refuses to start when /proc/swaps lists a swap device or cannot be
// read, before it reads a keystore or the password file; -allow-swap turns
// the refusal into a warning on stderr. With no swap it prints nothing.
func TestSplitSwapRefused(t *testing.T) {
	const (
		head   = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
		swapOn = head + "/swap.img                               file\t\t4194300\t\t0\t\t-2\n"
	)
	for _, c := range []struct {
		name, swaps string
		allow       bool
		refused     bool
		want        string
	}{
		{"swap on", swapOn, false, true, "swap is on (/swap.img)"},
		{"unreadable", "", false, true, "cannot read"},
		{"swap on, allowed", swapOn, true, false, "swap is on (/swap.img)"},
		{"unreadable, allowed", "", true, false, "cannot read"},
		{"no swap", head, false, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newSplitEnv(t, "scrypt")
			// newSplitEnv restores splitSwaps.
			if c.swaps == "" {
				splitSwaps = filepath.Join(e.dir, "missing")
			} else {
				writeFile(t, splitSwaps, c.swaps)
			}
			args := e.args("-chain", "devnet", "-t", "2", "-n", "3", "-signers", "a,b,c")
			if c.allow {
				args = append(args, "-allow-swap")
			}
			if c.refused {
				// A missing password file: a split that got as far as
				// the keystores would fail on it instead.
				if err := os.Remove(e.pass); err != nil {
					t.Fatal(err)
				}
				var out string
				stderr := captureStderr(t, func() { out = failTool(t, args...) })
				wantIn(t, out, c.want, "-allow-swap")
				if stderr != "" {
					t.Fatalf("stderr: %q, want nothing", stderr)
				}
				if _, err := os.Lstat(e.out); !os.IsNotExist(err) {
					t.Fatalf("%s exists after the refusal", e.out)
				}
				return
			}
			var out string
			stderr := captureStderr(t, func() { out = mustTool(t, args...) })
			wantIn(t, out, "split 1 keys 2 of 3")
			if c.want == "" {
				if stderr != "" {
					t.Fatalf("stderr: %q, want nothing", stderr)
				}
				return
			}
			wantIn(t, stderr, "warning: ", c.want)
		})
	}
}
