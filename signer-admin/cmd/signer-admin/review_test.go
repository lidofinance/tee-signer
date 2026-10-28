package main

import (
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// reviewBodies are two open-group drafts of the dev sample setup that
// differ in activate_at only.
func reviewBodies(t *testing.T) ([]byte, []byte) {
	t.Helper()
	s, err := setupwire.DecodeSetup(mustRead(t, filepath.Join("..", "..", "..", "governance", "setupwire", "testdata", "setup-dev.bin")))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, at := range []uint64{1_800_000_000, 1_900_000_000} {
		b := setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: setupwire.GroupOpen, Version: 1,
			ActivateAt: at, Open: &s.Open}
		b.PrevHash, _ = s.GroupHash(setupwire.GroupOpen)
		if err := b.DrawSalts(rand.Reader); err != nil {
			t.Fatal(err)
		}
		raw, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out[0], out[1]
}

// swappingDraft is a named pipe that hands out first, then second on
// every later open: a draft that someone with write access changes while
// the approver reviews it.
func swappingDraft(t *testing.T, first, second []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "update.bin")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for n := 0; ; n++ {
			f, err := os.OpenFile(p, os.O_WRONLY, 0)
			if err != nil {
				return
			}
			select {
			case <-done:
				f.Close()
				return
			default:
			}
			b := second
			if n == 0 {
				b = first
			}
			_, _ = f.Write(b)
			f.Close()
			// Wait until that reader closed its end (a non-blocking open for
			// writing fails with ENXIO when no reader is open), so the next
			// open reads the next content and nothing else.
			for {
				w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if err != nil {
					break
				}
				w.Close()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	t.Cleanup(func() {
		close(done)
		// Release a writer that waits for a reader.
		if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	})
	return p
}

// SG-REVIEW-01: show reads the draft once. It printed the signing digests
// from its first read and the values, diff and body_sha256 from a second
// one, so an approver could review one body and approve another. With a
// draft that changes between opens, every value show prints is the first
// body's.
func TestShowReadsTheDraftOnce(t *testing.T) {
	a, b := reviewBodies(t)
	ba, err := setupwire.DecodeUpdateBody(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, _ := setupwire.DecodeUpdateBody(b)
	ha, _ := ba.Hash()
	hb, _ := bb.Hash()
	ctx, body, _ := signingInput(a)
	da := sha256.Sum256(setupwire.ApprovalMessage(ctx, false, body))
	out := mustTool(t, "show", swappingDraft(t, a, b))
	wantIn(t, out, "body_sha256 "+fullHex(ha), "sha256 "+fullHex(da))
	if strings.Contains(out, fullHex(hb)) {
		t.Fatalf("show printed the hash of the second read:\n%s", out)
	}
}

// sign -expect-sha256 takes the direct signing message's sha256 that show
// printed and refuses a draft whose message is another.
func TestSignExpectSHA256(t *testing.T) {
	dir := t.TempDir()
	keys := approvers(t, dir, 1)
	a, b := reviewBodies(t)
	ctx, body, _ := signingInput(a)
	da := sha256.Sum256(setupwire.ApprovalMessage(ctx, false, body))
	pa := writeFile(t, filepath.Join(dir, "a.bin"), string(a))
	pb := writeFile(t, filepath.Join(dir, "b.bin"), string(b))
	wantIn(t, failTool(t, "sign", "-key", keys[0].file, "-expect-sha256", fullHex(da), pb), "not the one reviewed")
	if _, err := os.Stat(pb + "." + keys[0].pub[2:10] + ".sig"); err == nil {
		t.Fatal("a signature file was written for the other draft")
	}
	mustTool(t, "sign", "-key", keys[0].file, "-expect-sha256", fullHex(da), pa)
	wantIn(t, failTool(t, "sign", "-key", keys[0].file, "-expect-sha256", "00", pa), "-expect-sha256")
}
