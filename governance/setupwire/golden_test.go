package setupwire

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// goldenFiles builds every vector: the binary form of each sample setup
// and of three signed updates, the hashes, and the context list. Their
// human forms are in governance/setuptext/testdata (TestGolden there). Approver keys and salts come from fixed seeds and Ed25519 signs
// deterministically, so the files are the same on every run.
func goldenFiles(t *testing.T) map[string][]byte {
	files := map[string][]byte{}
	var hashes strings.Builder
	ss := samples(t)
	names := make([]string, 0, len(ss))
	for name := range ss {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		s := ss[name]
		b := must(s.Encode())
		files[name+".bin"] = b
		lh, _ := s.GroupHash(GroupLocked)
		oh, _ := s.GroupHash(GroupOpen)
		sh, _ := SetupHash(b)
		pr, _ := s.PolicyRoot()
		pc, _ := s.PlatformCommitment()
		fmt.Fprintf(&hashes, "%s setup_hash %x\n", name, sh)
		fmt.Fprintf(&hashes, "%s policy_root %x\n", name, pr)
		fmt.Fprintf(&hashes, "%s platform_commitment %x\n", name, pc)
		fmt.Fprintf(&hashes, "%s chain_hash %x\n", name, s.Chain.Hash())
		fmt.Fprintf(&hashes, "%s locked_hash %x\n", name, lh)
		fmt.Fprintf(&hashes, "%s open_hash %x\n", name, oh)
		fmt.Fprintf(&hashes, "%s approver_set_hash %x\n", name, s.Locked.Approvers.Hash())
	}
	s := ss["setup-nitro"]
	for _, u := range []struct {
		name string
		u    *Update
	}{
		{"update-locked", signedUpdate(t, s, lockedBody(s), []byte{0, 2}, nil)},
		{"update-open", signedUpdate(t, s, openBody(s), []byte{1, 2}, nil)},
		{"update-rotation", signedUpdate(t, s, rotationBody(s), []byte{0, 1}, []byte{2, 3, 4})},
	} {
		files[u.name+".bin"] = must(u.u.Encode())
		h, _ := u.u.Body.Hash()
		fmt.Fprintf(&hashes, "%s update_hash %x\n", u.name, h)
	}
	files["hashes.txt"] = []byte(hashes.String())
	var ctx strings.Builder
	for _, c := range Contexts {
		ctx.WriteString(c.String() + "\n")
	}
	files["contexts.txt"] = []byte(ctx.String())
	return files
}

// The vectors in testdata match the code, and each binary file decodes and
// encodes back to itself.
func TestGolden(t *testing.T) {
	files := goldenFiles(t)
	for name, want := range files {
		path := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update to make it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what the code makes", name)
		}
	}
	s := samples(t)["setup-nitro"]
	for name := range files {
		base, ok := strings.CutSuffix(name, ".bin")
		if !ok {
			continue
		}
		bin, _ := os.ReadFile(filepath.Join("testdata", name))
		var fromBin []byte
		if strings.HasPrefix(base, "setup-") {
			d, err := DecodeSetup(bin)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			fromBin = must(d.Encode())
		} else {
			d, err := DecodeUpdate(bin)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if err := d.Verify(&s.Locked.Approvers); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			fromBin = must(d.Encode())
		}
		if !bytes.Equal(fromBin, bin) {
			t.Errorf("%s does not read back to itself", name)
		}
	}
}
