package setuptext

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The human form of each golden vector of setupwire is in testdata, and
// each pair reads back: the .bin formats to the .conf, the .conf parses to
// the .bin. After a change to the vectors, run setupwire's TestGolden with
// -update first, then this one.
func TestGolden(t *testing.T) {
	bins, err := filepath.Glob(filepath.Join(wireTestdata, "*.bin"))
	if err != nil || len(bins) == 0 {
		t.Fatalf("no golden files in %s: %v", wireTestdata, err)
	}
	nitro := setups(t)["setup-nitro"]
	for _, path := range bins {
		base := strings.TrimSuffix(filepath.Base(path), ".bin")
		bin := readFile(t, path)
		confPath := filepath.Join("testdata", base+".conf")
		var text []byte
		var parse func(conf []byte) ([]byte, error)
		if strings.HasPrefix(base, "setup-") {
			d, err := setupwire.DecodeSetup(bin)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			text = must(FormatSetup(d))
			parse = func(conf []byte) ([]byte, error) {
				p, err := ParseSetup(base+".conf", conf)
				if err != nil {
					return nil, err
				}
				return p.Encode()
			}
		} else {
			d, err := setupwire.DecodeUpdate(bin)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if err := d.Verify(&nitro.Locked.Approvers); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			text = must(FormatUpdate(d))
			parse = func(conf []byte) ([]byte, error) {
				p, err := ParseUpdate(base+".conf", conf)
				if err != nil {
					return nil, err
				}
				return p.Encode()
			}
		}
		if *update {
			if err := os.WriteFile(confPath, text, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		conf, err := os.ReadFile(confPath)
		if err != nil {
			t.Fatalf("%v (run with -update to make it)", err)
		}
		if !bytes.Equal(conf, text) {
			t.Errorf("%s differs from what the code makes", confPath)
		}
		if fromConf, err := parse(conf); err != nil || !bytes.Equal(fromConf, bin) {
			t.Errorf("%s does not read back to %s: %v", confPath, path, err)
		}
	}
	confs, _ := filepath.Glob(filepath.Join("testdata", "*.conf"))
	for _, c := range confs {
		bin := filepath.Join(wireTestdata, strings.TrimSuffix(filepath.Base(c), ".conf")+".bin")
		if _, err := os.Stat(bin); err != nil {
			t.Errorf("%s has no binary pair: %v", c, err)
		}
	}
}
