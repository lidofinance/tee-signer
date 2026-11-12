package gcp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Every GCP sample setup (governance/setupwire/testdata and the setup of
// the attestation statement vectors) passes checkSetupProject, so the
// samples stay setups a runner takes. A sample without project_number is
// checked against the number of its wif_provider.
func TestSampleSetupsPassTheProjectCheck(t *testing.T) {
	samples := map[string][]byte{}
	bins, err := filepath.Glob(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-*.bin"))
	if err != nil || len(bins) == 0 {
		t.Fatalf("no sample setups: %v", err)
	}
	for _, p := range bins {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		samples[filepath.Base(p)] = b
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "attestation-verify", "docs", "attestation-statement-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Setup struct {
			Bytes string `json:"bytes"`
		} `json:"setup"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(vec.Setup.Bytes, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	samples["attestation-statement-vectors.json"] = b
	providerNumber := regexp.MustCompile(`^//iam\.googleapis\.com/projects/([0-9]+)/`)
	gcp := 0
	for name, b := range samples {
		s, err := setupwire.DecodeSetup(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Platform.Platform != setupwire.PlatformGCP {
			continue
		}
		gcp++
		k := s.Platform.SealingKeyRelease
		number := ""
		if k.ProjectNumber != 0 {
			number = strconv.FormatUint(k.ProjectNumber, 10)
		} else if m := providerNumber.FindStringSubmatch(k.WIFProvider); m != nil {
			number = m[1]
		}
		if number == "" {
			t.Errorf("%s: no project number in project_number or wif_provider %q", name, k.WIFProvider)
			continue
		}
		if err := checkSetupProject(k.WIFProvider, k.KMSKey, number); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if gcp < 3 {
		t.Fatalf("%d GCP sample setups, want the two of testdata and the vector's", gcp)
	}
}
