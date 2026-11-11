package cluster

// The image pin and trust anchor of a cloud.json, held to the setup.
//
// The verifier trusts a runner whose attestation names the measurement
// that cloud.json pins, signed by the key source that cloud.json names.
// Any runner image attests to its own measurement, and the operator who
// hands over the file can name a key source of their own. So before a
// tool connects, CheckConn holds both to the setup: the pin must be on
// the approvers' list, and the key source must be the setup's.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	attest "github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// CheckConn refuses conn unless its attestation settings fit the setup s:
//   - the verifier is the one of s's platform; the dev verifier only for a
//     dev platform setup;
//   - setup_sha256 is the hash of s; CheckConn sets it when it is unset;
//   - mainnet is set if and only if s's chain is a prod chain;
//   - azure-maa: maa_host is the setup's maa_endpoint, and
//     compliance_status is the default;
//   - gcp-cs: gcp_issuer and gcp_jwks_file are unset, so the token comes
//     from Google's key set;
//   - the image pin is on the approved list of s and the signed locked
//     updates in updatesDir (setupwire.ApprovedImages at now).
//
// It returns the locked version the walk of updatesDir reached (0 for the
// dev platform). It prints a warning to stderr once for each update file
// that does not decode or does not chain.
func CheckConn(conn *runnerclient.Connection, s *setupwire.Setup, updatesDir string, now time.Time) (uint64, error) {
	a := &conn.Attestation
	p := s.Platform.Platform
	want := verifierFor(p)
	switch {
	case a.Verifier == runnerclient.VerifierDev && p != setupwire.PlatformDev:
		return 0, fmt.Errorf("verifier dev, but the setup is on the %s platform; the dev verifier proves nothing about a cloud runner, use %s", p, want)
	case a.Verifier != want:
		return 0, fmt.Errorf("verifier %q, but the setup is on the %s platform, use %s", a.Verifier, p, want)
	}
	h, err := s.Hash()
	if err != nil {
		return 0, err
	}
	switch pin := strings.ToLower(strings.TrimPrefix(a.SetupSHA256, "0x")); pin {
	case "":
		a.SetupSHA256, a.AllowUnpinnedSetup = hex.EncodeToString(h[:]), false
	case hex.EncodeToString(h[:]):
	default:
		return 0, fmt.Errorf("attestation pins setup_sha256 %s already, not the setup built for this signer (%x); remove it to pin a new setup", pin, h)
	}
	if p == setupwire.PlatformDev {
		return 0, nil
	}
	switch {
	case a.Mainnet && !s.Chain.Prod():
		return 0, errors.New("attestation.mainnet is set, but the setup's chain is not a prod chain")
	case !a.Mainnet && s.Chain.Prod():
		return 0, errors.New("attestation.mainnet is not set, but the setup's chain is a prod chain (mainnet)")
	case a.Verifier == runnerclient.VerifierAzureMAA && hostOf(a.MAAHost) != hostOf(s.Platform.SealingKeyRelease.MAAEndpoint):
		return 0, fmt.Errorf("attestation.maa_host %q is not the setup's maa_endpoint %q", a.MAAHost, s.Platform.SealingKeyRelease.MAAEndpoint)
	case a.ComplianceStatus != "" && a.ComplianceStatus != attest.ComplianceACI:
		return 0, fmt.Errorf("attestation.compliance_status %q: the setup allows the default %q only", a.ComplianceStatus, attest.ComplianceACI)
	case a.GCPIssuer != "" || a.GCPJWKSFile != "":
		return 0, errors.New("attestation.gcp_issuer and gcp_jwks_file must be unset: the token must come from Google's key set")
	}
	im, err := pinnedImage(a)
	if err != nil {
		return 0, err
	}
	files, err := readUpdateFiles(updatesDir)
	if err != nil {
		return 0, err
	}
	ap, err := setupwire.ApprovedImages(s, files, uint64(max(now.Unix(), 0)))
	if err != nil {
		return 0, err
	}
	for _, w := range ap.Warnings {
		WarnOnce(w)
	}
	if im.Listed(ap.Images) {
		return ap.Version, nil
	}
	why := ""
	if im.Listed(ap.Pending) {
		why = ", which adds it, but its activate_at has not passed"
	}
	return 0, fmt.Errorf("the pinned %s image %x is not on allowed_image_measurements of locked version %d (the setup and the signed locked updates in %s)%s (refusing to connect)",
		im.Kind, im.Measurement, ap.Version, updatesDir, why)
}

// hostOf is an MAA host as the verifier takes it: lower case, without
// https:// and without a trailing slash. Host and port compare exactly.
func hostOf(s string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(s), "https://"), "/")
}

var (
	warnedMu sync.Mutex
	warned   = map[string]bool{}
)

// WarnOnce prints a warning about the updates folder to stderr once per
// run: every member of a cluster reads the same folder.
func WarnOnce(w string) {
	warnedMu.Lock()
	defer warnedMu.Unlock()
	if !warned[w] {
		warned[w] = true
		fmt.Fprintf(os.Stderr, "warning: updates folder: %s\n", w)
	}
}

// verifierFor is the runnerclient verifier of platform p.
func verifierFor(p setupwire.Platform) string {
	switch p {
	case setupwire.PlatformNitro:
		return runnerclient.VerifierAWSNitro
	case setupwire.PlatformAzure:
		return runnerclient.VerifierAzureMAA
	case setupwire.PlatformGCP:
		return runnerclient.VerifierGCPCS
	}
	return runnerclient.VerifierDev
}

// pinnedImage converts the image pin of the attestation settings to an
// allowed_image_measurements entry: PCR0, PCR1 and PCR2 (nitro_pcrs) for
// aws-nitro, the CCE policy hash (cce_policy_sha256) for azure-maa, the
// image digest (gcp_image_digest) for gcp-cs.
func pinnedImage(a *runnerclient.Attestation) (*setupwire.Image, error) {
	var im setupwire.Image
	var hexPin string
	switch a.Verifier {
	case runnerclient.VerifierAWSNitro:
		pcrs, err := a.NitroPCRValues()
		if err != nil {
			return nil, err
		}
		im = setupwire.Image{Kind: setupwire.ImageNitro, Measurement: slices.Concat(pcrs[0], pcrs[1], pcrs[2])}
	case runnerclient.VerifierAzureMAA:
		im.Kind, hexPin = setupwire.ImageAzure, a.CCEPolicySHA256
	case runnerclient.VerifierGCPCS:
		im.Kind, hexPin = setupwire.ImageGCP, strings.TrimPrefix(strings.ToLower(a.GCPImageDigest), "sha256:")
	default:
		return nil, fmt.Errorf("attestation.verifier: %q pins no image", a.Verifier)
	}
	if im.Measurement == nil {
		var err error
		if im.Measurement, err = hex.DecodeString(hexPin); err != nil {
			return nil, fmt.Errorf("attestation: the %s image pin is not hex", im.Kind)
		}
	}
	if len(im.Measurement) != im.Kind.Size() {
		return nil, fmt.Errorf("attestation: a %s image pin is %d bytes, want %d", im.Kind, len(im.Measurement), im.Kind.Size())
	}
	return &im, nil
}

// readUpdateFiles reads the .signed files of dir, the folder push keeps
// updates in. An empty name or a missing folder holds none.
func readUpdateFiles(dir string) ([]setupwire.UpdateFile, error) {
	if dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []setupwire.UpdateFile
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".signed") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, setupwire.UpdateFile{Name: p, Raw: raw})
	}
	return out, nil
}
