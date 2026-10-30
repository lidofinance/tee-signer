// Package setup is the start of a runner that takes its operator values from
// a setup. The image is the same for every operator; the host hands
// the setup over at every start, over a channel that needs no key release:
//
//	nitro  the host agent on the parent, over vsock (agentclient.SetupChannel)
//	azure  the environment value SIGNER_SETUP, base64 (Env)
//	gcp    the instance metadata attribute signer-setup, base64 (gcp.MetadataSetup)
//	dev    SIGNER_SETUP, or a file for local runners (Env, File)
//
// Load decodes the bytes with the shared strict decoder (backend/setupwire),
// refuses a setup for another platform and computes setup_hash. The methods
// of Setup then give the values that were flags before: the platform
// options, the mark and state stores, the signer name, the client CA and
// max_keys. The runner turns the chain, safety and first config
// values into its chain config itself (runner/setupcfg.go).
//
// The setup is not secret. A host that hands over other bytes gets a runner
// with another setup_hash in its identity, another mark log and another
// state copy, and the shares stored here do not open for it. Every
// key-release call carries setup_hash (platform.Options.SetupHash), so such a
// runner gets other keys and opens nothing this signer sealed.
//
// This package holds no cloud code: the Nitro proxy routes are names and
// port numbers only. It does not link the C core either, so the host agent,
// which is built without cgo, can use it.
package setup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// EnvVar is the environment value that carries the setup, base64 of the
// binary form: on Azure (a wildcard rule of the CCE policy) and on dev.
const EnvVar = "SIGNER_SETUP"

// Setup is a setup that passed the decoder and the platform check.
type Setup struct {
	Raw    []byte           // the binary form, as handed over
	SHA256 [32]byte         // setup_hash
	Wire   *setupwire.Setup // the decoded values
}

// Load decodes raw strictly, refuses a setup for another platform than
// image (the runner's -platform: nitro, azure, gcp or dev) and computes
// setup_hash.
func Load(raw []byte, image string) (*Setup, error) {
	if len(raw) == 0 {
		return nil, errors.New("setup: empty")
	}
	want, err := setupwire.ParsePlatform(image)
	if err != nil {
		return nil, fmt.Errorf("setup: this image's %w", err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return nil, fmt.Errorf("setup refused: %w", err)
	}
	if err := s.CheckPlatform(want); err != nil {
		return nil, fmt.Errorf("setup refused: %w", err)
	}
	if want == setupwire.PlatformNitro {
		if _, err := NitroRoutes(&s.Platform); err != nil {
			return nil, fmt.Errorf("setup refused: %w", err)
		}
	}
	h, err := s.Hash()
	if err != nil {
		return nil, fmt.Errorf("setup refused: %w", err)
	}
	return &Setup{Raw: bytes.Clone(raw), SHA256: h, Wire: s}, nil
}

// AttestationEgress says which hosts the runner's HTTP client reaches when its
// egress is limited: on Nitro always, the setup's peer_attestation_hosts over the
// peer block of the port map (maybe none); on dev when the setup lists
// any, the same hosts dialled directly (dev.New, option egress). limited
// is false where the runner reaches any host: Azure, GCP, and dev without
// a list. The handover orders refuse an image whose verifier fetches a
// key set from a host outside a limited list.
func AttestationEgress(s *setupwire.Setup) (endpoints []string, limited bool) {
	switch p := &s.Platform; p.Platform {
	case setupwire.PlatformNitro:
		return p.PeerAttestationHosts, true
	case setupwire.PlatformDev:
		return p.PeerAttestationHosts, len(p.PeerAttestationHosts) > 0
	}
	return nil, false
}

// HashHex is setup_hash in hex.
func (s *Setup) HashHex() string { return hex.EncodeToString(s.SHA256[:]) }

// SignerID is the signer's name in the mark log and the state copy.
func (s *Setup) SignerID() string { return s.Wire.SignerName }

// MaxKeys is the signer's capacity (max_keys).
func (s *Setup) MaxKeys() uint32 { return s.Wire.MaxKeys }

// SlashingLogStore is the mark log in the syntax of -mark-store.
func (s *Setup) SlashingLogStore() string {
	return storeSpec(s.Wire.Platform.Platform, &s.Wire.Platform.SlashingLogStore)
}

// EncryptedStateStore is the state copy in the syntax of -state-store, or "" for
// none (always on Nitro, which keeps its state on the parent).
func (s *Setup) EncryptedStateStore() string {
	if s.Wire.Platform.EncryptedStateStore == nil {
		return ""
	}
	return storeSpec(s.Wire.Platform.Platform, s.Wire.Platform.EncryptedStateStore)
}

// storeSpec writes a store as the runner's store syntax. The decoder's
// rules keep commas, '=' and spaces out of bucket, region, account,
// container, subscription and resource group names, so the values cannot
// add a parameter. An Azure store names its subscription and resource
// group, which the mark log's lock check needs (azlog.Log.Lock).
func storeSpec(p setupwire.Platform, st *setupwire.Store) string {
	switch p {
	case setupwire.PlatformNitro:
		return "s3:bucket=" + st.Bucket + ",region=" + st.Region
	case setupwire.PlatformAzure:
		return "azblob:account=" + st.Account + ",container=" + st.Container +
			",subscription=" + st.Subscription + ",resource_group=" + st.ResourceGroup
	case setupwire.PlatformGCP:
		return "gcs:bucket=" + st.Bucket
	case setupwire.PlatformDev:
		return "file:" + st.Dir
	}
	return ""
}

// ClientCAPEM is the client CA for mutual TLS, as the PEM that
// -tls-client-ca names on the flag path.
func (s *Setup) ClientCAPEM() []byte {
	var b bytes.Buffer
	for _, der := range s.Wire.Platform.AllowedClientCA {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return b.Bytes()
}

// Options are the platform options (the -platform-opt values of the flag
// path) that follow from the setup. On Nitro they add the values fixed in
// the image: the host agent's address, the UDP relay, the store key of the
// record credentials and the proxy routes over the fixed port map, the
// setup's peer endpoints included. On dev a setup with peer_attestation_hosts
// limits the runner's HTTP client to them (option egress).
func (s *Setup) Options() map[string]string {
	k := &s.Wire.Platform.SealingKeyRelease
	switch s.Wire.Platform.Platform {
	case setupwire.PlatformNitro:
		// Load refused a setup whose routes fail.
		routes, _ := NitroRoutes(&s.Wire.Platform)
		return map[string]string{
			"agent":        NitroAgent,
			"region":       k.Region,
			"kms_key_id":   k.KMSKeyID,
			"proxy":        RouteOption(routes),
			"ntp_relay":    NitroNTPRelay,
			"record_creds": NitroRecordCreds,
		}
	case setupwire.PlatformDev:
		if e := s.Wire.Platform.PeerAttestationHosts; len(e) > 0 {
			return map[string]string{"egress": strings.Join(e, ",")}
		}
	case setupwire.PlatformAzure:
		return map[string]string{"maa_endpoint": k.MAAEndpoint, "akv_endpoint": k.AKVEndpoint, "kid": k.KID}
	case setupwire.PlatformGCP:
		return map[string]string{"wif_provider": k.WIFProvider, "kms_key": k.KMSKey, "attest_audience": k.AttestAudience}
	}
	return map[string]string{}
}

// MergeOptions adds the image's fixed options (-platform-opt flags) to the
// setup's. An option that both set is refused: the image must not override
// a value the setup carries, and the setup must not override one the image
// fixes.
func MergeOptions(fromSetup, fixed map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(fromSetup)+len(fixed))
	for k, v := range fromSetup {
		out[k] = v
	}
	for k, v := range fixed {
		if _, dup := fromSetup[k]; dup {
			return nil, fmt.Errorf("-platform-opt %s: the setup sets this option; leave it out of the command", k)
		}
		out[k] = v
	}
	return out, nil
}

// Channel hands the runner its setup at start.
type Channel interface {
	Read(ctx context.Context) ([]byte, error)
	String() string
}

// Reporter is a channel that can also take the runner's fatal error line
// (Nitro: the host agent's EXIT), for a failure before the platform exists.
type Reporter interface {
	ReportExit(text string)
}

// maxBase64 is the longest base64 text of a setup within setupwire.MaxSetup.
var maxBase64 = base64.StdEncoding.EncodedLen(setupwire.MaxSetup)

// DecodeBase64 reads the base64 text of a setup (standard alphabet, with
// padding; surrounding white space is dropped). what names the source in
// errors.
func DecodeBase64(what string, text []byte) ([]byte, error) {
	text = bytes.TrimSpace(text)
	if len(text) == 0 {
		return nil, fmt.Errorf("%s is empty", what)
	}
	if len(text) > maxBase64 {
		return nil, fmt.Errorf("%s: %d characters, a setup is at most %d bytes", what, len(text), setupwire.MaxSetup)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(string(text))
	if err != nil {
		return nil, fmt.Errorf("%s: not base64: %w", what, err)
	}
	return raw, nil
}

// Env reads the setup from an environment value, base64.
type Env struct {
	Name   string
	Lookup func(string) (string, bool) // nil: os.LookupEnv
}

func (e Env) Read(context.Context) ([]byte, error) {
	look := e.Lookup
	if look == nil {
		look = os.LookupEnv
	}
	v, ok := look(e.Name)
	if !ok {
		return nil, fmt.Errorf("%s is not set: the setup comes in this environment value (base64)", e.Name)
	}
	return DecodeBase64(e.Name, []byte(v))
}

func (e Env) String() string { return "env " + e.Name }

// File reads the binary setup from a file (dev only: local runners).
type File struct{ Path string }

func (f File) Read(context.Context) ([]byte, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	raw, err := io.ReadAll(io.LimitReader(fh, setupwire.MaxSetup+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > setupwire.MaxSetup {
		return nil, fmt.Errorf("%s: more than %d bytes", f.Path, setupwire.MaxSetup)
	}
	return raw, nil
}

func (f File) String() string { return "file " + f.Path }

// ParseSource reads the -setup flag's value: "platform" (the platform's own
// channel) or "file:PATH".
func ParseSource(s string) (file string, err error) {
	switch {
	case s == "platform":
		return "", nil
	case strings.HasPrefix(s, "file:") && len(s) > len("file:"):
		return strings.TrimPrefix(s, "file:"), nil
	}
	return "", fmt.Errorf("-setup %q: want platform, or file:PATH (dev only)", s)
}
