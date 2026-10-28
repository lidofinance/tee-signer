// Package azure is the Azure confidential containers platform (ACI). The
// runner does the attestation and the key release itself, in process: no
// Microsoft SKR sidecar runs in the group, so nothing but the runner's own
// port listens there. UNTESTED on Azure: it compiles and runs against
// fakes; nothing ran in a confidential container group.
//
// Flows (sources in cloud/azure/README.md and in the files named here):
//
//   - Attestation (maa.go, snp_linux.go, collateral.go): the runner asks
//     the SEV-SNP guest device for a report whose REPORT_DATA is the
//     SHA-256 of the runtime data, takes the VCEK certificate chain and the
//     UVM endorsements from the security context directory of the group,
//     and posts all of it to MAA. The token has the x-ms-sevsnpvm-* claims,
//     including hostdata (the hash of the CCE policy). Runtime data goes to
//     MAA with dataType JSON, so it is the JSON object
//     backend.MAARuntimeData(user data) for an identity and
//     {"signer-runner-clock":"<hex nonce>"} for the clock.
//   - Sealing (keyvault.go, imds.go): the runner makes a fresh RSA wrapping
//     key, gets an MAA token that offers it in x-ms-runtime, gets a Key
//     Vault token from the group's managed identity, and asks Key Vault to
//     release the exportable RSA key. Key Vault releases it only if the MAA
//     token satisfies the key's release policy (cloud/azure/skr-policy.json.tmpl
//     pins hostdata) and wraps it to the wrapping key. The sealing data key
//     and the AES key of platform.Keys (the mark log's keys) are both
//     derived from the released key and setup_hash (HKDF-SHA256 over its
//     private exponent, derivedKeys). Nothing of them is in the store: the
//     same Key Vault key version and setup give the same keys after the
//     state is lost, another setup gets other keys, and there is no stored
//     blob that a host could plant.
//   - Store: files under -state-dir (an Azure Files mount or similar). The
//     host can roll it back; use the restart floor.
//   - Clock: system clock (no Azure document says the host cannot set it),
//     or clock=maa-iat: the iat of a fresh MAA token.
//
// The protocol follows Microsoft's open-source sidecar
// (github.com/microsoft/confidential-sidecar-containers, MIT). The code is
// written here, from its behaviour; no part of it is copied.
package azure

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/platform/jwtclaims"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// optionNames are the platform options of the release build.
var optionNames = []string{"maa_endpoint", "akv_endpoint", "kid", "client_id", "clock"}

var (
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	// A key name, optionally followed by a slash and a 32-digit version.
	kidRE      = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}(/[0-9a-f]{32})?$`)
	clientIDRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

func checkOptions(params map[string]string) error {
	for k := range params {
		if !slices.Contains(optionNames, k) && !slices.Contains(debugOptions, k) {
			return fmt.Errorf("azure: unknown platform option %q", k)
		}
	}
	return nil
}

func parseRSAJWK(b []byte) (*rsa.PrivateKey, error) {
	// Key Vault's JWK has non-string members (key_ops is an array), so keep
	// only the string members; the RSA fields are all strings.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("azure: jwk: %w", err)
	}
	j := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			j[k] = s
		}
	}
	if kty := j["kty"]; kty != "RSA" && kty != "RSA-HSM" {
		return nil, fmt.Errorf("azure: jwk kty %q, want RSA", kty)
	}
	num := func(name string) (*big.Int, error) {
		v, err := base64.RawURLEncoding.DecodeString(j[name])
		if err != nil || len(v) == 0 {
			return nil, fmt.Errorf("azure: jwk field %s", name)
		}
		return new(big.Int).SetBytes(v), nil
	}
	var f [5]*big.Int
	for i, name := range []string{"n", "e", "d", "p", "q"} {
		v, err := num(name)
		if err != nil {
			return nil, err
		}
		f[i] = v
	}
	if !f[1].IsInt64() {
		return nil, errors.New("azure: jwk exponent too large")
	}
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: f[0], E: int(f[1].Int64())}, D: f[2], Primes: []*big.Int{f[3], f[4]}}
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("azure: jwk: %w", err)
	}
	k.Precompute()
	return k, nil
}

// Attester binds userData through the runtime data
// backend.MAARuntimeData(userData).
type Attester struct{ MAA *MAAClient }

func (a *Attester) Attest(ctx context.Context, _, userData []byte) (*backend.Attestation, error) {
	tok, err := a.MAA.Token(ctx, backend.MAARuntimeData(userData))
	if err != nil {
		return nil, err
	}
	return &backend.Attestation{Platform: "azure", Format: "azure-maa-jwt", UserData: userData, Document: []byte(tok)}, nil
}

// MAATime is a clock.Source: iat of a fresh MAA token. The token comes from
// MAA over TLS (embedded roots, the runner has no CA bundle from the host),
// and its runtime data holds a random nonce that the SNP report carries, so
// it is fresh; Fetch checks that the token states the report data of that
// nonce. It does not check the token's signature: a relying party that
// needs that checks it (attest.VerifyMAA). UNTESTED on a real token.
type MAATime struct{ MAA *MAAClient }

func (m MAATime) Name() string { return "azure-maa-iat" }

// clockRuntimeData is the JSON runtime data of a clock token. Its own key
// keeps it apart from an identity's.
func clockRuntimeData(nonce []byte) []byte {
	return []byte(`{"signer-runner-clock":"` + hex.EncodeToString(nonce) + `"}`)
}

func (m MAATime) Fetch(ctx context.Context) (time.Time, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return time.Time{}, err
	}
	rt := clockRuntimeData(n)
	tok, err := m.MAA.Token(ctx, rt)
	if err != nil {
		return time.Time{}, err
	}
	c, err := jwtclaims.Claims(tok)
	if err != nil {
		return time.Time{}, err
	}
	if got, _ := c["x-ms-sevsnpvm-reportdata"].(string); !sameHex(got, reportDataClaim(rt)) {
		return time.Time{}, errors.New("azure: the clock token does not state the report data of this request")
	}
	return jwtclaims.Time(c, "iat")
}

// derivedKeys derives the sealing data key and the wrapping key of
// platform.Keys from the released key and setup_hash: HKDF-SHA256 over the
// key's private exponent, with the info CtxAzureSealing or CtxAzureKeyWrap
// and setup_hash (research/setup-phase.md in the threshold-signer-poc repo, section
// 4). Before, the data key was a random key wrapped with RSA-OAEP to the
// released key's public half and kept in the store; anyone with the public
// key could make such a blob and plant it in a host-writable state folder.
// A derived key has no stored form to plant, and a runner with another
// setup derives other keys from the same Key Vault key.
func derivedKeys(key *rsa.PrivateKey, setup [32]byte) (dek, wrap []byte, err error) {
	ikm := key.D.Bytes()
	if dek, err = hkdf.Key(sha256.New, ikm, nil, string(setupwire.CtxAzureSealing.Message(setup[:])), 32); err != nil {
		return nil, nil, err
	}
	if wrap, err = hkdf.Key(sha256.New, ikm, nil, string(setupwire.CtxAzureKeyWrap.Message(setup[:])), 32); err != nil {
		return nil, nil, err
	}
	return dek, wrap, nil
}

// dataKey releases the key and returns the sealing data key and the
// wrapping key of platform.Keys for setup. Neither needs local state: a
// runner whose state directory is gone derives both again.
func dataKey(ctx context.Context, rel KeyReleaser, kid string, setup [32]byte) (dek, wrap []byte, err error) {
	key, err := rel.ReleaseKey(ctx, kid)
	if err != nil {
		return nil, nil, err
	}
	return derivedKeys(key, setup)
}

// releaseChecked reads the rule of the key kid (key_release_hash and the
// lock, o.ReadKeyRule), then releases exactly the key version that read
// described and checks that the released key is that key (RBRAZR-01). On
// mainnet a policy that is not immutable, or a kid without a version,
// stops the start here. Without a rule read (the flag path, or a failed
// read off mainnet) the release names kid as given, as before.
func releaseChecked(ctx context.Context, o platform.Options, rel *Releaser, kid string) (*platform.KeyRule, *rsa.PrivateKey, error) {
	name, version, _ := strings.Cut(kid, "/")
	if o.Mainnet && version == "" {
		return nil, nil, fmt.Errorf("azure: mainnet: kid %q names no key version; a mainnet setup names the version (kid <name>/<version>), so the approvers fix the key", kid)
	}
	var checked *CheckedKey
	rule, err := o.ReadKeyRule(ctx, func(ctx context.Context) (platform.KeyRule, error) {
		r, k, err := rel.KV.CheckKey(ctx, kid)
		if err == nil {
			checked = &k
		}
		return r, err
	})
	if err != nil {
		return nil, nil, err
	}
	if checked == nil {
		key, err := rel.ReleaseKey(ctx, kid)
		return rule, key, err
	}
	key, releasedKid, err := rel.releaseKid(ctx, name+"/"+checked.Version)
	if err != nil {
		return nil, nil, err
	}
	if err := checked.Matches(key, releasedKid); err != nil {
		return nil, nil, err
	}
	return rule, key, nil
}

// New builds the platform. Options: maa_endpoint, akv_endpoint, kid,
// clock=system|maa-iat, and client_id (a user-assigned identity, needed
// only if the group has more than one). The debug build has two more
// (hooks_debug.go).
//
// StorageResource is the resource of the managed identity token the mark
// log's Blob Storage requests carry. ManagementResource is the one of the
// lock check, which reads the container's immutability policy from the
// management plane.
const (
	StorageResource    = "https://storage.azure.com/"
	ManagementResource = "https://management.azure.com/"
)

func New(o platform.Options) (*platform.Platform, error) {
	if err := checkOptions(o.Params); err != nil {
		return nil, err
	}
	maaHost, akv, kid := o.Param("maa_endpoint", ""), o.Param("akv_endpoint", ""), o.Param("kid", "")
	if maaHost == "" || akv == "" || kid == "" {
		return nil, errors.New("azure: maa_endpoint, akv_endpoint and kid are required")
	}
	if !hostRE.MatchString(maaHost) || !hostRE.MatchString(akv) {
		return nil, errors.New("azure: maa_endpoint and akv_endpoint are host names (no scheme, no path)")
	}
	if !kidRE.MatchString(kid) {
		return nil, fmt.Errorf("azure: kid %q is not a Key Vault key name", kid)
	}
	clientID := o.Param("client_id", "")
	if clientID != "" && !clientIDRE.MatchString(clientID) {
		return nil, errors.New("azure: client_id is not an identity client id")
	}
	reports, imdsURL, err := hardwareFor(o)
	if err != nil {
		return nil, err
	}
	store, err := filestore.New(o.StateDir)
	if err != nil {
		return nil, err
	}
	httpc := newClient(60 * time.Second)
	local := newClient(10 * time.Second)
	maa := &MAAClient{Endpoint: maaHost, HTTP: httpc, Reports: reports, Collateral: &HostCollateral{HTTP: local}}
	tokens := &IMDSTokens{URL: imdsURL, ClientID: clientID, HTTP: local}
	rel := &Releaser{MAA: maa, KV: &KeyVault{Endpoint: akv, HTTP: httpc, Tokens: tokens}, Seen: &platform.ImageSeen{}}

	var clk platform.Clock = clock.System{}
	switch c := o.Param("clock", "system"); c {
	case "system":
	case "maa-iat":
		clk = &clock.Anchored{Src: MAATime{MAA: maa}, Interval: clock.DefaultInterval, TrustedSrc: true}
	default:
		return nil, errors.New("azure: unknown clock " + strconv.Quote(c))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rule, key, err := releaseChecked(ctx, o, rel, kid)
	if err != nil {
		return nil, err
	}
	dek, wrap, err := derivedKeys(key, o.SetupHash)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	wrapper, err := dev.NewGCMSealer(wrap)
	clear(wrap)
	if err != nil {
		return nil, err
	}
	p := &platform.Platform{Name: "azure", Store: store, Clock: clk, Attester: &Attester{MAA: maa},
		HTTPClient: newClient(30 * time.Second),
		// The mark log's container: the same managed identity, storage scope.
		StorageToken: func(ctx context.Context) (string, time.Time, error) {
			t, err := tokens.Fetch(ctx, StorageResource)
			return t.Value, t.Expires, err
		},
		// The mark log's lock check: the same identity, management scope.
		ManagementToken: func(ctx context.Context) (string, time.Time, error) {
			t, err := tokens.Fetch(ctx, ManagementResource)
			return t.Value, t.Expires, err
		},
		// Keys under a key derived from the released key and setup_hash: only
		// a group whose CCE policy the key's release policy names gets it,
		// and only with this setup.
		Keys:    platform.SealerKeys{Sealer: wrapper},
		KeyRule: rule,
		// The hostdata of the token Key Vault released the key against.
		SelfImage: rel.Seen.Get,
	}
	// The durable copy of the state (-state-store) restores the sealed
	// shares. The sealing key is derived, so nothing of it is restored.
	if p.Store, err = o.UseDurable(ctx, p); err != nil {
		return nil, err
	}
	if p.Sealer, err = dev.NewGCMSealer(dek); err != nil {
		return nil, err
	}
	return p, nil
}
