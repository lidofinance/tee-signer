// Package gcp is the Google Cloud Confidential Space platform. UNTESTED:
// it compiles; nothing ran in a Confidential Space VM.
//
// Flows (sources in cloud/gcp/README.md):
//
//   - Attestation: the workload asks the launcher for a custom-audience
//     token: POST /v1/token on the unix socket
//     /run/container_launcher/teeserver.sock with {audience, token_type,
//     nonces}. The token carries image_digest, swname, dbgstat,
//     support_attributes and the nonces. Its audience is the identity
//     audience (attest_audience, default signer-runner-identity), never one
//     that Workload Identity Federation takes: the runner gives this token
//     to any client that asks for IDENTITY, Dirk included, and a token with
//     the STS audience could be traded at STS for the workload's KMS access.
//   - Sealing: a 32-byte data key generated in the VM and wrapped with
//     Cloud KMS. platform.Keys (the mark log's keys) is KMS encrypt and
//     decrypt with additional authenticated data, nothing in the store.
//     Both AADs carry setup_hash (sealingAAD, Keys).
//     KMS access goes through Workload Identity Federation: a second
//     token, with audience https://sts.googleapis.com (the one audience the
//     WIF provider of cloud/gcp/deploy.sh wif-create accepts), is exchanged
//     at sts.googleapis.com for a federated token; the WIF provider's
//     attribute condition pins the image digest, hardware model, swname,
//     dbgstat and support attributes. The federated token itself calls KMS
//     and the buckets: deploy.sh grants the roles to the pool's principal
//     set, not to a service account, so the account the VM runs as gets no
//     key release (an unmeasured VM can run as it too). service_account, if
//     set, makes the runner impersonate that account instead; the setup of
//     deploy.sh no longer allows that. The STS-audience token goes only to
//     STS.
//   - Store: files under -state-dir on the VM's disk; the disk goes with
//     the VM. -state-store keeps a copy of what matters in a bucket
//     (runner/statestore). The operator can roll the disk back (Google
//     says so for dm-crypt), so use the restart floor.
//   - Clock: the system clock (kvmclock or TDX/SNP TSC; no document says
//     the host cannot set absolute time), or clock=token-iat: the iat of a
//     fresh, nonce-bound attestation token.
package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/platform/jwtclaims"
	"github.com/lidofinance/tee-signer/trusted-time/clock"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	DefaultSocket = "/run/container_launcher/teeserver.sock"
	// DefaultIdentityAudience is the audience of the attestation tokens the
	// runner hands out and reads its token-iat clock from. A client checks
	// it (attest.ConfidentialSpaceOptions.Audience).
	DefaultIdentityAudience = "signer-runner-identity"
	// stsAudience is the audience the WIF provider accepts. Only the KMS
	// exchange asks for it.
	stsAudience = "https://sts.googleapis.com"
	dekBlob     = "sealing/dek.gcpkms"
)

// CheckIdentityAudience refuses an identity audience that Workload Identity
// Federation could take: empty, the STS audience, or a WIF resource name (a
// provider may be set to accept any audience, its own name included).
// Whoever holds a token with such an audience could exchange it at STS for
// the workload's KMS access, and the identity token goes to every client.
func CheckIdentityAudience(aud string) error {
	a := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(aud), "/"))
	switch {
	case a == "":
		return errors.New("gcp: the identity audience is empty")
	case a == stsAudience || a == "sts.googleapis.com":
		return fmt.Errorf("gcp: identity audience %q is the STS audience, which the WIF provider accepts", aud)
	case strings.HasPrefix(a, "//iam.googleapis.com/") || strings.HasPrefix(a, "https://iam.googleapis.com/"):
		return fmt.Errorf("gcp: identity audience %q names a Workload Identity Federation resource", aud)
	}
	return nil
}

// identityAudience returns the attest_audience parameter, or the default,
// after CheckIdentityAudience.
func identityAudience(o platform.Options) (string, error) {
	aud := o.Param("attest_audience", DefaultIdentityAudience)
	return aud, CheckIdentityAudience(aud)
}

// Launcher asks the Confidential Space launcher for tokens.
type Launcher struct {
	client *http.Client
}

func NewLauncher(socket string) *Launcher {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	return &Launcher{client: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

// Token returns an OIDC token for audience with up to 6 nonces. Google's
// pages give different size limits (10-74 bytes on "connect external
// resources", 8-88 on "token claims"); 32-64 hex chars fit both.
func (l *Launcher) Token(ctx context.Context, audience string, nonces []string) (string, error) {
	body, _ := json.Marshal(map[string]any{"audience": audience, "token_type": "OIDC", "nonces": nonces})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp: launcher token: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp: launcher token: %s: %s", resp.Status, b)
	}
	return strings.TrimSpace(string(b)), nil
}

// Attester binds userData as a hex nonce (64 bytes, inside the 10-74 limit).
type Attester struct {
	L        *Launcher
	Audience string
}

func (a *Attester) Attest(ctx context.Context, _, userData []byte) (*backend.Attestation, error) {
	if err := CheckIdentityAudience(a.Audience); err != nil {
		return nil, err
	}
	tok, err := a.L.Token(ctx, a.Audience, []string{hex.EncodeToString(userData)})
	if err != nil {
		return nil, err
	}
	return &backend.Attestation{Platform: "gcp", Format: "gcp-confidential-space-jwt", UserData: userData, Document: []byte(tok)}, nil
}

// TokenTime is a clock.Source: the iat of a token requested with a fresh nonce.
type TokenTime struct {
	L        *Launcher
	Audience string
}

func (t TokenTime) Name() string { return "gcp-token-iat" }

func (t TokenTime) Fetch(ctx context.Context) (time.Time, error) {
	if err := CheckIdentityAudience(t.Audience); err != nil {
		return time.Time{}, err
	}
	n := make([]byte, 16)
	rand.Read(n)
	nonce := hex.EncodeToString(n)
	tok, err := t.L.Token(ctx, t.Audience, []string{nonce})
	if err != nil {
		return time.Time{}, err
	}
	c, err := jwtclaims.Claims(tok)
	if err != nil {
		return time.Time{}, err
	}
	// eat_nonce echoes the request nonces (string or array, per Google's
	// token claims reference).
	if !strings.Contains(fmt.Sprint(c["eat_nonce"]), nonce) {
		return time.Time{}, errors.New("gcp: token does not carry our nonce")
	}
	return jwtclaims.Time(c, "iat")
}

// KMS wraps and unwraps the data key with Cloud KMS through WIF.
type KMS struct {
	L              *Launcher
	HTTP           *http.Client
	Provider       string // //iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROV
	ServiceAccount string // optional: impersonate this account
	Key            string // projects/P/locations/L/keyRings/R/cryptoKeys/K
	// Endpoints; empty means the public Google endpoints. Tests use fakes.
	STSURL, IAMURL, KMSURL string
	// Seen, if set, records the image digest of every token sent to STS:
	// the runner's own image as its key release showed it.
	Seen *platform.ImageSeen
}

// tokenImage is the allowed_image_measurements entry of a launcher token:
// its submods.container.image_digest claim, sha256:<64 hex>. The token
// comes from the launcher socket inside the VM, so its claims are read
// without the signature check (jwtclaims).
func tokenImage(tok string) (setupwire.Image, error) {
	c, err := jwtclaims.Claims(tok)
	if err != nil {
		return setupwire.Image{}, fmt.Errorf("gcp: launcher token: %w", err)
	}
	sub, _ := c["submods"].(map[string]any)
	ctr, _ := sub["container"].(map[string]any)
	d, _ := ctr["image_digest"].(string)
	h, ok := strings.CutPrefix(d, "sha256:")
	b, err := hex.DecodeString(h)
	if !ok || err != nil || len(b) != 32 {
		return setupwire.Image{}, fmt.Errorf("gcp: launcher token: submods.container.image_digest %q is not sha256:<64 hex digits>", d)
	}
	return setupwire.Image{Kind: setupwire.ImageGCP, Measurement: b}, nil
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// statusError is an HTTP answer other than 200.
type statusError struct {
	url    string
	status int
	body   []byte
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s: %d %s: %s", e.url, e.status, http.StatusText(e.status), e.body)
}

// notAuthentic: a 400 whose Google API error body has status
// INVALID_ARGUMENT, what Cloud KMS answers a decrypt of a ciphertext that
// does not open under the key and aad.
func (e *statusError) notAuthentic() bool {
	var b struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	return e.status == http.StatusBadRequest && json.Unmarshal(e.body, &b) == nil && b.Error.Status == "INVALID_ARGUMENT"
}

func (k *KMS) postJSON(ctx context.Context, u, bearer string, in, out any) error {
	body, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return &statusError{url: u, status: resp.StatusCode, body: b}
	}
	return json.Unmarshal(b, out)
}

// accessToken: attestation token with the STS audience -> STS federated
// token -> (optional) SA token. The STS-audience token goes only to STS.
func (k *KMS) accessToken(ctx context.Context) (string, error) {
	att, err := k.L.Token(ctx, stsAudience, nil)
	if err != nil {
		return "", err
	}
	k.Seen.Record(tokenImage(att))
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {k.Provider},
		"scope":                {"https://www.googleapis.com/auth/cloud-platform"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {att},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, or(k.STSURL, "https://sts.googleapis.com")+"/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp: sts: %s: %s", resp.Status, b)
	}
	var sts struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &sts); err != nil {
		return "", err
	}
	if k.ServiceAccount == "" {
		return sts.AccessToken, nil
	}
	var sa struct {
		AccessToken string `json:"accessToken"`
	}
	u := or(k.IAMURL, "https://iamcredentials.googleapis.com") + "/v1/projects/-/serviceAccounts/" + k.ServiceAccount + ":generateAccessToken"
	err = k.postJSON(ctx, u, sts.AccessToken, map[string]any{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}}, &sa)
	return sa.AccessToken, err
}

// call runs encrypt or decrypt. aad, if set, is the request's
// additionalAuthenticatedData: decrypt needs the aad of the encrypt.
func (k *KMS) call(ctx context.Context, op, field string, in, aad []byte) ([]byte, error) {
	tok, err := k.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	// The answer has more fields than the one we read, some of them not
	// strings (decrypt answers with "usedPrimary": true), so each field stays raw.
	var out map[string]json.RawMessage
	u := or(k.KMSURL, "https://cloudkms.googleapis.com") + "/v1/" + k.Key + ":" + op
	req := map[string]string{field: base64.StdEncoding.EncodeToString(in)}
	if aad != nil {
		req["additionalAuthenticatedData"] = base64.StdEncoding.EncodeToString(aad)
	}
	if err := k.postJSON(ctx, u, tok, req, &out); err != nil {
		return nil, fmt.Errorf("gcp: kms %s: %w", op, err)
	}
	resField := map[string]string{"encrypt": "ciphertext", "decrypt": "plaintext"}[op]
	var s string
	if err := json.Unmarshal(out[resField], &s); err != nil {
		return nil, fmt.Errorf("gcp: kms %s: field %s: %w", op, resField, err)
	}
	return base64.StdEncoding.DecodeString(s)
}

// sealingAAD is the additional authenticated data of the sealing data key:
// CtxGCPSealing over setup_hash (research/setup-phase.md in the threshold-signer-poc
// repo, section 4). A data key of another setup does not decrypt under it,
// even under the same KMS key.
func sealingAAD(setup [32]byte) []byte { return setupwire.CtxGCPSealing.Message(setup[:]) }

// dataKey reads the sealing data key wrapped by KMS from the store, or makes
// one on the first start, under sealingAAD(setup). A stored blob of another
// setup or KMS key does not decrypt, and the start stops.
//
// Who can plant one: encrypt needs cryptoKeyVersions.useToEncrypt on the
// key. cloud/gcp/deploy.sh grants it (cryptoKeyEncrypterDecrypter) to the
// WIF principal set alone, whose attribute condition pins the image, and
// deploy_test.go checks that. The AAD is not secret, so a principal that
// holds the role anyway (an admin who grants it to itself, or a binding
// inherited from the project or the organization, which the runner cannot
// see) can still plant a data key. GCP stays outside the admin-proof goal
// (setup-phase.md, review N).
func (k *KMS) dataKey(ctx context.Context, store platform.Store, setup [32]byte) ([]byte, error) {
	aad := sealingAAD(setup)
	blob, err := store.Get(dekBlob)
	if errors.Is(err, platform.ErrNotFound) {
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return nil, err
		}
		wrapped, err := k.call(ctx, "encrypt", "plaintext", dek, aad)
		if err != nil {
			return nil, err
		}
		return dek, store.Put(dekBlob, wrapped)
	}
	if err != nil {
		return nil, err
	}
	dek, err := k.call(ctx, "decrypt", "ciphertext", blob, aad)
	var se *statusError
	if errors.As(err, &se) && se.status == http.StatusBadRequest {
		return nil, fmt.Errorf("gcp: the stored sealing key %s does not decrypt under this KMS key and setup_hash %x: "+
			"it belongs to another setup or key, or someone else put it there; a new setup starts on an empty store (%w)", dekBlob, setup, err)
	}
	if err != nil {
		return nil, err
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("gcp: the stored sealing key %s holds %d bytes, not 32", dekBlob, len(dek))
	}
	return dek, nil
}

// Keys is platform.Keys on Cloud KMS: a random key encrypted by KMS with
// CtxGCPKeyWrap over setup_hash and the caller's aad as additional
// authenticated data. Encrypt and decrypt need the same role on the key
// (cryptoKeyEncrypterDecrypter), which only the workload's identity has,
// so a blob that decrypts was made by a holder of that role for this
// setup.
type Keys struct {
	K *KMS
	// Setup is setup_hash; zero on the flag path.
	Setup [32]byte
}

func (g Keys) aad(aad []byte) []byte { return setupwire.CtxGCPKeyWrap.Message(g.Setup[:], aad) }

func (g Keys) NewKey(ctx context.Context, aad []byte) ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	blob, err := g.K.call(ctx, "encrypt", "plaintext", key, g.aad(aad))
	if err != nil {
		return nil, nil, err
	}
	return key, blob, nil
}

// OpenKey: KMS answers 400 with status INVALID_ARGUMENT ("Decryption
// failed") for a ciphertext it did not make, made under another key or with
// another aad; that is ErrNotAuthentic. Any other failure is returned as it
// is, so the caller stops instead of skipping a record: a 400 with another
// status (FAILED_PRECONDITION for a disabled or destroyed key version) or
// none, no token, 403, 5xx, network (RBRGCP-01).
func (g Keys) OpenKey(ctx context.Context, blob, aad []byte) ([]byte, error) {
	key, err := g.K.call(ctx, "decrypt", "ciphertext", blob, g.aad(aad))
	var se *statusError
	if errors.As(err, &se) && se.notAuthentic() {
		return nil, fmt.Errorf("%w (%v)", platform.ErrNotAuthentic, err)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, platform.ErrNotAuthentic
	}
	return key, nil
}

// New builds the platform. Params: socket, wif_provider, kms_key,
// attest_audience (default signer-runner-identity; the STS audience and WIF
// resource names are refused), clock=system|token-iat, and service_account
// (optional, impersonation; leave it unset with the setup of deploy.sh).
func New(o platform.Options) (*platform.Platform, error) {
	aud, err := identityAudience(o)
	if err != nil {
		return nil, err
	}
	l := NewLauncher(o.Param("socket", DefaultSocket))
	store, err := filestore.New(o.StateDir)
	if err != nil {
		return nil, err
	}
	k := &KMS{L: l, HTTP: &http.Client{Timeout: 30 * time.Second}, Provider: o.Param("wif_provider", ""),
		ServiceAccount: o.Param("service_account", ""), Key: o.Param("kms_key", ""), Seen: &platform.ImageSeen{}}
	if k.Provider == "" || k.Key == "" {
		return nil, errors.New("gcp: wif_provider and kms_key are required")
	}
	debugEndpoints(o, k)
	var clk platform.Clock = clock.System{}
	switch o.Param("clock", "system") {
	case "system":
	case "token-iat":
		clk = &clock.Anchored{Src: TokenTime{L: l, Audience: aud}, Interval: clock.DefaultInterval, TrustedSrc: true}
	default:
		return nil, fmt.Errorf("gcp: unknown clock %q", o.Param("clock", ""))
	}
	p := &platform.Platform{Name: "gcp", Store: store, Clock: clk,
		Attester: &Attester{L: l, Audience: aud}, HTTPClient: k.HTTP,
		// The buckets of the mark log and the state copy: the same federated
		// token as KMS, so the WIF condition on the image gates them too.
		// The token's expiry is not passed on: the cache keeps its fixed
		// ages on GCP.
		StorageToken: func(ctx context.Context) (string, time.Time, error) {
			t, err := k.accessToken(ctx)
			return t, time.Time{}, err
		},
		Keys: Keys{K: k, Setup: o.SetupHash},
		// The image digest of the tokens the WIF condition checked.
		SelfImage: k.Seen.Get,
	}
	// Cloud KMS has no lock on a key's IAM bindings, so there is nothing to
	// read; key_release_hash stays zero and the setup's project pins stand
	// in. On mainnet the start goes on only when the setup accepts that
	// (platform.Options.CheckNoLock).
	if p.KeyRule, err = o.ReadKeyRule(context.Background(), platform.NoLock("GCP Cloud KMS has no lock on a key's IAM bindings")); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// The durable copy of the state (-state-store) restores the wrapped
	// data key and the sealed shares before the data key is read.
	if p.Store, err = o.UseDurable(ctx, p); err != nil {
		return nil, err
	}
	dek, err := k.dataKey(ctx, p.Store, o.SetupHash)
	if err != nil {
		return nil, err
	}
	p.Sealer, err = dev.NewGCMSealer(dek)
	clear(dek)
	if err != nil {
		return nil, err
	}
	return p, nil
}
