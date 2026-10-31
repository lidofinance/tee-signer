package azure

// Secure key release from Azure Key Vault, in process.
//
// Sources: the sidecar's pkg/skr/skr.go (SecureKeyRelease: a fresh RSA-2048
// wrapping key, its JWK set as the MAA runtime data, the release call,
// the unwrap), pkg/common/akv.go (URL, request, JWS checks, the structs of
// the answer, RsaAESKeyUnwrap), pkg/common/crypto.go (GenerateJWKSet: the
// shape of the runtime data), internal/httpginendpoints/httpginendpoints.go
// (api-version=7.4). The documentation: Microsoft's REST reference for
// "Keys - Release" (POST {vault}/keys/{name}/{version}/release, body
// {target, enc, nonce}, answer {value}, with the KeyEncryptionAlgorithm
// values CKM_RSA_AES_KEY_WRAP, RSA_AES_KEY_WRAP_256 and
// RSA_AES_KEY_WRAP_384) and the page "Azure Key Vault secure key release
// policy grammar" (the token must carry x-ms-runtime.keys, a JWK set with
// an RSA key that has key_ops encrypt and a kid; "The first suitable key
// is chosen"; the key encryption key is "owned and protected by the target
// execution environment").
//
// The flow, as the sidecar runs it for /key/release:
//
//  1. Make a fresh RSA-2048 key pair. This is the wrapping key.
//  2. Get an MAA token whose runtime data is the JSON object
//     {"keys":[{"kty":"RSA","n":...,"e":...,"kid":<RFC 7638 thumbprint>,
//     "key_ops":["encrypt"]}]}. MAA puts it into x-ms-runtime.
//  3. Get a Key Vault access token from the managed identity (imds.go).
//  4. POST {"target": <MAA token>} to
//     https://<vault>/keys/<name>/release?api-version=7.4 with the access
//     token as bearer. Key Vault checks the token against the key's release
//     policy and answers {"value": <JWS>}.
//  5. The JWS carries an x5c chain; its leaf must be valid for the vault's
//     name, chain to a trusted root and sign the JWS.
//  6. The JWS payload is {"request":{"enc":...},"response":{"key":{"key":
//     {"key_hsm": base64url(JSON{"ciphertext": base64url(...), ...})}}}}.
//     The ciphertext is RSA-OAEP(KEK) followed by AES-KWP(key): the
//     first RSA-size bytes are an AES key encrypted to the wrapping key
//     with OAEP (hash by "enc": SHA-1 for CKM_RSA_AES_KEY_WRAP, SHA-256 or
//     SHA-384 for the others, empty label), the rest is the key wrapped with
//     that AES key by RFC 5649 key wrap with padding. For an RSA key the
//     unwrapped bytes are a PKCS#8 private key.
//
// A fresh wrapping key per release means a recorded answer is useless later,
// and the host, which sees all this traffic, cannot read the key: it is
// encrypted to a key that never leaves the process, and Key Vault only
// releases it against a token whose hostdata is the group's CCE policy.
//
// UNVERIFIED on Azure: every step. The sidecar is the reference; we saw no
// real answer. In particular the JWS algorithm (RS and PS variants are
// accepted), the payload field names, and that the unwrapped RSA key is
// PKCS#8 (a JWK is accepted too, see parseReleasedKey) come from the
// sidecar's code, not from Microsoft's documentation.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // CKM_RSA_AES_KEY_WRAP is defined with SHA-1 OAEP
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/jwtclaims"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	akvAPIVersion = "api-version=7.4"
	wrapKeyBits   = 2048
)

// KeyVault calls the release operation of one vault.
type KeyVault struct {
	Endpoint string // vault host, e.g. signer-poc-kv.vault.azure.net
	Tokens   TokenSource
	HTTP     *http.Client
	// Roots is the trust for the JWS certificate chain. nil means the
	// system roots, which the runner extends with embedded ones.
	Roots *x509.CertPool
	// Now is the time for certificate checks. nil means time.Now.
	Now func() time.Time
	// MAAHost is the attestation provider the release policy must name as
	// its only authority (the setup's maa_endpoint). Empty means no policy
	// counts as locked.
	MAAHost string
}

// Release asks Key Vault to release the key name to the holder of the key
// in the MAA token target. It returns the verified payload of the answer.
func (kv *KeyVault) Release(ctx context.Context, name, target string) ([]byte, error) {
	access, err := kv.Tokens.Token(ctx, vaultResource)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"target": target})
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s/keys/%s/release?%s", kv.Endpoint, name, akvAPIVersion)
	resp, err := httpDo(ctx, kv.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+access)
		return req, nil
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: Key Vault release: %w", err)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.Value == "" {
		return nil, fmt.Errorf("azure: Key Vault release answer has no value (%v)", err)
	}
	return kv.verifyJWS(out.Value)
}

// KeyRule reads the rule of the key name (platform.KeyRule): Get Key (GET
// https://<vault>/keys/<name>?api-version=7.4, the KeyBundle of
// Microsoft's REST reference). See keyRuleOf for the hash and the lock.
// The managed identity needs read access to the key (Key Vault Reader on
// it, cloud/azure/deploy.sh key-role); the release role alone does not
// allow Get Key. UNVERIFIED on Azure: the code ran against a fake.
func (kv *KeyVault) KeyRule(ctx context.Context, name string) (platform.KeyRule, error) {
	r, _, err := kv.CheckKey(ctx, name)
	return r, err
}

// CheckKey is KeyRule plus the key version the answer describes. kid is a
// key name, or name/version. The release must then name that version
// (RBRAZR-01): Get Key of a bare name answers the newest version, and a
// later release of the bare name may give a version made in between.
func (kv *KeyVault) CheckKey(ctx context.Context, kid string) (platform.KeyRule, CheckedKey, error) {
	access, err := kv.Tokens.Token(ctx, vaultResource)
	if err != nil {
		return platform.KeyRule{}, CheckedKey{}, err
	}
	url := fmt.Sprintf("https://%s/keys/%s?%s", kv.Endpoint, kid, akvAPIVersion)
	resp, err := httpDo(ctx, kv.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+access)
		return req, nil
	}, nil)
	if err != nil {
		return platform.KeyRule{}, CheckedKey{}, fmt.Errorf("azure: Key Vault get key: %w", err)
	}
	r, k, err := keyRuleOf(resp, kv.MAAHost)
	if err != nil {
		return platform.KeyRule{}, CheckedKey{}, err
	}
	if k.Version, err = checkedVersion(kid, k.Kid); err != nil {
		return platform.KeyRule{}, CheckedKey{}, err
	}
	return r, k, nil
}

// CheckedKey is the key version a Get Key answer describes.
type CheckedKey struct {
	Kid     string         // key.kid: https://<vault>/keys/<name>/<version>
	Version string         // the version part of Kid
	Pub     *rsa.PublicKey // key.n and key.e; nil if the answer has none
	// HostData is the image the release policy names (its
	// x-ms-sevsnpvm-hostdata literal), nil if the policy did not pass
	// checkReleasePolicy.
	HostData []byte
}

// Matches checks that a released key is this version: its public half is
// Pub, and the released kid, if the answer names one, is Kid.
func (k CheckedKey) Matches(key *rsa.PrivateKey, releasedKid string) error {
	if k.Pub == nil {
		return fmt.Errorf("azure: Get Key of %s gave no public key to compare the released key with", k.Kid)
	}
	if key.N.Cmp(k.Pub.N) != 0 || key.E != k.Pub.E {
		return fmt.Errorf("azure: the released key is not the key %s whose release policy the runner checked", k.Kid)
	}
	if releasedKid != "" && releasedKid != k.Kid {
		return fmt.Errorf("azure: Key Vault released %s, not the key %s whose release policy the runner checked", releasedKid, k.Kid)
	}
	return nil
}

var versionRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// checkedVersion returns the version of answered, the key.kid of a Get Key
// answer (https://<vault>/keys/<name>/<version>), after checking that it is
// the key kid asked for: the same name, and the same version if kid names
// one.
func checkedVersion(kid, answered string) (string, error) {
	name, want, _ := strings.Cut(kid, "/")
	_, rest, ok := strings.Cut(answered, "/keys/")
	gotName, version, ok2 := strings.Cut(rest, "/")
	switch {
	case !ok || !ok2 || !versionRE.MatchString(version):
		return "", fmt.Errorf("azure: Get Key answered key.kid %q, not https://<vault>/keys/<name>/<version>", answered)
	case gotName != name:
		return "", fmt.Errorf("azure: Get Key of %s answered key %s", kid, answered)
	case want != "" && version != want:
		return "", fmt.Errorf("azure: Get Key of %s answered version %s", kid, version)
	}
	return version, nil
}

// keyRuleOf reads a Get Key answer. key_release_hash is over the key id
// with version (key.kid), attributes.exportable, release_policy.immutable,
// release_policy.contentType and the policy bytes (release_policy.data,
// base64url), in that order, flags as one byte. An absent flag counts as
// false. The policy is locked when release_policy.immutable is true, so
// the policy cannot change, and the policy passes checkReleasePolicy for
// maaHost, so it releases the key to one measured image only. The public
// key (key.n, key.e) is not in the hash; the runner compares it with the
// released key.
func keyRuleOf(resp []byte, maaHost string) (platform.KeyRule, CheckedKey, error) {
	var out struct {
		Key struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"key"`
		Attributes struct {
			Exportable bool `json:"exportable"`
		} `json:"attributes"`
		ReleasePolicy *struct {
			ContentType string `json:"contentType"`
			Data        string `json:"data"`
			Immutable   bool   `json:"immutable"`
		} `json:"release_policy"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return platform.KeyRule{}, CheckedKey{}, fmt.Errorf("azure: Key Vault get key answer: %w", err)
	}
	rp := out.ReleasePolicy
	if out.Key.Kid == "" || rp == nil || rp.Data == "" {
		return platform.KeyRule{}, CheckedKey{}, errors.New("azure: Key Vault get key answer has no key.kid or no release_policy.data")
	}
	policy, err := decodeBase64(rp.Data)
	if err != nil {
		return platform.KeyRule{}, CheckedKey{}, fmt.Errorf("azure: release_policy.data: %w", err)
	}
	flag := func(b bool) []byte {
		if b {
			return []byte{1}
		}
		return []byte{0}
	}
	r := platform.KeyRule{Hash: backend.KeyReleaseHash(backend.KeyReleaseAzure, []byte(out.Key.Kid), flag(out.Attributes.Exportable),
		flag(rp.Immutable), []byte(rp.ContentType), policy), Lock: backend.KeyLockLocked}
	hostData, perr := checkReleasePolicy(policy, maaHost)
	var why []string
	if !rp.Immutable {
		why = append(why, "release_policy.immutable is false: the key's owner can change the release policy")
	}
	if perr != nil {
		why = append(why, "the release policy may release the key to more than one measured image: "+perr.Error())
	}
	if len(why) > 0 {
		r.Lock, r.Why = backend.KeyLockNotLocked, strings.Join(why, "; ")
	}
	k := CheckedKey{Kid: out.Key.Kid, HostData: hostData}
	if out.Key.N != "" || out.Key.E != "" {
		n, errN := decodeBase64(out.Key.N)
		e, errE := decodeBase64(out.Key.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return platform.KeyRule{}, CheckedKey{}, errors.New("azure: Key Vault get key answer: key.n or key.e is not a base64url number")
		}
		k.Pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return r, k, nil
}

// verifyJWS checks a compact JWS the way the sidecar does: the x5c leaf
// must verify for the vault's name against the roots, and its RSA key must
// have signed the token. It returns the payload.
func (kv *KeyVault) verifyJWS(compact string) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("azure: Key Vault answer is not a compact JWS")
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("azure: JWS header: %w", err)
	}
	var hdr struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, fmt.Errorf("azure: JWS header: %w", err)
	}
	if len(hdr.X5C) == 0 {
		return nil, errors.New("azure: JWS has no x5c certificate chain")
	}
	var certs []*x509.Certificate
	for i, c := range hdr.X5C {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("azure: JWS x5c[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("azure: JWS x5c[%d]: %w", i, err)
		}
		certs = append(certs, cert)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	now := time.Now()
	if kv.Now != nil {
		now = kv.Now()
	}
	host := kv.Endpoint
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: kv.Roots, Intermediates: inter, CurrentTime: now}); err != nil {
		return nil, fmt.Errorf("azure: JWS certificate chain: %w", err)
	}
	pub, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("azure: JWS signing key is not RSA")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("azure: JWS signature: %w", err)
	}
	var h crypto.Hash
	switch hdr.Alg {
	case "RS256", "PS256":
		h = crypto.SHA256
	case "RS384", "PS384":
		h = crypto.SHA384
	case "RS512", "PS512":
		h = crypto.SHA512
	default:
		return nil, fmt.Errorf("azure: JWS algorithm %q is not supported", hdr.Alg)
	}
	hh := h.New()
	hh.Write([]byte(parts[0] + "." + parts[1]))
	sum := hh.Sum(nil)
	if strings.HasPrefix(hdr.Alg, "RS") {
		err = rsa.VerifyPKCS1v15(pub, h, sum, sig)
	} else {
		err = rsa.VerifyPSS(pub, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	if err != nil {
		return nil, fmt.Errorf("azure: JWS signature: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("azure: JWS payload: %w", err)
	}
	return payload, nil
}

// wrapKeyRuntimeData is the MAA runtime data that offers pub to Key Vault as
// the key encryption key: a JWK set with one RSA key, key_ops encrypt, and
// the RFC 7638 thumbprint as kid (what the sidecar's jwx library assigns).
func wrapKeyRuntimeData(pub *rsa.PublicKey) ([]byte, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	n, e := b64(pub.N.Bytes()), b64(big.NewInt(int64(pub.E)).Bytes())
	sum := sha256.Sum256([]byte(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)))
	return json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "n": n, "e": e, "kid": b64(sum[:]), "key_ops": []string{"encrypt"},
	}}})
}

// unwrapReleased takes the verified payload of a release answer and returns
// the key material, decrypted with the wrapping key.
func unwrapReleased(payload []byte, wrap *rsa.PrivateKey) ([]byte, error) {
	plain, _, err := unwrapReleasedKid(payload, wrap)
	return plain, err
}

// unwrapReleasedKid is unwrapReleased plus the released key's kid
// (response.key.key.kid), "" if the payload has none. UNVERIFIED on Azure
// that a real answer carries it; the sidecar does not read it.
func unwrapReleasedKid(payload []byte, wrap *rsa.PrivateKey) ([]byte, string, error) {
	var p struct {
		Request struct {
			Enc string `json:"enc"`
		} `json:"request"`
		Response struct {
			Key struct {
				Key struct {
					Kid    string `json:"kid"`
					KeyHSM string `json:"key_hsm"`
				} `json:"key"`
			} `json:"key"`
		} `json:"response"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, "", fmt.Errorf("azure: release payload: %w", err)
	}
	hsm := p.Response.Key.Key.KeyHSM
	if hsm == "" {
		return nil, "", errors.New("azure: release payload has no response.key.key.key_hsm")
	}
	raw, err := decodeBase64(hsm)
	if err != nil {
		return nil, "", fmt.Errorf("azure: key_hsm: %w", err)
	}
	var blob struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, "", fmt.Errorf("azure: key_hsm: %w", err)
	}
	ct, err := decodeBase64(blob.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("azure: key_hsm ciphertext: %w", err)
	}
	plain, err := rsaAESUnwrap(p.Request.Enc, ct, wrap)
	return plain, p.Response.Key.Key.Kid, err
}

// rsaAESUnwrap undoes the RSA AES key wrap: OAEP for the AES key, then AES
// key wrap with padding for the target key.
func rsaAESUnwrap(enc string, wrapped []byte, priv *rsa.PrivateKey) ([]byte, error) {
	var h hash.Hash
	switch enc {
	case "", "CKM_RSA_AES_KEY_WRAP": // the default
		h = sha1.New() //nolint:gosec // defined with SHA-1
	case "RSA_AES_KEY_WRAP_256":
		h = sha256.New()
	case "RSA_AES_KEY_WRAP_384":
		h = sha512.New384()
	default:
		return nil, fmt.Errorf("azure: key wrap algorithm %q is not supported", enc)
	}
	k := priv.Size()
	if len(wrapped) <= k {
		return nil, errors.New("azure: wrapped key is too short")
	}
	kek, err := rsa.DecryptOAEP(h, nil, priv, wrapped[:k], nil)
	if err != nil {
		return nil, fmt.Errorf("azure: unwrap the key encryption key: %w", err)
	}
	defer clear(kek)
	return aesUnwrapWithPadding(kek, wrapped[k:])
}

// parseReleasedKey turns the unwrapped bytes into an RSA key. The sidecar
// reads a PKCS#8 private key for RSA. The earlier code of this package
// read a JWK from the sidecar, and parseRSAJWK still takes one, in case
// Key Vault ever releases the key that way. UNVERIFIED which of the two a
// real release holds.
func parseReleasedKey(plain []byte) (*rsa.PrivateKey, error) {
	t := bytes.TrimSpace(plain)
	if len(t) > 0 && t[0] == '{' {
		return parseRSAJWK(t)
	}
	k, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("azure: released key is not PKCS#8: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("azure: released key is not an RSA key")
	}
	if err := rk.Validate(); err != nil {
		return nil, fmt.Errorf("azure: released key: %w", err)
	}
	rk.Precompute()
	return rk, nil
}

// KeyReleaser gives the private RSA key behind a Key Vault key.
type KeyReleaser interface {
	ReleaseKey(ctx context.Context, name string) (*rsa.PrivateKey, error)
}

// Releaser is the in-process release: it needs the hardware report (through
// MAA) and the managed identity (through KV).
type Releaser struct {
	MAA *MAAClient
	KV  *KeyVault
	// Seen, if set, records the hostdata of every MAA token sent to Key
	// Vault: the runner's own image as its key release showed it.
	Seen *platform.ImageSeen
}

// tokenImage is the allowed_image_measurements entry of an MAA token: its
// x-ms-sevsnpvm-hostdata claim, the CCE policy hash. The token comes from
// MAA over TLS for a report the runner asked its own SEV-SNP device for, so
// its claims are read without the signature check (jwtclaims).
func tokenImage(tok string) (setupwire.Image, error) {
	c, err := jwtclaims.Claims(tok)
	if err != nil {
		return setupwire.Image{}, fmt.Errorf("azure: MAA token: %w", err)
	}
	hd, _ := c["x-ms-sevsnpvm-hostdata"].(string)
	b, err := hex.DecodeString(hd)
	if err != nil || len(b) != 32 {
		return setupwire.Image{}, fmt.Errorf("azure: MAA token: x-ms-sevsnpvm-hostdata %q is not 32 bytes of hex", hd)
	}
	return setupwire.Image{Kind: setupwire.ImageAzure, Measurement: b}, nil
}

func (r *Releaser) ReleaseKey(ctx context.Context, name string) (*rsa.PrivateKey, error) {
	key, _, err := r.releaseKid(ctx, name, nil)
	return key, err
}

// releaseKid is ReleaseKey plus the kid the answer names ("" if none). If
// policyImage is set (the hostdata the key's release policy names), a token
// that states another hostdata stops the release before Key Vault sees it:
// the policy is not for this runner's image.
func (r *Releaser) releaseKid(ctx context.Context, name string, policyImage []byte) (*rsa.PrivateKey, string, error) {
	wrap, err := rsa.GenerateKey(rand.Reader, wrapKeyBits)
	if err != nil {
		return nil, "", err
	}
	rt, err := wrapKeyRuntimeData(&wrap.PublicKey)
	if err != nil {
		return nil, "", err
	}
	target, err := r.MAA.Token(ctx, rt)
	if err != nil {
		return nil, "", err
	}
	im, imErr := tokenImage(target)
	r.Seen.Record(im, imErr)
	if policyImage != nil && (imErr != nil || !bytes.Equal(im.Measurement, policyImage)) {
		return nil, "", fmt.Errorf("azure: the key's release policy names image %x, this runner's MAA token states %x (%v)", policyImage, im.Measurement, imErr)
	}
	payload, err := r.KV.Release(ctx, name, target)
	if err != nil {
		return nil, "", err
	}
	plain, kid, err := unwrapReleasedKid(payload, wrap)
	if err != nil {
		return nil, "", err
	}
	defer clear(plain)
	key, err := parseReleasedKey(plain)
	return key, kid, err
}
