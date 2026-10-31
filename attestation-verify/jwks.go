//go:build !verifierselect || platform_azure || platform_gcp

package attest

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// KeySet holds the RSA signing keys of one token issuer by key id.
type KeySet struct {
	keys map[string]*rsa.PublicKey
}

// minRSABits is the smallest RSA modulus accepted for token signatures.
const minRSABits = 2048

// ParseJWKS reads a JSON Web Key Set (RFC 7517). It keeps RSA keys meant
// for signatures (use "sig" or absent, alg "RS256" or absent) and skips
// the rest. When a key carries x5c, the first certificate's key must equal
// n and e; the certificate's validity is not checked, because the key set
// itself is the trust anchor (pinned, or fetched over TLS from the
// issuer).
func ParseJWKS(b []byte) (*KeySet, error) {
	var doc struct {
		Keys []struct {
			Kid string   `json:"kid"`
			Kty string   `json:"kty"`
			Alg string   `json:"alg"`
			Use string   `json:"use"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: jwks: %v", ErrFormat, err)
	}
	ks := &KeySet{keys: map[string]*rsa.PublicKey{}}
	for i, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if k.Kid == "" {
			return nil, fmt.Errorf("%w: jwks key %d has no kid", ErrFormat, i)
		}
		if _, dup := ks.keys[k.Kid]; dup {
			return nil, fmt.Errorf("%w: jwks has kid %q twice", ErrFormat, k.Kid)
		}
		var pub *rsa.PublicKey
		if k.N != "" || k.E != "" {
			p, err := rsaFromJWK(k.N, k.E)
			if err != nil {
				return nil, fmt.Errorf("%w: jwks kid %q: %v", ErrFormat, k.Kid, err)
			}
			pub = p
		}
		if len(k.X5c) > 0 {
			der, err := base64.StdEncoding.DecodeString(k.X5c[0])
			if err != nil {
				return nil, fmt.Errorf("%w: jwks kid %q x5c: %v", ErrFormat, k.Kid, err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("%w: jwks kid %q x5c: %v", ErrFormat, k.Kid, err)
			}
			cp, ok := c.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%w: jwks kid %q: x5c key is not RSA", ErrFormat, k.Kid)
			}
			if pub != nil && !pub.Equal(cp) {
				return nil, fmt.Errorf("%w: jwks kid %q: n/e differ from the x5c certificate", ErrFormat, k.Kid)
			}
			pub = cp
		}
		if pub == nil {
			return nil, fmt.Errorf("%w: jwks kid %q has neither n/e nor x5c", ErrFormat, k.Kid)
		}
		if pub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("%w: jwks kid %q: RSA key of %d bits", ErrFormat, k.Kid, pub.N.BitLen())
		}
		ks.keys[k.Kid] = pub
	}
	if len(ks.keys) == 0 {
		return nil, fmt.Errorf("%w: jwks has no RSA signing key", ErrFormat)
	}
	return ks, nil
}

func rsaFromJWK(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil || len(nb) == 0 {
		return nil, fmt.Errorf("bad n")
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, fmt.Errorf("bad e")
	}
	ev := new(big.Int).SetBytes(eb).Int64()
	if ev < 3 || ev%2 == 0 {
		return nil, fmt.Errorf("bad e %d", ev)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(ev)}, nil
}

// NewKeySet builds a key set from keys by key id (for tests and for
// callers that load keys some other way).
func NewKeySet(keys map[string]*rsa.PublicKey) *KeySet {
	ks := &KeySet{keys: map[string]*rsa.PublicKey{}}
	for k, v := range keys {
		ks.keys[k] = v
	}
	return ks
}

// KeyIDs lists the key ids in the set, sorted.
func (ks *KeySet) KeyIDs() []string {
	ids := make([]string, 0, len(ks.keys))
	for k := range ks.keys {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return ids
}

func (ks *KeySet) lookup(kid string) *rsa.PublicKey {
	if ks == nil {
		return nil
	}
	return ks.keys[kid]
}

const maxFetch = 1 << 20

// defaultFetchTimeout bounds a fetch when the caller passes no client.
const defaultFetchTimeout = 30 * time.Second

// hostPort is u's host in lower case and its port, the scheme's default
// when u names none, so host and host:443 compare equal for https.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("attest: refusing non-https URL %q", url)
	}
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}
	// A copy, so the caller's client keeps its own redirect rule. A
	// redirect off the requested scheme and host is refused: the host checks
	// on the URL (checkJWKSURI) would mean nothing if the answer could come
	// from elsewhere.
	c := *client
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		first := via[0].URL
		if r.URL.Scheme != first.Scheme || hostPort(r.URL) != hostPort(first) {
			return fmt.Errorf("attest: %s redirects to %s, another host", url, r.URL.Redacted())
		}
		if len(via) >= 10 {
			return fmt.Errorf("attest: %s: more than 10 redirects", url)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFetch+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFetch {
		return nil, fmt.Errorf("attest: %s: response over %d bytes", url, maxFetch)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest: %s: %s", url, resp.Status)
	}
	return b, nil
}

// FetchJWKS downloads and parses a key set over HTTPS.
func FetchJWKS(ctx context.Context, client *http.Client, url string) (*KeySet, error) {
	b, err := httpGet(ctx, client, url)
	if err != nil {
		return nil, err
	}
	return ParseJWKS(b)
}

// jwksOffHost lists the issuers whose key set lives on another host, with
// the one jwks_uri each may name. Confidential Space's discovery document
// names Google's service account key URL (ConfidentialSpaceJWKSURL in
// gcp.go, not built into every peer build).
var jwksOffHost = map[string]string{
	"https://confidentialcomputing.googleapis.com": "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
}

// checkJWKSURI refuses a jwks_uri off the issuer's scheme and host, other
// than the one jwksOffHost names for the issuer. Whoever answers for the
// issuer's name could otherwise point jwks_uri at a host of their own.
func checkJWKSURI(issuer, jwksURI string) error {
	if want, ok := jwksOffHost[issuer]; ok && jwksURI == want {
		return nil
	}
	iu, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: issuer %q: %v", ErrIssuer, issuer, err)
	}
	ju, err := url.Parse(jwksURI)
	if err != nil {
		return fmt.Errorf("%w: jwks_uri %q: %v", ErrIssuer, jwksURI, err)
	}
	if ju.Scheme != iu.Scheme || !strings.EqualFold(ju.Host, iu.Host) || ju.User != nil {
		return fmt.Errorf("%w: openid-configuration names jwks_uri %q, not on the issuer's host %s", ErrIssuer, jwksURI, iu.Host)
	}
	return nil
}

// DiscoverJWKS reads issuer/.well-known/openid-configuration, checks that
// it names the same issuer, and fetches the key set from its jwks_uri,
// which must be on the issuer's host (checkJWKSURI).
func DiscoverJWKS(ctx context.Context, client *http.Client, issuer string) (*KeySet, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	b, err := httpGet(ctx, client, issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("attest: openid-configuration: %w", err)
	}
	if strings.TrimSuffix(cfg.Issuer, "/") != issuer {
		return nil, fmt.Errorf("%w: openid-configuration names issuer %q, want %q", ErrIssuer, cfg.Issuer, issuer)
	}
	if err := checkJWKSURI(issuer, cfg.JWKSURI); err != nil {
		return nil, err
	}
	return FetchJWKS(ctx, client, cfg.JWKSURI)
}
