//go:build !verifierselect || platform_azure || platform_gcp

package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// Claims is a decoded JWT payload. Numbers are json.Number.
type Claims map[string]any

// maxToken bounds the size of a compact JWT the verifiers accept.
const maxToken = 256 << 10

// maxNumericDate refuses time claims past the year 9999.
const maxNumericDate = 253402300799

var b64url = base64.RawURLEncoding.Strict()

// verifyJWT checks a compact JWS signed with RS256 by a key in ks and
// returns its claims. It never follows jku, x5u or x5c from the token
// header: the keys come only from the caller.
func verifyJWT(token string, ks *KeySet) (Claims, error) {
	token = strings.TrimSpace(token)
	if len(token) > maxToken {
		return nil, fmt.Errorf("%w: token over %d bytes", ErrFormat, maxToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: JWT has %d parts, want 3", ErrFormat, len(parts))
	}
	hb, err := b64url.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: JWT header: %v", ErrFormat, err)
	}
	cb, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: JWT payload: %v", ErrFormat, err)
	}
	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: JWT signature: %v", ErrFormat, err)
	}
	var hdr map[string]any
	if err := decodeJSONObject(hb, &hdr); err != nil {
		return nil, fmt.Errorf("%w: JWT header: %v", ErrFormat, err)
	}
	if alg, _ := hdr["alg"].(string); alg != "RS256" {
		return nil, fmt.Errorf("%w: JWT alg %v, only RS256 is accepted", ErrSignature, hdr["alg"])
	}
	if _, ok := hdr["crit"]; ok {
		return nil, fmt.Errorf("%w: JWT header has crit, not supported", ErrFormat)
	}
	kid, _ := hdr["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("%w: JWT header has no kid", ErrFormat)
	}
	pub := ks.lookup(kid)
	if pub == nil {
		return nil, fmt.Errorf("%w: kid %q", ErrUnknownKey, kid)
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return nil, fmt.Errorf("%w: RS256 signature does not verify with kid %q", ErrSignature, kid)
	}
	var c Claims
	if err := decodeJSONObject(cb, &c); err != nil {
		return nil, fmt.Errorf("%w: JWT payload: %v", ErrFormat, err)
	}
	return c, nil
}

// decodeJSONObject decodes one JSON object with numbers kept as
// json.Number, and refuses duplicate member names at any depth, so two
// parsers cannot read different values from the same signed bytes.
func decodeJSONObject(b []byte, out any) error {
	if err := checkNoDuplicateKeys(b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after JSON object")
	}
	return nil
}

func checkNoDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("JSON nested too deep")
		}
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k := kt.(string)
				if seen[k] {
					return fmt.Errorf("duplicate JSON member %q", k)
				}
				seen[k] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token() // '}'
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token() // ']'
			return err
		}
		return nil
	}
	return walk(0)
}

// path resolves a dotted claim name ("x-ms-isolation-tee.x-ms-attestation-type").
func (c Claims) path(p string) (any, bool) {
	var cur any = map[string]any(c)
	for _, part := range strings.Split(p, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func (c Claims) str(p string) (string, bool) {
	v, ok := c.path(p)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (c Claims) boolean(p string) (bool, bool) {
	v, ok := c.path(p)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func (c Claims) integer(p string) (int64, bool) {
	v, ok := c.path(p)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// strList reads a claim that is a string or an array of strings.
func (c Claims) strList(p string) ([]string, bool) {
	v, ok := c.path(p)
	if !ok {
		return nil, false
	}
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func (c Claims) numericDate(name string) (time.Time, bool, error) {
	v, ok := c[name]
	if !ok {
		return time.Time{}, false, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, true, fmt.Errorf("%w: %s is not a number", ErrFormat, name)
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > maxNumericDate {
		return time.Time{}, true, fmt.Errorf("%w: %s out of range", ErrFormat, name)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true, nil
}

// TokenTimes are the standard time claims of a verified token.
type TokenTimes struct {
	IssuedAt, NotBefore, Expiry time.Time
}

// checkStandard checks iss, aud (if want is not empty), exp, nbf and iat.
func checkStandard(c Claims, issuer, audience string, now time.Time, skew, maxAge time.Duration) (TokenTimes, error) {
	var tt TokenTimes
	iss, _ := c.str("iss")
	if strings.TrimSuffix(iss, "/") != strings.TrimSuffix(issuer, "/") {
		return tt, fmt.Errorf("%w: iss %q, want %q", ErrIssuer, iss, issuer)
	}
	if audience != "" {
		auds, ok := c.strList("aud")
		found := false
		for _, a := range auds {
			found = found || a == audience
		}
		if !ok || !found {
			return tt, fmt.Errorf("%w: aud %v, want %q", ErrAudience, c["aud"], audience)
		}
	}
	exp, ok, err := c.numericDate("exp")
	if err != nil {
		return tt, err
	}
	if !ok {
		return tt, fmt.Errorf("%w: no exp", ErrFormat)
	}
	iat, ok, err := c.numericDate("iat")
	if err != nil {
		return tt, err
	}
	if !ok {
		return tt, fmt.Errorf("%w: no iat", ErrFormat)
	}
	nbf, hasNbf, err := c.numericDate("nbf")
	if err != nil {
		return tt, err
	}
	tt = TokenTimes{IssuedAt: iat, NotBefore: nbf, Expiry: exp}
	if !now.Before(exp.Add(skew)) {
		return tt, fmt.Errorf("%w: expired at %s", ErrExpired, exp.Format(time.RFC3339))
	}
	if hasNbf && now.Add(skew).Before(nbf) {
		return tt, fmt.Errorf("%w: not valid before %s", ErrExpired, nbf.Format(time.RFC3339))
	}
	if now.Add(skew).Before(iat) {
		return tt, fmt.Errorf("%w: issued in the future (%s)", ErrStale, iat.Format(time.RFC3339))
	}
	if maxAge > 0 && now.Sub(iat) > maxAge {
		return tt, fmt.Errorf("%w: issued at %s, older than %s", ErrStale, iat.Format(time.RFC3339), maxAge)
	}
	return tt, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
