// Package jwtclaims reads the claims of a JWT without verifying it. The
// runner uses it only on tokens it fetched itself: from the Confidential
// Space launcher socket, which is inside its trust boundary, and from MAA
// over TLS (the Azure clock). Relying parties outside must verify the
// signature.
package jwtclaims

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Claims decodes the payload of a compact JWT.
func Claims(token string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: want 3 parts")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	return c, nil
}

// Time reads a NumericDate claim such as iat.
func Time(c map[string]any, name string) (time.Time, error) {
	n, ok := c[name].(json.Number)
	if !ok {
		return time.Time{}, errors.New("jwt: no numeric " + name)
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(f), 0), nil
}
