package azure

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// releasePolicyClaims are the claims a release policy may test, with the
// value each must equal; "" means any literal the check below accepts (the
// hostdata). These are the claims of platform-azure/deploy/skr-policy.json.tmpl,
// and all four must be there.
var releasePolicyClaims = map[string]string{
	"x-ms-compliance-status":      "azure-compliant-uvm",
	"x-ms-sevsnpvm-hostdata":      "",
	"x-ms-sevsnpvm-is-debuggable": "false",
	"x-ms-sevsnpvm-vmpl":          "0",
}

var requiredClaims = []string{"x-ms-compliance-status", "x-ms-sevsnpvm-hostdata", "x-ms-sevsnpvm-is-debuggable", "x-ms-sevsnpvm-vmpl"}

// checkReleasePolicy checks that a Key Vault release policy releases the
// key only to a token from the attestation provider maaHost for one
// measured, non-debuggable image, and returns that image's hostdata (the
// CCE policy hash). An immutable policy that lets in anything else is no
// lock: whoever wrote it before setting immutable keeps a way to the key.
//
// The policy must have the shape of skr-policy.json.tmpl: version 1.0.0,
// an anyOf with exactly one authority, https://<maaHost>, whose allOf
// tests the claims of releasePolicyClaims with equals and string values,
// each claim once. The token's is-debuggable claim is a boolean; Key Vault
// released keys under the template's string "false" on a live vault, and
// a JSON false is taken too. The authority is compared without case but
// otherwise exactly: a trailing slash, a path or another port is refused,
// since nothing shows how Key Vault matches such a value with the token's
// iss. Any other member, operator, nested anyOf or allOf, a
// second authority, a duplicate JSON member or an all-zero hostdata is
// refused. Duplicate members are refused because JSON parsers differ on
// which one wins, and Key Vault's parser is not the runner's.
func checkReleasePolicy(policy []byte, maaHost string) ([]byte, error) {
	if maaHost == "" {
		return nil, errors.New("the runner has no maa_endpoint to compare the policy's authority with")
	}
	top, err := strictObject(policy, "version", "anyOf")
	if err != nil {
		return nil, err
	}
	var version string
	if err := strictString(top, "version", &version); err != nil {
		return nil, err
	}
	if version != "1.0.0" {
		return nil, fmt.Errorf("version is %q, want 1.0.0", version)
	}
	var anyOf []json.RawMessage
	if err := json.Unmarshal(top["anyOf"], &anyOf); err != nil || top["anyOf"] == nil {
		return nil, errors.New("anyOf is not a list")
	}
	if len(anyOf) != 1 {
		return nil, fmt.Errorf("anyOf has %d authorities, want exactly one", len(anyOf))
	}
	auth, err := strictObject(anyOf[0], "authority", "allOf")
	if err != nil {
		return nil, fmt.Errorf("anyOf[0]: %w", err)
	}
	var authority string
	if err := strictString(auth, "authority", &authority); err != nil {
		return nil, err
	}
	if !strings.EqualFold(authority, "https://"+maaHost) {
		return nil, fmt.Errorf("authority is %q, want https://%s, the setup's maa_endpoint", authority, maaHost)
	}
	var allOf []json.RawMessage
	if err := json.Unmarshal(auth["allOf"], &allOf); err != nil || auth["allOf"] == nil {
		return nil, errors.New("allOf is not a list")
	}
	seen := map[string]string{}
	for i, raw := range allOf {
		c, err := strictObject(raw, "claim", "equals")
		if err != nil {
			return nil, fmt.Errorf("allOf[%d]: %w", i, err)
		}
		var claim, value string
		if err := strictString(c, "claim", &claim); err != nil {
			return nil, fmt.Errorf("allOf[%d]: %w", i, err)
		}
		if claim == "x-ms-sevsnpvm-is-debuggable" && string(c["equals"]) == "false" {
			value = "false"
		} else if err := strictString(c, "equals", &value); err != nil {
			return nil, fmt.Errorf("allOf[%d] (%s): %w", i, claim, err)
		}
		want, known := releasePolicyClaims[claim]
		switch _, dup := seen[claim]; {
		case !known:
			return nil, fmt.Errorf("allOf[%d] tests claim %q, which the runner does not know", i, claim)
		case dup:
			return nil, fmt.Errorf("allOf tests claim %q twice", claim)
		case want != "" && value != want:
			return nil, fmt.Errorf("claim %s equals %q, want %q", claim, value, want)
		}
		seen[claim] = value
	}
	for _, claim := range requiredClaims {
		if _, ok := seen[claim]; !ok {
			return nil, fmt.Errorf("allOf does not test %s", claim)
		}
	}
	hd, err := hex.DecodeString(seen["x-ms-sevsnpvm-hostdata"])
	if err != nil || len(hd) != 32 {
		return nil, fmt.Errorf("x-ms-sevsnpvm-hostdata %q is not 32 bytes of hex", seen["x-ms-sevsnpvm-hostdata"])
	}
	if bytes.Equal(hd, make([]byte, 32)) {
		return nil, errors.New("x-ms-sevsnpvm-hostdata is all zero")
	}
	return hd, nil
}

// strictObject reads one JSON object with the members names, each at most
// once, and nothing after it. Absent members are absent from the map.
func strictObject(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		if !slices.Contains(names, k) {
			return nil, fmt.Errorf("member %q is not allowed (allowed: %s)", k, strings.Join(names, ", "))
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("member %q appears twice", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	return out, nil
}

// strictString reads the member name of obj, which must be a JSON string.
func strictString(obj map[string]json.RawMessage, name string, out *string) error {
	raw, ok := obj[name]
	if !ok {
		return fmt.Errorf("%s is missing", name)
	}
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, out) != nil {
		return fmt.Errorf("%s is not a string", name)
	}
	return nil
}
