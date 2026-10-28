//go:build !peerselect || peer_azure

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Compliance status values from the Azure SKR policy examples
// (https://learn.microsoft.com/en-us/azure/confidential-computing/skr-policy-examples).
const (
	// ComplianceACI is the value for confidential containers on ACI.
	ComplianceACI = "azure-compliant-uvm"
	// ComplianceCVM is the value for confidential VMs.
	ComplianceCVM = "azure-compliant-cvm"
)

// MAAOptions configures VerifyMAA.
type MAAOptions struct {
	// Issuer is the attestation provider URL, e.g.
	// "https://myprovider.weu.attest.azure.net". Required. Each provider
	// has its own key set at Issuer + "/certs".
	Issuer string
	// Keys are the provider's signing keys (pinned, or DiscoverJWKS).
	Keys *KeySet
	// Now is the verification time; zero means time.Now().
	Now time.Time
	// Skew is the allowed clock difference; zero means DefaultSkew.
	Skew time.Duration
	// MaxAge, if positive, bounds the age of iat. Either RuntimeData or
	// MaxAge must be set.
	MaxAge time.Duration
	// ComplianceStatus is the required x-ms-compliance-status: ComplianceACI
	// or ComplianceCVM. Required.
	ComplianceStatus string
	// HostData lists accepted x-ms-sevsnpvm-hostdata values (hex). On ACI
	// this is the SHA-256 of the CCE policy, which pins the containers.
	HostData []string
	// LaunchMeasurements lists accepted x-ms-sevsnpvm-launchmeasurement
	// values (hex).
	LaunchMeasurements []string
	// VMID, if set, must equal x-ms-azurevm-vmid (guest attestation) or
	// x-ms-runtime.vm-configuration.vmUniqueId (HCL report), ignoring case.
	VMID string
	// AcceptAnyWorkload allows none of HostData, LaunchMeasurements and
	// VMID. For inspecting a token only.
	AcceptAnyWorkload bool
	// RuntimeData, if not nil, is the runtime data the runner sent to MAA;
	// x-ms-sevsnpvm-reportdata must be its SHA-256 followed by 32 zero
	// bytes (pkg/attest/attest.go in microsoft/confidential-sidecar-containers).
	RuntimeData []byte
	// Policy, if set, must also hold for the token, as Key Vault would
	// evaluate it for a release.
	Policy *ReleasePolicy
	// AllowDebug accepts x-ms-sevsnpvm-is-debuggable true. Never set it in
	// production.
	AllowDebug bool
}

// MAAToken is a verified Microsoft Azure Attestation token.
type MAAToken struct {
	Claims Claims
	Times  TokenTimes
	// AttestationType is the top-level x-ms-attestation-type ("sevsnpvm"
	// on ACI, "azurevm" for confidential VM guest attestation).
	AttestationType string
	// TEE holds the SEV-SNP claims: the top level, or
	// x-ms-isolation-tee for guest attestation tokens.
	TEEType           string
	ComplianceStatus  string
	HostData          string
	LaunchMeasurement string
	ReportData        string
	IsDebuggable      bool
	VMPL              int64
	VMID              string
	PolicyHash        string
	Runtime           map[string]any
}

// VerifyMAA verifies an MAA token (RS256, key set of one provider) and
// the claims our release policy depends on: TEE type, compliance status,
// debug off, VMPL 0, workload binding, VM id and runtime data.
func VerifyMAA(token string, o MAAOptions) (*MAAToken, error) {
	switch {
	case o.Issuer == "":
		return nil, fmt.Errorf("%w: no issuer", ErrConfig)
	case o.Keys == nil:
		return nil, fmt.Errorf("%w: no key set", ErrConfig)
	case o.ComplianceStatus == "":
		return nil, fmt.Errorf("%w: no compliance status", ErrConfig)
	case len(o.HostData) == 0 && len(o.LaunchMeasurements) == 0 && o.VMID == "" && !o.AcceptAnyWorkload:
		return nil, fmt.Errorf("%w: set HostData, LaunchMeasurements or VMID", ErrConfig)
	case o.RuntimeData == nil && o.MaxAge <= 0:
		return nil, fmt.Errorf("%w: set RuntimeData or MaxAge", ErrConfig)
	}
	c, err := verifyJWT(token, o.Keys)
	if err != nil {
		return nil, err
	}
	tt, err := checkStandard(c, o.Issuer, "", nowOr(o.Now), skewOr(o.Skew), o.MaxAge)
	if err != nil {
		return nil, err
	}
	t := &MAAToken{Claims: c, Times: tt}
	t.AttestationType, _ = c.str("x-ms-attestation-type")
	t.PolicyHash, _ = c.str("x-ms-policy-hash")
	t.Runtime, _ = c["x-ms-runtime"].(map[string]any)

	// Guest attestation tokens nest the hardware claims in
	// x-ms-isolation-tee (SKR policy example 2 for confidential VMs).
	pre := ""
	if t.AttestationType == "azurevm" {
		if _, ok := c["x-ms-isolation-tee"].(map[string]any); !ok {
			return nil, fmt.Errorf("%w: azurevm token without x-ms-isolation-tee", ErrFormat)
		}
		pre = "x-ms-isolation-tee."
	}
	t.TEEType, _ = c.str(pre + "x-ms-attestation-type")
	t.ComplianceStatus, _ = c.str(pre + "x-ms-compliance-status")
	t.HostData, _ = c.str(pre + "x-ms-sevsnpvm-hostdata")
	t.LaunchMeasurement, _ = c.str(pre + "x-ms-sevsnpvm-launchmeasurement")
	t.ReportData, _ = c.str(pre + "x-ms-sevsnpvm-reportdata")
	if id, ok := c.str("x-ms-azurevm-vmid"); ok {
		t.VMID = id
	} else {
		t.VMID, _ = c.str("x-ms-runtime.vm-configuration.vmUniqueId")
	}

	if t.TEEType != "sevsnpvm" {
		return nil, fmt.Errorf("%w: TEE type %q, want sevsnpvm", ErrClaim, t.TEEType)
	}
	if t.ComplianceStatus != o.ComplianceStatus {
		return nil, fmt.Errorf("%w: x-ms-compliance-status %q, want %q", ErrClaim, t.ComplianceStatus, o.ComplianceStatus)
	}
	dbg, ok := c.boolean(pre + "x-ms-sevsnpvm-is-debuggable")
	if !ok {
		return nil, fmt.Errorf("%w: no boolean x-ms-sevsnpvm-is-debuggable", ErrDebug)
	}
	t.IsDebuggable = dbg
	if dbg && !o.AllowDebug {
		return nil, fmt.Errorf("%w: x-ms-sevsnpvm-is-debuggable is true", ErrDebug)
	}
	vmpl, ok := c.integer(pre + "x-ms-sevsnpvm-vmpl")
	if !ok || vmpl != 0 {
		got, _ := c.path(pre + "x-ms-sevsnpvm-vmpl")
		return nil, fmt.Errorf("%w: x-ms-sevsnpvm-vmpl %v, want 0", ErrClaim, got)
	}
	t.VMPL = vmpl
	if len(o.HostData) > 0 && !containsFold(o.HostData, t.HostData) {
		return nil, fmt.Errorf("%w: x-ms-sevsnpvm-hostdata %q not in %v", ErrMeasurement, t.HostData, o.HostData)
	}
	if len(o.LaunchMeasurements) > 0 && !containsFold(o.LaunchMeasurements, t.LaunchMeasurement) {
		return nil, fmt.Errorf("%w: x-ms-sevsnpvm-launchmeasurement %q not in %v", ErrMeasurement, t.LaunchMeasurement, o.LaunchMeasurements)
	}
	if o.VMID != "" && !strings.EqualFold(o.VMID, t.VMID) {
		return nil, fmt.Errorf("%w: VM id %q, want %q", ErrClaim, t.VMID, o.VMID)
	}
	if o.RuntimeData != nil {
		sum := sha256.Sum256(o.RuntimeData)
		want := hex.EncodeToString(sum[:]) + strings.Repeat("00", 32)
		if !strings.EqualFold(t.ReportData, want) {
			return nil, fmt.Errorf("%w: x-ms-sevsnpvm-reportdata %q, want sha256(runtime data) %q", ErrNonce, t.ReportData, want)
		}
	}
	if o.Policy != nil {
		if err := o.Policy.Check(c); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func containsFold(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

// ReleasePolicy is an Azure Key Vault secure key release policy
// (https://learn.microsoft.com/en-us/azure/key-vault/keys/policy-grammar).
// Only the "equals" operator is supported, which the grammar page calls
// the only allowed condition "in the first iteration"; a policy with any
// other operator fails to parse.
type ReleasePolicy struct {
	anyOf, allOf []authorityRule
}

type authorityRule struct {
	authority string
	cond      condition
}

type condition struct {
	claim string
	value any // string, json.Number or bool
	anyOf []condition
	allOf []condition
}

// ParseReleasePolicy parses a release policy in JSON.
func ParseReleasePolicy(b []byte) (*ReleasePolicy, error) {
	var raw map[string]any
	if err := decodeJSONObject(b, &raw); err != nil {
		return nil, fmt.Errorf("%w: release policy: %v", ErrFormat, err)
	}
	p := &ReleasePolicy{}
	for k, v := range raw {
		switch strings.ToLower(k) {
		case "version":
			if v != "1.0.0" {
				return nil, fmt.Errorf("%w: release policy version %v, want 1.0.0", ErrFormat, v)
			}
		case "anyof", "allof":
			list, ok := v.([]any)
			if !ok || len(list) == 0 {
				return nil, fmt.Errorf("%w: release policy %s is not a non-empty array", ErrFormat, k)
			}
			for _, e := range list {
				r, err := parseAuthority(e)
				if err != nil {
					return nil, err
				}
				if strings.ToLower(k) == "anyof" {
					p.anyOf = append(p.anyOf, r)
				} else {
					p.allOf = append(p.allOf, r)
				}
			}
		default:
			return nil, fmt.Errorf("%w: release policy field %q", ErrFormat, k)
		}
	}
	if len(p.anyOf) == 0 && len(p.allOf) == 0 {
		return nil, fmt.Errorf("%w: release policy has no authority", ErrFormat)
	}
	return p, nil
}

func parseAuthority(v any) (authorityRule, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return authorityRule{}, fmt.Errorf("%w: release policy authority is not an object", ErrFormat)
	}
	var r authorityRule
	r.authority, _ = m["authority"].(string)
	if r.authority == "" {
		return r, fmt.Errorf("%w: release policy authority without a URL", ErrFormat)
	}
	rest := map[string]any{}
	for k, e := range m {
		if k != "authority" {
			rest[k] = e
		}
	}
	c, err := parseCondition(rest)
	if err != nil {
		return r, err
	}
	if c.claim != "" {
		return r, fmt.Errorf("%w: authority %q needs anyOf or allOf", ErrFormat, r.authority)
	}
	r.cond = c
	return r, nil
}

func parseCondition(m map[string]any) (condition, error) {
	var c condition
	if len(m) != 1 && len(m) != 2 {
		return c, fmt.Errorf("%w: release policy condition %v", ErrFormat, m)
	}
	for k, v := range m {
		switch strings.ToLower(k) {
		case "claim":
			s, ok := v.(string)
			if !ok || s == "" {
				return c, fmt.Errorf("%w: release policy claim name %v", ErrFormat, v)
			}
			c.claim = s
		case "equals":
			switch v.(type) {
			case string, json.Number, bool:
				c.value = v
			default:
				return c, fmt.Errorf("%w: release policy value %v is not a string, number or bool", ErrFormat, v)
			}
		case "anyof", "allof":
			list, ok := v.([]any)
			if !ok || len(list) == 0 {
				return c, fmt.Errorf("%w: release policy %s is not a non-empty array", ErrFormat, k)
			}
			for _, e := range list {
				em, ok := e.(map[string]any)
				if !ok {
					return c, fmt.Errorf("%w: release policy condition is not an object", ErrFormat)
				}
				sub, err := parseCondition(em)
				if err != nil {
					return c, err
				}
				if strings.ToLower(k) == "anyof" {
					c.anyOf = append(c.anyOf, sub)
				} else {
					c.allOf = append(c.allOf, sub)
				}
			}
		default:
			return c, fmt.Errorf("%w: release policy operator %q not supported (only equals)", ErrFormat, k)
		}
	}
	nClaim := 0
	if c.claim != "" {
		nClaim = 1
	}
	groups := 0
	if c.anyOf != nil {
		groups++
	}
	if c.allOf != nil {
		groups++
	}
	switch {
	case nClaim == 1 && (c.value == nil || groups > 0):
		return c, fmt.Errorf("%w: claim %q needs exactly one equals", ErrFormat, c.claim)
	case nClaim == 0 && groups != 1:
		return c, fmt.Errorf("%w: condition needs a claim, anyOf or allOf", ErrFormat)
	}
	return c, nil
}

// Check evaluates the policy against verified claims: an authority rule
// applies when its URL equals the token's iss.
func (p *ReleasePolicy) Check(c Claims) error {
	iss, _ := c.str("iss")
	match := func(r authorityRule) error {
		if strings.TrimSuffix(r.authority, "/") != strings.TrimSuffix(iss, "/") {
			return fmt.Errorf("%w: policy authority %q, token iss %q", ErrIssuer, r.authority, iss)
		}
		return r.cond.eval(c)
	}
	for _, r := range p.allOf {
		if err := match(r); err != nil {
			return fmt.Errorf("release policy: %w", err)
		}
	}
	if len(p.anyOf) == 0 {
		return nil
	}
	var first error
	for _, r := range p.anyOf {
		err := match(r)
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return fmt.Errorf("release policy: no authority rule holds: %w", first)
}

func (cd condition) eval(c Claims) error {
	switch {
	case cd.claim != "":
		got, ok := c.path(cd.claim)
		if !ok {
			return fmt.Errorf("%w: policy claim %q missing", ErrClaim, cd.claim)
		}
		if !policyEquals(cd.value, got) {
			err := ErrClaim
			if strings.HasSuffix(cd.claim, "is-debuggable") {
				err = ErrDebug
			}
			return fmt.Errorf("%w: policy claim %q is %v, want %v", err, cd.claim, got, cd.value)
		}
		return nil
	case cd.allOf != nil:
		for _, s := range cd.allOf {
			if err := s.eval(c); err != nil {
				return err
			}
		}
		return nil
	default:
		var first error
		for _, s := range cd.anyOf {
			err := s.eval(c)
			if err == nil {
				return nil
			}
			if first == nil {
				first = err
			}
		}
		return first
	}
}

// policyEquals compares a policy value with a claim. A string policy value
// also matches a bool or number claim with the same text ("false", "0"),
// because cloud/azure/skr-policy.json.tmpl writes them as strings; the
// grammar page does not say how Key Vault compares types.
func policyEquals(want, got any) bool {
	switch w := want.(type) {
	case string:
		switch g := got.(type) {
		case string:
			return g == w
		case bool:
			return fmt.Sprint(g) == w
		case json.Number:
			return g.String() == w
		}
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case json.Number:
		g, ok := got.(json.Number)
		return ok && g.String() == w.String()
	}
	return false
}
