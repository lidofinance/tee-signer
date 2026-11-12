package gcp

import (
	"fmt"
	"regexp"
	"strconv"
)

// checkSetupProject refuses a wif_provider or kms_key outside the setup's
// project_number (sealing_key_release.project_number, option
// project_number; rv-d3u.6). number "" (a setup without it): no check.
// The WIF provider's name holds the project number. The KMS key may be
// named by that number or by a project ID. Cloud KMS takes the ID form
// only (a name with the number answers 403, rv-d18), so the ID form is the
// one that works. An ID cannot be matched to the number here; the key
// release does it with the launcher token, which names the VM's project ID
// and number (checkProject).
//
// Without project_number nothing here parses the names, so any project ID
// passes, a domain-scoped one ("example.com:signer") too. With it, the key
// name must be whole: no domain-scoped ID, no extra segments.
//
// The mark log and state buckets get their own check against the same
// number (tee-signer checkStoreProject).
func checkSetupProject(provider, key, number string) error {
	if number == "" {
		return nil
	}
	if n, err := strconv.ParseUint(number, 10, 64); err != nil || n == 0 {
		return fmt.Errorf("gcp: project_number %q is not a project number", number)
	}
	if m := providerNumberRE.FindStringSubmatch(provider); m == nil || m[1] != number {
		return fmt.Errorf("gcp: wif_provider %q is not a WIF provider of project %s, the setup's project_number", provider, number)
	}
	m := kmsKeyRE.FindStringSubmatch(key)
	if m == nil {
		return fmt.Errorf("gcp: kms_key %q is not a KMS key name (projects/PROJECT_ID/locations/L/keyRings/R/cryptoKeys/K)", key)
	}
	if isNumber(m[1]) && m[1] != number {
		return fmt.Errorf("gcp: kms_key %q is a KMS key of project %s, not of the setup's project_number %s", key, m[1], number)
	}
	return nil
}

// isNumber reports whether a project segment is a project number. A project
// ID starts with a letter, so the two forms never overlap.
func isNumber(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// Whole names: the KMS key goes into the request path as it is, so a name
// with more segments or "..", whose first segment names this project,
// could reach a key of another.
var (
	providerNumberRE = regexp.MustCompile(`^//iam\.googleapis\.com/projects/([0-9]+)/locations/global/workloadIdentityPools/[a-z0-9-]+/providers/[a-z0-9-]+$`)
)
