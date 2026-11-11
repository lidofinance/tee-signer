package gcp

import (
	"fmt"
	"regexp"
	"strconv"
)

// checkSetupProject refuses a wif_provider or kms_key outside the setup's
// project_number (sealing_key_release.project_number, option
// project_number; rv-d3u.6). number "" (a setup without it): no check.
// The WIF provider's name holds the project number. The KMS key must be
// named by project number too, the same one: a key named by project ID
// cannot be matched to a number without an API call, so with
// project_number set that form is refused (rv-nsd.9).
//
// Without project_number nothing here parses the names, so any project ID
// passes, a domain-scoped one ("example.com:signer") too. With it, no
// name holds a project ID, so ':' and '.' never need to be allowed.
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
	m := keyNumberRE.FindStringSubmatch(key)
	if m == nil {
		return fmt.Errorf("gcp: kms_key %q is not a KMS key name by project number (projects/%s/locations/L/keyRings/R/cryptoKeys/K); with project_number set, the key is named by that number",
			key, number)
	}
	if m[1] != number {
		return fmt.Errorf("gcp: kms_key %q is a KMS key of project %s, not of the setup's project_number %s", key, m[1], number)
	}
	return nil
}

// Whole names: the KMS key goes into the request path as it is, so a name
// with more segments or "..", whose first segment names this project,
// could reach a key of another.
var (
	providerNumberRE = regexp.MustCompile(`^//iam\.googleapis\.com/projects/([0-9]+)/locations/global/workloadIdentityPools/[a-z0-9-]+/providers/[a-z0-9-]+$`)
	keyNumberRE      = regexp.MustCompile(`^projects/([0-9]+)/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`)
)
