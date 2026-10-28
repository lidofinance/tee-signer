package gcp

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Who can plant a GCP data key (setup-phase.md, review A): whoever may
// encrypt with the KMS key. cloud/gcp/deploy.sh grants that role
// (cryptoKeyEncrypterDecrypter) on the key to the WIF principal set alone,
// the pool whose provider takes only attestation tokens of the pinned
// image. No step grants a KMS role, owner or editor to anything else; the
// service account the VM runs as gets none. This test reads the script and
// checks that. Bindings made outside the script (an admin who grants itself
// the role, roles inherited from the project or the organization) are not
// visible here or to the runner: GCP stays outside the admin-proof goal
// (review N).
func TestDeployGrantsKeyUseToThePrincipalSetOnly(t *testing.T) {
	dir := filepath.Join("..", "deploy")
	script, err := os.ReadFile(filepath.Join(dir, "deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// One command per line: join the lines a backslash continues.
	cmds := strings.Split(strings.ReplaceAll(string(script), "\\\n", " "), "\n")
	role := regexp.MustCompile(`--role=(\S+)`)
	member := regexp.MustCompile(`--member=("[^"]*"|\S+)`)
	kmsGrants := 0
	for _, c := range cmds {
		if !strings.Contains(c, "add-iam-policy-binding") {
			continue
		}
		r, m := role.FindStringSubmatch(c), member.FindStringSubmatch(c)
		if r == nil || m == nil {
			t.Fatalf("binding without --role or --member: %s", strings.TrimSpace(c))
		}
		switch granted := r[1]; {
		case strings.HasPrefix(granted, "roles/cloudkms."):
			if !strings.Contains(c, "gcloud kms keys add-iam-policy-binding \"$KMS_KEY\"") || m[1] != `"$WIF_PRINCIPAL_SET"` ||
				granted != "roles/cloudkms.cryptoKeyEncrypterDecrypter" {
				t.Errorf("a KMS role to something other than the WIF principal set on the key: %s", strings.TrimSpace(c))
			}
			kmsGrants++
		case granted == "roles/owner" || granted == "roles/editor" || strings.Contains(granted, "serviceAccountTokenCreator") ||
			strings.Contains(granted, "workloadIdentityUser"):
			t.Errorf("a role that reaches the key some other way: %s", strings.TrimSpace(c))
		}
	}
	if kmsGrants == 0 {
		t.Fatal("deploy.sh grants the key to no one: the script changed, check this test")
	}
	common, err := os.ReadFile(filepath.Join(dir, "common.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(common), `WIF_PRINCIPAL_SET="principalSet://iam.googleapis.com/$WIF_POOL_RESOURCE/*"`) {
		t.Fatal("WIF_PRINCIPAL_SET is no longer the pool's principal set")
	}
}
