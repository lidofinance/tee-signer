#!/usr/bin/env bash
# platform-aws/deploy/main.tf under `terraform test` with a mock AWS
# provider, in the pinned Terraform image. No AWS account is used.
#
#   defaults   the names of one node per account (role signer-parent, group
#              and instance signer-node), the key's description, no key
#              tags, four egress rules, no key pair
#   key_pair   ssh_public_key makes signer-node-operator-node-1, the
#              instance's key pair (a state of its own: a new instance)
#   key_pair_later
#              ssh_public_key on the running node of "defaults" makes the
#              key pair and leaves the instance's key_name (no replacement)
#   names      parent_role_name, security_group_name and _description,
#              instance_name, key_description and key_tags reach their
#              resources; node_key names the record writer and the key
#              pair; extra_egress adds its rule after the four
#   prev_pcrs  the key policy takes both images' PCR0 and PCR2 as lists and
#              one PCR1 as a string when the two are equal
#   locked     key_policy_locked = true makes the key at enclave_locked with
#              the lockout check bypassed and none at enclave; the key's
#              creation date reaches the kms_key_creation_date output
#   locked_pcr_change
#              a new pcr0 leaves the locked key's policy as it was
#   mark_bucket the bucket policy refuses puts under fewer days of retention
#              than mark_min_lock_days + 1, or none, and writes under marks/
#              and config/ by anyone but the writer user, and lifecycle
#              rules on the bucket by anyone; the writer may read the rules
#   min_days_* mark_min_lock_days refuses 0 and a part day, and is
#              required with mark_bucket
#
# The provider comes from TF_PLUGIN_DIR (a folder with
# registry.terraform.io/hashicorp/aws/...), or terraform init downloads it
# into build/tf-test/.terraform once, as in tf-validate.sh.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
dir="$BUILD/tf-test"
mkdir -p "$dir/tests"
cp "$ROOT/platform-aws/deploy/main.tf" "$dir/main.tf"
plug=()
if [ -n "${TF_PLUGIN_DIR:-}" ]; then
  [ -d "$TF_PLUGIN_DIR/registry.terraform.io" ] || { echo "TF_PLUGIN_DIR=$TF_PLUGIN_DIR has no registry.terraform.io folder" >&2; exit 1; }
  plug=(-v "$TF_PLUGIN_DIR:/plugins:ro")
fi
# With a local provider nothing needs the network.
net=()
[ ${#plug[@]} -eq 0 ] || net=(--network none)
tf() {
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e TF_IN_AUTOMATION=1 ${plug[@]+"${plug[@]}"} ${net[@]+"${net[@]}"} \
    -v "$dir:/w" -w /w "$TERRAFORM_IMAGE" "$@"
}

h() { printf '%096d' "$1"; } # a 96-digit PCR value
cat >"$dir/tests/main.tftest.hcl" <<EOF
mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = { vpc_id = "vpc-00000000000000000" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/parent" }
  }
  mock_resource "aws_iam_user" {
    defaults = { arn = "arn:aws:iam::111122223333:user/writer" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-000000000000" }
  }
  mock_data "aws_kms_key" {
    defaults = { creation_date = "2026-11-05T16:14:45Z" }
  }
}

variables {
  ami_id            = "ami-00000000000000000"
  subnet_id         = "subnet-00000000000000000"
  pcr0              = "$(h 1)"
  pcr1              = "$(h 2)"
  pcr2              = "$(h 3)"
  pcr3              = "$(h 4)"
  admin_role_arn    = "arn:aws:iam::111122223333:role/admin"
  key_policy_locked = false
}

run "defaults" {
  command = apply
  assert {
    condition     = aws_iam_role.parent.name == "signer-parent" && aws_iam_instance_profile.parent.name == "signer-parent" && aws_iam_role.parent.description == null
    error_message = "parent role and profile are not signer-parent"
  }
  assert {
    condition     = aws_security_group.node.name == "signer-node" && aws_security_group.node.description == "Managed by Terraform" && aws_instance.node.tags["Name"] == "signer-node"
    error_message = "security group or instance name changed"
  }
  assert {
    condition     = aws_kms_key.enclave[0].description == "signer-runner sealing key, enclave-only" && length(coalesce(aws_kms_key.enclave[0].tags, {})) == 0
    error_message = "key description or tags changed"
  }
  assert {
    condition     = length(aws_security_group.node.egress) == 4 && length(aws_security_group.node.ingress) == 0
    error_message = "egress is not 443, 4460, 123 and 4123, or there is an ingress rule"
  }
  assert {
    condition     = jsondecode(aws_kms_key.enclave[0].policy).Statement[2].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR0"] == "$(h 1)"
    error_message = "PCR0 is not the one value"
  }
  assert {
    condition     = length(aws_key_pair.operator) == 0 && output.key_pair_name == null
    error_message = "a key pair without ssh_public_key"
  }
}

run "key_pair" {
  command   = apply
  state_key = "key_pair"
  variables {
    ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0000000000000000000000000000000000000000000 op"
  }
  assert {
    condition     = aws_key_pair.operator[0].key_name == "signer-node-operator-node-1" && aws_instance.node.key_name == "signer-node-operator-node-1" && output.key_pair_name == "signer-node-operator-node-1"
    error_message = "the key pair is not signer-node-operator-node-1, or not the instance's"
  }
}

run "key_pair_later" {
  command = plan
  variables {
    ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0000000000000000000000000000000000000000000 op"
  }
  assert {
    condition     = aws_key_pair.operator[0].key_name == "signer-node-operator-node-1" && aws_instance.node.key_name != "signer-node-operator-node-1"
    error_message = "a key pair set on a running node changes the instance's key_name (which replaces it)"
  }
}

run "names" {
  command = apply
  variables {
    parent_role_name           = "node-a-parent"
    parent_role_description    = "parent of node a"
    security_group_name        = "node-a"
    security_group_description = "node a parent"
    instance_name              = "node-a"
    key_description            = "node a sealing key"
    key_tags                   = { node = "a" }
    node_key                   = "node-a"
    ssh_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0000000000000000000000000000000000000000000 op"
    extra_egress = [{
      description = "entry"
      protocol    = "udp"
      from_port   = 0
      to_port     = 65535
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }
  assert {
    condition     = aws_iam_role.parent.name == "node-a-parent" && aws_iam_instance_profile.parent.name == "node-a-parent" && aws_iam_role.parent.description == "parent of node a"
    error_message = "parent_role_name or its description not used"
  }
  assert {
    condition     = aws_security_group.node.name == "node-a" && aws_security_group.node.description == "node a parent" && aws_instance.node.tags["Name"] == "node-a"
    error_message = "security group or instance names not used"
  }
  assert {
    condition     = aws_kms_key.enclave[0].description == "node a sealing key" && aws_kms_key.enclave[0].tags["node"] == "a"
    error_message = "key_description or key_tags not used"
  }
  assert {
    condition     = aws_key_pair.operator[0].key_name == "signer-node-operator-node-a" && aws_iam_user.record_writer.name == "signer-record-writer-node-a"
    error_message = "node_key does not name the key pair and the record writer"
  }
  assert {
    condition     = length(aws_security_group.node.egress) == 5 && anytrue([for r in aws_security_group.node.egress : r.description == "entry" && r.protocol == "udp" && r.to_port == 65535])
    error_message = "extra_egress rule missing"
  }
}

run "prev_pcrs" {
  command = apply
  variables {
    prev_pcrs = { pcr0 = "$(h 5)", pcr1 = "$(h 2)", pcr2 = "$(h 6)" }
  }
  assert {
    condition = (jsondecode(aws_kms_key.enclave[0].policy).Statement[2].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR0"] == ["$(h 1)", "$(h 5)"]
      && jsondecode(aws_kms_key.enclave[0].policy).Statement[2].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR1"] == "$(h 2)"
    && jsondecode(aws_kms_key.enclave[0].policy).Statement[2].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR2"] == ["$(h 3)", "$(h 6)"])
    error_message = "prev_pcrs not in the key policy as lists"
  }
}

run "locked" {
  command = apply
  variables {
    key_policy_locked = true
  }
  assert {
    condition     = length(aws_kms_key.enclave) == 0 && length(aws_kms_key.enclave_locked) == 1 && aws_kms_key.enclave_locked[0].bypass_policy_lockout_safety_check
    error_message = "a locked key is not at enclave_locked with the lockout check bypassed"
  }
  assert {
    condition     = jsondecode(aws_kms_key.enclave_locked[0].policy).Statement[2].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR0"] == "$(h 1)"
    error_message = "PCR0 is not in the locked key's policy"
  }
  assert {
    condition     = output.kms_key_creation_date == "2026-11-05T16:14:45Z"
    error_message = "kms_key_creation_date is not the key's creation date"
  }
}

run "locked_pcr_change" {
  command = plan
  variables {
    key_policy_locked = true
    pcr0              = "$(h 7)"
  }
  assert {
    condition     = jsondecode(aws_kms_key.enclave_locked[0].policy).Statement[2].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR0"] == "$(h 1)"
    error_message = "a plan writes the policy of the locked key"
  }
}

run "mark_bucket" {
  command = apply
  variables {
    mark_bucket        = "signer-marks"
    mark_min_lock_days = 30
  }
  assert {
    condition = (one([for st in jsondecode(aws_s3_bucket_policy.marks[0].policy).Statement : st.Condition.NumericLessThan["s3:object-lock-remaining-retention-days"] if st.Sid == "ShortRetention"]) == 31
    && one([for st in jsondecode(aws_s3_bucket_policy.marks[0].policy).Statement : st.Condition.Null["s3:object-lock-remaining-retention-days"] if st.Sid == "NoRetention"]) == "true")
    error_message = "the bucket policy does not refuse puts with short or no retention"
  }
  assert {
    condition = (one([for st in jsondecode(aws_s3_bucket_policy.marks[0].policy).Statement : st if st.Sid == "OnlyWriterWrites"]) == {
      Sid       = "OnlyWriterWrites"
      Effect    = "Deny"
      Principal = "*"
      Action    = ["s3:PutObject", "s3:PutObjectRetention", "s3:ReplicateObject", "s3:ReplicateDelete"]
      Resource  = ["arn:aws:s3:::signer-marks/marks/*", "arn:aws:s3:::signer-marks/config/*"]
      Condition = { StringNotEquals = { "aws:PrincipalArn" = "arn:aws:iam::111122223333:user/writer" } }
    })
    error_message = "the bucket policy does not deny writes under marks/ and config/ to every principal but the writer"
  }
  assert {
    condition = (one([for st in jsondecode(aws_s3_bucket_policy.marks[0].policy).Statement : st if st.Sid == "NoLifecycleRules"]) == {
      Sid       = "NoLifecycleRules"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:PutLifecycleConfiguration"
      Resource  = "arn:aws:s3:::signer-marks"
    })
    error_message = "the bucket policy does not deny lifecycle rules to every principal"
  }
  assert {
    condition     = contains(one([for st in jsondecode(aws_s3_bucket_policy.marks[0].policy).Statement : st.Action if st.Sid == "EnclaveWriterListsAndChecksTheLock"]), "s3:GetLifecycleConfiguration")
    error_message = "the writer cannot read the lifecycle rules for the lock check"
  }
}

run "min_days_zero" {
  command = plan
  variables {
    mark_bucket        = "signer-marks"
    mark_min_lock_days = 0
  }
  expect_failures = [var.mark_min_lock_days]
}

run "min_days_missing" {
  command = plan
  variables {
    mark_bucket = "signer-marks"
  }
  expect_failures = [var.mark_min_lock_days]
}

run "min_days_frac" {
  command = plan
  variables {
    mark_bucket        = "signer-marks"
    mark_min_lock_days = 1.5
  }
  expect_failures = [var.mark_min_lock_days]
}
EOF

if [ ! -d "$dir/.terraform/providers" ]; then
  if [ ${#plug[@]} -gt 0 ]; then
    tf init -backend=false -input=false -no-color -plugin-dir=/plugins >/dev/null
  else
    tf init -backend=false -input=false -no-color >/dev/null
  fi
fi
tf test -no-color
echo "aws-tf-test: all cases as expected"
