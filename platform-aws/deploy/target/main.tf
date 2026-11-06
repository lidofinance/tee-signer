# A second Nitro signer next to a running one.
#
# Its own root module and state, so no plan here can change the running
# signer's resources. It reads them by name (the parent role and its
# instance profile, the security group, the operator key pair) and makes
# two things of its own:
#
#   aws_kms_key.target     a new KMS key whose policy releases data keys only
#                          to the target EIF's PCR0..2 on a parent with the
#                          same role (the same PCR3), lets the parent role
#                          read the key and its policy (key_release_hash,
#                          platform-aws/nitro ReleaseHash), and lets the
#                          key admin encrypt the record credentials with
#                          purpose=record-creds and nothing else. No
#                          prev_pcrs: the source's PCRs are never in it.
#   aws_instance.target    a second c6g.large parent with Nitro Enclaves, the
#                          same role, subnet and security group. One parent
#                          cannot hold two enclaves here: each enclave takes
#                          one of the two vCPUs, and the vsock port map and
#                          the host agent serve one setup. Made only with
#                          instance = true, so the key can come first: the
#                          target's setup names the key, and the admin
#                          encrypts the writer credentials under it, before
#                          the parent starts.
#
# The record writer stays the running signer's IAM user, so the mark
# bucket's policy needs no change. The admin gives the target its own copy:
# a second access key of that user, encrypted under the new key
# (platform-aws/deploy/README.md, "Clone protection"; the user has one key, and an IAM
# user may hold two).
#
# Inputs: the target EIF's PCR0..2 (build/nitro-.../build-enclave-aarch64.json
# of the prover tree), and the running signer's region, AMI, subnet, PCR3 and
# admin role, the same values as its terraform.tfvars.

terraform {
  required_version = ">= 1.1" # moves a key made before count to [0]
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "region" { default = "eu-central-1" }
variable "name" {
  description = "the target's name: the instance's Name tag and the key's description, for example signer-node-2b"
  default     = "signer-node-2b"
}
variable "instance" {
  description = "false: the key only. true: the key and the parent instance (billed per second while it runs)"
  type        = bool
  default     = false
}
variable "instance_type" { default = "c6g.large" }
variable "ami_id" { description = "the running parent's AMI (Amazon Linux 2023, arm64 for c6g.large)" }
variable "subnet_id" { description = "the running parent's subnet" }
variable "pcr0" { description = "PCR0 of the target EIF" }
variable "pcr1" { description = "PCR1 of the target EIF" }
variable "pcr2" { description = "PCR2 of the target EIF" }
variable "pcr3" { description = "PCR3 of the parent role, the running signer's value (the role does not change)" }
variable "admin_role_arn" { description = "the role that administers the key and encrypts the record credentials" }
variable "key_policy_locked" {
  description = "true: create the key with its final policy, which no principal may change (no kms:PutKeyPolicy), so it never has a mutable phase (AWS-KMS-02, platform-aws/deploy/README.md). Required for a mainnet target. Once locked, the admin can never tag or untag the key, change its description or turn off its rotation, so any later Terraform change to aws_kms_key.target_locked fails. Nobody can schedule its deletion either: the key stays until the account closes. Terraform must run as admin_role_arn. false: the admin keeps kms:PutKeyPolicy (tests, devnets). Changing it replaces the key, as in ../main.tf."
  type        = bool
}
variable "parent_role_name" { default = "signer-parent" }
variable "security_group_name" { default = "signer-node" }
variable "key_pair_name" {
  description = "the running parent's key pair (the key_pair_name output of ../main.tf: signer-node-operator-<node_key>, signer-node-operator before that); empty: none"
  default     = "signer-node-operator-node-1"
}

provider "aws" { region = var.region }

data "aws_iam_role" "parent" { name = var.parent_role_name }
data "aws_iam_instance_profile" "parent" { name = var.parent_role_name }
data "aws_subnet" "sel" { id = var.subnet_id }
data "aws_security_group" "node" {
  name   = var.security_group_name
  vpc_id = data.aws_subnet.sel.vpc_id
}

locals {
  hex96 = "^[0-9a-f]{96}$"
}

# Keep the statements in step with ../main.tf and
# ../kms-key-policy.json.tmpl (the template is what the lock check tests).
locals {
  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = var.admin_role_arn }
        Action = concat(["kms:Describe*", "kms:Get*", "kms:List*"], var.key_policy_locked ? [] : ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"],
        ["kms:EnableKeyRotation", "kms:CancelKeyDeletion"])
        Resource = "*"
      },
      {
        # The record credentials only: the runner's own keys carry other
        # contexts (platform-aws/deploy/main.tf, the same statement).
        Sid       = "OperatorEncryptsRecordCredentials"
        Effect    = "Allow"
        Principal = { AWS = var.admin_role_arn }
        Action    = ["kms:Encrypt"]
        Resource  = "*"
        Condition = {
          StringEquals                = { "kms:EncryptionContext:purpose" = "record-creds" }
          "ForAllValues:StringEquals" = { "kms:EncryptionContextKeys" = ["purpose"] }
        }
      },
      {
        Sid       = "EnclaveOnlyDataKeys"
        Effect    = "Allow"
        Principal = { AWS = data.aws_iam_role.parent.arn }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.pcr0
            "kms:RecipientAttestation:PCR1" = var.pcr1
            "kms:RecipientAttestation:PCR2" = var.pcr2
            "kms:RecipientAttestation:PCR3" = var.pcr3
          }
        }
      },
      {
        Sid       = "EnclaveReadsItsKeyPolicy"
        Effect    = "Allow"
        Principal = { AWS = data.aws_iam_role.parent.arn }
        Action    = ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"]
        Resource  = "*"
      }
    ]
  })
  pcrs_ok = alltrue([for p in [var.pcr0, var.pcr1, var.pcr2, var.pcr3] : can(regex(local.hex96, p))])
}

# As in ../main.tf: one key resource per value of key_policy_locked, so a
# change of the flag replaces the key.
resource "aws_kms_key" "target" {
  count               = var.key_policy_locked ? 0 : 1
  description         = "signer-runner sealing key, enclave-only, ${var.name} (handover target)"
  enable_key_rotation = true
  policy              = local.key_policy
  lifecycle {
    precondition {
      condition     = local.pcrs_ok
      error_message = "pcr0..pcr3 must be 96 lowercase hex digits each."
    }
  }
}

resource "aws_kms_key" "target_locked" {
  count               = var.key_policy_locked ? 1 : 0
  description         = "signer-runner sealing key, enclave-only, ${var.name} (handover target)"
  enable_key_rotation = true
  # As in ../main.tf: a locked policy needs the lockout check bypassed.
  bypass_policy_lockout_safety_check = var.key_policy_locked
  policy                             = local.key_policy
  # Terraform never writes the policy of this address after creation: a
  # locked policy cannot change anyway, and a key moved here by mistake
  # stays as it is in AWS (unlocked), which the runner's lock check refuses
  # on a prod chain, instead of being locked in place (AWS-KMS-02).
  lifecycle {
    ignore_changes = [policy, bypass_policy_lockout_safety_check]
    precondition {
      condition     = local.pcrs_ok
      error_message = "pcr0..pcr3 must be 96 lowercase hex digits each."
    }
  }
}

locals {
  kms_key = one(concat(aws_kms_key.target, aws_kms_key.target_locked))
}

# The key's CreationDate, for sealing_key_release.kms_key_creation_date.
data "aws_kms_key" "target" {
  key_id = local.kms_key.arn
}

resource "aws_instance" "target" {
  count                  = var.instance ? 1 : 0
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  iam_instance_profile   = data.aws_iam_instance_profile.parent.name
  key_name               = var.key_pair_name == "" ? null : var.key_pair_name
  vpc_security_group_ids = [data.aws_security_group.node.id]
  enclave_options { enabled = true }
  metadata_options {
    http_tokens = "required" # IMDSv2, used by the host agent
  }
  tags = { Name = var.name }
  # As in ../main.tf: a new key_name would replace the instance, and EC2
  # reads the key pair only at launch.
  lifecycle {
    ignore_changes = [key_name]
  }
}

output "kms_key_arn" { value = local.kms_key.arn }
output "kms_key_creation_date" { value = data.aws_kms_key.target.creation_date }
output "parent_role_arn" { value = data.aws_iam_role.parent.arn }
output "instance_id" { value = var.instance ? aws_instance.target[0].id : "" }
output "public_ip" { value = var.instance ? aws_instance.target[0].public_ip : "" }
