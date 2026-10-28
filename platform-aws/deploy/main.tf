# No instance type of the AWS Free plan supports Nitro Enclaves.
#
# One signer node: a KMS key whose policy releases data keys only to the
# measured enclave image on a parent with the signer-parent role, an
# instance role for the parent, an EC2 instance with Nitro Enclaves
# enabled, the record writer user whose credentials only the enclave can
# decrypt, and with mark_bucket set the mark log's bucket policy. Feed
# PCR0/1/2 from build/nitro/build-enclave-<arch>.json (scripts/nitro-eif.sh;
# aarch64 for the default c6g.large) and PCR3 from
# `scripts/kms-policy.sh pcr3 arn:aws:iam::<account>:role/signer-parent`.
#
# The EIF is generic (research/setup-phase.md in the threshold-signer-poc repo): its
# PCRs are the same for every signer and chain, so the key policy and the
# bucket policy are set once per image. A new chain or signer is a new setup
# on the parent (parent-run.sh SETUP), not a change here. The DynamoDB clone
# guard below is the per-chain images'; the generic image does not use it
# (the setup's mark log is the clone protection). It stays here because the
# table has deletion protection.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "region" {
  description = "AWS region of the node and of its KMS key. The setups the parent hands over must name it in key_release.region: the enclave dials kms.<region> and sts.<region> through the parent's proxies. Documented choice: eu-central-1."
  default     = "eu-central-1"
}
variable "instance_type" {
  # Documented choice: c6g.large, Graviton (arm64), 2 vCPUs. The AWS Nitro
  # Enclaves user guide lists it as supported (it excludes c6g.medium).
  # The parent keeps 1 vCPU and the enclave gets 1 (parent-run.sh
  # CPU_COUNT). The EIF and the AMI must be arm64 for it:
  # `ARCH=aarch64 scripts/nitro-eif.sh`. For an x86_64 node set for example
  # m6i.xlarge (4 vCPUs, 2 stay with the parent), an x86_64 AMI and an
  # x86_64 EIF. Check the supported list in the user guide.
  default = "c6g.large"
}
variable "ami_id" {
  description = "Amazon Linux 2023 AMI for the region, of the CPU architecture of instance_type: arm64 for c6g.large (an x86_64 AMI does not launch on it). Pin one; this file does not look one up."
}
variable "subnet_id" {}
variable "pcr0" {}
variable "pcr1" {}
variable "pcr2" {}
variable "pcr3" {
  description = "SHA-384 of 48 zero bytes and the parent role ARN: scripts/kms-policy.sh pcr3 arn:aws:iam::ACCOUNT:role/signer-parent"
}
variable "admin_role_arn" { description = "role that administers the key (can change its policy!)" }
variable "node_key" {
  description = "this node's record key, the runner's -record-key"
  default     = "node-1"
}
variable "entry_cidrs" {
  description = "CIDR blocks that may reach the network entry (the forwarder's TCP port on the parent), for example the Dirk fork hosts. Empty: no inbound rule. This limits exposure. It is not a security boundary: the runner's mutual TLS inside the enclave is."
  type        = list(string)
  default     = []
}
variable "entry_port" {
  description = "TCP port of the forwarder (parent-run.sh ENTRY_PORT)"
  default     = 7100
}
variable "ssh_public_key" {
  description = "OpenSSH public key to import as an EC2 key pair, to copy the files to the parent and run parent-run.sh. Empty: no key pair. A key pair can only be set when the instance is created."
  default     = ""
}
variable "ssh_cidrs" {
  description = "CIDR blocks that may reach SSH (port 22) on the parent, for example the operator's address as a /32. Empty: no inbound SSH rule. Remove it when the setup is done."
  type        = list(string)
  default     = []
}
variable "prev_pcrs" {
  description = "PCR0, PCR1 and PCR2 of a second image that may still use the key, next to pcr0..pcr2: the image being replaced, so a rollback needs no key policy change. null: only pcr0..pcr2. PCR0 covers the whole image, so a mix of the two sets matches no real enclave."
  type        = object({ pcr0 = string, pcr1 = string, pcr2 = string })
  default     = null
}
variable "nts_egress" {
  description = "Allow the enclave's NTS clock out: TCP 4460 (NTS-KE, through vsock-proxy) and UDP 123 and 4123 (NTP, through udprelay) to anywhere. A security group cannot name hosts, and the operators' addresses change (Cloudflare anycast; Netnod's NTS-KE names NTP servers by address). The narrow rule is udprelay's allowlist and vsock-proxy's."
  type        = bool
  default     = true
}

variable "mark_bucket" {
  description = "S3 bucket of the mark log (the setups' mark_store.bucket), made outside Terraform with Object Lock in compliance mode (its retention cannot be undone). When set, this file writes its bucket policy: the record writer (the enclave's credentials) may create and read records and update bodies under marks/ and config/ of any setup, list versions and read the Object Lock configuration (the runner's lock check); the parent role writes nothing; plain HTTP is refused. One policy for every setup of this image, so a new setup needs no change here. null: no bucket policy."
  type        = string
  default     = null
}

provider "aws" { region = var.region }

data "aws_caller_identity" "me" {}

resource "aws_iam_role" "parent" {
  name = "signer-parent"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "parent" {
  name = "signer-parent"
  role = aws_iam_role.parent.name
}

resource "aws_kms_key" "enclave" {
  description         = "signer-runner sealing key, enclave-only"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = var.admin_role_arn }
        Action = ["kms:Describe*", "kms:Get*", "kms:List*", "kms:PutKeyPolicy",
        "kms:EnableKeyRotation", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]
        Resource = "*"
      },
      {
        # The admin encrypts the writer credentials for the enclave
        # (record/writer-credentials.kms in the host store) with the
        # encryption context purpose=record-creds, and with no other
        # context. The runner's own keys carry other contexts: the sealing
        # key {purpose: sealing, signer-setup}, the mark log and state copy
        # keys {signer-key, signer-setup} (platform-aws/nitro). Only the
        # enclave makes those (GenerateDataKey with its attestation as
        # recipient), so the admin cannot plant a sealing key or a mark log
        # key. The admin also holds kms:PutKeyPolicy: the fix holds fully
        # once the key policy is locked.
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
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = local.pcr0
            "kms:RecipientAttestation:PCR1" = local.pcr1
            "kms:RecipientAttestation:PCR2" = local.pcr2
            # PCR3 pins the parent's IAM role; PCR4 (instance ID) is left
            # out so the node can move to a replacement instance.
            "kms:RecipientAttestation:PCR3" = var.pcr3
          }
        }
      },
      {
        # The runner reads the key's metadata and this policy at start and
        # hashes them into key_release_hash of its attested setup state
        # (platform-aws/nitro ReleaseHash), so a verifier sees whether
        # the policy is locked. Reads only; the parent could make them too.
        Sid       = "EnclaveReadsItsKeyPolicy"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = ["kms:DescribeKey", "kms:GetKeyPolicy"]
        Resource  = "*"
      }
    ]
  })
}

# Clone guard: one item per node, written only with a condition on its
# version (tee-signer/record). The writer is an IAM user whose access key the
# enclave alone can decrypt; the parent role may not write the table.
resource "aws_dynamodb_table" "records" {
  name                        = "signer-records"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "node"
  deletion_protection_enabled = true
  attribute {
    name = "node"
    type = "S"
  }
}

resource "aws_iam_user" "record_writer" {
  name = "signer-record-writer-${var.node_key}"
}

# Create its access key out of band (not in Terraform state), encrypt the
# JSON {"access_key_id","secret_access_key"} with this KMS key, and put the
# ciphertext in the host store as record/writer-credentials.kms.
resource "aws_iam_user_policy" "record_writer" {
  name = "signer-record-writer"
  user = aws_iam_user.record_writer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
      Resource = aws_dynamodb_table.records.arn
      Condition = {
        "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = [var.node_key] }
      }
    }]
  })
}

resource "aws_iam_role_policy" "parent_no_record_writes" {
  name = "signer-parent-no-record-writes"
  role = aws_iam_role.parent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"]
      Resource = aws_dynamodb_table.records.arn
    }]
  })
}

# The mark log's bucket policy (variable mark_bucket). The runner writes
# marks/<setup_hash>/<signer>/... and config/<setup_hash>/... with the
# record writer's credentials, which only the enclave can decrypt
# (record/writer-credentials.kms, purpose=record-creds). The paths carry
# setup_hash, so the policy names the two prefixes and no setup: each
# setup's log stays apart by its path and by the keys bound to setup_hash.
# s3:GetBucketObjectLockConfiguration is the lock check at every start.
# No delete and no retention change for anyone here; the compliance-mode
# default retention keeps every version for its time. NoDeleteMarkers
# denies DeleteObject (which puts a delete marker on a versioned bucket)
# and DeleteObjectVersion to every principal, the account's admins
# included: a delete marker over a clone's record would let a second
# runner's conditional create through (issue #5 R3). An admin who can
# change this policy can still lift it; the runner's check after each
# create (s3log checkHidden) catches a marker either way.
resource "aws_s3_bucket_policy" "marks" {
  count  = var.mark_bucket == null ? 0 : 1
  bucket = var.mark_bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnclaveWriterRecords"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.record_writer.arn }
        Action    = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
        Resource  = ["arn:aws:s3:::${var.mark_bucket}/marks/*", "arn:aws:s3:::${var.mark_bucket}/config/*"]
      },
      {
        Sid       = "EnclaveWriterListsAndChecksTheLock"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.record_writer.arn }
        Action    = ["s3:ListBucketVersions", "s3:GetBucketObjectLockConfiguration"]
        Resource  = "arn:aws:s3:::${var.mark_bucket}"
      },
      {
        Sid       = "ParentWritesNothing"
        Effect    = "Deny"
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:BypassGovernanceRetention"]
        Resource  = "arn:aws:s3:::${var.mark_bucket}/*"
      },
      {
        Sid       = "NoDeleteMarkers"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = "arn:aws:s3:::${var.mark_bucket}/*"
      },
      {
        Sid       = "TLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::${var.mark_bucket}", "arn:aws:s3:::${var.mark_bucket}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

locals {
  # Every field of an ingress rule, so that the rules above have one type.
  no_rule = {
    description      = ""
    from_port        = 0
    to_port          = 0
    protocol         = "tcp"
    cidr_blocks      = []
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }
  # KMS key policy: this image's PCRs, and those of prev_pcrs if set. One
  # value stays a string, so without prev_pcrs the policy is the one before.
  # (jsondecode: the two branches of a condition must have one type.)
  pcr_lists = {
    for i in [0, 1, 2] : i => distinct(compact([
      [var.pcr0, var.pcr1, var.pcr2][i],
      var.prev_pcrs == null ? "" : [var.prev_pcrs.pcr0, var.prev_pcrs.pcr1, var.prev_pcrs.pcr2][i],
    ]))
  }
  pcr0 = jsondecode(length(local.pcr_lists[0]) == 1 ? jsonencode(local.pcr_lists[0][0]) : jsonencode(local.pcr_lists[0]))
  pcr1 = jsondecode(length(local.pcr_lists[1]) == 1 ? jsonencode(local.pcr_lists[1][0]) : jsonencode(local.pcr_lists[1]))
  pcr2 = jsondecode(length(local.pcr_lists[2]) == 1 ? jsonencode(local.pcr_lists[2][0]) : jsonencode(local.pcr_lists[2]))

  # Egress: HTTPS (KMS, STS, DynamoDB, S3, the clock URLs, an overlay
  # network entry's coordination and relays over TCP), the NTS clock's
  # NTS-KE and NTP when nts_egress is set.
  egress_rules = concat(
    [merge(local.no_rule, { from_port = 443, to_port = 443, cidr_blocks = ["0.0.0.0/0"] })],
    var.nts_egress ? [merge(local.no_rule, {
      description = "NTS-KE of the enclave NTS clock (vsock-proxy, TLS ends in the enclave)"
      from_port   = 4460
      to_port     = 4460
      cidr_blocks = ["0.0.0.0/0"]
    })] : [],
    var.nts_egress ? [for p in [123, 4123] : merge(local.no_rule, {
      description = "NTP of the enclave NTS clock (udprelay, which sends to its allowlist only)"
      protocol    = "udp"
      from_port   = p
      to_port     = p
      cidr_blocks = ["0.0.0.0/0"]
    })] : [],
  )
}

resource "aws_security_group" "node" {
  name   = "signer-node"
  vpc_id = data.aws_subnet.sel.vpc_id
  # Inbound: only the network entry, and only from entry_cidrs, plus SSH
  # from ssh_cidrs while the parent is set up. The forwarder copies bytes to
  # the enclave, where mutual TLS ends. The parent is not trusted, and
  # neither is this rule.
  #
  # `ingress` is an attribute and not a set of dynamic blocks on purpose: the
  # argument is optional and computed, so dropping the last block from the
  # file leaves the rule in place (ssh_cidrs = [] would change nothing).
  # With an explicit list, an empty list removes the rules.
  ingress = concat(
    length(var.entry_cidrs) > 0 ? [merge(local.no_rule, {
      description = "network entry: forwarder to the enclave (mutual TLS ends inside it)"
      from_port   = var.entry_port
      to_port     = var.entry_port
      cidr_blocks = var.entry_cidrs
    })] : [],
    length(var.ssh_cidrs) > 0 ? [merge(local.no_rule, {
      description = "operator SSH, to set up the parent"
      from_port   = 22
      to_port     = 22
      cidr_blocks = var.ssh_cidrs
    })] : [],
  )
  # An attribute, like ingress, so that removing a rule here removes it.
  egress = local.egress_rules
}

data "aws_subnet" "sel" { id = var.subnet_id }

resource "aws_key_pair" "operator" {
  count      = var.ssh_public_key == "" ? 0 : 1
  key_name   = "signer-node-operator"
  public_key = var.ssh_public_key
}

resource "aws_instance" "node" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  iam_instance_profile   = aws_iam_instance_profile.parent.name
  key_name               = var.ssh_public_key == "" ? null : aws_key_pair.operator[0].key_name
  vpc_security_group_ids = [aws_security_group.node.id]
  enclave_options { enabled = true }
  metadata_options {
    http_tokens = "required" # IMDSv2, used by the host agent
  }
  tags = { Name = "signer-node" }
}

output "kms_key_arn" { value = aws_kms_key.enclave.arn }
output "parent_role_arn" { value = aws_iam_role.parent.arn }
output "records_table" { value = aws_dynamodb_table.records.name }
output "instance_id" { value = aws_instance.node.id }
output "public_ip" { value = aws_instance.node.public_ip }
output "record_writer_user" { value = aws_iam_user.record_writer.name }
