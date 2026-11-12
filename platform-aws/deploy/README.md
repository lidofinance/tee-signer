# AWS Nitro Enclaves backend

The runner runs in a Nitro enclave on an EC2 parent instance. The parent is
not trusted: it stores sealed blobs, relays the enclave's outbound TLS and
forwards client connections into the enclave over vsock. One enclave image
file (EIF) serves every signer of every operator. It holds the runner and the
flags that are the same for everyone, and the signer's values come in its
setup ("Setup").

To move a running signer to a new image, see [docs/upgrade.md](../../docs/upgrade.md).

## Files

| File | What |
| --- | --- |
| `nitro-cli/Dockerfile` | builds nitro-cli v1.5.2 from source (Rust 1.94.1 image), applies `target-arch.patch`, and adds the kernel/init blobs |
| `nitro-cli/target-arch.patch` | one change to `src/lib.rs` of nitro-cli: the kernel blob name follows `NITRO_CLI_TARGET_ARCH` when it is set, so an x86_64 machine can build an arm64 EIF |
| `enclave/Dockerfile` | the generic enclave image: static runner and the flags that are the same for every operator (`-setup platform`, the NTS clock). Built into an EIF by `scripts/nitro-eif.sh`. The fixed vsock port map is in its comments |
| `test-client-ca.pem` | public root certificate of a test PKI (`scripts/make-test-ca.sh`), for a test setup's `allowed_client_ca` (base64 of its DER). Its private key is not in the repo |
| `kms-key-policy.json.tmpl` | key policy: `Decrypt`/`GenerateDataKey` only with `kms:RecipientAttestation:PCR0/1/2/3`; `Encrypt` for the key admin only with exactly the encryption context `purpose=record-creds` (the record credentials), so the admin cannot make a sealing key (`purpose=sealing`) or a mark log key (`signer-key`), which carry setup_hash (`platform-aws/nitro`, `slashing-log/docs/marklog.md`, "Record keys"); `DescribeKey`, `GetKeyPolicy` and `ListGrants` for the parent role, which the runner reads at start for key_release_hash and the lock check (`platform-aws/nitro` KeyRule). `platform-aws/nitro/planting_test.go` evaluates these conditions. `scripts/kms-policy.sh` renders it per build to `build/nitro/kms-key-policy-<arch>.json` |
| `main.tf` | KMS key (PCR0-3), parent role, enclave-enabled EC2 instance, the record writer user (the mark log's S3 credentials), the mark bucket's policy (`mark_bucket`), and an optional inbound rule for the network entry (`entry_cidrs`). Optional `ssh_public_key` and `ssh_cidrs` give a key pair and an SSH rule for the operator. Variables `instance_type` (default `c6g.large`) and `region` (default `eu-central-1`) are the Graviton choice, see "Graviton (arm64)". The name variables and `extra_egress` are in "Steps". `scripts/aws-tf-test.sh` tests it with a mock provider |
| `target/main.tf` | a second signer next to a running one. Its own root module and state, so no plan of it can change the running signer. It reads the parent role, instance profile, security group and key pair by name. It makes a new KMS key that releases to the target EIF's PCR0..2 alone (the same PCR3, the parent role's read of the key and its policy, the admin's `record-creds` encrypt) and, with `instance = true`, a second `c6g.large` parent. The admin encrypts a second access key of the record writer under the new key. `scripts/tf-validate.sh` validates it |
| `parent-run.sh` | parent setup: allocator, one vsock-proxy per route of the signer's setup (KMS, STS, the coarse-time host, the mark bucket, one NTS-KE route per catalog host), the host agent with the setup (`SETUP`), udprelay, `nitro-cli run-enclave`, the forwarder (network entry). Runs on x86_64 and arm64 parents (`SETUP`, `CPU_COUNT`, `MEMORY_MIB`) |
| `../../platform-aws/cmd/forwarder` | the network entry: a plain TCP to vsock byte forwarder, no TLS. Built by `scripts/build-runner.sh`, started by `parent-run.sh` |
| `../../platform-aws/cmd/udprelay` | the NTS clock's NTP path: vsock 7102 to UDP 123 and 4123, for an allowlist of the catalog's NTS servers, with rate limits (package `platform-aws/udprelay`). Built by `scripts/build-runner.sh`, started by `parent-run.sh` |
| `signer-runner.service`, `parent-service.sh`, `parent.env.example` | the parent as a systemd service: `parent-run.sh` at boot, a new start after the enclave or a parent tool ends, none after `systemctl stop` ("Restarts"). `scripts/aws-parent-service-test.sh` tests it with a fake `nitro-cli` |
| `allocator.yaml`, `vsock-proxy.yaml` | parent config in the formats shipped with nitro-cli v1.5.2. `vsock-proxy.yaml` is an example: `parent-run.sh` writes the allowlist from the setup |

## Setup

The chain config, the client CA, the KMS key and region, the mark bucket and
the signer name are in the signer's setup, a binary file that
`signer-admin/cmd/setup-tool encode` makes from a human `key = value` file
(`governance/setuptext/testdata/setup-nitro.conf` is an example;
`setup-tool chain-lines <chain config>` prints the chain lines of a chain).

```sh
setup-tool encode signer-2.conf signer-2.bin                      # prints setup_sha256
setup-tool check -platform nitro -chain governance/chains/<chain>.json signer-2.bin
SETUP=signer-2.bin platform-aws/deploy/parent-run.sh               # on the parent
```

- The host agent checks the setup with the runner's decoder and hands it to
  the enclave at every start (SETUP over vsock 7101), before any KMS call.
  The runner checks it again, refuses one for another platform, and puts
  setup_hash and the mark log's config state in IDENTITY, ATTEST and HEALTH
  (IDENTITY, `signer-protocol/docs/protocol.md`).
- Every KMS call carries setup_hash in its encryption context: the sealing
  data key `{purpose: sealing, signer-setup: <hex>}`, the mark log and
  state copy keys `{signer-key: <hex of the AAD>, signer-setup: <hex>}`. A
  runner started with another setup does not decrypt this signer's sealing
  key (it stops) and opens none of its keys. The shares, the mark log and
  the state copy are bound to setup_hash too.
- The key admin may call `kms:Encrypt` with exactly the context
  `purpose=record-creds` (`kms-key-policy.json.tmpl`, `main.tf`). So the
  admin can make the record credentials and nothing else: no blob it makes
  opens as a sealing key or a mark log key. The admin still holds
  `kms:PutKeyPolicy`, so this holds fully only once the key policy is
  locked. A runner whose setup is on mainnet refuses to start until it is:
  no principal may hold PutKeyPolicy, CreateGrant, ImportKeyMaterial,
  ReplicateKey or the alias actions, Decrypt and GenerateDataKey need
  literal PCR0, PCR1 and PCR2 values that are not all zeros, and the key
  may have no grants
  (`signer-protocol/docs/protocol.md`, "Key rule lock"). The key policy
  template does not pass that check. The no-grants rule counts grants
  that AWS services make too (EBS, S3 or DynamoDB encryption with the
  key), so the signer's key must serve no other service.
- The locked policy may name more than one image: a second value in the
  PCR0 list (`prev_pcrs`) or a second enclave statement. The lock check
  passes either, so the runner also compares every PCR0 the policy names
  (`ImageSha384` counts as PCR0) with `allowed_image_measurements` in
  force at start, before any share is unsealed. On a prod chain an image
  the list does not name keeps the shares sealed: an enclave of that
  image would get the sealing key and open every share without the image
  check, which only the listed runner runs on itself. The runner stays
  up, signs nothing, says `key_rule_unlisted` in HEALTH and takes the
  locked update that lists the image; after it is in force a restart
  loads the shares. Off prod the runner logs a warning. So keep every
  image the policy names on the list, the rollback image too, until the
  shares move to a new key. A locked update that drops such an image
  later does not stop a running signer; the next start on a prod chain
  withholds the shares.
- A locked policy lets no principal manage the key. AWS calls such a key
  unmanageable, and its guide says the account owner then contacts AWS
  Support to regain access
  ([KMS: default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)).
  So the lock holds against the account's own admins only as far as AWS
  Support refuses such a request from the account's root user. That is a
  residual trust in AWS and in whoever holds the root user. Reduce it:
  hardware MFA on the root user, no root access keys, an AWS
  Organizations SCP that limits what the root user can do, and a
  CloudTrail alert on `PutKeyPolicy` for the key. The runner cannot close
  it: a later start reads the changed policy as not locked and refuses,
  but by then the shares could already be decrypted.
- Before the lock the admin can still allow itself `kms:Encrypt` under
  the sealing context and leave a blob of a key it knows at
  `sealing/datakey.kms`. The runner uses a stored sealing blob only when
  the store also lists an object under `shares/`. On a store without
  one it copies the blob to `sealing/datakey.kms.ignored-<hash>`, logs a
  warning and makes a new key. `<hash>` is the first 8 bytes of the
  blob's SHA-256. Each start without a share leaves one more copy: it
  sets aside the blob the start before it made. A signer that waits for
  its first import gathers one copy per restart;
  delete them on the parent once the signer's shares open. A production
  enclave has no console, so look for `.ignored-` files on the parent
  rather than for the log line.
- If shares were only missing at such a start (a partial restore, a late
  mount), the blob they were sealed under is one of those copies: the
  oldest copy whose file time is after the newest file under `shares/`
  (the first start that found no shares set it aside). The other copies
  hold keys made for an empty store, or a planted blob, and can be
  deleted once the shares open. To restore, first move the current
  `sealing/datakey.kms` aside by hand. Shares imported since that start
  were sealed under it and open only with it; the runner opens one
  sealing key, so keep those shares and that blob together, apart from
  the old set. Then put the copy back as `sealing/datakey.kms` with the
  old shares and start. The runner uses it only if `shares/` lists
  something at that start. A wrong copy stops the start with "the stored
  sealing key opens 0 of N stored shares": move the current blob aside
  again and try the next copy.
- Any object under `shares/` makes the platform take the stored blob, and
  the host writes the store. So the runner treats a key from a stored
  blob as unproven: before it loads a share or seals a new one, every
  share listed at that start must unseal under the key, and at least one
  must be listed (`server.ProveSealingKey`). Otherwise the start stops
  and names the shares that did not open. A planted blob next to junk
  under `shares/`, or next to the runner's own shares, fails this. So
  does a legitimate leftover: every object under `shares/` must open
  under the current sealing key and the mark log's current log_id. A
  share from an earlier life of the mark log (the log was made again
  with a new log_id) or a share restored from another signer's backup by
  mistake now stops the start, where before it was logged and skipped.
  Remove what does not open from `shares/` on the parent (keep a copy
  elsewhere if in doubt), and if no share opens, move the blob aside as
  well, then restart. While the image check holds the
  shares sealed, the check cannot run, so the runner seals no share
  until a restart with the image allowed.
- That check needs a share sealed under the planted key, and whoever
  planted the key can make one: the key is theirs, and the share's AAD
  (setup_hash, log_id, public key) is public. On a fresh store the mark
  log's claim then refuses stored shares without a record that opens, but
  before the lock the admin can plant such a record too (`kms:Encrypt`
  under a mark log key's context). So the runner's checks raise the cost
  of the attack; only a key that never had a mutable phase rules it out.
  For mainnet, create the key with its final, locked policy:
  `key_policy_locked = true` in `main.tf` and `target/main.tf`, or
  `create-key` with the locked policy (below). If the key had a mutable
  phase, check its CloudTrail history before the first start: no
  `CreateGrant`, no `Encrypt` under a context other than
  `purpose=record-creds`, and every `PutKeyPolicy` reviewed. CloudTrail
  must have logged KMS management events in the key's region for the
  whole mutable phase, or the history proves nothing. With a locked
  creation, the history to check is one `CreateKey` whose policy, in
  canonical form (attestation-statement.md, section 5), hashes to the
  `key_release_sha256` the verifiers pin.
- KMS grants are eventually consistent: a grant can take some minutes to
  show in `ListGrants`, and AWS gives no upper bound. The runner reads the
  grants once at start and cannot tell a grant that is not listed yet
  from none, so its lock check cannot rule out such a grant. For mainnet,
  create the key with its final, locked policy (`key_policy_locked =
  true`, above): then no principal ever held `kms:CreateGrant` and the
  key has no grants at all. A key with a mutable phase needs the
  CloudTrail check above, and the runner started well after the last
  `CreateGrant`, with `aws kms list-grants` empty at that time; that
  narrows the gap but does not close it.
- To create the key locked, `aws kms create-key --policy` needs
  `--bypass-policy-lockout-safety-check`: without it KMS refuses a
  policy that does not let the caller change it later, which is the
  point here. With it, a mistake in the policy is permanent. Render the
  policy with `scripts/kms-policy.sh render`, check the PCRs against the
  build and the principals against the deploy, and run it through the
  lock check (`policyLock` in `platform-aws/nitro`, as its tests do)
  before `create-key`. `main.tf` and `target/main.tf` do the same with
  `key_policy_locked = true`: the admin gets no `kms:PutKeyPolicy` and
  no `kms:ScheduleKeyDeletion`, and Terraform sets
  `bypass_policy_lockout_safety_check`. The lock check refuses a policy
  that allows `ScheduleKeyDeletion` or `DisableKey`: under a locked
  policy nobody could enable or keep the key again, and every share
  sealed under it would be lost. A locked key therefore stays until the
  account closes. A key locked under the older policy, whose admin still
  holds `kms:ScheduleKeyDeletion`, now reads as not locked, and its
  policy can never change. Such a key needs a new locked key
  (`target/main.tf`) and the shares imported again under it. On mainnet a
  runner with this check refuses to start on the old key; off mainnet the
  runner only logs a warning. Run Terraform as
  `admin_role_arn` then, since no other principal can read the key
  afterwards. The policy never changes again: a new image gets a new key
  (`target/main.tf`) and the shares imported again, so set `prev_pcrs` at creation if a
  rollback image should keep this key. The variable has no default.
  Each value has its own key resource: `aws_kms_key.enclave` (unlocked)
  and `aws_kms_key.enclave_locked`, one of them with `count = 1`. So a
  change of the flag destroys one key and creates the other, also on the
  first apply of this file, and never locks a key in place, which would
  not undo its mutable phase (AWS-KMS-02). Terraform schedules the old key
  for deletion (30 days; `aws kms cancel-key-deletion` stops it), and the
  shares sealed under it must be imported again under the new key. Before
  such an apply, check that the plan destroys `aws_kms_key.enclave[0]`
  and creates `aws_kms_key.enclave_locked[0]`, and updates no key in
  place. A key made before this split sits at `aws_kms_key.enclave`;
  Terraform moves it to `aws_kms_key.enclave[0]` by itself, so an
  unlocked key plans no change. A key that an older version of this file
  created locked sits there too, and Terraform cannot tell it from an
  unlocked one. Only for a key that was created locked, move it before
  the first plan with this file:
  `terraform state mv aws_kms_key.enclave 'aws_kms_key.enclave_locked[0]'`.
  Check first that it was: the CloudTrail `CreateKey` check below, and
  `aws kms get-key-policy --key-id ID --policy-name default --output text`
  (the same in bash and PowerShell) must not contain `kms:PutKeyPolicy`.
  Terraform never writes the policy of `enclave_locked` after creation
  (`ignore_changes`), so after a correct move the plan shows no change to
  the key. For the same reason a change of `pcr0` to `pcr2` or `prev_pcrs`
  plans no change on `enclave_locked` and gives no warning: the old key
  still releases to the old image only, and a new image needs a new key
  (`target/main.tf`). An unlocked key moved there by mistake stays
  unlocked, which the runner refuses on a prod chain. Without the move the plan
  creates a second locked key and tries to destroy the first, which its
  policy refuses; do not apply such a plan.
- Flipping `key_policy_locked` destroys the old key: Terraform calls
  `ScheduleKeyDeletion`, and once the pending window ends every share
  sealed under that key is gone. The signer moves as a new signer, with
  a new setup and the shares imported again
  ([docs/upgrade.md](../../docs/upgrade.md#when-this-works)).
  `target/main.tf` has the same pair (`aws_kms_key.target`,
  `aws_kms_key.target_locked`).
- The setup pins the key's creation (AWS-KMS-02). KMS shows a key's
  current policy and its `CreationDate`, not when the policy was locked.
  So before they sign a setup, the approvers check the key's history:
  1. In CloudTrail (the key's region, event source `kms.amazonaws.com`),
     the `CreateKey` event whose `responseElements.keyMetadata.arn` is the
     key has `requestParameters.bypassPolicyLockoutSafetyCheck` set to
     `true` and a `requestParameters.policy` that is the locked policy:
     it passes the lock check and, in canonical form
     (attestation-verify/docs/attestation-statement.md, section 5), hashes
     to the `key_release_sha256` the verifiers pin.
  2. No `PutKeyPolicy` event for the key without an `errorCode` follows
     it.
  3. `aws kms describe-key --key-id ARN` gives a `CreationDate` at the
     same instant, to the second, as
     `responseElements.keyMetadata.creationDate` of that event. The CLI
     prints a fraction and an offset (`2026-10-31T01:44:48.048000+00:00`)
     where CloudTrail prints `2026-10-31T01:44:48Z`, so compare the first
     19 characters, or both as Unix seconds (`date -u -d TIME +%s` in
     bash, `([DateTimeOffset]'TIME').ToUnixTimeSeconds()` in PowerShell).
  CloudTrail event history keeps 90 days; for an older key, read a trail
  that has logged KMS management events since the key was created. The
  setup then carries that time, to the second, as
  `sealing_key_release.kms_key_creation_date` (RFC 3339, for example
  `2026-11-05T16:14:45Z`; `terraform output kms_key_creation_date` prints
  it; the CLI form with a fraction and `+00:00` reads the same, the
  fraction dropped), and `setup-tool show` prints it next to `kms_key_id`.
  At every start on a setup the runner compares it with the
  `CreationDate` of `DescribeKey` in whole Unix seconds and stops on any
  other key, on every chain, so a replaced key or another key under the
  same alias does not start. It also stops when
  `DescribeKey` fails or gives no answer to compare. A Nitro setup of a
  prod chain must carry it; off prod it may be left out, and the runner
  then skips the compare.
- The routes follow from the setup over a fixed port map: KMS and STS of
  the key release region on vsock 8000 and 8001, `www.cloudflare.com` on
  8002, the mark bucket on 8004 and NTS-KE on the catalog ports of the
  catalog's hosts (8005 to 8018, trusted-time/ntscatalog Endpoints): the
  parent cannot see which of them the enclave's command chose.
  `hostagent -setup FILE -proxy-routes` prints them; `parent-run.sh` starts
  one vsock-proxy per line and writes the allowlist. A line of an NTS-KE
  host outside the default set ends in `optional`: if its proxy exits at
  start (vsock-proxy resolves its host then), the script warns and goes
  on, so a DNS failure of a host the default runner never dials does not
  stop the parent. The coarse-time URLs
  name `{region}`; the runner fills in the setup's region.
- The setup's mark log is the clone protection (see "Clone protection"). The S3
  writer credentials stay at `record/writer-credentials.kms` on the parent.
- `-mark-create`, `-state-create` and the flags the setup
  replaces are refused with `-setup`, and the runner hands over to no one.
- `CHAIN` picks the runner build of `scripts/nitro-eif.sh` (the mainnet
  runner when unset); the chain config is checked, not put into the image.
  The script refuses `CLIENT_CA`, `REGION`, `KMS_KEY_ARN`, `MARK_BUCKET`
  and `MARK_SIGNER`, and checks that the image holds no `/etc/signer`.

The mark bucket must have no lifecycle rules. The runner's lock check
refuses an enabled transition rule (the start stops, or mark writes stop
on a running signer) and warns of an expiration rule; both messages say
how to remove the rules. With the bucket policy's `NoLifecycleRules`
statement in force, removing a rule (`aws s3api delete-bucket-lifecycle`)
is denied like adding one, so drop that statement from the policy first,
remove the rules, and put the statement back.

With `mark_bucket` set, `main.tf` writes the bucket policy: the writer may
create and read objects under `marks/` and `config/`, set each new object's
retention (`s3:PutObjectRetention`, see "Mark log"), list versions and read
the Object Lock configuration and the lifecycle rules (the runner's lock
check needs `s3:GetBucketObjectLockConfiguration` and
`s3:GetLifecycleConfiguration`); the parent role is denied every
write. No principal but the writer user may put objects, retention or
replicas under `marks/` and `config/`, the account's root user and admins
included: objects planted under a signer's path can stop its mark writes
for `slashing_log_min_lock_days`. A principal that can change the bucket
policy can still lift this. The policy also refuses a put under `marks/` or
`config/` that names no retention or less than `mark_min_lock_days` days.
`mark_min_lock_days` has no default and is required with `mark_bucket`: set
it to the lowest `slashing_log_min_lock_days` of the setups that write to
the bucket, never higher, or S3 refuses the runner's writes. AWS does not
document how it rounds a part day, so the policy refuses fewer than
`mark_min_lock_days` + 1 remaining days and the runner adds a day and an
hour to its retention.
Apply this policy only after every signer that writes to the bucket runs
an image whose runner adds a day and an hour to its retention (this
change); older runners use a 1 h margin and S3 may refuse their writes.
For the same reason, a rollback through `prev_pcrs` to an image from
before this change needs `mark_min_lock_days` lowered by 1 first, or the
bucket policy reapplied from the older `main.tf` when it is 1. Otherwise
S3 may refuse that image's record writes and it stops signing. A runner
without a setup (the debug flag path) names no retention and cannot write
to a bucket with this policy; test it against a bucket without
`mark_bucket` set. A bucket policy written by an older `main.tf` lacks
`s3:PutObjectRetention`: apply this one before the runner that sets
retention starts, or its first record write fails with AccessDenied. The
paths carry setup_hash, so one policy serves every setup of the image. The
KMS key policy and the bucket policy are set once per EIF; a new chain or
signer is a new setup on the parent. The order of a deploy is in
`governance/docs/setup-phase-cloud-test.md`.

## How the runner uses Nitro

```
 parent EC2 (untrusted)                         enclave (runner, measured: PCR0/1/2; parent role: PCR3)
 ------------------------                       -------------------------------------
 network entry (forwarder) --- vsock 16:7100 --> runner: mutual TLS 1.3, core + shares + slashing state
 hostagent  <------------------ vsock 3:7101 -- sealed blobs (shares, KMS data-key blob,
                                                 KMS-encrypted record credentials),
                                                 role credentials for KMS calls
 hostagent  <------------------ vsock 3:7101 -- the setup (SETUP), at every start
 vsock-proxy 8000 -> kms.<region>:443  <-------- TLS from inside the enclave (KMS, Date header)
 vsock-proxy 8001/8002 -> time sources
 vsock-proxy 8004 -> <bucket>.s3.<region>:443 <-- mark log, signed with enclave-only keys
 vsock-proxy 8005-8018 -> NTS-KE (TCP 4460)
```

The signing client connects to the forwarder over TCP and never sees vsock (see
"Network entry").

- Attestation: `/dev/nsm` through `github.com/hf/nsm` (MIT). The document is
  COSE_Sign1, ES384 ([AWS: verify root](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)).
  Verifiers check it against the AWS Nitro root and compare PCR0/1/2.
  `attest.VerifyNitro` does that. `attestation-verify/runnerclient` has it as
  the verifier `aws-nitro`, so the dealer tool `share-import`,
  `signer-admin import` and the signing client can select it. Its settings are
  `nitro_pcrs` (PCR0, PCR1 and PCR2 of the image; `scripts/nitro-eif.sh`
  prints them), and optionally more PCRs and `nitro_root_sha256` (see
  `attestation-verify/README.md`). The NSM writes the payload's top-level map
  with an indefinite length (`0xbf ... 0xff`), so the verifier decodes the
  payload with `nitroPayloadDec`, which allows indefinite lengths and keeps
  the rest strict (duplicate keys, tags, nesting). The COSE array and the
  headers stay strict. Tests: public sample documents, a synthetic document
  with an indefinite payload map (`TestNitroSynthetic`), and a real enclave
  document (`TestNitroRealRunnerDocument`,
  `attestation-verify/testdata/nitro/aws-signer-2/`).
- Sealing: KMS `GenerateDataKey` (first boot) or `Decrypt` (later) with
  `Recipient = {attestation document with an RSA-2048 key, RSAES_OAEP_SHA_256}`.
  KMS returns the key as `CiphertextForRecipient` and leaves `Plaintext`
  empty ([KMS Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)).
  The AWS docs do not state the format; the AWS C SDK parses it as CMS
  EnvelopedData with RSA-OAEP-SHA256 key transport and AES-256-CBC content
  ([aws-nitro-enclaves-sdk-c source/cms.c](https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/cms.c)).
  `platform-aws/nitro/cms.go` follows that and is tested against
  `openssl cms -encrypt` output in DER and streamed BER.
- Key policy: without a valid attestation document the PCR condition is
  not met and KMS denies ([KMS condition keys for Nitro](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html)).
  Anyone who can `PutKeyPolicy` can remove the condition, so the admin
  role is part of the trust base.
- PCR3 is SHA-384 over 48 zero bytes and the ARN of the parent's IAM role
  ([AWS: where to get an enclave's measurements](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#pcr3);
  `scripts/kms-policy.sh self-test` reproduces AWS's example output, and
  `scripts/kms-policy.sh pcr3` computes it for a role). With it, the measured
  image unseals only on a parent that has the `signer-parent` role. PCR4
  (instance ID) is left out on purpose, so a node can move to a replacement
  instance.
- Debug mode and `--attach-console` zero all PCRs
  ([AWS: set up attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)),
  so the policy fails closed for debug enclaves.
- What stops a start on Nitro, before any share loads: a stored sealing
  blob that does not decrypt under this KMS key and setup_hash; on
  mainnet, a key policy someone can still change; and,
  when the sealing key came from the stored blob, any object under
  `shares/` that does not open under that key and the current log_id,
  including shares left from an earlier log life or restored by mistake,
  or an empty `shares/` listing (`server.ProveSealingKey`). The exit line
  names the shares; remove them on the parent and restart. A key policy
  that releases the key to an image `allowed_image_measurements` in force
  does not name does not stop the start: the runner stays up with the
  shares sealed and says `key_rule_unlisted` in HEALTH (see "Setup").
- A document of a running enclave carries PCR0 to PCR2 of the EIF, PCR3 of
  the parent role, PCR4 (the instance), PCR5 to PCR8 as zero, debug off,
  the enclave id as module id, and a leaf certificate with the subject
  `<module id>.<region>.aws`. It has no public key.

## Clone protection

A parent can run up to four enclaves from one EIF and feed each the same
sealed share blob. Each would unseal it and keep its own slashing state. The
clone protection is the setup's mark log (see "Mark log"). Each runner
claims the log at start with its own record. When a second instance claims
it, the first one's next write finds its name taken by another owner's
record, and from then on it signs nothing new
(`slashing-log/docs/marklog.md`).

The log only helps if the parent cannot write it. The parent holds the
instance role, so the mark bucket's policy denies the role every write, and
the writer is an IAM user whose access key only the enclave can read:

1. `terraform apply` creates the user `signer-record-writer-<node>` and,
   with `mark_bucket` set, the bucket policy that lets the user write
   records and denies the parent role.
2. The key admin creates an access key for that user, writes
   `{"access_key_id": "...", "secret_access_key": "..."}`, encrypts it with
   `aws kms encrypt --key-id <enclave key> --encryption-context
   purpose=record-creds` and drops the plaintext. Do it all in pipes:
   `aws iam create-access-key` to a JSON wrapper to `aws kms encrypt` to the
   ciphertext file, with no plaintext file and nothing printed. The key
   policy refuses any other context, and so does the enclave: it decrypts
   the credentials with exactly this one. The admin's own `Decrypt` of the
   file fails with AccessDenied.
3. The ciphertext goes into the host agent's store as
   `record/writer-credentials.kms` (`/var/lib/signer-runner/record/` on the
   parent). The enclave decrypts it with `Recipient` (the same PCR-bound
   policy as the data key), so the parent never sees the plaintext.

While the bucket policy stands, the account admins cannot put objects or
retention under `marks/` and `config/`, and neither a request nor a new
lifecycle rule adds a delete marker (see "Mark log"). They can still mint
new access keys or a console password for the user and write records with
them, and, if they can change the bucket policy, lift the denies. They
already control the KMS key policy, so this adds no new trusted party.
SigV4 signing uses the enclave's clock; a host that moves it can only make
AWS refuse the request (the runner then refuses to sign).

The runner had a second clone guard, a DynamoDB record per node
(`-record dynamodb:...`). The mark log replaced it and the runner no longer
has it. A deployment made with an older `main.tf` holds the table
`signer-records` with deletion protection, so `terraform apply` of this
file cannot delete it. Drop the table from the state first, then delete it
by hand if it holds nothing you keep:

    terraform state rm aws_dynamodb_table.records
    aws dynamodb update-table --table-name signer-records --no-deletion-protection-enabled
    aws dynamodb delete-table --table-name signer-records

The apply then removes the writer user's DynamoDB policy and the parent
role's deny on table writes.

## Mark log (S3 Object Lock)

The setup's `slashing_log_store` (bucket and region) and `signer_name` keep
the runner's mark in an S3 bucket with versioning and Object Lock, default
retention in compliance mode (`slashing-log/docs/marklog.md`). The mark log
is required. The client signs with the enclave-held record credentials
(`RecordCredentials`, `record/writer-credentials.kms`), so the parent cannot
write records. While the bucket policy stands, no principal but the record
writer may put objects or retention under `marks/` and `config/`, and no
principal, the account's admins included, may delete an object or a
version, so no request adds a delete marker. S3 runs a lifecycle rule
whatever the bucket policy says, and an expiration rule adds delete
markers, so the policy also denies `s3:PutLifecycleConfiguration` (setting
or deleting rules, transitions to archive classes included) to every
principal. Before applying this policy, on a new or an existing
deployment, check that the bucket has no lifecycle rule (`aws s3api
get-bucket-lifecycle-configuration` returns `NoSuchLifecycleConfiguration`);
after it, removing one takes a policy change. The runner's lock check
reads the rules at every start: an enabled rule with a transition stops
the start (an archive class makes records unreadable), and an expiration
rule logs a warning. Apply this policy before or with a runner that has
this check: under an older policy the runner cannot read the rules, logs
a warning and starts without the check. A lifecycle rule, such as cleanup
of old versions after the lock ends, takes a policy change that drops
NoLifecycleRules. That raises the PutBucketPolicy alert, and the runner's
checks still catch a marker it lets through. Compliance mode keeps
everyone from deleting or overwriting a locked version. An admin who can
change the bucket policy can lift these denies, and one who mints an
access key or a console password for the record writer user writes as it
without changing the policy. So alert in CloudTrail on `PutBucketPolicy`,
`DeleteBucketPolicy` and `PutBucketLifecycle` for the bucket, and on
`CreateAccessKey`, `UpdateAccessKey`, `CreateLoginProfile`,
`UpdateLoginProfile` and `CreateUser` for the record writer user. The
reader lists every version, and the runner's checks after each create
(s3log `checkHidden`, `checkMarker`) catch a create that a delete marker
let through either way.

The lock check at start reads the bucket's default retention, but that
default is a bucket setting: an admin with
`s3:PutBucketObjectLockConfiguration` can lower or remove it at any time,
and compliance mode protects only versions already written. So every PUT of
the runner (records and config bodies) names its own retention:
`x-amz-object-lock-mode: COMPLIANCE` and
`x-amz-object-lock-retain-until-date` at least `slashing_log_min_lock_days`
ahead (or the default the check read, if longer), plus an hour for the
clock skew S3 allows on a signed request and a day for the bucket policy's
rounding margin (see above). That date replaces the default
for the object and nobody can shorten it. A later change of the default
then has no effect on the runner's objects. The date comes from the
enclave's clock, which the host sets; it is the same clock that dates the
signed request, and S3 refuses a request more than 15 minutes off.

The Nitro platform restores no state copy (`-state-store` is restored on
Azure, GCP and dev), so the bucket policy grants nothing under `state/`. A
state copy in this bucket would need `state/*` with the same four actions
as `marks/*`; it would then get the same per-object retention.

The route `B.s3.R.amazonaws.com:443` on vsock port 8004 follows from the
setup, on both sides.

## An overlay network on the parent

The parent may run an overlay network entry of the operator. The security
group allows outbound TCP 443, and with `nts_egress` the NTS clock's
TCP 4460 and UDP 123 and 4123, so such an entry gets only relayed paths
over TCP, unless `extra_egress` opens more. If TLS handshakes stall on such a path, set a smaller MTU, for
example 1280 on the parent and 1200 on the client. `prev_pcrs` lets the KMS
key accept a second image's PCRs next to `pcr0..2`, so a rollback needs no
key policy change.

## PCRs of the image

`scripts/nitro-eif.sh` builds the EIF twice from scratch, compares the
PCRs, and prints PCR0, PCR1 and PCR2. If any of them differs between the
two builds, the script stops with an error. Record the PCRs of the commit you
deploy. Any change to the runner binary or a flag changes PCR2 and PCR0, and
so does a comment added to a Go file, because it moves the line numbers in
the binary. PCR1 covers the kernel and ramdisk. The image holds no chain
config, client CA, region or key ARN, so those do not change the PCRs.

The files in the enclave image have explicit modes (`COPY --chmod` in
`enclave/Dockerfile`, and `install -m` on the context in
`scripts/nitro-eif.sh`: 0555 for the runner). Without them the image would
take the modes of the context files, and PCR0 and PCR2 would follow the
builder's umask. With them, an EIF built under umask 022 and one under 077
have the same PCR0, PCR1 and PCR2.

The KMS key policy takes these PCRs. `scripts/kms-policy.sh` renders it from
the build, so a new image means a new rendered policy and a new key policy on
the KMS key (or `prev_pcrs` during a rollover).

Approve PCRs only from your own reproducible build; `scripts/eif-check.sh`
is a second check, not a substitute.

## Graviton (arm64)

The documented node is a `c6g.large` (Graviton, 2 vCPUs) in `eu-central-1`.
The AWS user guide lists `c6g.large` for Nitro Enclaves and excludes
`c6g.medium`. `main.tf` (`instance_type`, `region`) defaults to these two. An
x86_64 node needs another instance type, an x86_64 AMI and an x86_64 EIF.

No instance type that is Free Tier eligible supports Nitro Enclaves, so the
account needs the paid plan. On the Free plan `RunInstances` fails with
`InvalidParameterCombination: The specified instance type is not eligible for
Free Tier`.

### Build the arm64 EIF on an x86_64 machine

```sh
sudo apt-get install -y qemu-user-static   # once, "make deps" does it too
ARCH=aarch64 scripts/nitro-eif.sh
scripts/nitro-eif.sh aarch64                # the same, arch as the argument
```

The image is generic: no chain config, client CA or region goes in
("Setup"). `CHAIN` picks the runner build, the mainnet runner when unset.
The chain is checked when the setup is made (`setup-tool check -chain`).

The script writes `runner-aarch64.eif`, `build-enclave-aarch64.json`,
`describe-eif-aarch64.json`, `kms-key-policy-aarch64.json` and
`inputs-aarch64.txt` into `build/nitro/`. The image holds the arm64 release
runner and the same flags as the x86_64 image. It builds the EIF twice and
compares the PCRs, as for x86_64.

How an x86_64 machine builds an arm64 EIF:

- nitro-cli 1.5.2 takes the kernel file name from the arch it runs on
  (`src/lib.rs`, `bzImage` or `Image`). `nitro-cli/target-arch.patch` makes
  it read `NITRO_CLI_TARGET_ARCH` first. The nitro-cli Dockerfile applies the
  patch to the pinned source and rebuilds nitro-cli, so nothing in
  `third_party/` is edited by hand. Without the variable nitro-cli behaves as
  upstream, and the x86_64 PCRs are the same.
- The arm64 blob set (kernel `Image`, `init`, `nsm.ko`, `linuxkit`) is part
  of the pinned source. `nitro-eif.sh` mounts it over the blobs in the
  nitro-cli image and sets `NITRO_CLI_TARGET_ARCH=aarch64`. nitro-cli itself
  stays an x86_64 program.
- `linuxkit` builds the two ramdisks, and the copy in the arm64 blob set is
  an arm64 program. It runs inside the container through qemu-user. The
  package `qemu-user-static` registers the `binfmt_misc` entry
  `qemu-aarch64` with the `F` flag, which opens the interpreter at
  registration, so a container needs no copy of qemu. The script runs
  `linuxkit version` in the container first and stops with a hint if that
  fails.
- The enclave image is built with `docker buildx build --platform
  linux/arm64`. It is `FROM scratch` with `COPY` lines only, so nothing runs
  in it. nitro-cli sets the arm64 flag in the EIF header from the image's
  architecture.

### Region

The setup names the region (`sealing_key_release.region`,
`slashing_log_store.region`): the KMS key ARN, the proxy routes and the
coarse-time URLs follow from it. The enclave dials
`kms.<region>.amazonaws.com` by name through the vsock-proxy on the parent,
and `parent-run.sh` starts the proxies from the same setup. The region of the
setup and of `main.tf` (`region`) must be the same.

### Check the EIF without hardware

Approve PCRs only from your own reproducible rebuild of the source
(`tee-signer/docs/runner.md`, "Building and verifying an image"), never from
an EIF someone else built. `scripts/eif-check.sh` is an extra sanity check on
top of that rebuild. `nitro-eif.sh` ends with it, and you can run it on an
EIF:

```sh
scripts/eif-check.sh build/nitro/runner-aarch64.eif aarch64 \
  --runner build/aarch64/bin/runner-aws --build-json build/nitro/build-enclave-aarch64.json
```

It reads the file and does not use nitro-cli. It checks:

- the arch flag in the EIF header,
- the kernel: for arm64 the `Image` header magic `ARMd` at offset 56 (for
  x86_64 `HdrS` at 0x202), and that the bytes are the blob file's,
- each ramdisk is one cpio newc archive with only zero bytes after its
  trailer (the kernel would unpack a second archive over the first),
- `init` and the runner in the ramdisks are ELF files of the arch, and the
  runner has the sha256 of `build/<arch>/bin/runner-aws`,
- with `--generic`, that the image holds no operator files (`/etc/signer`),
- PCR0, PCR1 and PCR2 recomputed from the sections (SHA-384 of 48 zero
  bytes and the SHA-384 of the section bytes). They must equal what
  nitro-cli printed. On an x86_64 EIF the same code reproduces nitro-cli's
  PCRs.

It reads only the files it knows. It does not show that the EIF holds
nothing else, so it does not replace the rebuild, and it does not show that
the hardware measures the EIF the same way.

### Check the PCRs on the parent

What the parent reports for the running enclave is the real check:

1. Copy the EIF, `build/<arch>/bin/hostagent`, `forwarder` and `udprelay`
   and the files of `platform-aws/deploy/` to the instance and run
   `parent-run.sh`. It ends with `nitro-cli describe-enclaves`.
2. The `Measurements` in that output must equal the ones in
   `build/nitro/build-enclave-<arch>.json` (`inputs-<arch>.txt` has them):
   PCR0, PCR1 and PCR2, all three.
3. If one differs, do not use the KMS policy rendered from the build: KMS
   refuses an enclave whose PCRs are not in the policy. Compare the sha256
   of the EIF on both machines, then run `nitro-cli describe-eif` on the
   instance. PCR1 covers the kernel, the command line and the bootstrap
   ramdisk, PCR2 the image ramdisk, and PCR0 all of them.

### The parent on Graviton

- `parent-run.sh` finds the EIF by `uname -m` (`runner-aarch64.eif`).
  `hostagent` and `forwarder` must be the arm64 builds in
  `build/aarch64/bin/`. `scripts/build-runner.sh` builds them without a C
  compiler (pure Go) and checks that every binary is static and of the right
  arch. `hostagent` and `forwarder` are built with `-tags platform_aws`, the
  tag that brings vsock.
- A 2-vCPU instance cannot give both vCPUs to the enclave and keep one for
  itself. `parent-run.sh` gives the enclave 1 vCPU there (`CPU_COUNT`,
  default 2 on 4 vCPUs or more) and writes it into the allocator config. An
  enclave with 1 vCPU and 512 MiB (`MEMORY_MIB`, the default) runs the
  runner. The runner sets its Go memory limit to 3/4 of the enclave's
  memory, so it follows `MEMORY_MIB` (tee-signer/docs/runner.md,
  "Configuration").
- `main.tf`: `instance_type` defaults to `c6g.large`, `region` to
  `eu-central-1`, and `ami_id` has to be an Amazon Linux 2023 arm64 AMI of that
  region (an x86_64 AMI does not launch on a c6g). The file looks no AMI up,
  so the AMI stays pinned. AWS publishes the current one under the SSM
  parameter `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64`.
- `aws-nitro-enclaves-cli` and the allocator install from the AL2023 arm64
  repository (`dnf install aws-nitro-enclaves-cli
  aws-nitro-enclaves-cli-devel`). An EIF built with nitro-cli 1.5.2 runs
  under the 1.5.0 package. The group `ne` applies from the next login, so
  run `parent-run.sh` in a session that started after the install.
- The security group's `ingress` is an explicit list, so `ssh_cidrs = []`
  removes the SSH rule. With no `entry_cidrs` and no `ssh_cidrs` the parent
  has no inbound rule.

## Restart protection and time on Nitro

- No persistent storage in the enclave, no sealing primitive, no
  monotonic counter: Trail of Bits, "AWS Nitro doesn't provide any
  specific data sealing mechanism"
  ([notes on the Nitro attack surface](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/)).
  The host agent stores the sealed blobs, so the parent can roll them back.
  The image therefore runs `-restart-floor=true -persist-watermarks=false`
  with the default margin `max_epochs_ahead + 1`, plus the mark log as a
  floor the parent cannot roll back.
- No AWS document says who sets the enclave clock. One vendor reports the
  clock is set at start and drifts; their fix reads time from the host
  ([Evervault](https://evervault.com/blog/how-we-built-enclaves-resolving-clock-drift-in-nitro-enclaves)),
  which is exactly what the floor must not trust. The image runs the NTS
  clock instead (`-nts-clock`, next section): the six default NTS
  operators and any the setup adds (`time_servers`; from seven a shift
  schedule), a quorum with an error bound, signing refused above the
  setup's `time_policy` bound (100 ms by default) or when the samples are
  over 90 s old. The parent can delay or
  drop that traffic but not forge it. The same clock checks the dates of
  client certificates. HTTPS Date readings over vsock-proxy are its coarse
  check.

## NTS clock in the enclave

The enclave has no network, and vsock-proxy carries TCP only
(`vsock_proxy/src/proxy.rs`). The NTS clock (`trusted-time/docs/nts.md`)
therefore takes two paths out, both through the parent and both untrusted:

| Traffic | Enclave side | Parent side | Destination |
| --- | --- | --- | --- |
| NTS-KE, TLS 1.3 | `proxy=` routes `time.cloudflare.com:4460=vsock:3:8005`, `nts.netnod.se:4460=vsock:3:8006`, `ptbtime1.ptb.de:4460=vsock:3:8007` ... `any.time.nl:4460=vsock:3:8018`, one per catalog host | vsock-proxy, allowlist in `vsock-proxy.yaml` | the catalog's hosts, TCP 4460 |
| NTP with NTS fields | `ntp_relay=vsock:3:7102` | `udprelay -listen vsock:any:7102` | the NTP server each NTS-KE named, UDP 123 or 4123 |
| coarse check (HTTPS Date) | the routes 8000 to 8002 | vsock-proxy | KMS, STS, `www.cloudflare.com` |

The port map is fixed in the image (`enclave/Dockerfile`), and the KMS, STS
and bucket hosts follow from the setup, which setup_hash covers. The parent
chooses none of them. The runner dials them through
`platform.Platform.Dial` (`platform-aws/nitro`, `NetDial`): TCP to the route
of the host and port, UDP through the relay.

### Relay protocol

`platform-aws/udprelay` uses one stream connection per NTP query. Frames are
a u16 big-endian length and 1 to 2048 octets. The enclave sends the
destination (`host:port`, as NTS-KE named it), the relay answers one status
frame (0x00, or 0x01 and a reason), then each frame is one datagram either
way. A frame of length 0 or over the limit ends the session. The relay sends
on a connected UDP socket, so it only passes back datagrams from the
destination it accepted.

### Allowlist

The destination's port must be 123 or 4123. A name must be one of the NTP
host names of every catalog host (`udprelay.DefaultNames`: each
server's own name, `time.meta.com`, and the plain NTP hosts `ntp.se` and
`ntp.hr` that plain NTP asks for Netnod and FER); the relay resolves it itself and
sends to the first public address, IPv4 first. An address must lie in `194.58.200.0/21` or be a public one that one of the
allowed names resolves to now (cached 5 minutes, a failed lookup 30 s).
Public means global unicast, not private (RFC 1918, fc00::/7) and not
shared space, NAT64, 6to4 or another special block, so a DNS answer that
points a catalog name at a private or special address (the VPC's IPv4
space, the parent's private address, loopback) gets no datagram. The relay
cannot tell a public address of the VPC or the parent (an Elastic IP, the
VPC's global IPv6 block) from an NTP server's, so a DNS answer that names
one is sent to. That answer comes from the parent's resolver, which the
host runs, and the host can send datagrams there itself. An address the
enclave names directly that is not public is refused before any lookup.
Nothing else goes out and no other name is resolved. The block is for
Netnod: each IPv4 address of `nts.netnod.se` names a different NTP server by
address, port 4123, in `194.58.203.x` to `194.58.207.x`, and none of them is
an address of the name. Meta's NTS-KE names time.meta.com, which is on the
list; the other servers name themselves. If
Netnod moves its NTP servers out of the block, the relay refuses them
(`destination refused` in its log) and the quorum runs on the others
until `-allow-nets` is extended.

### Limits

16 sessions at once; a session ends 10 s after its last datagram or 30 s
after it began; 8 datagrams out per session; 10 datagrams per second out in
all (burst 20) and 0.5 per second to one address (burst 4). Under the shift
schedule the clock asks each server at most once per 60 s: 4 actives make
4 datagrams a normal minute, plus fallbacks; the start round asks every dialed
server at once, and until the first quorum a server that did not answer is
asked again every 20 s (at most the 90 s start wait). The one exception
after the first quorum: a lost answer may get one retry 20 s later, at most
one per lost contact and within the clock's 120 per hour cap of extra
queries, so a server whose answers are lost gets at most two requests per
60 s. Over a
limit the datagram is dropped and counted, as a network would drop it.
`udprelay` logs its counters every 10 minutes.

### What the parent can do

Delay or drop NTS-KE and NTP. A delayed answer widens that sample's bound by
half the delay and cannot move the time outside it; dropped answers stop
signing once the oldest sample of the last quorum is 90 s old, or the bound,
aged by 500 ppm, reaches 100 ms first. It cannot forge: TLS 1.3 with pinned roots ends in the
enclave, and every NTP answer carries the NTS authenticator with keys from
that TLS session (AES-SIV-CMAC-256). It can send unauthenticated
Kiss-o'-Death packets with our unique identifier, which may disable a server
(RFC 8915 section 5.7 allows the client to act on them). A disabled
active's slots go to fallbacks among the other servers; with too few
servers answering, signing stops: fail closed. The parent does not run
the enclave's CPU counter, the clock's local time (`CLOCK_MONOTONIC_RAW`):
the enclave's CPUs are taken away from the parent, and the Nitro
hypervisor, which AWS runs, keeps the counter. So the parent cannot move
the time ahead by running the counter fast; the lead stays within the
bound (`trusted-time/docs/nts.md`). The drift check against a quorum
17 minutes old still refuses a rate beyond 500 ppm.

With `time_policy` protocol ntp (plain NTP, no NTS) none of this holds: the
parent sees every request and can forge every answer. The time is then
only as good as the coarse check, up to about 46 s behind and 31 s ahead
of real time (`trusted-time/docs/nts.md`, "Plain NTP"); the 196 s case
there needs a counter the host can run fast, which the parent cannot.

### Security group

`main.tf` variable `nts_egress` (default true): TCP 4460 and UDP 123 and
4123 out to anywhere. A security group cannot name hosts and the operators'
addresses move, so the narrow rules are the relay's allowlist and
vsock-proxy's.

`TestE2ENTSClockThroughRelay` (`tests/e2e`) runs the relay, the
proxies and the clock over TCP on loopback, and `TestE2ENTSRelayInterop`
runs them against the catalog's default public servers.

## Share import

Shares arrive only as IMPORT_SHARE_SEALED: HPKE (ML-KEM-768 + X25519,
Go's `crypto/hpke`) to a key the runner makes at boot and binds into the
NSM document's `user_data` (`signer-protocol/docs/protocol.md`). The image
holds the release AWS runner (`build/<arch>/bin/runner-aws`, tag
`platform_aws`: the Nitro platform and no Azure or GCP code), which has no
plaintext import at all; only the debug builds for local tests have it. The
dealer verifies the NSM document (AWS root, PCRs) with `share-import
-verifier aws-nitro -nitro-pcr 0=... -nitro-pcr 1=... -nitro-pcr 2=...
-tls-cert client.pem -tls-key client-key.pem -addr tcp:<parent>:7100`. The
runner's vsock listener needs a client certificate like every other client,
so the tool connects through the forwarder on the parent (`-addr` is the
forwarder's TCP port), and the TLS ends inside the enclave. The share leaves
the tool sealed to the key in the verified identity, so the forwarder and
the parent see ciphertext only.

## Network entry

The enclave has no network. The parent instance forwards traffic into it over
vsock, and the parent is not trusted: the network between the parts is not
trusted and can be replaced. So the way in has three parts, and only the
last two are trusted.

```
 client --- TCP ---> forwarder (parent) --- vsock 16:7100 ---> runner (enclave)
    |                   copies bytes, no TLS                        |
    +------------- mutual TLS 1.3, ends inside the enclave ---------+
    aws-nitro check of the identity on every connection (client side)
```

The signing client stays on TCP. Its copy of the client has no vsock. It connects
to `tcp:HOST:PORT` of the forwarder, like it does to a signer on Azure. The
forwarder can be replaced without touching the signing client or the enclave.

### TLS inside the enclave

The runner serves the same mutual TLS 1.3 on its vsock listener as on TCP
(`tee-signer/attls`, one configuration for every tcp and vsock listener):

- A fresh ECDSA P-256 key at every boot, made inside the enclave, with a
  self-signed certificate. Clients do not check that certificate against a
  CA. They pin its key through the attestation.
- A client has to present a certificate that chains to the setup's client
  CA. The handshake fails without a certificate, with a certificate from
  another CA, with an expired one, with TLS 1.2 and with plain bytes.
  Session tickets are off, so each connection gets the full certificate
  check. A peer that connects and does not finish the handshake is dropped
  after 10 seconds.
- The identity carries `tls_key_hash`, the sha256 of that key, and the NSM
  document's `user_data` covers the identity. `attestation-verify/runnerclient`
  accepts a connection only if the key of the handshake is the key in the
  verified identity. A parent or forwarder that ends TLS with its own key
  fails that check, even with a valid client certificate.
- The runner refuses to start on the `nitro` platform without a client CA,
  for vsock and for TCP listeners. A release build also refuses a plain
  vsock listener on any platform. Only the debug build keeps one, on the dev
  platform, for the vsock loopback test.

The parent has no client certificate, so it cannot send requests of its own.
It can still drop, delay and refuse to forward traffic, stop the enclave, and
see who connects and how much they send. TLS rejects replayed or changed
records.

### The forwarder

`platform-aws/cmd/forwarder` (code in `platform-aws/forward`) is the network
entry:

```
forwarder -listen tcp:0.0.0.0:7100 -to vsock:16:7100
```

`scripts/build-runner.sh` builds it as `build/<arch>/bin/forwarder`, and
`parent-run.sh` starts it. It accepts TCP connections, dials the enclave's
vsock port for each one and copies bytes both ways. A half-close passes
through. It allows 256 connections at once (`-max-conns`) and, from one
source IP address, 16 in their first 15 seconds (`-max-conns-per-source`:
the runner's handshake deadline of 10 seconds plus the 5 seconds it gives
the dial; the forwarder sees no handshake, only its deadline). A connection
past that window counts against the 256 only, so clients behind one address
keep their pools. The cap per source is the only one per peer on Nitro: the
enclave sees every connection come from the parent's vsock address, so
without it one outside peer that connects and says nothing could hold every
handshake slot of the runner. It has no
certificate, key or CA, reads no request and answers none. Tests (`platform-aws/forward`): mutual TLS 1.3 with the
runner's real TLS configuration runs through it, the client sees the
target's key, and the bytes it copies do not contain the payload.

`socat TCP-LISTEN:7100,fork,reuseaddr VSOCK-CONNECT:16:7100` does the same
job.

The security group can allow the forwarder's port from the signing client hosts
(`entry_cidrs` in `main.tf`, empty by default: no inbound rule). That limits
exposure and the load on the instance. It is not what keeps the runner safe.

### What the image measures

The client CA certificates (public, 1 to 4, DER) are the setup's
`allowed_client_ca`. setup_hash covers them, and the runner puts setup_hash
in its attested identity. The parent can hand over a setup with its own CA.
That runner shows another setup_hash and finds another, empty mark log, so it
stops while this signer's shares are stored, and the shares do not open for
it. Its KMS calls carry its own setup_hash, so it does not get the sealing
key either. The runner refuses a client certificate listed in the setup's
`revoked_client_certs`, one of a listed public key, or one below a listed CA
(`signer-protocol/docs/protocol.md`, "Client roles"). `test-client-ca.pem` is the root of a test PKI made by
`scripts/make-test-ca.sh`. Its private key is not in the repo.

### Client certificates, the clock and the CA

- The setup pins the CA only, not the client certificates. Client
  certificates can be short-lived (hours or days) and can be rotated
  without a new setup. A change of the CA is a new setup, so a new
  setup_hash.
- The runner checks the validity dates of the client certificate, and of
  its chain, against the clock of its platform (the NTS clock, "NTS clock in
  the enclave"), not against the system clock that the parent sets. If that
  clock has no time (no quorum, a bound over 100 ms, or samples over 90 s
  old), no client
  certificate is accepted until it has one. With `clock=system` the parent
  could move time and let an expired certificate through, but it would still
  need that certificate and its key.
- Use a root and an intermediate. Pin the root in the setup and keep its
  key offline. The intermediate is online, issues the client certificates
  and is renewed every few months. A client file holds the leaf and then the
  intermediate, because the runner knows the root only (`client_cert` of
  `attestation-verify/runnerclient` takes the whole chain). A client file
  with the leaf alone is refused. Tests in `tee-signer/attls`
  (`TestPinnedRootWithIntermediate`) show a rotated intermediate accepted by
  the same server, and an expired one refused.
- The runner has no revocation list. A leaked client key works until its
  certificate expires, so issue for hours or days. A leaked intermediate key
  mints certificates until the intermediate expires. The runner cannot be
  told to distrust one intermediate. If that key leaks, the fix is a new
  root. Keep intermediates short-lived, and the key in an HSM or KMS.
- Issue with `NotBefore` about five minutes in the past. The runner clock
  is at or just behind real time (about a second in normal operation).

`scripts/make-test-ca.sh` makes a root, an intermediate and one client
certificate under it for tests.

## Steps

The full order of a deploy, with the setup, is in
`governance/docs/setup-phase-cloud-test.md`. In short:

1. Build: `scripts/build-runner.sh` (runner, `hostagent`, `forwarder`,
   `udprelay` for the parent's arch), then `scripts/nitro-eif.sh` (with
   `ARCH=aarch64` for Graviton). Note the PCRs it prints.
2. `terraform apply` of `main.tf` with `pcr0`, `pcr1`, `pcr2`, the
   `admin_role_arn`, `key_policy_locked` (true for mainnet, see "Setup"), `ami_id`, `subnet_id` and, if wanted, `mark_bucket`
   with `mark_min_lock_days`, `entry_cidrs`, `ssh_public_key` and `ssh_cidrs`. Terraform state stays
   outside the repo.
3. The writer credentials (see "Clone protection", steps 2 and 3).
4. Copy the EIF, the parent binaries and the files of
   `platform-aws/deploy/` to the instance, install the Nitro CLI, and run
   `SETUP=<setup> parent-run.sh` in a new session, or install
   `signer-runner.service` ("Restarts").
5. Check the PCRs on the parent ("Check the PCRs on the parent"), then the
   proof from a client (see "Verify").

The names default to one node per account: role and instance profile
`signer-parent`, security group and instance `signer-node`, record writer
`signer-record-writer-node-1` and key pair `signer-node-operator-node-1`.
For a second node in the account, set `node_key` (it names the record
writer and the key pair) and `parent_role_name`. IAM names are global to
the account, so these two must differ even for a node in another region.
In the same region, set `security_group_name` too. Give each node its own
mark bucket, named after the node (for example `<org>-marks-<node_key>`):
each node's apply writes the whole bucket policy, so two nodes on one
bucket would drop each other's record writer, and the runner whose writer
is dropped stops signing. To take over resources made earlier, set
`parent_role_name`, `parent_role_description`, `security_group_name`,
`security_group_description`, `instance_name`, `key_description` and
`key_tags`, and import the existing resources (`terraform import`, or
`import` blocks in a file of the operator's next to `main.tf`). A plan with
no changes shows that they match. Three of these matter more than the
others. PCR3 is computed from the role's ARN, so a new role name means a new
key policy. A new security group description replaces the group. A locked
key's description and tags can never change. `extra_egress` adds outbound
rules to the four of the security group, for example for a network entry
the operator runs on the parent; the enclave still reaches only the routes
of its setup.

Upgrade note for a node with `ssh_public_key` set: the key pair was
`signer-node-operator` before it was named per `node_key`. The next plan
replaces it with `signer-node-operator-<node_key>` (same public key) and
leaves the instance alone. A new `key_name` would replace the instance, and
the host store on its disk with it, so `main.tf` ignores changes to the
instance's `key_name`: EC2 reads the key pair only at launch, and the
parent keeps the key it has. The resource address does not change, so no
`terraform state mv` is needed. A `target/main.tf` deploy reads the key pair
by name: set its `key_pair_name` to the `key_pair_name` output of
`main.tf`. Its instance ignores a new `key_name` too.

`parent-run.sh` starts the processes on the parent (`vsock-proxy` for each
route, `hostagent`, `udprelay`, `forwarder`) with `nohup`. Run by hand, a
reboot ends them and needs `parent-run.sh` again. `signer-runner.service`
does that at boot ("Restarts"). The store under `/var/lib/signer-runner`
stays.

A runner that fails sends the line it prints (`runner: ...`) to the host
agent before it exits (hostagent EXIT). The agent writes it with the time to
`/var/lib/signer-runner/last-exit.txt` (`-exit-file`) and to its log.

The reason for each exit is in `last-exit.txt`. Nothing else leaves the
enclave this way: one line of printable ASCII, at most 2048 bytes, the same
text a console would show. An enclave that is not in debug mode has no
console.

## Restarts

`signer-runner.service` runs `parent-run.sh` at boot, after the allocator
and the network, and starts it again after a failure, as `restartPolicy`
OnFailure does on Azure and `tee-restart-policy=OnFailure` on GCP.
`nitro-cli run-enclave` returns once the enclave runs, so
`parent-service.sh`, the unit's main process, checks the enclave
(`nitro-cli describe-enclaves`) and the parent tools that `parent-run.sh`
started every 10 seconds (`WATCH_INTERVAL`). After `parent-run.sh`
returns, it waits up to 10 seconds (`START_WAIT`) for each tool to
start. When the enclave or any of the tools has ended, it logs the
reason with the line of `last-exit.txt`, terminates the enclave, stops
the tools and exits 1. systemd starts the whole set again.

- A crash and an exit on purpose are the same here. The runner ends only on
  an error: a refused setup, an image that the setup does not list, no NTS
  quorum within `-nts-wait` (90 s), a sealing key it cannot open. Each is a
  non-zero exit, which OnFailure restarts on Azure and GCP, so the service
  restarts each too. The exit 0 of the other platforms comes from a stop
  signal, and nothing sends one inside an enclave. So a refused setup, a
  missing EIF or an image that the setup does not allow also restarts,
  every few minutes once the wait is at `BACKOFF_MAX`: check the journal.
  A later locked update that allows the image takes effect at the next
  restart.
- `systemctl stop signer-runner` is the clean stop. The main process alone
  gets SIGTERM (`KillMode=mixed`), terminates the enclave, stops the tools
  and exits 0, and systemd does not restart a stopped unit. An enclave
  terminated by hand with `nitro-cli terminate-enclave` while the unit runs
  counts as a failure and is started again.
- The wait before a start grows after each failure: 10 s, then doubled up to
  300 s (`BACKOFF_BASE`, `BACKOFF_MAX`). An enclave that ran 600 s
  (`BACKOFF_RESET`) starts the count again. The unit has no start limit
  (`StartLimitIntervalSec=0`): like Azure, it keeps trying, every 300 s
  once the wait is at its longest, so a signer comes back by itself after
  an outage of any length, for example of NTS. A setup the runner refuses
  is retried the same way; `last-exit.txt` and the journal show the
  reason.
- One enclave and one set of tools. The service starts only when no
  enclave and none of `hostagent`, `forwarder`, `udprelay` and `vsock-proxy`
  runs. Otherwise it exits 3, which the unit does not restart, and touches
  neither, so a set started by hand stays as it is. `ExecStopPost`
  terminates an enclave that the service started and left behind, for
  example after the main process was killed.

The settings go in `/etc/signer-runner/parent.env` (`parent.env.example`):
`SETUP` and `STATE_DIR` as absolute paths, and if needed `EIF`,
`CPU_COUNT`, `MEMORY_MIB`, `ENTRY_PORT` and `ENCLAVE_CID`. They hold file
names and sizes, no secret, and reach `parent-run.sh` in its environment.
The logs of the tools stay in `/tmp`, those of the service in the journal
(`journalctl -u signer-runner`).

Install, on the parent, as `ec2-user` (the user of the unit, `User=`).
A parent that uses another account sets `User=` in a drop-in
(`systemctl edit signer-runner`); that account must own `STATE_DIR` and be
in the group `ne`.

```sh
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo usermod -aG ne ec2-user
sudo install -d -o ec2-user -g ec2-user /opt/signer-runner
cp runner-$(uname -m).eif hostagent forwarder udprelay parent-run.sh parent-service.sh   allocator.yaml signer.setup /opt/signer-runner/
sudo install -d /etc/signer-runner
sudo install -m 644 parent.env.example /etc/signer-runner/parent.env   # then edit SETUP, STATE_DIR
sudo install -m 644 signer-runner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now signer-runner
systemctl status signer-runner
```

A parent that runs `parent-run.sh` by hand moves to the service in one
short downtime: `nitro-cli terminate-enclave --all`, stop the four tools
(`pkill -x 'hostagent|forwarder|udprelay|vsock-proxy'`), then the steps
above with the same `STATE_DIR` and `SETUP`. The store stays, so the
runner starts from it as after any restart.

## Verify

- `nitro-cli describe-enclaves` on the parent reports the PCRs of the
  build, all three equal.
- CloudTrail shows `GenerateDataKey` (first start) or `Decrypt` by the
  instance role session without an error code. The runner only starts to
  serve after the sealing key and the writer credentials both decrypt, so a
  listening runner means the PCR conditions of the key policy accepted its
  document.
- From a client, through the forwarder, with a client certificate of the
  setup's CA: `share-import` or the signing client with the `aws-nitro` verifier
  and the PCRs of the build. A wrong PCR is refused with `measurement
  mismatch: pcr2 is ..., want ...`. `scripts/kms-policy.sh pcr3` gives the
  PCR3 the document should carry for `role/signer-parent`.

## Limits

- A kernel without vsock loopback (WSL2) skips the vsock tests of
  `tee-signer/attls` and `tests/e2e`. They run over TCP loopback there.
- The parent processes run under `nohup`, not as services.
- The enclave's clock: see "Restart protection and time on Nitro".
