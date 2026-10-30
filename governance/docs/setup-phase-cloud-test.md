# Setup phase: real-cloud test of the generic images

The procedure for testing the generic images on all three clouds: one image
per cloud, the key policy, release policy and WIF condition set once, and
each signer's values in its setup. It is phase 1 item 9 of the setup-phase
design (`research/setup-phase.md` in
[threshold-signer-poc](https://github.com/lidofinance/threshold-signer-poc/blob/main/research/setup-phase.md),
"Build plan").

Every step that creates or changes something in a cloud needs the
operator's approval. The deploy scripts refuse such a step unless
`CONFIRM=yes` is set. Network entry credentials and AWS writer credentials are read
from files and never printed or put on a command line.

## What the test shows

- One image per cloud runs any signer of any chain. The signer's values
  come in its setup at start, through the platform's channel: the host
  agent over vsock on Nitro, `SIGNER_SETUP` on Azure, the metadata
  attribute `signer-setup` on GCP.
- The key policy (AWS), the release policy (Azure) and the WIF condition
  (GCP) pin the image once. A new chain or a new signer is a new setup, not
  a new policy.
- IDENTITY carries `setup_hash`, and the verifiers refuse a runner whose
  setup is not the pinned one.
- Config updates work on real stores: a `locked` update with time lock 0, an
  `open` fork-schedule update, an approver rotation, a supersede, and the
  effective config survives a restart.
- Each mark store's lock is checked at start, and a start against a store
  with too short a retention stops.
- On AWS the key admin cannot plant a sealing key.

## Needed before the run

- The operator's approval for each cloud step below.
- No other signer set serves the validators of the test (rule 1).
- A test chain with new validators.
- The operator's network entry for each signer, and its credentials, if it
  needs any, in mode 600 files. The C3 negative starts on Azure and GCP may
  need one more each.
- AWS admin credentials for a second access key of the record writer and
  one `kms:Encrypt` (step 3).

## Images

`scripts/generic-images.sh build` builds the three images and writes their
measurements; `scripts/generic-images.sh check` compares a later build with
the recorded values before any push. Build twice and compare: the values
must be the same.

| Cloud | Image | What is fixed in it |
| --- | --- | --- |
| AWS | Nitro EIF for arm64 (Graviton `c6g.large`), `scripts/nitro-eif.sh aarch64` | runner with `platform_aws,nts`, `-setup platform`, NTS clock, `-record none`, the fixed vsock port map; no DynamoDB, no `-record-key` |
| Azure | container with the operator's network entry (`NETWORK`), `platform-azure/deploy/build-image.sh`; CCE policy from `deploy.sh policy` with `STDIO=enable` | the whole command (the entry's start, if any, then the runner with `-setup platform`); `SIGNER_SETUP` and the entry's credential are wildcard rules |
| GCP | Confidential Space workload with the operator's `NETWORK_ENTRY` (default `public`), `platform-gcp/deploy/build-image.sh` | entrypoint with `-setup platform`; `log_redirect` always |

These are test images. Production images differ in two settings, so they
get their own measurements: Azure `STDIO=disable`, GCP `log_redirect`
never.

### Testnet images (research only)

The testnet build is the same code built with `-tags testnet`
(`signer-protocol/buildflavor`). Each governance time lock that is an image
constant runs one minute for each day of the default build:

| Image constant | Default build | Testnet build |
| --- | --- | --- |
| Default time lock (the setup names none) | 48 hours | 2 minutes |
| Time lock cap (`change_delay_seconds` at most) | 30 days | 30 minutes |
| Activation horizon, past the required wait | 30 days | 30 minutes |
| Images minimum: allowed-images updates, handover orders on a cloud | 7 days | 7 minutes |

Use them while research changes images and runs handover orders, when a week
per step would stall the work. They never hold real keys: production, and
every signer whose keys matter, runs the default build. What keeps the two
apart:

- A testnet runner starts on a devnet, or on Hoodi, Sepolia or Chiado with
  their exact genesis fork version and genesis validators root. It refuses
  mainnet, Gnosis, Holesky and LUKSO, any chain with one of their values
  or a test network's fork version with another root, and the flag path
  (`governance/flavor/chains.go` names the source of each value).
  The check runs before the platform starts, so before key release.
- It says what it is: HEALTH's version and the start log say
  `0.1.0+testnet`, and its TLS certificate is named
  `signer-runner testnet`.
- Every client refuses it in the TLS handshake unless the connection sets
  `"allow_testnet_build": true`: cloud.json of the Dirk fork and
  signer-admin's runner entries, identity-check, handover-source and
  handover-target;
  `-allow-testnet-build` for cloud-import and share-import.
  `platform-gcp/deploy/deploy.sh verifier-config` writes it for a testnet image.
- Its measurements are its own, so key-release policies, `allowed_image_measurements`
  and the verifier pins name the testnet values, never the default ones,
  and the reverse.
- Its setups keep `change_delay_seconds` at 1800 or less (the testnet cap);
  without one, the 2-minute default holds. `signer-config setup -build
  testnet` refuses more. signer-config reads each signer's build from
  HEALTH and drafts with that build's waits.

Build, offline: `IMAGE_FLAVOR=testnet scripts/generic-images.sh build`. The
flavour goes into every name: runners `runner-<cloud>-testnet`, folders
`build/nitro-testnet` and `build/gcp-testnet`, local images
`signer-cloud/{azure,gcp}-runner-testnet`, registry tags `generic-testnet-ts`
(Azure) and `generic-testnet` (GCP), record `cloud/generic-images-testnet.txt`.

The testnet tests: `scripts/handover-gate.sh` runs the handover gate on
`runner-dev-testnet` too, and `tests/e2e` built with `-tags testnet` (from
`tests/`: `go test -tags testnet -timeout 20m -run TestE2ETestnet -v ./e2e`)
runs the chain refusals and a testnet dev runner whose allowed-images update
stays pending past its 2-minute time lock and comes into force 7 minutes
after it is sent. Deploying testnet images follows the steps below, with the
testnet values and `allow_testnet_build` in every connection.

### Nitro peer endpoints (handover)

A runner checks the other image of a handover with the attestation
verifier of its own platform (`attestation-verify/runnerclient`, build tag
`verifierselect`, which `scripts/common.sh` sets for every runner build). A
Nitro signer hands over to a Nitro signer and checks it with `aws-nitro`,
whose root certificate is in the binary, so it fetches no key set. The
Azure and GCP verifiers (`azure-maa`, `gcp-cs`) fetch their key sets over
HTTPS, and the Azure and GCP signers have egress of their own; a Nitro
enclave reaches only the routes of its setup.

A Nitro signer's setup may list hosts in `peer_attestation_hosts`. The
parent starts a vsock-proxy for each on ports 8010 to 8025 (at most 16),
in the setup's order, and the enclave maps those names to them; nothing
else gets a route. On a runner with limited egress a handover order whose
verifier would fetch a key set from a host outside that list is refused,
and the refusal names the host; with the own-platform verifier a Nitro
signer never needs one, so the sample setup below lists none. `setup-tool check` prints the list
(`peer_attestation_hosts none` for a Nitro setup without one);
`hostagent -proxy-routes` prints the routes, 8010 and up last. The
parent's security group allows TCP 443 out (`main.tf`), so a listed host
on another port needs a rule.

## Rules for this test

1. Never two live signer sets for one validator. If the test reuses the
   parent instance, container group or VM of running signers, it starts
   only after those signers stop. It uses a new test chain with new
   validators. No key of another signer set is imported into a generic
   signer.
2. The state of signers the test replaces stays where it is. An AWS store
   moves aside on the parent; Azure and GCP state copies stay in the locked
   stores under their signer names. Nothing of it opens in a generic
   signer: other measurement, other `setup_hash`, other paths.
3. Run the steps in this order, one cloud at a time if you like. Read each
   step's check before the next step.
4. The mark stores are an S3 bucket, a GCS bucket and an Azure container
   (`S3_BUCKET`, `GCS_BUCKET`, `AZ_ACCOUNT`, `AZ_CONTAINER`). Each has a
   locked 1-day retention, so every setup of this test sets
   `slashing_log_min_lock_days = 1`. A runner stops when its newest record
   is older than half of that (12 hours): a signer stopped for longer needs
   a new setup and a new import.

## Settings

Set these once per shell, from the deploy settings of each cloud.

| Setting | Value |
| --- | --- |
| `CHAIN`, `CHAIN_JSON` | the test chain's name and its chain file (step 0) |
| `IMAGE_TAG=generic` | registry tags `generic` (GCP) and `generic-ts` (Azure) |
| Azure | `NETWORK` (the operator's network entry), `KEY_NAME_PREFIX=signer-gkek` (a key of its own, so an earlier key keeps its release policy for a rollback), `SUBSCRIPTION_ID`, `LOCATION_1`, `VAULT`, `ACR_NAME`, `RG` |
| GCP | `NETWORK_ENTRY` (default `public`), `MARK_STORE=gcs:bucket=$GCS_BUCKET` |
| AWS | Terraform folder `<terraform-dir>`, parent folder `<parent-dir>` |
| Network entry | the operator's, with its own names and credentials per signer. On AWS it runs on the parent, outside the setup |

## Step 0: local, no cloud

1. Images: `scripts/generic-images.sh check` passes.
2. Tools: `signer-config`, `cloud-import` and `proof-check` from the Dirk
   fork (`dirk-fork/backends/cloudremote/cmd` in threshold-signer-poc),
   `identity-check` and `setup-tool` from this repo (`signer-admin/cmd`).
3. Approver keys: three test keys `approver-1.key` to `approver-3.key`
   (never real keys). For the rotation make a fourth test key:
   `umask 077; openssl rand -hex 32 >approver-4.key` in a private folder.
   `signer-config sign` prints each key's public key.
4. The test chain and its chain file:
   `platform-azure/deploy/chain-from-devnet.sh <beacon URL> $CHAIN_JSON`, then
   `setup-tool chain-lines $CHAIN_JSON`. It prints the chain, the safety
   values, the `locked` values the chain file holds
   (`allowed_fee_recipients`, the builder gas limits,
   `builder_registration_max_future_seconds`, `exit_allowed_validators`,
   `allow_unverified_nonslashable_signing`) and the `open` `fork_schedule`.
5. The cluster file `setup.conf` (setup format 1, field names of
   `research/attestation-prover.md` in threshold-signer-poc, "Field names").
   Before the first section, the lines all signers share:
   `setup_format_version = 1`, `handover_generation = 1`, the chain lines
   (set `allow_unverified_nonslashable_signing` as the test's signing paths need),
   `allowed_client_ca` (the client CA, base64 DER), `max_keys`,
   `slashing_log_min_lock_days = 1`, and the rest of `locked`: approvers 1
   to 3, `approvals_needed = 2`, `change_delay_seconds = 0`, the exit and
   balance values and `withdrawal_credentials`
   (`governance/setupwire/testdata/setup-gcp.conf` lists them, without its
   `salt.*` and `platform_salt` lines: `signer-config setup` draws the
   salts). Then one section per signer:

   ```
   [signer signer-1]
   platform = azure
   slashing_log_store.account = <AZ_ACCOUNT>
   slashing_log_store.container = marks
   slashing_log_store.subscription = <SUBSCRIPTION_ID>
   slashing_log_store.resource_group = <RG>
   encrypted_state_store.account = <AZ_ACCOUNT>
   encrypted_state_store.container = marks
   encrypted_state_store.subscription = <SUBSCRIPTION_ID>
   encrypted_state_store.resource_group = <RG>
   sealing_key_release.maa_endpoint = sharedneu.neu.attest.azure.net
   sealing_key_release.akv_endpoint = <VAULT>.vault.azure.net
   sealing_key_release.kid = signer-gkek-1

   [signer signer-2]
   platform = nitro
   slashing_log_store.bucket = <S3_BUCKET>
   slashing_log_store.region = eu-central-1
   sealing_key_release.region = eu-central-1
   sealing_key_release.kms_key_id = <AWS_KMS_KEY_ARN>

   [signer signer-3]
   platform = gcp
   slashing_log_store.bucket = <GCS_BUCKET>
   encrypted_state_store.bucket = <GCS_BUCKET>
   sealing_key_release.wif_provider = //iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/signer-pool/providers/signer-attestation
   sealing_key_release.kms_key = projects/<PROJECT_ID>/locations/europe-west4/keyRings/signer/cryptoKeys/sealing
   sealing_key_release.attest_audience = signer-runner-identity
   ```

   A file with one GCP signer and nothing else is refused: that signer
   would hold keys alone (1 of 1), and on GCP the key release rests on IAM
   bindings that anyone with IAM or KMS admin rights on the project, the
   pool or the key (folder and organization admins included) can change
   at any time, with no image to run: a changed binding lets any
   principal decrypt the sealing key outside any TEE and open the sealed
   key, the whole validator key, from the state bucket
   (`setupwire.UnsafeSingleKeyWarning`). To accept that risk, run
   `signer-admin setup -allow-gcp-unsafe-single-key` (for a one-signer
   GCP file only) or put
   `sealing_key_release.unsafe_single_key_accepted = true` in the signer's
   section; the tool prints a WARNING line for the setup, and the runner
   logs the warning at start and at every 1 of 1 import. On mainnet the
   same section also needs `sealing_key_release.no_lock_accepted = true`,
   or the runner does not start, and the tool refuses the setup without
   it. The 1 of 1 import order itself needs
   `signer-admin import-draft -allow-gcp-unsafe-single-key`, and `show`
   prints the warning to each approver.

6. `signer-config setup -out setups setup.conf` writes `setups/signer-N.setup`
   and prints `cluster_id` and each `setup_sha256`. Keep the output.
7. Each setup against its deploy: `setup-tool check -platform azure -chain $CHAIN_JSON setups/signer-1.setup`,
   the same for nitro and gcp. Dry runs: `platform-azure/deploy/deploy.sh plan`,
   `platform-gcp/deploy/deploy.sh plan`, and
   `build/x86_64/bin/hostagent -setup setups/signer-2.setup -proxy-routes`,
   which prints the parent's routes as `parent-run.sh` will start them:
   8000 to 8008, and nothing from 8010 up, as the setup lists no peer
   host.
8. Negative setups for the lock check (C3): the same file with
   `slashing_log_min_lock_days = 2` and the names `lockneg-N`, written to
   `setups-neg/`.
9. `cluster.json` for signer-config: one entry per signer, with its
   `cloud.json` (address, client certificate, the attestation values of the
   built images) and its setup.

## Step 1: snapshot, read only

If the test replaces running signers, save their live settings first: group
template and CCE hash, VM metadata and WIF condition, key policy, enclave
and store on the parent.

## Step 2: stop the signers the test replaces

Skip this step on fresh resources.

1. Stop the validator clients and Dirk forks that use them, so nothing
   signs through them.
2. AWS: terminate the enclave and its proxies, host agent, forwarder and
   udprelay, and move `/var/lib/signer-runner` to
   `/var/lib/signer-runner.before-generic` (kept).
3. Azure: `az container delete -g $RG -n signer-1 --yes`. Its state copy
   stays in the container under its signer names.
4. GCP: `CONFIRM=yes platform-gcp/deploy/deploy.sh vm-delete`.

## Step 3: pin the image once

AWS (Terraform in `<terraform-dir>`):

1. Copy this repo's `platform-aws/deploy/main.tf` over the folder's (keep a backup).
   `generic.auto.tfvars`: `pcr0`, `pcr1`, `pcr2` from the build,
   `prev_pcrs` the PCRs of the image before it, if any (so a rollback needs
   no policy change), `mark_bucket = "<S3_BUCKET>"`.
2. `terraform plan`. Expect two changes and no other: `aws_kms_key.enclave`
   (the PCRs, and `kms:Encrypt` for the admin only with exactly
   `purpose=record-creds`) and `aws_s3_bucket_policy.marks[0]` (create: the
   writer may write `marks/*` and `config/*` and read the Object Lock
   configuration). Then apply.
3. Record credentials. The generic runner decrypts them with
   `purpose=record-creds`, so make a blob with that context:
   `aws iam create-access-key --user-name signer-record-writer-node-1` into a
   mode 600 file, turn it into `{"access_key_id": ..., "secret_access_key": ...}`,
   `aws kms encrypt --key-id <AWS_KMS_KEY_ARN> --encryption-context purpose=record-creds --plaintext fileb://creds.json --query CiphertextBlob --output text | base64 -d >writer-credentials.kms`,
   then shred the plaintext. An older access key stays for a rollback until
   the test passes.

Azure (`platform-azure/deploy/deploy.sh`, settings above):

1. `image-push`: the image `generic-ts`; it compares the pushed digest with
   the build.
2. `policy`: one hash for the three signers, written to
   `build/azure/policy.sha256`. It must equal the build record.
3. `key-create 1`: key `signer-gkek-1` with the release policy for that
   hash. `KEY_IMMUTABLE` stays false for the test.
4. `key-role 1`, then `store-role 1` with `SETUP_FILE_1=setups/signer-1.setup`:
   the data role on the container and Reader on its storage account.
   Reader lets the lock check read the account and the container. Wait a
   few minutes for the roles to apply.

GCP (`platform-gcp/deploy/deploy.sh`, settings above):

1. `image-push`: tag `generic`, digest checked against the build.
2. `provider-update`: the WIF condition takes the generic digest only.
3. `bucket-bind $GCS_BUCKET`: adds `roles/storage.legacyBucketReader`
   (the lock check's `storage.buckets.get`) to the two object roles.

None of these steps names a chain or a signer, except the AWS record
credentials (per parent) and the Azure key (per signer index). They are not
repeated for a new chain.

## Step 4: deploy the three signers

AWS:

1. Copy to the parent folder: `runner-aarch64.eif`, the arm64 `hostagent`,
   `forwarder` and `udprelay`, `parent-run.sh`, `allocator.yaml`,
   `signer-2.setup`, with a `SHA256SUMS` checked there.
2. New store: `/var/lib/signer-runner` with `record/writer-credentials.kms`
   (the new blob) and nothing else.
3. First the negative starts of C3 and C9, each in a store of its own
   (`STATE_DIR=/var/lib/signer-runner-neg` and
   `/var/lib/signer-runner-plant`), each with a copy of the record blob.
   `parent-run.sh` starts the proxies, the host agent, the enclave and the
   forwarder every time, so between two starts terminate the enclave and
   stop `vsock-proxy`, `hostagent`, `forwarder` and `udprelay`.
4. `SETUP=./signer-2.setup bash ./parent-run.sh`. The host agent refuses a
   setup the runner would refuse and prints the routes.
5. `nitro-cli describe-enclaves`: PCR0 to PCR2 equal the build.

Azure: `SETUP_FILE_1=setups/signer-1.setup CONFIRM=yes platform-azure/deploy/deploy.sh group-deploy 1`, with the network entry's settings.
It checks the setup (platform, chain, provider, vault, key, subscription)
and that the rendered policy equals the key's release policy.

GCP: `SETUP_FILE=setups/signer-3.setup CONFIRM=yes platform-gcp/deploy/deploy.sh vm-create`,
then `verifier-config` for the attestation settings.

Then `signer-config pin -cluster cluster.json` (C1) and the share import.

## Step 5: checks

| # | Check | How | Expected |
| --- | --- | --- | --- |
| C1 | Setup read, hash in IDENTITY | `signer-config pin`, `identity-check -config cloud.json` | each IDENTITY shows the `setup_sha256` that `signer-config setup` printed; pin writes it into each `cloud.json` |
| C2 | Pins | describe-enclaves PCRs; the group's `ccePolicy` hash (`az container show`, base64 -d, sha256sum); the GCP token's `image_digest` (`identity-check`); a copy of `cloud.json` with one hex digit of `setup_sha256` changed | measurements equal the build; the wrong pin is refused (`identity-check` and `cloud-import` name 8-digit prefixes of both hashes) |
| C3 | Lock self-check | positive: the start logs `mark log ready` after the lock line. Negative: start the `lockneg-N` setup (`slashing_log_min_lock_days = 2`, the stores hold 1 day). AWS before the real start (step 4). Azure and GCP are optional: a deploy before the real one, which may leave a network entry node `lockneg-N` to remove | positive starts; negative stops before the claim with the lock error (AWS `last-exit.txt`, Azure container log, GCP serial or Cloud Logging) |
| C4 | `locked` update, time lock 0 | change `fee_recipients` or `gas_limit_max`: `signer-config draft -group locked`, `show`, `sign` with approvers 1 and 2, `assemble`, `push`, then `status` | pending with the effective time `activate_at` (draft margin 10 minutes), then active: locked version 1 on all three, same hash |
| C5 | Fork-schedule update | `draft -group open` with one more fork far ahead (current epoch plus 100,000, an unused version); push; then a second open update that restores the schedule. Negative: a fork at the next epoch | both accepted and active at once; signing goes on; the near fork is refused by the fork rule (`max_epochs_ahead + 2` epochs) |
| C6 | Rotation | `locked` update with approvers 1, 2 and 4, `k = 2`: signed by 1 and 2 and by every new key (1, 2, 4). Then an update signed by 3 and 1 | `assemble` refuses a rotation without key 4's signature; after activation the approver set hash changes on all three; the update with key 3 is refused |
| C7 | Supersede | `draft -margin 30m` a `locked` update, push; before it activates, push one with a higher version and the active values; while a rotation is pending, push an update signed by the new set only. Optional: add an `allowed_image_measurements` entry | the second replaces the first and starts its own wait; the update of the pending set is refused; the image entry shows an effective time 7 days out (the image minimum), then a supersede cancels it |
| C8 | Restart keeps the effective config | AWS: terminate the enclave and run `parent-run.sh` again with the same setup; Azure: `az container restart`; GCP: `gcloud compute instances reset` | `signer-config status` shows the same setup hash, versions, hashes and approver set as before the restart; signing resumes after the restart floor |
| C9 | Planting attempt on AWS | as the key admin: `aws kms encrypt` with the context `purpose=sealing,signer-setup=<hex>`, with no context, and with `purpose=record-creds` plus one more key; then put 32 random bytes encrypted under `purpose=record-creds` as `sealing/datakey.kms` into a store of its own (`STATE_DIR=/var/lib/signer-runner-plant`, with the record blob) and start a setup there, before step 4's real start | the three encrypt calls are denied (AccessDeniedException); the runner does not use the planted key: its Decrypt under `{purpose: sealing, signer-setup}` fails and it stops (`last-exit.txt`) |
| C10 | Signing | import a few test validators with `cloud-import` (setup pins in `cloud.json`), start their Dirk forks and validator client | attestations included; HEALTH shows the NTS clock |

Keep each check's output as the test's evidence.

## Step 6: after the test

- Keep `prev_pcrs` and any older access key until the rollback window
  closes. Then: `prev_pcrs = null` (Terraform), delete the old access key
  of the writer user, and remove old network entry nodes.
- Stop the generic signers when the test ends: delete the
  Azure group, `vm-delete`, terminate the enclave.

## Rollback

| Cloud | Back to the signers before the test |
| --- | --- |
| AWS | Terminate the generic enclave, move its store aside, move `/var/lib/signer-runner.before-generic` back, run the earlier `parent-run.sh` from its folder. The key policy still holds the earlier PCRs (`prev_pcrs`). |
| Azure | Delete the generic group and deploy the earlier template: the earlier key is untouched, so its release policy still names the earlier CCE hash. |
| GCP | `vm-delete`, then `provider-update` with the earlier digest and `vm-create`. The bucket roles only grew. |
| Dirk forks | They keep their `cloud.json`; start them again. |

The records the generic signers wrote stay locked for a day; nothing needs
them after a rollback.

## Not checked offline

- Reader on the account scope grants `storageAccounts/read` and
  `containers/read` for the lock check (Azure RBAC docs; not run).
- `roles/storage.legacyBucketReader` holds `storage.buckets.get` (GCP role
  reference; not run).
- `SIGNER_SETUP` near the 64 KB setup cap under a wildcard CCE rule, and the
  metadata attribute read inside Confidential Space (design open point 2).
  Typical setups are 1.0 to 1.2 KB; a large setup (8 approvers, 32
  images, 4 CAs) is an optional extra start.
- The generic arm64 EIF on Graviton: only the launch shows that the
  hardware reports the PCRs built here.
