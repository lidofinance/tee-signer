# Upgrade a running cluster

How to move a running signer cluster to a new runner image on the same
setups, mark logs and stores, one signer at a time, without a new share
import.

## When this works

This procedure keeps each signer's sealing key, so the cloud's key rule
must be able to name a second image:

- GCP: always. The WIF condition takes two digests (`PREV_IMAGE_DIGEST`).
- AWS: only with `key_policy_locked = false`. A locked key policy never
  changes.
- Azure: only with `KEY_IMMUTABLE=false`, which non-prod chains alone
  allow. An immutable release policy names one image.

A mainnet signer on AWS or Azure therefore moves as a new signer: a new
setup, key and mark log, and the shares imported again
([slashing-log/docs/durable-state.md](../slashing-log/docs/durable-state.md#a-new-image),
"A new image"). On AWS the new key and parent come from `target/main.tf`
([platform-aws/deploy/README.md](../platform-aws/deploy/README.md#files),
"Files"). The Azure steps are in
[platform-azure/deploy/README.md](../platform-azure/deploy/README.md#a-new-image-for-a-running-signer),
"A new image for a running signer". The old and the new signer then have
separate mark logs, so nothing stops both from signing with the same
share. Before the import, stop the old signer and keep it from starting
again:

- AWS with the service: `sudo systemctl disable --now signer-runner`.
- AWS by hand: `nitro-cli terminate-enclave --all`, then
  `pkill -x 'hostagent|forwarder|udprelay|vsock-proxy'`.
- On AWS `nitro-cli describe-enclaves` must then print no enclave.
- Azure: stop the old group (`az container stop`), and delete it after
  the import.

Import with an EIP-3076 interchange exported from the validator client's
slashing protection after that stop. Without one, the import sets each key's source floor at
the clock's restart floor epoch
([slashing-log/docs/marklog.md](../slashing-log/docs/marklog.md#source-gate),
"Source gate"). The order and the rules below still apply.

## A new setup format

A runner image reads one setup format (`setup_format_version`) and
refuses the others, and the format is part of `setup_hash`. So across a
format change no signer can move on its old setup: each one moves as a
new signer, as above.

Format 5 added `sealing_key_release.kms_key_creation_date` (AWS-KMS-02),
required for Nitro on a prod chain. A new image refuses format 4 setups.

1. Build `signer-admin` and `setup-tool` from the new commit.
2. Nitro on a prod chain: check the key's CloudTrail history
   ([platform-aws/deploy/README.md](../platform-aws/deploy/README.md#setup),
   "Setup", the bullet "The setup pins the key's creation"). Then add
   `sealing_key_release.kms_key_creation_date = <terraform output
   kms_key_creation_date>` to the signer's section. A key that fails the
   check needs a new locked key (`target/main.tf`).
   Nitro off prod: the date is optional. A key made with
   `key_policy_locked = false` fails the CloudTrail check by design, so
   skip the check. Pinning the date still binds the setup to that key.
3. Set `setup_format_version = 5` and run
   `signer-admin setup -out DIR FILE`. It prints each new `setup_sha256`.
4. The approvers read each setup with `setup-tool show FILE` and approve
   its `setup_sha256`.
5. Put the new setups in force one signer at a time, as new signers:
   stop the old signer and start the new one on its setup (above, and
   "Rules" below). No locked update comes first: a locked update applies under
   the old setup_hash, and each new setup lists the new image in its own
   `allowed_image_measurements`.
6. Import the shares again under new import orders. An import order names
   the setup_hash of its target (`target_setup_hash`), so no order signed
   for the old setup works on the new one: `approvals_needed` approvers
   sign a new order for each signer, then `assemble` and `import`
   ([signer-admin/README.md](../signer-admin/README.md#splitting-existing-keys),
   "Splitting existing keys", steps 1 to 4).

## A cloud moves to a new TLS root

The runner trusts a few roots per cloud, listed in
`platform/cloudroots`. If a cloud moves its KMS, STS, Key Vault, MAA or
storage endpoints to a root outside that list, those calls fail at the
TLS handshake: mark writes stop, so the signer stops signing, and it
cannot start again. Clouds announce such moves months ahead. Add the
root's PEM, its SHA-256 and its source to `platform/cloudroots`, and roll
out the new image as below before the move.

For Azure the list is the roots Microsoft's "Azure Certificate Authority
details" page names, except DigiCert Global Root CA (G1): no chain the
runner sees ends there, and the Mozilla list no longer has it. If an Azure
endpoint the runner calls moves to G1, add it.

## Rules

- Keep t of n signers up. Switch one signer at a time, and finish it
  (signing again) before the next one goes down.
- Size splits with n - t >= 2, so one signer can be mid-upgrade while
  another fails and t still sign. With n - t = 1 (3 of 4, 4 of 5) a fault
  during an upgrade stops the keys until one of the two is back. On a prod
  chain the smallest split with both rules is 4 of 6.
- Never run the old and the new image of one signer at the same time.
  They share one mark log; the second writer finds a record it did not
  write and stops.
- Same setup format only: put the locked update that lists the new
  images in force on every signer before the first switch. Across a
  format change the new setups list them ("A new setup format").

## Downtime per signer

An estimate: the stop and start time of the platform (minutes) plus the
restart floor. The floor epoch is the clock epoch at start plus
`max_sign_epochs_ahead_of_clock` plus 1, so 3 epochs when it is 2. A
restarted runner refuses votes with a target up to the floor epoch or a
source below it, so its first vote also waits until the chain justifies
the floor epoch. On a chain with 12 s slots and 32 slots per epoch that is
about 20 to 25 minutes, and longer while the chain does not justify. On
Azure and GCP the runner logs `restart from the mark log` once, with
`clock_epoch` and `floor_epoch`, and `runner started` shows
`floor_margin`. A log that still holds a source gate logs `source gate
dropped` at a start where its source has reached the gate's floor. An AWS
enclave outside debug mode has no console, so there count it from the
start time.

A single-node signer (1 of 1) has no other signer to cover this time:
it misses its duties for the whole downtime of every restart, upgrades
included.

## Order

### 1. Build, push and publish the measurements

Build the images from a tagged commit and publish their measurements:
PCR0 to PCR2 (AWS), the CCE policy hash (Azure), the image digest (GCP).
A second build from the same commit must give the same values. Each
platform README says how: AWS
["PCRs of the image"](../platform-aws/deploy/README.md#pcrs-of-the-image),
Azure ["Steps"](../platform-azure/deploy/README.md#steps)
(`build-image.sh`, then `deploy.sh policy N`), GCP
["The image digest"](../platform-gcp/deploy/README.md#the-image-digest).

On Azure and GCP set a new `IMAGE_TAG` before `build-image.sh`, then run
`deploy.sh image-push` with it, so the running image keeps its tag in the
registry. On AWS the EIF goes to the parent instead (see "AWS").

### 2. Upgrade the client tools first

Check the merged pull requests since your current build for wire or
attestation changes. When there is one, rebuild `signer-admin`, the
gateway and any monitoring built on `attestation-verify/runnerclient`
from the new commit before you switch a runner. Example: the TLS chain mark grew from 4 to 36
bytes (#135). Clients built before it refuse a new runner ("chain mark
that does not read as 4 bytes"); clients built after it read both.

### 3. Locked update that lists both images

Without it the new image keeps its shares sealed: the runner checks its
own image against `allowed_image_measurements` in force before it unseals
anything ([signer-protocol/docs/protocol.md](../signer-protocol/docs/protocol.md#image-check),
"Image check").

You need:

- `approvals_needed` approver keys, as key files or `openpgp:KEYGRIP`.
- `cluster.json` with every signer. Each signer's `cloud.json` names an
  admin client certificate: `signer-admin probe -cluster cluster.json`
  passes for each.
- The `updates` folder of `cluster.json` with the signed file of the
  locked update in force, when its version is above 0. `push` keeps a
  copy there.

Then:

1. Write FILE: every key of the locked group as the setup file has it,
   with the changes of later locked updates, not only the image lines.
   List two `allowed_image_measurements` lines per kind, old and new:
   `allowed_image_measurements = gcp 0x...` and so on.
2. `signer-admin draft -cluster cluster.json -group locked -out update.bin FILE`
   reads the active values from every member, prints the diff and
   `activate_at`. Pick a `-margin` that covers the time to sign and push
   (steps 3 to 6): `push` refuses an update whose `activate_at` is more
   than 5 minutes earlier than now plus the wait.
3. `signer-admin show update.bin`: each approver checks the values and
   notes the sha256 on the `signing message, direct form:` line, not
   `body_sha256`.
4. Each approver: `signer-admin sign -key KEY -expect-sha256 HEX update.bin`.
5. `signer-admin assemble -out update.signed update.bin SIG...`
6. `signer-admin push -cluster cluster.json update.signed`
7. Wait for `activate_at`. `signer-admin status -cluster cluster.json`
   shows it as `pending=locked:vN/...@TIME`. It is now plus the wait plus
   the `draft -margin` (default 10 minutes). For a new image the wait is
   at least the images minimum (7 days on a prod chain, 7 minutes off
   prod). On a prod chain the change delay never drops below the build's
   default time lock.
8. `signer-admin status -cluster cluster.json` shows `locked=vN/...` with
   the new version and no `pending=` on every signer.

`draft` refuses a locked update that lists no image of a signer's
platform (#132). It does not check the image a signer runs now, so keep
the old measurements listed until every signer has switched.

### 4. Each signer, one at a time

1. Key rule switch: let the old and the new image get the key. Without
   it the new image gets no sealing key.
2. List pins: a signing client that takes a list of measurements gets
   old and new now.
3. Check that the other signers are up and signing (step 8 says what to
   look for).
4. Stop the old runner. Downtime starts.
5. Start the new image on the same setup and store.
6. Check the start (see the platform section).
7. One-value pins: `runnerclient` (`signer-admin`, the gateway, other
   tools on it) pins one value per signer: `nitro_pcrs`,
   `cce_policy_sha256` or `gcp_image_digest`. Set the new value now, in
   every place that holds it, on every machine:
   - `signer-admin` and the tools that read its connection files: every
     copy of that signer's `cloud.json`. The tools check the pin: the
     new image must be on the approved list, so the signed file of the
     step 3 update must be in the `updates` folder, and 5 minutes must
     have passed since its `activate_at` (`push` makes the update come
     into force by then). They refuse a pin that no list names, and an
     image that a later update dropped once that update's `activate_at`
     has passed
     ([signer-admin/README.md](../signer-admin/README.md#image-pin),
     "Image pin").
   - The gateway: `signers.nodes[].attestation` of that signer in
     `gateway.yml`. The gateway does not read `cloud.json`, and reads
     `gateway.yml` at its start only, so start it again
     ([gateway/README.md](../gateway/README.md#configuration),
     "Configuration").

   Until you do, that client refuses the signer with
   `measurement mismatch`.
8. Check the signer:
   - `signer-admin status -cluster cluster.json -signers NAME` prints
     `NAME setup=... locked=vN/...`: the signer's setup hash (first 8
     hex digits), the locked version of step 3, no `pending=`.
   - `signer-admin probe -cluster cluster.json -signers NAME` prints
     `admin: the role check passed (BAD_REQUEST)`. BAD_REQUEST is the
     expected answer to the empty probe.
   - After the restart floor it signs: HEALTH `ready` is true,
     `validators` equals the number of keys, and `stats.signatures` and
     the mark log's `record` rise.
     `signer-admin/cmd/proof-check -once` writes these to its `-out` file.
9. Key rule final: the new image only. This closes the way back to the
   old image.
10. List pins: the new value only.

Then the next signer.

### 5. Later: drop the old images

Optional, after every key rule is final: a second locked update without
the old images, signed and pushed as in step 3.

## Platforms

### AWS

[platform-aws/deploy/README.md](../platform-aws/deploy/README.md)

- Key rule switch: in Terraform set `pcr0..pcr2` to the new image and
  `prev_pcrs` to the old one. The plan must change the key policy only.
  Final: `prev_pcrs = null`.
- Before the stop, put the new EIF, `hostagent`, `forwarder`, `udprelay`
  and the files of `platform-aws/deploy/` in a new folder on the parent.
  `nitro-cli describe-eif` on that EIF must print the published PCR0 to
  PCR2. Do not copy them to `/opt/signer-runner` while the service runs:
  the service restarts on any failure and would start the new EIF before
  step 4.4, and a running program cannot be overwritten.
- Stop (4.4): `sudo systemctl stop signer-runner`. Then copy the new files
  into `/opt/signer-runner`.
- Start (4.5): `sudo systemctl start signer-runner`, with the same `SETUP`
  and `STATE_DIR` in `/etc/signer-runner/parent.env`. A parent that still
  runs `parent-run.sh` by hand moves to the service in the same downtime
  (README, ["Restarts"](../platform-aws/deploy/README.md#restarts)).
- Check the start: the enclave sends no log lines to the parent, so look
  for `parent-service: running` in `journalctl -u signer-runner`, the new
  PCRs in `nitro-cli describe-enclaves`, and no new line in
  `$STATE_DIR/last-exit.txt` (`STATE_DIR` from `parent.env`). Then the
  checks of step 4.8.

### Azure

[platform-azure/deploy/README.md](../platform-azure/deploy/README.md)

The signer's build folder is `$OUT/<group name>` (`deploy.sh plan` prints
`$OUT`). `key-create` left `key.policy.sha256` and `skr-policy.json`
there with the hash of the image it was run for. No later step updates
them, so build each key rule from the live release policy.

- Key rule switch: read the live policy, check that it names the running
  hash alone, add a second `anyOf` entry with the new hash and set it on
  the key:

  ```sh
  key=<key name>
  hosts='[.anyOf[].allOf[] | select(.claim == "x-ms-sevsnpvm-hostdata") | .equals] | join(" ")'
  az keyvault key show --vault-name "$VAULT" -n "$key" -o json | jq -r .releasePolicy.encodedPolicy >live.json
  jq -r "$hosts" live.json   # the running hash alone
  jq --arg h <new hash> '.anyOf += [.anyOf[0]
    | .allOf |= map(if .claim == "x-ms-sevsnpvm-hostdata" then .equals = $h else . end)]' \
    live.json >switch.json
  az keyvault key set-attributes --vault-name "$VAULT" -n "$key" --policy @switch.json
  ```

  Then `az keyvault key show` must give both hashes.
- Key rule final (4.9): read the live policy again and keep the new hash
  alone, in its own file:

  ```sh
  az keyvault key show --vault-name "$VAULT" -n "$key" -o json | jq -r .releasePolicy.encodedPolicy >live.json
  jq --arg h <new hash> '.anyOf |= map(select(any(.allOf[];
    .claim == "x-ms-sevsnpvm-hostdata" and .equals == $h)))' live.json >final.json
  jq -r "$hosts" final.json   # the new hash alone
  az keyvault key set-attributes --vault-name "$VAULT" -n "$key" --policy @final.json
  ```

- Stop and start: `group-deploy` reads `key.policy.sha256` first and
  ignores `EXPECT_POLICY_SHA256` while that file exists, so move it aside.
  Then run `EXPECT_POLICY_SHA256=<new hash> deploy.sh group-deploy N` with
  the new `runner.digest` from step 1 and the same settings as the running
  group's deploy: `CHAIN`, `RG`, `VAULT`, `ACR_NAME`, `SETUP_FILE_N`,
  `GROUP_NAME_N`, `KEY_NAME_N` or `KEY_NAME_PREFIX`, `IDENTITY_NAME_N`,
  `LOCATION_N`, `MAA_ENDPOINT_N`, `SUBNET_ID_N`, `LOG_WORKSPACE_ID` and
  `LOG_WORKSPACE_KEY_FILE`, `NETWORK`, `STDIO` and `SUBSCRIPTION_ID`, each
  where the first deploy set it. `group-deploy` rebuilds the whole group
  from these: a missing `SUBNET_ID_N` or `LOG_WORKSPACE_ID` drops the
  private IP or the log workspace, and another identity gets no key. ACI
  restarts the group in place; the private IP may stay the same, but
  check it and update any record that points to it.
- Check the start: `az container logs -g "$RG" -n <group> --container-name runner`
  shows `image check: this image is on allowed_image_measurements in force`,
  `runner started` with the expected `config_sha256` (the setup hash), and
  `mark log ready` with `shares_stored` equal to the number of keys.
- Never deploy a second group with the same setup while the first runs.

### GCP

[platform-gcp/deploy/README.md](../platform-gcp/deploy/README.md)

- Key rule switch: `PREV_IMAGE_DIGEST=<running digest> deploy.sh provider-update`
  with the new image. Final: `deploy.sh provider-update` without
  `PREV_IMAGE_DIGEST`.
- Stop and start on the same VM, which keeps its disk and internal IP.
  On its `Image` line `deploy.sh plan` prints the new reference, REPO@DIGEST:

  ```sh
  gcloud compute instances stop "$VM" --zone="$ZONE" --project="$PROJECT_ID"
  gcloud compute instances add-metadata "$VM" --zone="$ZONE" --project="$PROJECT_ID" \
    --metadata='^~^tee-image-reference=<REPO@DIGEST>~tee-restart-policy=OnFailure'
  gcloud compute instances start "$VM" --zone="$ZONE" --project="$PROJECT_ID"
  ```

  A VM made by an older script may have another `tee-restart-policy`; this
  sets it to `OnFailure` too. The README's route after a rebuild
  (`vm-delete`, `vm-create`) makes a new VM. It keeps the shares only
  when the setup has a state copy; without one they need a new import.
- Check the start: `deploy.sh logs` shows the same lines as on Azure.
