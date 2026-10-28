# GCP Confidential Space backend

Each signer is one Confidential Space VM. The workload image holds the
runner and its fixed flags, and the WIF provider pins the image's digest, so
only that image gets the signer's Cloud KMS key. `deploy.sh` creates the
project resources one step at a time.

## Setup

The image is the same for every signer of every operator and every project:
the runner and its fixed flags. The signer's values are in its setup: chain
config, client CA, WIF provider, KMS key, identity audience
(`sealing_key_release`), mark log (required) and state copy buckets, signer
name, and optional network entry names. `signer-admin/cmd/setup-tool encode`
makes the binary setup from a human `key = value` file
(`governance/setupwire/testdata/setup-gcp.conf` is an example).

```sh
platform-gcp/deploy/build-image.sh                           # the generic image
setup-tool encode signer-3.conf signer-3.bin
CHAIN=<chain> CHAIN_JSON=chain.json SETUP_FILE=signer-3.bin CONFIRM=yes platform-gcp/deploy/deploy.sh vm-create
```

- `vm-create` checks `SETUP_FILE` with the runner's decoder: a GCP setup, of
  chain `CHAIN`, naming this project's WIF provider, KMS key and identity
  audience, and `MARK_STORE`'s bucket when that is set. It puts the setup,
  base64, into the instance metadata attribute `signer-setup`. Not
  `tee-env-*`: those values are copied into every attestation token.
- The runner reads the attribute from the metadata server first, refuses a
  setup for another platform and puts setup_hash and the mark log's config
  state in IDENTITY, ATTEST and HEALTH (IDENTITY, `signer-protocol/docs/protocol.md`).
- Every Cloud KMS call carries setup_hash in its additional authenticated
  data: the sealing data key under `signer-runner gcp sealing v1` and
  setup_hash, the mark log and state copy keys under
  `signer-runner gcp key wrap v1`, setup_hash and the caller's AAD (all
  length-prefixed, `governance/setupwire` contexts). A runner started with
  another setup does not decrypt this signer's data key (it stops) and opens
  none of its keys.
- Who can plant a data key: whoever may encrypt with the key. `deploy.sh`
  grants `cryptoKeyEncrypterDecrypter` on the key to the WIF principal set
  alone, whose provider pins the image; the service account gets no KMS
  role (`platform-gcp/gcp/deploy_test.go` checks the script). The AAD is
  not secret, so a principal that holds the role anyway (an admin who
  grants it to itself, a binding inherited from the project or the
  organization) can still plant one, and the runner cannot see such
  bindings. GCP is outside the admin-proof goal.
- `build-image.sh` refuses `CHAIN`, `CHAIN_JSON` and `CLIENT_CA`, and
  `render_dockerfile` refuses `STATE_STORE` and `MARK_SIGNER`: those are
  setup fields.

## Hardware: default and production

`HARDWARE=amd-sev` is the default (`n2d-highcpu-2`, hwmodel `GCP_AMD_SEV`),
for tests. Azure runs on AMD SEV-SNP, so a GCP signer on AMD puts two of the
three shares on one chip family.

Production must run on Intel TDX (`HARDWARE=intel-tdx`, `c3-highcpu-4`,
hwmodel `GCP_INTEL_TDX`), so that no chip family holds two of the three
shares. The verifier accepts every hwmodel on its list, so production lists
`GCP_INTEL_TDX` only. Google's supported-configurations page names
`c3-standard-*` for TDX and does not name `c3-highcpu-*`. Check that before a
production deploy, or set `MACHINE`. The settings sit in `common.sh`, in the
WIF condition that `deploy.sh wif-create` writes, and in the file that
`deploy.sh verifier-config` writes.

| Setting | `amd-sev` (default, tests) | `intel-tdx` (production) |
| --- | --- | --- |
| Hardware | AMD SEV, Milan | Intel TDX |
| Machine | `n2d-highcpu-2` (2 vCPU, 2 GiB) | `c3-highcpu-4` (see above) |
| `--confidential-compute-type` | `SEV` | `TDX` |
| Maintenance policy | `MIGRATE` (live migration, N2D with SEV only) | `TERMINATE` |
| `gcp_hwmodels` | `["GCP_AMD_SEV"]` | `["GCP_INTEL_TDX"]` |
| Image | family `confidential-space` of project `confidential-space-images`, the production image, never the debug family | same |

2 GiB of RAM holds the Confidential Space OS, the launcher and the runner.
Google's examples use `n2d-standard-2` (8 GiB). If the VM fails to start or
the launcher is killed, set `MACHINE=n2d-standard-2`.
`--min-cpu-platform="AMD Milan"` for SEV comes from Google's create page, and
the supported-configurations page names Milan for N2D with SEV.

## Files

| File | What |
| --- | --- |
| `Dockerfile` | workload image, `FROM scratch`: the runner (mode 0555, `COPY --chmod`), launch policy labels, `EXPOSE 7100/tcp`, all runner flags fixed |
| `common.sh` | every name (project, key, service account, WIF pool and provider, network, VM) and the hardware profile. The image and `deploy.sh` read the same values |
| `build-image.sh` | builds the image twice from the GCP release runner (`runner-gcp`) and checks that both digests match. Pushes nothing. Writes `build/gcp/runner.digest` |
| `deploy.sh` | `plan` prints every step with its exact commands. Each step runs only with `CONFIRM=yes`. Also `preflight` (read-only), `verifier-config`, `logs` |

## What the image bakes in

`build-image.sh` reads them back from the built image
(`build/gcp/runner.entrypoint` and `runner.labels.json`):

- Files: the GCP release runner (`/runner`, mode 0555, from
  `build/x86_64/bin/runner-gcp`). The release runner has no plaintext
  import (`build-image.sh` refuses a binary that holds `-allow-import`). The
  image holds no chain config and no client CA.
- Flags: `-platform gcp`, `-setup platform`, `-listen tcp:0.0.0.0:7100`,
  `-state-dir /var/lib/signer`, `-restart-floor=true`,
  `-persist-watermarks=false`, `-record none`, `-nts-clock` (the NTS clock,
  runner built with the tag nts, `trusted-time/docs/nts.md`) with the
  coarse-check URLs `cloudkms.googleapis.com`, `sts.googleapis.com` and
  `www.cloudflare.com` (`-nts-coarse-urls`), `-log-json`. The clock reaches
  the four NTS operators directly: TCP 4460 and UDP 123 and 4123 out through
  the VM's external address. The custom VPC has no egress rule of its own,
  so the implied allow-all egress rule applies (Google, "VPC firewall
  rules", implied rules).
- Launch policy labels: `allow_cmd_override=false`, `allow_capabilities=false`,
  `allow_cgroups=false`, `monitoring_memory_allow=never`,
  `log_redirect=always`. There is no `allow_env_override` and no
  `allow_mount_destinations`. `tee-mount` offers tmpfs only
  ([deploy workloads](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads)),
  and the runner keeps its store on the container's own file system.
  `log_redirect=always` lets the operator read the runner's log in Cloud
  Logging. Use `never` for production shares.
- `EXPOSE 7100/tcp`. The launcher opens only the ports the image declares.
  Without it the launcher logs `Exposed Ports: map[]` and every connection to
  7100 times out.

The setup's `sealing_key_release` names the GCP resources, all from
`common.sh`. `vm-create` refuses a setup whose values differ:

| Setup field | Value |
| --- | --- |
| `wif_provider` | `//iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/signer-pool/providers/signer-attestation` |
| `kms_key` | `projects/<gcp-project>/locations/europe-west4/keyRings/signer/cryptoKeys/sealing` |
| `attest_audience` | `signer-runner-identity` |

`PROJECT_ID`, `PROJECT_NUMBER`, `REGION` and `ZONE` (default
`europe-west4-a`) set the project and location. The mark log and the state
copy (`slashing-log/docs/durable-state.md`) are the setup's
`slashing_log_store` and `encrypted_state_store`.

## The image digest

```sh
platform-gcp/deploy/build-image.sh
```

The build takes no chain and no CA. `build-image.sh` builds twice per run and
compares the digests. The context file gets an explicit mode (`install -m`,
`COPY --chmod`), as in `platform-azure/deploy`, so the digest does not depend
on the builder's umask. A change to the runner or the flags changes the
digest, and then `deploy.sh provider-update` points the WIF provider at the
new one. A new chain or signer is a new setup only.

Started outside Confidential Space with its exact entrypoint, the image
stops at the first launcher call (`dial unix
/run/container_launcher/teeserver.sock`). That is the right failure there.

## Network entry

The network entry is how the Dirk forks reach port 7100. It is not trusted and
can be replaced. Security comes from mutual TLS 1.3, with the runner's TLS
key bound to its attested identity, which the client checks on every
connection. Only port 7100 may listen in the TEE.

The default entry (`NETWORK_ENTRY=public`) is the VM's external IP and a
firewall rule that opens TCP 7100 from the operator's public IP only.

- (a) An overlay network daemon in the workload image. Not used.
  Confidential Space runs one workload container, so the daemon and the
  runner would share one container, one process namespace and one uid, and a
  flaw in the daemon would read the runner's memory. The image also needs a
  second binary and a supervisor, and the daemon opens its own sockets. The
  credential is the other problem (see below).
- (b) The default. External IP and firewall. No extra code in the image and
  nothing new is measured. The runner listens on `0.0.0.0:7100`. The VM
  needs outbound internet for KMS, STS, the registry and the clock, so it
  has an external IP anyway, and the entry adds no cost beyond that.

| | (a) overlay daemon in the image | (b) external IP and firewall |
| --- | --- | --- |
| What listens in the TEE | 7100, and the daemon's own sockets | 7100 only |
| What is measured | runner, overlay binaries, supervisor | runner only |
| Secret that is not measured | the overlay credential (see below) | none |
| Extra cost | none for the entry, but the VM still needs outbound access | none beyond the address the VM needs anyway |

How Confidential Space passes variables, and why (a) has no safe place for the
credential. The operator sets a variable with the metadata key `tee-env-NAME`.
The image must allow it with the label
`tee.launch_policy.allow_env_override=NAME`, a comma-separated list, so the
operator can be allowed exactly one variable, the credential
([launch policies](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies)).
The metadata value is not part of the image digest. But the token claims page
says that `submods.container.env` holds "the environment variables and their
values that have been explicitly passed to the container"
([token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)).
So the credential would be readable in the attestation token that the runner
hands to every client that asks for `IDENTITY`, as well as in the VM
metadata. The other route is Secret Manager, read by the runner after
attestation. That is new runner code and one more secret store. It is the
reason this image has no `allow_env_override`.

What (b) is made of (`deploy.sh network-create`, `address-reserve`,
`firewall-create`, `vm-create`):

- A dedicated custom VPC `signer-net`. A custom VPC has no allow rule, so the
  `default` network's ssh, rdp, icmp and internal rules do not apply, and
  port 22 is closed.
- A static regional address `signer-node-1-ip`, so the Dirk fork's `address`
  survives a VM restart.
- One ingress rule `signer-allow-7100`: TCP 7100 from `OPERATOR_IP/32` to VMs
  tagged `signer-node`.

The firewall limits exposure and denial of service. It is not what protects
the runner. A changed public IP of the operator needs
`gcloud compute firewall-rules update signer-allow-7100 --source-ranges=...`,
and the runner's TLS stack and the client certificate check are the only gate
for an address inside the allowed range. The runner drops a peer that does not
finish the handshake after 10 seconds. The launcher runs the workload on the
VM's own network, so the VM's other listeners, if any, share the NIC with
port 7100. The custom VPC filters them.

### Other network entries

A build overlay (`SIGNER_BUILD_OVERLAY_DIR`) can add other entries through
`NETWORK_ENTRY` and a hook in `common.sh`. Such an entry must keep the
runner on `127.0.0.1:7100` behind it, keep its credential out of the token's
env claim, and keep its node state in the runner's sealed store if it has
any (`slashing-log/docs/durable-state.md`, "The network entry's node
state"). `firewall-delete` removes the TCP 7100 rule when another entry
replaces it.

### Outbound internet

The signer needs outbound internet: the network entry (its coordination
service and direct paths, if it has any), the NTS servers (TCP 4460, UDP 123
and 4123) and the coarse HTTPS time sources. Google's own services (Cloud
KMS, STS, Cloud Storage, Artifact Registry) also work without a public
address, through Private Google Access on the subnet. The operator picks one
of these when deploying. The signer's safety does not depend on the choice,
because the network is untrusted:

| Option | Cost (list prices, estimate) | Inbound reach |
| --- | --- | --- |
| External IP on the VM (`deploy.sh` default) | about USD 3.65 a month for the address | only what the VPC firewall allows |
| No external IP, Cloud NAT for egress, Private Google Access on | about USD 4.70 a month (NAT gateway and its address) | none: the VM has no public address. An overlay entry still works, with fewer direct paths |

A VM with neither an external IP nor Cloud NAT reaches no NTS server and no
network entry, so the signer refuses to start (no trusted time). Choose NAT
where a VM with a public address is not wanted.

## Deploy plan

`platform-gcp/deploy/deploy.sh plan` prints this with the exact `gcloud`
commands. It calls no `gcloud`, `docker` or network command.
`deploy.sh preflight` is the read-only check: the project number, the APIs
the setup needs, that every name below is free, the zone's CPU platform and
machine type, quota, and the newest Confidential Space image.

0. Local: `build-image.sh`.
1. `services-enable`: APIs `compute`, `cloudkms`, `artifactregistry`,
   `confidentialcomputing`, `iam`, `iamcredentials`, `sts`, `logging`.
2. `network-create`: VPC `signer-net`, subnet `signer-subnet` (`10.10.0.0/24`,
   `europe-west4`).
3. `address-reserve`: `signer-node-1-ip`.
4. `firewall-create`: `signer-allow-7100` (needs `OPERATOR_IP`).
5. `registry-create`: Artifact Registry Docker repository `signer`.
6. `image-push`: tag `IMAGE_TAG` (default `poc`), then compare the registry's
   digest with `runner.digest`. The login token goes through stdin into a
   temporary Docker config, so `~/.docker` stays as it is.
7. `kms-create`: key ring `signer`, HSM key `sealing` (purpose `encryption`).
   Key rings and keys cannot be deleted. Only key versions can be destroyed.
8. `sa-create`: `signer-workload`.
9. `sa-bindings`: the service account gets `artifactregistry.reader` on the
   repository only, and at project level
   `confidentialcomputing.workloadUser` (attestation tokens) and
   `logging.logWriter`. Google lists these for a workload service account
   ([deploy workloads](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads)).
   It gets no KMS role and no bucket role.
10. `wif-create`: pool `signer-pool`, provider `signer-attestation` (issuer
    `https://confidentialcomputing.googleapis.com`, audience
    `https://sts.googleapis.com` only), and
    `cloudkms.cryptoKeyEncrypterDecrypter` on the key for the pool's
    principal set `principalSet://iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/signer-pool/*`.
    The attribute condition holds all of:
    `swname == 'CONFIDENTIAL_SPACE'`, `'STABLE'` in `support_attributes`,
    `dbgstat == 'disabled-since-boot'`, `hwmodel == 'GCP_AMD_SEV'` (or
    `GCP_INTEL_TDX`), `image_digest == '<digest>'`, and the service account
    in `google_service_accounts`.
11. `bucket-bind B`: `storage.objectCreator`, `storage.objectViewer` and
    `storage.legacyBucketReader` on the mark log's bucket (which also holds
    the state copy) for the same principal set. The last one carries
    `storage.buckets.get`, which the runner's lock check needs to read the
    bucket's retention policy at every start.
12. `vm-create`: `signer-node-1` in `europe-west4-a`, `n2d-highcpu-2`,
    `--confidential-compute-type=SEV`, `--min-cpu-platform="AMD Milan"`,
    `--maintenance-policy=MIGRATE`, `--shielded-secure-boot`, image family
    `confidential-space`, 20 GB `pd-balanced` boot disk, the service account,
    the address and the tag, and the metadata `tee-image-reference` (the image
    by digest), `tee-restart-policy=OnFailure`,
    `tee-container-log-redirect=true` and `signer-setup`. The metadata holds
    no secret.

Role bindings take a few minutes to apply. A VM created right after
`sa-bindings` can fail its first boot with `PermissionDenied` for
`logging.logEntries.create` and `confidentialcomputing.locations.list`.
Wait for IAM before `vm-create`, or reset the VM.

After a rebuild: `build-image.sh`, `image-push`, `provider-update`,
`vm-delete`, `vm-create`. The VM's state goes with it. Without a state copy
the runner makes a new data key and the shares need a new import. With one,
the new VM restores the wrapped data key and the sealed shares from the
bucket (the WIF condition moves to the new digest, the KMS key stays, so the
new image opens the old snapshots and the old log). `teardown` deletes
everything except the key ring and key. A deleted WIF pool and provider keep
their names for 30 days.

A second signer next to a running one, for example a handover target, sets
`VM`, `ADDRESS_NAME`, `KMS_KEY`, `WIF_POOL` and `WIF_PROVIDER`: its own VM,
address, key (`kms-key-create`), pool and provider (`wif-create`, which then
pins the target's digest alone and binds the new key to the new pool), and
`bucket-bind` for the new pool. It needs its own pool because the key grants
its role to a pool's principal set, and every identity that passes any
provider of the pool would get the key. The project's network, firewall
rules, registry, key ring and service account stay shared, so `teardown`
refuses with these set and lists the target's own deletes instead.

## Key release through the principal set

The KMS key and the buckets grant their roles to the WIF pool's principal
set, and to nothing else in the project. Only a token that passes the
provider's attribute condition becomes a member of that set: an attestation
token from the Confidential Space attestation service for the pinned image
digest, hardware model, `swname`, `dbgstat` and support attributes. The
runner calls KMS and Cloud Storage with the federated token from STS itself
(`platform-gcp/gcp`, `KMS.accessToken` without `service_account`).

The service account `signer-workload` only runs the VM, and its own token
opens nothing. If the roles sat on the account, anyone who may attach it to
a VM (an unmeasured one, no Confidential Space) would get its token from the
metadata server, and with it key release, and the WIF condition would never
run.

From Google's documentation:

- Cloud KMS and Cloud Storage both take federated principals directly
  ("Identity federation: products and limitations": Cloud KMS GA, no known
  limitations; Cloud Storage GA, only on buckets with uniform bucket-level
  access, so the mark log bucket must have it).
- Google's own Confidential Space tutorial binds
  `roles/cloudkms.cryptoKeyDecrypter` to a principal set of the pool
  (`.../attribute.image_digest/DIGEST`) and has the workload call KMS with
  the federated credential, no impersonation.

The tutorial narrows the set to one digest (`attribute.image_digest`, with
an attribute mapping on the provider). The setup here grants the whole pool
and relies on the provider's condition, so a rebuild changes one place
(`provider-update`). The narrower set is a second lock on the digest; it
needs the KMS and bucket bindings changed on every rebuild. Keep the pool to
one provider either way: a provider added to the pool joins the set.
Project-level roles of an admin (Owner, Cloud KMS Admin) may include encrypt
and decrypt on the key, and an admin can grant them anyway
(`slashing-log/docs/marklog.md`, "What it does not cover").

## Token claims

A Confidential Space token for this image carries `hwmodel` (`GCP_AMD_SEV`
or `GCP_INTEL_TDX`), `swname` `CONFIDENTIAL_SPACE`, `support_attributes`
(for example `[LATEST, STABLE, USABLE]`), `dbgstat` `disabled-since-boot`,
`secboot` true, `google_service_accounts` with the workload account, and the
issuer `https://confidentialcomputing.googleapis.com`. The provider
condition and the verifier check these. The token also carries the
container arguments and the names of the environment variables
(`submods.container.args`, `submods.container.env`).

## Cost estimate

List prices from the Cloud Billing Catalog API, region `europe-west4`, 730
hours a month. Rows marked "estimate" are not a bill. The Confidential
Computing SKUs are global, and the table assumes that N2D with SEV uses the
plain "Confidential Computing Instance Core" and "Instance RAM" SKUs (the
SEV-SNP and TDX SKUs are separate). The catalog lists the external address
with a 0 USD tier for the first 744 hours a month. The table uses the full
0.005 USD an hour.

| Item | Price | Per hour |
| --- | --- | --- |
| n2d core, 2 | 0.030278 USD per core-hour | 0.060556 |
| n2d RAM, 2 GiB | 0.004058 USD per GiB-hour | 0.008116 |
| Confidential Computing core, 2 (estimate) | 0.005479 USD per core-hour | 0.010958 |
| Confidential Computing RAM, 2 GiB (estimate) | 0.0007342 USD per GiB-hour | 0.001468 |
| External IPv4 address on a standard VM (estimate) | 0.005 USD per hour | 0.005000 |
| Boot disk, 20 GiB `pd-balanced` | 0.11 USD per GiB-month | 0.003014 |
| KMS HSM key version, 1 | 1.00 USD per month | 0.001370 |
| KMS HSM operations (a few per start) | 0.000003 USD each | about 0 |
| Artifact Registry storage (one small image) | 0.10 USD per GiB-month above 0.5 GiB | 0 |
| Egress and Cloud Logging | small | about 0 |
| Total while the VM runs | | about 0.090 USD per hour, 2.17 USD per day |

- The VM alone (core, RAM and the Confidential Computing premium) is 0.081 USD
  an hour, 1.95 USD a day.
- A deleted VM leaves the reserved address (0.011 USD an hour while unused,
  catalog "Static Ip Charge") and the KMS key (1 USD a month). `teardown`
  removes the address. The key stays.
- A stopped VM still bills the disk and the reserved address.
- An overlay entry (a) would cost the same: the VM needs outbound access
  either way. Cloud NAT instead of an external address is not cheaper for one VM.

## Mark log (Bucket Lock)

The setup's `slashing_log_store` keeps the runner's mark in a Cloud Storage
bucket with a locked retention policy (`slashing-log/docs/marklog.md`). The
client uses the workload's federated token (the same STS exchange as KMS, so
the WIF provider's condition on the image digest gates it); the principal
set needs `storage.objects.create`, `storage.objects.get` and
`storage.objects.list` on that bucket only, and `storage.buckets.get` for
the lock check (`deploy.sh bucket-bind`). Object versioning stays off (Cloud
Storage does not allow it next to a retention policy); the create is
`ifGenerationMatch=0`. The setup's `encrypted_state_store` (the same bucket)
keeps the durable state copy under `state/` with the same client and roles
(`slashing-log/docs/durable-state.md`). `MARK_STORE=gcs:bucket=B`
(`common.sh`) names the bucket for `bucket-bind` and the setup check.

## Verifier settings

For the Dirk fork's cloud adapter, `cloud-import` and `share-import`
(`attestation-verify/runnerclient`, verifier `gcp-cs`). `deploy.sh
verifier-config` writes them to `$GCP_TEST_DIR/gcp-signer.json` (directory
700, file 600, no secrets; some chains add a suffix to the file name). With `HARDWARE=amd-sev` it writes a `NOTE.txt` next to it
that says the file is for AMD SEV only. It needs `GCP_TEST_DIR`, a private
directory outside the repo, and `CLIENT_CERT` and `CLIENT_KEY`, the Dirk
fork's client certificate and key; it stops if one is missing.

| Setting | Value |
| --- | --- |
| `verifier` | `gcp-cs` |
| `gcp_image_digest` | the digest in `build/gcp/runner.digest` |
| `gcp_audience` | `signer-runner-identity` |
| `gcp_hwmodels` | `["GCP_AMD_SEV"]` with `HARDWARE=amd-sev`. Production: `["GCP_INTEL_TDX"]` only |
| `gcp_service_account` | `signer-workload@<gcp-project>.iam.gserviceaccount.com` |
| `gcp_issuer` | not set: the default `https://confidentialcomputing.googleapis.com` |
| `address` | `tcp:<signer-node-1-ip>:7100`. The address exists after `address-reserve`. Until then the file holds `tcp:SIGNER_IP:7100` (or set `SIGNER_ADDRESS`) |
| `client_cert`, `client_key` | the Dirk fork's client certificate and key from the setup's client CA |

`runnerclient.Connection.New()` accepts the file. The command also prints the
`share-import` flags: `-verifier gcp-cs -gcp-image-digest ... -gcp-audience
signer-runner-identity -gcp-hwmodel GCP_AMD_SEV -gcp-service-account ...`.

## Checking a running signer

`signer-admin/cmd/identity-check` connects the way the Dirk fork's cloud
adapter does: mutual TLS with a client certificate, IDENTITY with a fresh
nonce on every connection, and the `gcp-cs` verifier of the config. It sends
nothing but IDENTITY and imports no share.

```sh
cd signer-admin && go build -o identity-check ./cmd/identity-check
./identity-check -config <secrets-dir>/gcp-signer.json -address tcp:<signer-node-1-ip>:7100
./identity-check -config ... -address ... -gcp-image-digest sha256:<another digest>    # must be refused
```

It prints `accepted` or `REFUSED` with the reason for each run, and on the
first accepted run the claims of the Confidential Space token (names and
values; the values of the container's env claims are masked). Compare them
with the WIF condition and with what `attestation-verify/gcp.go` checks. A
wrong digest is refused with `measurement mismatch: image_digest`.

`deploy.sh logs` reads the VM's serial console and Cloud Logging (it
assumes the launcher's log is named `confidential-space-launcher`).

## Flows (platform-gcp/gcp)

- Attestation: `POST /v1/token` on `/run/container_launcher/teeserver.sock`
  with `{audience, token_type: "OIDC", nonces}`
  ([connect to external resources](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)).
  The runner sends `hex(user_data)` as the nonce; the token echoes it in
  `eat_nonce` ([token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)).
  The two pages give different nonce size limits (10-74 and 8-88 bytes);
  64 hex characters fit both. The audience is `signer-runner-identity`
  (`attest_audience`, from the setup, and the runner's default).
  The runner gives this token to every client that asks for `IDENTITY`,
  Dirk included, so the runner refuses an audience the WIF provider could
  take: `https://sts.googleapis.com` or a WIF resource name. Clients verify
  `signer-runner-identity` (`attestation-verify/identity` refuses the STS
  audience).
- Sealing: a random 32-byte data key, wrapped with Cloud KMS. Access: a
  second attestation token, audience `https://sts.googleapis.com`, the only
  audience the provider accepts (`deploy.sh wif-create`), goes to STS alone
  and is exchanged for a federated token, which calls KMS itself.
  The provider takes the issuer
  `https://confidentialcomputing.googleapis.com`, without a trailing slash,
  as in Google's discovery document and the token's `iss` claim. Google's
  impersonation example has a slash.
- Launch policy: CMD override is off by default; the image labels spell
  it out ([launch policies](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies)).
  All runner flags sit in the image, so the digest in the WIF condition
  covers them.
- Store: files under `/var/lib/signer` on the container's own file system.
  Google says the operator can roll back the dm-crypt writable partition
  ([Confidential Space security overview](https://docs.cloud.google.com/docs/security/confidential-space)),
  so the image uses the restart floor and no persisted marks. After a new VM,
  or if the store does not survive a container restart
  (`tee-restart-policy=OnFailure`), the runner restores it from the state
  copy; without one it makes a new data key and the shares need a new
  import.
- Clock: Google documents nothing on guest clock trust. The image uses the
  NTS clock (`-nts-clock`), with three HTTPS-date URLs as its coarse check.
  `clock=token-iat` (iat of a nonce-bound attestation token) is also
  implemented; the launcher fetches it over TLS from Google, so the host can
  delay it but not forge it.

## Channel and share import

- The runner listens on TCP 7100 with mutual TLS 1.3 only; it refuses to
  start on TCP without a client CA. The CA is the setup's
  `allowed_client_ca`, which setup_hash covers. Its TLS key is made in the
  VM at each start; the token nonce carries the identity user data, which
  binds the key's hash (`signer-protocol/docs/protocol.md`, "Channel
  binding"). A client connects with `remote.WithTLS` and a client
  certificate from that CA. The Dirk fork's adapter does that through
  `attestation-verify/runnerclient`.
- Shares arrive only sealed with HPKE (ML-KEM-768 + X25519) to the
  runner's attested per-boot key. The image holds the GCP release runner
  (`build-image.sh` builds `build/x86_64/bin/runner-gcp`, tag `platform_gcp`:
  no AWS SDK, no Azure code), which has no plaintext import at all (only the
  debug builds for local tests have it).

## Limits

- `attest.VerifyConfidentialSpace` checks Confidential Space tokens
  (Google key set, claims, nonce). `attestation-verify/runnerclient` has
  it as the verifier `gcp-cs`, so the dealer tool `share-import`, the Dirk
  fork's `cloud-import` and its adapter can select it. Its settings are
  `gcp_image_digest`, `gcp_audience` and `gcp_hwmodels`, and optionally
  `gcp_issuer`, `gcp_jwks_file` and `gcp_service_account` (see
  `attestation-verify/README.md`).
- Three-cloud layout (Azure on AMD SEV-SNP, AWS Nitro, GCP): set
  `gcp_hwmodels` to `GCP_INTEL_TDX` only, so one chip family never holds two
  shares, and run `HARDWARE=intel-tdx deploy.sh`. The verifier accepts every
  model on the list, so a list that names an AMD model would let a runner on
  AMD hardware pass. The default `amd-sev` setting does not meet that.
- The image runs `-record none`. The setup's mark log is the clone
  protection.
- Whether the value of a `tee-env-` variable appears in the token does not
  matter here: the image allows none.
- Physical attacks (TEE.Fail, Battering RAM) are outside Google's stated
  threat model.
