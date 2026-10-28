# AWS Nitro Enclaves backend

The runner runs in a Nitro enclave on an EC2 parent instance. The parent is
not trusted: it stores sealed blobs, relays the enclave's outbound TLS and
forwards client connections into the enclave over vsock. One enclave image
file (EIF) serves every signer of every operator. It holds the runner and the
flags that are the same for everyone, and the signer's values come in its
setup ("Setup").

## Files

| File | What |
| --- | --- |
| `nitro-cli/Dockerfile` | builds nitro-cli v1.5.2 from source (Rust 1.94.1 image), applies `target-arch.patch`, and adds the kernel/init blobs |
| `nitro-cli/target-arch.patch` | one change to `src/lib.rs` of nitro-cli: the kernel blob name follows `NITRO_CLI_TARGET_ARCH` when it is set, so an x86_64 machine can build an arm64 EIF |
| `enclave/Dockerfile` | the generic enclave image: static runner and the flags that are the same for every operator (`-setup platform`, the NTS clock, `-record none`). Built into an EIF by `scripts/nitro-eif.sh`. The fixed vsock port map is in its comments |
| `test-client-ca.pem` | public root certificate of a test PKI (`scripts/make-test-ca.sh`), for a test setup's `allowed_client_ca` (base64 of its DER). Its private key is not in the repo |
| `kms-key-policy.json.tmpl` | key policy: `Decrypt`/`GenerateDataKey` only with `kms:RecipientAttestation:PCR0/1/2/3`; `Encrypt` for the key admin only with exactly the encryption context `purpose=record-creds` (the record credentials), so the admin cannot make a sealing key (`purpose=sealing`) or a mark log key (`signer-key`), which carry setup_hash (`platform-aws/nitro`, `slashing-log/docs/marklog.md`, "Record keys"); `DescribeKey` and `GetKeyPolicy` for the parent role, which the runner reads at start for key_release_hash (`platform-aws/nitro` ReleaseHash). `platform-aws/nitro/planting_test.go` evaluates these conditions. `scripts/kms-policy.sh` renders it per build to `build/nitro/kms-key-policy-<arch>.json` |
| `main.tf` | KMS key (PCR0-3), parent role, enclave-enabled EC2 instance, the DynamoDB record table, its writer user, a deny on table writes for the parent role, and an optional inbound rule for the network entry (`entry_cidrs`). Optional `ssh_public_key` and `ssh_cidrs` give a key pair and an SSH rule for the operator. Variables `instance_type` (default `c6g.large`) and `region` (default `eu-central-1`) are the Graviton choice, see "Graviton (arm64)" |
| `target/main.tf` | a second signer next to a running one, a handover target. Its own root module and state, so no plan of it can change the running signer. It reads the parent role, instance profile, security group and key pair by name. It makes a new KMS key that releases to the target EIF's PCR0..2 alone (the same PCR3, the parent role's read of the key and its policy, the admin's `record-creds` encrypt) and, with `instance = true`, a second `c6g.large` parent. The admin encrypts a second access key of the record writer under the new key. `scripts/tf-validate.sh` validates it |
| `parent-run.sh` | parent setup: allocator, one vsock-proxy per route of the signer's setup (KMS, STS, the coarse-time host, the mark bucket, four NTS-KE), the host agent with the setup (`SETUP`), udprelay, `nitro-cli run-enclave`, the forwarder (network entry). Runs on x86_64 and arm64 parents (`SETUP`, `CPU_COUNT`, `MEMORY_MIB`) |
| `../../platform-aws/cmd/forwarder` | the network entry: a plain TCP to vsock byte forwarder, no TLS. Built by `scripts/build-runner.sh`, started by `parent-run.sh` |
| `../../platform-aws/cmd/udprelay` | the NTS clock's NTP path: vsock 7102 to UDP 123 and 4123, for an allowlist of the four NTS operators, with rate limits (package `platform-aws/udprelay`). Built by `scripts/build-runner.sh`, started by `parent-run.sh` |
| `allocator.yaml`, `vsock-proxy.yaml` | parent config in the formats shipped with nitro-cli v1.5.2. `vsock-proxy.yaml` is an example: `parent-run.sh` writes the allowlist from the setup |

## Setup

The chain config, the client CA, the KMS key and region, the mark bucket and
the signer name are in the signer's setup, a binary file that
`signer-admin/cmd/setup-tool encode` makes from a human `key = value` file
(`governance/setupwire/testdata/setup-nitro.conf` is an example;
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
  no principal may hold PutKeyPolicy, CreateGrant, ImportKeyMaterial or
  ReplicateKey (`signer-protocol/docs/protocol.md`, "Key rule lock"). The
  key policy template does not pass that check.
- The routes follow from the setup over a fixed port map: KMS and STS of
  the key release region on vsock 8000 and 8001, `www.cloudflare.com` on
  8002, the mark bucket on 8004, NTS-KE on 8005 to 8008, and the setup's
  `keygen_peer_attestation_hosts` on 8010 to 8025 (at most 16): the hosts
  that the runner's attestation verifier fetches key sets from when it
  checks a handover target, an Azure MAA host or Google's Confidential Space hosts
  (`governance/docs/setup-phase-cloud-test.md`, "Nitro peer endpoints").
  `hostagent -setup FILE -proxy-routes` prints them; `parent-run.sh` starts
  one vsock-proxy per line and writes the allowlist. The coarse-time URLs
  name `{region}`; the runner fills in the setup's region.
- The setup's mark log is the clone protection (see "Clone guard"). The S3
  writer credentials stay at `record/writer-credentials.kms` on the parent.
- `-mark-create`, `-state-create`, `-record-create` and the flags the setup
  replaces are refused with `-setup`, and the runner hands over to no one.
- `scripts/nitro-eif.sh` refuses `CHAIN`, `CHAIN_JSON`, `CLIENT_CA`,
  `REGION`, `KMS_KEY_ARN` and `MARK_BUCKET`, and checks that the image holds
  no `/etc/signer`.

With `mark_bucket` set, `main.tf` writes the bucket policy: the writer may
create and read objects under `marks/` and `config/`, list versions and read
the Object Lock configuration (the runner's lock check needs
`s3:GetBucketObjectLockConfiguration`); the parent role is denied every
write. The paths carry setup_hash, so one policy serves every setup of the
image. The KMS key policy and the bucket policy are set once per EIF; a new
chain or signer is a new setup on the parent. The order of a deploy is in
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
 vsock-proxy 8005-8008 -> NTS-KE (TCP 4460)
```

The Dirk fork connects to the forwarder over TCP and never sees vsock (see
"Network entry").

- Attestation: `/dev/nsm` through `github.com/hf/nsm` (MIT). The document is
  COSE_Sign1, ES384 ([AWS: verify root](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)).
  Verifiers check it against the AWS Nitro root and compare PCR0/1/2.
  `attest.VerifyNitro` does that. `attestation-verify/runnerclient` has it as
  the verifier `aws-nitro`, so the dealer tool `share-import`, the Dirk
  fork's `cloud-import` and its adapter can select it. Its settings are
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
- A document of a running enclave carries PCR0 to PCR2 of the EIF, PCR3 of
  the parent role, PCR4 (the instance), PCR5 to PCR8 as zero, debug off,
  the enclave id as module id, and a leaf certificate with the subject
  `<module id>.<region>.aws`. It has no public key.

## Clone guard

A parent can run up to four enclaves from one EIF and feed each the same
sealed share blob. Each would unseal it and keep its own slashing state. The
clone protection is the setup's mark log (see "Mark log"). Each runner
claims the log at start with its own record. When a second instance claims
it, the first one's next write finds its name taken by another owner's
record, and from then on it signs nothing new
(`slashing-log/docs/marklog.md`).

The log only helps if the parent cannot write it. The parent holds the
instance role, so the role is denied every write, and the writer is an IAM
user whose access key only the enclave can read:

1. `terraform apply` creates the user `signer-record-writer-<node>` and the
   deny on the parent role.
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

The account admins can still delete or rewrite records and can mint new
keys for the user; they already control the KMS key policy, so this adds
no new trusted party. SigV4 signing uses the enclave's clock; a host that
moves it can only make AWS refuse the request (the runner then refuses to
sign).

The runner also has a DynamoDB record store (`tee-signer/record`): a
conditional `PutItem` on the item's version, with record values sealed with
the KMS data key and bound to that version. `main.tf` creates its table
`signer-records`, gives the writer user GetItem and PutItem on its own key
only (`dynamodb:LeadingKeys`), and denies table writes to the parent role.
The generic image runs `-record none` and does not use it.

## Mark log (S3 Object Lock)

The setup's `slashing_log_store` (bucket and region) and `signer_name` keep
the runner's mark in an S3 bucket with versioning and Object Lock, default
retention in compliance mode (`slashing-log/docs/marklog.md`). The mark log
is required. The client signs with the enclave-held record credentials
(`RecordCredentials`, `record/writer-credentials.kms`), so the parent cannot
write records. The admin can add versions and delete markers but not delete
or overwrite a locked version; the reader lists every version. The route
`B.s3.R.amazonaws.com:443` on vsock port 8004 follows from the setup, on
both sides.

## An overlay network on the parent

The parent may run an overlay network entry of the operator. The security
group allows outbound TCP 443, and with `nts_egress` the NTS clock's
TCP 4460 and UDP 123 and 4123, so such an entry gets only relayed paths
over TCP. If TLS handshakes stall on such a path, set a smaller MTU, for
example 1280 on the parent and 1200 on the client. `prev_pcrs` lets the KMS
key accept a second image's PCRs next to `pcr0..2`, so a rollback needs no
key policy change.

## PCRs of the image

`scripts/nitro-eif.sh` builds the EIF twice from scratch, compares the
PCRs, and prints PCR0, PCR1 and PCR2. Record the PCRs of the commit you
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
make eif EIF_ARCH=aarch64                  # the same
```

The image is generic: no chain, client CA or region goes in ("Setup"). The
chain is checked when the setup is made (`setup-tool check -chain`).

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

`nitro-eif.sh` ends with `scripts/eif-check.sh`. You can run it on any EIF:

```sh
scripts/eif-check.sh build/nitro/runner-aarch64.eif aarch64 \
  --runner build/aarch64/bin/runner-aws --build-json build/nitro/build-enclave-aarch64.json
```

It reads the file and does not use nitro-cli. It checks:

- the arch flag in the EIF header,
- the kernel: for arm64 the `Image` header magic `ARMd` at offset 56 (for
  x86_64 `HdrS` at 0x202), and that the bytes are the blob file's,
- `init` and the runner in the ramdisks are ELF files of the arch, and the
  runner has the sha256 of `build/<arch>/bin/runner-aws`,
- with `--generic`, that the image holds no operator files (`/etc/signer`),
- PCR0, PCR1 and PCR2 recomputed from the sections (SHA-384 of 48 zero
  bytes and the SHA-384 of the section bytes). They must equal what
  nitro-cli printed. On an x86_64 EIF the same code reproduces nitro-cli's
  PCRs.

This shows the file is the one you meant to build. It does not show that the
hardware measures it the same way.

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
  runner.
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
  clock instead (`-nts-clock`, next section): four NTS operators, a quorum
  with an error bound, signing refused above 100 ms. The parent can delay or
  drop that traffic but not forge it. The same clock checks the dates of
  client certificates. HTTPS Date readings over vsock-proxy are its coarse
  check.
- `clock=nsm` (NSM attestation timestamp) is implemented, but it is not
  known which clock the hypervisor stamps and whether the parent can
  influence it. Trail of Bits advises against using it for enclave time.

## NTS clock in the enclave

The enclave has no network, and vsock-proxy carries TCP only
(`vsock_proxy/src/proxy.rs`). The NTS clock (`trusted-time/docs/nts.md`)
therefore takes two paths out, both through the parent and both untrusted:

| Traffic | Enclave side | Parent side | Destination |
| --- | --- | --- | --- |
| NTS-KE, TLS 1.3 | `proxy=` routes `time.cloudflare.com:4460=vsock:3:8005`, `nts.netnod.se:4460=vsock:3:8006`, `ptbtime1.ptb.de:4460=vsock:3:8007`, `ntppool1.time.nl:4460=vsock:3:8008` | vsock-proxy, allowlist in `vsock-proxy.yaml` | the four hosts, TCP 4460 |
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

The destination's port must be 123 or 4123. A name must be one of the four
NTS-KE host names; the relay resolves it itself and sends to the first IPv4
address. An address must lie in `194.58.200.0/21` or be one that one of the
four names resolves to now (cached 5 minutes, a failed lookup 30 s).
Nothing else goes out and no other name is resolved. The block is for
Netnod: each IPv4 address of `nts.netnod.se` names a different NTP server by
address, port 4123, in `194.58.203.x` to `194.58.207.x`, and none of them is
an address of the name. Cloudflare, PTB and time.nl name themselves. If
Netnod moves its NTP servers out of the block, the relay refuses them
(`destination refused` in its log) and the quorum runs on the other three
until `-allow-nets` is extended.

### Limits

16 sessions at once; a session ends 10 s after its last datagram or 30 s
after it began; 8 datagrams out per session; 10 datagrams per second out in
all (burst 20) and 0.5 per second to one address (burst 4). The clock asks
each server every 32 s at most, so a normal minute is 8 datagrams. Over a
limit the datagram is dropped and counted, as a network would drop it.
`udprelay` logs its counters every 10 minutes.

### What the parent can do

Delay or drop NTS-KE and NTP. A delayed answer widens that sample's bound by
half the delay and cannot move the time outside it; dropped answers age the
bound until signing stops at 100 ms (500 ppm: about 140 s after a quorum
with a 30 ms bound). It cannot forge: TLS 1.3 with pinned roots ends in the
enclave, and every NTP answer carries the NTS authenticator with keys from
that TLS session (AES-SIV-CMAC-256). It can send unauthenticated
Kiss-o'-Death packets with our unique identifier, which may disable a server
(RFC 8915 section 5.7 allows the client to act on them); two of four
disabled stop the quorum, so signing stops: fail closed. The host also runs
the enclave's CPU counter, the clock's local time (`CLOCK_MONOTONIC_RAW`);
the drift check against a quorum 17 minutes old refuses a rate beyond
500 ppm, see `trusted-time/docs/nts.md`.

### Security group

`main.tf` variable `nts_egress` (default true): TCP 4460 and UDP 123 and
4123 out to anywhere. A security group cannot name hosts and the operators'
addresses move, so the narrow rules are the relay's allowlist and
vsock-proxy's.

`TestE2ENTSClockThroughRelay` (`tests/e2e`) runs the relay, the four
proxies and the clock over TCP on loopback, and `TestE2ENTSRelayInterop`
runs them against the four public operators.

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
 Dirk fork --- TCP ---> forwarder (parent) --- vsock 16:7100 ---> runner (enclave)
    |                   copies bytes, no TLS                        |
    +------------- mutual TLS 1.3, ends inside the enclave ---------+
    aws-nitro check of the identity on every connection (client side)
```

The Dirk fork stays on TCP. Its copy of the client has no vsock. It connects
to `tcp:HOST:PORT` of the forwarder, like it does to a signer on Azure. The
forwarder can be replaced without touching the Dirk fork or the enclave.

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
through. It allows 256 connections at once (`-max-conns`) and gives the
dial 5 seconds. It has no certificate, key or CA, reads no request and
answers none. Tests (`platform-aws/forward`): mutual TLS 1.3 with the
runner's real TLS configuration runs through it, the client sees the
target's key, and the bytes it copies do not contain the payload.

`socat TCP-LISTEN:7100,fork,reuseaddr VSOCK-CONNECT:16:7100` does the same
job.

The security group can allow the forwarder's port from the Dirk fork hosts
(`entry_cidrs` in `main.tf`, empty by default: no inbound rule). That limits
exposure and the load on the instance. It is not what keeps the runner safe.

### What the image measures

The client CA certificates (public, 1 to 4, DER) are the setup's
`allowed_client_ca`. setup_hash covers them, and the runner puts setup_hash
in its attested identity. The parent can hand over a setup with its own CA.
That runner shows another setup_hash and finds another, empty mark log, so it
stops while this signer's shares are stored, and the shares do not open for
it. Its KMS calls carry its own setup_hash, so it does not get the sealing
key either. `test-client-ca.pem` is the root of a test PKI made by
`scripts/make-test-ca.sh`. Its private key is not in the repo.

### Client certificates, the clock and the CA

- The setup pins the CA only, not the client certificates. Client
  certificates can be short-lived (hours or days) and can be rotated
  without a new setup. A change of the CA is a new setup, so a new
  setup_hash.
- The runner checks the validity dates of the client certificate, and of
  its chain, against the clock of its platform (the NTS clock, "NTS clock in
  the enclave"), not against the system clock that the parent sets. If that
  clock has no time (no quorum, or a bound over 100 ms), no client
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
   `admin_role_arn`, `ami_id`, `subnet_id` and, if wanted, `mark_bucket`,
   `entry_cidrs`, `ssh_public_key` and `ssh_cidrs`. Terraform state stays
   outside the repo.
3. The writer credentials (see "Clone guard", steps 2 and 3).
4. Copy the EIF, the parent binaries and the files of
   `platform-aws/deploy/` to the instance, install the Nitro CLI, and run
   `SETUP=<setup> parent-run.sh` in a new session.
5. Check the PCRs on the parent ("Check the PCRs on the parent"), then the
   proof from a client (see "Verify").

`parent-run.sh` starts the processes on the parent (`vsock-proxy` for each
route, `hostagent`, `udprelay`, `forwarder`) with `nohup`, not as services.
A reboot ends them and needs `parent-run.sh` again. The store under
`/var/lib/signer-runner` stays.

A runner that fails sends the line it prints (`runner: ...`) to the host
agent before it exits (hostagent EXIT). The agent writes it with the time to
`/var/lib/signer-runner/last-exit.txt` (`-exit-file`) and to its log.
Nothing else leaves the enclave this way: one line of printable ASCII, at
most 2048 bytes, the same text a console would show. An enclave that is not
in debug mode has no console.

## Verify

- `nitro-cli describe-enclaves` on the parent reports the PCRs of the
  build, all three equal.
- CloudTrail shows `GenerateDataKey` (first start) or `Decrypt` by the
  instance role session without an error code. The runner only starts to
  serve after the sealing key and the writer credentials both decrypt, so a
  listening runner means the PCR conditions of the key policy accepted its
  document.
- From a client, through the forwarder, with a client certificate of the
  setup's CA: `share-import` or the Dirk fork with the `aws-nitro` verifier
  and the PCRs of the build. A wrong PCR is refused with `measurement
  mismatch: pcr2 is ..., want ...`. `scripts/kms-policy.sh pcr3` gives the
  PCR3 the document should carry for `role/signer-parent`.

## Limits

- A kernel without vsock loopback (WSL2) skips the vsock tests of
  `tee-signer/attls` and `tests/e2e`. They run over TCP loopback there.
- The parent processes run under `nohup`, not as services.
- The enclave's clock: see "Restart protection and time on Nitro".
