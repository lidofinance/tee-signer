# Azure confidential containers backend (ACI)

Each signer is one confidential container group in Azure Container
Instances. The group holds the runner and, optionally, the operator's
network entry. Clients reach the runner's port 7100 through that entry, with
mutual TLS 1.3 on top. The runner does its own attestation and key release
in process (`platform-azure/azure/`): it requests the SNP report, calls
Microsoft Azure Attestation (MAA), gets the managed identity token and
releases its key from Key Vault. No Microsoft container runs in the group.

`common.sh` puts each of the three signers in its own region by default:
West Europe, North Europe and East US (`LOCATION_N` overrides it). The
gateway combines the first 2 of 3 partial signatures, so with all three
signers up the two closest ones set the signing time.

| File | What |
| --- | --- |
| `Dockerfile` | runner image, `FROM scratch`: the runner with mode 0555 (`COPY --chmod`) and `ENTRYPOINT ["/runner"]`. One image for every signer and every chain |
| `build-image.sh` | builds that image twice from the Azure release runner (`runner-azure`) and checks that both digests match. The context file gets an explicit mode, so the digest does not depend on the builder's umask |
| `aci-template.json` | container group template with placeholders: the runner and its fixed command, no IP address, `sku: Confidential` |
| network entry part | optional (`NETWORK`): a template part with its container and parameters. This tree has none. A build overlay (`SIGNER_BUILD_OVERLAY_DIR`) supplies one, and `deploy.sh render` merges it in |
| `skr-policy.json.tmpl` | Key Vault release policy pinned to the CCE policy hash |
| `common.sh` | regional MAA hosts, names per signer index, `NETWORK` |
| `deploy.sh` | one command per step: local `plan`, `render` and `policy`, then one command per Azure step |
| `make-test-ca.sh` | local test CA and one client certificate for the signing client |
| `chain-from-devnet.sh` | writes a `chain.json` for a local test chain from its beacon node |

The prover side of this backend, the in-process attestation, is one of
several. The [runner docs](../../tee-signer/docs/runner.md#provers-and-verifiers)
describe how provers and verifiers fit together, and how to add a platform.

## Setup

The image and the runner's command are the same for every signer of every
operator. The signer's values are in its setup: chain config, client CA,
MAA host, vault and key (`sealing_key_release`), mark log (required) and
state copy, signer name and optional network entry names. An Azure store
names `account`, `container`, `subscription` and `resource_group`, because
the lock check reads the storage account and the container with its
immutability policy from the management plane, which addresses the
account by its subscription and group. `signer-config setup` (the
signing client's tool) makes the setups of a
cluster with one `cluster_id`. `signer-admin/cmd/setup-tool encode` makes one
binary setup from a human `key = value` file
(`governance/setuptext/testdata/setup-azure.conf` is an example), and
`setup-tool chain-lines CHAIN_JSON` prints the chain lines of a chain.

```sh
setup-tool encode signer-1.conf signer-1.bin
CHAIN=<chain> CHAIN_JSON=chain.json SETUP_FILE_1=signer-1.bin CONFIRM=yes platform-azure/deploy/deploy.sh group-deploy 1
```

- `group-deploy N` checks `SETUP_FILE_N` with the runner's decoder: an
  Azure setup, of chain `CHAIN`, naming this deploy's attestation provider,
  vault and key. It passes the setup, base64, in the parameter
  `signerSetup`, which the template puts into the runner's `SIGNER_SETUP`.
  The parameter has no default, so `az confcom` makes it a wildcard rule,
  and the policy is the same for every signer as long as the network entry
  keeps per-signer values out of the measured command.
- `CHAIN` names a chain that `governance/chains/chain.sh` knows. A chain
  with a committed config in `governance/chains/` needs no `CHAIN_JSON`.
  `group-deploy` refuses a setup whose chain differs from that chain config.
- The runner reads `SIGNER_SETUP` first, refuses a setup for another
  platform and puts setup_hash and the mark log's config state in IDENTITY,
  ATTEST and HEALTH (IDENTITY, `signer-protocol/docs/protocol.md`).
- The sealing data key and the key that wraps the mark log and state copy
  keys are both derived from the released key and setup_hash: HKDF-SHA256
  over its private exponent, info `signer-runner azure sealing v1` or
  `signer-runner azure key wrap v1` (length-prefixed) and setup_hash. A
  runner started with another setup derives other keys and opens nothing of
  this signer.
- The runner stores no data key. Anyone with the released key's public half
  could make an RSA-OAEP blob and put it in a host-writable state folder, so
  a stored, wrapped data key could be planted.
- `build-image.sh` refuses `CHAIN`, `CHAIN_JSON` and `CLIENT_CA` and checks
  that the image holds no `/etc/signer`.

## What one signer looks like

| Container | Image | CPU | Memory |
| --- | --- | --- | --- |
| `runner` | `signer-runner@sha256:<digest>` from the registry, release build | 1 | 1 GB |
| network entry | optional, pinned by digest (one part of the template) | 0.5 | 0.5 GB |

The group asks for 1.5 CPUs and 1.5 GB. Each signer gets its own region, so
a region's 4 confidential cores hold one group with room to spare. The split
between the two containers is an estimate.

- ACI requires at least 1 CPU and 1 GB per container group, and lets single
  containers in it ask for less ([container groups](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-container-groups),
  "Minimum and maximum allocation"). It reserves some of the group's
  resources for itself, so keep a buffer (same page). The page names no
  minimum per container.
- The confidential maximum per group is 31 CPUs and 180 GB
  ([resource and quota limits](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-resource-and-quota-limits)).
  The 4-core quota is per region on a Free Trial subscription.
- ACI runs x64 images only ([ACI FAQ](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-faq)),
  so there is no arm64 variant.
- Containers in a group reach each other on localhost on any port (container
  groups page, "Networking"). That is why only the runner's port may listen
  (see "What listens in the group").

## What listens in the group

Only the runner listens on a TCP port of its own: `127.0.0.1:7100`. It does
the attestation and the key release in its own process and opens no port
for them.

A network entry in the group may open sockets for its own transport, but
it must not expose a service. The end-to-end test `TestE2EAzureRunner`
checks that the runner process listens on its one port and nothing else.
`az container exec` is the way to look inside a running group, if the
confidential group allows it.

## Network

The group has no `ipAddress` block: no public IP, no VNet, no NAT gateway.
The runner uses ACI's default outbound access for its NTS clock
(`-nts-clock`: TCP 4460 and UDP 123 and 4123 to the four NTS operators,
HTTPS to the three coarse-check URLs), and for MAA, Key Vault and the
managed identity endpoint. The runner's `nts: key exchange` and
`nts: status` log lines show whether the NTS traffic gets out.

Inbound TCP to port 7100 comes through the operator's network entry (see
"Network entry"). The runner listens on `127.0.0.1:7100` only, so the entry
forwards to the loopback address. The entry runs in the same confidential
VM, so its image is measured. Its credential and per-signer names come in
as ARM parameters without a default, which `az confcom` turns into wildcard
rules, so they do not change the policy hash. A peer on the network can
reach any local port of the group that the entry forwards, so nothing but
the runner may listen.

The host that starts the groups passes the entry's parameters, so it can
attach a signer to a network of its own. It cannot read the traffic: the
runner's TLS key is bound to the attested identity and the clients check
it. It can refuse service.

## CCE policy and secrets

`az confcom acipolicygen` makes the CCE policy from the template. The
Key Vault release policy pins the SHA-256 of that policy
(`x-ms-sevsnpvm-hostdata`). A network entry's credential and host name must
not change the hash, or every new credential would break the release policy.

How the tool treats environment variables (confcom 2.3.0, source
`azext_confcom/template_util.py`, `process_env_vars_from_template`, and the
[confcom README](https://github.com/Azure/azure-cli-extensions/blob/main/src/confcom/azext_confcom/README.md)):

- A literal `value` or `secureValue` becomes an exact-match rule, so it is
  in the hash. Two different literal `secureValue`s give two hashes, which is
  why the template only holds the parameter.
- A value that is an ARM parameter reference, for a parameter that has no
  `defaultValue` and no value in a parameters file, becomes the rule
  `NAME=.*` (strategy `re2`). The tool asks before it does this, and `-y`
  (`--approve-wildcards`) approves it. The README says the same: a parameter
  without a default gives a wildcard, and the value comes at deploy time.

So `signerSetup` and a network entry's per-signer parameters have no
default, and `deploy.sh policy` runs with `-y` and never passes a parameters
file for them. The deployment passes them in a parameters file. The policy
holds the parameter-backed variables as `re2` rules and every literal
variable as an exact string.

What does change the hash: the runner image, the runner's command line, the
network entry's image, the container names and `command`s, the stdio
setting, and the confcom version (it bundles the policy API version and the
infrastructure fragment). The registry name does not, because of
`--omit-id` (see "Key, identity and registry"). Create the keys after the
last change.

What the tool prints. With `-a template.json` it writes the base64 policy
into the template's `ccePolicy` and prints the SHA-256 of the decoded policy
on stdout, one line of 64 hex digits, and nothing else. Progress bars and
warnings go to stderr. If the template already has a `ccePolicy`, it asks
before it overwrites it, so `deploy.sh` always renders a fresh template and
closes stdin. `deploy.sh policy` also decodes the policy from the template
and checks that its SHA-256 equals the printed one. With a network entry
whose command holds nothing of one signer, it also checks that the three
signers have one policy.

## One image for every signer

ACI's `command` replaces the image entrypoint
([override entrypoint](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-start-command)),
and `az confcom` puts the `command` into the policy, so the runner's flags
are measured. The Dockerfile only has `ENTRYPOINT ["/runner"]`, and the
flags live in `aci-template.json`. On Azure the measured command takes the
role that baked-in flags play on the other clouds.

One image means one build, one push and one digest to audit for every
signer. The per-signer values are in the setup, which the policy matches as
a wildcard. `deploy.sh render N` fills the group name, the location, the
runner image and the network entry part's values into the template.

## Attestation and key release in the runner

This section is the protocol that `platform-azure/azure/` implements, with
the source of each step. The reference is Microsoft's open-source sidecar,
[confidential-sidecar-containers](https://github.com/microsoft/confidential-sidecar-containers)
(MIT, release v2.14), read through its source on GitHub. The code here is
written from scratch and uses the standard library only. Where a detail
comes only from the sidecar's code and not from a Microsoft document, this
section says so.

### 1. The SNP report, with chosen report data

The runner asks the SEV-SNP guest device with an ioctl.

- Device: `/dev/sev` if it exists (the 5.x kernel driver), else
  `/dev/sev-guest` (6.x). Source: sidecar `pkg/attest/snp_device.go`.
- ioctl: `SEV_SNP_GUEST_MSG_REPORT` on 5.x, `SNP_GET_REPORT` on 6.x. Both
  take a 96-byte request whose first 64 bytes are the report data, and fill
  a response of status, report size, 24 reserved bytes and the 1184-byte
  report. The two structs, their sizes (40 and 32 bytes) and the request
  numbers (3223868161 and 3223343872, that is `_IOWR('S', 1, 40 bytes)` and
  `_IOWR('S', 0, 32 bytes)`) are in sidecar
  `pkg/attest/attestation_report_fetcher.go`. `snp_linux.go` builds the
  structs with the same layout, and a test pins the sizes, the offsets and
  the numbers.
- Report data: SHA-256 of the runtime data, padded with zeros to 64 bytes.
  Source: sidecar `pkg/attest/attest.go`, `GenerateMAAReportData`.
  The runner checks that the report it gets back carries the report data it
  asked for.
- How a container gets the device. The sidecar's ACI example template has no
  device, volume or `securityContext` field. In Microsoft's `hcsshim`, which
  runs the utility VM's guest side, `Host.CreateContainer` calls
  `AddDevSev` for every workload container that is not privileged, when the
  group has a CCE policy (`internal/guest/runtime/hcsv2/uvm.go`,
  `internal/guest/spec/spec.go`). So the template gives the runner nothing
  extra for the device. Microsoft's page "Secure Key Release with Azure Key
  Vault and Confidential Containers on Azure Container Instance" says a
  custom application "shall fetch a RAW AMD SEV-SNP hardware report by doing
  a IOCTL Linux Socket call" and needs no guest attestation library.
- The runner fails at start with "no SEV-SNP guest device" if it sees no
  device.

### 2. The VCEK certificate chain and the UVM endorsements

MAA needs both next to the report: the chain that vouches for the report's
signing key, and the endorsements of the utility VM image. With the
endorsements MAA can say `azure-compliant-uvm` in `x-ms-compliance-status`,
the claim the release policy asks for and the verifier checks.

- Where they come from. `hcsshim` writes a directory `/security-context-XXXX`
  into each workload container and sets `UVM_SECURITY_CONTEXT_DIR` to it
  (`pkg/securitypolicy/securitypolicy_options.go`, `WriteSecurityContextDir`;
  sidecar `pkg/common/info.go`). The files the runner reads:
  `reference-info-base64` (the UVM reference info, a COSE_Sign1 document,
  base64) and `host-amd-cert-base64` (base64 of a JSON object with
  `vcekCert`, `tcbm`, `certificateChain` and `cacheControl`: the VCEK
  certificate of this host as PEM, the TCB version it is for as hex, and
  the ASK and ARK as PEM). The directory also holds `security-policy-base64`,
  which the runner does not need. Newer `hcsshim` also writes hash-envelope,
  TCB and platform reference info files, which sidecar v2.14 and the runner
  do not read.
- If the variable is not set, the runner looks for `/security-context-*`. If
  the files are missing it falls back to `UVM_REFERENCE_INFO` and
  `UVM_HOST_AMD_CERTIFICATE`, as the sidecar does. If the certificate is
  missing, or its `tcbm` is not the TCB version of the report, the runner
  asks the host's metadata endpoint
  `http://169.254.169.254/metadata/THIM/amd/certification` (header
  `Metadata: true`), which is the sidecar's fallback too
  (`pkg/attest/platform_cert_fetcher.go`). Microsoft's page above says
  these certificates are "delivered from Azure host IMDS endpoint".
- The VCEK chain sent to MAA is the `vcekCert` text followed by the
  `certificateChain` text. The runner refuses to go on without reference
  info, because MAA could not report `azure-compliant-uvm` then and the
  release would fail later with a less clear error.
- The file names and contents come from source code, not from a Microsoft
  document.

### 3. The MAA request

```
POST https://<maa host>/attest/SevSnpVM?api-version=2020-10-01
{"report":       base64url(JSON{"SnpReport":     base64url(raw report),
                                "VcekCertChain": base64url(PEM chain),
                                "Endorsements":  base64url(JSON{"Uvm":[base64url(UVM reference info)]})}),
 "runtimeData":  {"data": base64url(runtime data), "dataType": "JSON"},
 "initTimeData": {"data": "", "dataType": ""},
 "nonce":        <random uint64>}
```

The answer is `{"token": "<JWT>"}`. Sources: sidecar `pkg/common/maa.go` (the
structs, `base64.URLEncoding` with padding, `dataType` JSON) and
`internal/httpginendpoints/httpginendpoints.go` (`SevSnpVM`, the API
version). Microsoft's [REST reference](https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm)
documents `POST {instance}/attest/SevSnpVm`, the four fields and the data
types (`Binary`, `JSON`), and its sample request has the same `report` layout.
The reference describes version 2022-08-01. The sidecar and the runner send
2020-10-01. The empty `initTimeData` and the `Endorsements` field also follow
the sidecar.

The runtime data is `backend.MAARuntimeData` for an identity and
`{"signer-runner-clock":"<hex nonce>"}` for the clock, which
`attestation-verify/azureid` and the signing client expect byte for byte. With
`dataType` JSON, MAA puts it into the token as `x-ms-runtime`, and the report
data in the SNP report is the SHA-256 of those exact bytes. The sample token
on Microsoft's page [Attestation in confidential containers on ACI](https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts)
shows `x-ms-compliance-status`, `x-ms-sevsnpvm-hostdata`,
`x-ms-sevsnpvm-reportdata` and `x-ms-sevsnpvm-uvm-endorsement`.

### 4. The managed identity token for Key Vault

```
GET http://169.254.169.254/metadata/identity/oauth2/token
    ?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net
Metadata: true
```

The answer has `access_token`. Source: Microsoft's page
[Enable Managed Identity in a Container Group](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity),
which gives this request for a Linux container, and sidecar
`pkg/common/token.go`. The template assigns one user-assigned identity to the
group, so the request names none. The platform option `client_id` adds
`&client_id=<id>`, for a group with more than one identity. The page does not
say which identity answers when there are several and none is named. The
runner retries 404, 410, 429 and 5xx answers a few times, because the
metadata service answers 404 while an identity is not ready (Microsoft's
retry guidance for managed identities on VMs).

### 5. The Key Vault release

```
POST https://<vault>/keys/<name>/release?api-version=7.4
Authorization: Bearer <managed identity token>
{"target": "<MAA token>"}
```

The answer is `{"value": "<JWS>"}`. Sources: Microsoft's REST reference for
[Keys - Release](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release)
(request body `target`, `enc`, `nonce`; answer `value`) and sidecar
`pkg/common/akv.go` and `internal/httpginendpoints/httpginendpoints.go` (the
URL without a version and `api-version=7.4`).

Key Vault wraps the released key to an RSA key named in the MAA token. Its
page "Azure Key Vault secure key release policy grammar" says the token must
carry `x-ms-runtime.keys`, a JWK set with an RSA key that has `key_ops`
`encrypt` and a `kid`, and that "the first suitable key is chosen". So the
runner does what the sidecar does (`pkg/skr/skr.go`, `pkg/common/crypto.go`):

1. It makes a fresh RSA-2048 key pair for each release.
2. It asks MAA for a token whose runtime data is
   `{"keys":[{"e":"AQAB","key_ops":["encrypt"],"kid":"<thumbprint>","kty":"RSA","n":"..."}]}`.
   The `kid` is the RFC 7638 thumbprint.
3. It posts that token as `target`.
4. It checks the JWS in the answer: the `x5c` leaf must be valid for the
   vault's name, chain to a root of the runner (the embedded Mozilla roots,
   no host bundle) and have signed the JWS (`RS` or `PS` 256, 384, 512).
5. It reads `response.key.key.key_hsm` from the payload (base64url of JSON
   with a `ciphertext`), and unwraps the ciphertext as the sidecar does
   (`pkg/common/akv.go`, `RsaAESKeyUnwrap`, and `pkg/common/keywrap.go`): the
   first 256 bytes are an AES key encrypted to the wrapping key with RSA-OAEP
   (SHA-1 for `CKM_RSA_AES_KEY_WRAP`, the default; SHA-256 or SHA-384 for
   `RSA_AES_KEY_WRAP_256` and `_384`, named in `request.enc` of the payload),
   and the rest is the key wrapped with that AES key by RFC 5649 key wrap
   with padding. The unwrapped bytes of an RSA key are a PKCS#8 key.
6. If the unwrapped bytes are a JWK instead, `parseRSAJWK` reads them.
   `key_ops` in Key Vault's JWK is an array.

The runner then derives its sealing data key from the released key and
setup_hash (HKDF-SHA256, see "Setup"). It stores none of it. A fresh
wrapping key per release means a recorded answer is useless later, and the
host cannot read the key on the wire: it is encrypted to a key that never
leaves the runner.

Only in the sidecar's code, not in Microsoft's documents: the JWS check and
its algorithm, the payload field names, that the unwrapped RSA key is PKCS#8,
and that the path may leave out the key version.

### What the template gives the runner

- Device and security context: `hcsshim` provides both to the container
  (steps 1 and 2). Microsoft documents no ACI template field for either, and
  the sidecar's own ACI example has none.
- Identity: the group has `identity.userAssignedIdentities` with the
  signer's identity, and `deploy.sh key-role` gives it the role `Key Vault
  Crypto Service Release User` on its key, and `Key Vault Reader` on it for
  the key's release policy, which the runner hashes into key_release_hash
  (`platform-azure/azure` ReleaseHash). The runner container needs no
  field of its own.
- Resources: runner 1 CPU and 1 GB.

## Trust base

What a verifier has to believe:

- AMD's silicon and firmware, through the SNP report and the VCEK chain.
- The Azure utility VM image, which MAA checks against Microsoft's
  endorsement (`azure-compliant-uvm`), and the enforcement of the CCE policy
  by that image. The policy's SHA-256 is `x-ms-sevsnpvm-hostdata`.
- The runner image: the code that does the attestation, holds the TLS key and
  the shares. Reproducible build, pinned by digest in the policy.
- The network entry's container and image, if the group has one. It runs
  in the same VM as the runner and shares its kernel, so a flaw in it plus a
  container escape would expose the shares. It is measured, but it faces the
  network.
- Microsoft Azure Attestation: the provider's signing key, which signs every
  token. Key Vault's release policy trusts the same provider.
- Azure Key Vault Premium: it releases the key only to a token whose
  hostdata is the group's CCE policy hash, and holds the key in an HSM.
- The managed identity and Azure's role assignments: the identity can release
  one key. Whoever can change the key's release policy or its roles can
  change who gets the key (`KEY_IMMUTABLE`, the operator's roles).

Outside it, and untrusted by design: the host that starts the groups and
chooses the network, the network entry's services (see below), the
registry, and the state files (`/var/lib/signer` can be rolled back by the
host, so the runner has its restart floor).

## Risks of a network entry in the group

1. A network entry can forward inbound flows to loopback, so every port that
   listens in the group can be reached from the network the host picks. A
   local service that mints MAA tokens for any runtime data and releases the
   key without authentication would let a host mint a valid identity for keys
   it holds, and the dealer would then seal a share to it. That is why the
   runner does the attestation in process and opens no port for it, and why
   port 7100 is the only service that may listen.
2. The network entry shares the guest kernel with the runner and faces the
   network, so a flaw in it plus a container escape would expose the share
   in memory.
3. The host sees the entry's credential, so it can attach nodes or a network
   of its own.
4. The network's operator sees metadata and can drop or delay traffic.
5. Path MTU. A path through a network entry can drop packets above about
   1300 bytes, and then TLS handshakes stall. A smaller MTU on the client
   side fixes it.

Mitigations: mutual TLS 1.3 with client certificates, and the client checks
the MAA proof and the TLS key binding on every connection. A node without a
valid proof is refused. Nobody in the group mints proofs for others. A
network policy that opens TCP 7100 only is a second layer, and it holds only
on the operator's own network. The entry's image is pinned by digest: an
update changes the hash and needs new keys.

## Network entry

The network entry is how the signing clients reach port 7100 of each signer. It is
an optional part that can be replaced. This tree has no implementation. This
section is the contract and the options.

### Contract

- Carry TCP from the signing clients to port 7100 of each signer.
- A stable name or address per signer (the signing client's `address` setting).
- Pass full-size packets, or set a smaller MTU (see risk 5).
- It is not trusted. Security comes from mutual TLS 1.3, with the runner's
  TLS key bound to its attested identity, which the client checks on every
  connection. A network that carries the bytes can refuse service. It cannot
  read or change what passes, and it cannot make a signer look like another.
- Nothing but port 7100 may listen inside a signer group. A network
  component may add sockets for its own transport, but it must not expose a
  service.

An option is a template part with its parameters and its container (or
none), plus the overlay functions that `deploy.sh` calls (see "the network
entry part" in `deploy.sh`). `deploy.sh` stops with an error for any
`NETWORK` it does not know.

### Options

This tree implements none of these.

- An overlay network. A container of an overlay network in the group, in
  userspace mode, and the operator's side on the same overlay. Watch: the
  host picks the network (credential and host name are not measured), the
  packet size on the path, the overlay's control plane sees metadata, the
  network policy.
- Cloudflare Tunnel. The Cloudflare tunnel client in the group as a locally
  managed tunnel, so a configuration file with the ingress rules is part of
  the measured image or command and the rules cannot be changed from
  outside (a remotely managed tunnel takes its ingress from Cloudflare, which
  the measurement would not cover). One rule, `service: tcp://localhost:7100`,
  and the required catch-all ([configuration file](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/local-management/configuration-file/)).
  Operator side: the tunnel client in TCP access mode on each client host, or
  WARP with a private network route ([connect a private hostname](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)).
  Watch: the tunnel credential is a secret that is not measured (like any
  overlay credential), Cloudflare sees metadata and can drop traffic, the
  packet size, and what the tunnel client opens locally (metrics).
- Azure VPN gateway or Private Link. The group sits in a virtual network
  with a private address and only 7100, and the operator's network reaches
  it over a VPN gateway or a private endpoint. Watch: whether a confidential
  group can join a virtual network at all, the outbound access that MAA,
  Key Vault and the identity endpoint need (a NAT gateway), and the monthly
  price (about 37 USD for a Basic VPN gateway with one connection, retail
  price estimate).
- A public IP with only 7100. The group declares an `ipAddress` with port
  7100 and nothing else, no overlay at all. Watch: the TLS port faces the
  internet, so the client certificate check and TLS stack are the only gate,
  and a denial of service has no filter in front.
- A virtual network with a separate forwarder. The signer group has a
  private IP and only 7100. A non-confidential group or VM in the same
  network carries the overlay or VPN entry and forwards TCP 7100. Watch: the
  forwarder is outside the measurement (fine, the network is not trusted),
  the NAT gateway for outbound traffic, and again whether a confidential
  group supports a virtual network.

## Mark log (immutable Blob Storage)

`-mark-store azblob:account=A,container=C` keeps the runner's mark in a
Blob Storage container with a locked time-based retention policy
(`slashing-log/docs/marklog.md`). Use container-level immutability: do not
enable version-level immutability on the account or the container, and do
not migrate the container to it. Create the policy without protected
append writes (no `--allow-protected-append-writes` or
`--allow-protected-append-writes-all`), then lock it:

```sh
az storage container immutability-policy create --account-name A -c C -g G --period DAYS
etag=$(az storage container immutability-policy show --account-name A -c C -g G --query etag -o tsv)
az storage container immutability-policy lock --account-name A -c C -g G --if-match "$etag"
```

The lock check refuses a container or account with version-level
immutability and a policy that allows appends. None of these can be
undone, so the signer then needs a new container (or account) and setup. The client takes a token for
`https://storage.azure.com/` from the container group's managed identity
(the same identity as for Key Vault) and sends `x-ms-version: 2021-08-06`
and `If-None-Match: *`. The identity needs the data action to create and
read blobs in that container only (Storage Blob Data Contributor scoped to
the container; with WORM nothing can delete). The runner reaches the
storage account through the group's outbound path, not through the
network entry. The setup's `slashing_log_store` (account, container,
subscription and resource group) and `signer_name` name the log. The lock
check takes a token for `https://management.azure.com/` from the same
identity, reads the storage account and the container with its policy,
and needs Reader on the account (`deploy.sh store-role N`). A custom role
without `storageAccounts/read` and `containers/read` is not enough: the
runner stops on the 403. With a setup, the container of the state copy
gets the same checks at start; an account or container the management
plane does not find stops it too.

## State copy and handover

The runner's state lives on the container's own file system under
`/var/lib/signer`, not on a volume, so a group that restarts without it
loses the sealed share. The setup's `encrypted_state_store` (use the mark
log's container) turns on the copy: the runner keeps a copy of its sealed
state under `state/` in the container, encrypted under a key derived from
the released Key Vault key, and restores it before it claims the mark log
(`slashing-log/docs/durable-state.md`). The identity's role on the container
covers it. Without a state copy, a runner that lost its state makes a new
data key and the shares need a new import.

A new image gets a new Key Vault key, which cannot open the old image's
state or mark log. The old runner hands its shares and its mark to the new
one under an approver-signed handover order (HANDOVER,
`signer-protocol/docs/protocol.md`, "Handover").

## Key, identity and registry

- MAA host per region, a value of `common.sh`: West Europe
  `sharedweu.weu.attest.azure.net`, North Europe `sharedneu.neu.attest.azure.net`,
  East US `sharedeus.eus.attest.azure.net`. The Azure PowerShell reference for
  [Get-AzAttestationDefaultProvider](https://learn.microsoft.com/en-us/powershell/module/az.attestation/get-azattestationdefaultprovider)
  shows the pattern (`sharedeus.eus`, `sharedeus2.eus2`, `sharedcus.cus`,
  `shareduks.uks`) but not these three hosts. Each of them serves
  `/.well-known/openid-configuration` with its own issuer. The release
  policy `authority` and the runner's `maa_endpoint` use the same host.
  `MAA_ENDPOINT_N` sets another one.
- The runner gets its Key Vault token from a user-assigned managed identity
  on the group, and that identity needs the role
  `Key Vault Crypto Service Release User` (sidecar ACI example). So the vault
  uses Azure RBAC, not access policies, and each signer has its own identity
  `signer-id-N`, with the role on its own key only. The operator needs
  `Key Vault Crypto Officer` on the vault to create keys. Give the group
  exactly one identity, or set the platform option `client_id`.
- The release policy follows the sidecar example: `x-ms-compliance-status =
  azure-compliant-uvm`, `x-ms-sevsnpvm-hostdata` = policy hash,
  `x-ms-sevsnpvm-is-debuggable = false`, `x-ms-sevsnpvm-vmpl = 0`. It does
  not ask for `x-ms-attestation-type`: the example does not have it, and a
  claim missing from the token fails the release.
- `KEY_IMMUTABLE` defaults to `false`. An immutable release policy cannot be
  corrected, and every change of the image changes the hash. Set
  `KEY_IMMUTABLE=true` for anything beyond tests. A runner whose setup is on
  mainnet refuses to start with a key that is not immutable
  (`signer-protocol/docs/protocol.md`, "Key rule lock"). Keys are RSA-HSM,
  2048 bit by default (`KEY_SIZE`), enough to wrap one data key in a test.
  Use 3072 in production.
- Key names are `signer-kek-N` (`KEY_NAME_PREFIX`, `KEY_NAME_N`).
  `key-create` refuses a key name that exists and never makes a new version:
  the runner releases the newest version of its key, so a new version would
  take the key away from the running image.

The image must be pullable by ACI. This setup uses Azure Container Registry
Basic with a managed identity and `AcrPull`, so no password is in the
template. ACI supports pulls from ACR with a managed identity
([ACI FAQ](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-faq),
registry section, and the SKR example: "use either a managed identity or a
username and password"). The fallback is the registry's admin user with
username and password in `imageRegistryCredentials`. `IMAGE_TAG` sets the
image's registry tag (default `poc`).

Registry credentials do not change the CCE policy. The policy holds layer
hashes, commands and environment rules, not registry names or credentials.
`acipolicygen` reads the runner image from the local Docker daemon, so it
needs no registry login for it (confcom README: images "in the local Docker
Daemon"). It prints "Using local version of ..." for each image. Only an
image that is not local needs a login before the tool runs. By default the
policy also holds an `id` with the image name and tag. `--omit-id` leaves it
out, and then the hash does not depend on the registry name. `deploy.sh`
always uses it.

Alternatives, in one line: Docker Hub or GitHub Container Registry with a
username and token in `imageRegistryCredentials`, or a public repository with
no credentials (the image holds only the runner, which would then be public).

A network entry image from Docker Hub may hit its limit on anonymous pulls.
`az acr import` copies it into the registry with the same digest.

## Chain config

The chain config is in each signer's setup ("Setup"), and it must be the
network the validator client signs for. The image has none.

- The tests (`tests/e2e`, `signer-core/core`) build a made-up chain with
  `software.DevConfig`: a genesis validators root of
  `sha256("tee-signer dev chain")`, 12 s slots, one fork at epoch 10.
  `governance/chains/chain.testnet.json` is the same chain as a file.
- `chain-from-devnet.sh [BEACON_URL [OUT]]` reads a local test chain's
  beacon node (default `http://127.0.0.1:33001`) the same way the signing
  client's local test mode does, and writes `chain.json`. It sets the policy
  fields to the values of that mode: fee recipient `0x...dEaD`, gas limits
  30 to 60 million, `max_epochs_ahead` 2, no exits. Environment variables
  override them.

A local test chain gets a new genesis time each time it is created, so it
needs a new `chain.json` and new setups (`setup-tool chain-lines` prints
their chain lines). The image, the policy hash and the keys stay.

## Test client CA

`make-test-ca.sh <secrets-dir>` writes an ECDSA P-256 CA and one client
certificate to `<secrets-dir>` (directory mode 700, key files 600), which
must be outside the repo. It stops without the argument. Only
`client-ca.pem`, the public CA certificate, goes into the setup
(`allowed_client_ca`, base64 of its DER). The runner requires a client
certificate from that CA. The signing client uses `client.pem` and
`client-key.pem`.

## Steps

Local, no Azure account touched:

```sh
platform-azure/deploy/build-image.sh            # the same image for every signer and chain
export VAULT=<globally unique name> ACR_NAME=<globally unique name>
platform-azure/deploy/deploy.sh plan
platform-azure/deploy/deploy.sh policy          # the policy hashes, about 10 seconds
export CHAIN=<chain> CHAIN_JSON=<secrets-dir>/chain.json   # no CHAIN_JSON for a committed chain config
setup-tool chain-lines "$CHAIN_JSON"            # the chain lines of each signer's setup file
setup-tool encode signer-1.conf signer-1.bin    # and SETUP_FILE_1=signer-1.bin for group-deploy 1
```

`build-image.sh` makes `build/azure/runner.oci.tar` and `runner.digest`. It
builds twice and fails if the digests differ.

### The image digest does not depend on the builder's umask

The Dockerfile sets the runner's mode with `COPY --chmod` (0555), and
`build-image.sh` gives the context file the same mode and checks the mode
and hash of the file in the image. Without that, the image would take the
modes of the build context, which follow the builder's umask, and the same
inputs would give two image digests and two CCE policy hashes. With it,
builds under umask 022 and 077 give the same digest and the same policy
hash.

### Azure steps

In order. Each needs `CONFIRM=yes` and refuses without it. The costs are
retail price estimates for West Europe.

1. `rg-create`. Free. The resource group is `RG` (default `signer-poc-rg`).
2. `vault-create`. Premium vault, billed per operation and key.
3. `vault-operator-role`. Free. You need it to create keys.
4. `acr-create`. Registry Basic, a daily fee.
5. `image-push`. Runs `az acr login`, then `docker push`, and compares the
   pushed digest with `runner.digest`.
6. `identity-create 1`, `2`, `3`. Free.
7. `key-create 1`, `2`, `3`. About 1 USD per key per month for RSA 2048
   (RSA 3072 is about 5 USD). It runs `policy` again and uses that hash.
8. `key-role 1`, `2`, `3`. Free.
9. `acr-role 1`, `2`, `3`. Free. Then `store-role 1`, `2`, `3` (needs
   `SETUP_FILE_N`): Storage Blob Data Contributor on the containers of
   the setup and Reader on their storage accounts, free. Reader is for
   the lock check, which reads the account and the container at every
   start; without it the runner stops.
10. `group-deploy 1`, `2`, `3`, with the network entry's settings. It re-runs
    `policy` and stops if the hash is not the one in the key's release
    policy. About 0.10 USD per hour per group (1.5 CPUs at 0.0579 USD and
    1.5 GB at 0.0064 USD per hour), about 7 USD a day for three. Stop the
    groups when a test ends.

Role assignments may need a few minutes to apply before `group-deploy`
works. A network entry credential never goes on a command line or into the
template.

### A new image for a running signer

A new runner image gives a new policy hash, so it needs a new key and a new
group next to the running one. The old runner hands over to the new one.

1. Local: `build-image.sh`, then `deploy.sh policy N`.
2. `image-push` with another `IMAGE_TAG`, so the running image keeps its tag.
3. Set `GROUP_NAME_N` (for example `signer-1b`) and `KEY_NAME_N` (a new key
   name) for the new group. `IDENTITY_NAME_N` stays the running group's
   identity unless set.
4. `key-create N`, `key-role N`, then `group-deploy N`.
5. Watch `az container logs -g "$RG" -n <group> --container-name runner`
   (see "Verify").
6. Hand over from the old runner (see "State copy and handover"), then
   delete the old group.

## Verify

Locally, without Azure:

- `TestE2EAzureRunner` (`attestation-verify/runnerclient`) runs the whole
  flow with the debug runner against a fake hardware report, security
  context, metadata service, MAA and Key Vault, and checks that the runner
  listens on its one port only.
- The release image started with the template's exact command, outside a
  confidential group, stops at the hardware step with "no SEV-SNP guest
  device". That is the right failure outside Azure.
- A TLS handshake without a client certificate gets the alert "certificate
  required".

On Azure, the runner's log names the step that failed: "no SEV-SNP guest
device" (step 1), "no UVM reference info" or "host AMD certificate" (step
2), "MAA: ... 400" with MAA's message (step 3), "managed identity token"
(step 4), "Key Vault release: ... 403" with Key Vault's message (step 5,
usually the release policy), or "JWS" and "key wrap" errors (step 5).
Restart policy `OnFailure` makes ACI retry, so the log shows each try.

Then the client side: the signing client or `share-import` against the signer's
address with the hash of `deploy.sh policy N` (see "What the signing client and
the dealer check"). A wrong CCE policy hash is refused with `measurement
mismatch`.

## Flows (platform-azure/azure)

- Attestation: MAA token with the runner's user data in its runtime data
  (steps 1 to 3 above). The runner sends the JSON object
  `{"signer-runner-identity":"<hex of the user data>"}`
  (`backend.MAARuntimeData`); the SNP report data is the SHA-256 of those
  exact bytes, which `attestation-verify/azureid` recomputes. Clock tokens send
  `{"signer-runner-clock":"<hex nonce>"}`, and `clock=maa-iat` checks that the
  token states the report data of that nonce.
- Sealing: Key Vault releases the exportable RSA key only for a token
  that meets the release policy (steps 4 and 5). The runner derives its
  data key from it and setup_hash (HKDF-SHA256) and stores none.
- Key creation: `az keyvault key create --exportable true --policy ...`;
  release policies are mutable unless `--immutable` is set
  ([az keyvault key reference](https://learn.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest)).
- ARM fields `sku: "Confidential"` and
  `confidentialComputeProperties.ccePolicy`, apiVersion 2023-05-01, and
  `az confcom acipolicygen -a template.json` come from the
  [ACI confidential containers tutorial](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-tutorial-deploy-confidential-containers-cce-arm).
- Store and clock: files under `/var/lib/signer` (host-controlled, can
  be rolled back) and the NTS clock (`-nts-clock -nts-coarse-urls
  login.microsoftonline.com,management.azure.com,www.cloudflare.com`; the
  runner is built with the tag nts, `trusted-time/docs/nts.md`). The three
  HTTPS URLs are its coarse check. `clock=maa-iat` is also implemented.
- Platform options (`-platform-opt`): `maa_endpoint`, `akv_endpoint`, `kid`,
  `clock`, `client_id`. The runner refuses any other option. The debug build
  has two more for the end-to-end test (`test_snp_hostdata`,
  `test_imds_url`); the release build has no test options.

## Channel and share import

- Mutual TLS 1.3 on port 7100 with a key made in the container at each
  start, bound to the MAA token through the identity user data
  (`signer-protocol/docs/protocol.md`, "Channel binding"). Client
  certificates must chain to the setup's `allowed_client_ca`, which
  setup_hash covers.
- Shares arrive only sealed with HPKE (ML-KEM-768 + X25519) to the
  runner's attested per-boot key. `build-image.sh` takes the release
  Azure runner (`build/x86_64/bin/runner-azure`, tag `platform_azure`: no
  AWS SDK, no GCP code), which has no plaintext import at all, and refuses a
  binary that holds the `-allow-import` flag. Only the debug builds
  (`runner-azure-debugimport` and `runner-dev-debugimport`), for local
  tests, have it.

## What the signing client and the dealer check

The signing client, its `cloud-import` tool and
`signer-admin/cmd/share-import` build their client with
`attestation-verify/runnerclient` (`attest.VerifyMAA` through
`attestation-verify/azureid`). On every connection they check the MAA token
before they send a request or a share. Settings per signer:

| Setting | Value for signer N |
| --- | --- |
| `address` | `tcp:<signer N address>:7100` (the network entry's name or address) |
| `client_cert`, `client_key` | `client.pem` and `client-key.pem` of `make-test-ca.sh` |
| `attestation.verifier` | `azure-maa` |
| `attestation.maa_host` | the MAA host of the signer's region, the `maa_endpoint` in `common.sh` (`sharedweu.weu.attest.azure.net`, `sharedneu.neu.attest.azure.net`, `sharedeus.eus.attest.azure.net`) |
| `attestation.cce_policy_sha256` | the hash of `deploy.sh policy N` (it also writes `build/azure/signer-N/policy.sha256`) |
| `attestation.compliance_status` | `azure-compliant-uvm` (the default) |

The verifier refuses a token that is not signed by a key of `maa_host`,
has another issuer, is not bound to this identity and nonce, says the
container is debuggable or runs at a VMPL other than 0, has another
compliance status, or carries another `x-ms-sevsnpvm-hostdata` than the
configured hash. The settings have no switch that turns a check off, and a
config without the hash does not start.

The dealer does the same from the command line, with the share in a file
(`cd signer-admin && go build -o share-import ./cmd/share-import`):

```sh
share-import -addr tcp:signer-1:7100 -pubkey 0x... -index 9 -share-file share.hex \
  -tls-cert client.pem -tls-key client-key.pem \
  -verifier azure-maa -maa-host sharedweu.weu.attest.azure.net \
  -cce-policy-sha256 "$(cat build/azure/signer-1/policy.sha256)"
```

The MAA key set comes from `https://<maa_host>/.well-known/openid-configuration`
over HTTPS, so the machine that runs the signing client needs outbound HTTPS to
the three MAA hosts and CA roots to check their certificates (the
`debian:bookworm-slim` image has none; mount the host's bundle). The local
tests use a fake provider and fakes for the runner's own calls
(`signer-protocol/docs/protocol.md`, `attestation-verify/README.md`).

## Limits

- The image runs `-record none`. The setup's mark log is the clone
  protection.
- Logs: stdio of the containers is on by default (`STDIO=enable`), so
  `az container logs` works. `STDIO=disable` closes it. The policy hash
  differs between the two.
- The runner checks the JWS of a Key Vault release with the time of the
  guest, and the host can move that clock. A late clock makes the check fail.
  An early one could make an expired certificate pass. Neither can make a
  chain pass that does not end in a root the runner embeds.
- If ACI rounds each container up to a whole core for the quota, a group
  with a network entry needs 2 of a region's 4 cores.
