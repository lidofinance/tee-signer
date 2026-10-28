# Key generation among runners

Runners make validator keys together, so no full key exists anywhere and no
share leaves a TEE. It is a Joint-Feldman DKG like the OP-TEE trusted app's
(threshold-signer-poc F7, `ta/trusted-app/dkg.c`), with three changes: the runners
authenticate each other by attestation and by a pinned operator key instead
of a device CA, nobody keeps a share until every participant has confirmed
the same transcript, and the runners sign the setup messages (deposits,
builder registrations, a Charon lock hash) themselves after checking them.
The design and the reasons are in threshold-signer-poc `research/charon-tee-dkg.md`.

One key generation serves every path: the Dirk fork with the gateway or
Vouch, and Charon. The result is the same for all: a validator key, the
share at x = i+1 sealed in participant i's runner, and the public share
keys. The coordinator builds what each path needs from it: deposit data and
accounts files for the Dirk fork, a Charon lock and signer shim settings for
Charon.

Code: `tee-signer/keygen` (runner side), `signer-protocol/dkgmsg` (messages and their
wire types), `signer-core/dkgmath` (scalar, G1 and G2 helpers on blst),
`tee-signer/charonlock` (Charon v1.11.0 lock types, hashes and checks),
`tee-signer/keygen/relay` and `signer-admin/cmd/dkg-coordinator` (the coordinator),
`charonnode` (a separate module: the Charon node's signature over the lock).
Tests: `make dkg-test`.

## Builds: the peer verifiers are plugins

Key generation exists only in runners built with peer tags, like the
platforms (`tee-signer/platforms.go`): `peer_azure`, `peer_aws`, `peer_gcp` and
`peer_dev` name the attestation verifiers the runner can check its DKG peers
with, and `peerselect` makes `attestation-verify/runnerclient` link only those
(`verifierFactories`). `peer_dev` needs `platform_dev`; `peer_optee` is
reserved for the boards and stops the build, as does a peer tag in a debug
build (`tee-signer/dkg_guard.go`).

| Build | Tags | Key generation |
| --- | --- | --- |
| `runner-azure`, `runner-aws`, `runner-gcp`, `runner-dev` and the debug builds | their usual tags, no peer tag | none |
| `runner-<cloud>-dkg-<peers>` | the platform, `peerselect`, `peer_<p>` for each peer | yes, with those verifiers |
| `runner-dev-dkg-dev` | `platform_dev,peerselect,peer_dev` | yes, dev verifier only (local tests) |

`scripts/build-runner.sh` takes `PEERS` (default `azure aws gcp`, the
three-cloud cluster) and writes `runner-<cloud>-dkg-<sorted peers>.peers`
next to each such binary (peer set and tags). The image scripts take
`IMAGE_PEERS` and put the peer set in the image name
(`signer-cloud/azure-runner-dkg-aws-azure-gcp:poc`,
`signer-cloud/runner-enclave-dkg-aws-azure-gcp:<arch>`, output folder
`build/nitro-dkg-aws-azure-gcp`). `scripts/check-deps.sh` checks every build:
the Nitro verifier's CBOR parser (`fxamacker/cbor`, `x448/float16`) only with
`platform_aws` or `peer_aws`, and off the AWS platform only imported by
`github.com/lidofinance/tee-signer/attestation-verify`; key generation packages only in peer builds;
`attestation-verify/azureid` only with `peer_azure`.

A runner whose policy names a verifier it was built without stops at start:
`dkg policy: participant 3 (op3): verifier "aws-nitro" is not built into this
runner`.

## Policy

A runner serves key generation only with `-dkg-policy FILE`:

```json
{"version": 1, "threshold": 2, "participants": [
  {"name": "op1-azure", "operator_key": "<64 hex>",
   "attestation": {"verifier": "azure-maa", "maa_host": "...", "cce_policy_sha256": "..."}},
  {"name": "op2-aws", "operator_key": "<64 hex>",
   "attestation": {"verifier": "aws-nitro", "nitro_pcrs": {"0": "...", "1": "...", "2": "...", "3": "..."}}},
  {"name": "op3-gcp", "operator_key": "<64 hex>",
   "attestation": {"verifier": "gcp-cs", "gcp_image_digest": "...", "gcp_audience": "...", "gcp_hwmodels": ["GCP_INTEL_TDX"],
                   "gcp_project_id": "...", "gcp_service_account": "..."}}],
 "setup": {"path": "charon", "withdrawal_address": "0x...", "deposit_amounts_gwei": [32000000000],
           "charon_enrs": ["enr:...", "enr:...", "enr:..."]}}
```

- Participant i (from 0) holds the shares at x = i+1: the operator at index
  i of a Charon lock, Dirk participant i+1.
- `attestation` uses the settings of `attestation-verify/runnerclient`. Each peer's
  hello must pass the settings of its position. For a runner with a setup
  that includes `setup_sha256`, the hash of the setup its operator built:
  a hello with another setup is refused, and so is a runner with a setup
  that no pin names. Runners on the flag path (no setup) need no pin.
- Account binding, refused without it: `gcp-cs` needs `gcp_project_id` (new
  verifier setting, checked against `submods.gce.project_id`) and
  `gcp_service_account`; `aws-nitro` needs PCR3 (the parent instance's IAM
  role; its ARN holds the AWS account). MAA tokens of Azure confidential
  containers carry no subscription or resource group claim (Microsoft's
  SEV-SNP claim set), so for Azure the operator key below is the binding.
- `operator_key`: the runner's operator key, read with
  `dkg-coordinator operator-keys`. Each runner makes it once and keeps it
  sealed; on the clouds the sealing key comes from the operator's own KMS key
  or Key Vault and is released only to the attested image, so only that
  operator's runner reports it. Every hello carries it, every runner checks
  each position's key, and a runner whose own key is not the one for its
  position refuses to deal.
- The threshold must be more than half of n; n is 2 to 10. On a chain with
  mainnet's genesis fork version it must also leave a margin, 2t - n >= 2
  (3 of 4, 4 of 5): two signing sets overlap in 2t - n signers, and one
  failed mark plus a hostile gateway must not make a slashable pair (issue
  #5 R1; `setupwire.CheckThreshold`, applied to DKG orders, to the runner's
  `-dkg-policy` and to sealed imports). Other chains allow 2-of-3. The dev
  verifier works only on the dev platform; `gcp_jwks_file` is refused.
- `setup` (optional): `path` is `dirk` (deposits) or `charon` (deposits,
  builder registrations, the lock hash). `compounding` defaults to true
  (0x02, invariant 11). The Charon path needs `charon_enrs`, one per
  position.
- The policy hash is SHA-256 of `signer-dkg-policy-v1` and the file bytes.
  Every runner of a cluster loads the same file, and refuses hellos with
  another hash.

The policy file is for runners on the flag path (no setup). A runner with a
setup refuses `-dkg-policy` and takes DKG orders instead.

## DKG orders (runners with a setup)

threshold-signer-poc `research/setup-phase.md`, section 10. A DKG order replaces the
policy file for a runner with a setup (`governance/dkgorder`, the runner's side
in `tee-signer/keygen/orders.go`):

- k approvers in force sign it under `signer-dkg-order-v1`, as they sign a
  config update. It names the cluster (`cluster_id`, chain hash), a label,
  the path (`dirk` or `charon`), the threshold, `not_after`, and for each
  participant its name, `setup_sha256`, operator key, verifier and settings
  (the image as in the allowed-images list: PCR0 to PCR2, the CCE policy
  hash or the image digest; PCR3 and optionally PCR8 on Nitro; the MAA host
  and compliance status on Azure; audience, hwmodels, issuer, service
  account and project on GCP; nothing for dev). The Charon path adds one
  ENR per participant. It is a fixed binary form with a strict decoder and
  a human form for approvers (`signer-config show`), like the setup.
- Withdrawal credentials and deposit amounts are not in it: the runner takes
  them from its locked group in force at each setup signature (0x01 or 0x02
  credentials; amounts of 1 ETH to 32 ETH, or 2048 ETH with 0x02).
- The relay pushes it with `DKG_ORDER` (0x27). The runner checks that the
  order is for its cluster and chain, names its own setup with its own
  operator key, carries k signatures of the approvers in force, names only
  images on the allowed list in force and only verifiers built in (dev only
  on the dev platform), and that `not_after` comes after it acts. It keeps
  the order sealed in its store (`dkg/orders/<hash>`) with the arrival time
  on the trusted clock and answers the order's state: pending, active,
  expired or void, with arrival, act time and `not_after`. Pushing it again
  answers "known" and keeps the arrival.
- Peer key sets on Nitro. The azure-maa and gcp-cs verifiers fetch key sets
  over HTTPS: the MAA host's `/.well-known/openid-configuration` and
  `/certs`, and for Google's issuer
  `confidentialcomputing.googleapis.com` and `www.googleapis.com`. A Nitro
  enclave reaches only the routes of its setup, so the setup lists these
  hosts in `keygen_peer_attestation_hosts` (`governance/setupwire`), and the parent
  starts a vsock-proxy for each on ports 8010 to 8025 (`hostagent
  -proxy-routes`). A Nitro runner refuses an order, when it arrives and at
  each use, if a peer's verifier needs a host its setup does not list, and
  names every such host (`runnerclient.Attestation.Endpoints`). Azure and
  GCP runners reach the hosts directly and check nothing here; a dev runner
  whose setup lists `keygen_peer_attestation_hosts` is limited to them like Nitro, for
  tests. A gcp-cs issuer other than Google's names its key set host only
  in its openid-configuration, so the check covers the issuer alone.
- The order acts once its wait from the arrival has passed: the time lock in
  force at arrival, and at least the images minimum time lock (7 days),
  which no config lowers. On the dev platform, which protects nothing, the
  wait is the time lock alone. IDENTITY's order slot shows the order that
  acts last while any waits.
- Every key generation message of an order travels in a `DKG_IN_ORDER`
  (0x28) envelope with the order's hash: HELLO, DEAL, FINISH, COMMIT, ABORT
  and SETUP_SIGN. Each order has its own manager and session, so one runner
  serves the Dirk fork lanes and the Charon lane at once. A hello carries the
  order's hash where a policy hash was; peers check each hello's
  `setup_hash` against the order (and the verifier pins it too).
- At each use the order must still be in force: k signatures of the set in
  force, and that set must be the one in force at arrival, whose hash the
  record keeps. After any change of the set (a rotation, one key replaced,
  k changed) the order is void until it is pushed again with k signatures
  of the new set over the same body, which keeps its hash and counts as a
  new arrival with a new wait,
  every image still on the allowed list, HELLO before `not_after`. Setup
  signatures for the keys an order made go on after `not_after`.
- Key records carry the order's hash and path; setup signing under one order
  takes only its own keys.
- A runner with a setup answers plain DKG_HELLO and the other plain messages
  with UNSUPPORTED.

## Messages

| Message | Type | Request | Runner does | Answer |
| --- | --- | --- | --- | --- |
| DKG_OPERATOR | 0x25 | nonce | (any time) its operator key, attested over the nonce and the key | key, identity |
| DKG_HELLO | 0x20 | relay nonce (16 to 64 bytes), validator count (1 to 64) | ends any session; makes a session HPKE key (ML-KEM-768 + X25519) and an Ed25519 key; attests them with its operator key and the policy hash | hello |
| DKG_DEAL | 0x21 | n hellos | finds its own hello and checks its operator key is its position's; checks every other hello: same policy hash, nonce and count, operator key of that position, attestation binds the hello, the position's verifier accepts it, no session key repeats. Per validator: a random polynomial of degree t-1, commitments, each peer's share sealed to its session key | deal, signed |
| DKG_FINISH | 0x22 | n deals | per dealer: session, position, threshold, count; own deal unchanged; signature; commitments in G1; one sealed entry per peer; Feldman check of its own share. Adds the shares, derives keys and public shares, checks its own. Stores the shares sealed as pending | result, signed confirmation |
| DKG_COMMIT | 0x23 | n confirmations | all signatures valid and the same transcript and result: seals each share as an import would, loads it, writes a key record | keys it holds |
| DKG_ABORT | 0x24 | empty | ends the session in memory | empty |
| DKG_SETUP_SIGN | 0x26 | kind and the full message | see "Setup signatures" | signature(s) |

The types sit in `signer-protocol/dkgmsg`, not in package `wire`: the runner links
`wire` into every build, and one more file there would change the bytes of
every runner binary.

Hello, as attested: policy hash, relay nonce, count, 32 random bytes of the
runner, the session Ed25519 key, the operator key, and an IDENTITY with the
session HPKE key. The attestation binds `DKGHelloUserData(AttestNonce(hello),
identity)`: the IDENTITY layout under its own context `signer-dkg-hello-v1`,
so an IDENTITY answer for the same nonce does not pass for a hello.
`AttestNonce` hashes every hello field. The runner also checks that binding
itself, since the dev verifier does not.

The DKG_OPERATOR answer binds `DKGOperatorUserData(AttestNonce(answer),
identity)` the same way, under `signer-dkg-operator-v1`: IDENTITY answers
any nonce a signing or attest-only client sends, so under IDENTITY's
context a client could get an "operator key" of its choice attested. The
coordinator's `operator-keys` and signer-admin's `dkg-draft` check it with
the operator verifier (runnerclient `NewDKGOperatorVerifier`).

Shares: per recipient one HPKE message (info `signer-dkg-share-v1`); the
associated data is the session ID, both share IDs and the hash of the
dealer's commitments. Transcript hash: the session ID and the SHA-256 of
each deal as received. A confirmation signs session, transcript hash,
result hash and share ID.

## Abort and restart

- Any bad hello or deal ends the session: memory wiped, nothing stored, the
  refusal names the participant or dealer.
- A session lives in memory only, 10 minutes at most from HELLO to FINISH. A
  new HELLO or a message out of order ends it.
- From FINISH on the shares wait sealed in `dkg/pending/<session>`, so a
  runner restarted before COMMIT still commits.
- A confirmation with a bad signature changes nothing; a validly signed one
  of another transcript drops the pending shares for good.
- Without every confirmation no runner keeps a share (a rogue dealer leaves
  no key anywhere).

## Setup signatures (DKG_SETUP_SIGN)

Only for keys this runner generated under the loaded policy and still
holds, only while their setup is open, and only after checking the full
message. The runner computes each signing root itself (invariant 2).

| Kind | Checks | Signs |
| --- | --- | --- |
| deposit | withdrawal credentials are the policy's; amount is one of the policy's | `DepositMessage` under `DOMAIN_DEPOSIT`, the chain config's genesis fork version, zero genesis validators root |
| builder registration (Charon path) | through the signer core: pubkey, fee recipient allowlist, gas limit range, timestamp | `ValidatorRegistrationV1` under `DOMAIN_APPLICATION_BUILDER` |
| Charon lock (Charon path) | the whole `cluster-lock.json`: version v1.11.0; threshold and operator count of the policy; no creator, no operator address or EIP-712 signature; each operator's ENR is the policy's for that position; fork version is the chain's genesis fork version; compounding and every withdrawal address are the policy's; every fee recipient in the allowlist; deposit amounts in the policy; the three hashes recompute; public shares lie on one polynomial and are this runner's key records in order; every key of the session is in the lock and nothing else; deposit and registration signatures verify, gas limits in range | the lock hash it computed, once with each share; answers the lock hash and one signature per key |

Setup closes for a key after the lock signature (Charon) or once every
deposit amount of the policy is signed (Dirk). The record of that is sealed
in the host's store, so a host that rolls the store back reopens it and can
get the same signatures again; it is not a rollback-proof guarantee.

## What is stored

| Key | Sealed content |
| --- | --- |
| `operator/key` | the operator key's seed |
| `dkg/pending/<session>` | state, hashes, result, the participants' Ed25519 keys, policy hash; the shares until commit or abort |
| `shares/<pubkey>` | the share, as for an imported share (loaded at start) |
| `dkg/keys/<pubkey>` | session, transcript, policy hash, threshold, own share ID, all public shares, setup state; for an order its hash and path |
| `dkg/orders/<hash>` | a DKG order as received, its arrival and act time, the hash of the approver set in force at arrival (record version 2; a version 1 record has none and its order is void until pushed again) |

No share is logged or put on a command line; the tests look for every share
in logs and storage and find none.

## Coordinator

```
dkg-coordinator operator-keys -config pre.json                   # attested operator key of each runner
dkg-coordinator push-order    -config c.json [-wait 30s]         # runners with a setup: the signed order
dkg-coordinator keygen        -config c.json -count 4            # dkg-result.json
dkg-coordinator deposits      -config c.json -result dkg-result.json -fork-version 00000000 -network-name mainnet
dkg-coordinator accounts      -result dkg-result.json -endpoints dirk1:9091,dirk2:9091,dirk3:9091
dkg-coordinator charon-lock   -config c.json -result dkg-result.json -cluster cluster.json
dkg-coordinator charon-shims  -config c.json -result dkg-result.json -chain chain.json
charon-node-sign -lock cluster-lock.json -key .charon/charon-enr-private-key   # on each Charon node
```

For runners with a setup the config names the signed order in place of
the policy, and the locked group the setup commands take the credentials
and amounts from (the signers' binary setup, or the locked update in force):
`{"order": "dkg.order", "locked": "signer-1.setup", "runners": [...]}`.
`check-deposits` takes `-order` and `-locked` the same way. threshold-signer-poc
`signer-config dkg-draft`, `sign`, `assemble` and `push` make and send the
order.

It connects to each runner over mutual TLS with `attestation-verify/runnerclient` and
the policy's attestation settings for that position, checks every hello
before any runner deals, and checks every partial signature under the
runner's public share and every combination under the validator key. It sees
no share and is not trusted.

- `deposits` writes `deposit-data.json` in the staking deposit CLI's format,
  each signature combined from the runners' partials.
- `check-deposits -config c.json` checks deposits, or a lock's, before
  anyone sends them. The result file is the coordinator's, so it asks the
  runners too: each one, attested with the policy's settings for its
  position, must answer the operator key the policy pins there and hold
  every key of the result with the share at its position. A consistent
  result of keys that no runner holds, with deposits signed under them, is
  refused (TKGARTIFACT-01). It needs the runners online and the admin
  client certificate, as the other commands do.
- `accounts` writes `accounts-<id>.json` per participant: the accounts file
  of the Dirk fork's TEE backends and of the signer shim (validator key,
  that participant's share key, every participant's share key, threshold).
- `charon-lock` builds the lock from `cluster.json` (name, fork version, fee
  recipient, gas limit, registration timestamp), the policy (withdrawal
  address, compounding, ENRs) and the result; gets deposits and
  registrations as threshold signatures, then every runner's signature over
  the lock hash, and aggregates them into `signature_aggregate`.
- `charon-node-sign` (module `charonnode`) runs on each Charon node: it
  checks the lock, finds the operator whose ENR is its key, and adds its
  secp256k1 signature over the lock hash. The node's key stays on the node.
- `charon-shims` writes per node `shim.yml`, `cloud.json` (that node's
  runner, with the policy's attestation settings and 8 connections, as in
  the Dirk forks' `cloud.json`) and `accounts.json`, for threshold-signer-poc
  `gateway/cmd/signer-shim` built with `-tags shim,dirkfork,cloudremote`.
  With one connection the selection proofs at each epoch start queue
  behind each other.

## Not done yet

- Key generation is not tested on the clouds. The tests use the dev
  platform, and a dev runner whose setup lists
  `keygen_peer_attestation_hosts` plays the Nitro egress limit ("DKG orders"
  above).
- For a gcp-cs issuer other than Google's, the endpoint check covers the
  issuer host only: its key set host is known from its openid-configuration
  alone.
- On the flag path the policy is agreed by hash and pinned operator keys,
  not signed by approvers. Runners with a setup take approver-signed DKG
  orders.
- Setup closure lives in host storage (rollback reopens it).
- The Dirk fork has not loaded generated keys yet (the accounts file format
  is the one `dirk-fork/backends/accounts` reads).
