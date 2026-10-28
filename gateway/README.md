# gateway

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The gateway serves the Web3Signer eth2 signing API (EIP-3030) to a validator client and signs through the TEE signers of this repo. It talks to each signer directly over mutual TLS and combines their partial signatures into the validator signature. It holds no key and keeps no slashing state: each signer checks every message and applies its own slashing protection and policy.

```
validator client --HTTP (Web3Signer API)--> gateway --mutual TLS 1.3--> signer 1 (TEE runner)
                                                                    +-> signer 2
                                                                    +-> signer 3
```

Module path `github.com/lidofinance/tee-signer/gateway`. The request parsing is the [web3signer-api](../web3signer-api) module, the connection to a signer is [attestation-verify/runnerclient](../attestation-verify/runnerclient), and the wire messages are [signer-protocol](../signer-protocol).

## How a request is signed

1. The gateway parses the body with `web3signer-api`. It computes the domain from its pinned chain and the signing root from the full message, and refuses a body that does not parse or names another chain (400).
2. Its own policy runs: no voluntary exits, and registrations only for allowlisted fee recipients (412).
3. It turns the request into the typed message of the signers' `SIGN` (attestation data, block header, aggregate SSZ and so on) and sends it to every signer that holds a share of the key, all at once.
4. Each signer computes the signing root from the typed message with its own chain config, refuses a domain that differs from its own, applies slashing protection and policy, and returns a partial signature.
5. The gateway checks each partial signature against the share key that signer listed and the root the gateway computed. As soon as a threshold of them pass, it combines them (Lagrange interpolation at zero with the share indices), checks the result against the validator key, and returns it.
6. It stops waiting as soon as the threshold is in or out of reach. A refusal by the signers is a 412; signers that failed, timed out or sent a partial that does not verify are a 500. The calls to the other signers go on until the request's deadline, so every signer sees every request.

Every new connection to a signer goes through all of `runnerclient`'s checks before a request goes on it:

- TLS 1.3 with the gateway's client certificate, which the signer's `-tls-client-ca` must accept;
- the signer's certificate: a testnet build is refused unless `allow_testnet_build` is set, and its chain mark must agree with `attestation.mainnet`;
- `IDENTITY` with a fresh nonce over the new channel, and the attestation document checked by its verifier (`dev`, `azure-maa`, `aws-nitro` or `gcp-cs`) with the setup pins (`setup_sha256`, the minimum config versions, `key_release_sha256`);
- the TLS key the signer presented must be the one its attested identity names, and `tls_key_pin` if set.

A connection that fails a check takes no request. The gateway keeps `signers.connections` connections to each signer (default 2) and uses one per request at a time. After an I/O error or a timeout a connection is closed, and the next request on that slot dials a new one with every check again; a restarted signer has a new TLS key and a new identity, so this is how the gateway notices. A request whose connection the signer closed under it goes once more on a new connection: a signer signs an exact repeat of an attestation or block again with the same signature.

## Keys, shares and the threshold

The gateway asks each signer for `PUBLIC_KEYS`: the validator keys it holds a share of, and the share's public key. It groups the answers by validator key. The share index of each share and the threshold come from the public keys alone: the gateway looks for the smallest threshold t, and distinct indices from 1 to `signers.max_share_index` (default: the number of signers), for which every t of the share keys interpolate to the validator key. With those indices any t partial signatures combine into the validator's signature, so the signers can be listed in any order. A key whose shares fit no threshold and no indices is not served, and the gateway logs `key refused` once.

The list is loaded at start (retried for a minute while the signers start). A request that finds it older than 30 s loads it again first, so keys the signers get later show up without a restart. One load runs at a time, and a failed one keeps the old list. A signer that does not answer a load keeps its last answer, so its share stays in the group and the others still sign.

## API

| Endpoint | Response |
|---|---|
| `GET /upcheck` | `200`, `text/plain; charset=utf-8`, body `OK` |
| `GET /api/v1/eth2/publicKeys` | `200`, JSON array of validator public keys, `0x` lowercase hex |
| `POST /api/v1/eth2/sign/{identifier}` | `200` with the signature, or an error below |

The sign response follows Web3Signer's `Eth2SignForIdentifierHandler` (checked against tag 26.9.0). If any `Accept` entry is `application/json` or `*/*`, the body is `{"signature":"0x..."}` with `application/json; charset=utf-8`. Otherwise, including no `Accept` header at all, the body is the bare `0x...` hex with `text/plain; charset=utf-8`. curl sends `Accept: */*` by default and so gets JSON.

Errors use Web3Signer's JSON shape, `{"code":<status>,"message":"..."}`:

| Status | When |
|---|---|
| 400 | Malformed body, unknown or unsupported `type`, a `signingRoot`/`signing_root` that differs from the root computed from the data, or a `fork_info` that disagrees with the pinned chain (another `genesis_validators_root`, a fork not in the schedule, or a fork version the schedule does not give for the message's epoch); the gateway log names the reason |
| 404 | The identifier is not a key the signers hold |
| 412 | Gateway policy refused, or signers refused (slashing protection, their policy, another domain) and the threshold was out of reach |
| 500 | Too few signers answered with a partial signature that verifies, before `signers.timeout` |

The `identifier` may come with or without `0x`, in any case.

## Request types and signer messages

| Web3Signer type | Signer message (`SIGN` kind) | Domain | Checked by the signer |
|---|---|---|---|
| `ATTESTATION` | `attestation` | `DOMAIN_BEACON_ATTESTER` at target epoch | slashing protection |
| `BLOCK_V2` (all versions; PHASE0/ALTAIR full blocks are reduced to a header) | `block` | `DOMAIN_BEACON_PROPOSER` at block slot | slashing protection |
| `RANDAO_REVEAL` | `root` (RANDAO, epoch and object root) | `DOMAIN_RANDAO` | the root is `hash_tree_root(epoch)` |
| `AGGREGATION_SLOT` | `selection_proof` | `DOMAIN_SELECTION_PROOF` | clock |
| `AGGREGATE_AND_PROOF`, `AGGREGATE_AND_PROOF_V2` (PHASE0 to GLOAS; an object without `version` is phase0 unless its aggregate has `committee_bits`, then Electra, which is what Lighthouse and Teku send; from `chain.gloas_fork_epoch` on, an aggregate with `committee_bits` hashes as the Gloas one, a progressive Attestation, and an explicit version that disagrees with the aggregate's epoch is a 400) | `aggregate_and_proof` (SSZ, form phase0, Electra or Gloas) | `DOMAIN_AGGREGATE_AND_PROOF` | aggregator index, selection proof under the validator key, form of the epoch |
| `SYNC_COMMITTEE_MESSAGE` | `sync_committee_message` | `DOMAIN_SYNC_COMMITTEE` | clock |
| `SYNC_COMMITTEE_SELECTION_PROOF` | `sync_selection_proof` | `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` | clock |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | `contribution_and_proof` (SSZ) | `DOMAIN_CONTRIBUTION_AND_PROOF` | aggregator index, selection proof |
| `VALIDATOR_REGISTRATION` | `validator_registration` | `DOMAIN_APPLICATION_BUILDER`, genesis fork version, zero root | fee recipient, gas limit, timestamp; the gateway's allowlist first |
| `VOLUNTARY_EXIT` | none, refused by gateway policy (412) | | |
| `PAYLOAD_ATTESTATION_MESSAGE`, `PAYLOAD_ATTESTATION` (Gloas PTC vote) | `payload_attestation` | `DOMAIN_PTC_ATTESTER` at the slot's epoch | one vote per slot |
| `EXECUTION_PAYLOAD_ENVELOPE` (Gloas, self-built only) | `payload_envelope` (payload as a summary: variable fields as roots) | `DOMAIN_BEACON_BUILDER` at the slot's epoch | own block, fee recipient, one envelope per slot |
| `PROPOSER_PREFERENCES` (Gloas) | `proposer_preferences` | `DOMAIN_PROPOSER_PREFERENCES`, fork version of the proposal epoch | index, fee recipient, gas limit |
| `BUILDER_REQUEST_AUTH` (builder-specs Gloas, `{"version":"GLOAS","data":{"data":"0x..","slot":".."}}`, no `fork_info`; data of 1 to 4096 bytes, more is a 400) | `builder_request_auth` | `DOMAIN_BUILDER_REQUEST_AUTH` (0x0B000001), genesis fork version, zero root | data root on the setup's allowlist |
| `EXECUTION_PAYLOAD_BID` | none, refused (412) | | validators never sign bids |
| `DEPOSIT`, `BLOCK` (v1) | none, 400 unsupported | | |

No type goes to the signers as a bare root they cannot check. RANDAO is a root message, and the signer checks that root against the epoch.

The gateway pins its chain: `chain.genesis_validators_root` and the fork schedule (`chain.genesis_fork_version` plus `chain.forks`) in its config. It computes every domain from that schedule at the message's epoch and refuses (400) a request whose `fork_info` names another `genesis_validators_root`, a fork that is not a schedule entry with its predecessor as `previous_version`, or a fork version other than the schedule's for that epoch. One more `fork_info` passes: the genesis state's fork of a chain that starts at a later fork, whose previous and current version are both the version at epoch 0 (some clients send that for a chain that starts at Fulu; others send the previous fork's version, which the schedule rule already accepts). So a client cannot get a signature under another chain's domain through the gateway; Web3Signer itself builds the domain from `fork_info`. The signers check the domain again against their own chain config.

The Gloas types need `chain.gloas_fork_epoch`; without it, or for an epoch before it, policy refuses them (412). For `PROPOSER_PREFERENCES` the domain uses the fork version of the proposal epoch (`validator.md`), so preferences for the first Gloas epoch, signed while `fork_info` still names Fulu, get the Gloas version; `fork_info` must still name the chain. For an envelope the gateway hashes the whole payload, builds the summary the signers take and checks that the summary gives the same root. `BUILDER_REQUEST_AUTH` authenticates a validator's requests to an external builder. It never reaches the chain and is not slashable. Its slot must be at or past `chain.gloas_fork_epoch`, and the gateway hashes it as go-eth2-client v0.30.3 does (a plain container as in builder-specs, data as `ByteList[4096]`). The gateway passes any data on; each signer decides which data it signs.

## Coalescing

Some clients send the same request several times at once. Grandine 2.0.6 sends each sync committee selection proof once per committee seat, 5 to 6 copies a slot at 100 validators. The gateway sends one copy to the signers and gives the others its answer (`internal/coalesce`).

- Types: `RANDAO_REVEAL`, `AGGREGATION_SLOT`, `AGGREGATE_AND_PROOF` and `_V2`, `SYNC_COMMITTEE_MESSAGE`, `SYNC_COMMITTEE_SELECTION_PROOF`, `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF`. None is slashable, and the BLS signature over one root never changes. Every attestation, block, exit, registration and Gloas request still goes to the signers.
- Two requests share when they have the same validator key, the same type and the same signing root, which the gateway computes from the full message. Aggregates and contributions therefore share only when their content is identical.
- A request that arrives while the same call is in flight waits for that call. One that arrives within `coalesce.cache_slots` slots (default 2) after the call succeeded gets the stored signature. The gateway stores only a signature that passed its checks, never an error or a refusal.
- The shared call has its own timeout, so a client that hangs up does not fail the others.
- The gateway hands out only a signature the signers already gave for that key and root.

The request that made the call logs `signer_ms` on its `signed` line. A request that waited for it logs `coalesced=true` instead, and one that got a stored signature logs `cache_hit=true`. `total_ms` stays what each client waited. At start the gateway logs `msg=coalesce` with its settings.

To turn it off, set `coalesce.enabled: false` and restart the gateway. `cache_slots: 0` keeps the sharing of calls in flight and stores nothing. The chain pin has no slot time, so `chain.seconds_per_slot` (default 12) turns slots into seconds.

## Policy

- `VOLUNTARY_EXIT` is never signed.
- `VALIDATOR_REGISTRATION` is signed only when `fee_recipient` is in `policy.fee_recipient_allowlist` and `pubkey` equals the key in the URL.

Both are refused with 412 and a message naming the rule, before any signer is contacted. The signers apply their own policy on top.

## Configuration

`gateway -config gateway.yml`:

```yaml
listen: 127.0.0.1:19000
# metrics: 127.0.0.1:19001        # Prometheus endpoint, see Metrics; absent: off
chain:
  preset: mainnet                 # mainnet or minimal; sets SSZ list limits and slots per epoch
  genesis_fork_version: "0x00000000"   # first entry of the fork schedule; also for VALIDATOR_REGISTRATION
  # slots_per_epoch: 32           # optional override
  # Required: the chain the gateway signs for.
  genesis_validators_root: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
  forks:                          # in epoch order; several may share an epoch (devnets)
    - {epoch: 74240, version: "0x01000000"}    # Altair
    - {epoch: 144896, version: "0x02000000"}   # Bellatrix
    - {epoch: 194048, version: "0x03000000"}   # Capella
    - {epoch: 269568, version: "0x04000000"}   # Deneb
    - {epoch: 364032, version: "0x05000000"}   # Electra
    - {epoch: 411392, version: "0x06000000"}   # Fulu
  # gloas_fork_epoch: <epoch>     # GLOAS_FORK_EPOCH, the epoch of one of forks; absent: Gloas types refused
  # seconds_per_slot: 12          # SECONDS_PER_SLOT, default 12; only coalescing uses it
# coalesce:                       # optional, see Coalescing
#   enabled: true                 # default; false sends every request to the signers
#   cache_slots: 2                # default; 0 shares calls in flight only
signers:
  client_cert: gateway.pem        # client certificate of the signing role, with its chain
  client_key: gateway-key.pem
  # cert_reload_interval: 10s     # how often both files are read again for a renewed pair
  # timeout: 5s                   # one sign request, and each key list call
  # dial_timeout: 30s             # each new connection: TCP, TLS, IDENTITY, attestation check
  # connections: 2                # connections to each signer, 1 to 16
  # max_share_index: 3            # highest share index tried; default: the number of signers
  nodes:
    - name: azure
      address: tcp:203.0.113.10:7000
      attestation:
        verifier: azure-maa
        maa_host: sharedweu.weu.attest.azure.net
        cce_policy_sha256: "<64 hex digits>"
        setup_sha256: "<64 hex digits>"
        key_release_sha256: "<64 hex digits>"
        mainnet: true
    - name: aws
      address: tcp:203.0.113.20:7000     # the forwarder on the parent instance; TLS ends in the enclave
      attestation:
        verifier: aws-nitro
        nitro_pcrs: {"0": "<96 hex digits>", "1": "<96 hex digits>", "2": "<96 hex digits>"}
        setup_sha256: "<64 hex digits>"
        key_release_sha256: "<64 hex digits>"
        mainnet: true
    - name: gcp
      address: tcp:203.0.113.30:7000
      attestation:
        verifier: gcp-cs
        gcp_image_digest: "sha256:<64 hex digits>"
        gcp_audience: signer-runner-identity
        gcp_hwmodels: [GCP_INTEL_TDX]
        setup_sha256: "<64 hex digits>"
        mainnet: true
      # tls_key_pin: "<64 hex digits>"   # optional; the key changes at every start of the signer
      # allow_testnet_build: false
policy:
  fee_recipient_allowlist: ["0x1111111111111111111111111111111111111111"]
```

The `attestation` settings of each signer are those of `runnerclient.Attestation`, under the same names; [attestation-verify/runnerclient/runnerclient.go](../attestation-verify/runnerclient/runnerclient.go) says what each one checks. Settings of one verifier are refused with another, and a required one that is missing stops the start. Quote map keys such as the `nitro_pcrs` indices. A local dev runner takes `attestation: {verifier: dev}`, which proves nothing about the code that answered.

Relative paths in the file resolve against the file's directory. The gateway refuses to start without `chain.genesis_validators_root`, with fork epochs out of order, without signers or a client certificate, and with an unknown key anywhere in the file. A new fork needs a config line before its epoch, as it does in the beacon node and in the signers.

## Client certificate renewal

The client certificate is short-lived, so the gateway picks up a renewed one without a restart. It reads `signers.client_cert` and `signers.client_key` at start, where a pair that fails the checks below stops the start, and again every `signers.cert_reload_interval` (default 10s). A pair that changed takes effect only if it parses, the key belongs to the certificate, and the certificate is valid at the gateway's clock. Otherwise the pair in force stays, and the gateway logs `client certificate on disk refused, keeping the one in force` once for that content, not at every read. A certificate that is not valid yet is checked again at each read and takes effect once it is. Write the new files to temporary names and rename them over the old ones: a key written a read after its certificate costs one refused line and no outage.

A good new pair logs `client certificate reloaded` with its serial and expiry. New clients use it at once. The connections already open move to it in the background, one connection to each signer at a time: the gateway dials a new connection with the new certificate, runs every check of a new connection on it (attestation, pins, chain mark, nonce), and only then puts it in the place of an idle connection on the old certificate and closes that one (`connection moved to the new client certificate`). Each signer keeps `signers.connections` connections throughout, and a request in flight ends on the connection it started on. A new connection that fails a check leaves the old one in place and is tried again 5 s later. A connection whose certificate expired before it could move (its signer was down, say) takes the new certificate at its next request.

If the certificate in force expires with no valid replacement on disk, the gateway logs `client certificate expired and no valid replacement on disk` once a minute, and every sign request fails: a 500 to the validator client, and a `signing failed` line whose `err` names the certificate file and its expiry. A valid pair written there ends it at the next read.

The expiry of the certificate in force and the result of each read are also in the metrics (see Metrics).

Each signing request leaves one log line (`msg=signed`, `"denied by signers"`, `"signing failed"`, `"bad request"`, ...). Once the body parses, the line carries the request `type` and the `signer_call`, the signer message it becomes; signed, denied and failed lines also carry `signer_ms`. The reasons of the signers that refused or failed are in the `err` of a denied or failed line. A partial signature that does not verify is logged on its own (`bad partial signature`, with the signer's name). Each attested connection logs `signer attested` with the signer's setup state.

## Metrics

With `metrics: HOST:PORT` in the config, the gateway serves Prometheus metrics at `GET /metrics` on that address: plain HTTP, the text format 0.0.4, and nothing else on that listener. Without `metrics` there is no endpoint. It has no TLS and no authentication, so bind it to loopback (`127.0.0.1:19001`) or to a monitoring network. The exporter is a small registry in `internal/metrics` on the standard library, so the gateway needs no Prometheus client module.

No label holds a public key or a value a client picks. `signer` is a name from `signers.nodes`, `type` is a Web3Signer request type the gateway parsed, and the other labels take the values listed here.

| Metric | Type | Labels | What it counts |
|---|---|---|---|
| `teesigner_gateway_client_cert_not_after_seconds` | gauge | | Unix time the client certificate in force expires |
| `teesigner_gateway_client_cert_not_before_seconds` | gauge | | Unix time it became valid |
| `teesigner_gateway_client_cert_reloads_total` | counter | `result`: `ok`, `refused`, `unchanged` | Reads of `client_cert` and `client_key`: a new pair swapped in, content refused (at every read until it changes), or the pair in force |
| `teesigner_gateway_client_cert_last_reload_timestamp_seconds` | gauge | | Unix time the pair in force took effect: the start or the last successful reload |
| `teesigner_gateway_signer_connections_up` | gauge | `signer` | Connections that passed every check and have not failed since |
| `teesigner_gateway_signer_dials_total` | counter | `signer`, `result`: `ok`, `failed` | New connections, with every check |
| `teesigner_gateway_signer_rotations_total` | counter | `signer`, `result`: `ok`, `failed` | Connections moved to a new client certificate; a failed move is tried again 5 s later |
| `teesigner_gateway_signer_attestation_failures_total` | counter | `signer`, `reason`: `tls`, `key_pin`, `identity`, `verifier` | New connections a check refused: `tls` the handshake (client certificate, build flavour, chain mark), `key_pin` the `tls_key_pin`, `identity` the `IDENTITY` exchange and its TLS key, `verifier` the attestation document and the setup pins |
| `teesigner_gateway_signer_requests_total` | counter | `signer`, `result`: `ok`, `refused`, `error`, `timeout` | Calls to the signer, `SIGN` and `PUBLIC_KEYS`; `refused` is an answer with a refusal (slashing protection, policy, not ready) |
| `teesigner_gateway_signer_keys_refreshed_timestamp_seconds` | gauge | `signer` | Unix time of the last key list the signer answered, 0 before the first |
| `teesigner_gateway_keys` | gauge | | Validator keys the gateway signs for |
| `teesigner_gateway_requests_total` | counter | `type`, `result`: `ok`, `unknown_key`, `policy`, `denied`, `error`, `timeout` | Sign requests whose body parsed. `policy` is the gateway's own rule, `denied` a refusal by the signers (both 412), `timeout` the end of `signers.timeout`. A body that does not parse has no type and is not counted |
| `teesigner_gateway_sign_duration_seconds` | histogram | `type` | Time from sending a request to the signers to the combined signature, for requests that signed; buckets from 5 ms to 10 s. A request that got a shared or stored signature (Coalescing) made no call and is not in it |
| `teesigner_gateway_combine_failures_total` | counter | `reason`: `bad_partial`, `below_threshold`, `verify` | Partial signatures that do not verify under their share key, requests that got too few good partial signatures before the deadline ran out of signers, and combined signatures that do not verify |

The gateway connects on demand and sends no probes, so the connection metrics show what the requests found. A connection counts as up from the first request on it. One the signer closed counts until the next request on it fails. A dial the request gave up on goes on in the background and is not counted. Each series of a signer exists with 0 from the start, so `increase()` sees the first event.

An alert for a client certificate that expires in under 2 days:

```yaml
groups:
  - name: tee-signer-gateway
    rules:
      - alert: GatewayClientCertExpiresSoon
        expr: teesigner_gateway_client_cert_not_after_seconds - time() < 2 * 86400
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "The gateway client certificate expires in {{ $value | humanizeDuration }}"
          description: "Renew signers.client_cert. If a renewed pair was written, see client_cert_reloads_total{result=\"refused\"} and the gateway log."
```

## Build and test

| Script | What it does |
|---|---|
| `scripts/build.sh` | Builds `bin/gateway` and `bin/blsverify`. Needs Go 1.26 and gcc (cgo for BLS). |
| `scripts/test-unit.sh` | `go vet` and `go test ./...`. |
| `scripts/update-spec-vectors.sh` | Regenerates the Web3Signer example vectors in `web3signer-api/signing/testdata` from the pinned Web3Signer tag. |

From the repo root, `scripts/test-modules.sh gateway` runs gofmt, vet and the unit tests under the race detector. The unit tests run the combining against fake signers (2 of 3, a signer down, a slow signer, a partial that does not verify, refusals, all down) and the connections against a fake TLS signer (attestation on every new connection, a wrong `tls_key_pin`, a wrong chain mark, an attestation without the nonce). The reload tests write good and bad pairs in random order and check that the last good one stays in force, and swap the certificate under load against fake signers that accept only the old certificate and then only the new one, with no failed request. The metrics tests check the text format and that each counter moves on its event: calls by result, dials, connections up, each attestation failure reason against the fake TLS signer, rotations, combine failures, request results and reload results.

`TestE2EGateway` in [tests/e2e](../tests/e2e) is the end-to-end test: three dev runners of `scripts/build-runner.sh` with mutual TLS, each with one share of a 2-of-3 key, and the gateway binary in front of them. It sends a validator client's HTTP requests (attestation, block, selection proof, aggregate), checks each signature under the validator key against the root the signer core computes, and checks a double vote, an aggregate with a bad selection proof, one signer down, two down, a new client certificate written mid-run while requests go on, and a signer that restarts with a new TLS key. It scrapes `/metrics` before and after the new certificate: 3 connections up to each signer, the requests by type and result, the expiry of the certificate in the file, one reload and 3 connections moved per signer:

```sh
scripts/build-runner.sh
cd tests && RUNNER_BIN="$PWD/../build/x86_64/bin/runner-dev" go test -race -count=1 -v -run TestE2EGateway ./e2e
```

## Code

```
cmd/gateway          main: config, signers, HTTP server, metrics listener
cmd/blsverify        independent verifier: hand-written SSZ on crypto/sha256 + blst
internal/config      gateway.yml: defaults, required keys, chain pin and fork schedule, signers
internal/backend     the signers: connections (runnerclient), typed messages, share indices, fan-out, combining
internal/certreload  the client certificate in force: reads it again, checks a new pair, swaps it in
internal/metrics     Prometheus registry and text format, and the gateway's metrics
internal/policy      exit and registration rules
internal/server      HTTP handlers, content negotiation, error bodies
internal/coalesce    one call to the signers for identical non-slashable requests, results kept 2 slots
tools/specvectors    converts Web3Signer's OpenAPI examples to test vectors
```

`web3signer-api/signing/testdata/web3signer-26.9.0-sign-examples.json` holds the request examples from Web3Signer's OpenAPI spec (Consensys, Apache-2.0), converted to JSON.

BLS: the gateway checks and combines with `github.com/herumi/bls-eth-go-binary v1.36.1`; `cmd/blsverify` uses `github.com/supranational/blst v0.3.17`, the library of the signers' core. Request types come from `github.com/attestantio/go-eth2-client v0.30.3` (see `go.mod`).
