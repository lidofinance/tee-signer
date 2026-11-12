# gateway

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

The gateway lets a standard validator client sign through the TEE signers of this repo. It serves the Web3Signer eth2 signing API (EIP-3030) over HTTPS with client certificates, or plain HTTP on loopback, sends each request to every signer over mutual TLS, and combines their partial signatures into the validator signature. It holds no key and keeps no slashing state: each signer checks every message and applies its own slashing protection and policy.

```
validator client --HTTPS, client certificate--> gateway --mutual TLS 1.3--> signer 1 (TEE runner)
                  (Web3Signer API)                                     +-> signer 2
                                                                       +-> signer 3
```

**Not audited.** The gateway is a separate module; no runner imports it. It cannot get a signature the signers would refuse. A bug in it can only stop signing: the validator client gets an error instead of a signature.

Module path `github.com/lidofinance/tee-signer/gateway`. The request parsing is the [web3signer-api](../web3signer-api) module, the connection to a signer is [attestation-verify/runnerclient](../attestation-verify/runnerclient), and the wire messages are [signer-protocol](../signer-protocol).

## Run it

1. Build it: `gateway/scripts/build.sh` writes `gateway/bin/gateway`. It needs Go 1.26 and gcc.
2. Get a client certificate of the signing role for the gateway, with its chain, from the CA the signers trust (`-tls-client-ca`; see "Client roles" in [signer-protocol/docs/protocol.md](../signer-protocol/docs/protocol.md)). An attest-only or admin certificate does not sign.
3. If the validator client runs on another host or in another container, make a server certificate for the gateway and a client certificate for each validator client (see [TLS](#tls)).
4. Write `gateway.yml` (see [Configuration](#configuration)): the chain, the certificate, one entry per signer with its address and the attestation pins the signer must show, and `access` with the `tls` section if the API is not on loopback.
5. Start it: `gateway/bin/gateway -config gateway.yml`. It logs `signer attested` for each signer it reaches and `listening` with its address. `curl --cacert server-ca.pem --cert vc.pem --key vc-key.pem https://127.0.0.1:19000/api/v1/eth2/publicKeys` lists the validator keys it can sign for (`curl http://127.0.0.1:19000/...` without TLS).
6. Point the validator client at it (next section).

`access` decides who reaches the API (see [Access](#access)): plain HTTP on loopback by default, or `mtls` for any other address. Whoever gets in can ask for signatures; the signers still refuse anything slashable and anything their policy forbids, and the gateway refuses exits and fee recipients that are not on its allowlist.

## Point a validator client at it

Set the validator client's Web3Signer URL to the gateway's `listen` address, for example `https://gateway.example:19000`, or `http://127.0.0.1:19000` without TLS. For the client's certificate settings see [TLS](#tls). The client uses three endpoints: `GET /upcheck`, `GET /api/v1/eth2/publicKeys` and `POST /api/v1/eth2/sign/{pubkey}` (see [API](#api)).

Register each validator key with the client as a remote (Web3Signer) key at that URL, or let the client load the key list from `/api/v1/eth2/publicKeys` if it can. A key the signers do not hold gets a 404.

The signers hold the slashing protection. A validator client's own slashing protection database can stay on: it refuses on top of the signers, never instead of them. Do not run the same keys through another signer at the same time.

## Access

`access` sets how the API listener (`listen`) is exposed, and `metrics_access` the same for the metrics listener (`metrics`), with the same four values:

| Value | Protocol | Address | Who gets in | Needs |
|---|---|---|---|---|
| `local` | plain HTTP | loopback only | anything on the host | no `tls` section for `access` |
| `mtls` | TLS | any | clients with an accepted certificate | `tls.cert`, `tls.key`, and `tls.client_ca` or `tls.client_fingerprints` |
| `unsafe_open_tls` | TLS | any | anyone who reaches the port; no client certificate is checked | `tls.cert`, `tls.key`; for `access`, no `client_ca` or `client_fingerprints` |
| `unsafe_plain_http` | plain HTTP | any | anyone who reaches the port | no `tls` section for `access` |

`access` defaults to `mtls` when the `tls` section is set and to `local` otherwise. `metrics_access` defaults to `local`. Both listeners use the one `tls` section: the same server certificate and the same accepted clients. The `tls` section needs `access` to be `mtls` or `unsafe_open_tls`, so a TLS metrics listener goes with a TLS API listener.

A value that does not fit the rest of the config stops the start: `local` on an address other than loopback, `local` or `unsafe_plain_http` for `access` with a `tls` section, `mtls` without the server certificate or without accepted clients, `unsafe_open_tls` without the server certificate or, for `access`, with `client_ca` or `client_fingerprints`, an unknown value, and `metrics_access` without `metrics`. The two `unsafe_` values log a warning at start.

`access` refuses `unsafe_open_tls` and `unsafe_plain_http` when a signer can sign for mainnet: a signer with `attestation.mainnet: true`, or one without `allow_chain_build` (mainnet builds only). It refuses them too when `chain` is a prod chain: mainnet, or a chain with no non-prod row in `governance/setupwire/chains.go`. `metrics_access` still takes them; the metrics hold counts, times and signer names, no keys.

For a validator client on another host or in another container, use `mtls`. Keep `unsafe_open_tls` and `unsafe_plain_http` for a network that only the validator client, or only the monitoring, can reach.

## TLS

A listener with access `mtls` serves HTTPS, and every client must show a certificate the gateway accepts. Two settings name the accepted clients; at least one is required, and with both, either one lets a client in:

- `tls.client_ca`: a PEM bundle of CAs. A client certificate that chains to one of them is accepted if it allows client authentication (extended key usage `clientAuth`, or none at all). The client sends its intermediates.
- `tls.client_fingerprints`: SHA-256 fingerprints of client certificates, accepted whoever issued them (Web3Signer calls these known clients). A self-signed client certificate works here.

The certificate must be valid at the gateway's clock either way. A client without an accepted certificate fails the TLS handshake and gets no HTTP answer, and the gateway logs `TLS handshake error` with the reason. Plain HTTP to the TLS port gets a 400. A listener with access `unsafe_open_tls` asks for no client certificate.

The gateway takes TLS 1.3 only (`tls.min_version`, default `"1.3"`). Teku offers only TLS 1.2 to its external signer, so with Teku set `tls.min_version: "1.2"`. Clients that offer TLS 1.3 still get it, and TLS 1.2 uses ECDHE with AES-GCM or ChaCha20-Poly1305 only.

The gateway reads `tls.cert`, `tls.key` and `tls.client_ca` at start, where a bad file stops the start, and again every `tls.reload_interval` (default 10s). New files take effect for new and resumed connections once all of them parse, the key belongs to the certificate and the certificate is valid at the gateway's clock; the gateway then logs `server TLS files reloaded`. Otherwise the files in force stay, and it logs `server TLS files on disk refused, keeping the ones in force` once for that content. Write new files to temporary names and rename them over the old ones. A resumed TLS session passes the client check in force at the resumption, so a client the new `client_ca` no longer names cannot resume one. When a reload changes `tls.client_ca`, every `mtls` listener closes its open connections: an idle one at once, a busy one after its current request (`Connection: close`, or GOAWAY on HTTP/2), and the gateway logs `client CA changed`. For 30 s after that each connection serves one request, so every client reconnects and passes the new check; new connections are served throughout. The first request on an open connection after the change, a new HTTP/2 stream too, runs the client check again with the new files, and a client it refuses gets 403. Connections also close after 120 s without a request. Each listener allows 10 s for the request headers (64 KiB at most), 30 s to read the whole request, and 30 s plus twice `signers.timeout` until the response is written. A change to `tls.client_fingerprints` needs a restart. On SIGTERM or SIGINT the gateway stops taking new connections and gives requests in flight up to 5 s to finish.

The start line `server TLS` and each `server TLS files reloaded` line carry the certificate's `not_after`. While the certificate in force ends within 30 days, the gateway logs `server certificate expires in under 30 days` at start, at each reload and once a day, and the metric `teesigner_gateway_server_cert_not_after_seconds` holds its expiry.

### Make the certificates

With openssl 3. The server certificate must name the address the validator client uses, as a DNS name or an IP address (`subjectAltName`).

```sh
# Server CA and the gateway's certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=gateway server CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
  -keyout server-ca-key.pem -out server-ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=gateway" \
  -keyout server-key.pem -out server.csr
printf 'subjectAltName=DNS:gateway.example,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' >server.ext
openssl x509 -req -in server.csr -CA server-ca.pem -CAkey server-ca-key.pem -CAcreateserial -days 365 \
  -extfile server.ext -out server.pem

# Client CA and one validator client's certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=validator client CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
  -keyout client-ca-key.pem -out client-ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=validator client 1" \
  -keyout vc-key.pem -out vc.csr
printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n' >client.ext
openssl x509 -req -in vc.csr -CA client-ca.pem -CAkey client-ca-key.pem -CAcreateserial -days 365 \
  -extfile client.ext -out vc.pem

# The client's certificate and key as PKCS#12, for Lighthouse and Teku
openssl rand -hex 16 >vc.p12.pass
openssl pkcs12 -export -in vc.pem -inkey vc-key.pem -name validator-client -out vc.p12 -passout file:vc.p12.pass

# Its fingerprint, for tls.client_fingerprints instead of a client CA
openssl x509 -in vc.pem -noout -fingerprint -sha256
```

Then in `gateway.yml`:

```yaml
listen: 0.0.0.0:19000
access: mtls
metrics: 0.0.0.0:19001
metrics_access: mtls        # Prometheus with a client certificate, below
tls:
  cert: server.pem          # followed by its intermediates, if any
  key: server-key.pem
  client_ca: client-ca.pem
  # client_fingerprints: ["83:1A:D2:...:6E:95"]
```

Keep the CA keys off the gateway host. The gateway needs `server.pem`, `server-key.pem` and `client-ca.pem` only. Make one client certificate per client (each validator client, Prometheus) with the client CA commands above.

### Lighthouse

One entry per validator key in `validator_definitions.yml`. Lighthouse reads the client certificate as PKCS#12 only.

```yaml
- enabled: true
  voting_public_key: "0x..."
  type: web3signer
  url: "https://gateway.example:19000"
  root_certificate_path: /path/to/server-ca.pem
  client_identity_path: /path/to/vc.p12
  client_identity_password: "<the content of vc.p12.pass>"
```

### Teku

Teku offers only TLS 1.2 to its external signer, so set `tls.min_version: "1.2"` in `gateway.yml`; with the default `"1.3"` its handshake fails. Teku takes the gateway's CA as a PKCS#12 truststore. Make it with keytool, which comes with Java and with the Teku image:

```sh
openssl rand -hex 16 >truststore.pass
keytool -importcert -noprompt -alias gateway-ca -file server-ca.pem \
  -keystore truststore.p12 -storetype PKCS12 -storepass:file truststore.pass
```

```sh
teku validator-client ... \
  --validators-external-signer-url=https://gateway.example:19000 \
  --validators-external-signer-public-keys=external-signer \
  --validators-external-signer-keystore=vc.p12 \
  --validators-external-signer-keystore-password-file=vc.p12.pass \
  --validators-external-signer-truststore=truststore.p12 \
  --validators-external-signer-truststore-password-file=truststore.pass
```

`external-signer` loads the keys from `/api/v1/eth2/publicKeys`.

### Prometheus

With `metrics_access: mtls`, Prometheus scrapes with its own client certificate, PEM files made like `vc.pem` and `vc-key.pem` above:

```yaml
scrape_configs:
  - job_name: tee-signer-gateway
    scheme: https
    tls_config:
      ca_file: /path/to/server-ca.pem
      cert_file: /path/to/prometheus.pem
      key_file: /path/to/prometheus-key.pem
      # server_name: gateway.example   # if the target address is not in the certificate
    static_configs:
      - targets: ["gateway.example:19001"]
```

## How a request is signed

1. The gateway parses the body with `web3signer-api`. It computes the domain from its pinned chain and the signing root from the full message, and refuses a body that does not parse or names another chain (400).
2. Its own policy runs: no voluntary exits, and registrations only for allowlisted fee recipients (412).
3. It turns the request into the typed message of the signers' `SIGN` (attestation data, block header, aggregate SSZ and so on) and sends it to every signer that holds a share of the key, all at once.
4. Each signer computes the signing root from the typed message with its own chain config, refuses a domain that differs from its own, applies slashing protection and policy, and returns a partial signature.
5. The gateway checks each partial signature against the share key that signer listed and the root the gateway computed. As soon as a threshold of them pass, it combines them (Lagrange interpolation at zero with the share indices), checks the result against the validator key, and returns it.
6. It stops waiting as soon as the threshold is in or out of reach. A refusal by the signers is a 412; signers that failed, timed out or sent a partial that does not verify are a 500. The calls to the other signers go on until the request's deadline, so every signer sees every request.

Every new connection to a signer goes through all of `runnerclient`'s checks before a request goes on it:

- TLS 1.3 with the gateway's client certificate, which the signer's `-tls-client-ca` must accept;
- the signer's certificate: it must name a build, a non-prod build (hoodi, devnet, ci-test) is refused unless `allow_chain_build` names its chain, and its chain mark must agree with `attestation.mainnet`;
- `IDENTITY` with a fresh nonce over the new channel, and the attestation document checked by its verifier (`dev`, `azure-maa`, `aws-nitro` or `gcp-cs`) with the setup pins (`setup_sha256`, the minimum config versions, `key_release_sha256`);
- the TLS key the signer presented must be the one its attested identity names, and `tls_key_pin` if set.

A connection that fails a check takes no request. The gateway keeps `signers.connections` connections to each signer (default 2) and uses one per request at a time. After an I/O error or a timeout a connection is closed, and the next request on that slot dials a new one with every check again; a restarted signer has a new TLS key and a new identity, so this is how the gateway notices. A request whose connection the signer closed under it goes once more, on a new connection in the same slot (another slot could hold a connection the same restart closed): a signer signs an exact repeat of an attestation or block again with the same signature.

## Keys, shares and the threshold

The gateway asks each signer for `PUBLIC_KEYS`: the validator keys it holds a share of, and the share's public key. It groups the answers by validator key. The share index of each share and the threshold come from the public keys alone: the gateway looks for the smallest threshold t, and distinct indices from 1 to `signers.max_share_index` (default: the number of signers), for which every t of the share keys interpolate to the validator key. With those indices any t partial signatures combine into the validator's signature, so the signers can be listed in any order. The gateway takes at most 8 signers and indices up to 8, because this search grows fast with both. A key whose shares fit no threshold and no indices is not served, and the gateway logs `key refused` once. It also refuses a key unless twice the threshold exceeds the number of shares, and a key held whole by one signer while others hold shares of it, so any two sets of signers that can sign share one signer. That signer, if honest, refuses the second side of a conflicting pair. A rogue one signs both, so the overlap guards against a wrong configuration, not a rogue signer: two sets that share at least two signers keep an honest one in common when one signer is rogue, and the signers ask that of prod chains (`2t - n >= 2`).

A whole key is served only from one signer with no other shares, and only when that signer reports `signing_mode` `single` in `HEALTH`. The gateway asks `HEALTH` of each signer that lists a whole key. A share key equal to the validator key is not enough: a signer of a threshold setup refuses a whole key at import, and a runner without a setup, or one older than `signing_mode`, does not report one, so the gateway refuses its whole keys. Give such a runner a single-mode setup before the gateway upgrade. `HEALTH` is not attested, so this check catches a wrong configuration, not a runner that lies.

A signer that lists a wrong share key for a validator, after a bad import say, makes that key fit no threshold, so the gateway refuses the whole key and logs `key refused`. It does not skip the signer and serve the rest: two separate splits of one key, on different signers, would then each pass, and each could sign alone. Fix or remove that signer's share. If every key is refused, the load fails and the last list stays in force: a key served before keeps its old shares, and the wrong share's partials fail their check. A signer that is down is different: see the next paragraph.

The list is loaded at start (retried for a minute while the signers start). A request that finds it older than 30 s loads it again, so keys the signers get later, and a signer that was down at the last load, show up without a restart. `GET publicKeys` and a sign request for a key the list lacks wait for that load; a sign request for a key the list has starts it in the background and signs with the list as it is. One load runs at a time, and a failed one keeps the old list. A signer that does not answer a load keeps its last answer, so its share stays in the group and the others still sign.

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
| 413 | Body over 10 MiB |
| 412 | Gateway policy refused, or signers refused (slashing protection, their policy, another domain) and the threshold was out of reach |
| 500 | Too few signers answered with a partial signature that verifies, before `signers.timeout` |

A 412 means the signers refused the request, for example because another client already signed that duty. Lighthouse logs it as `CRIT Failed to sign ...`. It is not a gateway error.

The `identifier` may come with or without `0x`, in any case.

## Request types and signer messages

| Web3Signer type | Signer message (`SIGN` kind) | Domain | Checked by the signer |
|---|---|---|---|
| `ATTESTATION` | `attestation` | `DOMAIN_BEACON_ATTESTER` at target epoch | slashing protection |
| `BLOCK_V2` (all versions; PHASE0/ALTAIR full blocks are reduced to a header) | `block` | `DOMAIN_BEACON_PROPOSER` at block slot | slashing protection |
| `RANDAO_REVEAL` | `root` (RANDAO, epoch and object root) | `DOMAIN_RANDAO` | the root is `hash_tree_root(epoch)` |
| `AGGREGATION_SLOT` | `selection_proof` | `DOMAIN_SELECTION_PROOF` | clock |
| `AGGREGATE_AND_PROOF`, `AGGREGATE_AND_PROOF_V2` (PHASE0 to GLOAS; an object without `version` is phase0 unless its aggregate has `committee_bits`, then Electra, as validator clients send it; from `chain.gloas_fork_epoch` on, an aggregate with `committee_bits` hashes as the Gloas one, a progressive Attestation, and an explicit version that disagrees with the aggregate's epoch is a 400) | `aggregate_and_proof` (SSZ, form phase0, Electra or Gloas) | `DOMAIN_AGGREGATE_AND_PROOF` | aggregator index, selection proof under the validator key, form of the epoch |
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

The gateway pins its chain: `chain.genesis_validators_root` and the fork schedule (`chain.genesis_fork_version` plus `chain.forks`) in its config. It computes every domain from that schedule at the message's epoch and refuses (400) a request whose `fork_info` names another `genesis_validators_root`, a fork the schedule does not have, or a fork version other than the schedule's for that epoch. A fork in `fork_info` passes when its `current_version` is a version of the schedule, its epoch falls in that version's period (at or after the version's first epoch, before the next version), and its `previous_version` is either the version before it in the schedule or `current_version` itself. The second form is a blob-parameter-only (BPO) fork: it changes the blob limits, not the fork version, and some clients (Prysm) send the latest BPO fork in `fork_info`, for example Fulu as previous and current version at Hoodi's BPO epoch 54016. The genesis state's fork of a chain that starts at a later fork has the same form at epoch 0. BPO forks need no line in `chain.forks`; a line that repeats the version before it changes no domain. So a client cannot get a signature under another chain's domain through the gateway; Web3Signer itself builds the domain from `fork_info`. The signers check the domain again against their own chain config.

The Gloas types need `chain.gloas_fork_epoch`; without it, or for an epoch before it, policy refuses them (412). For `PROPOSER_PREFERENCES` the domain uses the fork version of the proposal epoch (`validator.md`), so preferences for the first Gloas epoch, signed while `fork_info` still names Fulu, get the Gloas version; `fork_info` must still name the chain. For an envelope the gateway hashes the whole payload, builds the summary the signers take and checks that the summary gives the same root. `BUILDER_REQUEST_AUTH` authenticates a validator's requests to an external builder. It never reaches the chain and is not slashable. Its slot must be at or past `chain.gloas_fork_epoch`, and the gateway hashes it as go-eth2-client v0.30.3 does (a plain container as in builder-specs, data as `ByteList[4096]`). The gateway passes any data on; each signer decides which data it signs.

## Coalescing

Some validator clients send the same request several times at once, for example a sync committee selection proof once per committee seat. The gateway sends one copy to the signers and gives the others its answer (`internal/coalesce`).

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

`gateway -config gateway.yml`. An unknown key anywhere in the file stops the start. Relative paths resolve against the file's directory.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:19000` | HOST:PORT of the Web3Signer API |
| `access` | `mtls` with a `tls` section, else `local` | how `listen` is exposed: `local`, `mtls`, `unsafe_open_tls` or `unsafe_plain_http` (see [Access](#access)) |
| `metrics` | off | HOST:PORT of the Prometheus endpoint (see [Metrics](#metrics)) |
| `metrics_access` | `local` | how `metrics` is exposed, the same values as `access` |
| `tls.cert`, `tls.key` | off | PEM files of the server certificate (followed by its intermediates) and its key, for both listeners (see [TLS](#tls)) |
| `tls.client_ca` | none | PEM bundle of the CAs whose client certificates `mtls` accepts |
| `tls.client_fingerprints` | none | SHA-256 fingerprints of client certificates `mtls` accepts: 64 hex digits, colons and either case allowed |
| `tls.min_version` | `"1.3"` | `"1.3"`, or `"1.2"` for Teku |
| `tls.reload_interval` | `10s` | how often `tls.cert`, `tls.key` and `tls.client_ca` are read again |
| `chain.preset` | `mainnet` | `mainnet` for every public network, `minimal` for spec tests |
| `chain.genesis_fork_version` | `0x00000000` | the chain's `GENESIS_FORK_VERSION` |
| `chain.genesis_validators_root` | required | the chain's genesis validators root |
| `chain.forks` | none | the fork schedule after genesis: `{epoch, version}` in epoch order |
| `chain.gloas_fork_epoch` | absent | `GLOAS_FORK_EPOCH`, the epoch of one entry of `forks`; absent: the Gloas types are refused |
| `chain.slots_per_epoch`, `chain.seconds_per_slot` | preset, 12 | overrides |
| `coalesce.enabled`, `coalesce.cache_slots` | `true`, 2 | see [Coalescing](#coalescing) |
| `signers.client_cert`, `signers.client_key` | required | PEM files of the gateway's client certificate (signing role, followed by its intermediate) and its key |
| `signers.cert_reload_interval` | `10s` | how often both files are read again (see [Client certificate renewal](#client-certificate-renewal)) |
| `signers.timeout` | `5s` | one sign request, from the HTTP request to the combined signature, and each key list call |
| `signers.dial_timeout` | `30s` | each new connection: TCP, TLS, `IDENTITY` and the attestation check |
| `signers.connections` | 2 | connections to each signer, 1 to 16 |
| `signers.max_share_index` | number of signers | highest share index tried when the gateway matches shares to keys, up to 8 |
| `signers.nodes` | required | the signers, at most 8 |
| `signers.nodes[].name` | `signer-N` | the signer's name in the log and the metrics |
| `signers.nodes[].address` | required | `tcp:HOST:PORT` of the signer's mutual TLS listener; for AWS Nitro, the forwarder on the parent instance (the TLS ends inside the enclave) |
| `signers.nodes[].attestation` | required | what the signer's attestation must show, below |
| `signers.nodes[].allow_chain_build` | empty | accept a signer of the non-prod build of this chain: `hoodi`, `devnet` or `ci-test`. Empty: mainnet builds only |
| `signers.nodes[].tls_key_pin` | none | sha256 of the signer's TLS key, 64 hex digits; the key changes at every start of the signer |
| `policy.fee_recipient_allowlist` | empty | fee recipients a `VALIDATOR_REGISTRATION` may name |

The `attestation` block takes the fields of `runnerclient.Attestation` under the same names; [attestation-verify/runnerclient/verify/verify.go](../attestation-verify/runnerclient/verify/verify.go) says what each one checks. The usual ones:

| Field | Meaning |
|---|---|
| `verifier` | `azure-maa`, `aws-nitro`, `gcp-cs`, or `dev` for a local dev runner (which proves nothing about the code that answered) |
| `setup_sha256` | the setup the signer must run; a signer with a setup no pin names is refused |
| `key_release_sha256` | the key release policy (`azure-maa`, `aws-nitro`); required with `mainnet` |
| `mainnet` | the signer signs for a prod chain; must agree with the chain mark in the signer's certificate |
| `maa_host`, `cce_policy_sha256` | `azure-maa`: the attestation provider and the container policy |
| `nitro_pcrs` | `aws-nitro`: PCR values by index; quote the indices |
| `gcp_image_digest`, `gcp_audience`, `gcp_hwmodels`, `gcp_project_id` | `gcp-cs`: the image, token audience, hardware and project |

Settings of one verifier are refused with another, and a required one that is missing stops the start.

The gateway refuses to start without `chain.genesis_validators_root`, with fork epochs out of order, without signers or with more than 8, without a client certificate, with an `allow_chain_build` that is not a non-prod chain, and with an `access` or `metrics_access` that does not fit the rest of the config (see [Access](#access)). A new fork needs a config line before its epoch, as it does in the beacon node and in the signers. A blob-parameter-only fork (`BLOB_SCHEDULE`) keeps the fork version and needs no line.

A configuration for three Hoodi signers:

```yaml
listen: 0.0.0.0:19000
access: mtls
# metrics: 127.0.0.1:19001        # metrics_access: local (default)
tls:
  cert: server.pem                # followed by its intermediates, if any
  key: server-key.pem
  client_ca: client-ca.pem        # the validator clients' CA
  # min_version: "1.2"            # for Teku
chain:
  preset: mainnet
  genesis_fork_version: "0x10000910"
  genesis_validators_root: "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
  forks:
    - {epoch: 0, version: "0x20000910"}       # Altair
    - {epoch: 0, version: "0x30000910"}       # Bellatrix
    - {epoch: 0, version: "0x40000910"}       # Capella
    - {epoch: 0, version: "0x50000910"}       # Deneb
    - {epoch: 2048, version: "0x60000910"}    # Electra
    - {epoch: 50688, version: "0x70000910"}   # Fulu; the BPO forks after it need no lines
signers:
  client_cert: gateway.pem        # signing role, followed by its intermediate
  client_key: gateway-key.pem
  nodes:
    - name: azure
      address: tcp:203.0.113.10:7000
      allow_chain_build: hoodi
      attestation:
        verifier: azure-maa
        maa_host: sharedweu.weu.attest.azure.net
        cce_policy_sha256: "<64 hex digits>"
        setup_sha256: "<64 hex digits>"
        key_release_sha256: "<64 hex digits>"
    - name: aws
      address: tcp:203.0.113.20:7000  # the forwarder on the parent instance
      allow_chain_build: hoodi
      attestation:
        verifier: aws-nitro
        nitro_pcrs: {"0": "<96 hex digits>", "1": "<96 hex digits>", "2": "<96 hex digits>"}
        setup_sha256: "<64 hex digits>"
        key_release_sha256: "<64 hex digits>"
    - name: gcp
      address: tcp:203.0.113.30:7000
      allow_chain_build: hoodi
      attestation:
        verifier: gcp-cs
        gcp_image_digest: "sha256:<64 hex digits>"
        gcp_audience: signer-runner-identity
        gcp_hwmodels: [GCP_INTEL_TDX]
        setup_sha256: "<64 hex digits>"
policy:
  fee_recipient_allowlist: ["0x1111111111111111111111111111111111111111"]
```

For mainnet signers, leave out `allow_chain_build`, set `mainnet: true` in each `attestation` block and use the mainnet chain values. A local dev runner takes `attestation: {verifier: dev}`; a dev runner of a non-prod build also needs `allow_chain_build` with its chain.

## Client certificate renewal

The client certificate is short-lived, so the gateway picks up a renewed one without a restart. It reads `signers.client_cert` and `signers.client_key` at start, where a pair that fails the checks below stops the start, and again every `signers.cert_reload_interval` (default 10s). A pair that changed takes effect only if it parses, the key belongs to the certificate, and the certificate is valid at the gateway's clock. Otherwise the pair in force stays, and the gateway logs `client certificate on disk refused, keeping the one in force` once for that content, not at every read. A certificate that is not valid yet is checked again at each read and takes effect once it is. Write the new files to temporary names and rename them over the old ones: a key written a read after its certificate costs one refused line and no outage.

A good new pair logs `client certificate reloaded` with its serial and expiry. New clients use it at once. The connections already open move to it in the background, one connection to each signer at a time: the gateway dials a new connection with the new certificate, runs every check of a new connection on it (attestation, pins, chain mark, nonce), and only then puts it in the place of an idle connection on the old certificate and closes that one (`connection moved to the new client certificate`). Each signer keeps `signers.connections` connections throughout, and a request in flight ends on the connection it started on. A new connection that fails a check leaves the old one in place and is tried again 5 s later. A connection whose certificate expired before it could move (its signer was down, say) takes the new certificate at its next request.

If the certificate in force expires with no valid replacement on disk, the gateway logs `client certificate expired and no valid replacement on disk` once a minute, and every sign request fails: a 500 to the validator client, and a `signing failed` line whose `err` names the certificate file and its expiry. A valid pair written there ends it at the next read.

The expiry of the certificate in force and the result of each read are also in the metrics (see Metrics).

Each signing request leaves one log line (`msg=signed`, `"denied by signers"`, `"signing failed"`, `"bad request"`, ...). Once the body parses, the line carries the request `type` and the `signer_call`, the signer message it becomes; signed, denied and failed lines also carry `signer_ms`. A denied or failed line has the reasons in `err`, and what each configured signer did under `signers.<name>`: `result` is `signed`, `denied`, `error`, `pending` (asked, no answer by then) or `no_share` (holds no share of the key, not asked). A denial adds `reason` (the signer's status) and `detail`; an error adds `reason` (the status, or `timeout`, `canceled`, `bad_partial`, `failed`) and `detail`. A signer's refusal detail is cut to 1024 bytes. When a request signs but a signer refused or failed, the gateway logs `signer did not sign, threshold met` with `signer`, `type`, `pubkey` (first 4 bytes), `result`, `reason` and `detail`. It logs that at most once per signer, type and reason every 5 minutes, with every status code the gateway has no name for counted as one reason; the first line after that carries `suppressed`, the number of lines held back. A partial signature that does not verify is logged on its own (`bad partial signature`, with the signer's name). Each attested connection logs `signer attested` with the signer's setup state.

## Metrics

With `metrics: HOST:PORT` in the config, the gateway serves Prometheus metrics at `GET /metrics` on that address: the text format 0.0.4, and nothing else on that listener. Without `metrics` there is no endpoint. `metrics_access` decides who reaches it (see [Access](#access)): by default `local`, plain HTTP on a loopback address (`127.0.0.1:19001`). For a scrape from another host use `mtls`, with a client certificate for Prometheus (see [Prometheus](#prometheus)). The exporter is a small registry in `internal/metrics` on the standard library, so the gateway needs no Prometheus client module.

No label holds a public key or a value a client picks. `signer` is a name from `signers.nodes`, `type` is a Web3Signer request type the gateway parsed, and the other labels take the values listed here.

| Metric | Type | Labels | What it counts |
|---|---|---|---|
| `teesigner_gateway_client_cert_not_after_seconds` | gauge | | Unix time the client certificate in force expires |
| `teesigner_gateway_client_cert_not_before_seconds` | gauge | | Unix time it became valid |
| `teesigner_gateway_client_cert_reloads_total` | counter | `result`: `ok`, `refused`, `unchanged` | Reads of `client_cert` and `client_key`: a new pair swapped in, content refused (at every read until it changes), or the pair in force |
| `teesigner_gateway_client_cert_last_reload_timestamp_seconds` | gauge | | Unix time the pair in force took effect: the start or the last successful reload |
| `teesigner_gateway_server_cert_not_after_seconds` | gauge | | With `tls` only: Unix time the API listener's server certificate in force expires |
| `teesigner_gateway_signer_connections_up` | gauge | `signer` | Connections that passed every check and have not failed since |
| `teesigner_gateway_signer_dials_total` | counter | `signer`, `result`: `ok`, `failed` | New connections, with every check |
| `teesigner_gateway_signer_rotations_total` | counter | `signer`, `result`: `ok`, `failed` | Connections moved to a new client certificate; a failed move is tried again 5 s later |
| `teesigner_gateway_signer_attestation_failures_total` | counter | `signer`, `reason`: `tls`, `key_pin`, `identity`, `verifier` | New connections a check refused: `tls` the handshake (client certificate, build, chain mark), `key_pin` the `tls_key_pin`, `identity` the `IDENTITY` exchange and its TLS key, `verifier` the attestation document and the setup pins |
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
| `scripts/build.sh` | Builds the signer core and blst (`scripts/build-core.sh` of the repo, into `build/<arch>/lib`), then `bin/gateway` and `bin/blsverify`. Needs Go 1.26 and gcc (cgo for BLS). |
| `scripts/test-unit.sh` | Builds the signer core as `scripts/build.sh` does, then `go vet` and `go test ./...`. |
| `scripts/update-spec-vectors.sh` | Regenerates the Web3Signer example vectors in `web3signer-api/signing/testdata` from the pinned Web3Signer tag. |

The gateway links the signer core's static libraries, so build them first (`make core` from the repo root; `make test-modules` does it). From the repo root, `scripts/test-modules.sh gateway` runs gofmt, vet and the unit tests under the race detector. The unit tests run the combining against fake signers (2 of 3, a signer down, a slow signer, a partial that does not verify, refusals, all down) and the connections against a fake TLS signer (attestation on every new connection, a wrong `tls_key_pin`, a wrong chain mark, a non-prod build without its `allow_chain_build`, an attestation without the nonce). The reload tests write good and bad pairs in random order and check that the last good one stays in force, and swap the certificate under load against fake signers that accept only the old certificate and then only the new one, with no failed request. The metrics tests check the text format and that each counter moves on its event: calls by result, dials, connections up, each attestation failure reason against the fake TLS signer, rotations, combine failures, request results and reload results. The listener TLS tests check the config refusals and real handshakes: a client of the client CA or of an intermediate it sends, a listed fingerprint, and refusals for no certificate, another CA, an expired or not yet valid certificate, a certificate without client authentication, a listed fingerprint that expired, TLS 1.2 against a 1.3 minimum, TLS 1.2 with CBC suites only, and plain HTTP. They also reload a renewed server certificate and a new client CA, keep the files in force when the files on disk are bad, log a certificate that ends within 30 days, refuse to resume a TLS 1.2 or 1.3 session of a client whose CA left the bundle, with or without its certificate, and close the open connections of an mtls listener when the client CA changes, after the request in flight. The config tests take each `access` and `metrics_access` value with every refusal, and a listener test serves `/metrics` under each value to plain HTTP, HTTPS without a certificate and HTTPS with one.

`TestE2EGateway` in [tests/e2e](../tests/e2e) is the end-to-end test: three dev runners of `scripts/build-runner.sh` with mutual TLS, each with one share of a 2-of-3 key, and the gateway binary in front of them. The test reaches the gateway over TLS with a client certificate of the client CA, checks that a client listed by fingerprint gets in too, and that no certificate, a certificate of another CA, and plain HTTP get no service. The metrics listener is `mtls` too. It sends a validator client's requests (attestation, block, selection proof, aggregate), checks each signature under the validator key against the root the signer core computes, and checks a double vote, an aggregate with a bad selection proof, one signer down, two down, a new client certificate written mid-run while requests go on, and a signer that restarts with a new TLS key. It scrapes `/metrics` before and after the new certificate: 3 connections up to each signer, the requests by type and result, the expiry of the certificate in the file, one reload and 3 connections moved per signer:

```sh
make build
cd tests && RUNNER_BIN="$PWD/../build/x86_64/bin/runner-dev" go test -race -count=1 -v -tags platform_aws -run TestE2EGateway ./e2e
```

CI runs it for every change to `gateway/` or `web3signer-api/` (`CI_E2E_GATEWAY` in `scripts/ci-scope.sh`), and with every other e2e test for a change to `signer-core/`.

## Code

```
cmd/gateway          main: config, signers, HTTP server, metrics listener
cmd/blsverify        independent verifier: hand-written SSZ on crypto/sha256 + blst
internal/config      gateway.yml: defaults, required keys, chain pin and fork schedule, signers
internal/backend     the signers: connections (runnerclient), typed messages, share indices, fan-out, combining
internal/certreload  the client certificate in force: reads it again, checks a new pair, swaps it in
internal/servertls   the API listener's TLS: server certificate and client CA reloaded, client certificates by CA or fingerprint
internal/metrics     Prometheus registry and text format, and the gateway's metrics
internal/policy      exit and registration rules
internal/server      HTTP handlers, content negotiation, error bodies
internal/coalesce    one call to the signers for identical non-slashable requests, results kept 2 slots
tools/specvectors    converts Web3Signer's OpenAPI examples to test vectors
```

`web3signer-api/signing/testdata/web3signer-26.9.0-sign-examples.json` holds the request examples from Web3Signer's OpenAPI spec (Consensys, Apache-2.0), converted to JSON.

BLS: the gateway uses the signers' own code on blst, the copy vendored in `signer-core/third_party/blst` (v0.3.16). It checks signatures with `signer-core/core` (`Verify`: the proof-of-possession ciphersuite, a key at infinity and points outside their subgroup refused) and combines partial signatures and share keys with `signer-core/threshold`. `cmd/blsverify` calls blst's Go bindings from the same copy (`go.mod` replaces `github.com/supranational/blst` with it). Request types come from `github.com/attestantio/go-eth2-client v0.30.3` (see `go.mod`).
