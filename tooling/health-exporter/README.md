# health-exporter

A Prometheus exporter for tee-signer runners. It polls each runner's HEALTH
over the runner's attested mutual TLS and serves the answers on `/metrics`.

The runner has no metrics endpoint: its only listener is attested mutual TLS.
The exporter runs outside the TEE, next to Prometheus. Each new connection
checks the runner's attestation and setup pins first, the same check
`signer-admin` makes. HEALTH answers are not attested, so treat the metrics as
monitoring data, not as proof.

This tool is not part of the runner or of the audited code.

## Build

From this folder, in a clone of the repo (the `replace` lines point at the
other modules):

```sh
CGO_ENABLED=0 go build -trimpath -o health-exporter .
```

## Run

One connection file per runner, in the format `signer-admin` reads. Give the
exporter a client certificate of the attest-only role
(`signer-admin issue-client-cert -role attest ...`). HEALTH needs nothing more.

```sh
health-exporter -listen 127.0.0.1:9478 -every 30s -timeout 20s \
  aws-1=aws-1.json azure-1=azure-1.json gcp-1=gcp-1.json
```

A connection file for an AWS Nitro runner on mainnet. Relative certificate
paths are relative to the file. A non-mainnet runner drops `mainnet` and sets
`allow_chain_build` (`hoodi`, `devnet` or `ci-test`).

```json
{
  "address": "tcp:10.0.0.10:7100",
  "client_cert": "monitor.pem",
  "client_key": "monitor-key.pem",
  "attestation": {
    "verifier": "aws-nitro",
    "mainnet": true,
    "nitro_pcrs": {"0": "...", "1": "...", "2": "..."},
    "setup_sha256": "...",
    "key_release_sha256": "..."
  }
}
```

A runner that fails the attestation check, or does not answer, shows as
`tee_signer_up 0` and the reason goes to the log. Its other metrics disappear
until it answers again.

## Docker Compose

Build the binary as above, then run it next to Prometheus. The exporter port
stays on the compose network.

```yaml
services:
  health-exporter:
    image: gcr.io/distroless/static-debian12:nonroot
    command: ["/health-exporter", "-listen", "0.0.0.0:9478",
              "aws-1=/conn/aws-1.json", "azure-1=/conn/azure-1.json", "gcp-1=/conn/gcp-1.json"]
    volumes:
      - ./health-exporter:/health-exporter:ro
      - ./conn:/conn:ro
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:v3.5.0
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./tee-signer.rules.yml:/etc/prometheus/tee-signer.rules.yml:ro
    ports:
      - "127.0.0.1:9090:9090"
    restart: unless-stopped
```

`prometheus.yml`:

```yaml
rule_files: [tee-signer.rules.yml]
scrape_configs:
  - job_name: tee-signer
    scrape_interval: 30s
    static_configs:
      - targets: ["health-exporter:9478"]
```

The `conn` folder holds the connection files and the client certificate and
key. Make the key readable by the container user (uid 65532 in the image
above) and nobody else.

## Metrics

Every metric has the label `runner`, the name given on the command line.

| Metric | Type | Meaning |
|---|---|---|
| `tee_signer_up` | gauge | The last HEALTH call passed the attestation check and answered |
| `tee_signer_health_errors_total` | counter | HEALTH calls that failed |
| `tee_signer_attestations_verified_total` | counter | Runner identities verified, one per new connection |
| `tee_signer_info` | gauge | Always 1; labels `platform`, `version`, `signing_mode`, `single_key`, `clock_source`, `key_lock`, `restart_mode` |
| `tee_signer_ready` | gauge | The runner reports it can sign |
| `tee_signer_not_ready_reason` | gauge | 1 while a reason holds; label `reason`: `load_failed`, `state_copy_failed`, `mark_log_lost`, `request_panic` |
| `tee_signer_image_check` | gauge | 1, with label `state`: the runner's check of its own image (`allowed`, `not_allowed`, `restart_needed`, `key_rule_unlisted`, `unknown`, `override`, `not_applicable`) |
| `tee_signer_config_version` | gauge | Active version of each config group; label `group`: `locked`, `open` |
| `tee_signer_config_pending_effective_timestamp_seconds` | gauge | When the pending update of the group takes effect; 0 if none |
| `tee_signer_validators` | gauge | Keys or shares loaded |
| `tee_signer_started_timestamp_seconds` | gauge | Runner start time |
| `tee_signer_health_rtt_seconds` | gauge | Duration of the last HEALTH call on an open connection |
| `tee_signer_clock_skew_seconds` | gauge | Runner clock minus this host's clock, from the same call. A poll that opens a new connection makes a second call on it and takes both values from that one, so they leave out the dial and attestation check. Both are absent after a failed poll; skew is also absent when the runner reports no clock in ms |
| `tee_signer_clock_trusted` | gauge | The runner's clock is a trusted source |
| `tee_signer_allow_unverified_nonslashable` | gauge | The runner signs bare roots it cannot check |
| `tee_signer_unverified_signatures_total` | counter | Such signatures since start |
| `tee_signer_signatures_total` | counter | Signatures since start |
| `tee_signer_watermark_writes_total` | counter | Slashing mark writes since start |
| `tee_signer_exact_repeats_total` | counter | Exact repeats signed again since start |
| `tee_signer_hash_cache_hits_total`, `_misses_total` | counter | Signing root cache hits and misses since start |
| `tee_signer_nts_quorum` | gauge | The NTS clock answers |
| `tee_signer_nts_bound_seconds`, `_max_bound_seconds` | gauge | Current NTS error bound, and the limit above which the runner signs nothing |
| `tee_signer_nts_sample_age_seconds`, `_max_sample_age_seconds` | gauge | Age of the oldest sample in the quorum, and its limit |
| `tee_signer_nts_quorum_age_seconds` | gauge | Time since the last quorum |
| `tee_signer_nts_offset_from_host_seconds` | gauge | NTS time minus the host-set clock inside the TEE |
| `tee_signer_nts_coarse_diff_seconds` | gauge | NTS time minus the HTTPS-date time at the last quorum |
| `tee_signer_nts_members` | gauge | NTS servers in the quorum |
| `tee_signer_nts_refusals_total` | counter | Times the NTS clock refused to give a time |
| `tee_signer_nts_rho_violations_total` | counter | Quorums the drift check refused |
| `tee_signer_nts_drift_ppm` | gauge | Measured drift of the local clock |

The runner's counters restart from 0 when the runner restarts. Metrics a
runner does not report (no setup, no NTS clock, an older version) are left
out.

## Suggested alerts

`tee-signer.rules.yml`:

```yaml
groups:
  - name: tee-signer
    rules:
      - alert: TeeSignerDown
        expr: tee_signer_up == 0
        for: 2m
      - alert: TeeSignerNotReady
        expr: tee_signer_ready == 0
        for: 2m
      - alert: TeeSignerImageNotAllowed
        expr: tee_signer_image_check{state!~"allowed|not_applicable"} == 1
      - alert: TeeSignerNoNTSQuorum
        expr: tee_signer_nts_quorum == 0
        for: 2m
      - alert: TeeSignerNTSBoundHigh
        expr: tee_signer_nts_bound_seconds > 0.8 * tee_signer_nts_max_bound_seconds
        for: 5m
      - alert: TeeSignerConfigUpdatePending
        expr: tee_signer_config_pending_effective_timestamp_seconds > 0
      - alert: TeeSignerRestarted
        expr: changes(tee_signer_started_timestamp_seconds[15m]) > 0
      - alert: TeeSignerFewerKeys
        expr: tee_signer_validators < 100  # the number of keys you imported
        for: 5m
```

A pending config update means a governance change takes effect at the given
time. Check that you expect it.
