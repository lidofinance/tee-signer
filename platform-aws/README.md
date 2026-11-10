# platform-aws

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

AWS Nitro Enclaves: the platform (`nitro`: NSM attestation, KMS key release bound to PCRs, vsock), the mark log on S3 with Object Lock (`s3log`), and the parent instance side, which is not trusted: the host agent (`hostagent`, `cmd/hostagent`), the TCP to vsock forwarder (`forward`, `cmd/forwarder`) and the NTP relay (`udprelay`, `cmd/udprelay`).

Deploy files (Terraform, enclave image, KMS key policy, nitro-cli build): [deploy/](deploy/README.md).

Module path `github.com/lidofinance/tee-signer/platform-aws`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform-aws`.

## Metrics

The forwarder and the host agent can serve Prometheus metrics at `/metrics`. Both are off by default. The endpoint is plain HTTP without authentication, so it refuses an address that is not loopback unless `-metrics-allow-remote` is set.

| Flag | Program | Meaning |
|---|---|---|
| `-metrics-listen HOST:PORT` | both | Serve metrics, for example `127.0.0.1:9101`. Empty (default): off. |
| `-metrics-allow-remote` | both | Allow a non-loopback `-metrics-listen`. |
| `-metrics-nitro-cli PATH` | hostagent | Run `PATH describe-enclaves` at each scrape and add the enclave state. Needs `-metrics-listen`. |

The deploy scripts do not set these flags. To use them, add them to the `forwarder` and `hostagent` lines of `deploy/parent-run.sh`, for example `-metrics-listen 127.0.0.1:9101` and `-metrics-listen 127.0.0.1:9102 -metrics-nitro-cli nitro-cli`.

The security group has no inbound rule for metrics, and none is needed. Run a collector on the parent that scrapes the loopback endpoints and pushes the samples out, for example Prometheus in agent mode (`prometheus --agent --config.file=agent.yml`):

```yaml
global:
  scrape_interval: 30s
  external_labels: { node: node-1 }
scrape_configs:
  - job_name: signer-parent
    static_configs:
      - targets: ["127.0.0.1:9101", "127.0.0.1:9102"]
remote_write:
  - url: https://metrics.example.org/api/v1/write
    basic_auth:
      username: node-1
      password_file: /etc/prometheus/remote-write.pass
```

The parent's egress already allows TCP 443 to anywhere, so a receiver on 443 needs no change. A receiver on another port needs one `extra_egress` rule (`deploy/main.tf`), for example `{ description = "metrics remote write", protocol = "tcp", from_port = 9090, to_port = 9090, cidr_blocks = ["203.0.113.10/32"] }`.

Forwarder:

- `signer_forwarder_start_time_seconds`
- `signer_forwarder_connections_accepted_total`, refused ones included
- `signer_forwarder_connections_open`
- `signer_forwarder_connections_refused_total{reason="max_conns"|"max_conns_per_source"}`
- `signer_forwarder_dial_failures_total`: dials to the enclave that failed

The forwarder logs a refused connection or a failed dial at most once every 10 s for each kind, with the count since start, so a peer that keeps connecting does not fill `/tmp/forwarder.log`. These counters have every one.

Host agent:

- `signer_hostagent_start_time_seconds`
- `signer_hostagent_connections_total`, `signer_hostagent_connections_open`: connections from the enclave
- `signer_hostagent_read_errors_total`: connections ended by a frame that did not read
- `signer_hostagent_requests_total{kind, result}`: kind is `get`, `put`, `list`, `creds`, `exit`, `setup` or `other`; result is `ok`, `refused` (a status code, `NOT_FOUND` included) or `error`. A series shows up after its first request. Credential refreshes are `kind="creds",result="ok"`.
- `signer_hostagent_credentials_expiry_timestamp_seconds`: expiry of the last credentials handed out

Enclave state, with `-metrics-nitro-cli`:

- `signer_enclave_running`: 1 if an enclave is in state `RUNNING`; missing when `describe-enclaves` failed
- `signer_enclave_describe_errors_total`
- `signer_enclave_info{enclave_id, name, cid, state, pcr0}`
- `signer_enclave_cpus`, `signer_enclave_memory_bytes`, `signer_enclave_start_time_seconds` (start of the nitro-cli process that holds the enclave), each by `enclave_id`

Suggested alerts:

- `signer_enclave_running == 0` or `absent(signer_enclave_running)` for 2 minutes
- `count(count by (enclave_id) (count_over_time(signer_enclave_info[1h]))) > 1`: the enclave was replaced
- `increase(signer_forwarder_dial_failures_total[5m]) > 0`: the forwarder cannot reach the enclave
- `increase(signer_forwarder_connections_refused_total[5m]) > 0`: a bound was hit
- `increase(signer_hostagent_requests_total{result="error"}[10m]) > 0`, `kind="creds"` above all
- `changes(signer_forwarder_start_time_seconds[1h]) > 0` and the same for the host agent: a restart
