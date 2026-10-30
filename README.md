# tee-signer

> **Early proof of concept. Do not use it with real funds.**
>
> Provided as is, without any warranty or guarantee. Not audited. Not for
> production or mainnet funds. Interfaces and formats will change without
> notice.

A BLS signer for Ethereum validators that runs inside a trusted execution
environment: AWS Nitro Enclaves, Azure confidential containers (SEV-SNP) or
GCP Confidential Space. The runner keeps validator keys or key shares sealed
to its measured image, refuses slashable messages, and keeps its signing marks
in an external append-only log, so a restarted, rolled back or cloned runner
cannot sign below them. Operators set it up with an approver-signed setup.
Everything that talks to the runner (the Dirk fork, the gateway, validator
clients, the operator tools) is untrusted, and the runner checks what they send.

On GCP a signer that holds a key alone (1 of 1) is unsafe and refused unless
its setup accepts the risk: Cloud KMS cannot lock the rule that releases the
sealing key, so anyone with IAM or KMS admin rights on the project, the pool
or the key (folder and organization admins included) can rebind it and
decrypt the sealing key outside any TEE, which opens the whole key from the
state bucket. See
[platform-gcp/deploy/README.md](platform-gcp/deploy/README.md#setup), "Setup".

The history before this repo is in
[lidofinance/threshold-signer-poc](https://github.com/lidofinance/threshold-signer-poc).

## Modules

Each folder is one module with its own `go.mod` (or C build), tests
and README. A module uses another one only through its public packages, and
every module builds and tests on its own.

| Module | What it holds |
|---|---|
| [markformat](markformat) | Portable C watermark storage codec and its Go binding |
| [signer-core](signer-core) | The C signing core: SSZ, BLS (blst, vendored), EIP-3076 slashing protection, signing policy; its Go binding, fuzz targets and simulator |
| [signer-protocol](signer-protocol) | The runner's wire protocol: request types, frames, transports, client connection |
| [governance](governance) | The setup format, approver sets and signed updates, approved orders (handover, import, exit), chain configs |
| [tee-signer](tee-signer) | The runner that runs in the TEE: server, state, clone guard, attested TLS, handover |
| [slashing-log](slashing-log) | The mark log and the encrypted state copy on host storage |
| [platform](platform) | The platform interface of the runner, setup loading, the dev platform |
| [platform-aws](platform-aws) | Nitro Enclaves: attestation, KMS key release, S3 mark log, the parent instance tools, deploy files |
| [platform-azure](platform-azure) | Azure confidential containers: SNP and MAA, Key Vault key release, Blob mark log, deploy files |
| [platform-gcp](platform-gcp) | GCP Confidential Space: token, Cloud KMS, Cloud Storage mark log, deploy files |
| [attestation-verify](attestation-verify) | Verifiers of the runner's attestation (Nitro, MAA, Confidential Space) and the attested client |
| [trusted-time](trusted-time) | The runner clock and the NTS client: a C core under a Go wrapper |
| [signer-admin](signer-admin) | Operator tools: setup updates and orders, share import, handover |
| [web3signer-api](web3signer-api) | Parsing and checks of Web3Signer signing requests |
| [devkit](devkit) | Test helpers: fuzz oracles and driver, goroutine leak and lock order checks |
| [tests](tests) | End-to-end tests across modules, against the built runners |

## Build

Inside an Ubuntu 22.04 or 24.04 workbench (native, WSL2 or a VM), with Go
1.26 or newer, gcc, Docker, and for arm64 builds the aarch64 cross compiler
and qemu-user. `make deps` installs the apt packages.

```sh
make core     # C core and blst, build/<arch>/lib
make build    # the runners, one per cloud, and the host tools; each passes the release gate
```

## Test

```sh
make check          # module boundaries, secret scan, release gate self-test, gofmt
make test-modules   # vet and unit tests of every Go module, with -race
make test           # all of it: build, gate, modules, e2e, signer-core suites, short fuzz
make model          # the slashing model test, MODEL_RUNS seeds (default 500)
make fuzz           # every Go fuzz target for FUZZ_TIME (default 3s)
make fuzz-core      # the C fuzz targets with ASan and UBSan
make test-core      # signer-core's own suites
```

The signer-core vector suites need the pinned test vectors:
`signer-core/scripts/fetch.sh` downloads them, or `VECTORS_DIR` names a copy.
Without network, set `NO_NETWORK=1` and `GOPROXY=off` and use a filled Go module
cache. `make loc` prints code line counts per module and per runner build.

## License

Unless otherwise noted, first-party code and documentation are licensed under the
[Apache License 2.0](LICENSE) (`Apache-2.0`). Third-party code, dependencies and
imported test fixtures retain their own licences and notices; the root licence
does not replace those terms.

Binary distributions must include the accompanying licence bundle. The cloud
image builds include it at `/licenses`. See [licence packaging](docs/licensing.md)
for the bundle contents and redistribution instructions.
