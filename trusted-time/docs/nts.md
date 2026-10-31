# nts: Rust library for the signer's NTS time client

The signer gets a trusted clock from NTS (RFC 8915). In the clouds Go
runs the TLS session of the key exchange (`crypto/tls`, `ExportKeyingMaterial`)
and owns every socket. The Rust code does the NTS-KE records, the NTPv4
packets with NTS, AES-SIV-CMAC-256, the error bound and the quorum, with no
I/O of its own. It is a static library with a C ABI that the Go runner
links through cgo, like `libsigner_core.a`. On the boards the same protocol
code is meant to run in an OP-TEE trusted app, with TLS inside it. This file
is the design note.

The parts:

- The Rust toolchain, with static linking into the runner on x86_64 and
  aarch64 and the same bytes on every build.
- The protocol logic, the error bound and the quorum in the `no_std` crate
  `signer-nts-core`, with Rust tests, and the C ABI over all of it
  (`include/signer_nts.h`).
- The Go side, behind the build tag `nts`: NTS-KE over `crypto/tls` and NTP
  over UDP in `trusted-time/nts`, the clock `runner/clock.NTS`, the switch
  `RUNNER_NTS_CLOCK=1` in tagged runners (`tee-signer/platforms_nts.go`),
  and the interop test against four public operators
  (`scripts/nts-interop.sh`).
- The clouds. The cloud runners (azure, aws, gcp, their debug and key
  generation builds) have the tag, and their images run `-nts-clock`
  (section "In the clouds"). On AWS, NTS-KE goes through vsock-proxy and
  NTP through a UDP relay on the parent (`platform-aws/udprelay`,
  `platform-aws/cmd/udprelay`).

## Workspace

`trusted-time/rust/Cargo.toml` is a cargo workspace with one lock file:

| Crate | Folder | What it is |
| --- | --- | --- |
| `signer-nts` | `nts/` | The staticlib `libsigner_nts.a` with the C header `include/signer_nts.h`. `std`. 17 C functions over the core: handles, buffers, error codes (see "C ABI"). |
| `signer-nts-core` | `trusted-time/rust/core/` | All protocol logic. `#![no_std]` with `alloc`, `#![forbid(unsafe_code)]`. No clock reads, no sockets, no random number generator: the caller passes in timestamps, nonces and unique IDs. |
| `signer-nts-nostd-check` | `trusted-time/rust/nostd-check/` | A `no_std` staticlib with its own panic handler that calls the core. Built only to show the core links without `std`; never linked into anything or run. |

The core's dependencies come from crates.io (see "Crates and where they live"), all with default features
off: `aes-siv` (`alloc`), `aes` and `cmac` (only to turn on `zeroize`, so the
expanded AES keys and the CMAC state are wiped on drop), `subtle`, `zeroize`.

## What the core does

`ke` (RFC 8915 section 4, 5.1):

- `build_request()`: 16 octets, Next Protocol NTPv4, AEAD 15
  (AEAD_AES_SIV_CMAC_256), End of Message, all with the critical bit.
- `response_length(buf)`: how many octets the response has once End of
  Message arrived, so the reader knows when to stop.
- `parse_response(buf)`: the cookies (first 8 kept), the NTP server and port.
  Refuses an Error or Warning record, an unknown critical record, a missing
  Next Protocol, AEAD or cookie record, another protocol or AEAD, duplicates,
  bad bodies, and anything over the caps.
- `EXPORTER_LABEL`, `exporter_context(direction)`: the TLS exporter values for
  the C2S and S2C keys, so Go and Rust use the same bytes.

`ntp` (RFC 8915 section 5, RFC 7822, RFC 5905):

- `build_request(c2s, input)`: mode 3, version 4, the caller's random transmit
  timestamp, Unique Identifier, NTS Cookie, 0 to 7 Cookie Placeholders, and
  the NTS Authenticator over all of it. Returns the packet and a
  `PendingRequest`.
- `PendingRequest::verify_response(s2c, packet)`: mode 4, origin timestamp
  equal to our transmit timestamp, our Unique Identifier, the RFC 7822 field
  rules, the authenticator with the S2C key, the new cookies from the
  encrypted part. Refuses leap indicator 3 and stratum above 15. Stratum 0
  gives `Response::KissOfDeath(code)` (RATE, NTSN, DENY, RSTR, other) and no
  time. Otherwise `Response::Time` with the four timestamps, root delay, root
  dispersion, precision, stratum, leap indicator and the cookies. One
  accepted response per request; a second is refused as a replay.

`keys`: `C2sKey`, `S2cKey`, wiped on drop, not printed by `Debug`.
`cookie`: `Cookie`, 1 to 1024 octets, wiped on drop. `time`: `NtpTimestamp`,
`NtpShort`, `NtpDuration` and the era-safe conversion to and from Unix
nanoseconds.

`sample` (RFC 5905 sections 7.3, 8, 11.2): `measure(sample, t1, t4, pivot)`.
T1 and T4 come from the caller's monotonic clock, T2 and T3 from the server,
so the offset is real Unix time minus the caller's monotonic clock. Delay =
(T4 - T1) - (T3 - T2); offset = ((T2 - T1) + (T3 - T4)) / 2; bound = delay/2
+ rootdelay/2 + rootdisp + 2^precision + rho (T4 - T1) + 3 ns of rounding,
rho = 500 ppm (RFC 5905 MAXFREQ). Refused: T4 before T1, T3 before T2, a
negative delay, stratum outside 1 to 15, a zero reference timestamp or one
after T3, and a bound over 1 s (MAXDIST).

`quorum`: `combine(intervals, now)`. 3 to 16 intervals from distinct
operators (labels from the caller, duplicates refused), F = 1. Each bound
first grows by rho times its age at `now`. [lo, hi] spans the points that at
least n - 1 intervals cover (the intersection of RFC 5905 section 11.2.1,
without clustering); no such point is an error. Result: the midpoint, bound
(hi - lo) / 2. The plan's rule ("(F+1)-th smallest lower end, (F+1)-th
largest upper end, fail if lo > hi") never fails for three servers; the
module comment has the reason. The result here is always inside that rule's
interval.

## C ABI

`include/signer_nts.h` documents each function. In short: KE request bytes,
response framing, ALPN, exporter label and contexts; an opaque `snts_assoc`
(keys and up to 8 cookies, wiped on free) made from a KE response and the two
exported keys; `snts_ntp_request` (takes the oldest cookie, asks for enough
placeholders to hold 8 again, gives an `snts_request` handle) and
`snts_ntp_verify` (checks, keeps the new cookies, measures); `snts_quorum`
over a pointer-free array of intervals. The caller passes buffers with their
lengths, the random octets (56 per request) and every time. Return codes are
`SNTS_*`; refusals carry a `reason` (kind << 16 | value) and
`snts_reason_text` names it. No panic crosses the boundary: `panic =
"abort"` in the release profile (and Rust aborts on unwind out of an
`extern "C"` function since 1.81), so there is no `catch_unwind`. A test in
`src/tests.rs` checks that the header declares every export with the same
numbers and struct sizes; a Go test checks cgo's struct sizes against it.

## Go side (build tag `nts`)

- `trusted-time/nts`: the cgo binding; `KeyExchange` (TLS 1.3 only, ALPN
  `ntske/1`, the ALPN check Go leaves to the caller, `ExportKeyingMaterial`
  with the label and contexts from Rust, certificate validity checked against
  a clock the caller passes, never the host's: a zero time from that clock
  stops the exchange before the dial, and during the handshake becomes
  `nts.NoTrustedTime` (1970), which no certificate covers. Go's
  `crypto/x509` would read a zero time as `time.Now()`); `Association.Query` over a connected UDP socket
  (refused packets do not end the wait: they may be forgeries); pinned roots
  per operator in `roots/` with their source in `roots.go`.
- `runner/clock.NTS`: polls each server every 32 s (at least 16 s apart,
  RFC 5905 MINPOLL), doubles a server's interval on RATE up to 1024 s, drops
  a server on DENY or RSTR, runs NTS-KE again on NTSN, feeds the latest
  sample of each server (at most 4 intervals old) to the Rust quorum, ages
  the bound by rho, and fails `Now` over 100 ms. Local time is
  `CLOCK_MONOTONIC_RAW` (`nts.Monotonic`), not Go's `CLOCK_MONOTONIC`, which
  an NTP daemon in the kernel slews. Each
  quorum is checked against the last one and against a baseline quorum
  about 17 minutes older: if the offset moved more than the two bounds and
  rho allow, the local clock broke rho and `Now` fails until the next
  quorum agrees. The status line's `drift_ppm` is the rate over that
  baseline, `drift_err_ppm` what the bounds leave open; a quorum is refused
  exactly when |drift_ppm| > 500 + drift_err_ppm. The HTTPS-date quorum is
  the coarse check (NTS time outside -30 s to +31 s of it is refused: 30 s
  plus the Date header's 1 s resolution), the certificate clock of NTS-KE
  (`nts.NoTrustedTime` when it has no reading) and the NTP era. Its `Anchored` clock ages on `CLOCK_MONOTONIC_RAW` too.
  There is no fallback to it.
- `tee-signer/platforms_nts.go`: `-nts-clock` (or `RUNNER_NTS_CLOCK=1`) gives a
  tagged runner the NTS clock, with `-nts-coarse-urls`, `-nts-wait` and
  `-nts-max-bound` (or their variables; a set flag wins). With no quorum
  within `-nts-wait` (90 s by default) the start fails and the runner exits
  with the peers' status in its error line, which goes to the host on
  Nitro. The supervisor starts it again: `restartPolicy` `OnFailure` on
  ACI, `tee-restart-policy=OnFailure` on Confidential Space, the operator
  or the parent's service manager on Nitro. A runner that went on without
  a quorum would load no share (each share's restart floor reads the
  clock) and would not load them once the quorum formed. `-clock https-date`
  next to it is refused, since main would replace the NTS clock with it.
  The clock dials through the platform (`platform.Platform.Dial`; nil is
  the default dialer). `runner -nts-clock-check`
  queries the servers once and prints the result. A debug build (tag debugimport) can name
  test servers instead of the public ones (`RUNNER_NTS_TEST_SERVERS`,
  `RUNNER_NTS_TEST_ROOTS`, `nts_servers_debug.go`); a release build cannot.
- `trusted-time/nts/ntstest`: a loopback NTS-KE and NTP server for the tests,
  with its own AES-SIV from RFC 5297 (checked against appendix A.1).

Untrusted bytes are read only through checked reads (`core/src/bytes.rs`),
with no indexing, `unwrap` or `expect` on parsed data, and every allocation
has a fixed upper bound:

| Cap | Value | Source |
| --- | ---: | --- |
| NTS-KE response | 65536 octets | RFC 8915 section 4: clients SHOULD accept at least 65536 |
| NTS-KE records per response | 64 | ours (a normal response has about 12) |
| NTS-KE record body | 1024 octets | ours |
| Cookies kept from NTS-KE | 8 | RFC 8915 section 4.1.6: servers SHOULD send 8 |
| Cookie | 1 to 1024 octets | ours |
| Server name | 255 octets | RFC 1035 section 2.3.4 |
| NTP request we build | 1280 octets | RFC 8915 section 5.7 (fragmentation), IPv6 minimum MTU |
| NTP response | 2048 octets | ours |
| Cookies in an NTP response | placeholders + 1 | RFC 8915 section 5.7: MUST NOT exceed |

## Files

```
trusted-time/rust/Cargo.toml, Cargo.lock    the workspace; the lock pins the 20 crates.io crates
trusted-time/rust/crates.allow              the crates Cargo.lock may hold, name and version
trusted-time/rust/src/                      signer-nts: the C exports (lib.rs), the association
                              (assoc.rs), reason codes (reason.rs), tests (tests.rs)
trusted-time/rust/include/signer_nts.h      the C header, written by hand
trusted-time/rust/core/src/                 signer-nts-core: ke, ntp, sample, quorum, keys, cookie, time, selftest
trusted-time/rust/core/tests/               requests, answers and refusals against a test server,
                              randomized garbage and mutations (fixed seeds)
trusted-time/rust/nostd-check/src/lib.rs    the no_std build check
trusted-time/toolchain/toolchain.Dockerfile     the toolchain image
scripts/fetch-nts.sh          checks the lock, fetches the crates into build/nts/cargo-home,
                              checks the archives
scripts/nts-verify-crates.sh  checks the crate archives against the sha256 in Cargo.lock
scripts/build-nts.sh          builds libsigner_nts.a for both architectures, runs
                              the Rust tests and the no_std checks of the core
scripts/nts-container.sh      the part of build-nts.sh that runs in the container
scripts/build-runner-nts.sh   builds the runners with the build tag nts
scripts/test-nts.sh           all of it, then the Go test on each architecture
scripts/nts-interop.sh        the interop test against the four public operators (network)
trusted-time/nts/                   the cgo binding, NTS-KE, NTP, pinned roots, tests (tag nts)
trusted-time/clock/nts*.go          the NTS clock and its tests (tag nts)
tee-signer/nts_on.go              -nts-selftest and -nts-clock-check (tag nts)
tee-signer/platforms_nts.go       -nts-clock and RUNNER_NTS_CLOCK=1 (tag nts)
runner/nts_servers_*.go       the servers: public in release builds, test servers in debug builds
platform-aws/udprelay/              the UDP relay: protocol, allowlist, rate limits, client (Nitro)
platform-aws/cmd/udprelay/          the relay program on the Nitro parent
tests/e2e/nts_relay_test.go  the Nitro runner's NTS clock through the relay (test servers; NTS_INTEROP=1: public)
```

## The no_std checks

The pinned toolchain has the standard library for the two Linux targets only.
A bare-metal target (for example `aarch64-unknown-none`) or `-Zbuild-std`
would be a download, so no real `no_std` target is built. Three checks
stand in for it, in `scripts/nts-container.sh` and `build-nts.sh`, on both
architectures:

1. `cargo tree -p signer-nts-core -e features` has no `feature "std"`
   line (output in `build/nts/<arch>/nostd-check/core-features.txt`).
2. `signer-nts-nostd-check` builds: a `#![no_std]` staticlib with its own
   `#[panic_handler]`. If anything in the graph linked `std`, the build would
   fail with a duplicate `panic_impl` lang item.
3. The symbols that archive needs from outside are listed: for the core's
   own object after LTO (`nostd-check/undefined-core.txt`: `malloc`, `free`,
   `memcpy`, `memmove`, `memset`, and `__udivti3` for the 128-bit division
   in `time.rs`, which `compiler_builtins` has) and for the whole archive
   with the target's precompiled `compiler_builtins`
   (`nostd-check/undefined.txt`). That is what a trusted app would have to
   provide.

## Commands

```sh
make nts                       # fetch the crates, build for x86_64 and aarch64, Rust tests on x86_64
bash scripts/test-nts.sh       # also the runners with the tag nts and the Go tests, aarch64 under qemu
bash scripts/nts-interop.sh    # network: NTS-KE and 3 queries per public operator
```

`make nts` and the scripts write to `build/nts/`. They do not touch
`build/<arch>/bin`. The image builds take their runners from there, built by
`scripts/build-runner.sh`, which builds the library into `build/nts/`
first.

## Toolchain

The toolchain is a Docker image, `trusted-time/toolchain/toolchain.Dockerfile`. It starts from
`rust:1.94.1-slim-bookworm`, pinned by digest, and adds the aarch64 standard
library with `rustup target add` (rustup checks the sha256 from the release
manifest). A Rust static library needs no linker, so the image has no aarch64
compiler. The final link is the Go build's, with the host's
`aarch64-linux-gnu-gcc`, as for the C core.

`build-nts.sh` runs the compiler in a new container for each architecture,
as the calling user, with `--network none`. It stops if the compiler is not
the commit named in `scripts/common.sh`. The image is built locally and its
layer holds files with the date of the build, so a rebuild is not expected to
have the same digest. The pins that count are the base image digest, the
commit of rustc and the sums of each target's standard library
(`NTS_STD_SHA256_x86_64` and `NTS_STD_SHA256_aarch64` in
`scripts/common.sh`: the sha256 of the sorted file sums under
`lib/rustlib/<target>`). rustup checks the aarch64 rust-std only against
the release manifest it downloads from the same server, so the pin is what
keeps a changed download out of the build. A Rust update changes all
three.

## Crates and where they live

The 20 crates (aes-siv and its dependencies) come from crates.io. None is in
git. The pin is `trusted-time/rust/Cargo.lock`, which holds the version and
sha256 of each crate archive. `scripts/fetch-nts.sh` first checks that the
lock holds exactly the crates of `trusted-time/rust/crates.allow`, all from
crates.io (`make check` runs this part too). The archives live in
`build/nts/cargo-home` (git ignores `build/`); `cargo fetch --locked`
downloads the ones that are missing.

cargo checks an archive's sha256 against the lock only when it downloads it,
and it takes dependency features from the registry index files, which the
lock does not cover. So nothing in the cache is trusted:

- `fetch-nts.sh` runs `scripts/nts-verify-crates.sh` first: each archive in
  the cache against its sha256 in the lock. All there and matching: no
  fetch. Some missing: `cargo fetch`, then the same check again. One that
  differs (changed, cut short): the script stops and says to remove the
  cache. It also deletes the extracted sources (`registry/src`).
- `build-nts.sh` mounts the cache read-only at `/crates` in each build
  container. `nts-container.sh` copies only the lock's archives out of it,
  checks the copies with `nts-verify-crates.sh`, and unpacks them into
  `/tmp/vendor`, a cargo directory source whose `.cargo-checksum.json` per
  crate names the lock's sha256. cargo builds with crates.io replaced by
  that directory. The registry index, the extracted sources and every other
  file of the cache are never read in the build, so features come from the
  crates' own `Cargo.toml`. A changed archive stops the build.

The first build needs a network once, for the fetch. `make clean` removes
`build/` and the cache with it; an offline machine can take a copy of
`build/nts/cargo-home` from another one, since every archive is checked
anyway.

`build-nts.sh` runs `fetch-nts.sh` first. Apart from building the toolchain
image, that is the only step with a network. The build containers start
with `--network none` and run cargo with `--locked --offline --frozen`. A new crate in the lock, for example after
a version bump, stops the build until someone reviews it and edits
`crates.allow`. The three workspace crates are in the lock too, without a
source or checksum; the checks count only the crates.io ones.

## Same bytes on every build

- Fixed compiler, crate archives checked against the sha256 in Cargo.lock
  before every build, `--locked --offline --frozen`.
- The archive holds a few crate source paths (panic locations), remapped
  to `/vendor/<crate>-<version>/...`, the same for every cargo version.
- `--remap-path-prefix` for the mount point of the sources, the crates and
  the cargo, rustup and target folders. The standard library keeps the `/rustc/<commit>/`
  paths it was built with, which are the same for this compiler.
- `panic = "abort"`, `codegen-units = 1`, fat LTO, `opt-level = "s"`,
  `debug = 0`, no build script of our own. Fat LTO drops the standard library
  code that nothing reaches. Without it the runner grows more and the static
  link prints glibc warnings about `getaddrinfo`.
- A new container for each build and the script's own umask. After the build
  the script checks the exports, the architecture of every object and that
  the archive names no path of this machine.

The archive still holds the debug sections of the precompiled standard
library. The runner link strips them (`-s -w`), and the runner binaries have
none.

## In the runner

`trusted-time/nts` is the cgo binding. It has code only with the build tag `nts`, so
a build without the tag neither links Rust nor needs the library. With the
tag, a runner also answers `runner -nts-selftest` (prints the library
version, runs the self-test, exits) and has the NTS clock.

`scripts/build-runner.sh` builds the library first (`build-nts.sh --no-test`:
the crates from crates.io, then offline in the toolchain image) and gives the tag to the cloud runners:
`runner-azure`, `runner-aws`, `runner-gcp`, their `-debugimport` builds and
their debug builds (`scripts/common.sh`, `runner_tags`). The dev
runners (`runner-dev`, `runner-dev-debugimport`) stay
without it; `scripts/build-runner-nts.sh` still makes tagged copies of every
build for `test-nts.sh`. The link flags are
`-linkmode external -extldflags -static`. `check-deps.sh` checks that the
cloud builds link `trusted-time/nts` and the dev builds do not, and
`build-runner.sh` that only the cloud builds hold the library and the
`-nts-*` flags, and only their debug builds the test server variables.

## In the clouds

Each cloud image runs the NTS clock from its measured command, so the host
cannot turn it off or point it elsewhere:

| Image | Where the flags are | Coarse check URLs | Path to the NTS servers |
| --- | --- | --- | --- |
| AWS EIF | `platform-aws/deploy/enclave/Dockerfile` (PCR0, PCR2) | KMS, STS, `www.cloudflare.com`, through the platform's vsock-proxy routes | NTS-KE through vsock-proxy (vsock 8005 to 8008, TCP 4460), NTP through `udprelay` on the parent (vsock 7102) |
| Azure | `platform-azure/deploy/aci-template.json` command (CCE policy hash) | `login.microsoftonline.com`, `management.azure.com`, `www.cloudflare.com` | ACI's default outbound access, direct |
| GCP | `platform-gcp/deploy/Dockerfile` entrypoint (image digest) | `cloudkms.googleapis.com`, `sts.googleapis.com`, `www.cloudflare.com` | the VM's external address, direct (implied allow-all egress) |

The coarse URLs are the ones `-clock https-date` uses on that platform, so
its egress already allows them. `-nts-max-bound` is not set: the default, 100 ms.
The build scripts check the flags (`nitro-eif.sh`, `gcp/build-image.sh`,
`azure/deploy.sh render`) and refuse a command that has `-clock`.

The UDP relay (`platform-aws/udprelay`, `platform-aws/deploy/README.md`, "NTS clock in the
enclave"): one vsock connection per NTP query; frames of a u16 length and
1 to 2048 octets; the destination first, then a status, then datagrams. It
sends only to ports 123 and 4123, and only to one of the four NTS-KE host
names (resolved by the relay), an address those names resolve to, or
Netnod's NTP block `194.58.200.0/21`. Rate limits per session, per address
and in all. It cannot forge an answer (NTS authenticates every one), only
delay or drop it.

Not checked on a cloud: the delays and bounds there, UDP 123 and 4123 out of
ACI and Confidential Space, and the relay and proxies on EC2.
