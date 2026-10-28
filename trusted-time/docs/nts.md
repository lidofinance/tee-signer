# nts: the signer's NTS time client

The runner's trusted time comes from Network Time Security (RFC 8915) over
NTPv4 (RFC 5905), from several operators at once, and from nothing else. The
client is this package on the Go standard library; only the NTPv4 exchange
itself comes from a library. This
note says what the client is made of, what it guarantees and how it is tested.
The clock built on it is `trusted-time/clock.NTS`; its rules (polls, drift
check, coarse check, the bound that fails `Now` over 100 ms) are in that
package's comments.

## What the library does and what stays here

| Part | Where | What |
| --- | --- | --- |
| AES-SIV-CMAC-256 (RFC 5297), the one AEAD offered | `nts/siv.go` on `crypto/aes` | branch-free `dbl`, constant-time tag compare; checked against RFC 5297 appendix A.1 and A.2 (`AESSIVSelfTest`) and against `ntstest`'s independent AES-SIV on random inputs |
| NTS-KE: TLS 1.3 with ALPN `ntske/1`, the records, the two keys from the TLS exporter, the cookies | `nts/ke.go` on `crypto/tls` | `KeyExchange` dials through the platform (`DialFunc`), pins the operator's roots and checks the certificate against the caller's clock, never the host's; the records are read with the caps below |
| The NTPv4 header, the random transmit timestamp, the socket, the origin check | `github.com/beevik/ntp` | one query per call; the first answer is taken |
| The NTS extension fields: Unique Identifier, cookie, placeholders, the authenticator; the new cookies | `nts/query.go` on the library's extension hook | the authenticator covers the header and every field before it; an answer without our identifier or a verifying authenticator is refused |
| T1 and T4 | `nts/query.go` | the library's `GetSystemTime` hook returns `Monotonic` (`CLOCK_MONOTONIC_RAW`), so every offset is real time minus the local monotonic clock |
| Kiss-o'-Death | `nts/query.go` | stratum 0 with our Unique Identifier, taken without an authenticator as RFC 8915 section 5.7 allows: NTSN runs NTS-KE again, RATE, DENY and RSTR go to the clock |
| Sample: offset, delay, error bound and the RFC 5905 checks | `nts/sample.go` | `measure`, below |
| Quorum of 3 to 16 operators, one of which may be wrong | `nts/quorum.go` | `Quorum`, below |
| Pinned roots per operator, the public servers | `nts/roots.go`, `nts/roots/` | |
| Loopback NTS-KE and NTP servers for tests, with their own AES-SIV | `nts/ntstest/` | checked against RFC 5297 appendix A.1 |

Caps on untrusted bytes: an NTS-KE response of at most 65536 octets, 64
records, a record body of 1024, cookies of 1 to 1024 octets, 8 cookies kept,
a server name of 255; an NTP answer of at most 2048 octets, at most 8
cookies in one answer.

The package has code only with the build tag `nts`: the cloud runners carry
it, the dev runners do not (`scripts/common.sh`, `runner_tags`;
`scripts/check-deps.sh` checks both, and that only the builds with the tag
link the NTP library and, through it, `golang.org/x/net` and `x/sys`).

## Sample (RFC 5905 sections 7.3, 8, 11.2)

T1 and T4 come from the local monotonic clock, T2 and T3 from the server, so
the offset is real Unix time minus the local clock. Delay = (T4 - T1) - (T3 -
T2); offset = ((T2 - T1) + (T3 - T4)) / 2; bound = delay/2 + rootdelay/2 +
rootdisp + 2^precision + rho (T4 - T1) + 3 ns of rounding, rho = 500 ppm
(RFC 5905 MAXFREQ). Refused: T4 before T1, T3 before T2, a negative delay,
stratum outside 1 to 15, leap indicator 3, a zero reference timestamp or one
after T3, and a bound over 1 s (MAXDIST).

## Quorum

`Quorum(intervals, now)`: 3 to 16 intervals from distinct operators, F = 1.
Each bound first grows by rho times its age at `now`. [lo, hi] spans the
points that at least n - 1 intervals cover (the intersection of RFC 5905
section 11.2.1, without clustering); no such point is an error. The result
is the midpoint, bound (hi - lo) / 2.

## Tests

- `nts`: the record rules of NTS-KE on hand-made responses; key exchange and
  queries against the loopback servers; the certificate checked against the
  given clock; TLS 1.2, a missing ALPN, an Error record and foreign roots
  refused; RATE, a forged authenticator and NTSN; no cookie left after eight
  lost requests; the quorum; the pinned roots; the AES-SIV self-test and the
  cross check against the test server's AES-SIV.
- `clock`: the quorum of three, one server wrong, two wrong, the bound that
  grows until `Now` fails, the coarse check, the Kiss-o'-Death codes, NTSN,
  the drift check, duplicate operators, time that never goes back.
- `clock/nts_interop_test.go` (network, `NTS_INTEROP=1`): the four public
  operators.
- `tests/e2e/nts_relay_test.go`: the Nitro runner's clock through the UDP
  relay and the proxy routes.

## In the runner and the clouds

`tee-signer/platforms_nts.go`: `-nts-clock` (or `RUNNER_NTS_CLOCK=1`) gives a
tagged runner the NTS clock, with `-nts-coarse-urls`, `-nts-wait` and
`-nts-max-bound`. The clock dials through the platform (`platform.Platform.Dial`).
`runner -nts-clock-check` queries the servers once and prints the result;
`runner -nts-selftest` prints the library version and runs the AES-SIV
self-test. A debug build (tag `debugimport`) can name test servers instead
of the public ones (`RUNNER_NTS_TEST_SERVERS`, `RUNNER_NTS_TEST_ROOTS`); a
release build cannot.

Each cloud image runs the NTS clock from its measured command, so the host
cannot turn it off or point it elsewhere:

| Image | Where the flags are | Coarse check URLs | Path to the NTS servers |
| --- | --- | --- | --- |
| AWS EIF | `platform-aws/deploy/enclave/Dockerfile` (PCR0, PCR2) | KMS, STS, `www.cloudflare.com`, through the platform's vsock-proxy routes | NTS-KE through vsock-proxy (vsock 8005 to 8008, TCP 4460), NTP through `udprelay` on the parent (vsock 7102) |
| Azure | `platform-azure/deploy/aci-template.json` command (CCE policy hash) | `login.microsoftonline.com`, `management.azure.com`, `www.cloudflare.com` | ACI's default outbound access, direct |
| GCP | `platform-gcp/deploy/Dockerfile` entrypoint (image digest) | `cloudkms.googleapis.com`, `sts.googleapis.com`, `www.cloudflare.com` | the VM's external address, direct (implied allow-all egress) |

The UDP relay (`platform-aws/udprelay`, `platform-aws/deploy/README.md`, "NTS
clock in the enclave"): one vsock connection per NTP query; frames of a u16
length and 1 to 2048 octets. It sends only to ports 123 and 4123, and only to
one of the four NTS-KE host names, an address those names resolve to, or
Netnod's NTP block. It cannot forge an answer (NTS authenticates every one),
only delay or drop it.
