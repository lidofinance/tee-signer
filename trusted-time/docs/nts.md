# nts: the signer's NTS time client

The runner's trusted time comes from Network Time Security (RFC 8915) over
NTPv4 (RFC 5905), from several operators at once, and from nothing else. The
client is this package on the Go standard library alone: the port of the
Rust core the runner linked before, with the sockets and the clock in Go.
This note says what the client is made of, what it guarantees and how it is
tested.
The clock built on it is `trusted-time/clock.NTS`; its rules (polls, drift
check, coarse check, the bound that fails `Now` over 100 ms) are in that
package's comments.

## What the package is made of

| Part | Where | What |
| --- | --- | --- |
| AES-SIV-CMAC-256 (RFC 5297), the one AEAD offered | `nts/siv.go` on `crypto/aes` | branch-free `dbl`, constant-time tag compare; checked against RFC 5297 appendix A.1 and A.2 (`AESSIVSelfTest`) and against `ntstest`'s independent AES-SIV on random inputs |
| NTS-KE: TLS 1.3 with ALPN `ntske/1`, the records, the two keys from the TLS exporter, the cookies | `nts/ke.go` on `crypto/tls` | `KeyExchange` dials through the platform (`DialFunc`), pins the operator's roots and checks the certificate against the caller's clock, never the host's; the records are read with the caps below |
| The NTP time formats with era-safe conversion (RFC 5905 section 6) | `nts/ntp.go` | the era of T2 and T3 is the one nearest the coarse clock's time (the pivot); the arithmetic runs in `big.Int`, so no wire value overflows it |
| The NTPv4 request: the header with a random transmit timestamp, the Unique Identifier, the cookie, the placeholders, the authenticator with the C2S key | `nts/ntp.go` | each cookie goes out once; the request asks for enough placeholders to refill the jar of 8 within 1280 octets |
| The check of the response, in this order: length, version 4, mode 4, the origin timestamp equal to our transmit timestamp, the extension fields (RFC 7822: a multiple of 4, at least 16 octets), our Unique Identifier before the authenticator (exactly ours, constant time), the authenticator with the S2C key over everything before it (nonce of 1 octet or more, zero padding), the new cookies from the encrypted part (1 to 1024 octets each, at most one more than the placeholders), leap indicator and stratum | `nts/ntp.go` | a refused response leaves the request open for the real one; an accepted one closes it, so a replay is refused |
| T1 and T4 | `nts/query.go` | `Monotonic` (`CLOCK_MONOTONIC_RAW`) around the UDP exchange, so every offset is real time minus the local monotonic clock |
| The answers that fail the check | `nts/query.go` | dropped: the query reads on until the real answer comes, the time runs out or the socket fails, so a spoofer's datagram sent before the real one does not fail the query; the last refusal is named in the timeout error |
| Kiss-o'-Death | `nts/ntp.go`, `nts/query.go` | stratum 0 with our Unique Identifier and origin timestamp, as RFC 8915 section 5.7 asks; it does not end the query, which reads on for half a second for a real answer, since those fields travel in the clear and anyone on the path can forge a KoD. The verdict says whether the KoD carried an authenticator that verifies. The clock obeys an authenticated RATE, DENY or RSTR (a server that holds the cookie's keys can sign them) and counts an unauthenticated one without acting on it; after NTSN, which is never authenticated, it keeps polling with the cookies it holds and runs NTS-KE when they run out (section 5.7) |
| Sample: offset, delay, error bound and the RFC 5905 checks | `nts/sample.go` | `measure`, below; every precision value a server can state is taken (-128 is a 1 ns term, not a shift by 128) |
| Quorum of 3 to 16 operators, one of which may be wrong | `nts/quorum.go` | `Quorum`, below |
| Pinned roots per operator, the public servers | `nts/roots.go`, `nts/roots/` | |
| Loopback NTS-KE and NTP servers for tests, with their own AES-SIV | `nts/ntstest/` | checked against RFC 5297 appendix A.1 |

Caps on untrusted bytes: an NTS-KE response of at most 65536 octets, 64
records, a record body of 1024, cookies of 1 to 1024 octets, 8 cookies kept,
a server name of 255; an NTP answer of at most 2048 octets, at most 8
cookies in one answer.

The package has code only with the build tag `nts`: the cloud runners carry
it, the dev runners do not (`scripts/common.sh`, `runner_tags`;
`scripts/check-deps.sh` checks both). It adds no module: the module has no
dependency outside the standard library.

## Sample (RFC 5905 sections 7.3, 8, 11.2)

T1 and T4 come from the local monotonic clock, T2 and T3 from the server, so
the offset is real Unix time minus the local clock. Delay = (T4 - T1) - (T3 -
T2); offset = ((T2 - T1) + (T3 - T4)) / 2; bound = delay/2 + rootdelay/2 +
rootdisp + 2^precision + rho (T4 - T1) + 3 ns of rounding, rho = 500 ppm
(RFC 5905 MAXFREQ). Refused: T4 before T1, T3 before T2, a negative delay,
stratum outside 1 to 15, leap indicator 3, a zero reference, receive or
transmit timestamp, a reference after T3, and a bound over 1 s (MAXDIST).

## Quorum

`Quorum(intervals, now)`: 3 to 16 intervals from distinct operators, F = 1.
Each bound first grows by rho times its age at `now`. [lo, hi] spans the
points that at least n - 1 intervals cover (the intersection of RFC 5905
section 11.2.1, without clustering); no such point is an error. The result
is the midpoint, bound (hi - lo) / 2.

## Tests

- `nts`: the tests of the Rust core, ported. `ntp_test.go` builds the
  server side from the RFC on `ntstest`'s independent AES-SIV and checks the
  request layout and limits, a round trip, every single-octet change of a
  valid response (refused, except stratum 0, which is a KoD), the Unique
  Identifier and origin checks, replays, truncated and oversized packets,
  malformed plain and encrypted fields, fields after the authenticator,
  cookies in the clear, the KoD codes, leap and stratum, version and mode,
  the authenticator's nonce and padding rules, and the cookie jar.
  `sample_test.go`: the bound on a symmetric path, the root values, the true
  time inside the bound for any path asymmetry, the refusals, extreme
  inputs, every precision value. `time_test.go`: the era boundary of 2036,
  round trips with a pivot up to 68 years away, overflow. `ke_test.go`: the
  record rules of NTS-KE, record by record. `random_test.go`: 20,000 garbage
  and 20,000 mutated packets into each parser from a fixed seed (2,000 with
  `-short`). `fuzz_test.go`: `FuzzVerifyResponse` and `FuzzKEResponse` for
  `go test -fuzz`. `nts_test.go`, against the loopback servers: key exchange
  and queries; the certificate checked against the given clock; TLS 1.2, a
  missing ALPN, an Error record and foreign roots refused; RATE, a forged
  authenticator (dropped, the query times out and says so), a decoy sent
  before the real answer (dropped, the real answer taken) and NTSN; precision
  -128 and 127; no cookie left after eight lost requests; the quorum; the
  pinned roots; the AES-SIV self-test and the cross check against the test
  server's AES-SIV.
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
