# nts: the signer's NTS time client

The runner's trusted time comes from Network Time Security (RFC 8915) over
NTPv4 (RFC 5905), from several operators at once, and from nothing else.
The client is a C core, `trusted-time/ntscore`, under a Go wrapper,
`trusted-time/nts`; the clock built on them is `trusted-time/clock.NTS`.
This note says where the line between the two runs and why, what the core
is made of, what it guarantees and how it is tested.

## The boundary

The split is made for a trusted application: an OP-TEE TA, where Go cannot
run and where the wrapper would be the untrusted world. The rule that
places the line is that **the wrapper is the network**: whatever it hands
the core must be something an attacker on the wire could hand it too, that
is ciphertext and datagrams. Everything the time rests on lives in the
core, and the core gets what it needs through host operations of two kinds
(`ntscore/nts_core.h`, `nts_host_ops`):

| Operation | Trust | On the cloud runners | In an OP-TEE TA |
| --- | --- | --- | --- |
| Random bytes for the request | trusted | `crypto/rand` | `TEE_GenerateRandom` |
| The monotonic clock (T1, T4, the ageing of bounds) | trusted | `CLOCK_MONOTONIC_RAW` | the secure counter |
| The TLS 1.3 session of NTS-KE: ALPN `ntske/1`, the chain to the operator's pinned roots, the certificate dated by the core's time, the keys from the exporter | trusted | `crypto/tls` | mbedTLS inside the TA |
| The TCP connection under it; the UDP socket of the NTP exchange | untrusted | `net`, through the platform's dialer | the GP TEE sockets, served by the normal world |

What the core holds: the NTS-KE records and their check, the keys and the
cookie jar, the request with its random transmit timestamp, Unique
Identifier and nonce, the check of every response, the measurement, the
samples of every server, the quorum, the drift and coarse checks, the
anchored result and its ageing, and the time it serves. The whole runner
is inside the TEE on AWS, Azure and GCP, so there the wrapper implements
every operation and nothing changes in behaviour; in a TA the three
trusted ones move inside and the sockets stay out.

If the sockets lie, delay or drop, the client gets no time, never a wrong
one: NTS authenticates every answer, the Unique Identifier and the random
origin refuse replays, delay widens the bound, and a bound past the limit
refuses the time. What stays outside is harmless there: when to poll (if
the wrapper stops polling, the bound ages past the limit and the core
refuses), logging and status. The server list and the pinned roots are
configuration of the core and reach it by a trusted path (the image, the
sealed setup), never from the wrapper at run time.

Two host inputs are trusted a little, until the first quorum: the coarse
time (the HTTPS-date quorum) dates the certificates of the first key
exchanges and is a gross check on every quorum after; the NTP era of
server timestamps is fixed by a build-time floor (`nts.FloorTime`), never
by it. After the first quorum the core dates certificates with its own
time.

## What the core is made of

Freestanding C11 (`ntscore/*.c`, about 1,900 lines), no allocation, no
floating point, no outside symbol but `memcpy`, `memmove`, `memchr`,
`memset` and `memcmp` (`make check` in `ntscore/` builds it so and checks);
128-bit arithmetic where the Go code it replaced used `big.Int`, with its
own division. The checks and their order are those of the Go code, error
code for error value.

| Part | Where | What |
| --- | --- | --- |
| AES-SIV-CMAC-256 (RFC 5297), the one AEAD offered | `siv.c` | an AES-128 of its own (S-box computed, not typed), branch-free `dbl`, constant-time tag compare; checked against RFC 5297 appendix A.1 and A.2 (`nts.AESSIVSelfTest`), Wycheproof, and `ntstest`'s independent AES-SIV |
| NTS-KE records: the request, the framing of a response as it arrives, the check of a whole response | `ke.c` | the caps below; an Error or Warning record, an unknown critical record, a missing or duplicate record, a wrong protocol or AEAD refused |
| The NTP time formats with era-safe conversion (RFC 5905 section 6) | `sample.c` | the era of T2 and T3 is the one nearest the floor |
| The NTPv4 request: the header with the random transmit timestamp, the Unique Identifier, the cookie, the placeholders, the authenticator with the C2S key | `ntp.c` | each cookie goes out once; the request asks for enough placeholders to refill the jar of 8 within 1280 octets |
| The check of the response, in this order: length, version 4, mode 4, the origin timestamp equal to our transmit timestamp, the extension fields (RFC 7822: a multiple of 4, at least 16 octets), our Unique Identifier before the authenticator (exactly ours, constant time), the authenticator with the S2C key over everything before it (nonce of 1 octet or more, zero padding), the new cookies from the encrypted part (1 to 1024 octets each, at most one more than the placeholders), leap indicator and stratum | `ntp.c` | a refused response leaves the request open for the real one; an accepted one closes it, so a replay is refused |
| Sample: offset, delay, error bound and the RFC 5905 checks | `sample.c` | below; every precision value a server can state is taken (-128 is a 1 ns term, not a shift by 128) |
| Quorum of 3 to 16 operators, one of which may be wrong | `quorum.c` | below |
| The client: the cookie jar, one poll (NTS-KE if needed, one query with T1 and T4 from the monotonic clock, the answers that fail the check dropped until the real one comes or the time runs out, Kiss-o'-Death and its policy, the backoff), the quorum of the fresh samples, the coarse and drift checks, the anchored result, the time served | `client.c` | the rules of the clock, below |
| The Go wrapper: the host operations, the pinned roots per operator, the public servers | `nts/` | |
| The clock: when to poll, logs, status | `clock/nts.go` | |
| Loopback NTS-KE and NTP servers for tests, with their own AES-SIV | `nts/ntstest/` | checked against RFC 5297 appendix A.1 |

Caps on untrusted bytes: an NTS-KE response of at most 65536 octets, 64
records, a record body of 1024, cookies of 1 to 1024 octets, 8 cookies kept,
a server name of 255; an NTP answer of at most 2048 octets, at most 8
cookies in one answer.

Kiss-o'-Death: stratum 0 with our Unique Identifier and origin timestamp,
as RFC 8915 section 5.7 asks; it does not end the query, which reads on
for half a second for a real answer, since those fields travel in the
clear and anyone on the path can forge a KoD. The core notes whether the
KoD carried an authenticator that verifies, obeys an authenticated RATE
(the poll doubles, up to 1024 s), DENY or RSTR (1024 s of silence and a
new key exchange, never the rest of the process) and counts an
unauthenticated one without acting on it; after NTSN, which is never
authenticated, it keeps polling with the cookies it holds and runs NTS-KE
when they run out (section 5.7).

The packages have code only with the build tag `nts`: the cloud runners
carry them, the dev runners do not (`scripts/common.sh`, `runner_tags`;
`scripts/check-deps.sh` checks both). The module has no dependency outside
the standard library; the core is compiled by cgo with the C compiler of
the runner build.

## Sample (RFC 5905 sections 7.3, 8, 11.2)

T1 and T4 come from the local monotonic clock, T2 and T3 from the server, so
the offset is real Unix time minus the local clock. Delay = (T4 - T1) - (T3 -
T2); offset = ((T2 - T1) + (T3 - T4)) / 2; bound = delay/2 + rootdelay/2 +
rootdisp + 2^precision + rho (T4 - T1) + 3 ns of rounding, rho = 500 ppm
(RFC 5905 MAXFREQ). Refused: T4 before T1, T3 before T2, a negative delay,
stratum outside 1 to 15, leap indicator 3, a zero reference, receive or
transmit timestamp, a reference after T3, and a bound over 1 s (MAXDIST).

## Quorum and the clock's rules

`nts_quorum`: 3 to 16 intervals from distinct operators, F = 1. Each bound
first grows by rho times its age at `now`. [lo, hi] spans the points that
at least n - 1 intervals cover (the intersection of RFC 5905 section
11.2.1, without clustering); no such point is an error. The result is the
midpoint, bound (hi - lo) / 2.

Each server is asked every 32 s (at least 16 s apart), with a query timeout
of 5 s or half the interval. The latest sample of each server, at most 4
intervals old, goes to the quorum. Between quorums the bound grows by rho
of the elapsed monotonic time; the time is refused once the bound is over
100 ms. Each quorum is checked against the last one and against a baseline
quorum about 32 intervals older: if the offset moved more than the two
bounds and rho allow, the local clock broke rho (or more servers are
wrong), the quorum is refused and so is the time until the next quorum
agrees with it. Each quorum is checked against the coarse time: more than
30 s off, after the coarse reading's one-second resolution, is refused.
The time never goes back.

## Tests

- `ntscore`: the tests of the Rust core, ported twice now, run against the
  C through the binding. `ntp_test.go` builds the server side from the RFC
  on `ntstest`'s independent AES-SIV and checks the request layout and
  limits, a round trip, every single-octet change of a valid response
  (refused, except stratum 0, which is a KoD), the Unique Identifier and
  origin checks, replays, truncated and oversized packets, malformed plain
  and encrypted fields, fields after the authenticator, cookies in the
  clear, the KoD codes, leap and stratum, version and mode, the
  authenticator's nonce and padding rules. `sample_test.go`: the bound on a
  symmetric path, the root values, the true time inside the bound for any
  path asymmetry, the refusals, extreme inputs, every precision value.
  `time_test.go`: the era boundary of 2036, round trips with a pivot up to
  68 years away, overflow. `ke_test.go`: the record rules of NTS-KE, record
  by record. `random_test.go`: 20,000 garbage and 20,000 mutated packets
  into each parser from a fixed seed (2,000 with `-short`). `siv_test.go`:
  Wycheproof's AES-SIV-CMAC vectors of the 32-octet key (`testdata/`).
  `quorum_test.go`: the quorum against its definition on random intervals.
- `ntscore/hostile_test.go`: **the hostile host**. A host whose untrusted
  operations do whatever the fuzzer picks: key exchange responses mutated,
  garbage, another operator's cookies, refused; datagrams that are the
  honest answer, the answer with octets appended, mutated, garbage, a
  replay of any earlier answer, a forged or an authentic Kiss-o'-Death of
  any code, a forgery before the real answer, another server's answer
  under its keys, nothing at all; sockets that fail to open, reset, time
  out; a virtual clock that jumps by microseconds or by days; a coarse
  time a little or wildly off; one of the servers lying by up to a
  thousand seconds. The trusted operations stay honest. On every run: a
  sample is taken only when the honest answer to the core's own live
  request was delivered, and it measures that server within its bound;
  every request verifies under the C2S key and carries a Unique
  Identifier never used before; the jar never holds more than 8 cookies;
  a time is served only from a quorum of 3 or more operators and, with
  at most one liar, within its bound of the true time; it never goes
  back; the key exchange request and the NTP address are the right ones.
  `TestHostileHostRounds` runs 300 fixed seeds (40 with `-short`);
  `FuzzHostileHost` runs the harness under the fuzzing engine.
- The fuzz targets, for `go test -fuzz` and `scripts/fuzz.sh`:
  `FuzzVerifyResponse`, `FuzzKEResponse`, `FuzzMeasure` (answers built
  from a known truth, the true time inside the bound), `FuzzSIV` (the
  core's AES-SIV against `ntstest`'s copy), `FuzzQuorum` (the one-liar
  property), `FuzzHostileHost`.
- `scripts/test-modules.sh trusted-time` also builds the core
  freestanding (`make -C ntscore check`) and runs the `ntscore` and `nts`
  tests once more under AddressSanitizer and UndefinedBehaviorSanitizer
  (`go test -asan`).
- `nts`, against the loopback servers: key exchange and queries through
  the client; the certificate dated by the given coarse time; TLS 1.2, a
  missing ALPN, an Error record, octets after End of Message, foreign
  roots, a wrong host name and no roots refused; RATE, a forged
  authenticator (dropped, the query times out and says why), NTSN with the
  cookies kept, a decoy sent before the real answer (dropped, the real
  answer taken), a forged DENY before the answer and alone, the server's
  own DENY; precision -128 and 127; eight lost requests, then NTS-KE again;
  a failed dial that costs no cookie; the pinned roots; the AES-SIV
  self-test.
- `clock`: the quorum of three, one server wrong, two wrong, the bound that
  grows until `Now` fails, the coarse check, the Kiss-o'-Death codes, NTSN,
  a forged KoD, the drift check (a jump, a steady rate over rho caught by
  the baseline), duplicate operators, time that never goes back, DENY
  lifted after the longest poll, the query timeout of half the interval.
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

## Toward a trusted application

Not done here, and not decided: the OP-TEE build. The core is ready for
it (freestanding, the symbol check, the host operations split as above);
what a TA needs besides is the three trusted operations inside it, TLS
1.3 with the exporter among them (mbedTLS), the GP TEE sockets for the
untrusted two, the configuration by a trusted path, and a signer core in
the same application to take the time from `nts_bounded`.
