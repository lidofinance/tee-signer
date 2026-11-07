# nts: the signer's NTS time client

The runner's trusted time comes from Network Time Security (RFC 8915) over
NTPv4 (RFC 5905), from several operators at once, and from nothing else.
The client is a C core, `trusted-time/ntscore` (the C in `ntscore/c`,
its cgo binding in `ntscore/go`), under a Go wrapper, `trusted-time/nts`;
the clock built on them is `trusted-time/clock.NTS`.
This note says where the line between the two runs and why, what the core
is made of, what it guarantees and how it is tested.

## The boundary

The split is made for a trusted application: an OP-TEE TA, where Go cannot
run and where the wrapper would be the untrusted world. The rule that
places the line is that **the wrapper is the network**: whatever it hands
the core must be something an attacker on the wire could hand it too, that
is ciphertext and datagrams. Everything the time rests on lives in the
core, and the core gets what it needs through host operations of two kinds
(`ntscore/c/nts_core.h`, `nts_host_ops`):

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
by it. The core dates certificates with its own time whenever it would
serve it, under the rules of the time served below; otherwise the coarse
time does: before the first quorum, after the drift check refused one, and
once the quorum in force has aged past its bound or age limit (a stale
quorum on a counter run ahead would otherwise date certificates ahead of
real time). A coarse time that is not after the floor (no reading, a zero time,
a host clock reset to 2000) is no time: the core refuses the key exchange
before it asks the host, so no certificate is checked at it, and Go's
`crypto/x509`, which reads a zero time as `time.Now()`, never sees one
(the host operation refuses a time at or before 1970 as well).

Residual: the HTTPS-date sources' own TLS checks their certificates
against the system clock, because the platform HTTP clients set no `Time`
(`clock/httpsdate.go`). A host that sets the system clock and holds leaked
certificates for a majority of the coarse hosts can answer their `Date`
headers itself, move the coarse clock, and with it the time NTS-KE checks
certificates at before the first quorum. Without such certificates,
setting the system clock moves neither. HTTPS-date is no longer a signing
clock, but it is still the coarse check, so this residual stays.

## What the core is made of

Freestanding C11 (`ntscore/c/*.c`, about 1,900 lines), no allocation, no
floating point, no outside symbol but `memcpy`, `memmove`, `memchr`,
`memset` and `memcmp`. `make -C ntscore/c` builds the archive the Go
binding links, so a runner carries the core as checked, and `make check`
there lists the archive's undefined symbols with the compiler of the
build: what the compiler emits on its own counts too (a 128-bit division
becomes a call into its runtime), so the 128-bit arithmetic, used where
the Go code it replaced used `big.Int`, has its own division and none by
a variable. Secrets are wiped through a volatile pointer (`nts_wipe`), not
by a `memset` the compiler may drop. The checks and their order are those
of the Go code, error code for error value. The core is sized by its
servers (`nts_core_size_for`): about 110 KB each, mostly the buffers of
one key exchange and one query, so the four public operators take about
450 KB.

| Part | Where | What |
| --- | --- | --- |
| AES-SIV-CMAC-256 (RFC 5297), the one AEAD offered | `siv.c` | an AES-128 of its own on the CPU's instructions (AES-NI, the ARMv8 Cryptography Extension; found at start), else constant-time software with the S-box computed per byte as the field inverse, never a table: the host shares the cache and sees every request and tag, so a table lookup by a key byte would leak the keys; branch-free `dbl`, constant-time tag compare; the vectors (RFC 5297 appendix A.1 and A.2 in `nts.AESSIVSelfTest`, Wycheproof) and the fuzzer against `ntstest`'s independent AES-SIV run on both paths |
| NTS-KE records: the request, the framing of a response as it arrives, the check of a whole response | `ke.c` | the caps below; an Error or Warning record, an unknown critical record, a missing or duplicate record, a wrong protocol or AEAD refused |
| The NTP time formats with era-safe conversion (RFC 5905 section 6) | `sample.c` | the era of T2 and T3 is the one nearest the floor |
| The NTPv4 request: the header with the random transmit timestamp, the Unique Identifier, the cookie, the placeholders, the authenticator with the C2S key | `ntp.c` | each cookie goes out once (one whose send failed is not used again: it may have left); the request asks for enough placeholders to refill the jar of 8 within 1280 octets; every extension field is at least 16 octets (RFC 7822 section 7.5.1.4), so a cookie under 12 octets is padded with zeros, which the Rust client did not do |
| The check of the response, in this order: length, version 4, mode 4, the origin timestamp equal to our transmit timestamp, the extension fields (RFC 7822: a multiple of 4, at least 16 octets), our Unique Identifier before the authenticator (exactly ours, constant time), the authenticator with the S2C key over everything before it (nonce of 1 octet or more, zero padding), the new cookies from the encrypted part (1 to 1024 octets each, at most one more than the placeholders), leap indicator and stratum | `ntp.c` | a refused response leaves the request open for the real one; an accepted one closes it, so a replay is refused |
| Sample: offset, delay, error bound and the RFC 5905 checks | `sample.c` | below; every precision value a server can state is taken (-128 is a 1 ns term, not a shift by 128) |
| Quorum of 3 to 16 operators, one of which may be wrong | `quorum.c` | below |
| The client: the cookie jar, one poll (NTS-KE if needed, one query with T1 and T4 from the monotonic clock, the answers that fail the check dropped until the real one comes or the time runs out, Kiss-o'-Death and its policy, the backoff), the quorum of the fresh samples, the coarse and drift checks, the anchored result, the time served | `client.c` | the rules of the clock, below |
| The cgo binding: `Core` for the clock, the host operations routed to Go, the core's functions one by one for the tests | `ntscore/go/` | links the archive of `ntscore/c`; the only place a Go pointer meets the C |
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
when they run out (section 5.7). So a real NTSN (the server lost the keys
behind the cookie) costs its operator up to 8 polls, about 128 s, before
the key exchange, on purpose: a key exchange at once is what a forged
NTSN per poll, which anyone on the path can send, would turn into a TLS
session every 16 s; the other three operators keep the quorum meanwhile.

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

Each server is asked every 16 s (RFC 5905 MINPOLL, the shortest allowed),
with a query timeout of 5 s or half the interval. The latest sample of
each server, at most 60 s old, goes to the quorum. Between quorums the
bound grows by rho of the elapsed monotonic time; the time is refused once
the bound is over 100 ms, and once the oldest sample of the quorum in
force is over 60 s old on the local clock.

The host sets that clock's rate. If it blocks the servers and runs the
clock fast, the bound ages too slowly, and only the age limit keeps the
time served within 60 s of real time (`TestNTSClockFastCounterLeadIsBounded`).
With the servers answering, a counter run fast moves the offset: the
drift check refuses the first quorum that shows it and re-admits the lead
once a quorum of new samples agrees with the refused one, so the bound on
the lead is then the coarse check's, 30 s plus the coarse reading's 1 s
resolution, and about 106 s if the host also leads the coarse clock by
the 75 s its `MaxAdvance` allows (the HTTPS-date sources blocked). That
is the lead the restart floor of signer-core must cover (its README,
"Restart floor"); a mainnet epoch is 384 s.
The other direction has no such limit: a host that runs the clock slow
makes the samples look young and the polls rare, so the time served falls
behind real time without a bound until the drift check sees new samples.
On a platform without a host-proof counter (SEV-SNP without Secure TSC)
the host can do this. The runner's own signatures stay safe, because its
time never goes back and a restart waits for a fresh quorum. What lags: a
client certificate that expired during the lag is still accepted, and a
key imported during it gets a restart floor that is too low for history
it built elsewhere.

A healthy server answers every 16 s, so one lost answer still leaves its
sample under 60 s; a quorum needs 3 of the 4 operators. If every server
is out of reach, signing stops within 60 s and resumes with the next
quorum: within about one interval after a short outage, later after a
long one, when the cookies ran out and NTS-KE backs off (up to 1024 s;
before the first quorum of a run NTS-KE is tried again every 16 s, so a
relay that comes up late does not push the first quorum past the
runner's start wait).
HEALTH reports `sample_age_ms`, `max_sample_age_ms` and, while the clock
refuses, the reason in `refused`.

Each quorum is checked against the last one and against a baseline quorum
about 64 intervals (17 minutes) older: if the offset moved more than the
two bounds and rho allow, the local clock broke rho (or more servers are
wrong), the quorum is refused and so is the time until a quorum of new
samples agrees with it; the refused quorum's samples do not enter a quorum
again. The status line's `drift_ppm` is the rate over that baseline,
`drift_err_ppm` what the bounds leave open; a quorum is refused exactly
when |drift_ppm| > 500 + drift_err_ppm. The core keeps at most 64 quorums
for this: the baseline, the newest, and between them candidates for the
next baseline at least 1/60 of the baseline apart (a refresh forms a
quorum, four per interval, and one closer than that replaces the newest),
so how often the wrapper combines does not matter and the baseline is at
most 1/60 older than it should be. Each
quorum is checked against the coarse time: more than 30 s off, after the
coarse reading's one-second resolution, is refused, and the time with it
until a quorum passes, as after a drift refusal. The time never goes
back.

## Tests

- `ntscore/go`: the tests of the Rust core, ported twice now, run against the
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
  Wycheproof's AES-SIV-CMAC vectors of the 32-octet key (`testdata/`),
  and the refusals the vectors do not show (RFC 5297 A.2 with its strings
  reordered, another key, ciphertexts shorter than the tag).
  `quorum_test.go`: the quorum against its definition on random intervals.
  `client_test.go`: the client's rules through an honest host: the drift
  baseline stays about 64 intervals old however often combine runs, the
  refused samples do not come back, samples over the age limit, keys or a
  response of the wrong length from the key exchange, the jar refilled
  through placeholders after lost requests, a failed send that spends its
  cookie, authenticated DENY, RSTR and RATE, the NTP address without
  Server and Port records and for an IPv6 server, cores on many
  goroutines, one error and text per code (the numbers are the header's,
  checked at compile time in `lowlevel.go`).
- `ntscore/go/hostile_test.go`: **the hostile host**. A host whose untrusted
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
  Identifier and a cookie never sent before; the jar never holds more than 8 cookies;
  a time is served only from a quorum of 3 or more operators and, with
  at most one liar, within its bound of the true time, from samples within
  the age limit; it never goes back; the key exchange request and the NTP
  address are the right ones; the certificate is dated by the core's own
  time while it would serve it and by the coarse reading otherwise;
  cookies of 4 to 1024 octets (the padding of short ones, the request
  without placeholders for long ones).
  `TestHostileHostRounds` runs 300 fixed seeds (40 with `-short`);
  `FuzzHostileHost` runs the harness under the fuzzing engine. The same
  host with every choice honest drives `client_test.go`: the NTS-KE
  backoff (interval, doubling to MaxPoll, reset by a success), a CSPRNG
  that fails (no cookie, no socket), the Server and Port records each
  alone and an IPv6 KE host, an authentic KoD followed by the answer
  within the grace (the answer wins) and one of an unknown code (only
  counted), the certificate dated by the core's time with the coarse
  clock 20 s off, the counter that went back, the time that never goes
  back when every server's clock moves back, Close.
- The fuzz targets, for `go test -fuzz` and `scripts/fuzz.sh`:
  `FuzzVerifyResponse`, `FuzzKEResponse`, `FuzzMeasure` (answers built
  from a known truth, the true time inside the bound), `FuzzSIV` (the
  core's AES-SIV against `ntstest`'s copy), `FuzzQuorum` (the one-liar
  property), `FuzzEncryptedPart` (plaintexts sealed under the test key,
  so every input reaches the parser behind the authenticator),
  `FuzzHostileHost`; in `nts`, `FuzzReadKEResponse` (the incremental
  reader against the core's framing walk, however the bytes are chunked).
  The nightly run keeps the inputs found so far (an actions cache of
  `GOCACHE/fuzz`), and runs the trusted-time targets with `-asan`, so the
  C under them is instrumented.
- The C core's own fuzz targets (`ntscore/c/fuzz/`, `make fuzz`,
  `fuzz/fuzz.sh ci|long|replay`; `make fuzz-core` at the root runs them
  with signer-core's and markformat's, in CI and nightly): the NTS-KE
  parsers, the response check against a fixed request, AES-SIV (a sealed
  message opens, a changed bit does not, the two AES paths agree), the
  measurement, and the hostile host in C: the whole client with its
  untrusted operations fed from the input (honest, mutated, garbage,
  Kiss-o'-Death, another server's keys, nothing; sockets that fail; a
  counter that jumps). They run the C under AddressSanitizer and
  UndefinedBehaviorSanitizer with coverage guidance, which the Go engine
  cannot give the C; the Go targets keep the protocol oracles.
- `scripts/test-modules.sh trusted-time` also builds the core's archive
  and checks its symbols (`make -C ntscore/c check`), runs the `ntscore`
  and `nts` tests once more against an archive built with AddressSanitizer
  and UndefinedBehaviorSanitizer (`make -C ntscore/c asan`, `go test
  -asan`), and, where the cross compiler and qemu-user are installed (the
  x86_64 CI runner), the `ntscore` tests once more on aarch64: the AES is
  hand-written and the arithmetic 128-bit, so one architecture's pass
  does not vouch for the other. `COV=1` adds a gcov run of the C
  (`make -C ntscore/c cov`, the tests with the tag `ntscov`, `make
  cov-report`): the line coverage of the core by its Go tests.
- `nts`, against the loopback servers: key exchange and queries through
  the client; the certificate dated by the given coarse time, and no key
  exchange without one (a zero time, 1970, 2000, just before the floor:
  refused before the dial); TLS 1.2, a
  missing ALPN, an Error record, octets after End of Message, foreign
  roots, a wrong host name and no roots refused; RATE, a forged
  authenticator (dropped, the query times out and says why), NTSN with the
  cookies kept, a decoy sent before the real answer (dropped, the real
  answer taken), a forged DENY before the answer and alone, the server's
  own DENY; precision -128 and 127; eight lost requests, then NTS-KE again;
  a failed dial that costs no cookie; a dial that never returns, ended by
  the query's own timeout under a caller's context without one; a KE
  server that accepts and never speaks (the exchange timeout, no cookie);
  a caller's context that ends the poll; Close during a poll (waits for
  it, refuses after); the polls of three servers on one core at once
  while the time is read, then their quorum; the incremental KE reader
  with every chunking, a stream that ends early, a response over the
  buffer, a reader without progress; the pinned roots; the AES-SIV
  self-test.
- `clock`: the quorum of three, one server wrong, two wrong, the bound that
  grows until `Now` fails, the coarse check, the Kiss-o'-Death codes, NTSN,
  a forged KoD, the drift check (a jump, a steady rate over rho caught by
  the baseline; the refused samples do not form a quorum again), duplicate
  operators, time that never goes back, DENY lifted after the longest poll,
  RATE capped at it, the query timeout of half the interval, samples over
  the age limit (no time, no quorum, HEALTH says why), a fast counter
  while the servers are blocked (the lead stays under a minute), no
  certificate check without a coarse time, status snapshots that own
  their counts.
- `clock/nts_interop_test.go` (network, `NTS_INTEROP=1`): the four public
  operators.
- `tests/e2e/nts_relay_test.go`: the Nitro runner's clock through the UDP
  relay and the proxy routes.

## In the runner and the clouds

`tee-signer/platforms_nts.go`: `-nts-clock` (or `RUNNER_NTS_CLOCK=1`) gives a
tagged runner the NTS clock, with `-nts-coarse-urls`, `-nts-wait` and
`-nts-max-bound` (or their variables; a set flag wins). The runner refuses
a max bound over 250 ms: a sample's bound is about half its round trip, so
that leaves room for servers about 400 ms away. With no quorum within
`-nts-wait` (90 s by default) the start fails and the runner exits with
the peers' status in its error line, which goes to the host on Nitro. The
supervisor starts it again: `restartPolicy` `OnFailure` on ACI,
`tee-restart-policy=OnFailure` on Confidential Space, the operator or the
parent's service manager on Nitro. A runner that went on without a quorum
would load no share (each share's restart floor reads the clock) and
would not load them once the quorum formed. The clock dials through the
platform (`platform.Platform.Dial`; nil is the default dialer).
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

The coarse URLs are hosts the platform's egress already allows. Each
command also sets `-nts-wait 90s` and `-nts-max-bound 100ms` (the
defaults), so no environment variable of the host or the launcher can
change them. The build scripts check the flags (`nitro-eif.sh`,
`gcp/build-image.sh`, `azure/deploy.sh render`), refuse a command without
`-nts-clock`, `-nts-wait` or `-nts-max-bound`, and refuse one that has
`-clock`. The runner itself refuses to start on a cloud platform whose
clock the host can set (`checkClock` in `tee-signer/main.go`). Only the
dev platform and debug builds may run on the system clock.

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
