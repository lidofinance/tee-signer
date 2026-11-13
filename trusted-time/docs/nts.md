# nts: the signer's NTS time client

The runner's trusted time comes from Network Time Security (RFC 8915) over
NTPv4 (RFC 5905), from several operators at once, and from nothing else.
The client is a C core, `trusted-time/ntscore` (the C in `ntscore/c`,
its cgo binding in `ntscore/go`), under a Go wrapper, `trusted-time/nts`;
the clock built on them is `trusted-time/clock.NTS`.
This note says where the line between the two runs and why, what the core
is made of, what it guarantees and how it is tested. A setup can select
plain NTP in place of NTS; that is a weaker clock with its own section
("Plain NTP (unauthenticated)"), and wherever this note says the time is
authenticated it speaks of NTS.

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
samples of every server, the receipt bound of a sample, the quorum and how
many of its members may be wrong, the era of server timestamps, the drift
and coarse checks, the anchored result and its ageing, and the time it
serves. No argument of a poll or of a combine carries one of these: the
wrapper cannot pass a quorum size, a bound or an era. The whole runner
is inside the TEE on AWS, Azure and GCP, so there the wrapper implements
every operation and nothing changes in behaviour; in a TA the three
trusted ones move inside and the sockets stay out.

If the sockets lie, delay or drop, the client gets no time, never a wrong
one: NTS authenticates every answer, the Unique Identifier and the random
origin refuse replays, delay widens the bound, and a bound past the limit
refuses the time. What stays outside is harmless there: when to poll (if
the wrapper stops polling, the bound ages past the limit and the core
refuses), the shift schedule and its fallbacks, bursts and gaps, the DNS
lookup of the NTP host, logging and status.

Configuration is not a host operation. The server list, the pinned roots,
the protocol and the bounds are configuration of the core and reach it by
a trusted path (the image, the sealed setup, a signed config update),
never from the wrapper as the network. Three calls take it:

- `nts_core_init`: the list, the roots, the protocol, the bounds, the
  floor, and the capacity (how many servers a later list may hold).
- `nts_core_set_servers`: another server list on a running core
  ("Server list swap" below).
- `nts_core_set_policy`: another protocol or other bounds on a running
  core ("Policy change" below).

On the cloud runners the caller of the last two is the runner's config
sync (`server.Updates`, through its `TimeSink`), inside the TEE, after it
checked the update's signatures. In a trusted application these two calls
must not be reachable from the wrapper; who checks the update there is
open and not part of this code ("Toward a trusted application").

Both calls refuse during a poll (`NTS_ERR_BUSY`, nothing changed; the
clock keeps polls out with its refresh lock, and on `NTS_ERR_BUSY` tries
again for up to 10 s). That is an exclusion the core keeps itself, not a
rule for its caller: one atomic word in `client.c`, taken by
compare-and-swap and never waited for (inline instructions, no outside
symbol). A poll holds it shared; a configuration call, the combine, the
full status and the wipe hold it alone. Whichever comes second is
refused: the call during a poll, and equally a poll that starts while
such a call is at work, so no poll ever runs on a peer that is being
wiped or given to another server, in a trusted application too, whatever
the wrapper calls and when. Two polls of one server exclude each other
the same way. The Go binding adds its own lock on top (`Core.polls`: the
four calls take it with `TryLock` and answer `ErrBusy`, a poll waits for
them), so on the runners a poll is never the one refused. `nts_bounded`
and `nts_summary_get` stay outside the exclusion: they may run during
polls, and the caller serializes them with the combine and the
configuration calls (the binding's `Core.mu`). A value the calls refuse is
`NTS_ERR_BAD_CONFIG`, and then nothing changed. Otherwise the change is
taken, also when it leaves no quorum: then `nts_status.have_result` is
false, `nts_status.last_err` says why, and `nts_status.cold` shows the
start state. The time never goes back across either call.

Plain NTP sits inside the same core, never in Go, and only the trusted
configuration turns it on: the protocol enters through `nts_core_init`
and `nts_core_set_policy` alone, one protocol per core, never mixed in a
quorum, and the core's status names it (`nts_status.protocol`), so no
result passes for NTS. A core built with `NTS_NO_PLAIN_NTP` refuses the
protocol in both calls (`NTS_ERR_BAD_CONFIG`); that flag is for a build
where the wrapper is outside the TEE, since under plain NTP the wrapper,
being the network, can forge every answer and only the coarse check
bounds the time. `make -C ntscore/c noplain` builds that core
(`build/<arch>/noplain/`), and `scripts/test-modules.sh trusted-time`
runs the binding's tests against it (tag `ntsnoplain`). No build of a
runner sets the flag: the cloud runners are built without it, so a setup
can select plain NTP as on main.

One return code of the untrusted operations says more than "failed":
`NTS_ERR_HOST_CANCELLED`, the caller's deadline cut the exchange. The
core then counts no loss, no loss streak and no NTS-KE backoff; the
cookie is still spent. It cannot change the time. It lets the wrapper
skip a backoff, and the wrapper already chooses when to poll:
`nts_poll` polls whenever it is called, and `nts_due` with the poll
intervals behind it (`min_poll_ns` among them) is advice to the wrapper,
which a cancel does not make weaker. Any other code from the key exchange
or a socket operation is read as a plain failure (`NTS_ERR_HOST`): the
host cannot hand the core one of the core's own findings, such as "the
answer was too wide" (which ends a loss streak and clears a DENY) or a
Kiss-o'-Death.

Two host inputs are trusted a little, until the first quorum: the coarse
time (the HTTPS-date quorum) dates the certificates of the first key
exchanges and is a gross check on every quorum after. The NTP era of
server timestamps never comes from it: answers are read around the era
pivot, which is the build-time floor (`nts.FloorTime`, a constant of the
image, in the past), or the highest time served or the quorum in force
if later. Only a combine and the two configuration calls move the pivot,
never a poll, and it never goes back. A quorum before the floor or
more than 20 years after the pivot is refused before the coarse and drift
checks (`NTS_ERR_ERA_WINDOW`), so it leaves the drift history alone. A
coarse clock 2^32 s off would otherwise move every honest answer one era,
about 136 years. The core dates certificates with its own time whenever it would
serve it, under the rules of the time served below; otherwise the coarse
time does: before the first quorum, after the drift check refused one, and
once the quorum in force has aged past its bound or age limit (a stale
quorum on a counter run ahead would otherwise date certificates ahead of
real time). The coarse time never dates a certificate before the era
pivot: a reading below it is raised to it. The pivot is a time the core
has served, so real time is not before it by more than that quorum's
bound, and a wrapper that hands over a low coarse reading once no quorum
is in force (after a configuration call, a refusal, samples aged out)
cannot bring back a certificate that expired before that time. A coarse time that is not after the floor (no reading, a zero time,
a host clock reset to 2000) is no time: the core refuses the key exchange
before it asks the host, so no certificate is checked at it, and Go's
`crypto/x509`, which reads a zero time as `time.Now()`, never sees one
(the host operation refuses a time at or before 1970 as well).

The NTS time has no fallback to the coarse time. The runner's config
updates read it while the NTS clock has no quorum (`NTS.CoarseNow`;
signer-protocol protocol.md, CONFIG_UPDATE, step 3), and so does the
start fallback to the config log's time values, which takes an update
only once the coarse time has passed its `activate_at` plus its wait
(`tee-signer/starttime.go`). Signing never reads it.

Each HTTPS-date source reads the Date of the first TLS answer of its URL,
whatever the status, and never follows a redirect: the target is a host
nobody measured into the image, may be plain HTTP (TIME-SOURCE-01), and
may have no egress route (TIME-SOURCE-02, `sts.{region}.amazonaws.com`
answers 302 to `aws.amazon.com`).

Residual: the HTTPS-date sources' own TLS checks their certificates
against the system clock, because the platform HTTP clients set no `Time`
(`clock/httpsdate.go`). A host that sets the system clock and holds leaked
certificates for a majority of the coarse hosts can answer their `Date`
headers itself, move the coarse clock, and with it the time NTS-KE checks
certificates at before the first quorum. Without such certificates,
setting the system clock moves neither. HTTPS-date is no longer a signing
clock, but it is still the coarse check, so this residual stays. The
certificates must come from the roots of each host's own catalog entry
(see "In the clouds" below), not from any root the image trusts.

## What the core is made of

Freestanding C11 (`ntscore/c/*.c`), no allocation, no
floating point, no outside symbol but `memcpy`, `memmove`, `memchr`,
`memset` and `memcmp`, and the two of the stack protector
(`__stack_chk_fail`, `__stack_chk_guard`): `-ffreestanding` drops the
distro's default stack protector, so the build names
`-fstack-protector-strong`, as signer-core's does, and a trusted
application has to provide the two. `__stack_chk_guard` shows only where
the canary is a global (aarch64); on x86_64 it is read from the thread
pointer and only `__stack_chk_fail` shows. `make -C ntscore/c` builds the
archive the Go binding links, so a runner carries the core as checked,
and `make check` there lists the archive's undefined symbols with the
compiler of the build: what the compiler emits on its own counts too (a
128-bit division becomes a call into its runtime), so the 128-bit
arithmetic, used where the Go code it replaced used `big.Int`, has its
own division and none by a variable. Beyond the seven, the check lets
through only `_GLOBAL_OFFSET_TABLE_`, the linker's own symbol under
`-fPIC` on x86_64. It also fails when the archive does not reference
`__stack_chk_fail` (the flag did not reach the objects), and so does
`scripts/build-core.sh`. Every variant of the archive (sanitizers,
coverage, noplain, fuzz) is built with the stack protector. Secrets are
wiped through a volatile pointer (`nts_wipe`), not by a `memset` the
compiler may drop. The core is sized by its capacity
(`nts_core_size_for`): 112,760 octets per server on a 64-bit build,
mostly the buffers of one key exchange and one query and the operator's
pinned roots. The clock always makes it for `nts.MaxServers` (16), about
1.8 MB, so a swap needs no new memory and moves no peer.

| Part | Where | What |
| --- | --- | --- |
| AES-SIV-CMAC-256 (RFC 5297), the one AEAD offered | `siv.c` | an AES-128 of its own on the CPU's instructions (AES-NI, the ARMv8 Cryptography Extension; found at start), else constant-time software with the S-box computed per byte as the field inverse, never a table: the host shares the cache and sees every request and tag, so a table lookup by a key byte would leak the keys; branch-free `dbl`, constant-time tag compare; the vectors (RFC 5297 appendix A.1 and A.2 in `nts.AESSIVSelfTest`, Wycheproof) and the fuzzer against `ntstest`'s independent AES-SIV run on both paths |
| NTS-KE records: the request, the framing of a response as it arrives, the check of a whole response | `ke.c` | the caps below; an Error or Warning record, an unknown critical record, a missing or duplicate record, a wrong protocol or AEAD refused |
| The NTP time formats with era-safe conversion (RFC 5905 section 6) | `sample.c` | the era of T2 and T3 is the one nearest the era pivot |
| The NTPv4 request: the header with the random transmit timestamp, the Unique Identifier, the cookie, the placeholders, the authenticator with the C2S key | `ntp.c` | each cookie goes out once (one whose send failed is not used again: it may have left); the request asks for enough placeholders to refill the jar of 8 within 1280 octets; every extension field is at least 16 octets (RFC 7822 section 7.5.1.4), so a cookie under 12 octets is padded with zeros, which the Rust client before this one did not do |
| The check of the response, in this order: length, version 4, mode 4, the origin timestamp equal to our transmit timestamp, the extension fields (RFC 7822: a multiple of 4, at least 16 octets), our Unique Identifier before the authenticator (exactly ours, constant time), the authenticator with the S2C key over everything before it (nonce of 1 octet or more, zero padding), the new cookies from the encrypted part (1 to 1024 octets each, at most one more than the placeholders), leap indicator and stratum | `ntp.c` | a refused response leaves the request open for the real one; an accepted one closes it, so a replay is refused |
| Plain NTP: the request (the 48-octet header alone, 8 random octets as the transmit timestamp) and the check of its response | `ntp.c` (`nts_plain_request`, `nts_plain_verify`) | the header checks of the NTS response, by the same code (length caps, version 4, mode 4, origin, Kiss-o'-Death on stratum 0, leap indicator 3, stratum above 15); what follows the header is ignored; no cookies, and nothing is authenticated |
| Sample: offset, delay, error bound and the RFC 5905 checks | `sample.c` | below; every precision value a server can state is taken (-128 is a 1 ns term, not a shift by 128) |
| Quorum of 3 to 16 operators under the majority rule, at least 3 agreeing | `quorum.c` (`nts_quorum`, `nts_majority_wrong`, `nts_quorum_wrong`) | below |
| The client: the cookie jar, one poll (NTS-KE if needed, one query with T1 and T4 from the monotonic clock, the answers that fail the check dropped until the real one comes or the time runs out, Kiss-o'-Death and its policy, the backoff, NTS-KE again after lost queries), the receipt bound, the quorum of the fresh samples, the era window, the coarse and drift checks, the anchored result, the time served, the server list swap and the policy change | `client.c` | the rules of the clock, below |
| The cgo binding: `Core` for the clock, the host operations routed to Go, the core's functions one by one for the tests | `ntscore/go/` | links the archive of `ntscore/c`; the only place a Go pointer meets the C |
| The Go wrapper: the host operations, the pinned roots per operator, the public servers | `nts/` | under the shift schedule with the default dialer, the NTP host is resolved once at NTS-KE (plain NTP: once, and again per loss streak), IPv4 first |
| The clock: when to poll, the server list's minimum, logs, status | `clock/nts.go` | |
| The shift schedule: who is asked when | `clock/ntsshift.go` | no build tag, no cgo |
| The server catalog | `ntscatalog/` | "The server catalog" below; no build tag, no cgo |
| Loopback NTS-KE and NTP servers for tests, with their own AES-SIV; a plain NTP server | `nts/ntstest/` | checked against RFC 5297 appendix A.1 |
| A virtual world for tests: the host operations on a clock the test moves, with made-up operators that answer, lose, lie or kiss | `nts/ntstest/ntsworld/` | every answer is a real datagram from `ntstest`'s server code; no sample is ever handed to the core |

Caps on untrusted bytes: an NTS-KE response of at most 65536 octets
(RFC 8915 section 4: clients SHOULD accept at least 65536), 64 records (a
normal response has about 12), a record body of 1024, cookies of 1 to
1024 octets, 8 cookies kept (RFC 8915 section 4.1.6), a server name of
255 (RFC 1035 section 2.3.4); an NTP request of at most 1280 octets
(RFC 8915 section 5.7, the IPv6 minimum MTU), an NTP answer of at most
2048 octets, at most one cookie more than the placeholders in one answer
(RFC 8915 section 5.7).

Kiss-o'-Death: stratum 0 with our Unique Identifier and origin timestamp,
as RFC 8915 section 5.7 asks; it does not end the query, which reads on
for half a second for a real answer, since those fields travel in the
clear and anyone on the path can forge a KoD. Under NTS the core notes whether the
KoD carried an authenticator that verifies, obeys an authenticated RATE
(the poll doubles, up to 1024 s), DENY or RSTR (1024 s of silence and a
new key exchange, never the rest of the process) and counts an
unauthenticated one without acting on it. NTSN is never authenticated
(the reference ID "NTS" and a zero octet, which nts1.ntp.hr sends for a
stale cookie, is read as NTSN too): the core counts it, keeps the keys
and keeps polling with the cookies it holds, one per poll. A key exchange
at once is what a forged NTSN per poll, which anyone on the path can
send, would turn into a TLS session per poll. A query that ends in a
kiss (NTSN or another code, authenticated or not) is not a lost query:
it neither adds to a loss streak nor ends one. So a server that answers
every query with NTSN gets its key exchange when the cookies run out,
after up to 8 polls; one that drops the old cookies without an answer
gets it from the rule for lost queries below, after 3 lost in a row,
once per streak.

Under plain NTP no kiss can be authenticated. There the core obeys RATE,
DENY and RSTR as they come (it costs availability only, and the protocol
is unauthenticated already) and counts NTSN and other codes. A plain kiss
ends the query at once: the check closed the request, and whoever can
forge the kiss can forge the answer too. This is main's rule for plain
NTP; the other choice would be to only count them, as under NTS, and then
a public server's RATE would be ignored.

The packages have code only with the build tag `nts`: the cloud runners
carry them, the dev runners do not (`scripts/common.sh`, `runner_tags`;
`scripts/check-deps.sh` checks both). The module has no dependency outside
the standard library; the core is the archive of `ntscore/c`, built by
its Makefile with the C compiler of the runner build
(`scripts/build-core.sh`), and the binding's own C is compiled by cgo
with the stack protector named (`CGO_HARDEN` in `scripts/common.sh`).

## Sample (RFC 5905 sections 7.3, 8, 11.2)

T1 and T4 come from the local monotonic clock, T2 and T3 from the server, so
the offset is real Unix time minus the local clock. Delay = (T4 - T1) - (T3 -
T2); offset = ((T2 - T1) + (T3 - T4)) / 2; bound = delay/2 + rootdelay/2 +
rootdisp + 2^precision + rho (T4 - T1) + 3 ns of rounding, rho = 500 ppm
(RFC 5905 MAXFREQ). Refused: T4 before T1, T3 before T2, a negative delay,
stratum outside 1 to 15, leap indicator 3, a zero reference, receive or
transmit timestamp, a reference after T3, and a bound over 1 s (MAXDIST).

The receipt bound. A sample whose bound at receipt is over the setup's
`max_sample_bound_ms` less the aging over the join age (38 ms at 76 s, so
62 ms at the default 100 ms; `nts_config.max_sample_bound_ns`, the limit
computed in the core, never under half the cap) joins no quorum
(`NTS_ERR_SAMPLE_WIDE`). The server's earlier sample stays. It
counts as a lost answer for the schedule, so a fallback may follow, and HEALTH counts it in
`wide`; it ends a loss streak (the cookies work) and gets no start retry.
A sample within that limit joins for its whole join age, and its bound,
aged by rho as the quorum ages it, stays within the cap all that time. A
check of the aged bound against the cap alone would let a sample with
bound B join for only 2 x (cap - B) seconds, 30 s at 85 ms, and leave
before its operator's next contact 60 s later; letting the aged bound pass
the cap would widen the error below (rv-dko.5). The setup's
`max_sample_bound_ms` and the runner's `-nts-max-sample-bound` take a cap
from `max_bound_ms`, and at least 80 ms, up to 1 s, where the cap is
off; the clock (`clock.NTS.SetPolicy`) and the core take any cap from the
max bound to 1 s. Why: a host that delays the honest answers of a small fresh set
widens their bounds, and wrong servers can then place the time anywhere
inside them while the quorum's bound looks small: two wrong of 4 or 5
fresh samples, and one wrong of exactly 3, where no wrong sample is
outvoted. The bound is a half-width, and the host's delay can put the true
time at either edge, so the error is up to twice the cap: about 200 ms at
the default 100 ms, against about 1 s each way without the cap (RFC 5905
MAXDIST, beyond which the core refuses a sample). HEALTH `bound_now_ms`
does not show this; `worst_bound_ms` does for the 3-sample case (twice the
widest member's bound; the core computes it in the combine,
`nts_status.worst`). A setup that raises the sample cap above
`max_bound_ms` gives part of that back. A far deployment raises both, and
that error grows with them (about 500 ms at 250 ms).

## Quorum and the clock's rules

`nts_quorum(intervals, n, max_wrong, now)`: 3 to 16 intervals from
distinct operators. Up to F = `max_wrong` of them may be wrong; fewer
than 2F + 1 intervals is an error. The core's combine passes the majority
rule, F = (n - 1) / 2 rounded down (`nts_majority_wrong`), but never so
many that fewer than 3 agree (`nts_quorum_wrong`, which the combine calls
itself; `nts.QuorumWrong` shows the same number to Go): 3 of 3, 3 of 4,
3 of 5, 4 of 6 and 4 of 7 must agree. With 4 intervals this is F = 1,
with 3 it is F = 0. Without that floor 2 of 3 would do, and a host that
drops answers until 3 are fresh could let 2 wrong operators set the time.
Each bound first grows by rho times its age at `now`. [lo, hi] spans the
points that at least n - F intervals cover (the intersection of RFC 5905
section 11.2.1, without clustering); no such point is an error. The
result is the midpoint, bound (hi - lo) / 2. The rule "(F+1)-th smallest
lower end, (F+1)-th largest upper end, fail if lo > hi" never fails for
three servers; the result here is always inside that rule's interval.

Without the 60 s schedule (a library user; the runner always runs it,
"Shift schedule" below) each server is asked every 16 s (RFC 5905
MINPOLL, the shortest allowed), with a query timeout of 5 s or half the
interval. The latest sample of each server goes to the quorum if it is at
most 46 s old with the defaults (`JoinAge`: 60 s minus the 4 s tick of
the clock's `Run` and the 10 s a refresh can take for one NTS-KE and one
query, so it stays under 60 s until the next quorum can replace the one
it joins; the clock refuses a `MaxAge` that leaves no room for that,
before it contacts any server). The join age is the core's one age rule
for a combine (`nts_config.join_age_ns`, never over the age limit); the
clock passes at most 4 intervals without the schedule and the schedule's
76 s with it. Between quorums the bound grows by rho of the elapsed
monotonic time; the time is refused once the bound is over 100 ms, and
once the oldest sample of the quorum in force is over `MaxAge` old on the
local clock (90 s under the 60 s schedule, 60 s without it).

The host sets that clock's rate: if it blocks the servers and runs the
clock fast, the bound ages too slowly, and only this limit keeps the time
a quorum in force serves within `MaxAge` of real time
(`TestNTSClockFastCounterLeadIsBounded`). So on a counter the host can
set, the lead is at most the sample age limit plus the bound: about 90 s
under the 60 s schedule. A drift refusal and the coarse clock do not add
to this. Each quorum is made of authenticated samples, so its time is
real time at its samples plus the counter's advance since then, and the
time stops at the age limit. (With plain NTP the samples are the host's,
and the coarse window is the only limit; see "Plain NTP".) Nitro is not
affected: the parent cannot set `CLOCK_MONOTONIC_RAW` there; the Nitro
hypervisor, which AWS runs, keeps the enclave's counter. The restart
floor's one epoch (384 s on mainnet) covers 90 s (signer-core/README.md,
"Restart floor").
The other direction has no such limit: a host that runs the clock slow
makes the samples look young and the polls rare, so the time served falls
behind real time without a bound until the drift check sees new samples.
On a platform without a host-proof counter (SEV-SNP without Secure TSC)
the host can do this. The runner's own signatures stay safe, because its
time never goes back and a restart waits for a fresh quorum. What lags: a
client certificate that expired during the lag is still accepted, and a
key imported during it gets a restart floor that is too low for history
it built elsewhere.

Without the 60 s schedule a healthy server answers every 16 s, so after
one lost answer its sample is usually still under 46 s when the next
answer comes; with 4 servers a quorum needs 3 of them. If every server is
out of reach, signing stops within 60 s and resumes with the next quorum:
within about one interval after a short outage, later after a long one,
when NTS-KE backs off (up to 1024 s; before the first quorum of a run
NTS-KE is tried again after a random 12 to 20 s, so a relay that comes up
late does not push the first quorum past the runner's start wait; a
server swap or policy change that leaves no quorum brings these retries
back for the start wait at most, see the server list swap below). After 3
lost queries in a row the core runs NTS-KE again, once per streak, and
keeps the old keys and cookies until the new exchange succeeds. The first
refresh of a run waits a random time under 5 s before it contacts anyone
(the clock's `StartDelay`), so signers that restart together (a release,
a region outage) do not reach every server in the same second; the
retries keep the spread.
HEALTH reports `sample_age_ms`, `max_sample_age_ms` and, while the clock
refuses, the reason in `refused`. Local time is `CLOCK_MONOTONIC_RAW`,
not Go's `CLOCK_MONOTONIC`, which an NTP daemon in the kernel slews; the
coarse clock's `Anchored` ages on it too.

Each quorum is checked against the last one and against a baseline quorum
about 64 intervals (17 minutes) older: if the offset moved more than the
two bounds and rho allow, the local clock broke rho (or more servers are
wrong), the quorum is refused and so is the time until a quorum of new
samples agrees with it; the refused quorum's samples do not enter a quorum
again. A monotonic counter that went back is drift too. The status line's
`drift_ppm` is the rate over that baseline,
`drift_err_ppm` what the bounds leave open; a quorum is refused exactly
when |drift_ppm| > 500 + drift_err_ppm. The core keeps at most 64 quorums
for this: the baseline, the newest, and between them candidates for the
next baseline at least 1/60 of the baseline apart (a refresh forms a
quorum, and one closer than that replaces the newest),
so how often the wrapper combines does not matter and the baseline is at
most 1/60 older than it should be. Each
quorum is checked against the coarse time: outside -30 s to +31 s of it
(30 s plus the Date header's 1 s resolution) is refused, and the time with it
until a quorum passes, as after a drift refusal. Before both checks comes
the era window ("The boundary"): a quorum before the floor or over 20
years after the pivot is refused and does not enter the drift history.
The time never goes back.

### Shift schedule

`clock.NTS.Shifts` or `ScheduleSeed`, `clock/ntsshift.go`; off by
default. It is all in Go: it decides only whom to ask and when, which the
boundary leaves to the wrapper. The core gives it what it needs in its
status (each server's next poll, whether NTS-KE is due and when it may
run) and takes two values of it as configuration: the 1 s query timeout
(`nts_config.query_timeout_ns`) and the 76 s join age.

The runner always turns it on and refuses fewer than 4 servers (with 3,
one slow server would stop the quorum). Below 7 servers every server is
active, each asked once per 60 s on the same grid (the one exception:
after the first quorum, a lost answer may get one retry 20 s later, at
most one per lost contact and within the 120 per hour cap, so the worst
case per operator is two requests per 60 s while its answers are lost),
and nothing hands over: a small set (a region with few close operators)
is asked no more often than a shift asks. From 7 servers: 4 actives and 3
kept for fallbacks with 7, 5 actives from 8 on (`clock.ShiftActives`).
With 4 actives the quorum is 3 of 4, so two wrong at once (a leap smear
plus one more) stop it: 15.6 % of the time against 0.07 % with 5 actives,
in a simulation of 10 runs of 6 h. The newcomer of a handover is asked at
once, off its slot, and its next slot can come up to 116 s later, so that
first sample ages out before it and exactly 3 are fresh for up to about
40 s. Fewer than 4 fresh starts a burst (`NTSShiftBurstBelow`), so that
gap does not leave a quorum of 3 that one wrong operator stops; in the
simulation this adds about one burst per handover. Seeded with an HMAC of
the sealing key (`platform.ScheduleSeed`), which the host does not know,
so the order cannot be computed ahead from public data, and signers with
other keys spread over the operators in other orders. It does not keep
the order from the host. The order stays the same after a restart, and
the host sees where each query goes, so after one round of handovers (n
times 15 minutes) it knows the next active sets. Every start also begins
at the same window, so a host that restarts the signer within each shift
keeps the same actives for as long as it likes, and by timing a restart
chooses which window is active when. That gives it nothing it does not
have already: a host that drops answers chooses which servers form the
quorum, and 3 must still agree. The catalog's default set has 6 servers,
all active; with one more from the setup's `time_servers` they hand over.
It asks public servers less often and keeps the quorum alive when
operators fail:

- Time is counted in ticks of 4 s since the start round. The start round
  asks every operator once, after a random wait under 10 s. Until the
  first quorum, an operator that did not answer (and sent no RATE) may
  be asked again 20 s after its last try (`NTSShiftStartRetry`), so a
  relay that comes up late gets up to 5 tries in the 90 s start wait,
  not 2. A server that does not answer gets those tries once per run
  (per restart), then the full 60 s gap. A server swap or a policy
  change that leaves no quorum starts them again, for the start wait
  at most.
- `ShiftActives(n)` operators are active (all below 7, 4 of 7, 5 from 8),
  each asked on its own slot of a 60 s grid (slots 12 s apart with 5, 12
  to 16 s with 4, the phase from the seed). Two contacts with one
  operator start at least 60 s apart, except those start retries and
  the retry of a lost answer below (a contact that runs NTS-KE first
  sends its query a few seconds later); an obeyed RATE doubles that
  operator's gap up to 1024 s.
  Without a seed every operator is active.
- Every 15 minutes the window of actives moves one place along an order
  drawn from the seed. The outgoing leaves on time; its last sample stays
  until it ages out. An incoming that does not answer is not replaced.
- A lost answer of an active gets one fallback at once to a random
  operator not asked in 60 s that can be asked (not stopped by DENY or
  RSTR, not in an NTS-KE backoff), at most 120 per hour. With fewer than
  4 fresh samples, every such operator not asked in 60 s is asked (a
  burst), at most 120 burst contacts per hour (`NTSShiftBurstCap`, a cap
  of their own: sharing the fallbacks' cap left two down actives of 7
  operators without fallbacks, 5.7 % blocked in the simulation). A set under 7 has no operator for a
  fallback: there, and wherever none is free, a lost answer gets one
  retry of the same operator 20 s later (`NTSShiftStartRetry`), after
  the first quorum, within the same 120 per hour. Its next slot stays 60 s
  after the lost contact, so a lost answer costs at most one more query.
  In a simulation of 4 servers, 30 % loss blocked signing 18 % of the
  time without the retry and under 1 % with it; one server down and 10 %
  loss on the others, 17 % and 1 %. A wide answer and a RATE get no
  retry (the server answered), nor does an operator in a RATE backoff, a
  contact that sent nothing, or one that cannot be asked when the retry
  is due (DENY, RSTR, NTS-KE backoff). A retry more than a tick late, or
  within 20 s of the operator's next slot, is dropped. HEALTH counts only
  requests that went out.
- NTP queries time out after 1 s; the NTP host is resolved once at
  NTS-KE (default dialer only). NTS-KE keeps 5 s.
- `MaxAge` is 90 s. Each tick ends within 10 s, as a refresh without
  shifts does, so a sample joins a quorum while it is at most 76 s old
  (90 s minus the 4 s tick and the 10 s) and stays under 90 s until the
  next quorum. On a counter the host can set, the fast-counter lead is
  up to 90 s instead of 60 s, and the restart floor's 384 s epoch
  covers it.
- The quorum is the majority rule over the fresh samples, so 5 actives
  give a time with 2 of them wrong or missing, and 4 actives with 1.
- Consecutive quorums share most members, so a jump of the local
  counter first shows as outvoted samples. In the simulation a 2 s jump
  was served for 24 to 32 s before the drift check refused it, inside
  the lead the age limit allows anyway.
- `NTSSummary` adds the active operators, per-operator counts (queries,
  answers, losses, fallbacks, bursts, RATE answers, handovers, failed
  handovers, fallbacks that needed NTS-KE first, retries of a lost
  answer) and the fallbacks the cap refused. Fallbacks to an operator that often need NTS-KE mean its
  cookies expire while it idles; an operator can idle for about (n -
  ShiftActives(n)) x 15 minutes: 45 minutes with 7 or 8 operators.

The simulation figures in this section were measured on the Go clock
before the C core took over the rules, and were not measured again. The
simulations now run the core on the virtual world
(`ntsshift_sim_test.go`, `ntsshift_followup_test.go`,
`nts/ntstest/ntsworld/`); they check limits (no blocked second where
none is allowed, for example under 3 % blocked at 30 % loss on 4
servers), not each figure. `TestNTSShiftScenarioTable` and
`TestNTSShiftSevenVersusEight` print the tables again (long runs, with
`NTS_SHIFT_SIM=1`).

### Server list swap

`clock.NTS.SetServers`, for setup format 6, where the approvers change
the extra time servers with a fast config update. The running clock takes
the new list without a restart. Two parts refuse a list, and then nothing
changes:

- the clock (Go, runner policy): fewer than 4 servers, or the caller's
  minimum if higher;
- the core (`nts_core_set_servers`): more servers than its capacity
  (`nts.MaxServers`), an operator label outside 1 to `nts.MaxOperatorLen`
  octets, an operator named twice, and a host or NTP address named twice
  (one server, two votes).

The clock checks the core's rules first (`checkServers`), to name the
reason in words; the core checks them again. A start list over
`nts.MaxServers`, with a bad label or with an operator named twice is
refused too (by the clock, then `nts_core_init`), before any server is
contacted. A Refresh in flight finishes on the old list; SetServers waits
for it, and the next tick uses the new one. An operator that stays with
the same host, addresses and roots keeps everything in the core: keys
and cookies, sample, poll interval, Kiss-o'-Death stop, loss streak and
counters; and in the clock its RATE gap, health counters and last
contact. Any other operator gets a new peer in the core, with nothing of
the old one (new NTS-KE, no sample, no stop). A removed
operator's association is wiped. Its sample, and the old sample of a
changed operator, leave the quorum at once: if one was a member of the
quorum in force, that quorum stops serving inside the same call and the
core forms it again from the samples left. If that fails (too few
samples, no coarse time, a check refuses it), the clock serves no time
until a Refresh forms a quorum, and is back in its start state until then
(20 s start retries, NTS-KE retried after 12 to 20 s), for the start wait
at most (`clock.NTS.StartWait`, which the runner sets to `-nts-wait`;
90 s by default; `nts_config.start_wait_ns` in the core, which shows the
state in `nts_status.cold`). The drift history and the highest time
served stay, so the time never goes back across a swap. A real start has
that limit because the runner gives up after `-nts-wait`; a running clock
had none, so a host that dropped the answers at a swap could hold it on
the start retries, with NTS-KE to failing servers every 12 to 20 s, for
as long as it liked. Once the start wait is over without a quorum, the
first Refresh puts the clock back on the normal schedule, as after a
start that formed a quorum: NTS-KE failures back off from 16 s to 1024 s,
and under shifts each operator's gap is the full 60 s again, with one
retry of a lost answer and the bursts under their caps of 120 per hour.
The clock still serves no time until a quorum forms, and a quorum ends
the start state early. A second swap that fails gets a start wait of its
own; each swap needs a signed update.

A server that leaves (removed, or changed under its label) is kept by
label and by host for `NTSMaxPoll`, or until its stop ends if that is
later. This table is the clock's (`left` in `clock/nts.go`): it is
schedule state, and the core keeps nothing of a server that left. If its
label comes back, with any host, or its host comes back under a new
label, the core sees a new peer and the clock carries the rest: it does
not ask that peer until the DENY or RSTR stop has run out (HEALTH `off`
shows it meanwhile), it keeps the last contact in local time, and under
shifts the last contact, gap and RATE count. So
under shifts a changed, returning or relabelled server is asked at its
next slot past its gap, not at once, and no server is asked twice within
its gap across a swap. A server new by label and host is asked at the
next tick, as in the start round, then on the 60 s rule. Without shifts
there are no gaps: every new peer is asked at the next Refresh unless it
is stopped. Under shifts the seed and the grid phase stay; the order and
the active slots are drawn again for the new count (`ShiftActives`), so
the handover position starts over. `NTSSummary.ServerSwaps` counts the
swaps. In the simulation swaps from 7 to 8, 8 to 7, 6 to 7 and 8 to 9
servers on a healthy set never stopped the time.

### Policy change

`clock.NTS.SetPolicy`, for a config update of the setup's `time_policy`;
in the core `nts_core_set_policy`. It refuses a protocol other than nts
and ntp, a max bound of 0 or less, and a sample cap below the max bound
or over 1 s, and then changes nothing. Like SetServers it waits for a
Refresh in flight. The bounds apply at once: the quorum in force is
checked against the new max bound at the next read of the time, so a
lower bound can stop the time at once and a higher one serve the same
quorum again. A lower sample cap drops each sample over its receipt
bound; if one was a member of the quorum in force, that quorum forms
again from the samples left, or the clock serves no time until a Refresh
forms one. A new protocol fails closed: every association is wiped,
every sample, the quorum in force and the drift history (made of the
other protocol's answers) are dropped, and the clock is back in its start
state until a quorum forms on the new protocol, for the start wait at
most, as after a swap. The schedule seed, the grid, each server's last
contact and gap, its poll interval and its DENY or RSTR stop stay, so no
server is asked within its gap. The highest time served and the era
pivot stay, so the time still never goes back. In the simulation the next
tick formed the new quorum, with a burst to the servers past their gap.

### HEALTH

HEALTH `clock_nts.operators` has one entry per server the clock dials,
with or without shifts, servers that never answered included:
`operator`, `host`, `active`, `queries`, `answers`, `losses`, `wide`
(losses that were answers over the receipt bound), `ke_ok`,
`ke_fail`, `last_answer_age_ms` (-1: no answer yet), `off` (a DENY or
RSTR stop), `last_error` (cut at 256 octets), and under shifts
`fallbacks`, `bursts`, `rates`, `handovers`, `failed_handovers`,
`fallback_ke` and `retries`.
`clock_nts.fallbacks_capped` counts the fallbacks the hourly cap refused.
A server with no answers and either queries or `ke_fail` is dead from
this signer's network before it costs a refusal: `queries` counts NTP
queries only, so a server whose NTS-KE fails (TCP 4460 blocked, a bad
certificate) shows `queries` 0 and `ke_fail` growing. A query that the
tick's 10 s deadline cut counts as no loss, no loss streak and no
backoff (`NTS_ERR_HOST_CANCELLED`): HEALTH counts it in neither
`queries` nor `losses` and leaves `last_error` as it was. A cookie that
left the jar for it stays spent, and the contact counts for the 60 s
gap. A key exchange the deadline cut is named in `last_error` and not
counted in `ke_fail`. Under shifts `queries` and `retries` count only
requests that went out.
`clock_nts.protocol` is `"nts"` or `"ntp"`: the protocol the clock last
gave the core (the core's `nts_status.protocol` is the same).
`clock_nts.coarse` has one entry per HTTPS-date host of the coarse
check: `source`, `queries`, `answers`, `failures`, `last_answer_age_ms`
(-1: no answer yet), `last_diff_ms` (its Date minus the coarse quorum's
answer, from the last round that formed a quorum, in whole seconds) and
`last_error` (empty after an answer). Without
a coarse time there is no NTS time, so a host that fails or lags matters
as much as an NTS server.

## Tests

- `ntscore/go`: the tests of the Rust core, ported twice now, run against the
  C through the binding. `ntp_test.go` builds the server side from the RFC
  on `ntstest`'s independent AES-SIV and checks the request layout and
  limits, a round trip, every single-octet change of a valid response
  (refused, except stratum 0, which is a KoD), the Unique Identifier and
  origin checks, replays, truncated and oversized packets, malformed plain
  and encrypted fields, fields after the authenticator, cookies in the
  clear, the KoD codes ("NTS" and a zero octet among them), leap and
  stratum, version and mode, the
  authenticator's nonce and padding rules. `plain_test.go`: the
  plain request is the header alone, a plain response gives a sample
  without cookies, what follows the header is ignored, a refusal leaves
  the request open, the plain Kiss-o'-Death, the round trip with the
  measurement. `sample_test.go`: the bound on a
  symmetric path, the root values, the true time inside the bound for any
  path asymmetry, the refusals, extreme inputs, every precision value.
  `time_test.go`: the era boundary of 2036, round trips with a pivot up to
  68 years away, overflow. `drift_test.go`: the aging of a bound over a
  long outage. `ke_test.go`: the record rules of NTS-KE, record
  by record. `random_test.go`: 20,000 garbage and 20,000 mutated packets
  into each parser from a fixed seed (2,000 with `-short`). `siv_test.go`:
  Wycheproof's AES-SIV-CMAC vectors of the 32-octet key (`testdata/`),
  and the refusals the vectors do not show (RFC 5297 A.2 with its strings
  reordered, another key, ciphertexts shorter than the tag).
  `quorum_test.go`: the quorum against its definition on random intervals;
  the majority counts and `QuorumWrong` (3: 0, 4: 1, 5: 2, 6: 2, 7: 3), an
  unsound `max_wrong` refused, two wrong of 3 to 12, two colluders of 5 to
  12, a smear plus one wrong; `binding_test.go`: the majority rule through
  the binding.
  `client_test.go`: the client's rules through an honest host: the drift
  baseline stays about 64 intervals old however often combine runs, the
  refused samples do not come back, samples over the age limit, keys or a
  response of the wrong length from the key exchange, the jar refilled
  through placeholders after lost requests, a failed send that spends its
  cookie, authenticated DENY, RSTR and RATE, the NTP address without
  Server and Port records and for an IPv6 server, cores on many
  goroutines, one error and text per code (the numbers are the header's,
  checked at compile time in `lowlevel.go`). `join_age_test.go`: the join
  age (a sample older than it enters no quorum, one at it serves until
  `MaxAge`; a day of one server losing half its answers under `Run`'s
  schedule on a virtual clock, with no refusal once the first quorum is
  in force). `policy_test.go`, the rules that moved into the core with
  the port: the combine uses `QuorumWrong` (2 liars of 5 outvoted, 2 of 3
  refused); a wide answer refused, the earlier sample kept, the streak
  ended; the receipt bound leaves room for aging over the join age;
  NTS-KE after 3 lost queries, once per streak, a failed one keeps the
  cookies; the era pivot follows the served time and never the coarse
  reading (a coarse reading 2^32 s off: refused, history intact, over NTS
  and plain NTP); the window refusals keep the drift history; `worst`
  with exactly 3; the server list swap (a kept server keeps cookies and
  sample, a changed host is a new peer, a removed member drops the quorum
  and it forms again or fails closed, a duplicate host and a list over
  the capacity refused, busy during a poll, the highest time survives);
  the exact edges, to the nanosecond: the era window (a quorum time
  exactly 20 years after the pivot served, 1 ns more refused; at the
  floor served, 1 ns before it refused), the receipt bound (an answer at
  it taken, 1 ns over it wide, on both branches of the formula) and the
  join age and the age limit (exactly at the limit in, 1 ns over out);
  the policy change (a refusal changes nothing, a tighter sample bound
  drops the member, a protocol change clears samples, result and history
  and keeps the highest time); the start state ends after the start wait
  and at a quorum; a cancelled exchange costs no backoff; the query
  timeout; plain NTP as the protocol and its kisses (obeyed, the query
  ended at the kiss), an unauthenticated kiss under NTS only counted; a
  build without plain NTP refuses it (`TestPlainRefusedByTheBuild`, run
  against the `noplain` archive with the tag `ntsnoplain`).
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
  no more liars than the quorum allows, within its bound of the true time, from samples within
  the age limit; it never goes back; the key exchange request and the NTP
  address are the right ones; the certificate is dated by the core's own
  time while it would serve it and by the coarse reading otherwise, and
  never before the era pivot;
  cookies of 4 to 1024 octets (the padding of short ones, the request
  without placeholders for long ones). What the host can reach grew with
  the port, and the harness with it: plain NTP worlds, where the
  host forges answers freely and the invariant is that the time served is
  never further from the coarse reading than the coarse check allows,
  never before the floor and never goes back; server list swaps and
  policy changes, legal and illegal, issued between rounds as the trusted
  configuration side (after a removal no served quorum has that operator,
  an illegal call changes nothing, the time never goes back across a
  call); a host that reports a cancelled exchange at random (no wrong
  time, each cookie still spent once); coarse readings 2^32 s off (nothing
  of another era is served); up to `QuorumWrong(n)` lying operators with
  authentic answers, colluding or not, never put the time served further
  from the truth than its bound and one sample's cap (at least three
  members agree, and one of them is honest).
  `TestHostileHostRounds` runs 300 fixed seeds (40 with `-short`);
  `FuzzHostileHost` runs the harness under the fuzzing engine. The same
  host with every choice honest drives `client_test.go`: the NTS-KE
  backoff (a random 3/4 to 5/4 interval before the first quorum, then
  doubling to MaxPoll, reset by a success), a CSPRNG
  that fails (no cookie, no socket), the Server and Port records each
  alone and an IPv6 KE host, an authentic KoD followed by the answer
  within the grace (the answer wins) and one of an unknown code (only
  counted), the certificate dated by the core's time with the coarse
  clock 20 s off, the counter that went back, the time that never goes
  back when every server's clock moves back, Close. `exclusion_test.go`:
  the exclusion of polls and configuration calls under real concurrency
  (one goroutine polls, another calls `SetServers` or `SetPolicy` with a
  protocol change, through the binding and with the binding's lock left
  out so that the core's gate alone holds; run with `-race` and `-asan`),
  a poll that comes in during a configuration call and a second poll of
  one server (refused as busy), the certificate never dated before the
  pivot, and host operations that return the core's own codes (a failed
  host operation, nothing else).
- The fuzz targets, for `go test -fuzz` and `scripts/fuzz.sh`:
  `FuzzVerifyResponse`, `FuzzKEResponse`, `FuzzMeasure` (answers built
  from a known truth, the true time inside the bound), `FuzzSIV` (the
  core's AES-SIV against `ntstest`'s copy), `FuzzQuorum` (the property
  that up to `max_wrong` liars do not move the time off the truth, with
  `max_wrong` fuzzed too), `FuzzEncryptedPart` (plaintexts sealed under the test key,
  so every input reaches the parser behind the authenticator),
  `FuzzHostileHost`; in `nts`, `FuzzReadKEResponse` (the incremental
  reader against the core's framing walk, however the bytes are chunked).
  The nightly run keeps the inputs found so far (an actions cache of
  `GOCACHE/fuzz`), and runs the trusted-time targets with `-asan`, so the
  C under them is instrumented.
- The C core's own fuzz targets (`ntscore/c/fuzz/`, `make fuzz`,
  `fuzz/fuzz.sh ci|long|replay`; `make fuzz-core` at the root runs them
  with signer-core's and markformat's, in CI and nightly): the NTS-KE
  parsers, the response check against a fixed request, the plain NTP
  response check followed by the measurement (`target_plain.c`), AES-SIV (a sealed
  message opens, a changed bit does not, the two AES paths agree), the
  measurement, and the hostile host in C: the whole client with its
  untrusted operations fed from the input (honest, mutated, garbage,
  Kiss-o'-Death, another server's keys, nothing; sockets that fail; a
  counter that jumps; the two configuration calls and plain NTP; host
  operations that return codes of the core's own; and, on every run, the
  excluded calls made from inside a poll and a poll made from inside a
  combine or a configuration call, each of which must be refused as
  busy). They run the C under AddressSanitizer and
  UndefinedBehaviorSanitizer with coverage guidance, which the Go engine
  cannot give the C; the Go targets keep the protocol oracles.
- `scripts/test-modules.sh trusted-time` also builds the core's archive
  and checks its symbols (`make -C ntscore/c check`), runs the `ntscore`
  and `nts` tests once more against an archive built with AddressSanitizer
  and UndefinedBehaviorSanitizer (`make -C ntscore/c asan`, `go test
  -asan`), and, where the cross compiler and qemu-user are installed (the
  x86_64 CI runner), the symbol check and the `ntscore`, `nts` and
  `clock` tests once more on aarch64: the AES is
  hand-written and the arithmetic 128-bit, so one architecture's pass
  does not vouch for the other. The `nts` tests run a cloud runner's
  `-nts-selftest` when one is built (`build/<arch>/bin`; without one
  `TestRunnerBuiltWithTheTag` skips), and `scripts/test.sh` runs the
  self-test of every runner it built with the tag. `scripts/build-core.sh`
  builds each architecture's archive with `make check`, so the archive a
  runner links has passed the symbol check. It also builds the core with
  `NTS_NO_PLAIN_NTP` (`make -C ntscore/c noplain`) and runs the
  `ntscore` tests against it (`go test -tags nts,ntsnoplain`). `COV=1`
  adds a gcov run of the C
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
  own DENY; precision -128 and 127; lost requests, then NTS-KE again;
  a failed dial that costs no cookie; a dial that never returns, ended by
  the query's own timeout under a caller's context without one; a KE
  server that accepts and never speaks (the exchange timeout, no cookie);
  a caller's context that ends the poll; Close during a poll (waits for
  it, refuses after); the polls of three servers on one core at once
  while the time is read, then their quorum; the incremental KE reader
  with every chunking, a stream that ends early, a response over the
  buffer, a reader without progress; the pinned roots; the AES-SIV
  self-test; a plain NTP client against `ntstest.StartPlainNTP` (the
  query, its kiss and checks, a forgery skipped); the server list and the
  policy changed on a running client; the NTP host resolved once per key
  exchange; and the catalog's limits against the core's
  (`TestCatalogLimitsMatchTheCore`).
- `clock`: the quorum of three, one server wrong, two wrong, the majority
  rule, the bound that
  grows until `Now` fails, the coarse check, the Kiss-o'-Death codes, NTSN,
  a forged KoD, the drift check (a jump, a steady rate over rho caught by
  the baseline; the refused samples do not form a quorum again), duplicate
  operators, time that never goes back, DENY lifted after the longest poll,
  RATE capped at it, the query timeout of half the interval, samples over
  the age limit (no time, no quorum, HEALTH says why), a fast counter
  while the servers are blocked (the lead stays under a minute), no
  certificate check without a coarse time, status snapshots that own
  their counts, a `MaxAge` too short for any sample to join (refused
  before any server is contacted), the random start wait (500 signers on
  fake clocks spread their first contacts over 5 s and keep as many tries
  in the runner's wait as before; a one-shot check does not wait). From
  main, through real `ntstest` servers: plain NTP (`nts_plain_test.go`),
  the era (`nts_era_test.go`), wide samples, the key exchange after lost
  queries and one the caller's deadline cut, the worst bound with three
  samples, the summary. On the virtual world with made-up operators
  (`nts/ntstest/ntsworld/`; no sample is ever put into the core): the
  shift schedule's simulations (`ntsshift_sim_test.go`,
  `ntsshift_followup_test.go`), the server list swap (`nts_swap_test.go`)
  and the start state after it (`nts_swapstart_test.go`), the policy
  change (`nts_policy_test.go`), a sample that joins with its aged bound.
  `ntsshift_test.go` tests the schedule alone, with no tag.
- `clock/nts_interop_test.go` (network, `NTS_INTEROP=1`): the catalog's
  default public servers.
- `ntscatalog`: the catalog's entries, roots and regions.
- `tee-signer`, tag `nts`: the tests of package main behind the tag
  (`coarseroots_test.go`, `nts_on_test.go`, the setup's time values) run in `scripts/test-modules.sh tee-signer`, in a release and a
  debug build (`netgo,osusergo,platform_dev,nts` and
  `netgo,osusergo,platform_aws,platform_dev,debugimport,nts`).
- `tests/e2e/nts_relay_test.go`: the Nitro runner's clock through the UDP
  relay and the proxy routes (`scripts/test.sh`; test servers, or the
  public ones with `NTS_INTEROP=1`).

## Commands

```sh
make core                                    # the archives, libnts_core.a among them (trusted-time/ntscore/c/build/<arch>)
make -C trusted-time/ntscore/c check         # the core alone and its symbol check
make -C trusted-time/ntscore/c noplain       # the core built with NTS_NO_PLAIN_NTP, then its symbol check
(cd trusted-time && go test -count=1 -tags nts,ntsnoplain ./ntscore/go)   # the binding's tests against it
bash scripts/test-modules.sh trusted-time    # the Go tests, the symbol check, the sanitizer run, the other architecture
bash scripts/test-modules.sh tee-signer      # among the rest, the runner's tests with the tag nts
make fuzz-core                               # the C fuzz targets, the core's among them
# network: NTS-KE and 3 queries per default public server, about 70 s
(cd trusted-time && NTS_INTEROP=1 go test -count=1 -tags nts -run '^TestNTSInteropPublicServers$' -v ./clock)
```

The interop test contacts TCP 4460 (NTS-KE) and UDP 123 or 4123 (NTP) of
the catalog's default servers (`trusted-time/ntscatalog/catalog.json`),
plus their DNS lookups, and nothing else: its coarse check uses the host
clock, not HTTPS-date. At most one query per server per 33 s.
`NTS_INTEROP_OUT=<file>` writes its result as JSON.

## In the runner

`trusted-time/nts`, `trusted-time/ntscore/go` and the NTS clock have code
only with the build tag `nts`, so a build without the tag neither links
the core nor needs its archive. `scripts/build-core.sh` builds the
archive per architecture and `scripts/build-runner.sh` gives the tag to
the cloud runners: `runner-azure`, `runner-aws`, `runner-gcp` and their
`-debugimport` builds (`scripts/common.sh`, `runner_tags`). The dev
runners (`runner-dev`, `runner-dev-debugimport`) stay without it. The
link flags are `-linkmode external -extldflags -static`. `check-deps.sh`
checks that the cloud builds link `trusted-time/nts` and the dev builds
do not, and `build-runner.sh` that only the cloud builds hold the clock
and the `-nts-*` flags, and only their debug builds the test server
variables.

`tee-signer/platforms_nts.go`: `-nts-clock` (or `RUNNER_NTS_CLOCK=1`) gives a
tagged runner the NTS clock, with `-nts-coarse-urls` and `-nts-wait` (or
their variables; a set flag wins). The protocol, the bounds and the
servers next to the default set come from the setup ("Time values from
the setup" below). The runner refuses a max bound over 250 ms: a
sample's bound is about half its round trip, so that leaves room for
servers about 400 ms away. With no quorum within
`-nts-wait` (90 s by default) the start fails and the runner exits with
the peers' status in its error line, which goes to the host on Nitro. The
supervisor starts it again: `restartPolicy` `OnFailure` on ACI,
`tee-restart-policy=OnFailure` on Confidential Space, the operator or the
parent's service manager on Nitro. A runner that went on without a quorum
would load no share (each share's restart floor reads the clock) and
would not load them once the quorum formed. The start loop refreshes
every 5 s until 5 s are left, so its last refresh is at the end of the
wait. Before the random start wait and retry, a server that did not
answer got a try at 0, 20, 40, 60 and 80 s (16 s rounded up to the loop):
5 in 90 s, 2 in the 30 s of the e2e tests. Now the loop starts up to 5 s
later and a retry comes 15 or 20 s after a try: at the latest 5, 25, 45,
65 and 85 s, so as many tries as before. Under the 60 s schedule, which
every runner runs, the start retries above give a server that did not
answer a try every 20 s until the first quorum. The clock dials through
the platform (`platform.Platform.Dial`; nil is the default dialer).
`runner -nts-clock-check` runs the start round of the runner's schedule
once (every server, the 1 s query timeout of the shift schedule), with no
start wait, and prints the result, so a server that answers in 1 to 5 s
fails the check as it would fail the runner;
`runner -nts-selftest` prints the library version and runs the AES-SIV
self-test. A debug build (tag `debugimport`) can name test servers instead
of the public ones (`RUNNER_NTS_TEST_SERVERS`, `RUNNER_NTS_TEST_ROOTS`,
`nts_servers_debug.go`); a release build cannot.

## The server catalog

`trusted-time/ntscatalog/catalog.json`: the image's NTS servers, one entry
per operator, embedded in the binary. Each entry has its pinned root
files, Nitro vsock port, status (active, retired, withdrawn), `terms`,
`regions`, optional `alt` hosts and a `note`. The catalog is Go and
configuration: the roots reach the core as PEM with the server list
(`nts.RootsPEM`), by the trusted path.

- `terms`: `open` when the operator's published terms allow use without
  contact and state no limit the clock breaks; `ask` when the operator
  wants contact first, states a limit the polling exceeds (TimeNL: one
  query per 1024 s), or publishes no terms. `terms_url` is the page they
  were read from (required for `open`). The image never decides for a
  user: an `ask` operator is for a setup whose writer asked it.
- `regions`: `global` (anycast), or some of `eu`, `na`, `sa`, `apac`,
  where the median NTP round trip was under 180 ms from every test point
  (the 100 ms bound limit is about half the round trip plus the server's
  root distance). Measured 2026-11 from GCP europe-west3, -west4, -west9,
  us-east4, us-west1, southamerica-east1, asia-northeast1, asia-southeast1
  and australia-southeast1. `ForRegion` lists what a new setup for a
  region may name; signer-admin will suggest from it.
- Open servers per region today: eu and na 7, sa 4 (Cloudflare, Meta,
  Wiktel, NIC.br). Asia and Oceania have no NTS operator close enough of
  their own. Their open set is the two anycast services, Cloudflare and
  Meta, under the quorum's 3; a setup there needs `ask` operators
  (TimeNL's any.time.nl is anycast; MBIX is at the edge of the bound).
- `alt`: other hosts of the same operator (more sites, anycast). They count
  as the same operator. The runner dials one only when a deployment
  names it as `id@host` (see below).
- `default`: dialed while setups cannot name servers. Only open
  operators of eu and na (or global): Cloudflare, Netnod, PTB, BEV, Meta
  and Wiktel. Earlier images dialed Cloudflare, Netnod, PTB and TimeNL;
  TimeNL left the set for its terms, FER for failing NTS-KE in a live run.
  The six are all active, each asked once per 60 s (one retry 20 s
  after a lost answer aside, see the shift schedule above). A deployment
  adds operators in the setup's `time_servers` (open group), and the
  approvers' signature confirms the terms of `ask` operators (for
  example `time.nl@any.time.nl`, TimeNL's anycast host); from seven
  servers they hand over in shifts. Outside eu and na this set gives fewer close servers (Asia
  and Oceania: Cloudflare and Meta only), so a deployment there adds more.
  Where no NTS server is close, the samples of distant ones are wide
  (about half the round trip): such a deployment raises `max_bound_ms`
  and `max_sample_bound_ms` in the setup's `time_policy` (locked group),
  up to 250 ms, which fits round trips up to about 500 ms.
- `alt` hosts with a `nitro_port` can be chosen in place of the entry's
  host (`id@host`). The Nitro parent routes every entry and every such alt
  host (`Endpoints`), and its UDP relay allows their NTP host names, since
  it cannot see the enclave's command; the enclave dials only its choice.
- `ntp_names`: NTP host names an NTS-KE server names other than its own
  (Meta's names time.meta.com). The Nitro UDP relay allows them.
- `plain_ntp_host` (optional): the host plain NTP asks on port 123
  (`time_policy` protocol ntp) when the operator answers plain NTP on another
  name (Netnod: `ntp.se`, FER: `ntp.hr`). A host name, not the entry's
  own, once in the catalog like every host. The Nitro UDP relay allows it.

## Time values from the setup

A setup (format 6) holds the clock's values in two fields:

- `time_policy`, in the locked group: the protocol (nts or ntp),
  `max_bound_ms` (1 to 250) and `max_sample_bound_ms` (from the max bound
  to 1000);
- `time_servers`, in the open group: the catalog entries dialed next to the
  image's default set, `id` or `id@alt-host`.

The runner builds the server list with `ntscatalog.WithConfirmed`: the
default set always, plus `time_servers`. A config update is refused when
its list names an entry the catalog does not have, has withdrawn or cannot
route (an alt host without a Nitro port), or an entry of the default set,
or when the list gives fewer than 4 servers in all. At start such an entry
of the starting values is skipped with a warning, so a setup made for an
older catalog still starts; the start still needs 4 servers.

Start order. Key release needs the clock, and the config log, which says
which config updates are in force, is read only after key release. So
each start runs the clock on the setup's own values (version 0 of each
group) until the config log is read. Then the runner switches the clock
once to the values in force (`server.Updates.StartConfig`):
`time_servers` through `clock.NTS.SetServers`, `time_policy` through
`clock.NTS.SetPolicy`, which hand them to the core's two configuration
calls ("The boundary"). A switch to the other protocol drops every sample,
so the start then waits for a quorum on the values in force, up to
`-nts-wait` again, before the core is built and the shares load
(`server.Updates.WaitClock`); with none the start fails, as at the first
quorum. A share load needs the clock for its restart floor.

If no quorum forms on the setup's values within `-nts-wait`, for example
because an update moved the deployment to NTP or to wider bounds, the
clock tries once more on the newest values that a chain of signed updates
from the setup reaches in the config log (`tee-signer/starttime.go`). It
reads the update bodies from the log's store before the mark log is
claimed and checks each update's signatures against the approvers before
it: a locked update against the set before it, an open one against the
last set of that locked chain only. It reads no record, so it takes an
update only once the coarse clock's time has passed its `activate_at`
plus the wait its signatures allow; one whose `activate_at` lies before
its arrival can still count up to that much early. StartConfig then
switches to the values really in force. The log line `nts: clock started on the time
values of ...` names the values the clock started on. If no quorum forms
on those either, the start fails as before: without trusted time the
runner could not check a config update anyway.

The window before the switch. Time read before StartConfig switches comes
from the starting values. The coarse check bounds it (at most about 31 s
ahead of real time) on NTS. A host can force the fallback, by blocking
NTS-KE at a restart and showing the store without a later body, so the
starting values may be the weakest signed values past their wait. On
plain NTP where the host sets the counter, the window is that of plain
NTP: about 196 s ahead (see "Plain NTP"). The time stays as the clock's
floor, since `Now` never goes back. A pending update can therefore come into force up to that much
early at this start. Nothing is signed in this window: the core is built
after the switch, and the runner signs only while the clock runs on the
time values in force (`Updates.blockedLocked`).

Live changes. After that, each config update that comes into force
switches the clock again, within the 1 s config sync. Until it has, the
runner signs nothing, so no signature uses the values before the update. A `time_servers`
update is an open update and needs no wait; the runner refuses one whose
list the catalog refuses before it stores it, so no such list comes into
force. A `time_policy` update is a locked update: lower bounds and NTP back
to NTS tighten and come into force at once; NTS to NTP and higher bounds
wait the change delay, or come into force at once when every approver
signs (break-glass). If the clock still refuses values in force (an image
whose catalog withdrew an entry), the runner signs nothing and keeps taking
config updates, so the approvers can send values it takes.

The flags. With a setup, `-clock-protocol`, `-nts-max-bound`,
`-nts-max-sample-bound` and `-nts-terms-confirmed` do not count. On a cloud
platform the runner refuses to start when one of them or its variable
(`RUNNER_CLOCK_PROTOCOL`, `RUNNER_NTS_MAX_BOUND`,
`RUNNER_NTS_MAX_SAMPLE_BOUND`, `RUNNER_NTS_TERMS_CONFIRMED`) is set; the
dev platform logs a warning. Without a setup (the dev platform, and the
flag path of debug builds) they work as before, and so does
`-nts-clock-check`, which reads no setup: set its variables to the setup's
values for a pre-flight.

## Plain NTP (unauthenticated)

`time_policy` protocol ntp runs the same clock with plain NTP (RFC 5905) in
place of NTS (without a setup: `-clock-protocol ntp` or
`RUNNER_CLOCK_PROTOCOL=ntp`). `-nts-clock` still turns the clock on; the
protocol only picks how it asks the servers. The default is `nts`, and any
other value stops the runner at start, also with the clock off.
`-nts-clock-check` reads `RUNNER_CLOCK_PROTOCOL` too (see the release rule
below).

It is a fallback for a deployment where NTS does not work, for example a
path that blocks NTS-KE on TCP 4460. It is not a second kind of NTS.

Where it lives. The plain request and the check of its answer are the
core's (`nts_plain_request`, `nts_plain_verify`), and the core's poll runs
the plain query in place of NTS-KE and the NTS query; the protocol is the
core's configuration ("The boundary"), never an argument of a poll. So the
rule of the boundary holds in its letter: the wrapper still hands the core
datagrams only. What it no longer gives is the promise, since under plain
NTP whoever is the network makes the time.

The risk. Nothing authenticates the answers. The request carries a random
64-bit transmit timestamp and the answer must echo it, so a party that does
not see the request cannot answer it. The host sees every request. It can
answer each one with any time it likes, for every operator at once, and the
path to the servers can do the same (on Nitro the parent's UDP relay, on
Azure and GCP the network between the cloud and the servers). The quorum,
the error bound, the sample cap and the drift check then measure the
forged answers, not real time. The one check the host cannot forge is the
coarse check: the HTTPS-date quorum, over TLS to pinned roots. So against a
hostile host the time is only as good as the coarse check. The check allows
-30 s to +31 s against the coarse clock (`NTSMaxCoarseDiff` and the
one-second resolution), and the coarse clock is itself off real time:

- Behind: an HTTP Date names the second the server was in, up to 1 s
  before the answer, and `HTTPSDate.Fetch` has no round-trip cap, so a
  host that holds every answer up to the 15 s timeout of `Anchored.Run`
  puts the coarse clock about 16 s behind. With the 30 s window that is
  about 46 s behind real time.
- Ahead, with a local counter the host cannot set: the coarse clock is
  never ahead, so under 31 s.
- Ahead, where the host sets the counter: the coarse clock runs up to 75 s
  ahead (`Anchored.MaxAdvance`, while the host blocks HTTPS), a forged
  quorum may stand 31 s past it, and `Now` then serves that quorum's offset
  plus the counter until its samples are 90 s old on the counter
  (`NTSShiftMaxAge`). Forged samples are fresh at the quorum, and no drift
  check catches it: the host makes all the samples. That is 75 + 31 + 90,
  about 196 s ahead of real time. Behind has no limit there, as for NTS.

The restart floor (signer-core/README.md, "Restart floor") needs the lead
before a restart plus the lag after it under one epoch, and with plain NTP
the host sets both: up to about 196 s ahead before a restart and 46 s
behind at the first quorum after it, a swing of about 242 s. With a counter
the host cannot set it is about 31 + 46 = 77 s. Both are under the 384 s
epoch of mainnet and Hoodi. The host can move the time anywhere in this
range, slowly enough that the drift
check, which compares quorums of its own answers, sees nothing. HEALTH's
`bound_now_ms` does not bound that error. Plain NTP also trusts DNS:
whoever answers DNS for an NTP name (the runner's resolver on Azure and
GCP, the Nitro parent's relay) receives the request and can forge the
answer. Against an honest host and path, plain NTP is as precise as NTS.

With a setup, only the setup picks the protocol. Without one, in a
release build only the `-clock-protocol` flag picks it:
`RUNNER_CLOCK_PROTOCOL` stops the runner at start, except on the dev
platform. Debug builds and `-nts-clock-check` take the variable.

What changes against NTS: no NTS-KE, no cookies, no TLS to the time
servers. The NTS-KE retries, the NTS-KE after lost queries and the NTSN
kiss do not apply, and a Kiss-o'-Death is obeyed without authentication
("What the core is made of"). Each server is asked on UDP port 123 at the catalog
entry's `plain_ntp_host` (Netnod: `ntp.se`, FER: `ntp.hr`), else at its
first `ntp_names` entry when its NTS-KE server names another NTP host
(Meta: `time.meta.com`), else at the entry's host (the server's
`ntp_addr` in the core's list). Operators pick servers from
the same catalog as for NTS: the default set plus `time_servers`.
The Nitro relay already allows those names and port 123. Everything else
is the same: the 60 s schedule and its shifts, the quorum (at least 3
agree, `nts_quorum_wrong`), the sample cap, the era window, the coarse
check, the drift check, `MaxAge` and HEALTH.

How the runner marks it, so no reader takes it for NTS:

- the clock source is `ntp(op,...)` instead of `nts(op,...)` (HEALTH
  `clock_source`, the start lines);
- HEALTH has `clock_nts.protocol` = `"ntp"` (`"nts"` otherwise; missing
  from older runners);
- every log line of the clock carries `protocol=ntp-unauthenticated`, and
  the `nts: status` line `protocol=ntp`;
- at start the runner logs a WARN line: "plain NTP: the host can forge
  every answer; the time is only as good as the coarse check (up to about
  46 s behind and 31 s ahead of real time; where the host sets the local
  counter, 196 s ahead and behind without a limit)".

The clock still counts as trusted (`Trusted()` is true for both
protocols): the runner starts on a cloud platform with it, because the
coarse check bounds the time.

Two points of this section are as main had them and are open product
decisions: that the setup can select plain NTP at all, and that
`Trusted()` stays true under it.

Measured on 2026-11-11 (plain NTP to port 123 from WSL): 11 of the 13
catalog hosts answer. `nts.netnod.se` (Netnod) and `nts1.ntp.hr` (FER)
time out. Their plain NTP hosts answer: `ntp.se` for Netnod (also
`sth1`, `sth2`, `gbg1`, `mmo1`, `lul1`, `svl1.ntp.se` and `ntp.netnod.se`)
and `ntp.hr` for FER, so their entries set `plain_ntp_host`.

## In the clouds

Each cloud image runs the NTS clock from its measured command, so the host
cannot turn it off or point it elsewhere:

| Image | Where the flags are | Coarse check URLs | Path to the NTS servers |
| --- | --- | --- | --- |
| AWS EIF | `platform-aws/deploy/enclave/Dockerfile` (PCR0, PCR2) | KMS, STS, `www.cloudflare.com`, through the platform's vsock-proxy routes | NTS-KE through vsock-proxy (catalog ports 8005 to 8018, one per catalog host, TCP 4460), NTP through `udprelay` on the parent (vsock 7102) |
| Azure | `platform-azure/deploy/aci-template.json` command (CCE policy hash) | `login.microsoftonline.com`, `management.azure.com`, `www.cloudflare.com` | ACI's default outbound access, direct |
| GCP | `platform-gcp/deploy/Dockerfile` entrypoint (image digest) | `cloudkms.googleapis.com`, `sts.googleapis.com`, `www.cloudflare.com` | the VM's external address, direct (implied allow-all egress) |

The coarse URLs are hosts the platform's egress already allows. Their
status does not matter, only the Date header of their own answer: on
2026-11-09 KMS, `cloudkms` and `sts.googleapis.com` answered 404,
`sts.{region}.amazonaws.com` 302, `management.azure.com` 400, and
`login.microsoftonline.com` and `www.cloudflare.com` 200, all with a
Date. Each is
an entry of the `coarse` list in `trusted-time/ntscatalog/catalog.json`,
with the roots it may chain to: a cloud's pinned set
(`platform/cloudroots`: `aws`, `google`, `azure`) and root files of
`trusted-time/nts/roots`. Each HTTPS-date source trusts its own entry's
roots and no others, so a certificate for the KMS host from Cloudflare's
CA, or for `www.cloudflare.com` from Amazon's, is refused. On a platform
with pinned roots the runner refuses a coarse URL that is not in the list;
a debug build takes others (the tests' servers) with the platform's roots
and the NTS operators'. `www.cloudflare.com` chained to ISRG Root X1 on
2026-11-11; Cloudflare's edge certificates also come from Google Trust
Services and SSL.com, so its entry has the ISRG, SSL.com and Google roots.
Each command also sets `-nts-wait 90s` (the default), so no environment
variable of the host or the launcher can change it. The protocol, the
bounds and the extra servers come from the setup, and no command names
them. The build scripts check the flags (`scripts/nitro-eif.sh`,
`platform-gcp/deploy/build-image.sh`, `platform-azure/deploy/deploy.sh
render`), refuse a command without
`-nts-clock` or `-nts-wait`, and refuse one that has `-clock`,
`-clock-protocol`, `-nts-max-bound`, `-nts-max-sample-bound` or
`-nts-terms-confirmed`. The runner itself refuses to start on a cloud platform whose
clock the host can set (`checkClock` in `tee-signer/main.go`). Only the
dev platform and debug builds may run on the system clock.

The UDP relay (`platform-aws/udprelay`, `platform-aws/deploy/README.md`, "NTS clock in the
enclave"): one vsock connection per NTP query; frames of a u16 length and
1 to 2048 octets; the destination first, then a status, then datagrams. It
sends only to ports 123 and 4123, and only to one of the catalog hosts'
NTP host names (resolved by the relay; `udprelay.DefaultNames`), an address those names resolve to, or
Netnod's NTP block `194.58.200.0/21`. Rate limits per session, per address
and in all. It cannot forge an answer (NTS authenticates every one), only
delay or drop it. With plain NTP it can forge every answer.

Not checked on a cloud: the delays and bounds there, UDP 123 and 4123 out of
ACI and Confidential Space, and the relay and proxies on EC2.

## Toward a trusted application

Not done here, and not decided: the OP-TEE build. The core is ready for
it (freestanding, the symbol check, the host operations split as above);
what a TA needs besides is the three trusted operations inside it, TLS
1.3 with the exporter among them (mbedTLS), the GP TEE sockets for the
untrusted two, the stack protector's two symbols, the configuration by a
trusted path, and a signer core in the same application to take the time
from `nts_bounded`.

Two points are open there and are product decisions, not code:

- Plain NTP. On the cloud runners the whole process is in the TEE, so a
  wrapper that could forge plain answers is no new party. In a trusted
  application the wrapper is outside, and under plain NTP it could set
  the time within the coarse window, whose reading is also its input.
  `NTS_NO_PLAIN_NTP` builds a core that refuses the protocol.
- The two configuration calls. On the runners their caller is inside the
  TEE and has checked the update's signatures. In a trusted application
  they must not be reachable from the wrapper, and who checks a signed
  update there is not designed.
