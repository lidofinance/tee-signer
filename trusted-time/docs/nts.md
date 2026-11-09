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
  over UDP in `trusted-time/nts`, the clock `trusted-time/clock.NTS`, the switch
  `RUNNER_NTS_CLOCK=1` in tagged runners (`tee-signer/platforms_nts.go`),
  and the interop test against the default public servers
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
- `build_plain_request(transmit)` and `PlainRequest::verify_response(packet)`:
  plain NTP without NTS (see "Plain NTP" below). The request is the 48-octet
  header alone. The response gets the same header checks (length caps,
  version 4, mode 4, origin, KoD on stratum 0, leap indicator 3, stratum
  above 15) and anything after the header is ignored. No cookies, and
  nothing is authenticated.

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

`quorum`: `combine_with(intervals, now, max_wrong)`. 3 to 16 intervals from
distinct operators (labels from the caller, duplicates refused). Up to F =
max_wrong of them may be wrong; fewer than 2F + 1 intervals is an error. The
clock passes the majority rule, F = (n - 1) / 2 rounded down, but never
so many that fewer than 3 agree (`nts.QuorumWrong`): 3 of 3, 3 of 4, 3 of 5,
4 of 6 and 4 of 7 must agree. With 4 intervals this is F = 1, with 3 it is
F = 0. Without that floor 2 of 3 would do, and a host that drops answers
until 3 are fresh could let 2 wrong operators set the time.
Each bound first grows by rho times its age at `now`. [lo, hi] spans the
points that at least n - F intervals cover (the intersection of RFC 5905
section 11.2.1, without clustering); no such point is an error. Result:
the midpoint, bound (hi - lo) / 2. The plan's rule ("(F+1)-th smallest
lower end, (F+1)-th largest upper end, fail if lo > hi") never fails for
three servers; the module comment has the reason. The result here is
always inside that rule's interval.

## C ABI

`include/signer_nts.h` documents each function. In short: KE request bytes,
response framing, ALPN, exporter label and contexts; an opaque `snts_assoc`
(keys and up to 8 cookies, wiped on free) made from a KE response and the two
exported keys; `snts_ntp_request` (takes the oldest cookie, asks for enough
placeholders to hold 8 again, gives an `snts_request` handle) and
`snts_ntp_verify` (checks, keeps the new cookies, measures);
`snts_plain_request`, `snts_plain_verify` and `snts_plain_free` for plain
NTP (an `snts_plain` handle, 8 random octets, the same `snts_sample` with no
cookie counts); `snts_quorum` over a pointer-free array of intervals. The caller passes buffers with their
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
  a clock the caller passes, not the system clock: a zero time from that
  clock stops the exchange before the dial, and during the handshake
  becomes `nts.NoTrustedTime` (1970), which no certificate covers. Go's
  `crypto/x509` would read a zero time as `time.Now()`); `Association.Query` over a connected UDP socket
  (refused packets do not end the wait: they may be forgeries); `QueryPlain`,
  the same exchange with plain NTP; pinned roots
  per operator in `roots/` with their source in `roots.go`.
- `trusted-time/clock.NTS`: polls each server every 16 s (RFC 5905 MINPOLL),
  doubles a server's interval on RATE up to 1024 s, stops asking a server
  for 1024 s on DENY or RSTR (a Kiss-o'-Death is not authenticated, so a
  forged one must not stop it for good), runs NTS-KE again on NTSN (or
  "NTS" and a zero octet, which nts1.ntp.hr sends for a stale cookie), feeds
  the latest sample of each server to the Rust quorum if it is at most 46 s
  old with the defaults (60 s minus the 4 s tick of `Run` with the
  defaults and the 10 s a refresh can take for one NTS-KE and one query,
  so it stays under 60 s until the next quorum can replace the one it
  joins; the clock refuses a `MaxAge` that leaves no room for that), ages
  the bound by rho, and fails `Now` over 100 ms. `Now` also fails once the
  oldest sample of the quorum in force is over `MaxAge` old on the local
  clock (90 s under the 60 s schedule, 60 s without it). The host sets that clock's rate: if it blocks the servers and runs
  the clock fast, the bound ages too slowly, and only this limit keeps the
  time a quorum in force serves within `MaxAge` of real time. So on a
  counter the host can set, the lead is at most the sample age limit plus
  the bound: about 90 s under the 60 s schedule. A drift refusal and the
  coarse clock do not add to this. Each quorum is made of authenticated
  samples, so its time is real time at its samples plus the counter's
  advance since then, and `Now` stops at the age limit. (With plain NTP
  the samples are the host's, and the coarse window is the only limit; see
  "Plain NTP".) Nitro is not affected: the parent cannot set
  `CLOCK_MONOTONIC_RAW` there; the Nitro hypervisor, which AWS runs, keeps
  the enclave's counter. The restart floor's one epoch (384 s on
  mainnet) covers 90 s (signer-core/README.md, "Restart floor"). The other direction has no such limit: a
  host that runs the clock slow makes the samples look young and the polls
  rare, so the time served falls behind real time without a bound until
  the drift check sees new samples. On a platform without a host-proof
  counter (SEV-SNP without Secure TSC) the host can do this. The runner's
  own signatures stay safe, because its time never goes back and a
  restart waits for a fresh quorum. What lags: a client certificate that
  expired during the lag is still accepted, and a key imported during it
  gets a restart floor that is too low for history it built elsewhere.
  Without the 60 s schedule (a library user; the runner always runs it,
  next item) a healthy server answers every 16 s, so after one lost answer its sample is usually
  still under 46 s when the next answer comes; with 4 servers a quorum
  needs 3 of them. If every server is out of reach, signing stops within
  60 s and resumes with the next quorum: within about one interval after a
  short outage, later after a long one, when the cookies ran out and NTS-KE
  backs off (up to 1024 s; before the first quorum of a run NTS-KE is tried
  again after a random 12 to 20 s, so a relay that comes up late does not
  push the first quorum past the runner's start wait). The first refresh
  of a run waits a random time under 5 s before it contacts anyone, so
  signers that restart together (a release, a region outage) do not reach
  every server in the same second; the retries keep the spread. HEALTH reports `sample_age_ms`, `max_sample_age_ms` and, while the
  clock refuses, the reason in `refused`. Local time is
  `CLOCK_MONOTONIC_RAW` (`nts.Monotonic`), not Go's `CLOCK_MONOTONIC`, which
  an NTP daemon in the kernel slews. Each
  quorum is checked against the last one and against a baseline quorum
  about 17 minutes (64 intervals) older: if the offset moved more than the two bounds and
  rho allow, the local clock broke rho and `Now` fails until the next
  quorum agrees. The status line's `drift_ppm` is the rate over that
  baseline, `drift_err_ppm` what the bounds leave open; a quorum is refused
  exactly when |drift_ppm| > 500 + drift_err_ppm. The HTTPS-date quorum is
  the coarse check (NTS time outside -30 s to +31 s of it is refused: 30 s
  plus the Date header's 1 s resolution; a refusal stops `Now` until a
  quorum passes, as a drift refusal does), the certificate clock of NTS-KE
  (no reading: NTS-KE is refused) and the NTP era. Its `Anchored` clock ages on `CLOCK_MONOTONIC_RAW` too.
  The NTS time has no fallback to it. The runner's config updates read it
  while the NTS clock has no quorum (`NTS.CoarseNow`; signer-protocol
  protocol.md, CONFIG_UPDATE, step 3), and so does the start fallback to
  the config log's time values, which takes an update only once the
  coarse time has passed its `activate_at` plus its wait
  (`tee-signer/starttime.go`). Signing never reads it.

  Each HTTPS-date source reads the Date of the first TLS answer of its
  URL, whatever the status, and never follows a redirect: the target is a
  host nobody measured into the image, may be plain HTTP
  (TIME-SOURCE-01), and may have no egress route (TIME-SOURCE-02,
  `sts.{region}.amazonaws.com` answers 302 to `aws.amazon.com`).

  Residual: the HTTPS-date sources' own TLS checks their certificates
  against the system clock, because the platform HTTP clients set no
  `Time` (`httpsdate.go`). A host that sets the system clock and holds
  leaked certificates for a majority of the coarse hosts can answer their
  `Date` headers itself, move the coarse clock, and with it the time NTS-KE
  checks certificates at. Without such certificates, setting the system
  clock moves neither. HTTPS-date is no longer a signing clock, but it
  is still the coarse check, so this residual stays. The certificates
  must come from the roots of each host's own catalog entry (see "In the
  clouds" below), not from any root the image trusts.
- Shift schedule (`clock.NTS.Shifts` or `ScheduleSeed`, `ntsshift.go`; off
  by default). The runner always turns it on and refuses fewer than 4
  servers (with 3, one slow server would stop the quorum). Below 7
  servers every server is active, each asked once per 60 s on the same
  grid (the one exception: after the first quorum, a lost answer may get one retry 20 s later, at most one per lost contact and within the 120 per hour cap, so the worst case per operator is two requests per 60 s while its answers are lost), and nothing hands over: a small set (a region with few close
  operators) is asked no more often than a shift asks. From 7 servers:
  4 actives and 3 kept for fallbacks with 7, 5 actives from 8 on
  (`clock.ShiftActives`). With 4 actives the quorum is 3 of 4, so two
  wrong at once (a leap smear plus one more) stop it: 15.6 % of the time
  against 0.07 % with 5 actives, in a simulation of 10 runs of 6 h. The
  newcomer of a handover is asked at once, off its slot, and its next slot
  can come up to 116 s later, so that first sample ages out before it and
  exactly 3 are fresh for up to about 40 s. Fewer than 4 fresh starts a
  burst (`NTSShiftBurstBelow`), so that gap does not leave a quorum of 3
  that one wrong operator stops; in the simulation this adds about one
  burst per handover. Seeded with an HMAC of the sealing
  key (`platform.ScheduleSeed`), which the host does not know, so the
  order cannot be computed ahead from public data, and signers with other
  keys spread over the operators in other orders. It does not keep the
  order from the host. The order stays the same after a restart, and the
  host sees where each query goes, so after one round of handovers (n
  times 15 minutes) it knows the next active sets. Every start also
  begins at the same window, so a host that restarts the signer within
  each shift keeps the same actives for as long as it likes, and by timing
  a restart chooses which window is active when. That gives it nothing it
  does not have already: a host that drops answers chooses which servers
  form the quorum, and 3 must still agree. The catalog's default set has
  6 servers, all active; with one more from the setup's `time_servers`
  they hand over.
  It asks public servers less
  often and keeps the quorum alive when operators fail:
  - Time is counted in ticks of 4 s since the start round. The start round
    asks every operator once, after a random wait under 10 s. Until the
    first quorum, an operator that did not answer (and sent no RATE) may
    be asked again 20 s after its last try (`NTSShiftStartRetry`), so a
    relay that comes up late gets up to 5 tries in the 90 s start wait,
    not 2. A server that does not answer gets those tries once per run
    (per restart), then the full 60 s gap.
  - `ShiftActives(n)` operators are active (all below 7, 4 of 7, 5 from 8), each asked
    on its own slot of a 60 s grid (slots 12 s apart with 5, 12 to 16 s
    with 4, the phase from the seed). Two contacts with one
    operator start at least 60 s apart, except those start retries and
    the retry of a lost answer below: after the first quorum, a lost answer may get one retry 20 s later, at most one per lost contact and within the 120 per hour cap, so the worst case per operator is two requests per 60 s while its answers are lost (a contact that runs NTS-KE first
    sends its query a few seconds later); a RATE doubles that operator's
    gap up to 1024 s.
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
- Server list swap (`clock.NTS.SetServers`, for setup format 6, where the
  approvers change the extra time servers with a fast config update). The
  running clock takes the new list without a restart. It refuses fewer
  than 4 servers (or the caller's minimum, if higher), more than
  `nts.MaxServers`, an operator label outside 1 to `nts.MaxOperatorLen`
  octets, an operator named twice, and a host or NTP address named twice
  (one server, two votes), and then changes nothing. Refresh refuses a
  start list over `nts.MaxServers`, with a bad label or with an operator
  named twice too, since `nts.Quorum` would refuse every quorum of it. A
  Refresh in flight finishes on the old list; SetServers waits for it,
  and the next tick uses the new one. An operator that stays with the
  same host, addresses and roots keeps everything: association and
  cookies, sample, poll interval, RATE gap, Kiss-o'-Death stop, loss
  streak, health counters and last contact. Any other operator gets a new
  peer (new NTS-KE, no sample). A removed operator's association is
  closed. Its sample, and the old sample of a changed operator, leave the
  quorum at once: if one was a member of the quorum in force, that quorum
  stops serving in the same lock hold as the swap and forms again from
  the samples left. If that fails (too few samples, no coarse time, a
  check refuses it), the clock serves no time until a Refresh forms a
  quorum, and is back in its start state until then (20 s start retries,
  NTS-KE retried after 12 to 20 s).
  A server that leaves (removed, or changed under its label) is kept by
  label and by host for `NTSMaxPoll`. If its label comes back, with any
  host, or its host comes back under a new label, the new peer keeps its
  DENY or RSTR stop and its last contact in local time, and under shifts
  its last contact, gap and RATE count. So under shifts a changed,
  returning or relabelled server is asked at its next slot past its gap,
  not at once, and no server is asked twice within its gap across a
  swap. A server new by label and host is asked at the next tick, as in
  the start round, then on the 60 s rule. Without shifts there are no
  gaps: every new peer is asked at the next Refresh unless it is stopped.
  Under shifts the seed and the grid phase stay; the order and the active
  slots are drawn again for the new count (`ShiftActives`), so the
  handover position starts over. `NTSSummary.ServerSwaps`
  counts the swaps. In the simulation swaps from 7 to 8, 8 to 7, 6 to 7
  and 8 to 9 servers on a healthy set never stopped the time.
- Policy change (`clock.NTS.SetPolicy`, for a config update of the setup's
  `time_policy`). It refuses a protocol other than nts and ntp, a max
  bound of 0 or less, and a sample cap below the max bound or over 1 s,
  and then changes nothing. Like SetServers it waits for a Refresh in
  flight. The bounds apply at once: `Now` checks the quorum in force
  against the new max bound at its next call, so a lower bound can stop
  the time at once and a higher one serve the same quorum again. A lower
  sample cap drops each sample over it; if one was a member of the quorum
  in force, that quorum forms again from the samples left, or the clock
  serves no time until a Refresh forms one. A new protocol fails closed:
  every association is closed, every sample, the quorum in force and the
  drift history (made of the other protocol's answers) are dropped, and
  the clock is back in its start state until a quorum forms on the new
  protocol. The schedule seed, the grid, each server's last contact and
  gap, its poll interval and its DENY or RSTR stop stay, so no server is
  asked within its gap. `Now` still never goes back. In the simulation the
  next tick formed the new quorum, with a burst to the servers past their
  gap.
- HEALTH `clock_nts.operators` has one entry per server the clock dials,
  with or without shifts, servers that never answered included:
  `operator`, `host`, `active`, `queries`, `answers`, `losses`, `wide`
  (losses that were answers over the sample cap), `ke_ok`,
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
  `last_error`; its request went out, so its cookie is used and the
  contact counts for the 60 s gap. Under shifts `queries` and `retries`
  count only requests that went out.
  `clock_nts.coarse` has one entry per HTTPS-date host of the coarse
  check: `source`, `queries`, `answers`, `failures`, `last_answer_age_ms`
  (-1: no answer yet), `last_diff_ms` (its Date minus the coarse quorum's
  answer, from the last round that formed a quorum, in whole seconds) and
  `last_error` (empty after an answer). Without
  a coarse time there is no NTS time, so a host that fails or lags matters
  as much as an NTS server.
- `tee-signer/platforms_nts.go`: `-nts-clock` (or `RUNNER_NTS_CLOCK=1`) gives a
  tagged runner the NTS clock, with `-nts-coarse-urls` and `-nts-wait` (or
  their variables; a set flag wins). The protocol, the bounds and the
  servers next to the default set come from the setup ("Time values from
  the setup" below). The runner refuses a max bound over 250 ms: a
  sample's bound is about half its round trip, so that leaves room for
  servers about 400 ms away. With no quorum
  within `-nts-wait` (90 s by default) the start fails and the runner exits
  with the peers' status in its error line, which goes to the host on
  Nitro. The supervisor starts it again: `restartPolicy` `OnFailure` on
  ACI, `tee-restart-policy=OnFailure` on Confidential Space, the operator
  or the parent's service manager on Nitro. A runner that went on without
  a quorum would load no share (each share's restart floor reads the
  clock) and would not load them once the quorum formed.
  The start loop refreshes every 5 s until 5 s are left, so its last
  refresh is at the end of the wait. Before the random start wait and
  retry, a server that did not answer got a try at 0, 20, 40, 60 and
  80 s (16 s rounded up to the loop): 5 in 90 s, 2 in the 30 s of the
  e2e tests. Now the loop starts up to 5 s later and a retry comes 15 or
  20 s after a try: at the latest 5, 25, 45, 65 and 85 s, so as many tries
  as before. Under the 60 s schedule, which every runner runs, the start
  retries above give a server that did not answer a try every 20 s until
  the first quorum.
  The clock dials through the platform (`platform.Platform.Dial`; nil is
  the default dialer). `runner -nts-clock-check`
  runs the start round of the runner's schedule once (every server, the
  1 s query timeout of the shift schedule), with no start wait, and prints
  the result, so a server that answers in 1 to 5 s fails the check as it
  would fail the runner. A debug build (tag debugimport) can name
  test servers instead of the public ones (`RUNNER_NTS_TEST_SERVERS`,
  `RUNNER_NTS_TEST_ROOTS`, `nts_servers_debug.go`); a release build cannot.
- `trusted-time/nts/ntstest`: a loopback NTS-KE and NTP server for the tests,
  with its own AES-SIV from RFC 5297 (checked against appendix A.1).
- `trusted-time/ntscatalog/catalog.json`: the image's NTS servers, one entry
  per operator, embedded in the binary. Each entry has its pinned root
  files, Nitro vsock port, status (active, retired, withdrawn), `terms`,
  `regions`, optional `alt` hosts and a `note`.
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
                              (assoc.rs), plain NTP (plain.rs), reason codes (reason.rs),
                              tests (tests.rs)
trusted-time/rust/include/signer_nts.h      the C header, written by hand
trusted-time/rust/core/src/                 signer-nts-core: ke, ntp, sample, quorum, keys, cookie, time, selftest
trusted-time/rust/core/tests/               requests, answers and refusals against a test server,
                              randomized garbage and mutations (fixed seeds)
trusted-time/rust/nostd-check/src/lib.rs    the no_std build check
trusted-time/toolchain/toolchain.Dockerfile     the toolchain image
scripts/fetch-nts.sh          checks the lock, fetches the crates into build/nts/cargo-home,
                              checks the archives
scripts/nts-verify-crates.sh  checks the crate archives against the sha256 in Cargo.lock
scripts/nts-verify-crates-test.sh  its self-test on a fixture cache (make check)
scripts/build-nts.sh          builds libsigner_nts.a for both architectures, runs
                              the Rust tests and the no_std checks of the core
scripts/nts-container.sh      the part of build-nts.sh that runs in the container
scripts/build-runner-nts.sh   builds the runners with the build tag nts
scripts/test-nts.sh           all of it, then the Go test on each architecture
scripts/nts-interop.sh        the interop test against the default public servers (network)
trusted-time/nts/                   the cgo binding, NTS-KE, NTP, pinned roots, tests (tag nts)
trusted-time/clock/nts*.go          the NTS clock and its tests (tag nts)
tee-signer/nts_on.go              -nts-selftest and -nts-clock-check (tag nts)
tee-signer/platforms_nts.go       -nts-clock and RUNNER_NTS_CLOCK=1, -clock-protocol (tag nts)
tee-signer/nts_servers_*.go       the servers: public in release builds, test servers in debug builds
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

Run the Rust tests through `make nts` or `make test-rust`, not bare `cargo`
in `trusted-time/rust`: bare cargo uses `~/.cargo` and the network, and it
does not check archives already in that cache.

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

The reference build platform is linux/amd64. The image is built and run with
`--platform linux/amd64` (`NTS_PLATFORM` in `scripts/common.sh`), also on an
arm64 host, where it runs under emulation. A native arm64 toolchain builds a
different aarch64 library, and that library is in the Nitro EIF, so PCR0 and
PCR2 would depend on the build host. The x86_64 library is the same either way.

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
  the cache against its sha256 in the lock. Each archive must be in at least
  one registry folder of the cache, and every copy of it must match. All
  there and matching: no fetch. Some missing: `cargo fetch`, then the same check again. One that
  differs (changed, cut short): the script stops and says to remove the
  cache. It also deletes the extracted sources (`registry/src`).
- `build-nts.sh` mounts the cache read-only at `/crates` in each build
  container. `nts-container.sh` copies only the lock's archives out of it,
  checks the copies with `nts-verify-crates.sh`, and unpacks them into
  `/tmp/vendor`, a cargo directory source whose `.cargo-checksum.json` per
  crate names the lock's sha256 and the sha256 of each unpacked file, which
  cargo checks before it builds. cargo builds with crates.io replaced by
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
`clock.NTS.SetPolicy`. A switch to the other protocol drops every sample,
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
kiss do not apply. Each server is asked on UDP port 123 at the catalog
entry's `plain_ntp_host` (Netnod: `ntp.se`, FER: `ntp.hr`), else at its
first `ntp_names` entry when its NTS-KE server names another NTP host
(Meta: `time.meta.com`), else at the entry's host. Operators pick servers from
the same catalog as for NTS: the default set plus `time_servers`.
The Nitro relay already allows those names and port 123. Everything else
is the same: the 60 s schedule and its shifts, the quorum (at least 3
agree, `nts.QuorumWrong`), the sample cap, the coarse check, the drift
check, `MaxAge` and HEALTH.

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

The clock still counts as trusted (`Trusted()`): the runner starts on a
cloud platform with it, because the coarse check bounds the time.

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

A sample whose own bound is over the setup's `max_sample_bound_ms` joins no
quorum (`clock.NTS.MaxSampleBound`). At receipt it counts as a lost answer,
so a fallback may follow, and HEALTH counts it in `wide`; it ends a loss
streak (the cookies work) and gets no start retry. A sample under the cap
at receipt joins for its whole join age (76 s): its bound, aged by rho as
the quorum ages it, may pass the cap by that aging, at most 38 ms. Without
that allowance a sample with bound B would join for only 2 x (cap - B)
seconds, 30 s at 85 ms, and leave before its operator's next contact 60 s
later. The cap is at least `max_bound_ms` and may be raised up to 1 s,
where the cap is off. Why: a host that delays the one honest answer of a
small fresh set widens its bound, and two wrong servers can then place
the time anywhere inside it while the quorum's bound looks small. The
bound is a half-width, and the host's delay can put the true time at
either edge, so the error is up to twice the aged cap: about
2 x (100 + 38) ms, 276 ms, at the default 100 ms, against about 1 s each
way without the cap (RFC 5905 MAXDIST, beyond which the core refuses a
sample). A setup that raises the sample cap above `max_bound_ms` gives
part of that back. A far deployment raises both, and that error grows
with them (about 2 x (250 + 38) ms, 576 ms, at 250 ms).

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
them. The build scripts check the flags (`nitro-eif.sh`,
`gcp/build-image.sh`, `azure/deploy.sh render`), refuse a command without
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
