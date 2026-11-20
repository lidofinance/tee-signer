//! Deterministic randomized tests: garbage and mutated packets into both
//! parsers. A panic fails the test; the crate must return an error instead.
//! The PRNG is the splitmix64 in `common`, with fixed seeds, so every run
//! feeds the same inputs.

mod common;

use common::*;
use signer_nts_core::cookie::{Cookie, MAX_COOKIE_LEN};
use signer_nts_core::ke;
use signer_nts_core::keys::{C2sKey, S2cKey};
use signer_nts_core::ntp::{self, RequestInput, Response, TimeSample};
use signer_nts_core::sample;
use signer_nts_core::time::NtpTimestamp;

const ROUNDS: usize = 20_000;

/// One random change: flip, set, insert or delete octets, cut the end, add
/// to the end, or write a random 16-bit length at a random place.
fn mutate(rng: &mut Rng, good: &[u8]) -> Vec<u8> {
    let mut m = good.to_vec();
    for _ in 0..1 + rng.below(3) {
        let at = rng.below(m.len().max(1));
        match rng.below(7) {
            0 if !m.is_empty() => m[at] ^= 1 << rng.below(8),
            1 if !m.is_empty() => m[at] = rng.byte(),
            2 => m.insert(at.min(m.len()), rng.byte()),
            3 if !m.is_empty() => {
                m.remove(at);
            }
            4 => m.truncate(rng.below(m.len() + 1)),
            5 => {
                let n = 1 + rng.below(64);
                m.extend(rng.bytes(n));
            }
            _ if m.len() >= 2 => {
                let at = rng.below(m.len() - 1);
                let v = [0u16, 1, 2, 3, 4, 15, 16, 28, 0x7fff, 0xffff, rng.next_u64() as u16][rng.below(11)];
                m[at..at + 2].copy_from_slice(&v.to_be_bytes());
            }
            _ => {}
        }
    }
    m
}

fn check_ke(buf: &[u8]) -> bool {
    if let Ok(Some(n)) = ke::response_length(buf) {
        assert!(n <= buf.len() && n <= ke::MAX_RESPONSE_LEN);
    }
    match ke::parse_response(buf) {
        Ok(r) => {
            assert!((1..=ke::MAX_COOKIES).contains(&r.cookies.len()));
            assert!(r.cookies.iter().all(|c| (1..=MAX_COOKIE_LEN).contains(&c.len())));
            assert!(r.server.as_ref().is_none_or(|s| (1..=ke::MAX_SERVER_NAME_LEN).contains(&s.len())));
            assert_ne!(r.port, Some(0));
            true
        }
        Err(_) => false,
    }
}

#[test]
fn ke_garbage_and_mutations() {
    let mut rng = Rng::new(0x4b45_0001);
    let good = good_ke_response();
    let mut accepted = 0;
    for _ in 0..ROUNDS {
        // Garbage: random length, random octets; half of them start with a
        // valid-looking record header so the parser gets past the first one.
        let n = rng.below(600);
        let mut g = rng.bytes(n);
        if rng.below(2) == 0 && g.len() >= 4 {
            g[0] &= 0x80;
            g[1] = rng.below(9) as u8;
            g[2] = 0;
            g[3] = rng.below(40) as u8;
        }
        check_ke(&g);
        if check_ke(&mutate(&mut rng, &good)) {
            accepted += 1;
        }
    }
    println!("NTS-KE: {ROUNDS} garbage and {ROUNDS} mutated responses, {accepted} mutated ones still valid");
}

fn request(rng: &mut Rng, placeholders: usize) -> (Vec<u8>, ntp::PendingRequest) {
    let cookie = Cookie::new(&[0xc0; 100]).unwrap();
    let mut unique_id = [0u8; 32];
    unique_id.copy_from_slice(&rng.bytes(32));
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&rng.bytes(16));
    let input = RequestInput {
        transmit: NtpTimestamp::from_bits(rng.next_u64()),
        unique_id,
        nonce,
        cookie: &cookie,
        placeholders,
    };
    ntp::build_request(&C2sKey::from_slice(&C2S).unwrap(), &input).unwrap()
}

#[test]
fn ntp_garbage_and_mutations() {
    let mut rng = Rng::new(0x4e54_5001);
    let s2c = S2cKey::from_slice(&S2C).unwrap();
    let (mut accepted, mut kod) = (0, 0);
    for round in 0..ROUNDS {
        let placeholders = rng.below(ntp::MAX_PLACEHOLDERS + 1);
        let (packet, mut pending) = request(&mut rng, placeholders);
        let read = server_read_request(&C2S, &packet).unwrap();
        let cookies = (0..=placeholders).map(|i| vec![i as u8; 4 + rng.below(120)]).collect();
        let nonce_len = 1 + rng.below(32);
        let reply = ServerReply { cookies, nonce: rng.bytes(nonce_len), ..ServerReply::default() };
        let good = server_response(&S2C, &read, &reply);

        // Garbage after a real header start, so the field parser is reached.
        let n = rng.below(1200);
        let mut g = rng.bytes(n);
        if round % 2 == 0 && g.len() >= 48 {
            g[..48].copy_from_slice(&good[..48]);
        }
        assert!(!matches!(pending.verify_response(&s2c, &g), Ok(Response::Time(_))));

        let m = mutate(&mut rng, &good);
        match pending.verify_response(&s2c, &m) {
            Ok(Response::Time(t)) => {
                // Only a change that changed nothing, or octets added after
                // the end, may leave a response valid: those octets are
                // unauthenticated fields and are discarded.
                assert!(m.len() >= good.len() && m[..good.len()] == good[..], "round {round}");
                assert!(t.cookies.len() <= placeholders + 1);
                accepted += 1;
            }
            Ok(Response::KissOfDeath(_)) => {
                assert_eq!(m[1], 0, "round {round}: a KoD needs stratum 0");
                kod += 1;
            }
            Err(_) => {}
        }
        // The real response still works after the refused ones.
        if !pending.is_answered() {
            assert!(matches!(pending.verify_response(&s2c, &good), Ok(Response::Time(_))), "round {round}");
        }
    }
    println!(
        "NTP: {ROUNDS} garbage and {ROUNDS} mutated responses, {accepted} mutated ones accepted \
         (unchanged, or octets added after the end), {kod} KoD"
    );
}

// ---- Hostile servers: responses with our origin, our Unique Identifier and
// a valid authenticator, so the checks after those see hostile header values
// and hostile encrypted fields; then `sample::measure` on what is accepted.
// A panic here is an abort in the release build (panic = "abort").

const SEC: i64 = 1_000_000_000;
/// The pivot of the NTP era, Unix time in ns (late 2026).
const PIVOT: i64 = 1_790_000_000 * SEC;
const EXTREME_I64: [i64; 7] = [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX];

fn pick<T: Copy>(rng: &mut Rng, xs: &[T]) -> T {
    xs[rng.below(xs.len())]
}

/// A timestamp: an extreme, a random one, or one within a second of `unix`.
fn timestamp(rng: &mut Rng, unix: i64) -> u64 {
    match rng.below(4) {
        0 => pick(rng, &[0, 1, u64::MAX, 1 << 63, (1 << 63) - 1, 1 << 32, 0xffff_ffff, 0xffff_ffff_0000_0000]),
        1 => rng.next_u64(),
        _ => NtpTimestamp::from_unix_nanos(unix + (rng.below(200) as i64 - 100) * SEC / 100).to_bits(),
    }
}

/// The header fields of a response, with the local send and receive times
/// t1 and t4 of the exchange: with `realistic` the values a correct server
/// sends, else extreme and random ones. Version and mode stay valid: the
/// mutation test above covers those checks.
fn hostile_header(rng: &mut Rng, realistic: bool) -> (ServerReply, i64, i64) {
    let t1 = 1_000 * SEC + rng.below(10_000) as i64 * 1_000_000;
    let rtt = rng.below(20_000_000) as i64;
    let hold = rng.below(rtt as usize + 1) as i64;
    let t2 = PIVOT + rng.below(1_000) as i64 * 1_000_000;
    let t4 = t1 + rtt;
    let r = if realistic {
        ServerReply {
            leap: rng.below(3) as u8,
            stratum: 1 + rng.below(15) as u8,
            precision: -10 - rng.below(21) as i8,
            root_delay: rng.below(0x2000) as u32,
            root_dispersion: rng.below(0x2000) as u32,
            reference: NtpTimestamp::from_unix_nanos(t2 - rng.below(1_000) as i64 * SEC).to_bits(),
            receive: NtpTimestamp::from_unix_nanos(t2).to_bits(),
            transmit: NtpTimestamp::from_unix_nanos(t2 + hold).to_bits(),
            ..ServerReply::default()
        }
    } else {
        let short = |rng: &mut Rng| match rng.below(3) {
            0 => pick(rng, &[0, 1, 0xffff, 0x1_0000, 0x7fff_ffff, 0x8000_0000, u32::MAX]),
            1 => rng.next_u64() as u32,
            _ => rng.below(0x4000) as u32,
        };
        let (any_stratum, any_precision) = (rng.byte(), rng.byte() as i8);
        ServerReply {
            leap: rng.below(4) as u8,
            stratum: pick(rng, &[0, 1, 2, 15, 16, 255, any_stratum]),
            poll: rng.byte() as i8,
            precision: pick(rng, &[i8::MIN, -64, -30, -1, 0, 1, 7, 8, i8::MAX, any_precision]),
            root_delay: short(rng),
            root_dispersion: short(rng),
            reference_id: [rng.byte(), rng.byte(), rng.byte(), rng.byte()],
            reference: timestamp(rng, t2),
            receive: timestamp(rng, t2),
            transmit: timestamp(rng, t2 + hold),
            ..ServerReply::default()
        }
    };
    (r, t1, t4)
}

/// The plaintext of the encrypted part from a hostile server: cookies empty
/// or over the cap, more cookies than asked for, broken field framing,
/// unknown fields, junk.
fn hostile_plaintext(rng: &mut Rng, max_cookies: usize) -> Vec<u8> {
    let mut pt = Vec::new();
    for _ in 0..rng.below(13) {
        let any = rng.next_u64();
        let t = pick(rng, &[0x0204u16, 0x0204, 0x0304, 0x0104, 0x0404, 0x0000, 0xffff, any as u16]);
        match rng.below(8) {
            0..=2 => {
                let short = 1 + any as usize % 128;
                let n = pick(rng, &[0, 1, 3, 4, MAX_COOKIE_LEN - 1, MAX_COOKIE_LEN, MAX_COOKIE_LEN + 1, short]);
                pt.extend(field(0x0204, &rng.bytes(n)));
            }
            3 => {
                for _ in 0..=max_cookies {
                    let n = 1 + rng.below(16);
                    pt.extend(field(0x0204, &rng.bytes(n)));
                }
            }
            4 => {
                let n = rng.below(65);
                pt.extend(field(t, &rng.bytes(n)));
            }
            5 => {
                // A length under 4, not a multiple of 4, or past the end.
                let len = pick(rng, &[0u16, 1, 3, 5, 18, 0xfffc, 0xffff, (any >> 16) as u16]);
                pt.extend(t.to_be_bytes());
                pt.extend(len.to_be_bytes());
                let n = rng.below(40);
                pt.extend(rng.bytes(n));
            }
            _ => {
                let n = 1 + rng.below(16);
                pt.extend(rng.bytes(n));
            }
        }
    }
    pt
}

/// `sample::measure` on an accepted sample, with the round's local times
/// and with extreme ones: an error or a measurement inside its limits.
fn check_measure(rng: &mut Rng, s: &TimeSample, t1: i64, t4: i64) -> bool {
    let mut ok = false;
    for (t1, t4, pivot) in [
        (t1, t4, PIVOT),
        (pick(rng, &EXTREME_I64), pick(rng, &EXTREME_I64), pick(rng, &EXTREME_I64)),
        (t1, rng.next_u64() as i64, rng.next_u64() as i64),
    ] {
        if let Ok(m) = sample::measure(s, t1, t4, pivot) {
            assert!((0..=sample::MAX_BOUND_NS).contains(&m.bound_ns) && m.delay_ns >= 0 && m.t4_local_ns == t4, "{m:?}");
            ok = true;
        }
    }
    ok
}

#[test]
fn ntp_authentic_hostile_responses() {
    let mut rng = Rng::new(0x4e54_5002);
    let s2c = S2cKey::from_slice(&S2C).unwrap();
    let (mut accepted, mut measured) = (0, 0);
    for round in 0..ROUNDS {
        let placeholders = rng.below(ntp::MAX_PLACEHOLDERS + 1);
        let (packet, mut pending) = request(&mut rng, placeholders);
        let read = server_read_request(&C2S, &packet).unwrap();
        let realistic = rng.below(2) == 0;
        let (mut reply, t1, t4) = hostile_header(&mut rng, realistic);
        if rng.below(2) == 0 {
            reply.raw_plaintext = Some(hostile_plaintext(&mut rng, placeholders + 1));
        } else {
            let k = 1 + rng.below(placeholders + 1);
            reply.cookies = (0..k)
                .map(|_| {
                    let cap = if rng.below(8) == 0 { MAX_COOKIE_LEN } else { 128 };
                    let n = 1 + rng.below(cap);
                    rng.bytes(n)
                })
                .collect();
        }
        let nonce_len = 1 + rng.below(64);
        reply.nonce = rng.bytes(nonce_len);
        if rng.below(10) == 0 {
            reply.additional_padding = vec![0; 4 * rng.below(8)];
        }
        if rng.below(10) == 0 {
            let n = 1 + rng.below(200);
            reply.after_auth = rng.bytes(n);
        }
        let p = server_response(&S2C, &read, &reply);
        if let Ok(Response::Time(s)) = pending.verify_response(&s2c, &p) {
            assert!((1..=placeholders + 1).contains(&s.cookies.len()), "round {round}: {} cookies", s.cookies.len());
            assert!(s.cookies.iter().all(|c| (1..=MAX_COOKIE_LEN).contains(&c.len())), "round {round}");
            accepted += 1;
            if check_measure(&mut rng, &s, t1, t4) {
                measured += 1;
            }
        }
    }
    println!("NTP authentic hostile: {ROUNDS} responses, {accepted} accepted, {measured} measured");
    // The generator must still reach the code after the authenticator.
    assert!(accepted >= ROUNDS / 4 && measured >= ROUNDS / 10, "accepted {accepted}, measured {measured}");
}

#[test]
fn plain_ntp_hostile_responses() {
    let mut rng = Rng::new(0x4e54_5003);
    let (mut accepted, mut measured) = (0, 0);
    for round in 0..ROUNDS {
        let transmit = rng.next_u64();
        let (_, mut pending) = ntp::build_plain_request(NtpTimestamp::from_bits(transmit));
        let realistic = rng.below(2) == 0;
        let (reply, t1, t4) = hostile_header(&mut rng, realistic);
        let mut p = header(&reply, transmit.to_be_bytes());
        let n = match rng.below(4) {
            0 => 0,
            1 => rng.below(65),
            _ => rng.below(2100),
        };
        p.extend(rng.bytes(n));
        if let Ok(Response::Time(s)) = pending.verify_response(&p) {
            assert!(s.cookies.is_empty(), "round {round}");
            accepted += 1;
            if check_measure(&mut rng, &s, t1, t4) {
                measured += 1;
            }
        }
    }
    println!("plain NTP hostile: {ROUNDS} responses, {accepted} accepted, {measured} measured");
    assert!(accepted >= ROUNDS / 4 && measured >= ROUNDS / 10, "accepted {accepted}, measured {measured}");
}
