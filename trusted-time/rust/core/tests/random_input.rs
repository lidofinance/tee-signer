//! Deterministic randomized tests: garbage and mutated packets into both
//! parsers. A panic fails the test; the crate must return an error instead.
//! The PRNG is the splitmix64 in `common`, with fixed seeds, so every run
//! feeds the same inputs.

mod common;

use common::*;
use signer_nts_core::cookie::{Cookie, MAX_COOKIE_LEN};
use signer_nts_core::ke;
use signer_nts_core::keys::{C2sKey, S2cKey};
use signer_nts_core::ntp::{self, RequestInput, Response};
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
