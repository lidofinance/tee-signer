//! NTPv4 with NTS: client request built by the crate, response built by the
//! test server in `common`, checked by the crate.

mod common;

use common::*;
use signer_nts_core::cookie::{Cookie, MAX_COOKIE_LEN};
use signer_nts_core::keys::{C2sKey, S2cKey};
use signer_nts_core::ntp::{
    self, KissCode, LeapIndicator, NtpError, PendingRequest, RequestInput, Response, TimeSample, field_type,
};
use signer_nts_core::time::NtpTimestamp;

const TRANSMIT: u64 = 0x5eed_1234_9abc_def0;
const NONCE: [u8; 16] = [0x4e; 16];

fn uid(seed: u8) -> [u8; 32] {
    std::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
}

fn c2s() -> C2sKey {
    C2sKey::from_slice(&C2S).unwrap()
}

fn s2c() -> S2cKey {
    S2cKey::from_slice(&S2C).unwrap()
}

/// A request with a 100-octet cookie. The same arguments give the same
/// bytes and an equal pending state.
fn request_with(placeholders: usize, transmit: u64, unique_id: [u8; 32]) -> (Vec<u8>, PendingRequest) {
    let cookie = Cookie::new(&[0xc0; 100]).unwrap();
    let input = RequestInput {
        transmit: NtpTimestamp::from_bits(transmit),
        unique_id,
        nonce: NONCE,
        cookie: &cookie,
        placeholders,
    };
    ntp::build_request(&c2s(), &input).unwrap()
}

/// The standard request (one placeholder), its pending state, and what the
/// test server reads from it.
fn request() -> (Vec<u8>, PendingRequest, ClientRequest) {
    let (packet, pending) = request_with(1, TRANSMIT, uid(1));
    let read = server_read_request(&C2S, &packet).expect("the server accepts the request");
    (packet, pending, read)
}

fn pending() -> PendingRequest {
    request().1
}

fn verify(packet: &[u8]) -> Result<Response, NtpError> {
    pending().verify_response(&s2c(), packet)
}

fn time(r: Result<Response, NtpError>) -> TimeSample {
    match r {
        Ok(Response::Time(t)) => t,
        other => panic!("expected a time sample, got {other:?}"),
    }
}

fn reply_with(r: ServerReply) -> Vec<u8> {
    server_response(&S2C, &request().2, &r)
}

#[test]
fn request_layout() {
    let (packet, pending, read) = request();
    // 48 header + 36 Unique Identifier + 2 * 104 cookie and placeholder + 40 authenticator.
    assert_eq!(packet.len(), 48 + 36 + 2 * 104 + 40);
    assert_eq!(packet[0], 0x23, "leap 0, version 4, mode 3");
    assert!(packet[1..40].iter().all(|&b| b == 0), "header fields other than transmit are zero");
    assert_eq!(packet[40..48], TRANSMIT.to_be_bytes());
    assert_eq!(read.unique_id, uid(1));
    assert_eq!(read.cookie, [0xc0; 100]);
    assert_eq!((read.placeholders, read.placeholder_len), (1, 100));
    assert_eq!(pending.transmit().to_bits(), TRANSMIT);
    assert!(!pending.is_answered());
    // Field order and types: UID, cookie, placeholder, authenticator.
    let types: Vec<u16> = [48, 84, 188, 292].iter().map(|&at| u16::from_be_bytes([packet[at], packet[at + 1]])).collect();
    assert_eq!(
        types,
        [field_type::UNIQUE_IDENTIFIER, field_type::NTS_COOKIE, field_type::NTS_COOKIE_PLACEHOLDER, field_type::NTS_AUTHENTICATOR]
    );
    // The placeholder body is zeros.
    assert!(packet[192..292].iter().all(|&b| b == 0));
    // Authenticator: nonce length 16, ciphertext length 16 (tag only), our nonce.
    assert_eq!(packet[292..300], [0x04, 0x04, 0, 40, 0, 16, 0, 16]);
    assert_eq!(packet[300..316], NONCE);
    // Only the C2S key verifies it.
    assert!(server_read_request(&S2C, &packet).is_none());
}

#[test]
fn request_is_deterministic_and_depends_on_every_input() {
    let (a, _) = request_with(1, TRANSMIT, uid(1));
    assert_eq!(a, request_with(1, TRANSMIT, uid(1)).0);
    assert_ne!(a, request_with(1, TRANSMIT + 1, uid(1)).0);
    assert_ne!(a, request_with(1, TRANSMIT, uid(2)).0);
    assert_ne!(a.len(), request_with(2, TRANSMIT, uid(1)).0.len());
}

#[test]
fn request_limits() {
    let cookie = Cookie::new(&[1; 100]).unwrap();
    let mut input = RequestInput {
        transmit: NtpTimestamp::from_bits(TRANSMIT),
        unique_id: uid(1),
        nonce: NONCE,
        cookie: &cookie,
        placeholders: 8,
    };
    assert_eq!(ntp::build_request(&c2s(), &input).err(), Some(NtpError::TooManyPlaceholders));
    input.placeholders = 7;
    let (p, _) = ntp::build_request(&c2s(), &input).unwrap();
    assert_eq!(p.len(), 48 + 36 + 8 * 104 + 40);
    assert_eq!(server_read_request(&C2S, &p).unwrap().placeholders, 7);

    let big = Cookie::new(&[1; MAX_COOKIE_LEN]).unwrap();
    assert_eq!(ntp::max_placeholders(&big), 0);
    input.cookie = &big;
    input.placeholders = 1;
    assert_eq!(ntp::build_request(&c2s(), &input).err(), Some(NtpError::RequestTooLong));
    input.placeholders = 0;
    let (p, _) = ntp::build_request(&c2s(), &input).unwrap();
    assert!(p.len() <= ntp::MAX_REQUEST_LEN);

    // A cookie whose length is not a multiple of 4 is padded, and so is
    // each placeholder.
    let odd = Cookie::new(&[9; 101]).unwrap();
    input.cookie = &odd;
    input.placeholders = 2;
    let (p, _) = ntp::build_request(&c2s(), &input).unwrap();
    let read = server_read_request(&C2S, &p).unwrap();
    assert_eq!(read.cookie.len(), 104);
    assert_eq!(read.cookie[..101], [9; 101]);
    assert_eq!(read.cookie[101..], [0, 0, 0]);
    assert_eq!((read.placeholders, read.placeholder_len), (2, 104));
}

#[test]
fn round_trip() {
    let (_, mut pending, read) = request();
    let r = ServerReply {
        leap: 1,
        stratum: 3,
        precision: -24,
        root_delay: 0x0001_8000,
        root_dispersion: 0x0000_0042,
        cookies: vec![vec![0xaa; 100], vec![0xbb; 104]],
        ..ServerReply::default()
    };
    let packet = server_response(&S2C, &read, &r);
    let t = time(pending.verify_response(&s2c(), &packet));
    assert_eq!(t.leap, LeapIndicator::InsertSecond);
    assert_eq!((t.stratum, t.precision), (3, -24));
    assert_eq!(t.root_delay.to_bits(), 0x0001_8000);
    assert_eq!(t.root_delay.to_nanos(), 1_500_000_000);
    assert_eq!(t.root_dispersion.to_bits(), 0x0000_0042);
    assert_eq!(t.reference.to_bits(), r.reference);
    assert_eq!(t.origin.to_bits(), TRANSMIT);
    assert_eq!(t.receive.to_bits(), r.receive);
    assert_eq!(t.transmit.to_bits(), r.transmit);
    let cookies: Vec<&[u8]> = t.cookies.iter().map(Cookie::as_bytes).collect();
    assert_eq!(cookies, [&[0xaa; 100][..], &[0xbb; 104][..]]);
    assert!(pending.is_answered());
}

#[test]
fn leap_indicator_values() {
    for (leap, want) in [(0, LeapIndicator::NoWarning), (1, LeapIndicator::InsertSecond), (2, LeapIndicator::DeleteSecond)] {
        assert_eq!(time(verify(&reply_with(ServerReply { leap, ..ServerReply::default() }))).leap, want);
    }
}

#[test]
fn cookies_up_to_placeholders_plus_one() {
    for placeholders in 0..=ntp::MAX_PLACEHOLDERS {
        let (packet, mut pending) = request_with(placeholders, TRANSMIT, uid(3));
        let read = server_read_request(&C2S, &packet).unwrap();
        let cookies = |n: usize| (0..n).map(|i| vec![i as u8 + 1; 100]).collect::<Vec<_>>();
        let too_many = server_response(&S2C, &read, &ServerReply { cookies: cookies(placeholders + 2), ..ServerReply::default() });
        assert_eq!(pending.verify_response(&s2c(), &too_many), Err(NtpError::TooManyCookies));
        let ok = server_response(&S2C, &read, &ServerReply { cookies: cookies(placeholders + 1), ..ServerReply::default() });
        assert_eq!(time(pending.verify_response(&s2c(), &ok)).cookies.len(), placeholders + 1);
    }
}

/// Every single-octet change of a valid response is refused. The one
/// exception the RFC allows: stratum 2 changed to 0 makes it a KoD, which
/// still has our Unique Identifier and origin and gives no time.
#[test]
fn every_changed_octet_is_refused() {
    let r = ServerReply { cookies: vec![vec![0xaa; 100], vec![0xbb; 100]], ..ServerReply::default() };
    let good = reply_with(r);
    time(verify(&good));
    let (mut refused, mut kod) = (0, 0);
    for i in 0..good.len() {
        for mask in [0x01u8, 0x02, 0x04, 0x10, 0x40, 0x80, 0xff] {
            let mut m = good.clone();
            m[i] ^= mask;
            match verify(&m) {
                Err(_) => refused += 1,
                Ok(Response::KissOfDeath(code)) => {
                    assert_eq!((i, m[1]), (1, 0), "only stratum 0 makes a KoD");
                    assert_eq!(code, KissCode::Other([192, 0, 2, 7]));
                    kod += 1;
                }
                Ok(Response::Time(_)) => panic!("octet {i} xor {mask:#04x} was accepted"),
            }
        }
    }
    assert_eq!(kod, 1);
    assert_eq!(refused + kod, good.len() * 7);
    println!("{} octets x 7 masks: {refused} refused, {kod} KoD", good.len());
}

#[test]
fn wrong_unique_id() {
    let (_, mut pending, read) = request();
    let other = ClientRequest { unique_id: uid(9).to_vec(), ..read.clone() };
    let packet = server_response(&S2C, &other, &ServerReply::default());
    assert_eq!(pending.verify_response(&s2c(), &packet), Err(NtpError::UniqueIdMismatch));
    // A shorter or longer echo is not ours either.
    for len in [16, 31, 36] {
        let mut u = uid(1).to_vec();
        u.resize(len, 0);
        let packet = server_response(&S2C, &ClientRequest { unique_id: u, ..read.clone() }, &ServerReply::default());
        assert_eq!(pending.verify_response(&s2c(), &packet), Err(NtpError::UniqueIdMismatch), "length {len}");
    }
    let missing = server_response(&S2C, &read, &ServerReply { with_unique_id: false, ..ServerReply::default() });
    assert_eq!(pending.verify_response(&s2c(), &missing), Err(NtpError::MissingUniqueId));
    let twice = server_response(
        &S2C,
        &read,
        &ServerReply { plain_fields: vec![field(field_type::UNIQUE_IDENTIFIER, &uid(1))], ..ServerReply::default() },
    );
    assert_eq!(pending.verify_response(&s2c(), &twice), Err(NtpError::DuplicateUniqueId));
    // After all of these the real response is still accepted.
    time(pending.verify_response(&s2c(), &server_response(&S2C, &read, &ServerReply::default())));
}

#[test]
fn wrong_origin() {
    let (_, mut pending, read) = request();
    let other = ClientRequest { transmit: (TRANSMIT ^ 1).to_be_bytes(), ..read };
    let packet = server_response(&S2C, &other, &ServerReply::default());
    assert_eq!(pending.verify_response(&s2c(), &packet), Err(NtpError::OriginMismatch));
}

#[test]
fn replayed_response() {
    let (_, mut pending, read) = request();
    let packet = server_response(&S2C, &read, &ServerReply::default());
    // A refused packet first does not use up the request.
    assert!(pending.verify_response(&s2c(), &packet[..60]).is_err());
    time(pending.verify_response(&s2c(), &packet));
    assert_eq!(pending.verify_response(&s2c(), &packet), Err(NtpError::AlreadyAnswered));
    // The same response against a later request: other transmit timestamp,
    // other Unique Identifier.
    let (_, mut next) = request_with(1, TRANSMIT + 1, uid(2));
    assert_eq!(next.verify_response(&s2c(), &packet), Err(NtpError::OriginMismatch));
    let (_, mut same_transmit) = request_with(1, TRANSMIT, uid(2));
    assert_eq!(same_transmit.verify_response(&s2c(), &packet), Err(NtpError::UniqueIdMismatch));
}

#[test]
fn truncated_packets() {
    let packet = reply_with(ServerReply::default());
    for len in 0..packet.len() {
        let r = verify(&packet[..len]);
        assert!(r.is_err(), "length {len}: {r:?}");
        if len < 48 {
            assert_eq!(r, Err(NtpError::TooShort));
        }
    }
    // The header alone: no Unique Identifier.
    assert_eq!(verify(&packet[..48]), Err(NtpError::MissingUniqueId));
}

#[test]
fn oversized_and_malformed_fields() {
    let good = reply_with(ServerReply::default());
    let mut long = good.clone();
    long.resize(ntp::MAX_RESPONSE_LEN + 1, 0);
    assert_eq!(verify(&long), Err(NtpError::TooLong));

    // Cookies: too long, empty.
    let r = ServerReply { cookies: vec![vec![1; MAX_COOKIE_LEN + 4]], ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::BadCookie));
    let r = ServerReply { cookies: vec![vec![]], ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::BadCookie));

    // Plain fields: length not a multiple of 4, under 16, past the end.
    for bad in [
        [0x7f, 0x00, 0x00, 0x11].to_vec(),
        [0x7f, 0x00, 0x00, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0].to_vec(),
        [0x7f, 0x00, 0x00, 0x04].to_vec(),
        [0x7f, 0x00, 0x00, 0x00].to_vec(),
    ] {
        let r = ServerReply { plain_fields: vec![bad], ..ServerReply::default() };
        assert_eq!(verify(&reply_with(r)), Err(NtpError::BadExtensionField));
    }
    let mut past_end = reply_with(ServerReply { with_authenticator: false, ..ServerReply::default() });
    past_end.extend_from_slice(&[0x7f, 0x00, 0x01, 0x00, 0, 0, 0, 0]);
    assert_eq!(verify(&past_end), Err(NtpError::BadExtensionField));

    // Encrypted fields: a length that is not a multiple of 4, too short, past the end.
    for raw in [
        vec![0x02, 0x04, 0x00, 0x06, 0xaa, 0xbb, 0, 0],
        vec![0x02, 0x04, 0x00, 0x02],
        vec![0x02, 0x04, 0x00, 0x10, 1, 2, 3, 4],
        vec![0x02, 0x04],
    ] {
        let r = ServerReply { raw_plaintext: Some(raw), ..ServerReply::default() };
        assert_eq!(verify(&reply_with(r)), Err(NtpError::BadEncryptedField));
    }
}

#[test]
fn other_encrypted_fields_are_skipped() {
    // A 4-octet unknown field and an encrypted placeholder, then a cookie.
    let mut raw = vec![0x7e, 0x00, 0x00, 0x04];
    raw.extend(field(field_type::NTS_COOKIE_PLACEHOLDER, &[0; 8]));
    raw.extend(field(field_type::NTS_COOKIE, &[0xcc; 100]));
    let r = ServerReply { raw_plaintext: Some(raw), ..ServerReply::default() };
    let t = time(verify(&reply_with(r)));
    assert_eq!(t.cookies.len(), 1);
    assert_eq!(t.cookies[0].as_bytes(), [0xcc; 100]);
}

#[test]
fn kiss_of_death_packets() {
    let read = request().2;
    for (code, want) in [
        (*b"RATE", KissCode::Rate),
        (*b"NTSN", KissCode::Ntsn),
        (*b"DENY", KissCode::Deny),
        (*b"RSTR", KissCode::Rstr),
        (*b"STEP", KissCode::Other(*b"STEP")),
    ] {
        let mut pending = pending();
        let packet = kiss_of_death(&read, &code, true);
        assert_eq!(pending.verify_response(&s2c(), &packet), Ok(Response::KissOfDeath(want)));
        assert!(pending.is_answered());
        assert_eq!(pending.verify_response(&s2c(), &packet), Err(NtpError::AlreadyAnswered));
    }
    // Without our Unique Identifier, with another one, or with another origin: refused.
    assert_eq!(verify(&kiss_of_death(&read, b"DENY", false)), Err(NtpError::MissingUniqueId));
    let other = ClientRequest { unique_id: uid(7).to_vec(), ..read.clone() };
    assert_eq!(verify(&kiss_of_death(&other, b"DENY", true)), Err(NtpError::UniqueIdMismatch));
    let other = ClientRequest { transmit: [0; 8], ..read.clone() };
    assert_eq!(verify(&kiss_of_death(&other, b"DENY", true)), Err(NtpError::OriginMismatch));
    // A KoD that is also authenticated is a KoD too.
    let r = ServerReply { stratum: 0, reference_id: *b"RATE", ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Ok(Response::KissOfDeath(KissCode::Rate)));
}

#[test]
fn unsynchronized_or_bad_stratum_is_refused() {
    assert_eq!(verify(&reply_with(ServerReply { leap: 3, ..ServerReply::default() })), Err(NtpError::Unsynchronized));
    for stratum in [16u8, 17, 255] {
        let r = ServerReply { stratum, ..ServerReply::default() };
        assert_eq!(verify(&reply_with(r)), Err(NtpError::BadStratum(stratum)));
    }
    for stratum in [1u8, 15] {
        assert_eq!(time(verify(&reply_with(ServerReply { stratum, ..ServerReply::default() }))).stratum, stratum);
    }
}

#[test]
fn version_and_mode() {
    assert_eq!(verify(&reply_with(ServerReply { version: 3, ..ServerReply::default() })), Err(NtpError::BadVersion(3)));
    for mode in [0u8, 1, 2, 3, 5, 6, 7] {
        assert_eq!(verify(&reply_with(ServerReply { mode, ..ServerReply::default() })), Err(NtpError::BadMode(mode)));
    }
}

/// RFC 8915 section 5.7: the client MUST discard unauthenticated extension
/// fields, the ones after the authenticator. They do not change the result.
#[test]
fn fields_after_the_authenticator_are_discarded() {
    let mut after = field(field_type::NTS_COOKIE, &[0xee; 100]);
    after.extend(field(field_type::UNIQUE_IDENTIFIER, &uid(5)));
    after.extend([0xde, 0xad, 0xbe]);
    let r = ServerReply { after_auth: after, ..ServerReply::default() };
    let t = time(verify(&reply_with(r)));
    assert_eq!(t.cookies.len(), 1);
    assert_eq!(t.cookies[0].as_bytes(), [0xc1; 100]);
}

/// Cookies must come encrypted (RFC 8915 section 5.7). One in the clear,
/// before the authenticator, is skipped.
#[test]
fn a_cookie_in_the_clear_is_not_used() {
    let r = ServerReply { plain_fields: vec![field(field_type::NTS_COOKIE, &[0xdd; 100])], ..ServerReply::default() };
    let t = time(verify(&reply_with(r)));
    assert_eq!(t.cookies.len(), 1);
    assert_eq!(t.cookies[0].as_bytes(), [0xc1; 100]);
}

#[test]
fn authenticator_checks() {
    let read = request().2;
    // Signed with the wrong key.
    assert_eq!(verify(&server_response(&C2S, &read, &ServerReply::default())), Err(NtpError::AuthenticationFailed));
    // No authenticator.
    let r = ServerReply { with_authenticator: false, ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::MissingAuthenticator));
    // No cookie.
    let r = ServerReply { cookies: vec![], ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::NoCookies));
    // Server nonces of other lengths, padded with zeros.
    for len in [1, 12, 13, 24, 32] {
        let r = ServerReply { nonce: vec![0x77; len], ..ServerReply::default() };
        time(verify(&reply_with(r)));
    }
    // Padding that is not zero, in the nonce or in the Additional Padding.
    let r = ServerReply { nonce: vec![0x77; 13], pad_byte: 1, ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::BadAuthenticator));
    let r = ServerReply { additional_padding: vec![0; 8], ..ServerReply::default() };
    time(verify(&reply_with(r)));
    let r = ServerReply { additional_padding: vec![0, 0, 0, 1], ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::BadAuthenticator));
    // A zero-length nonce (RFC 5297 section 6.1: at least 1 octet).
    let r = ServerReply { nonce: vec![], ..ServerReply::default() };
    assert_eq!(verify(&reply_with(r)), Err(NtpError::BadAuthenticator));
}
