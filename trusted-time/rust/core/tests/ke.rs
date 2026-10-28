//! NTS-KE records: the client request read back by the test server, server
//! responses built by the test code in `common`, checked by the crate.

mod common;

use common::*;
use signer_nts_core::ke::{self, KeError, record_type as rt};

fn parse(records: &[Vec<u8>]) -> Result<ke::KeResponse, KeError> {
    ke::parse_response(&records.concat())
}

/// A good response with `extra` records added before End of Message.
fn with(extra: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut r = good_ke_records(&[vec![7; 100]]);
    r.extend_from_slice(extra);
    r.push(end_of_message());
    r
}

#[test]
fn request_as_the_server_reads_it() {
    let req = ke::build_request();
    assert_eq!(
        split_records(&req),
        [(true, rt::NEXT_PROTOCOL, vec![0, 0]), (true, rt::AEAD_ALGORITHM, vec![0, 15]), (true, rt::END_OF_MESSAGE, vec![])]
    );
    assert_eq!(ke::response_length(&req), Ok(Some(req.len())));
}

#[test]
fn round_trip() {
    let mut records = good_ke_records(&eight_cookies());
    records.push(record(true, rt::SERVER, b"ntp1.example.net"));
    records.push(record(false, rt::PORT, &1234u16.to_be_bytes()));
    records.push(end_of_message());
    let buf = records.concat();
    let r = ke::parse_response(&buf).unwrap();
    assert_eq!(r.cookies.len(), 8);
    for (i, c) in r.cookies.iter().enumerate() {
        assert_eq!(c.as_bytes(), vec![i as u8 + 1; 100]);
    }
    assert_eq!(r.cookies_dropped, 0);
    assert_eq!(r.server.as_deref(), Some("ntp1.example.net"));
    assert_eq!((r.port, r.ntp_port()), (Some(1234), 1234));
    assert_eq!(ke::response_length(&buf), Ok(Some(buf.len())));
}

#[test]
fn defaults_without_server_and_port() {
    let r = ke::parse_response(&good_ke_response()).unwrap();
    assert_eq!((r.ntp_port(), r.port, r.server), (123, None, None));
}

#[test]
fn records_in_any_order() {
    // Only End of Message has a fixed place (section 4.1.1).
    let mut records = good_ke_records(&[vec![1; 64], vec![2; 64]]);
    records.reverse();
    records.push(end_of_message());
    assert_eq!(parse(&records).unwrap().cookies.len(), 2);
}

#[test]
fn response_length_waits_for_end_of_message() {
    let buf = good_ke_response();
    for n in 0..buf.len() {
        assert_eq!(ke::response_length(&buf[..n]), Ok(None), "prefix {n}");
        assert_eq!(ke::parse_response(&buf[..n]).err(), Some(KeError::Truncated), "prefix {n}");
    }
    let mut more = buf.clone();
    more.extend_from_slice(&[1, 2, 3]);
    assert_eq!(ke::response_length(&more), Ok(Some(buf.len())));
    assert_eq!(ke::parse_response(&more).err(), Some(KeError::TrailingData));
}

#[test]
fn error_and_warning_records() {
    for code in [0u16, 1, 2, 0x1234] {
        assert_eq!(parse(&with(&[record(true, rt::ERROR, &code.to_be_bytes())])), Err(KeError::ServerError(code)));
        assert_eq!(parse(&with(&[record(true, rt::WARNING, &code.to_be_bytes())])), Err(KeError::ServerWarning(code)));
    }
    // An Error record alone, as a server sends it.
    assert_eq!(
        parse(&[record(true, rt::ERROR, &[0, 1]), end_of_message()]),
        Err(KeError::ServerError(ke::error_code::BAD_REQUEST))
    );
    assert_eq!(parse(&with(&[record(true, rt::ERROR, &[0])])), Err(KeError::BadRecordBody { record_type: rt::ERROR }));
}

#[test]
fn unknown_records() {
    assert_eq!(
        parse(&with(&[record(true, 0x1234, b"x")])),
        Err(KeError::UnknownCriticalRecord { record_type: 0x1234 })
    );
    assert!(parse(&with(&[record(false, 0x1234, b"x"), record(false, 0x7fff, &[])])).is_ok());
}

#[test]
fn missing_records() {
    let np = record(true, rt::NEXT_PROTOCOL, &[0, 0]);
    let aead = record(true, rt::AEAD_ALGORITHM, &[0, 15]);
    let cookie = record(false, rt::NEW_COOKIE, &[1; 16]);
    let eom = end_of_message();
    let missing = |record_type| Err(KeError::MissingRecord { record_type });
    assert_eq!(parse(&[aead.clone(), cookie.clone(), eom.clone()]), missing(rt::NEXT_PROTOCOL));
    assert_eq!(parse(&[np.clone(), cookie.clone(), eom.clone()]), missing(rt::AEAD_ALGORITHM));
    assert_eq!(parse(&[np.clone(), aead.clone(), eom.clone()]), missing(rt::NEW_COOKIE));
    assert_eq!(parse(&[np, aead, cookie]), Err(KeError::Truncated));
    assert_eq!(ke::parse_response(&[]), Err(KeError::Truncated));
}

#[test]
fn wrong_protocol_or_aead() {
    let response = |np: &[u8], aead: &[u8]| {
        parse(&[
            record(true, rt::NEXT_PROTOCOL, np),
            record(true, rt::AEAD_ALGORITHM, aead),
            record(false, rt::NEW_COOKIE, &[1; 16]),
            end_of_message(),
        ])
    };
    assert!(response(&[0, 0], &[0, 15]).is_ok());
    assert_eq!(response(&[0, 1], &[0, 15]), Err(KeError::WrongProtocol(1)));
    assert_eq!(response(&[0, 0, 0x80, 0], &[0, 15]), Err(KeError::WrongProtocol(0x8000)));
    assert_eq!(response(&[], &[0, 15]), Err(KeError::NoCommonProtocol));
    assert_eq!(response(&[0], &[0, 15]), Err(KeError::BadRecordBody { record_type: rt::NEXT_PROTOCOL }));
    assert_eq!(response(&[0, 0], &[0, 16]), Err(KeError::WrongAead(16)));
    assert_eq!(response(&[0, 0], &[0, 30]), Err(KeError::WrongAead(30)));
    assert_eq!(response(&[0, 0], &[]), Err(KeError::NoCommonAead));
    assert_eq!(response(&[0, 0], &[0, 15, 0, 15]), Err(KeError::BadRecordBody { record_type: rt::AEAD_ALGORITHM }));
    assert_eq!(response(&[0, 0], &[0, 15, 0]), Err(KeError::BadRecordBody { record_type: rt::AEAD_ALGORITHM }));
}

#[test]
fn critical_bits() {
    // Next Protocol and End of Message MUST have it (sections 4.1.2, 4.1.1).
    let mut r = good_ke_records(&[vec![1; 16]]);
    r[0] = record(false, rt::NEXT_PROTOCOL, &[0, 0]);
    r.push(end_of_message());
    assert_eq!(parse(&r), Err(KeError::CriticalBitMissing { record_type: rt::NEXT_PROTOCOL }));
    let mut r = good_ke_records(&[vec![1; 16]]);
    r.push(record(false, rt::END_OF_MESSAGE, &[]));
    assert_eq!(parse(&r), Err(KeError::BadEndOfMessage));
    let mut r = good_ke_records(&[vec![1; 16]]);
    r.push(record(true, rt::END_OF_MESSAGE, &[0, 0]));
    assert_eq!(parse(&r), Err(KeError::BadEndOfMessage));
    // AEAD, cookie, server and port may come with or without it.
    let r = [
        record(true, rt::NEXT_PROTOCOL, &[0, 0]),
        record(false, rt::AEAD_ALGORITHM, &[0, 15]),
        record(true, rt::NEW_COOKIE, &[1; 16]),
        record(true, rt::SERVER, b"192.0.2.1"),
        record(true, rt::PORT, &[0, 123]),
        end_of_message(),
    ];
    assert!(parse(&r).is_ok());
}

#[test]
fn duplicate_records() {
    for dup in [
        record(true, rt::NEXT_PROTOCOL, &[0, 0]),
        record(true, rt::AEAD_ALGORITHM, &[0, 15]),
    ] {
        assert_eq!(parse(&with(&[dup.clone()])), Err(KeError::DuplicateRecord { record_type: split_records(&dup)[0].1 }));
    }
    let server = record(false, rt::SERVER, b"a.example");
    assert_eq!(parse(&with(&[server.clone(), server])), Err(KeError::DuplicateRecord { record_type: rt::SERVER }));
    let port = record(false, rt::PORT, &[0, 123]);
    assert_eq!(parse(&with(&[port.clone(), port])), Err(KeError::DuplicateRecord { record_type: rt::PORT }));
}

#[test]
fn bad_bodies() {
    let bad = |record_type| Err(KeError::BadRecordBody { record_type });
    assert_eq!(parse(&with(&[record(false, rt::NEW_COOKIE, &[])])), bad(rt::NEW_COOKIE));
    for name in [&b""[..], b"fe80::1%eth0", b"a b", b"x\0y", b"time.example.com/"] {
        assert_eq!(parse(&with(&[record(false, rt::SERVER, name)])), bad(rt::SERVER));
    }
    assert_eq!(parse(&with(&[record(false, rt::SERVER, &[b'a'; 256])])), bad(rt::SERVER));
    assert!(parse(&with(&[record(false, rt::SERVER, &[b'a'; 255])])).is_ok());
    for port in [&[0u8, 0][..], &[1], &[0, 1, 2]] {
        assert_eq!(parse(&with(&[record(false, rt::PORT, port)])), bad(rt::PORT));
    }
}

#[test]
fn caps() {
    // A cookie or any record body over 1024 octets.
    assert_eq!(
        parse(&with(&[record(false, rt::NEW_COOKIE, &[1; 1025])])),
        Err(KeError::RecordTooLong { record_type: rt::NEW_COOKIE })
    );
    assert_eq!(parse(&with(&[record(false, 0x2222, &[1; 1025])])), Err(KeError::RecordTooLong { record_type: 0x2222 }));
    assert!(parse(&with(&[record(false, rt::NEW_COOKIE, &[1; 1024])])).is_ok());
    let big = [record(false, 0x2222, &[1; 1025])].concat();
    assert_eq!(ke::response_length(&big), Err(KeError::RecordTooLong { record_type: 0x2222 }));

    // More than 64 records: 4 in `with`, plus 61 unknown ones.
    let filler: Vec<Vec<u8>> = (0..60).map(|_| record(false, 0x2222, &[])).collect();
    assert!(parse(&with(&filler)).is_ok());
    let filler: Vec<Vec<u8>> = (0..61).map(|_| record(false, 0x2222, &[])).collect();
    assert_eq!(parse(&with(&filler)), Err(KeError::TooManyRecords));
    assert_eq!(ke::response_length(&with(&filler).concat()), Err(KeError::TooManyRecords));

    // More than 65536 octets: 64 records of 1028 octets are 65792.
    let huge = vec![0u8; ke::MAX_RESPONSE_LEN + 1];
    assert_eq!(ke::parse_response(&huge), Err(KeError::TooLong));
    let long: Vec<u8> = (0..64).flat_map(|_| record(false, 0x2222, &[1; 1024])).collect();
    assert_eq!(ke::response_length(&long[..ke::MAX_RESPONSE_LEN - 1]), Ok(None));
    assert_eq!(ke::response_length(&long), Err(KeError::TooLong));
    assert_eq!(ke::response_length(&long[..ke::MAX_RESPONSE_LEN]), Err(KeError::TooLong));

    // Twenty cookies: eight kept, twelve counted.
    let cookies: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i + 1; 32]).collect();
    let mut r = good_ke_records(&cookies);
    r.push(end_of_message());
    let r = parse(&r).unwrap();
    assert_eq!((r.cookies.len(), r.cookies_dropped), (8, 12));
    assert_eq!(r.cookies[7].as_bytes(), [8; 32]);
}

#[test]
fn exporter_values() {
    assert_eq!(ke::EXPORTER_LABEL, "EXPORTER-network-time-security");
    assert_eq!(ke::exporter_context(ke::KeyDirection::ClientToServer), [0x00, 0x00, 0x00, 0x0f, 0x00]);
    assert_eq!(ke::exporter_context(ke::KeyDirection::ServerToClient), [0x00, 0x00, 0x00, 0x0f, 0x01]);
    assert_eq!((ke::ALPN, ke::NTS_KE_PORT, ke::KEY_LEN), (&b"ntske/1"[..], 4460, 32));
}
