//! Tests of the C functions, called through their raw-pointer signatures,
//! against the test server of the core's integration tests.

#![allow(unsafe_code)]

use super::code::*;
use super::ffi::*;
use super::*;
use core::ffi::CStr;
use core::ptr::{null, null_mut};
use signer_nts_core::selftest::SelfTestError;

#[path = "../core/tests/common/mod.rs"]
mod common;

use common::{C2S, S2C, ServerReply, good_ke_response, kiss_of_death, server_read_request, server_response};

const MS: i64 = 1_000_000;
const PIVOT: i64 = 1_790_000_000 * 1_000_000_000;

fn new_assoc() -> *mut SntsAssoc {
    let resp = good_ke_response();
    let mut a = null_mut();
    let mut why = 0u32;
    let rc = unsafe { snts_assoc_new(resp.as_ptr(), resp.len(), C2S.as_ptr(), 32, S2C.as_ptr(), 32, &mut a, &mut why) };
    assert_eq!(rc, OK, "reason {why:#x}");
    assert!(!a.is_null());
    a
}

fn random(seed: u8) -> [u8; REQUEST_RANDOM_LEN] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8).wrapping_mul(31))
}

/// Builds a request; returns the packet and the request handle.
fn request(a: *mut SntsAssoc, seed: u8) -> (Vec<u8>, *mut SntsRequest) {
    let mut buf = [0u8; 1280];
    let (mut n, mut r) = (0usize, null_mut());
    let rnd = random(seed);
    let rc = unsafe { snts_ntp_request(a, rnd.as_ptr(), rnd.len(), buf.as_mut_ptr(), buf.len(), &mut n, &mut r) };
    assert_eq!(rc, OK);
    (buf[..n].to_vec(), r)
}

fn verify(a: *mut SntsAssoc, r: *mut SntsRequest, p: &[u8], t1: i64, t4: i64) -> (c_int, Sample, u32) {
    let mut s = Sample::default();
    let mut why = 0;
    let rc = unsafe { snts_ntp_verify(a, r, p.as_ptr(), p.len(), t1, t4, PIVOT, &mut s, &mut why) };
    (rc, s, why)
}

fn cstr(p: *const c_char) -> &'static str {
    unsafe { CStr::from_ptr(p) }.to_str().unwrap()
}

#[test]
fn selftest_passes() {
    assert_eq!(snts_aes_siv_selftest(), 0);
}

// The C header documents these numbers.
#[test]
fn selftest_step_numbers() {
    assert_eq!(SelfTestError::EncryptFailed as c_int, 1);
    assert_eq!(SelfTestError::CiphertextDiffers as c_int, 2);
    assert_eq!(SelfTestError::DecryptFailed as c_int, 3);
    assert_eq!(SelfTestError::PlaintextDiffers as c_int, 4);
    assert_eq!(SelfTestError::TamperedAccepted as c_int, 5);
}

#[test]
fn version_is_a_c_string() {
    assert_eq!(cstr(snts_version()), concat!("signer-nts ", env!("CARGO_PKG_VERSION")));
}

// The header is written by hand. It must declare every export, with the
// numbers and struct layouts used here.
#[test]
fn header_matches_the_library() {
    let h = include_str!("../include/signer_nts.h");
    for decl in [
        "const char *snts_version(void);",
        "int snts_aes_siv_selftest(void);",
        "const char *snts_reason_text(int code, uint32_t reason);",
        "const char *snts_ke_alpn(void);",
        "const char *snts_ke_exporter_label(void);",
        "int snts_ke_exporter_context(int direction, uint8_t *out, size_t cap, size_t *out_len);",
        "int snts_ke_request(uint8_t *out, size_t cap, size_t *out_len);",
        "int snts_ke_response_length(const uint8_t *buf, size_t len, size_t *out_len, uint32_t *reason);",
        "int snts_assoc_new(const uint8_t *response, size_t response_len, const uint8_t *c2s, size_t c2s_len,\n                   const uint8_t *s2c, size_t s2c_len, snts_assoc **out, uint32_t *reason);",
        "void snts_assoc_free(snts_assoc *a);",
        "size_t snts_assoc_cookies(const snts_assoc *a);",
        "uint16_t snts_assoc_port(const snts_assoc *a);",
        "int snts_assoc_server(const snts_assoc *a, uint8_t *out, size_t cap, size_t *out_len);",
        "int snts_ntp_request(snts_assoc *a, const uint8_t *random, size_t random_len, uint8_t *out, size_t cap,\n                     size_t *out_len, snts_request **req);",
        "void snts_request_free(snts_request *r);",
        "int snts_ntp_verify(snts_assoc *a, snts_request *r, const uint8_t *packet, size_t packet_len,\n                    int64_t t1_local_ns, int64_t t4_local_ns, int64_t pivot_unix_ns, snts_sample *out,\n                    uint32_t *reason);",
        "int snts_quorum(const snts_interval *intervals, size_t n, int64_t now_local_ns, snts_quorum_result *out,\n                uint32_t *reason);",
    ] {
        assert!(h.contains(decl), "header lacks: {decl}");
    }
    for (name, v) in [
        ("SNTS_OK", OK),
        ("SNTS_KISS", KISS),
        ("SNTS_MORE", MORE),
        ("SNTS_E_NULL", E_NULL),
        ("SNTS_E_BUFFER", E_BUFFER),
        ("SNTS_E_ARG", E_ARG),
        ("SNTS_E_KE", E_KE),
        ("SNTS_E_NO_COOKIE", E_NO_COOKIE),
        ("SNTS_E_NTP", E_NTP),
        ("SNTS_E_SAMPLE", E_SAMPLE),
        ("SNTS_E_QUORUM", E_QUORUM),
    ] {
        let line = format!("#define {name} ({v})");
        assert!(h.contains(&line), "header lacks: {line}");
    }
    for (name, v) in [
        ("SNTS_REQUEST_RANDOM_LEN", REQUEST_RANDOM_LEN as i64),
        ("SNTS_KEY_LEN", signer_nts_core::keys::KEY_LEN as i64),
        ("SNTS_MAX_OPERATOR_LEN", signer_nts_core::quorum::MAX_OPERATOR_LEN as i64),
        ("SNTS_MAX_SERVERS", signer_nts_core::quorum::MAX_SERVERS as i64),
        ("SNTS_RHO_PPM", signer_nts_core::sample::RHO_PPM),
        ("SNTS_MAX_BOUND_NS", signer_nts_core::sample::MAX_BOUND_NS),
        ("SNTS_KE_MAX_RESPONSE_LEN", signer_nts_core::ke::MAX_RESPONSE_LEN as i64),
        ("SNTS_NTP_MAX_REQUEST_LEN", signer_nts_core::ntp::MAX_REQUEST_LEN as i64),
        ("SNTS_NTP_MAX_RESPONSE_LEN", signer_nts_core::ntp::MAX_RESPONSE_LEN as i64),
        ("SNTS_SAMPLE_SIZE", size_of::<Sample>() as i64),
        ("SNTS_INTERVAL_SIZE", size_of::<IntervalIn>() as i64),
        ("SNTS_QUORUM_RESULT_SIZE", size_of::<QuorumOut>() as i64),
    ] {
        let line = format!("#define {name} {v}");
        assert!(h.contains(&line), "header lacks: {line}");
    }
}

#[test]
fn struct_layouts() {
    assert_eq!(size_of::<Sample>(), 72);
    assert_eq!(size_of::<IntervalIn>(), 64);
    assert_eq!(size_of::<QuorumOut>(), 32);
    assert_eq!(core::mem::offset_of!(Sample, cookies_received), 48);
    assert_eq!(core::mem::offset_of!(Sample, kiss), 62);
    assert_eq!(core::mem::offset_of!(IntervalIn, offset_ns), 40);
}

#[test]
fn ke_constants() {
    assert_eq!(cstr(snts_ke_alpn()), "ntske/1");
    assert_eq!(cstr(snts_ke_exporter_label()), "EXPORTER-network-time-security");
    let mut out = [0u8; 5];
    let mut n = 0;
    assert_eq!(unsafe { snts_ke_exporter_context(0, out.as_mut_ptr(), 5, &mut n) }, OK);
    assert_eq!((out, n), ([0, 0, 0, 15, 0], 5));
    assert_eq!(unsafe { snts_ke_exporter_context(1, out.as_mut_ptr(), 5, &mut n) }, OK);
    assert_eq!(out, [0, 0, 0, 15, 1]);
    assert_eq!(unsafe { snts_ke_exporter_context(2, out.as_mut_ptr(), 5, &mut n) }, E_ARG);
    assert_eq!(unsafe { snts_ke_exporter_context(0, out.as_mut_ptr(), 4, &mut n) }, E_BUFFER);
    assert_eq!(n, 5);

    let mut req = [0u8; 16];
    assert_eq!(unsafe { snts_ke_request(req.as_mut_ptr(), 16, &mut n) }, OK);
    assert_eq!(req, signer_nts_core::ke::build_request());
    assert_eq!(unsafe { snts_ke_request(req.as_mut_ptr(), 15, &mut n) }, E_BUFFER);
    assert_eq!(unsafe { snts_ke_request(req.as_mut_ptr(), 16, null_mut()) }, E_NULL);
    assert_eq!(unsafe { snts_ke_request(null_mut(), 16, &mut n) }, E_NULL);
}

#[test]
fn ke_response_length() {
    let resp = good_ke_response();
    let (mut n, mut why) = (0usize, 0u32);
    for cut in 0..resp.len() {
        assert_eq!(unsafe { snts_ke_response_length(resp.as_ptr(), cut, &mut n, &mut why) }, MORE, "cut {cut}");
    }
    let mut longer = resp.clone();
    longer.extend_from_slice(b"junk");
    assert_eq!(unsafe { snts_ke_response_length(longer.as_ptr(), longer.len(), &mut n, &mut why) }, OK);
    assert_eq!(n, resp.len());
    // A record body over the cap is refused at once.
    let bad = [0x00, 0x05, 0x04, 0x01];
    assert_eq!(unsafe { snts_ke_response_length(bad.as_ptr(), 4, &mut n, &mut why) }, E_KE);
    assert_eq!(why, (4 << 16) | 5);
    assert_eq!(unsafe { snts_ke_response_length(null(), 4, &mut n, &mut why) }, E_NULL);
}

#[test]
fn assoc_new_refusals() {
    let resp = good_ke_response();
    let (mut a, mut why) = (null_mut(), 0u32);
    let rc = unsafe { snts_assoc_new(resp.as_ptr(), resp.len(), C2S.as_ptr(), 31, S2C.as_ptr(), 32, &mut a, &mut why) };
    assert_eq!((rc, a), (E_ARG, null_mut()));
    // The server sends Error 1 (bad request).
    let err = [common::record(true, 2, &[0, 1]), common::end_of_message()].concat();
    let rc = unsafe { snts_assoc_new(err.as_ptr(), err.len(), C2S.as_ptr(), 32, S2C.as_ptr(), 32, &mut a, &mut why) };
    assert_eq!((rc, why), (E_KE, (12 << 16) | 1));
    assert_eq!(cstr(snts_reason_text(rc, why)), "NTS-KE server error (value: error code, RFC 8915 4.1.3)");
    let rc = unsafe { snts_assoc_new(resp.as_ptr(), resp.len(), C2S.as_ptr(), 32, S2C.as_ptr(), 32, null_mut(), &mut why) };
    assert_eq!(rc, E_NULL);
    unsafe { snts_assoc_free(null_mut()) };
    unsafe { snts_request_free(null_mut()) };
}

#[test]
fn server_and_port() {
    let mut records = common::good_ke_records(&common::eight_cookies());
    records.push(common::record(true, 6, b"ntp.example.net"));
    records.push(common::record(true, 7, &[0x12, 0x34]));
    records.push(common::end_of_message());
    let resp = records.concat();
    let (mut a, mut why) = (null_mut(), 0u32);
    assert_eq!(unsafe { snts_assoc_new(resp.as_ptr(), resp.len(), C2S.as_ptr(), 32, S2C.as_ptr(), 32, &mut a, &mut why) }, OK);
    let mut buf = [0u8; 64];
    let mut n = 0;
    assert_eq!(unsafe { snts_assoc_server(a, buf.as_mut_ptr(), buf.len(), &mut n) }, OK);
    assert_eq!(&buf[..n], b"ntp.example.net");
    assert_eq!(unsafe { snts_assoc_server(a, buf.as_mut_ptr(), 3, &mut n) }, E_BUFFER);
    assert_eq!(n, 15);
    assert_eq!(unsafe { snts_assoc_port(a) }, 0x1234);
    unsafe { snts_assoc_free(a) };

    let a = new_assoc();
    assert_eq!(unsafe { snts_assoc_server(a, buf.as_mut_ptr(), buf.len(), &mut n) }, OK);
    assert_eq!(n, 0);
    assert_eq!(unsafe { snts_assoc_port(a) }, 123);
    unsafe { snts_assoc_free(a) };
    assert_eq!(unsafe { snts_assoc_port(null()) }, 0);
}

#[test]
fn round_trip_with_measurement() {
    let a = new_assoc();
    assert_eq!(unsafe { snts_assoc_cookies(a) }, 8);
    let (packet, r) = request(a, 1);
    assert_eq!(unsafe { snts_assoc_cookies(a) }, 7);
    let req = server_read_request(&C2S, &packet).expect("the test server reads the request");
    // Eight cookies held when it was built, so no placeholders.
    assert_eq!(req.placeholders, 0);
    let reply = ServerReply::default();
    let resp = server_response(&S2C, &req, &reply);
    let (rc, s, why) = verify(a, r, &resp, 5 * MS, 25 * MS);
    assert_eq!(rc, OK, "{}", cstr(snts_reason_text(rc, why)));
    assert_eq!((s.stratum, s.precision, s.leap, s.cookies_received, s.cookies_held), (2, -20, 0, 1, 8));
    assert_eq!(s.t4_local_ns, 25 * MS);
    let t2 = signer_nts_core::time::NtpTimestamp::from_bits(reply.receive).to_unix_nanos(PIVOT).unwrap();
    let t3 = signer_nts_core::time::NtpTimestamp::from_bits(reply.transmit).to_unix_nanos(PIVOT).unwrap();
    assert_eq!(s.delay_ns, 20 * MS - (t3 - t2));
    assert!((s.offset_ns - ((t2 - 5 * MS) + (t3 - 25 * MS)) / 2).abs() <= 1);
    assert!(s.bound_ns >= s.delay_ns / 2 + s.root_delay_ns / 2 + s.root_dispersion_ns);
    // The same response again is a replay.
    let (rc, _, why) = verify(a, r, &resp, 5 * MS, 25 * MS);
    assert_eq!((rc, why >> 16), (E_NTP, 4));
    unsafe { snts_request_free(r) };
    unsafe { snts_assoc_free(a) };
}

#[test]
fn placeholders_refill_the_jar() {
    let a = new_assoc();
    // Use five cookies without answers: 3 left.
    for i in 0..5 {
        let (_, r) = request(a, i);
        unsafe { snts_request_free(r) };
    }
    assert_eq!(unsafe { snts_assoc_cookies(a) }, 3);
    let (packet, r) = request(a, 9);
    let req = server_read_request(&C2S, &packet).unwrap();
    // 3 held with this one: 5 placeholders, so 2 + 6 = 8 after the answer.
    assert_eq!(req.placeholders, 5);
    let reply = ServerReply { cookies: vec![vec![0xc2; 100]; 6], ..ServerReply::default() };
    let (rc, s, _) = verify(a, r, &server_response(&S2C, &req, &reply), 0, 10 * MS);
    assert_eq!((rc, s.cookies_received, s.cookies_held), (OK, 6, 8));
    unsafe { snts_request_free(r) };
    unsafe { snts_assoc_free(a) };
}

#[test]
fn cookies_run_out_and_a_short_buffer_keeps_the_cookie() {
    let a = new_assoc();
    let rnd = random(3);
    let mut buf = [0u8; 1280];
    let (mut n, mut r) = (0usize, null_mut());
    let rc = unsafe { snts_ntp_request(a, rnd.as_ptr(), rnd.len(), buf.as_mut_ptr(), 100, &mut n, &mut r) };
    assert_eq!((rc, n, r), (E_BUFFER, 228, null_mut()));
    assert_eq!(unsafe { snts_assoc_cookies(a) }, 8);
    let rc = unsafe { snts_ntp_request(a, rnd.as_ptr(), 55, buf.as_mut_ptr(), buf.len(), &mut n, &mut r) };
    assert_eq!(rc, E_ARG);
    for i in 0..8 {
        let (_, r) = request(a, i);
        unsafe { snts_request_free(r) };
    }
    let rc = unsafe { snts_ntp_request(a, rnd.as_ptr(), rnd.len(), buf.as_mut_ptr(), buf.len(), &mut n, &mut r) };
    assert_eq!(rc, E_NO_COOKIE);
    assert_eq!(cstr(snts_reason_text(rc, 0)), "no cookie left; run NTS-KE again");
    unsafe { snts_assoc_free(a) };
}

#[test]
fn kiss_of_death_gives_the_code() {
    let a = new_assoc();
    let (packet, r) = request(a, 4);
    let req = server_read_request(&C2S, &packet).unwrap();
    let (rc, s, _) = verify(a, r, &kiss_of_death(&req, b"RATE", true), 0, MS);
    assert_eq!((rc, &s.kiss, s.cookies_held), (KISS, b"RATE", 7));
    unsafe { snts_request_free(r) };
    unsafe { snts_assoc_free(a) };
}

#[test]
fn a_refused_response_leaves_the_request_open() {
    let a = new_assoc();
    let (packet, r) = request(a, 5);
    let req = server_read_request(&C2S, &packet).unwrap();
    let good = server_response(&S2C, &req, &ServerReply::default());
    // Signed with the C2S key instead of S2C.
    let forged = server_response(&C2S, &req, &ServerReply::default());
    let (rc, _, why) = verify(a, r, &forged, 0, MS);
    assert_eq!((rc, why), (E_NTP, 16 << 16));
    assert_eq!(cstr(snts_reason_text(rc, why)), "NTS authenticator does not verify");
    let (rc, _, _) = verify(a, r, &good, 0, MS);
    assert_eq!(rc, OK);
    unsafe { snts_request_free(r) };
    unsafe { snts_assoc_free(a) };
}

#[test]
fn a_failed_sanity_check_keeps_the_new_cookie() {
    let a = new_assoc();
    let (packet, r) = request(a, 6);
    let req = server_read_request(&C2S, &packet).unwrap();
    let resp = server_response(&S2C, &req, &ServerReply::default());
    // T4 before T1.
    let (rc, _, why) = verify(a, r, &resp, MS, 0);
    assert_eq!((rc, why), (E_SAMPLE, 1 << 16));
    assert_eq!(unsafe { snts_assoc_cookies(a) }, 8);
    unsafe { snts_request_free(r) };

    // A zero reference timestamp: the server clock was never set.
    let (packet, r) = request(a, 7);
    let req = server_read_request(&C2S, &packet).unwrap();
    let resp = server_response(&S2C, &req, &ServerReply { reference: 0, ..ServerReply::default() });
    let (rc, _, why) = verify(a, r, &resp, 0, MS);
    assert_eq!((rc, why), (E_SAMPLE, 5 << 16));
    unsafe { snts_request_free(r) };
    unsafe { snts_assoc_free(a) };
}

#[test]
fn null_pointers() {
    let a = new_assoc();
    let (packet, r) = request(a, 8);
    let mut s = Sample::default();
    let mut why = 0;
    unsafe {
        assert_eq!(snts_ntp_verify(null_mut(), r, packet.as_ptr(), packet.len(), 0, 1, PIVOT, &mut s, &mut why), E_NULL);
        assert_eq!(snts_ntp_verify(a, null_mut(), packet.as_ptr(), packet.len(), 0, 1, PIVOT, &mut s, &mut why), E_NULL);
        assert_eq!(snts_ntp_verify(a, r, null(), 10, 0, 1, PIVOT, &mut s, &mut why), E_NULL);
        assert_eq!(snts_ntp_verify(a, r, packet.as_ptr(), packet.len(), 0, 1, PIVOT, null_mut(), &mut why), E_NULL);
        // The reason pointer may be null.
        assert_eq!(snts_ntp_verify(a, r, packet.as_ptr(), 3, 0, 1, PIVOT, &mut s, null_mut()), E_NTP);
        let rnd = random(1);
        let mut n = 0;
        let mut rr = null_mut();
        assert_eq!(snts_ntp_request(null_mut(), rnd.as_ptr(), rnd.len(), null_mut(), 0, &mut n, &mut rr), E_NULL);
        assert_eq!(snts_ntp_request(a, rnd.as_ptr(), rnd.len(), null_mut(), 1280, &mut n, &mut rr), E_NULL);
        assert_eq!(snts_ntp_request(a, rnd.as_ptr(), rnd.len(), null_mut(), 1280, &mut n, null_mut()), E_NULL);
        assert_eq!(snts_assoc_cookies(a), 7);
        assert_eq!(snts_assoc_cookies(null()), 0);
        snts_request_free(r);
        snts_assoc_free(a);
    }
}

fn interval(op: &str, offset_ns: i64, bound_ns: i64) -> IntervalIn {
    let mut label = [0u8; 32];
    label[..op.len()].copy_from_slice(op.as_bytes());
    IntervalIn { operator_label: label, operator_len: op.len() as u32, offset_ns, bound_ns, t4_local_ns: 0 }
}

#[test]
fn quorum_through_c() {
    let ivs = [interval("cloudflare", 100 * MS, 10 * MS), interval("netnod", 110 * MS, 15 * MS), interval("ptb", 102 * MS, 2 * MS)];
    let mut q = QuorumOut::default();
    let mut why = 0;
    assert_eq!(unsafe { snts_quorum(ivs.as_ptr(), 3, 0, &mut q, &mut why) }, OK);
    assert_eq!((q.lo_ns, q.hi_ns, q.offset_ns, q.bound_ns), (95 * MS, 110 * MS, 102_500_000, 7_500_000));
    let dup = [ivs[0], ivs[1], ivs[0]];
    assert_eq!(unsafe { snts_quorum(dup.as_ptr(), 3, 0, &mut q, &mut why) }, E_QUORUM);
    assert_eq!(cstr(snts_reason_text(E_QUORUM, why)), "two servers of one operator");
    assert_eq!(unsafe { snts_quorum(ivs.as_ptr(), 2, 0, &mut q, &mut why) }, E_QUORUM);
    assert_eq!(why, 1 << 16);
    assert_eq!(unsafe { snts_quorum(ivs.as_ptr(), 17, 0, &mut q, &mut why) }, E_QUORUM);
    assert_eq!(why, 2 << 16);
    let mut bad = ivs;
    bad[2].operator_len = 33;
    assert_eq!(unsafe { snts_quorum(bad.as_ptr(), 3, 0, &mut q, &mut why) }, E_QUORUM);
    assert_eq!(why, 3 << 16);
    assert_eq!(unsafe { snts_quorum(null(), 3, 0, &mut q, &mut why) }, E_NULL);
    assert_eq!(unsafe { snts_quorum(ivs.as_ptr(), 3, 0, null_mut(), &mut why) }, E_NULL);
}

// Go calls C from many threads. Each association is used by one thread at a
// time (Go holds a lock), but different ones run at once.
#[test]
fn associations_on_many_threads() {
    let handles: Vec<_> = (0..8u8)
        .map(|t| {
            std::thread::spawn(move || {
                let a = new_assoc();
                for i in 0..50u8 {
                    let (packet, r) = request(a, t.wrapping_mul(50).wrapping_add(i));
                    let req = server_read_request(&C2S, &packet).unwrap();
                    let (rc, _, _) = verify(a, r, &server_response(&S2C, &req, &ServerReply::default()), 0, MS);
                    assert_eq!(rc, OK);
                    unsafe { snts_request_free(r) };
                }
                unsafe { snts_assoc_free(a) };
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
