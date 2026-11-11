//! Plain NTP (RFC 5905) without NTS: one request and the check and
//! measurement of its response. Nothing authenticates the response; see
//! `signer_nts_core::ntp::PlainRequest`.

use signer_nts_core::ntp::{self, PlainRequest, Response};
use signer_nts_core::time::NtpTimestamp;

use crate::assoc::{Verified, measured};
use crate::code::*;
use crate::{Sample, reason};
use core::ffi::c_int;

/// Random octets a plain request takes: the transmit timestamp.
pub const PLAIN_RANDOM_LEN: usize = 8;

/// Builds a plain request with the random transmit timestamp.
pub fn request(random: &[u8; PLAIN_RANDOM_LEN]) -> ([u8; ntp::HEADER_LEN], PlainRequest) {
    ntp::build_plain_request(NtpTimestamp::from_be_bytes(*random))
}

/// Checks the response to `req` and measures it, as `Association::verify`
/// does for NTS. The sample has no cookie counts.
pub fn verify(
    req: &mut PlainRequest,
    packet: &[u8],
    t1_local_ns: i64,
    t4_local_ns: i64,
    pivot_unix_ns: i64,
) -> Result<Verified, (c_int, u32)> {
    match req.verify_response(packet) {
        Err(e) => Err((E_NTP, reason::ntp(&e))),
        Ok(Response::KissOfDeath(code)) => Ok(Verified::Kiss(Sample { kiss: reason::kiss_octets(code), ..Sample::default() })),
        Ok(Response::Time(s)) => measured(&s, t1_local_ns, t4_local_ns, pivot_unix_ns).map(Verified::Time),
    }
}
