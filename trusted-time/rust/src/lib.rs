//! signer-nts: the C ABI of the signer's NTS time client, built as
//! `libsigner_nts.a` and linked into the Go runner through cgo.
//!
//! The protocol logic is in `signer-nts-core` (`core/`), a `no_std` +
//! `alloc` crate that can also link into an OP-TEE trusted app. This crate
//! is the `std` side for the runner: handles, buffers and error codes around
//! the core. `include/signer_nts.h` documents every function.
//!
//! The crate holds no socket and no clock and draws no random numbers. Go
//! runs TLS and UDP, reads its monotonic clock and passes in random octets.
//!
//! Panics: the release build has `panic = "abort"` (Cargo.toml), and since
//! Rust 1.81 a panic that reaches an `extern "C"` function aborts as well, so
//! no panic unwinds into Go. There is no `catch_unwind`: an abort is the
//! answer to a bug here, not an error code. The code is written not to panic
//! (checked reads, no indexing of input, no unwrap outside tests).

#![deny(unsafe_code)]

mod assoc;
mod reason;

pub use assoc::{Association, Verified};

use core::ffi::{c_char, c_int};

/// Return codes of the C functions (`SNTS_*` in the header).
pub mod code {
    use core::ffi::c_int;
    /// Done.
    pub const OK: c_int = 0;
    /// `snts_ntp_verify`: the response is a Kiss-o'-Death; no time.
    pub const KISS: c_int = 1;
    /// `snts_ke_response_length`: the message is not complete yet.
    pub const MORE: c_int = 2;
    /// A pointer that must not be null is null.
    pub const E_NULL: c_int = -1;
    /// An output buffer is too small; `*out_len` holds the size needed.
    pub const E_BUFFER: c_int = -2;
    /// An argument is out of range (a key length, the random octets, a direction).
    pub const E_ARG: c_int = -3;
    /// The NTS-KE response is refused; `*reason` says why.
    pub const E_KE: c_int = -4;
    /// The association has no cookie left: run NTS-KE again.
    pub const E_NO_COOKIE: c_int = -5;
    /// The NTP response is refused; `*reason` says why.
    pub const E_NTP: c_int = -6;
    /// The NTP response is authentic but fails an RFC 5905 check; `*reason`.
    pub const E_SAMPLE: c_int = -7;
    /// No quorum; `*reason` says why.
    pub const E_QUORUM: c_int = -8;
}

/// Random octets one NTP request takes: the transmit timestamp (8), the
/// Unique Identifier (32, RFC 8915 section 5.3) and the AEAD nonce (16,
/// section 5.6).
pub const REQUEST_RANDOM_LEN: usize = 8 + signer_nts_core::ntp::UNIQUE_ID_LEN + signer_nts_core::ntp::NONCE_LEN;

/// One measurement, `snts_sample` in the header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub offset_ns: i64,
    pub delay_ns: i64,
    pub bound_ns: i64,
    pub t4_local_ns: i64,
    pub root_delay_ns: i64,
    pub root_dispersion_ns: i64,
    pub cookies_received: u32,
    pub cookies_held: u32,
    pub precision: i32,
    pub stratum: u8,
    pub leap: u8,
    pub kiss: [u8; 4],
}

/// One server's interval for the quorum, `snts_interval` in the header.
/// The label is inline, so Go can pass an array of these without pointers.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntervalIn {
    pub operator_label: [u8; signer_nts_core::quorum::MAX_OPERATOR_LEN],
    pub operator_len: u32,
    pub offset_ns: i64,
    pub bound_ns: i64,
    pub t4_local_ns: i64,
}

/// The quorum's answer, `snts_quorum_result` in the header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuorumOut {
    pub offset_ns: i64,
    pub bound_ns: i64,
    pub lo_ns: i64,
    pub hi_ns: i64,
}

/// The quorum over C intervals: checks the labels and calls the core.
pub fn quorum(input: &[IntervalIn], now_local_ns: i64) -> Result<QuorumOut, signer_nts_core::quorum::QuorumError> {
    use signer_nts_core::quorum::{Interval, QuorumError, combine};
    let mut v = Vec::with_capacity(input.len());
    for i in input {
        let len = usize::try_from(i.operator_len).map_err(|_| QuorumError::BadOperator)?;
        let operator = i.operator_label.get(..len).ok_or(QuorumError::BadOperator)?;
        v.push(Interval { operator, offset_ns: i.offset_ns, bound_ns: i.bound_ns, t4_local_ns: i.t4_local_ns });
    }
    let r = combine(&v, now_local_ns)?;
    Ok(QuorumOut { offset_ns: r.offset_ns, bound_ns: r.bound_ns, lo_ns: r.lo_ns, hi_ns: r.hi_ns })
}

// The C ABI. Raw pointers and `no_mangle` are the reasons for unsafe code
// here. Every function checks its pointers for null and its lengths before
// it makes a slice.
#[allow(unsafe_code)]
mod ffi {
    use super::code::*;
    use super::*;
    use signer_nts_core::ke;
    use signer_nts_core::ntp::PendingRequest;
    use signer_nts_core::quorum::{MAX_SERVERS, QuorumError};
    use signer_nts_core::selftest::aes_siv_selftest;

    /// `snts_assoc` in C.
    pub struct SntsAssoc(pub(crate) Association);
    /// `snts_request` in C.
    pub struct SntsRequest(pub(crate) PendingRequest);

    /// `len` octets at `p`; null is fine for 0 octets.
    unsafe fn input<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        if p.is_null() || len > isize::MAX as usize {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(p, len) })
    }

    /// Writes the length of `data` to `out_len` and copies `data` to `out`
    /// (capacity `cap`). E_BUFFER, with the length written, if it does not fit.
    unsafe fn output(data: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> c_int {
        if out_len.is_null() {
            return E_NULL;
        }
        unsafe { out_len.write(data.len()) };
        if data.len() > cap {
            return E_BUFFER;
        }
        if data.is_empty() {
            return OK;
        }
        if out.is_null() {
            return E_NULL;
        }
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
        OK
    }

    /// Writes `v` to `p` unless `p` is null.
    unsafe fn put<T>(p: *mut T, v: T) {
        if !p.is_null() {
            unsafe { p.write(v) };
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn snts_version() -> *const c_char {
        concat!("signer-nts ", env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast::<c_char>()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn snts_aes_siv_selftest() -> c_int {
        match aes_siv_selftest() {
            Ok(()) => 0,
            Err(step) => step as c_int,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn snts_reason_text(code: c_int, reason: u32) -> *const c_char {
        reason::text(code, reason).as_ptr()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn snts_ke_alpn() -> *const c_char {
        reason::ALPN.as_ptr()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn snts_ke_exporter_label() -> *const c_char {
        reason::EXPORTER_LABEL.as_ptr()
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_ke_exporter_context(
        direction: c_int,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> c_int {
        let d = match direction {
            0 => ke::KeyDirection::ClientToServer,
            1 => ke::KeyDirection::ServerToClient,
            _ => return E_ARG,
        };
        unsafe { output(&ke::exporter_context(d), out, cap, out_len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_ke_request(out: *mut u8, cap: usize, out_len: *mut usize) -> c_int {
        unsafe { output(&ke::build_request(), out, cap, out_len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_ke_response_length(
        buf: *const u8,
        len: usize,
        out_len: *mut usize,
        reason: *mut u32,
    ) -> c_int {
        let Some(buf) = (unsafe { input(buf, len) }) else { return E_NULL };
        if out_len.is_null() {
            return E_NULL;
        }
        match ke::response_length(buf) {
            Ok(Some(n)) => {
                unsafe { out_len.write(n) };
                OK
            }
            Ok(None) => MORE,
            Err(e) => {
                unsafe { put(reason, reason::ke(&e)) };
                E_KE
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_assoc_new(
        response: *const u8,
        response_len: usize,
        c2s: *const u8,
        c2s_len: usize,
        s2c: *const u8,
        s2c_len: usize,
        out: *mut *mut SntsAssoc,
        reason: *mut u32,
    ) -> c_int {
        let (Some(resp), Some(c2s), Some(s2c)) =
            (unsafe { input(response, response_len) }, unsafe { input(c2s, c2s_len) }, unsafe { input(s2c, s2c_len) })
        else {
            return E_NULL;
        };
        if out.is_null() {
            return E_NULL;
        }
        match Association::new(resp, c2s, s2c) {
            Ok(a) => {
                unsafe { out.write(Box::into_raw(Box::new(SntsAssoc(a)))) };
                OK
            }
            Err((code, why)) => {
                unsafe { put(reason, why) };
                code
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_assoc_free(a: *mut SntsAssoc) {
        if !a.is_null() {
            drop(unsafe { Box::from_raw(a) });
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_assoc_cookies(a: *const SntsAssoc) -> usize {
        unsafe { a.as_ref() }.map_or(0, |a| a.0.cookies())
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_assoc_port(a: *const SntsAssoc) -> u16 {
        unsafe { a.as_ref() }.map_or(0, |a| a.0.port())
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_assoc_server(
        a: *const SntsAssoc,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> c_int {
        let Some(a) = (unsafe { a.as_ref() }) else { return E_NULL };
        unsafe { output(a.0.server().unwrap_or("").as_bytes(), out, cap, out_len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_ntp_request(
        a: *mut SntsAssoc,
        random: *const u8,
        random_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
        req: *mut *mut SntsRequest,
    ) -> c_int {
        let Some(a) = (unsafe { a.as_mut() }) else { return E_NULL };
        let Some(random) = (unsafe { input(random, random_len) }) else { return E_NULL };
        if out_len.is_null() || req.is_null() {
            return E_NULL;
        }
        let Ok(random) = <&[u8; REQUEST_RANDOM_LEN]>::try_from(random) else { return E_ARG };
        // The length first, so a short buffer does not use up a cookie.
        let Some(needed) = a.0.request_len() else { return E_NO_COOKIE };
        unsafe { out_len.write(needed) };
        if needed > cap {
            return E_BUFFER;
        }
        if out.is_null() {
            return E_NULL;
        }
        match a.0.request(random) {
            Ok((packet, pending)) => {
                let rc = unsafe { output(&packet, out, cap, out_len) };
                if rc == OK {
                    unsafe { req.write(Box::into_raw(Box::new(SntsRequest(pending)))) };
                }
                rc
            }
            Err(code) => code,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_request_free(r: *mut SntsRequest) {
        if !r.is_null() {
            drop(unsafe { Box::from_raw(r) });
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_ntp_verify(
        a: *mut SntsAssoc,
        r: *mut SntsRequest,
        packet: *const u8,
        packet_len: usize,
        t1_local_ns: i64,
        t4_local_ns: i64,
        pivot_unix_ns: i64,
        out: *mut Sample,
        reason: *mut u32,
    ) -> c_int {
        let (Some(a), Some(r)) = (unsafe { a.as_mut() }, unsafe { r.as_mut() }) else { return E_NULL };
        let Some(packet) = (unsafe { input(packet, packet_len) }) else { return E_NULL };
        if out.is_null() {
            return E_NULL;
        }
        match a.0.verify(&mut r.0, packet, t1_local_ns, t4_local_ns, pivot_unix_ns) {
            Ok(Verified::Time(s)) => {
                unsafe { out.write(s) };
                OK
            }
            Ok(Verified::Kiss(s)) => {
                unsafe { out.write(s) };
                KISS
            }
            Err((code, why)) => {
                unsafe { put(reason, why) };
                code
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn snts_quorum(
        intervals: *const IntervalIn,
        n: usize,
        now_local_ns: i64,
        out: *mut QuorumOut,
        reason: *mut u32,
    ) -> c_int {
        if out.is_null() || (n > 0 && intervals.is_null()) {
            return E_NULL;
        }
        if n > MAX_SERVERS {
            unsafe { put(reason, reason::quorum(&QuorumError::TooMany)) };
            return E_QUORUM;
        }
        let input: &[IntervalIn] = if n == 0 { &[] } else { unsafe { std::slice::from_raw_parts(intervals, n) } };
        match quorum(input, now_local_ns) {
            Ok(q) => {
                unsafe { out.write(q) };
                OK
            }
            Err(e) => {
                unsafe { put(reason, reason::quorum(&e)) };
                E_QUORUM
            }
        }
    }
}

#[cfg(test)]
mod tests;
