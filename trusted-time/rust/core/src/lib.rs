//! signer-nts-core: the NTS (RFC 8915) client logic of the signer, with no I/O.
//!
//! The crate is `no_std` + `alloc` so the same code can link into an OP-TEE
//! trusted app on the boards. It reads no clock, opens no socket and has no
//! random number generator. The caller moves the bytes over TLS and UDP and
//! passes in every timestamp, nonce and unique ID.
//!
//! - [`ke`]: NTS-KE records (RFC 8915 section 4) and the TLS exporter
//!   values for the two keys (section 5.1).
//! - [`ntp`]: the NTPv4 client request and the check of the server response,
//!   with the NTS extension fields (RFC 8915 section 5, RFC 7822, RFC 5905).
//! - [`keys`]: the C2S and S2C keys, wiped when dropped.
//! - [`cookie`]: the cookies the server hands out (RFC 8915 sections 4.1.6, 5.4).
//! - [`time`]: the NTP timestamp formats with era-safe conversion
//!   (RFC 5905 section 6).
//! - [`sample`]: offset, delay and error bound of one response, with the
//!   RFC 5905 checks that need no earlier state (sections 7.3, 8, 11.2).
//! - [`quorum`]: one time from several operators' servers, one of which may
//!   be wrong.
//! - [`selftest`]: the AES-SIV-CMAC-256 vector of RFC 5297 appendix A.1.
//!
//! Untrusted bytes are read only through checked reads (`bytes::Reader`), and
//! every allocation has a fixed upper bound.

#![no_std]
#![forbid(unsafe_code)]
// clippy is not in the pinned toolchain yet, so these are not checked today.
// They record the rule for when it is: no indexing, unwrap or panic in the
// library code.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

extern crate alloc;

mod bytes;
pub mod cookie;
pub mod ke;
pub mod keys;
pub mod ntp;
pub mod quorum;
pub mod sample;
pub mod selftest;
mod siv;
pub mod time;
