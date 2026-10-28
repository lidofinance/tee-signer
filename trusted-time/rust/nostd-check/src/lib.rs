//! Build check, never linked or run: signer-nts-core inside a `no_std`
//! static library, built for the same Linux targets as the runner.
//!
//! The pinned toolchain has no bare-metal target (adding one is a
//! download), so this is the nearest check without one. If any crate in the
//! core's graph linked the standard library, std's panic handler would clash
//! with the one below (error E0152, duplicate lang item `panic_impl`) and
//! the build would fail. `scripts/build-nts.sh` also lists the symbols the
//! archive leaves undefined: what a trusted app would have to provide.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::hint::black_box;
use core::panic::PanicInfo;

use signer_nts_core::cookie::Cookie;
use signer_nts_core::keys::{C2sKey, S2cKey};
use signer_nts_core::ntp::{self, RequestInput, Response};
use signer_nts_core::quorum::{self, Interval};
use signer_nts_core::sample;
use signer_nts_core::time::NtpTimestamp;
use signer_nts_core::{ke, selftest};

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

// The heap of the environment, as a trusted app would have it (OP-TEE's
// libutils has malloc and free). The archive is never linked, so these stay
// undefined and show up in undefined.txt. An allocator that always returned
// null would let the optimizer drop every path that allocates, and the
// archive would no longer hold the core's code.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}

struct ExternAlloc;

unsafe impl GlobalAlloc for ExternAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // malloc aligns to 16 octets at most.
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        unsafe { malloc(layout.size()) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        unsafe { free(ptr) }
    }
}

#[global_allocator]
static ALLOCATOR: ExternAlloc = ExternAlloc;

/// Calls every entry point of the core, so their code is in the archive.
#[unsafe(no_mangle)]
pub extern "C" fn snts_nostd_check(x: u8) -> i32 {
    let buf = black_box([x; 128]);
    let mut n = 0;
    if selftest::aes_siv_selftest().is_ok() {
        n += 1;
    }
    if ke::parse_response(&buf).is_ok() || ke::response_length(&buf).is_ok() {
        n += 2;
    }
    if black_box(ke::build_request())[0] == x {
        n += 4;
    }
    let (Some(c2s), Some(s2c), Some(cookie)) =
        (C2sKey::from_slice(&buf[..32]), S2cKey::from_slice(&buf[32..64]), Cookie::new(&buf[..100]))
    else {
        return n;
    };
    let input = RequestInput {
        transmit: NtpTimestamp::from_unix_nanos(i64::from(x)),
        unique_id: [x; ntp::UNIQUE_ID_LEN],
        nonce: [x; ntp::NONCE_LEN],
        cookie: &cookie,
        placeholders: ntp::max_placeholders(&cookie),
    };
    if let Ok((packet, mut pending)) = ntp::build_request(&c2s, &input) {
        if let Ok(Response::Time(s)) = pending.verify_response(&s2c, black_box(&packet)) {
            n += 8;
            if let Ok(m) = sample::measure(&s, black_box(0), black_box(i64::from(x)), 0) {
                let iv = |op: &'static [u8]| Interval {
                    operator: op,
                    offset_ns: m.offset_ns,
                    bound_ns: m.bound_ns,
                    t4_local_ns: m.t4_local_ns,
                };
                if quorum::combine(&[iv(b"a"), iv(b"b"), iv(b"c")], black_box(i64::from(x))).is_ok() {
                    n += 16;
                }
            }
        }
        if let Some(t) = pending.transmit().to_unix_nanos(0) {
            n += (t & 1) as i32;
        }
    }
    n
}
