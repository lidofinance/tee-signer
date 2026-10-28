//! NTS cookies. The server makes them and the client sends each one back
//! once (RFC 8915 sections 4.1.6, 5.4 and 5.7). They are opaque to the client.

use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

/// The longest cookie accepted or sent, in octets (our cap; the RFC sets
/// none). A cookie in the format of RFC 8915 section 6 is about 100 octets.
/// At 1024 octets one cookie with no placeholders still fits in a request of
/// [`crate::ntp::MAX_REQUEST_LEN`] octets.
pub const MAX_COOKIE_LEN: usize = 1024;

/// One cookie, 1 to [`MAX_COOKIE_LEN`] octets. `Debug` shows the length
/// only: a cookie links the requests that carry it to one client
/// (RFC 8915 section 9.1), so it stays out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct Cookie(Vec<u8>);

impl Cookie {
    /// A copy of `bytes` as a cookie, or `None` if it is empty or longer
    /// than [`MAX_COOKIE_LEN`].
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_COOKIE_LEN {
            return None;
        }
        Some(Self(bytes.to_vec()))
    }

    /// The cookie's octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The cookie's length in octets, never 0.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

// A cookie ties requests to one client (RFC 8915 section 9.1), so its
// octets are wiped when it goes away, like the keys.
impl Drop for Cookie {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cookie({} octets)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn length_limits() {
        assert!(Cookie::new(&[]).is_none());
        assert!(Cookie::new(&[1; MAX_COOKIE_LEN + 1]).is_none());
        assert_eq!(Cookie::new(&[1; MAX_COOKIE_LEN]).map(|c| c.len()), Some(MAX_COOKIE_LEN));
        assert_eq!(Cookie::new(&[5]).map(|c| c.as_bytes().to_vec()), Some([5u8].to_vec()));
    }

    #[test]
    fn debug_shows_the_length_only() {
        let c = Cookie::new(&[0xab; 100]).unwrap();
        assert_eq!(format!("{c:?}"), "Cookie(100 octets)");
    }
}
