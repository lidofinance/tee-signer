//! The two AEAD keys of an NTS association (RFC 8915 section 5.1). Both are
//! wiped when dropped, and `Debug` does not print them.
//!
//! The caller exports each key from the TLS session of NTS-KE (label and
//! context in [`crate::ke`]) and hands the bytes over with `from_slice`. The
//! caller wipes its own copy. Copies the compiler makes on the stack while
//! moving a key are not wiped; the keys are not `Clone`, so the code makes no
//! copies of its own.

use core::fmt;
use zeroize::Zeroize;

/// Key length of AEAD_AES_SIV_CMAC_256: two AES-128 keys, one for S2V (CMAC)
/// and one for CTR (RFC 5297 section 6.1, K_LEN 32 octets).
pub const KEY_LEN: usize = 32;

/// The client-to-server key, C2S (RFC 8915 section 5.1, context octet 0x00).
/// It authenticates our requests (RFC 8915 section 5.6).
pub struct C2sKey([u8; KEY_LEN]);

/// The server-to-client key, S2C (RFC 8915 section 5.1, context octet 0x01).
/// It authenticates and decrypts the server's responses (RFC 8915 section 5.6).
pub struct S2cKey([u8; KEY_LEN]);

impl C2sKey {
    /// The key from exactly [`KEY_LEN`] octets, else `None`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; KEY_LEN]>::try_from(bytes).ok().map(Self)
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl S2cKey {
    /// The key from exactly [`KEY_LEN`] octets, else `None`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; KEY_LEN]>::try_from(bytes).ok().map(Self)
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for C2sKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for S2cKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for C2sKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("C2sKey(..)")
    }
}

impl fmt::Debug for S2cKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("S2cKey(..)")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn only_32_octets_make_a_key() {
        assert!(C2sKey::from_slice(&[7; 31]).is_none());
        assert!(C2sKey::from_slice(&[7; 33]).is_none());
        assert!(S2cKey::from_slice(&[]).is_none());
        assert_eq!(C2sKey::from_slice(&[7; 32]).map(|k| *k.bytes()), Some([7; 32]));
        assert_eq!(S2cKey::from_slice(&[9; 32]).map(|k| *k.bytes()), Some([9; 32]));
    }

    #[test]
    fn debug_does_not_print_the_key() {
        let c = C2sKey::from_slice(&[0xab; 32]).unwrap();
        let s = S2cKey::from_slice(&[0xab; 32]).unwrap();
        assert_eq!(format!("{c:?} {s:?}"), "C2sKey(..) S2cKey(..)");
    }
}
