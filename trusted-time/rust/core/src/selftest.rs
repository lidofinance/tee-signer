//! The AES-SIV-CMAC-256 self-test: RFC 5297 appendix A.1 through the
//! `aes-siv` crate that the NTS packets use. The C wrapper exports it as
//! `snts_aes_siv_selftest`. The tests below add appendix A.2, the
//! nonce-based form that NTS uses.

use aes_siv::KeyInit;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::siv::Aes128Siv;

// RFC 5297 appendix A.1, "Deterministic Authenticated Encryption Example".
// The key is 32 octets: AES-SIV-CMAC-256 is two AES-128 keys.
const KEY: [u8; 32] = [
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];
const HEADER: [u8; 24] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
];
const PLAINTEXT: [u8; 14] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
];
// The output of the RFC: the 16-octet IV, then the ciphertext.
const IV_AND_CIPHERTEXT: [u8; 30] = [
    0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f, 0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
    0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c,
];

/// The step of the self-test that failed. The number is the C return value
/// of `snts_aes_siv_selftest` (see `include/signer_nts.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SelfTestError {
    /// Encryption returned an error.
    EncryptFailed = 1,
    /// The ciphertext differs from the RFC.
    CiphertextDiffers = 2,
    /// Decryption returned an error.
    DecryptFailed = 3,
    /// The plaintext differs from the RFC.
    PlaintextDiffers = 4,
    /// A ciphertext with one flipped bit was accepted.
    TamperedAccepted = 5,
}

/// Runs the RFC 5297 A.1 vector: encrypt, decrypt, and a tampered
/// ciphertext that must be refused.
pub fn aes_siv_selftest() -> Result<(), SelfTestError> {
    use SelfTestError::*;
    let mut siv = Aes128Siv::new(GenericArray::from_slice(&KEY));

    let sealed = siv.encrypt([&HEADER[..]], &PLAINTEXT).map_err(|_| EncryptFailed)?;
    if sealed.as_slice() != IV_AND_CIPHERTEXT {
        return Err(CiphertextDiffers);
    }

    let opened = siv.decrypt([&HEADER[..]], &sealed).map_err(|_| DecryptFailed)?;
    if opened.as_slice() != PLAINTEXT {
        return Err(PlaintextDiffers);
    }

    // A flipped bit in the IV must be refused.
    let mut tampered = sealed;
    if let Some(first) = tampered.first_mut() {
        *first ^= 0x01;
    }
    if siv.decrypt([&HEADER[..]], &tampered).is_ok() {
        return Err(TamperedAccepted);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::siv;
    use aes_siv::Aes128SivAead;
    use aes_siv::aead::{Aead, Payload};

    fn cipher(key: &[u8; 32]) -> Aes128Siv {
        Aes128Siv::new(GenericArray::from_slice(key))
    }

    #[test]
    fn rfc5297_a1_encrypt() {
        let sealed = cipher(&KEY).encrypt([&HEADER[..]], &PLAINTEXT).unwrap();
        assert_eq!(sealed.as_slice(), IV_AND_CIPHERTEXT);
    }

    #[test]
    fn rfc5297_a1_decrypt() {
        let opened = cipher(&KEY).decrypt([&HEADER[..]], &IV_AND_CIPHERTEXT).unwrap();
        assert_eq!(opened.as_slice(), PLAINTEXT);
    }

    #[test]
    fn a_changed_header_or_ciphertext_is_refused() {
        assert!(cipher(&KEY).decrypt([&[0u8; 24][..]], &IV_AND_CIPHERTEXT).is_err());
        let mut tampered = IV_AND_CIPHERTEXT;
        tampered[29] ^= 0x80;
        assert!(cipher(&KEY).decrypt([&HEADER[..]], &tampered).is_err());
    }

    #[test]
    fn selftest_passes() {
        assert_eq!(aes_siv_selftest(), Ok(()));
    }

    // RFC 5297 appendix A.2, "Nonce-Based Authenticated Encryption Example":
    // two associated data strings, then the nonce as the last component.
    // This is the shape NTS uses (one AD string, then the nonce).
    const A2_KEY: [u8; 32] = [
        0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];
    const A2_AD1: [u8; 40] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xda, 0xda, 0xde, 0xad, 0xda, 0xda, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    ];
    const A2_AD2: [u8; 10] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0];
    const A2_NONCE: [u8; 16] = [
        0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b, 0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0,
    ];
    const A2_PLAINTEXT: &[u8] = b"this is some plaintext to encrypt using SIV-AES";
    const A2_OUTPUT: [u8; 63] = [
        0x7b, 0xdb, 0x6e, 0x3b, 0x43, 0x26, 0x67, 0xeb, 0x06, 0xf4, 0xd1, 0x4b, 0xff, 0x2f, 0xbd, 0x0f,
        0xcb, 0x90, 0x0f, 0x2f, 0xdd, 0xbe, 0x40, 0x43, 0x26, 0x60, 0x19, 0x65, 0xc8, 0x89, 0xbf, 0x17,
        0xdb, 0xa7, 0x7c, 0xeb, 0x09, 0x4f, 0xa6, 0x63, 0xb7, 0xa3, 0xf7, 0x48, 0xba, 0x8a, 0xf8, 0x29,
        0xea, 0x64, 0xad, 0x54, 0x4a, 0x27, 0x2e, 0x9c, 0x48, 0x5b, 0x62, 0xa3, 0xfd, 0x5c, 0x0d,
    ];

    #[test]
    fn rfc5297_a2_nonce_based() {
        let headers = [&A2_AD1[..], &A2_AD2[..], &A2_NONCE[..]];
        let sealed = cipher(&A2_KEY).encrypt(headers, A2_PLAINTEXT).unwrap();
        assert_eq!(sealed.as_slice(), A2_OUTPUT);
        let opened = cipher(&A2_KEY).decrypt(headers, &A2_OUTPUT).unwrap();
        assert_eq!(opened.as_slice(), A2_PLAINTEXT);
        // The nonce in another position is another input.
        let swapped = [&A2_AD1[..], &A2_NONCE[..], &A2_AD2[..]];
        assert!(cipher(&A2_KEY).decrypt(swapped, &A2_OUTPUT).is_err());
    }

    // siv::seal passes (A, N) to S2V. The RFC 5116 interface of the crate,
    // which other NTS implementations use, must give the same bytes.
    #[test]
    fn seal_matches_the_rfc5116_interface() {
        let ad = b"ntp header and fields before the authenticator";
        for pt in [&b""[..], &b"\x02\x04\x00\x08abcd"[..]] {
            let ours = siv::seal(&A2_KEY, ad, &A2_NONCE, pt).unwrap();
            let aead = Aes128SivAead::new(GenericArray::from_slice(&A2_KEY));
            let theirs = aead.encrypt(GenericArray::from_slice(&A2_NONCE), Payload { msg: pt, aad: ad }).unwrap();
            assert_eq!(ours, theirs);
            assert_eq!(siv::open(&A2_KEY, ad, &A2_NONCE, &ours).unwrap(), pt);
            assert!(siv::open(&A2_KEY, ad, &A2_NONCE[..15], &ours).is_none());
            assert!(siv::open(&KEY, ad, &A2_NONCE, &ours).is_none());
        }
        assert!(siv::open(&A2_KEY, b"", &A2_NONCE, &[0u8; 15]).is_none());
    }
}
