//! AEAD_AES_SIV_CMAC_256 as NTS uses it (RFC 8915 section 5.6).
//!
//! RFC 5297 section 3: in nonce-based use the nonce is the last component of
//! the associated data, right before the plaintext. NTS has one associated
//! data string A and one nonce N, so S2V gets the vector (A, N) and then the
//! plaintext. This is also what the RFC 5116 AEAD interface of the `aes-siv`
//! crate does; a test in `selftest` checks that both give the same bytes.
//!
//! The expanded AES keys and the CMAC state live in the `Siv` value for one
//! call and are wiped when it is dropped (the `zeroize` features of `aes` and
//! `cmac`, turned on in Cargo.toml).

use aes_siv::KeyInit;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::siv::Aes128Siv;
use alloc::vec::Vec;

use crate::keys::KEY_LEN;

/// Length of the synthetic IV that leads the output: 128 bits
/// (RFC 5297 section 2.6). It is also the authentication tag.
pub(crate) const TAG_LEN: usize = 16;

fn cipher(key: &[u8; KEY_LEN]) -> Aes128Siv {
    // A [u8; 32] always has the 32 octets the key type needs.
    Aes128Siv::new(GenericArray::from_slice(key))
}

/// The ciphertext field of RFC 8915 section 5.6: the 16-octet synthetic IV,
/// then the encrypted plaintext. `None` only if the crate refuses the input,
/// which it does for more than 126 associated data components (we pass 2).
pub(crate) fn seal(key: &[u8; KEY_LEN], ad: &[u8], nonce: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    cipher(key).encrypt([ad, nonce], plaintext).ok()
}

/// The plaintext if `ciphertext` (IV, then encrypted data) is authentic for
/// this key, associated data and nonce, else `None`. The tag compare in the
/// crate is constant time.
pub(crate) fn open(key: &[u8; KEY_LEN], ad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    cipher(key).decrypt([ad, nonce], ciphertext).ok()
}
