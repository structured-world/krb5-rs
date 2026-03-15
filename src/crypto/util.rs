//! Cryptographic utility functions.

use rand::Rng;

/// Generate `len` cryptographically random bytes using the OS CSPRNG.
pub(crate) fn generate_random(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill(&mut buf[..]);
    buf
}
