//! Kerberos encryption and checksum framework (RFC 3961).
//!
//! Provides pluggable encryption type profiles behind the [`EtypeProfile`] trait,
//! with a global registry for runtime lookup by etype number.

mod aes_cts;
mod aes_sha1;
mod dk;
mod hmac_sha1;
mod nfold;
mod util;

pub use aes_sha1::{Aes128CtsHmacSha196, Aes256CtsHmacSha196};

use std::collections::HashMap;
use std::sync::LazyLock;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Standard Kerberos key usage values (RFC 4120).
pub mod key_usage {
    /// Client pre-auth encrypted timestamp.
    pub const PA_ENC_TIMESTAMP: i32 = 1;
    /// Ticket encrypted part (KDC uses service key).
    pub const TICKET: i32 = 2;
    /// AS-REP encrypted part (client's key).
    pub const AS_REP_ENCPART: i32 = 3;
    /// TGS-REQ authenticator checksum (session key).
    pub const TGS_REQ_AUTH_CKSUM: i32 = 6;
    /// TGS-REQ authenticator (encrypted with session key).
    pub const TGS_REQ_AUTH: i32 = 7;
    /// TGS-REP enc-part (session key -- Heimdal compat).
    pub const TGS_REP_ENCPART_SESSKEY: i32 = 8;
    /// TGS-REP enc-part (subkey -- preferred).
    pub const TGS_REP_ENCPART_SUBKEY: i32 = 9;
    /// AP-REQ authenticator checksum.
    pub const AP_REQ_AUTH_CKSUM: i32 = 10;
    /// AP-REQ authenticator.
    pub const AP_REQ_AUTH: i32 = 11;
    /// AP-REP encrypted part.
    pub const AP_REP_ENCPART: i32 = 12;
    /// KRB-PRIV encrypted part.
    pub const KRB_PRIV_ENCPART: i32 = 13;
    /// KRB-CRED encrypted part.
    pub const KRB_CRED_ENCPART: i32 = 14;
    /// KRB-SAFE checksum.
    pub const KRB_SAFE_CKSUM: i32 = 15;
}

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Integrity check (HMAC) failed during decryption.
    #[error("integrity check failed")]
    IntegrityFailure,

    /// Input too short for the expected operation.
    #[error("input too short for decryption")]
    InputTooShort,

    /// Key size does not match the expected length.
    #[error("invalid key size")]
    BadKeySize,

    /// Invalid string-to-key parameters.
    #[error("invalid string-to-key parameters")]
    BadParams,

    /// Checksum verification failed.
    #[error("checksum mismatch")]
    ChecksumMismatch,

    /// Requested encryption type is not supported/registered.
    #[error("unsupported encryption type")]
    UnsupportedEtype,
}

/// A complete RFC 3961 encryption type profile.
///
/// Each implementation bundles a cipher, checksum algorithm, and
/// string-to-key function into a single coherent profile.
pub trait EtypeProfile: Send + Sync {
    /// The etype number (e.g., 17 for AES128, 18 for AES256).
    fn etype(&self) -> i32;

    /// Key size in bytes (input to `random_to_key`).
    fn key_bytes(&self) -> usize;

    /// Actual protocol key length in bytes.
    fn key_length(&self) -> usize;

    /// Block size of the underlying cipher.
    fn block_size(&self) -> usize;

    /// Size of the confounder prepended to plaintext.
    fn confounder_size(&self) -> usize;

    /// Size of the integrity checksum appended to ciphertext.
    fn checksum_size(&self) -> usize;

    /// The mandatory checksum type number for this etype (RFC 3961 §6.2).
    ///
    /// For AES128: `hmac-sha1-96-aes128` (15).
    /// For AES256: `hmac-sha1-96-aes256` (16).
    fn checksum_type(&self) -> i32;

    /// Encrypt plaintext with the given key and key usage number.
    fn encrypt(&self, key: &[u8], key_usage: i32, plaintext: &[u8])
        -> Result<Vec<u8>, CryptoError>;

    /// Decrypt ciphertext with the given key and key usage number.
    /// Verifies integrity and strips confounder.
    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Derive an encryption key from a password and salt.
    fn string_to_key(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Compute a keyed checksum over data.
    fn checksum(&self, key: &[u8], key_usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Verify a keyed checksum using constant-time comparison.
    fn verify_checksum(
        &self,
        key: &[u8],
        key_usage: i32,
        data: &[u8],
        checksum: &[u8],
    ) -> Result<(), CryptoError> {
        let computed = self.checksum(key, key_usage, data)?;
        if bool::from(computed.ct_eq(checksum)) {
            Ok(())
        } else {
            Err(CryptoError::ChecksumMismatch)
        }
    }

    /// Convert random bytes to a protocol key.
    fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// Registry of available encryption types.
pub static ETYPE_REGISTRY: LazyLock<HashMap<i32, &'static dyn EtypeProfile>> =
    LazyLock::new(|| {
        let aes128 = &Aes128CtsHmacSha196 as &dyn EtypeProfile;
        let aes256 = &Aes256CtsHmacSha196 as &dyn EtypeProfile;
        HashMap::from([(aes128.etype(), aes128), (aes256.etype(), aes256)])
    });

/// Look up an etype implementation by number.
pub fn find_etype(etype: i32) -> Result<&'static dyn EtypeProfile, CryptoError> {
    ETYPE_REGISTRY
        .get(&etype)
        .copied()
        .ok_or(CryptoError::UnsupportedEtype)
}
