//! RFC 3961 DK (Derive Key) function and sub-key derivation helpers.

use zeroize::Zeroizing;

use super::aes_cts::aes_ecb_encrypt_block;
use super::nfold::nfold;
use super::CryptoError;

const AES_BLOCK: usize = 16;

/// RFC 3961 DK: derive a protocol key from a base key and a constant.
///
/// 1. Fold the constant to `block_size` bytes using n-fold.
/// 2. Repeatedly AES-ECB encrypt until `key_size` bytes are collected.
///    Each iteration feeds the output back as input (effectively CBC with
///    zero IV where each block's plaintext is the previous ciphertext).
pub(crate) fn dk(
    base_key: &[u8],
    constant: &[u8],
    key_size: usize,
    block_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    if constant.is_empty() || block_size == 0 || key_size == 0 {
        return Err(CryptoError::BadParams);
    }
    let mut block = nfold(constant, block_size);
    let mut result = Vec::with_capacity(key_size);

    while result.len() < key_size {
        block = aes_ecb_encrypt_block(base_key, &block)?;
        result.extend_from_slice(&block);
    }
    result.truncate(key_size);
    Ok(result)
}

/// Derive a sub-key (Ke, Ki, or Kc) from a base key and key usage number.
///
/// The constant is `key_usage` (4 bytes big-endian) || `derivation_byte`:
/// - `0xAA` -> encryption sub-key (Ke)
/// - `0x55` -> integrity sub-key (Ki)
/// - `0x99` -> checksum sub-key (Kc)
///
/// Negative key usage values are not supported and will cause a panic.
pub(crate) fn derive_key(
    base_key: &[u8],
    key_usage: i32,
    derivation_byte: u8,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    assert!(
        key_usage >= 0,
        "negative key_usage ({key_usage}) is not supported",
    );
    let mut constant = (key_usage as u32).to_be_bytes().to_vec();
    constant.push(derivation_byte);
    let key_size = base_key.len();
    dk(base_key, &constant, key_size, AES_BLOCK).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test DK with known n-fold constant "kerberos" — used in string-to-key
    #[test]
    fn test_dk_produces_deterministic_output() {
        // Using a known 16-byte key and "kerberos" constant
        let key = [0x42u8; 16];
        let result = dk(&key, b"kerberos", 16, 16).expect("dk");
        assert_eq!(result.len(), 16);

        // Same input → same output
        let result2 = dk(&key, b"kerberos", 16, 16).expect("dk");
        assert_eq!(result, result2);
    }

    #[test]
    fn test_dk_aes256_key_size() {
        let key = [0x42u8; 32];
        let result = dk(&key, b"kerberos", 32, 16).expect("dk");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_derive_key_ke_ki_kc_differ() {
        let key = [0x11u8; 16];
        let ke = derive_key(&key, 1, 0xAA).expect("Ke");
        let ki = derive_key(&key, 1, 0x55).expect("Ki");
        let kc = derive_key(&key, 1, 0x99).expect("Kc");

        // All three sub-keys must differ
        assert_ne!(*ke, *ki);
        assert_ne!(*ke, *kc);
        assert_ne!(*ki, *kc);
    }

    #[test]
    fn test_derive_key_different_usages() {
        let key = [0x22u8; 16];
        let k1 = derive_key(&key, 1, 0xAA).expect("usage 1");
        let k2 = derive_key(&key, 2, 0xAA).expect("usage 2");
        assert_ne!(*k1, *k2);
    }
}
