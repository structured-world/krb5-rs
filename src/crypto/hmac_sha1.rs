//! HMAC-SHA1-96 computation for AES-CTS-HMAC-SHA1-96 etypes.
//!
//! Computes full HMAC-SHA1 (20 bytes) and truncates to 96 bits (12 bytes).

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Compute HMAC-SHA1-96: full HMAC-SHA1 truncated to 12 bytes.
pub(crate) fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    result[..12].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha1_96_output_length() {
        let key = [0x0Bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha1_96(&key, data);
        assert_eq!(result.len(), 12);
    }

    #[test]
    fn test_hmac_sha1_96_deterministic() {
        let key = [0xAAu8; 16];
        let data = b"test data";
        let r1 = hmac_sha1_96(&key, data);
        let r2 = hmac_sha1_96(&key, data);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hmac_sha1_96_different_keys() {
        let data = b"same data";
        let r1 = hmac_sha1_96(&[0x01u8; 16], data);
        let r2 = hmac_sha1_96(&[0x02u8; 16], data);
        assert_ne!(r1, r2);
    }
}
