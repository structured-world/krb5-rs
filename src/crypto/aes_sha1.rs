//! AES-128-CTS-HMAC-SHA1-96 (etype 17) and AES-256-CTS-HMAC-SHA1-96 (etype 18).
//!
//! Both variants share identical logic parameterized by key size,
//! matching MIT's approach where both use the same encrypt/decrypt functions.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::aes_cts::{aes_cts_decrypt, aes_cts_encrypt};
use super::dk::{derive_key, dk};
use super::hmac_sha1::hmac_sha1_96;
use super::util::generate_random;
use super::{CryptoError, EtypeProfile};

const AES_BLOCK: usize = 16;
const HMAC_TRAILER: usize = 12; // HMAC-SHA1-96 = 96 bits

/// AES-128-CTS-HMAC-SHA1-96 (etype 17).
pub struct Aes128CtsHmacSha196;

/// AES-256-CTS-HMAC-SHA1-96 (etype 18).
pub struct Aes256CtsHmacSha196;

// Shared implementation parameterized by key size.
// `expected_key_len` enforces that the key matches the profile (16 for AES-128, 32 for AES-256).
fn aes_encrypt(
    key: &[u8],
    key_usage: i32,
    plaintext: &[u8],
    expected_key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_exact_key_len(key, expected_key_len)?;
    let ke = derive_key(key, key_usage, 0xAA)?;
    let ki = derive_key(key, key_usage, 0x55)?;

    let confounder = generate_random(AES_BLOCK);
    let mut data = Zeroizing::new(Vec::with_capacity(AES_BLOCK + plaintext.len()));
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);

    let hmac = hmac_sha1_96(&ki, &data);
    let mut ct = aes_cts_encrypt(&ke, &data)?;
    ct.extend_from_slice(&hmac);
    Ok(ct)
}

fn aes_decrypt(
    key: &[u8],
    key_usage: i32,
    ciphertext: &[u8],
    expected_key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_exact_key_len(key, expected_key_len)?;
    let ke = derive_key(key, key_usage, 0xAA)?;
    let ki = derive_key(key, key_usage, 0x55)?;

    let ct_len = ciphertext
        .len()
        .checked_sub(HMAC_TRAILER)
        .ok_or(CryptoError::InputTooShort)?;

    if ct_len < AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }

    let (ct, received_hmac) = ciphertext.split_at(ct_len);
    let plain = Zeroizing::new(aes_cts_decrypt(&ke, ct)?);
    let computed_hmac = hmac_sha1_96(&ki, plain.as_slice());

    if !bool::from(computed_hmac.ct_eq(received_hmac)) {
        return Err(CryptoError::IntegrityFailure);
    }

    Ok(plain[AES_BLOCK..].to_vec()) // strip confounder
}

fn aes_string_to_key(
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
    key_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let iter_count = match params {
        Some(p) if p.len() == 4 => {
            let arr: [u8; 4] = p.try_into().map_err(|_| CryptoError::BadParams)?;
            let count = u32::from_be_bytes(arr);
            // RFC 3962: 0x00000000 means 2^32 iterations (sentinel), reject as unsupported
            if count == 0 {
                return Err(CryptoError::BadParams);
            }
            count
        }
        Some(_) => return Err(CryptoError::BadParams),
        None => 4096,
    };

    let mut seed = Zeroizing::new(vec![0u8; key_length]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iter_count, &mut seed);

    let derived = dk(&seed, b"kerberos", key_length, AES_BLOCK)?;
    Ok(Zeroizing::new(derived))
}

/// Strictly enforce that `key.len()` matches the expected length for a profile.
fn validate_exact_key_len(key: &[u8], expected: usize) -> Result<(), CryptoError> {
    if key.len() == expected {
        Ok(())
    } else {
        Err(CryptoError::BadKeySize)
    }
}

fn aes_checksum(
    key: &[u8],
    key_usage: i32,
    data: &[u8],
    expected_key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_exact_key_len(key, expected_key_len)?;
    let kc = derive_key(key, key_usage, 0x99)?;
    Ok(hmac_sha1_96(&kc, data))
}

fn aes_random_to_key(random: &[u8], expected: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if random.len() != expected {
        return Err(CryptoError::BadKeySize);
    }
    Ok(Zeroizing::new(random.to_vec()))
}

impl EtypeProfile for Aes128CtsHmacSha196 {
    fn etype(&self) -> i32 {
        17
    }
    fn key_bytes(&self) -> usize {
        16
    }
    fn key_length(&self) -> usize {
        16
    }
    fn block_size(&self) -> usize {
        AES_BLOCK
    }
    fn confounder_size(&self) -> usize {
        AES_BLOCK
    }
    fn checksum_size(&self) -> usize {
        HMAC_TRAILER
    }
    fn checksum_type(&self) -> i32 {
        15 // hmac-sha1-96-aes128
    }

    fn encrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes_encrypt(key, key_usage, plaintext, self.key_length())
    }

    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes_decrypt(key, key_usage, ciphertext, self.key_length())
    }

    fn string_to_key(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        aes_string_to_key(password, salt, params, 16)
    }

    fn checksum(&self, key: &[u8], key_usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aes_checksum(key, key_usage, data, self.key_length())
    }

    fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        aes_random_to_key(random, 16)
    }
}

impl EtypeProfile for Aes256CtsHmacSha196 {
    fn etype(&self) -> i32 {
        18
    }
    fn key_bytes(&self) -> usize {
        32
    }
    fn key_length(&self) -> usize {
        32
    }
    fn block_size(&self) -> usize {
        AES_BLOCK
    }
    fn confounder_size(&self) -> usize {
        AES_BLOCK
    }
    fn checksum_size(&self) -> usize {
        HMAC_TRAILER
    }
    fn checksum_type(&self) -> i32 {
        16 // hmac-sha1-96-aes256
    }

    fn encrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes_encrypt(key, key_usage, plaintext, self.key_length())
    }

    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes_decrypt(key, key_usage, ciphertext, self.key_length())
    }

    fn string_to_key(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        aes_string_to_key(password, salt, params, 32)
    }

    fn checksum(&self, key: &[u8], key_usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aes_checksum(key, key_usage, data, self.key_length())
    }

    fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        aes_random_to_key(random, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify PBKDF2 works against RFC 6070 test vector
    #[test]
    fn test_pbkdf2_rfc6070() {
        // RFC 6070: P="password", S="salt", c=1, dkLen=20
        let mut out = vec![0u8; 20];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            [
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
            ],
            "PBKDF2 RFC 6070 test vector mismatch"
        );

        // RFC 3962 Test 1: P="password", S="ATHENA.MIT.EDUraeburn", c=1, dkLen=16
        let mut seed = vec![0u8; 16];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"ATHENA.MIT.EDUraeburn", 1, &mut seed);
        // Expected: cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
        assert_eq!(
            seed,
            [
                0xcd, 0xed, 0xb5, 0x28, 0x1b, 0xb2, 0xf8, 0x01, 0x56, 0x5a, 0x11, 0x22, 0xb2, 0x56,
                0x35, 0x15
            ],
            "PBKDF2 RFC 3962 Test 1 mismatch"
        );
    }

    // RFC 3962 Appendix B: AES128 string-to-key test vectors
    #[test]
    fn test_aes128_string_to_key_rfc3962() {
        let etype = Aes128CtsHmacSha196;

        // iter_count=1
        let key = etype
            .string_to_key(
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&1u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0x42, 0x26, 0x3c, 0x6e, 0x89, 0xf4, 0xfc, 0x28, 0xb8, 0xdf, 0x68, 0xee, 0x09, 0x79,
                0x9f, 0x15
            ]
        );

        // iter_count=1200
        let key = etype
            .string_to_key(
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&1200u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0x4c, 0x01, 0xcd, 0x46, 0xd6, 0x32, 0xd0, 0x1e, 0x6d, 0xbe, 0x23, 0x0a, 0x01, 0xed,
                0x64, 0x2a
            ]
        );

        // iter_count=5, password="password", salt=binary 0x1234567878563412
        let key = etype
            .string_to_key(
                b"password",
                &[0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12],
                Some(&5u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0xe9, 0xb2, 0x3d, 0x52, 0x27, 0x37, 0x47, 0xdd, 0x5c, 0x35, 0xcb, 0x55, 0xbe, 0x61,
                0x9d, 0x8e
            ]
        );

        // iter_count=50, UTF-8 "𝄞" (U+1D11E MUSICAL SYMBOL G CLEF)
        let key = etype
            .string_to_key(
                "\u{1D11E}".as_bytes(),
                b"EXAMPLE.COMpianist",
                Some(&50u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0xf1, 0x49, 0xc1, 0xf2, 0xe1, 0x54, 0xa7, 0x34, 0x52, 0xd4, 0x3e, 0x7f, 0xe6, 0x2a,
                0x56, 0xe5
            ]
        );
    }

    // RFC 3962 Appendix B: AES256 string-to-key test vectors
    #[test]
    fn test_aes256_string_to_key_rfc3962() {
        let etype = Aes256CtsHmacSha196;

        // iter_count=1
        let key = etype
            .string_to_key(
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&1u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0xfe, 0x69, 0x7b, 0x52, 0xbc, 0x0d, 0x3c, 0xe1, 0x44, 0x32, 0xba, 0x03, 0x6a, 0x92,
                0xe6, 0x5b, 0xbb, 0x52, 0x28, 0x09, 0x90, 0xa2, 0xfa, 0x27, 0x88, 0x39, 0x98, 0xd7,
                0x2a, 0xf3, 0x01, 0x61
            ]
        );

        // iter_count=1200
        let key = etype
            .string_to_key(
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&1200u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0x55, 0xa6, 0xac, 0x74, 0x0a, 0xd1, 0x7b, 0x48, 0x46, 0x94, 0x10, 0x51, 0xe1, 0xe8,
                0xb0, 0xa7, 0x54, 0x8d, 0x93, 0xb0, 0xab, 0x30, 0xa8, 0xbc, 0x3f, 0xf1, 0x62, 0x80,
                0x38, 0x2b, 0x8c, 0x2a
            ]
        );

        // iter_count=5, password="password", salt=binary 0x1234567878563412
        let key = etype
            .string_to_key(
                b"password",
                &[0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12],
                Some(&5u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0x97, 0xa4, 0xe7, 0x86, 0xbe, 0x20, 0xd8, 0x1a, 0x38, 0x2d, 0x5e, 0xbc, 0x96, 0xd5,
                0x90, 0x9c, 0xab, 0xcd, 0xad, 0xc8, 0x7c, 0xa4, 0x8f, 0x57, 0x45, 0x04, 0x15, 0x9f,
                0x16, 0xc3, 0x6e, 0x31
            ]
        );

        // iter_count=50, "𝄞"
        let key = etype
            .string_to_key(
                "\u{1D11E}".as_bytes(),
                b"EXAMPLE.COMpianist",
                Some(&50u32.to_be_bytes()),
            )
            .expect("s2k");
        assert_eq!(
            key.as_slice(),
            &[
                0x4b, 0x6d, 0x98, 0x39, 0xf8, 0x44, 0x06, 0xdf, 0x1f, 0x09, 0xcc, 0x16, 0x6d, 0xb4,
                0xb8, 0x3c, 0x57, 0x18, 0x48, 0xb7, 0x84, 0xa3, 0xd6, 0xbd, 0xc3, 0x46, 0x58, 0x9a,
                0x3e, 0x39, 0x3f, 0x9e
            ]
        );
    }

    // Default iterations (4096)
    #[test]
    fn test_aes128_string_to_key_default_iterations() {
        let etype = Aes128CtsHmacSha196;
        let key = etype
            .string_to_key(b"password", b"ATHENA.MIT.EDUraeburn", None)
            .expect("s2k");
        assert_eq!(key.len(), 16);
        // Default 4096 should produce a deterministic result
        let key2 = etype
            .string_to_key(b"password", b"ATHENA.MIT.EDUraeburn", None)
            .expect("s2k");
        assert_eq!(*key, *key2);
    }

    // Encrypt/decrypt round-trip for AES-128
    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        let etype = Aes128CtsHmacSha196;
        let key = etype
            .string_to_key(b"testpass", b"EXAMPLE.COMuser", None)
            .expect("s2k");

        for plain in [b"hello".as_slice(), b"", &[0xAB; 256], &[0; 1]] {
            let ct = etype.encrypt(&key, 1, plain).expect("encrypt");
            // ciphertext = confounder(16) + plaintext_padded + hmac(12)
            assert!(
                ct.len() >= 28,
                "ciphertext too short for plain len={}",
                plain.len()
            );
            let dec = etype.decrypt(&key, 1, &ct).expect("decrypt");
            assert_eq!(dec, plain, "roundtrip failed for len={}", plain.len());
        }
    }

    // Encrypt/decrypt round-trip for AES-256
    #[test]
    fn test_aes256_encrypt_decrypt_roundtrip() {
        let etype = Aes256CtsHmacSha196;
        let key = etype
            .string_to_key(b"testpass", b"EXAMPLE.COMuser", None)
            .expect("s2k");

        for plain in [b"hello world".as_slice(), b"", &[0xCD; 500]] {
            let ct = etype.encrypt(&key, 7, plain).expect("encrypt");
            let dec = etype.decrypt(&key, 7, &ct).expect("decrypt");
            assert_eq!(dec, plain);
        }
    }

    // Wrong key should produce IntegrityFailure
    #[test]
    fn test_decrypt_wrong_key_fails() {
        let etype = Aes256CtsHmacSha196;
        let key1 = etype
            .string_to_key(b"correct", b"REALM", None)
            .expect("s2k");
        let key2 = etype.string_to_key(b"wrong", b"REALM", None).expect("s2k");

        let ct = etype.encrypt(&key1, 1, b"secret").expect("encrypt");
        let result = etype.decrypt(&key2, 1, &ct);
        assert!(matches!(result, Err(CryptoError::IntegrityFailure)));
    }

    // Wrong key_usage should produce IntegrityFailure
    #[test]
    fn test_decrypt_wrong_usage_fails() {
        let etype = Aes128CtsHmacSha196;
        let key = etype.string_to_key(b"pass", b"REALM", None).expect("s2k");

        let ct = etype.encrypt(&key, 1, b"data").expect("encrypt");
        let result = etype.decrypt(&key, 2, &ct);
        assert!(matches!(result, Err(CryptoError::IntegrityFailure)));
    }

    // Checksum verification
    #[test]
    fn test_checksum_verify() {
        let etype = Aes256CtsHmacSha196;
        let key = etype.string_to_key(b"pass", b"REALM", None).expect("s2k");

        let cksum = etype.checksum(&key, 15, b"test data").expect("cksum");
        assert_eq!(cksum.len(), 12);

        // Verify should succeed
        etype
            .verify_checksum(&key, 15, b"test data", &cksum)
            .expect("verify");

        // Tampered data should fail
        let result = etype.verify_checksum(&key, 15, b"test datb", &cksum);
        assert!(matches!(result, Err(CryptoError::ChecksumMismatch)));
    }

    // random_to_key
    #[test]
    fn test_random_to_key() {
        let etype128 = Aes128CtsHmacSha196;
        let etype256 = Aes256CtsHmacSha196;

        assert!(etype128.random_to_key(&[0u8; 16]).is_ok());
        assert!(etype128.random_to_key(&[0u8; 15]).is_err());
        assert!(etype256.random_to_key(&[0u8; 32]).is_ok());
        assert!(etype256.random_to_key(&[0u8; 31]).is_err());
    }

    // s2k with bad params
    #[test]
    fn test_string_to_key_bad_params() {
        let etype = Aes128CtsHmacSha196;
        // 3-byte params should fail
        let result = etype.string_to_key(b"pass", b"REALM", Some(&[0, 0, 0]));
        assert!(matches!(result, Err(CryptoError::BadParams)));
    }

    // Zero s2kparams sentinel (RFC 3962: 0x00000000 = 2^32 iterations)
    #[test]
    fn test_string_to_key_zero_params_rejected() {
        let etype = Aes128CtsHmacSha196;
        let result = etype.string_to_key(b"pass", b"REALM", Some(&[0, 0, 0, 0]));
        assert!(matches!(result, Err(CryptoError::BadParams)));
    }

    // Key length validation
    #[test]
    fn test_encrypt_wrong_key_length_rejected() {
        let etype128 = Aes128CtsHmacSha196;
        let etype256 = Aes256CtsHmacSha196;

        // 24-byte key: neither AES-128 nor AES-256
        let bad_key = [0x42u8; 24];
        assert!(matches!(
            etype128.encrypt(&bad_key, 1, b"data"),
            Err(CryptoError::BadKeySize)
        ));

        // 32-byte key with AES-128 profile: must be rejected
        let aes256_key = [0x42u8; 32];
        assert!(matches!(
            etype128.encrypt(&aes256_key, 1, b"data"),
            Err(CryptoError::BadKeySize)
        ));

        // 16-byte key with AES-256 profile: must be rejected
        let aes128_key = [0x42u8; 16];
        assert!(matches!(
            etype256.encrypt(&aes128_key, 1, b"data"),
            Err(CryptoError::BadKeySize)
        ));
    }

    // MIT krb5 known-answer decrypt vectors (t_decrypt.c)
    // Format: {plaintext, key_usage, key, ciphertext} for AES128
    #[test]
    fn test_aes128_decrypt_mit_vectors() {
        let etype = Aes128CtsHmacSha196;

        // Vector 1: empty plaintext, usage=0
        let key = [
            0x5A, 0x5C, 0x0F, 0x0B, 0xA5, 0x4F, 0x38, 0x28, 0xB2, 0x19, 0x5E, 0x66, 0xCA, 0x24,
            0xA2, 0x89,
        ];
        let ct = [
            0x49, 0xFF, 0x8E, 0x11, 0xC1, 0x73, 0xD9, 0x58, 0x3A, 0x32, 0x54, 0xFB, 0xE7, 0xB1,
            0xF1, 0xDF, 0x36, 0xC5, 0x38, 0xE8, 0x41, 0x67, 0x84, 0xA1, 0x67, 0x2E, 0x66, 0x76,
        ];
        let plain = etype.decrypt(&key, 0, &ct).expect("decrypt");
        assert_eq!(plain, b"");

        // Vector 2: "1", usage=1
        let key = [
            0x98, 0x45, 0x0E, 0x3F, 0x3B, 0xAA, 0x13, 0xF5, 0xC9, 0x9B, 0xEB, 0x93, 0x69, 0x81,
            0xB0, 0x6F,
        ];
        let ct = [
            0xF8, 0x67, 0x42, 0xF5, 0x37, 0xB3, 0x5D, 0xC2, 0x17, 0x4A, 0x4D, 0xBA, 0xA9, 0x20,
            0xFA, 0xF9, 0x04, 0x20, 0x90, 0xB0, 0x65, 0xE1, 0xEB, 0xB1, 0xCA, 0xD9, 0xA6, 0x53,
            0x94,
        ];
        let plain = etype.decrypt(&key, 1, &ct).expect("decrypt");
        assert_eq!(plain, b"1");

        // Vector 3: "9 bytesss", usage=2
        let key = [
            0x90, 0x62, 0x43, 0x0C, 0x8C, 0xDA, 0x33, 0x88, 0x92, 0x2E, 0x6D, 0x6A, 0x50, 0x9F,
            0x5B, 0x7A,
        ];
        let ct = [
            0x68, 0xFB, 0x96, 0x79, 0x60, 0x1F, 0x45, 0xC7, 0x88, 0x57, 0xB2, 0xBF, 0x82, 0x0F,
            0xD6, 0xE5, 0x3E, 0xCA, 0x8D, 0x42, 0xFD, 0x4B, 0x1D, 0x70, 0x24, 0xA0, 0x92, 0x05,
            0xAB, 0xB7, 0xCD, 0x2E, 0xC2, 0x6C, 0x35, 0x5D, 0x2F,
        ];
        let plain = etype.decrypt(&key, 2, &ct).expect("decrypt");
        assert_eq!(plain, b"9 bytesss");

        // Vector 4: "13 bytes byte", usage=3
        let key = [
            0x03, 0x3E, 0xE6, 0x50, 0x2C, 0x54, 0xFD, 0x23, 0xE2, 0x77, 0x91, 0xE9, 0x87, 0x98,
            0x38, 0x27,
        ];
        let ct = [
            0xEC, 0x36, 0x6D, 0x03, 0x27, 0xA9, 0x33, 0xBF, 0x49, 0x33, 0x0E, 0x65, 0x0E, 0x49,
            0xBC, 0x6B, 0x97, 0x46, 0x37, 0xFE, 0x80, 0xBF, 0x53, 0x2F, 0xE5, 0x17, 0x95, 0xB4,
            0x80, 0x97, 0x18, 0xE6, 0x19, 0x47, 0x24, 0xDB, 0x94, 0x8D, 0x1F, 0xD6, 0x37,
        ];
        let plain = etype.decrypt(&key, 3, &ct).expect("decrypt");
        assert_eq!(plain, b"13 bytes byte");

        // Vector 5: "30 bytes bytes bytes bytes byt", usage=4
        let key = [
            0xDC, 0xEE, 0xB7, 0x0B, 0x3D, 0xE7, 0x65, 0x62, 0xE6, 0x89, 0x22, 0x6C, 0x76, 0x42,
            0x91, 0x48,
        ];
        let ct = [
            0xC9, 0x60, 0x81, 0x03, 0x2D, 0x5D, 0x8E, 0xEB, 0x7E, 0x32, 0xB4, 0x08, 0x9F, 0x78,
            0x9D, 0x0F, 0xAA, 0x48, 0x1D, 0xEA, 0x74, 0xC0, 0xF9, 0x7C, 0xBF, 0x31, 0x46, 0xDD,
            0xFC, 0xF8, 0xE8, 0x00, 0x15, 0x6E, 0xCB, 0x53, 0x2F, 0xC2, 0x03, 0xE3, 0x0F, 0xF6,
            0x00, 0xB6, 0x3B, 0x35, 0x09, 0x39, 0xFE, 0xCE, 0x51, 0x0F, 0x02, 0xD7, 0xFF, 0x1E,
            0x7B, 0xAC,
        ];
        let plain = etype.decrypt(&key, 4, &ct).expect("decrypt");
        assert_eq!(plain, b"30 bytes bytes bytes bytes byt");
    }

    // MIT krb5 known-answer decrypt vectors for AES-256 (t_decrypt.c)
    #[test]
    fn test_aes256_decrypt_mit_vectors() {
        let etype = Aes256CtsHmacSha196;

        // Vector 1: empty plaintext, usage=0
        let key = [
            0x17, 0xF2, 0x75, 0xF2, 0x95, 0x4F, 0x2E, 0xD1, 0xF9, 0x0C, 0x37, 0x7B, 0xA7, 0xF4,
            0xD6, 0xA3, 0x69, 0xAA, 0x01, 0x36, 0xE0, 0xBF, 0x0C, 0x92, 0x7A, 0xD6, 0x13, 0x3C,
            0x69, 0x37, 0x59, 0xA9,
        ];
        let ct = [
            0xE5, 0x09, 0x4C, 0x55, 0xEE, 0x7B, 0x38, 0x26, 0x2E, 0x2B, 0x04, 0x42, 0x80, 0xB0,
            0x69, 0x37, 0x9A, 0x95, 0xBF, 0x95, 0xBD, 0x83, 0x76, 0xFB, 0x32, 0x81, 0xB4, 0x35,
        ];
        let plain = etype.decrypt(&key, 0, &ct).expect("decrypt");
        assert_eq!(plain, b"");
    }

    // Registry lookup
    #[test]
    fn test_etype_registry() {
        use crate::crypto::find_etype;

        let e17 = find_etype(17).expect("etype 17");
        assert_eq!(e17.etype(), 17);
        assert_eq!(e17.key_length(), 16);

        let e18 = find_etype(18).expect("etype 18");
        assert_eq!(e18.etype(), 18);
        assert_eq!(e18.key_length(), 32);

        assert!(matches!(find_etype(23), Err(CryptoError::UnsupportedEtype)));
    }
}
