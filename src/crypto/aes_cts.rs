//! AES-CTS (Ciphertext Stealing, CS3 variant) per RFC 3962.
//!
//! CTS eliminates padding so ciphertext length equals plaintext length.
//! For inputs > 1 block, the last two ciphertext blocks are swapped and
//! the second-to-last is truncated to the actual data length.

use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use super::CryptoError;

const AES_BLOCK: usize = 16;

/// AES-CTS encrypt (CS3 variant). Key must be 16 or 32 bytes.
/// Plaintext must be at least one block (16 bytes).
pub(crate) fn aes_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() < AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }

    // Single block: standard AES-CBC with zero IV
    if plaintext.len() == AES_BLOCK {
        return aes_cbc_encrypt(key, &[0u8; AES_BLOCK], plaintext);
    }

    // Pad to block boundary for CBC processing
    let pad_len = (AES_BLOCK - (plaintext.len() % AES_BLOCK)) % AES_BLOCK;
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len() + pad_len, 0);

    // CBC-encrypt the entire padded plaintext with zero IV
    let cbc_out = aes_cbc_encrypt(key, &[0u8; AES_BLOCK], &padded)?;

    let nblocks = cbc_out.len() / AES_BLOCK;
    let mut result = Vec::with_capacity(plaintext.len());

    // All blocks before the last two pass through unchanged
    if nblocks > 2 {
        result.extend_from_slice(&cbc_out[..(nblocks - 2) * AES_BLOCK]);
    }

    // Swap last two blocks; truncate second-to-last to actual data length
    let second_last = &cbc_out[(nblocks - 2) * AES_BLOCK..(nblocks - 1) * AES_BLOCK];
    let last = &cbc_out[(nblocks - 1) * AES_BLOCK..nblocks * AES_BLOCK];
    let actual_tail_len = plaintext.len() - (nblocks - 1) * AES_BLOCK;

    result.extend_from_slice(last); // C[n-1] goes first (swap)
    result.extend_from_slice(&second_last[..actual_tail_len]); // truncated C[n-2]

    Ok(result)
}

/// AES-CTS decrypt (CS3 variant). Key must be 16 or 32 bytes.
/// Ciphertext must be at least one block (16 bytes).
pub(crate) fn aes_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }

    // Single block: standard AES-CBC decrypt with zero IV
    if ciphertext.len() == AES_BLOCK {
        return aes_cbc_decrypt(key, &[0u8; AES_BLOCK], ciphertext);
    }

    let nblocks = ciphertext.len().div_ceil(AES_BLOCK);
    let tail_len = ciphertext.len() - (nblocks - 1) * AES_BLOCK;

    let mut plaintext = Vec::with_capacity(ciphertext.len());

    // Step 1: CBC-decrypt all blocks before the last two.
    // For nblocks == 2, prev_iv stays zero — correct since CBC IV for the first block is zero.
    let mut prev_iv = [0u8; AES_BLOCK];
    if nblocks > 2 {
        let prefix_end = (nblocks - 2) * AES_BLOCK;
        let prefix_plain = aes_cbc_decrypt(key, &prev_iv, &ciphertext[..prefix_end])?;
        // IV for penultimate block is the last ciphertext block of the prefix
        prev_iv.copy_from_slice(&ciphertext[prefix_end - AES_BLOCK..prefix_end]);
        plaintext.extend_from_slice(&prefix_plain);
    }

    // The input has the last two blocks swapped:
    //   ciphertext[(n-2)*16..(n-1)*16] is actually C[n-1] (full block)
    //   ciphertext[(n-1)*16..] is the partial C[n-2] (tail_len bytes)
    let cn1 = &ciphertext[(nblocks - 2) * AES_BLOCK..(nblocks - 1) * AES_BLOCK];
    let cn2_partial = &ciphertext[(nblocks - 1) * AES_BLOCK..];

    // Step 2: ECB-decrypt C[n-1] to get intermediate value
    let ecb_dec = aes_ecb_decrypt_block(key, cn1)?;

    // Step 3: XOR first tail_len bytes of ECB result with partial C[n-2]
    // to recover final plaintext block
    let mut final_plain_block = vec![0u8; tail_len];
    for i in 0..tail_len {
        final_plain_block[i] = ecb_dec[i] ^ cn2_partial[i];
    }

    // Step 4: Reconstruct complete C[n-2] by appending recovered pad bytes
    let mut cn2_full = cn2_partial.to_vec();
    cn2_full.extend_from_slice(&ecb_dec[tail_len..AES_BLOCK]);

    // Step 5: ECB-decrypt reconstructed C[n-2], XOR with previous IV
    let pen_dec = aes_ecb_decrypt_block(key, &cn2_full)?;
    let mut penultimate_plain = vec![0u8; AES_BLOCK];
    for i in 0..AES_BLOCK {
        penultimate_plain[i] = pen_dec[i] ^ prev_iv[i];
    }

    plaintext.extend_from_slice(&penultimate_plain);
    plaintext.extend_from_slice(&final_plain_block);

    Ok(plaintext)
}

/// AES-ECB encrypt a single block (used in DK key derivation).
pub(crate) fn aes_ecb_encrypt_block(key: &[u8], block: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if block.len() != AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).map_err(|_| CryptoError::BadKeySize)?;
            let mut out =
                Block::<aes::Aes128>::try_from(block).map_err(|_| CryptoError::InputTooShort)?;
            cipher.encrypt_block(&mut out);
            Ok(out.to_vec())
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).map_err(|_| CryptoError::BadKeySize)?;
            let mut out =
                Block::<aes::Aes256>::try_from(block).map_err(|_| CryptoError::InputTooShort)?;
            cipher.encrypt_block(&mut out);
            Ok(out.to_vec())
        }
        _ => Err(CryptoError::BadKeySize),
    }
}

/// AES-CBC encrypt with given IV. Input must be block-aligned.
/// Implemented manually using AES-ECB + XOR (standard CBC construction).
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; AES_BLOCK], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !data.len().is_multiple_of(AES_BLOCK) {
        return Err(CryptoError::InputTooShort);
    }
    let mut result = Vec::with_capacity(data.len());
    let mut prev = *iv;

    for chunk in data.chunks_exact(AES_BLOCK) {
        // XOR plaintext block with previous ciphertext (or IV)
        let mut block = [0u8; AES_BLOCK];
        for i in 0..AES_BLOCK {
            block[i] = chunk[i] ^ prev[i];
        }
        let encrypted = aes_ecb_encrypt_block(key, &block)?;
        prev.copy_from_slice(&encrypted);
        result.extend_from_slice(&encrypted);
    }
    Ok(result)
}

/// AES-CBC decrypt with given IV. Input must be block-aligned.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; AES_BLOCK], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !data.len().is_multiple_of(AES_BLOCK) {
        return Err(CryptoError::InputTooShort);
    }
    let mut result = Vec::with_capacity(data.len());
    let mut prev = *iv;

    for chunk in data.chunks_exact(AES_BLOCK) {
        let decrypted = aes_ecb_decrypt_block(key, chunk)?;
        let mut plain_block = [0u8; AES_BLOCK];
        for i in 0..AES_BLOCK {
            plain_block[i] = decrypted[i] ^ prev[i];
        }
        prev.copy_from_slice(chunk);
        result.extend_from_slice(&plain_block);
    }
    Ok(result)
}

/// AES-ECB decrypt a single block.
fn aes_ecb_decrypt_block(key: &[u8], block: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if block.len() != AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).map_err(|_| CryptoError::BadKeySize)?;
            let mut out =
                Block::<aes::Aes128>::try_from(block).map_err(|_| CryptoError::InputTooShort)?;
            cipher.decrypt_block(&mut out);
            Ok(out.to_vec())
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).map_err(|_| CryptoError::BadKeySize)?;
            let mut out =
                Block::<aes::Aes256>::try_from(block).map_err(|_| CryptoError::InputTooShort)?;
            cipher.decrypt_block(&mut out);
            Ok(out.to_vec())
        }
        _ => Err(CryptoError::BadKeySize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trip tests at various lengths
    #[test]
    fn test_cts_roundtrip_one_block() {
        let key = [0x42u8; 16];
        let plain = [0xABu8; 16];
        let ct = aes_cts_encrypt(&key, &plain).expect("encrypt");
        assert_eq!(ct.len(), 16);
        let dec = aes_cts_decrypt(&key, &ct).expect("decrypt");
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_cts_roundtrip_two_full_blocks() {
        let key = [0x42u8; 32]; // AES-256
        let plain = [0xCDu8; 32];
        let ct = aes_cts_encrypt(&key, &plain).expect("encrypt");
        assert_eq!(ct.len(), 32);
        let dec = aes_cts_decrypt(&key, &ct).expect("decrypt");
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_cts_roundtrip_partial_last_block() {
        let key = [0x11u8; 16];
        // 17 bytes: 1 full block + 1 byte
        let plain: Vec<u8> = (0..17).collect();
        let ct = aes_cts_encrypt(&key, &plain).expect("encrypt");
        assert_eq!(ct.len(), 17);
        let dec = aes_cts_decrypt(&key, &ct).expect("decrypt");
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_cts_roundtrip_various_lengths() {
        let key = [0x55u8; 16];
        for len in [16, 17, 31, 32, 33, 47, 48, 64, 100] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aes_cts_encrypt(&key, &plain).expect("encrypt");
            assert_eq!(ct.len(), len, "ciphertext length mismatch for len={len}");
            let dec = aes_cts_decrypt(&key, &ct).expect("decrypt");
            assert_eq!(dec, plain, "roundtrip failed for len={len}");
        }
    }

    #[test]
    fn test_cts_roundtrip_aes256_various() {
        let key = [0xAAu8; 32];
        for len in [16, 17, 31, 32, 48, 63, 64, 128] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let ct = aes_cts_encrypt(&key, &plain).expect("encrypt");
            assert_eq!(ct.len(), len);
            let dec = aes_cts_decrypt(&key, &ct).expect("decrypt");
            assert_eq!(dec, plain, "roundtrip failed for AES-256 len={len}");
        }
    }

    #[test]
    fn test_cts_too_short() {
        let key = [0u8; 16];
        assert!(aes_cts_encrypt(&key, &[0u8; 15]).is_err());
        assert!(aes_cts_decrypt(&key, &[0u8; 15]).is_err());
    }

    // CBC encrypt/decrypt round-trip
    #[test]
    fn test_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0u8; AES_BLOCK];
        let plain = [0xABu8; 48]; // 3 blocks
        let ct = aes_cbc_encrypt(&key, &iv, &plain).expect("cbc encrypt");
        assert_eq!(ct.len(), 48);
        let dec = aes_cbc_decrypt(&key, &iv, &ct).expect("cbc decrypt");
        assert_eq!(dec, plain);
    }
}
