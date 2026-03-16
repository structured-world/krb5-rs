//! RFC 3961 n-fold algorithm.
//!
//! Folds an arbitrary-length input to exactly `out_len` bytes by cyclically
//! rotating the input by 13 bits and summing copies with one's-complement
//! (end-around carry) addition.

/// Fold `input` to exactly `out_len` bytes per RFC 3961 section 5.1.
pub(crate) fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    let in_len = input.len();
    let lcm = lcm(in_len, out_len);
    let copies = lcm / in_len;

    // Generate all 13-bit-rotated copies concatenated
    let mut series = Vec::with_capacity(lcm);
    for i in 0..copies {
        let rotated = rotate_right_bits(input, 13 * i);
        series.extend_from_slice(&rotated);
    }

    // Split into out_len-sized chunks and sum with 1's complement addition
    let mut result: Vec<u16> = vec![0; out_len];
    for chunk_start in (0..series.len()).step_by(out_len) {
        for j in 0..out_len {
            result[j] += series[chunk_start + j] as u16;
        }
    }

    // Propagate carry (one's complement: carry wraps around to LSB position)
    loop {
        let has_carry = result.iter().any(|&x| x > 0xff);
        if !has_carry {
            break;
        }
        let mut next = vec![0u16; out_len];
        for i in 0..out_len {
            // Carry from the byte to our right (big-endian: right-to-left)
            let carry_from = (i + 1) % out_len;
            next[i] = (result[carry_from] >> 8) + (result[i] & 0xff);
        }
        result = next;
    }

    result.iter().map(|&x| x as u8).collect()
}

/// Rotate `data` right by `nbits` bits (cyclic, bit-level).
fn rotate_right_bits(data: &[u8], nbits: usize) -> Vec<u8> {
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let byte_shift = (nbits / 8) % len;
    let bit_shift = nbits % 8;

    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        // Index of the byte that contributes the high bits
        let idx_a = (i + len - byte_shift) % len;
        // Index of the byte that contributes the low bits (one position before)
        let idx_b = (i + len - byte_shift + len - 1) % len;

        let val = ((data[idx_a] as u16) >> bit_shift) | ((data[idx_b] as u16) << (8 - bit_shift));
        out.push(val as u8);
    }
    out
}

/// Least common multiple via GCD.
fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 3961 test vectors + MIT krb5 test vectors
    #[test]
    fn test_nfold_rfc3961_vectors() {
        assert_eq!(
            nfold(b"012345", 8),
            [0xbe, 0x07, 0x26, 0x31, 0x27, 0x6b, 0x19, 0x55]
        );

        assert_eq!(
            nfold(b"password", 7),
            [0x78, 0xa0, 0x7b, 0x6c, 0xaf, 0x85, 0xfa]
        );

        assert_eq!(
            nfold(b"Rough Consensus, and Running Code", 8),
            [0xbb, 0x6e, 0xd3, 0x08, 0x70, 0xb7, 0xf0, 0xe0]
        );

        assert_eq!(
            nfold(b"password", 21),
            [
                0x59, 0xe4, 0xa8, 0xca, 0x7c, 0x03, 0x85, 0xc3, 0xc3, 0x7b, 0x3f, 0x6d, 0x20, 0x00,
                0x24, 0x7c, 0xb6, 0xe6, 0xbd, 0x5b, 0x3e
            ]
        );

        assert_eq!(
            nfold(b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 24),
            [
                0xdb, 0x3b, 0x0d, 0x8f, 0x0b, 0x06, 0x1e, 0x60, 0x32, 0x82, 0xb3, 0x08, 0xa5, 0x08,
                0x41, 0x22, 0x9a, 0xd7, 0x98, 0xfa, 0xb9, 0x54, 0x0c, 0x1b
            ]
        );

        assert_eq!(
            nfold(b"Q", 21),
            [
                0x51, 0x8a, 0x54, 0xa2, 0x15, 0xa8, 0x45, 0x2a, 0x51, 0x8a, 0x54, 0xa2, 0x15, 0xa8,
                0x45, 0x2a, 0x51, 0x8a, 0x54, 0xa2, 0x15
            ]
        );

        assert_eq!(
            nfold(b"ba", 21),
            [
                0xfb, 0x25, 0xd5, 0x31, 0xae, 0x89, 0x74, 0x49, 0x9f, 0x52, 0xfd, 0x92, 0xea, 0x98,
                0x57, 0xc4, 0xba, 0x24, 0xcf, 0x29, 0x7e
            ]
        );
    }

    #[test]
    fn test_nfold_kerberos_constant() {
        // "kerberos" folded to various sizes — used in string-to-key
        assert_eq!(
            nfold(b"kerberos", 8),
            [0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73]
        );

        assert_eq!(
            nfold(b"kerberos", 16),
            [
                0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x7b, 0x9b, 0x5b, 0x2b, 0x93, 0x13,
                0x2b, 0x93
            ]
        );

        assert_eq!(
            nfold(b"kerberos", 21),
            [
                0x83, 0x72, 0xc2, 0x36, 0x34, 0x4e, 0x5f, 0x15, 0x50, 0xcd, 0x07, 0x47, 0xe1, 0x5d,
                0x62, 0xca, 0x7a, 0x5a, 0x3b, 0xce, 0xa4
            ]
        );

        assert_eq!(
            nfold(b"kerberos", 32),
            [
                0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x7b, 0x9b, 0x5b, 0x2b, 0x93, 0x13,
                0x2b, 0x93, 0x5c, 0x9b, 0xdc, 0xda, 0xd9, 0x5c, 0x98, 0x99, 0xc4, 0xca, 0xe4, 0xde,
                0xe6, 0xd6, 0xca, 0xe4
            ]
        );
    }
}
