// SPDX-License-Identifier: GPL-3.0-only
//! CRC-32 and the CRC32-Base62 suffix of GitHub and npm tokens.

use super::charset::{in_alphabet, BASE62};

/// Length of a CRC32-Base62 checksum suffix.
pub const CRC32_BASE62_LENGTH: usize = 6;

/// CRC-32/ISO-HDLC (zlib `crc32`, reflected polynomial `0xEDB88320`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// CRC-32 of `text` as six big-endian base62 digits, left-padded with `0`.
pub fn crc32_base62(text: &str) -> String {
    let mut checksum = crc32(text.as_bytes());
    let mut digits = [b'0'; CRC32_BASE62_LENGTH];
    for digit in digits.iter_mut().rev() {
        *digit = BASE62.as_bytes()[(checksum % 62) as usize];
        checksum /= 62;
    }
    digits.iter().map(|digit| char::from(*digit)).collect()
}

/// Whether the base62 `body` ends in the CRC32-Base62 of the characters before
/// it (GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` and npm `npm_` tokens: the
/// body after the prefix is 30 random characters plus the checksum).
pub fn crc32_base62_valid(body: &str) -> bool {
    if body.len() <= CRC32_BASE62_LENGTH || !in_alphabet(body, BASE62) {
        return false;
    }
    let (payload, checksum) = body.split_at(body.len() - CRC32_BASE62_LENGTH);
    crc32_base62(payload) == checksum
}
