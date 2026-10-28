// SPDX-License-Identifier: MIT OR Apache-2.0
//! CRC-32, the CRC32-Base62 suffix of GitHub and npm tokens and the CRC32-hex
//! suffix of Packagist tokens.

use super::charset::{in_alphabet, BASE62, HEX_LOWER};

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

/// Length of a CRC32-hex checksum suffix.
const CRC32_HEX_LENGTH: usize = 8;

/// Whether `token` ends in eight lower-case hex digits that are the CRC-32 of
/// the characters before them (Packagist tokens: prefix, 60 hex characters
/// and the zero-padded CRC32 of both).
pub fn crc32_hex_valid(token: &str) -> bool {
    let Some(split) = token
        .len()
        .checked_sub(CRC32_HEX_LENGTH)
        .filter(|&split| split > 0)
    else {
        return false;
    };
    let Some((payload, checksum)) = token.is_char_boundary(split).then(|| token.split_at(split))
    else {
        return false;
    };
    in_alphabet(checksum, HEX_LOWER) && format!("{:08x}", crc32(payload.as_bytes())) == checksum
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
