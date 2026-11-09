// SPDX-License-Identifier: MIT OR Apache-2.0
//! Strict canonical base64 (RFC 4648).

use super::charset::{BASE64, BASE64URL};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64Kind {
    /// Section 4 alphabet with `=` padding to a multiple of four.
    Standard,
    /// Section 4 alphabet without padding (PHC strings, some tokens).
    StandardUnpadded,
    /// Section 5 alphabet without padding (JWS, RFC 7515 section 2).
    UrlSafe,
}

const NO_DIGIT: u32 = 0xff;
static STANDARD_DIGITS: [u8; 256] = digit_table(BASE64);
static URL_DIGITS: [u8; 256] = digit_table(BASE64URL);

/// The value of every byte in `alphabet`, `NO_DIGIT` for the other bytes.
const fn digit_table(alphabet: &str) -> [u8; 256] {
    let mut table = [NO_DIGIT as u8; 256];
    let alphabet = alphabet.as_bytes();
    let mut index = 0;
    while index < alphabet.len() {
        table[alphabet[index] as usize] = index as u8;
        index += 1;
    }
    table
}

/// The 6-bit value of `byte` in the alphabet of `kind`.
pub fn base64_digit(byte: u8, kind: Base64Kind) -> Option<u8> {
    let digits = match kind {
        Base64Kind::Standard | Base64Kind::StandardUnpadded => &STANDARD_DIGITS,
        Base64Kind::UrlSafe => &URL_DIGITS,
    };
    let value = digits[usize::from(byte)];
    (u32::from(value) != NO_DIGIT).then_some(value)
}

/// Decode `value` only if it is canonical for `kind`: no whitespace, padding
/// exactly where the kind requires it, and zero unused trailing bits, so that
/// re-encoding yields `value` again.
pub fn base64_decode(value: &str, kind: Base64Kind) -> Option<Vec<u8>> {
    let padded = kind == Base64Kind::Standard;
    let data = if padded {
        if !value.len().is_multiple_of(4) {
            return None;
        }
        let data = value.trim_end_matches('=');
        if value.len() - data.len() > 2 {
            return None;
        }
        data
    } else {
        value
    };
    // Padded input re-pads exactly the dropped characters; unpadded input
    // only rules out a single trailing character.
    if data.len() % 4 == 1 || (padded && value.len() - data.len() != (4 - data.len() % 4) % 4) {
        return None;
    }
    let mut decoded = Vec::with_capacity(data.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in data.bytes() {
        let value = u32::from(base64_digit(byte, kind)?);
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    (accumulator == 0).then_some(decoded)
}
