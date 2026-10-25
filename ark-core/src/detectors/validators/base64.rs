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

/// Decode `value` only if it is canonical for `kind`: no whitespace, padding
/// exactly where the kind requires it, and zero unused trailing bits, so that
/// re-encoding yields `value` again.
pub fn base64_decode(value: &str, kind: Base64Kind) -> Option<Vec<u8>> {
    let (alphabet, padded) = match kind {
        Base64Kind::Standard => (BASE64, true),
        Base64Kind::StandardUnpadded => (BASE64, false),
        Base64Kind::UrlSafe => (BASE64URL, false),
    };
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
        let value = alphabet.bytes().position(|digit| digit == byte)? as u32;
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
