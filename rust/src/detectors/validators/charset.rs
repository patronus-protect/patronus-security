// SPDX-License-Identifier: GPL-3.0-only
//! Alphabets of token encodings and character-class counts.

/// Base62 in the digit-upper-lower order of GitHub/npm checksums.
pub const BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Bitcoin Base58 (no `0`, `O`, `I`, `l`).
pub const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// RFC 4648 section 4 base64.
pub const BASE64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// RFC 4648 section 5 base64url.
pub const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/// RFC 4648 section 6 base32.
pub const BASE32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// BIP 173 data characters in value order.
pub const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const HEX_LOWER: &str = "0123456789abcdef";
pub const HEX_UPPER: &str = "0123456789ABCDEF";

/// Whether `value` is non-empty and every character is in the ASCII `alphabet`.
pub fn in_alphabet(value: &str, alphabet: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| alphabet.as_bytes().contains(&byte))
}

/// Number of characters per class in a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CharClasses {
    pub lower: usize,
    pub upper: usize,
    pub digit: usize,
    /// ASCII punctuation, symbols, whitespace and control characters.
    pub symbol: usize,
    pub non_ascii: usize,
}

impl CharClasses {
    pub fn of(value: &str) -> Self {
        let mut classes = Self::default();
        for ch in value.chars() {
            match ch {
                'a'..='z' => classes.lower += 1,
                'A'..='Z' => classes.upper += 1,
                '0'..='9' => classes.digit += 1,
                _ if ch.is_ascii() => classes.symbol += 1,
                _ => classes.non_ascii += 1,
            }
        }
        classes
    }

    /// Number of classes with at least one character.
    pub fn distinct(&self) -> usize {
        [
            self.lower,
            self.upper,
            self.digit,
            self.symbol,
            self.non_ascii,
        ]
        .iter()
        .filter(|count| **count > 0)
        .count()
    }
}
