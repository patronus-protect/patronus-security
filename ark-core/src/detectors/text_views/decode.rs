// SPDX-License-Identifier: MIT OR Apache-2.0
//! Decoders for transport encodings that hide text: base64/base64url runs,
//! continuous hex and ROT13. Every decoder returns text only when the decoded
//! bytes are printable UTF-8, so digests, keys and binary data stay undecoded.

/// Longest prefix of a fragment that is decoded; a multiple of 4 and 2, so a
/// cut base64 or hex run still decodes.
const MAX_FRAGMENT: usize = 1024;

/// Candidate fragments of at least 8 bytes; a longer run yields its first
/// [`MAX_FRAGMENT`] bytes.
pub fn split_fragments(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | ',' | ':' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .filter(|fragment| fragment.len() >= 8)
    .map(|fragment| {
        let mut end = fragment.len().min(MAX_FRAGMENT);
        while !fragment.is_char_boundary(end) {
            end -= 1;
        }
        &fragment[..end]
    })
}

pub fn continuous_hex_decode(fragment: &str) -> Option<String> {
    if !fragment.len().is_multiple_of(2)
        || fragment.len() < 8
        || !fragment.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(fragment.len() / 2);
    for pair in fragment.as_bytes().chunks(2) {
        bytes.push(hex_byte(pair[0], pair[1])?);
    }
    printable_text(bytes)
}

pub fn base64_decode_text(fragment: &str) -> Option<String> {
    if fragment.len() < 12 || !fragment.len().is_multiple_of(4) {
        return None;
    }
    if !fragment.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
    }) {
        return None;
    }

    let mut out = Vec::with_capacity(fragment.len() * 3 / 4);
    let mut chunk = [0u8; 4];
    for raw in fragment.as_bytes().chunks(4) {
        for (idx, byte) in raw.iter().enumerate() {
            chunk[idx] = base64_value(*byte)?;
        }
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
        if raw[2] != b'=' {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if raw[3] != b'=' {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }

    printable_text(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        b'=' => Some(0),
        _ => None,
    }
}

pub fn rot13_decode_text(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            'a'..='m' | 'A'..='M' => char::from_u32(character as u32 + 13).unwrap(),
            'n'..='z' | 'N'..='Z' => char::from_u32(character as u32 - 13).unwrap(),
            _ => character,
        })
        .collect()
}

pub fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_nibble(high)? << 4 | hex_nibble(low)?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The bytes as text when they are UTF-8 without control characters other than
/// whitespace (`Grüße` decodes, a digest or an image does not). A character cut
/// at the end of a truncated run is dropped.
fn printable_text(mut bytes: Vec<u8>) -> Option<String> {
    if let Err(error) = std::str::from_utf8(&bytes) {
        if error.error_len().is_some() {
            return None;
        }
        bytes.truncate(error.valid_up_to());
    }
    let decoded = String::from_utf8(bytes).ok()?;
    decoded
        .chars()
        .all(|ch| !ch.is_control() || ch.is_whitespace())
        .then_some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoders_return_printable_text_only() {
        assert_eq!(
            base64_decode_text("R3LDvMOfZSBhdXMgS8O2bG4=").as_deref(),
            Some("Grüße aus Köln")
        );
        assert_eq!(
            continuous_hex_decode("4772c3bc c39f65").as_deref(),
            None,
            "a fragment with a space is not one hex run"
        );
        assert_eq!(
            continuous_hex_decode("4772c3bcc39f65").as_deref(),
            Some("Grüße")
        );
        // A SHA-256 digest and an image header decode to binary.
        assert_eq!(
            continuous_hex_decode(
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            ),
            None
        );
        assert_eq!(base64_decode_text("iVBORw0KGgoAAAANSUhEUg=="), None);
        assert_eq!(rot13_decode_text("Uryyb, Jbeyq!"), "Hello, World!");
    }

    #[test]
    fn long_runs_decode_their_first_bytes() {
        let hex = "41".repeat(2000);
        let fragments: Vec<_> = split_fragments(&hex).collect();
        assert_eq!(fragments, vec![&hex[..MAX_FRAGMENT]]);
        assert_eq!(
            continuous_hex_decode(fragments[0]).map(|text| text.len()),
            Some(512)
        );
        // "ü" (c3 bc) cut after its first byte loses only that character.
        assert_eq!(continuous_hex_decode("41424344c3").as_deref(), Some("ABCD"));
        assert!(split_fragments("short abc").next().is_none());
    }
}
