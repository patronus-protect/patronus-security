// SPDX-License-Identifier: GPL-3.0-only
pub(super) fn is_token_boundary(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>'
        )
}

pub(super) fn token_contains_unicode_confusable(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }

    let mut has_ascii_letter = false;
    let mut has_confusable = false;
    for ch in token.chars() {
        let cp = ch as u32;
        if cp < 0x80 {
            if ch.is_ascii_alphabetic() {
                has_ascii_letter = true;
            }
            continue;
        }

        if is_confusable_codepoint(cp) {
            has_confusable = true;
        }
    }

    has_ascii_letter && has_confusable
}

pub(super) fn confusable_ascii(ch: char) -> Option<char> {
    let cp = ch as u32;
    if (0xFF21..=0xFF3A).contains(&cp) {
        return char::from_u32(b'A' as u32 + cp - 0xFF21);
    }
    if (0xFF41..=0xFF5A).contains(&cp) {
        return char::from_u32(b'a' as u32 + cp - 0xFF41);
    }
    Some(match cp {
        0x0430 | 0x03B1 | 0x0251 => 'a',
        0x0410 | 0x0391 => 'A',
        0x0432 | 0x03B2 => 'b',
        0x0412 | 0x0392 => 'B',
        0x0441 | 0x03F2 => 'c',
        0x0421 => 'C',
        0x0435 | 0x03B5 => 'e',
        0x0415 | 0x0395 => 'E',
        0x0261 => 'g',
        0x043D | 0x03B7 => 'h',
        0x041D | 0x0397 => 'H',
        0x0406 | 0x0456 | 0x03B9 | 0x0131 => 'i',
        0x0399 => 'I',
        0x0458 => 'j',
        0x043A | 0x03BA => 'k',
        0x041A | 0x039A => 'K',
        0x0142 => 'l',
        0x043C => 'm',
        0x041C | 0x039C => 'M',
        0x03BD => 'v',
        0x043E | 0x03BF | 0x0254 => 'o',
        0x041E | 0x039F => 'O',
        0x0440 | 0x03C1 => 'p',
        0x0420 | 0x03A1 => 'P',
        0x0455 => 's',
        0x0442 | 0x03C4 => 't',
        0x0422 | 0x03A4 => 'T',
        0x0443 | 0x03C5 => 'y',
        0x03A5 => 'Y',
        0x0445 | 0x03C7 => 'x',
        0x0425 | 0x03A7 => 'X',
        _ => return None,
    })
}

pub(super) fn is_confusable_codepoint(cp: u32) -> bool {
    if (0xFF21..=0xFF5A).contains(&cp) {
        return true;
    }

    matches!(
        cp,
        0x0430
            | 0x0432
            | 0x0435
            | 0x043A
            | 0x043C
            | 0x043D
            | 0x043E
            | 0x0440
            | 0x0441
            | 0x0442
            | 0x0443
            | 0x0445
            | 0x0406
            | 0x0455
            | 0x0456
            | 0x0458
            | 0x0410
            | 0x0412
            | 0x0415
            | 0x041A
            | 0x041C
            | 0x041D
            | 0x041E
            | 0x0420
            | 0x0421
            | 0x0422
            | 0x0425
            | 0x0474
            | 0x03B1
            | 0x03B2
            | 0x03B3
            | 0x03B5
            | 0x03B6
            | 0x03B7
            | 0x03B9
            | 0x03BA
            | 0x03BD
            | 0x03BF
            | 0x03C1
            | 0x03C5
            | 0x03C7
            | 0x0391
            | 0x0392
            | 0x0395
            | 0x0396
            | 0x0397
            | 0x0399
            | 0x039A
            | 0x039C
            | 0x039D
            | 0x039F
            | 0x03A1
            | 0x03A4
            | 0x03A5
            | 0x03A7
            | 0x0131
            | 0x0142
            | 0x0251
            | 0x0254
            | 0x0257
            | 0x0261
            | 0x0274
            | 0x0280
    )
}

pub(super) fn remove_zero_width(text: &str) -> String {
    text.chars()
        .filter(|ch| {
            !matches!(
                ch,
                '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
            )
        })
        .collect()
}

pub(super) fn percent_decode_lossy(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            if let Some(value) = hex_byte(bytes[idx + 1], bytes[idx + 2]) {
                out.push(value);
                idx += 3;
                continue;
            }
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn slash_hex_decode_lossy(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' && idx + 3 < bytes.len() && bytes[idx + 1] == b'x' {
            if let Some(value) = hex_byte(bytes[idx + 2], bytes[idx + 3]) {
                out.push(value);
                idx += 4;
                continue;
            }
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn slash_unicode_decode_lossy(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' && idx + 5 < bytes.len() && bytes[idx + 1] == b'u' {
            let hex = &text[idx + 2..idx + 6];
            if hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                if let Ok(value) = u32::from_str_radix(hex, 16) {
                    if let Some(ch) = char::from_u32(value) {
                        out.push(ch);
                        idx += 6;
                        continue;
                    }
                }
            }
        }
        if let Some(ch) = text[idx..].chars().next() {
            out.push(ch);
            idx += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

pub(super) fn split_fragments(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | ',' | ':' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .filter(|fragment| (8..=256).contains(&fragment.len()))
}

pub(super) fn continuous_hex_decode(fragment: &str) -> Option<String> {
    if fragment.len() % 2 != 0
        || fragment.len() < 8
        || !fragment.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(fragment.len() / 2);
    for pair in fragment.as_bytes().chunks(2) {
        bytes.push(hex_byte(pair[0], pair[1])?);
    }
    let decoded = String::from_utf8(bytes).ok()?;
    if decoded
        .chars()
        .all(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
    {
        Some(decoded)
    } else {
        None
    }
}

pub(super) fn base64_decode_text(fragment: &str) -> Option<String> {
    if fragment.len() < 12 || fragment.len() % 4 != 0 {
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

    let decoded = String::from_utf8(out).ok()?;
    if decoded
        .chars()
        .all(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
    {
        Some(decoded)
    } else {
        None
    }
}

pub(super) fn base64_value(byte: u8) -> Option<u8> {
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

pub(super) fn rot13_decode_text(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            'a'..='m' | 'A'..='M' => char::from_u32(character as u32 + 13).unwrap(),
            'n'..='z' | 'N'..='Z' => char::from_u32(character as u32 - 13).unwrap(),
            _ => character,
        })
        .collect()
}

pub(super) fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_nibble(high)? << 4 | hex_nibble(low)?)
}

pub(super) fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
