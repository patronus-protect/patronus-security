// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::detectors::text_views::decode::hex_byte;

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

pub fn percent_decode_lossy(text: &str) -> String {
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

pub fn slash_unicode_decode_lossy(text: &str) -> String {
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
