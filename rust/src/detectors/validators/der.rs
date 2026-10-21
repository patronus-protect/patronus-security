// SPDX-License-Identifier: GPL-3.0-only
//! DER TLV parsing (ITU-T X.690) for key material.

/// One DER element: single-byte tag and its content octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub content: &'a [u8],
}

/// Parse `raw` completely into consecutive TLV elements. Single-byte tags and
/// definite minimal lengths of at most four length bytes only; `None` on any
/// truncation, high-tag-number identifier, indefinite length (BER) or
/// non-minimal length encoding.
pub fn der_parse(raw: &[u8]) -> Option<Vec<DerElement<'_>>> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let tag = *raw.get(offset)?;
        if tag & 0x1f == 0x1f {
            // High-tag-number form: the tag continues in the next octets.
            return None;
        }
        let first = *raw.get(offset + 1)?;
        offset += 2;
        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            let bytes = raw.get(offset..offset.checked_add(count)?)?;
            if count == 0 || count > 4 || bytes[0] == 0 {
                return None;
            }
            let length = bytes
                .iter()
                .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
            if length < 0x80 {
                return None;
            }
            offset += count;
            length
        };
        let content = raw.get(offset..offset.checked_add(length)?)?;
        elements.push(DerElement { tag, content });
        offset += length;
    }
    Some(elements)
}

/// Fields of `raw` if it is exactly one SEQUENCE whose content parses completely.
pub fn der_sequence(raw: &[u8]) -> Option<Vec<DerElement<'_>>> {
    match der_parse(raw)?.as_slice() {
        [DerElement { tag: 0x30, content }] => der_parse(content),
        _ => None,
    }
}

/// Whether INTEGER `content` is non-empty, non-negative and minimally encoded.
pub fn der_integer_ok(content: &[u8]) -> bool {
    match content {
        [] => false,
        [first, ..] if first & 0x80 != 0 => false,
        [0, second, ..] => second & 0x80 != 0,
        _ => true,
    }
}
