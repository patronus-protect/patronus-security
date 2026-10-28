// SPDX-License-Identifier: MIT OR Apache-2.0
//! Macaroon V2 binary format (libmacaroons `serialize_v2`, pymacaroons
//! `MacaroonV2Serializer`), the payload of PyPI API tokens.
//!
//! Version byte `0x02`, then sections of fields, each closed by an end byte
//! `0x00`. A field is its type and a LEB128 length, both varints, and the
//! data. The header section holds an optional location (type 1) and the
//! identifier (type 2); each caveat section an optional location, the
//! identifier and an optional verification ID (type 4); an empty section ends
//! the caveats. The signature field (type 6, 32 bytes) closes the macaroon.

const LOCATION: u64 = 1;
const IDENTIFIER: u64 = 2;
const VERIFICATION_ID: u64 = 4;
const SIGNATURE: u64 = 6;
/// HMAC-SHA256 signature length.
const SIGNATURE_LENGTH: usize = 32;

/// A parsed Macaroon V2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacaroonV2<'a> {
    /// Location hint of the header (`pypi.org`), if present.
    pub location: Option<&'a [u8]>,
    pub identifier: &'a [u8],
    /// Number of caveats.
    pub caveats: usize,
    pub signature: &'a [u8],
}

/// LEB128 varint at `*pos`, at most 9 bytes.
fn varint(raw: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..63).step_by(7) {
        let byte = *raw.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// One field at `*pos`: `None` at the end byte of a section.
fn field<'a>(raw: &'a [u8], pos: &mut usize) -> Option<Option<(u64, &'a [u8])>> {
    let kind = varint(raw, pos)?;
    if kind == 0 {
        return Some(None);
    }
    let length = usize::try_from(varint(raw, pos)?).ok()?;
    let data = raw.get(*pos..pos.checked_add(length)?)?;
    *pos += length;
    Some(Some((kind, data)))
}

/// One section at `*pos` with fields of the `allowed` types in ascending
/// order: its location and identifier, `None` for an empty section.
#[allow(clippy::type_complexity)]
fn section<'a>(
    raw: &'a [u8],
    pos: &mut usize,
    allowed: &[u64],
) -> Option<Option<(Option<&'a [u8]>, &'a [u8])>> {
    let (mut location, mut identifier, mut last, mut empty) = (None, None, 0, true);
    while let Some((kind, data)) = field(raw, pos)? {
        if kind <= last || !allowed.contains(&kind) {
            return None;
        }
        match kind {
            LOCATION => location = Some(data),
            IDENTIFIER => identifier = Some(data),
            _ => {}
        }
        last = kind;
        empty = false;
    }
    if empty {
        return Some(None);
    }
    Some(Some((location, identifier?)))
}

/// Parse `raw` as a complete Macaroon V2; `None` unless every byte belongs to
/// it.
pub fn macaroon_v2_parse(raw: &[u8]) -> Option<MacaroonV2<'_>> {
    if raw.first() != Some(&2) {
        return None;
    }
    let mut pos = 1;
    let (location, identifier) = section(raw, &mut pos, &[LOCATION, IDENTIFIER])??;
    let mut caveats = 0;
    while section(raw, &mut pos, &[LOCATION, IDENTIFIER, VERIFICATION_ID])?.is_some() {
        caveats += 1;
    }
    let (kind, signature) = field(raw, &mut pos)??;
    (kind == SIGNATURE && signature.len() == SIGNATURE_LENGTH && pos == raw.len()).then_some(
        MacaroonV2 {
            location,
            identifier,
            caveats,
            signature,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::macaroon_v2_parse;

    /// A macaroon with location `pypi.org`, a 4-byte identifier, the given
    /// caveat sections and a signature of `signature` bytes.
    fn macaroon(caveats: &[&[u8]], signature: u8) -> Vec<u8> {
        let mut raw = vec![2, 1, 8];
        raw.extend_from_slice(b"pypi.org");
        raw.extend_from_slice(&[2, 4, 0xde, 0xad, 0xbe, 0xef, 0]);
        for caveat in caveats {
            raw.extend_from_slice(caveat);
        }
        raw.extend_from_slice(&[0, 6, signature]);
        raw.extend(std::iter::repeat_n(0x5a, usize::from(signature)));
        raw
    }

    #[test]
    fn complete_macaroons_parse() {
        let raw = macaroon(&[&[2, 3, b'a', b'=', b'1', 0]], 32);
        let parsed = macaroon_v2_parse(&raw).unwrap();
        assert_eq!(parsed.location, Some(&b"pypi.org"[..]));
        assert_eq!(parsed.identifier, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parsed.caveats, 1);
        assert_eq!(parsed.signature.len(), 32);
        // No caveat; a third-party caveat with location and verification ID.
        assert_eq!(macaroon_v2_parse(&macaroon(&[], 32)).unwrap().caveats, 0);
        let third_party: &[u8] = &[1, 1, b'x', 2, 1, b'y', 4, 2, 7, 7, 0];
        assert_eq!(
            macaroon_v2_parse(&macaroon(&[third_party, &[2, 1, b'z', 0]], 32))
                .unwrap()
                .caveats,
            2
        );
        // A two-byte varint length (200 bytes of identifier).
        let mut long = vec![2, 2, 0xc8, 0x01];
        long.extend(std::iter::repeat_n(b'i', 200));
        long.extend_from_slice(&[0, 0, 6, 32]);
        long.extend(std::iter::repeat_n(1, 32));
        assert_eq!(macaroon_v2_parse(&long).unwrap().identifier.len(), 200);
    }

    #[test]
    fn broken_macaroons_are_rejected() {
        let valid = macaroon(&[&[2, 1, b'c', 0]], 32);
        // Every truncation and a trailing byte.
        for end in 0..valid.len() {
            assert_eq!(macaroon_v2_parse(&valid[..end]), None, "{end}");
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(macaroon_v2_parse(&trailing), None);
        // Version 1, a short signature, a header without identifier, fields
        // out of order, a signature field of another type, a caveat with an
        // unknown field type.
        let mut version = valid.clone();
        version[0] = 1;
        assert_eq!(macaroon_v2_parse(&version), None);
        assert_eq!(macaroon_v2_parse(&macaroon(&[], 31)), None);
        assert_eq!(macaroon_v2_parse(&[2, 1, 1, b'x', 0, 0, 6, 0]), None);
        assert_eq!(macaroon_v2_parse(&[2, 2, 1, b'x', 1, 1, b'y', 0, 0]), None);
        let mut kind = valid.clone();
        let signature = kind.len() - 34;
        kind[signature] = 5;
        assert_eq!(macaroon_v2_parse(&kind), None);
        assert_eq!(macaroon_v2_parse(&macaroon(&[&[3, 1, b'c', 0]], 32)), None);
        // An overlong varint.
        let mut overlong = vec![2];
        overlong.extend([0xff; 12]);
        assert_eq!(macaroon_v2_parse(&overlong), None);
    }
}
