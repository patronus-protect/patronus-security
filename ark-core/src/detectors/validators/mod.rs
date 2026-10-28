// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared validator library for DLP and PII rules.
//!
//! Offline structure and checksum primitives: CRC-32 and the CRC32-Base62
//! suffix of GitHub/npm tokens, Base58/Base58Check, Bech32/Bech32m, strict
//! canonical base64, DER TLV parsing, JWT headers and compact JWS, Macaroon V2,
//! the CRC32-hex suffix of Packagist tokens, Shannon
//! entropy and character classes. Every function is pure, never panics on
//! untrusted input and returns `None`/`false` for anything that does not parse
//! completely. Format-specific checks (WIF version byte, PEM key types,
//! provider prefixes) live with their rules and build on these primitives.

mod base58;
mod base64;
mod bech32;
mod charset;
mod checksum;
mod der;
mod entropy;
mod jwt;
mod macaroon;

pub use base58::{base58_decode, base58check_decode};
pub use base64::{base64_decode, Base64Kind};
pub use bech32::{
    bech32_decode, bech32_decode_with_limit, convert_bits, Bech32, Bech32Variant, BECH32_MAX_LENGTH,
};
pub use charset::{
    in_alphabet, CharClasses, BASE32, BASE58, BASE62, BASE64, BASE64URL, BECH32, HEX_LOWER,
    HEX_UPPER,
};
pub use checksum::{crc32, crc32_base62, crc32_base62_valid, crc32_hex_valid, CRC32_BASE62_LENGTH};
pub use der::{der_integer_ok, der_parse, der_sequence, DerElement};
pub use entropy::shannon_entropy;
pub use jwt::{jwt_header, jwt_parse, Jwt, JwtHeader};
pub use macaroon::{macaroon_v2_parse, MacaroonV2};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every prefix and every single-byte mutation of the seed inputs parses or
    /// is rejected without panicking.
    #[test]
    fn decoders_never_panic_on_truncated_or_mutated_input() {
        let seeds: [&[u8]; 4] = [
            b"a12uel5l",
            b"StV1DL6CwTryKyV",
            b"eyJhbGciOiJub25lIn0.e30.",
            &[0x30, 0x82, 0x01, 0x00, 0x02, 0x81, 0x80, 0x04, 0x84, 0xff],
        ];
        for seed in seeds {
            for end in 0..=seed.len() {
                for index in 0..end.max(1) {
                    for replacement in [0x00, 0x31, 0x3d, 0x2e, 0x80, 0xff] {
                        let mut input = seed[..end].to_vec();
                        if let Some(byte) = input.get_mut(index) {
                            *byte = replacement;
                        }
                        let _ = der_parse(&input);
                        let _ = der_sequence(&input);
                        let _ = convert_bits(&input, 5, 8, false);
                        let text = String::from_utf8_lossy(&input);
                        let _ = base58check_decode(&text);
                        let _ = bech32_decode(&text);
                        let _ = jwt_parse(&text);
                        let _ = crc32_base62_valid(&text);
                        let _ = crc32_hex_valid(&text);
                        let _ = macaroon_v2_parse(&input);
                        let _ = shannon_entropy(&text);
                        for kind in [
                            Base64Kind::Standard,
                            Base64Kind::StandardUnpadded,
                            Base64Kind::UrlSafe,
                        ] {
                            let _ = base64_decode(&text, kind);
                        }
                    }
                }
            }
        }
    }
}
