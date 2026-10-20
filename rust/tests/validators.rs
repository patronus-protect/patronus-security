//! Shared validator library (K03): structure and checksum primitives that DLP
//! and PII rules reuse. Vectors come from the specifications (CRC-32 check
//! value, Bitcoin Core base58 vectors, BIP 173/350, RFC 4648, X.690 DER) or are
//! assembled at test time; no token with a valid checksum is checked in. The
//! generator cross-check validates values materialized by the independent
//! golden encoder (`golden_recipes`).

use std::path::{Path, PathBuf};

use patronus_ark::{
    detectors::validators::{
        base58_decode, base58check_decode, base64_decode, bech32_decode, bech32_decode_with_limit,
        convert_bits, crc32, crc32_base62, crc32_base62_valid, der_integer_ok, der_parse,
        der_sequence, in_alphabet, jwt_header, jwt_parse, shannon_entropy, Base64Kind,
        Bech32Variant, CharClasses, BASE32, BASE58, BASE62, BASE64, BASE64URL, BECH32, HEX_LOWER,
    },
    golden_recipes::GeneratorSet,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn generators() -> GeneratorSet {
    GeneratorSet::load(repo_root().join("python/patronus_ark/dlp_synth/generators.json"))
        .expect("generator spec loads")
}

/// Minimal unpadded base64url encoder for test-time JWT assembly.
fn b64url(raw: &[u8]) -> String {
    let alphabet = BASE64URL.as_bytes();
    let mut encoded = String::new();
    for chunk in raw.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..=chunk.len() {
            encoded.push(char::from(
                alphabet[((bits >> (18 - 6 * index)) & 63) as usize],
            ));
        }
    }
    encoded
}

/// `value` with the character at `index` replaced by the next one of `alphabet`.
fn flip(value: &str, index: usize, alphabet: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    let position = alphabet.find(chars[index]).unwrap();
    chars[index] = alphabet[(position + 1) % alphabet.len()..]
        .chars()
        .next()
        .unwrap();
    chars.into_iter().collect()
}

// ── CRC-32 / CRC32-Base62 ────────────────────────────────────────────────

#[test]
fn crc32_matches_the_iso_hdlc_check_value() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32_base62("123456789"), "3jZRME");
    assert_eq!(crc32_base62(""), "000000");
}

#[test]
fn crc32_base62_suffix_accepts_assembled_bodies_and_rejects_mutations() {
    let payload = "Q7xK2mWv9TzR4bLp8NcY3hJf6DsG1a";
    let body = format!("{payload}{}", crc32_base62(payload));
    assert_eq!(body.len(), 36);
    assert!(crc32_base62_valid(&body));
    for index in [0, 17, 29, 30, 35] {
        assert!(!crc32_base62_valid(&flip(&body, index, BASE62)), "{index}");
    }
    assert!(!crc32_base62_valid(&format!("{payload}000000")));
    assert!(!crc32_base62_valid(&body[..6]));
    assert!(!crc32_base62_valid(""));
    assert!(!crc32_base62_valid(&body.replacen('Q', "-", 1)));
}

// ── Base58 / Base58Check ─────────────────────────────────────────────────

#[test]
fn base58_decodes_bitcoin_core_vectors() {
    for (encoded, hex) in [
        ("2g", "61"),
        ("a3gV", "626262"),
        ("aPEr", "636363"),
        ("StV1DL6CwTryKyV", "68656c6c6f20776f726c64"),
        ("1111111111", "00000000000000000000"),
        ("11", "0000"),
    ] {
        let expected: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect();
        assert_eq!(base58_decode(encoded), Some(expected), "{encoded}");
    }
    for invalid in ["0", "O", "I", "l", "2g ", "+", "ä"] {
        assert_eq!(base58_decode(invalid), None, "{invalid:?}");
    }
}

#[test]
fn base58check_verifies_the_double_sha256_checksum() {
    // Public P2PKH address of the Bitcoin genesis block (not a secret).
    let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let payload = base58check_decode(address).unwrap();
    assert_eq!(payload.len(), 21);
    assert_eq!(payload[0], 0x00);
    assert_eq!(payload[1..5], [0x62, 0xe9, 0x07, 0xb1]);
    assert_eq!(base58check_decode(&flip(address, 33, BASE58)), None);
    assert_eq!(base58check_decode(&flip(address, 10, BASE58)), None);
    assert_eq!(base58check_decode("2g"), None, "shorter than the checksum");
    assert_eq!(base58check_decode(""), None);
}

// ── Bech32 / Bech32m ─────────────────────────────────────────────────────

#[test]
fn bech32_accepts_bip173_and_bip350_vectors_with_their_variant() {
    for (value, variant) in [
        ("A12UEL5L", Bech32Variant::Bech32),
        ("a12uel5l", Bech32Variant::Bech32),
        (
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            Bech32Variant::Bech32,
        ),
        (
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            Bech32Variant::Bech32,
        ),
        (
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            Bech32Variant::Bech32,
        ),
        ("?1ezyfcl", Bech32Variant::Bech32),
        ("A1LQFN3A", Bech32Variant::Bech32m),
        ("a1lqfn3a", Bech32Variant::Bech32m),
        (
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            Bech32Variant::Bech32m,
        ),
        (
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            Bech32Variant::Bech32m,
        ),
        ("?1v759aa", Bech32Variant::Bech32m),
    ] {
        let decoded = bech32_decode(value).unwrap_or_else(|| panic!("{value}"));
        assert_eq!(decoded.variant, variant, "{value}");
        assert_eq!(decoded.hrp, value[..value.rfind('1').unwrap()].to_lowercase());
    }
    let decoded = bech32_decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").unwrap();
    assert_eq!(decoded.hrp, "abcdef");
    assert_eq!(decoded.data, (0..32).collect::<Vec<u8>>());
}

#[test]
fn bech32_rejects_bip173_and_bip350_invalid_vectors() {
    for value in [
        "A1G7SGD8",      // checksum over the uppercase HRP
        "10a06t8",       // empty HRP
        "1qzzfhee",      // empty HRP
        "pzry9x0s0muk",  // no separator
        "1pzry9x0s0muk", // empty HRP
        "x1b4n0q5v",     // invalid data character
        "li1dgmt3",      // checksum too short
        "A1aUEL5L",      // mixed case
        "M1VUXWEZ",      // bech32m checksum over the uppercase HRP
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "a12uel5m", // flipped checksum character
        "a 12uel5l",
        "",
    ] {
        assert!(bech32_decode(value).is_none(), "{value:?}");
    }
}

#[test]
fn bech32_length_limit_is_configurable() {
    let long = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs";
    assert!(bech32_decode_with_limit(long, 89).is_none());
    assert!(bech32_decode_with_limit(long, 90).is_some());
}

#[test]
fn convert_bits_regroups_five_bit_words() {
    assert_eq!(convert_bits(&[0xff], 8, 5, true), Some(vec![31, 28]));
    assert_eq!(convert_bits(&[31, 28], 5, 8, false), Some(vec![0xff]));
    // Non-zero padding bits and values wider than `from` are invalid.
    assert_eq!(convert_bits(&[31, 29], 5, 8, false), None);
    assert_eq!(convert_bits(&[32], 5, 8, true), None);
    assert_eq!(convert_bits(&[1], 0, 8, true), None);
    assert_eq!(convert_bits(&[1], 5, 0, true), None);
    assert_eq!(convert_bits(&[1], 5, 9, true), None);
}

// ── Base64 ───────────────────────────────────────────────────────────────

#[test]
fn base64_decodes_rfc4648_vectors_canonically() {
    for (encoded, decoded) in [
        ("", ""),
        ("Zg==", "f"),
        ("Zm8=", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYg==", "foob"),
        ("Zm9vYmE=", "fooba"),
        ("Zm9vYmFy", "foobar"),
    ] {
        assert_eq!(
            base64_decode(encoded, Base64Kind::Standard).as_deref(),
            Some(decoded.as_bytes()),
            "{encoded}"
        );
        let unpadded = encoded.trim_end_matches('=');
        assert_eq!(
            base64_decode(unpadded, Base64Kind::StandardUnpadded).as_deref(),
            Some(decoded.as_bytes())
        );
        assert_eq!(
            base64_decode(unpadded, Base64Kind::UrlSafe).as_deref(),
            Some(decoded.as_bytes())
        );
    }
    assert_eq!(
        base64_decode("+/8=", Base64Kind::Standard),
        Some(vec![0xfb, 0xff])
    );
    assert_eq!(
        base64_decode("-_8", Base64Kind::UrlSafe),
        Some(vec![0xfb, 0xff])
    );
    for (invalid, kind) in [
        ("Zh==", Base64Kind::Standard), // non-zero unused bits
        ("Zg", Base64Kind::Standard),   // missing padding
        ("Zg=", Base64Kind::Standard),  // short padding
        ("Zg==", Base64Kind::StandardUnpadded),
        ("Z", Base64Kind::StandardUnpadded),  // length 1 mod 4
        ("Zm9=v", Base64Kind::Standard),      // padding inside
        ("-_8=", Base64Kind::Standard),       // URL alphabet in standard
        ("+/8", Base64Kind::UrlSafe),         // standard alphabet in URL-safe
        ("Zm9v\nYg==", Base64Kind::Standard), // line break
    ] {
        assert_eq!(base64_decode(invalid, kind), None, "{invalid:?} {kind:?}");
    }
}

// ── DER ──────────────────────────────────────────────────────────────────

#[test]
fn der_parses_complete_tlv_sequences() {
    let raw = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
    let outer = der_parse(&raw).unwrap();
    assert_eq!(outer.len(), 1);
    assert_eq!(outer[0].tag, 0x30);
    let fields = der_sequence(&raw).unwrap();
    assert_eq!(
        fields.iter().map(|field| field.tag).collect::<Vec<_>>(),
        [0x02, 0x02]
    );
    assert_eq!(fields[0].content, [0x01]);

    let mut long = vec![0x04, 0x81, 0x80];
    long.extend([0xab; 0x80]);
    assert_eq!(der_parse(&long).unwrap()[0].content.len(), 0x80);
    let mut two_byte = vec![0x04, 0x82, 0x01, 0x00];
    two_byte.extend([0xcd; 0x100]);
    assert_eq!(der_parse(&two_byte).unwrap()[0].content.len(), 0x100);
    assert_eq!(der_parse(&[]).unwrap().len(), 0);
}

#[test]
fn der_rejects_truncated_indefinite_and_non_minimal_lengths() {
    for invalid in [
        &[0x30, 0x03, 0x02, 0x01][..],          // truncated content
        &[0x30][..],                            // missing length
        &[0x30, 0x80, 0x00, 0x00][..],          // indefinite length (BER)
        &[0x04, 0x81, 0x05, 0, 0, 0, 0, 0][..], // long form for a short length
        &[0x04, 0x82, 0x00, 0x80][..],          // leading zero length byte
        &[0x04, 0x85, 1, 0, 0, 0, 0][..],       // more than four length bytes
    ] {
        assert!(der_parse(invalid).is_none(), "{invalid:02x?}");
    }
    // A sequence must be the only top-level element and contain valid TLVs.
    assert!(der_sequence(&[0x30, 0x00, 0x05, 0x00]).is_none());
    assert!(der_sequence(&[0x02, 0x01, 0x00]).is_none());
    assert!(der_sequence(&[0x30, 0x02, 0x02, 0x05]).is_none());
}

#[test]
fn der_integer_is_minimal_and_non_negative() {
    assert!(der_integer_ok(&[0x00]));
    assert!(der_integer_ok(&[0x7f]));
    assert!(der_integer_ok(&[0x00, 0x80]));
    assert!(der_integer_ok(&[0x01, 0x00]));
    assert!(!der_integer_ok(&[]));
    assert!(!der_integer_ok(&[0x80]), "negative");
    assert!(!der_integer_ok(&[0x00, 0x7f]), "non-minimal");
}

// ── JWT ──────────────────────────────────────────────────────────────────

#[test]
fn jwt_header_reads_alg_and_typ() {
    // RFC 7519 section 3.1 header with CRLF and spaces.
    let header = jwt_header("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9").unwrap();
    assert_eq!(header.alg, "HS256");
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    assert!(!header.is_unsecured());

    let unsecured = jwt_header(&b64url(br#"{"alg":"none"}"#)).unwrap();
    assert!(unsecured.is_unsecured());
    assert_eq!(unsecured.typ, None);
    assert!(jwt_header(&b64url(br#"{"alg":"NONE","kid":"k1"}"#))
        .unwrap()
        .is_unsecured());
    assert_eq!(
        jwt_header(&b64url(br#"{"alg":"RS256","kid":"k1"}"#))
            .unwrap()
            .fields["kid"],
        "k1"
    );

    for invalid in [
        b64url(br#"{"typ":"JWT"}"#),    // no alg
        b64url(br#"{"alg":256}"#),      // alg not a string
        b64url(br#"["alg","HS256"]"#),  // not an object
        b64url(b"alg=HS256"),           // not JSON
        b64url(&[0xff, 0xfe, 0x7b]),    // not UTF-8
        "eyJhbGciOiJIUzI1NiJ9=".into(), // padded
        "eyJhbGciOiJIUzI1NiJ9+".into(), // standard alphabet
        String::new(),
    ] {
        assert!(jwt_header(&invalid).is_none(), "{invalid:?}");
    }
}

#[test]
fn jwt_parse_needs_three_segments_with_json_header_and_claims() {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = b64url(br#"{"sub":"1234567890","iat":1700000000}"#);
    let signature = b64url(&[7u8; 32]);
    let token = format!("{header}.{claims}.{signature}");
    let jwt = jwt_parse(&token).unwrap();
    assert_eq!(jwt.header.alg, "HS256");
    assert_eq!(jwt.claims["sub"], "1234567890");
    assert_eq!(jwt.signature, [7u8; 32]);

    let unsecured = format!("{}.{claims}.", b64url(br#"{"alg":"none"}"#));
    let jwt = jwt_parse(&unsecured).unwrap();
    assert!(jwt.header.is_unsecured() && jwt.signature.is_empty());

    for invalid in [
        format!("{header}.{claims}"),
        format!("{header}.{claims}.{signature}.{signature}"),
        format!("{header}.{}.{signature}", b64url(b"[1,2]")),
        format!("{header}.{}.{signature}", b64url(b"not json")),
        format!("{header}.{claims}.{signature}="),
        format!("{}.{claims}.{signature}", b64url(br#"{"typ":"JWT"}"#)),
    ] {
        assert!(jwt_parse(&invalid).is_none(), "{invalid}");
    }
}

// ── Entropy and character classes ────────────────────────────────────────

#[test]
fn shannon_entropy_counts_bits_per_character() {
    let close = |value: &str, bits: f64| (shannon_entropy(value) - bits).abs() < 1e-9;
    assert!(close("", 0.0));
    assert!(close("aaaa", 0.0));
    assert!(close("ab", 1.0));
    assert!(close("abcd", 2.0));
    assert!(close("aabb", 1.0));
    assert!(close("0123456789abcdef", 4.0));
    assert!(close("äöüß", 2.0), "characters, not bytes");
    assert!(close(BASE64, 6.0));
}

#[test]
fn character_classes_are_counted_per_class() {
    let classes = CharClasses::of("aB3$ä-xY");
    assert_eq!(
        (
            classes.lower,
            classes.upper,
            classes.digit,
            classes.symbol,
            classes.non_ascii
        ),
        (2, 2, 1, 2, 1)
    );
    assert_eq!(classes.distinct(), 5);
    assert_eq!(CharClasses::of("").distinct(), 0);
    assert_eq!(CharClasses::of("abc").distinct(), 1);
    assert_eq!(CharClasses::of("abcDEF123").distinct(), 3);
}

#[test]
fn alphabets_match_their_specifications() {
    assert_eq!(BASE62.len(), 62);
    assert_eq!(BASE58.len(), 58);
    assert_eq!(BASE64.len(), 64);
    assert_eq!(BASE64URL.len(), 64);
    assert_eq!(BASE32.len(), 32);
    assert_eq!(BECH32.len(), 32);
    assert_eq!(HEX_LOWER.len(), 16);
    for confusable in ['0', 'O', 'I', 'l'] {
        assert!(!BASE58.contains(confusable));
    }
    for excluded in ['1', 'b', 'i', 'o'] {
        assert!(!BECH32.contains(excluded));
    }
    assert!(in_alphabet("deadbeef", HEX_LOWER));
    assert!(!in_alphabet("DEADBEEF", HEX_LOWER));
    assert!(in_alphabet("AKIAZ234567", BASE32));
    assert!(!in_alphabet("AKIA0189", BASE32));
    assert!(!in_alphabet("", BASE62), "empty values never match");
    assert!(!in_alphabet("abcä", BASE62));
}

// ── Cross-check against the golden generator ─────────────────────────────

#[test]
fn validators_accept_generated_values_and_reject_example_fills() {
    let generators = generators();
    for name in [
        "github_ghp_token",
        "github_gho_token",
        "github_ghu_token",
        "github_ghs_token",
        "github_ghr_token",
        "npm_access_token",
    ] {
        for seed in 0..32 {
            let token = generators.generate(name, seed).unwrap();
            let body = &token[4..];
            assert!(crc32_base62_valid(body), "{name} seed {seed}");
            assert!(!crc32_base62_valid(&flip(body, 3, BASE62)), "{name} {seed}");
        }
        let filled = generators
            .generate_filled(name, 1, Some("EXAMPLE"))
            .unwrap();
        assert!(!crc32_base62_valid(&filled[4..]), "{name} example fill");
    }

    for name in ["btc_wif_mainnet_uncompressed", "btc_wif_mainnet_compressed"] {
        for seed in 0..32 {
            let wif = generators.generate(name, seed).unwrap();
            let payload = base58check_decode(&wif).unwrap_or_else(|| panic!("{name} {seed}"));
            assert_eq!(payload[0], 0x80);
            assert!(matches!(payload.len(), 33 | 34));
            let last = wif.len() - 1;
            assert_eq!(base58check_decode(&flip(&wif, last, BASE58)), None);
        }
    }

    for name in ["jwt_signed_hs256", "jwt_signed_rs256"] {
        for seed in 0..16 {
            let token = generators.generate(name, seed).unwrap();
            let jwt = jwt_parse(&token).unwrap_or_else(|| panic!("{name} {seed}"));
            assert!(jwt.header.alg.ends_with("256"));
            assert!(jwt.claims.contains_key("sub"));
        }
    }

    for seed in 0..16 {
        let basic = generators.generate("http_basic_auth", seed).unwrap();
        let raw = base64_decode(&basic, Base64Kind::Standard).unwrap();
        assert!(raw.contains(&b':'));
        let discord = generators.generate("discord_bot_token", seed).unwrap();
        let parts: Vec<_> = discord.split('.').collect();
        let snowflake = base64_decode(parts[0], Base64Kind::UrlSafe).unwrap();
        assert!(snowflake.iter().all(u8::is_ascii_digit));
        assert_eq!(
            base64_decode(parts[2], Base64Kind::UrlSafe).unwrap().len(),
            20
        );
    }

    for name in [
        "pem_pkcs8_ed25519_private_key",
        "pem_pkcs1_rsa_private_key",
        "pem_sec1_ec_private_key",
        "pem_dsa_private_key",
    ] {
        for seed in 0..8 {
            let pem = generators.generate(name, seed).unwrap();
            let body: String = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            let der = base64_decode(&body, Base64Kind::Standard)
                .unwrap_or_else(|| panic!("{name} {seed}"));
            let fields = der_sequence(&der).unwrap_or_else(|| panic!("{name} {seed}"));
            assert_eq!(fields[0].tag, 0x02, "{name} version");
            assert!(der_integer_ok(fields[0].content));
            let mut truncated = der.clone();
            truncated.pop();
            assert!(der_sequence(&truncated).is_none(), "{name} truncated");
        }
    }
}
