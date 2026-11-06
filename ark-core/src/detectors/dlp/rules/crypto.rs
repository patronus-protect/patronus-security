// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key material: wallet keys and PEM private keys.
use crate::detectors::dlp::key_context::has_key_context;
use crate::detectors::dlp::{
    dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
    prefilter::ValueClass,
};
use crate::detectors::validators::base58check_decode;
use regex::bytes::Regex;
use std::ops::Range;
use std::sync::LazyLock;

/// Order of the secp256k1 group, big-endian.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// WIF version bytes: mainnet and testnet (also signet and regtest).
const WIF_MAINNET: u8 = 0x80;
const WIF_TESTNET: u8 = 0xef;

/// WIF: Base58Check with version byte 0x80 (`5…` uncompressed, `K…`/`L…`
/// compressed) or 0xef (`9…`, `c…`), a secp256k1 scalar and the 0x01 flag of
/// compressed keys.
fn is_btc_wif(value: &str) -> bool {
    let Some(payload) = base58check_decode(value) else {
        return false;
    };
    let scalar = match (payload.as_slice(), value.len()) {
        ([WIF_MAINNET | WIF_TESTNET, scalar @ ..], 51) if scalar.len() == 32 => scalar,
        ([WIF_MAINNET | WIF_TESTNET, scalar @ .., 0x01], 52) if scalar.len() == 32 => scalar,
        _ => return false,
    };
    is_secp256k1_scalar(scalar)
}

/// A private key in 1..n-1 of secp256k1, 32 bytes big-endian.
fn is_secp256k1_scalar(scalar: &[u8]) -> bool {
    scalar.len() == 32
        && scalar.iter().any(|byte| *byte != 0)
        && scalar < SECP256K1_ORDER.as_slice()
}

/// BIP 32 / SLIP-0132 version bytes of the extended private keys per prefix:
/// `xprv` (BIP 32), `yprv` (BIP 49), `zprv` (BIP 84) on mainnet and `tprv`,
/// `uprv`, `vprv` on testnet.
const EXTENDED_PRIVATE_VERSIONS: [(&str, [u8; 4]); 6] = [
    ("xprv", [0x04, 0x88, 0xad, 0xe4]),
    ("yprv", [0x04, 0x9d, 0x78, 0x78]),
    ("zprv", [0x04, 0xb2, 0x43, 0x0c]),
    ("tprv", [0x04, 0x35, 0x83, 0x94]),
    ("uprv", [0x04, 0x4a, 0x4e, 0x28]),
    ("vprv", [0x04, 0x5f, 0x18, 0xbc]),
];

/// C02: a serialized BIP 32 extended private key, Base58Check over 78 bytes:
/// the version of its prefix, depth, parent fingerprint and child number
/// (both zero for a master key at depth 0), chain code and `0x00` with a
/// secp256k1 scalar.
fn is_extended_private_key(value: &str) -> bool {
    let Some(version) = EXTENDED_PRIVATE_VERSIONS
        .iter()
        .find(|(prefix, _)| value.starts_with(prefix))
        .map(|(_, version)| version)
    else {
        return false;
    };
    let Some(payload) = base58check_decode(value) else {
        return false;
    };
    match payload.as_slice() {
        [v0, v1, v2, v3, depth, parent @ .., _] if payload.len() == 78 => {
            let (parent, rest) = parent.split_at(8);
            [*v0, *v1, *v2, *v3] == *version
                && (*depth != 0 || parent.iter().all(|byte| *byte == 0))
                && rest[32] == 0
                && is_secp256k1_scalar(&payload[46..])
        }
        _ => false,
    }
}

/// C03: an Ethereum keystore (Web3 Secret Storage v3) around the ciphertext:
/// the `kdf` (scrypt or pbkdf2) and the `mac` of the same `crypto` object
/// within a few hundred bytes. Other JSON with a `ciphertext` field (KMS,
/// JWE, Vault transit) has neither.
fn has_keystore_structure(text: &str, range: Range<usize>) -> bool {
    static KDF: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""kdf"\s*:\s*"(?:scrypt|pbkdf2)""#).expect("valid regex"));
    static MAC: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""mac"\s*:\s*"[0-9a-f]{64}""#).expect("valid regex"));
    const WINDOW: usize = 800;
    let window =
        &text.as_bytes()[range.start.saturating_sub(WINDOW)..(range.end + WINDOW).min(text.len())];
    KDF.is_match(window) && MAC.is_match(window)
}

/// C03: a Solana keypair as a JSON byte array (`solana-keygen` `id.json`,
/// `Keypair.fromSecretKey`): 64 numbers that are bytes and not one repeated
/// or counted filler.
fn is_solana_keypair(value: &str) -> bool {
    let mut seen = [false; 256];
    let mut count = 0;
    for number in value
        .trim_matches(['[', ']'])
        .split(',')
        .map(|number| number.trim().parse::<u16>())
    {
        match number {
            Ok(byte @ 0..=255) => seen[usize::from(byte)] = true,
            _ => return false,
        }
        count += 1;
    }
    count == 64 && seen.iter().filter(|seen| **seen).count() >= 24
}

/// Order of the secp256k1 group as 64 lowercase hex digits.
const SECP256K1_ORDER_HEX: &str =
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// Ethereum private key: a secp256k1 scalar in 1..n-1 as `0x` and 64
/// lowercase hex digits, which compare like the numbers they spell.
fn is_eth_private_key(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            && hex.bytes().any(|byte| byte != b'0')
            && hex < SECP256K1_ORDER_HEX
    })
}

pub(super) const RULES: &[DlpPattern] = &[
    // ── Crypto ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_eth_private_key",
        pattern: r"0x[0-9a-f]{64}\b",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_eth_private_key),
        span_group: None,
        base_score: 25,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://ethereum.org/en/developers/docs/accounts/",
            &["0x"],
        )
        .with_provider("ethereum")
        .with_min_entropy(3.0)
        .with_boundary("")
        // F01: tx/block hashes, roots and digests share the shape.
        .with_context_gate(has_key_context)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_btc_wif",
        pattern: r"(?P<anchor_1>[59][1-9A-HJ-NP-Za-km-z]{50}|[KLc][1-9A-HJ-NP-Za-km-z]{51})",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_btc_wif),
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://en.bitcoin.it/wiki/Wallet_import_format",
            &[],
        )
        .with_provider("bitcoin")
        // Testnet keys (version byte 0xef); mainnet keys never start so.
        .with_test_prefixes(&["9", "c"])
        .with_min_entropy(3.0)
        .with_value_run(ValueClass::Base58, 51)
        .with_boundary("")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_bip32_extended_private_key",
        pattern: r"(?P<anchor_1>[xyztuv]prv)[1-9A-HJ-NP-Za-km-z]{107}",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_extended_private_key),
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format",
            &["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"],
        )
        .with_provider("bitcoin")
        // Testnet versions (BIP 32 tprv, SLIP-0132 uprv/vprv).
        .with_test_prefixes(&["tprv", "uprv", "vprv"])
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_eth_keystore_ciphertext",
        pattern: r#""ciphertext"\s*:\s*"([0-9a-f]{64})""#,
        entity_group: "CRYPTO_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/",
            &["ciphertext"],
        )
        .with_provider("ethereum")
        .with_min_entropy(3.0)
        .with_context_gate(has_keystore_structure)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_solana_keypair",
        // A key term before the array: a bare list of 64 numbers is data.
        pattern: r"(?i)(?:keypair|secret[ _.-]?key|private[ _.-]?key|signer|id\.json)[^\[\]\n]{0,40}\n?[^\[\]\n]{0,10}(\[\s*(?:[0-9]{1,3}\s*,\s*){63}[0-9]{1,3}\s*\])",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_solana_keypair),
        span_group: Some(1),
        base_score: 25,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://solana.com/docs/core/accounts#keypair",
            &["keypair", "secret", "private", "signer", "id.json"],
        )
        .with_provider("solana")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    // ── Private key material ─────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_private_key_block",
        pattern: r"(?s)-----BEGIN\s+(?P<anchor_2>RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?P<anchor_1>RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
        span_group: None,
        base_score: 70,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:private-key",
            &["-----begin"],
        )
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_private_key_header",
        pattern: r"-----BEGIN\s+(?P<anchor_1>RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:private-key",
            &["-----begin"],
        )
        .with_subtype(SecretSubtype::PrivateKey),
    },
];
