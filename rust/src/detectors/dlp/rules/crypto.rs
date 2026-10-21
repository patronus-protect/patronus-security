// SPDX-License-Identifier: GPL-3.0-only
//! Key material: wallet keys and PEM private keys.
use crate::detectors::dlp::{
    dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
    prefilter::ValueClass,
};
use crate::detectors::validators::base58check_decode;

/// Order of the secp256k1 group, big-endian.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Mainnet WIF: Base58Check with version byte 0x80, a secp256k1 scalar and an
/// optional 0x01 compression flag (`5…` uncompressed, `K…`/`L…` compressed).
fn is_btc_wif(value: &str) -> bool {
    let Some(payload) = base58check_decode(value) else {
        return false;
    };
    let scalar = match (payload.as_slice(), value.len()) {
        ([0x80, scalar @ ..], 51) if scalar.len() == 32 => scalar,
        ([0x80, scalar @ .., 0x01], 52) if scalar.len() == 32 => scalar,
        _ => return false,
    };
    scalar.iter().any(|byte| *byte != 0) && scalar < SECP256K1_ORDER.as_slice()
}

pub(super) const RULES: &[DlpPattern] = &[
    // ── Crypto ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_eth_private_key",
        pattern: r"0x[0-9a-f]{64}\b",
        entity_group: "CRYPTO_KEY",
        validator: None,
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
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_btc_wif",
        pattern: r"(?P<anchor_1>5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_btc_wif),
        span_group: None,
        base_score: 30,
        // Scored as format until the score model is recalibrated for the
        // checksum (F02); the validator only filters.
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://en.bitcoin.it/wiki/Wallet_import_format",
            &[],
        )
        .with_provider("bitcoin")
        .with_min_entropy(3.0)
        .with_value_run(ValueClass::Base58, 51)
        .with_boundary("")
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
