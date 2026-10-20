// SPDX-License-Identifier: GPL-3.0-only
//! Key material: wallet keys and PEM private keys.
use crate::detectors::dlp::{
    dlp::{DlpPattern, RuleMeta, ValidatorStrength},
    prefilter::ValueClass,
};

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
        .with_min_entropy(3.0),
    },
    DlpPattern {
        name: "dlp_btc_wif",
        pattern: r"(?P<anchor_1>5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})",
        entity_group: "CRYPTO_KEY",
        validator: None,
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://en.bitcoin.it/wiki/Wallet_import_format",
            &[],
        )
        .with_provider("bitcoin")
        .with_min_entropy(3.0)
        .with_value_run(ValueClass::Base58, 51),
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
        ),
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
        ),
    },
];
