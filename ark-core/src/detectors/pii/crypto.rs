// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crypto wallet addresses (A02): Bitcoin and Litecoin in Base58Check or
//! Bech32/Bech32m, Ethereum with its EIP-55 checksum.
//!
//! Base58Check carries four bytes of double SHA-256 and Bech32 a 30-bit BCH
//! code, so a random string passes about one time in a billion; together with
//! the version byte or human-readable part these rules report the bare value in
//! every mode. An EIP-55 address proves one bit per letter (about fifteen in
//! forty hex digits). A lower-case Ethereum address carries no checksum and is
//! reported only with a wallet term near it or as its key.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// Bitcoin address: P2PKH `1…`, P2SH `3…` or segwit `bc1…`.
pub(super) const BTC: PiiPattern = PiiPattern {
    name: "pii_crypto_btc",
    pattern: r"(?-u:\b)(?:[13][1-9A-HJ-NP-Za-km-z]{25,33}|(?:bc1[02-9ac-hj-np-z]{11,71}|BC1[02-9AC-HJ-NP-Z]{11,71}))(?-u:\b)",
    entity_group: "CRYPTO",
    validator: Some(validators::btc_address),
    strength: ValidatorStrength::Checksum,
    base_score: 30,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

/// Litecoin address: P2PKH `L…`, P2SH `M…` or segwit `ltc1…`.
pub(super) const LTC: PiiPattern = PiiPattern {
    name: "pii_crypto_ltc",
    pattern: r"(?-u:\b)(?:[LM][1-9A-HJ-NP-Za-km-z]{33}|(?:ltc1[02-9ac-hj-np-z]{11,71}|LTC1[02-9AC-HJ-NP-Z]{11,71}))(?-u:\b)",
    entity_group: "CRYPTO",
    validator: Some(validators::ltc_address),
    strength: ValidatorStrength::Checksum,
    base_score: 30,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

/// Ethereum address in the mixed-case EIP-55 form.
pub(super) const ETH: PiiPattern = PiiPattern {
    name: "pii_crypto_eth",
    pattern: r"(?-u:\b)0x[0-9a-fA-F]{40}(?-u:\b)",
    entity_group: "CRYPTO",
    validator: Some(validators::eth_checksum_address),
    strength: ValidatorStrength::Checksum,
    base_score: 30,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

/// Ethereum address in lower case, with a wallet term near the value or as its
/// key.
pub(super) const ETH_UNCHECKED: PiiPattern = PiiPattern {
    name: "pii_crypto_eth_unchecked",
    pattern: r"(?-u:\b)0x[0-9a-f]{40}(?-u:\b)",
    entity_group: "CRYPTO",
    validator: Some(validators::eth_address),
    strength: ValidatorStrength::Format,
    base_score: 35,
    captured_value: false,
    requires_context: true,
    scored_only: false,
};
