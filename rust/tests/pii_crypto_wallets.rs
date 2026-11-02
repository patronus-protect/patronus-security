// SPDX-License-Identifier: GPL-3.0-only
//! Crypto wallet addresses (A02).
//!
//! Bitcoin (`pii_crypto_btc`) and Litecoin (`pii_crypto_ltc`) addresses carry a
//! Base58Check checksum (four bytes of double SHA-256 after a version byte) or a
//! Bech32/Bech32m checksum after their human-readable part `bc`/`ltc`; Ethereum
//! addresses in mixed case carry the EIP-55 checksum (`pii_crypto_eth`). These
//! three rules report the bare value in every mode. A lower-case Ethereum
//! address has no checksum (`pii_crypto_eth_unchecked`) and needs a wallet term
//! or key. All four report the label `CRYPTO`.

use patronus_ark::detectors::pii::{
    pii::{PiiPattern, PII_PATTERNS},
    score::{self, Context, PiiMode, ValidatorStrength},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

const BTC: &str = "pii_crypto_btc";
const LTC: &str = "pii_crypto_ltc";
const ETH: &str = "pii_crypto_eth";
const ETH_UNCHECKED: &str = "pii_crypto_eth_unchecked";
const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];

fn pii_result(text: &str, mode: PiiMode) -> SecurityScanResult {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix {
        pii_mode: mode,
        ..Default::default()
    });
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

/// `(text, score)` of every span with `label`.
fn spans(text: &str, mode: PiiMode, label: &str) -> Vec<(String, f64)> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == label)
        .map(|span| (span.text, span.score))
        .collect()
}

/// Rule ids that matched with the value text they matched.
fn rules(text: &str, mode: PiiMode) -> Vec<(String, String)> {
    let result = pii_result(text, mode);
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            (
                rule["rule_id"].as_str().unwrap().to_owned(),
                text[start..end].to_owned(),
            )
        })
        .collect()
}

fn pattern(rule_id: &str) -> &'static PiiPattern {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"))
}

/// `rule_id` reports `value`, the only span of its label, in each of `modes`.
fn assert_reports(rule_id: &str, text: &str, value: &str, modes: &[PiiMode]) {
    let label = pattern(rule_id).entity_group;
    for &mode in modes {
        assert!(
            rules(text, mode)
                .iter()
                .any(|(rule, found)| rule == rule_id && found == value),
            "{mode}: {rule_id} must report the expected value in {text:?}"
        );
        let found = spans(text, mode, label);
        assert!(
            found.len() == 1 && found[0].0 == value,
            "{mode}: the expected value must be the only {label} span in {text:?}"
        );
    }
}

fn assert_silent(text: &str, label: &str, modes: &[PiiMode]) {
    for &mode in modes {
        assert!(
            spans(text, mode, label).is_empty(),
            "{mode}: no {label} expected in {text:?}"
        );
    }
}

// ── validators ───────────────────────────────────────────────────────────────

// ── validators ───────────────────────────────────────────────────────────────

#[test]
fn btc_validator_checks_base58check_and_segwit_addresses() {
    for valid in [
        // P2PKH, P2SH, the BIP 173 P2WPKH vector, P2WSH, taproot addresses and
        // the BIP 350 witness version 2 vector.
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
        "1AEFrMeUH752ufsx8tzkBEy6PpQ6jzT2A",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "3EqejfZLnd2C685ZWSjKm7cDdgVzJCJnM7",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "bc1qdxzz49uezypkeulgygyxaj4qqadxnlqh3w50sdcc428nh50kt6qsnqptka",
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
    ] {
        assert!(validators::btc_address(valid), "{valid}");
    }
    for invalid in [
        // A changed character, the checksum of a Litecoin address, the testnet
        // version, a v1 address with a Bech32 checksum, mixed case, the testnet
        // and the Litecoin human-readable part.
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2",
        "LaEYR5j5A168XQWEq76xAhcpZyKbzSbWNc",
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "ltc1qc3hd72r6gwumyyt4xpk8d2q627yexgj8q20d9g",
        "",
        "1",
    ] {
        assert!(!validators::btc_address(invalid), "{invalid}");
    }
}

#[test]
fn ltc_validator_checks_its_versions_and_human_readable_part() {
    for valid in [
        "LaEYR5j5A168XQWEq76xAhcpZyKbzSbWNc",
        "LSCL2hJdHouk8JH5nksh1fQ3xWAvwN812i",
        "MLeXaUDTZRFNvvyqB5am3jXNwKvNwS9QJS",
        "ltc1qc3hd72r6gwumyyt4xpk8d2q627yexgj8q20d9g",
        "LTC1QC3HD72R6GWUMYYT4XPK8D2Q627YEXGJ8Q20D9G",
    ] {
        assert!(validators::ltc_address(valid), "{valid}");
    }
    for invalid in [
        "LaEYR5j5A168XQWEq76xAhcpZyKbzSbWNd",
        "MLeXaUDTZRFNvvyqB5am3jXNwKvNwS9QJT",
        "ltc1qc3hd72r6gwumyyt4xpk8d2q627yexgj8q20d9h",
        // A Bitcoin P2PKH and P2SH address and a Bitcoin segwit address.
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    ] {
        assert!(!validators::ltc_address(invalid), "{invalid}");
    }
}

#[test]
fn eth_validators_check_eip55_and_the_lower_case_form() {
    for valid in [
        // The EIP-55 test vectors.
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0x3081cD277Bcd1E3763eA0bF5EE5974C3790f2b56",
    ] {
        assert!(validators::eth_checksum_address(valid), "{valid}");
        assert!(!validators::eth_address(valid), "{valid}");
        assert!(
            validators::eth_address(&valid.to_ascii_lowercase()),
            "{valid}"
        );
    }
    for invalid in [
        // One letter in the wrong case, one letter case only, 39 and 41 hex
        // digits, a non-hex letter and no `0x`.
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg",
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    ] {
        assert!(!validators::eth_checksum_address(invalid), "{invalid}");
    }
    for invalid in [
        "0x0000000000000000000000000000000000000000",
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae",
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaedd",
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaeg",
        "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
    ] {
        assert!(!validators::eth_address(invalid), "{invalid}");
    }
}

#[test]
fn the_crypto_rules_have_their_label_validator_and_context() {
    let validator = |pattern: &PiiPattern| pattern.validator.map(|validator| validator as usize);
    let balanced = PiiMode::Balanced.min_score().unwrap();
    for (rule_id, check, strength, bound) in [
        (
            BTC,
            validators::btc_address as fn(&str) -> bool,
            ValidatorStrength::Checksum,
            false,
        ),
        (
            LTC,
            validators::ltc_address,
            ValidatorStrength::Checksum,
            false,
        ),
        (
            ETH,
            validators::eth_checksum_address,
            ValidatorStrength::Checksum,
            false,
        ),
        (
            ETH_UNCHECKED,
            validators::eth_address,
            ValidatorStrength::Format,
            true,
        ),
    ] {
        let rule = pattern(rule_id);
        assert_eq!(rule.entity_group, "CRYPTO", "{rule_id}");
        assert_eq!(rule.strength, strength, "{rule_id}");
        assert_eq!(validator(rule), Some(check as usize), "{rule_id}");
        assert!(!rule.captured_value, "{rule_id}");
        assert!(!rule.scored_only, "{rule_id}");
        assert_eq!(rule.requires_context, bound, "{rule_id}");
        let context = if bound {
            Context::Support { gap: 48 }
        } else {
            Context::None
        };
        assert!(score::score(rule, context) >= balanced, "{rule_id}");
    }
}

// ── rules ────────────────────────────────────────────────────────────────────

#[test]
fn checksummed_addresses_are_reported_bare_in_every_mode() {
    for (rule_id, text, value) in [
        (
            BTC,
            "Please send it to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa today.",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ),
        (
            BTC,
            "Bitte an 3EqejfZLnd2C685ZWSjKm7cDdgVzJCJnM7 überweisen.",
            "3EqejfZLnd2C685ZWSjKm7cDdgVzJCJnM7",
        ),
        (
            BTC,
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        ),
        (
            BTC,
            r#"{"to": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}"#,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ),
        (
            LTC,
            "Payout: LaEYR5j5A168XQWEq76xAhcpZyKbzSbWNc",
            "LaEYR5j5A168XQWEq76xAhcpZyKbzSbWNc",
        ),
        (
            LTC,
            "an ltc1qc3hd72r6gwumyyt4xpk8d2q627yexgj8q20d9g gesendet",
            "ltc1qc3hd72r6gwumyyt4xpk8d2q627yexgj8q20d9g",
        ),
        (
            ETH,
            "Transfer to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed.",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ),
    ] {
        assert_reports(rule_id, text, value, &MODES);
    }
}

#[test]
fn a_lower_case_ethereum_address_needs_a_wallet_term_or_key() {
    let value = "0xed732a1a1131be177dea42619767c2188e12e65b";
    for text in [
        format!("Wallet address: {value}"),
        format!("Die Ethereum-Adresse lautet {value}."),
        format!(r#"{{"wallet": "{value}"}}"#),
    ] {
        assert_reports(ETH_UNCHECKED, &text, value, &MODES);
    }
    assert_silent(&format!("Commit {value} was merged."), "CRYPTO", &MODES);
}

#[test]
fn addresses_need_a_valid_checksum() {
    for text in [
        "Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "my wallet address is: 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2",
        "BTC: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "Wallet: bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "LTC: LaEYR5j5A168XQWEq76xAhcpZyKbzSbWNd",
        "ETH: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
        // A private key (DLP) and a transaction hash are no addresses.
        "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        "Wallet: 0x0000000000000000000000000000000000000000",
        // Part of a longer token.
        "id=x1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ] {
        assert_silent(text, "CRYPTO", &MODES);
    }
}
