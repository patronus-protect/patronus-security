// SPDX-License-Identifier: GPL-3.0-only
//! dlp_btc_wif validates Base58Check: the WIF version byte (mainnet 0x80,
//! testnet/signet/regtest 0xef), a secp256k1 scalar and, for compressed keys,
//! the 0x01 flag (F02). The checksum scores the rule at checksum strength;
//! testnet keys have severity `test`. Keys come from the golden generator;
//! invalid vectors are built here and are no keys.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::{
        dlp::{
            dlp::{ValidatorStrength, DLP_PATTERNS},
            score::DlpMode,
        },
        validators::BASE58,
    },
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const MAINNET: [&str; 2] = ["btc_wif_mainnet_uncompressed", "btc_wif_mainnet_compressed"];
const TESTNET: [&str; 2] = ["btc_wif_testnet_uncompressed", "btc_wif_testnet_compressed"];
const GENERATORS: [&str; 4] = [MAINNET[0], MAINNET[1], TESTNET[0], TESTNET[1]];

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

fn wif(gen: &str, seed: u64) -> String {
    let (text, _) = materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(gen, seed)],
    )
    .expect("template must materialize");
    text
}

fn scan(text: &str) -> SecurityScanResult {
    static SCANNER: OnceLock<SecurityGateway> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            )
        })
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn mode_scan(text: &str, mode: DlpMode) -> SecurityScanResult {
    static SCANNERS: OnceLock<[SecurityGateway; 3]> = OnceLock::new();
    let scanners = SCANNERS.get_or_init(|| {
        [DlpMode::Strict, DlpMode::Balanced, DlpMode::Recall].map(|mode| {
            let scanner = SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            );
            scanner.set_execution_gates(ScanGateMatrix {
                dlp_mode: mode,
                ..ScanGateMatrix::all_enabled()
            });
            scanner
        })
    });
    scanners[mode as usize]
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

/// The `matched_rules` entry of the WIF rule, if it reported the value.
fn wif_entry(text: &str, mode: DlpMode) -> Option<serde_json::Value> {
    mode_scan(text, mode).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .and_then(|rules| {
            rules
                .iter()
                .find(|rule| {
                    rule["rule_id"] == "dlp_btc_wif" && rule.get("suppressed_by").is_none()
                })
                .cloned()
        })
}

fn reports_key(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == "CRYPTO_KEY" && span.text == value)
}

fn base58check_encode(payload: &[u8]) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        ring::digest::digest(&ring::digest::SHA256, payload).as_ref(),
    );
    let mut raw = payload.to_vec();
    raw.extend_from_slice(&digest.as_ref()[..4]);
    let mut digits: Vec<u8> = Vec::new();
    for byte in &raw {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = raw.iter().take_while(|byte| **byte == 0).count();
    let alphabet = BASE58.as_bytes();
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| alphabet[*digit as usize] as char),
        )
        .collect()
}

const CARRIERS: &[&str] = &[
    "BTC_WIF_KEY={}\n",
    "wallet:\n  wif: \"{}\"\n",
    "{\"wif\": \"{}\"}\n",
    "Der WIF-Schlüssel des Wallets lautet {}.\n",
    "importprivkey {} \"cold\"\n",
    "$ bitcoin-cli -testnet importprivkey {} \"faucet\" false\n",
    "key = PrivateKeyTestnet(\"{}\")\n",
];

#[test]
fn generated_wif_keys_are_reported_in_de_and_en_carriers() {
    for gen in GENERATORS {
        for seed in 0..16 {
            let value = wif(gen, seed);
            for carrier in CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports_key(&text, &value), "{gen}/{seed}: {text:?}");
            }
        }
    }
}

#[test]
fn a_wrong_checksum_character_is_no_key() {
    let alphabet: Vec<char> = BASE58.chars().collect();
    for gen in GENERATORS {
        for seed in 0..16 {
            let value = wif(gen, seed);
            for index in [10, value.len() - 1] {
                let mut chars: Vec<char> = value.chars().collect();
                let position = alphabet.iter().position(|c| *c == chars[index]).unwrap();
                chars[index] = alphabet[(position + 1) % alphabet.len()];
                let broken: String = chars.into_iter().collect();
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &broken);
                    assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
                }
            }
        }
    }
}

fn with(version: u8, scalar: &[u8], flag: Option<u8>) -> String {
    let mut payload = vec![version];
    payload.extend_from_slice(scalar);
    payload.extend(flag);
    base58check_encode(&payload)
}

const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn scalar() -> [u8; 32] {
    let mut scalar = [0x5a_u8; 32];
    scalar[0] = 0x3c;
    scalar
}

#[test]
fn mainnet_and_testnet_version_bytes_give_wif_keys() {
    let scalar = scalar();
    let mut below_order = ORDER;
    below_order[31] = 0x40;
    let mut one = [0_u8; 32];
    one[31] = 1;
    for (version, flag, lead) in [
        (0x80, None, "5"),
        (0x80, Some(0x01), "KL"),
        (0xef, None, "9"),
        (0xef, Some(0x01), "c"),
    ] {
        for key in [scalar, below_order, one] {
            let value = with(version, &key, flag);
            assert!(lead.contains(&value[..1]), "{value}");
            assert_eq!(value.len(), if flag.is_some() { 52 } else { 51 });
            for carrier in CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports_key(&text, &value), "{text:?}");
            }
        }
    }
}

#[test]
fn checksum_valid_strings_without_a_wif_key_are_no_key() {
    let scalar = scalar();
    let invalid = [
        with(0x80, &scalar, Some(0x02)), // compression flag other than 0x01
        with(0xef, &scalar, Some(0x00)),
        with(0x80, &[0; 32], None), // zero scalar
        with(0x80, &[0; 32], Some(0x01)),
        with(0xef, &[0; 32], None),
        with(0x80, &ORDER, None), // scalar = group order
        with(0xef, &ORDER, Some(0x01)),
        with(0x80, &[0xff; 32], Some(0x01)),
        with(0xef, &[0xff; 32], None),
        // Version bytes next to 0x80/0xef whose strings keep a WIF lead.
        with(0x7f, &[0xff; 32], None),
        with(0x81, &[0x00; 32], None),
        with(0xee, &[0xff; 32], None),
        with(0xf0, &[0x00; 32], Some(0x01)),
    ];
    for value in invalid {
        assert!(matches!(value.len(), 51 | 52), "{value}");
        assert!("5KL9c".contains(&value[..1]), "{value}");
        for carrier in CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(!reports_key(&text, &value), "{text:?}");
        }
    }
}

#[test]
fn the_rule_scores_at_checksum_strength() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "dlp_btc_wif")
        .unwrap();
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Checksum);
    let value = wif(TESTNET[1], 3);
    let entry = wif_entry(&format!("faucet wif: {value}\n"), DlpMode::Strict).unwrap();
    assert_eq!(entry["validator_strength"], "checksum");
}

#[test]
fn testnet_keys_have_test_severity() {
    for (generators, severity) in [(MAINNET, "live"), (TESTNET, "test")] {
        for gen in generators {
            for seed in 0..8 {
                let value = wif(gen, seed);
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &value);
                    let entry = wif_entry(&text, DlpMode::Strict).expect(&text);
                    assert_eq!(entry["severity"], severity, "{text:?}");
                }
            }
        }
    }
}

#[test]
fn a_bare_key_stays_in_balanced_and_a_checksum_term_drops_it() {
    for gen in GENERATORS {
        let value = wif(gen, 7);
        for mode in [DlpMode::Balanced, DlpMode::Recall] {
            let entry = wif_entry(&value, mode).expect(gen);
            assert_eq!(entry["score"].as_f64(), Some(0.65), "{gen} {mode:?}");
        }
        for template in ["Export checksum: {}", "Prüfsumme des Exports: {}"] {
            let text = template.replace("{}", &value);
            assert!(wif_entry(&text, DlpMode::Strict).is_some(), "{text:?}");
            assert!(wif_entry(&text, DlpMode::Balanced).is_none(), "{text:?}");
            assert!(wif_entry(&text, DlpMode::Recall).is_some(), "{text:?}");
        }
    }
}
