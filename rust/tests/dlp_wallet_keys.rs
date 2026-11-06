// SPDX-License-Identifier: GPL-3.0-only
//! C-WALLET (C02 + C03): BIP 32 / SLIP-0132 extended private keys
//! (Base58Check with the version bytes of their prefix, severity `test` on
//! testnet), Ethereum keystore v3 ciphertexts (only inside a keystore with
//! `kdf` and `mac`) and Solana keypair arrays (64 bytes after a key term).
//! Values come from the golden generator; invalid vectors are built here.

#[path = "support/base58check.rs"]
mod base58check;

use std::path::Path;
use std::sync::OnceLock;

use base58check::base58check_encode;
use patronus_ark::{
    detectors::dlp::dlp::{ValidatorStrength, DLP_PATTERNS},
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

fn generate(gen: &str, seed: u64) -> String {
    materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(gen, seed)],
    )
    .expect("template must materialize")
    .0
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

/// The unsuppressed `matched_rules` entry of `rule`, if it reported a value.
fn entry(text: &str, rule: &str) -> Option<serde_json::Value> {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .and_then(|rules| {
            rules
                .iter()
                .find(|entry| entry["rule_id"] == rule && entry.get("suppressed_by").is_none())
                .cloned()
        })
}

fn reports_key(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == "CRYPTO_KEY" && span.text == value)
}

// ── Extended private keys ────────────────────────────────────────────────────

const MAINNET: [&str; 4] = ["bip32_xprv", "bip32_xprv_child", "bip32_yprv", "bip32_zprv"];
const XKEY_CARRIERS: &[&str] = &[
    "WALLET_XPRV={}\n",
    "wallet:\n  yprv: \"{}\"\n",
    "{\"keystore\": {\"type\": \"bip32\", \"xprv\": \"{}\"}}\n",
    "Der Master-Key der Wallet lautet {}.\n",
    "importdescriptors '[{\"desc\": \"wpkh({}/0/*)\"}]'\n",
];

const XPRV: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// A serialized extended key: version, depth, parent fingerprint and child
/// number, chain code and 33 key bytes (`key_lead` and the scalar).
fn xkey(version: [u8; 4], depth: u8, parent: [u8; 8], key_lead: u8, scalar: [u8; 32]) -> String {
    let mut payload = version.to_vec();
    payload.push(depth);
    payload.extend_from_slice(&parent);
    payload.extend_from_slice(&[0x6b; 32]);
    payload.push(key_lead);
    payload.extend_from_slice(&scalar);
    base58check_encode(&payload)
}

fn scalar() -> [u8; 32] {
    let mut scalar = [0x5a_u8; 32];
    scalar[0] = 0x3c;
    scalar
}

#[test]
fn generated_extended_private_keys_are_reported_in_de_and_en_carriers() {
    for gen in MAINNET.iter().chain(&["bip32_tprv"]) {
        for seed in 0..16 {
            let value = generate(gen, seed);
            assert_eq!(value.len(), 111, "{gen}/{seed}");
            for carrier in XKEY_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports_key(&text, &value), "{gen}/{seed}: {text:?}");
            }
        }
    }
}

#[test]
fn built_extended_private_keys_are_reported() {
    let mut one = [0_u8; 32];
    one[31] = 1;
    let mut below_order = ORDER;
    below_order[31] = 0x40;
    for value in [
        xkey(XPRV, 0, [0; 8], 0, scalar()),
        xkey(XPRV, 3, [0x1d; 8], 0, one),
        xkey(TPRV, 0, [0; 8], 0, below_order),
    ] {
        assert!(reports_key(&format!("xkey: {value}\n"), &value), "{value}");
    }
}

#[test]
fn checksum_valid_strings_without_an_extended_private_key_are_no_key() {
    let invalid = [
        xkey(XPUB, 0, [0; 8], 0x02, scalar()), // public key data
        xkey(XPRV, 0, [0; 8], 0x02, scalar()), // public key lead under xprv
        xkey(XPRV, 0, [0; 8], 0x01, scalar()), // key lead other than 0x00
        xkey(XPRV, 0, [0x1d; 8], 0, scalar()), // depth 0 with a parent
        xkey(XPRV, 0, [0; 8], 0, [0; 32]),     // zero scalar
        xkey(XPRV, 0, [0; 8], 0, ORDER),       // scalar = group order
        xkey(TPRV, 2, [0x1d; 8], 0, [0xff; 32]),
    ];
    for value in invalid {
        assert_eq!(value.len(), 111, "{value}");
        for carrier in XKEY_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(!reports_key(&text, &value), "{text:?}");
        }
    }
}

#[test]
fn a_wrong_checksum_character_or_a_public_key_is_no_key() {
    let alphabet: Vec<char> = patronus_ark::detectors::validators::BASE58
        .chars()
        .collect();
    for seed in 0..8 {
        let value = generate("bip32_xprv", seed);
        for index in [20, value.len() - 1] {
            let mut chars: Vec<char> = value.chars().collect();
            let position = alphabet.iter().position(|c| *c == chars[index]).unwrap();
            chars[index] = alphabet[(position + 1) % alphabet.len()];
            let broken: String = chars.into_iter().collect();
            assert!(entry(
                &format!("WALLET_XPRV={broken}\n"),
                "dlp_bip32_extended_private_key"
            )
            .is_none());
        }
        for gen in ["bip32_xpub", "bip32_tpub", "bip32_xprv_shape"] {
            let value = generate(gen, seed);
            let text = format!("account_key: \"{value}\"\n");
            assert!(!reports_key(&text, &value), "{gen}/{seed}");
        }
    }
}

#[test]
fn testnet_extended_keys_have_test_severity_and_checksum_strength() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "dlp_bip32_extended_private_key")
        .unwrap();
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Checksum);
    for (gen, severity) in [
        ("bip32_xprv", "live"),
        ("bip32_zprv", "live"),
        ("bip32_tprv", "test"),
    ] {
        let text = format!("WALLET_XPRV={}\n", generate(gen, 5));
        let entry = entry(&text, "dlp_bip32_extended_private_key").expect(gen);
        assert_eq!(entry["severity"], severity, "{gen}");
        assert_eq!(entry["validator_strength"], "checksum", "{gen}");
    }
}

#[test]
fn an_extended_key_inside_a_longer_base58_run_is_no_key() {
    let value = generate("bip32_xprv", 9);
    for text in [format!("A{value}"), format!("{value}z")] {
        assert!(
            entry(&text, "dlp_bip32_extended_private_key").is_none(),
            "{text}"
        );
    }
}

// ── Ethereum keystore ────────────────────────────────────────────────────────

fn keystore(ciphertext: &str, kdf: &str) -> String {
    format!(
        "{{\"address\": \"5d3c0f1e9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d\", \"crypto\": {{\"cipher\": \"aes-128-ctr\", \
         \"cipherparams\": {{\"iv\": \"6087dab2f9fdbbfaddc31a909735c1e6\"}}, \"ciphertext\": \"{ciphertext}\", \
         \"kdf\": \"{kdf}\", \"kdfparams\": {{\"dklen\": 32, \"n\": 262144, \"p\": 1, \"r\": 8, \
         \"salt\": \"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd\"}}, \
         \"mac\": \"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2\"}}, \"version\": 3}}"
    )
}

#[test]
fn keystore_ciphertexts_are_reported_with_kdf_and_mac() {
    for seed in 0..8 {
        let value = generate("eth_keystore_ciphertext", seed);
        for kdf in ["scrypt", "pbkdf2"] {
            let text = keystore(&value, kdf);
            assert!(reports_key(&text, &value), "{kdf}/{seed}");
            let pretty = text.replace(", \"", ",\n    \"");
            assert!(reports_key(&pretty, &value), "{kdf}/{seed}");
        }
    }
}

#[test]
fn a_ciphertext_without_the_keystore_structure_is_no_key() {
    let value = generate("eth_keystore_ciphertext", 1);
    for text in [
        // Unknown key derivation, no mac, JWE and KMS-like JSON.
        keystore(&value, "argon2"),
        keystore(&value, "scrypt").replace("\"mac\"", "\"tag\""),
        format!("{{\"iv\": \"9c1e2f4a7b3d8e6f0a5c2b1d\", \"ciphertext\": \"{value}\", \"tag\": \"4e1f2a3b\"}}"),
        format!("ciphertext = \"{value}\"\nkdf = \"scrypt\"\n"),
    ] {
        assert!(entry(&text, "dlp_eth_keystore_ciphertext").is_none(), "{text}");
    }
    // Public keystore fields with a redacted ciphertext.
    let redacted = keystore("<redacted>", "scrypt");
    assert!(scan(&redacted).evidence_spans.is_empty(), "{redacted}");
}

// ── Solana keypair ───────────────────────────────────────────────────────────

const SOLANA_CARRIERS: &[&str] = &[
    "SOLANA_KEYPAIR={}\n",
    "$ cat ~/.config/solana/id.json\n{}\n",
    "const payer = Keypair.fromSecretKey(Uint8Array.from({}));\n",
    "Privater Schlüssel des Signers: {}\n",
    "{\"secretKey\": {}}\n",
];

fn byte_array(bytes: impl Iterator<Item = u16>) -> String {
    let numbers: Vec<String> = bytes.map(|byte| byte.to_string()).collect();
    format!("[{}]", numbers.join(","))
}

#[test]
fn solana_keypairs_are_reported_after_a_key_term() {
    for seed in 0..16 {
        let value = generate("solana_keypair_array", seed);
        for carrier in SOLANA_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(reports_key(&text, &value), "{seed}: {carrier:?}");
        }
    }
    let spaced = byte_array((0..64).map(|index| (index * 37 + 11) % 256)).replace(',', ", ");
    assert!(reports_key(&format!("keypair = {spaced}\n"), &spaced));
}

#[test]
fn number_arrays_that_are_no_keypair_are_no_key() {
    let bytes = || (0..64).map(|index| (index * 37 + 11) % 256);
    let keypair = byte_array(bytes());
    for text in [
        // No key term before the array.
        format!("const weights = {keypair};\n"),
        format!("werte = {keypair}\n"),
        format!("SOLANA_KEYPAIR_PATH=~/.config/solana/id.json\n\n\nhistogram = {keypair}\n"),
        // Not bytes, too few, too many or a filler.
        format!(
            "SOLANA_KEYPAIR={}\n",
            byte_array(bytes().map(|byte| byte + 256))
        ),
        format!("SOLANA_KEYPAIR={}\n", byte_array(bytes().take(32))),
        format!("SOLANA_KEYPAIR={}\n", byte_array(bytes().chain([7]))),
        format!(
            "SOLANA_KEYPAIR={}\n",
            byte_array((0..64).map(|index| index % 8))
        ),
        format!(
            "SOLANA_KEYPAIR={}\n",
            byte_array(std::iter::repeat_n(0, 64))
        ),
    ] {
        assert!(entry(&text, "dlp_solana_keypair").is_none(), "{text}");
    }
}
