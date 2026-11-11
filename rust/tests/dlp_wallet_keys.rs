// SPDX-License-Identifier: GPL-3.0-only
//! C-WALLET (C02 + C03): BIP 32 / SLIP-0132 extended private keys
//! (Base58Check with the version bytes of their prefix, severity `test` on
//! testnet), Ethereum keystore v3 ciphertexts (only inside a keystore with
//! `kdf` and `mac`), Solana keypair arrays (64 bytes after a key term),
//! Cardano CIP-5 signing keys (Bech32 with the key length of the prefix),
//! Electrum seeds (12 words with the version prefix of a seed type) and Monero
//! mnemonic seeds (25 words with the CRC-32 checksum word), both after a seed
//! term. Values come from the golden generator; invalid vectors and
//! Electrum seeds are built here.

#[path = "support/base58check.rs"]
mod base58check;

use patronus_ark::detectors::score::ValidatorStrength;
use std::path::Path;
use std::sync::OnceLock;

use base58check::base58check_encode;
use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS,
    detectors::validators::crc32,
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
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

// ── Electrum seeds ───────────────────────────────────────────────────────────

fn bip39_words() -> Vec<&'static str> {
    include_str!("../../ark-core/src/detectors/dlp/bip39/english.txt")
        .lines()
        .collect()
}

/// The hex digits of Electrum's seed version, HMAC-SHA512 under `Seed version`.
fn seed_version(phrase: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, b"Seed version");
    ring::hmac::sign(&key, phrase.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `count` deterministic picks from `list` for `seed`.
fn pick(list: &[&'static str], seed: u64, count: usize) -> Vec<&'static str> {
    let mut rng = SplitMix64::new(seed);
    (0..count)
        .map(|_| list[(rng.next_u64() % list.len() as u64) as usize])
        .collect()
}

/// The first 12-word phrase from deterministic word picks after `start`
/// whose seed version satisfies `accept`.
fn phrase(start: u64, accept: impl Fn(&str) -> bool) -> String {
    let words = bip39_words();
    (start..)
        .map(|attempt| pick(&words, attempt, 12).join(" "))
        .find(|phrase| accept(&seed_version(phrase)))
        .expect("a phrase with the version prefix")
}

/// Electrum seed types: standard, segwit, 2FA and 2FA segwit.
const SEED_TYPES: [&str; 4] = ["01", "100", "101", "102"];

fn electrum_seed(seed_type: &str, start: u64) -> String {
    phrase(start, |version| version.starts_with(seed_type))
}

const SEED_CARRIERS: [&str; 10] = [
    "ELECTRUM_SEED=\"{}\"\n",
    "electrum:\n  seed: {}\n",
    "{\"wallet\": \"electrum\", \"seed\": \"{}\"}",
    "Your wallet generation seed is:\n{}\n",
    "Here is my Electrum seed: {}. Please keep it safe.",
    "Mein Electrum-Seed lautet: {}",
    "Wiederherstellungsphrase der Electrum-Wallet:\n{}\n",
    "Seed-Phrase (Electrum, Segwit): „{}“ – bitte sicher aufbewahren.",
    "seed = '{}'  # electrum restore",
    "Recovery phrase: {}",
];

#[test]
fn electrum_seeds_of_every_type_are_reported_after_a_seed_term() {
    for seed_type in SEED_TYPES {
        for start in [0, 5000] {
            let seed = electrum_seed(seed_type, start);
            for carrier in SEED_CARRIERS {
                let text = carrier.replace("{}", &seed);
                let found = entry(&text, "dlp_electrum_seed");
                assert!(found.is_some(), "{seed_type}: {carrier:?}");
                assert!(reports_key(&text, &seed), "{seed_type}: {carrier:?}");
            }
        }
    }
}

#[test]
fn electrum_seeds_have_checksum_strength_and_the_seed_phrase_subtype() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == "dlp_electrum_seed")
        .expect("rule exists");
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Checksum);
    let text = format!("Electrum seed: {}\n", electrum_seed("01", 0));
    let found = entry(&text, "dlp_electrum_seed").expect("seed is reported");
    assert_eq!(found["subtype"], "seed_phrase");
}

#[test]
fn phrases_that_are_no_electrum_seed_are_no_key() {
    let no_version = phrase(0, |version| {
        !SEED_TYPES
            .iter()
            .any(|seed_type| version.starts_with(seed_type))
    });
    let seed = electrum_seed("01", 0);
    let words: Vec<&str> = seed.split(' ').collect();
    let mut outside_list = words.clone();
    outside_list[5] = "zzzz";
    for text in [
        // A word-list phrase without the version prefix of a seed type
        // (a BIP39 mnemonic, not an Electrum seed).
        format!("Electrum seed: {no_version}\n"),
        format!("Mein Electrum-Seed lautet: {no_version}"),
        // A word outside the list.
        format!("Electrum seed: {}\n", outside_list.join(" ")),
        // 11 or 13 words, or the seed inside a longer run of words.
        format!("Electrum seed: {}\n", words[..11].join(" ")),
        format!("Electrum seed: {seed} able\n"),
        format!("Seed: the words {seed}\n"),
        // No seed term on the line or the line before.
        format!("{seed}\n"),
        format!("Notiz: {seed}\n"),
        format!("electrum restore\n\n\nwords: {seed}\n"),
        // Format prose and placeholders.
        "Electrum seed: <your twelve seed words here>\n".to_string(),
        "Electrum zeigt den Seed aus zwölf Wörtern beim Erstellen der Wallet an.".to_string(),
    ] {
        assert!(entry(&text, "dlp_electrum_seed").is_none(), "{text}");
    }
}

// ── Cardano signing keys ─────────────────────────────────────────────────────

const CARDANO_CARRIERS: [&str; 6] = [
    "CARDANO_SIGNING_KEY={}\n",
    "payment:\n  signing_key: \"{}\"\n",
    "cardano-address key child 1852H/1815H/0H/0/0 < root.xsk # {}\n",
    "Signierschlüssel der Cardano-Wallet: {}",
    "Der Schlüssel {} lag im Klartext im Backup.",
    "Here is the payment signing key: {}.",
];

#[test]
fn cardano_signing_keys_are_reported_in_de_and_en_carriers() {
    for gen in ["cardano_ed25519_sk", "cardano_addr_xsk"] {
        for seed in 0..8 {
            let value = generate(gen, seed);
            for carrier in CARDANO_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports_key(&text, &value), "{gen} {seed}: {carrier:?}");
                assert!(
                    entry(&text, "dlp_cardano_signing_key").is_some(),
                    "{gen} {seed}"
                );
            }
        }
    }
}

#[test]
fn cardano_lookalikes_are_no_key() {
    let key = generate("cardano_ed25519_sk", 3);
    let xsk = generate("cardano_addr_xsk", 3);
    // One data character changed: the Bech32 checksum fails.
    let mut broken = key.clone().into_bytes();
    let index = broken.len() - 10;
    broken[index] = if broken[index] == b'q' { b'p' } else { b'q' };
    let broken = String::from_utf8(broken).unwrap();
    for text in [
        // A verification key is public.
        format!(
            "CARDANO_VERIFICATION_KEY={}\n",
            generate("cardano_addr_vk", 3)
        ),
        format!("Cardano-Schlüssel: {broken}\n"),
        // The 32-byte body under an _xsk prefix or the 96-byte body under _sk:
        // the key length does not fit the prefix (and the checksum fails).
        format!("key: addr_xsk1{}\n", &key["ed25519_sk1".len()..]),
        format!("key: addr_sk1{}\n", &xsk["addr_xsk1".len()..]),
        "Cardano signing keys look like addr_xsk1… or ed25519_sk1…".to_string(),
    ] {
        assert!(entry(&text, "dlp_cardano_signing_key").is_none(), "{text}");
    }
}

// ── Monero mnemonic seeds ────────────────────────────────────────────────────

fn monero_words() -> Vec<&'static str> {
    include_str!("../../ark-core/src/detectors/dlp/rules/data/monero_english.txt")
        .lines()
        .collect()
}

/// 24 deterministic words from `start` and the checksum word of Monero's
/// `electrum-words.cpp`: the word at CRC-32 of the 3-letter prefixes mod 24.
fn monero_seed(start: u64) -> Vec<&'static str> {
    let mut words = pick(&monero_words(), start, 24);
    let prefixes: String = words.iter().map(|word| &word[..3]).collect();
    words.push(words[crc32(prefixes.as_bytes()) as usize % 24]);
    words
}

const MONERO_CARRIERS: [&str; 6] = [
    "MONERO_SEED=\"{}\"\n",
    "monero:\n  mnemonic: {}\n",
    "NOTE: the following 25 words can be used to recover access to your wallet.\nWrite them down and store them somewhere safe and secure. Your seed:\n{}\n",
    "Mein Monero-Seed: {}",
    "Wiederherstellungsphrase der Monero-Wallet:\n{}\n",
    "Here is the recovery phrase of my Monero wallet: {}. Keep it offline.",
];

#[test]
fn monero_seeds_are_reported_after_a_seed_term() {
    for start in [0, 17, 4000] {
        let seed = monero_seed(start).join(" ");
        for carrier in MONERO_CARRIERS {
            let text = carrier.replace("{}", &seed);
            assert!(
                entry(&text, "dlp_monero_seed").is_some(),
                "{start}: {carrier:?}"
            );
            assert!(reports_key(&text, &seed), "{start}: {carrier:?}");
        }
    }
    // monero-wallet-cli prints the seed over three lines.
    let words = monero_seed(3);
    let lines = [&words[..8], &words[8..16], &words[16..]].map(|line| line.join(" "));
    let text = format!("Monero seed:\n{}\n", lines.join("\n"));
    let found = entry(&text, "dlp_monero_seed").expect("multi-line seed");
    assert_eq!(found["subtype"], "seed_phrase");
}

#[test]
fn list_words_that_look_like_example_markers_keep_a_seed_reported() {
    // `dummy` is a Monero word, `sample` and `test` are BIP39 words.
    let mut words = monero_seed(1);
    words[3] = "dummy";
    let prefixes: String = words[..24].iter().map(|word| &word[..3]).collect();
    words[24] = words[crc32(prefixes.as_bytes()) as usize % 24];
    let text = format!("Monero seed: {}\n", words.join(" "));
    assert!(entry(&text, "dlp_monero_seed").is_some());
    let words = bip39_words();
    let electrum = (0..)
        .map(|attempt| pick(&words, attempt, 12).join(" "))
        .find(|seed| {
            seed_version(seed).starts_with("01")
                && seed
                    .split(' ')
                    .any(|word| matches!(word, "sample" | "test"))
        })
        .expect("a standard seed with a marker-like word");
    let text = format!("Electrum seed: {electrum}\n");
    assert!(entry(&text, "dlp_electrum_seed").is_some());
}

#[test]
fn phrases_that_are_no_monero_seed_are_no_key() {
    let words = monero_seed(5);
    let seed = words.join(" ");
    let list = monero_words();
    // A checksum word with another prefix.
    let mut wrong_checksum = words.clone();
    wrong_checksum[24] = list
        .iter()
        .find(|word| word[..3] != words[24][..3])
        .unwrap();
    let mut outside_list = words.clone();
    outside_list[7] = "zzzzz";
    for text in [
        format!("Monero seed: {}\n", wrong_checksum.join(" ")),
        format!("Monero seed: {}\n", outside_list.join(" ")),
        // 24 words or the seed inside a longer run of words.
        format!("Monero seed: {}\n", words[..24].join(" ")),
        format!("Monero seed: {seed} abbey\n"),
        // No seed term on the line or the line before.
        format!("{seed}\n"),
        format!("Notiz: {seed}\n"),
        "Monero zeigt beim Anlegen der Wallet einen Seed aus 25 Wörtern an.".to_string(),
        // Explicit example context around the seed.
        format!("Example Monero seed: {seed}\n"),
        format!("Monero seed: {seed} # Beispiel\n"),
    ] {
        assert!(entry(&text, "dlp_monero_seed").is_none(), "{text}");
    }
}
