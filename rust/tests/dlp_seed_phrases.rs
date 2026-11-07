// SPDX-License-Identifier: GPL-3.0-only
//! dlp_bip39_seed_phrase (C01): BIP39 mnemonics of 12 to 24 words of the
//! English, Italian, Portuguese, Czech, Spanish or French word list with a valid checksum, in
//! a line, comma-separated, numbered or one word per line. Phrases are built
//! here from entropy at test time; invalid vectors are no phrases.

use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::{
        dlp::{SecretSubtype, ValidatorStrength, DLP_PATTERNS},
        seed_phrase::mnemonic,
    },
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const RULE: &str = "dlp_bip39_seed_phrase";

fn entropy(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|at| {
            (seed ^ 0xa5)
                .wrapping_mul(29)
                .wrapping_add((at as u8).wrapping_mul(73))
                ^ 0x3c
        })
        .collect()
}

fn phrase(language: &str, seed: u8, len: usize) -> String {
    mnemonic(language, &entropy(seed, len)).expect("entropy length is valid")
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

/// The texts of the seed phrase spans of `text`.
fn reported(text: &str) -> Vec<String> {
    let result = scan(text);
    let rules = result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default();
    rules
        .iter()
        .filter(|rule| rule["rule_id"] == RULE && rule.get("suppressed_by").is_none())
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            text[start..end].to_string()
        })
        .collect()
}

#[test]
fn rule_metadata() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == RULE)
        .expect("rule registered");
    assert_eq!(rule.entity_group, "CRYPTO_KEY");
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Checksum);
    assert_eq!(rule.meta.subtype, Some(SecretSubtype::SeedPhrase));
}

#[test]
fn reports_phrases_of_every_length_and_language() {
    for language in [
        "english",
        "italian",
        "portuguese",
        "czech",
        "spanish",
        "french",
    ] {
        for (seed, len) in [(1, 16), (2, 20), (3, 24), (4, 28), (5, 32)] {
            let value = phrase(language, seed, len);
            let text = format!("MNEMONIC=\"{value}\"\n");
            assert_eq!(reported(&text), [value], "{language} {len}");
        }
    }
}

#[test]
fn reports_spanish_and_french_phrases_with_or_without_accents() {
    use unicode_normalization::UnicodeNormalization;
    for (language, intro) in [
        ("spanish", "Frase de recuperación"),
        ("french", "Phrase de récupération"),
    ] {
        let value = (0..=255)
            .map(|seed| phrase(language, seed, 16))
            .find(|value| !value.is_ascii())
            .expect("an accented phrase");
        let nfc: String = value.nfc().collect();
        let plain: String = value.nfd().filter(char::is_ascii).collect();
        for value in [value, nfc, plain] {
            let text = format!("{intro} : {value}\n");
            assert_eq!(reported(&text), std::slice::from_ref(&value), "{language}");
            let numbered: String = value
                .split(' ')
                .enumerate()
                .map(|(at, word)| format!("{}. {word}\n", at + 1))
                .collect();
            assert_eq!(reported(&numbered).len(), 1, "{language}");
        }
    }
}

#[test]
fn rejects_spanish_and_french_word_lists_and_short_phrases_without_context() {
    for language in ["spanish", "french"] {
        let value = phrase(language, 21, 16);
        assert!(reported(&format!("note: {value}")).is_empty(), "{language}");
        let dump: Vec<String> = (0..40)
            .map(|seed| {
                phrase(language, seed, 16)
                    .split(' ')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(reported(&format!("mnemonic:\n{}", dump.join("\n"))).is_empty());
    }
}

#[test]
fn reports_numbered_and_line_by_line_phrases() {
    let value = phrase("english", 11, 16);
    let words: Vec<&str> = value.split(' ').collect();
    let numbered: String = words
        .iter()
        .enumerate()
        .map(|(at, word)| format!("{:>2}. {word}\n", at + 1))
        .collect();
    let text = format!("Recovery phrase:\n{numbered}");
    let found = reported(&text);
    assert_eq!(found.len(), 1);
    assert!(found[0].starts_with(words[0]) && found[0].ends_with(words[11]));
    let lines = format!("Deine Wiederherstellungswörter:\n{}\n", words.join("\n"));
    assert_eq!(reported(&lines), [words.join("\n")]);
    let json = format!("{{\"seed\": [\"{}\"]}}", words.join("\", \""));
    assert_eq!(reported(&json), [words.join("\", \"")]);
}

#[test]
fn reports_a_phrase_after_list_words_in_prose() {
    let value = phrase("english", 12, 16);
    let text = format!("Here is my wallet secret phrase: {value}. Keep it safe!");
    assert_eq!(reported(&text), [value]);
}

#[test]
fn short_phrases_need_context_long_ones_do_not() {
    let short = phrase("english", 13, 16);
    assert!(reported(&format!("note: {short}")).is_empty());
    let long = phrase("english", 13, 32);
    assert_eq!(reported(&format!("note: {long}")), [long]);
}

#[test]
fn rejects_invalid_checksums_test_vectors_and_word_lists() {
    let value = phrase("english", 14, 16);
    let mut words: Vec<String> = value.split(' ').map(str::to_string).collect();
    // Swapping two different words keeps the words but breaks the checksum
    // for nearly every phrase; pick a swap that does.
    let swapped = (0..11)
        .map(|at| {
            let mut changed = words.clone();
            changed.swap(at, 11);
            changed.join(" ")
        })
        .find(|changed| reported(&format!("seed: {changed}")).is_empty())
        .expect("a swap breaks the checksum");
    assert!(reported(&format!("seed: {swapped}")).is_empty());
    // Published test vector (all-zero entropy).
    let vector = mnemonic("english", &[0; 16]).unwrap();
    assert!(reported(&format!("mnemonic: {vector}")).is_empty());
    // Eleven words.
    words.pop();
    assert!(reported(&format!("seed: {}", words.join(" "))).is_empty());
    // A word list dump.
    let dump: Vec<String> = (0..40)
        .map(|seed| {
            phrase("english", seed, 16)
                .split(' ')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(reported(&format!("words:\n{}", dump.join("\n"))).is_empty());
}

#[test]
fn ignores_prose_and_capitalised_words() {
    let value = phrase("english", 15, 16);
    let upper = value.to_uppercase();
    assert!(reported(&format!("seed phrase: {upper}")).is_empty());
    let prose = "The wallet backup process will need a secret phrase and some words \
                 about the recovery of the account, so please follow the guide.";
    assert!(reported(prose).is_empty());
    assert!(reported("MNEMONIC=${WALLET_MNEMONIC}\nseed: <your 12 word mnemonic>").is_empty());
}

#[test]
fn marker_words_inside_a_phrase_are_list_words() {
    // `test` and `example` are BIP39 words; only a context marks an example.
    let value = (0..=255)
        .flat_map(|seed| [phrase("english", seed, 16), phrase("english", seed, 32)])
        .find(|value| {
            value
                .split(' ')
                .any(|word| word == "test" || word == "example")
        })
        .expect("a phrase with a marker word");
    let text = format!("seed phrase: {value}\n");
    assert_eq!(reported(&text), [value]);
}

#[test]
fn reports_phrases_on_their_own_lines_in_a_longer_run() {
    // Review of C01: a run of more than 27 list words over several lines
    // still holds the phrases that fill a line.
    let (first, second) = (phrase("english", 16, 32), phrase("english", 17, 32));
    let text = format!("wallet backup:\n{first}\n{second}\n");
    assert_eq!(reported(&text), [first.clone(), second]);
    let short: Vec<String> = (18..21).map(|seed| phrase("english", seed, 16)).collect();
    let text = format!("seed phrases:\n{}\n", short.join("\n"));
    assert_eq!(reported(&text), short);
    let text = format!("{first}\nkeep this safe never share\n");
    assert_eq!(reported(&text), std::slice::from_ref(&first));
    let text = format!("Wiederherstellungsphrase:\n{first}\nnie teilen, sicher aufbewahren\n");
    assert_eq!(reported(&text), [first]);
    // A one-word-per-line dump of more than 27 words stays no phrase.
    let dump: Vec<String> = (0..3)
        .flat_map(|seed| {
            phrase("english", seed, 16)
                .split(' ')
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(reported(&format!("mnemonic:\n{}\n", dump.join("\n"))).is_empty());
}
