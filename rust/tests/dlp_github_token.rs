// SPDX-License-Identifier: GPL-3.0-only
//! GitHub tokens (F03). `dlp_github_token` takes `ghp_`/`gho_`/`ghu_`/`ghs_`/
//! `ghr_` and exactly 36 base62 characters: 30 random ones and their CRC32 as
//! six base62 digits. It scores at checksum strength. `dlp_github_pat` takes
//! `github_pat_` and exactly 82 word characters. A generic rule does not report
//! a token-shaped value whose CRC32 fails. Tokens come from the golden
//! generator or get their checksum here at test time; no checksum-valid token
//! is checked in.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::{
        dlp::{
            dlp::{ValidatorStrength, DLP_PATTERNS},
            score::DlpMode,
        },
        validators::{crc32_base62, BASE62},
    },
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const PREFIXES: [&str; 5] = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
const GENERATORS: [&str; 5] = [
    "github_ghp_token",
    "github_gho_token",
    "github_ghu_token",
    "github_ghs_token",
    "github_ghr_token",
];

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

fn generated(gen: &str, seed: u64) -> String {
    materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(gen, seed)],
    )
    .expect("template must materialize")
    .0
}

fn random(seed: u64, alphabet: &str, len: usize) -> String {
    let alphabet = alphabet.as_bytes();
    let mut rng = SplitMix64::new(seed);
    (0..len)
        .map(|_| alphabet[(rng.next_u64() % alphabet.len() as u64) as usize] as char)
        .collect()
}

/// `prefix`, a random base62 payload of `len` characters and its CRC32.
fn token(prefix: &str, seed: u64, len: usize) -> String {
    let payload = random(seed, BASE62, len);
    format!("{prefix}{payload}{}", crc32_base62(&payload))
}

/// `value` with the base62 character at `index` replaced by its successor.
fn flip(value: &str, index: usize) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    let position = BASE62.find(chars[index]).expect("base62 character");
    chars[index] = BASE62.as_bytes()[(position + 1) % BASE62.len()] as char;
    chars.into_iter().collect()
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
                ..ScanGateMatrix::default()
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

fn scan(text: &str) -> SecurityScanResult {
    mode_scan(text, DlpMode::Strict)
}

/// The unsuppressed `matched_rules` entry of `rule_id`, if it reported a value.
fn entry(text: &str, rule_id: &str, mode: DlpMode) -> Option<serde_json::Value> {
    mode_scan(text, mode).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .and_then(|rules| {
            rules
                .iter()
                .find(|rule| rule["rule_id"] == rule_id && rule.get("suppressed_by").is_none())
                .cloned()
        })
}

fn reports_token(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == "SECRET_TOKEN" && span.text == value)
}

/// DE and EN carriers: .env, YAML, JSON, code, log, CLI, prose.
const CARRIERS: &[&str] = &[
    "GITHUB_TOKEN={}\n",
    "# CI-Zugang\nGH_TOKEN=\"{}\"\n",
    "github:\n  token: {}\n",
    "{\"github\": {\"owner\": \"acme\", \"token\": \"{}\"}}\n",
    "client = Github(auth=Auth.Token(\"{}\"))\n",
    "2026-10-21T10:02:11Z WARN deploy: GitHub hat das Token {} abgelehnt\n",
    "$ git clone https://x-access-token:{}@github.com/acme/app.git\n",
    "$ curl -H \"Authorization: token {}\" https://api.github.com/user\n",
    "Das neue GitHub-Token für den Release-Job lautet {}, bitte im Tresor ablegen.\n",
    "Hi Jo, here is the bot token for the mirror job: {}\n",
    "password = {}\n",
];

#[test]
fn generated_tokens_are_reported_in_de_and_en_carriers() {
    for gen in GENERATORS {
        for seed in 0..12 {
            let value = generated(gen, seed);
            assert_eq!(value.len(), 40, "{value}");
            for carrier in CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports_token(&text, &value), "{gen}/{seed}: {text:?}");
                assert!(
                    entry(&text, "dlp_github_token", DlpMode::Strict).is_some(),
                    "{text:?}"
                );
            }
        }
    }
}

#[test]
fn every_prefix_with_a_crc32_suffix_is_a_token() {
    for (index, prefix) in PREFIXES.iter().enumerate() {
        for seed in 0..16 {
            let value = token(prefix, 100 * index as u64 + seed, 30);
            let text = format!("token: {value}\n");
            assert!(reports_token(&text, &value), "{text:?}");
        }
    }
}

#[test]
fn a_wrong_checksum_character_is_no_finding() {
    for gen in GENERATORS {
        for seed in 0..8 {
            let value = generated(gen, seed);
            // A payload character (the CRC32 no longer matches) and a
            // checksum character.
            for index in [7, value.len() - 1] {
                let broken = flip(&value, index);
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &broken);
                    let result = scan(&text);
                    assert!(
                        result.evidence_spans.is_empty(),
                        "{text:?}: {:?}",
                        result.evidence_spans
                    );
                }
            }
        }
    }
}

#[test]
fn bodies_of_another_length_are_no_github_token() {
    for prefix in PREFIXES {
        for seed in 0..8 {
            // 35 and 37 characters, each ending in the CRC32 of its payload,
            // and 36 random characters without one.
            for value in [
                token(prefix, seed, 29),
                token(prefix, seed, 31),
                format!("{prefix}{}", random(seed, BASE62, 40)),
            ] {
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &value);
                    assert!(
                        entry(&text, "dlp_github_token", DlpMode::Strict).is_none(),
                        "{text:?}"
                    );
                }
            }
            let short = token(prefix, seed, 29);
            let text = format!("Hi Jo, here is the bot token for the mirror job: {short}\n");
            assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
        }
    }
}

#[test]
fn a_random_body_without_a_checksum_is_no_github_token() {
    for prefix in PREFIXES {
        for seed in 0..32 {
            let value = format!("{prefix}{}", random(1000 + seed, BASE62, 36));
            let text = format!("Hi Jo, here is the bot token for the mirror job: {value}\n");
            assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
        }
    }
}

#[test]
fn an_underscore_in_the_body_is_no_github_token() {
    let value = generated("github_ghp_token", 3);
    let glued = format!("{}_{}", &value[..20], &value[21..]);
    for carrier in CARRIERS {
        let text = carrier.replace("{}", &glued);
        assert!(
            entry(&text, "dlp_github_token", DlpMode::Strict).is_none(),
            "{text:?}"
        );
    }
}

#[test]
fn generic_rules_skip_a_token_with_a_wrong_checksum() {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix::default().with_rule("dlp_github_token", false));
    let scan = |text: &str| {
        scanner
            .scan_category(SecurityCategory::Dlp, text)
            .into_iter()
            .find(|result| result.model == "native:dlp")
            .unwrap()
    };
    for seed in 0..4 {
        let value = generated("github_ghp_token", seed);
        let broken = flip(&value, 39);
        for template in ["password = {}\n", "GITHUB_TOKEN={}\n", "api_key: \"{}\"\n"] {
            let text = template.replace("{}", &value);
            assert!(
                scan(&text)
                    .evidence_spans
                    .iter()
                    .any(|span| span.label == "CREDENTIAL" && span.text == value),
                "{text:?}"
            );
            let text = template.replace("{}", &broken);
            assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
        }
    }
    // A value that only starts like a token stays a generic credential.
    let text = "password = ghp_shortButRealPassword\n";
    assert!(!scan(text).evidence_spans.is_empty());
}

#[test]
fn github_tokens_score_at_checksum_strength() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "dlp_github_token")
        .unwrap();
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Checksum);
    let value = generated("github_ghs_token", 5);
    let entry_strict = entry(
        &format!("GITHUB_TOKEN={value}\n"),
        "dlp_github_token",
        DlpMode::Strict,
    )
    .expect("token must match");
    assert_eq!(entry_strict["validator_strength"], "checksum");
    assert_eq!(entry_strict["severity"], "live");
    assert_eq!(entry_strict["provider"], "github");
    // Base 55 + checksum 35 without context.
    for mode in [DlpMode::Balanced, DlpMode::Recall] {
        let bare = entry(&value, "dlp_github_token", mode).expect("bare token");
        assert_eq!(bare["score"].as_f64(), Some(0.9), "{mode:?}");
    }
}

#[test]
fn fine_grained_tokens_have_82_characters_after_the_prefix() {
    for seed in 0..12 {
        let value = generated("github_fine_grained_pat", seed);
        assert_eq!(value.len(), 93, "{value}");
        for carrier in CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(reports_token(&text, &value), "{text:?}");
            assert!(
                entry(&text, "dlp_github_pat", DlpMode::Strict).is_some(),
                "{text:?}"
            );
        }
        for wrong in [&value[..value.len() - 1], &format!("{value}Q")] {
            for carrier in CARRIERS {
                let text = carrier.replace("{}", wrong);
                assert!(
                    entry(&text, "dlp_github_pat", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
    }
}

#[test]
fn generic_rules_skip_github_tokens_of_another_length() {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    let scan = |text: &str| {
        scanner
            .scan_category(SecurityCategory::Dlp, text)
            .into_iter()
            .find(|result| result.model == "native:dlp")
            .unwrap()
    };
    let templates = [
        "password = {}\n",
        "GITHUB_TOKEN={}\n",
        "api_key: \"{}\"\n",
        "export GH_TOKEN='{}'\n",
    ];
    for seed in 0..4 {
        let mut wrong = Vec::new();
        for prefix in PREFIXES {
            // 35 and 37 characters ending in a CRC32, 35 and 40 random ones.
            wrong.push(token(prefix, seed, 29));
            wrong.push(token(prefix, seed, 31));
            wrong.push(format!("{prefix}{}", random(seed, BASE62, 35)));
            wrong.push(format!("{prefix}{}", random(seed, BASE62, 40)));
        }
        let pat = generated("github_fine_grained_pat", seed);
        wrong.push(pat[..pat.len() - 1].to_string());
        wrong.push(format!("{pat}Q"));
        for value in &wrong {
            for template in templates {
                let text = template.replace("{}", value);
                assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
            }
        }
        // The exact lengths stay findings in the same carriers.
        for value in [generated("github_ghp_token", seed), pat] {
            for template in templates {
                let text = template.replace("{}", &value);
                assert!(
                    scan(&text)
                        .evidence_spans
                        .iter()
                        .any(|span| span.text == value),
                    "{text:?}"
                );
            }
        }
    }
}
