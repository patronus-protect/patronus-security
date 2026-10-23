// SPDX-License-Identifier: GPL-3.0-only
//! K02: rule metadata v2. Every DLP rule declares its provider, validator
//! strength, prefilter keywords, minimum value entropy, format source and
//! live/test severity; matches report them in `matched_rules`. Token values
//! are synthetic and assembled at test time.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use patronus_ark::{
    detectors::{
        dlp::{
            dlp::{Severity, ValidatorStrength, DLP_PATTERNS},
            prefilter::FOLDS_TO_ASCII,
        },
        validators::crc32_base62,
    },
    golden_recipes::{materialize_fragments, GeneratorSet, SecretRecipe, SplitMix64},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use regex::Regex;
use serde::Deserialize;

const SECRET_GROUPS: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
];

/// Rules whose regex has no literal every match must contain; they declare a
/// structural prefilter instead (`RuleMeta::value_run`, K07,
/// `dlp_rule_prefilter.rs`). New rules must declare keywords.
const KEYWORDLESS_RULES: &[&str] = &["dlp_btc_wif", "dlp_discord_token"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
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

fn matched_rule(text: &str, rule_id: &str) -> Option<serde_json::Value> {
    scan(text).layers[0]
        .details
        .get("matched_rules")?
        .as_array()?
        .iter()
        .find(|rule| rule["rule_id"] == rule_id)
        .cloned()
}

fn random_body(seed: u64, alphabet: &str, len: usize) -> String {
    let alphabet = alphabet.as_bytes();
    let mut rng = SplitMix64::new(seed);
    (0..len)
        .map(|_| alphabet[(rng.next_u64() % alphabet.len() as u64) as usize] as char)
        .collect()
}

const BASE62: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[test]
fn every_rule_declares_metadata() {
    let provider = Regex::new(r"^[a-z][a-z0-9_]*$").unwrap();
    for rule in DLP_PATTERNS {
        let meta = &rule.meta;
        if let Some(name) = meta.provider {
            assert!(provider.is_match(name), "{}: provider {name:?}", rule.name);
        }
        assert!(!meta.source_ref.is_empty(), "{}: source_ref", rule.name);
        if matches!(
            meta.validator_strength,
            ValidatorStrength::Checksum | ValidatorStrength::Structure
        ) {
            assert!(
                rule.validator.is_some(),
                "{}: {} strength needs a validator",
                rule.name,
                meta.validator_strength.as_str()
            );
        }
        if let Some(bits) = meta.min_entropy {
            assert!(
                bits > 0.0 && bits <= 6.0,
                "{}: min_entropy {bits}",
                rule.name
            );
            assert!(
                SECRET_GROUPS.contains(&rule.entity_group),
                "{}: min_entropy only for secret rules",
                rule.name
            );
        }
        for prefix in meta.test_prefixes {
            assert!(!prefix.is_empty(), "{}: empty test prefix", rule.name);
            assert!(
                SECRET_GROUPS.contains(&rule.entity_group),
                "{}: severity only for secret rules",
                rule.name
            );
        }
    }
}

#[test]
fn validator_strength_names_are_stable() {
    assert_eq!(ValidatorStrength::Checksum.as_str(), "checksum");
    assert_eq!(ValidatorStrength::Structure.as_str(), "structure");
    assert_eq!(ValidatorStrength::Format.as_str(), "format");
    assert_eq!(ValidatorStrength::None.as_str(), "none");
    assert_eq!(Severity::Live.as_str(), "live");
    assert_eq!(Severity::Test.as_str(), "test");
}

#[test]
fn provider_rules_name_their_provider() {
    for rule in DLP_PATTERNS {
        if matches!(rule.entity_group, "API_KEY" | "CLOUD_KEY" | "PAYMENT_KEY") {
            assert!(rule.meta.provider.is_some(), "{}: provider", rule.name);
        }
        if rule.meta.provider.is_some() {
            assert_ne!(
                rule.meta.validator_strength,
                ValidatorStrength::None,
                "{}: provider rules have a format",
                rule.name
            );
        }
    }
}

#[test]
fn keywords_are_lowercase_and_minimal() {
    for rule in DLP_PATTERNS {
        let keywords = rule.meta.keywords;
        if KEYWORDLESS_RULES.contains(&rule.name) {
            assert!(keywords.is_empty(), "{}: listed as keywordless", rule.name);
            continue;
        }
        assert!(
            !keywords.is_empty(),
            "{}: keywords for the prefilter",
            rule.name
        );
        let unique: BTreeSet<_> = keywords.iter().collect();
        assert_eq!(
            unique.len(),
            keywords.len(),
            "{}: duplicate keyword",
            rule.name
        );
        for keyword in keywords {
            assert!(!keyword.is_empty(), "{}: empty keyword", rule.name);
            assert_eq!(*keyword, keyword.to_lowercase(), "{}: {keyword}", rule.name);
            assert!(
                !keywords
                    .iter()
                    .any(|other| other != keyword && keyword.contains(other)),
                "{}: keyword {keyword:?} is covered by a shorter one",
                rule.name
            );
        }
    }
}

#[derive(Deserialize)]
struct GoldenRow {
    id: String,
    text: Option<String>,
    template: Option<String>,
    secrets: Option<Vec<SecretRecipe>>,
}

fn golden_texts() -> Vec<(String, String)> {
    let generators =
        GeneratorSet::load(repo_root().join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load");
    std::fs::read_to_string(repo_root().join("python/patronus_ark/benchmark_data/dlp_l1.jsonl"))
        .expect("dlp_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str::<GoldenRow>(line).expect("valid golden row"))
        .map(|row| {
            let text = match (row.text, row.template) {
                (Some(text), _) => text,
                (None, Some(template)) => {
                    materialize_fragments(&generators, &template, &row.secrets.unwrap_or_default())
                        .expect("golden template must materialize")
                        .0
                }
                (None, None) => panic!("{}: neither text nor template", row.id),
            };
            (row.id, text)
        })
        .collect()
}

/// The keyword prefilter must never hide a match: every regex match in the
/// goldens contains one of the rule's keywords (ASCII case-insensitive, with
/// LONG S and KELVIN SIGN folded as `(?i)` does; such texts skip the
/// prefilter, see `dlp_rule_prefilter.rs`).
#[test]
fn every_golden_match_contains_a_keyword() {
    let texts = golden_texts();
    assert!(texts.len() > 500);
    let mut checked = BTreeMap::<&str, usize>::new();
    for rule in DLP_PATTERNS {
        if rule.meta.keywords.is_empty() {
            continue;
        }
        let regex = Regex::new(rule.pattern).unwrap();
        for (id, text) in &texts {
            for matched in regex.find_iter(text) {
                let lower: String = matched
                    .as_str()
                    .chars()
                    .map(|c| {
                        FOLDS_TO_ASCII
                            .iter()
                            .find(|(folded, _)| *folded == c)
                            .map_or(c.to_ascii_lowercase(), |&(_, ascii)| ascii)
                    })
                    .collect();
                assert!(
                    rule.meta.keywords.iter().any(|kw| lower.contains(kw)),
                    "{}: golden {id} matches without a keyword",
                    rule.name
                );
                *checked.entry(rule.name).or_default() += 1;
            }
        }
    }
    for rule in DLP_PATTERNS {
        if !rule.meta.keywords.is_empty() {
            assert!(
                checked.contains_key(rule.name),
                "{}: no golden match",
                rule.name
            );
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSources {
    schema: String,
    rules: BTreeMap<String, RuleSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSource {
    provider: Option<String>,
    source_ref: String,
    format: String,
    #[serde(default)]
    pending: Option<String>,
}

#[derive(Deserialize)]
struct EntityMap {
    baselines: BTreeMap<String, Baseline>,
}

#[derive(Deserialize)]
struct Baseline {
    #[serde(default)]
    inventory: Vec<String>,
}

#[derive(Deserialize)]
struct Backlog {
    tasks: Vec<BacklogTask>,
}

#[derive(Deserialize)]
struct BacklogTask {
    id: String,
}

fn load_yaml<T: serde::de::DeserializeOwned>(path: &str) -> T {
    serde_yaml::from_str(&std::fs::read_to_string(repo_root().join(path)).unwrap())
        .unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// `research/dlp/rule_sources.yaml` lists every rule with a provider or an
/// external format source, with the same `source_ref` as the rule.
#[test]
fn rule_sources_match_the_rule_metadata() {
    let sources: RuleSources = load_yaml("research/dlp/rule_sources.yaml");
    assert_eq!(sources.schema, "ark-dlp-rule-sources-v1");
    let entity_map: EntityMap = load_yaml("research/dlp/entity_map.yaml");
    let gitleaks: BTreeSet<_> = entity_map.baselines["gitleaks"].inventory.iter().collect();
    let backlog: Backlog = load_yaml("research/dlp/backlog.yaml");
    let tasks: BTreeSet<_> = backlog.tasks.iter().map(|task| task.id.as_str()).collect();

    let mut expected = BTreeSet::new();
    for rule in DLP_PATTERNS {
        let meta = &rule.meta;
        let source_ref = meta.source_ref;
        if let Some(id) = source_ref.strip_prefix("gitleaks:") {
            assert!(
                gitleaks.contains(&id.to_owned()),
                "{}: {source_ref}",
                rule.name
            );
        } else {
            assert!(
                source_ref == "ark" || source_ref.starts_with("https://"),
                "{}: source_ref {source_ref:?} must be gitleaks:<id>, https://… or ark",
                rule.name
            );
        }
        if meta.provider.is_none() && source_ref == "ark" {
            continue;
        }
        expected.insert(rule.name);
        let entry = sources
            .rules
            .get(rule.name)
            .unwrap_or_else(|| panic!("{}: missing in rule_sources.yaml", rule.name));
        assert_eq!(entry.source_ref, source_ref, "{}", rule.name);
        assert_eq!(entry.provider.as_deref(), meta.provider, "{}", rule.name);
        assert!(!entry.format.trim().is_empty(), "{}: format", rule.name);
        match (&entry.pending, source_ref) {
            (Some(task), "ark") => assert!(tasks.contains(task.as_str()), "{}: {task}", rule.name),
            (None, "ark") => panic!("{}: ark source needs a pending task", rule.name),
            (Some(_), _) => panic!("{}: pending only for ark sources", rule.name),
            (None, _) => {}
        }
    }
    let listed: BTreeSet<_> = sources.rules.keys().map(String::as_str).collect();
    assert_eq!(
        listed, expected,
        "rule_sources.yaml lists exactly the sourced rules"
    );
}

#[test]
fn matched_rules_report_metadata() {
    let body = random_body(11, BASE62, 30);
    let token = format!("{}{body}{}", "ghp_", crc32_base62(&body));
    let rule = matched_rule(&format!("GITHUB_TOKEN={token}"), "dlp_github_token")
        .expect("github token must match");
    assert_eq!(rule["provider"], "github");
    assert_eq!(rule["validator_strength"], "checksum");
    assert_eq!(rule["source_ref"], "gitleaks:github-pat");
    assert_eq!(rule["severity"], "live");

    let rule = matched_rule(
        "Das Passwort lautet Kx9vQ2mLp7Rt",
        "dlp_password_assignment",
    )
    .expect("password must match");
    assert!(rule.get("provider").is_none(), "{rule}");
    assert_eq!(rule["validator_strength"], "none");
    assert_eq!(rule["source_ref"], "ark");
    assert_eq!(rule["severity"], "live");

    // Content classes are off by default; enable them for this check.
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    gateway.set_execution_gates(ScanGateMatrix::all_enabled());
    let text = "Fehlerprotokoll:\nTraceback (most recent call last):\n  File \"app.py\", line 3\n";
    let result = gateway
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .unwrap();
    let rule = result.layers[0].details["matched_rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["rule_id"] == "dlp_stacktrace_block")
        .cloned()
        .expect("stack trace must match");
    assert_eq!(rule["validator_strength"], "format");
    assert_eq!(rule["source_ref"], "ark");
    assert!(
        rule.get("severity").is_none(),
        "content rules have no severity: {rule}"
    );
}

#[test]
fn stripe_test_keys_have_severity_test() {
    for (mode, severity) in [("live", "live"), ("test", "test")] {
        for kind in ["sk", "rk"] {
            let key = [kind, "_", mode, "_", &random_body(23, BASE62, 24)].concat();
            let rule = matched_rule(&format!("STRIPE_KEY={key}"), "dlp_stripe_key")
                .unwrap_or_else(|| panic!("{kind}_{mode} key must match"));
            assert_eq!(rule["severity"], severity, "{kind}_{mode}");
            assert_eq!(rule["provider"], "stripe");
        }
    }
}

#[test]
fn severity_follows_test_prefixes() {
    let stripe = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == "dlp_stripe_key")
        .unwrap();
    let body = random_body(5, BASE62, 24);
    assert_eq!(
        stripe.meta.severity(&["sk_test_", &body].concat()),
        Severity::Test
    );
    assert_eq!(
        stripe.meta.severity(&["rk-test-", &body].concat()),
        Severity::Test
    );
    assert_eq!(
        stripe.meta.severity(&["sk_live_", &body].concat()),
        Severity::Live
    );
    let github = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == "dlp_github_token")
        .unwrap();
    assert_eq!(
        github.meta.severity(&["ghp_test", &body].concat()),
        Severity::Live
    );
}

/// A provider-shaped value drawn from a handful of characters has too little
/// entropy for a random token and is dropped; the same shape with a random
/// base62 body stays a finding.
#[test]
fn min_entropy_drops_low_entropy_provider_values() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == "dlp_openai_legacy")
        .unwrap();
    assert!(rule.meta.min_entropy.is_some());

    let random = ["sk-", &random_body(31, BASE62, 48)].concat();
    assert!(matched_rule(&format!("OPENAI_API_KEY={random}"), "dlp_openai_legacy").is_some());

    for seed in 0..8 {
        let low = ["sk-", &random_body(seed, "aBcDe5", 48)].concat();
        assert!(
            matched_rule(&format!("OPENAI_API_KEY={low}"), "dlp_openai_legacy").is_none(),
            "low-entropy value reported: seed {seed}"
        );
    }
}

/// Generic credential rules have no entropy floor: weak but real passwords
/// stay findings (F11 decides password likeness).
#[test]
fn generic_credentials_have_no_entropy_floor() {
    for name in [
        "dlp_password_assignment",
        "dlp_generic_credential_assignment",
        "dlp_env_var_secret",
        "dlp_url_userinfo_password",
    ] {
        let rule = DLP_PATTERNS.iter().find(|rule| rule.name == name).unwrap();
        assert_eq!(rule.meta.min_entropy, None, "{name}");
    }
    assert!(matched_rule("password=abcabcabcabc", "dlp_password_assignment").is_some());
}
