// SPDX-License-Identifier: GPL-3.0-only
//! E03 synthetic secret generator: every `dlp_*` rule in `DLP_PATTERNS` has
//! format-valid generators in `dlp_synth/rules.json` (or is a content rule),
//! each rule alone reports exactly the generated value in every probe carrier,
//! and the Rust materializer reproduces the Python generator output pinned in
//! `fixtures/dlp_synth_vectors.json`. Baseline entities (GOLD-D2) have generators
//! for carrier gold without an ARK rule.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS,
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMap {
    version: u32,
    #[allow(dead_code)]
    note: String,
    rules: BTreeMap<String, RuleEntry>,
    content_rules: BTreeMap<String, String>,
    /// Entities without an ARK rule (GOLD-D2): generators for carrier gold and lookalikes
    /// for carrier hard negatives.
    baseline_entities: BTreeMap<String, BaselineEntity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineEntity {
    generators: Vec<String>,
    lookalike: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    generators: Vec<String>,
    #[serde(default)]
    shape_only: Vec<String>,
    /// Low-variety but real values (T06) the rule must keep reporting.
    #[serde(default)]
    weak: Vec<String>,
    /// Real values with spaces or `;`/`,`/`}` inside (F-GEN2); the rule reports them up
    /// to the closing quote, so each probe wraps them in double quotes.
    #[serde(default)]
    quoted: Vec<String>,
    /// Real values with RFC 3986 reserved characters (T17); each probe inserts them
    /// percent-encoded and the rule reports the encoded span.
    #[serde(default)]
    url_encoded: Vec<String>,
    /// Values in the rule's shape with a wrong check value or length (F03); the rule must
    /// not report them.
    #[serde(default)]
    lookalike: Vec<String>,
    probes: Vec<String>,
}

#[derive(Deserialize)]
struct Vectors {
    seeds: Vec<u64>,
    generators: BTreeMap<String, String>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn generators() -> GeneratorSet {
    GeneratorSet::load(repo_root().join("python/patronus_ark/dlp_synth/generators.json"))
        .expect("generator spec must load")
}

fn rule_map() -> RuleMap {
    let raw = std::fs::read_to_string(repo_root().join("python/patronus_ark/dlp_synth/rules.json"))
        .expect("rules.json must exist");
    let map: RuleMap = serde_json::from_str(&raw).expect("valid rules.json");
    assert_eq!(map.version, 1);
    map
}

/// First 24 hex digits of SHA-256, as recorded by `recipes.fingerprint`.
fn fingerprint(text: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref()[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_content_group(group: &str) -> bool {
    group.starts_with("dlp.content.") || group.starts_with("dlp.internal.")
}

#[test]
fn every_dlp_pattern_has_generators_or_is_a_content_rule() {
    let map = rule_map();
    let generators = generators();
    let known = generators.names().into_iter().collect::<BTreeSet<_>>();
    let mut referenced = BTreeSet::new();
    for pattern in DLP_PATTERNS {
        let rule = pattern.name;
        if is_content_group(pattern.entity_group) {
            assert!(map.content_rules.contains_key(rule), "{rule}: content rule");
            assert!(!map.rules.contains_key(rule), "{rule}: content rule");
            continue;
        }
        let entry = map
            .rules
            .get(rule)
            .unwrap_or_else(|| panic!("{rule}: no generator in rules.json"));
        assert!(!entry.generators.is_empty(), "{rule}");
        assert!(entry.probes.len() >= 2, "{rule}: need at least two probes");
        for name in entry
            .generators
            .iter()
            .chain(&entry.shape_only)
            .chain(&entry.weak)
            .chain(&entry.quoted)
            .chain(&entry.url_encoded)
            .chain(&entry.lookalike)
        {
            assert!(known.contains(name.as_str()), "{rule}: unknown {name}");
            referenced.insert(name.as_str());
        }
        assert!(
            entry
                .generators
                .iter()
                .all(|name| !entry.shape_only.contains(name)),
            "{rule}: generator listed as valid and shape_only"
        );
        assert!(
            entry
                .lookalike
                .iter()
                .all(|name| !entry.generators.contains(name) && !entry.weak.contains(name)),
            "{rule}: generator listed as reported and lookalike"
        );
    }
    let patterns = DLP_PATTERNS
        .iter()
        .map(|pattern| pattern.name.to_owned())
        .collect::<BTreeSet<_>>();
    let mapped = map
        .rules
        .keys()
        .chain(map.content_rules.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        mapped, patterns,
        "rules.json must list exactly DLP_PATTERNS"
    );
    for (entity, entry) in &map.baseline_entities {
        assert!(
            !patterns.contains(entity),
            "{entity}: a baseline entity is no rule"
        );
        assert!(
            !entry.generators.is_empty() && !entry.lookalike.is_empty(),
            "{entity}"
        );
        for name in entry.generators.iter().chain(&entry.lookalike) {
            assert!(known.contains(name.as_str()), "{entity}: unknown {name}");
            assert!(
                referenced.insert(name.as_str()),
                "{entity}: {name} already belongs to a rule"
            );
        }
    }
    assert_eq!(
        referenced, known,
        "every generator belongs to a rule or a baseline entity"
    );
}

#[test]
fn rust_generators_match_the_pinned_python_vectors() {
    let raw =
        std::fs::read_to_string(repo_root().join("rust/tests/fixtures/dlp_synth_vectors.json"))
            .expect("vector fixture must exist");
    let vectors: Vectors = serde_json::from_str(&raw).expect("valid vector fixture");
    let generators = generators();
    assert_eq!(
        vectors
            .generators
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        generators.names()
    );
    for (name, expected) in &vectors.generators {
        let values = vectors
            .seeds
            .iter()
            .map(|seed| generators.generate(name, *seed).unwrap())
            .collect::<Vec<_>>();
        for value in &values {
            assert_eq!(
                value.chars().count(),
                generators.length(name).unwrap(),
                "{name}"
            );
        }
        assert_eq!(&fingerprint(&values.join("\n")), expected, "{name}");
    }
}

#[test]
fn each_rule_reports_exactly_its_generated_values() {
    let map = rule_map();
    let generators = generators();
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    for (rule, entry) in &map.rules {
        let mut gates = ScanGateMatrix::default();
        for pattern in DLP_PATTERNS {
            gates.set_rule(pattern.name, pattern.name == rule);
        }
        gateway.set_execution_gates(gates);
        let values = entry
            .generators
            .iter()
            .chain(&entry.weak)
            .map(|name| (name, "<<secret:0>>"))
            .chain(entry.quoted.iter().map(|name| (name, "\"<<secret:0>>\"")))
            .chain(
                entry
                    .url_encoded
                    .iter()
                    .map(|name| (name, "<<secret:0|url>>")),
            );
        for (name, placeholder) in values {
            for probe in &entry.probes {
                let probe = probe.replace("<<secret:0>>", placeholder);
                for seed in 0..32 {
                    let recipes = [SecretRecipe::new(name, seed)];
                    let (text, spans) = materialize(&generators, &probe, &recipes).unwrap();
                    let predicted = gateway
                        .scan_category(SecurityCategory::Dlp, &text)
                        .into_iter()
                        .filter(|result| result.model == "native:dlp")
                        .flat_map(|result| result.evidence_spans)
                        .map(|span| (span.start_char, span.end_char))
                        .collect::<BTreeSet<_>>();
                    assert_eq!(
                        predicted,
                        BTreeSet::from([spans[0]]),
                        "{rule} gen={name} seed={seed} probe={probe:?}"
                    );
                }
            }
        }
    }
    gateway.set_execution_gates(ScanGateMatrix::default());
}

#[test]
fn rules_do_not_report_their_lookalike_values() {
    // F03: a token shape with a wrong check value or length is no match for its rule.
    let map = rule_map();
    let generators = generators();
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    let mut checked = 0;
    for (rule, entry) in &map.rules {
        let mut gates = ScanGateMatrix::default();
        for pattern in DLP_PATTERNS {
            gates.set_rule(pattern.name, pattern.name == rule);
        }
        gateway.set_execution_gates(gates);
        for name in &entry.lookalike {
            for probe in &entry.probes {
                for seed in 0..32 {
                    let recipes = [SecretRecipe::new(name, seed)];
                    let (text, _) = materialize(&generators, probe, &recipes).unwrap();
                    let predicted = gateway
                        .scan_category(SecurityCategory::Dlp, &text)
                        .into_iter()
                        .filter(|result| result.model == "native:dlp")
                        .flat_map(|result| result.evidence_spans)
                        .collect::<Vec<_>>();
                    assert!(
                        predicted.is_empty(),
                        "{rule} gen={name} seed={seed} probe={probe:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    gateway.set_execution_gates(ScanGateMatrix::default());
    assert!(checked > 0, "no lookalike generator");
}
