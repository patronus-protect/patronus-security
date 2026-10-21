//! PII golden schema v2 (E10): every row names the `pii_*` rule it exercises.
//! These static checks tie the declared rule ids to `PII_PATTERNS`; the dynamic
//! side (the rule really reports the gold span) runs in `13_l1_golden_eval`.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use patronus_ark::detectors::pii::pii::PII_PATTERNS;
use serde::Deserialize;

const LANGUAGES: [&str; 2] = ["de", "en"];
const MIN_PER_LANGUAGE: usize = 5;

#[derive(Deserialize)]
struct Row {
    id: String,
    schema_version: u32,
    language: String,
    case_type: String,
    target_label: String,
    rule_id: String,
    known_gap: bool,
}

fn rows() -> Vec<Row> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("pii_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid v2 golden row"))
        .collect()
}

fn group_of(rule_id: &str) -> Option<&'static str> {
    PII_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .map(|pattern| pattern.entity_group)
}

#[test]
fn rows_name_existing_rules_of_their_target_label() {
    for row in rows() {
        assert_eq!(row.schema_version, 2, "{}", row.id);
        let group = group_of(&row.rule_id)
            .unwrap_or_else(|| panic!("{}: unknown rule {}", row.id, row.rule_id));
        assert_eq!(group, row.target_label, "{}", row.id);
        if row.case_type != "positive" {
            assert_eq!(row.case_type, "hard_negative", "{}", row.id);
            assert!(
                !row.known_gap,
                "{}: only positives can be known gaps",
                row.id
            );
        }
    }
}

#[test]
fn every_pii_rule_has_gated_positives_in_both_languages_and_a_hard_negative() {
    let mut positives = BTreeSet::new();
    let mut negatives = BTreeSet::new();
    let rows = rows();
    for row in &rows {
        if row.case_type == "positive" && !row.known_gap {
            positives.insert((row.rule_id.as_str(), row.language.as_str()));
        } else if row.case_type == "hard_negative" {
            negatives.insert(row.rule_id.as_str());
        }
    }
    for pattern in PII_PATTERNS {
        for language in LANGUAGES {
            assert!(
                positives.contains(&(pattern.name, language)),
                "{} has no gated {language} positive",
                pattern.name
            );
        }
        assert!(
            negatives.contains(pattern.name),
            "{} has no hard negative",
            pattern.name
        );
    }
}

#[test]
fn every_pii_label_has_n_gated_positives_and_hard_negatives_per_language() {
    let mut counts = BTreeMap::<(String, String, String), usize>::new();
    for row in rows().into_iter().filter(|row| !row.known_gap) {
        *counts
            .entry((row.target_label, row.language, row.case_type))
            .or_default() += 1;
    }
    let labels = PII_PATTERNS
        .iter()
        .map(|pattern| pattern.entity_group)
        .collect::<BTreeSet<_>>();
    for label in labels {
        for language in LANGUAGES {
            for case_type in ["positive", "hard_negative"] {
                let count = counts
                    .get(&(label.to_owned(), language.to_owned(), case_type.to_owned()))
                    .copied()
                    .unwrap_or_default();
                assert!(
                    count >= MIN_PER_LANGUAGE,
                    "{label}/{language}/{case_type}: {count} < {MIN_PER_LANGUAGE}"
                );
            }
        }
    }
}

/// T26: FR/ES/IT/NL field names of the anchor rules, at least five gated positives and five
/// hard negatives per language, each naming a rule that binds a field name.
#[test]
fn fr_es_it_nl_field_names_have_n_gated_positives_and_hard_negatives() {
    const FIELD_LANGUAGES: [&str; 4] = ["fr", "es", "it", "nl"];
    let mut counts = BTreeMap::<(String, String), usize>::new();
    for row in rows().into_iter().filter(|row| !row.known_gap) {
        if !FIELD_LANGUAGES.contains(&row.language.as_str()) {
            assert!(LANGUAGES.contains(&row.language.as_str()), "{}", row.id);
            continue;
        }
        let pattern = PII_PATTERNS
            .iter()
            .find(|pattern| pattern.name == row.rule_id)
            .unwrap();
        assert!(
            pattern.captured_value,
            "{}: {} binds no field name",
            row.id, row.rule_id
        );
        *counts.entry((row.language, row.case_type)).or_default() += 1;
    }
    for language in FIELD_LANGUAGES {
        for case_type in ["positive", "hard_negative"] {
            let count = counts
                .get(&(language.to_owned(), case_type.to_owned()))
                .copied()
                .unwrap_or_default();
            assert!(
                count >= MIN_PER_LANGUAGE,
                "{language}/{case_type}: {count} < {MIN_PER_LANGUAGE}"
            );
        }
    }
}
