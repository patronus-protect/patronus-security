//! DLP golden schema v2 (E13): every row names the `dlp_*` rule it exercises.
//! These static checks tie the declared rule ids to `DLP_PATTERNS`; the dynamic
//! side (the rule really fires on the gold span) runs in `13_l1_golden_eval`.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use patronus_ark::detectors::dlp::dlp::DLP_PATTERNS;
use serde::Deserialize;

const LANGUAGES: [&str; 2] = ["de", "en"];

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
        .join("../python/patronus_ark/benchmark_data/dlp_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("dlp_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid v2 golden row"))
        .collect()
}

fn group_of(rule_id: &str) -> Option<&'static str> {
    DLP_PATTERNS
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
        if row.case_type == "positive" {
            assert_eq!(group, row.target_label, "{}", row.id);
        } else {
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
fn every_dlp_rule_has_gated_positives_in_both_languages_and_a_hard_negative() {
    let mut positives = BTreeMap::<(&str, String), usize>::new();
    let mut negatives = BTreeSet::new();
    let rows = rows();
    for row in &rows {
        if row.case_type == "positive" && !row.known_gap {
            *positives
                .entry((row.rule_id.as_str(), row.language.clone()))
                .or_default() += 1;
        } else if row.case_type == "hard_negative" {
            negatives.insert(row.rule_id.as_str());
        }
    }
    for pattern in DLP_PATTERNS {
        for language in LANGUAGES {
            assert!(
                positives.contains_key(&(pattern.name, language.to_owned())),
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
