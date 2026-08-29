// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashSet;

use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use serde_json::json;

use super::signal::{detection_from_signals, InjectionReference, InjectionSignal};
use crate::detectors::NativeDetection;
use crate::EvaluationResult;

const CATALOG_JSONS: [(&str, &str); 2] = [
    (
        "rust/src/detectors/injection/rules/prompt_armor_95e532e.json",
        include_str!("rules/prompt_armor_95e532e.json"),
    ),
    (
        "rust/src/detectors/injection/rules/source_derived_p0_0_1_6.json",
        include_str!("rules/source_derived_p0_0_1_6.json"),
    ),
];

#[derive(Debug, Deserialize)]
struct RuleCatalog {
    schema_version: u32,
    catalog_id: String,
    source: String,
    source_revision: String,
    license: String,
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Deserialize)]
struct RuleDefinition {
    id: String,
    upstream_id: String,
    family: String,
    severity: String,
    upstream_weight: f64,
    description: String,
    #[serde(default)]
    adaptation: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    source_revision: Option<String>,
    #[serde(default)]
    source_license: Option<String>,
    #[serde(default)]
    source_file: Option<String>,
    #[serde(default)]
    references: Vec<InjectionReference>,
    pattern: String,
}

#[derive(Debug)]
struct CompiledCatalog {
    catalog: RuleCatalog,
    regex_set: RegexSet,
    regexes: Vec<Regex>,
    embedded_file: String,
}

#[derive(Debug)]
pub struct InjectionRuleCatalogPipeline {
    catalogs: Vec<CompiledCatalog>,
}

impl InjectionRuleCatalogPipeline {
    pub fn new() -> Self {
        let catalogs = CATALOG_JSONS
            .into_iter()
            .map(|(embedded_file, catalog_json)| {
                let catalog: RuleCatalog = serde_json::from_str(catalog_json)
                    .expect("embedded injection rule catalog must parse");
                validate_catalog(&catalog);
                let patterns = catalog
                    .rules
                    .iter()
                    .map(|rule| rule.pattern.as_str())
                    .collect::<Vec<_>>();
                let regex_set = RegexSetBuilder::new(&patterns)
                    .case_insensitive(true)
                    .build()
                    .expect("embedded injection rule catalog patterns must compile");
                let regexes = patterns
                    .iter()
                    .map(|pattern| {
                        RegexBuilder::new(pattern)
                            .case_insensitive(true)
                            .build()
                            .expect("embedded injection rule must compile")
                    })
                    .collect();
                CompiledCatalog {
                    catalog,
                    regex_set,
                    regexes,
                    embedded_file: embedded_file.to_string(),
                }
            })
            .collect();

        Self { catalogs }
    }

    pub(crate) fn detect(&self, text: &str) -> NativeDetection {
        let mut matches = Vec::new();
        for compiled in &self.catalogs {
            let candidates = compiled.regex_set.matches(text);
            for index in candidates.iter() {
                let rule = &compiled.catalog.rules[index];
                for matched in compiled.regexes[index].find_iter(text) {
                    matches.push((compiled, rule, matched.start(), matched.end()));
                }
            }
        }
        if matches.is_empty() {
            return safe_detection();
        }
        matches.sort_by_key(|(_, rule, start, end)| (*start, *end, rule.id.as_str()));

        let mut signals = matches
            .iter()
            .map(|(compiled, rule, start, end)| InjectionSignal {
                rule_id: rule.id.clone(),
                upstream_id: Some(rule.upstream_id.clone()),
                family: rule.family.clone(),
                severity: rule.severity.clone(),
                description: rule.description.clone(),
                source: rule
                    .source
                    .clone()
                    .unwrap_or_else(|| compiled.catalog.source.clone()),
                source_revision: rule
                    .source_revision
                    .clone()
                    .unwrap_or_else(|| compiled.catalog.source_revision.clone()),
                source_license: Some(
                    rule.source_license
                        .clone()
                        .unwrap_or_else(|| compiled.catalog.license.clone()),
                ),
                source_file: Some(
                    rule.source_file
                        .clone()
                        .unwrap_or_else(|| compiled.embedded_file.clone()),
                ),
                provenance_weight: Some(rule.upstream_weight),
                adaptation: rule.adaptation.clone(),
                references: rule.references.clone(),
                start_byte: *start,
                end_byte: *end,
                span_precision: "exact",
                feature_kind: "rule_match",
                components: Vec::new(),
            })
            .collect::<Vec<_>>();
        signals.dedup_by(|left, right| {
            left.rule_id == right.rule_id
                && left.start_byte == right.start_byte
                && left.end_byte == right.end_byte
        });

        let decisive = matches
            .iter()
            .max_by(|(_, left, _, _), (_, right, _, _)| {
                severity_rank(&left.severity)
                    .cmp(&severity_rank(&right.severity))
                    .then_with(|| left.upstream_weight.total_cmp(&right.upstream_weight))
            })
            .map(|(compiled, rule, _, _)| (*compiled, *rule))
            .expect("matched catalog must contain a decisive rule");
        let mut detection = detection_from_signals(
            EvaluationResult {
                class_name: decisive.1.family.clone(),
                confidence: 1.0,
                level: "L1".to_string(),
            },
            text,
            signals,
            Some("ark-injection-rule-catalog-v1"),
        );
        let catalog_ids = matches
            .iter()
            .map(|(compiled, _, _, _)| compiled.catalog.catalog_id.as_str())
            .collect::<HashSet<_>>();
        let mut catalog_ids = catalog_ids.into_iter().collect::<Vec<_>>();
        catalog_ids.sort_unstable();
        detection
            .details
            .insert("catalog_ids".to_string(), json!(catalog_ids));
        detection.details.insert(
            "catalog_id".to_string(),
            json!(decisive.0.catalog.catalog_id),
        );
        detection.details.insert(
            "catalog_schema_version".to_string(),
            json!(decisive.0.catalog.schema_version),
        );
        detection.details.insert(
            "source".to_string(),
            json!(decisive
                .1
                .source
                .as_ref()
                .unwrap_or(&decisive.0.catalog.source)),
        );
        detection.details.insert(
            "source_revision".to_string(),
            json!(decisive
                .1
                .source_revision
                .as_ref()
                .unwrap_or(&decisive.0.catalog.source_revision)),
        );
        detection.details.insert(
            "source_license".to_string(),
            json!(decisive
                .1
                .source_license
                .as_ref()
                .unwrap_or(&decisive.0.catalog.license)),
        );
        detection
    }
}

fn validate_catalog(catalog: &RuleCatalog) {
    assert_eq!(catalog.schema_version, 1, "unsupported rule catalog schema");
    assert!(
        !catalog.source_revision.is_empty(),
        "catalog revision is required"
    );
    let mut ids = HashSet::new();
    let mut upstream_ids = HashSet::new();
    for rule in &catalog.rules {
        assert!(ids.insert(&rule.id), "duplicate Ark rule ID: {}", rule.id);
        assert!(
            upstream_ids.insert(&rule.upstream_id),
            "duplicate upstream rule ID: {}",
            rule.upstream_id
        );
        assert!(
            (0.0..=1.0).contains(&rule.upstream_weight),
            "invalid upstream weight for {}",
            rule.id
        );
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn safe_detection() -> NativeDetection {
    detection_from_signals(
        EvaluationResult {
            class_name: "safe".to_string(),
            confidence: 1.0,
            level: "L1".to_string(),
        },
        "",
        Vec::new(),
        None,
    )
}

impl Default for InjectionRuleCatalogPipeline {
    fn default() -> Self {
        Self::new()
    }
}
