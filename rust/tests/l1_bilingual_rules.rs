// SPDX-License-Identifier: GPL-3.0-only
use patronus_ark::{
    detectors::{dlp::dlp::DLP_PATTERNS, pii::pii::PII_PATTERNS},
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Deserialize)]
struct Case {
    category: String,
    rule_id: String,
    de: String,
    en: String,
    /// Provider-format DLP values are generator recipes (`<<secret:0>>` in
    /// `de`/`en`), materialized here so the fixture holds no plaintext token.
    #[serde(default)]
    secrets: Vec<SecretRecipe>,
    /// Lookalikes per language (T07: placeholders and environment/template
    /// references) that no DLP rule may report.
    #[serde(default)]
    hard_negatives: BTreeMap<String, Vec<String>>,
    language_neutral: bool,
}

impl Case {
    fn texts(&self, generators: &GeneratorSet) -> [(&'static str, String); 2] {
        let text = |template: &str| {
            if self.secrets.is_empty() {
                return template.to_owned();
            }
            materialize(generators, template, &self.secrets)
                .unwrap_or_else(|error| panic!("{}: {error}", self.rule_id))
                .0
        };
        [("de", text(&self.de)), ("en", text(&self.en))]
    }
}

#[test]
fn every_pii_and_dlp_rule_is_reachable_with_bilingual_source_evidence() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let expected: BTreeSet<_> = PII_PATTERNS
        .iter()
        .map(|p| p.name)
        .chain(DLP_PATTERNS.iter().map(|p| p.name))
        .collect();
    let actual: BTreeSet<_> = cases.iter().map(|case| case.rule_id.as_str()).collect();
    assert_eq!(
        actual, expected,
        "every registered rule needs DE/EN fixtures"
    );
    assert_eq!(actual.len(), cases.len(), "duplicate fixtures");
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii, SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    gateway.set_execution_gates(ScanGateMatrix::all_enabled());
    let generators = GeneratorSet::load(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../python/patronus_ark/dlp_synth/generators.json"),
    )
    .expect("generator spec must load");
    let mut missing = Vec::new();
    for case in cases {
        assert!(
            case.language_neutral || case.de != case.en,
            "translate {}",
            case.rule_id
        );
        for (language, text) in case.texts(&generators) {
            let text = &text;
            let category = if case.category == "pii" {
                SecurityCategory::Pii
            } else {
                SecurityCategory::Dlp
            };
            let model = format!("native:{}", case.category);
            let results = gateway.scan_category(category, text);
            let result = results.iter().find(|r| r.model == model).unwrap();
            let matched = result.layers[0]
                .details
                .get("matched_rules")
                .and_then(|r| r.as_array())
                .and_then(|rules| rules.iter().find(|r| r["rule_id"] == case.rule_id));
            let Some(matched) = matched else {
                missing.push(format!("{} ({language}): {text:?}", case.rule_id));
                continue;
            };
            let components = matched["components"].as_array().unwrap();
            assert!(
                !components.is_empty(),
                "missing evidence for {}",
                case.rule_id
            );
            for component in components {
                let start = component["start_byte"].as_u64().unwrap() as usize;
                let end = component["end_byte"].as_u64().unwrap() as usize;
                assert!(
                    start < end && text.get(start..end).is_some(),
                    "invalid source evidence"
                );
            }
            assert!(!result.evidence_spans.is_empty());
        }
    }
    assert!(missing.is_empty(), "unreachable rules: {missing:#?}");
}

#[test]
fn dlp_hard_negatives_are_silent_in_de_and_en() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    let mut reported = Vec::new();
    let mut rules = 0;
    for case in cases.iter().filter(|case| !case.hard_negatives.is_empty()) {
        assert_eq!(case.category, "dlp", "{}", case.rule_id);
        for language in ["de", "en"] {
            let texts = case
                .hard_negatives
                .get(language)
                .map_or(&[][..], Vec::as_slice);
            assert!(
                !texts.is_empty(),
                "{}: no {language} hard negative",
                case.rule_id
            );
        }
        assert_eq!(case.hard_negatives.len(), 2, "{}: only de/en", case.rule_id);
        rules += 1;
        for (language, text) in case
            .hard_negatives
            .iter()
            .flat_map(|(language, texts)| texts.iter().map(move |text| (language, text)))
        {
            let spans = gateway
                .scan_category(SecurityCategory::Dlp, text)
                .into_iter()
                .flat_map(|result| result.evidence_spans)
                .map(|span| span.text)
                .collect::<Vec<_>>();
            if !spans.is_empty() {
                reported.push(format!(
                    "{} ({language}): {text:?} -> {spans:?}",
                    case.rule_id
                ));
            }
        }
    }
    assert!(rules >= 8, "T07 hard negatives missing");
    assert!(
        reported.is_empty(),
        "hard negatives reported: {reported:#?}"
    );
}
