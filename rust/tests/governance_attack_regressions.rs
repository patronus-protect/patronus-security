// SPDX-License-Identifier: GPL-3.0-only
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};
use patronus_ark_core::detectors::injection::signal::rule_category;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    text: String,
    expected_category: ExpectedCategory,
    rule_id: Option<String>,
    rationale: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedCategory {
    TerminalInjection,
    Nonterminal,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "fixtures/governance_attack_regressions_0_1_9.json"
    ))
    .expect("governance attack fixture must parse")
}

fn gateway() -> SecurityGateway {
    SecurityGateway::with_max_level(
        SecurityCategory::ATTACK_CLASSES.to_vec(),
        SecurityLevel::L1,
        None,
        false,
    )
}

#[test]
fn governance_attack_goldens_preserve_terminal_and_nonterminal_taxonomy() {
    let gateway = gateway();
    for case in fixture().cases {
        // An audited rule reports under its taxonomy class; a case without
        // one may be flagged by any attack class.
        let categories = case.rule_id.as_deref().map_or_else(
            || SecurityCategory::ATTACK_CLASSES.to_vec(),
            |rule_id| vec![rule_category(rule_id)],
        );
        let results: Vec<_> = categories
            .into_iter()
            .filter_map(|category| {
                gateway
                    .scan_category(category, &case.text)
                    .into_iter()
                    .find(|result| result.model == "native:injection_l1")
            })
            .collect();
        let result = results
            .iter()
            .find(|result| result.class_name != "safe")
            .or(results.first())
            .expect("aggregated native injection L1 result")
            .clone();
        let context = format!("{} — {}", case.id, case.rationale);
        match case.expected_category {
            ExpectedCategory::TerminalInjection => {
                assert_ne!(
                    result.class_name, "safe",
                    "{context} remained candidate-only: {result:#?}"
                );
                assert!(
                    result
                        .decision
                        .as_ref()
                        .is_some_and(|decision| decision.recommendation.accepted),
                    "{context} did not reach an accepted terminal decision: {result:#?}"
                );
                if let Some(rule_id) = case.rule_id.as_deref() {
                    assert!(
                        result.layers[0].details["l1_candidates"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .flat_map(|candidate| {
                                candidate["features"].as_array().into_iter().flatten()
                            })
                            .any(|feature| feature["provenance"]["rule_id"] == rule_id),
                        "{context} lacks its audited rule {rule_id}: {result:#?}"
                    );
                }
                assert!(
                    !result.evidence_spans.is_empty(),
                    "{context} lacks source evidence"
                );
            }
            // The injection L1 rules report across the attack classes, so a
            // nonterminal case must stay safe in every one of them.
            ExpectedCategory::Nonterminal => {
                for category in SecurityCategory::ATTACK_CLASSES {
                    for result in gateway
                        .scan_category(category, &case.text)
                        .into_iter()
                        .filter(|result| result.model == "native:injection_l1")
                    {
                        assert_eq!(
                            result.class_name, "safe",
                            "{context} must remain nonterminal: {result:#?}"
                        );
                    }
                }
            }
        }
    }
}
