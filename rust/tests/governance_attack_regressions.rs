// SPDX-License-Identifier: GPL-3.0-only
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    source_id: String,
    source_file: String,
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
        vec![SecurityCategory::Injection],
        SecurityLevel::L1,
        None,
        false,
    )
}

#[test]
fn governance_attack_goldens_preserve_terminal_and_nonterminal_taxonomy() {
    let gateway = gateway();
    for case in fixture().cases {
        let result = gateway
            .scan_category(SecurityCategory::Injection, &case.text)
            .into_iter()
            .find(|result| result.model == "native:injection_l1")
            .expect("aggregated native Injection L1 result");
        let context = format!(
            "{} from {} ({}) — {}",
            case.id, case.source_id, case.source_file, case.rationale
        );
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
            ExpectedCategory::Nonterminal => assert_eq!(
                result.class_name, "safe",
                "{context} must remain nonterminal: {result:#?}"
            ),
        }
    }
}
