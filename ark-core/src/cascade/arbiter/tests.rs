use super::*;

/// One binary pipeline `p`: classes `attack`/`benign`, L2 0.5, L3 0.8 and a
/// union `0.5 * l2 + 0.5 * l3 >= 0.6`.
struct Table {
    union: bool,
}

impl ThresholdTable for Table {
    fn operating_point(&self) -> &str {
        "test_point"
    }
    fn default_class(&self, _pipeline: &str) -> &str {
        "benign"
    }
    fn threshold(&self, _pipeline: &str, layer: SecurityLevel, class_name: &str) -> Option<f64> {
        (class_name == "attack").then_some(match layer {
            SecurityLevel::L3 => 0.8,
            _ => 0.5,
        })
    }
    fn union_policies(&self, _pipeline: &str) -> Vec<(&str, UnionPolicy)> {
        if !self.union {
            return Vec::new();
        }
        vec![(
            "attack",
            UnionPolicy {
                threshold: 0.6,
                l2_weight: 0.5,
                l3_weight: 0.5,
            },
        )]
    }
    fn binary_positive_class(&self, _pipeline: &str) -> Option<&str> {
        Some("attack")
    }
}

fn result(class_name: &str, confidence: f64, level: &str) -> NativeResult {
    NativeResult {
        category: "p".into(),
        class_name: class_name.into(),
        confidence,
        level: level.into(),
        model: "m".into(),
        duration_ms: 0.0,
        layers: vec![LayerResult {
            level: level.into(),
            layer_type: "model".into(),
            class_name: class_name.into(),
            confidence,
            matched: true,
            duration_ms: 0.0,
            thresholds: HashMap::new(),
            details: HashMap::new(),
        }],
        evidence_spans: Vec::new(),
        label_scores: Vec::new(),
        decision: None,
    }
}

fn arbitration(result: &NativeResult) -> &str {
    result.layers[0].details["final_arbitration"]
        .as_str()
        .unwrap()
}

#[test]
fn accepted_l3_wins_over_l2() {
    let table = Table { union: true };
    let out = arbitrate_l3_l2(
        &table,
        "p",
        Some(result("attack", 0.9, "L3")),
        result("attack", 0.99, "L2"),
    )
    .unwrap();
    assert_eq!((out.level.as_str(), arbitration(&out)), ("L3", "l3"));
    let decision = out.decision.unwrap();
    assert_eq!(decision.recommendation.operating_point, "test_point");
    assert_eq!(decision.decision_candidate.unwrap().source, "l3");
}

#[test]
fn rejected_l3_falls_back_to_union_then_l2_then_default() {
    // Union: 0.5 * 0.7 + 0.5 * 0.7 = 0.7 >= 0.6.
    let out = arbitrate_l3_l2(
        &Table { union: true },
        "p",
        Some(result("attack", 0.7, "L3")),
        result("attack", 0.7, "L2"),
    )
    .unwrap();
    assert_eq!(
        (out.class_name.as_str(), arbitration(&out)),
        ("attack", "union")
    );
    assert_eq!(out.layers[0].thresholds["union"], 0.6);

    let out = arbitrate_l3_l2(
        &Table { union: false },
        "p",
        Some(result("attack", 0.7, "L3")),
        result("attack", 0.6, "L2"),
    )
    .unwrap();
    assert_eq!((out.level.as_str(), arbitration(&out)), ("L2", "l2"));

    let out = arbitrate_l3_l2(
        &Table { union: false },
        "p",
        Some(result("attack", 0.7, "L3")),
        result("attack", 0.2, "L2"),
    )
    .unwrap();
    assert_eq!(out.class_name, "benign");
    assert!((out.confidence - 0.3).abs() < 1e-12);
    assert_eq!(arbitration(&out), "default");
    let decision = out.decision.unwrap();
    assert!(!decision.recommendation.accepted);
    assert_eq!(decision.decision_candidate.unwrap().source, "l3");
}

#[test]
fn direct_l3_placeholder_without_output_is_returned_for_degradation() {
    let placeholder = result("pending", 0.0, "L3");
    let err = arbitrate_l3_l2(&Table { union: true }, "p", None, placeholder).unwrap_err();
    assert_eq!(err.class_name, "pending");

    let out = arbitrate_l3_l2(
        &Table { union: true },
        "p",
        Some(result("attack", 0.85, "L3")),
        result("pending", 0.0, "L3"),
    )
    .unwrap();
    assert_eq!(out.class_name, "attack");
    assert!(out
        .decision
        .unwrap()
        .candidates
        .iter()
        .all(|candidate| candidate.source == "l3"));
}

#[test]
fn l2_alone_is_accepted_or_defaulted() {
    let table = Table { union: false };
    let accepted = arbitrate_l2(&table, "p", result("attack", 0.6, "L2"));
    assert_eq!(arbitration(&accepted), "l2");
    let rejected = arbitrate_l2(&table, "p", result("attack", 0.4, "L2"));
    assert_eq!(rejected.class_name, "benign");
    assert_eq!(arbitration(&rejected), "default");

    let (thresholded, decision) = threshold_l2_result(
        &table,
        "p",
        EvaluationResult {
            class_name: "attack".into(),
            confidence: 0.4,
            level: "L2".into(),
        },
    );
    assert_eq!(decision, LayerDecision::Default);
    assert_eq!(
        (thresholded.class_name.as_str(), thresholded.confidence),
        ("benign", 0.0)
    );
    assert!(!accepts_class(
        &table,
        "p",
        SecurityLevel::L2,
        "benign",
        1.0
    ));
    assert!(!accepts_class(&table, "p", SecurityLevel::L2, "other", 1.0));
}

#[test]
fn sync_final_layers_updates_pending_fallback() {
    let mut out = result("attack", 0.9, "L2");
    out.layers.push(LayerResult {
        layer_type: "l3_pending".into(),
        level: "L3".into(),
        ..out.layers[0].clone()
    });
    out.set_class("benign".into(), 0.1);
    sync_final_layers(&mut out);
    assert_eq!(out.layers[0].class_name, "benign");
    assert_eq!(out.layers[1].details["fallback_class"], "benign");
}
