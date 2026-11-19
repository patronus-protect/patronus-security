use std::collections::HashMap;

use super::*;
use crate::{
    DecisionCandidate, DecisionEnvelope, DecisionProvenance, DecisionRecommendation,
    DecisionResult, DecisionTerminality, LayerResult, NativeResult,
};

/// A fake model that counts its calls and answers with a fixed score.
struct Fake {
    layer: SecurityLevel,
    score: f64,
    threshold: f64,
    escalate_at: Option<f64>,
    calls: usize,
}

impl Fake {
    fn new(layer: SecurityLevel, score: f64) -> Self {
        Self {
            layer,
            score,
            threshold: 0.9,
            escalate_at: None,
            calls: 0,
        }
    }
}

impl LayerModel for Fake {
    fn layer(&self) -> SecurityLevel {
        self.layer
    }
    fn module(&self) -> SecurityCategory {
        SecurityCategory::Injection
    }
    fn infer(&mut self, _text: &str, _control: &ScanControl) -> Result<LayerOutput, ScanError> {
        self.calls += 1;
        let matched = self.score >= self.threshold;
        Ok(LayerOutput {
            result: LayerResult {
                level: self.layer.as_str().into(),
                layer_type: "fake".into(),
                class_name: if matched { "attack" } else { "benign" }.into(),
                confidence: self.score,
                matched,
                duration_ms: 0.0,
                thresholds: HashMap::new(),
                details: HashMap::new(),
            },
            escalation: self.escalate_at.map(|threshold| EscalationSignal {
                score: self.score,
                threshold,
                spans: Vec::new(),
                source: "fake".into(),
            }),
        })
    }
}

/// An injection L1 result with a scored candidate.
fn l1(score: f64, accepted: bool) -> NativeResult {
    NativeResult {
        category: "injection".into(),
        class_name: if accepted { "injection" } else { "safe" }.into(),
        confidence: if accepted { score } else { 1.0 - score },
        level: "L1".into(),
        model: "ark.injection.l1".into(),
        duration_ms: 0.0,
        layers: Vec::new(),
        evidence_spans: Vec::new(),
        label_scores: Vec::new(),
        decision: Some(DecisionEnvelope {
            schema_version: "ark.decision.v1".into(),
            final_result: DecisionResult {
                class_name: "safe".into(),
                confidence: 1.0 - score,
                source: "default".into(),
            },
            decision_candidate: Some(DecisionCandidate {
                source: "l1".into(),
                class_name: "injection".into(),
                confidence: score,
                acceptance_threshold: 0.7,
                accepted,
                evidence: None,
                chunk_evidence: None,
            }),
            recommendation: DecisionRecommendation {
                accepted,
                final_arbitration: "default".into(),
                operating_point: "v".into(),
                acceptance_threshold: Some(0.7),
            },
            candidates: Vec::new(),
            terminality: DecisionTerminality {
                completion: "complete".into(),
                degraded: false,
                degradation_reason: None,
            },
            provenance: DecisionProvenance {
                ark_version: "0".into(),
                schema_version: "ark.decision.v1".into(),
                model: "ark.injection.l1".into(),
            },
        }),
    }
}

fn cascade(clear: Option<f64>) -> Cascade {
    let mut config = CascadeConfig::default();
    config.modules.insert(
        SecurityCategory::Injection,
        ModuleThresholds {
            clear_threshold: clear,
        },
    );
    Cascade::new(config).unwrap()
}

fn run(cascade: &Cascade, l1_result: &NativeResult, l3: &mut Fake) -> ModuleDecision {
    let stage = cascade.l1_stage(SecurityCategory::Injection, [l1_result]);
    cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &mut [],
            Some(l3),
            &ScanControl::default(),
        )
        .unwrap()
}

#[test]
fn l1_detection_is_final_and_skips_l3() {
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    let decision = run(&cascade(None), &l1(0.8, true), &mut l3);
    assert_eq!(l3.calls, 0);
    assert_eq!(decision.outcome, StageOutcome::Detected);
    assert_eq!(decision.decided_by, Stage::Heuristic);
    assert_eq!(decision.score, 0.8);
}

#[test]
fn l1_clear_below_the_clear_threshold_skips_l3() {
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    let decision = run(&cascade(Some(0.3)), &l1(0.1, false), &mut l3);
    assert_eq!(l3.calls, 0);
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Clear, Stage::Heuristic)
    );
}

#[test]
fn undecided_l1_escalates_to_l3() {
    for (clear, score) in [(None, 0.0), (Some(0.3), 0.3), (Some(0.3), 0.5)] {
        let mut l3 = Fake::new(SecurityLevel::L3, 0.95);
        let decision = run(&cascade(clear), &l1(score, false), &mut l3);
        assert_eq!(l3.calls, 1, "clear {clear:?} score {score}");
        assert_eq!(
            (decision.outcome, decision.decided_by, decision.score),
            (StageOutcome::Detected, Stage::L3, 0.95)
        );
    }
    let mut benign = Fake::new(SecurityLevel::L3, 0.2);
    let decision = run(&cascade(None), &l1(0.4, false), &mut benign);
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Clear, Stage::L3)
    );
}

#[test]
fn escalation_without_a_configured_later_layer_is_clear() {
    let cascade = cascade(None);
    let stage = cascade.l1_stage(SecurityCategory::Injection, [&l1(0.5, false)]);
    assert_eq!(stage.outcome, StageOutcome::Escalate);
    let decision = cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &mut [],
            None,
            &ScanControl::default(),
        )
        .unwrap();
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Clear, Stage::Heuristic)
    );

    // A max level of L1 keeps a configured L3 from running.
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    let capped = Cascade::new(CascadeConfig {
        max_level: SecurityLevel::L1,
        ..CascadeConfig::default()
    })
    .unwrap();
    let decision = run(&capped, &l1(0.5, false), &mut l3);
    assert_eq!(l3.calls, 0);
    assert_eq!(decision.outcome, StageOutcome::Clear);
}

#[test]
fn l2_runs_first_and_l3_only_when_l2_escalates() {
    let cascade = cascade(None);
    let mut l3 = Fake::new(SecurityLevel::L3, 0.97);
    let mut l2 = Fake::new(SecurityLevel::L2, 0.4);
    let stage = cascade.l1_stage(SecurityCategory::Injection, [&l1(0.5, false)]);
    let decision = cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &mut [&mut l2],
            Some(&mut l3),
            &ScanControl::default(),
        )
        .unwrap();
    assert_eq!((l2.calls, l3.calls), (1, 0));
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Clear, Stage::L2)
    );

    let mut l2 = Fake::new(SecurityLevel::L2, 0.4);
    l2.escalate_at = Some(0.3);
    let stage = cascade.l1_stage(SecurityCategory::Injection, [&l1(0.5, false)]);
    let decision = cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &mut [&mut l2],
            Some(&mut l3),
            &ScanControl::default(),
        )
        .unwrap();
    assert_eq!((l2.calls, l3.calls), (1, 1));
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Detected, Stage::L3)
    );
}

#[test]
fn conditional_gate_keeps_l3_from_running() {
    let config: CascadeConfig = serde_json::from_value(serde_json::json!({
        "conditional": [{
            "level": "l3",
            "pipeline": "injection",
            "when": {"metadata": {"path": "tenant", "exists": true}}
        }]
    }))
    .unwrap();
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    let decision = run(&Cascade::new(config).unwrap(), &l1(0.5, false), &mut l3);
    assert_eq!(l3.calls, 0);
    assert_eq!(decision.outcome, StageOutcome::Clear);
}

#[test]
fn l3_executor_ignores_other_modules_and_layers() {
    let mut l2 = Fake::new(SecurityLevel::L2, 0.99);
    let signal = EscalationSignal {
        score: 0.5,
        threshold: 0.0,
        spans: Vec::new(),
        source: "s".into(),
    };
    let control = ScanControl::default();
    assert!(l2
        .execute_l3(SecurityCategory::Injection, "t", &signal, &control)
        .unwrap()
        .is_none());
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    assert!(l3
        .execute_l3(SecurityCategory::Jailbreak, "t", &signal, &control)
        .unwrap()
        .is_none());
    assert_eq!(l2.calls + l3.calls, 0);
}

#[test]
fn evidence_without_a_decision_envelope_counts_as_detected() {
    let mut result = l1(0.0, false);
    result.decision = None;
    result.category = "pii".into();
    let cascade = Cascade::default();
    let stage = cascade.l1_stage(SecurityCategory::Pii, [&result]);
    assert_eq!(stage.outcome, StageOutcome::Escalate);
    result.evidence_spans.push(crate::EvidenceSpan {
        label: "email".into(),
        text: "x".into(),
        score: 0.9,
        start_byte: 0,
        end_byte: 1,
        start_char: 0,
        end_char: 1,
    });
    result.confidence = 0.9;
    let stage = cascade.l1_stage(SecurityCategory::Pii, [&result]);
    assert_eq!((stage.outcome, stage.score), (StageOutcome::Detected, 0.9));
}

#[test]
fn cascade_config_serde_round_trips_and_validates() {
    let value = serde_json::json!({
        "max_level": "L2",
        "conditional": [],
        "modules": {"injection": {"clear_threshold": 0.25}}
    });
    let config: CascadeConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&config).unwrap(), value);
    assert_eq!(
        serde_json::from_value::<CascadeConfig>(serde_json::json!({})).unwrap(),
        CascadeConfig::default()
    );
    for invalid in [
        serde_json::json!({"modules": {"injection": {"clear_threshold": 1.5}}}),
        serde_json::json!({"conditional": [{"level": "l1", "when": {"metadata": {"path": "a", "exists": true}}}]}),
        serde_json::json!({"max_level": "L4"}),
        serde_json::json!({"unknown": true}),
    ] {
        let parsed = serde_json::from_value::<CascadeConfig>(invalid.clone())
            .map_err(|error| error.to_string())
            .and_then(|config| config.validate());
        assert!(parsed.is_err(), "{invalid}");
    }
    let decision = ModuleDecision {
        module: SecurityCategory::Injection,
        outcome: StageOutcome::Detected,
        decided_by: Stage::L1Model,
        score: 0.5,
    };
    assert_eq!(
        serde_json::to_value(decision).unwrap(),
        serde_json::json!({"module": "injection", "outcome": "detected", "decided_by": "l1_model", "score": 0.5})
    );
}

#[test]
fn l1_stage_decision_is_final_only_when_l1_does_not_escalate() {
    let cascade = Cascade::default();
    let detected = cascade.l1_stage(SecurityCategory::Injection, [&l1(0.95, true)]);
    assert_eq!(
        detected.decision(SecurityCategory::Injection),
        Some(ModuleDecision {
            module: SecurityCategory::Injection,
            outcome: StageOutcome::Detected,
            decided_by: Stage::Heuristic,
            score: 0.95,
        })
    );
    let undecided = cascade.l1_stage(SecurityCategory::Injection, [&l1(0.5, false)]);
    assert_eq!(undecided.decision(SecurityCategory::Injection), None);
}

#[test]
fn each_level_maps_to_the_stage_that_answers_there() {
    assert_eq!(
        [SecurityLevel::L1, SecurityLevel::L2, SecurityLevel::L3].map(Stage::from),
        [Stage::Heuristic, Stage::L2, Stage::L3]
    );
}
