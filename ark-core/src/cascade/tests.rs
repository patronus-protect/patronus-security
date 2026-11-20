use std::collections::HashMap;

use super::*;
use crate::native::ScoreMode;
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
        ModuleConfig {
            clear_threshold: clear,
            ..ModuleConfig::default()
        },
    );
    Cascade::new(config).unwrap()
}

fn run(cascade: &Cascade, l1_result: &NativeResult, l3: &mut Fake) -> ModuleDecision {
    let stage = cascade.l1_stage(SecurityCategory::Injection, ScoreMode::Strict, [l1_result]);
    cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &[],
            &mut [],
            Some(l3),
            &ScanControl::default(),
        )
        .unwrap()
        .expect("a stage ran")
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
    // Below the clear cut: the heuristic counts a score at or above a cut.
    for score in [0.1, 0.29] {
        let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
        let decision = run(&cascade(Some(0.3)), &l1(score, false), &mut l3);
        assert_eq!(l3.calls, 0);
        assert_eq!(
            (decision.outcome, decision.decided_by),
            (StageOutcome::Clear, Stage::Heuristic)
        );
    }
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
    let stage = cascade.l1_stage(
        SecurityCategory::Injection,
        ScoreMode::Strict,
        [&l1(0.5, false)],
    );
    assert_eq!(stage.outcome, StageOutcome::Escalate);
    let decision = cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &[],
            &mut [],
            None,
            &ScanControl::default(),
        )
        .unwrap()
        .expect("a stage ran");
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
    let stage = cascade.l1_stage(
        SecurityCategory::Injection,
        ScoreMode::Strict,
        [&l1(0.5, false)],
    );
    let decision = cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &[],
            &mut [&mut l2],
            Some(&mut l3),
            &ScanControl::default(),
        )
        .unwrap()
        .expect("a stage ran");
    assert_eq!((l2.calls, l3.calls), (1, 0));
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Clear, Stage::L2)
    );

    let mut l2 = Fake::new(SecurityLevel::L2, 0.4);
    l2.escalate_at = Some(0.3);
    let stage = cascade.l1_stage(
        SecurityCategory::Injection,
        ScoreMode::Strict,
        [&l1(0.5, false)],
    );
    let decision = cascade
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &[],
            &mut [&mut l2],
            Some(&mut l3),
            &ScanControl::default(),
        )
        .unwrap()
        .expect("a stage ran");
    assert_eq!((l2.calls, l3.calls), (1, 1));
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Detected, Stage::L3)
    );
}

#[test]
fn conditional_gates_read_every_modules_l1_results() {
    // L3 of injection only when PII's L1 found an email.
    let config: CascadeConfig = serde_json::from_value(serde_json::json!({
        "conditional": [{
            "level": "l3",
            "pipeline": "injection",
            "when": {"result": {"pipeline": "pii", "classes": ["email"]}}
        }]
    }))
    .unwrap();
    let cascade = Cascade::new(config).unwrap();
    assert!(cascade.has_conditional_gates() && !Cascade::default().has_conditional_gates());
    let pii = GateResult {
        pipeline: "pii".into(),
        class_name: "email".into(),
        confidence: 0.9,
        level: SecurityLevel::L1,
    };
    for (l1_results, runs) in [(vec![], 0), (vec![pii], 1)] {
        let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
        let stage = cascade.l1_stage(
            SecurityCategory::Injection,
            ScoreMode::Strict,
            [&l1(0.5, false)],
        );
        let decision = cascade
            .decide(
                SecurityCategory::Injection,
                "text",
                stage,
                &l1_results,
                &mut [],
                Some(&mut l3),
                &ScanControl::default(),
            )
            .unwrap()
            .expect("a stage ran");
        assert_eq!(l3.calls, runs);
        assert_eq!(
            decision.decided_by,
            if runs == 1 {
                Stage::L3
            } else {
                Stage::Heuristic
            }
        );
    }
    // Core scans carry no request metadata.
    let metadata: CascadeConfig = serde_json::from_value(serde_json::json!({
        "conditional": [{"level": "l3", "when": {"not": {"metadata": {"path": "tenant", "exists": true}}}}]
    }))
    .unwrap();
    assert!(metadata.validate().unwrap_err().contains("metadata"));
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
    let stage = cascade.l1_stage(SecurityCategory::Pii, ScoreMode::Strict, [&result]);
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
    let stage = cascade.l1_stage(SecurityCategory::Pii, ScoreMode::Strict, [&result]);
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
        layers: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(decision).unwrap(),
        serde_json::json!({"module": "injection", "outcome": "detected", "decided_by": "l1_model", "score": 0.5})
    );
}

#[test]
fn one_cut_rule_for_every_l1_stage() {
    use CutRule::{Above, AtOrAbove};
    assert_eq!(
        StageOutcome::from_cuts(true, 0.0, Some(1.0), AtOrAbove),
        StageOutcome::Detected
    );
    // Clear: the score does not count against the clear cut.
    assert_eq!(
        StageOutcome::from_cuts(false, 0.49, Some(0.5), AtOrAbove),
        StageOutcome::Clear
    );
    assert_eq!(
        StageOutcome::from_cuts(false, 0.5, Some(0.5), AtOrAbove),
        StageOutcome::Escalate
    );
    assert_eq!(
        StageOutcome::from_cuts(false, 0.5, Some(0.5), Above),
        StageOutcome::Clear
    );
    assert_eq!(
        StageOutcome::from_cuts(false, -9.0, None, Above),
        StageOutcome::Escalate
    );
    assert!(AtOrAbove.counts(0.5, 0.5) && !Above.counts(0.5, 0.5));
}

/// The synthetic L1 model at cuts around its own score on the test text:
/// `Detected`, `Clear` or `Escalate` (clearing on), or `None` for clearing off.
fn l1_model(name: &str, outcome: Option<StageOutcome>) -> L1TextModel {
    use crate::detectors::text::l1_model::test_model::{bundle, TEXT};
    let config = bundle(name);
    let score = L1TextModel::load(SecurityCategory::Injection, &config)
        .unwrap()
        .evaluate(TEXT, &[], &[])
        .score;
    let (detect, clear, clear_enabled) = match outcome {
        Some(StageOutcome::Detected) => (score - 1.0, score - 2.0, true),
        Some(StageOutcome::Clear) => (score + 2.0, score, true),
        Some(StageOutcome::Escalate) => (score + 2.0, score - 1.0, true),
        None => (score + 2.0, score + 1.0, false),
    };
    let model = L1TextModel::load(
        SecurityCategory::Injection,
        &L1ModelConfig {
            detect_threshold: Some(detect),
            clear_threshold: Some(clear),
            clear_enabled,
            ..config.clone()
        },
    )
    .unwrap();
    std::fs::remove_dir_all(&config.bundle_dir).ok();
    model
}

/// Heuristic escalation, then the L1 model, then `l3` when given.
fn run_with_model(
    model: &L1TextModel,
    heuristic: &NativeResult,
    l3: Option<&mut Fake>,
) -> ModuleDecision {
    use crate::detectors::text::l1_model::test_model::TEXT;
    let cascade = cascade(None);
    let stage = cascade.l1_stage(SecurityCategory::Injection, ScoreMode::Strict, [heuristic]);
    let stage = cascade.l1_model_stage(stage, Some(model), TEXT, &[]);
    cascade
        .decide(
            SecurityCategory::Injection,
            TEXT,
            stage,
            &[],
            &mut [],
            l3.map(|l3| l3 as &mut dyn L3Executor),
            &ScanControl::default(),
        )
        .unwrap()
        .expect("a stage ran")
}

#[test]
fn l1_model_answers_what_the_heuristic_escalates() {
    let detected = l1_model("cascade_model_detected", Some(StageOutcome::Detected));
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    let decision = run_with_model(&detected, &l1(0.5, false), Some(&mut l3));
    assert_eq!(l3.calls, 0);
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Detected, Stage::L1Model)
    );
    assert_eq!(decision.layers.len(), 1);
    assert_eq!(
        decision.layers[0].layer_type,
        crate::detectors::text::L1_MODEL_LAYER
    );
    assert!(decision.layers[0].matched);

    let clear = l1_model("cascade_model_clear", Some(StageOutcome::Clear));
    let mut l3 = Fake::new(SecurityLevel::L3, 0.99);
    let decision = run_with_model(&clear, &l1(0.5, false), Some(&mut l3));
    assert_eq!(l3.calls, 0);
    assert_eq!(
        (decision.outcome, decision.decided_by),
        (StageOutcome::Clear, Stage::L1Model)
    );

    // A heuristic detection is final: the model does not run.
    let decision = run_with_model(&clear, &l1(0.8, true), None);
    assert_eq!(
        (decision.outcome, decision.decided_by, decision.layers.len()),
        (StageOutcome::Detected, Stage::Heuristic, 0)
    );
}

#[test]
fn l1_model_escalation_runs_l3_or_ends_clear() {
    for (name, outcome) in [
        ("cascade_model_escalate", Some(StageOutcome::Escalate)),
        ("cascade_model_no_clear", None),
    ] {
        let model = l1_model(name, outcome);
        let decision = run_with_model(&model, &l1(0.5, false), None);
        assert_eq!(
            (decision.outcome, decision.decided_by),
            (StageOutcome::Clear, Stage::L1Model),
            "{name}"
        );
        let mut l3 = Fake::new(SecurityLevel::L3, 0.95);
        let decision = run_with_model(&model, &l1(0.5, false), Some(&mut l3));
        assert_eq!(l3.calls, 1, "{name}");
        assert_eq!(
            (decision.outcome, decision.decided_by, decision.score),
            (StageOutcome::Detected, Stage::L3, 0.95),
            "{name}"
        );
        let types: Vec<_> = decision
            .layers
            .iter()
            .map(|l| l.layer_type.as_str())
            .collect();
        assert_eq!(types, [crate::detectors::text::L1_MODEL_LAYER, "fake"]);
    }
}

#[test]
fn cascade_config_carries_the_l1_model_per_module() {
    let config: CascadeConfig = serde_json::from_value(serde_json::json!({
        "modules": {
            "injection": {"l1_model": {"bundle_dir": "m", "manifest_sha256": "ab", "clear_enabled": false}},
            "pii": {"clear_threshold": 0.1}
        }
    }))
    .unwrap();
    let models: Vec<_> = config.l1_models().collect();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].0, SecurityCategory::Injection);
    assert!(!models[0].1.clear_enabled);
}

/// A Threat result as the producer reports it: no decision envelope; in the
/// details the matched rules (`scorer`: one rule the document scorer reads,
/// probability [`scorer_score`]; `points`: an accepted points rule) and the
/// registry id; evidence when `evidence`.
fn threat(scorer: bool, points: bool, evidence: bool) -> NativeResult {
    let mut result = l1(0.0, false);
    result.decision = None;
    result.category = "exfiltration".into();
    let mut rules = Vec::new();
    if scorer {
        rules.push(crate::detectors::threat::scorer_finding().0);
    }
    if points {
        rules.push(
            serde_json::json!({"rule_id": "points", "rule_score": 0.8, "accepted": true,
            "start_byte": 0, "end_byte": 1}),
        );
    }
    result.layers.push(LayerResult {
        level: "L1".into(),
        layer_type: "native".into(),
        class_name: if evidence { "exfiltration" } else { "benign" }.into(),
        confidence: 1.0,
        matched: true,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::from([
            ("matched_rules".to_string(), serde_json::json!(rules)),
            // The reported score; the cascade recomputes its own.
            ("score".to_string(), 0.5.into()),
            ("registry_id".to_string(), "ark-threat-l1-0.1.7".into()),
        ]),
    });
    if evidence {
        result.evidence_spans.push(crate::EvidenceSpan {
            label: "exfiltration".into(),
            text: "x".into(),
            score: 0.8,
            start_byte: 0,
            end_byte: 1,
            start_char: 0,
            end_char: 1,
        });
    }
    result
}

/// The document scorer's probability of the one-rule finding of [`threat`].
fn scorer_score() -> f64 {
    crate::detectors::threat::scorer_finding().1
}

fn module_stage(detect: Option<f64>, clear: Option<f64>, result: &NativeResult) -> L1Stage {
    module_stage_at(ScoreMode::Strict, detect, clear, result)
}

fn module_stage_at(
    mode: ScoreMode,
    detect: Option<f64>,
    clear: Option<f64>,
    result: &NativeResult,
) -> L1Stage {
    let mut config = CascadeConfig::default();
    config.modules.insert(
        SecurityCategory::Exfiltration,
        ModuleConfig {
            detect_threshold: detect,
            clear_threshold: clear,
            l1_model: None,
        },
    );
    Cascade::new(config)
        .unwrap()
        .l1_stage(SecurityCategory::Exfiltration, mode, [result])
}

#[test]
fn threat_cuts_read_the_document_scorer_and_points_hits_detect_on_their_own() {
    let p = scorer_score();
    assert!(p > 0.0 && p < 1.0);
    // Accepted by the producer, but below the module's cut: the cut applies
    // to the scorer's probability, not the combined score (0.8).
    let low = threat(true, false, true);
    assert_eq!(
        module_stage(None, None, &low).outcome,
        StageOutcome::Detected
    );
    let stage = module_stage(Some((p + 0.01).min(1.0)), None, &low);
    assert_eq!((stage.outcome, stage.score), (StageOutcome::Escalate, p));
    assert_eq!(
        module_stage(Some(p), None, &low).outcome,
        StageOutcome::Detected
    );
    // A points rule hit detects whatever the cut says and carries its
    // points score (0.8), never 0; with the scorer too, the higher one.
    let hit = threat(false, true, true);
    let stage = module_stage(Some(0.9), Some(0.1), &hit);
    assert_eq!((stage.outcome, stage.score), (StageOutcome::Detected, 0.8));
    let both = module_stage(None, None, &threat(true, true, true));
    assert_eq!(
        (both.outcome, both.score),
        (StageOutcome::Detected, p.max(0.8))
    );
    // The mode floor dropped the hit's evidence: no rule hit, and its points
    // score no longer counts (only the scorer's probability, here 0).
    let floored = threat(false, true, false);
    let stage = module_stage(Some(0.9), Some(0.1), &floored);
    assert_eq!((stage.outcome, stage.score), (StageOutcome::Clear, 0.0));
}

#[test]
fn score_based_detection_needs_the_mode_floor() {
    // Score 0 counts against the cut 0, but only `strict` admits it.
    let none = threat(false, false, false);
    assert_eq!(
        module_stage_at(ScoreMode::Strict, Some(0.0), None, &none).outcome,
        StageOutcome::Detected
    );
    assert_eq!(
        module_stage_at(ScoreMode::Recall, Some(0.0), None, &none).outcome,
        StageOutcome::Escalate
    );
    let p = scorer_score();
    for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
        let detected = module_stage_at(mode, Some(p), None, &threat(true, false, false)).outcome
            == StageOutcome::Detected;
        assert_eq!(detected, mode.admits(p), "{mode}");
    }
}

#[test]
fn every_escalation_signal_escalates() {
    let p = scorer_score();
    for clear in [None, Some(p / 2.0), Some(p)] {
        let stage = module_stage(None, clear, &threat(true, false, false));
        let signal = stage.escalation.expect("escalates");
        assert!(signal.escalates(), "heuristic clear {clear:?}");
        assert_eq!(signal.threshold, clear.unwrap_or(f64::MIN));
    }
    for (name, outcome) in [
        ("signal_model_escalate", Some(StageOutcome::Escalate)),
        ("signal_model_no_clear", None),
    ] {
        let model = l1_model(name, outcome);
        let stage = cascade(None).l1_stage(
            SecurityCategory::Injection,
            ScoreMode::Strict,
            [&l1(0.5, false)],
        );
        let stage = cascade(None).l1_model_stage(
            stage,
            Some(&model),
            crate::detectors::text::l1_model::test_model::TEXT,
            &[],
        );
        let signal = stage.escalation.expect("escalates");
        assert!(
            signal.escalates() && signal.score > signal.threshold,
            "{name}"
        );
    }
}

#[test]
fn clear_threshold_reads_the_scorer_score_of_results_without_an_envelope() {
    let p = scorer_score();
    let below = threat(true, false, false);
    let stage = module_stage(None, Some((p + 0.01).min(1.0)), &below);
    assert_eq!((stage.outcome, stage.score), (StageOutcome::Clear, p));
    // At or above the clear cut it escalates instead of being cleared as 0.
    assert_eq!(
        module_stage(None, Some(p), &below).outcome,
        StageOutcome::Escalate
    );
    assert_eq!(
        module_stage(None, Some(0.1), &threat(true, false, true)).outcome,
        StageOutcome::Detected
    );
}

#[test]
fn detect_threshold_is_the_per_module_heuristic_cut() {
    let p = scorer_score();
    // Unset: the producer's own acceptance.
    assert_eq!(
        module_stage(None, None, &threat(true, false, false)).outcome,
        StageOutcome::Escalate
    );
    // Set: the scorer score at or above it detects, below it does not, accepted or not.
    assert_eq!(
        module_stage(Some(p), None, &threat(true, false, false)).outcome,
        StageOutcome::Detected
    );
    assert_eq!(
        module_stage(
            Some((p + 0.01).min(1.0)),
            Some(p / 2.0),
            &threat(true, false, true)
        )
        .outcome,
        StageOutcome::Escalate
    );
    let config: CascadeConfig = serde_json::from_value(serde_json::json!({
        "modules": {"exfiltration": {"detect_threshold": 0.3, "clear_threshold": 0.4}}
    }))
    .unwrap();
    assert!(config.validate().is_err());
    let config: CascadeConfig = serde_json::from_value(serde_json::json!({
        "modules": {"exfiltration": {"detect_threshold": 1.3}}
    }))
    .unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn l1_stage_decision_is_final_only_when_l1_does_not_escalate() {
    let cascade = Cascade::default();
    let detected = cascade.l1_stage(
        SecurityCategory::Injection,
        ScoreMode::Strict,
        [&l1(0.95, true)],
    );
    let decision = detected.decision(SecurityCategory::Injection).unwrap();
    assert_eq!(
        (
            decision.module,
            decision.outcome,
            decision.decided_by,
            decision.score
        ),
        (
            SecurityCategory::Injection,
            StageOutcome::Detected,
            Stage::Heuristic,
            0.95
        )
    );
    let undecided = cascade.l1_stage(
        SecurityCategory::Injection,
        ScoreMode::Strict,
        [&l1(0.5, false)],
    );
    assert!(undecided.decision(SecurityCategory::Injection).is_none());
}

#[test]
fn each_level_maps_to_the_stage_that_answers_there() {
    assert_eq!(
        [SecurityLevel::L1, SecurityLevel::L2, SecurityLevel::L3].map(Stage::from),
        [Stage::Heuristic, Stage::L2, Stage::L3]
    );
}

#[test]
fn level_switches_turn_single_layers_off() {
    let no_l2 = Cascade::new(CascadeConfig {
        l2: Some(false),
        ..CascadeConfig::default()
    })
    .unwrap();
    assert!(!no_l2.allows_level(SecurityLevel::L2) && no_l2.allows_level(SecurityLevel::L3));
    let mut l2 = Fake::new(SecurityLevel::L2, 0.99);
    let mut l3 = Fake::new(SecurityLevel::L3, 0.95);
    let stage = no_l2.l1_off(SecurityCategory::Injection);
    let decision = no_l2
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &[],
            &mut [&mut l2],
            Some(&mut l3),
            &ScanControl::default(),
        )
        .unwrap()
        .expect("a stage ran");
    assert_eq!((l2.calls, l3.calls), (0, 1));
    assert_eq!(decision.decided_by, Stage::L3);
    // L1 off escalates whatever the clear threshold.
    let stage = cascade(Some(1.0)).l1_off(SecurityCategory::Injection);
    assert_eq!(stage.outcome, StageOutcome::Escalate);
    assert!(stage.escalation.as_ref().unwrap().escalates());
    // No stage ran at all: no decision, never one "by the heuristic".
    let none = cascade(None)
        .decide(
            SecurityCategory::Injection,
            "text",
            stage,
            &[],
            &mut [],
            None,
            &ScanControl::default(),
        )
        .unwrap();
    assert!(none.is_none());
}

#[test]
fn a_points_hit_needs_its_own_evidence_after_the_mode_floor() {
    // The floor kept only another span: the accepted points rule is no hit.
    let mut other = threat(true, true, true);
    other.evidence_spans[0].start_byte = 5;
    other.evidence_spans[0].end_byte = 9;
    assert_eq!(
        module_stage(Some(0.99), None, &other).outcome,
        StageOutcome::Escalate
    );
    assert_eq!(
        module_stage(Some(0.99), None, &threat(true, true, true)).outcome,
        StageOutcome::Detected
    );
}

#[test]
fn l1_gate_results_include_rejected_injection_candidates() {
    let mut result = l1(0.5, false);
    result.model = crate::injection_l1::MODEL.into();
    let decision = result.decision.as_mut().unwrap();
    decision
        .candidates
        .push(decision.decision_candidate.clone().unwrap());
    let gates = l1_gate_results([&result]);
    assert_eq!(gates.len(), 2);
    assert_eq!(gates[0].pipeline, "injection");
    assert_eq!(
        (gates[1].pipeline.as_str(), gates[1].class_name.as_str()),
        (crate::injection_l1::MODEL, "injection")
    );
}

#[test]
fn a_cascade_loads_its_l1_models_once_and_refuses_non_native_modules() {
    use crate::detectors::text::l1_model::test_model::bundle;
    assert!(Cascade::default()
        .l1_model(SecurityCategory::Injection)
        .is_none());
    let config = |module| {
        let mut config = CascadeConfig::default();
        config.modules.insert(
            module,
            ModuleConfig {
                l1_model: Some(bundle("cascade_owns_l1_model")),
                ..Default::default()
            },
        );
        config
    };
    let first = Cascade::new(config(SecurityCategory::Injection)).unwrap();
    let second = Cascade::new(config(SecurityCategory::Injection)).unwrap();
    assert!(std::ptr::eq(
        first.l1_model(SecurityCategory::Injection).unwrap(),
        second.l1_model(SecurityCategory::Injection).unwrap(),
    ));
    assert!(matches!(
        Cascade::new(config(SecurityCategory::ShellCommand)),
        Err(ScanError::Config(message)) if message.contains("non-native")
    ));
}
