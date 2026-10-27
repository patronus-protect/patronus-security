// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::{native::NativeEngine, ScanControl, ScanError, ScannerConfig};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[test]
fn registry_keeps_category_order_and_all_outer_gate_combinations() {
    let engine = NativeEngine::new(&[Category::Pii, Category::Dlp, Category::Injection]);
    assert_eq!(
        engine
            .producers(Category::Pii)
            .iter()
            .map(|p| p.id())
            .collect::<Vec<_>>(),
        ["native:pii"]
    );
    assert_eq!(
        engine
            .producers(Category::Dlp)
            .iter()
            .map(|p| p.id())
            .collect::<Vec<_>>(),
        [
            "native:dlp",
            "native:sensitive_material",
            "native:secret_transfer",
            "native:mcp_runtime_risk",
            "native:mcp_policy",
            "native:destructive_operation",
        ]
    );
    assert_eq!(
        engine
            .producers(Category::Injection)
            .iter()
            .map(|p| p.id())
            .collect::<Vec<_>>(),
        [
            "native:injection_rule_catalog",
            "native:injection_structural",
            "native:cross_tool_instruction",
            "native:instruction_leak",
            "native:encoded_instruction",
            "native:multi_turn_escalation",
            "native:guardrail_tamper",
            "native:tool_output_instruction",
            "native:hidden_html_instruction",
            "native:unicode_confusable",
            "native:zero_width_obfuscation",
            "native:agentic_control_abuse",
            "native:binary_smuggling",
            "native:instruction_override",
            "native:jailbreak_framing",
            "native:covert_instruction",
            "native:instruction_boundary",
            "native:authority_escalation",
            "native:tool_call_injection",
            "native:output_manipulation",
        ]
    );
    for category in [Category::Pii, Category::Dlp, Category::Injection] {
        for spec in engine.producers(category) {
            assert_eq!(spec.category(), category);
            for parent in [false, true] {
                for model in [false, true] {
                    for rule in [false, true] {
                        let mut policy = ScannerConfig::default();
                        policy.models.insert(spec.id().into(), model);
                        if let Some(id) = spec.parent {
                            policy.models.insert(id.into(), parent);
                        }
                        if let Some(id) = spec.rule {
                            policy.rules.insert(id.into(), rule);
                        }
                        assert_eq!(
                            spec.enabled(&policy),
                            model
                                && (spec.parent.is_none() || parent)
                                && (spec.rule.is_none() || rule),
                            "{}",
                            spec.id()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn selected_categories_reuse_pipeline_state_and_preserve_internal_rule_policy() {
    assert!(NativeEngine::new(&[]).producers(Category::Pii).is_empty());
    let engine = NativeEngine::new(&[Category::Pii]);
    assert!(engine.producers(Category::Dlp).is_empty());
    assert!(engine.producers(Category::Injection).is_empty());
    let producers = engine.producers(Category::Pii);
    let spec = &producers[0];
    let source = format!("Kontakt: {}@{}", "alice", "example.org");
    let text = NativeText::new(&source);
    for mode in [
        pii::score::PiiMode::Strict,
        pii::score::PiiMode::Balanced,
        pii::score::PiiMode::Recall,
    ] {
        let policy = ScannerConfig {
            pii_mode: mode,
            explain: true,
            ..Default::default()
        };
        let actual = engine
            .run_producer(spec, &text, &policy, &ScanControl::default())
            .unwrap();
        let expected = pii::pii::PiiPipeline::new().detect_prepared_with_mode(
            &text,
            |id| policy.allows_rule(id),
            true,
            mode,
        );
        assert!(!expected.evidence_spans.is_empty());
        assert_eq!(
            actual.detection.result.class_name,
            expected.result.class_name
        );
        assert_eq!(
            actual.detection.result.confidence,
            expected.result.confidence
        );
        assert_eq!(actual.detection.evidence_spans, expected.evidence_spans);
        assert_eq!(actual.detection.details, expected.details);
        assert!(std::ptr::eq(
            producers.as_ptr(),
            engine.producers(Category::Pii).as_ptr()
        ));
    }
    let mut disabled = ScannerConfig::default();
    disabled.rules.insert("pii_email".into(), false);
    assert!(engine
        .run_producer(spec, &text, &disabled, &ScanControl::default())
        .unwrap()
        .detection
        .evidence_spans
        .is_empty());
}

fn probe(detect: Detect) -> NativeProducerSpec {
    NativeProducerSpec {
        category: Category::Pii,
        id: "test:probe",
        parent: None,
        rule: None,
        detect,
    }
}

fn clean_detection() -> NativeDetection {
    NativeDetection {
        result: crate::detectors::safe_result(),
        evidence_spans: Vec::new(),
        details: HashMap::new(),
    }
}

#[test]
fn disabled_producer_is_skipped_and_control_checks_bracket_active_detection() {
    let engine = NativeEngine::new(&[]);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let spec = probe(Box::new(move |_, _| {
        observed.fetch_add(1, Ordering::Relaxed);
        clean_detection()
    }));
    let mut policy = ScannerConfig::default();
    policy.models.insert("test:probe".into(), false);
    let text = NativeText::new("text");
    if spec.enabled(&policy) {
        engine
            .run_producer(&spec, &text, &policy, &ScanControl::default())
            .unwrap();
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let control = ScanControl::default();
    control.cancel();
    assert!(matches!(
        engine.run_producer(&spec, &text, &policy, &control),
        Err(ScanError::Cancelled)
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let control = ScanControl::default();
    let during = control.clone();
    let spec = probe(Box::new(move |_, _| {
        during.cancel();
        clean_detection()
    }));
    assert!(matches!(
        engine.run_producer(&spec, &text, &policy, &control),
        Err(ScanError::Cancelled)
    ));
}

#[test]
fn producer_panic_preserves_payload_for_host_failure_policy() {
    let engine = NativeEngine::new(&[]);
    let spec = probe(Box::new(|_, _| panic!("producer sentinel")));
    assert!(
        matches!(engine.run_producer(&spec, &NativeText::new("text"), &ScannerConfig::default(), &ScanControl::default()), Err(ScanError::Detector(message)) if message == "producer sentinel")
    );
    let spec = probe(Box::new(|_, _| std::panic::panic_any(42_u8)));
    assert!(matches!(
        engine.run_producer(
            &spec,
            &NativeText::new("text"),
            &ScannerConfig::default(),
            &ScanControl::default()
        ),
        Err(ScanError::Detector(message)) if message == "scanner panicked"
    ));
}
