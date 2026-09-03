use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use patronus_ark::{
    assets::DYNAMIC_PII_ASSET, DynamicPiiConditionalLabels, DynamicPiiConfig,
    DynamicPiiExecutionGate, DynamicPiiResultCondition, QueuedSecurityEvent, SecurityCategory,
    SecurityGateway, SecurityLevel, SecurityLevelReadiness, SecurityRequestCompletion,
    SecurityRequestState,
};

#[test]
fn default_labels_are_a_small_core_bundle() {
    assert_eq!(
        DynamicPiiConfig::default().labels,
        ["organization", "date", "person", "city", "country"].map(String::from)
    );
}

#[test]
fn config_deduplicates_labels_and_validates_limits() {
    let config = DynamicPiiConfig {
        labels: ["person", "location", "person"].map(String::from).to_vec(),
        ..DynamicPiiConfig::default()
    };
    assert_eq!(
        config.validated().unwrap().labels,
        ["person", "location"].map(String::from)
    );

    let defaults = DynamicPiiConfig::default();
    let config = DynamicPiiConfig {
        chunk_overlap_words: defaults.chunk_size_words,
        ..defaults
    };
    assert!(config.validated().is_err());

    let config = DynamicPiiConfig {
        threshold: f32::NAN,
        ..DynamicPiiConfig::default()
    };
    assert!(config.validated().is_err());

    let config = DynamicPiiConfig {
        label_thresholds: HashMap::from([("unknown".to_string(), 0.5)]),
        ..DynamicPiiConfig::default()
    };
    assert!(config.validated().is_err());

    let config = DynamicPiiConfig {
        labels: (0..31).map(|index| format!("label-{index}")).collect(),
        ..DynamicPiiConfig::default()
    };
    assert!(config.validated().is_err());

    let config = DynamicPiiConfig {
        labels: ["medical_condition", "medical condition"]
            .map(String::from)
            .to_vec(),
        ..DynamicPiiConfig::default()
    };
    assert!(config.validated().is_err());
}

#[test]
fn gate_config_normalizes_sources_and_validates_possible_labels() {
    let config = DynamicPiiConfig {
        labels: Vec::new(),
        label_thresholds: HashMap::from([("organization".to_string(), 0.7)]),
        execution_gate: DynamicPiiExecutionGate::IfResultIn {
            pipeline: "tool_class".to_string(),
            results: vec![" tool_class.web.fetch ".to_string()],
        },
        conditional_labels: vec![DynamicPiiConditionalLabels {
            labels: vec!["organization".to_string(), "organization".to_string()],
            when: DynamicPiiResultCondition {
                pipeline: "routing".to_string(),
                results: vec!["action".to_string()],
            },
        }],
        ..DynamicPiiConfig::default()
    }
    .validated()
    .unwrap();
    assert!(config.labels.is_empty());
    assert_eq!(config.conditional_labels[0].labels, ["organization"]);
    assert!(matches!(
        config.execution_gate,
        DynamicPiiExecutionGate::IfResultIn { ref pipeline, ref results }
            if pipeline == "tool_class" && results == &["tool_class.web.fetch"]
    ));

    let self_dependency = DynamicPiiConfig {
        execution_gate: DynamicPiiExecutionGate::IfNoResult {
            pipeline: "dynamic-pii".to_string(),
        },
        ..DynamicPiiConfig::default()
    };
    assert!(self_dependency.validated().is_err());

    let unknown_pipeline = DynamicPiiConfig {
        execution_gate: DynamicPiiExecutionGate::IfNoResult {
            pipeline: "missing".to_string(),
        },
        ..DynamicPiiConfig::default()
    };
    assert!(unknown_pipeline.validated().is_err());
}

fn completion_for(gateway: &SecurityGateway, request_id: &str) -> SecurityRequestCompletion {
    loop {
        match gateway
            .consume_next_event(Some(Duration::from_secs(2)))
            .expect("request must reach a terminal event")
        {
            QueuedSecurityEvent::Result(result) => assert_eq!(result.request_id, request_id),
            QueuedSecurityEvent::Progress(_) | QueuedSecurityEvent::Provisional(_) => {}
            QueuedSecurityEvent::Finished {
                request_id: finished_id,
                completion,
            } => {
                assert_eq!(finished_id, request_id);
                return completion;
            }
        }
    }
}

#[test]
fn execution_gates_skip_or_enqueue_dynamic_pii_deterministically() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp, SecurityCategory::DynamicPii],
        SecurityLevel::L3,
        None,
        false,
    );
    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: vec!["person".to_string()],
            execution_gate: DynamicPiiExecutionGate::IfResultIn {
                pipeline: "dlp".to_string(),
                results: vec!["never".to_string()],
            },
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    let skipped = gateway.enqueue("ordinary text", None);
    assert!(matches!(
        completion_for(&gateway, &skipped),
        SecurityRequestCompletion::Complete
    ));

    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: vec!["person".to_string()],
            execution_gate: DynamicPiiExecutionGate::IfResultIn {
                pipeline: "dlp".to_string(),
                results: vec!["safe".to_string()],
            },
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    let enqueued = gateway.enqueue("ordinary text", None);
    assert!(matches!(
        completion_for(&gateway, &enqueued),
        SecurityRequestCompletion::Degraded { .. }
    ));

    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: vec!["person".to_string()],
            execution_gate: DynamicPiiExecutionGate::IfNoResult {
                pipeline: "dlp".to_string(),
            },
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    let source_delivered = gateway.enqueue("ordinary text", None);
    assert!(matches!(
        completion_for(&gateway, &source_delivered),
        SecurityRequestCompletion::Complete
    ));

    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: vec!["person".to_string()],
            execution_gate: DynamicPiiExecutionGate::IfNoResult {
                pipeline: "routing".to_string(),
            },
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    let source_absent = gateway.enqueue("ordinary text", None);
    assert!(matches!(
        completion_for(&gateway, &source_absent),
        SecurityRequestCompletion::Degraded { .. }
    ));
}

#[test]
fn dynamic_pii_gate_waits_for_authoritative_l3_source_result() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Injection, SecurityCategory::DynamicPii],
        SecurityLevel::L3,
        None,
        false,
    );
    let started = Instant::now();
    let request_id = gateway.enqueue_test_dynamic_pii_dependency_request(150);
    let first = gateway
        .consume_next_event(Some(Duration::from_millis(20)))
        .expect("source fallback must be immediately visible");
    assert!(matches!(first, QueuedSecurityEvent::Result(_)));
    assert!(gateway
        .consume_next_event(Some(Duration::from_millis(20)))
        .is_none());
    assert_eq!(
        gateway.request_state(&request_id),
        Some(SecurityRequestState::Running)
    );
    assert!(matches!(
        completion_for(&gateway, &request_id),
        SecurityRequestCompletion::Degraded { .. }
    ));
    assert!(started.elapsed() >= Duration::from_millis(100));
}

#[test]
fn category_and_readiness_expose_l3_only_pipeline() {
    assert_eq!(
        "dynamic-pii".parse::<SecurityCategory>().unwrap(),
        SecurityCategory::DynamicPii
    );
    assert_eq!(
        "dynamic_pii".parse::<SecurityCategory>().unwrap(),
        SecurityCategory::DynamicPii
    );
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::DynamicPii],
        SecurityLevel::L3,
        None,
        false,
    );
    let readiness = gateway.runtime_readiness();
    assert!(matches!(
        readiness.l1,
        SecurityLevelReadiness::NotConfigured
    ));
    assert!(matches!(
        readiness.l2,
        SecurityLevelReadiness::NotConfigured
    ));
    assert!(matches!(
        readiness.l3,
        SecurityLevelReadiness::NotReady { .. }
    ));
}

#[test]
fn l2_gateway_does_not_run_l3_only_pipeline() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::DynamicPii],
        SecurityLevel::L2,
        None,
        false,
    );
    assert!(gateway
        .scan_category(SecurityCategory::DynamicPii, "Ada lives in Berlin")
        .is_empty());
}

#[test]
#[cfg(unix)]
#[ignore = "requires PATRONUS_TEST_GLINER_DIR"]
fn local_edge_bundle_runs_through_gateway_and_l3_worker() {
    let bundle_source = std::env::var("PATRONUS_TEST_GLINER_DIR")
        .expect("PATRONUS_TEST_GLINER_DIR must point to the Edge bundle");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let model_dir = std::env::temp_dir().join(format!(
        "patronus_dynamic_pii_test_{}_{}",
        std::process::id(),
        suffix
    ));
    let bundle_dir = model_dir.join(DYNAMIC_PII_ASSET.destination_path);
    std::fs::create_dir_all(bundle_dir.parent().unwrap()).unwrap();
    symlink(bundle_source, &bundle_dir).unwrap();
    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp, SecurityCategory::DynamicPii],
        SecurityLevel::L3,
        Some(model_dir.clone()),
        false,
    );
    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: ["person", "organization", "location"]
                .map(String::from)
                .to_vec(),
            chunk_size_words: 4,
            chunk_overlap_words: 1,
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    gateway.warmup().unwrap();
    assert!(matches!(
        gateway.runtime_readiness().l3,
        SecurityLevelReadiness::Ready
    ));

    let results = gateway.scan_category(
        SecurityCategory::DynamicPii,
        "Alexandr works at Patronus-Studio in Frankfurt.",
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].category, "dynamic-pii");
    assert_eq!(results[0].class_name, "entities");
    let spans = results[0]
        .evidence_spans
        .iter()
        .map(|span| {
            (
                span.label.as_str(),
                span.text.as_str(),
                span.start_byte,
                span.end_byte,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        spans,
        [
            ("person", "Alexandr", 0, 8),
            ("organization", "Patronus-Studio", 18, 33),
            ("location", "Frankfurt", 37, 46),
        ]
    );

    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: ["person", "organization", "location"]
                .map(String::from)
                .to_vec(),
            label_thresholds: HashMap::from([("organization".to_string(), 1.0)]),
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    let filtered = gateway.scan_category(
        SecurityCategory::DynamicPii,
        "Alexandr works at Patronus-Studio in Frankfurt.",
    );
    assert_eq!(filtered.len(), 1);
    assert!(filtered[0]
        .evidence_spans
        .iter()
        .all(|span| span.label != "organization"));

    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: vec!["person".to_string()],
            conditional_labels: vec![DynamicPiiConditionalLabels {
                labels: ["organization", "location"].map(String::from).to_vec(),
                when: DynamicPiiResultCondition {
                    pipeline: "dlp".to_string(),
                    results: vec!["safe".to_string()],
                },
            }],
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    let conditional = gateway.scan_categories(
        &[SecurityCategory::Dlp, SecurityCategory::DynamicPii],
        "Alexandr works at Patronus-Studio in Frankfurt.",
    );
    let dynamic = conditional
        .iter()
        .find(|result| result.category == "dynamic-pii")
        .expect("conditional dynamic-pii result must be present");
    assert_eq!(
        dynamic.layers[0].details.get("labels"),
        Some(&serde_json::json!(["person"]))
    );
    assert_eq!(
        dynamic.layers[0].details.get("activated_conditional_rules"),
        Some(&serde_json::json!([0]))
    );
    let groups = dynamic.layers[0].details["inference_groups"]
        .as_array()
        .unwrap();
    assert_eq!(groups[0]["labels"], serde_json::json!(["person"]));
    assert_eq!(
        groups[1]["labels"],
        serde_json::json!(["organization", "location"])
    );
    drop(gateway);
    std::fs::remove_dir_all(model_dir).unwrap();
}

#[test]
#[cfg(unix)]
#[ignore = "requires PATRONUS_TEST_GLINER_DIR"]
fn hey_person_score_uses_the_stable_base_only_label_group() {
    let bundle_source = std::env::var("PATRONUS_TEST_GLINER_DIR")
        .expect("PATRONUS_TEST_GLINER_DIR must point to the Edge bundle");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let model_dir = std::env::temp_dir().join(format!(
        "patronus_dynamic_pii_hey_test_{}_{}",
        std::process::id(),
        suffix
    ));
    let bundle_dir = model_dir.join(DYNAMIC_PII_ASSET.destination_path);
    std::fs::create_dir_all(bundle_dir.parent().unwrap()).unwrap();
    symlink(bundle_source, &bundle_dir).unwrap();
    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp, SecurityCategory::DynamicPii],
        SecurityLevel::L3,
        Some(model_dir.clone()),
        false,
    );
    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: vec!["person".to_string()],
            label_thresholds: HashMap::from([("person".to_string(), 0.8)]),
            conditional_labels: vec![DynamicPiiConditionalLabels {
                // Production profiles repeat base labels in their contextual
                // bundles. The resolver must subtract `person` here.
                labels: ["person", "street_address"].map(String::from).to_vec(),
                when: DynamicPiiResultCondition {
                    pipeline: "dlp".to_string(),
                    results: vec!["safe".to_string()],
                },
            }],
            ..DynamicPiiConfig::default()
        })
        .unwrap();
    gateway.warmup().unwrap();

    let results = gateway.scan_categories(
        &[SecurityCategory::Dlp, SecurityCategory::DynamicPii],
        "Hey",
    );
    let dynamic = results
        .iter()
        .find(|result| result.category == "dynamic-pii")
        .expect("dynamic-pii result must be present");
    assert!(dynamic
        .evidence_spans
        .iter()
        .all(|span| span.label != "person"));
    let groups = dynamic.layers[0].details["inference_groups"]
        .as_array()
        .unwrap();
    assert_eq!(groups[0]["labels"], serde_json::json!(["person"]));
    assert_eq!(groups[1]["labels"], serde_json::json!(["street_address"]));

    drop(gateway);
    std::fs::remove_dir_all(model_dir).unwrap();
}

#[test]
#[cfg(unix)]
#[ignore = "requires PATRONUS_TEST_GLINER_DIR"]
fn warmed_gliner_single_scan_excludes_warmup_from_latency() {
    let bundle_source = std::env::var("PATRONUS_TEST_GLINER_DIR")
        .expect("PATRONUS_TEST_GLINER_DIR must point to the Edge bundle");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let model_dir = std::env::temp_dir().join(format!(
        "patronus_dynamic_pii_latency_test_{}_{}",
        std::process::id(),
        suffix
    ));
    let bundle_dir = model_dir.join(DYNAMIC_PII_ASSET.destination_path);
    std::fs::create_dir_all(bundle_dir.parent().unwrap()).unwrap();
    symlink(bundle_source, &bundle_dir).unwrap();

    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::DynamicPii],
        SecurityLevel::L3,
        Some(model_dir.clone()),
        false,
    );
    gateway
        .set_dynamic_pii_config(DynamicPiiConfig {
            labels: ["person", "organization", "location"]
                .map(String::from)
                .to_vec(),
            ..DynamicPiiConfig::default()
        })
        .unwrap();

    let warmup_started = Instant::now();
    gateway.warmup().unwrap();
    let warmup_ms = warmup_started.elapsed().as_secs_f64() * 1_000.0;

    let scan_started = Instant::now();
    let results = gateway.scan_category(
        SecurityCategory::DynamicPii,
        "Alexandr works at Patronus-Studio in Frankfurt.",
    );
    let scan_wall_ms = scan_started.elapsed().as_secs_f64() * 1_000.0;
    let result = results
        .iter()
        .find(|result| result.category == "dynamic-pii")
        .expect("warmed GLiNER scan must return a Dynamic PII result");

    eprintln!(
        "GLiNER single scan: warmup_ms={warmup_ms:.2} (excluded), inference_ms={:.2}, wall_ms={scan_wall_ms:.2}",
        result.duration_ms
    );
    assert_eq!(result.class_name, "entities");
    assert!(
        scan_wall_ms < 1_000.0,
        "warmed GLiNER single scan took {scan_wall_ms:.2} ms; warmup took {warmup_ms:.2} ms and was excluded"
    );

    drop(gateway);
    std::fs::remove_dir_all(model_dir).unwrap();
}
