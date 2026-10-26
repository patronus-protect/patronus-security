// SPDX-License-Identifier: GPL-3.0-only
use super::super::tests::{test_job, test_result, test_worker_state};
use super::super::{
    finish_job, publish_progress, publish_provisional, L3WorkerInput, RequestState,
};
use super::*;
use crate::{QueuedSecurityEvent, QueuedSecurityProgress, SecurityRequestCompletion};
use patronus_ark_core::ScanError;
use std::{
    collections::HashMap,
    sync::mpsc,
    time::{Duration, Instant},
};

fn requests() -> Arc<RequestRegistry> {
    let requests = Arc::new(RequestRegistry::default());
    let mut request = RequestState::running();
    request.pending_l3_job_ids.extend([1, 2, 3]);
    requests
        .state
        .lock()
        .unwrap()
        .requests
        .insert("request".into(), request);
    requests
}

#[test]
fn early_exit_cancels_only_eligible_runs_and_rejects_late_registration() {
    let requests = requests();
    let eligible = ActiveRunGuard::register(Arc::clone(&requests), "request", 1, true).unwrap();
    let direct = ActiveRunGuard::register(Arc::clone(&requests), "request", 2, false).unwrap();
    requests.cancel_early_exit_runs("request", "threat:attack:0.9900");
    assert!(matches!(
        eligible.control().check(),
        Err(ScanError::Cancelled)
    ));
    direct.control().check().unwrap();
    assert_eq!(
        eligible.early_exit_reason().as_deref(),
        Some("threat:attack:0.9900")
    );
    assert!(matches!(
        ActiveRunGuard::register(Arc::clone(&requests), "request", 3, true),
        Err(Stopped::EarlyExit(_))
    ));
    drop(eligible);
    drop(direct);
    assert!(requests.state.lock().unwrap().active_runs.is_empty());
}

#[test]
fn one_job_control_never_cancels_siblings_and_guard_drop_unregisters() {
    let requests = requests();
    let first = ActiveRunGuard::register(Arc::clone(&requests), "request", 1, true).unwrap();
    let sibling = ActiveRunGuard::register(Arc::clone(&requests), "request", 2, true).unwrap();
    first.control().cancel();
    sibling.control().check().unwrap();
    drop(first);
    assert_eq!(requests.state.lock().unwrap().active_runs.len(), 1);
    drop(sibling);
    assert!(requests.state.lock().unwrap().active_runs.is_empty());
}

#[test]
fn terminal_registration_race_cancels_existing_runs_and_rejects_late_ones() {
    for _ in 0..32 {
        let requests = requests();
        let finishing = Arc::clone(&requests);
        let terminal = std::thread::spawn(move || {
            finishing
                .state
                .lock()
                .unwrap()
                .requests
                .get_mut("request")
                .unwrap()
                .completion = Some(SecurityRequestCompletion::Complete);
            finishing.cancel_finished_runs("request");
        });
        let active = ActiveRunGuard::register(Arc::clone(&requests), "request", 1, true);
        terminal.join().unwrap();
        match active {
            Ok(active) => assert!(matches!(
                active.control().check(),
                Err(ScanError::Cancelled)
            )),
            Err(stopped) => assert!(matches!(stopped, Stopped::Inactive)),
        }
        assert!(requests.state.lock().unwrap().active_runs.is_empty());
        assert!(matches!(
            ActiveRunGuard::register(Arc::clone(&requests), "request", 2, false),
            Err(Stopped::Inactive)
        ));
    }
}

#[test]
fn request_early_exit_terminates_active_onnx_and_preserves_terminal_lifecycle() {
    let dir = std::env::temp_dir().join(format!("ark-active-wolf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    std::fs::write(
        dir.join("tokenizer.mmbpe"),
        include_bytes!("../../../../../ark-core/tests/fixtures/tokenizer.mmbpe"),
    )
    .unwrap();
    std::fs::write(
        dir.join("model_fp16.onnx"),
        include_bytes!("../../../../../ark-core/tests/fixtures/wolf_cancellable.onnx"),
    )
    .unwrap();
    std::fs::write(dir.join("config.json"), r#"{"num_labels":1}"#).unwrap();
    let mut classifier = crate::ml::onnx::LazyOnnxTextClassifier::from_dir_with_paths(
        &dir,
        vec!["benign".into(), "attack".into()],
        "wolf-defender-small",
        &["model_fp16.onnx"],
        "tokenizer.json",
        256,
    )
    .unwrap()
    .unwrap();
    let runtime = crate::OnnxRuntimeOptions::default();
    let backend = crate::ExecutionBackend::Cpu;
    classifier
        .ensure_wolf_loaded(0.93, backend, runtime, Default::default())
        .unwrap();
    let requests = requests();
    requests
        .state
        .lock()
        .unwrap()
        .requests
        .get_mut("request")
        .unwrap()
        .pending_l3_job_ids
        .remove(&3);
    let worker = Arc::new(test_worker_state(Arc::clone(&requests)));
    let model = Arc::new(std::sync::Mutex::new(classifier));
    worker
        .models
        .lock()
        .unwrap()
        .insert("wolf-defender-small".into(), Arc::clone(&model));
    let mut job = test_job("request", "injection", 0, 1);
    job.model = "wolf-defender-small".into();
    job.input = L3WorkerInput::Text(Arc::from(" a"));
    job.execution.set_backend(backend);
    let mut gates = crate::ScanGateMatrix::default();
    gates.set_l3_policy(crate::L3SchedulerPolicy {
        progress: crate::L3ProgressMode::Progress,
        ..Default::default()
    });
    job.execution.set_gates(gates);
    let (tx, rx) = mpsc::channel();
    let running = Arc::clone(&worker);
    let scan = std::thread::spawn(move || {
        let (id, request_id, result) = super::super::dedicated::execute(&running, job);
        finish_job(&running, id, request_id, result.clone());
        tx.send(result).unwrap();
    });
    let mut registry = requests.state.lock().unwrap();
    let budget = Instant::now() + Duration::from_secs(5);
    while !registry
        .ready
        .iter()
        .any(|event| matches!(event, QueuedSecurityEvent::Progress(p) if p.stage == "l3_started"))
    {
        let remaining = budget.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "Wolf did not start");
        registry = requests
            .available
            .wait_timeout(registry, remaining)
            .unwrap()
            .0;
    }
    drop(registry);
    // The fixture's nonempty input stays in an ONNX Loop until terminated.
    // Let inference enter the kernel after the start callback before stopping it.
    std::thread::sleep(Duration::from_millis(30));
    finish_job(
        &worker,
        2,
        "request".into(),
        test_result("threat", "attack", 0.99, "L3"),
    );
    let result = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("active ONNX run did not stop");
    scan.join().unwrap();
    assert_eq!(result.level, "L2");
    assert!(result.layers.iter().any(|layer| layer
        .details
        .get("degraded_reason")
        .and_then(|v| v.as_str())
        == Some("request_wide_early_exit")));
    {
        let registry = requests.state.lock().unwrap();
        assert!(registry.active_runs.is_empty());
        assert_eq!(
            registry
                .ready
                .iter()
                .filter(|event| matches!(event, QueuedSecurityEvent::Finished { .. }))
                .count(),
            1
        );
        assert!(matches!(
            registry.requests["request"].completion,
            Some(SecurityRequestCompletion::Complete)
        ));
    }
    let before = requests.state.lock().unwrap().ready.len();
    publish_progress(
        &worker,
        QueuedSecurityProgress {
            request_id: "request".into(),
            category: "injection".into(),
            model: "wolf-defender-small".into(),
            stage: "late".into(),
            completed_chunks: 1,
            total_chunks: 1,
            inferred_chunks: 1,
            propagated_chunks: 0,
            cache_hits: 0,
            early_exit: false,
            coverage: 1.0,
            details: HashMap::new(),
        },
    );
    publish_provisional(&worker, "request".into(), result.clone());
    finish_job(&worker, 1, "request".into(), result);
    assert_eq!(requests.state.lock().unwrap().ready.len(), before);
    let recovered = model
        .lock()
        .unwrap()
        .infer_wolf_document_with_progress("", 0.93, backend, runtime, Default::default(), None)
        .unwrap();
    assert_eq!(recovered.document_logit, 0.0);
}
