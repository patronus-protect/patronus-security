use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{ExecutionBackend, RequestId, SecurityCategory, SecurityScanResult};

use super::{degraded_error_result, degraded_timeout_result, l3_metadata_layer};

pub(crate) struct RequestRegistry {
    pub states: Mutex<HashMap<RequestId, RequestState>>,
    pub available: Condvar,
}

impl Default for RequestRegistry {
    fn default() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            available: Condvar::new(),
        }
    }
}

pub(crate) struct RequestState {
    pub expected_results: usize,
    pub completed_results: VecDeque<SecurityScanResult>,
    pub pending_l3_jobs: usize,
    pub created_at: Instant,
    pub category_filter: Vec<SecurityCategory>,
    pub finished: bool,
}

#[derive(Clone)]
pub(crate) struct L3Worker {
    state: Arc<L3WorkerState>,
}

struct L3WorkerState {
    jobs: Mutex<Vec<L3WorkerJob>>,
    available: Condvar,
    models: Mutex<HashMap<String, LazyOnnxTextClassifier>>,
    requests: Arc<RequestRegistry>,
    next_sequence: Mutex<u64>,
}

struct L3WorkerJob {
    request_id: RequestId,
    category: String,
    model: String,
    text: String,
    fallback: SecurityScanResult,
    priority: usize,
    ttl_ms: u64,
    enqueued_at: Instant,
    backend: ExecutionBackend,
    degraded_factor: f64,
    sequence: u64,
    #[cfg(test)]
    test_delay_ms: Option<u64>,
}

pub(crate) struct L3JobSpec {
    pub request_id: RequestId,
    pub category: String,
    pub model: String,
    pub text: String,
    pub fallback: SecurityScanResult,
    pub priority: usize,
    pub ttl_ms: u64,
    pub backend: ExecutionBackend,
    pub degraded_factor: f64,
}

impl L3Worker {
    pub(crate) fn start(requests: Arc<RequestRegistry>) -> Self {
        let state = Arc::new(L3WorkerState {
            jobs: Mutex::new(Vec::new()),
            available: Condvar::new(),
            models: Mutex::new(HashMap::new()),
            requests,
            next_sequence: Mutex::new(0),
        });
        let worker_state = Arc::clone(&state);
        thread::spawn(move || worker_loop(worker_state));
        Self { state }
    }

    pub(crate) fn register_model(
        &self,
        model: impl Into<String>,
        classifier: LazyOnnxTextClassifier,
    ) {
        self.state
            .models
            .lock()
            .expect("l3 model registry mutex poisoned")
            .insert(model.into(), classifier);
    }

    pub(crate) fn enqueue(&self, spec: L3JobSpec) {
        let sequence = {
            let mut next = self
                .state
                .next_sequence
                .lock()
                .expect("l3 sequence mutex poisoned");
            let sequence = *next;
            *next += 1;
            sequence
        };
        let job = L3WorkerJob {
            request_id: spec.request_id,
            category: spec.category,
            model: spec.model,
            text: spec.text,
            fallback: spec.fallback,
            priority: spec.priority,
            ttl_ms: spec.ttl_ms,
            enqueued_at: Instant::now(),
            backend: spec.backend,
            degraded_factor: spec.degraded_factor,
            sequence,
            #[cfg(test)]
            test_delay_ms: None,
        };
        self.state
            .jobs
            .lock()
            .expect("l3 job queue mutex poisoned")
            .push(job);
        self.state.available.notify_one();
    }

    #[cfg(test)]
    pub(crate) fn enqueue_test_delay(&self, spec: L3JobSpec, delay_ms: u64) {
        self.enqueue_test_delays(vec![(spec, delay_ms)]);
    }

    #[cfg(test)]
    pub(crate) fn enqueue_test_delays(&self, specs: Vec<(L3JobSpec, u64)>) {
        let mut jobs = self.state.jobs.lock().expect("l3 job queue mutex poisoned");
        let mut next = self
            .state
            .next_sequence
            .lock()
            .expect("l3 sequence mutex poisoned");
        for (spec, delay_ms) in specs {
            let sequence = *next;
            *next += 1;
            jobs.push(L3WorkerJob {
                request_id: spec.request_id,
                category: spec.category,
                model: spec.model,
                text: spec.text,
                fallback: spec.fallback,
                priority: spec.priority,
                ttl_ms: spec.ttl_ms,
                enqueued_at: Instant::now(),
                backend: spec.backend,
                degraded_factor: spec.degraded_factor,
                sequence,
                test_delay_ms: Some(delay_ms),
            });
        }
        drop(next);
        drop(jobs);
        self.state.available.notify_one();
    }
}

fn worker_loop(state: Arc<L3WorkerState>) {
    loop {
        let job = next_job(&state);
        let result = execute_job(&state, job);
        finish_job(&state.requests, result.0, result.1);
    }
}

fn next_job(state: &L3WorkerState) -> L3WorkerJob {
    let mut jobs = state.jobs.lock().expect("l3 job queue mutex poisoned");
    loop {
        if !jobs.is_empty() {
            let selected = jobs
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    left.priority
                        .cmp(&right.priority)
                        .then_with(|| left.sequence.cmp(&right.sequence))
                })
                .map(|(index, _)| index)
                .unwrap();
            return jobs.swap_remove(selected);
        }
        jobs = state
            .available
            .wait(jobs)
            .expect("l3 job queue mutex poisoned");
    }
}

fn execute_job(state: &L3WorkerState, job: L3WorkerJob) -> (RequestId, SecurityScanResult) {
    #[cfg(test)]
    if let Some(delay_ms) = job.test_delay_ms {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let mut result = job.fallback;
        for layer in &mut result.layers {
            layer.matched = false;
        }
        let mut layer = l3_metadata_layer(
            "test_l3",
            &job.model,
            1.0,
            job.enqueued_at.elapsed().as_secs_f64() * 1000.0,
        );
        layer
            .details
            .insert("category".to_string(), serde_json::json!(job.category));
        layer
            .details
            .insert("l3_worker".to_string(), serde_json::json!("rust_l3_worker"));
        layer
            .details
            .insert("priority".to_string(), serde_json::json!(job.priority));
        result.layers.push(layer);
        result.class_name = "test_l3".to_string();
        result.confidence = 1.0;
        result.level = "L3".to_string();
        result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
        return (job.request_id, result);
    }

    let queued_ms = job.enqueued_at.elapsed().as_secs_f64() * 1000.0;
    if queued_ms > job.ttl_ms as f64 {
        return (
            job.request_id,
            degraded_timeout_result(job.fallback, queued_ms, job.ttl_ms, job.degraded_factor),
        );
    }

    let mut models = state
        .models
        .lock()
        .expect("l3 model registry mutex poisoned");
    let Some(model) = models.get_mut(&job.model) else {
        return (
            job.request_id,
            degraded_error_result(
                job.fallback,
                queued_ms,
                job.ttl_ms,
                job.degraded_factor,
                format!("L3 model '{}' is not registered", job.model),
            ),
        );
    };

    let started = Instant::now();
    match model.infer(&job.text, job.backend) {
        Ok(l3_result) => {
            let mut result = job.fallback;
            for layer in &mut result.layers {
                layer.matched = false;
            }
            let mut layer = l3_metadata_layer(
                &l3_result.class_name,
                &job.model,
                l3_result.confidence,
                started.elapsed().as_secs_f64() * 1000.0,
            );
            layer
                .details
                .insert("l3_worker".to_string(), serde_json::json!("rust_l3_worker"));
            layer
                .details
                .insert("category".to_string(), serde_json::json!(job.category));
            layer
                .details
                .insert("queued_ms".to_string(), serde_json::json!(queued_ms));
            layer
                .details
                .insert("ttl_ms".to_string(), serde_json::json!(job.ttl_ms));
            layer
                .details
                .insert("priority".to_string(), serde_json::json!(job.priority));
            layer.details.insert(
                "model_name".to_string(),
                serde_json::json!(model.model_name()),
            );
            if let Some(model_path) = model.model_path() {
                layer.details.insert(
                    "model_path".to_string(),
                    serde_json::json!(model_path.display().to_string()),
                );
            }
            if let Some(precision) = model.precision() {
                layer
                    .details
                    .insert("precision".to_string(), serde_json::json!(precision));
            }
            if let Some(provider) = model.execution_provider() {
                layer.details.insert(
                    "execution_provider".to_string(),
                    serde_json::json!(provider),
                );
            }
            result.layers.push(layer);
            result.class_name = l3_result.class_name;
            result.confidence = l3_result.confidence;
            result.level = "L3".to_string();
            result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
            (job.request_id, result)
        }
        Err(err) => (
            job.request_id,
            degraded_error_result(
                job.fallback,
                queued_ms,
                job.ttl_ms,
                job.degraded_factor,
                err.to_string(),
            ),
        ),
    }
}

fn finish_job(requests: &Arc<RequestRegistry>, request_id: RequestId, result: SecurityScanResult) {
    let mut states = requests
        .states
        .lock()
        .expect("request registry mutex poisoned");
    if let Some(state) = states.get_mut(&request_id) {
        state.completed_results.push_back(result);
        state.pending_l3_jobs = state.pending_l3_jobs.saturating_sub(1);
        if state.pending_l3_jobs == 0 {
            state.finished = true;
        }
    }
    requests.available.notify_all();
}
