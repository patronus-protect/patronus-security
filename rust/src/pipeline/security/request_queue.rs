#[cfg(test)]
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::pipeline::{has_l3_pending, priority_index, ttl_ms, L3JobSpec, RequestState};
#[cfg(test)]
use crate::{ExecutionBackend, LayerResult};
use crate::{RequestId, SecurityCategory, SecurityScanResult};

use super::PatronusSecurity;

impl PatronusSecurity {
    /// Scan text with a single category.
    pub fn scan_category(&self, category: SecurityCategory, text: &str) -> Vec<SecurityScanResult> {
        let request_id = self.enqueue_categories(vec![category], text);
        self.drain_request(request_id)
    }

    /// Queue a scan with every category configured on this gateway.
    pub fn enqueue(&self, text: impl Into<String>) -> RequestId {
        self.enqueue_categories(self.categories.clone(), text)
    }

    /// Queue a scan with a caller-provided category subset.
    pub fn enqueue_categories(
        &self,
        categories: Vec<SecurityCategory>,
        text: impl Into<String>,
    ) -> RequestId {
        let text = text.into();
        let request_id = self.next_request_id();
        let results = self.scan_categories_direct(&categories, &text);
        let pending_l3_jobs = results
            .iter()
            .filter(|result| has_l3_pending(result))
            .count();
        let expected_results = results.len() + pending_l3_jobs;
        let state = RequestState {
            expected_results,
            completed_results: VecDeque::from(results),
            pending_l3_jobs,
            created_at: Instant::now(),
            category_filter: categories,
            finished: pending_l3_jobs == 0,
        };

        let mut states = self
            .requests
            .states
            .lock()
            .expect("request registry mutex poisoned");
        states.insert(request_id.clone(), state);
        self.requests.available.notify_all();
        drop(states);

        if pending_l3_jobs > 0 {
            self.enqueue_l3_jobs(&request_id, &text);
        }
        request_id
    }

    /// Consume the next complete ResultSchema result for a queued request.
    pub fn consume_results(
        &self,
        request_id: RequestId,
        timeout: Option<Duration>,
    ) -> Option<SecurityScanResult> {
        let mut states = self
            .requests
            .states
            .lock()
            .expect("request registry mutex poisoned");

        loop {
            if let Some(state) = states.get_mut(&request_id) {
                if let Some(result) = state.completed_results.pop_front() {
                    return Some(result);
                }
                if state.finished {
                    debug_assert!(state.expected_results >= state.completed_results.len());
                    let _pending_l3_jobs = state.pending_l3_jobs;
                    let _request_age_ms = state.created_at.elapsed().as_secs_f64() * 1000.0;
                    let _category_filter_len = state.category_filter.len();
                    states.remove(&request_id);
                    return None;
                }
            } else {
                return None;
            }

            states = match timeout {
                Some(timeout) => {
                    let (guard, wait_result) = self
                        .requests
                        .available
                        .wait_timeout(states, timeout)
                        .expect("request registry mutex poisoned");
                    if wait_result.timed_out() {
                        return None;
                    }
                    guard
                }
                None => self
                    .requests
                    .available
                    .wait(states)
                    .expect("request registry mutex poisoned"),
            };
        }
    }

    /// Return whether a queued request id is still known to the Rust aggregator.
    pub fn has_request(&self, request_id: &str) -> bool {
        self.requests
            .states
            .lock()
            .expect("request registry mutex poisoned")
            .contains_key(request_id)
    }

    fn next_request_id(&self) -> RequestId {
        let id = self.request_counter.fetch_add(1, Ordering::Relaxed);
        format!("rq-{id:016x}")
    }

    pub(super) fn drain_request(&self, request_id: RequestId) -> Vec<SecurityScanResult> {
        let mut results = Vec::new();
        while let Some(result) = self.consume_results(request_id.clone(), None) {
            results.push(result);
        }
        results
    }

    /// Scan text with a caller-provided category subset.
    pub fn scan_categories(
        &self,
        categories: &[SecurityCategory],
        text: &str,
    ) -> Vec<SecurityScanResult> {
        let request_id = self.enqueue_categories(categories.to_vec(), text);
        self.drain_request(request_id)
    }

    /// Scan text with every category configured on this gateway.
    pub fn scan_all(&self, text: &str) -> Vec<SecurityScanResult> {
        self.scan_categories(&self.categories, text)
    }

    fn enqueue_l3_jobs(&self, request_id: &str, text: &str) {
        let execution = self.scan_execution();
        let policy = execution.l3_policy();
        let states = self
            .requests
            .states
            .lock()
            .expect("request registry mutex poisoned");
        let Some(state) = states.get(request_id) else {
            return;
        };
        let jobs: Vec<L3JobSpec> = state
            .completed_results
            .iter()
            .filter(|result| has_l3_pending(result))
            .map(|result| L3JobSpec {
                request_id: request_id.to_string(),
                category: result.category.clone(),
                model: result.model.clone(),
                text: text.to_string(),
                fallback: result.clone(),
                priority: priority_index(policy, &result.category, &result.model),
                ttl_ms: ttl_ms(policy, &result.category, &result.model),
                backend: execution.backend(),
                degraded_factor: policy.degraded_factor,
            })
            .collect();
        drop(states);

        for job in jobs {
            self.l3_worker.enqueue(job);
        }
    }

    #[cfg(test)]
    pub(super) fn enqueue_test_l3_delay_request(
        &self,
        priority: usize,
        delay_ms: u64,
        model: &str,
    ) -> RequestId {
        let request_id = self.insert_test_l3_request(model);
        let fallback = self.test_l3_fallback(model);
        self.l3_worker.enqueue_test_delay(
            L3JobSpec {
                request_id: request_id.clone(),
                category: fallback.category.clone(),
                model: fallback.model.clone(),
                text: "test".to_string(),
                fallback,
                priority,
                ttl_ms: 10_000,
                backend: ExecutionBackend::Cpu,
                degraded_factor: 0.75,
            },
            delay_ms,
        );
        request_id
    }

    #[cfg(test)]
    pub(super) fn enqueue_test_l3_delay_requests(
        &self,
        jobs: &[(usize, u64, &str)],
    ) -> Vec<RequestId> {
        let mut specs = Vec::new();
        let mut request_ids = Vec::new();
        for (priority, delay_ms, model) in jobs {
            let request_id = self.insert_test_l3_request(model);
            let fallback = self.test_l3_fallback(model);
            specs.push((
                L3JobSpec {
                    request_id: request_id.clone(),
                    category: fallback.category.clone(),
                    model: fallback.model.clone(),
                    text: "test".to_string(),
                    fallback,
                    priority: *priority,
                    ttl_ms: 10_000,
                    backend: ExecutionBackend::Cpu,
                    degraded_factor: 0.75,
                },
                *delay_ms,
            ));
            request_ids.push(request_id);
        }
        self.l3_worker.enqueue_test_delays(specs);
        request_ids
    }

    #[cfg(test)]
    fn insert_test_l3_request(&self, model: &str) -> RequestId {
        let request_id = self.next_request_id();
        let fallback = self.test_l3_fallback(model);
        let state = RequestState {
            expected_results: 2,
            completed_results: VecDeque::from([fallback]),
            pending_l3_jobs: 1,
            created_at: Instant::now(),
            category_filter: vec![SecurityCategory::Injection],
            finished: false,
        };
        self.requests
            .states
            .lock()
            .expect("request registry mutex poisoned")
            .insert(request_id.clone(), state);
        self.requests.available.notify_all();
        request_id
    }

    #[cfg(test)]
    fn test_l3_fallback(&self, model: &str) -> SecurityScanResult {
        SecurityScanResult {
            category: "injection".to_string(),
            class_name: "benign".to_string(),
            confidence: 0.5,
            level: "L2".to_string(),
            model: model.to_string(),
            duration_ms: 1.0,
            layers: vec![
                LayerResult {
                    level: "L2".to_string(),
                    layer_type: "veto_consensus".to_string(),
                    class_name: "benign".to_string(),
                    confidence: 0.5,
                    matched: true,
                    duration_ms: 1.0,
                    thresholds: HashMap::new(),
                    details: HashMap::new(),
                },
                LayerResult {
                    level: "L3".to_string(),
                    layer_type: "l3_pending".to_string(),
                    class_name: "benign".to_string(),
                    confidence: 0.0,
                    matched: false,
                    duration_ms: 0.0,
                    thresholds: HashMap::new(),
                    details: HashMap::new(),
                },
            ],
        }
    }
}
