use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::WorkerConfig;

#[derive(Clone, Deserialize)]
pub(super) struct WorkerStatus {
    pub instance_id: String,
    pub epoch: u64,
    pub ready: bool,
    pub active_submissions: usize,
    pub active_jobs: usize,
}

struct PoolState {
    idle: VecDeque<WorkerConfig>,
    quarantined: HashSet<String>,
    status: HashMap<String, (WorkerStatus, Instant)>,
}

/// Idle workers are returned only after every upstream job finishes. Recovery
/// requires an authenticated idle fence, not a successful liveness check.
pub(super) struct WorkerPool {
    workers: Vec<WorkerConfig>,
    state: Mutex<PoolState>,
    slots: Arc<Semaphore>,
    admission: Arc<Semaphore>,
}

pub(super) struct WorkerLease {
    pub worker: WorkerConfig,
    pub instance_id: String,
    pub epoch: u64,
    pool: Arc<WorkerPool>,
    slot: Option<OwnedSemaphorePermit>,
    _admission: OwnedSemaphorePermit,
    reusable: AtomicBool,
    unfinished: AtomicUsize,
}

impl PoolState {
    fn healthy(&self, name: &str) -> bool {
        self.status.get(name).is_some_and(|(status, checked)| {
            status.ready && checked.elapsed() < Duration::from_secs(5)
        })
    }
}

impl WorkerPool {
    pub fn new(workers: Vec<WorkerConfig>, max_waiting: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(0)),
            admission: Arc::new(Semaphore::new(workers.len() + max_waiting)),
            state: Mutex::new(PoolState {
                idle: VecDeque::new(),
                quarantined: workers.iter().map(|worker| worker.name.clone()).collect(),
                status: HashMap::new(),
            }),
            workers,
        })
    }

    #[cfg(test)]
    pub fn healthy_test_pool() -> Arc<Self> {
        let worker = WorkerConfig {
            name: "healthy-fixture".into(),
            url: "http://unused".into(),
        };
        let pool = Self::new(vec![worker.clone()], 0);
        pool.recovered(
            &worker,
            WorkerStatus {
                instance_id: "fixture-process".into(),
                epoch: 1,
                ready: true,
                active_submissions: 0,
                active_jobs: 0,
            },
        );
        pool
    }

    pub fn ready(&self) -> bool {
        let state = self.state.lock().expect("worker state mutex poisoned");
        self.workers
            .iter()
            .any(|worker| !state.quarantined.contains(&worker.name) && state.healthy(&worker.name))
    }

    pub async fn acquire(self: &Arc<Self>) -> Result<Arc<WorkerLease>, &'static str> {
        let admission = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| "worker queue full")?;
        loop {
            // Semaphore waiters are FIFO; the next completion supplies their worker.
            let slot = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "worker pool closed")?;
            let mut state = self.state.lock().expect("worker state mutex poisoned");
            let worker = state
                .idle
                .pop_front()
                .expect("worker slot without idle worker");
            if !state.healthy(&worker.name) {
                state.quarantined.insert(worker.name.clone());
                slot.forget();
                continue;
            }
            let status = &state.status[&worker.name].0;
            return Ok(Arc::new(WorkerLease {
                instance_id: status.instance_id.clone(),
                epoch: status.epoch,
                worker,
                pool: self.clone(),
                slot: Some(slot),
                _admission: admission,
                reusable: AtomicBool::new(true),
                unfinished: AtomicUsize::new(0),
            }));
        }
    }

    fn recovered(&self, worker: &WorkerConfig, status: WorkerStatus) {
        if !status.ready
            || status.active_submissions != 0
            || status.active_jobs != 0
            || status.instance_id.is_empty()
        {
            return;
        }
        let mut state = self.state.lock().expect("worker state mutex poisoned");
        if state.quarantined.remove(&worker.name) {
            state
                .status
                .insert(worker.name.clone(), (status, Instant::now()));
            state.idle.push_back(worker.clone());
            self.slots.add_permits(1);
            tracing::info!(worker = %worker.name, "worker admitted after idle fence");
        }
    }

    fn observed(&self, worker: &WorkerConfig, status: Option<WorkerStatus>) {
        let mut state = self.state.lock().expect("worker state mutex poisoned");
        let Some((previous, checked)) = state.status.get_mut(&worker.name) else {
            return;
        };
        let healthy = status.as_ref().is_some_and(|status| {
            status.ready
                && status.instance_id == previous.instance_id
                && status.epoch == previous.epoch
        });
        previous.ready = healthy;
        *checked = Instant::now();
        if !healthy {
            // Reserve a free slot before removing an idle worker. Already-awoken
            // acquirers still own their permits and will quarantine on inspection.
            if let Some(index) = state.idle.iter().position(|idle| idle.name == worker.name) {
                if let Ok(slot) = self.slots.clone().try_acquire_owned() {
                    state.idle.remove(index);
                    state.quarantined.insert(worker.name.clone());
                    slot.forget();
                }
            }
        }
    }

    pub fn spawn_monitor(self: &Arc<Self>, client: reqwest::Client, token: String) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                futures::future::join_all(pool.workers.iter().map(|worker| {
                    let pool = &pool;
                    let client = &client;
                    let token = &token;
                    async move {
                        let recover = pool
                            .state
                            .lock()
                            .expect("worker state mutex poisoned")
                            .quarantined
                            .contains(&worker.name);
                        let path = if recover {
                            "/internal/recover"
                        } else {
                            "/internal/status"
                        };
                        let url = format!("{}{}", worker.url.trim_end_matches('/'), path);
                        let request = if recover {
                            client.post(url)
                        } else {
                            client.get(url)
                        };
                        // Bound both response headers and JSON body reads.
                        let status = tokio::time::timeout(Duration::from_millis(500), async {
                            let mut response = request.bearer_auth(token).send().await.ok()?;
                            if !response.status().is_success() {
                                return None;
                            }
                            let mut body = Vec::new();
                            while let Some(chunk) = response.chunk().await.ok()? {
                                if body.len() + chunk.len() > 4096 {
                                    return None;
                                }
                                body.extend_from_slice(&chunk);
                            }
                            serde_json::from_slice::<WorkerStatus>(&body).ok()
                        })
                        .await
                        .ok()
                        .flatten();
                        if recover {
                            if let Some(status) = status {
                                pool.recovered(worker, status);
                            }
                        } else {
                            pool.observed(worker, status);
                        }
                    }
                }))
                .await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

impl WorkerLease {
    pub fn start_dispatch(&self) {
        self.unfinished.store(1, Ordering::Relaxed);
    }
    pub fn accepted(&self, jobs: usize) {
        self.unfinished.store(jobs, Ordering::Relaxed);
    }
    pub fn finished(&self) {
        self.unfinished.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn quarantine(&self) {
        self.reusable.store(false, Ordering::Relaxed);
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().expect("worker state mutex poisoned");
        if self.reusable.load(Ordering::Relaxed)
            && self.unfinished.load(Ordering::Relaxed) == 0
            && state.healthy(&self.worker.name)
        {
            state.idle.push_back(self.worker.clone());
            // Return the permit only after publishing the idle worker.
        } else if let Some(slot) = self.slot.take() {
            state.quarantined.insert(self.worker.name.clone());
            slot.forget();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pool(count: usize, waiting: usize) -> Arc<WorkerPool> {
        let pool = WorkerPool::new(
            (1..=count)
                .map(|i| WorkerConfig {
                    name: format!("worker-{i}"),
                    url: format!("http://worker-{i}:8080"),
                })
                .collect(),
            waiting,
        );
        for worker in &pool.workers {
            pool.recovered(worker, healthy_status());
        }
        pool
    }

    fn healthy_status() -> WorkerStatus {
        WorkerStatus {
            instance_id: "process-1".into(),
            epoch: 1,
            ready: true,
            active_submissions: 0,
            active_jobs: 0,
        }
    }

    #[tokio::test]
    async fn next_request_uses_first_finished_worker_not_round_robin() {
        let pool = pool(3, 2);
        let slow = pool.acquire().await.unwrap();
        let fast = pool.acquire().await.unwrap();
        let other = pool.acquire().await.unwrap();
        let waiting_pool = pool.clone();
        let next = tokio::spawn(async move { waiting_pool.acquire().await.unwrap() });
        tokio::task::yield_now().await;
        assert!(
            !next.is_finished(),
            "busy workers must not receive another request"
        );
        drop(fast);
        let next = tokio::time::timeout(Duration::from_secs(1), next)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.worker.name, "worker-2");
        assert_eq!(slow.worker.name, "worker-1");
        assert_eq!(other.worker.name, "worker-3");
    }

    #[tokio::test]
    async fn batch_lease_is_held_until_last_job_finishes() {
        let pool = pool(1, 1);
        let first = pool.acquire().await.unwrap();
        let second = first.clone();
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pool.acquire())
                .await
                .is_err()
        );
        drop(second);
        assert!(tokio::time::timeout(Duration::from_secs(1), pool.acquire())
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn cancelled_waiter_releases_admission_and_saturation_is_bounded() {
        let pool = pool(1, 1);
        let active = pool.acquire().await.unwrap();
        let waiting_pool = pool.clone();
        let waiting = tokio::spawn(async move { waiting_pool.acquire().await });
        tokio::task::yield_now().await;
        assert!(matches!(pool.acquire().await, Err("worker queue full")));
        waiting.abort();
        let _ = waiting.await;
        drop(active);
        assert!(pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn uncertain_worker_is_not_reused_but_other_workers_continue() {
        let pool = pool(2, 1);
        let failed = pool.acquire().await.unwrap();
        failed.quarantine();
        drop(failed);
        for _ in 0..3 {
            let active = pool.acquire().await.unwrap();
            assert_eq!(active.worker.name, "worker-2");
        }
    }

    #[tokio::test]
    async fn cancelled_dispatch_does_not_release_an_upstream_worker_still_computing() {
        let pool = pool(2, 1);
        let cancelled = pool.acquire().await.unwrap();
        cancelled.start_dispatch();
        drop(cancelled);
        assert_eq!(pool.acquire().await.unwrap().worker.name, "worker-2");
    }

    #[tokio::test]
    async fn accepted_batch_is_reusable_only_after_all_terminal_events() {
        let pool = pool(1, 1);
        let batch = pool.acquire().await.unwrap();
        batch.start_dispatch();
        batch.accepted(2);
        batch.finished();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pool.acquire())
                .await
                .is_err()
        );
        batch.finished();
        drop(batch);
        assert!(pool.acquire().await.is_ok());
    }
    #[tokio::test]
    async fn busy_healthy_worker_remains_ready_but_quarantine_does_not() {
        let pool = pool(1, 0);
        let worker = pool.acquire().await.unwrap();
        assert!(pool.ready());
        worker.quarantine();
        drop(worker);
        assert!(!pool.ready());
    }

    #[tokio::test]
    async fn recovery_requires_idle_and_does_not_duplicate_slots() {
        let pool = pool(1, 0);
        let worker = pool.acquire().await.unwrap();
        let config = worker.worker.clone();
        worker.quarantine();
        drop(worker);
        let mut busy = healthy_status();
        busy.active_jobs = 1;
        pool.recovered(&config, busy);
        assert!(!pool.ready());
        let mut submitting = healthy_status();
        submitting.active_submissions = 1;
        pool.recovered(&config, submitting);
        assert!(!pool.ready());
        let mut recovered = healthy_status();
        recovered.epoch = 2;
        pool.recovered(&config, recovered.clone());
        pool.recovered(&config, recovered);
        assert!(pool.ready());
        assert_eq!(pool.slots.available_permits(), 1);
        assert_eq!(pool.acquire().await.unwrap().epoch, 2);
    }

    #[tokio::test]
    async fn failed_idle_worker_is_removed_and_restarted_worker_needs_new_fence() {
        let pool = pool(1, 0);
        let worker = pool.workers[0].clone();
        let mut restarted = healthy_status();
        restarted.instance_id = "process-2".into();
        pool.observed(&worker, Some(restarted.clone()));
        assert!(!pool.ready());
        assert_eq!(pool.slots.available_permits(), 0);
        pool.recovered(&worker, restarted);
        let lease = pool.acquire().await.unwrap();
        assert_eq!(lease.instance_id, "process-2");
    }

    #[tokio::test]
    async fn failed_busy_worker_is_quarantined_on_release() {
        let pool = pool(1, 0);
        let worker = pool.acquire().await.unwrap();
        pool.observed(&worker.worker, None);
        assert!(!pool.ready());
        drop(worker);
        assert_eq!(pool.slots.available_permits(), 0);
        assert!(pool.state.lock().unwrap().quarantined.contains("worker-1"));
    }
}
