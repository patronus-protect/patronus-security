use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::WorkerConfig;

/// Idle workers are returned only after the upstream jobs finish, not after POST.
pub(super) struct WorkerPool {
    idle: Mutex<VecDeque<WorkerConfig>>,
    slots: Arc<Semaphore>,
    admission: Arc<Semaphore>,
}

pub(super) struct WorkerLease {
    pub worker: WorkerConfig,
    pool: Arc<WorkerPool>,
    slot: Option<OwnedSemaphorePermit>,
    _admission: OwnedSemaphorePermit,
    reusable: AtomicBool,
    unfinished: AtomicUsize,
}

impl WorkerPool {
    pub fn new(workers: Vec<WorkerConfig>, max_waiting: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(workers.len())),
            admission: Arc::new(Semaphore::new(workers.len() + max_waiting)),
            idle: Mutex::new(workers.into()),
        })
    }

    pub async fn acquire(self: &Arc<Self>) -> Result<Arc<WorkerLease>, &'static str> {
        let admission = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| "worker queue full")?;
        // Semaphore waiters are FIFO; the next completion supplies their worker.
        let slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "worker pool closed")?;
        let worker = self
            .idle
            .lock()
            .expect("idle worker mutex poisoned")
            .pop_front()
            .expect("worker slot without idle worker");
        Ok(Arc::new(WorkerLease {
            worker,
            pool: self.clone(),
            slot: Some(slot),
            _admission: admission,
            reusable: AtomicBool::new(true),
            unfinished: AtomicUsize::new(0),
        }))
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

    /// An interrupted stream does not prove that the worker stopped computing.
    /// Keep it out of circulation until the entrypoint is restarted by an operator.
    pub fn quarantine(&self) {
        self.reusable.store(false, Ordering::Relaxed);
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        if self.reusable.load(Ordering::Relaxed) && self.unfinished.load(Ordering::Relaxed) == 0 {
            self.pool
                .idle
                .lock()
                .expect("idle worker mutex poisoned")
                .push_back(self.worker.clone());
            // Return the semaphore permit only after publishing the idle worker.
        } else if let Some(slot) = self.slot.take() {
            slot.forget();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pool(count: usize, waiting: usize) -> Arc<WorkerPool> {
        WorkerPool::new(
            (1..=count)
                .map(|i| WorkerConfig {
                    name: format!("worker-{i}"),
                    url: format!("http://worker-{i}:8080"),
                })
                .collect(),
            waiting,
        )
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
}
