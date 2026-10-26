//! One process-wide timer thread for active native-run deadlines.
use super::ScanControl;
use crate::ScanError;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    time::Instant,
};

type Key = (Instant, u64);
#[derive(Default)]
struct Queue {
    deadlines: Mutex<BTreeMap<Key, ScanControl>>,
    wake: Condvar,
}

impl Queue {
    fn shared() -> Result<&'static Arc<Self>, ScanError> {
        static QUEUE: OnceLock<Result<Arc<Queue>, String>> = OnceLock::new();
        QUEUE
            .get_or_init(|| {
                let queue = Arc::new(Self::default());
                let worker = Arc::clone(&queue);
                std::thread::Builder::new()
                    .name("ark-scan-deadlines".into())
                    .stack_size(128 * 1024)
                    .spawn(move || worker.run())
                    .map_err(|e| format!("cannot start scan deadline timer: {e}"))?;
                Ok(queue)
            })
            .as_ref()
            .map_err(|e| ScanError::Inference(e.clone()))
    }

    fn run(&self) {
        let mut deadlines = self.deadlines.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let Some((&key, _)) = deadlines.first_key_value() else {
                deadlines = self.wake.wait(deadlines).unwrap_or_else(|e| e.into_inner());
                continue;
            };
            let remaining = key.0.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                deadlines = self
                    .wake
                    .wait_timeout(deadlines, remaining)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
                continue;
            }
            let control = deadlines.remove(&key).expect("deadline is locked");
            drop(deadlines);
            control.cancel_deadline();
            deadlines = self.deadlines.lock().unwrap_or_else(|e| e.into_inner());
        }
    }
}

pub(super) struct Deadline {
    queue: &'static Arc<Queue>,
    key: Key,
}
impl Deadline {
    pub(super) fn register(control: ScanControl, deadline: Instant) -> Result<Self, ScanError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let queue = Queue::shared()?;
        let key = (deadline, NEXT.fetch_add(1, Ordering::Relaxed));
        queue
            .deadlines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, control);
        queue.wake.notify_one();
        Ok(Self { queue, key })
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        self.queue
            .deadlines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
        self.queue.wake.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn deadlines_across_controls_reuse_one_thread_and_wake_for_earlier_work() {
        let (tx, rx) = mpsc::channel();
        let later = ScanControl::with_timeout(Duration::from_secs(60)).unwrap();
        let first_tx = tx.clone();
        let _later = later
            .register_abort(move || {
                first_tx
                    .send(("later", std::thread::current().id()))
                    .unwrap();
            })
            .unwrap();
        let earlier = ScanControl::with_timeout(Duration::from_millis(20)).unwrap();
        let _earlier = earlier
            .register_abort(move || {
                tx.send(("earlier", std::thread::current().id())).unwrap();
            })
            .unwrap();
        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(first.0, "earlier");
        let (second_tx, second_rx) = mpsc::channel();
        let next = ScanControl::with_timeout(Duration::from_millis(20)).unwrap();
        let _next = next
            .register_abort(move || {
                second_tx.send(std::thread::current().id()).unwrap();
            })
            .unwrap();
        assert_eq!(
            first.1,
            second_rx.recv_timeout(Duration::from_secs(2)).unwrap()
        );
        assert!(matches!(earlier.check(), Err(ScanError::DeadlineExceeded)));
        assert!(matches!(next.check(), Err(ScanError::DeadlineExceeded)));
        assert!(later.check().is_ok());
    }

    #[test]
    fn completed_runs_do_not_receive_a_late_deadline_callback() {
        let (tx, rx) = mpsc::channel();
        let control = ScanControl::with_timeout(Duration::from_millis(100)).unwrap();
        let completed = control
            .register_abort(move || {
                let _ = tx.send(());
            })
            .unwrap();
        drop(completed);
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }
}
