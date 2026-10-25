//! Shared cooperative cancellation for one logical scanning operation.
use crate::ScanError;
#[cfg(feature = "wolf")]
use std::{
    collections::HashMap,
    sync::{atomic::AtomicU64, Condvar, Mutex, Weak},
};
use std::{
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[cfg(feature = "wolf")]
type Abort = Arc<dyn Fn() + Send + Sync>;
struct State {
    deadline: Option<Instant>,
    reason: AtomicU8,
    #[cfg(feature = "wolf")]
    next_abort: AtomicU64,
    #[cfg(feature = "wolf")]
    aborts: Mutex<HashMap<u64, Abort>>,
}

/// A cloneable work budget. Cancellation also signals any registered native model run.
/// Checkpoints stop further work; an ONNX kernel acknowledges termination cooperatively.
#[derive(Clone)]
pub struct ScanControl(Arc<State>);
impl Default for ScanControl {
    fn default() -> Self {
        Self::new(None)
    }
}
impl ScanControl {
    fn new(deadline: Option<Instant>) -> Self {
        Self(Arc::new(State {
            deadline,
            reason: AtomicU8::new(0),
            #[cfg(feature = "wolf")]
            next_abort: AtomicU64::new(0),
            #[cfg(feature = "wolf")]
            aborts: Mutex::new(HashMap::new()),
        }))
    }
    pub fn with_timeout(timeout: Duration) -> Result<Self, ScanError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ScanError::Config("scan timeout exceeds the monotonic clock range".into())
        })?;
        Ok(Self::new(Some(deadline)))
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.0.deadline
    }
    pub fn cancel(&self) {
        self.signal(1);
    }
    pub fn cancel_deadline(&self) {
        self.signal(2);
    }
    pub fn check(&self) -> Result<(), ScanError> {
        if self
            .0
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.cancel_deadline();
        }
        match self.0.reason.load(Ordering::Acquire) {
            0 => Ok(()),
            2 => Err(ScanError::DeadlineExceeded),
            _ => Err(ScanError::Cancelled),
        }
    }
    fn signal(&self, reason: u8) {
        if self
            .0
            .reason
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        #[cfg(feature = "wolf")]
        {
            let callbacks: Vec<_> = self
                .0
                .aborts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .cloned()
                .collect();
            // Native callbacks run outside the registry lock, including during teardown.
            for callback in callbacks {
                callback();
            }
        }
    }
    #[cfg(feature = "wolf")]
    pub(crate) fn register_abort(
        &self,
        callback: impl Fn() + Send + Sync + 'static,
    ) -> Result<AbortRegistration, ScanError> {
        let callback: Abort = Arc::new(callback);
        let id = self.0.next_abort.fetch_add(1, Ordering::Relaxed);
        self.0
            .aborts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&callback));
        let mut registration = AbortRegistration {
            state: Arc::downgrade(&self.0),
            id,
            watcher: None,
        };
        // Close the cancellation-before-registration race. Termination is idempotent.
        if self.check().is_err() {
            callback();
        } else if let Some(deadline) = self.0.deadline {
            registration.watcher = Some(DeadlineWatcher::start(self.clone(), deadline)?);
        }
        Ok(registration)
    }
}
#[cfg(feature = "wolf")]
pub(crate) struct AbortRegistration {
    state: Weak<State>,
    id: u64,
    watcher: Option<DeadlineWatcher>,
}
#[cfg(feature = "wolf")]
impl Drop for AbortRegistration {
    fn drop(&mut self) {
        // End the timer before removing its active native-run cancellation hook.
        self.watcher.take();
        if let Some(state) = self.state.upgrade() {
            state
                .aborts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.id);
        }
    }
}

/// A deadline timer exists only for an active native run with a finite budget.
/// It owns no scanner, work queue or model session, and is joined on teardown.
#[cfg(feature = "wolf")]
struct DeadlineWatcher {
    stopped: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}
#[cfg(feature = "wolf")]
impl DeadlineWatcher {
    fn start(control: ScanControl, deadline: Instant) -> Result<Self, ScanError> {
        let stopped = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&stopped);
        let thread = std::thread::Builder::new()
            .name("ark-scan-deadline".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let (lock, wake) = &*signal;
                let state = lock.lock().unwrap_or_else(|e| e.into_inner());
                let (state, elapsed) = wake
                    .wait_timeout_while(
                        state,
                        deadline.saturating_duration_since(Instant::now()),
                        |stopped| !*stopped,
                    )
                    .unwrap_or_else(|e| e.into_inner());
                if elapsed.timed_out() && !*state {
                    drop(state);
                    control.cancel_deadline();
                }
            })
            .map_err(|e| ScanError::Inference(format!("cannot start scan deadline timer: {e}")))?;
        Ok(Self {
            stopped,
            thread: Some(thread),
        })
    }
}
#[cfg(feature = "wolf")]
impl Drop for DeadlineWatcher {
    fn drop(&mut self) {
        let (lock, wake) = &*self.stopped;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        wake.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_expiration_keep_their_typed_cause() {
        let control = ScanControl::default();
        control.check().unwrap();
        control.cancel();
        control.cancel_deadline();
        assert!(matches!(control.check(), Err(ScanError::Cancelled)));
        let expired = ScanControl::with_timeout(Duration::ZERO).unwrap();
        assert!(matches!(expired.check(), Err(ScanError::DeadlineExceeded)));
    }
    #[test]
    fn invalid_clock_budget_is_a_configuration_error() {
        assert!(matches!(
            ScanControl::with_timeout(Duration::MAX),
            Err(ScanError::Config(_))
        ));
    }
    #[test]
    #[cfg(feature = "wolf")]
    fn abort_registration_handles_both_races_and_unregisters_completed_runs() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let control = ScanControl::default();
        let counter = Arc::clone(&calls);
        let completed = control
            .register_abort(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
        drop(completed);
        control.cancel();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let counter = Arc::clone(&calls);
        let _late = control
            .register_abort(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let running = ScanControl::default();
        let counter = Arc::clone(&calls);
        let _registered = running
            .register_abort(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
        running.cancel_deadline();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
    #[test]
    #[cfg(feature = "wolf")]
    fn finite_budget_signals_a_blocked_native_run_without_host_polling() {
        let control = ScanControl::with_timeout(Duration::from_millis(20)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let _active = control
            .register_abort(move || {
                let _ = tx.send(());
            })
            .unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(control.check(), Err(ScanError::DeadlineExceeded)));
    }
}
