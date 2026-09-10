use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use patronus_ark::{QueuedSecurityEvent, RequestId, SecurityGateway};
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::config::Config;
use crate::worker_admission::Admission;

const EVENT_CHANNEL_CAPACITY: usize = 64;
/// How long a finished request's event buffer is kept around so a client
/// that only starts polling `/v1/scan/{id}/events` after completion (a very
/// fast L1-only scan can finish before the client issues its second
/// request) still sees the full event history instead of a 404.
const FINISHED_RETENTION: Duration = Duration::from_secs(60);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct RequestChannel {
    /// Every event published for this request so far, replayed to any
    /// subscriber that joins late.
    buffer: Vec<Arc<QueuedSecurityEvent>>,
    sender: broadcast::Sender<QueuedSecurityEvent>,
    finished_at: Option<Instant>,
}

impl RequestChannel {
    fn new() -> Self {
        let (sender, _receiver) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            buffer: Vec::new(),
            sender,
            finished_at: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub gateway: Arc<SecurityGateway>,
    channels: Arc<Mutex<HashMap<RequestId, RequestChannel>>>,
    pub admission: Arc<Mutex<Admission>>,
    distributed_jobs: Arc<AtomicUsize>,
    // Match the single inference worker configured in main; the permit lives
    // inside the blocking task so cancelling HTTP cannot admit overlapping work.
    distributed_inference: Arc<Semaphore>,
}

pub struct DistributedJobGuard(Arc<AtomicUsize>);

impl Drop for DistributedJobGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl AppState {
    pub fn new(config: Config, gateway: SecurityGateway) -> Self {
        let state = Self {
            config: Arc::new(config),
            gateway: Arc::new(gateway),
            channels: Arc::new(Mutex::new(HashMap::new())),
            admission: Arc::new(Mutex::new(Admission::default())),
            distributed_jobs: Arc::new(AtomicUsize::new(0)),
            distributed_inference: Arc::new(Semaphore::new(1)),
        };
        state.spawn_dispatcher();
        state.spawn_sweeper();
        state
    }

    /// Call while holding admission: active submissions cover the interval
    /// before enqueue/register, and channels cover all work after registration.
    pub fn active_jobs(&self) -> usize {
        let queued = self
            .channels
            .lock()
            .expect("channel registry mutex poisoned")
            .values()
            .filter(|channel| channel.finished_at.is_none())
            .count();
        queued.saturating_add(self.distributed_jobs.load(Ordering::Acquire))
    }

    /// Count worker inference independently of the HTTP future so client cancellation cannot
    /// make recovery race a still-running blocking model invocation.
    pub fn begin_distributed_job(&self) -> DistributedJobGuard {
        self.distributed_jobs.fetch_add(1, Ordering::AcqRel);
        DistributedJobGuard(Arc::clone(&self.distributed_jobs))
    }

    pub fn try_begin_distributed_inference(
        &self,
    ) -> Result<(OwnedSemaphorePermit, DistributedJobGuard), TryAcquireError> {
        let permit = self.distributed_inference.clone().try_acquire_owned()?;
        Ok((permit, self.begin_distributed_job()))
    }

    /// Ensure a request event buffer exists. The dispatcher also creates the
    /// buffer on first event, covering fast scans that finish before the HTTP
    /// handler returns from enqueueing.
    pub fn register(&self, request_id: RequestId) {
        self.channels
            .lock()
            .expect("channel registry mutex poisoned")
            .entry(request_id)
            .or_insert_with(RequestChannel::new);
    }

    /// Subscribe to the event stream for a request registered via
    /// [`register`]: replays every event recorded so far, then continues
    /// with a live receiver for subsequent ones. Returns `None` once the
    /// request's buffer has been swept (see `FINISHED_RETENTION`).
    pub fn subscribe(
        &self,
        request_id: &str,
    ) -> Option<(
        Vec<QueuedSecurityEvent>,
        broadcast::Receiver<QueuedSecurityEvent>,
    )> {
        let (buffer, receiver) = {
            let channels = self
                .channels
                .lock()
                .expect("channel registry mutex poisoned");
            let channel = channels.get(request_id)?;
            (channel.buffer.clone(), channel.sender.subscribe())
        };
        Some((
            buffer.into_iter().map(|event| (*event).clone()).collect(),
            receiver,
        ))
    }

    /// Background thread that drains `SecurityGateway::consume_next_event`
    /// (a single shared queue covering all concurrently running requests)
    /// and fans each event out to the channel registered for its
    /// `request_id`. `SecurityGateway` itself schedules and executes many
    /// requests concurrently; this loop only routes their results.
    fn spawn_dispatcher(&self) {
        let gateway = Arc::clone(&self.gateway);
        let channels = Arc::clone(&self.channels);
        std::thread::spawn(move || loop {
            let Some(event) = gateway.consume_next_event(Some(Duration::from_secs(1))) else {
                continue;
            };
            let request_id = event.request_id().to_string();
            let is_terminal = matches!(event, QueuedSecurityEvent::Finished { .. });
            let buffered_event = Arc::new(event.clone());

            let mut channels = channels.lock().expect("channel registry mutex poisoned");
            let channel = channels
                .entry(request_id)
                .or_insert_with(RequestChannel::new);
            channel.buffer.push(buffered_event);
            let _ = channel.sender.send(event);
            if is_terminal {
                channel.finished_at = Some(Instant::now());
            }
        });
    }

    /// Background thread that evicts finished requests' buffers once
    /// `FINISHED_RETENTION` has elapsed, bounding memory use.
    fn spawn_sweeper(&self) {
        let channels = Arc::clone(&self.channels);
        std::thread::spawn(move || loop {
            std::thread::sleep(SWEEP_INTERVAL);
            let mut channels = channels.lock().expect("channel registry mutex poisoned");
            channels.retain(|_, channel| match channel.finished_at {
                Some(finished_at) => finished_at.elapsed() < FINISHED_RETENTION,
                None => true,
            });
        });
    }
}
