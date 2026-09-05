// SPDX-License-Identifier: GPL-3.0-only
//! Bounded request-level admission and fair attempt scheduling.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};

const HISTORY: usize = 128;
const AGING: Duration = Duration::from_secs(1);
pub(crate) const MAX_REQUESTS: usize = 128;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Estimate {
    pub ewma: f64,
    pub p50: f64,
    pub p95: f64,
    #[serde(skip)]
    samples: VecDeque<f64>,
}
impl Estimate {
    pub fn new(prior: f64) -> Self {
        Self {
            ewma: prior,
            p50: prior,
            p95: prior,
            samples: VecDeque::new(),
        }
    }
    pub fn observe(&mut self, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        self.ewma = if self.samples.is_empty() {
            value
        } else {
            0.2 * value + 0.8 * self.ewma
        };
        if self.samples.len() == HISTORY {
            self.samples.pop_front();
        }
        self.samples.push_back(value);
        let mut sorted = self.samples.iter().copied().collect::<Vec<_>>();
        sorted.sort_by(f64::total_cmp);
        self.p50 = sorted[(sorted.len() - 1) / 2];
        self.p95 = sorted[(sorted.len() * 95).div_ceil(100) - 1];
    }
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Forecast {
    pub rps: Estimate,
    pub tokens: Estimate,
    pub promotion: Estimate,
}
struct Request {
    remaining: f64,
    service: f64,
    last: Instant,
    active: usize,
    pending: BTreeMap<u64, f64>,
}
struct State {
    requests: BTreeMap<u64, Request>,
    next: u64,
    active: usize,
    floor: f64,
    forecast: Forecast,
    window: Instant,
    arrivals: usize,
    worker_rate: f64,
    uncertain_workers: bool,
}
impl State {
    fn tick(&mut self, now: Instant) {
        let seconds = now.duration_since(self.window).as_secs();
        if seconds == 0 {
            return;
        }
        self.forecast.rps.observe(self.arrivals as f64);
        // Bound both runtime and histories after long idle periods.
        for _ in 1..seconds.min(HISTORY as u64 + 1) {
            self.forecast.rps.observe(0.0);
        }
        self.arrivals = 0;
        self.window += Duration::from_secs(seconds);
    }
    fn reserve(&self, capacity: usize) -> usize {
        let f = &self.forecast;
        let demand =
            f.rps.ewma.max(f.rps.p50) * f.tokens.ewma.max(f.tokens.p95) * (1.0 + f.promotion.p95)
                / self.worker_rate.max(1.0);
        (demand.ceil() as usize).min(capacity / 2)
    }
    fn winner(&self, now: Instant, capacity: usize) -> Option<u64> {
        if self.active >= capacity {
            return None;
        }
        let ready = || self.requests.iter().filter(|(_, r)| !r.pending.is_empty());
        if let Some((id, _)) = ready()
            .filter(|(_, r)| now.duration_since(r.last) >= AGING)
            .min_by_key(|(id, r)| (r.last, **id))
        {
            return Some(*id);
        }
        let typical = self.forecast.tokens.p50.max(1.0);
        let small_waiting = ready().any(|(_, r)| r.remaining <= typical);
        // One-second forecast horizon; reserve is lent to bulk when no small work waits.
        let reserve = self.reserve(capacity);
        let bulk_active: usize = self
            .requests
            .values()
            .filter(|r| r.remaining > typical)
            .map(|r| r.active)
            .sum();
        ready()
            .filter(|(_, r)| {
                !small_waiting || r.remaining <= typical || bulk_active < capacity - reserve
            })
            .min_by(|(a, x), (b, y)| {
                x.service
                    .total_cmp(&y.service)
                    .then_with(|| x.remaining.total_cmp(&y.remaining))
                    .then(a.cmp(b))
            })
            .map(|(id, _)| *id)
    }
}
#[derive(Clone)]
pub struct FairQueue {
    state: Arc<Mutex<State>>,
    wake: Arc<Notify>,
    capacity: usize,
}
pub struct RequestHandle {
    queue: FairQueue,
    id: u64,
}
pub struct AttemptPermit {
    queue: FairQueue,
    request: u64,
    ticket: u64,
    active: bool,
}
impl FairQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                requests: BTreeMap::new(),
                next: 0,
                active: 0,
                floor: 0.0,
                forecast: Forecast {
                    rps: Estimate::new(0.0),
                    tokens: Estimate::new(3072.0),
                    promotion: Estimate::new(0.25),
                },
                window: Instant::now(),
                arrivals: 0,
                worker_rate: 3072.0,
                uncertain_workers: false,
            })),
            wake: Arc::new(Notify::new()),
            capacity: capacity.max(1),
        }
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn register(&self) -> Option<RequestHandle> {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();
        s.tick(now);
        s.arrivals += 1;
        if s.requests.len() >= MAX_REQUESTS {
            return None;
        }
        s.next += 1;
        let id = s.next;
        let service = s.floor;
        s.requests.insert(
            id,
            Request {
                remaining: 1.0,
                service,
                last: now,
                active: 0,
                pending: BTreeMap::new(),
            },
        );
        Some(RequestHandle {
            queue: self.clone(),
            id,
        })
    }
    pub fn forecast(&self) -> Forecast {
        let mut s = self.state.lock().unwrap();
        s.tick(Instant::now());
        s.forecast.clone()
    }
    pub fn update_workers(&self, rates: &[Estimate]) {
        let mut s = self.state.lock().unwrap();
        if !rates.is_empty() {
            s.worker_rate = rates
                .iter()
                .map(|r| r.ewma.min(r.p50).max(1.0))
                .sum::<f64>()
                / rates.len() as f64;
            s.uncertain_workers = rates.iter().any(|r| r.p95 > 2.0 * r.p50.max(1.0));
        }
    }
    pub fn batch_size(&self, cold: usize) -> usize {
        let mut s = self.state.lock().unwrap();
        s.tick(Instant::now());
        if s.requests.len() > 1 || s.forecast.promotion.p95 > 0.5 || s.uncertain_workers {
            4
        } else if s.forecast.tokens.samples.len() < 4 {
            if cold <= 4 {
                4
            } else if cold >= 8 {
                8
            } else {
                6
            }
        } else {
            8
        }
    }
}
impl RequestHandle {
    pub fn prepare(&self, tokens: usize, pipelines: usize) {
        let mut s = self.queue.state.lock().unwrap();
        s.forecast.tokens.observe(tokens as f64);
        s.requests.get_mut(&self.id).unwrap().remaining = (tokens * pipelines.max(1)) as f64;
    }
    pub fn complete(&self, work: f64, promoted: usize, eligible: usize) {
        let mut s = self.queue.state.lock().unwrap();
        if eligible > 0 {
            s.forecast
                .promotion
                .observe(promoted as f64 / eligible as f64);
        }
        let r = s.requests.get_mut(&self.id).unwrap();
        r.remaining = (r.remaining - work).max(0.0);
    }
    pub async fn acquire(&self, work: f64) -> AttemptPermit {
        let mut guard = {
            let mut s = self.queue.state.lock().unwrap();
            s.next += 1;
            let ticket = s.next;
            let floor = s.floor;
            let r = s.requests.get_mut(&self.id).unwrap();
            if r.pending.is_empty() && r.active == 0 {
                r.service = r.service.max(floor);
                r.last = Instant::now();
            }
            assert!(r.pending.len() < self.queue.capacity);
            r.pending.insert(ticket, work.max(1.0));
            AttemptPermit {
                queue: self.queue.clone(),
                request: self.id,
                ticket,
                active: false,
            }
        };
        self.queue.wake.notify_waiters();
        loop {
            let notified = self.queue.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut s = self.queue.state.lock().unwrap();
                let now = Instant::now();
                s.tick(now);
                let first = s.requests[&self.id]
                    .pending
                    .first_key_value()
                    .map(|(id, _)| *id);
                if first == Some(guard.ticket)
                    && s.winner(now, self.queue.capacity) == Some(self.id)
                {
                    let typical = s.forecast.tokens.p50.max(1.0);
                    let promotion = s.forecast.promotion.ewma;
                    let r = s.requests.get_mut(&self.id).unwrap();
                    let weight = 1.0 + (typical / r.remaining.max(1.0)).sqrt().min(1.0);
                    r.service += work.max(1.0) * (1.0 + promotion) / weight;
                    r.last = now;
                    r.active += 1;
                    r.pending.remove(&guard.ticket);
                    s.active += 1;
                    s.floor = s
                        .requests
                        .values()
                        .filter(|r| r.active > 0 || !r.pending.is_empty())
                        .map(|r| r.service)
                        .min_by(f64::total_cmp)
                        .unwrap_or(s.floor)
                        .max(s.floor);
                    guard.active = true;
                    self.queue.wake.notify_waiters();
                    return guard;
                }
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep(AGING) => {} }
        }
    }
}
impl Drop for RequestHandle {
    fn drop(&mut self) {
        self.queue.state.lock().unwrap().requests.remove(&self.id);
        self.queue.wake.notify_waiters();
    }
}
impl Drop for AttemptPermit {
    fn drop(&mut self) {
        let mut s = self.queue.state.lock().unwrap();
        if self.active {
            s.active -= 1;
        }
        if let Some(r) = s.requests.get_mut(&self.request) {
            if self.active {
                r.active -= 1;
            } else {
                r.pending.remove(&self.ticket);
            }
        }
        drop(s);
        self.queue.wake.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    #[test]
    fn statistics_are_bounded_and_idle_arrivals_decay() {
        let mut estimate = Estimate::new(5.0);
        for n in 1..=256 {
            estimate.observe(n as f64);
        }
        assert_eq!(estimate.samples.len(), HISTORY);
        assert_eq!(estimate.p50, 192.0);
        assert_eq!(estimate.p95, 250.0);
        estimate.observe(f64::NAN);
        assert!(estimate.ewma.is_finite());
        let q = FairQueue::new(4);
        let _r = q.register().unwrap();
        let mut s = q.state.lock().unwrap();
        let now = s.window + Duration::from_secs(1);
        s.tick(now);
        assert_eq!(s.forecast.rps.ewma, 1.0);
        s.tick(now + Duration::from_secs(200));
        assert!(s.forecast.rps.ewma < 0.001);
        assert_eq!(s.forecast.rps.p95, 0.0);
    }
    #[test]
    fn arrival_windows_keep_fractional_seconds() {
        let q = FairQueue::new(1);
        let mut s = q.state.lock().unwrap();
        let start = s.window;
        for n in 1..=10 {
            s.arrivals += 1;
            s.tick(start + Duration::from_millis(n * 1900));
        }
        assert_eq!(s.window, start + Duration::from_secs(19));
        assert_eq!(s.forecast.rps.samples.len(), 19);
        assert_eq!(s.forecast.rps.samples.iter().sum::<f64>(), 10.0);
    }
    #[tokio::test]
    async fn dropping_granted_future_releases_slot() {
        let q = FairQueue::new(1);
        let parent = q.register().unwrap();
        let mut running = Box::pin(async {
            let _permit = parent.acquire(1.0).await;
            futures::future::pending::<()>().await;
        });
        assert!(poll!(running.as_mut()).is_pending());
        assert_eq!(q.state.lock().unwrap().active, 1);
        drop(running);
        assert_eq!(q.state.lock().unwrap().active, 0);
        drop(parent.acquire(1.0).await);
    }

    #[tokio::test]
    async fn small_request_overtakes_bulk_pending_and_drop_recovers_capacity() {
        let q = FairQueue::new(1);
        let bulk = q.register().unwrap();
        bulk.prepare(100_000, 1);
        let active = bulk.acquire(4000.0).await;
        let mut bulk_next = Box::pin(bulk.acquire(4000.0));
        assert!(poll!(bulk_next.as_mut()).is_pending());
        let small = q.register().unwrap();
        small.prepare(10, 1);
        let mut small_next = Box::pin(small.acquire(10.0));
        assert!(poll!(small_next.as_mut()).is_pending());
        drop(active);
        assert!(poll!(bulk_next.as_mut()).is_pending());
        let small_active = small_next.await;
        assert_eq!(q.state.lock().unwrap().active, 1);
        drop(small_active);
        drop(bulk_next);
        assert!(q.state.lock().unwrap().requests[&bulk.id]
            .pending
            .is_empty());
        let retry = bulk.acquire(4000.0).await;
        assert_eq!(q.state.lock().unwrap().active, 1);
        drop(retry);
        drop(small);
        drop(bulk);
        assert_eq!(q.state.lock().unwrap().active, 0);
        assert!(q.state.lock().unwrap().requests.is_empty());
    }
    #[tokio::test]
    async fn aging_beats_continuous_small_arrivals_and_reserve() {
        let q = FairQueue::new(4);
        let bulk = q.register().unwrap();
        bulk.prepare(100_000, 1);
        let mut s = q.state.lock().unwrap();
        s.requests
            .get_mut(&bulk.id)
            .unwrap()
            .pending
            .insert(10000, 4000.0);
        s.requests.get_mut(&bulk.id).unwrap().service = 1e9;
        let now = Instant::now();
        s.requests.get_mut(&bulk.id).unwrap().last = now - AGING;
        drop(s);
        for _ in 0..100 {
            let small = q.register().unwrap();
            small.prepare(1, 1);
            let mut s = q.state.lock().unwrap();
            s.requests
                .get_mut(&small.id)
                .unwrap()
                .pending
                .insert(20000, 1.0);
            assert_eq!(s.winner(now, 4), Some(bulk.id));
        }
    }
    #[tokio::test]
    async fn inactive_request_does_not_hold_service_floor_and_retry_is_charged() {
        let q = FairQueue::new(1);
        let _unprepared = q.register().unwrap();
        let bulk = q.register().unwrap();
        bulk.prepare(10000, 1);
        drop(bulk.acquire(1000.0).await);
        let first = q.state.lock().unwrap().floor;
        assert!(first > 0.0);
        drop(bulk.acquire(1000.0).await);
        assert!(q.state.lock().unwrap().floor > first);
        assert_eq!(
            q.state.lock().unwrap().requests[&bulk.id].remaining,
            10000.0
        );
        let next = q.register().unwrap();
        assert!(q.state.lock().unwrap().requests[&next.id].service > first);
    }
    #[test]
    fn admission_is_bounded_and_recovers() {
        let q = FairQueue::new(2);
        let mut requests = (0..MAX_REQUESTS)
            .map(|_| q.register().unwrap())
            .collect::<Vec<_>>();
        assert!(q.register().is_none());
        requests.pop();
        assert!(q.register().is_some());
    }
    #[test]
    fn batches_adapt_and_reserve_is_bounded_and_borrowable() {
        let q = FairQueue::new(4);
        let bulk = q.register().unwrap();
        bulk.prepare(100000, 1);
        assert_eq!(q.batch_size(6), 6);
        {
            let mut s = q.state.lock().unwrap();
            for _ in 0..4 {
                s.forecast.tokens.observe(1000.0);
            }
        }
        assert_eq!(q.batch_size(6), 8);
        let small = q.register().unwrap();
        small.prepare(10, 1);
        assert_eq!(q.batch_size(6), 4);
        let mut s = q.state.lock().unwrap();
        s.forecast.rps.observe(100.0);
        assert_eq!(s.reserve(4), 2);
        s.requests
            .get_mut(&bulk.id)
            .unwrap()
            .pending
            .insert(10, 1000.0);
        s.requests.get_mut(&bulk.id).unwrap().active = 3;
        s.active = 3;
        assert_eq!(s.winner(Instant::now(), 4), Some(bulk.id));
        s.requests
            .get_mut(&small.id)
            .unwrap()
            .pending
            .insert(11, 1.0);
        assert_eq!(s.winner(Instant::now(), 4), Some(small.id));
    }
}
