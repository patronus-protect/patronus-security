use crate::{config::Cube, fair_queue::Estimate};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Notify;
pub const SLOTS_PER_CUBE: usize = 3;
struct Member {
    cube: Cube,
    active: usize,
    queued: f64,
    rate: Estimate,
    healthy: bool,
}
struct State {
    members: Vec<Member>,
    next: usize,
}
pub struct CubePool {
    state: Mutex<State>,
    wake: Notify,
}
pub struct CubeLease {
    pub cube: Cube,
    pool: Arc<CubePool>,
    index: usize,
    work: f64,
    started: Instant,
}
impl CubePool {
    pub fn new(cubes: Vec<Cube>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                members: cubes
                    .into_iter()
                    .map(|cube| Member {
                        cube,
                        active: 0,
                        queued: 0.0,
                        rate: Estimate::new(3072.0),
                        healthy: false,
                    })
                    .collect(),
                next: 0,
            }),
            wake: Notify::new(),
        })
    }
    pub fn members(&self) -> Vec<Cube> {
        self.state
            .lock()
            .unwrap()
            .members
            .iter()
            .map(|m| m.cube.clone())
            .collect()
    }
    pub fn capacity(&self) -> usize {
        self.state.lock().unwrap().members.len() * SLOTS_PER_CUBE
    }
    pub fn ready(&self) -> bool {
        self.state.lock().unwrap().members.iter().any(|m| m.healthy)
    }
    pub fn health(&self, name: &str, healthy: bool) {
        if let Some(m) = self
            .state
            .lock()
            .unwrap()
            .members
            .iter_mut()
            .find(|m| m.cube.name == name)
        {
            m.healthy = healthy;
        }
        self.wake.notify_waiters();
    }
    pub async fn acquire(self: &Arc<Self>, work: f64) -> CubeLease {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                let count = state.members.len();
                let selected = (0..count)
                    .map(|n| (state.next + n) % count)
                    .filter(|&i| {
                        let m = &state.members[i];
                        m.healthy && m.active < SLOTS_PER_CUBE
                    })
                    .min_by(|&a, &b| {
                        let estimate = |i: usize| {
                            let m = &state.members[i];
                            (m.queued + work) / m.rate.ewma.min(m.rate.p50).max(1.0)
                        };
                        estimate(a).total_cmp(&estimate(b))
                    });
                if let Some(index) = selected {
                    let m = &mut state.members[index];
                    m.active += 1;
                    m.queued += work;
                    let cube = m.cube.clone();
                    state.next = (index + 1) % count;
                    return CubeLease {
                        cube,
                        pool: self.clone(),
                        index,
                        work,
                        started: Instant::now(),
                    };
                }
            }
            notified.await;
        }
    }
    pub fn snapshot(&self) -> Vec<(String, usize)> {
        self.state
            .lock()
            .unwrap()
            .members
            .iter()
            .map(|m| (m.cube.name.clone(), m.active))
            .collect()
    }
}
impl CubeLease {
    pub fn observe_completion(&self) {
        let seconds = self.started.elapsed().as_secs_f64();
        if seconds > 0.0 {
            self.pool.state.lock().unwrap().members[self.index]
                .rate
                .observe(self.work / seconds);
        }
    }
}
impl Drop for CubeLease {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        let m = &mut state.members[self.index];
        m.active = m.active.saturating_sub(1);
        m.queued = (m.queued - self.work).max(0.0);
        drop(state);
        self.pool.wake.notify_waiters();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn twelve_cubes_have_exactly_36_slots_and_release_wakes_next() {
        let pool = CubePool::new(
            (11..=22)
                .map(|n| Cube {
                    name: format!("cube-{n}"),
                    url: format!("http://cube-{n:02}.example.invalid:8080"),
                    max_in_flight: 3,
                })
                .collect(),
        );
        for n in 11..=22 {
            pool.health(&format!("cube-{n}"), true);
        }
        assert_eq!(pool.capacity(), 36);
        let mut held = Vec::new();
        for _ in 0..36 {
            held.push(pool.acquire(100.0).await);
        }
        assert!(pool.snapshot().iter().all(|(_, n)| *n == 3));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), pool.acquire(1.0))
                .await
                .is_err()
        );
        let freed = held.pop().unwrap().cube.name.clone(); // A single released slot permits exactly one replacement.
        let next = tokio::time::timeout(std::time::Duration::from_millis(100), pool.acquire(1.0))
            .await
            .unwrap();
        assert_eq!(next.cube.name, freed);
        assert!(pool.snapshot().iter().all(|(_, n)| *n == 3));
        drop(next);
        drop(held);
    }
}
