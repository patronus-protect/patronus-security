// SPDX-License-Identifier: GPL-3.0-only
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const PHASE_METRICS_ENV: &str = "PATRONUS_PHASE_METRICS";
const PHASE_METRICS_SAMPLE_RSS_ENV: &str = "PATRONUS_PHASE_METRICS_SAMPLE_RSS";

pub(crate) struct PhaseMetricScope {
    enabled: bool,
    scope: &'static str,
    started: Instant,
    previous: Instant,
    previous_current_rss: Option<u64>,
    previous_peak_rss: Option<u64>,
    sampler: Option<PhaseMetricSampler>,
}

impl PhaseMetricScope {
    pub(crate) fn new(scope: &'static str, details: impl AsRef<str>) -> Self {
        let enabled = phase_metrics_enabled();
        let now = Instant::now();
        let snapshot = enabled.then(memory_snapshot).flatten();
        let mut metric = Self {
            enabled,
            scope,
            started: now,
            previous: now,
            previous_current_rss: snapshot.and_then(|snapshot| snapshot.current_rss_bytes),
            previous_peak_rss: snapshot.map(|snapshot| snapshot.peak_rss_bytes),
            sampler: phase_metrics_sampling_enabled().then(PhaseMetricSampler::start),
        };
        if let Some(sampler) = &metric.sampler {
            sampler.reset(metric.previous_current_rss);
        }
        metric.emit("start", details.as_ref(), now, snapshot);
        metric
    }

    pub(crate) fn checkpoint(&mut self, phase: &'static str, details: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let snapshot = memory_snapshot();
        self.emit(phase, details.as_ref(), now, snapshot);
        self.previous = now;
        self.previous_current_rss = snapshot.and_then(|snapshot| snapshot.current_rss_bytes);
        self.previous_peak_rss = snapshot.map(|snapshot| snapshot.peak_rss_bytes);
        if let Some(sampler) = &self.sampler {
            sampler.reset(self.previous_current_rss);
        }
    }

    fn emit(
        &mut self,
        phase: &'static str,
        details: &str,
        now: Instant,
        snapshot: Option<MemorySnapshot>,
    ) {
        if !self.enabled {
            return;
        }
        let phase_ms = now.duration_since(self.previous).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.started).as_secs_f64() * 1000.0;
        let current_rss = snapshot.and_then(|snapshot| snapshot.current_rss_bytes);
        let peak_rss = snapshot.map(|snapshot| snapshot.peak_rss_bytes);
        let phase_max_current = self
            .sampler
            .as_ref()
            .and_then(|sampler| sampler.max_current_rss_bytes());
        let delta_current = delta_bytes(current_rss, self.previous_current_rss);
        let delta_peak = delta_bytes(peak_rss, self.previous_peak_rss);
        let delta_phase_max_current = delta_bytes(phase_max_current, self.previous_current_rss);
        eprintln!(
            "PATRONUS_PHASE_METRIC\tscope={}\tphase={phase}\tphase_ms={phase_ms:.3}\ttotal_ms={total_ms:.3}\tcurrent_rss_mb={}\tpeak_rss_mb={}\tphase_max_current_rss_mb={}\tdelta_current_mb={}\tdelta_peak_mb={}\tdelta_phase_max_current_mb={}\t{}",
            self.scope,
            format_mb(current_rss),
            format_mb(peak_rss),
            format_mb(phase_max_current),
            format_signed_mb(delta_current),
            format_signed_mb(delta_peak),
            format_signed_mb(delta_phase_max_current),
            details
        );
    }
}

struct PhaseMetricSampler {
    running: Arc<AtomicBool>,
    max_current_rss_bytes: Arc<AtomicU64>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PhaseMetricSampler {
    fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let max_current_rss_bytes = Arc::new(AtomicU64::new(0));
        let thread_running = Arc::clone(&running);
        let thread_max = Arc::clone(&max_current_rss_bytes);
        let handle = thread::spawn(move || {
            while thread_running.load(Ordering::Relaxed) {
                if let Some(current) = current_rss_bytes() {
                    update_max(&thread_max, current);
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        Self {
            running,
            max_current_rss_bytes,
            handle: Some(handle),
        }
    }

    fn reset(&self, current_rss_bytes: Option<u64>) {
        self.max_current_rss_bytes
            .store(current_rss_bytes.unwrap_or(0), Ordering::Relaxed);
    }

    fn max_current_rss_bytes(&self) -> Option<u64> {
        let value = self.max_current_rss_bytes.load(Ordering::Relaxed);
        (value > 0).then_some(value)
    }
}

impl Drop for PhaseMetricSampler {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn update_max(max: &AtomicU64, candidate: u64) {
    let mut observed = max.load(Ordering::Relaxed);
    while candidate > observed {
        match max.compare_exchange_weak(observed, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => observed = next,
        }
    }
}

pub(crate) fn phase_metrics_enabled() -> bool {
    std::env::var_os(PHASE_METRICS_ENV).is_some()
}

fn phase_metrics_sampling_enabled() -> bool {
    phase_metrics_enabled() && std::env::var_os(PHASE_METRICS_SAMPLE_RSS_ENV).is_some()
}

#[derive(Clone, Copy)]
struct MemorySnapshot {
    current_rss_bytes: Option<u64>,
    peak_rss_bytes: u64,
}

fn memory_snapshot() -> Option<MemorySnapshot> {
    Some(MemorySnapshot {
        current_rss_bytes: current_rss_bytes(),
        peak_rss_bytes: peak_rss_bytes()?,
    })
}

fn delta_bytes(current: Option<u64>, previous: Option<u64>) -> Option<i64> {
    Some(current? as i64 - previous? as i64)
}

fn format_mb(bytes: Option<u64>) -> String {
    bytes
        .map(|bytes| format!("{:.3}", bytes as f64 / (1024.0 * 1024.0)))
        .unwrap_or_else(|| "n/a".to_string())
}

fn format_signed_mb(bytes: Option<i64>) -> String {
    bytes
        .map(|bytes| format!("{:.3}", bytes as f64 / (1024.0 * 1024.0)))
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(target_os = "macos")]
fn current_rss_bytes() -> Option<u64> {
    use std::ffi::{c_int, c_void};

    const PROC_PIDTASKINFO: c_int = 4;

    #[repr(C)]
    #[derive(Default)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }

    extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }

    let mut info = ProcTaskInfo::default();
    let size = std::mem::size_of::<ProcTaskInfo>() as c_int;
    let read = unsafe {
        proc_pidinfo(
            std::process::id() as c_int,
            PROC_PIDTASKINFO,
            0,
            (&mut info as *mut ProcTaskInfo).cast::<c_void>(),
            size,
        )
    };
    (read == size).then_some(info.pti_resident_size)
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(resident_pages * page_size_bytes()?)
}

#[cfg(target_os = "linux")]
fn page_size_bytes() -> Option<u64> {
    use std::ffi::c_int;
    extern "C" {
        fn sysconf(name: c_int) -> isize;
    }
    const _SC_PAGESIZE: c_int = 30;
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    (page_size > 0).then_some(page_size as u64)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current_rss_bytes() -> Option<u64> {
    None
}

fn peak_rss_bytes() -> Option<u64> {
    use std::ffi::{c_int, c_long};

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct TimeVal {
        tv_sec: c_long,
        tv_usec: c_long,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct RUsage {
        ru_utime: TimeVal,
        ru_stime: TimeVal,
        ru_maxrss: c_long,
        ru_ixrss: c_long,
        ru_idrss: c_long,
        ru_isrss: c_long,
        ru_minflt: c_long,
        ru_majflt: c_long,
        ru_nswap: c_long,
        ru_inblock: c_long,
        ru_oublock: c_long,
        ru_msgsnd: c_long,
        ru_msgrcv: c_long,
        ru_nsignals: c_long,
        ru_nvcsw: c_long,
        ru_nivcsw: c_long,
    }

    extern "C" {
        fn getrusage(who: c_int, usage: *mut RUsage) -> c_int;
    }

    let mut usage = RUsage::default();
    if unsafe { getrusage(0, &mut usage) } != 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(usage.ru_maxrss as u64)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(usage.ru_maxrss as u64 * 1024)
    }
}
