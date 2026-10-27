// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{registry, NativePolicy, NativeProducerSpec};
use crate::{detectors::NativeDetection, threat::NativeText, Category, ScanControl, ScanError};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

/// Raw producer output; result/decision mapping remains the host's responsibility.
pub struct NativeProducerOutcome {
    pub detection: NativeDetection,
    pub duration_ms: f64,
}

/// Owns each selected category's detector state once, without worker threads.
pub struct NativeEngine {
    groups: [Vec<NativeProducerSpec>; 3],
}

impl NativeEngine {
    /// Initialize only configured categories. An empty selection creates no pipelines.
    pub fn new(categories: &[Category]) -> Self {
        let mut groups = std::array::from_fn(|_| Vec::new());
        for &category in categories {
            let group = &mut groups[index(category)];
            if group.is_empty() {
                *group = registry::producers(category);
            }
        }
        Self { groups }
    }

    /// Producers in the established category order, or empty for an unselected category.
    pub fn producers(&self, category: Category) -> &[NativeProducerSpec] {
        &self.groups[index(category)]
    }

    /// Execute an active producer. Call `producer.enabled(policy)` before this method.
    /// Cancellation is checked before and after detection; panics become detector errors.
    pub fn run_producer(
        &self,
        producer: &NativeProducerSpec,
        prepared: &NativeText<'_>,
        policy: &dyn NativePolicy,
        control: &ScanControl,
    ) -> Result<NativeProducerOutcome, ScanError> {
        control.check()?;
        let start = Instant::now();
        let detection = catch_unwind(AssertUnwindSafe(|| producer.detect(prepared, policy)))
            .map_err(|payload| {
                let message = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "scanner panicked".into());
                ScanError::Detector(message)
            })?;
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        control.check()?;
        Ok(NativeProducerOutcome {
            detection,
            duration_ms,
        })
    }
}

fn index(category: Category) -> usize {
    match category {
        Category::Pii => 0,
        Category::Dlp => 1,
        Category::Injection => 2,
    }
}
