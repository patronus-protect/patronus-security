// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{registry, NativeGates, NativeProducerSpec};
use crate::{
    detectors::NativeDetection, threat::NativeText, ScanControl, ScanError, SecurityCategory,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

/// Raw producer output; result/decision mapping remains the host's responsibility.
pub struct NativeProducerOutcome {
    pub detection: NativeDetection,
    pub duration_ms: f64,
}

/// The categories with native producers, in group order.
pub const NATIVE_CATEGORIES: [SecurityCategory; 3] = [
    SecurityCategory::Pii,
    SecurityCategory::Dlp,
    SecurityCategory::Injection,
];

/// Owns each selected category's detector state once, without worker threads.
pub struct NativeEngine {
    groups: [Vec<NativeProducerSpec>; 3],
}

impl NativeEngine {
    /// Initialize only configured native categories; other categories have no
    /// native producers. An empty selection creates no pipelines.
    pub fn new(categories: &[SecurityCategory]) -> Self {
        let mut groups = std::array::from_fn(|_| Vec::new());
        for &category in categories {
            if let Some(group) = index(category).map(|i| &mut groups[i]) {
                if group.is_empty() {
                    *group = registry::producers(category);
                }
            }
        }
        Self { groups }
    }

    /// Producers in the established category order, or empty for an unselected
    /// or non-native category.
    pub fn producers(&self, category: SecurityCategory) -> &[NativeProducerSpec] {
        index(category).map_or(&[], |i| &self.groups[i])
    }

    /// Execute an active producer. Call `producer.enabled(gates)` before this method.
    /// Cancellation is checked before and after detection; panics become detector errors.
    pub fn run_producer(
        &self,
        producer: &NativeProducerSpec,
        prepared: &NativeText<'_>,
        gates: &NativeGates,
        control: &ScanControl,
    ) -> Result<NativeProducerOutcome, ScanError> {
        control.check()?;
        let start = Instant::now();
        let detection = catch_unwind(AssertUnwindSafe(|| producer.detect(prepared, gates)))
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

fn index(category: SecurityCategory) -> Option<usize> {
    NATIVE_CATEGORIES
        .iter()
        .position(|&native| native == category)
}
