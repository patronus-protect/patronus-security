// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{registry, NativeProducerSpec};
use crate::cascade::ScanGateMatrix;
use crate::{
    detectors::NativeDetection, threat::NativeText, LayerResult, NativeResult, ScanControl,
    ScanError, SecurityCategory,
};
use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

/// Raw producer output; result/decision mapping remains the host's responsibility.
pub struct NativeProducerOutcome {
    pub detection: NativeDetection,
    pub duration_ms: f64,
}

/// The native text-scan categories, in group order: pii, dlp and the eleven
/// attack classes. A class without rules yet has no producers.
pub const NATIVE_CATEGORIES: [SecurityCategory; 13] = [
    SecurityCategory::Pii,
    SecurityCategory::Dlp,
    SecurityCategory::Injection,
    SecurityCategory::Jailbreak,
    SecurityCategory::PromptExtraction,
    SecurityCategory::ToolPoisoning,
    SecurityCategory::AgentConfigTampering,
    SecurityCategory::MemoryPoisoning,
    SecurityCategory::Exfiltration,
    SecurityCategory::UnsafeAction,
    SecurityCategory::ResourceExhaustion,
    SecurityCategory::HarmfulContent,
    SecurityCategory::ToxicLanguage,
];

/// Owns each selected category's detector state once, without worker threads.
pub struct NativeEngine {
    groups: [Vec<NativeProducerSpec>; NATIVE_CATEGORIES.len()],
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

    /// Builds what a scan under `gates` runs, for every enabled producer:
    /// rules and pipelines are built on first use, so the ones the gates
    /// keep off cost no memory. Call it when the gates are fixed (a scanner's
    /// config, a gateway's execution gates) so that no scan under them
    /// builds anything; a scan under other gates builds what they enable on
    /// first use. What is built stays, also after a gate change turns it off.
    pub fn prepare(&self, gates: &ScanGateMatrix) {
        for producer in self.groups.iter().flatten() {
            if producer.enabled(gates) {
                producer.prepare(gates);
            }
        }
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
        gates: &ScanGateMatrix,
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

    /// The L1 pass of one module, shared by the Core [`crate::Scanner`] and
    /// Ark's gateway: every producer of `category` that `gates` enable, its
    /// evidence filtered by post-prediction, and the `ark.injection.*`
    /// producers merged into one scored decision
    /// ([`crate::injection_l1::category_results`]). A failing producer
    /// reports an `error` result ([`NativeResult::scanner_error`]);
    /// cancellation and an exceeded deadline are returned as errors.
    pub fn scan_module(
        &self,
        category: SecurityCategory,
        prepared: &NativeText<'_>,
        gates: &ScanGateMatrix,
        control: &ScanControl,
    ) -> Result<Vec<NativeResult>, ScanError> {
        let text = prepared.text();
        let mut outputs = Vec::new();
        for producer in self.producers(category) {
            if !producer.enabled(gates) {
                continue;
            }
            let result = match self.run_producer(producer, prepared, gates, control) {
                Ok(outcome) => measure(category, producer.id(), text, outcome),
                Err(ScanError::Detector(message)) => {
                    NativeResult::scanner_error(category, producer.id(), message)
                }
                Err(error) => return Err(error),
            };
            outputs.push((producer.scored(), result));
        }
        Ok(crate::injection_l1::category_results(
            category, text, outputs,
        ))
    }
}

/// One producer's result: its evidence filtered by post-prediction, the
/// confidence the best remaining span score (the producer's own without spans).
fn measure(
    category: SecurityCategory,
    model: &str,
    text: &str,
    outcome: NativeProducerOutcome,
) -> NativeResult {
    let NativeProducerOutcome {
        detection,
        duration_ms,
    } = outcome;
    let spans = crate::post_prediction::filter_evidence(category, text, detection.evidence_spans);
    let confidence = spans
        .iter()
        .map(|s| s.score)
        .reduce(f64::max)
        .unwrap_or(detection.result.confidence);
    NativeResult {
        category: category.as_str().into(),
        class_name: detection.result.class_name.clone(),
        confidence,
        level: "L1".into(),
        model: model.into(),
        duration_ms,
        layers: vec![LayerResult {
            level: "L1".into(),
            layer_type: "native".into(),
            class_name: detection.result.class_name,
            confidence,
            matched: true,
            duration_ms,
            thresholds: HashMap::new(),
            details: detection.details,
        }],
        evidence_spans: spans,
        label_scores: Vec::new(),
        decision: None,
    }
}

fn index(category: SecurityCategory) -> Option<usize> {
    NATIVE_CATEGORIES
        .iter()
        .position(|&native| native == category)
}
