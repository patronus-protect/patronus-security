//! Extension points of the cascade: application L1 detectors, layer models,
//! L3 executors and the escalation signal they pass on.
use std::{ops::Range, sync::Arc};

use serde::Serialize;

use super::SecurityLevel;
use crate::{EvaluationResult, LayerResult, ScanControl, ScanError, SecurityCategory};

/// A layer's request to hand its input to the next configured layer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EscalationSignal {
    /// Escalation score of the layer (for L1 its rule or model score, for L2
    /// its promote score).
    pub score: f64,
    /// The lower bound of the layer's escalate band, the same meaning for
    /// every producer: the signal escalates when `score >= threshold`
    /// ([`Self::escalates`]). For an L1 stage it is its clear cut, or
    /// `f64::MIN` when clearing is off.
    pub threshold: f64,
    /// Byte ranges the next layer should look at; empty means the whole input.
    pub spans: Vec<Range<usize>>,
    /// Model or detector that raised the signal.
    pub source: String,
}

impl EscalationSignal {
    /// The signal of an L1 stage that escalated `score`: it did not clear, so
    /// the score is in the band from the clear cut up (`None`: no lower
    /// bound).
    pub fn above(score: f64, clear_threshold: Option<f64>, source: &str) -> Self {
        Self {
            score,
            threshold: clear_threshold.unwrap_or(f64::MIN),
            spans: Vec::new(),
            source: source.to_string(),
        }
    }

    /// Whether the signal asks for the next layer.
    pub fn escalates(&self) -> bool {
        escalates(self.score, self.threshold)
    }
}

/// The escalation predicate of L2 and L3 signals: `score >= threshold`. L1
/// stages decide by [`super::StageOutcome::from_cuts`] instead.
pub fn escalates(score: f64, threshold: f64) -> bool {
    score >= threshold
}

/// What a model layer answers for one input.
#[derive(Debug, Clone)]
pub struct LayerOutput {
    /// The layer's evidence; `matched` is its detection, `confidence` its score.
    pub result: LayerResult,
    /// Set when the layer leaves the input to the next layer.
    pub escalation: Option<EscalationSignal>,
}

/// A model that runs at L2 or L3 for one analysis module.
pub trait LayerModel: Send {
    /// The layer this model runs at (L2 or L3).
    fn layer(&self) -> SecurityLevel;
    /// The analysis module it serves.
    fn module(&self) -> SecurityCategory;
    /// Infer on the whole input.
    fn infer(&mut self, text: &str, control: &ScanControl) -> Result<LayerOutput, ScanError>;
}

/// Runs L3 work for escalated inputs: in-process for a local [`LayerModel`],
/// or through a host's scheduler.
pub trait L3Executor {
    /// Run the L3 stage of `module` on an escalated input; `None` when this
    /// executor has no L3 for the module.
    fn execute_l3(
        &mut self,
        module: SecurityCategory,
        text: &str,
        escalation: &EscalationSignal,
        control: &ScanControl,
    ) -> Result<Option<LayerOutput>, ScanError>;
}

impl<M: LayerModel> L3Executor for M {
    fn execute_l3(
        &mut self,
        module: SecurityCategory,
        text: &str,
        _escalation: &EscalationSignal,
        control: &ScanControl,
    ) -> Result<Option<LayerOutput>, ScanError> {
        if self.layer() != SecurityLevel::L3 || self.module() != module {
            return Ok(None);
        }
        self.infer(text, control).map(Some)
    }
}

/// Input passed to an externally registered L1 heuristic.
#[derive(Debug, Clone)]
pub struct ExternalL1Input {
    pub category: SecurityCategory,
    pub text: Arc<str>,
}

impl ExternalL1Input {
    /// Create an input for one security category.
    pub fn new(category: SecurityCategory, text: impl Into<String>) -> Self {
        Self::from_shared_text(category, Arc::<str>::from(text.into()))
    }

    /// Create an input that shares request text with other categories.
    pub fn from_shared_text(category: SecurityCategory, text: Arc<str>) -> Self {
        Self { category, text }
    }
}

/// An application-provided L1 heuristic attached to one security category:
/// the L1 extension point of an analysis module.
pub trait ExternalL1Detector: Send + Sync {
    /// Stable detector id used in the public model name `external:<id>`.
    fn id(&self) -> &'static str;

    /// Security pipeline extended by this detector.
    fn category(&self) -> SecurityCategory;

    /// Evaluate one request input.
    fn evaluate(&self, input: &ExternalL1Input) -> EvaluationResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_can_share_request_text_across_categories() {
        let text = Arc::<str>::from("shared large request text");

        let first =
            ExternalL1Input::from_shared_text(SecurityCategory::Injection, Arc::clone(&text));
        let second = ExternalL1Input::from_shared_text(SecurityCategory::Dlp, Arc::clone(&text));

        assert!(Arc::ptr_eq(&first.text, &second.text));
        assert!(Arc::ptr_eq(&first.text, &text));
    }

    #[test]
    fn escalation_predicate_is_inclusive() {
        assert!(escalates(0.5, 0.5));
        assert!(escalates(0.51, 0.5));
        assert!(!escalates(0.49, 0.5));
        let signal = EscalationSignal {
            score: 0.2,
            threshold: 0.3,
            spans: vec![0..4, 6..8],
            source: "m".into(),
        };
        assert!(!signal.escalates());
    }
}
