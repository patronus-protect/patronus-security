use crate::{EvaluationResult, SecurityCategory};

/// Input passed to an externally registered L1 heuristic.
#[derive(Debug, Clone)]
pub struct ExternalL1Input {
    pub category: SecurityCategory,
    pub text: String,
}

impl ExternalL1Input {
    /// Create an input for one security category.
    pub fn new(category: SecurityCategory, text: impl Into<String>) -> Self {
        Self {
            category,
            text: text.into(),
        }
    }
}

/// An application-provided L1 heuristic attached to one security category.
pub trait ExternalL1Detector: Send + Sync {
    /// Stable detector id used in the public model name `external:<id>`.
    fn id(&self) -> &'static str;

    /// Security pipeline extended by this detector.
    fn category(&self) -> SecurityCategory;

    /// Evaluate one request input.
    fn evaluate(&self, input: &ExternalL1Input) -> EvaluationResult;
}
