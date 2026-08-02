// SPDX-License-Identifier: GPL-3.0-only
use std::sync::Arc;

use crate::{EvaluationResult, SecurityCategory};

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

/// An application-provided L1 heuristic attached to one security category.
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
}
