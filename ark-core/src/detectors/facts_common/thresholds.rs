// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two cuts of an L1 model's decision score, shared by every model form
//! (K26 TF-IDF + LR, fastText-type) and every detector that reads one: Cat's
//! shell-risk model and the text category models.
//!
//! The model files declare `decision_rule: "score > threshold"`: a score above
//! the detect cut is detected, a score at or below the clear cut is clear, and
//! a score in between escalates to the next configured layer
//! ([`StageOutcome::from_cuts`], the rule the heuristic follows too). Without a
//! clear cut nothing is cleared by the model. Cat reads the same three outcomes
//! as `block`, `allow` and `ask`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::model::ModelForm;
use crate::cascade::StageOutcome;

/// The detect and clear cuts of an L1 model, on its decision-score (logit)
/// scale. The heuristic's cuts live on its probability scale instead
/// ([`crate::cascade::ModuleConfig`]); both follow [`StageOutcome::from_cuts`].
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct L1Thresholds {
    /// Upper cut: a score above it is detected (Cat: `block`, the 0.1 % FPR cut).
    pub detect_threshold: f64,
    /// Lower cut: a score at or below it is clear (Cat: `allow` below the
    /// 1 % FPR `ask` cut); `None` switches clearing off.
    pub clear_threshold: Option<f64>,
}

impl L1Thresholds {
    /// The cuts a model file names for `form`: detect at its `block`
    /// threshold, clear at its `ask` threshold.
    pub(crate) fn from_model(
        thresholds: &BTreeMap<String, f64>,
        form: ModelForm,
        what: &str,
    ) -> Result<Self, String> {
        let cut = |name: &str| {
            thresholds
                .get(name)
                .copied()
                .ok_or_else(|| format!("{what} has no {name} threshold"))
        };
        Ok(Self {
            detect_threshold: cut(form.block_threshold)?,
            clear_threshold: Some(cut(form.ask_threshold)?),
        })
    }

    /// The outcome of decision score `score`.
    pub fn outcome(&self, score: f64) -> StageOutcome {
        StageOutcome::from_cuts(score > self.detect_threshold, score, self.clear_threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORM: ModelForm = ModelForm {
        label: "test",
        analyzer: "tf1",
        ask_threshold: "ask",
        block_threshold: "block",
    };

    #[test]
    fn reads_detect_and_clear_from_the_named_thresholds() {
        let file = BTreeMap::from([("ask".to_string(), 0.5), ("block".to_string(), 2.0)]);
        let cuts = L1Thresholds::from_model(&file, FORM, "test model").unwrap();
        assert_eq!(
            cuts,
            L1Thresholds {
                detect_threshold: 2.0,
                clear_threshold: Some(0.5)
            }
        );
        let missing = BTreeMap::from([("ask".to_string(), 0.5)]);
        let error = L1Thresholds::from_model(&missing, FORM, "test model").unwrap_err();
        assert_eq!(error, "test model has no block threshold");
    }

    #[test]
    fn outcome_follows_score_above_threshold() {
        let cuts = L1Thresholds {
            detect_threshold: 2.0,
            clear_threshold: Some(0.5),
        };
        assert_eq!(cuts.outcome(2.1), StageOutcome::Detected);
        assert_eq!(cuts.outcome(2.0), StageOutcome::Escalate);
        assert_eq!(cuts.outcome(0.6), StageOutcome::Escalate);
        assert_eq!(cuts.outcome(0.5), StageOutcome::Clear);
        assert_eq!(cuts.outcome(-3.0), StageOutcome::Clear);
        let no_clear = L1Thresholds {
            clear_threshold: None,
            ..cuts
        };
        assert_eq!(no_clear.outcome(-3.0), StageOutcome::Escalate);
        assert_eq!(no_clear.outcome(2.1), StageOutcome::Detected);
    }
}
