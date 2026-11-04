// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLP score model (K04), on the PII score model (PII K02); the output modes
//! are [`crate::native::ScoreMode`].
//!
//! A finding scores its rule base (how specific the regex form is) plus the
//! strength of its validator plus its context ([`super::context`]): the field
//! bonus, the proximity tiers and the counter-context penalty of PII. The
//! points are integers so that scores are exact two-digit fractions, and the
//! thresholds of `balanced` and `recall` are those of PII. `strict` ignores the
//! model: it keeps the rule acceptance and the fixed score `1.0`.
use super::context;
use super::dlp::{DlpPattern, ValidatorStrength};
use crate::detectors::pii::score::Context;

impl ValidatorStrength {
    /// Score-model points of the strength. Checksum and format match the PII
    /// model; a verified structure (JWT header, DER, SQL) lies between them.
    pub const fn points(self) -> u8 {
        match self {
            Self::Checksum => 35,
            Self::Structure => 25,
            Self::Format => 15,
            Self::None => 0,
        }
    }
}

/// Model score of a finding of `pattern` without proximity context: field
/// rules get the field bonus, all other rules no context points.
pub fn rule_score(pattern: &DlpPattern) -> f64 {
    let context = if context::source(pattern) == context::ContextSource::Field {
        Context::Field
    } else {
        Context::None
    };
    score(pattern, context)
}

/// Model score of a finding of `pattern` in `context`, in `0.0..=1.0`.
pub fn score(pattern: &DlpPattern, context: Context) -> f64 {
    let points = i16::from(pattern.base_score)
        + i16::from(pattern.meta.validator_strength.points())
        + context.points();
    f64::from(points.clamp(0, 100)) / 100.0
}
