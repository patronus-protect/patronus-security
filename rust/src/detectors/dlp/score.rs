// SPDX-License-Identifier: GPL-3.0-only
//! DLP score model and output modes (K04), on the PII score model (PII K02).
//!
//! A finding scores its rule base (how specific the regex form is) plus the
//! strength of its validator plus its context ([`super::context`]): the field
//! bonus, the proximity tiers and the counter-context penalty of PII. The
//! points are integers so that scores are exact two-digit fractions, and the
//! thresholds of `balanced` and `recall` are those of PII. `strict` ignores the
//! model: it keeps the rule acceptance and the fixed score `1.0`.
use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use super::context;
use super::dlp::{DlpPattern, ValidatorStrength};
use crate::detectors::pii::score::{Context, PiiMode};

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

/// DLP output mode. `Strict` is the default and the pre-score behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpMode {
    /// Rule acceptance only; every finding scores `1.0`.
    #[default]
    Strict,
    /// Model scores; candidates below the PII `balanced` threshold are dropped.
    Balanced,
    /// Model scores; candidates below the PII `recall` threshold are dropped.
    Recall,
}

impl DlpMode {
    /// Minimum model score of an emitted finding; `None` keeps strict scoring.
    pub const fn min_score(self) -> Option<f64> {
        match self {
            Self::Strict => PiiMode::Strict.min_score(),
            Self::Balanced => PiiMode::Balanced.min_score(),
            Self::Recall => PiiMode::Recall.min_score(),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Recall => "recall",
        }
    }
}

impl fmt::Display for DlpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DlpMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "recall" => Ok(Self::Recall),
            _ => Err(format!(
                "unknown dlp_mode {value:?}; expected strict, balanced or recall"
            )),
        }
    }
}
