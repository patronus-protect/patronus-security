// SPDX-License-Identifier: GPL-3.0-only
//! PII score model and output modes.
//!
//! A finding scores its rule base (how specific the regex form is) plus the
//! strength of its validator plus a context bonus. The points are integers so
//! that scores are exact two-digit fractions. `strict` ignores the model: it
//! keeps the rule acceptance and the fixed score `1.0`. `balanced` and
//! `recall` report the model score and drop candidates below their threshold.
use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use super::pii::PiiPattern;

/// Bonus for a value the rule binds to a field name (`captured_value`).
pub const FIELD_CONTEXT_POINTS: u8 = 25;

/// What the validator of a rule proves about a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStrength {
    /// Real check digit or checksum (Luhn, ISO 7064, weighted sums).
    Checksum,
    /// Form only: length, alphabet, ranges, dates, prefixes.
    Format,
    /// No validator after the regex.
    None,
}

impl ValidatorStrength {
    pub const fn points(self) -> u8 {
        match self {
            Self::Checksum => 35,
            Self::Format => 15,
            Self::None => 0,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checksum => "checksum",
            Self::Format => "format",
            Self::None => "none",
        }
    }
}

/// Model score of a finding of `pattern`, in `0.0..=1.0`.
pub fn rule_score(pattern: &PiiPattern) -> f64 {
    let context = if pattern.captured_value {
        FIELD_CONTEXT_POINTS
    } else {
        0
    };
    let points =
        (u16::from(pattern.base_score) + u16::from(pattern.strength.points()) + u16::from(context))
            .min(100);
    f64::from(points) / 100.0
}

/// PII output mode. `Strict` is the default and the pre-score behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiMode {
    /// Rule acceptance only; every finding scores `1.0`.
    #[default]
    Strict,
    /// Model scores; candidates below `0.50` are dropped.
    Balanced,
    /// Model scores; candidates below `0.30` are dropped.
    Recall,
}

impl PiiMode {
    /// Minimum model score of an emitted finding; `None` keeps strict scoring.
    pub const fn min_score(self) -> Option<f64> {
        match self {
            Self::Strict => None,
            Self::Balanced => Some(0.5),
            Self::Recall => Some(0.3),
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

impl fmt::Display for PiiMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PiiMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "recall" => Ok(Self::Recall),
            _ => Err(format!(
                "unknown pii_mode {value:?}; expected strict, balanced or recall"
            )),
        }
    }
}
