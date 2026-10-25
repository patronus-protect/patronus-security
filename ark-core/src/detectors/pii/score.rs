// SPDX-License-Identifier: MIT OR Apache-2.0
//! PII score model and output modes.
//!
//! A finding scores its rule base (how specific the regex form is) plus the
//! strength of its validator plus its context (K03): a field name the rule binds
//! to the value, or else the nearest lexicon term on either side of the value,
//! minus a penalty when a counter-context term (order, invoice, tracking
//! number ...) is nearer. The points are integers so that scores are exact
//! two-digit fractions. `strict` ignores the model: it keeps the rule
//! acceptance and the fixed score `1.0`. `balanced` and `recall` report the
//! model score and drop candidates below their threshold.
use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use super::pii::PiiPattern;

/// Bonus for a value the rule binds to a field name (`captured_value`).
pub const FIELD_CONTEXT_POINTS: u8 = 25;

/// Bonus for a support term of the label near an unbound value, by the number
/// of characters between term and value: up to 16, up to 32, up to the window.
pub const PROXIMITY_CONTEXT_POINTS: [(usize, u8); 3] = [(16, 25), (32, 20), (48, 15)];

/// Penalty when a counter-context term is nearer to the value than any
/// support term of its label.
pub const COUNTER_CONTEXT_POINTS: u8 = 30;

/// Penalty for a finding that only the `recall` normalization reveals: a
/// spelled-out e-mail address or digits spaced one by one (K06).
pub const SPELLED_OUT_PENALTY_POINTS: u8 = 10;

/// Context of one finding, as the context engine sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// The rule bound the value to a field name.
    Field,
    /// Nearest support term `gap` characters away, no nearer counter term.
    Support { gap: usize },
    /// A counter-context term is nearer than any support term.
    Counter,
    /// Neither support nor counter terms in the window.
    None,
}

impl Context {
    /// Signed context points of the score model.
    pub fn points(self) -> i16 {
        match self {
            Self::Field => i16::from(FIELD_CONTEXT_POINTS),
            Self::Support { gap } => PROXIMITY_CONTEXT_POINTS
                .iter()
                .find(|(max_gap, _)| gap <= *max_gap)
                .map_or(0, |(_, points)| i16::from(*points)),
            Self::Counter => -i16::from(COUNTER_CONTEXT_POINTS),
            Self::None => 0,
        }
    }

    /// Whether the context supports the label: a field name or a support term
    /// that no counter term outranks. Context-bound rules require this.
    pub fn supports(self) -> bool {
        self.points() > 0
    }
}

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

/// Model score of a finding of `pattern` without proximity context: field
/// rules get the field bonus, unbound rules no context points.
pub fn rule_score(pattern: &PiiPattern) -> f64 {
    let context = if pattern.captured_value {
        Context::Field
    } else {
        Context::None
    };
    score(pattern, context)
}

/// Model score of a finding of `pattern` in `context`, in `0.0..=1.0`.
pub fn score(pattern: &PiiPattern, context: Context) -> f64 {
    let points =
        i16::from(pattern.base_score) + i16::from(pattern.strength.points()) + context.points();
    f64::from(points.clamp(0, 100)) / 100.0
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
