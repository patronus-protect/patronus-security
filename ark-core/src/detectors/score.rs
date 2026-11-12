// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared pattern form and points of the L1 categories; the output modes are
//! [`crate::native::ScoreMode`].
//!
//! Every category scores a finding the same way: the rule base (how specific
//! the regex form is) plus the strength of its validator plus its context (a
//! field name the rule binds to the value, or else the nearest lexicon term on
//! either side of the value, minus a penalty when a counter-context term is
//! nearer), plus the normalisation points of the category when only a
//! normalised view reveals the finding. The points are integers so that scores
//! are exact two-digit fractions. `strict` ignores the points: it keeps the rule
//! acceptance and the fixed score `1.0`. `balanced` and `recall` report the
//! points as score and drop candidates below their threshold.

/// Bonus for a value the rule binds to a field name.
pub const FIELD_CONTEXT_POINTS: u8 = 25;

/// Bonus for a support term of the label near an unbound value, by the number
/// of characters between term and value: up to 16, up to 32, up to the window.
pub const PROXIMITY_CONTEXT_POINTS: [(usize, u8); 3] = [(16, 25), (32, 20), (48, 15)];

/// Penalty when a counter-context term is nearer to the value than any
/// support term of its label.
pub const COUNTER_CONTEXT_POINTS: u8 = 30;

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
    /// Signed context points.
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
    /// Real check digit or checksum (Luhn, ISO 7064, CRC32, Base58Check, Bech32).
    Checksum,
    /// The decoded or parsed structure is verified (JWT header, DER, SQL).
    Structure,
    /// Form only: length, alphabet, ranges, dates, prefixes, syntax shape.
    Format,
    /// No validator after the regex: keyword or context anchor only.
    None,
}

impl ValidatorStrength {
    /// Points of the strength; a verified structure lies between checksum and format.
    pub const fn points(self) -> u8 {
        match self {
            Self::Checksum => 35,
            Self::Structure => 25,
            Self::Format => 15,
            Self::None => 0,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checksum => "checksum",
            Self::Structure => "structure",
            Self::Format => "format",
            Self::None => "none",
        }
    }
}

/// The L1 categories that score their findings in points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Pii,
    Dlp,
    Injection,
    Threat,
}

impl Category {
    /// Points for a finding that only a normalised view reveals (spelled-out
    /// or spaced-out text, confusables, decoded content). For personal data
    /// such a finding is less certain; for attack categories the obfuscation
    /// itself is suspicious and adds points.
    pub const fn normalisation_points(self) -> i16 {
        match self {
            Self::Pii => -10,
            Self::Dlp => 0,
            Self::Injection | Self::Threat => 10,
        }
    }
}

/// The scored part of a rule, the same form in every category.
pub trait ScoredPattern {
    /// Points (1–100) for the regex form alone.
    fn base_score(&self) -> u8;
    /// What the rule's validator proves about a value.
    fn strength(&self) -> ValidatorStrength;
    /// Whether the rule binds its value to a field name of its own.
    fn binds_field(&self) -> bool;
}

/// Score of a finding of `pattern` in `context`, in `0.0..=1.0`.
pub fn score(pattern: &impl ScoredPattern, context: Context) -> f64 {
    let points =
        i16::from(pattern.base_score()) + i16::from(pattern.strength().points()) + context.points();
    to_score(points)
}

/// Score of a finding of `pattern` without proximity context: field rules get
/// the field bonus, unbound rules no context points.
pub fn rule_score(pattern: &impl ScoredPattern) -> f64 {
    let context = if pattern.binds_field() {
        Context::Field
    } else {
        Context::None
    };
    score(pattern, context)
}

/// `score` of a finding that only a normalised view of `category` reveals.
pub fn normalised_score(score: f64, category: Category) -> f64 {
    to_score((score * 100.0).round() as i16 + category.normalisation_points())
}

fn to_score(points: i16) -> f64 {
    f64::from(points.clamp(0, 100)) / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rule {
        base: u8,
        strength: ValidatorStrength,
        field: bool,
    }

    impl ScoredPattern for Rule {
        fn base_score(&self) -> u8 {
            self.base
        }
        fn strength(&self) -> ValidatorStrength {
            self.strength
        }
        fn binds_field(&self) -> bool {
            self.field
        }
    }

    const fn rule(base: u8, strength: ValidatorStrength, field: bool) -> Rule {
        Rule {
            base,
            strength,
            field,
        }
    }

    #[test]
    fn score_adds_base_strength_and_context_points() {
        let unbound = rule(40, ValidatorStrength::Checksum, false);
        assert_eq!(score(&unbound, Context::None), 0.75);
        assert_eq!(score(&unbound, Context::Support { gap: 10 }), 1.0);
        assert_eq!(score(&unbound, Context::Support { gap: 30 }), 0.95);
        assert_eq!(score(&unbound, Context::Support { gap: 48 }), 0.9);
        assert_eq!(score(&unbound, Context::Support { gap: 49 }), 0.75);
        assert_eq!(score(&unbound, Context::Counter), 0.45);
        assert_eq!(rule_score(&unbound), 0.75);
        assert_eq!(rule_score(&rule(40, ValidatorStrength::Format, true)), 0.8);
    }

    #[test]
    fn score_is_clamped_to_the_unit_interval() {
        assert_eq!(
            score(
                &rule(100, ValidatorStrength::Checksum, true),
                Context::Field
            ),
            1.0
        );
        assert_eq!(
            score(&rule(10, ValidatorStrength::None, false), Context::Counter),
            0.0
        );
    }

    #[test]
    fn strengths_rank_checksum_structure_format_none() {
        let points = [
            ValidatorStrength::Checksum,
            ValidatorStrength::Structure,
            ValidatorStrength::Format,
            ValidatorStrength::None,
        ]
        .map(ValidatorStrength::points);
        assert_eq!(points, [35, 25, 15, 0]);
    }

    #[test]
    fn only_field_and_support_context_supports_the_label() {
        assert!(Context::Field.supports());
        assert!(Context::Support { gap: 0 }.supports());
        assert!(!Context::Support { gap: 49 }.supports());
        assert!(!Context::Counter.supports());
        assert!(!Context::None.supports());
    }

    #[test]
    fn normalisation_lowers_pii_and_raises_attack_categories() {
        assert_eq!(normalised_score(0.75, Category::Pii), 0.65);
        assert_eq!(normalised_score(0.05, Category::Pii), 0.0);
        assert_eq!(normalised_score(0.75, Category::Dlp), 0.75);
        assert_eq!(normalised_score(0.75, Category::Injection), 0.85);
        assert_eq!(normalised_score(0.95, Category::Threat), 1.0);
    }
}
