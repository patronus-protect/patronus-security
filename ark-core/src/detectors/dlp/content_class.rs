// SPDX-License-Identifier: MIT OR Apache-2.0
//! M01: content class engine. A document class is a rule whose regex matches
//! a strong anchor (a marker such as "attorney-client privileged"); that match
//! is the evidence span and the document label. The marker alone is no proof:
//! it is quoted in definitions, templates and course notes. The class holds
//! when the anchors within `window` bytes on either side of the marker add up
//! (the minimum density):
//!
//! - strong: the marker itself, [`STRONG_WEIGHT`] points;
//! - medium: domain terms (counsel, Kanzlei, Rechtsstreit), [`MEDIUM_WEIGHT`]
//!   points each, at least `min_medium` of them;
//! - structural: document structure (Subject:, Betreff:, Dear, Mit
//!   freundlichen Grüßen), [`STRUCTURAL_WEIGHT`] point each, at least
//!   `min_structural` of them. A strong or medium anchor used as a field
//!   label (`Sperrfrist:`, `Term:`, `"fees":`) is record structure and counts
//!   as one more structural anchor;
//! - counter: counter-context (example, template, Vorlage, Seminar), minus
//!   [`COUNTER_WEIGHT`] points each.
//!
//! Each distinct anchor counts once, and anchors inside the marker do not
//! count. Anchors are lower-case ASCII-case-insensitive literals matched as
//! whole words, on one Aho-Corasick automaton per class built once; the gate
//! runs only where the marker regex matched.
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::ops::Range;

pub(crate) const STRONG_WEIGHT: i32 = 3;
pub(crate) const MEDIUM_WEIGHT: i32 = 2;
pub(crate) const STRUCTURAL_WEIGHT: i32 = 1;
pub(crate) const COUNTER_WEIGHT: i32 = 3;
/// The anchors a class may have: one bit each in the per-scan `seen` set.
const MAX_ANCHORS: usize = 256;

/// The tier of a non-strong anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Medium,
    Structural,
    Counter,
}

/// Thresholds of a class around its strong anchor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Density {
    /// Bytes on either side of the strong anchor in which anchors count.
    pub window: usize,
    /// Minimum score, the strong anchor included.
    pub min_score: i32,
    /// Minimum number of distinct medium anchors.
    pub min_medium: usize,
    /// Minimum number of distinct structural anchors and field labels:
    /// prose about a document type (an encyclopedia article on NDAs) has the
    /// domain terms but not the form of a letter, agreement or record.
    pub min_structural: usize,
}

/// A compiled content class: its anchors and thresholds.
pub(crate) struct ContentClass {
    tiers: Vec<Tier>,
    automaton: AhoCorasick,
    density: Density,
}

impl ContentClass {
    /// Compiles the anchors (lower-case literals, at most [`MAX_ANCHORS`]) of a class.
    pub(crate) fn new(anchors: &[(&str, Tier)], density: Density) -> Self {
        assert!(
            anchors.len() <= MAX_ANCHORS,
            "a content class has at most {MAX_ANCHORS} anchors"
        );
        Self {
            tiers: anchors.iter().map(|(_, tier)| *tier).collect(),
            automaton: AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(anchors.iter().map(|(term, _)| term))
                .expect("content class anchors compile"),
            density,
        }
    }

    /// The score of the anchors around the strong anchor at `evidence`, or
    /// `None` when fewer than `min_medium` medium or `min_structural`
    /// structural anchors are near it.
    pub(crate) fn score(&self, text: &str, evidence: Range<usize>) -> Option<i32> {
        let bytes = text.as_bytes();
        let start = evidence.start.saturating_sub(self.density.window);
        let end = evidence
            .end
            .saturating_add(self.density.window)
            .min(bytes.len());
        let mut seen = [0u128; MAX_ANCHORS / 128];
        let (mut score, mut medium, mut structural) = (STRONG_WEIGHT, 0, 0);
        if is_field_label(bytes, evidence.end) {
            score += STRUCTURAL_WEIGHT;
            structural += 1;
        }
        for hit in self.automaton.find_overlapping_iter(&bytes[start..end]) {
            let range = start + hit.start()..start + hit.end();
            let id = hit.pattern().as_usize();
            let (word, bit) = (id / 128, 1u128 << (id % 128));
            if seen[word] & bit != 0
                || (range.start < evidence.end && evidence.start < range.end)
                || !is_whole_word(bytes, &range)
            {
                continue;
            }
            seen[word] |= bit;
            score += match self.tiers[id] {
                Tier::Medium if is_field_label(bytes, range.end) => {
                    medium += 1;
                    structural += 1;
                    MEDIUM_WEIGHT + STRUCTURAL_WEIGHT
                }
                Tier::Medium => {
                    medium += 1;
                    MEDIUM_WEIGHT
                }
                Tier::Structural => {
                    structural += 1;
                    STRUCTURAL_WEIGHT
                }
                Tier::Counter => -COUNTER_WEIGHT,
            };
        }
        (medium >= self.density.min_medium && structural >= self.density.min_structural)
            .then_some(score)
    }

    /// Whether the strong anchor at `evidence` labels the document.
    pub(crate) fn holds(&self, text: &str, evidence: Range<usize>) -> bool {
        self.score(text, evidence)
            .is_some_and(|score| score >= self.density.min_score)
    }
}

/// Whether a colon follows the anchor ending at `end`, directly or after the
/// closing quote of a JSON key: `Term:`, `"fees":`.
fn is_field_label(bytes: &[u8], end: usize) -> bool {
    match bytes.get(end) {
        Some(b':') => true,
        Some(b'"' | b'\'') => bytes.get(end + 1) == Some(&b':'),
        _ => false,
    }
}

/// Letters, digits, `_` and every byte of a non-ASCII character (`ä`) join
/// words.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || !byte.is_ascii()
}

/// Whether `range` is no part of a longer word: a word byte at either end of
/// the anchor may not continue outside it (`mandat` is not in `Mandatsgeheimnis`,
/// `re:` is not in `Store:`).
fn is_whole_word(bytes: &[u8], range: &Range<usize>) -> bool {
    let continues_before =
        is_word_byte(bytes[range.start]) && range.start > 0 && is_word_byte(bytes[range.start - 1]);
    let continues_after = is_word_byte(bytes[range.end - 1])
        && bytes.get(range.end).is_some_and(|&byte| is_word_byte(byte));
    !continues_before && !continues_after
}

#[cfg(test)]
mod tests {
    use super::{ContentClass, Density, Tier};

    fn class() -> ContentClass {
        ContentClass::new(
            &[
                ("counsel", Tier::Medium),
                ("kanzlei", Tier::Medium),
                ("mandat", Tier::Medium),
                ("subject:", Tier::Structural),
                ("re:", Tier::Structural),
                ("mit freundlichen grüßen", Tier::Structural),
                ("example", Tier::Counter),
                ("for example", Tier::Counter),
            ],
            Density {
                window: 40,
                min_score: 6,
                min_medium: 1,
                min_structural: 0,
            },
        )
    }

    fn evidence(text: &str) -> std::ops::Range<usize> {
        let start = text.find("MARK").unwrap();
        start..start + 4
    }

    #[test]
    fn strong_medium_and_structural_anchors_add_up() {
        let text = "Subject: MARK from counsel";
        assert_eq!(class().score(text, evidence(text)), Some(3 + 2 + 1));
        assert!(class().holds(text, evidence(text)));
    }

    #[test]
    fn a_strong_anchor_without_a_medium_anchor_never_holds() {
        let text = "Subject: Re: MARK";
        assert_eq!(class().score(text, evidence(text)), None);
        assert!(!class().holds(text, evidence(text)));
    }

    #[test]
    fn each_distinct_anchor_counts_once() {
        let text = "MARK counsel, counsel, COUNSEL";
        assert_eq!(class().score(text, evidence(text)), Some(5));
        assert!(!class().holds(text, evidence(text)));
    }

    #[test]
    fn counter_context_subtracts_and_overlapping_counters_both_count() {
        let text = "Subject: MARK from counsel, for example";
        assert_eq!(class().score(text, evidence(text)), Some(6 - 3 - 3));
        assert!(!class().holds(text, evidence(text)));
    }

    #[test]
    fn anchors_count_only_as_whole_words() {
        // `mandat` inside `Mandatsträger`, `re:` inside `Store:`.
        let text = "Store: MARK Mandatsträger counsel";
        assert_eq!(class().score(text, evidence(text)), Some(5));
        // An umlaut continues a word; ß inside a structural anchor matches.
        let text = "Mit freundlichen Grüßen\nMARK Kanzleiä counsel";
        assert_eq!(class().score(text, evidence(text)), Some(6));
    }

    #[test]
    fn anchors_outside_the_window_do_not_count() {
        let far = " ".repeat(60);
        let text = format!("Subject:{far}MARK counsel{far}Kanzlei");
        assert_eq!(class().score(&text, evidence(&text)), Some(5));
        let text = format!("Subject: MARK counsel{far}for example");
        assert!(class().holds(&text, evidence(&text)));
    }

    #[test]
    fn anchors_beyond_the_first_128_count_once_each() {
        let terms: Vec<String> = (0..200).map(|i| format!("term{i}")).collect();
        let mut anchors: Vec<(&str, Tier)> = terms
            .iter()
            .map(|term| (term.as_str(), Tier::Structural))
            .collect();
        anchors.push(("counsel", Tier::Medium));
        let class = ContentClass::new(
            &anchors,
            Density {
                window: 100,
                min_score: 0,
                min_medium: 1,
                min_structural: 0,
            },
        );
        let text = "MARK counsel term150 term150 term199";
        assert_eq!(class.score(text, evidence(text)), Some(3 + 2 + 1 + 1));
    }

    #[test]
    fn the_last_of_256_anchors_counts() {
        let terms: Vec<String> = (0..255).map(|i| format!("term{i}")).collect();
        let mut anchors: Vec<(&str, Tier)> = terms
            .iter()
            .map(|term| (term.as_str(), Tier::Structural))
            .collect();
        anchors.push(("counsel", Tier::Medium));
        let class = ContentClass::new(
            &anchors,
            Density {
                window: 100,
                min_score: 0,
                min_medium: 1,
                min_structural: 0,
            },
        );
        let text = "MARK counsel counsel term254";
        assert_eq!(class.score(text, evidence(text)), Some(3 + 2 + 1));
    }

    #[test]
    #[should_panic(expected = "a content class has at most 256 anchors")]
    fn more_than_256_anchors_are_rejected() {
        let terms: Vec<String> = (0..257).map(|i| format!("term{i}")).collect();
        let anchors: Vec<(&str, Tier)> = terms
            .iter()
            .map(|term| (term.as_str(), Tier::Structural))
            .collect();
        ContentClass::new(
            &anchors,
            Density {
                window: 100,
                min_score: 0,
                min_medium: 0,
                min_structural: 0,
            },
        );
    }

    #[test]
    fn a_medium_anchor_used_as_field_label_is_structure() {
        // `counsel:` and the JSON key `"kanzlei":` are labels; `counsel` in
        // prose and a quoted value are not.
        let text = "MARK counsel: Lee";
        assert_eq!(class().score(text, evidence(text)), Some(3 + 2 + 1));
        let text = r#"{"doc": "MARK", "kanzlei": "Lee"}"#;
        assert_eq!(class().score(text, evidence(text)), Some(3 + 2 + 1));
        let text = r#"MARK from counsel, "kanzlei" and more"#;
        assert_eq!(class().score(text, evidence(text)), Some(3 + 2 + 2));
    }

    #[test]
    fn a_strong_anchor_used_as_field_label_is_structure() {
        let text = "MARK: Monday, counsel";
        assert_eq!(class().score(text, evidence(text)), Some(3 + 1 + 2));
    }

    #[test]
    fn a_class_with_a_structure_minimum_needs_document_form() {
        let class = ContentClass::new(
            &[("counsel", Tier::Medium), ("subject:", Tier::Structural)],
            Density {
                window: 40,
                min_score: 5,
                min_medium: 1,
                min_structural: 1,
            },
        );
        let text = "MARK from counsel";
        assert_eq!(class.score(text, evidence(text)), None);
        let text = "Subject: MARK from counsel";
        assert!(class.holds(text, evidence(text)));
        let text = "MARK\ncounsel: Lee";
        assert!(class.holds(text, evidence(text)));
    }

    #[test]
    fn anchors_inside_the_strong_anchor_do_not_count() {
        let text = "Re: counsel-MARK";
        let start = text.find("counsel").unwrap();
        assert_eq!(class().score(text, start..text.len()), None);
    }
}
