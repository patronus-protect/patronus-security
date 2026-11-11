// SPDX-License-Identifier: MIT OR Apache-2.0
//! Context engine of the L1 categories (core layer): support and
//! counter-context terms of the DE/EN lexica in `anchor_lexicons/*.json`, looked
//! up on both sides of a value. A term counts within [`BEFORE_WINDOW`]
//! characters before or [`AFTER_WINDOW`] after the value, never across a line
//! break or past a digit, and only as a whole word. The nearest term decides:
//! a support term gives [`Context::Support`], a strictly nearer counter term
//! [`Context::Counter`]. [`Evidence`] names the deciding term for
//! `matched_rules[].context`. The categories only map lexicon IDs to labels.
use regex::Regex;

use crate::detectors::lexical_anchors::LexicalAnchorScanner;
use crate::detectors::score::Context;

/// Characters between a term and the value: before it (field names, "erreichbar
/// unter") and after it ("(Handy)", "erreichbar").
pub const BEFORE_WINDOW: usize = 48;
pub const AFTER_WINDOW: usize = 32;

/// The words of the lexicon IDs in `anchor_lexicons/*.json`.
pub(crate) fn lexicon_words(ids: &[&str]) -> Vec<&'static str> {
    let definitions = LexicalAnchorScanner::shared().definitions();
    ids.iter()
        .flat_map(|id| {
            let definition = definitions
                .iter()
                .find(|definition| definition.id == *id)
                .unwrap_or_else(|| panic!("unknown lexicon id {id}"));
            definition.words().map(String::as_str)
        })
        .collect()
}

/// Case-insensitive alternation of every word of the lexicon IDs, longest first.
pub(crate) fn lexicon_regex(ids: &[&str]) -> Regex {
    Regex::new(&format!("(?i)(?:{})", lexicon_alternation(ids))).unwrap()
}

fn lexicon_alternation(ids: &[&str]) -> String {
    let mut words: Vec<_> = lexicon_words(ids).into_iter().map(regex::escape).collect();
    words.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    words.dedup();
    words.join("|")
}

/// Gap in characters between a term and the value, if the term may describe
/// the value. A term never reaches across a line break or past a digit (the
/// value of another field). After the value, the term must also not be the
/// field name of the next value ("…, Telefon: …"): the gap holds no list or
/// field separator and the term is not followed by `:`, `=`, `#` or a digit.
fn term_gap(text: &str, term: (usize, usize), value: (usize, usize)) -> Option<usize> {
    let word = |ch: Option<char>| ch.is_some_and(char::is_alphanumeric);
    let term_text = &text[term.0..term.1];
    // Whole words only where the term starts or ends with a letter or digit.
    if (word(term_text.chars().next()) && word(text[..term.0].chars().next_back()))
        || (word(term_text.chars().next_back()) && word(text[term.1..].chars().next()))
    {
        return None;
    }
    let (gap, window, after) = if term.1 <= value.0 {
        (&text[term.1..value.0], BEFORE_WINDOW, false)
    } else if term.0 >= value.1 {
        (&text[value.1..term.0], AFTER_WINDOW, true)
    } else {
        return None;
    };
    if gap
        .chars()
        .any(|ch| ch == '\n' || ch == '\r' || ch.is_ascii_digit() || matches!(ch, ';' | '|'))
    {
        return None;
    }
    if after {
        let next = text[term.1..]
            .trim_start_matches([' ', '\t'])
            .chars()
            .next();
        if gap.chars().any(|ch| matches!(ch, ',' | ':' | '=' | '#'))
            || next.is_some_and(|ch| matches!(ch, ':' | '=' | '#') || ch.is_ascii_digit())
        {
            return None;
        }
    }
    let gap = gap.chars().count();
    (gap <= window).then_some(gap)
}

/// Byte range around `value` that holds every term whose gap fits the windows:
/// the window plus the longest term on each side, never past a line break.
fn region(text: &str, value: (usize, usize), longest: usize) -> (usize, usize) {
    let start = text[..value.0]
        .char_indices()
        .rev()
        .take(BEFORE_WINDOW + longest)
        .take_while(|(_, ch)| !matches!(ch, '\n' | '\r'))
        .last()
        .map_or(value.0, |(index, _)| index);
    let end = text[value.1..]
        .char_indices()
        .take(AFTER_WINDOW + longest)
        .take_while(|(_, ch)| !matches!(ch, '\n' | '\r'))
        .last()
        .map_or(value.1, |(index, ch)| value.1 + index + ch.len_utf8());
    (start, end)
}

/// Which side of the value a context term stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Before,
    After,
    /// The term is the structural key of the value (K04).
    Key,
}

impl Side {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Key => "key",
        }
    }
}

/// Context of one value and the term that decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub context: Context,
    /// Lexicon ID of the deciding term, or `field` for a field name the rule
    /// binds itself.
    pub anchor: Option<&'static str>,
    pub side: Option<Side>,
    /// Characters between the deciding term and the value.
    pub distance: Option<usize>,
}

impl Evidence {
    /// A value the rule binds to its own field name.
    pub fn field() -> Self {
        Self {
            context: Context::Field,
            anchor: Some("field"),
            ..Self::none()
        }
    }

    /// A value bound to a field name: right before it, or as its structural key
    /// (K04) when `structural`.
    pub fn field_at(structural: bool) -> Self {
        Self {
            side: structural.then_some(Side::Key),
            ..Self::field()
        }
    }

    pub const fn none() -> Self {
        Self {
            context: Context::None,
            anchor: None,
            side: None,
            distance: None,
        }
    }

    /// Context points the score adds.
    pub fn bonus(&self) -> u8 {
        u8::try_from(self.context.points().max(0)).unwrap_or(u8::MAX)
    }

    /// Counter-context points the score subtracts.
    pub fn penalty(&self) -> u8 {
        u8::try_from((-self.context.points()).max(0)).unwrap_or(u8::MAX)
    }

    /// `matched_rules[].context` of a finding in a scored mode.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({"bonus": self.bonus(), "penalty": self.penalty()});
        if let Some(anchor) = self.anchor {
            value["anchor"] = anchor.into();
        }
        if let Some(side) = self.side {
            value["side"] = side.as_str().into();
        }
        if let Some(distance) = self.distance {
            value["distance"] = distance.into();
        }
        value
    }
}

/// A term that may describe the value: its byte range, side and gap.
#[derive(Clone, Copy)]
pub(crate) struct Term {
    range: (usize, usize),
    side: Side,
    pub(crate) gap: usize,
}

/// Nearest term of `regex` within `region` on either side of `value`.
fn nearest(
    text: &str,
    regex: &Regex,
    region: (usize, usize),
    value: (usize, usize),
) -> Option<Term> {
    regex
        .find_iter(&text[region.0..region.1])
        .filter_map(|term| {
            let range = (region.0 + term.start(), region.0 + term.end());
            let side = if range.1 <= value.0 {
                Side::Before
            } else {
                Side::After
            };
            term_gap(text, range, value).map(|gap| Term { range, side, gap })
        })
        .min_by_key(|term| term.gap)
}

/// Nearest term of `regex` within the windows around `value`, for lexica
/// whose longest term has `longest` characters.
pub(crate) fn nearest_term(
    text: &str,
    regex: &Regex,
    longest: usize,
    value: (usize, usize),
) -> Option<Term> {
    nearest(text, regex, region(text, value, longest), value)
}

/// One support and one counter-context lexicon: the proximity context of a
/// value as the nearest of their terms decides it.
pub struct ProximityLexicon {
    support_ids: &'static [&'static str],
    counter_ids: &'static [&'static str],
    support: Option<Regex>,
    counter: Option<Regex>,
    /// Whole-term matchers per lexicon ID, to name the ID of a found term.
    ids: Vec<(&'static str, Regex)>,
    /// Characters of the longest term the windows must hold.
    longest: usize,
}

impl ProximityLexicon {
    pub fn new(support_ids: &'static [&'static str], counter_ids: &'static [&'static str]) -> Self {
        let all = || support_ids.iter().chain(counter_ids);
        let regex = |ids: &[&str]| (!ids.is_empty()).then(|| lexicon_regex(ids));
        Self {
            support_ids,
            counter_ids,
            support: regex(support_ids),
            counter: regex(counter_ids),
            ids: all()
                .map(|id| {
                    let words = lexicon_alternation(&[id]);
                    (*id, Regex::new(&format!("(?i)^(?:{words})$")).unwrap())
                })
                .collect(),
            longest: all()
                .flat_map(|id| lexicon_words(&[id]))
                .map(|word| word.chars().count())
                .max()
                .unwrap_or(0),
        }
    }

    /// The same lexicon with windows that hold terms of `longest` characters,
    /// so that lexica built for one label search the region of a shared one.
    pub(crate) fn with_longest(mut self, longest: usize) -> Self {
        self.longest = self.longest.max(longest);
        self
    }

    /// Characters of the longest term.
    pub(crate) fn longest(&self) -> usize {
        self.longest
    }

    /// Two-sided proximity context of the value at `value` (byte range): the
    /// nearest support term gives [`Context::Support`] unless a counter-context
    /// term is strictly nearer, which gives [`Context::Counter`].
    pub fn evidence(&self, text: &str, value: (usize, usize)) -> Evidence {
        self.evidence_with(text, value, true)
    }

    /// Whether the context supports the value; skips the counter search when
    /// there is no support term at all.
    pub fn supports(&self, text: &str, value: (usize, usize)) -> bool {
        self.evidence_with(text, value, false).context.supports()
    }

    fn evidence_with(&self, text: &str, value: (usize, usize), always_counter: bool) -> Evidence {
        let region = region(text, value, self.longest);
        let nearest = |regex: &Option<Regex>| {
            regex
                .as_ref()
                .and_then(|regex| nearest(text, regex, region, value))
        };
        let support = nearest(&self.support);
        if support.is_none() && !always_counter {
            return Evidence::none();
        }
        let counter = nearest(&self.counter);
        let (context, term, ids) = match (support, counter) {
            (Some(support), Some(counter)) if counter.gap < support.gap => {
                (Context::Counter, counter, self.counter_ids)
            }
            (Some(support), _) => (
                Context::Support { gap: support.gap },
                support,
                self.support_ids,
            ),
            (None, Some(counter)) => (Context::Counter, counter, self.counter_ids),
            (None, None) => return Evidence::none(),
        };
        let found = &text[term.range.0..term.range.1];
        Evidence {
            context,
            anchor: ids.iter().copied().find(|id| {
                self.ids
                    .iter()
                    .any(|(known, regex)| known == id && regex.is_match(found))
            }),
            side: Some(term.side),
            distance: Some(term.gap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORT: &[&str] = &["dlp.password"];
    const COUNTER: &[&str] = &["dlp.digest_reference"];

    fn value_of(text: &str, value: &str) -> (usize, usize) {
        let start = text.find(value).unwrap();
        (start, start + value.len())
    }

    #[test]
    fn nearest_support_term_names_anchor_side_and_distance() {
        let lexicon = ProximityLexicon::new(SUPPORT, COUNTER);
        let text = "Das Kennwort lautet Xq7-Lm2-Pz9";
        let evidence = lexicon.evidence(text, value_of(text, "Xq7-Lm2-Pz9"));
        assert_eq!(evidence.context, Context::Support { gap: 8 });
        assert_eq!(evidence.anchor, Some("dlp.password"));
        assert_eq!(evidence.side, Some(Side::Before));
        assert!(lexicon.supports(text, value_of(text, "Xq7-Lm2-Pz9")));
    }

    #[test]
    fn strictly_nearer_counter_term_decides() {
        let lexicon = ProximityLexicon::new(SUPPORT, COUNTER);
        let text = "password file, checksum abcdef0123";
        let evidence = lexicon.evidence(text, value_of(text, "abcdef0123"));
        assert_eq!(evidence.context, Context::Counter);
        assert_eq!(evidence.anchor, Some("dlp.digest_reference"));
        assert!(!lexicon.supports(text, value_of(text, "abcdef0123")));
    }

    #[test]
    fn terms_count_only_as_whole_words_on_the_value_line() {
        let lexicon = ProximityLexicon::new(SUPPORT, COUNTER);
        for text in ["password\nXq7-Lm2-Pz9", "superpasswordy Xq7-Lm2-Pz9"] {
            let evidence = lexicon.evidence(text, value_of(text, "Xq7-Lm2-Pz9"));
            assert_eq!(evidence, Evidence::none(), "{text}");
        }
    }

    #[test]
    fn counter_only_lexicon_never_supports() {
        let lexicon = ProximityLexicon::new(&[], COUNTER);
        let text = "password Xq7-Lm2-Pz9";
        assert_eq!(
            lexicon.evidence(text, value_of(text, "Xq7-Lm2-Pz9")),
            Evidence::none()
        );
        let text = "checksum abcdef0123";
        let value = value_of(text, "abcdef0123");
        assert_eq!(lexicon.evidence(text, value).context, Context::Counter);
        assert!(!lexicon.supports(text, value));
    }

    #[test]
    fn terms_beyond_the_window_do_not_count() {
        let lexicon = ProximityLexicon::new(SUPPORT, COUNTER);
        let filler = "x ".repeat(BEFORE_WINDOW / 2 + 1);
        let text = format!("password {filler}Xq7-Lm2-Pz9");
        let evidence = lexicon.evidence(&text, value_of(&text, "Xq7-Lm2-Pz9"));
        assert_eq!(evidence, Evidence::none());
    }
}
