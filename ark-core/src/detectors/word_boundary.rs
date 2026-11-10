// SPDX-License-Identifier: MIT OR Apache-2.0
//! Searches of patterns with a Unicode word boundary on the lazy DFA.
//!
//! A Unicode word boundary sends the lazy DFA to the slow NFA at the first
//! non-ASCII byte (`ä` in German prose), for the rest of the text. The pattern
//! without its word boundaries stays on the DFA and matches wherever the
//! pattern does: each of its match starts is probed anchored with the pattern
//! itself, and only a start that holds is searched with it (H03, H06-6).
use regex::Regex;
use regex_automata::{meta, Anchored, Input};
use regex_syntax::ast;
use regex_syntax::hir::{Hir, HirKind, Look};

/// A regex searched like [`Regex::find_at`], on the lazy DFA also when it has
/// a Unicode word boundary.
pub struct BoundarySearch {
    regex: Regex,
    relaxed: Option<(Regex, meta::Regex)>,
}

impl BoundarySearch {
    pub fn new(pattern: &str) -> Self {
        Self {
            regex: Regex::new(pattern).unwrap(),
            relaxed: without_unicode_word_boundaries(pattern).map(|relaxed| {
                (
                    Regex::new(&relaxed).expect("a pattern without assertions stays valid"),
                    meta::Regex::new(pattern).unwrap(),
                )
            }),
        }
    }

    /// The leftmost match from `at`, as `Regex::find_at`.
    fn find_at<'t>(&self, text: &'t str, at: usize) -> Option<regex::Match<'t>> {
        let Some((relaxed, anchored)) = &self.relaxed else {
            return self.regex.find_at(text, at);
        };
        self.regex
            .find_at(text, leftmost_start(relaxed, anchored, text, at)?)
    }

    /// The matches in order, as `Regex::find_iter` for a pattern that never
    /// matches the empty string.
    pub fn find_iter<'s, 't>(&'s self, text: &'t str) -> impl Iterator<Item = regex::Match<'t>> + 's
    where
        't: 's,
    {
        let mut at = 0;
        std::iter::from_fn(move || {
            let matched = self.find_at(text, at)?;
            debug_assert!(!matched.is_empty());
            at = matched.end().max(matched.start() + 1);
            Some(matched)
        })
    }
}

/// The start of the leftmost match from `at` of the pattern that `relaxed`
/// is without its word boundaries and `anchored` is with them.
pub(crate) fn leftmost_start(
    relaxed: &Regex,
    anchored: &meta::Regex,
    text: &str,
    at: usize,
) -> Option<usize> {
    let mut start = at;
    loop {
        let candidate = relaxed.find_at(text, start)?.start();
        if anchored.is_match(Input::new(text).range(candidate..).anchored(Anchored::Yes)) {
            // The match starts here, so it is the leftmost one from here.
            return Some(candidate);
        }
        start = candidate + text[candidate..].chars().next()?.len_utf8();
    }
}

/// `pattern` without its word boundaries if it has a Unicode one, else `None`:
/// a necessary condition of the rule that the lazy DFA searches on any text.
/// The assertions are cut out of the pattern source at their syntax spans;
/// the result stays a valid pattern.
pub(crate) fn without_unicode_word_boundaries(pattern: &str) -> Option<String> {
    fn unicode_boundary(hir: &Hir) -> bool {
        match hir.kind() {
            HirKind::Look(look) => matches!(
                look,
                Look::WordUnicode
                    | Look::WordStartUnicode
                    | Look::WordEndUnicode
                    | Look::WordStartHalfUnicode
                    | Look::WordEndHalfUnicode
            ),
            HirKind::Repetition(repetition) => unicode_boundary(&repetition.sub),
            HirKind::Capture(capture) => unicode_boundary(&capture.sub),
            HirKind::Concat(hirs) | HirKind::Alternation(hirs) => hirs.iter().any(unicode_boundary),
            _ => false,
        }
    }
    if !unicode_boundary(&regex_syntax::parse(pattern).ok()?) {
        return None;
    }
    cut_assertions(pattern, |kind| {
        !matches!(
            kind,
            ast::AssertionKind::StartLine
                | ast::AssertionKind::EndLine
                | ast::AssertionKind::StartText
                | ast::AssertionKind::EndText
                | ast::AssertionKind::NotWordBoundary
        )
    })
}

/// `pattern` without any assertion: it matches wherever `pattern` matches,
/// in any context.
pub(crate) fn without_assertions(pattern: &str) -> String {
    cut_assertions(pattern, |_| true).expect("a valid pattern")
}

/// `pattern` with the assertions that `cut` selects cut out at their syntax
/// spans; the result stays a valid pattern.
fn cut_assertions(pattern: &str, cut: fn(&ast::AssertionKind) -> bool) -> Option<String> {
    struct Boundaries(Vec<ast::Span>, fn(&ast::AssertionKind) -> bool);
    impl ast::Visitor for Boundaries {
        type Output = Vec<ast::Span>;
        type Err = ();
        fn finish(self) -> Result<Self::Output, ()> {
            Ok(self.0)
        }
        fn visit_pre(&mut self, node: &ast::Ast) -> Result<(), ()> {
            if let ast::Ast::Assertion(assertion) = node {
                if (self.1)(&assertion.kind) {
                    self.0.push(assertion.span);
                }
            }
            Ok(())
        }
    }
    let syntax = ast::parse::Parser::new().parse(pattern).ok()?;
    let boundaries = ast::visit(&syntax, Boundaries(Vec::new(), cut)).ok()?;
    let mut relaxed = String::with_capacity(pattern.len());
    let mut at = 0;
    for span in boundaries {
        relaxed.push_str(&pattern[at..span.start.offset]);
        at = span.end.offset;
    }
    relaxed.push_str(&pattern[at..]);
    Some(relaxed)
}

/// Asserts that [`BoundarySearch::find_iter`] of `pattern` yields the matches
/// of `Regex::find_iter` on the strings of the bilingual fixture, each after
/// German prose (non-ASCII before the match) and all of them in one text.
#[cfg(test)]
pub(crate) fn assert_finds_as_regex(pattern: &str) {
    use std::sync::OnceLock;
    static TEXTS: OnceLock<Vec<String>> = OnceLock::new();
    let texts = TEXTS.get_or_init(|| {
        fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::String(text) => out.push(format!("Grüße – {text}")),
                serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
                serde_json::Value::Object(map) => map.values().for_each(|v| strings(v, out)),
                _ => {}
            }
        }
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/l1_bilingual_rules.json"))
                .unwrap();
        let mut texts = Vec::new();
        strings(&cases, &mut texts);
        let all = texts.join("\nÄnderung: ");
        texts.push(all);
        texts
    });
    let search = BoundarySearch::new(pattern);
    for text in texts {
        let expected: Vec<_> = search.regex.find_iter(text).map(|m| m.range()).collect();
        let found: Vec<_> = search.find_iter(text).map(|m| m.range()).collect();
        assert_eq!(found, expected, "{pattern} on {text:.80}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unicode_word_boundaries_take_the_relaxed_search() {
        assert!(BoundarySearch::new(r"(?i)\bname\b").relaxed.is_some());
        assert!(BoundarySearch::new(r"(?i-u:\b)name(?-u:\b)")
            .relaxed
            .is_none());
        assert!(BoundarySearch::new(r"name").relaxed.is_none());
    }

    #[test]
    fn without_assertions_cuts_every_assertion() {
        assert_eq!(
            without_assertions(r"(?:^|[.;]\s*)\bsend\B(?-u:\b)\s+keys$"),
            r"(?:|[.;]\s*)send(?-u:)\s+keys"
        );
        assert_eq!(without_assertions(r"(?m)^a\Ab\z"), "(?m)ab");
    }

    #[test]
    fn boundary_search_finds_what_the_regex_finds_after_non_ascii_text() {
        let search = BoundarySearch::new(r"(?i)\b(?:name|straße)\b");
        let text = "Grüße, Name: Ada; Straßenname; Straße 5; ÜName; name";
        let found: Vec<_> = search.find_iter(text).map(|m| m.as_str()).collect();
        assert_eq!(found, ["Name", "Straße", "name"]);
        assert_finds_as_regex(r"(?i)\b(?:name|straße)\b");
    }
}
