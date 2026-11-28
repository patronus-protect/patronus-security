// SPDX-License-Identifier: MIT OR Apache-2.0
//! Necessary lexical conditions only; the original matcher still decides.
use regex_syntax::hir::{Class, Hir, HirKind};

use super::lexical_anchors::{AnchorPresence, LexicalAnchorScanner};

#[derive(Debug, Clone, Default)]
pub enum AnchorGate {
    #[default]
    Always,
    Present(Vec<usize>),
    /// One of these words of the anchor automaton occurs.
    Words(Vec<usize>),
    All(Vec<Self>),
    Any(Vec<Self>),
}

impl AnchorGate {
    pub fn regex(pattern: &str, case_insensitive: bool) -> Self {
        regex_syntax::ParserBuilder::new()
            .case_insensitive(case_insensitive)
            .build()
            .parse(pattern)
            .map(|hir| Self::from_hir(&hir))
            .unwrap_or(Self::Always)
    }

    pub fn literals<'a>(words: impl IntoIterator<Item = &'a str>) -> Self {
        Self::any(words.into_iter().map(Self::literal).collect())
    }

    fn literal(word: &str) -> Self {
        let indices = LexicalAnchorScanner::shared().indices_in_literal(word);
        if indices.is_empty() {
            Self::Always
        } else {
            Self::Present(indices)
        }
    }

    /// A gate on the words of [`necessary_words`] (in the anchor automaton);
    /// unconditional without them.
    pub fn words(words: &[String]) -> Self {
        let scanner = LexicalAnchorScanner::shared();
        let indices: Option<Vec<usize>> = words.iter().map(|w| scanner.word_index(w)).collect();
        match indices {
            Some(indices) if !indices.is_empty() => Self::Words(indices),
            _ => Self::Always,
        }
    }

    pub fn all(gates: Vec<Self>) -> Self {
        let mut gates: Vec<_> = gates
            .into_iter()
            .filter(|g| !g.is_unconditional())
            .collect();
        match gates.len() {
            0 => Self::Always,
            1 => gates.pop().unwrap(),
            _ => Self::All(gates),
        }
    }

    pub fn any(mut gates: Vec<Self>) -> Self {
        if gates.is_empty() || gates.iter().any(Self::is_unconditional) {
            Self::Always
        } else if gates.len() == 1 {
            gates.pop().unwrap()
        } else {
            Self::Any(gates)
        }
    }

    pub fn is_unconditional(&self) -> bool {
        matches!(self, Self::Always)
    }

    /// Least number of anchors that every allowed input contains: one per
    /// required literal, the cheapest branch of an alternation.
    pub fn required_anchors(&self) -> usize {
        match self {
            Self::Always => 0,
            Self::Present(_) => 1,
            Self::Words(_) => 0,
            Self::All(gates) => gates.iter().map(Self::required_anchors).sum(),
            Self::Any(gates) => gates.iter().map(Self::required_anchors).min().unwrap_or(0),
        }
    }

    pub fn allows(&self, presence: &AnchorPresence) -> bool {
        match self {
            Self::Always => true,
            Self::Present(indices) => indices.iter().any(|&i| presence.contains_index(i)),
            Self::Words(words) => words.iter().any(|&w| presence.contains_word(w)),
            Self::All(gates) => gates.iter().all(|gate| gate.allows(presence)),
            Self::Any(gates) => gates.iter().any(|gate| gate.allows(presence)),
        }
    }

    fn from_hir(hir: &Hir) -> Self {
        if let Some(word) = fixed_text(hir) {
            return Self::literal(&word);
        }
        match hir.kind() {
            HirKind::Capture(capture) => Self::from_hir(&capture.sub),
            HirKind::Repetition(repeat) if repeat.min > 0 => Self::from_hir(&repeat.sub),
            HirKind::Alternation(branches) => {
                Self::any(branches.iter().map(Self::from_hir).collect())
            }
            HirKind::Concat(parts) => {
                let mut gates = Vec::new();
                let mut run = String::new();
                for part in parts {
                    if let Some(fragment) = fixed_text(part) {
                        run.push_str(&fragment);
                    } else {
                        gates.push(Self::literal(&run));
                        run.clear();
                        gates.push(Self::from_hir(part));
                    }
                }
                gates.push(Self::literal(&run));
                Self::all(gates)
            }
            _ => Self::Always,
        }
    }
}

/// Folded words one of which every match of `pattern` holds (each at least
/// two characters), or `None` when no such set is known.
pub fn necessary_words(pattern: &str, case_insensitive: bool) -> Option<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .case_insensitive(case_insensitive)
        .build()
        .parse(pattern)
        .ok()?;
    let mut words = words_of(&hir)?;
    words.sort();
    words.dedup();
    Some(words)
}

const MIN_WORD_CHARS: usize = 2;

fn words_of(hir: &Hir) -> Option<Vec<String>> {
    words_after(String::new(), std::slice::from_ref(hir))
}

/// Words of the concatenation of the literal `prefix` and `parts`. The parser
/// factors common prefixes out of alternations ("r(?:m…|emove-item…)"), so a
/// literal run before an alternation joins each of its branches.
fn words_after(prefix: String, parts: &[Hir]) -> Option<Vec<String>> {
    let long_enough = |word: &str| word.chars().count() >= MIN_WORD_CHARS;
    // Any required part's set will do; keep the one whose shortest word is
    // longest (fewest chance hits).
    let shortest = |set: &Vec<String>| set.iter().map(|w| w.chars().count()).min();
    let mut best: Option<Vec<String>> = None;
    let mut consider = |candidate: Option<Vec<String>>| {
        if let Some(candidate) = candidate.filter(|set| !set.is_empty()) {
            if best
                .as_ref()
                .is_none_or(|b| shortest(&candidate) > shortest(b))
            {
                best = Some(candidate);
            }
        }
    };
    let mut run = prefix;
    let mut stack: Vec<&Hir> = parts.iter().rev().collect();
    while let Some(part) = stack.pop() {
        if let Some(fragment) = fixed_text(part) {
            run.push_str(&fragment);
            continue;
        }
        match part.kind() {
            HirKind::Capture(capture) => {
                stack.push(&capture.sub);
                continue;
            }
            HirKind::Concat(inner) => {
                stack.extend(inner.iter().rev());
                continue;
            }
            HirKind::Alternation(branches) if !run.is_empty() => consider(
                branches
                    .iter()
                    .map(|branch| words_after(run.clone(), std::slice::from_ref(branch)))
                    .collect::<Option<Vec<_>>>()
                    .map(|sets| sets.concat()),
            ),
            _ => {}
        }
        consider(long_enough(&run).then(|| vec![run.clone()]));
        run.clear();
        consider(match part.kind() {
            HirKind::Repetition(repeat) if repeat.min > 0 => words_of(&repeat.sub),
            HirKind::Alternation(branches) => branches
                .iter()
                .map(words_of)
                .collect::<Option<Vec<_>>>()
                .map(|sets| sets.concat()),
            _ => None,
        });
    }
    consider(long_enough(&run).then_some(vec![run]));
    best
}

// Return an exact string only when every alternative has the same lexical
// spelling after our case normalization. Variable classes/repetitions break
// literal runs; optional words can never become mandatory anchors.
fn fixed_text(hir: &Hir) -> Option<String> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(String::new()),
        HirKind::Literal(literal) => std::str::from_utf8(&literal.0)
            .ok()
            .map(super::lexical_anchors::fold_literal),
        HirKind::Capture(capture) => fixed_text(&capture.sub),
        HirKind::Concat(parts) => parts
            .iter()
            .map(fixed_text)
            .collect::<Option<Vec<_>>>()
            .map(|v| v.concat()),
        HirKind::Class(Class::Unicode(class)) => {
            let mut spelling = None;
            let mut count = 0;
            for range in class.ranges() {
                for codepoint in range.start() as u32..=range.end() as u32 {
                    count += 1;
                    if count > 8 {
                        return None;
                    }
                    let character = char::from_u32(codepoint)?;
                    let value = super::lexical_anchors::fold_literal(&character.to_string());
                    if spelling.as_ref().is_some_and(|previous| previous != &value) {
                        return None;
                    }
                    spelling = Some(value);
                }
            }
            spelling
        }
        HirKind::Repetition(repeat) if repeat.max == Some(repeat.min) && repeat.min <= 32 => {
            fixed_text(&repeat.sub).map(|s| s.repeat(repeat.min as usize))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_bilingual_anchors_preserve_unicode_and_spacing_matches() {
        let pattern = r"(?i)(?:ignore|ignoriere)\s+(?:instructions|regeln)";
        let regex = regex::Regex::new(pattern).unwrap();
        let gate = AnchorGate::regex(pattern, false);
        assert!(!gate.is_unconditional());
        for text in [
            "IGNORE\tINSTRUCTIONS",
            "Ignoriere\nRegeln",
            "ignore inſtructions",
        ] {
            assert!(regex.is_match(text), "{text}");
            let prepared = crate::threat::NativeText::new(text);
            assert!(gate.allows(prepared.anchors()), "{text}");
        }
        let prepared = crate::threat::NativeText::new("a quiet afternoon");
        assert!(!gate.allows(prepared.anchors()));
    }

    #[test]
    fn unknown_alternatives_and_optional_words_cannot_be_required() {
        for pattern in [r"(?:ignore|xyzzy)\d+", r"(?:ignore)?\d+", r"\d{4}-\d{4}"] {
            assert!(
                AnchorGate::regex(pattern, false).is_unconditional(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn required_anchors_count_literals_and_take_the_cheapest_branch() {
        let two = AnchorGate::all(vec![
            AnchorGate::Present(vec![0]),
            AnchorGate::Present(vec![1]),
        ]);
        assert_eq!(two.required_anchors(), 2);
        let gate = AnchorGate::regex(r"(?:ignore|ignoriere)\s+(?:instructions|regeln)", true);
        assert!(gate.required_anchors() >= 1);
        assert_eq!(
            AnchorGate::regex(r"\d{4}-\d{4}", true).required_anchors(),
            0
        );
        let any = AnchorGate::any(vec![
            AnchorGate::regex(r"ignore\s+instructions", true),
            AnchorGate::regex(r"ignore", true),
        ]);
        assert_eq!(any.required_anchors(), 1);
    }

    #[test]
    fn necessary_words_join_factored_prefixes_and_take_the_longest_set() {
        // The parser factors "r" out of the branches; each branch keeps it.
        let pattern = r"(?:\brmtree\(|\brm\s+-r|\bremove-item\s+-recurse)\s*(?:~|/home/)";
        assert_eq!(
            necessary_words(pattern, true),
            Some(vec!["remove-item".into(), "rm".into(), "rmtree(".into()])
        );
        // The required part with the longest shortest word wins.
        assert_eq!(
            necessary_words(r"(?:send|mail)\s+(?:password|secret)", true),
            Some(vec!["password".into(), "secret".into()])
        );
        // A branch without any literal makes the alternation unknown.
        assert_eq!(necessary_words(r"(?:send|\d+)\s+x", true), None);
        for (pattern, text) in [
            (pattern, "Rm -r ~/"),
            (r"(?:send|mail)\s+(?:password|secret)", "SEND  Secret"),
        ] {
            let regex = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .unwrap();
            assert!(regex.is_match(text));
            let words = necessary_words(pattern, true).unwrap();
            let lower = text.to_lowercase();
            assert!(words.iter().any(|w| lower.contains(w.as_str())), "{text}");
        }
    }

    #[test]
    fn synonym_presence_does_not_require_a_rule_match() {
        let text = "Bitte außer Acht lassen. Please discard.";
        let signals = LexicalAnchorScanner::shared().scan(text);
        assert!(signals.contains(&"injection.io_override"));
        let regex = regex::Regex::new(r"(?i)ignore\s+instructions").unwrap();
        assert!(!regex.is_match(text));
    }
}
