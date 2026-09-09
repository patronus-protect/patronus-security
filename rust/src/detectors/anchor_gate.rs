// SPDX-License-Identifier: GPL-3.0-only
//! Necessary lexical conditions only; the original matcher still decides.
use regex_syntax::hir::{Class, Hir, HirKind};

use super::lexical_anchors::{AnchorPresence, LexicalAnchorScanner};

#[derive(Debug, Clone, Default)]
pub(crate) enum AnchorGate {
    #[default]
    Always,
    Present(Vec<usize>),
    All(Vec<Self>),
    Any(Vec<Self>),
}

impl AnchorGate {
    pub(crate) fn regex(pattern: &str, case_insensitive: bool) -> Self {
        regex_syntax::ParserBuilder::new()
            .case_insensitive(case_insensitive)
            .build()
            .parse(pattern)
            .map(|hir| Self::from_hir(&hir))
            .unwrap_or(Self::Always)
    }

    pub(crate) fn literals<'a>(words: impl IntoIterator<Item = &'a str>) -> Self {
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

    pub(crate) fn all(gates: Vec<Self>) -> Self {
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

    pub(crate) fn any(mut gates: Vec<Self>) -> Self {
        if gates.is_empty() || gates.iter().any(Self::is_unconditional) {
            Self::Always
        } else if gates.len() == 1 {
            gates.pop().unwrap()
        } else {
            Self::Any(gates)
        }
    }

    pub(crate) fn is_unconditional(&self) -> bool {
        matches!(self, Self::Always)
    }

    pub(crate) fn allows(&self, presence: &AnchorPresence) -> bool {
        match self {
            Self::Always => true,
            Self::Present(indices) => indices.iter().any(|&i| presence.contains_index(i)),
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
    fn synonym_presence_does_not_require_a_rule_match() {
        let text = "Bitte außer Acht lassen. Please discard.";
        let signals = LexicalAnchorScanner::shared().scan(text);
        assert!(signals.contains(&"injection.io_override"));
        let regex = regex::Regex::new(r"(?i)ignore\s+instructions").unwrap();
        assert!(!regex.is_match(text));
    }
}
