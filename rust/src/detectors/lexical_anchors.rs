// SPDX-License-Identifier: GPL-3.0-only
//! Independent lexical signals, also reused by necessary-condition rule gates.
use aho_corasick::AhoCorasick;
use serde::Deserialize;
use std::{collections::HashMap, sync::OnceLock};

#[derive(Debug, Deserialize)]
pub struct LexicalAnchor {
    pub id: String,
    pub description: String,
    pub en: Vec<String>,
    pub de: Vec<String>,
    pub shared: Vec<String>,
    pub sources: Vec<String>,
}

pub struct LexicalAnchorScanner {
    definitions: Vec<LexicalAnchor>,
    matcher: AhoCorasick,
    pattern_anchors: Vec<Vec<usize>>,
}

pub struct AnchorPresence {
    present: Vec<bool>,
}

impl AnchorPresence {
    pub(crate) fn contains_index(&self, index: usize) -> bool {
        self.present[index]
    }
}

pub(crate) fn fold_literal(word: &str) -> String {
    word.chars()
        .flat_map(char::to_lowercase)
        .map(|c| if c == 'ſ' { 's' } else { c })
        .collect()
}

impl LexicalAnchorScanner {
    /// One immutable automaton shared by all four categories and all requests.
    pub fn shared() -> &'static Self {
        static SCANNER: OnceLock<LexicalAnchorScanner> = OnceLock::new();
        SCANNER.get_or_init(|| {
            let definitions: Vec<LexicalAnchor> = [
                include_str!("anchor_lexicons/injection.json"),
                include_str!("anchor_lexicons/pii.json"),
                include_str!("anchor_lexicons/dlp.json"),
                include_str!("anchor_lexicons/threat.json"),
            ]
            .into_iter()
            .flat_map(|source| {
                serde_json::from_str::<Vec<LexicalAnchor>>(source)
                    .expect("valid embedded anchor word list")
            })
            .collect();
            let mut indices = HashMap::new();
            let mut words = Vec::new();
            let mut pattern_anchors: Vec<Vec<usize>> = Vec::new();
            for (anchor, definition) in definitions.iter().enumerate() {
                for word in definition
                    .en
                    .iter()
                    .chain(&definition.de)
                    .chain(&definition.shared)
                {
                    let word = fold_literal(word);
                    assert!(!word.is_empty(), "empty anchor word: {}", definition.id);
                    let index = *indices.entry(word.clone()).or_insert_with(|| {
                        let index = words.len();
                        words.push(word);
                        pattern_anchors.push(Vec::new());
                        index
                    });
                    if !pattern_anchors[index].contains(&anchor) {
                        pattern_anchors[index].push(anchor);
                    }
                }
            }
            Self {
                matcher: AhoCorasick::new(words).expect("valid anchor automaton"),
                definitions,
                pattern_anchors,
            }
        })
    }

    pub fn definitions(&self) -> &[LexicalAnchor] {
        &self.definitions
    }

    pub fn pattern_count(&self) -> usize {
        self.pattern_anchors.len()
    }

    /// Lowercase once, then find all lexical signals. Substrings are signals too.
    pub fn scan(&self, text: &str) -> Vec<&str> {
        self.scan_lowercase(&text.to_lowercase())
    }

    /// Reuse an already Unicode-lowercased view. Returns each present ID once,
    /// in definition order; no word-boundary or rule-context filtering occurs.
    pub fn scan_lowercase(&self, text: &str) -> Vec<&str> {
        let presence = self.presence_lowercase(text);
        self.definitions
            .iter()
            .zip(presence.present)
            .filter_map(|(definition, found)| found.then_some(definition.id.as_str()))
            .collect()
    }

    pub fn presence_lowercase(&self, text: &str) -> AnchorPresence {
        // Unicode regex case folding includes long s. Lowercase alone does not;
        // normalize this rare variant without allocating on ordinary input.
        let folded;
        let text = if text.contains('ſ') {
            folded = text.replace('ſ', "s");
            &folded
        } else {
            text
        };
        let mut present = vec![false; self.definitions.len()];
        for hit in self.matcher.find_overlapping_iter(text) {
            for &anchor in &self.pattern_anchors[hit.pattern().as_usize()] {
                present[anchor] = true;
            }
        }
        AnchorPresence { present }
    }

    pub(crate) fn indices_in_literal(&self, literal: &str) -> Vec<usize> {
        self.presence_lowercase(&fold_literal(literal))
            .present
            .into_iter()
            .enumerate()
            .filter_map(|(i, found)| found.then_some(i))
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiturn_signals_are_present_in_both_languages() {
        let scanner = LexicalAnchorScanner::shared();
        for (suffix, en, de) in [
            (
                "carry_forward",
                "Preserve this for later.",
                "Bitte behalte bei, was wir besprochen haben.",
            ),
            ("task_resume", "Resume the task.", "Bitte setze fort."),
            (
                "deferred_action",
                "Leave for later.",
                "Das können wir zurückstellen.",
            ),
            (
                "memory_reference",
                "Remember our discussion.",
                "Erinnere dich an das Gespräch.",
            ),
            (
                "word_mapping",
                "Use a word replacement.",
                "Nutze eine Ersetzungstabelle.",
            ),
            (
                "encoding_action",
                "Encode the output.",
                "Die Ausgabe verschlüsseln.",
            ),
            (
                "output_restriction",
                "Answer only with the result.",
                "Antworte nur mit dem Ergebnis.",
            ),
            (
                "exact_copy",
                "Copy unchanged.",
                "Bitte übernimm unverändert.",
            ),
            (
                "claimed_exception",
                "An exception applies.",
                "Es gibt eine Sonderfreigabe.",
            ),
            (
                "pending_review",
                "This is awaiting approval.",
                "Die Prüfung ausstehend lassen.",
            ),
            (
                "risk_downgrade",
                "Mark it informational only.",
                "Als unkritisch einstufen.",
            ),
            (
                "scope_limit",
                "This is review only.",
                "Das ist nur zur Prüfung.",
            ),
            (
                "selection_action",
                "Exclude that row.",
                "Diese Zeile weglassen.",
            ),
            (
                "sequence_relation",
                "First check, then continue.",
                "Zuerst prüfen, anschließend fortsetzen.",
            ),
            (
                "source_reference",
                "Consult the runbook.",
                "Sieh in der Checkliste nach.",
            ),
            (
                "workflow_status",
                "The task is completed.",
                "Die Aufgabe ist erledigt.",
            ),
            (
                "verification_action",
                "Verify the result.",
                "Das Ergebnis überprüfen.",
            ),
            ("state_write", "Save state.", "Den Zustand speichern."),
            (
                "warning_suppression",
                "Omit the warning.",
                "Die Warnung weglassen.",
            ),
        ] {
            let id = format!("injection.{suffix}");
            for text in [en, de] {
                assert!(scanner.scan(text).contains(&id.as_str()), "{id}: {text}");
                assert!(
                    scanner.scan(&text.to_uppercase()).contains(&id.as_str()),
                    "uppercase {id}: {text}"
                );
            }
        }
    }

    #[test]
    fn presence_retains_negated_overlapping_and_substring_signals() {
        let scanner = LexicalAnchorScanner::shared();
        for text in ["not approved", "nicht genehmigt"] {
            let ids = scanner.scan(text);
            assert!(ids.contains(&"injection.authority_approval"));
            assert!(ids.contains(&"injection.pending_review"));
        }
        // Presence is not an attack verdict, a word-boundary check, or turn memory.
        assert!(scanner
            .scan("Vorabüberprüfung")
            .contains(&"injection.verification_action"));
        let ids = scanner.scan("resume resume");
        assert_eq!(
            ids.iter()
                .filter(|&&id| id == "injection.task_resume")
                .count(),
            1
        );
        assert!(scanner.scan("").is_empty());
    }

    #[test]
    fn lexical_definitions_have_unique_ids_and_nonempty_literals() {
        let scanner = LexicalAnchorScanner::shared();
        let mut ids = std::collections::HashSet::new();
        for definition in scanner.definitions() {
            assert!(
                ids.insert(&definition.id),
                "duplicate ID: {}",
                definition.id
            );
            for words in [&definition.en, &definition.de, &definition.shared] {
                let mut seen = std::collections::HashSet::new();
                for word in words {
                    assert!(!word.trim().is_empty(), "{}", definition.id);
                    assert!(
                        seen.insert(fold_literal(word)),
                        "duplicate literal in {}: {word}",
                        definition.id
                    );
                }
            }
        }
    }
}
