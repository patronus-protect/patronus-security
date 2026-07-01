use aho_corasick::AhoCorasick;
use regex::RegexSet;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct RawRule {
    pub ngram: String,
    pub class: String,
    pub count: u32,
}

pub struct HeuristicsEngine {
    ac: AhoCorasick,
    classes: Vec<String>,
}

impl HeuristicsEngine {
    pub fn new(raw_rules: Vec<RawRule>) -> Self {
        let mut patterns = Vec::with_capacity(raw_rules.len());
        let mut classes = Vec::with_capacity(raw_rules.len());
        for r in raw_rules {
            patterns.push(r.ngram.clone());
            classes.push(r.class);
        }
        let ac = AhoCorasick::new(patterns).unwrap();
        HeuristicsEngine { ac, classes }
    }

    pub fn evaluate(&self, text: &str) -> Option<(String, f64)> {
        let cleaned = clean_text_for_rules(text);
        let mut best_match: Option<(usize, String)> = None;

        for mat in self.ac.find_overlapping_iter(&cleaned) {
            let pattern_idx = mat.pattern().as_usize();

            if let Some((best_idx, _)) = best_match {
                if pattern_idx >= best_idx {
                    continue;
                }
            }

            let start = mat.start();
            let end = mat.end();

            // Verify word boundaries
            let has_left_boundary = if start > 0 {
                let prev_char = cleaned[..start].chars().next_back().unwrap();
                !is_word_char(prev_char)
            } else {
                true
            };

            let has_right_boundary = if end < cleaned.len() {
                let next_char = cleaned[end..].chars().next().unwrap();
                !is_word_char(next_char)
            } else {
                true
            };

            if has_left_boundary && has_right_boundary {
                best_match = Some((pattern_idx, self.classes[pattern_idx].clone()));
            }
        }

        best_match.map(|(_, class)| (class, 1.0))
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

pub fn clean_text_for_rules(text: &str) -> String {
    let lower = text.to_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();
    parts.join(" ")
}

pub struct NativeHeuristicsEngine {
    set: RegexSet,
}

impl NativeHeuristicsEngine {
    pub fn new() -> Self {
        let patterns: Vec<&str> = crate::detectors::injection::pi::PI_PATTERNS
            .iter()
            .map(|p| p.pattern)
            .collect();
        let set = RegexSet::new(patterns).unwrap();
        NativeHeuristicsEngine { set }
    }

    pub fn evaluate(&self, text: &str) -> bool {
        let cleaned = clean_text_for_rules(text);
        self.set.is_match(&cleaned)
    }
}
