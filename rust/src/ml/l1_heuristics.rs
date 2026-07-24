// SPDX-License-Identifier: GPL-3.0-only
use aho_corasick::AhoCorasick;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct RawRule {
    pub ngram: String,
    pub class: String,
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
    let normalized = normalize_json_text_for_rules(text).unwrap_or_else(|| text.to_string());
    let lower = normalized.to_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();
    parts.join(" ")
}

fn normalize_json_text_for_rules(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    if !value.is_object() && !value.is_array() {
        return None;
    }

    let mut parts = Vec::new();
    flatten_json_value_for_rules(&value, &mut parts);
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn flatten_json_value_for_rules(value: &serde_json::Value, parts: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                parts.push(normalize_json_key_for_rules(key));
                flatten_json_value_for_rules(value, parts);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                flatten_json_value_for_rules(value, parts);
            }
        }
        serde_json::Value::String(value) => parts.push(value.clone()),
        serde_json::Value::Number(value) => parts.push(value.to_string()),
        serde_json::Value::Bool(value) => parts.push(value.to_string()),
        serde_json::Value::Null => {}
    }
}

fn normalize_json_key_for_rules(key: &str) -> String {
    match key {
        "cmd" | "command" => "command".to_string(),
        "name" | "tool" | "tool_name" => "tool_name".to_string(),
        _ => key.to_string(),
    }
}
