use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

use super::features::{extract_char_ngrams, extract_ngrams};

#[derive(Debug, Deserialize, Clone)]
pub struct TFIDFVectorizerConfig {
    pub ngram_range: Vec<usize>,
    pub vocabulary: HashMap<String, usize>,
    pub idf: Vec<f64>,
}

#[derive(Clone)]
pub struct TFIDFVectorizer {
    pub config: TFIDFVectorizerConfig,
    pub token_regex: Regex,
}

impl TFIDFVectorizer {
    pub fn new(config: TFIDFVectorizerConfig) -> Self {
        let token_regex = Regex::new(r"\b\w{2,}\b").unwrap();
        TFIDFVectorizer {
            config,
            token_regex,
        }
    }

    pub fn transform_word(&self, text: &str) -> Vec<f64> {
        let lower = text.to_lowercase();
        let tokens: Vec<&str> = self
            .token_regex
            .find_iter(&lower)
            .map(|m| m.as_str())
            .collect();

        let min_n = self.config.ngram_range.first().copied().unwrap_or(1);
        let max_n = self.config.ngram_range.last().copied().unwrap_or(3);

        let ngrams = extract_ngrams(&tokens, min_n, max_n);

        let mut counts = vec![0.0; self.config.idf.len()];
        for ngram in ngrams {
            if let Some(&idx) = self.config.vocabulary.get(&ngram) {
                counts[idx] += 1.0;
            }
        }

        let mut sq_sum = 0.0;
        for i in 0..counts.len() {
            counts[i] *= self.config.idf[i];
            sq_sum += counts[i] * counts[i];
        }

        let norm = sq_sum.sqrt();
        if norm > 0.0 {
            for val in &mut counts {
                *val /= norm;
            }
        }
        counts
    }

    pub fn transform_char(&self, text: &str) -> Vec<f64> {
        let lower = text.to_lowercase();
        let min_n = self.config.ngram_range.first().copied().unwrap_or(2);
        let max_n = self.config.ngram_range.last().copied().unwrap_or(5);

        let ngrams = extract_char_ngrams(&lower, min_n, max_n);

        let mut counts = vec![0.0; self.config.idf.len()];
        for ngram in ngrams {
            if let Some(&idx) = self.config.vocabulary.get(&ngram) {
                counts[idx] += 1.0;
            }
        }

        let mut sq_sum = 0.0;
        for i in 0..counts.len() {
            counts[i] *= self.config.idf[i];
            sq_sum += counts[i] * counts[i];
        }

        let norm = sq_sum.sqrt();
        if norm > 0.0 {
            for val in &mut counts {
                *val /= norm;
            }
        }
        counts
    }
}
