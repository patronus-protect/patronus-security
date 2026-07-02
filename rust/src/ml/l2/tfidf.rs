use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

use super::features::{for_each_char_ngram, for_each_ngram};

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
        let mut counts = vec![0.0; self.config.idf.len()];
        self.transform_word_into(text, &mut counts);
        counts
    }

    pub fn transform_word_into(&self, text: &str, counts: &mut [f64]) {
        counts.fill(0.0);
        let lower = text.to_lowercase();
        let tokens: Vec<&str> = self
            .token_regex
            .find_iter(&lower)
            .map(|m| m.as_str())
            .collect();

        let min_n = self.config.ngram_range.first().copied().unwrap_or(1);
        let max_n = self.config.ngram_range.last().copied().unwrap_or(3);

        for_each_ngram(&tokens, min_n, max_n, |ngram| {
            if let Some(&idx) = self.config.vocabulary.get(ngram) {
                if idx < counts.len() {
                    counts[idx] += 1.0;
                }
            }
        });

        let mut sq_sum = 0.0;
        for i in 0..counts.len().min(self.config.idf.len()) {
            counts[i] *= self.config.idf[i];
            sq_sum += counts[i] * counts[i];
        }

        let norm = sq_sum.sqrt();
        if norm > 0.0 {
            for val in counts.iter_mut() {
                *val /= norm;
            }
        }
    }

    pub fn transform_char(&self, text: &str) -> Vec<f64> {
        let mut counts = vec![0.0; self.config.idf.len()];
        self.transform_char_into(text, &mut counts);
        counts
    }

    pub fn transform_char_into(&self, text: &str, counts: &mut [f64]) {
        counts.fill(0.0);
        let lower = text.to_lowercase();
        let min_n = self.config.ngram_range.first().copied().unwrap_or(2);
        let max_n = self.config.ngram_range.last().copied().unwrap_or(5);

        for_each_char_ngram(&lower, min_n, max_n, |ngram| {
            if let Some(&idx) = self.config.vocabulary.get(ngram) {
                if idx < counts.len() {
                    counts[idx] += 1.0;
                }
            }
        });

        let mut sq_sum = 0.0;
        for i in 0..counts.len().min(self.config.idf.len()) {
            counts[i] *= self.config.idf[i];
            sq_sum += counts[i] * counts[i];
        }

        let norm = sq_sum.sqrt();
        if norm > 0.0 {
            for val in counts.iter_mut() {
                *val /= norm;
            }
        }
    }
}
