use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

use super::config::{L2ModelConfig, CLASSES};
use super::features::{extract_char_ngrams, extract_ngrams};

#[derive(Clone)]
pub struct L2LogisticRegression {
    pub config: L2ModelConfig,
    pub token_regex: Regex,
}

impl L2LogisticRegression {
    pub fn new(config: L2ModelConfig) -> Self {
        let token_regex = Regex::new(r"\b\w{2,}\b").unwrap();
        L2LogisticRegression {
            config,
            token_regex,
        }
    }

    pub fn predict_probs(&self, text: &str) -> Vec<f64> {
        let lower = text.to_lowercase();

        let ngrams = if self.config.analyzer == "char" {
            let min_n = self
                .config
                .ngram_range
                .as_ref()
                .and_then(|r| r.first().copied())
                .unwrap_or(2);
            let max_n = self
                .config
                .ngram_range
                .as_ref()
                .and_then(|r| r.last().copied())
                .unwrap_or(5);
            extract_char_ngrams(&lower, min_n, max_n)
        } else {
            // word
            let tokens: Vec<&str> = self
                .token_regex
                .find_iter(&lower)
                .map(|m| m.as_str())
                .collect();
            let min_n = self
                .config
                .ngram_range
                .as_ref()
                .and_then(|r| r.first().copied())
                .unwrap_or(1);
            let max_n = self
                .config
                .ngram_range
                .as_ref()
                .and_then(|r| r.last().copied())
                .unwrap_or(3);
            extract_ngrams(&tokens, min_n, max_n)
        };

        // Sparse TF-IDF Weighting
        let mut counts = HashMap::new();
        if let Some(ref vocab) = self.config.vocabulary {
            for ngram in ngrams {
                if let Some(&idx) = vocab.get(&ngram) {
                    *counts.entry(idx).or_insert(0.0) += 1.0;
                }
            }
        }

        let idf = self.config.idf.as_ref().unwrap();
        let mut sparse_vector = Vec::with_capacity(counts.len());
        let mut sq_sum = 0.0;
        for (idx, count) in counts {
            let val = count * idf[idx];
            sq_sum += val * val;
            sparse_vector.push((idx, val));
        }

        let norm = sq_sum.sqrt();
        if norm > 0.0 {
            for (_, val) in &mut sparse_vector {
                *val /= norm;
            }
        }

        let coef = self.config.coef.as_ref().unwrap();
        let intercept = self.config.intercept.as_ref().unwrap();
        let classes = self.config.classes.as_ref().unwrap();
        let num_classes = classes.len();
        let mut logits = vec![0.0; num_classes];
        for c in 0..num_classes {
            let mut sum = 0.0;
            for &(idx, val) in &sparse_vector {
                sum += val * coef[c][idx];
            }
            logits[c] = sum + intercept[c];
        }

        let max_logit = logits.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        let mut exps = vec![0.0; num_classes];
        let mut sum_exp = 0.0;
        for i in 0..num_classes {
            exps[i] = (logits[i] - max_logit).exp();
            sum_exp += exps[i];
        }

        let mut probs = vec![0.0; num_classes];
        for i in 0..num_classes {
            probs[i] = exps[i] / sum_exp;
        }
        probs
    }

    pub fn predict(&self, text: &str) -> (String, f64) {
        let probs = self.predict_probs(text);
        if probs.is_empty() {
            return ("unknown".to_string(), 0.0);
        }

        let mut best_idx = 0;
        let mut best_prob = -1.0;
        for i in 0..probs.len() {
            if probs[i] > best_prob {
                best_prob = probs[i];
                best_idx = i;
            }
        }

        let class_name = if let Some(ref names) = self.config.class_names {
            if best_idx < names.len() {
                names[best_idx].clone()
            } else {
                "unknown".to_string()
            }
        } else {
            if let Some(ref classes_list) = self.config.classes {
                if best_idx < classes_list.len() {
                    let class_id = classes_list[best_idx];
                    if class_id < CLASSES.len() {
                        CLASSES[class_id].to_string()
                    } else {
                        class_id.to_string()
                    }
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            }
        };

        (class_name, best_prob)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogisticRegressionConfig {
    pub coef: Vec<f64>,
    pub intercept: f64,
}

#[derive(Clone)]
pub struct LogisticRegressionPredictor {
    pub config: LogisticRegressionConfig,
}

impl LogisticRegressionPredictor {
    pub fn new(config: LogisticRegressionConfig) -> Self {
        LogisticRegressionPredictor { config }
    }

    pub fn predict(&self, features: &[f64]) -> f64 {
        let mut dot = 0.0;
        for i in 0..features.len().min(self.config.coef.len()) {
            dot += features[i] * self.config.coef[i];
        }
        let z = dot + self.config.intercept;
        1.0 / (1.0 + (-z).exp())
    }
}
