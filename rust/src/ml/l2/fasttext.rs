use serde::Deserialize;

use super::config::FastTextMulticlassConfig;

#[derive(Clone)]
pub struct FastTextPredictorMulticlass {
    pub config: FastTextMulticlassConfig,
}

impl FastTextPredictorMulticlass {
    pub fn new(config: FastTextMulticlassConfig) -> Self {
        FastTextPredictorMulticlass { config }
    }

    pub fn predict_probs(&self, text: &str) -> Vec<f64> {
        let lower = text.to_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();
        let mut hashes = Vec::new();

        for w in words {
            let h_w = (fasttext_hash(w) as usize) % self.config.bucket_size;
            hashes.push(h_w);

            let w_bound = format!("<{}>", w);
            let chars: Vec<char> = w_bound.chars().collect();
            let wl = chars.len();
            for n in self.config.min_n..=self.config.max_n {
                if wl >= n {
                    for i in 0..=(wl - n) {
                        let ngram: String = chars[i..i + n].iter().collect();
                        let h_ng = (fasttext_hash(&ngram) as usize) % self.config.bucket_size;
                        hashes.push(h_ng);
                    }
                }
            }
        }

        if hashes.is_empty() {
            hashes.push(0);
        }

        let mut mean_embedding = vec![0.0; self.config.embed_dim];
        let num_hashes = hashes.len() as f64;

        for &h in &hashes {
            if h < self.config.embeddings.len() {
                let embed_vector = &self.config.embeddings[h];
                for d in 0..self.config.embed_dim {
                    mean_embedding[d] += embed_vector[d];
                }
            }
        }

        for d in 0..self.config.embed_dim {
            mean_embedding[d] /= num_hashes;
        }

        let num_classes = self.config.classes.len();
        let mut logits = vec![0.0; num_classes];
        for c in 0..num_classes {
            let mut z = self.config.intercept[c];
            for d in 0..self.config.embed_dim {
                z += mean_embedding[d] * self.config.coef[c][d];
            }
            logits[c] = z;
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
}

#[derive(Debug, Deserialize, Clone)]
pub struct FastTextConfig {
    pub bucket_size: usize,
    pub embed_dim: usize,
    pub min_n: usize,
    pub max_n: usize,
    pub embeddings: Vec<Vec<f64>>,
    pub coef: Vec<f64>,
    pub intercept: f64,
}

#[derive(Clone)]
pub struct FastTextPredictor {
    pub config: FastTextConfig,
}

impl FastTextPredictor {
    pub fn new(config: FastTextConfig) -> Self {
        FastTextPredictor { config }
    }

    pub fn predict(&self, text: &str) -> f64 {
        let lower = text.to_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();
        let mut hashes = Vec::new();

        for w in words {
            // 1. Word hash
            let h_w = (fasttext_hash(w) as usize) % self.config.bucket_size;
            hashes.push(h_w);

            // 2. Char n-grams with word boundaries
            let w_bound = format!("<{}>", w);
            let chars: Vec<char> = w_bound.chars().collect();
            let wl = chars.len();
            for n in self.config.min_n..=self.config.max_n {
                if wl >= n {
                    for i in 0..=(wl - n) {
                        let ngram: String = chars[i..i + n].iter().collect();
                        let h_ng = (fasttext_hash(&ngram) as usize) % self.config.bucket_size;
                        hashes.push(h_ng);
                    }
                }
            }
        }

        if hashes.is_empty() {
            hashes.push(0);
        }

        // Mode: Mean embedding
        let mut mean_embedding = vec![0.0; self.config.embed_dim];
        let num_hashes = hashes.len() as f64;

        for &h in &hashes {
            if h < self.config.embeddings.len() {
                let embed_vector = &self.config.embeddings[h];
                for d in 0..self.config.embed_dim {
                    mean_embedding[d] += embed_vector[d];
                }
            }
        }

        for d in 0..self.config.embed_dim {
            mean_embedding[d] /= num_hashes;
        }

        // Linear layer prediction
        let mut z = self.config.intercept;
        for d in 0..self.config.embed_dim {
            z += mean_embedding[d] * self.config.coef[d];
        }

        // Sigmoid
        1.0 / (1.0 + (-z).exp())
    }
}

pub fn fasttext_hash(s: &str) -> u32 {
    let mut h: u32 = 0;
    for byte in s.as_bytes() {
        h = h.wrapping_mul(33).wrapping_add(*byte as u32);
    }
    h
}
