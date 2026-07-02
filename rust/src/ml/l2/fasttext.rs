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
        let mut mean_embedding = vec![0.0; self.config.embed_dim];
        let mut num_hashes = 0usize;

        for w in lower.split_whitespace() {
            let h_w = (fasttext_hash(w) as usize) % self.config.bucket_size;
            add_embedding(
                &self.config.embeddings,
                self.config.embed_dim,
                &mut mean_embedding,
                h_w,
            );
            num_hashes += 1;

            let mut chars = Vec::with_capacity(w.chars().count() + 2);
            chars.push('<');
            chars.extend(w.chars());
            chars.push('>');
            let wl = chars.len();
            for n in self.config.min_n..=self.config.max_n {
                if wl >= n {
                    for i in 0..=(wl - n) {
                        let h_ng = (fasttext_hash_chars(&chars[i..i + n]) as usize)
                            % self.config.bucket_size;
                        add_embedding(
                            &self.config.embeddings,
                            self.config.embed_dim,
                            &mut mean_embedding,
                            h_ng,
                        );
                        num_hashes += 1;
                    }
                }
            }
        }

        if num_hashes == 0 {
            add_embedding(
                &self.config.embeddings,
                self.config.embed_dim,
                &mut mean_embedding,
                0,
            );
            num_hashes = 1;
        }

        let num_hashes = num_hashes as f64;
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
        let mut mean_embedding = vec![0.0; self.config.embed_dim];
        let mut num_hashes = 0usize;

        for w in lower.split_whitespace() {
            let h_w = (fasttext_hash(w) as usize) % self.config.bucket_size;
            add_embedding(
                &self.config.embeddings,
                self.config.embed_dim,
                &mut mean_embedding,
                h_w,
            );
            num_hashes += 1;

            let mut chars = Vec::with_capacity(w.chars().count() + 2);
            chars.push('<');
            chars.extend(w.chars());
            chars.push('>');
            let wl = chars.len();
            for n in self.config.min_n..=self.config.max_n {
                if wl >= n {
                    for i in 0..=(wl - n) {
                        let h_ng = (fasttext_hash_chars(&chars[i..i + n]) as usize)
                            % self.config.bucket_size;
                        add_embedding(
                            &self.config.embeddings,
                            self.config.embed_dim,
                            &mut mean_embedding,
                            h_ng,
                        );
                        num_hashes += 1;
                    }
                }
            }
        }

        if num_hashes == 0 {
            add_embedding(
                &self.config.embeddings,
                self.config.embed_dim,
                &mut mean_embedding,
                0,
            );
            num_hashes = 1;
        }

        let num_hashes = num_hashes as f64;
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

fn fasttext_hash_chars(chars: &[char]) -> u32 {
    let mut h: u32 = 0;
    let mut buf = [0; 4];
    for c in chars {
        for byte in c.encode_utf8(&mut buf).as_bytes() {
            h = h.wrapping_mul(33).wrapping_add(*byte as u32);
        }
    }
    h
}

fn add_embedding(
    embeddings: &[Vec<f64>],
    embed_dim: usize,
    mean_embedding: &mut [f64],
    hash: usize,
) {
    if hash < embeddings.len() {
        let embed_vector = &embeddings[hash];
        for d in 0..embed_dim {
            mean_embedding[d] += embed_vector[d];
        }
    }
}
