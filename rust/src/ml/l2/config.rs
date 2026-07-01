use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct L2ModelConfig {
    #[serde(default = "default_model_type")]
    pub model_type: String,
    pub ngram_range: Option<Vec<usize>>,
    pub vocabulary: Option<HashMap<String, usize>>,
    pub idf: Option<Vec<f64>>,
    pub classes: Option<Vec<usize>>,
    pub coef: Option<Vec<Vec<f64>>>,
    pub intercept: Option<Vec<f64>>,
    #[serde(default = "default_analyzer")]
    pub analyzer: String,
    pub class_names: Option<Vec<String>>,

    // Ensemble fields
    pub lr_word: Option<Box<L2ModelConfig>>,
    pub lr_char: Option<Box<L2ModelConfig>>,
    pub fasttext: Option<FastTextMulticlassConfig>,
}

fn default_model_type() -> String {
    "LogisticRegression".to_string()
}

fn default_analyzer() -> String {
    "word".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct FastTextMulticlassConfig {
    pub bucket_size: usize,
    pub embed_dim: usize,
    pub min_n: usize,
    pub max_n: usize,
    pub embeddings: Vec<Vec<f64>>,
    pub coef: Vec<Vec<f64>>,
    pub intercept: Vec<f64>,
    pub classes: Vec<usize>,
    pub class_names: Option<Vec<String>>,
}

pub const CLASSES: &[&str] = &[
    "tool_class.file.read",      // 0
    "tool_class.file.search",    // 1
    "tool_class.file.list",      // 2
    "tool_class.file.write",     // 3
    "tool_class.file.delete",    // 4
    "tool_class.shell.execute",  // 5
    "tool_class.web.search",     // 6
    "tool_class.web.fetch",      // 7
    "tool_class.browser.action", // 8
    "tool_class.api.read",       // 9
    "tool_class.api.write",      // 10
    "tool_class.database.read",  // 11
    "tool_class.database.write", // 12
    "tool_class.vcs.read",       // 13
    "tool_class.vcs.write",      // 14
    "tool_class.memory.read",    // 15
    "tool_class.memory.write",   // 16
    "tool_class.messaging.send", // 17
    "tool_class.unknown",        // 18
];
