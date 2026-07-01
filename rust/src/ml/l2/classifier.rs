use super::config::{L2ModelConfig, CLASSES};
use super::fasttext::FastTextPredictorMulticlass;
use super::logistic::L2LogisticRegression;

pub struct L2Classifier {
    pub model_type: String,
    pub lr: Option<L2LogisticRegression>,
    pub ensemble: Option<EnsembleClassifier>,
}

pub struct EnsembleClassifier {
    pub lr_word: Option<L2LogisticRegression>,
    pub lr_char: Option<L2LogisticRegression>,
    pub fasttext: Option<FastTextPredictorMulticlass>,
    pub classes: Vec<usize>,
    pub class_names: Option<Vec<String>>,
}

impl L2Classifier {
    pub fn new(config: L2ModelConfig) -> Self {
        let model_type = config.model_type.clone();
        if model_type == "Ensemble" {
            let lr_word = config
                .lr_word
                .as_ref()
                .map(|c| L2LogisticRegression::new(*c.clone()));
            let lr_char = config
                .lr_char
                .as_ref()
                .map(|c| L2LogisticRegression::new(*c.clone()));
            let fasttext = config
                .fasttext
                .as_ref()
                .map(|c| FastTextPredictorMulticlass::new(c.clone()));

            let classes = if let Some(ref lr) = lr_word {
                lr.config.classes.clone().unwrap()
            } else if let Some(ref lr) = lr_char {
                lr.config.classes.clone().unwrap()
            } else if let Some(ref ft) = fasttext {
                ft.config.classes.clone()
            } else {
                Vec::new()
            };

            let class_names = if let Some(ref lr) = lr_word {
                lr.config.class_names.clone()
            } else if let Some(ref lr) = lr_char {
                lr.config.class_names.clone()
            } else if let Some(ref ft) = fasttext {
                ft.config.class_names.clone()
            } else {
                None
            };

            L2Classifier {
                model_type,
                lr: None,
                ensemble: Some(EnsembleClassifier {
                    lr_word,
                    lr_char,
                    fasttext,
                    classes,
                    class_names,
                }),
            }
        } else {
            L2Classifier {
                model_type,
                lr: Some(L2LogisticRegression::new(config)),
                ensemble: None,
            }
        }
    }

    pub fn predict(&self, text: &str) -> (String, f64) {
        if self.model_type == "Ensemble" {
            if let Some(ref ens) = self.ensemble {
                let mut sum_probs = vec![0.0; ens.classes.len()];
                let mut num_models = 0;

                if let Some(ref lr_w) = ens.lr_word {
                    let probs = lr_w.predict_probs(text);
                    for i in 0..probs.len() {
                        sum_probs[i] += probs[i];
                    }
                    num_models += 1;
                }

                if let Some(ref lr_c) = ens.lr_char {
                    let probs = lr_c.predict_probs(text);
                    for i in 0..probs.len() {
                        sum_probs[i] += probs[i];
                    }
                    num_models += 1;
                }

                if let Some(ref ft) = ens.fasttext {
                    let probs = ft.predict_probs(text);
                    for i in 0..probs.len() {
                        sum_probs[i] += probs[i];
                    }
                    num_models += 1;
                }

                if num_models > 0 {
                    for i in 0..sum_probs.len() {
                        sum_probs[i] /= num_models as f64;
                    }
                }

                if sum_probs.is_empty() {
                    return ("unknown".to_string(), 0.0);
                }

                let mut best_idx = 0;
                let mut best_prob = -1.0;
                for i in 0..sum_probs.len() {
                    if sum_probs[i] > best_prob {
                        best_prob = sum_probs[i];
                        best_idx = i;
                    }
                }

                let class_name = if let Some(ref names) = ens.class_names {
                    if best_idx < names.len() {
                        names[best_idx].clone()
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    if best_idx < ens.classes.len() {
                        let class_id = ens.classes[best_idx];
                        if class_id < CLASSES.len() {
                            CLASSES[class_id].to_string()
                        } else {
                            class_id.to_string()
                        }
                    } else {
                        "unknown".to_string()
                    }
                };

                (class_name, best_prob)
            } else {
                ("unknown".to_string(), 0.0)
            }
        } else {
            if let Some(ref lr) = self.lr {
                lr.predict(text)
            } else {
                ("unknown".to_string(), 0.0)
            }
        }
    }
}
