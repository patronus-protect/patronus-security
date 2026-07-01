use super::fasttext::{FastTextConfig, FastTextPredictor};
use super::features::extract_handcrafted_features;
use super::lgbm::LGBMBooster;
use super::logistic::{LogisticRegressionConfig, LogisticRegressionPredictor};
use super::tfidf::{TFIDFVectorizer, TFIDFVectorizerConfig};

#[derive(Clone)]
pub struct PromptInjectionClassifier {
    model_a: LGBMBooster,
    model_b: LGBMBooster,
    model_c: LGBMBooster,
    tfidf_word_a: TFIDFVectorizer,
    tfidf_char_a: TFIDFVectorizer,
    tfidf_word_b: TFIDFVectorizer,
    tfidf_char_b: TFIDFVectorizer,
    tfidf_word_c: TFIDFVectorizer,
    tfidf_char_c: TFIDFVectorizer,
    logistic_regression: LogisticRegressionPredictor,
    fasttext: FastTextPredictor,
}

impl PromptInjectionClassifier {
    pub fn new<P: AsRef<std::path::Path>>(dir: P) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();

        let model_a = LGBMBooster::from_file(dir.join("model_A.txt"))?;
        let model_b = LGBMBooster::from_file(dir.join("model_B.txt"))?;
        let model_c = LGBMBooster::from_file(dir.join("model_C.txt"))?;

        let load_tfidf =
            |prefix: &str, suffix: &str| -> Result<TFIDFVectorizer, Box<dyn std::error::Error>> {
                let f = std::fs::File::open(dir.join(format!("tfidf_{}_{}.json", prefix, suffix)))?;
                let reader = std::io::BufReader::new(f);
                let config: TFIDFVectorizerConfig = serde_json::from_reader(reader)?;
                Ok(TFIDFVectorizer::new(config))
            };

        let tfidf_word_a = load_tfidf("word", "A")?;
        let tfidf_char_a = load_tfidf("char", "A")?;

        let tfidf_word_b = load_tfidf("word", "B")?;
        let tfidf_char_b = load_tfidf("char", "B")?;

        let tfidf_word_c = load_tfidf("word", "C")?;
        let tfidf_char_c = load_tfidf("char", "C")?;

        let lr_file = std::fs::File::open(dir.join("logistic_regression_C.json"))?;
        let lr_reader = std::io::BufReader::new(lr_file);
        let lr_config: LogisticRegressionConfig = serde_json::from_reader(lr_reader)?;
        let logistic_regression = LogisticRegressionPredictor::new(lr_config);

        let ft_file = std::fs::File::open(dir.join("fasttext_C.json"))?;
        let ft_reader = std::io::BufReader::new(ft_file);
        let ft_config: FastTextConfig = serde_json::from_reader(ft_reader)?;
        let fasttext = FastTextPredictor::new(ft_config);

        Ok(PromptInjectionClassifier {
            model_a,
            model_b,
            model_c,
            tfidf_word_a,
            tfidf_char_a,
            tfidf_word_b,
            tfidf_char_b,
            tfidf_word_c,
            tfidf_char_c,
            logistic_regression,
            fasttext,
        })
    }

    pub fn predict_a(&self, text: &str) -> f64 {
        let mut features = vec![0.0; 10013];
        let w_feats = self.tfidf_word_a.transform_word(text);
        features[..5000].copy_from_slice(&w_feats);
        let c_feats = self.tfidf_char_a.transform_char(text);
        features[5000..10000].copy_from_slice(&c_feats);
        let h_feats = extract_handcrafted_features(text);
        features[10000..10013].copy_from_slice(&h_feats);
        self.model_a.predict(&features)
    }

    pub fn predict_b(&self, text: &str) -> f64 {
        let mut features = vec![0.0; 10013];
        let w_feats = self.tfidf_word_b.transform_word(text);
        features[..5000].copy_from_slice(&w_feats);
        let c_feats = self.tfidf_char_b.transform_char(text);
        features[5000..10000].copy_from_slice(&c_feats);
        let h_feats = extract_handcrafted_features(text);
        features[10000..10013].copy_from_slice(&h_feats);
        self.model_b.predict(&features)
    }

    pub fn predict_c(&self, text: &str) -> f64 {
        let features = self.extract_features_c(text);
        self.predict_c_from_features(&features)
    }

    pub fn extract_features_c(&self, text: &str) -> Vec<f64> {
        let mut features = vec![0.0; 10013];
        let w_feats = self.tfidf_word_c.transform_word(text);
        features[..5000].copy_from_slice(&w_feats);
        let c_feats = self.tfidf_char_c.transform_char(text);
        features[5000..10000].copy_from_slice(&c_feats);
        let h_feats = extract_handcrafted_features(text);
        features[10000..10013].copy_from_slice(&h_feats);
        features
    }

    pub fn predict_c_from_features(&self, features: &[f64]) -> f64 {
        self.model_c.predict(features)
    }

    pub fn predict_lr_from_features(&self, features: &[f64]) -> f64 {
        self.logistic_regression.predict(features)
    }

    pub fn predict_ft(&self, text: &str) -> f64 {
        self.fasttext.predict(text)
    }
}
