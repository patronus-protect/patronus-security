use std::collections::HashMap;

use patronus_security::ml::l2::{
    fasttext_hash, L2Classifier, L2LogisticRegression, L2ModelConfig, LGBMBooster,
    LogisticRegressionConfig, LogisticRegressionPredictor, TFIDFVectorizer, TFIDFVectorizerConfig,
};

fn tiny_l2_config(class_names: Option<Vec<String>>) -> L2ModelConfig {
    L2ModelConfig {
        model_type: "LogisticRegression".to_string(),
        ngram_range: Some(vec![1, 1]),
        vocabulary: Some(HashMap::from([("attack".to_string(), 0)])),
        idf: Some(vec![1.0]),
        classes: Some(vec![0, 1]),
        coef: Some(vec![vec![-2.0], vec![2.0]]),
        intercept: Some(vec![0.0, 0.0]),
        analyzer: "word".to_string(),
        class_names,
        lr_word: None,
        lr_char: None,
        fasttext: None,
    }
}

#[test]
fn fasttext_hash_is_stable() {
    assert_eq!(fasttext_hash("attack"), fasttext_hash("attack"));
    assert_ne!(fasttext_hash("attack"), fasttext_hash("benign"));
}

#[test]
fn logistic_regression_predictor_applies_sigmoid() {
    let predictor = LogisticRegressionPredictor::new(LogisticRegressionConfig {
        coef: vec![2.0, -1.0],
        intercept: 0.0,
    });

    let probability = predictor.predict(&[2.0, 1.0]);

    assert!(probability > 0.95);
}

#[test]
fn l2_logistic_regression_uses_class_names_when_available() {
    let model = L2LogisticRegression::new(tiny_l2_config(Some(vec![
        "safe".to_string(),
        "attack".to_string(),
    ])));

    let (class_name, confidence) = model.predict("attack");

    assert_eq!(class_name, "attack");
    assert!(confidence > 0.9);
}

#[test]
fn l2_classifier_falls_back_to_tool_class_names() {
    let classifier = L2Classifier::new(tiny_l2_config(None));

    let (class_name, confidence) = classifier.predict("attack");

    assert_eq!(class_name, "tool_class.file.search");
    assert!(confidence > 0.9);
}

#[test]
fn tfidf_vectorizer_transforms_word_and_char_inputs() {
    let word = TFIDFVectorizer::new(TFIDFVectorizerConfig {
        ngram_range: vec![1, 1],
        vocabulary: HashMap::from([("secret".to_string(), 0)]),
        idf: vec![2.0],
    });
    assert_eq!(word.transform_word("secret"), vec![1.0]);

    let chars = TFIDFVectorizer::new(TFIDFVectorizerConfig {
        ngram_range: vec![3, 3],
        vocabulary: HashMap::from([("abc".to_string(), 0)]),
        idf: vec![3.0],
    });
    assert_eq!(chars.transform_char("abc"), vec![1.0]);
}

#[test]
fn lgbm_booster_parses_minimal_tree_and_predicts() {
    let booster = LGBMBooster::from_str(
        r#"
Tree=0
split_feature=0
threshold=0.5
left_child=-1
right_child=-2
leaf_value=-2 2

"#,
    )
    .unwrap();

    assert_eq!(booster.trees.len(), 1);
    assert!(booster.predict(&[0.2]) < 0.5);
    assert!(booster.predict(&[0.8]) > 0.5);
}
