//! Unit tests for the L1 heuristics engine and the NTDB executor internals,
//! reached through the `test-util` feature surface.

mod l1_heuristics {
    use patronus_ark::ml::l1_heuristics::{clean_text_for_rules, HeuristicsEngine, RawRule};

    #[test]
    fn clean_text_for_rules_flattens_json_before_ngram_matching() {
        let cleaned = clean_text_for_rules(
            r#"{"arguments":{"cmd":"rg token rust/src"},"name":"exec_command"}"#,
        );

        assert!(cleaned.contains("arguments command rg token rust/src"));
        assert!(cleaned.contains("tool_name exec_command"));
    }

    #[test]
    fn heuristics_engine_matches_rules_against_flattened_json() {
        let engine = HeuristicsEngine::new(vec![RawRule {
            ngram: "arguments command".to_string(),
            class: "tool_class.shell.execute".to_string(),
        }]);

        assert_eq!(
            engine.evaluate(r#"{"arguments":{"cmd":"rg token rust/src"},"name":"exec_command"}"#),
            Some(("tool_class.shell.execute".to_string(), 1.0))
        );
    }
}

mod ntdb_decision {
    use patronus_ark::ml::ntdb_executor::{NtdbDecision, ScoreOutput};

    fn binary_output() -> ScoreOutput {
        ScoreOutput {
            aggregator_id: "router".to_string(),
            task: "binary_promote".to_string(),
            labels: vec![
                "benign".to_string(),
                "attack".to_string(),
                "promote".to_string(),
            ],
            predicted_label: "promote".to_string(),
            predicted_index: 2,
            class_scores: vec![0.1, 0.9, 0.8],
            class_logits: vec![0.0, 2.0, 1.0],
            chunks: 2,
            attack_threshold: Some(0.5),
            promote_score: Some(0.8),
            promote_threshold: Some(0.7),
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        }
    }

    #[test]
    fn binary_promote_routes_l3_without_exposing_promote_label() {
        let decision =
            NtdbDecision::from_score_output("injection".to_string(), binary_output()).unwrap();

        assert_eq!(decision.fallback_label, "attack");
        assert!(decision.route_to_l3);
        assert_eq!(decision.promote_score, Some(0.800000011920929));
    }

    #[test]
    fn binary_task_with_promote_label_uses_attack_threshold() {
        let mut output = binary_output();
        output.task = "binary".to_string();
        output.predicted_label = "promote".to_string();
        output.predicted_index = 2;

        let decision = NtdbDecision::from_score_output("injection".to_string(), output).unwrap();

        assert_eq!(decision.task, "binary");
        assert_eq!(decision.fallback_label, "attack");
        assert_ne!(decision.fallback_label, "promote");
        assert!(decision.route_to_l3);
    }

    #[test]
    fn multiclass_promote_uses_real_class_as_fallback() {
        let output = ScoreOutput {
            aggregator_id: "aggregator".to_string(),
            task: "multiclass".to_string(),
            labels: vec![
                "finance".to_string(),
                "legal".to_string(),
                "promote".to_string(),
            ],
            predicted_label: "promote".to_string(),
            predicted_index: 2,
            class_scores: vec![0.7, 0.2, 0.9],
            class_logits: vec![1.0, 0.0, 2.0],
            chunks: 1,
            attack_threshold: None,
            promote_score: Some(0.9),
            promote_threshold: Some(0.8),
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };

        let decision = NtdbDecision::from_score_output("sensitive".to_string(), output).unwrap();

        assert_eq!(decision.fallback_label, "finance");
        assert!(decision.route_to_l3);
    }
}

mod ntdb_heuristics {
    use patronus_ark::ml::ntdb_executor::test_util::{
        global_text_heuristics, local_text_heuristics,
    };

    #[test]
    fn heuristic_shapes_match_router_contract() {
        assert_eq!(local_text_heuristics("ABC{}", &[100, 200, 300]).len(), 11);
        assert_eq!(
            global_text_heuristics("ABC{}", &[100, 200, 300], 1, 0.1, 0.2, 0.3, 0.4, 0.8).len(),
            18
        );
    }
}

mod ntdb_encoder {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use patronus_ark::ml::ntdb_executor::manifest::MiniLmManifest;
    use patronus_ark::ml::ntdb_executor::test_util::StaticEncoderStore;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "patronus_ntdb_encoder_{name}_{}_{}",
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn shared_encoder_reuses_source_model_identity() {
        let dir = temp_dir("reuse");
        let first = dir.join("a.f32");
        let second = dir.join("b.f32");
        fs::write(&first, 1.0_f32.to_le_bytes()).unwrap();
        fs::write(&second, 2.0_f32.to_le_bytes()).unwrap();
        let manifest = MiniLmManifest {
            embedding_matrix_file: "embedding_matrix.f32".to_string(),
            vocab_size: 1,
            embedding_dim: 1,
            content_tokens_per_chunk: 1,
            source_model_path: Some("same-minilm".to_string()),
            model: None,
            tokenizer_family: None,
            compab_l3_tokenizer: None,
        };

        let mut store = StaticEncoderStore::default();
        let a = store.load(&first, &manifest).unwrap();
        let b = store.load(&second, &manifest).unwrap();

        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert_eq!(store.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shared_encoder_reuses_model_identity_when_source_path_is_missing() {
        let dir = temp_dir("reuse_model");
        let first = dir.join("a.f32");
        let second = dir.join("b.f32");
        fs::write(&first, 1.0_f32.to_le_bytes()).unwrap();
        fs::write(&second, 2.0_f32.to_le_bytes()).unwrap();
        let manifest = MiniLmManifest {
            embedding_matrix_file: "embedding_matrix.f32".to_string(),
            vocab_size: 1,
            embedding_dim: 1,
            content_tokens_per_chunk: 1,
            source_model_path: None,
            model: Some("ibm-granite/granite-embedding-97m-multilingual-r2".to_string()),
            tokenizer_family: None,
            compab_l3_tokenizer: None,
        };

        let mut store = StaticEncoderStore::default();
        let a = store.load(&first, &manifest).unwrap();
        let b = store.load(&second, &manifest).unwrap();

        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert_eq!(store.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}

mod ntdb_lightgbm {
    use patronus_ark::ml::ntdb_executor::test_util::Tree;

    #[test]
    fn stump_tree_predicts_single_leaf_value() {
        let tree = Tree::parse(
            r#"Tree=0
num_leaves=1
num_cat=0
split_feature=
threshold=
left_child=
right_child=
leaf_value=0.42
is_linear=0
"#,
        )
        .unwrap();

        assert_eq!(tree.predict_raw(&[1.0, 2.0]), 0.42);
    }
}

mod ntdb_package {
    use patronus_ark::ml::ntdb_executor::test_util::unit_left_dot;
    use patronus_ark::ml::ntdb_executor::{NtdbMultiPackage, NtdbPackageSpec};

    #[test]
    fn centroid_feature_matches_python_contract() {
        let chunk = [3.0_f32, 4.0];
        let raw_centroid = [0.2_f32, 0.1];

        assert!((unit_left_dot(&chunk, &raw_centroid) - 0.2).abs() < 1e-6);
    }

    #[test]
    fn multi_loader_rejects_empty_specs() {
        assert!(NtdbMultiPackage::load_specs(Vec::<NtdbPackageSpec>::new()).is_err());
    }

    #[test]
    fn multi_loader_rejects_duplicate_model_ids() {
        let result = NtdbMultiPackage::load_specs([
            NtdbPackageSpec::new("same", "/missing/a"),
            NtdbPackageSpec::new("same", "/missing/b"),
        ]);

        assert!(result.is_err());
    }
}
