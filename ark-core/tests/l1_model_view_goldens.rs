// SPDX-License-Identifier: MIT OR Apache-2.0
//! The built-in L1 models answer on the text, not on its obfuscation: on the
//! model-view goldens (`generate_l1_goldens.py`, suite `l1_model_views_l1`)
//! each model detects its positives and clears its hard negatives clean and
//! under zero-width characters, Unicode tags, base64, leetspeak and homoglyphs.
use std::path::Path;

use patronus_ark_core::cascade::StageOutcome;
use patronus_ark_core::detectors::text::l1_model::BUILTIN_L1_MODELS;
use patronus_ark_core::detectors::text::{L1ModelConfig, L1TextModel};
use patronus_ark_core::detectors::text_views::TextViews;
use serde_json::Value;

fn goldens() -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/l1_model_views_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("model view goldens")
        .lines()
        .map(|line| serde_json::from_str(line).expect("golden row"))
        .collect()
}

fn str_of<'a>(row: &'a Value, key: &str) -> &'a str {
    row[key].as_str().expect(key)
}

#[test]
fn every_model_answers_alike_on_clean_and_obfuscated_text() {
    let models: Vec<(&str, L1TextModel)> = BUILTIN_L1_MODELS
        .iter()
        .map(|&(name, category)| {
            let model = L1TextModel::load(category, &L1ModelConfig::builtin(name)).unwrap();
            (name, model)
        })
        .collect();
    let mut failures = Vec::new();
    for row in goldens() {
        let (_, model) = models
            .iter()
            .find(|(name, _)| *name == str_of(&row, "model"))
            .expect("built-in model");
        let answer = model.evaluate(str_of(&row, "text"), &[], &[]);
        let detected = answer.outcome == StageOutcome::Detected;
        if detected
            != row["expected_detected"]
                .as_bool()
                .expect("expected_detected")
        {
            failures.push(format!("{}: score {}", row["id"], answer.score));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every case is six consecutive rows: clean first, then each obfuscation.
#[test]
fn obfuscated_text_reads_as_the_clean_text() {
    let rows = goldens();
    for case in rows.chunks(6) {
        assert_eq!(
            str_of(&case[0], "obfuscation"),
            "clean",
            "{}",
            case[0]["id"]
        );
        let clean = str_of(&case[0], "text");
        assert_eq!(TextViews::new(clean).model_text(clean), clean);
        for row in &case[1..] {
            let text = str_of(row, "text");
            let read = TextViews::new(text).model_text(text).into_owned();
            match str_of(row, "obfuscation") {
                "zero_width" => assert_eq!(read, clean, "{}", row["id"]),
                "unicode_tags" | "base64" => assert_eq!(read.trim(), clean, "{}", row["id"]),
                _ => assert_ne!(read, text, "{}: nothing undone", row["id"]),
            }
        }
    }
}

#[test]
fn goldens_cover_every_model_in_both_languages() {
    let rows = goldens();
    for (name, _) in BUILTIN_L1_MODELS {
        for language in ["de", "en"] {
            for case_type in ["positive", "hard_negative"] {
                let obfuscations: Vec<&str> = rows
                    .iter()
                    .filter(|row| {
                        str_of(row, "model") == *name
                            && str_of(row, "language") == language
                            && str_of(row, "case_type") == case_type
                    })
                    .map(|row| str_of(row, "obfuscation"))
                    .collect();
                for obfuscation in [
                    "clean",
                    "zero_width",
                    "unicode_tags",
                    "base64",
                    "leetspeak",
                    "homoglyph",
                ] {
                    assert!(
                        obfuscations.contains(&obfuscation),
                        "{name} {language} {case_type}: no {obfuscation} row"
                    );
                }
            }
        }
    }
}
