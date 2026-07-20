// SPDX-License-Identifier: AGPL-3.0-only
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct BenchmarkRow {
    text: String,
}

pub(crate) fn texts() -> Vec<String> {
    let mut texts: Vec<String> = serde_json::from_str(include_str!(
        "../../tests/fixtures/tokenizer_adversarial.json"
    ))
    .expect("tokenizer adversarial fixture must be valid JSON");

    let dataset_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../python/patronus_ark/benchmark_data");
    let mut paths = fs::read_dir(&dataset_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dataset_dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        texts.extend(
            contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    serde_json::from_str::<BenchmarkRow>(line)
                        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
                        .text
                }),
        );
    }
    texts
}

pub(crate) fn first_difference(left: &[u32], right: &[u32]) -> Option<usize> {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
}
