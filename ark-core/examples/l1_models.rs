// SPDX-License-Identifier: MIT OR Apache-2.0
//! Score rows with every built-in L1 model at its own detect cut
//! (`scripts/l1_threat/model_obfuscation.py`): reads rows with `id` and
//! `text` on stdin and writes per row `{"id", "flagged": [<model>...],
//! "scores": {<model>: <logit>}}` to stdout: the models whose answer on the
//! text is Detected, and every model's decision score. No rule findings
//! are passed in, so the models answer on the text alone.
//!
//! Run: `cargo run --release -q -p patronus-ark-core --example l1_models < rows.jsonl > flags.jsonl`

use std::io::{self, BufRead, BufWriter, Write};

use patronus_ark_core::{
    cascade::StageOutcome,
    detectors::text::{l1_model::BUILTIN_L1_MODELS, L1ModelConfig, L1TextModel},
};
use serde_json::{json, Map, Value};

fn main() -> io::Result<()> {
    let models: Vec<(&str, L1TextModel)> = BUILTIN_L1_MODELS
        .iter()
        .map(|&(name, category)| {
            L1TextModel::load(category, &L1ModelConfig::builtin(name))
                .map(|model| (name, model))
                .map_err(io::Error::other)
        })
        .collect::<io::Result<_>>()?;
    let mut out = BufWriter::new(io::stdout().lock());
    for (number, line) in io::stdin().lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line)
            .map_err(|error| io::Error::other(format!("line {}: {error}", number + 1)))?;
        let text = row["text"]
            .as_str()
            .ok_or_else(|| io::Error::other(format!("line {}: no text", number + 1)))?;
        let answers: Vec<_> = models
            .iter()
            .map(|(name, model)| {
                (
                    *name,
                    model.evaluate(&patronus_ark_core::threat::NativeText::new(text), &[], &[]),
                )
            })
            .collect();
        let flagged: Vec<&str> = answers
            .iter()
            .filter(|(_, answer)| answer.outcome == StageOutcome::Detected)
            .map(|(name, _)| *name)
            .collect();
        let scores: Map<String, Value> = answers
            .iter()
            .filter(|(_, answer)| answer.score.is_finite() && answer.score > f64::MIN)
            .map(|(name, answer)| (name.to_string(), json!(answer.score)))
            .collect();
        serde_json::to_writer(
            &mut out,
            &json!({"id": row["id"], "flagged": flagged, "scores": scores}),
        )?;
        out.write_all(b"\n")?;
    }
    out.flush()
}
