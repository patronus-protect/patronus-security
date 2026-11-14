// SPDX-License-Identifier: MIT OR Apache-2.0
//! Add the `patronus.text_facts/1` document of every row to a JSONL file:
//! reads rows with a `text` field on stdin and writes each row with a `facts`
//! field to stdout. The text category model training
//! (`scripts/l1_threat/category_model.py train`) reads these rows, so the
//! `tf1` tokens it trains on are the ones the Rust inference sees.
//!
//! Run: `cargo run -q -p patronus-ark-core --example text_facts < rows.jsonl > rows.facts.jsonl`

use std::io::{self, BufRead, BufWriter, Write};

use patronus_ark_core::detectors::text::extract;
use serde_json::Value;

fn main() -> io::Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    for (number, line) in io::stdin().lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut row: Value = serde_json::from_str(&line)
            .map_err(|error| io::Error::other(format!("line {}: {error}", number + 1)))?;
        let text = row["text"]
            .as_str()
            .ok_or_else(|| io::Error::other(format!("line {}: no text", number + 1)))?;
        let facts = extract(text, &[], &[]).to_json();
        row["facts"] = facts;
        serde_json::to_writer(&mut out, &row)?;
        out.write_all(b"\n")?;
    }
    out.flush()
}
