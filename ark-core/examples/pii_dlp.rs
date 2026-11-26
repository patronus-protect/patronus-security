// SPDX-License-Identifier: MIT OR Apache-2.0
//! PII and DLP with the native L1 rules: no model files, no downloads.
//!
//! - `scan` returns one result per category with its evidence spans
//!   (UTF-8 byte and character offsets into the original text), so you can
//!   redact, block or log.
//! - `rules` switches single rules off by their stable id (see
//!   `docs/reference/l1-rule-catalog.md`).
//!
//! Run: `cargo run -p patronus-ark-core --example pii_dlp`

use patronus_ark_core::{Scanner, ScannerConfig};

const TEXT: &str = "Hi, I'm Jane Doe. Reach me at jane.doe@example.com or +49 30 901820.\n\
    Refund to IBAN DE89 3704 0044 0532 0130 00.\n\
    DATABASE_URL=postgres://app:Xk9#mP2vQ7rL@db.internal:5432/prod";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The same JSON object as the Python config: every key is optional.
    let config: ScannerConfig = serde_json::from_value(serde_json::json!({
        "categories": ["pii", "dlp"],
    }))?;
    let mut scanner = Scanner::new(config)?;

    let report = scanner.scan(TEXT)?;
    for result in &report.native {
        println!(
            "{:<4} class={:<18} confidence={:.2}",
            result.category, result.class_name, result.confidence
        );
        for span in &result.evidence_spans {
            println!(
                "     {:<22} chars {:>3}..{:<3} {:?}",
                span.label, span.start_char, span.end_char, span.text
            );
        }
    }

    // Redact every PII span, back to front so earlier offsets stay valid.
    let mut spans: Vec<_> = report
        .native
        .iter()
        .filter(|r| r.category == "pii")
        .flat_map(|r| &r.evidence_spans)
        .collect();
    spans.sort_by_key(|s| std::cmp::Reverse(s.start_byte));
    let mut redacted = TEXT.to_string();
    for span in spans {
        redacted.replace_range(span.start_byte..span.end_byte, &format!("<{}>", span.label));
    }
    println!("\n{redacted}\n");

    // Turn a single rule off by its id: the first span's rule here.
    if let Some(rule) = report
        .native
        .iter()
        .flat_map(|r| &r.layers)
        .flat_map(|l| l.details["matched_rules"].as_array().into_iter().flatten())
        .find_map(|r| r["rule_id"].as_str())
    {
        let config: ScannerConfig = serde_json::from_value(serde_json::json!({
            "categories": ["pii", "dlp"],
            "rules": { rule: false },
        }))?;
        let spans = Scanner::new(config)?
            .scan(TEXT)?
            .native
            .iter()
            .map(|r| r.evidence_spans.len())
            .sum::<usize>();
        println!("without {rule}: {spans} spans");
    }
    Ok(())
}
