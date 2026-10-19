use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureRow {
    text: String,
    #[serde(default)]
    entities: Vec<FixtureEntity>,
}

#[derive(Deserialize)]
struct FixtureEntity {
    start: usize,
    end: usize,
    label: String,
    /// `false` marks a checksum-invalid gold value (T02): it stays in the fixture for the
    /// L3 NER, but no L1 validator may accept it, so the L1 evaluation skips it.
    #[serde(default = "checksum_valid_default")]
    checksum_valid: bool,
}

fn checksum_valid_default() -> bool {
    true
}

fn ark_label(label: &str) -> Option<&'static str> {
    Some(match label {
        "email" => "EMAIL",
        "phone_number" => "PHONE",
        "ip_address" => "IP_ADDRESS",
        "credit_card" => "CREDITCARD",
        "employee_identifier" => "EMPLOYEE_ID",
        "username" => "USERNAME",
        "passport_number" => "PASSPORT_NUMBER",
        "driver_license_number" => "DRIVER_LICENSE_NUMBER",
        "medical_record_number" => "PATIENT_ID",
        "health_insurance_number" => "HEALTH_INSURANCE_NUMBER",
        "student_identifier" => "STUDENT_ID",
        "applicant_identifier" => "APPLICANT_ID",
        "date_of_birth" => "DOB",
        _ => return None,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("../python/patronus_ark/benchmark_data/dynamic_pii.jsonl")
        });
    let mut rows = Vec::new();
    for line in BufReader::new(File::open(&path)?).lines() {
        rows.push(serde_json::from_str::<FixtureRow>(&line?)?);
    }

    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    gateway.warmup()?;

    let mut totals = (0usize, 0usize, 0usize);
    let mut per_label = BTreeMap::<String, (usize, usize, usize)>::new();
    for (index, row) in rows.iter().enumerate() {
        let expected = expected_spans(row)
            .map_err(|error| format!("{}:{}: {error}", path.display(), index + 1))?;
        let predicted = predicted_spans(&gateway, &row.text);

        if expected != predicted && (!expected.is_empty() || !predicted.is_empty()) {
            eprintln!(
                "mismatch text={:?} expected={expected:?} predicted={predicted:?}",
                row.text
            );
        }

        for item in expected.intersection(&predicted) {
            totals.0 += 1;
            per_label.entry(item.2.clone()).or_default().0 += 1;
        }
        for item in predicted.difference(&expected) {
            totals.1 += 1;
            per_label.entry(item.2.clone()).or_default().1 += 1;
        }
        for item in expected.difference(&predicted) {
            totals.2 += 1;
            per_label.entry(item.2.clone()).or_default().2 += 1;
        }
    }

    let precision = ratio(totals.0, totals.0 + totals.1);
    let recall = ratio(totals.0, totals.0 + totals.2);
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    println!(
        "fixture={} rows={} span_unit={SPAN_UNIT}",
        path.display(),
        rows.len()
    );
    println!(
        "exact_span tp={} fp={} fn={} precision={precision:.4} recall={recall:.4} f1={f1:.4}",
        totals.0, totals.1, totals.2
    );
    for (label, (tp, fp, fn_count)) in per_label {
        println!("{label:<28} tp={tp:<3} fp={fp:<3} fn={fn_count:<3}");
    }
    Ok(())
}

/// `(start, end, ARK label)`; offsets follow `SPAN_UNIT`.
type Span = (usize, usize, String);

/// Fixture spans count Unicode code points (Python `str` indices), not UTF-8 bytes.
const SPAN_UNIT: &str = "char";

/// Gold spans of one row mapped to ARK labels, without spans marked checksum-invalid;
/// rejects spans outside the text.
fn expected_spans(row: &FixtureRow) -> Result<BTreeSet<Span>, String> {
    let text_chars = row.text.chars().count();
    let mut spans = BTreeSet::new();
    for entity in &row.entities {
        if entity.start >= entity.end || entity.end > text_chars {
            return Err(format!(
                "{} span {}..{} outside text of {text_chars} chars",
                entity.label, entity.start, entity.end
            ));
        }
        if !entity.checksum_valid {
            continue;
        }
        if let Some(label) = ark_label(&entity.label) {
            spans.insert((entity.start, entity.end, label.to_string()));
        }
    }
    Ok(spans)
}

/// Public `native:pii` spans for the evaluated labels.
fn predicted_spans(gateway: &SecurityGateway, text: &str) -> BTreeSet<Span> {
    gateway
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must exist")
        .evidence_spans
        .into_iter()
        .filter(|span| ark_label_for_output(&span.label))
        .map(|span| (span.start_char, span.end_char, span.label))
        .collect()
}

fn ark_label_for_output(label: &str) -> bool {
    matches!(
        label,
        "EMAIL"
            | "PHONE"
            | "IP_ADDRESS"
            | "CREDITCARD"
            | "EMPLOYEE_ID"
            | "USERNAME"
            | "PASSPORT_NUMBER"
            | "DRIVER_LICENSE_NUMBER"
            | "PATIENT_ID"
            | "HEALTH_INSURANCE_NUMBER"
            | "STUDENT_ID"
            | "APPLICANT_ID"
            | "DOB"
    )
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> SecurityGateway {
        let mut gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::Pii],
            SecurityLevel::L1,
            None,
            false,
        );
        gateway.warmup().expect("PII L1 warmup");
        gateway
    }

    fn span(start: usize, end: usize, label: &str) -> Span {
        (start, end, label.to_string())
    }

    fn row(text: &str, entities: &[(usize, usize, &str)]) -> FixtureRow {
        FixtureRow {
            text: text.to_string(),
            entities: entities
                .iter()
                .map(|&(start, end, label)| FixtureEntity {
                    start,
                    end,
                    label: label.to_string(),
                    checksum_valid: true,
                })
                .collect(),
        }
    }

    /// Char offset of `needle`, computed independently of the evaluator.
    fn char_span(text: &str, needle: &str, label: &str) -> Span {
        let byte = text.find(needle).expect("needle in text");
        let start = text[..byte].chars().count();
        span(start, start + needle.chars().count(), label)
    }

    #[test]
    fn predicted_spans_use_char_offsets_after_umlauts() {
        let text = "Rückfragen bitte an Frau Müller: anna.mueller@example.com";
        let expected = char_span(text, "anna.mueller@example.com", "EMAIL");
        assert_ne!(expected.0, text.find("anna.mueller").unwrap());
        assert_eq!(
            predicted_spans(&gateway(), text),
            BTreeSet::from([expected])
        );
    }

    #[test]
    fn predicted_spans_use_char_offsets_after_four_byte_chars() {
        let text = "📧📧 Kontakt: ada@example.com und 192.168.10.20";
        let predicted = predicted_spans(&gateway(), text);
        assert_eq!(
            predicted,
            BTreeSet::from([
                char_span(text, "ada@example.com", "EMAIL"),
                char_span(text, "192.168.10.20", "IP_ADDRESS"),
            ])
        );
    }

    #[test]
    fn ascii_offsets_are_unchanged() {
        let text = "Contact ada@example.com today.";
        assert_eq!(
            predicted_spans(&gateway(), text),
            BTreeSet::from([span(8, 23, "EMAIL")])
        );
    }

    #[test]
    fn non_ascii_gold_row_scores_as_exact_match() {
        let text = "Grüße aus München, schreiben Sie an joerg@example.com.";
        let gold = char_span(text, "joerg@example.com", "EMAIL");
        let fixture = row(text, &[(gold.0, gold.1, "email")]);
        let expected = expected_spans(&fixture).unwrap();
        assert_eq!(expected, BTreeSet::from([gold]));
        assert_eq!(predicted_spans(&gateway(), text), expected);
    }

    #[test]
    fn expected_spans_map_labels_and_skip_unmapped() {
        let fixture = row(
            "Sorgeberechtigte: Sabine Krüger, ada@example.com",
            &[(18, 31, "parent_or_guardian"), (33, 48, "email")],
        );
        assert_eq!(
            expected_spans(&fixture).unwrap(),
            BTreeSet::from([span(33, 48, "EMAIL")])
        );
    }

    #[test]
    fn expected_spans_reject_byte_offsets_beyond_the_text() {
        // "Jörg" is 4 chars but 5 bytes: a byte-offset end overshoots.
        let fixture = row("Jörg", &[(0, 5, "email")]);
        assert!(expected_spans(&fixture).is_err());
        let empty = row("Jörg", &[(2, 2, "email")]);
        assert!(expected_spans(&empty).is_err());
    }

    #[test]
    fn bundled_fixture_offsets_are_char_offsets() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../python/patronus_ark/benchmark_data/dynamic_pii.jsonl"
        );
        let content = std::fs::read_to_string(path).expect("fixture");
        let mut non_ascii = 0;
        for line in content.lines() {
            let row: FixtureRow = serde_json::from_str(line).expect("fixture row");
            expected_spans(&row).expect("gold span inside text");
            non_ascii += usize::from(!row.text.is_ascii());
        }
        assert!(non_ascii > 0, "fixture must keep non-ASCII rows");
    }

    #[test]
    fn expected_spans_skip_gold_marked_checksum_invalid() {
        let fixture: FixtureRow = serde_json::from_str(
            r#"{"text": "Card 4111 1111 1111 1112 or 4111 1111 1111 1111", "entities": [
                {"start": 5, "end": 24, "label": "credit_card", "checksum_valid": false},
                {"start": 28, "end": 47, "label": "credit_card"}]}"#,
        )
        .unwrap();
        assert_eq!(
            expected_spans(&fixture).unwrap(),
            BTreeSet::from([span(28, 47, "CREDITCARD")])
        );
    }

    /// T02: the fixture also feeds L3 NER, so Luhn-invalid card numbers stay in it but
    /// carry `"checksum_valid": false`; a mark on a valid number would hide a real FN.
    #[test]
    fn bundled_fixture_marks_exactly_the_luhn_invalid_cards() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../python/patronus_ark/benchmark_data/dynamic_pii.jsonl"
        );
        let content = std::fs::read_to_string(path).expect("fixture");
        let mut cards = 0;
        for line in content.lines() {
            let row: serde_json::Value = serde_json::from_str(line).expect("fixture row");
            for entity in row["entities"].as_array().expect("entities") {
                if entity["label"] != "credit_card" {
                    continue;
                }
                cards += 1;
                let value = entity["text"].as_str().expect("entity text");
                let marked_invalid = entity["checksum_valid"] == false;
                assert_eq!(
                    marked_invalid,
                    !patronus_ark::detectors::pii::validators::luhn(value),
                    "{} {value}",
                    row["id"]
                );
            }
        }
        assert!(cards > 0, "fixture must keep credit_card spans");
    }
}
