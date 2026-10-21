//! Gold hygiene of `pii_l1.jsonl` (T02, TRIAGE 2026-W42 buckets 6 + 7).
//!
//! A positive annotates every real entity in its text, not only the target span, and
//! every gold value is a value of its label: it passes a validator of that label in
//! `PII_PATTERNS` (Luhn, MOD-97, Steuer-ID, ...). A known gap may be a format the
//! validator does not accept yet; a checksum must still hold. Validators are never relaxed
//! for gold.

use std::{collections::BTreeSet, path::Path};

use patronus_ark::detectors::pii::pii::PII_PATTERNS;
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult};
use serde::Deserialize;

/// Non-target primary L1 findings on positives that are detector false positives, not gold
/// gaps: `(row id, label, value)`. Fixing the detector must remove the entry. Since T07 the
/// PAN-shaped part of a valid IBAN and an account finding on an IBAN value are secondary
/// evidence (`details.secondary_evidence`) and not checked here.
const KNOWN_DETECTOR_FP: &[(&str, &str, &str)] = &[
    // Phone digits that happen to pass Luhn.
    ("pii_l1-phone-pos-09", "CREDITCARD", "49 89 2019 4400"),
    ("pii_l1-phone-pos-19", "CREDITCARD", "49 40 3005 1200"),
    // PAN-shaped part of an IBAN form that is not reported as an IBAN yet: a grouped
    // IBAN outside DE (T05).
    ("pii_l1-iban-pos-13", "CREDITCARD", "1904 3002 3457 3201"),
];

/// Labels whose validators are checksums: they hold for every gold value, known gaps included.
const CHECKSUM_LABELS: [&str; 3] = ["CREDITCARD", "IBAN", "STEUERID"];

#[derive(Deserialize)]
struct Row {
    id: String,
    case_type: String,
    target_label: String,
    known_gap: bool,
    text: String,
    entities: Vec<Entity>,
}

#[derive(Deserialize)]
struct Entity {
    label: String,
    text: String,
    start: usize,
    end: usize,
}

fn positives() -> Vec<Row> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../python/patronus_ark/benchmark_data/pii_l1.jsonl");
    std::fs::read_to_string(path)
        .expect("pii_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str::<Row>(line).expect("golden row"))
        .filter(|row| row.case_type == "positive")
        .collect()
}

fn char_slice(text: &str, start: usize, end: usize) -> String {
    text.chars().skip(start).take(end - start).collect()
}

/// Undo the `obfuscated` tag's tricks (zero-width and full-width characters, defanged
/// `[.]`) so the value under the obfuscation is checked; the detector never sees this.
fn deobfuscate(value: &str) -> String {
    value
        .replace("[.]", ".")
        .chars()
        .filter(|ch| !matches!(ch, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'))
        .map(|ch| match ch {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
            '\u{3000}' => ' ',
            _ => ch,
        })
        .collect()
}

#[test]
fn every_gold_value_passes_a_validator_of_its_label() {
    let mut checked = BTreeSet::new();
    let mut invalid = Vec::new();
    for row in positives() {
        for entity in &row.entities {
            assert_eq!(
                char_slice(&row.text, entity.start, entity.end),
                entity.text,
                "{}: span text",
                row.id
            );
            let validators = PII_PATTERNS
                .iter()
                .filter(|pattern| pattern.entity_group == entity.label)
                .filter_map(|pattern| pattern.validator)
                .collect::<Vec<_>>();
            if validators.is_empty()
                || (row.known_gap && !CHECKSUM_LABELS.contains(&entity.label.as_str()))
            {
                continue;
            }
            let value = deobfuscate(&entity.text);
            if !validators.iter().any(|validator| validator(&value)) {
                invalid.push(format!("{} {} {:?}", row.id, entity.label, entity.text));
            }
            checked.insert(entity.label.clone());
        }
    }
    assert!(
        invalid.is_empty(),
        "gold values fail every validator of their label: {invalid:#?}"
    );
    for label in ["CREDITCARD", "IBAN", "STEUERID", "SSN", "NATIONALID"] {
        assert!(checked.contains(label), "no {label} gold value checked");
    }
}

#[test]
fn positives_target_exactly_one_entity_and_keep_text_order() {
    for row in positives() {
        let targets = row
            .entities
            .iter()
            .filter(|entity| entity.label == row.target_label)
            .count();
        assert_eq!(targets, 1, "{}", row.id);
        assert!(
            row.entities
                .windows(2)
                .all(|pair| pair[0].end <= pair[1].start),
            "{}: entities overlap or are out of order",
            row.id
        );
    }
}

/// `(label, start_byte, end_byte)` of the findings strict marks as secondary evidence (T07).
fn secondary_evidence(result: &SecurityScanResult) -> BTreeSet<(String, usize, usize)> {
    result
        .layers
        .iter()
        .filter_map(|layer| layer.details.get("secondary_evidence"))
        .filter_map(|entries| entries.as_array())
        .flatten()
        .filter_map(|entry| {
            Some((
                entry.get("label")?.as_str()?.to_owned(),
                entry.get("start_byte")?.as_u64()? as usize,
                entry.get("end_byte")?.as_u64()? as usize,
            ))
        })
        .collect()
}

#[test]
fn every_l1_finding_on_a_positive_is_gold_or_a_known_detector_fp() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    let rows = positives();
    let mut unexplained = Vec::new();
    let mut seen_fp = BTreeSet::new();
    for row in &rows {
        let gold = row
            .entities
            .iter()
            .map(|entity| (entity.start, entity.end, entity.label.as_str()))
            .collect::<BTreeSet<_>>();
        let result = gateway
            .scan_category(SecurityCategory::Pii, &row.text)
            .into_iter()
            .find(|result| result.model == "native:pii")
            .expect("native PII result must be present");
        let secondary = secondary_evidence(&result);
        for span in result.evidence_spans {
            // Target-label spans are scored by 13_l1_golden_eval (incl. known gaps).
            if span.label == row.target_label
                || secondary.contains(&(span.label.clone(), span.start_byte, span.end_byte))
                || gold.contains(&(span.start_char, span.end_char, span.label.as_str()))
            {
                continue;
            }
            let value = char_slice(&row.text, span.start_char, span.end_char);
            let key = (row.id.as_str(), span.label.as_str(), value.as_str());
            if KNOWN_DETECTOR_FP.contains(&key) {
                seen_fp.insert(KNOWN_DETECTOR_FP.iter().position(|fp| *fp == key));
            } else {
                unexplained.push(format!("{} {} {value:?}", row.id, span.label));
            }
        }
    }
    assert!(
        unexplained.is_empty(),
        "annotate these entities in generate_l1_goldens.py (`also=`) or list them as detector FPs: {unexplained:#?}"
    );
    for (index, fp) in KNOWN_DETECTOR_FP.iter().enumerate() {
        assert!(
            seen_fp.contains(&Some(index)),
            "{fp:?} is no longer reported; remove it from KNOWN_DETECTOR_FP"
        );
    }
}
