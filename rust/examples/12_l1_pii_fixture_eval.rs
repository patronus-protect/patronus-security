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
    for row in &rows {
        let expected = row
            .entities
            .iter()
            .filter_map(|entity| {
                ark_label(&entity.label).map(|label| (entity.start, entity.end, label.to_string()))
            })
            .collect::<BTreeSet<_>>();
        let result = gateway
            .scan_category(SecurityCategory::Pii, &row.text)
            .into_iter()
            .find(|result| result.model == "native:pii")
            .expect("native PII result must exist");
        let predicted = result
            .evidence_spans
            .into_iter()
            .filter(|span| ark_label_for_output(&span.label))
            .map(|span| (span.start_byte, span.end_byte, span.label))
            .collect::<BTreeSet<_>>();

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
    println!("fixture={} rows={}", path.display(), rows.len());
    println!(
        "exact_span tp={} fp={} fn={} precision={precision:.4} recall={recall:.4} f1={f1:.4}",
        totals.0, totals.1, totals.2
    );
    for (label, (tp, fp, fn_count)) in per_label {
        println!("{label:<28} tp={tp:<3} fp={fp:<3} fn={fn_count:<3}");
    }
    Ok(())
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
