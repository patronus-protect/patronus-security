use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureRow {
    id: String,
    case_type: String,
    target_label: String,
    text: String,
    entities: Vec<FixtureEntity>,
}

#[derive(Deserialize)]
struct FixtureEntity {
    start: usize,
    end: usize,
    label: String,
}

fn evaluate(
    gateway: &SecurityGateway,
    path: &Path,
    category: SecurityCategory,
    model: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        rows.push(serde_json::from_str::<FixtureRow>(&line?)?);
    }
    let mut positive_total = 0;
    let mut positive_exact = 0;
    let mut negative_total = 0;
    let mut negative_rejected = 0;

    for row in &rows {
        let expected = row
            .entities
            .iter()
            .filter(|entity| entity.label == row.target_label)
            .map(|entity| (entity.start, entity.end, entity.label.clone()))
            .collect::<BTreeSet<_>>();
        let result = gateway
            .scan_category(category, &row.text)
            .into_iter()
            .find(|result| result.model == model)
            .expect("native L1 result must exist");
        let predicted_all = result
            .evidence_spans
            .into_iter()
            .map(|span| (span.start_char, span.end_char, span.label))
            .collect::<BTreeSet<_>>();
        let predicted = predicted_all
            .iter()
            .filter(|(_, _, label)| label == &row.target_label)
            .cloned()
            .collect::<BTreeSet<_>>();

        match row.case_type.as_str() {
            "positive" => {
                positive_total += 1;
                if predicted == expected {
                    positive_exact += 1;
                } else {
                    eprintln!(
                        "positive mismatch id={} expected={expected:?} predicted={predicted:?}",
                        row.id
                    );
                }
            }
            "hard_negative" => {
                negative_total += 1;
                if predicted_all.is_empty() {
                    negative_rejected += 1;
                } else {
                    eprintln!(
                        "negative mismatch id={} target={} predicted={predicted_all:?}",
                        row.id, row.target_label
                    );
                }
            }
            other => return Err(format!("unknown case_type {other:?} in {}", row.id).into()),
        }
    }

    println!(
        "fixture={} rows={} positive_exact={}/{} hard_negative_rejected={}/{}",
        path.display(),
        rows.len(),
        positive_exact,
        positive_total,
        negative_rejected,
        negative_total
    );
    if positive_exact != positive_total || negative_rejected != negative_total {
        return Err("L1 golden evaluation failed".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii, SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    gateway.warmup()?;
    let root = Path::new("../python/patronus_ark/benchmark_data");
    evaluate(
        &gateway,
        &root.join("pii_l1.jsonl"),
        SecurityCategory::Pii,
        "native:pii",
    )?;
    evaluate(
        &gateway,
        &root.join("dlp_l1.jsonl"),
        SecurityCategory::Dlp,
        "native:dlp",
    )
}
