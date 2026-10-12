use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS,
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureRow {
    id: String,
    case_type: String,
    target_label: String,
    /// Literal rows carry `text`; secret rows carry `template` + `secrets` recipes.
    text: Option<String>,
    template: Option<String>,
    secrets: Option<Vec<SecretRecipe>>,
    entities: Vec<FixtureEntity>,
}

impl FixtureRow {
    /// Secret values exist only in memory, materialized from their recipes.
    fn materialized_text(
        &self,
        generators: &GeneratorSet,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match (&self.text, &self.template, &self.secrets) {
            (Some(text), None, None) => Ok(text.clone()),
            (None, Some(template), Some(secrets)) => {
                Ok(materialize(generators, template, secrets)?.0)
            }
            _ => Err(format!("{}: need either text or template + secrets", self.id).into()),
        }
    }
}

#[derive(Deserialize)]
struct FixtureEntity {
    start: usize,
    end: usize,
    label: String,
}

/// Default-off DLP classes (business records, content) are reachability-tested
/// with exactly their own rules opted in; every other row runs on the defaults.
fn gates_for(target_label: &str) -> ScanGateMatrix {
    let mut gates = ScanGateMatrix::default();
    for pattern in DLP_PATTERNS {
        if pattern.entity_group == target_label && !gates.allows_rule(pattern.name) {
            gates.set_rule(pattern.name, true);
        }
    }
    gates
}

fn evaluate(
    gateway: &SecurityGateway,
    generators: &GeneratorSet,
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
        gateway.set_execution_gates(gates_for(&row.target_label));
        let text = row.materialized_text(generators)?;
        let result = gateway
            .scan_category(category, &text)
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

    gateway.set_execution_gates(ScanGateMatrix::default());

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
    let generators = GeneratorSet::load("../python/patronus_ark/dlp_synth/generators.json")?;
    // Optional suite filter: `pii`, `dlp` or `all` (default).
    let suite = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    if !matches!(suite.as_str(), "pii" | "dlp" | "all") {
        return Err(format!("unknown suite {suite:?}; expected pii, dlp or all").into());
    }
    if suite != "dlp" {
        evaluate(
            &gateway,
            &generators,
            &root.join("pii_l1.jsonl"),
            SecurityCategory::Pii,
            "native:pii",
        )?;
    }
    if suite != "pii" {
        evaluate(
            &gateway,
            &generators,
            &root.join("dlp_l1.jsonl"),
            SecurityCategory::Dlp,
            "native:dlp",
        )?;
    }
    Ok(())
}
