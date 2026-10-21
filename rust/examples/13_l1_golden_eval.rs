use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use patronus_ark::{
    detectors::{
        dlp::{dlp::DLP_PATTERNS, score::DlpMode},
        pii::{pii::PII_PATTERNS, score::PiiMode},
    },
    golden_recipes::{materialize_fragments, GeneratorSet, SecretRecipe},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureRow {
    id: String,
    language: String,
    case_type: String,
    target_label: String,
    /// Golden schema v2 (PII and DLP): the rule that must report every gold span,
    /// the difficulty tags, and whether the positive is a known gap (reported, not gated).
    rule_id: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    known_gap: bool,
    /// PII rows for the opt-in modes (K03 context engine) name the mode they run in.
    #[serde(default)]
    pii_mode: PiiMode,
    /// DLP rows for the opt-in modes (K04 score model) name the mode they run in.
    #[serde(default)]
    dlp_mode: DlpMode,
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
                Ok(materialize_fragments(generators, template, secrets)?.0)
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
/// with exactly their own rules opted in; every other row runs on the defaults,
/// in the PII and DLP modes the row names (default `strict`).
fn gates_for(target_label: &str, pii_mode: PiiMode, dlp_mode: DlpMode) -> ScanGateMatrix {
    let mut gates = ScanGateMatrix {
        pii_mode,
        dlp_mode,
        ..ScanGateMatrix::default()
    };
    for pattern in DLP_PATTERNS {
        if pattern.entity_group == target_label && !gates.allows_rule(pattern.name) {
            gates.set_rule(pattern.name, true);
        }
    }
    gates
}

/// `(start_char, end_char, rule_id)` of every rule match the scanner reported.
fn matched_rules(result: &SecurityScanResult, text: &str) -> BTreeSet<(usize, usize, String)> {
    let char_at = |byte: usize| text[..byte].chars().count();
    result
        .layers
        .iter()
        .filter_map(|layer| layer.details.get("matched_rules"))
        .filter_map(|rules| rules.as_array())
        .flatten()
        .filter_map(|rule| {
            Some((
                char_at(rule.get("start_byte")?.as_u64()? as usize),
                char_at(rule.get("end_byte")?.as_u64()? as usize),
                rule.get("rule_id")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// `(start_byte, end_byte, label)` of the findings the scanner marked as secondary
/// evidence of another finding (T07).
fn secondary_evidence(result: &SecurityScanResult) -> BTreeSet<(usize, usize, String)> {
    result
        .layers
        .iter()
        .filter_map(|layer| layer.details.get("secondary_evidence"))
        .filter_map(|entries| entries.as_array())
        .flatten()
        .filter_map(|entry| {
            Some((
                entry.get("start_byte")?.as_u64()? as usize,
                entry.get("end_byte")?.as_u64()? as usize,
                entry.get("label")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Gated positives per rule and language that the declared rule reported exactly,
/// out of the gated positives declaring that rule; plus pass/total and known gaps per
/// tag and language.
#[derive(Default)]
struct Coverage {
    rules: BTreeMap<String, BTreeMap<String, (usize, usize)>>,
    tags: BTreeMap<(String, String), (usize, usize, usize)>,
    gaps_closed: Vec<String>,
}

impl Coverage {
    fn record(&mut self, row: &FixtureRow, rule_id: &str, passed: bool) {
        if row.known_gap {
            if passed {
                self.gaps_closed.push(row.id.clone());
            }
        } else {
            let cell = self
                .rules
                .entry(rule_id.to_owned())
                .or_default()
                .entry(row.language.clone())
                .or_default();
            cell.0 += usize::from(passed);
            cell.1 += 1;
        }
        let tags = if row.tags.is_empty() {
            vec!["plain".to_owned()]
        } else {
            row.tags.clone()
        };
        for tag in tags {
            let cell = self.tags.entry((tag, row.language.clone())).or_default();
            if row.known_gap {
                cell.2 += 1;
            } else {
                cell.0 += usize::from(passed);
                cell.1 += 1;
            }
        }
    }

    /// Print the report and list every rule without a passing gated positive per language.
    fn report(&self, rules: &[&str]) -> Vec<String> {
        println!("coverage per rule_id (gated positives reported by the rule, de | en):");
        let mut missing = Vec::new();
        for rule in rules {
            let cells = ["de", "en"].map(|language| {
                let (passed, total) = self
                    .rules
                    .get(*rule)
                    .and_then(|languages| languages.get(language))
                    .copied()
                    .unwrap_or_default();
                if passed == 0 {
                    missing.push(format!("{rule}/{language}"));
                }
                format!("{passed}/{total}")
            });
            println!("  {rule:<40} {:>5} | {:>5}", cells[0], cells[1]);
        }
        println!("positives per difficulty tag and language (gated passed/total, known gaps):");
        for ((tag, language), (passed, total, gaps)) in &self.tags {
            println!("  {tag:<12} {language} {passed}/{total} gaps={gaps}");
        }
        missing
    }
}

fn evaluate(
    gateway: &SecurityGateway,
    generators: &GeneratorSet,
    path: &Path,
    category: SecurityCategory,
    model: &str,
    rule_ids: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        rows.push(serde_json::from_str::<FixtureRow>(&line?)?);
    }
    let mut positive_total = 0;
    let mut positive_exact = 0;
    let mut negative_total = 0;
    let mut negative_rejected = 0;
    let mut known_gaps = 0;
    let mut coverage = Coverage::default();

    for row in &rows {
        let expected = row
            .entities
            .iter()
            .filter(|entity| entity.label == row.target_label)
            .map(|entity| (entity.start, entity.end, entity.label.clone()))
            .collect::<BTreeSet<_>>();
        gateway.set_execution_gates(gates_for(&row.target_label, row.pii_mode, row.dlp_mode));
        let text = row.materialized_text(generators)?;
        let result = gateway
            .scan_category(category, &text)
            .into_iter()
            .find(|result| result.model == model)
            .expect("native L1 result must exist");
        let rules = matched_rules(&result, &text);
        // T07: only primary findings are scored; strict keeps secondary evidence (the
        // card-shaped part of a valid IBAN, an account finding on an IBAN value) as well.
        let secondary = secondary_evidence(&result);
        let predicted_all = result
            .evidence_spans
            .into_iter()
            .filter(|span| {
                !secondary.contains(&(span.start_byte, span.end_byte, span.label.clone()))
            })
            .map(|span| (span.start_char, span.end_char, span.label))
            .collect::<BTreeSet<_>>();
        let predicted = predicted_all
            .iter()
            .filter(|(_, _, label)| label == &row.target_label)
            .cloned()
            .collect::<BTreeSet<_>>();

        match row.case_type.as_str() {
            "positive" => {
                // v2 rows also require that the declared rule reported every gold span.
                let attributed = row.rule_id.as_ref().is_none_or(|rule_id| {
                    expected
                        .iter()
                        .all(|(start, end, _)| rules.contains(&(*start, *end, rule_id.clone())))
                });
                let passed = predicted == expected && attributed;
                if let Some(rule_id) = &row.rule_id {
                    coverage.record(row, rule_id, passed);
                }
                if row.known_gap {
                    known_gaps += 1;
                    continue;
                }
                positive_total += 1;
                if passed {
                    positive_exact += 1;
                } else {
                    eprintln!(
                        "positive mismatch id={} rule={:?} expected={expected:?} predicted={predicted:?} rules={rules:?}",
                        row.id, row.rule_id
                    );
                }
            }
            "hard_negative" if row.known_gap => {
                return Err(format!("{}: only positives can be known gaps", row.id).into())
            }
            "hard_negative" => {
                // A hard negative may annotate other real entities in its text (T07: the
                // IBAN around a card-shaped BBAN); they must be found, nothing else.
                let annotated = row
                    .entities
                    .iter()
                    .map(|entity| (entity.start, entity.end, entity.label.clone()))
                    .collect::<BTreeSet<_>>();
                negative_total += 1;
                if predicted_all == annotated {
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
        "fixture={} rows={} positive_exact={}/{} hard_negative_rejected={}/{} known_gaps={}",
        path.display(),
        rows.len(),
        positive_exact,
        positive_total,
        negative_rejected,
        negative_total,
        known_gaps
    );
    let mut failed = positive_exact != positive_total || negative_rejected != negative_total;
    if rows.iter().any(|row| row.rule_id.is_some()) {
        let missing = coverage.report(rule_ids);
        if !missing.is_empty() {
            eprintln!("rules without a passing gated positive: {missing:?}");
            failed = true;
        }
        if !coverage.gaps_closed.is_empty() {
            // A detection change closed a gap: flip `known_gap` so the row is gated.
            eprintln!(
                "known gaps now detected, set known_gap=false: {:?}",
                coverage.gaps_closed
            );
            failed = true;
        }
    }
    if failed {
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
            &PII_PATTERNS
                .iter()
                .map(|pattern| pattern.name)
                .collect::<Vec<_>>(),
        )?;
    }
    if suite != "pii" {
        evaluate(
            &gateway,
            &generators,
            &root.join("dlp_l1.jsonl"),
            SecurityCategory::Dlp,
            "native:dlp",
            &DLP_PATTERNS
                .iter()
                .map(|pattern| pattern.name)
                .collect::<Vec<_>>(),
        )?;
    }
    Ok(())
}
