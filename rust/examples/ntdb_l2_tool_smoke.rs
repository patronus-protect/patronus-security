use patronus_security::{
    NtdbOperatingPoint, ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TOOL_PROMPTS_MODEL: &str = "tool-prompts-model";
const TOOL_EXECUTIONS_MODEL: &str = "tool-executions-model";
const TOOL_DESCRIPTIONS_MODEL: &str = "tool-classifier-descriptions-model";

#[derive(Debug)]
struct Args {
    prompts_export_dir: PathBuf,
    executions_export_dir: PathBuf,
    descriptions_export_dir: PathBuf,
    prompts_dataset: PathBuf,
    executions_dataset: PathBuf,
    descriptions_dataset: PathBuf,
    limit: usize,
    operating_point: String,
    out_json: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ManifestLabels {
    task: ManifestTaskLabels,
}

#[derive(Debug, Deserialize)]
struct ManifestTaskLabels {
    labels: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DatasetKind {
    Prompts,
    Executions,
    Descriptions,
}

#[derive(Debug, Clone)]
struct Sample {
    dataset: DatasetKind,
    text: String,
    expected: String,
}

#[derive(Debug)]
struct SpeedObservation {
    e2e: Duration,
    ntdb_l2_wall_ms: f64,
    public_l2_results: usize,
    error_results: usize,
}

#[derive(Debug, Clone)]
struct ModelOutcome {
    predicted: String,
    l2_result: bool,
    l3_pending_result: bool,
    l3_result: bool,
    degraded_result: bool,
    error_result: bool,
    missing_result: bool,
    error_message: Option<String>,
}

#[derive(Debug)]
struct JointObservation {
    sample: Sample,
    prompts: ModelOutcome,
    executions: ModelOutcome,
    descriptions: ModelOutcome,
    latency: Duration,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    configure_ntdb_exports(&args);
    let operating_point = args.operating_point.parse::<NtdbOperatingPoint>()?;

    let label_sets = LabelSets {
        prompts: load_manifest_labels(&args.prompts_export_dir)?,
        executions: load_manifest_labels(&args.executions_export_dir)?,
        descriptions: load_manifest_labels(&args.descriptions_export_dir)?,
    };
    let samples = load_samples(&args, &label_sets)?;
    let model_dir = std::env::temp_dir().join("patronus_ntdb_tool_smoke_assets");

    let joint_l2 = measure_joint_l2(&model_dir, &samples, operating_point)?;
    let sequential_l2 = measure_sequential_l2(&model_dir, &samples, operating_point)?;
    let joint_l3 = measure_joint_l3_no_l3(&model_dir, &samples, operating_point)?;

    let report = report(&args, &samples, &joint_l2, &sequential_l2, &joint_l3);
    if let Some(parent) = args.out_json.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.out_json, serde_json::to_string_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

struct LabelSets {
    prompts: Vec<String>,
    executions: Vec<String>,
    descriptions: Vec<String>,
}

fn measure_joint_l2(
    model_dir: &Path,
    samples: &[Sample],
    operating_point: NtdbOperatingPoint,
) -> Result<Vec<SpeedObservation>, Box<dyn std::error::Error>> {
    let mut scanner = scanner(SecurityLevel::L2, model_dir, operating_point);
    scanner.warmup()?;
    let _ = scanner.scan_categories(
        &[SecurityCategory::ToolClassifier],
        "neutral warmup text for NTDB tool L2",
    );

    let mut observations = Vec::with_capacity(samples.len());
    for sample in samples {
        let started = Instant::now();
        let results = scanner.scan_categories(&[SecurityCategory::ToolClassifier], &sample.text);
        let e2e = started.elapsed();
        observations.push(SpeedObservation {
            e2e,
            ntdb_l2_wall_ms: ntdb_l2_wall_ms(&results),
            public_l2_results: public_l2_results(&results),
            error_results: public_error_results(&results),
        });
    }
    Ok(observations)
}

fn measure_sequential_l2(
    model_dir: &Path,
    samples: &[Sample],
    operating_point: NtdbOperatingPoint,
) -> Result<Vec<SpeedObservation>, Box<dyn std::error::Error>> {
    let mut scanner = scanner(SecurityLevel::L2, model_dir, operating_point);
    scanner.warmup()?;
    let gates = [
        gate_only(TOOL_PROMPTS_MODEL),
        gate_only(TOOL_EXECUTIONS_MODEL),
        gate_only(TOOL_DESCRIPTIONS_MODEL),
    ];

    let mut observations = Vec::with_capacity(samples.len());
    for sample in samples {
        let started = Instant::now();
        let mut l2_wall_ms = 0.0;
        let mut public_l2_count = 0usize;
        let mut error_count = 0usize;
        for gate in &gates {
            scanner.set_execution_gates(gate.clone());
            let results =
                scanner.scan_categories(&[SecurityCategory::ToolClassifier], &sample.text);
            l2_wall_ms += ntdb_l2_wall_ms(&results);
            public_l2_count += public_l2_results(&results);
            error_count += public_error_results(&results);
        }
        scanner.set_execution_gates(ScanGateMatrix::all_enabled());
        observations.push(SpeedObservation {
            e2e: started.elapsed(),
            ntdb_l2_wall_ms: l2_wall_ms,
            public_l2_results: public_l2_count,
            error_results: error_count,
        });
    }
    Ok(observations)
}

fn measure_joint_l3_no_l3(
    model_dir: &Path,
    samples: &[Sample],
    operating_point: NtdbOperatingPoint,
) -> Result<Vec<JointObservation>, Box<dyn std::error::Error>> {
    let mut scanner = scanner(SecurityLevel::L3, model_dir, operating_point);
    scanner.warmup()?;

    let mut observations = Vec::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        eprintln!(
            "[tool-smoke] sample {}/{} start dataset={}",
            index + 1,
            samples.len(),
            dataset_name(sample.dataset)
        );
        let started = Instant::now();
        let results = scanner.scan_categories(&[SecurityCategory::ToolClassifier], &sample.text);
        let latency = started.elapsed();
        observations.push(JointObservation {
            sample: sample.clone(),
            prompts: model_outcome(&results, TOOL_PROMPTS_MODEL),
            executions: model_outcome(&results, TOOL_EXECUTIONS_MODEL),
            descriptions: model_outcome(&results, TOOL_DESCRIPTIONS_MODEL),
            latency,
        });
    }
    Ok(observations)
}

fn scanner(
    level: SecurityLevel,
    model_dir: &Path,
    operating_point: NtdbOperatingPoint,
) -> SecurityGateway {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::ToolClassifier],
        level,
        Some(model_dir.to_path_buf()),
        false,
    );
    scanner.set_ntdb_operating_point(operating_point);
    scanner
}

fn gate_only(model: &str) -> ScanGateMatrix {
    let mut gates = ScanGateMatrix::all_enabled()
        .with_model(TOOL_PROMPTS_MODEL, false)
        .with_model(TOOL_EXECUTIONS_MODEL, false)
        .with_model(TOOL_DESCRIPTIONS_MODEL, false);
    gates.set_model(model, true);
    gates
}

fn configure_ntdb_exports(args: &Args) {
    std::env::set_var("PATRONUS_NTDB_TOOL_PROMPTS_DIR", &args.prompts_export_dir);
    std::env::set_var(
        "PATRONUS_NTDB_TOOL_EXECUTIONS_DIR",
        &args.executions_export_dir,
    );
    std::env::set_var(
        "PATRONUS_NTDB_TOOL_DESCRIPTIONS_DIR",
        &args.descriptions_export_dir,
    );
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut prompts_export_dir = None;
    let mut executions_export_dir = None;
    let mut descriptions_export_dir = None;
    let mut prompts_dataset = None;
    let mut executions_dataset = None;
    let mut descriptions_dataset = None;
    let mut limit = 100usize;
    let mut operating_point = "best_f1".to_string();
    let mut out_json = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--prompts-export-dir" => {
                prompts_export_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --prompts-export-dir value")?,
                ))
            }
            "--executions-export-dir" => {
                executions_export_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --executions-export-dir value")?,
                ))
            }
            "--descriptions-export-dir" => {
                descriptions_export_dir = Some(PathBuf::from(
                    args.next()
                        .ok_or("missing --descriptions-export-dir value")?,
                ))
            }
            "--prompts-dataset" => {
                prompts_dataset = Some(PathBuf::from(
                    args.next().ok_or("missing --prompts-dataset value")?,
                ))
            }
            "--executions-dataset" => {
                executions_dataset = Some(PathBuf::from(
                    args.next().ok_or("missing --executions-dataset value")?,
                ))
            }
            "--descriptions-dataset" => {
                descriptions_dataset = Some(PathBuf::from(
                    args.next().ok_or("missing --descriptions-dataset value")?,
                ))
            }
            "--limit" => limit = args.next().ok_or("missing --limit value")?.parse()?,
            "--operating-point" => {
                operating_point = args.next().ok_or("missing --operating-point value")?
            }
            "--out-json" => {
                out_json = Some(PathBuf::from(
                    args.next().ok_or("missing --out-json value")?,
                ))
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(Args {
        prompts_export_dir: prompts_export_dir.ok_or("missing --prompts-export-dir")?,
        executions_export_dir: executions_export_dir.ok_or("missing --executions-export-dir")?,
        descriptions_export_dir: descriptions_export_dir
            .ok_or("missing --descriptions-export-dir")?,
        prompts_dataset: prompts_dataset.ok_or("missing --prompts-dataset")?,
        executions_dataset: executions_dataset.ok_or("missing --executions-dataset")?,
        descriptions_dataset: descriptions_dataset.ok_or("missing --descriptions-dataset")?,
        limit,
        operating_point,
        out_json: out_json.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("benchmarks/ntdb_l2_tool_smoke_results.json")
        }),
    })
}

fn load_manifest_labels(export_dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let manifest: ManifestLabels =
        serde_json::from_str(&fs::read_to_string(export_dir.join("manifest.json"))?)?;
    Ok(manifest.task.labels)
}

fn load_samples(
    args: &Args,
    labels: &LabelSets,
) -> Result<Vec<Sample>, Box<dyn std::error::Error>> {
    let mut samples = Vec::new();
    samples.extend(load_csv_samples(
        DatasetKind::Prompts,
        &args.prompts_dataset,
        &labels.prompts,
        args.limit,
    )?);
    samples.extend(load_csv_samples(
        DatasetKind::Executions,
        &args.executions_dataset,
        &labels.executions,
        args.limit,
    )?);
    samples.extend(load_csv_samples(
        DatasetKind::Descriptions,
        &args.descriptions_dataset,
        &labels.descriptions,
        args.limit,
    )?);
    Ok(samples)
}

fn load_csv_samples(
    dataset: DatasetKind,
    path: &Path,
    labels: &[String],
    limit: usize,
) -> Result<Vec<Sample>, Box<dyn std::error::Error>> {
    let records = parse_csv(&fs::read_to_string(path)?)?;
    let header = records.first().ok_or("CSV is empty")?;
    if header.len() != 2 || header[0] != "label" || header[1] != "text" {
        return Err(format!("unsupported CSV header in {}", path.display()).into());
    }
    let mut samples = Vec::new();
    for (index, record) in records.into_iter().skip(1).enumerate() {
        if record.len() != 2 {
            return Err(format!("invalid CSV record {} in {}", index + 2, path.display()).into());
        }
        let label_index: usize = record[0].parse()?;
        let expected = labels
            .get(label_index)
            .ok_or_else(|| format!("label index {label_index} missing in manifest labels"))?
            .clone();
        samples.push(Sample {
            dataset,
            text: record[1].clone(),
            expected,
        });
        if samples.len() >= limit {
            break;
        }
    }
    Ok(samples)
}

fn parse_csv(input: &str) -> Result<Vec<Vec<String>>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut at_field_start = true;

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
            continue;
        }

        match ch {
            '"' if at_field_start => {
                in_quotes = true;
                at_field_start = false;
            }
            ',' => {
                record.push(std::mem::take(&mut field));
                at_field_start = true;
            }
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                at_field_start = true;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                at_field_start = true;
            }
            other => {
                field.push(other);
                at_field_start = false;
            }
        }
    }

    if in_quotes {
        return Err("unterminated quoted CSV field".into());
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

fn model_outcome(results: &[SecurityScanResult], model: &str) -> ModelOutcome {
    let public_results = results
        .iter()
        .filter(|result| result.model == model)
        .collect::<Vec<_>>();
    ModelOutcome {
        predicted: public_results
            .last()
            .map(|result| result.class_name.clone())
            .unwrap_or_else(|| "missing".to_string()),
        l2_result: public_results.iter().any(|result| result.level == "L2"),
        l3_pending_result: any_layer(&public_results, "l3_pending"),
        l3_result: public_results.iter().any(|result| result.level == "L3"),
        degraded_result: any_layer(&public_results, "degraded_timeout")
            || any_layer(&public_results, "degraded_error"),
        error_result: any_layer(&public_results, "ntdb_error"),
        missing_result: public_results.is_empty(),
        error_message: public_results.iter().find_map(|result| {
            result.layers.iter().find_map(|layer| {
                layer
                    .details
                    .get("error")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
        }),
    }
}

fn any_layer(results: &[&SecurityScanResult], layer_type: &str) -> bool {
    results.iter().any(|result| {
        result
            .layers
            .iter()
            .any(|layer| layer.layer_type == layer_type)
    })
}

fn ntdb_l2_wall_ms(results: &[SecurityScanResult]) -> f64 {
    results
        .iter()
        .filter(|result| is_tool_model(&result.model))
        .flat_map(|result| result.layers.iter())
        .filter(|layer| layer.layer_type == "ntdb_l2")
        .map(|layer| layer.duration_ms)
        .fold(0.0, f64::max)
}

fn public_l2_results(results: &[SecurityScanResult]) -> usize {
    results
        .iter()
        .filter(|result| is_tool_model(&result.model) && result.level == "L2")
        .count()
}

fn public_error_results(results: &[SecurityScanResult]) -> usize {
    results
        .iter()
        .filter(|result| is_tool_model(&result.model))
        .filter(|result| {
            result
                .layers
                .iter()
                .any(|layer| layer.layer_type == "ntdb_error")
        })
        .count()
}

fn is_tool_model(model: &str) -> bool {
    matches!(
        model,
        TOOL_PROMPTS_MODEL | TOOL_EXECUTIONS_MODEL | TOOL_DESCRIPTIONS_MODEL
    )
}

fn report(
    args: &Args,
    samples: &[Sample],
    joint_l2: &[SpeedObservation],
    sequential_l2: &[SpeedObservation],
    joint_l3: &[JointObservation],
) -> serde_json::Value {
    json!({
        "generated_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "operating_point": args.operating_point,
        "exports": {
            "tool_prompts": args.prompts_export_dir,
            "tool_executions": args.executions_export_dir,
            "tool_descriptions": args.descriptions_export_dir,
        },
        "datasets": {
            "tool_prompts": {
                "path": args.prompts_dataset,
                "samples": samples.iter().filter(|sample| sample.dataset == DatasetKind::Prompts).count(),
            },
            "tool_executions": {
                "path": args.executions_dataset,
                "samples": samples.iter().filter(|sample| sample.dataset == DatasetKind::Executions).count(),
            },
            "tool_descriptions": {
                "path": args.descriptions_dataset,
                "samples": samples.iter().filter(|sample| sample.dataset == DatasetKind::Descriptions).count(),
            },
        },
        "limit_per_dataset": args.limit,
        "l2_speed": {
            "joint": speed_report(joint_l2),
            "sequential": speed_report(sequential_l2),
            "speedup_e2e_total": ratio(total_e2e_ms(sequential_l2), total_e2e_ms(joint_l2)),
            "speedup_ntdb_l2_wall_total": ratio(total_l2_wall_ms(sequential_l2), total_l2_wall_ms(joint_l2)),
        },
        "no_l3_check": no_l3_report(joint_l3),
        "metrics": {
            "tool_prompts_on_prompts_dataset": classification_report(
                &joint_l3.iter()
                    .filter(|observation| observation.sample.dataset == DatasetKind::Prompts)
                    .map(|observation| (observation.sample.expected.clone(), observation.prompts.predicted.clone()))
                    .collect::<Vec<_>>()
            ),
            "tool_executions_on_executions_dataset": classification_report(
                &joint_l3.iter()
                    .filter(|observation| observation.sample.dataset == DatasetKind::Executions)
                    .map(|observation| (observation.sample.expected.clone(), observation.executions.predicted.clone()))
                    .collect::<Vec<_>>()
            ),
            "tool_descriptions_on_descriptions_dataset": classification_report(
                &joint_l3.iter()
                    .filter(|observation| observation.sample.dataset == DatasetKind::Descriptions)
                    .map(|observation| (observation.sample.expected.clone(), observation.descriptions.predicted.clone()))
                    .collect::<Vec<_>>()
            ),
        },
    })
}

fn speed_report(observations: &[SpeedObservation]) -> serde_json::Value {
    let e2e = observations
        .iter()
        .map(|observation| observation.e2e)
        .collect::<Vec<_>>();
    let l2_wall = observations
        .iter()
        .map(|observation| observation.ntdb_l2_wall_ms)
        .collect::<Vec<_>>();
    json!({
        "samples": observations.len(),
        "total_e2e_ms": total_e2e_ms(observations),
        "latency_e2e_ms": latency_stats(&e2e),
        "total_ntdb_l2_wall_ms": total_l2_wall_ms(observations),
        "latency_ntdb_l2_wall_ms": f64_stats(&l2_wall),
        "public_l2_results": observations.iter().map(|observation| observation.public_l2_results).sum::<usize>(),
        "error_results": observations.iter().map(|observation| observation.error_results).sum::<usize>(),
    })
}

fn no_l3_report(observations: &[JointObservation]) -> serde_json::Value {
    let latencies = observations
        .iter()
        .map(|observation| observation.latency)
        .collect::<Vec<_>>();
    let outcomes = observations.iter().flat_map(|observation| {
        [
            &observation.prompts,
            &observation.executions,
            &observation.descriptions,
        ]
    });
    let mut total = 0usize;
    let mut l2_results = 0usize;
    let mut l3_pending_results = 0usize;
    let mut l3_results = 0usize;
    let mut degraded_results = 0usize;
    let mut error_results = 0usize;
    let mut missing_results = 0usize;
    let mut error_messages = BTreeMap::<String, usize>::new();
    for outcome in outcomes {
        total += 1;
        l2_results += usize::from(outcome.l2_result);
        l3_pending_results += usize::from(outcome.l3_pending_result);
        l3_results += usize::from(outcome.l3_result);
        degraded_results += usize::from(outcome.degraded_result);
        error_results += usize::from(outcome.error_result);
        missing_results += usize::from(outcome.missing_result);
        if let Some(message) = &outcome.error_message {
            *error_messages.entry(message.clone()).or_default() += 1;
        }
    }
    json!({
        "samples": observations.len(),
        "model_results": total,
        "l2_results": l2_results,
        "l3_pending_results": l3_pending_results,
        "l3_results": l3_results,
        "degraded_results": degraded_results,
        "error_results": error_results,
        "missing_results": missing_results,
        "error_messages": error_messages,
        "latency_ms": latency_stats(&latencies),
    })
}

fn classification_report(rows: &[(String, String)]) -> serde_json::Value {
    let mut labels = BTreeSet::new();
    let mut confusion = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut correct = 0usize;
    for (expected, predicted) in rows {
        labels.insert(expected.clone());
        labels.insert(predicted.clone());
        *confusion
            .entry(expected.clone())
            .or_default()
            .entry(predicted.clone())
            .or_default() += 1;
        correct += usize::from(expected == predicted);
    }
    json!({
        "samples": rows.len(),
        "accuracy": if rows.is_empty() { 0.0 } else { correct as f64 / rows.len() as f64 },
        "macro_f1": macro_f1(&labels, &confusion),
        "confusion": confusion,
    })
}

fn macro_f1(
    labels: &BTreeSet<String>,
    confusion: &BTreeMap<String, BTreeMap<String, usize>>,
) -> f64 {
    if labels.is_empty() {
        return 0.0;
    }
    let mut total = 0.0;
    for label in labels {
        let tp = count(confusion, label, label) as f64;
        let fp = labels
            .iter()
            .filter(|expected| *expected != label)
            .map(|expected| count(confusion, expected, label))
            .sum::<usize>() as f64;
        let fn_ = labels
            .iter()
            .filter(|predicted| *predicted != label)
            .map(|predicted| count(confusion, label, predicted))
            .sum::<usize>() as f64;
        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        total += if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
    }
    total / labels.len() as f64
}

fn count(
    confusion: &BTreeMap<String, BTreeMap<String, usize>>,
    expected: &str,
    predicted: &str,
) -> usize {
    confusion
        .get(expected)
        .and_then(|row| row.get(predicted))
        .copied()
        .unwrap_or(0)
}

fn total_e2e_ms(observations: &[SpeedObservation]) -> f64 {
    observations
        .iter()
        .map(|observation| observation.e2e.as_secs_f64() * 1000.0)
        .sum()
}

fn total_l2_wall_ms(observations: &[SpeedObservation]) -> f64 {
    observations
        .iter()
        .map(|observation| observation.ntdb_l2_wall_ms)
        .sum()
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn latency_stats(latencies: &[Duration]) -> serde_json::Value {
    if latencies.is_empty() {
        return json!({"avg": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0});
    }
    let mut ms = latencies
        .iter()
        .map(|duration| duration.as_secs_f64() * 1000.0)
        .collect::<Vec<_>>();
    ms.sort_by(f64::total_cmp);
    f64_stats(&ms)
}

fn f64_stats(values: &[f64]) -> serde_json::Value {
    if values.is_empty() {
        return json!({"avg": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0});
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    json!({
        "avg": sorted.iter().sum::<f64>() / sorted.len() as f64,
        "p50": percentile(&sorted, 0.50),
        "p95": percentile(&sorted, 0.95),
        "max": *sorted.last().unwrap(),
    })
}

fn percentile(values: &[f64], pct: f64) -> f64 {
    let index = ((values.len() - 1) as f64 * pct).round() as usize;
    values[index]
}

fn dataset_name(dataset: DatasetKind) -> &'static str {
    match dataset {
        DatasetKind::Prompts => "tool_prompts",
        DatasetKind::Executions => "tool_executions",
        DatasetKind::Descriptions => "tool_descriptions",
    }
}
