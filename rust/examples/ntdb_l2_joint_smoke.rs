use patronus_security::{
    NtdbOperatingPoint, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const INJECTION_MODEL: &str = "wolf-defender-small";
const SENSITIVE_MODEL: &str = "orca-sonar-document-classifier";

#[derive(Debug)]
struct Args {
    injection_export_dir: PathBuf,
    sensitive_export_dir: PathBuf,
    injection_l3_dir: PathBuf,
    sensitive_l3_dir: PathBuf,
    injection_dataset: PathBuf,
    sensitive_dataset: PathBuf,
    limit: usize,
    operating_point: String,
    out_json: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Row {
    text: String,
    label: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatasetKind {
    Injection,
    Sensitive,
}

#[derive(Debug, Clone)]
struct Sample {
    dataset: DatasetKind,
    dataset_index: usize,
    text: String,
    injection_expected: Option<String>,
    sensitive_expected: Option<String>,
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
    l2_predicted: String,
    predicted: String,
    l2_result: bool,
    promoted_result: bool,
    l3_pending_result: bool,
    l3_result: bool,
    l3_worker_result: bool,
    degraded_timeout_result: bool,
    degraded_error_result: bool,
    error_result: bool,
    missing_result: bool,
    error_message: Option<String>,
}

#[derive(Debug)]
struct L3Observation {
    dataset: DatasetKind,
    dataset_index: usize,
    text: String,
    injection_expected: Option<String>,
    sensitive_expected: Option<String>,
    injection: ModelOutcome,
    sensitive: ModelOutcome,
    latency: Duration,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    configure_ntdb_exports(&args);
    let operating_point = args.operating_point.parse::<NtdbOperatingPoint>()?;

    let model_dir = std::env::temp_dir().join("patronus_ntdb_joint_smoke_assets");
    prepare_l3_assets(&args, &model_dir)?;

    let injection_rows = load_rows(&args.injection_dataset, args.limit)?;
    let sensitive_rows = load_rows(&args.sensitive_dataset, args.limit)?;
    let samples = samples_from_rows(&injection_rows, &sensitive_rows);

    let joint_l2 = measure_joint_l2(&model_dir, &samples, operating_point)?;
    let sequential_l2 = measure_sequential_l2(&model_dir, &samples, operating_point)?;
    let l3 = measure_joint_l3(&model_dir, &samples, operating_point)?;

    let report = report(&args, &samples, &joint_l2, &sequential_l2, &l3);
    if let Some(parent) = args.out_json.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.out_json, serde_json::to_string_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn measure_joint_l2(
    model_dir: &Path,
    samples: &[Sample],
    operating_point: NtdbOperatingPoint,
) -> Result<Vec<SpeedObservation>, Box<dyn std::error::Error>> {
    let mut scanner = scanner(SecurityLevel::L2, model_dir, operating_point);
    scanner.warmup()?;
    let _ = scanner.scan_categories(
        &[
            SecurityCategory::Injection,
            SecurityCategory::SensitiveDocuments,
        ],
        "neutral warmup text for NTDB L2",
    );

    let mut observations = Vec::with_capacity(samples.len());
    for sample in samples {
        let started = Instant::now();
        let results = scanner.scan_categories(
            &[
                SecurityCategory::Injection,
                SecurityCategory::SensitiveDocuments,
            ],
            &sample.text,
        );
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
    let _ = scanner.scan_categories(
        &[SecurityCategory::Injection],
        "neutral warmup text for NTDB L2",
    );
    let _ = scanner.scan_categories(
        &[SecurityCategory::SensitiveDocuments],
        "neutral warmup text for NTDB L2",
    );

    let mut observations = Vec::with_capacity(samples.len());
    for sample in samples {
        let started = Instant::now();
        let injection_results =
            scanner.scan_categories(&[SecurityCategory::Injection], &sample.text);
        let sensitive_results =
            scanner.scan_categories(&[SecurityCategory::SensitiveDocuments], &sample.text);
        let e2e = started.elapsed();
        observations.push(SpeedObservation {
            e2e,
            ntdb_l2_wall_ms: ntdb_l2_wall_ms(&injection_results)
                + ntdb_l2_wall_ms(&sensitive_results),
            public_l2_results: public_l2_results(&injection_results)
                + public_l2_results(&sensitive_results),
            error_results: public_error_results(&injection_results)
                + public_error_results(&sensitive_results),
        });
    }
    Ok(observations)
}

fn measure_joint_l3(
    model_dir: &Path,
    samples: &[Sample],
    operating_point: NtdbOperatingPoint,
) -> Result<Vec<L3Observation>, Box<dyn std::error::Error>> {
    let mut scanner = scanner(SecurityLevel::L3, model_dir, operating_point);
    scanner.warmup()?;
    let mut observations = Vec::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        eprintln!(
            "[joint-smoke] L3 sample {}/{} start dataset={}",
            index + 1,
            samples.len(),
            dataset_name(sample.dataset)
        );
        let started = Instant::now();
        let results = scan_via_security_queue(
            &scanner,
            &[
                SecurityCategory::Injection,
                SecurityCategory::SensitiveDocuments,
            ],
            &sample.text,
        )?;
        let latency = started.elapsed();
        let injection = model_outcome(&results, INJECTION_MODEL);
        let sensitive = model_outcome(&results, SENSITIVE_MODEL);
        eprintln!(
            "[joint-smoke] L3 sample {}/{} done latency_ms={:.2} injection={} promoted={} l3_worker={} error={:?} sensitive={} promoted={} l3_worker={} error={:?}",
            index + 1,
            samples.len(),
            latency.as_secs_f64() * 1000.0,
            injection.predicted,
            injection.promoted_result,
            injection.l3_worker_result,
            injection.error_message.as_deref(),
            sensitive.predicted,
            sensitive.promoted_result,
            sensitive.l3_worker_result,
            sensitive.error_message.as_deref()
        );
        observations.push(L3Observation {
            dataset: sample.dataset,
            dataset_index: sample.dataset_index,
            text: sample.text.clone(),
            injection_expected: sample.injection_expected.clone(),
            sensitive_expected: sample.sensitive_expected.clone(),
            injection,
            sensitive,
            latency,
        });
    }
    Ok(observations)
}

fn dataset_name(dataset: DatasetKind) -> &'static str {
    match dataset {
        DatasetKind::Injection => "injection",
        DatasetKind::Sensitive => "sensitive_documents",
    }
}

fn scanner(
    level: SecurityLevel,
    model_dir: &Path,
    operating_point: NtdbOperatingPoint,
) -> SecurityGateway {
    let scanner = SecurityGateway::with_max_level(
        vec![
            SecurityCategory::Injection,
            SecurityCategory::SensitiveDocuments,
        ],
        level,
        Some(model_dir.to_path_buf()),
        false,
    );
    scanner.set_ntdb_operating_point(operating_point);
    scanner
}

fn scan_via_security_queue(
    scanner: &SecurityGateway,
    categories: &[SecurityCategory],
    text: &str,
) -> Result<Vec<SecurityScanResult>, Box<dyn std::error::Error>> {
    let request_id = scanner.enqueue_categories(categories.to_vec(), text);
    let mut results = Vec::new();
    let started = Instant::now();
    loop {
        if let Some(queued) = scanner.consume_next_result(Some(Duration::from_secs(30))) {
            if queued.request_id != request_id {
                return Err(format!(
                    "received result for unexpected request {}",
                    queued.request_id
                )
                .into());
            }
            results.push(queued.result);
            continue;
        }
        if !scanner.has_request(&request_id) {
            break;
        }
        if started.elapsed() > Duration::from_secs(300) {
            return Err(format!("timed out waiting for queued request {request_id}").into());
        }
    }
    Ok(results)
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut injection_export_dir = None;
    let mut sensitive_export_dir = None;
    let mut injection_l3_dir = None;
    let mut sensitive_l3_dir = None;
    let mut injection_dataset = None;
    let mut sensitive_dataset = None;
    let mut limit = 100usize;
    let mut operating_point = "best_latency_in_f1".to_string();
    let mut out_json = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--injection-export-dir" => {
                injection_export_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --injection-export-dir value")?,
                ))
            }
            "--sensitive-export-dir" => {
                sensitive_export_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --sensitive-export-dir value")?,
                ))
            }
            "--injection-l3-dir" => {
                injection_l3_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --injection-l3-dir value")?,
                ))
            }
            "--sensitive-l3-dir" => {
                sensitive_l3_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --sensitive-l3-dir value")?,
                ))
            }
            "--injection-dataset" => {
                injection_dataset = Some(PathBuf::from(
                    args.next().ok_or("missing --injection-dataset value")?,
                ))
            }
            "--sensitive-dataset" => {
                sensitive_dataset = Some(PathBuf::from(
                    args.next().ok_or("missing --sensitive-dataset value")?,
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
        injection_export_dir: injection_export_dir.ok_or("missing --injection-export-dir")?,
        sensitive_export_dir: sensitive_export_dir.ok_or("missing --sensitive-export-dir")?,
        injection_l3_dir: injection_l3_dir.ok_or("missing --injection-l3-dir")?,
        sensitive_l3_dir: sensitive_l3_dir.ok_or("missing --sensitive-l3-dir")?,
        injection_dataset: injection_dataset.ok_or("missing --injection-dataset")?,
        sensitive_dataset: sensitive_dataset.ok_or("missing --sensitive-dataset")?,
        limit,
        operating_point,
        out_json: out_json.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("benchmarks/ntdb_l2_joint_smoke_results.json")
        }),
    })
}

fn configure_ntdb_exports(args: &Args) {
    std::env::set_var("PATRONUS_NTDB_INJECTION_DIR", &args.injection_export_dir);
    std::env::set_var(
        "PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR",
        &args.sensitive_export_dir,
    );
}

fn prepare_l3_assets(args: &Args, model_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    prepare_l3_asset_layout(
        &args.injection_l3_dir,
        &model_dir.join("injection").join("l3"),
        &[
            "onnx/onnx_fp16/model_fp16.onnx",
            "onnx/onnx_fp16/model.onnx",
        ],
    )?;
    prepare_l3_asset_layout(
        &args.sensitive_l3_dir,
        &model_dir.join("sensitive_documents").join("prompts"),
        &["onnx/model_fp16.onnx", "onnx/model.onnx"],
    )?;
    Ok(())
}

fn prepare_l3_asset_layout(
    source_dir: &Path,
    target_dir: &Path,
    target_model_candidates: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(target_dir)?;
    let tokenizer = source_dir.join("tokenizer.json");
    if !tokenizer.exists() {
        return Err(format!("missing tokenizer.json in {}", source_dir.display()).into());
    }
    link_or_copy(&tokenizer, &target_dir.join("tokenizer.json"))?;
    for file_name in [
        "tokenizer_config.json",
        "special_tokens_map.json",
        "config.json",
    ] {
        let source = source_dir.join(file_name);
        if source.exists() {
            link_or_copy(&source, &target_dir.join(file_name))?;
        }
    }

    let model = find_model_file(source_dir).ok_or_else(|| {
        format!(
            "missing ONNX model in {}; expected model_fp16.onnx/model.onnx or onnx/*",
            source_dir.display()
        )
    })?;
    let target_model = target_dir.join(target_model_candidates[0]);
    if let Some(parent) = target_model.parent() {
        fs::create_dir_all(parent)?;
    }
    link_or_copy(&model, &target_model)?;
    Ok(())
}

fn find_model_file(source_dir: &Path) -> Option<PathBuf> {
    [
        "model_fp16.onnx",
        "model.onnx",
        "onnx/onnx_fp16/model_fp16.onnx",
        "onnx/onnx_fp16/model.onnx",
        "onnx/model_fp16.onnx",
        "onnx/model.onnx",
    ]
    .iter()
    .map(|candidate| source_dir.join(candidate))
    .find(|candidate| candidate.exists())
}

fn link_or_copy(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if fs::symlink_metadata(destination).is_ok() {
        fs::remove_file(destination)?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(source, destination)?;
    }
    #[cfg(not(unix))]
    {
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn load_rows(path: &Path, limit: usize) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for (line_index, line) in fs::read_to_string(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: Row = serde_json::from_str(line)
            .map_err(|err| format!("failed to parse JSONL line {}: {err}", line_index + 1))?;
        rows.push(row);
        if rows.len() >= limit {
            break;
        }
    }
    Ok(rows)
}

fn samples_from_rows(injection_rows: &[Row], sensitive_rows: &[Row]) -> Vec<Sample> {
    let mut samples = Vec::with_capacity(injection_rows.len() + sensitive_rows.len());
    samples.extend(
        injection_rows
            .iter()
            .enumerate()
            .map(|(index, row)| Sample {
                dataset: DatasetKind::Injection,
                dataset_index: index,
                text: row.text.clone(),
                injection_expected: Some(normalize_injection_label(&row.label)),
                sensitive_expected: None,
            }),
    );
    samples.extend(
        sensitive_rows
            .iter()
            .enumerate()
            .map(|(index, row)| Sample {
                dataset: DatasetKind::Sensitive,
                dataset_index: index,
                text: row.text.clone(),
                injection_expected: None,
                sensitive_expected: Some(normalize_sensitive_label(&row.label)),
            }),
    );
    samples
}

fn normalize_injection_label(label: &serde_json::Value) -> String {
    let raw = raw_label(label);
    match raw.as_str() {
        "0" => "benign",
        "1" => "attack",
        other => other,
    }
    .to_string()
}

fn normalize_sensitive_label(label: &serde_json::Value) -> String {
    let raw = raw_label(label);
    match raw.as_str() {
        "0" => "finance",
        "1" => "hr",
        "2" => "internal_and_tech",
        "3" => "legal",
        "4" => "marketing",
        "5" => "other",
        "6" => "source_code",
        other => other,
    }
    .to_string()
}

fn raw_label(label: &serde_json::Value) -> String {
    label
        .as_str()
        .map(str::to_string)
        .or_else(|| label.as_i64().map(|value| value.to_string()))
        .unwrap_or_else(|| label.to_string())
}

fn model_outcome(results: &[SecurityScanResult], model: &str) -> ModelOutcome {
    let public_results = results
        .iter()
        .filter(|result| result.model == model)
        .collect::<Vec<_>>();
    let l2_predicted = public_results
        .iter()
        .find(|result| result.level == "L2")
        .map(|result| result.class_name.clone())
        .unwrap_or_else(|| "missing".to_string());
    let predicted = public_results
        .last()
        .map(|result| result.class_name.clone())
        .unwrap_or_else(|| "missing".to_string());

    ModelOutcome {
        l2_result: public_results.iter().any(|result| result.level == "L2"),
        promoted_result: public_results.iter().any(|result| {
            result.layers.iter().any(|layer| {
                layer.layer_type == "ntdb_l2"
                    && layer
                        .details
                        .get("route_to_l3")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false)
            })
        }),
        l3_pending_result: any_layer(&public_results, "l3_pending"),
        l3_result: public_results.iter().any(|result| result.level == "L3"),
        l3_worker_result: public_results.iter().any(|result| {
            result.layers.iter().any(|layer| {
                layer.level == "L3"
                    && layer.details.get("l3_worker") == Some(&serde_json::json!("rust_l3_worker"))
            })
        }),
        degraded_timeout_result: any_layer(&public_results, "degraded_timeout"),
        degraded_error_result: any_layer(&public_results, "degraded_error"),
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
        l2_predicted,
        predicted,
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
        .filter(|result| result.model == INJECTION_MODEL || result.model == SENSITIVE_MODEL)
        .flat_map(|result| result.layers.iter())
        .filter(|layer| layer.layer_type == "ntdb_l2")
        .map(|layer| layer.duration_ms)
        .fold(0.0, f64::max)
}

fn public_l2_results(results: &[SecurityScanResult]) -> usize {
    results
        .iter()
        .filter(|result| {
            (result.model == INJECTION_MODEL || result.model == SENSITIVE_MODEL)
                && result.level == "L2"
        })
        .count()
}

fn public_error_results(results: &[SecurityScanResult]) -> usize {
    results
        .iter()
        .filter(|result| result.model == INJECTION_MODEL || result.model == SENSITIVE_MODEL)
        .filter(|result| {
            result
                .layers
                .iter()
                .any(|layer| layer.layer_type == "ntdb_error")
        })
        .count()
}

fn report(
    args: &Args,
    samples: &[Sample],
    joint_l2: &[SpeedObservation],
    sequential_l2: &[SpeedObservation],
    l3: &[L3Observation],
) -> serde_json::Value {
    let injection_relevant = l3
        .iter()
        .filter_map(|observation| {
            observation
                .injection_expected
                .as_ref()
                .map(|expected| (expected.clone(), observation.injection.predicted.clone()))
        })
        .collect::<Vec<_>>();
    let sensitive_relevant = l3
        .iter()
        .filter_map(|observation| {
            observation
                .sensitive_expected
                .as_ref()
                .map(|expected| (expected.clone(), observation.sensitive.predicted.clone()))
        })
        .collect::<Vec<_>>();

    json!({
        "generated_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "operating_point": args.operating_point,
        "operating_point_note": "The configured point is applied to every loaded export that defines it; the loader falls back to best_f1 otherwise.",
        "exports": {
            "injection": args.injection_export_dir,
            "sensitive_documents": args.sensitive_export_dir,
        },
        "l3_dirs": {
            "injection": args.injection_l3_dir,
            "sensitive_documents": args.sensitive_l3_dir,
        },
        "datasets": {
            "injection": {
                "path": args.injection_dataset,
                "samples": samples.iter().filter(|sample| sample.dataset == DatasetKind::Injection).count(),
            },
            "sensitive_documents": {
                "path": args.sensitive_dataset,
                "samples": samples.iter().filter(|sample| sample.dataset == DatasetKind::Sensitive).count(),
            },
        },
        "l2_speed": {
            "joint": speed_report(joint_l2),
            "sequential": speed_report(sequential_l2),
            "speedup_e2e_total": ratio(total_e2e_ms(sequential_l2), total_e2e_ms(joint_l2)),
            "speedup_ntdb_l2_wall_total": ratio(total_l2_wall_ms(sequential_l2), total_l2_wall_ms(joint_l2)),
        },
        "l3": {
            "latency_ms": latency_stats(&l3.iter().map(|observation| observation.latency).collect::<Vec<_>>()),
            "injection": outcome_counts(l3.iter().map(|observation| &observation.injection)),
            "sensitive_documents": outcome_counts(l3.iter().map(|observation| &observation.sensitive)),
        },
        "relevant_metrics": {
            "injection_on_injection_dataset": classification_report(&injection_relevant),
            "sensitive_on_sensitive_dataset": classification_report(&sensitive_relevant),
        },
        "irrelevant_fpr": irrelevant_fpr_report(l3),
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

fn outcome_counts<'a>(outcomes: impl Iterator<Item = &'a ModelOutcome>) -> serde_json::Value {
    let mut total = 0usize;
    let mut l2_results = 0usize;
    let mut promoted_results = 0usize;
    let mut l3_pending_results = 0usize;
    let mut l3_results = 0usize;
    let mut l3_worker_results = 0usize;
    let mut degraded_timeout_results = 0usize;
    let mut degraded_error_results = 0usize;
    let mut error_results = 0usize;
    let mut missing_results = 0usize;
    let mut error_messages = BTreeMap::<String, usize>::new();
    for outcome in outcomes {
        total += 1;
        l2_results += usize::from(outcome.l2_result);
        promoted_results += usize::from(outcome.promoted_result);
        l3_pending_results += usize::from(outcome.l3_pending_result);
        l3_results += usize::from(outcome.l3_result);
        l3_worker_results += usize::from(outcome.l3_worker_result);
        degraded_timeout_results += usize::from(outcome.degraded_timeout_result);
        degraded_error_results += usize::from(outcome.degraded_error_result);
        error_results += usize::from(outcome.error_result);
        missing_results += usize::from(outcome.missing_result);
        if let Some(message) = &outcome.error_message {
            *error_messages.entry(message.clone()).or_default() += 1;
        }
    }
    json!({
        "samples": total,
        "l2_results": l2_results,
        "promoted_results": promoted_results,
        "l3_pending_results": l3_pending_results,
        "l3_results": l3_results,
        "l3_worker_results": l3_worker_results,
        "degraded_timeout_results": degraded_timeout_results,
        "degraded_error_results": degraded_error_results,
        "error_results": error_results,
        "missing_results": missing_results,
        "error_messages": error_messages,
    })
}

fn irrelevant_fpr_report(l3: &[L3Observation]) -> serde_json::Value {
    let sensitive_rows = l3
        .iter()
        .filter(|observation| observation.dataset == DatasetKind::Sensitive)
        .collect::<Vec<_>>();
    let injection_rows = l3
        .iter()
        .filter(|observation| observation.dataset == DatasetKind::Injection)
        .collect::<Vec<_>>();

    let injection_on_sensitive_final = sensitive_rows
        .iter()
        .filter(|observation| observation.injection.predicted == "attack")
        .count();
    let injection_on_sensitive_l2 = sensitive_rows
        .iter()
        .filter(|observation| observation.injection.l2_predicted == "attack")
        .count();
    let sensitive_on_injection_final = injection_rows
        .iter()
        .filter(|observation| observation.sensitive.predicted != "other")
        .count();
    let sensitive_on_injection_l2 = injection_rows
        .iter()
        .filter(|observation| observation.sensitive.l2_predicted != "other")
        .count();

    json!({
        "definition": {
            "injection_on_sensitive": "positive when final injection class is attack",
            "sensitive_on_injection": "positive when final sensitive_documents class is not other",
        },
        "injection_on_sensitive_dataset": {
            "samples": sensitive_rows.len(),
            "false_positives_final": injection_on_sensitive_final,
            "fpr_final": rate(injection_on_sensitive_final, sensitive_rows.len()),
            "false_positives_l2": injection_on_sensitive_l2,
            "fpr_l2": rate(injection_on_sensitive_l2, sensitive_rows.len()),
            "examples": sensitive_rows
                .iter()
                .filter(|observation| observation.injection.predicted == "attack")
                .map(|observation| json!({
                    "dataset_index": observation.dataset_index,
                    "true_sensitive_class": observation.sensitive_expected.as_deref(),
                    "injection_l2_class": observation.injection.l2_predicted.as_str(),
                    "injection_final_class": observation.injection.predicted.as_str(),
                    "text": observation.text.as_str(),
                }))
                .collect::<Vec<_>>(),
        },
        "sensitive_on_injection_dataset": {
            "samples": injection_rows.len(),
            "false_positives_final": sensitive_on_injection_final,
            "fpr_final": rate(sensitive_on_injection_final, injection_rows.len()),
            "false_positives_l2": sensitive_on_injection_l2,
            "fpr_l2": rate(sensitive_on_injection_l2, injection_rows.len()),
            "examples": injection_rows
                .iter()
                .filter(|observation| observation.sensitive.predicted != "other")
                .map(|observation| json!({
                    "dataset_index": observation.dataset_index,
                    "true_injection_class": observation.injection_expected.as_deref(),
                    "sensitive_l2_class": observation.sensitive.l2_predicted.as_str(),
                    "sensitive_final_class": observation.sensitive.predicted.as_str(),
                    "text": observation.text.as_str(),
                }))
                .collect::<Vec<_>>(),
        },
    })
}

fn classification_report(pairs: &[(String, String)]) -> serde_json::Value {
    let mut labels = BTreeSet::new();
    let mut confusion = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut correct = 0usize;
    for (expected, predicted) in pairs {
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
        "samples": pairs.len(),
        "accuracy": rate(correct, pairs.len()),
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

fn latency_stats(latencies: &[Duration]) -> serde_json::Value {
    let ms = latencies
        .iter()
        .map(|duration| duration.as_secs_f64() * 1000.0)
        .collect::<Vec<_>>();
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
        return 0.0;
    }
    numerator / denominator
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}
