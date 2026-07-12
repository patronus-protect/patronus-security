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

#[derive(Debug)]
struct Args {
    category: SecurityCategory,
    export_dir: PathBuf,
    l3_dir: Option<PathBuf>,
    max_level: SecurityLevel,
    operating_point: Option<String>,
    dataset: PathBuf,
    limit: usize,
    out_json: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Row {
    text: String,
    label: serde_json::Value,
}

#[derive(Debug)]
struct Prediction {
    expected: String,
    l2_predicted: String,
    predicted: String,
    latency: Duration,
    l2_result: bool,
    missing_result: bool,
    error_result: bool,
    promoted_result: bool,
    l3_pending_result: bool,
    l3_result: bool,
    l3_worker_result: bool,
    degraded_timeout_result: bool,
    degraded_error_result: bool,
    error_message: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    configure_ntdb_export(&args);
    let model_dir = std::env::temp_dir().join("patronus_ntdb_subset_smoke_assets");
    prepare_l3_assets(&args, &model_dir)?;

    let mut scanner = SecurityGateway::with_max_level(
        vec![args.category],
        args.max_level,
        Some(model_dir),
        false,
    );
    if let Some(operating_point) = &args.operating_point {
        scanner.set_ntdb_operating_point(operating_point.parse::<NtdbOperatingPoint>()?);
    }
    let warmup_started = Instant::now();
    scanner.warmup()?;
    let warmup_ms = warmup_started.elapsed().as_secs_f64() * 1000.0;

    let rows = load_rows(&args.dataset, args.limit)?;
    let mut predictions = Vec::with_capacity(rows.len());
    for row in rows {
        let expected = normalize_label(args.category, &row.label);
        let started = Instant::now();
        let results = scan_via_security_queue(&scanner, args.category, &row.text)?;
        let latency = started.elapsed();
        let public_results = results
            .iter()
            .filter(|result| result.model == public_model(args.category))
            .collect::<Vec<_>>();
        let first_public = public_results.first().copied();
        let final_public = public_results.last().copied();
        let l2_predicted = public_results
            .iter()
            .find(|result| result.level == "L2")
            .map(|result| result.class_name.clone())
            .unwrap_or_else(|| "missing".to_string());
        let predicted = final_public
            .map(|result| result.class_name.clone())
            .unwrap_or_else(|| "missing".to_string());
        let l2_result = first_public.is_some_and(|result| result.level == "L2");
        let error_result = any_layer(&public_results, "ntdb_error");
        let promoted_result = public_results.iter().any(|result| {
            result.layers.iter().any(|layer| {
                layer.layer_type == "ntdb_l2"
                    && layer
                        .details
                        .get("route_to_l3")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false)
            })
        });
        let l3_pending_result = any_layer(&public_results, "l3_pending");
        let l3_result = final_public.is_some_and(|result| result.level == "L3");
        let l3_worker_result = public_results.iter().any(|result| {
            result.layers.iter().any(|layer| {
                layer.level == "L3"
                    && layer.details.get("l3_worker") == Some(&serde_json::json!("rust_l3_worker"))
            })
        });
        let degraded_timeout_result = any_layer(&public_results, "degraded_timeout");
        let degraded_error_result = any_layer(&public_results, "degraded_error");
        let error_message = public_results.iter().find_map(|result| {
            result.layers.iter().find_map(|layer| {
                layer
                    .details
                    .get("error")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
        });
        predictions.push(Prediction {
            expected,
            l2_predicted,
            predicted,
            latency,
            l2_result,
            missing_result: final_public.is_none(),
            error_result,
            promoted_result,
            l3_pending_result,
            l3_result,
            l3_worker_result,
            degraded_timeout_result,
            degraded_error_result,
            error_message,
        });
    }

    let report = report(&args, &predictions, warmup_ms);
    if let Some(parent) = args.out_json.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.out_json, serde_json::to_string_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn scan_via_security_queue(
    scanner: &SecurityGateway,
    category: SecurityCategory,
    text: &str,
) -> Result<Vec<SecurityScanResult>, Box<dyn std::error::Error>> {
    let request_id = scanner.enqueue_categories(vec![category], text);
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
        if started.elapsed() > Duration::from_secs(180) {
            return Err(
                format!("timed out waiting for queued Security Lib request {request_id}").into(),
            );
        }
    }
    Ok(results)
}

fn any_layer(results: &[&SecurityScanResult], layer_type: &str) -> bool {
    results.iter().any(|result| {
        result
            .layers
            .iter()
            .any(|layer| layer.layer_type == layer_type)
    })
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut category = None;
    let mut export_dir = None;
    let mut l3_dir = None;
    let mut max_level = SecurityLevel::L2;
    let mut operating_point = None;
    let mut dataset = None;
    let mut limit = 100usize;
    let mut out_json = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--category" => {
                category = Some(args.next().ok_or("missing --category value")?.parse()?)
            }
            "--export-dir" => {
                export_dir = Some(PathBuf::from(
                    args.next().ok_or("missing --export-dir value")?,
                ))
            }
            "--l3-dir" => {
                l3_dir = Some(PathBuf::from(args.next().ok_or("missing --l3-dir value")?))
            }
            "--max-level" => {
                max_level = match args.next().ok_or("missing --max-level value")?.as_str() {
                    "L2" | "l2" => SecurityLevel::L2,
                    "L3" | "l3" => SecurityLevel::L3,
                    other => return Err(format!("unsupported --max-level value: {other}").into()),
                }
            }
            "--operating-point" => {
                operating_point = Some(args.next().ok_or("missing --operating-point value")?)
            }
            "--dataset" => {
                dataset = Some(PathBuf::from(args.next().ok_or("missing --dataset value")?))
            }
            "--limit" => limit = args.next().ok_or("missing --limit value")?.parse()?,
            "--out-json" => {
                out_json = Some(PathBuf::from(
                    args.next().ok_or("missing --out-json value")?,
                ))
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(Args {
        category: category.ok_or("missing --category")?,
        export_dir: export_dir.ok_or("missing --export-dir")?,
        l3_dir,
        max_level,
        operating_point,
        dataset: dataset.ok_or("missing --dataset")?,
        limit,
        out_json: out_json.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("benchmarks/ntdb_l2_subset_smoke_results.json")
        }),
    })
}

fn configure_ntdb_export(args: &Args) {
    match args.category {
        SecurityCategory::Injection => {
            std::env::set_var("PATRONUS_NTDB_INJECTION_DIR", &args.export_dir);
        }
        SecurityCategory::SensitiveDocuments => {
            std::env::set_var("PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR", &args.export_dir);
        }
        _ => {}
    }
}

fn prepare_l3_assets(args: &Args, model_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let Some(l3_dir) = &args.l3_dir else {
        return Ok(());
    };
    let target_dir = match args.category {
        SecurityCategory::Injection => model_dir.join("injection"),
        SecurityCategory::SensitiveDocuments => {
            model_dir.join("sensitive_documents").join("prompts")
        }
        _ => return Ok(()),
    };
    fs::create_dir_all(target_dir.join("onnx"))?;
    link_or_copy(
        &l3_dir.join("tokenizer.json"),
        &target_dir.join("tokenizer.json"),
    )?;
    if l3_dir.join("tokenizer_config.json").exists() {
        link_or_copy(
            &l3_dir.join("tokenizer_config.json"),
            &target_dir.join("tokenizer_config.json"),
        )?;
    }
    if l3_dir.join("special_tokens_map.json").exists() {
        link_or_copy(
            &l3_dir.join("special_tokens_map.json"),
            &target_dir.join("special_tokens_map.json"),
        )?;
    }
    link_or_copy(
        &l3_dir.join("model_fp16.onnx"),
        &target_dir.join("onnx").join("model_fp16.onnx"),
    )?;
    Ok(())
}

fn link_or_copy(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if destination.exists() {
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

fn load_rows(path: &PathBuf, limit: usize) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
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

fn public_model(category: SecurityCategory) -> &'static str {
    match category {
        SecurityCategory::Injection => "wolf-defender-small",
        SecurityCategory::SensitiveDocuments => "orca-sonar-document-classifier",
        _ => "",
    }
}

fn normalize_label(category: SecurityCategory, label: &serde_json::Value) -> String {
    let raw = label
        .as_str()
        .map(str::to_string)
        .or_else(|| label.as_i64().map(|value| value.to_string()))
        .unwrap_or_else(|| label.to_string());
    match category {
        SecurityCategory::SensitiveDocuments => match raw.as_str() {
            "0" => "finance",
            "1" => "hr",
            "2" => "internal_and_tech",
            "3" => "legal",
            "4" => "marketing",
            "5" => "other",
            "6" => "source_code",
            other => other,
        }
        .to_string(),
        SecurityCategory::Injection => match raw.as_str() {
            "0" => "benign",
            "1" => "attack",
            other => other,
        }
        .to_string(),
        _ => raw,
    }
}

fn report(args: &Args, predictions: &[Prediction], warmup_ms: f64) -> serde_json::Value {
    let mut labels = BTreeSet::new();
    let mut confusion = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut l2_confusion = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut correct = 0usize;
    let mut l2_correct = 0usize;
    let mut l2_results = 0usize;
    let mut missing = 0usize;
    let mut errors = 0usize;
    let mut promoted = 0usize;
    let mut l3_pending = 0usize;
    let mut l3_results = 0usize;
    let mut l3_worker_results = 0usize;
    let mut degraded_timeouts = 0usize;
    let mut degraded_errors = 0usize;
    let mut error_messages = BTreeMap::<String, usize>::new();
    for prediction in predictions {
        labels.insert(prediction.expected.clone());
        labels.insert(prediction.l2_predicted.clone());
        labels.insert(prediction.predicted.clone());
        *confusion
            .entry(prediction.expected.clone())
            .or_default()
            .entry(prediction.predicted.clone())
            .or_default() += 1;
        *l2_confusion
            .entry(prediction.expected.clone())
            .or_default()
            .entry(prediction.l2_predicted.clone())
            .or_default() += 1;
        correct += usize::from(prediction.expected == prediction.predicted);
        l2_correct += usize::from(prediction.expected == prediction.l2_predicted);
        l2_results += usize::from(prediction.l2_result);
        missing += usize::from(prediction.missing_result);
        errors += usize::from(prediction.error_result);
        promoted += usize::from(prediction.promoted_result);
        l3_pending += usize::from(prediction.l3_pending_result);
        l3_results += usize::from(prediction.l3_result);
        l3_worker_results += usize::from(prediction.l3_worker_result);
        degraded_timeouts += usize::from(prediction.degraded_timeout_result);
        degraded_errors += usize::from(prediction.degraded_error_result);
        if let Some(message) = &prediction.error_message {
            *error_messages.entry(message.clone()).or_default() += 1;
        }
    }
    let latencies = predictions
        .iter()
        .map(|prediction| prediction.latency)
        .collect::<Vec<_>>();

    json!({
        "generated_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "category": args.category.as_str(),
        "model": public_model(args.category),
        "max_level": format!("{:?}", args.max_level),
        "operating_point": args.operating_point,
        "export_dir": args.export_dir,
        "l3_dir": args.l3_dir,
        "dataset": args.dataset,
        "limit": args.limit,
        "samples": predictions.len(),
        "warmup_ms": warmup_ms,
        "accuracy": if predictions.is_empty() { 0.0 } else { correct as f64 / predictions.len() as f64 },
        "macro_f1": macro_f1(&labels, &confusion),
        "l2_accuracy": if predictions.is_empty() { 0.0 } else { l2_correct as f64 / predictions.len() as f64 },
        "l2_macro_f1": macro_f1(&labels, &l2_confusion),
        "l2_results": l2_results,
        "missing_results": missing,
        "error_results": errors,
        "promoted_results": promoted,
        "l3_pending_results": l3_pending,
        "l3_results": l3_results,
        "l3_worker_results": l3_worker_results,
        "degraded_timeout_results": degraded_timeouts,
        "degraded_error_results": degraded_errors,
        "error_messages": error_messages,
        "latency_ms": latency_stats(&latencies),
        "l2_confusion": l2_confusion,
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
    if latencies.is_empty() {
        return json!({"avg": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0});
    }
    let mut ms = latencies
        .iter()
        .map(|duration| duration.as_secs_f64() * 1000.0)
        .collect::<Vec<_>>();
    ms.sort_by(f64::total_cmp);
    json!({
        "avg": ms.iter().sum::<f64>() / ms.len() as f64,
        "p50": percentile(&ms, 0.50),
        "p95": percentile(&ms, 0.95),
        "max": *ms.last().unwrap(),
    })
}

fn percentile(values: &[f64], pct: f64) -> f64 {
    let index = ((values.len() - 1) as f64 * pct).round() as usize;
    values[index]
}
