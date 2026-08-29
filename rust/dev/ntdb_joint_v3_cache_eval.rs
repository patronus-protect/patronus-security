use patronus_ark::{ml::ntdb_executor::NtdbExecutor, NtdbOperatingPoint};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Deserialize)]
struct Row {
    text: String,
    label: usize,
    /// One L3 probability vector per L2 chunk. Unpromoted rows are ignored.
    l3_scores: Vec<Vec<f32>>,
    expected_l2_scores: Vec<Vec<f32>>,
    expected_promote_scores: Vec<f32>,
    expected_prediction: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let model_id = args.next().ok_or(
        "usage: ntdb_joint_v3_cache_eval <model-id> <package> <rows.jsonl> [operating-point]",
    )?;
    let package = args.next().ok_or("missing package")?;
    let rows_path = args.next().ok_or("missing rows.jsonl")?;
    let point = args
        .next()
        .as_deref()
        .unwrap_or("best_f1")
        .parse::<NtdbOperatingPoint>()?;
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(Path::new(&package).join("manifest.json"))?
            .replace("Infinity", "null")
            .replace("NaN", "null"),
    )?;
    let labels = manifest
        .pointer("/task/labels")
        .and_then(Value::as_array)
        .ok_or("manifest task labels missing")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    let default_index = manifest
        .pointer("/task/no_risk_class")
        .and_then(Value::as_str)
        .and_then(|label| labels.iter().position(|candidate| candidate == label))
        .unwrap_or(0);
    let rows = BufReader::new(File::open(rows_path)?)
        .lines()
        .map(|line| Ok(serde_json::from_str::<Row>(&line?)?))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;
    let mut executor = NtdbExecutor::load([(model_id, Path::new(&package))])?;
    let mut confusion = vec![vec![0_u64; labels.len()]; labels.len()];
    let mut promoted = 0_u64;
    let mut total_chunks = 0_u64;
    let mut promoter_mask_mismatches = 0_u64;
    let mut max_l2_abs_difference = 0.0_f32;
    let mut max_promoter_abs_difference = 0.0_f32;
    let mut final_prediction_mismatches = 0_u64;

    for batch in rows.chunks(128) {
        let texts = batch.iter().map(|row| row.text.clone()).collect::<Vec<_>>();
        for (row, decisions) in batch.iter().zip(executor.score_all_batch(&texts, point)?) {
            let decision = decisions
                .into_iter()
                .next()
                .ok_or("NTDB returned no decision")?;
            if row.l3_scores.len() != decision.l2_chunk_outputs.len() {
                return Err(format!(
                    "L3/L2 chunk count mismatch: {} != {}",
                    row.l3_scores.len(),
                    decision.l2_chunk_outputs.len()
                )
                .into());
            }
            for ((chunk, expected_l2), expected_promoter) in decision
                .l2_chunk_outputs
                .iter()
                .zip(&row.expected_l2_scores)
                .zip(&row.expected_promote_scores)
            {
                for (actual, expected) in chunk.class_probabilities.iter().zip(expected_l2) {
                    max_l2_abs_difference = max_l2_abs_difference.max((actual - expected).abs());
                }
                if let Some(actual) = chunk.promote_score {
                    max_promoter_abs_difference =
                        max_promoter_abs_difference.max((actual - expected_promoter).abs());
                }
                let threshold = chunk.promote_threshold.unwrap_or(f32::INFINITY);
                if chunk.promoted != (*expected_promoter >= threshold) {
                    promoter_mask_mismatches += 1;
                }
            }
            let l2_rows = decision
                .l2_chunk_outputs
                .iter()
                .map(|chunk| chunk.class_probabilities.clone())
                .collect::<Vec<_>>();
            let promoted_rows = decision
                .l2_chunk_outputs
                .iter()
                .zip(&row.l3_scores)
                .filter(|(chunk, _)| chunk.promoted)
                .map(|(_, scores)| scores.clone())
                .collect::<Vec<_>>();
            let union_rows = decision
                .l2_chunk_outputs
                .iter()
                .zip(&row.l3_scores)
                .map(|(chunk, l3)| {
                    if chunk.promoted {
                        l3.clone()
                    } else {
                        chunk.class_probabilities.clone()
                    }
                })
                .collect::<Vec<_>>();
            promoted += promoted_rows.len() as u64;
            total_chunks += l2_rows.len() as u64;

            let union = union_view(&manifest, point, &union_rows, default_index)?;
            let prediction = if union.accepted {
                union.risk_index
            } else {
                default_index
            };
            if prediction != row.expected_prediction {
                if final_prediction_mismatches < 5 {
                    eprintln!(
                        "final mismatch row={} ark={} export={} promoted_chunks={}",
                        confusion.iter().flatten().sum::<u64>(),
                        prediction,
                        row.expected_prediction,
                        promoted_rows.len()
                    );
                }
                final_prediction_mismatches += 1;
            }
            if row.label >= labels.len() {
                return Err("gold label out of range".into());
            }
            confusion[row.label][prediction] += 1;
        }
    }
    let macro_f1 = (0..labels.len())
        .map(|class| class_f1(&confusion, class))
        .sum::<f64>()
        / labels.len() as f64;
    println!(
        "{}",
        serde_json::json!({
            "rows": rows.len(), "labels": labels, "confusion_matrix": confusion,
            "macro_f1": macro_f1,
            "promotion_rate": promoted as f64 / total_chunks.max(1) as f64,
            "promoter_mask_mismatches": promoter_mask_mismatches,
            "max_l2_abs_difference": max_l2_abs_difference,
            "max_promoter_abs_difference": max_promoter_abs_difference,
            "final_prediction_mismatches": final_prediction_mismatches,
        })
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct View {
    risk_index: usize,
    accepted: bool,
}

fn view(
    manifest: &Value,
    mode: &str,
    point: NtdbOperatingPoint,
    rows: &[Vec<f32>],
    default: usize,
) -> Result<View, Box<dyn std::error::Error + Send + Sync>> {
    let profile = profile(point);
    let base = format!("/joint_v3/document_decision/modes/{mode}");
    let aggregation = manifest
        .pointer(&format!("{base}/aggregation"))
        .and_then(Value::as_str)
        .ok_or("aggregation missing")?;
    let threshold = manifest
        .pointer(&format!("{base}/operating_points/{profile}/threshold"))
        .or_else(|| {
            manifest.pointer(&format!(
                "{base}/operating_points/{profile}/document_risk_margin_threshold"
            ))
        })
        .and_then(Value::as_f64)
        .ok_or("document threshold missing")? as f32;
    scored_view(rows, aggregation, threshold, default)
}

fn union_view(
    manifest: &Value,
    point: NtdbOperatingPoint,
    rows: &[Vec<f32>],
    default: usize,
) -> Result<View, Box<dyn std::error::Error + Send + Sync>> {
    if matches!(
        point,
        NtdbOperatingPoint::BestF1 | NtdbOperatingPoint::BestPromote
    ) {
        let name = if point == NtdbOperatingPoint::BestPromote {
            "best_promote"
        } else {
            "utility_promote"
        };
        let base = format!("/joint_v3/promoter/operating_points/{name}");
        let aggregation = manifest
            .pointer(&format!("{base}/aggregation"))
            .and_then(Value::as_str)
            .ok_or("union aggregation missing")?;
        let threshold = manifest
            .pointer(&format!("{base}/document_risk_margin_threshold"))
            .and_then(Value::as_f64)
            .ok_or("union threshold missing")? as f32;
        scored_view(rows, aggregation, threshold, default)
    } else {
        view(manifest, "union_l2_l3", point, rows, default)
    }
}

fn profile(point: NtdbOperatingPoint) -> &'static str {
    match point {
        NtdbOperatingPoint::BestFprInF1 => "best_fpr_in_f1",
        NtdbOperatingPoint::BestFnrInF1 => "best_fnr_in_f1",
        _ => "best_f1",
    }
}

fn scored_view(
    rows: &[Vec<f32>],
    aggregation: &str,
    threshold: f32,
    default: usize,
) -> Result<View, Box<dyn std::error::Error + Send + Sync>> {
    let scores = aggregate(rows, aggregation)?;
    let (risk_index, risk_score) = scores
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| *index != default)
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .ok_or("no risk class")?;
    Ok(View {
        risk_index,
        accepted: risk_score - scores[default] >= threshold,
    })
}

fn aggregate(
    rows: &[Vec<f32>],
    method: &str,
) -> Result<Vec<f32>, Box<dyn std::error::Error + Send + Sync>> {
    let classes = rows.first().ok_or("no chunk scores")?.len();
    if classes == 0 || rows.iter().any(|row| row.len() != classes) {
        return Err("chunk score shape mismatch".into());
    }
    let mut result = vec![0.0; classes];
    match method {
        "max" => {
            for class in 0..classes {
                result[class] = rows
                    .iter()
                    .map(|row| row[class])
                    .fold(f32::NEG_INFINITY, f32::max);
            }
        }
        "mean" => {
            for class in 0..classes {
                result[class] = rows.iter().map(|row| row[class]).sum::<f32>() / rows.len() as f32;
            }
        }
        "smoothmax" => {
            for class in 0..classes {
                let max = rows
                    .iter()
                    .map(|row| row[class])
                    .fold(f32::NEG_INFINITY, f32::max);
                let weights = rows
                    .iter()
                    .map(|row| (10.0 * (row[class] - max)).exp())
                    .collect::<Vec<_>>();
                result[class] = rows
                    .iter()
                    .zip(&weights)
                    .map(|(row, weight)| row[class] * weight)
                    .sum::<f32>()
                    / weights.iter().sum::<f32>();
            }
        }
        _ => return Err(format!("unsupported aggregation {method}").into()),
    }
    Ok(result)
}

fn class_f1(confusion: &[Vec<u64>], class: usize) -> f64 {
    let tp = confusion[class][class] as f64;
    let fp = confusion
        .iter()
        .enumerate()
        .filter(|(actual, _)| *actual != class)
        .map(|(_, row)| row[class])
        .sum::<u64>() as f64;
    let fn_ = confusion[class]
        .iter()
        .enumerate()
        .filter(|(predicted, _)| *predicted != class)
        .map(|(_, count)| count)
        .sum::<u64>() as f64;
    if 2.0 * tp + fp + fn_ == 0.0 {
        0.0
    } else {
        2.0 * tp / (2.0 * tp + fp + fn_)
    }
}
