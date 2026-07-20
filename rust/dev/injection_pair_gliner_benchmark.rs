use patronus_ark::{
    gliner_onnx_engine::GlinerEngine, NtdbOperatingPoint, SecurityCategory, SecurityGateway,
    SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

const WOLF_MODEL: &str = "wolf-defender-small";
const WARMUP_SUFFIX: &str = " [benchmark warmup only]";
const L3_CHUNK_TOKENS: usize = 256;
const L3_OVERLAP_TOKENS: usize = 32;

#[derive(Deserialize)]
struct Row {
    text: String,
    expected_class: String,
}

struct BenchmarkEntity {
    label: String,
    text: String,
    score: f32,
    start_byte: usize,
    end_byte: usize,
    start_char: usize,
    end_char: usize,
}

struct NerEngine(GlinerEngine);

impl NerEngine {
    fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(GlinerEngine::from_path(path)?))
    }

    fn family(&self) -> &'static str {
        "gliner"
    }

    fn model(&self) -> &'static str {
        "patronus-studio/gliner_small-v2.5-edge"
    }

    fn text_token_count(&self, text: &str) -> Result<usize, Box<dyn std::error::Error>> {
        Ok(self.0.text_token_count(text)?)
    }

    fn extract_entities(
        &mut self,
        text: &str,
        labels: &[String],
        threshold: f32,
    ) -> Result<Vec<BenchmarkEntity>, Box<dyn std::error::Error>> {
        Ok(self
            .0
            .extract_entities(text, labels, threshold)?
            .into_iter()
            .map(|entity| BenchmarkEntity {
                label: entity.label,
                text: entity.text,
                score: entity.score,
                start_byte: entity.start_byte,
                end_byte: entity.end_byte,
                start_char: entity.start_char,
                end_char: entity.end_char,
            })
            .collect())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage: injection_pair_gliner_benchmark <l2-dir> <wolf-dir> <wolf-tokenizer.mmbpe> <gliner-dir> <dataset.jsonl>".into());
    }

    let l2_dir = Path::new(&args[1]);
    let wolf_dir = Path::new(&args[2]);
    let pair_tokenizer = Path::new(&args[3]);
    let gliner_dir = Path::new(&args[4]);
    let rows = load_rows(Path::new(&args[5]))?;
    let model_root = prepare_wolf_assets(wolf_dir, pair_tokenizer)?;
    std::env::set_var("PATRONUS_NTDB_INJECTION_DIR", l2_dir);
    std::env::set_var("PATRONUS_ONNX_EXECUTION_PROVIDER", "cpu");

    let started = Instant::now();
    let mut scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Injection],
        SecurityLevel::L3,
        Some(model_root),
        false,
    );
    scanner.set_ntdb_operating_point(NtdbOperatingPoint::BestLatencyInF1);
    scanner.warmup()?;
    let scanner_warmup_ms = started.elapsed().as_secs_f64() * 1_000.0;

    let started = Instant::now();
    let mut l3_warmup_executed = false;
    let mut l3_warmup_attempts = 0usize;
    for row in &rows {
        l3_warmup_attempts += 1;
        let warmup_text = format!("{}{WARMUP_SUFFIX}", row.text);
        let warmup_results = scanner.scan_category(SecurityCategory::Injection, &warmup_text);
        if final_wolf_result(&warmup_results).is_some_and(|result| result.level == "L3") {
            l3_warmup_executed = true;
            break;
        }
    }
    let l3_warmup_ms = started.elapsed().as_secs_f64() * 1_000.0;
    if !l3_warmup_executed {
        return Err("could not find an L3-routed warmup input".into());
    }

    let started = Instant::now();
    let mut gliner = NerEngine::from_path(gliner_dir)?;
    let gliner_load_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let labels = std::env::var("PATRONUS_GLINER_LABELS")
        .ok()
        .map(|value| value.split('|').map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_else(|| {
            ["instruction", "secret", "description of an action"]
                .map(String::from)
                .to_vec()
        });
    if labels.is_empty() || labels.iter().any(String::is_empty) {
        return Err("PATRONUS_GLINER_LABELS must contain non-empty pipe-separated labels".into());
    }
    let started = Instant::now();
    let _ = extract_entities_chunked(
        &mut gliner,
        &format!("{}{WARMUP_SUFFIX}", rows[0].text),
        &labels,
        0.5,
    )?;
    let gliner_warmup_ms = started.elapsed().as_secs_f64() * 1_000.0;

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut tn = 0usize;
    let mut fn_ = 0usize;
    let mut promoted = 0usize;
    let mut entity_count = 0usize;
    let mut gliner_chunk_count = 0usize;
    let mut max_gliner_chunks = 0usize;
    let mut scan_ms = Vec::with_capacity(rows.len());
    let mut gliner_ms = Vec::with_capacity(rows.len());
    let mut e2e_ms = Vec::with_capacity(rows.len());

    for (index, row) in rows.iter().enumerate() {
        let e2e_started = Instant::now();
        let started = Instant::now();
        let results = scanner.scan_category(SecurityCategory::Injection, &row.text);
        scan_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        let result = final_wolf_result(&results)
            .ok_or_else(|| format!("sample {index} returned no Wolf result"))?;
        promoted += usize::from(result.level == "L3");

        let started = Instant::now();
        let (entities, chunks) = extract_entities_chunked(&mut gliner, &row.text, &labels, 0.5)?;
        entity_count += entities.len();
        gliner_chunk_count += chunks;
        max_gliner_chunks = max_gliner_chunks.max(chunks);
        gliner_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        e2e_ms.push(e2e_started.elapsed().as_secs_f64() * 1_000.0);

        match (
            row.expected_class.as_str() == "attack",
            result.class_name == "attack",
        ) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_ += 1,
        }
        if (index + 1) % 25 == 0 || index + 1 == rows.len() {
            eprintln!("completed {}/{} samples", index + 1, rows.len());
        }
    }

    let f1 = ratio(2 * tp, 2 * tp + fp + fn_);
    let report = json!({
        "samples": rows.len(),
        "operating_point": "best_latency_in_f1",
        "tokenizers": {
            "l2": "kit",
            "l3": "explicit-pair mmbpe",
        },
        "quality": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn_,
            "f1": f1,
            "fpr": ratio(fp, fp + tn),
            "fnr": ratio(fn_, fn_ + tp),
        },
        "routing": {
            "l3_samples": promoted,
            "l2_only_samples": rows.len() - promoted,
        },
        "latency_ms": {
            "l2_l3_scan": stats(&scan_ms),
            "gliner": stats(&gliner_ms),
            "end_to_end": stats(&e2e_ms),
        },
        "gliner": {
            "family": gliner.family(),
            "model": gliner.model(),
            "precision": "uint4_embeddings_qint8_matmuls",
            "labels": labels,
            "threshold": 0.5,
            "entities_returned": entity_count,
            "chunk_size_tokens": L3_CHUNK_TOKENS,
            "overlap_tokens": L3_OVERLAP_TOKENS,
            "chunks_processed": gliner_chunk_count,
            "max_chunks_per_sample": max_gliner_chunks,
            "mean_latency_per_chunk_ms": gliner_ms.iter().sum::<f64>() / gliner_chunk_count as f64,
        },
        "initialization": {
            "l2_load_ms": scanner_warmup_ms,
            "l3_first_scan_ms": l3_warmup_ms,
            "l3_first_scan_executed": l3_warmup_executed,
            "l3_warmup_attempts": l3_warmup_attempts,
            "gliner_load_ms": gliner_load_ms,
            "gliner_first_inference_ms": gliner_warmup_ms,
        },
        "peak_rss_mb": peak_rss_mb(),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn final_wolf_result(results: &[SecurityScanResult]) -> Option<&SecurityScanResult> {
    results
        .iter()
        .filter(|result| result.model == WOLF_MODEL)
        .max_by_key(|result| if result.level == "L3" { 1 } else { 0 })
}

fn extract_entities_chunked(
    engine: &mut NerEngine,
    text: &str,
    labels: &[String],
    threshold: f32,
) -> Result<(Vec<BenchmarkEntity>, usize), Box<dyn std::error::Error>> {
    let chunks = text_chunks(engine, text)?;
    let mut candidates = Vec::new();
    for chunk in &chunks {
        for mut entity in engine.extract_entities(chunk.text, labels, threshold)? {
            entity.start_byte += chunk.start;
            entity.end_byte += chunk.start;
            entity.start_char = text[..entity.start_byte].chars().count();
            entity.end_char = text[..entity.end_byte].chars().count();
            entity.text = text[entity.start_byte..entity.end_byte].to_string();
            candidates.push(entity);
        }
    }

    candidates.sort_by(|left, right| right.score.total_cmp(&left.score));
    let mut entities = Vec::new();
    for candidate in candidates {
        let overlaps = entities.iter().any(|selected: &BenchmarkEntity| {
            selected.label == candidate.label
                && candidate.start_byte < selected.end_byte
                && candidate.end_byte > selected.start_byte
        });
        if !overlaps {
            entities.push(candidate);
        }
    }
    entities.sort_by_key(|entity| (entity.start_byte, entity.end_byte));
    Ok((entities, chunks.len()))
}

struct TextChunk<'a> {
    start: usize,
    text: &'a str,
}

fn text_chunks<'a>(
    engine: &NerEngine,
    text: &'a str,
) -> Result<Vec<TextChunk<'a>>, Box<dyn std::error::Error>> {
    if engine.text_token_count(text)? <= L3_CHUNK_TOKENS {
        return Ok(vec![TextChunk { start: 0, text }]);
    }

    let boundaries = text
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(text.len()))
        .collect::<Vec<_>>();
    let mut chunks = Vec::new();
    let mut start_index = 0usize;
    while start_index + 1 < boundaries.len() {
        let start = boundaries[start_index];
        let mut low = start_index + 1;
        let mut high = boundaries.len() - 1;
        let mut end_index = low;
        while low <= high {
            let middle = low + (high - low) / 2;
            if engine.text_token_count(&text[start..boundaries[middle]])? <= L3_CHUNK_TOKENS {
                end_index = middle;
                low = middle + 1;
            } else {
                high = middle.saturating_sub(1);
            }
        }
        let end = boundaries[end_index];
        chunks.push(TextChunk {
            start,
            text: &text[start..end],
        });
        if end == text.len() {
            break;
        }

        let mut low = start_index + 1;
        let mut high = end_index;
        let mut next_start = end_index;
        while low <= high {
            let middle = low + (high - low) / 2;
            if engine.text_token_count(&text[boundaries[middle]..end])? <= L3_OVERLAP_TOKENS {
                next_start = middle;
                high = middle.saturating_sub(1);
            } else {
                low = middle + 1;
            }
        }
        start_index = next_start.max(start_index + 1);
    }
    Ok(chunks)
}

fn load_rows(path: &Path) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn prepare_wolf_assets(
    source: &Path,
    pair_tokenizer: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "patronus_pair_gliner_benchmark_{}",
        std::process::id()
    ));
    let target = root.join("injection/l3");
    fs::create_dir_all(target.join("onnx/onnx_mixed"))?;
    link(
        &source.join("tokenizer.json"),
        &target.join("tokenizer.json"),
    )?;
    link(pair_tokenizer, &target.join("tokenizer.mmbpe"))?;
    link(
        &source.join("model.onnx"),
        &target.join("onnx/onnx_mixed/model_mixed.onnx"),
    )?;
    Ok(root)
}

#[cfg(unix)]
fn link(source: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if target.exists() || target.symlink_metadata().is_ok() {
        fs::remove_file(target)?;
    }
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn link(source: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::copy(source, target)?;
    Ok(())
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn stats(values: &[f64]) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |p: f64| {
        let index = ((sorted.len() - 1) as f64 * p).round() as usize;
        sorted[index]
    };
    json!({
        "mean": sorted.iter().sum::<f64>() / sorted.len() as f64,
        "p50": percentile(0.50),
        "p95": percentile(0.95),
        "max": sorted[sorted.len() - 1],
    })
}

#[cfg(target_os = "macos")]
fn peak_rss_mb() -> f64 {
    #[repr(C)]
    struct TimeVal {
        seconds: i64,
        microseconds: i64,
    }

    #[repr(C)]
    struct ResourceUsage {
        user_time: TimeVal,
        system_time: TimeVal,
        max_rss: i64,
        remaining: [i64; 13],
    }

    unsafe extern "C" {
        fn getrusage(who: i32, usage: *mut ResourceUsage) -> i32;
    }

    let mut usage = std::mem::MaybeUninit::<ResourceUsage>::zeroed();
    if unsafe { getrusage(0, usage.as_mut_ptr()) } == 0 {
        unsafe { usage.assume_init().max_rss as f64 / (1024.0 * 1024.0) }
    } else {
        f64::NAN
    }
}

#[cfg(not(target_os = "macos"))]
fn peak_rss_mb() -> f64 {
    f64::NAN
}
