//! Prepare a local Wolf FP16 directory from existing assets, using Rust only.
use patronus_ark_core::{
    assets::mmbert_tokenizer::ensure_mmbert_compact_tokenizer,
    wolf::{WolfConfig, WolfRunner},
};
use std::{fs, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let source = PathBuf::from(
        args.next()
            .ok_or("usage: prepare_wolf_bundle SNAPSHOT NEW_BUNDLE THRESHOLD")?,
    );
    let output = PathBuf::from(args.next().ok_or("new bundle directory required")?);
    let threshold: f64 = args
        .next()
        .ok_or("explicit probability threshold required")?
        .parse()?;
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        return Err("threshold must be in [0,1]".into());
    }
    let model = [
        "onnx/onnx_fp16/model_fp16.onnx",
        "onnx/fp16/model_fp16.onnx",
        "model_fp16.onnx",
    ]
    .into_iter()
    .map(|path| source.join(path))
    .find(|path| path.is_file())
    .ok_or("no existing Wolf FP16 ONNX artifact found")?;
    // Never overwrite another bundle. Reuse the source's assets and provenance.
    fs::create_dir(&output)?;
    fs::copy(model, output.join("model_fp16.onnx"))?;
    fs::copy(source.join("tokenizer.json"), output.join("tokenizer.json"))?;
    for name in ["config.json", "tokenizer_config.json", ".patronus-revision"] {
        if source.join(name).is_file() {
            fs::copy(source.join(name), output.join(name))?;
        }
    }
    ensure_mmbert_compact_tokenizer("wolf-defender-small", &output.join("tokenizer.json"))?
        .ok_or("unsupported tokenizer")?;
    let mut runner = WolfRunner::new(&WolfConfig::new(&output, threshold))?;
    let probe = runner.scan("Please summarize the meeting agenda.")?;
    println!(
        "{}",
        serde_json::json!({"bundle":output,"model":runner.model_path(),"loaded":true,"provider":runner.execution_provider(),"probe_windows":probe.windows})
    );
    Ok(())
}
