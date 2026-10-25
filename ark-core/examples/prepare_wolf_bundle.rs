//! Prepare a local bundle from the pinned published Wolf FP16 snapshot, using Rust only.
use patronus_ark_core::{
    assets::mmbert_tokenizer::ensure_mmbert_compact_tokenizer,
    wolf::{WolfConfig, WolfManifest, WolfRunner, PUBLISHED_MANIFEST, PUBLISHED_REVISION},
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
    let manifest: WolfManifest = serde_json::from_str(PUBLISHED_MANIFEST)?;
    // Never overwrite another bundle or silently bless a different artifact revision.
    fs::create_dir(&output)?;
    let model_target = output.join(&manifest.model.path);
    fs::create_dir_all(model_target.parent().ok_or("invalid model path")?)?;
    fs::copy(source.join(&manifest.model.path), &model_target)?;
    fs::copy(source.join("tokenizer.json"), output.join("tokenizer.json"))?;
    ensure_mmbert_compact_tokenizer("wolf-defender-small", &output.join("tokenizer.json"))?
        .ok_or("unsupported tokenizer")?;
    fs::write(output.join("wolf.manifest.json"), PUBLISHED_MANIFEST)?;
    let mut runner = WolfRunner::new(&WolfConfig::new(&output, threshold))?;
    let probe = runner.scan("Please summarize the meeting agenda.")?;
    println!(
        "{}",
        serde_json::json!({"bundle":output,"revision":PUBLISHED_REVISION,"verified":true,"provider":runner.execution_provider(),"probe_windows":probe.windows})
    );
    Ok(())
}
