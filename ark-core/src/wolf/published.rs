//! The settings a Wolf bundle publishes in `POOLING.json`, which are Core's defaults.
use super::{asset, validate_threshold};
use crate::ScanError;
use serde_json::Value;
use std::{fs, path::Path};

pub const POOLING_FILE: &str = "POOLING.json";

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Published {
    /// Encoder positions per window, BOS and EOS included.
    pub(crate) window_tokens: usize,
    /// Content tokens shared by adjacent windows.
    pub(crate) overlap_tokens: usize,
    /// Smooth-max temperature over several windows. A single window pools to
    /// its own logits at any temperature, so the published `T1 single` needs none.
    pub(crate) temperature: f64,
    pub(crate) threshold: f64,
    /// Detect only above the threshold (`>`), not at it.
    pub(crate) strict: bool,
}

impl Published {
    /// What Wolf Defender (Base, Small, Edge) publishes in `POOLING.json` and
    /// `inference.py`; a bundle without `POOLING.json` uses these.
    pub(crate) const MODEL: Self = Self {
        window_tokens: 2048,
        overlap_tokens: 64,
        temperature: 0.1,
        threshold: 0.5,
        strict: true,
    };

    pub(crate) fn read(bundle: &Path) -> Result<Self, ScanError> {
        match fs::read(bundle.join(POOLING_FILE)) {
            Ok(bytes) => Self::parse(&serde_json::from_slice(&bytes).map_err(invalid)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::MODEL),
            Err(e) => Err(asset(e)),
        }
    }

    /// Absent fields keep [`Self::MODEL`]; present fields must parse.
    fn parse(value: &Value) -> Result<Self, ScanError> {
        let mut published = Self::MODEL;
        let field = |name| value.get(name).filter(|v: &&Value| !v.is_null());
        if let Some(value) = field("encoder_positions") {
            published.window_tokens = size(value)?;
        }
        if let Some(value) = field("overlap") {
            published.overlap_tokens = size(value)?;
        }
        if let Some(value) = field("pooling") {
            published.temperature = multi_window_temperature(value)?;
        }
        if let Some(value) = field("threshold") {
            (published.threshold, published.strict) = threshold(value)?;
        }
        Ok(published)
    }
}

fn invalid(error: impl std::fmt::Display) -> ScanError {
    ScanError::Asset(format!("invalid Wolf {POOLING_FILE}: {error}"))
}

fn size(value: &Value) -> Result<usize, ScanError> {
    value
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| invalid(format!("{value} is not a token count")))
}

/// `normalized classwise Smoothmax T1 single/T0.1 multi then softmax` → 0.1.
fn multi_window_temperature(value: &Value) -> Result<f64, ScanError> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid("pooling must be text"))?;
    let lower = text.to_ascii_lowercase();
    if !lower.contains("classwise") || !lower.contains("softmax") {
        return Err(invalid(format!("unsupported pooling {text:?}")));
    }
    let words: Vec<_> = text
        .split(|c: char| c.is_whitespace() || c == '/' || c == ',')
        .filter(|word| !word.is_empty())
        .collect();
    words
        .windows(2)
        .find(|pair| pair[1].eq_ignore_ascii_case("multi"))
        .and_then(|pair| pair[0].strip_prefix('T')?.parse::<f64>().ok())
        .filter(|t| t.is_finite() && *t > 0.0)
        .ok_or_else(|| invalid(format!("no multi-window temperature in {text:?}")))
}

/// `strict >0.5`, `>0.5` or `0.5` are strict; `>=0.5` also detects at the threshold.
fn threshold(value: &Value) -> Result<(f64, bool), ScanError> {
    let (number, strict) = match value {
        Value::Number(number) => (number.as_f64(), true),
        Value::String(text) => {
            let text = text.trim();
            let (text, said_strict) = text
                .strip_prefix("strict")
                .map_or((text, false), |rest| (rest.trim_start(), true));
            let (number, strict) = match text.strip_prefix(">=") {
                Some(_) if said_strict => return Err(invalid("strict threshold with >=")),
                Some(number) => (number, false),
                None => (text.strip_prefix('>').unwrap_or(text), true),
            };
            (number.trim().parse().ok(), strict)
        }
        _ => (None, true),
    };
    let number = number.ok_or_else(|| invalid(format!("threshold {value}")))?;
    validate_threshold(number)?;
    Ok((number, strict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn published_pooling_files_parse_to_the_model_settings() {
        // Edge and Small/Base at their pinned revisions.
        for pooling in [
            "normalized classwise Smoothmax T1 single/T0.1 multi then softmax",
            "normalized classwise Smoothmax T1 single/T0.1 multi, then softmax",
        ] {
            let value = json!({"encoder_positions": 2048, "overlap": 64, "pooling": pooling,
                "threshold": "strict >0.5", "full_turns": true});
            assert_eq!(Published::parse(&value).unwrap(), Published::MODEL);
        }
        assert_eq!(Published::parse(&json!({})).unwrap(), Published::MODEL);
    }

    #[test]
    fn published_values_replace_the_model_defaults() {
        let value = json!({"encoder_positions": 512, "overlap": 8,
            "pooling": "classwise smoothmax T0.25 multi then softmax", "threshold": ">=0.7"});
        let published = Published::parse(&value).unwrap();
        assert_eq!(
            published,
            Published {
                window_tokens: 512,
                overlap_tokens: 8,
                temperature: 0.25,
                threshold: 0.7,
                strict: false,
            }
        );
        assert_eq!(threshold(&json!(0.4)).unwrap(), (0.4, true));
        assert_eq!(threshold(&json!("> 0.6")).unwrap(), (0.6, true));
    }

    #[test]
    fn malformed_published_settings_are_rejected() {
        for value in [
            json!({"encoder_positions": -1}),
            json!({"overlap": "64"}),
            json!({"pooling": "mean of window probabilities"}),
            json!({"pooling": "classwise smoothmax then softmax"}),
            json!({"pooling": "classwise smoothmax T0 multi then softmax"}),
            json!({"threshold": "strict >=0.5"}),
            json!({"threshold": "about half"}),
            json!({"threshold": 1.5}),
        ] {
            assert!(Published::parse(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn a_bundle_without_pooling_json_uses_the_model_settings() {
        let dir = std::env::temp_dir().join(format!("ark-wolf-pooling-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(Published::read(&dir).unwrap(), Published::MODEL);
        fs::write(dir.join(POOLING_FILE), r#"{"encoder_positions": 1024}"#).unwrap();
        assert_eq!(Published::read(&dir).unwrap().window_tokens, 1024);
        fs::write(dir.join(POOLING_FILE), "not json").unwrap();
        assert!(Published::read(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
