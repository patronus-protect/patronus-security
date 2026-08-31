// SPDX-License-Identifier: GPL-3.0-only
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::compact_tokenizer::{
    file_blake3, remove_file_if_exists, write_json_atomic, CacheLock, TemporaryPath,
};

const CACHE_SCHEMA_VERSION: u32 = 1;
const CONVERTER_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), ":mmbert-mmbpe-v1");
const FORMAT_VERSION: &str = "MMBPE-1";
const MAGIC: &[u8; 8] = b"MMBPE\0\x01\0";

#[derive(Debug, Deserialize, Serialize)]
struct MmbertTokenizerMetadata {
    schema_version: u32,
    converter_version: String,
    format_version: String,
    source_model: String,
    source_blake3: String,
    mmbpe_blake3: String,
}

#[derive(Deserialize)]
struct TokenizerJson {
    added_tokens: Vec<AddedToken>,
    model: BpeJson,
}

#[derive(Deserialize)]
struct AddedToken {
    id: u32,
    content: String,
    #[serde(default)]
    lstrip: bool,
}

#[derive(Deserialize)]
struct BpeJson {
    #[serde(rename = "type")]
    tokenizer_type: Option<String>,
    #[serde(default)]
    byte_fallback: bool,
    vocab: HashMap<String, u32>,
    merges: Vec<[String; 2]>,
}

type TokenizerConverter = fn(&Path, &Path) -> Result<(), Box<dyn std::error::Error>>;

pub(super) fn ensure_mmbert_compact_tokenizer(
    source_model: &str,
    tokenizer_json: &Path,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    ensure_mmbert_compact_tokenizer_with(source_model, tokenizer_json, convert_huggingface_to_mmbpe)
}

pub(super) fn ensure_mmbert_compact_tokenizer_with(
    source_model: &str,
    tokenizer_json: &Path,
    converter: TokenizerConverter,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    log::debug!(
        "checking compact mmBERT tokenizer support; source_model={}; tokenizer_json={}; tokenizer_json_exists={}",
        source_model,
        tokenizer_json.display(),
        tokenizer_json.is_file()
    );
    let supported = supports_mmbert_mmbpe(tokenizer_json)?;
    log::debug!(
        "compact mmBERT tokenizer support checked; source_model={}; supported={}",
        source_model,
        supported
    );
    if !supported {
        return Ok(None);
    }
    let tokenizer_dir = tokenizer_json
        .parent()
        .ok_or_else(|| format!("tokenizer path has no parent: {}", tokenizer_json.display()))?;
    fs::create_dir_all(tokenizer_dir)?;

    let compact_path = tokenizer_dir.join("tokenizer.mmbpe");
    let metadata_path = tokenizer_dir.join("tokenizer.mmbpe.meta.json");
    let lock_path = tokenizer_dir.join("tokenizer.mmbpe.lock");
    let source_hash = file_blake3(tokenizer_json)?;
    let cache_current =
        cache_is_current(&compact_path, &metadata_path, source_model, &source_hash)?;
    log::debug!(
        "checked compact mmBERT tokenizer cache before lock; source_model={}; compact_path={}; metadata_path={}; cache_current={}",
        source_model,
        compact_path.display(),
        metadata_path.display(),
        cache_current
    );
    if cache_current {
        return Ok(Some(compact_path));
    }

    let _lock = CacheLock::acquire(&lock_path)?;
    log::debug!(
        "acquired compact mmBERT tokenizer cache lock; source_model={}; lock_path={}",
        source_model,
        lock_path.display()
    );
    let source_hash = file_blake3(tokenizer_json)?;
    let cache_current =
        cache_is_current(&compact_path, &metadata_path, source_model, &source_hash)?;
    log::debug!(
        "checked compact mmBERT tokenizer cache after lock; source_model={}; cache_current={}",
        source_model,
        cache_current
    );
    if cache_current {
        return Ok(Some(compact_path));
    }

    remove_file_if_exists(&compact_path)?;
    remove_file_if_exists(&metadata_path)?;

    let mut compact_temp = TemporaryPath::new(tokenizer_dir, "tokenizer.mmbpe.tmp")?;
    log::debug!(
        "converting HuggingFace tokenizer to mmBERT compact tokenizer; source_model={}; source={}; temp={}",
        source_model,
        tokenizer_json.display(),
        compact_temp.path().display()
    );
    if let Err(err) = converter(tokenizer_json, compact_temp.path()) {
        log::debug!(
            "failed to convert HuggingFace tokenizer to mmBERT compact tokenizer; source_model={}; source={}; temp={}; error={err}",
            source_model,
            tokenizer_json.display(),
            compact_temp.path().display()
        );
        return Err(format!("mmBERT tokenizer conversion failed: {err}").into());
    }
    File::open(compact_temp.path())?.sync_all()?;
    let mmbpe_hash = file_blake3(compact_temp.path())?;

    compact_temp.persist(&compact_path)?;
    let metadata = MmbertTokenizerMetadata {
        schema_version: CACHE_SCHEMA_VERSION,
        converter_version: CONVERTER_VERSION.to_string(),
        format_version: FORMAT_VERSION.to_string(),
        source_model: source_model.to_string(),
        source_blake3: source_hash,
        mmbpe_blake3: mmbpe_hash,
    };
    write_json_atomic(&metadata_path, &metadata)?;

    log::debug!(
        "persisted compact mmBERT tokenizer; source_model={}; compact_path={}; metadata_path={}; compact_exists={}; metadata_exists={}",
        source_model,
        compact_path.display(),
        metadata_path.display(),
        compact_path.is_file(),
        metadata_path.is_file()
    );
    log::info!(
        "generated compact mmBERT tokenizer {} from {}",
        compact_path.display(),
        tokenizer_json.display()
    );
    Ok(Some(compact_path))
}

fn supports_mmbert_mmbpe(tokenizer_json: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let parsed: TokenizerJson = match serde_json::from_slice(&fs::read(tokenizer_json)?) {
        Ok(parsed) => parsed,
        Err(error) => {
            log::debug!(
                "failed to parse tokenizer while checking mmBERT compact support; tokenizer_json={}; error={error}",
                tokenizer_json.display()
            );
            return Ok(false);
        }
    };
    let vocab = &parsed.model.vocab;
    let is_bpe = parsed
        .model
        .tokenizer_type
        .as_deref()
        .is_none_or(|value| value.eq_ignore_ascii_case("BPE"));
    let has_bos = vocab.contains_key("<bos>");
    let has_eos = vocab.contains_key("<eos>");
    let has_unk = vocab.contains_key("<unk>");
    let missing_bytes = (0..=255)
        .filter(|byte| byte_token_id(vocab, *byte as u8).is_none())
        .collect::<Vec<_>>();
    let supported = is_bpe
        && parsed.model.byte_fallback
        && has_bos
        && has_eos
        && has_unk
        && missing_bytes.is_empty();
    log::debug!(
        "checked mmBERT compact tokenizer requirements; tokenizer_json={}; is_bpe={}; byte_fallback={}; has_bos={}; has_eos={}; has_unk={}; missing_byte_count={}; first_missing_byte={:?}; supported={}",
        tokenizer_json.display(),
        is_bpe,
        parsed.model.byte_fallback,
        has_bos,
        has_eos,
        has_unk,
        missing_bytes.len(),
        missing_bytes.first(),
        supported
    );
    Ok(supported)
}

fn cache_is_current(
    compact_path: &Path,
    metadata_path: &Path,
    source_model: &str,
    source_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !compact_path.is_file() || !metadata_path.is_file() {
        log::debug!(
            "compact mmBERT tokenizer cache is incomplete; compact_exists={}; metadata_exists={}; compact_path={}; metadata_path={}",
            compact_path.is_file(),
            metadata_path.is_file(),
            compact_path.display(),
            metadata_path.display()
        );
        return Ok(false);
    }
    let metadata: MmbertTokenizerMetadata = match serde_json::from_slice(&fs::read(metadata_path)?)
    {
        Ok(metadata) => metadata,
        Err(error) => {
            log::debug!(
                "failed to parse compact mmBERT tokenizer metadata; metadata_path={}; error={error}",
                metadata_path.display()
            );
            return Ok(false);
        }
    };
    if metadata.schema_version != CACHE_SCHEMA_VERSION
        || metadata.converter_version != CONVERTER_VERSION
        || metadata.format_version != FORMAT_VERSION
        || metadata.source_model != source_model
        || metadata.source_blake3 != source_hash
    {
        log::debug!(
            "compact mmBERT tokenizer metadata is stale; schema_match={}; converter_match={}; format_match={}; source_model_match={}; source_hash_match={}",
            metadata.schema_version == CACHE_SCHEMA_VERSION,
            metadata.converter_version == CONVERTER_VERSION,
            metadata.format_version == FORMAT_VERSION,
            metadata.source_model == source_model,
            metadata.source_blake3 == source_hash
        );
        return Ok(false);
    }
    let hash_matches = file_blake3(compact_path)? == metadata.mmbpe_blake3;
    log::debug!(
        "checked compact mmBERT tokenizer content hash; compact_path={}; hash_matches={}",
        compact_path.display(),
        hash_matches
    );
    Ok(hash_matches)
}

fn convert_huggingface_to_mmbpe(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed: TokenizerJson = serde_json::from_slice(&fs::read(source)?)?;
    let vocab = &parsed.model.vocab;
    let mut chars = vocab
        .iter()
        .filter_map(|(token, id)| {
            let mut values = token.chars();
            let value = values.next()?;
            values.next().is_none().then_some((value, *id))
        })
        .collect::<Vec<_>>();
    chars.sort_unstable_by_key(|(value, _)| *value);

    let mut bytes = [0; 256];
    for (byte, id) in bytes.iter_mut().enumerate() {
        *id = byte_token_id(vocab, byte as u8)
            .ok_or_else(|| format!("missing byte fallback token for byte {byte:#04X}"))?;
    }

    let mut writer = BufWriter::new(File::create(destination)?);
    writer.write_all(MAGIC)?;
    write_u32(&mut writer, *vocab.get("<bos>").ok_or("missing <bos>")?)?;
    write_u32(&mut writer, *vocab.get("<eos>").ok_or("missing <eos>")?)?;
    write_u32(&mut writer, *vocab.get("<unk>").ok_or("missing <unk>")?)?;
    write_u32(&mut writer, chars.len() as u32)?;
    for (value, id) in chars {
        write_u32(&mut writer, value as u32)?;
        write_u32(&mut writer, id)?;
    }
    for id in bytes {
        write_u32(&mut writer, id)?;
    }

    write_u32(&mut writer, parsed.model.merges.len() as u32)?;
    for (rank, [left, right]) in parsed.model.merges.iter().enumerate() {
        let left_id = *vocab
            .get(left)
            .ok_or_else(|| format!("missing merge token {left:?}"))?;
        let right_id = *vocab
            .get(right)
            .ok_or_else(|| format!("missing merge token {right:?}"))?;
        let output_id = *vocab
            .get(&format!("{left}{right}"))
            .ok_or_else(|| format!("missing merged token {left:?} + {right:?}"))?;
        write_u32(&mut writer, left_id)?;
        write_u32(&mut writer, right_id)?;
        write_u32(&mut writer, output_id)?;
        write_u32(&mut writer, rank as u32)?;
    }

    write_u32(&mut writer, parsed.added_tokens.len() as u32)?;
    for token in parsed.added_tokens {
        write_u32(&mut writer, token.id)?;
        write_u32(&mut writer, u32::from(token.lstrip))?;
        write_u32(&mut writer, token.content.len() as u32)?;
        writer.write_all(token.content.as_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

fn write_u32(writer: &mut impl Write, value: u32) -> std::io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn byte_token_id(vocab: &HashMap<String, u32>, byte: u8) -> Option<u32> {
    vocab
        .get(&format!("<{byte:#04X}>"))
        .copied()
        .or_else(|| literal_ascii_byte_token(byte).and_then(|token| vocab.get(token).copied()))
}

fn literal_ascii_byte_token(byte: u8) -> Option<&'static str> {
    match byte {
        b'\t' => Some("\t"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, sync::Arc, thread, time::SystemTime};

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "patronus_mmbpe_tokenizer_{name}_{}_{}",
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_supported_tokenizer(path: &Path, extra: &str) {
        let mut vocab = serde_json::Map::new();
        vocab.insert("<bos>".to_string(), 0.into());
        vocab.insert("<eos>".to_string(), 1.into());
        vocab.insert("<unk>".to_string(), 2.into());
        vocab.insert("▁".to_string(), 3.into());
        for byte in 0..=255 {
            vocab.insert(format!("<{byte:#04X}>"), (byte + 10).into());
        }
        let value = serde_json::json!({
            "added_tokens": [
                {"id": 0, "content": "<bos>", "lstrip": false},
                {"id": 1, "content": "<eos>", "lstrip": false}
            ],
            "model": {
                "type": "BPE",
                "byte_fallback": true,
                "vocab": vocab,
                "merges": [],
                "test_marker": extra
            }
        });
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn write_supported_tokenizer_with_literal_tab_byte(path: &Path) {
        let mut vocab = serde_json::Map::new();
        vocab.insert("<bos>".to_string(), 0.into());
        vocab.insert("<eos>".to_string(), 1.into());
        vocab.insert("<unk>".to_string(), 2.into());
        vocab.insert("▁".to_string(), 3.into());
        for byte in 0..=255 {
            let id = byte as u32 + 10;
            if byte == b'\t' {
                vocab.insert("\t".to_string(), id.into());
            } else {
                vocab.insert(format!("<{byte:#04X}>"), id.into());
            }
        }
        let value = serde_json::json!({
            "added_tokens": [
                {"id": 0, "content": "<bos>", "lstrip": false},
                {"id": 1, "content": "<eos>", "lstrip": false}
            ],
            "model": {
                "type": "BPE",
                "byte_fallback": true,
                "vocab": vocab,
                "merges": []
            }
        });
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn fake_converter(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(destination, blake3::hash(&fs::read(source)?).as_bytes())?;
        Ok(())
    }

    fn failing_converter(
        _source: &Path,
        _destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(std::io::Error::other("intentional conversion failure").into())
    }

    #[test]
    fn creates_reuses_and_invalidates_mmbpe_cache() {
        let root = temp_dir("lifecycle");
        let tokenizer_json = root.join("tokenizer.json");
        write_supported_tokenizer(&tokenizer_json, "first");

        let compact_path =
            ensure_mmbert_compact_tokenizer_with("mmbert-test", &tokenizer_json, fake_converter)
                .unwrap()
                .unwrap();
        let metadata_path = root.join("tokenizer.mmbpe.meta.json");
        let original_compact = fs::read(&compact_path).unwrap();
        let original_metadata = fs::read(&metadata_path).unwrap();

        assert_eq!(
            ensure_mmbert_compact_tokenizer_with("mmbert-test", &tokenizer_json, fake_converter)
                .unwrap(),
            Some(compact_path.clone())
        );
        assert_eq!(fs::read(&compact_path).unwrap(), original_compact);
        assert_eq!(fs::read(&metadata_path).unwrap(), original_metadata);

        fs::write(&compact_path, b"corrupt").unwrap();
        ensure_mmbert_compact_tokenizer_with("mmbert-test", &tokenizer_json, fake_converter)
            .unwrap();
        assert_ne!(fs::read(&compact_path).unwrap(), b"corrupt");

        write_supported_tokenizer(&tokenizer_json, "second");
        let before = fs::read(&metadata_path).unwrap();
        ensure_mmbert_compact_tokenizer_with("mmbert-test", &tokenizer_json, fake_converter)
            .unwrap();
        assert_ne!(fs::read(&metadata_path).unwrap(), before);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_unsupported_tokenizers() {
        let root = temp_dir("skip");
        let tokenizer_json = root.join("tokenizer.json");
        fs::write(
            &tokenizer_json,
            br#"{"added_tokens":[],"model":{"type":"Unigram","vocab":{},"merges":[]}}"#,
        )
        .unwrap();

        assert!(ensure_mmbert_compact_tokenizer("gliner", &tokenizer_json)
            .unwrap()
            .is_none());
        assert!(!root.join("tokenizer.mmbpe").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_literal_tab_as_byte_fallback_token() {
        let root = temp_dir("literal_tab");
        let tokenizer_json = root.join("tokenizer.json");
        write_supported_tokenizer_with_literal_tab_byte(&tokenizer_json);

        assert!(supports_mmbert_mmbpe(&tokenizer_json).unwrap());
        let compact_path = ensure_mmbert_compact_tokenizer("mmbert-test", &tokenizer_json)
            .unwrap()
            .unwrap();
        assert!(compact_path.is_file());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_regeneration_removes_stale_mmbpe_cache() {
        let root = temp_dir("failed_regeneration");
        let tokenizer_json = root.join("tokenizer.json");
        write_supported_tokenizer(&tokenizer_json, "first");

        ensure_mmbert_compact_tokenizer_with("mmbert-test", &tokenizer_json, fake_converter)
            .unwrap();
        write_supported_tokenizer(&tokenizer_json, "second");

        assert!(ensure_mmbert_compact_tokenizer_with(
            "mmbert-test",
            &tokenizer_json,
            failing_converter
        )
        .is_err());
        assert!(!root.join("tokenizer.mmbpe").exists());
        assert!(!root.join("tokenizer.mmbpe.meta.json").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_conversion_produces_one_valid_cache() {
        let root = temp_dir("concurrent");
        let tokenizer_json = Arc::new(root.join("tokenizer.json"));
        write_supported_tokenizer(&tokenizer_json, "first");

        let workers = (0..4)
            .map(|_| {
                let tokenizer_json = Arc::clone(&tokenizer_json);
                thread::spawn(move || {
                    ensure_mmbert_compact_tokenizer_with(
                        "mmbert-test",
                        &tokenizer_json,
                        fake_converter,
                    )
                    .unwrap()
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let paths = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert!(paths.iter().all(|path| path == &paths[0]));
        assert!(cache_is_current(
            &paths[0],
            &root.join("tokenizer.mmbpe.meta.json"),
            "mmbert-test",
            &file_blake3(&tokenizer_json).unwrap()
        )
        .unwrap());

        fs::remove_dir_all(root).unwrap();
    }
}
