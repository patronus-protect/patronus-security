// SPDX-License-Identifier: GPL-3.0-only
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::ml::ntdb_executor::{
    manifest::MiniLmManifest, tokenizer::convert_huggingface_to_compact, NtdbResult,
};

const CACHE_SCHEMA_VERSION: u32 = 1;
const CONVERTER_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), ":granite-kit-v1");
const KITOKEN_VERSION: &str = "0.11";
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const STALE_LOCK_AGE: Duration = Duration::from_secs(300);

#[derive(Debug, Deserialize, Serialize)]
struct CompactTokenizerMetadata {
    schema_version: u32,
    converter_version: String,
    kitoken_version: String,
    source_model: String,
    source_blake3: String,
    kit_blake3: String,
}

pub(super) fn ensure_granite_compact_tokenizer(
    minilm: &MiniLmManifest,
    tokenizer_json: &Path,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    ensure_granite_compact_tokenizer_with(minilm, tokenizer_json, convert_huggingface_to_compact)
}

pub(super) fn ensure_granite_compact_tokenizer_with(
    minilm: &MiniLmManifest,
    tokenizer_json: &Path,
    converter: fn(&Path, &Path) -> NtdbResult<()>,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let Some(source_model) = supported_granite_model(minilm) else {
        return Ok(None);
    };
    let tokenizer_dir = tokenizer_json
        .parent()
        .ok_or_else(|| format!("tokenizer path has no parent: {}", tokenizer_json.display()))?;
    fs::create_dir_all(tokenizer_dir)?;

    let compact_path = tokenizer_dir.join("tokenizer.kit");
    let metadata_path = tokenizer_dir.join("tokenizer.kit.meta.json");
    let lock_path = tokenizer_dir.join("tokenizer.kit.lock");
    let source_hash = file_blake3(tokenizer_json)?;
    if cache_is_current(&compact_path, &metadata_path, source_model, &source_hash)? {
        return Ok(Some(compact_path));
    }

    let _lock = CacheLock::acquire(&lock_path)?;
    let source_hash = file_blake3(tokenizer_json)?;
    if cache_is_current(&compact_path, &metadata_path, source_model, &source_hash)? {
        return Ok(Some(compact_path));
    }

    // Never leave a readable but stale compact tokenizer in front of the canonical JSON.
    // If conversion fails below, RuntimeTokenizer must observe no `.kit` and fall back.
    remove_file_if_exists(&compact_path)?;
    remove_file_if_exists(&metadata_path)?;

    let mut compact_temp = TemporaryPath::new(tokenizer_dir, "tokenizer.kit.tmp")?;
    converter(tokenizer_json, compact_temp.path())
        .map_err(|err| format!("Granite tokenizer conversion failed: {err}"))?;
    File::open(compact_temp.path())?.sync_all()?;
    let kit_hash = file_blake3(compact_temp.path())?;

    compact_temp.persist(&compact_path)?;
    let metadata = CompactTokenizerMetadata {
        schema_version: CACHE_SCHEMA_VERSION,
        converter_version: CONVERTER_VERSION.to_string(),
        kitoken_version: KITOKEN_VERSION.to_string(),
        source_model: source_model.to_string(),
        source_blake3: source_hash,
        kit_blake3: kit_hash,
    };
    write_json_atomic(&metadata_path, &metadata)?;

    log::info!(
        "generated compact Granite tokenizer {} from {}",
        compact_path.display(),
        tokenizer_json.display()
    );
    Ok(Some(compact_path))
}

pub(super) fn remove_file_if_exists(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn supported_granite_model(minilm: &MiniLmManifest) -> Option<&str> {
    let family = minilm.tokenizer_family.as_deref()?;
    if !family.eq_ignore_ascii_case("ModernBERT") {
        return None;
    }
    [minilm.model.as_deref(), minilm.source_model_path.as_deref()]
        .into_iter()
        .flatten()
        .find(|identity| identity.to_ascii_lowercase().contains("granite"))
}

fn cache_is_current(
    compact_path: &Path,
    metadata_path: &Path,
    source_model: &str,
    source_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !compact_path.is_file() || !metadata_path.is_file() {
        return Ok(false);
    }
    let metadata: CompactTokenizerMetadata = match serde_json::from_slice(&fs::read(metadata_path)?)
    {
        Ok(metadata) => metadata,
        Err(_) => return Ok(false),
    };
    if metadata.schema_version != CACHE_SCHEMA_VERSION
        || metadata.converter_version != CONVERTER_VERSION
        || metadata.kitoken_version != KITOKEN_VERSION
        || metadata.source_model != source_model
        || metadata.source_blake3 != source_hash
    {
        return Ok(false);
    }
    Ok(file_blake3(compact_path)? == metadata.kit_blake3)
}

pub(super) fn file_blake3(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn write_json_atomic<T: Serialize>(
    destination: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("metadata path has no parent: {}", destination.display()))?;
    let mut temporary = TemporaryPath::new(parent, "tokenizer.kit.meta.tmp")?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(temporary.path())?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    temporary.persist(destination)
}

pub(super) struct TemporaryPath {
    path: PathBuf,
    active: bool,
}

impl TemporaryPath {
    pub(super) fn new(parent: &Path, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos();
        let path = parent.join(format!("{name}.{}.{}", std::process::id(), suffix));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self { path, active: true })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn persist(&mut self, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
        replace_file(&self.path, destination)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)?;
    Ok(())
}

pub(super) struct CacheLock {
    path: PathBuf,
}

impl CacheLock {
    pub(super) fn acquire(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let started = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    writeln!(file, "pid={}", std::process::id())?;
                    file.sync_all()?;
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(path) {
                        let _ = fs::remove_file(path);
                        continue;
                    }
                    if started.elapsed() >= LOCK_TIMEOUT {
                        return Err(format!(
                            "timed out waiting for compact tokenizer conversion lock {}",
                            path.display()
                        )
                        .into());
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age >= STALE_LOCK_AGE)
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, thread, time::SystemTime};

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "patronus_compact_tokenizer_{name}_{}_{}",
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn minilm(model: &str, family: &str) -> MiniLmManifest {
        MiniLmManifest {
            embedding_matrix_file: "embedding_matrix.f16".to_string(),
            vocab_size: 10,
            embedding_dim: 4,
            content_tokens_per_chunk: 8,
            source_model_path: Some(format!("models/{model}")),
            model: Some(model.to_string()),
            tokenizer_family: Some(family.to_string()),
            compab_l3_tokenizer: None,
        }
    }

    fn write_test_tokenizer(path: &Path) {
        fs::write(path, br#"{"model":"test-tokenizer"}"#).unwrap();
    }

    fn fake_converter(source: &Path, destination: &Path) -> NtdbResult<()> {
        let hash = blake3::hash(&fs::read(source)?);
        fs::write(destination, hash.as_bytes())?;
        Ok(())
    }

    fn failing_converter(_source: &Path, _destination: &Path) -> NtdbResult<()> {
        Err(std::io::Error::other("intentional conversion failure").into())
    }

    #[test]
    fn creates_reuses_and_invalidates_granite_cache() {
        let root = temp_dir("lifecycle");
        let tokenizer_json = root.join("tokenizer.json");
        write_test_tokenizer(&tokenizer_json);
        let minilm = minilm(
            "ibm-granite/granite-embedding-97m-multilingual-r2",
            "ModernBERT",
        );

        let compact_path =
            ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, fake_converter)
                .unwrap()
                .unwrap();
        let metadata_path = root.join("tokenizer.kit.meta.json");
        let original_compact = fs::read(&compact_path).unwrap();
        let original_metadata = fs::read(&metadata_path).unwrap();
        assert!(!original_compact.is_empty());

        assert_eq!(
            ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, fake_converter)
                .unwrap(),
            Some(compact_path.clone())
        );
        assert_eq!(fs::read(&compact_path).unwrap(), original_compact);
        assert_eq!(fs::read(&metadata_path).unwrap(), original_metadata);

        fs::write(&compact_path, b"corrupt").unwrap();
        ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, fake_converter).unwrap();
        assert_ne!(fs::read(&compact_path).unwrap(), b"corrupt");

        let source: serde_json::Value =
            serde_json::from_slice(&fs::read(&tokenizer_json).unwrap()).unwrap();
        fs::write(&tokenizer_json, serde_json::to_vec_pretty(&source).unwrap()).unwrap();
        let before = fs::read(&metadata_path).unwrap();
        ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, fake_converter).unwrap();
        assert_ne!(fs::read(&metadata_path).unwrap(), before);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_non_granite_or_non_modernbert_tokenizers() {
        let root = temp_dir("skip");
        let tokenizer_json = root.join("tokenizer.json");
        write_test_tokenizer(&tokenizer_json);

        assert!(ensure_granite_compact_tokenizer(
            &minilm("other/model", "ModernBERT"),
            &tokenizer_json
        )
        .unwrap()
        .is_none());
        assert!(ensure_granite_compact_tokenizer(
            &minilm("ibm-granite/granite-model", "SentencePiece"),
            &tokenizer_json
        )
        .unwrap()
        .is_none());
        assert!(!root.join("tokenizer.kit").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_regeneration_removes_stale_compact_cache() {
        let root = temp_dir("failed_regeneration");
        let tokenizer_json = root.join("tokenizer.json");
        write_test_tokenizer(&tokenizer_json);
        let minilm = minilm(
            "ibm-granite/granite-embedding-97m-multilingual-r2",
            "ModernBERT",
        );

        ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, fake_converter).unwrap();
        fs::write(&tokenizer_json, br#"{"model":"changed"}"#).unwrap();

        assert!(
            ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, failing_converter)
                .is_err()
        );
        assert!(!root.join("tokenizer.kit").exists());
        assert!(!root.join("tokenizer.kit.meta.json").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_conversion_produces_one_valid_cache() {
        let root = temp_dir("concurrent");
        let tokenizer_json = root.join("tokenizer.json");
        write_test_tokenizer(&tokenizer_json);
        let minilm = Arc::new(minilm(
            "ibm-granite/granite-embedding-97m-multilingual-r2",
            "ModernBERT",
        ));
        let tokenizer_json = Arc::new(tokenizer_json);

        let workers = (0..4)
            .map(|_| {
                let minilm = Arc::clone(&minilm);
                let tokenizer_json = Arc::clone(&tokenizer_json);
                thread::spawn(move || {
                    ensure_granite_compact_tokenizer_with(&minilm, &tokenizer_json, fake_converter)
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
            &root.join("tokenizer.kit.meta.json"),
            "ibm-granite/granite-embedding-97m-multilingual-r2",
            &file_blake3(&tokenizer_json).unwrap()
        )
        .unwrap());

        fs::remove_dir_all(root).unwrap();
    }
}
