// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::useless_conversion)] // PyO3-generated wrappers convert PyErr into PyErr.
use patronus_ark::{
    detectors::shell::ShellPolicyConfig, normalize_text as rust_normalize_text,
    CacheEncryptionConfig, CacheWriteMode, DynamicPiiConfig, EvidenceSpan, ExactCacheConfig,
    ExecutionBackend, L3Strategy, LabelScore, LayerResult, MemoryCacheConfig, NtdbOperatingPoint,
    OnnxBatchMode, PersistentCacheConfig, QueuedSecurityEvent, QueuedSecurityScanResult,
    ScanGateMatrix, SecurityCategory, SecurityFailure, SecurityGateway as RustSecurityGateway,
    SecurityLevel, SecurityLevelReadiness, SecurityRequestCompletion, SecurityRequestState,
    SecurityRuntimeReadiness, TextNormalizationConfig, WolfExecutionOptions, WriteBehindConfig,
};
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBool, PyDict, PyList, PyString};
use rustc_hash::FxHashMap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[pyfunction]
#[pyo3(signature = (text, configs_json=None))]
fn normalize_text(text: &str, configs_json: Option<&str>) -> PyResult<String> {
    let config = parse_text_normalization_config_json(configs_json)?;
    Ok(rust_normalize_text(text, &config))
}

#[pyclass]
struct SecurityGateway {
    inner: RustSecurityGateway,
}

#[pymethods]
impl SecurityGateway {
    #[new]
    #[allow(clippy::too_many_arguments)] // Public Python constructor signature.
    #[pyo3(signature = (categories, max_level="l2", model_dir=None, download_files=true, download_categories=None, execution_gates_json=None, onnx_batch_mode="backend_default", execution_backend="auto", ntdb_operating_point="best_f1", l3_strategy="dedicated", dynamic_pii_config_json=None, cache_storage_location=None, cache_encryption_key_hex=None, cache_entry_ttl_seconds=2_592_000, cache_memory_max_entries=100_000, cache_memory_max_bytes=134_217_728, *, wolf_options_json=None))]
    fn new(
        categories: Vec<String>,
        max_level: &str,
        model_dir: Option<String>,
        download_files: bool,
        download_categories: Option<Vec<String>>,
        execution_gates_json: Option<&str>,
        onnx_batch_mode: &str,
        execution_backend: &str,
        ntdb_operating_point: &str,
        l3_strategy: &str,
        dynamic_pii_config_json: Option<&str>,
        cache_storage_location: Option<String>,
        cache_encryption_key_hex: Option<&str>,
        cache_entry_ttl_seconds: u64,
        cache_memory_max_entries: usize,
        cache_memory_max_bytes: usize,
        wolf_options_json: Option<&str>,
    ) -> PyResult<Self> {
        let wolf_options = parse_wolf_options_json(wolf_options_json)?;
        if cache_entry_ttl_seconds == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "cache_entry_ttl_seconds must be positive",
            ));
        }
        let rust_categories = parse_categories(categories)?;
        let rust_max_level = match max_level.parse::<SecurityLevel>() {
            Ok(level) => level,
            Err(e) => return Err(pyo3::exceptions::PyValueError::new_err(e)),
        };
        // `dynamic-pii` runs only on L3; below it every scan would silently return nothing.
        if rust_categories.contains(&SecurityCategory::DynamicPii)
            && rust_max_level != SecurityLevel::L3
        {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "dynamic-pii runs only on L3; set max_level=\"l3\" (got {max_level:?})"
            )));
        }
        let rust_model_dir = model_dir.map(PathBuf::from);
        let rust_download_categories = match download_categories {
            Some(categories) => Some(parse_categories(categories)?),
            None => None,
        };
        let encryption = parse_cache_encryption_key_hex(cache_encryption_key_hex)?;
        let cache_config = ExactCacheConfig {
            memory: MemoryCacheConfig {
                max_entries: cache_memory_max_entries,
                max_bytes: cache_memory_max_bytes,
            },
            persistent: cache_storage_location.map(|storage_location| PersistentCacheConfig {
                storage_location: PathBuf::from(storage_location),
                write_mode: CacheWriteMode::Async,
                write_behind: WriteBehindConfig::default(),
                encryption: encryption.clone(),
            }),
            entry_ttl: Duration::from_secs(cache_entry_ttl_seconds),
        };
        let inner = RustSecurityGateway::try_with_download_categories_and_cache(
            rust_categories,
            rust_max_level,
            rust_model_dir,
            download_files,
            rust_download_categories,
            cache_config,
        )
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        if let Some(gates) = parse_execution_gates_json(execution_gates_json)? {
            inner.set_execution_gates(gates);
        }
        inner.set_execution_backend(parse_execution_backend(execution_backend)?);
        inner.set_ntdb_decision_threshold_point(parse_ntdb_operating_point(ntdb_operating_point)?);
        inner.set_l3_strategy(parse_l3_strategy(l3_strategy)?);
        if let Some(options) = wolf_options {
            inner
                .set_wolf_execution_options(options)
                .map_err(pyo3::exceptions::PyValueError::new_err)?;
        }
        if onnx_batch_mode != "backend_default" {
            inner.set_onnx_batch_mode(parse_onnx_batch_mode(onnx_batch_mode)?);
        }
        if let Some(config) = parse_dynamic_pii_config_json(dynamic_pii_config_json)? {
            inner
                .set_dynamic_pii_config(config)
                .map_err(pyo3::exceptions::PyValueError::new_err)?;
        }
        Ok(SecurityGateway { inner })
    }

    fn warmup(&mut self, py: Python<'_>) -> PyResult<()> {
        match py.allow_threads(|| self.inner.warmup().map_err(|err| err.to_string())) {
            Ok(()) => Ok(()),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e)),
        }
    }

    fn stop_l3_models(&self, py: Python<'_>) {
        py.allow_threads(|| self.inner.stop_l3_models());
    }

    fn flush_cache(&self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.flush_cache())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    fn reset_cache_connections(&self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.reset_cache_connections())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    fn reset_cache(&self, py: Python<'_>, until_ts_unix_ms: u64) -> PyResult<usize> {
        py.allow_threads(|| self.inner.reset_cache(until_ts_unix_ms))
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    fn scan_all(&self, py: Python<'_>, text: &str) -> PyResult<Vec<PyEvaluationResult>> {
        let results = py.allow_threads(|| self.inner.scan_all(text));
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    #[pyo3(signature = (execution_gates_json=None))]
    fn set_execution_gates(&mut self, execution_gates_json: Option<&str>) -> PyResult<()> {
        let gates = parse_execution_gates_json(execution_gates_json)?.unwrap_or_default();
        self.inner.set_execution_gates(gates);
        Ok(())
    }

    fn set_onnx_batch_mode(&mut self, mode: &str) -> PyResult<()> {
        self.inner.set_onnx_batch_mode(parse_onnx_batch_mode(mode)?);
        Ok(())
    }

    fn set_execution_backend(&mut self, backend: &str) -> PyResult<()> {
        self.inner
            .set_execution_backend(parse_execution_backend(backend)?);
        Ok(())
    }

    fn set_ntdb_operating_point(&mut self, point: &str) -> PyResult<()> {
        self.inner
            .set_ntdb_decision_threshold_point(parse_ntdb_operating_point(point)?);
        Ok(())
    }

    fn set_l3_strategy(&mut self, strategy: &str) -> PyResult<()> {
        self.inner.set_l3_strategy(parse_l3_strategy(strategy)?);
        Ok(())
    }

    fn set_dynamic_pii_config(&self, config_json: &str) -> PyResult<()> {
        let config = parse_dynamic_pii_config_json(Some(config_json))?
            .expect("dynamic-pii config JSON was provided");
        self.inner
            .set_dynamic_pii_config(config)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[pyo3(signature = (policy_dirs=None, allowlist=None))]
    fn set_shell_command_policy_config(
        &self,
        policy_dirs: Option<Vec<PathBuf>>,
        allowlist: Option<std::collections::BTreeMap<String, String>>,
    ) -> PyResult<()> {
        ShellPolicyConfig::load(
            &policy_dirs.unwrap_or_default(),
            &allowlist.unwrap_or_default(),
        )
        .and_then(|config| self.inner.set_shell_command_policy_config(config))
        .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    fn scan_category(
        &self,
        py: Python<'_>,
        category: &str,
        text: &str,
    ) -> PyResult<Vec<PyEvaluationResult>> {
        let cat = match category.parse::<SecurityCategory>() {
            Ok(c) => c,
            Err(e) => return Err(pyo3::exceptions::PyValueError::new_err(e)),
        };
        let results = py.allow_threads(|| self.inner.scan_category(cat, text));
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    fn scan_categories(
        &self,
        py: Python<'_>,
        categories: Vec<String>,
        text: &str,
    ) -> PyResult<Vec<PyEvaluationResult>> {
        let rust_categories = parse_categories(categories)?;
        let profile = std::env::var_os("PATRONUS_PHASE_METRICS").is_some_and(|v| v == "1");
        let started = std::time::Instant::now();
        let results = py.allow_threads(|| self.inner.scan_categories(&rust_categories, text));
        let scanned = std::time::Instant::now();
        let results = results.into_iter().map(PyEvaluationResult::from).collect();
        if profile {
            eprintln!(
                "L1_BINDING_PROFILE scan_ms={} result_conversion_ms={}",
                scanned.duration_since(started).as_secs_f64() * 1000.0,
                scanned.elapsed().as_secs_f64() * 1000.0
            );
        }
        Ok(results)
    }

    #[pyo3(signature = (text, categories=None, execution_gates_json=None, metadata_json=None, ntdb_operating_point=None, chunk_overlap_tokens=0))]
    #[allow(clippy::too_many_arguments)]
    fn enqueue(
        &self,
        py: Python<'_>,
        text: &str,
        categories: Option<Vec<String>>,
        execution_gates_json: Option<&str>,
        metadata_json: Option<&str>,
        ntdb_operating_point: Option<&str>,
        chunk_overlap_tokens: i64,
    ) -> PyResult<String> {
        let chunk_overlap_tokens = patronus_ark::ChunkOverlapTokens::try_from(chunk_overlap_tokens)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        let gates = parse_execution_gates_json(execution_gates_json)?;
        let ntdb_operating_point = ntdb_operating_point
            .map(parse_ntdb_operating_point)
            .transpose()?;
        let metadata = metadata_json
            .map(|value| {
                serde_json::from_str(value)
                    .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
            })
            .transpose()?
            .unwrap_or_else(|| serde_json::json!({}));
        let request_id = match categories {
            Some(categories) => {
                let rust_categories = parse_categories(categories)?;
                py.allow_threads(|| {
                    self.inner.enqueue_categories_with_chunk_overlap_options(
                        rust_categories,
                        text,
                        metadata,
                        gates,
                        ntdb_operating_point,
                        chunk_overlap_tokens,
                    )
                })
            }
            None => py.allow_threads(|| {
                self.inner.enqueue_with_chunk_overlap_options(
                    text,
                    metadata,
                    gates,
                    ntdb_operating_point,
                    chunk_overlap_tokens,
                )
            }),
        };
        Ok(request_id)
    }

    #[pyo3(signature = (timeout=None))]
    fn consume_next_event(
        &self,
        py: Python<'_>,
        timeout: Option<f64>,
    ) -> PyResult<Option<PySecurityEvent>> {
        let timeout = timeout.map(Duration::from_secs_f64);
        Ok(py
            .allow_threads(|| self.inner.consume_next_event(timeout))
            .map(PySecurityEvent::from))
    }

    fn has_request(&self, request_id: &str) -> bool {
        self.inner.has_request(request_id)
    }

    fn request_state(&self, request_id: &str) -> Option<PyRequestState> {
        self.inner
            .request_state(request_id)
            .map(PyRequestState::from)
    }

    fn is_finished(&self, request_id: &str) -> Option<bool> {
        self.inner.is_finished(request_id)
    }

    fn runtime_readiness(&self) -> PyRuntimeReadiness {
        PyRuntimeReadiness::from(self.inner.runtime_readiness())
    }

    #[getter]
    fn wolf_options(&self) -> std::collections::HashMap<&'static str, usize> {
        let options = self.inner.distributed_execution().wolf_execution_options();
        [
            ("window_tokens", options.window_tokens),
            ("overlap_tokens", options.overlap_tokens),
            ("batch_size", options.batch_size),
        ]
        .into_iter()
        .collect()
    }

    #[getter]
    fn l3_strategy(&self) -> String {
        self.inner.l3_strategy().as_str().to_string()
    }
}

fn parse_categories(categories: Vec<String>) -> PyResult<Vec<SecurityCategory>> {
    categories
        .into_iter()
        .map(|cat_str| {
            cat_str
                .parse::<SecurityCategory>()
                .map_err(pyo3::exceptions::PyValueError::new_err)
        })
        .collect()
}

fn parse_onnx_batch_mode(value: &str) -> PyResult<OnnxBatchMode> {
    value
        .parse::<OnnxBatchMode>()
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

fn parse_execution_backend(value: &str) -> PyResult<ExecutionBackend> {
    value
        .parse::<ExecutionBackend>()
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

fn parse_ntdb_operating_point(value: &str) -> PyResult<NtdbOperatingPoint> {
    value
        .parse::<NtdbOperatingPoint>()
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

fn parse_l3_strategy(value: &str) -> PyResult<L3Strategy> {
    value
        .parse::<L3Strategy>()
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

fn parse_cache_encryption_key_hex(value: Option<&str>) -> PyResult<Option<CacheEncryptionConfig>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() != 64 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "cache_encryption_key_hex must contain exactly 64 hex characters",
        ));
    }
    let mut key = [0u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        key[index] = (high << 4) | low;
    }
    Ok(Some(CacheEncryptionConfig::from_key(key)))
}

fn hex_nibble(value: u8) -> PyResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "cache_encryption_key_hex must contain only hex characters",
        )),
    }
}

fn parse_wolf_options_json(value: Option<&str>) -> PyResult<Option<WolfExecutionOptions>> {
    value
        .map(|value| {
            let options: WolfExecutionOptions = serde_json::from_str(value)
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            options
                .validate()
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            Ok(options)
        })
        .transpose()
}

fn parse_dynamic_pii_config_json(value: Option<&str>) -> PyResult<Option<DynamicPiiConfig>> {
    value
        .map(|value| {
            serde_json::from_str::<DynamicPiiConfig>(value)
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?
                .validated()
                .map_err(pyo3::exceptions::PyValueError::new_err)
        })
        .transpose()
}

fn parse_text_normalization_config_json(value: Option<&str>) -> PyResult<TextNormalizationConfig> {
    let Some(value) = value else {
        return Ok(TextNormalizationConfig::default());
    };
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("configs must be a JSON object"))?;
    let mut config = TextNormalizationConfig::default();
    for (key, value) in object {
        let enabled = value.as_bool().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("configs.{key} must be a boolean"))
        })?;
        match key.as_str() {
            "html_entities" | "html" | "decode_html_entities" => config.html_entities = enabled,
            "nfkc" | "unicode_nfkc" | "unicode_normalization" => config.nfkc = enabled,
            "confusables" | "homoglyphs" => config.confusables = enabled,
            "format_characters" | "unicode_format_characters" | "zero_width" => {
                config.format_characters = enabled
            }
            "whitespace" | "collapse_whitespace" => config.whitespace = enabled,
            "trim" => config.trim = enabled,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown normalize_text config: {key}"
                )));
            }
        }
    }
    Ok(config)
}

/// Execution gates in the one gate schema of [`ScanGateMatrix`].
fn parse_execution_gates_json(value: Option<&str>) -> PyResult<Option<ScanGateMatrix>> {
    value
        .map(|value| {
            serde_json::from_str(value).map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!("execution_gates: {error}"))
            })
        })
        .transpose()
}

#[pyclass]
#[derive(Clone)]
struct PyLayerResult {
    #[pyo3(get)]
    level: String,
    #[pyo3(get)]
    layer_type: String,
    #[pyo3(get)]
    class_name: String,
    #[pyo3(get)]
    confidence: f64,
    #[pyo3(get)]
    matched: bool,
    #[pyo3(get)]
    duration_ms: f64,
    thresholds: HashMap<String, f64>,
    // Shared, so the `layers` getter clones a pointer and not the `matched_rules`.
    details: Arc<HashMap<String, serde_json::Value>>,
}

#[pymethods]
impl PyLayerResult {
    #[getter]
    fn thresholds(&self, py: Python<'_>) -> PyResult<PyObject> {
        Ok(self
            .thresholds
            .clone()
            .into_py_dict_bound(py)
            .into_any()
            .unbind())
    }

    /// The layer details as Python objects, built directly from the JSON values:
    /// a JSON text round trip (`serde_json` out, `json.loads` in) cost more than
    /// the scan on large texts (H06-2).
    #[getter]
    fn details(&self, py: Python<'_>) -> PyResult<PyObject> {
        let mut strings = PyStrings::new(py);
        let details = PyDict::new_bound(py);
        for (key, value) in self.details.iter() {
            details.set_item(strings.key(key), strings.json_to_py(value)?)?;
        }
        Ok(details.into_any().unbind())
    }
}

impl Drop for PyLayerResult {
    /// Large details go to [`release_off_thread`]; freeing a few entries
    /// here costs less than waking the thread.
    fn drop(&mut self) {
        const RELEASE_OFF_THREAD_MIN_RULES: usize = 64;
        let large = self
            .details
            .get("matched_rules")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|rules| rules.len() >= RELEASE_OFF_THREAD_MIN_RULES);
        if large && Arc::strong_count(&self.details) == 1 {
            release_off_thread(std::mem::take(&mut self.details));
        }
    }
}

/// Frees `value` on a background thread. The `matched_rules` of a 100 KiB
/// scan are about 20 000 small allocations, and freeing them with the GIL
/// held, when Python releases a result, cost about 2 ms per call (H06-3).
/// The queue is bounded: when the thread falls behind, the caller frees.
fn release_off_thread<T: Send + 'static>(value: T) {
    const QUEUED: usize = 64;
    static RELEASER: OnceLock<Option<SyncSender<Box<dyn Send>>>> = OnceLock::new();
    let releaser = RELEASER.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Box<dyn Send>>(QUEUED);
        std::thread::Builder::new()
            .name("patronus-release".into())
            .spawn(move || receiver.into_iter().for_each(drop))
            .ok()
            .map(|_| sender)
    });
    match releaser {
        // A full queue hands the value back in the error, freed here.
        Some(sender) => drop(sender.try_send(Box::new(value))),
        None => drop(value),
    }
}

/// Builds the Python objects of JSON values and shares one string object per
/// distinct text: the keys and most string values (`rule_id`,
/// `span_precision`, …) repeat in every `matched_rules` entry, and creating
/// and freeing a string per occurrence cost about a third of the details of
/// a 100 KiB scan (H06-3). A shared value string is equal and immutable, so
/// the dicts are the ones `json.loads` makes. The texts are short (rule
/// ids, component names, labels), so the cache hashes with Fx: SipHash cost
/// about a fifth of the details of a 100 KiB scan (H06-5).
struct PyStrings<'py, 'a> {
    py: Python<'py>,
    strings: FxHashMap<&'a str, Bound<'py, PyString>>,
}

impl<'py, 'a> PyStrings<'py, 'a> {
    fn new(py: Python<'py>) -> Self {
        Self {
            py,
            strings: FxHashMap::default(),
        }
    }

    /// A dict key, interned like the keys `json.loads` memoizes.
    fn key(&mut self, text: &'a str) -> Bound<'py, PyString> {
        let py = self.py;
        self.strings
            .entry(text)
            .or_insert_with(|| PyString::intern_bound(py, text))
            .clone()
    }

    /// A string value; not interned, as it may hold scanned text.
    fn value(&mut self, text: &'a str) -> Bound<'py, PyString> {
        let py = self.py;
        self.strings
            .entry(text)
            .or_insert_with(|| PyString::new_bound(py, text))
            .clone()
    }

    /// A JSON value as the Python object that `json.loads` makes of its JSON text.
    fn json_to_py(&mut self, value: &'a serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
        use serde_json::Value;
        let py = self.py;
        Ok(match value {
            Value::Null => py.None().into_bound(py),
            Value::Bool(flag) => PyBool::new_bound(py, *flag).to_owned().into_any(),
            Value::Number(number) => match (number.as_i64(), number.as_u64()) {
                (Some(int), _) => int.into_py(py).into_bound(py),
                (None, Some(int)) => int.into_py(py).into_bound(py),
                _ => number.as_f64().into_py(py).into_bound(py),
            },
            Value::String(text) => self.value(text).into_any(),
            Value::Array(items) => {
                let list = PyList::empty_bound(py);
                for item in items {
                    list.append(self.json_to_py(item)?)?;
                }
                list.into_any()
            }
            Value::Object(map) => {
                let dict = PyDict::new_bound(py);
                for (key, item) in map {
                    dict.set_item(self.key(key), self.json_to_py(item)?)?;
                }
                dict.into_any()
            }
        })
    }
}

#[pyclass]
#[derive(Clone)]
struct PyEvaluationResult {
    #[pyo3(get)]
    request_id: Option<String>,
    #[pyo3(get)]
    category: String,
    #[pyo3(get)]
    class_name: String,
    #[pyo3(get)]
    confidence: f64,
    #[pyo3(get)]
    level: String,
    #[pyo3(get)]
    model: String,
    #[pyo3(get)]
    duration_ms: f64,
    #[pyo3(get)]
    layers: Vec<PyLayerResult>,
    // Shared, so cloning a result (an event) does not copy its spans.
    evidence_spans: Arc<Vec<EvidenceSpan>>,
    #[pyo3(get)]
    label_scores: Vec<PyLabelScore>,
    #[pyo3(get)]
    decision_json: Option<String>,
}

#[pymethods]
impl PyEvaluationResult {
    /// The evidence spans as the dicts of the public result, built here: a
    /// span object per span read field by field in Python cost about 2 ms per
    /// 1 000 spans (H06-2).
    #[getter]
    fn evidence_spans<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let keys = [
            "label",
            "text",
            "score",
            "start_byte",
            "end_byte",
            "start_char",
            "end_char",
        ]
        .map(|key| PyString::intern_bound(py, key));
        let mut labels = PyStrings::new(py);
        self.evidence_spans
            .iter()
            .map(|span| {
                let dict = PyDict::new_bound(py);
                // Bound values: a dropped `PyObject` checks the GIL first.
                dict.set_item(&keys[0], labels.value(&span.label))?;
                dict.set_item(&keys[1], PyString::new_bound(py, &span.text))?;
                dict.set_item(&keys[2], span.score.into_py(py).into_bound(py))?;
                dict.set_item(&keys[3], span.start_byte.into_py(py).into_bound(py))?;
                dict.set_item(&keys[4], span.end_byte.into_py(py).into_bound(py))?;
                dict.set_item(&keys[5], span.start_char.into_py(py).into_bound(py))?;
                dict.set_item(&keys[6], span.end_char.into_py(py).into_bound(py))?;
                Ok(dict)
            })
            .collect()
    }
}

#[pyclass]
#[derive(Clone)]
struct PyLabelScore {
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    confidence: f64,
    #[pyo3(get)]
    matched: bool,
}

#[pyclass]
#[derive(Clone)]
struct PySecurityFailure {
    #[pyo3(get)]
    stage: String,
    #[pyo3(get)]
    level: Option<String>,
    #[pyo3(get)]
    detector_id: Option<String>,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    retryable: bool,
    #[pyo3(get)]
    message: String,
}

#[pyclass]
#[derive(Clone)]
struct PySecurityEvent {
    #[pyo3(get)]
    event_type: String,
    #[pyo3(get)]
    request_id: String,
    #[pyo3(get)]
    result: Option<PyEvaluationResult>,
    #[pyo3(get)]
    completion: Option<String>,
    #[pyo3(get)]
    failures: Vec<PySecurityFailure>,
    #[pyo3(get)]
    progress_json: Option<String>,
}

#[pyclass]
#[derive(Clone)]
struct PyRequestState {
    #[pyo3(get)]
    state: String,
    #[pyo3(get)]
    completion: Option<String>,
    #[pyo3(get)]
    failures: Vec<PySecurityFailure>,
}

#[pyclass]
#[derive(Clone)]
struct PyLevelReadiness {
    #[pyo3(get)]
    state: String,
    #[pyo3(get)]
    failures: Vec<PySecurityFailure>,
}

#[pyclass]
#[derive(Clone)]
struct PyRuntimeReadiness {
    #[pyo3(get)]
    l1: PyLevelReadiness,
    #[pyo3(get)]
    l2: PyLevelReadiness,
    #[pyo3(get)]
    l3: PyLevelReadiness,
}

impl From<SecurityFailure> for PySecurityFailure {
    fn from(failure: SecurityFailure) -> Self {
        Self {
            stage: failure.stage.as_str().to_string(),
            level: failure.level.map(|level| level.as_str().to_string()),
            detector_id: failure.detector_id,
            kind: failure.kind.as_str().to_string(),
            retryable: failure.retryable,
            message: failure.message,
        }
    }
}

fn completion_parts(completion: SecurityRequestCompletion) -> (String, Vec<PySecurityFailure>) {
    match completion {
        SecurityRequestCompletion::Complete => ("complete".to_string(), Vec::new()),
        SecurityRequestCompletion::Degraded { failures } => (
            "degraded".to_string(),
            failures.into_iter().map(PySecurityFailure::from).collect(),
        ),
        SecurityRequestCompletion::Failed { failures } => (
            "failed".to_string(),
            failures.into_iter().map(PySecurityFailure::from).collect(),
        ),
    }
}

impl From<QueuedSecurityEvent> for PySecurityEvent {
    fn from(event: QueuedSecurityEvent) -> Self {
        match event {
            QueuedSecurityEvent::Result(queued) => Self {
                event_type: "result".to_string(),
                request_id: queued.request_id.clone(),
                result: Some(PyEvaluationResult::from(queued)),
                completion: None,
                failures: Vec::new(),
                progress_json: None,
            },
            QueuedSecurityEvent::Provisional(queued) => Self {
                event_type: "provisional".to_string(),
                request_id: queued.request_id.clone(),
                result: Some(PyEvaluationResult::from(queued)),
                completion: None,
                failures: Vec::new(),
                progress_json: None,
            },
            QueuedSecurityEvent::Progress(progress) => Self {
                event_type: "progress".to_string(),
                request_id: progress.request_id.clone(),
                result: None,
                completion: None,
                failures: Vec::new(),
                progress_json: Some(
                    serde_json::to_string(&progress).unwrap_or_else(|_| "{}".to_string()),
                ),
            },
            QueuedSecurityEvent::Finished {
                request_id,
                completion,
            } => {
                let (completion, failures) = completion_parts(completion);
                Self {
                    event_type: "finished".to_string(),
                    request_id,
                    result: None,
                    completion: Some(completion),
                    failures,
                    progress_json: None,
                }
            }
        }
    }
}

impl From<SecurityRequestState> for PyRequestState {
    fn from(state: SecurityRequestState) -> Self {
        match state {
            SecurityRequestState::Running => Self {
                state: "running".to_string(),
                completion: None,
                failures: Vec::new(),
            },
            SecurityRequestState::Finished(completion) => {
                let (completion, failures) = completion_parts(completion);
                Self {
                    state: "finished".to_string(),
                    completion: Some(completion),
                    failures,
                }
            }
        }
    }
}

impl From<SecurityLevelReadiness> for PyLevelReadiness {
    fn from(readiness: SecurityLevelReadiness) -> Self {
        match readiness {
            SecurityLevelReadiness::Ready => Self {
                state: "ready".to_string(),
                failures: Vec::new(),
            },
            SecurityLevelReadiness::NotConfigured => Self {
                state: "not_configured".to_string(),
                failures: Vec::new(),
            },
            SecurityLevelReadiness::NotReady { failures } => Self {
                state: "not_ready".to_string(),
                failures: failures.into_iter().map(PySecurityFailure::from).collect(),
            },
        }
    }
}

impl From<SecurityRuntimeReadiness> for PyRuntimeReadiness {
    fn from(readiness: SecurityRuntimeReadiness) -> Self {
        Self {
            l1: PyLevelReadiness::from(readiness.l1),
            l2: PyLevelReadiness::from(readiness.l2),
            l3: PyLevelReadiness::from(readiness.l3),
        }
    }
}

impl From<patronus_ark::SecurityScanResult> for PyEvaluationResult {
    fn from(result: patronus_ark::SecurityScanResult) -> Self {
        let decision_json = result
            .decision
            .as_ref()
            .and_then(|decision| serde_json::to_string(decision).ok());
        PyEvaluationResult {
            request_id: None,
            category: result.category,
            class_name: result.class_name,
            confidence: result.confidence,
            level: result.level,
            model: result.model,
            duration_ms: result.duration_ms,
            layers: result.layers.into_iter().map(PyLayerResult::from).collect(),
            evidence_spans: Arc::new(result.evidence_spans),
            label_scores: result
                .label_scores
                .into_iter()
                .map(PyLabelScore::from)
                .collect(),
            decision_json,
        }
    }
}

impl From<LabelScore> for PyLabelScore {
    fn from(score: LabelScore) -> Self {
        Self {
            label: score.label,
            confidence: score.confidence,
            matched: score.matched,
        }
    }
}

impl From<QueuedSecurityScanResult> for PyEvaluationResult {
    fn from(queued: QueuedSecurityScanResult) -> Self {
        let mut result = PyEvaluationResult::from(queued.result);
        result.request_id = Some(queued.request_id);
        result
    }
}

impl From<LayerResult> for PyLayerResult {
    fn from(layer: LayerResult) -> Self {
        PyLayerResult {
            level: layer.level,
            layer_type: layer.layer_type,
            class_name: layer.class_name,
            confidence: layer.confidence,
            matched: layer.matched,
            duration_ms: layer.duration_ms,
            thresholds: layer.thresholds,
            details: Arc::new(layer.details),
        }
    }
}

#[pymodule]
fn _patronus_ark(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_text, m)?)?;
    m.add_class::<SecurityGateway>()?;
    m.add_class::<PyLayerResult>()?;
    m.add_class::<PyEvaluationResult>()?;
    m.add_class::<PyLabelScore>()?;
    m.add_class::<PySecurityFailure>()?;
    m.add_class::<PySecurityEvent>()?;
    m.add_class::<PyRequestState>()?;
    m.add_class::<PyLevelReadiness>()?;
    m.add_class::<PyRuntimeReadiness>()?;
    Ok(())
}
