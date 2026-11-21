// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::useless_conversion)] // PyO3-generated wrappers convert PyErr into PyErr.
use patronus_ark::{
    DynamicPiiConfig, GatewayConfig, QueuedSecurityEvent, SecurityFailure,
    SecurityGateway as RustSecurityGateway, SecurityLevelReadiness, SecurityRequestCompletion,
    SecurityRequestState, SecurityRuntimeReadiness, SecurityScanResult,
};
use patronus_ark_core::{
    cascade::ScanGateMatrix, cascade::SecurityLevel,
    normalization::normalize_text as rust_normalize_text, normalization::TextNormalizationConfig,
    NtdbOperatingPoint, SecurityCategory,
};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::mpsc::{self, SyncSender};
use std::sync::OnceLock;
use std::time::Duration;

mod py_serde;
use py_serde::PyStrings;

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
    /// `config_json`: the gateway config (`patronus_ark::GatewayConfig`),
    /// Ark Core's `Scanner` config plus Ark's keys. An unset `max_level`
    /// takes the Python default.
    #[new]
    fn new(config_json: &str) -> PyResult<Self> {
        let value_error = |error: String| pyo3::exceptions::PyValueError::new_err(error);
        let mut config: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(config_json).map_err(|error| value_error(error.to_string()))?;
        config
            .entry("max_level")
            .or_insert_with(|| patronus_ark::defaults::PYTHON_MAX_LEVEL.into());
        let config: GatewayConfig = serde_json::from_value(config.into())
            .map_err(|error| value_error(error.to_string()))?;
        // `dynamic_pii` runs only on L3; below it every scan would silently return nothing.
        if config
            .core
            .categories
            .contains(&SecurityCategory::DynamicPii)
            && config.core.max_level != SecurityLevel::L3
        {
            return Err(value_error(format!(
                "dynamic-pii runs only on L3; set max_level=\"l3\" (got {:?})",
                config.core.max_level.as_str()
            )));
        }
        let inner = RustSecurityGateway::new(config).map_err(value_error)?;
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

    fn scan_all(&self, py: Python<'_>, text: &str) -> PyResult<Vec<PyObject>> {
        let results = py.allow_threads(|| self.inner.scan_all(text));
        results_to_py(py, results)
    }

    #[pyo3(signature = (execution_gates_json=None))]
    fn set_execution_gates(&mut self, execution_gates_json: Option<&str>) -> PyResult<()> {
        let gates = parse_execution_gates_json(execution_gates_json)?.unwrap_or_default();
        self.inner.set_execution_gates(gates);
        Ok(())
    }

    fn set_dynamic_pii_config(&self, config_json: &str) -> PyResult<()> {
        let config = parse_dynamic_pii_config_json(Some(config_json))?
            .expect("dynamic-pii config JSON was provided");
        self.inner
            .set_dynamic_pii_config(config)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    fn scan_category(&self, py: Python<'_>, category: &str, text: &str) -> PyResult<Vec<PyObject>> {
        let cat = match category.parse::<SecurityCategory>() {
            Ok(c) => c,
            Err(e) => return Err(pyo3::exceptions::PyValueError::new_err(e)),
        };
        let results = py.allow_threads(|| self.inner.scan_category(cat, text));
        results_to_py(py, results)
    }

    fn scan_categories(
        &self,
        py: Python<'_>,
        categories: Vec<String>,
        text: &str,
    ) -> PyResult<Vec<PyObject>> {
        let rust_categories = parse_categories(categories)?;
        let profile = std::env::var_os("PATRONUS_PHASE_METRICS").is_some_and(|v| v == "1");
        let started = std::time::Instant::now();
        let results = py.allow_threads(|| self.inner.scan_categories(&rust_categories, text));
        let scanned = std::time::Instant::now();
        let results = results_to_py(py, results)?;
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
        let chunk_overlap_tokens =
            patronus_ark_core::ChunkOverlapTokens::try_from(chunk_overlap_tokens)
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
        py.allow_threads(|| self.inner.consume_next_event(timeout))
            .map(|event| security_event(py, event))
            .transpose()
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
    fn categories(&self) -> Vec<&'static str> {
        self.inner
            .categories()
            .iter()
            .map(|category| category.as_str())
            .collect()
    }

    #[getter]
    fn max_level(&self) -> &'static str {
        self.inner.max_level().as_str()
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

fn parse_ntdb_operating_point(value: &str) -> PyResult<NtdbOperatingPoint> {
    value
        .parse::<NtdbOperatingPoint>()
        .map_err(pyo3::exceptions::PyValueError::new_err)
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

/// The public result dicts, from the results' own `Serialize`: Core's result
/// fields, flat, plus `decided_by` and `l1_outcome` when set
/// (`docs/reference/result-schema.md`).
fn results_to_py(py: Python<'_>, results: Vec<SecurityScanResult>) -> PyResult<Vec<PyObject>> {
    let mut strings = PyStrings::new(py);
    let dicts = results
        .iter()
        .map(|result| result_dict(&mut strings, result).map(Bound::unbind))
        .collect::<PyResult<Vec<_>>>()?;
    let matched_rules = results.iter().map(matched_rules).sum();
    release(results, matched_rules);
    Ok(dicts)
}

/// One result dict; Python omits `decision` while it is unset.
fn result_dict<'py, T: serde::Serialize>(
    strings: &mut PyStrings<'py>,
    result: &T,
) -> PyResult<Bound<'py, PyAny>> {
    let dict = py_serde::to_py(strings, result)?.downcast_into::<PyDict>()?;
    if dict
        .get_item("decision")?
        .is_some_and(|decision| decision.is_none())
    {
        dict.del_item("decision")?;
    }
    Ok(dict.into_any())
}

fn matched_rules(result: &SecurityScanResult) -> usize {
    result
        .layers
        .iter()
        .filter_map(|layer| layer.details.get("matched_rules"))
        .filter_map(serde_json::Value::as_array)
        .map(Vec::len)
        .sum()
}

/// Results with many `matched_rules` go to [`release_off_thread`]; freeing a
/// few entries here costs less than waking the thread.
fn release<T: Send + 'static>(results: T, matched_rules: usize) {
    const RELEASE_OFF_THREAD_MIN_RULES: usize = 64;
    if matched_rules >= RELEASE_OFF_THREAD_MIN_RULES {
        release_off_thread(results);
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
struct PySecurityEvent {
    #[pyo3(get)]
    event_type: String,
    #[pyo3(get)]
    request_id: String,
    /// The result dict of a `result` or `provisional` event.
    result: Option<PyObject>,
    /// The progress dict of a `progress` event.
    progress: Option<PyObject>,
    #[pyo3(get)]
    completion: Option<String>,
    #[pyo3(get)]
    failures: Vec<PySecurityFailure>,
}

#[pymethods]
impl PySecurityEvent {
    #[getter]
    fn result(&self, py: Python<'_>) -> Option<PyObject> {
        self.result.as_ref().map(|result| result.clone_ref(py))
    }

    #[getter]
    fn progress(&self, py: Python<'_>) -> Option<PyObject> {
        self.progress
            .as_ref()
            .map(|progress| progress.clone_ref(py))
    }
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

fn security_event(py: Python<'_>, event: QueuedSecurityEvent) -> PyResult<PySecurityEvent> {
    let (event_type, queued) = match event {
        QueuedSecurityEvent::Result(queued) => ("result", queued),
        QueuedSecurityEvent::Provisional(queued) => ("provisional", queued),
        QueuedSecurityEvent::Progress(progress) => {
            return Ok(PySecurityEvent {
                event_type: "progress".to_string(),
                request_id: progress.request_id.clone(),
                result: None,
                progress: Some(py_serde::to_py(&mut PyStrings::new(py), &progress)?.unbind()),
                completion: None,
                failures: Vec::new(),
            })
        }
        QueuedSecurityEvent::Finished {
            request_id,
            completion,
        } => {
            let (completion, failures) = completion_parts(completion);
            return Ok(PySecurityEvent {
                event_type: "finished".to_string(),
                request_id,
                result: None,
                progress: None,
                completion: Some(completion),
                failures,
            });
        }
    };
    let result = result_dict(&mut PyStrings::new(py), &queued)?;
    let matched_rules = matched_rules(&queued.result);
    let request_id = queued.request_id.clone();
    release(queued, matched_rules);
    Ok(PySecurityEvent {
        event_type: event_type.to_string(),
        request_id,
        result: Some(result.unbind()),
        progress: None,
        completion: None,
        failures: Vec::new(),
    })
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

#[pymodule]
fn _patronus_ark(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_text, m)?)?;
    m.add_class::<SecurityGateway>()?;
    m.add_class::<PySecurityFailure>()?;
    m.add_class::<PySecurityEvent>()?;
    m.add_class::<PyRequestState>()?;
    m.add_class::<PyLevelReadiness>()?;
    m.add_class::<PyRuntimeReadiness>()?;
    Ok(())
}
