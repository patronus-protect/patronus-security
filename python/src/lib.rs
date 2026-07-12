use patronus_security::{
    ExecutionBackend, L3SchedulerPolicy, LayerResult, LongTextPolicy, NtdbOperatingPoint,
    OnnxBatchMode, QueuedSecurityScanResult, ScanGateMatrix, SecurityCategory,
    SecurityGateway as RustSecurityGateway, SecurityLevel,
};
use pyo3::prelude::*;
use std::path::PathBuf;
use std::time::Duration;

#[pyclass]
struct SecurityGateway {
    inner: RustSecurityGateway,
}

#[pymethods]
impl SecurityGateway {
    #[new]
    #[pyo3(signature = (categories, max_level="l2", model_dir=None, download_files=true, download_categories=None, execution_gates_json=None, onnx_batch_mode="backend_default", execution_backend="auto", ntdb_operating_point="best_promote"))]
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
    ) -> PyResult<Self> {
        let rust_categories = parse_categories(categories)?;
        let rust_max_level = match max_level.parse::<SecurityLevel>() {
            Ok(level) => level,
            Err(e) => return Err(pyo3::exceptions::PyValueError::new_err(e)),
        };
        let rust_model_dir = model_dir.map(PathBuf::from);
        let rust_download_categories = match download_categories {
            Some(categories) => Some(parse_categories(categories)?),
            None => None,
        };
        let inner = RustSecurityGateway::with_download_categories(
            rust_categories,
            rust_max_level,
            rust_model_dir,
            download_files,
            rust_download_categories,
        );
        if let Some(gates) = parse_execution_gates_json(execution_gates_json)? {
            inner.set_execution_gates(gates);
        }
        inner.set_execution_backend(parse_execution_backend(execution_backend)?);
        inner.set_ntdb_operating_point(parse_ntdb_operating_point(ntdb_operating_point)?);
        if onnx_batch_mode != "backend_default" {
            inner.set_onnx_batch_mode(parse_onnx_batch_mode(onnx_batch_mode)?);
        }
        Ok(SecurityGateway { inner })
    }

    fn warmup(&mut self, py: Python<'_>) -> PyResult<()> {
        match py.allow_threads(|| self.inner.warmup().map_err(|err| err.to_string())) {
            Ok(()) => Ok(()),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e)),
        }
    }

    fn scan_all(&self, py: Python<'_>, text: &str) -> PyResult<Vec<PyEvaluationResult>> {
        let results = py.allow_threads(|| self.inner.scan_all(text));
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    #[pyo3(signature = (execution_gates_json=None))]
    fn set_execution_gates(&mut self, execution_gates_json: Option<&str>) -> PyResult<()> {
        let gates = match parse_execution_gates_json(execution_gates_json)? {
            Some(gates) => gates,
            None => ScanGateMatrix::all_enabled(),
        };
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
            .set_ntdb_operating_point(parse_ntdb_operating_point(point)?);
        Ok(())
    }

    #[pyo3(signature = (enabled=true, no_full_l2_byte_limit=1024, chunk_size_bytes=512, overlap_bytes=96, verify_non_benign_l2=true))]
    fn set_long_text_policy(
        &mut self,
        enabled: bool,
        no_full_l2_byte_limit: usize,
        chunk_size_bytes: usize,
        overlap_bytes: usize,
        verify_non_benign_l2: bool,
    ) -> PyResult<()> {
        if chunk_size_bytes == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "chunk size must be greater than zero",
            ));
        }
        if overlap_bytes >= chunk_size_bytes {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "chunk overlap must be smaller than chunk size",
            ));
        }
        self.inner.set_long_text_policy(LongTextPolicy {
            enabled,
            no_full_l2_byte_limit,
            chunk_size_bytes,
            overlap_bytes,
            verify_non_benign_l2,
        });
        Ok(())
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
        let results = py.allow_threads(|| self.inner.scan_categories(&rust_categories, text));
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    #[pyo3(signature = (text, categories=None))]
    fn enqueue(
        &self,
        py: Python<'_>,
        text: &str,
        categories: Option<Vec<String>>,
    ) -> PyResult<String> {
        let request_id = match categories {
            Some(categories) => {
                let rust_categories = parse_categories(categories)?;
                py.allow_threads(|| self.inner.enqueue_categories(rust_categories, text))
            }
            None => py.allow_threads(|| self.inner.enqueue(text)),
        };
        Ok(request_id)
    }

    #[pyo3(signature = (timeout=None))]
    fn consume_next_result(
        &self,
        py: Python<'_>,
        timeout: Option<f64>,
    ) -> PyResult<Option<PyEvaluationResult>> {
        let timeout = timeout.map(Duration::from_secs_f64);
        Ok(py
            .allow_threads(|| self.inner.consume_next_result(timeout))
            .map(PyEvaluationResult::from))
    }

    fn has_request(&self, request_id: &str) -> bool {
        self.inner.has_request(request_id)
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

fn parse_execution_gates_json(value: Option<&str>) -> PyResult<Option<ScanGateMatrix>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))?;
    let object = parsed.as_object().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("execution_gates must be a JSON object")
    })?;

    let mut gates = ScanGateMatrix::all_enabled();
    if let Some(levels) = object.get("levels") {
        let levels = levels.as_object().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("execution_gates.levels must be an object")
        })?;
        for (level, enabled) in levels {
            let enabled = enabled.as_bool().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "execution_gates.levels.{level} must be a boolean"
                ))
            })?;
            let level = level
                .parse::<SecurityLevel>()
                .map_err(pyo3::exceptions::PyValueError::new_err)?;
            gates.set_level(level, enabled);
        }
    }
    if let Some(models) = object.get("models") {
        let models = models.as_object().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("execution_gates.models must be an object")
        })?;
        for (model, enabled) in models {
            let enabled = enabled.as_bool().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "execution_gates.models.{model} must be a boolean"
                ))
            })?;
            gates.set_model(model, enabled);
        }
    }
    if let Some(l3) = object.get("l3") {
        let l3 = l3.as_object().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("execution_gates.l3 must be an object")
        })?;
        let mut policy = L3SchedulerPolicy::default();
        if let Some(enabled) = l3.get("enabled") {
            policy.enabled = enabled.as_bool().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.enabled must be a boolean",
                )
            })?;
        }
        if let Some(priority) = l3.get("priority") {
            let priority = priority.as_array().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.priority must be an array",
                )
            })?;
            policy.priority = priority
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(|value| value.to_string())
                        .ok_or_else(|| {
                            pyo3::exceptions::PyValueError::new_err(
                                "execution_gates.l3.priority entries must be strings",
                            )
                        })
                })
                .collect::<PyResult<Vec<_>>>()?;
        }
        if let Some(ttl_ms) = l3.get("ttl_ms") {
            let ttl_ms = ttl_ms.as_object().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.ttl_ms must be an object",
                )
            })?;
            for (key, value) in ttl_ms {
                let ttl = value.as_u64().ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "execution_gates.l3.ttl_ms.{key} must be an integer"
                    ))
                })?;
                policy.ttl_ms.insert(key.clone(), ttl);
            }
        }
        if let Some(degraded_factor) = l3.get("degraded_factor") {
            let degraded_factor = degraded_factor.as_f64().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.degraded_factor must be a number",
                )
            })?;
            if !(0.0..=1.0).contains(&degraded_factor) {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.degraded_factor must be between 0.0 and 1.0",
                ));
            }
            policy.degraded_factor = degraded_factor;
        }
        gates.set_l3_policy(policy);
    }
    Ok(Some(gates))
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
    #[pyo3(get)]
    thresholds_json: String,
    #[pyo3(get)]
    details_json: String,
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
}

impl From<patronus_security::SecurityScanResult> for PyEvaluationResult {
    fn from(result: patronus_security::SecurityScanResult) -> Self {
        PyEvaluationResult {
            request_id: None,
            category: result.category,
            class_name: result.class_name,
            confidence: result.confidence,
            level: result.level,
            model: result.model,
            duration_ms: result.duration_ms,
            layers: result.layers.into_iter().map(PyLayerResult::from).collect(),
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
            thresholds_json: serde_json::to_string(&layer.thresholds)
                .unwrap_or_else(|_| "{}".to_string()),
            details_json: serde_json::to_string(&layer.details)
                .unwrap_or_else(|_| "{}".to_string()),
        }
    }
}

#[pymodule]
fn _patronus_security(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SecurityGateway>()?;
    m.add_class::<PyLayerResult>()?;
    m.add_class::<PyEvaluationResult>()?;
    Ok(())
}
