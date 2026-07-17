// SPDX-License-Identifier: AGPL-3.0-only
use patronus_security::{
    DynamicPiiConfig, EvidenceSpan, ExecutionBackend, L3SchedulerPolicy, L3Strategy, LabelScore,
    LayerResult, NtdbOperatingPoint, OnnxBatchMode, QueuedSecurityEvent, QueuedSecurityScanResult,
    ScanGateMatrix, SecurityCategory, SecurityFailure, SecurityGateway as RustSecurityGateway,
    SecurityLevel, SecurityLevelReadiness, SecurityRequestCompletion, SecurityRequestState,
    SecurityRuntimeReadiness,
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
    #[pyo3(signature = (categories, max_level="l2", model_dir=None, download_files=true, download_categories=None, execution_gates_json=None, onnx_batch_mode="backend_default", execution_backend="auto", ntdb_operating_point="best_promote", l3_strategy="dedicated", dynamic_pii_config_json=None))]
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
        inner.set_l3_strategy(parse_l3_strategy(l3_strategy)?);
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

    #[pyo3(signature = (text, categories=None, execution_gates_json=None))]
    fn enqueue(
        &self,
        py: Python<'_>,
        text: &str,
        categories: Option<Vec<String>>,
        execution_gates_json: Option<&str>,
    ) -> PyResult<String> {
        let gates = parse_execution_gates_json(execution_gates_json)?;
        let request_id = match categories {
            Some(categories) => {
                let rust_categories = parse_categories(categories)?;
                py.allow_threads(|| self.inner.enqueue_categories(rust_categories, text, gates))
            }
            None => py.allow_threads(|| self.inner.enqueue(text, gates)),
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
        if let Some(estimated_cost_ms) = l3.get("estimated_cost_ms") {
            let estimated_cost_ms = estimated_cost_ms.as_object().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.estimated_cost_ms must be an object",
                )
            })?;
            for (key, value) in estimated_cost_ms {
                let cost = value.as_u64().filter(|value| *value > 0).ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "execution_gates.l3.estimated_cost_ms.{key} must be a positive integer"
                    ))
                })?;
                policy.estimated_cost_ms.insert(key.clone(), cost);
            }
        }
        if let Some(fairness_quantum_ms) = l3.get("fairness_quantum_ms") {
            policy.fairness_quantum_ms = fairness_quantum_ms
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "execution_gates.l3.fairness_quantum_ms must be a positive integer",
                    )
                })?;
        }
        if let Some(max_wait_ms) = l3.get("max_wait_ms") {
            policy.max_wait_ms = max_wait_ms.as_u64().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "execution_gates.l3.max_wait_ms must be a non-negative integer",
                )
            })?;
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
    #[pyo3(get)]
    evidence_spans: Vec<PyEvidenceSpan>,
    #[pyo3(get)]
    label_scores: Vec<PyLabelScore>,
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
struct PyEvidenceSpan {
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    text: String,
    #[pyo3(get)]
    score: f64,
    #[pyo3(get)]
    start_byte: usize,
    #[pyo3(get)]
    end_byte: usize,
    #[pyo3(get)]
    start_char: usize,
    #[pyo3(get)]
    end_char: usize,
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
            evidence_spans: result
                .evidence_spans
                .into_iter()
                .map(PyEvidenceSpan::from)
                .collect(),
            label_scores: result
                .label_scores
                .into_iter()
                .map(PyLabelScore::from)
                .collect(),
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

impl From<EvidenceSpan> for PyEvidenceSpan {
    fn from(span: EvidenceSpan) -> Self {
        Self {
            label: span.label,
            text: span.text,
            score: span.score,
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_char: span.start_char,
            end_char: span.end_char,
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
    m.add_class::<PyLabelScore>()?;
    m.add_class::<PyEvidenceSpan>()?;
    m.add_class::<PySecurityFailure>()?;
    m.add_class::<PySecurityEvent>()?;
    m.add_class::<PyRequestState>()?;
    m.add_class::<PyLevelReadiness>()?;
    m.add_class::<PyRuntimeReadiness>()?;
    Ok(())
}
