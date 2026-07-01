use patronus_security::{LayerResult, PatronusSecurity, SecurityCategory, SecurityLevel};
use pyo3::prelude::*;
use std::path::PathBuf;

#[pyclass]
struct SecurityGateway {
    inner: PatronusSecurity,
}

#[pymethods]
impl SecurityGateway {
    #[new]
    #[pyo3(signature = (categories, max_level="l2", use_dir=None, download_files=true, download_categories=None))]
    fn new(
        categories: Vec<String>,
        max_level: &str,
        use_dir: Option<String>,
        download_files: bool,
        download_categories: Option<Vec<String>>,
    ) -> PyResult<Self> {
        let rust_categories = parse_categories(categories)?;
        let rust_max_level = match max_level.parse::<SecurityLevel>() {
            Ok(level) => level,
            Err(e) => return Err(pyo3::exceptions::PyValueError::new_err(e)),
        };
        let rust_use_dir = use_dir.map(PathBuf::from);
        let rust_download_categories = match download_categories {
            Some(categories) => Some(parse_categories(categories)?),
            None => None,
        };
        let inner = PatronusSecurity::with_download_categories(
            rust_categories,
            rust_max_level,
            rust_use_dir,
            download_files,
            rust_download_categories,
        );
        Ok(SecurityGateway { inner })
    }

    fn warmup(&mut self) -> PyResult<()> {
        match self.inner.warmup() {
            Ok(()) => Ok(()),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
        }
    }

    fn scan_all(&self, text: &str) -> PyResult<Vec<PyEvaluationResult>> {
        let results = self.inner.scan_all(text);
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    fn scan_category(&self, category: &str, text: &str) -> PyResult<Vec<PyEvaluationResult>> {
        let cat = match category.parse::<SecurityCategory>() {
            Ok(c) => c,
            Err(e) => return Err(pyo3::exceptions::PyValueError::new_err(e)),
        };
        let results = self.inner.scan_category(cat, text);
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    fn scan_categories(
        &self,
        categories: Vec<String>,
        text: &str,
    ) -> PyResult<Vec<PyEvaluationResult>> {
        let rust_categories = parse_categories(categories)?;
        let results = self.inner.scan_categories(&rust_categories, text);
        Ok(results.into_iter().map(PyEvaluationResult::from).collect())
    }

    fn evaluate(&self, pipeline: &str, text: &str) -> PyResult<PyEvaluationResult> {
        self.inner
            .evaluate_pipeline(pipeline, text)
            .map(PyEvaluationResult::from)
            .ok_or_else(|| pipeline_error(pipeline))
    }

    fn evaluate_batch(
        &self,
        pipeline: &str,
        texts: Vec<String>,
    ) -> PyResult<Vec<PyEvaluationResult>> {
        self.inner
            .evaluate_pipeline_batch(pipeline, &texts)
            .map(|results| results.into_iter().map(PyEvaluationResult::from).collect())
            .ok_or_else(|| pipeline_error(pipeline))
    }

    fn evaluate_injection(&self, text: &str) -> PyResult<PyEvaluationResult> {
        self.evaluate("injection", text)
    }

    fn evaluate_injection_batch(&self, texts: Vec<String>) -> PyResult<Vec<PyEvaluationResult>> {
        self.evaluate_batch("injection", texts)
    }

    fn evaluate_dlp(&self, text: &str) -> PyResult<PyEvaluationResult> {
        self.evaluate("dlp", text)
    }

    fn evaluate_dlp_batch(&self, texts: Vec<String>) -> PyResult<Vec<PyEvaluationResult>> {
        self.evaluate_batch("dlp", texts)
    }

    fn evaluate_pii(&self, text: &str) -> PyResult<PyEvaluationResult> {
        self.evaluate("pii", text)
    }

    fn evaluate_pii_batch(&self, texts: Vec<String>) -> PyResult<Vec<PyEvaluationResult>> {
        self.evaluate_batch("pii", texts)
    }
}

fn pipeline_error(pipeline: &str) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!(
        "pipeline '{}' is not initialized or is unknown",
        pipeline
    ))
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
