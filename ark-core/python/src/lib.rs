// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::useless_conversion)] // Generated PyO3 wrappers.
use patronus_ark_core::{ScanChecks, ScanControl as Control, ScanError, Scanner as CoreScanner};
use pyo3::{exceptions::*, prelude::*, types::PyDict};
use serde::de::DeserializeOwned;
use std::{sync::Mutex, time::Duration};

pyo3::create_exception!(_patronus_ark_core, CancelledError, PyRuntimeError);
pyo3::create_exception!(_patronus_ark_core, ScannerBusyError, PyRuntimeError);

fn scan_error(error: ScanError) -> PyErr {
    match error {
        ScanError::Config(_) => PyValueError::new_err(error.to_string()),
        ScanError::DeadlineExceeded => PyTimeoutError::new_err(error.to_string()),
        ScanError::Cancelled => CancelledError::new_err(error.to_string()),
        _ => PyRuntimeError::new_err(error.to_string()),
    }
}

fn config<T: DeserializeOwned + Default>(
    py: Python<'_>,
    value: Option<&Bound<'_, PyDict>>,
) -> PyResult<T> {
    match value {
        None => Ok(T::default()),
        Some(value) => {
            let text: String = py
                .import_bound("json")?
                .call_method1("dumps", (value,))?
                .extract()?;
            serde_json::from_str(&text).map_err(|e| PyValueError::new_err(e.to_string()))
        }
    }
}

#[pyclass(module = "patronus_ark_core")]
struct ScanControl {
    inner: Control,
}

#[pymethods]
impl ScanControl {
    #[new]
    #[pyo3(signature = (timeout_ms=None))]
    fn new(timeout_ms: Option<u64>) -> PyResult<Self> {
        Ok(Self {
            inner: match timeout_ms {
                Some(ms) => Control::with_timeout(Duration::from_millis(ms)).map_err(scan_error)?,
                None => Control::default(),
            },
        })
    }
    fn cancel(&self) {
        self.inner.cancel();
    }
}

#[pyclass(module = "patronus_ark_core")]
struct Scanner {
    inner: Mutex<CoreScanner>,
}

#[pymethods]
impl Scanner {
    #[new]
    #[pyo3(signature = (config=None, *, warmup=None, wolf_options=None))]
    fn new(
        py: Python<'_>,
        config: Option<&Bound<'_, PyDict>>,
        warmup: Option<&Bound<'_, PyDict>>,
        wolf_options: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let policy = self::config(py, config)?;
        let warmup = self::config(py, warmup)?;
        let execution = self::config(py, wolf_options)?;
        let scanner = py
            .allow_threads(move || CoreScanner::warmup_with_wolf_options(policy, warmup, execution))
            .map_err(scan_error)?;
        Ok(Self {
            inner: Mutex::new(scanner),
        })
    }

    #[pyo3(signature = (text, *, pii=true, dlp=true, injection=true, control=None))]
    fn scan(
        &self,
        py: Python<'_>,
        text: String,
        pii: bool,
        dlp: bool,
        injection: bool,
        control: Option<&ScanControl>,
    ) -> PyResult<PyObject> {
        let control = control.map(|c| c.inner.clone()).unwrap_or_default();
        let output = py.allow_threads(move || {
            control.check().map_err(scan_error)?;
            let mut scanner = self.inner.try_lock().map_err(|_| {
                ScannerBusyError::new_err(
                    "scanner is already in use; serialize calls or use separate scanners",
                )
            })?;
            let report = scanner
                .scan_with_control(
                    &text,
                    ScanChecks {
                        pii,
                        dlp,
                        injection,
                    },
                    &control,
                )
                .map_err(scan_error)?;
            serde_json::to_string(&report).map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })?;
        let report = py.import_bound("json")?.call_method1("loads", (output,))?;
        report.call_method1("setdefault", ("wolf", py.None()))?;
        Ok(report.unbind())
    }
}

#[pymodule]
fn _patronus_ark_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Scanner>()?;
    m.add_class::<ScanControl>()?;
    m.add("CancelledError", m.py().get_type_bound::<CancelledError>())?;
    m.add(
        "ScannerBusyError",
        m.py().get_type_bound::<ScannerBusyError>(),
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
