//! Shared ONNX Runtime initialization and provider/session selection.
use crate::{ExecutionBackend, OnnxRuntimeOptions};
#[cfg(any(
    feature = "onnx-coreml",
    feature = "onnx-cuda",
    feature = "onnx-directml",
    feature = "onnx-tensorrt"
))]
use ort::ep::ExecutionProvider;
#[cfg(feature = "onnx-cuda")]
use ort::execution_providers::CUDAExecutionProvider;
#[cfg(feature = "onnx-directml")]
use ort::execution_providers::DirectMLExecutionProvider;
#[cfg(feature = "onnx-tensorrt")]
use ort::execution_providers::TensorRTExecutionProvider;
#[cfg(feature = "onnx-coreml")]
#[allow(deprecated)]
use ort::execution_providers::{ArbitrarilyConfigurableExecutionProvider, CoreMLExecutionProvider};
#[allow(deprecated)]
use ort::{
    environment::GlobalThreadPoolOptions,
    execution_providers::ExecutionProviderDispatch,
    session::{
        builder::{GraphOptimizationLevel, SessionBuilder},
        Session,
    },
};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
static ACTIVE_EXECUTION_PROVIDERS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

fn record_active_provider(provider: &str) {
    ACTIVE_EXECUTION_PROVIDERS
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .expect("active execution provider mutex poisoned")
        .insert(provider.to_string());
}

/// ONNX Runtime providers compiled into and discoverable by this process.
pub fn available_execution_providers() -> Vec<String> {
    let providers = vec!["cpu".to_string()];
    #[cfg(feature = "onnx-cuda")]
    let mut providers = providers;
    #[cfg(feature = "onnx-cuda")]
    if CUDAExecutionProvider::default()
        .is_available()
        .unwrap_or(false)
    {
        providers.push("cuda".to_string());
    }
    providers
}

/// Providers successfully registered by warmed model sessions.
pub fn active_execution_providers() -> Vec<String> {
    ACTIVE_EXECUTION_PROVIDERS
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .expect("active execution provider mutex poisoned")
        .iter()
        .cloned()
        .collect()
}

pub fn warmup_runtime() -> bool {
    let Ok(threading) = GlobalThreadPoolOptions::default().with_spin_control(false) else {
        return false;
    };
    let initialized = ort::init().with_global_thread_pool(threading).commit();
    #[cfg(ort_rc_10)]
    {
        initialized.unwrap_or(false)
    }
    #[cfg(not(ort_rc_10))]
    {
        initialized
    }
}

pub fn configured_session_builder(
    backend: ExecutionBackend,
    model_dir: Option<&Path>,
    options: OnnxRuntimeOptions,
) -> Result<(SessionBuilder, String), Box<dyn std::error::Error>> {
    let mut builder =
        Session::builder()?.with_optimization_level(GraphOptimizationLevel::Level3)?;
    let options = options.normalized();
    if let Some(threads) = options.intra_threads {
        builder = builder.with_intra_threads(threads)?;
    }
    if let Some(threads) = options.inter_threads {
        builder = builder.with_inter_threads(threads)?;
    }
    if let Some(enabled) = options.spinning {
        builder = builder.with_intra_op_spinning(enabled)?;
        builder = builder.with_inter_op_spinning(enabled)?;
    }
    #[cfg(feature = "onnx-cuda")]
    if default_accelerator_provider(backend) == Some("cuda") {
        let cuda = CUDAExecutionProvider::default();
        match cuda.register(&mut builder) {
            Ok(()) => {
                record_active_provider("cuda");
                return Ok((builder, "cuda".to_string()));
            }
            Err(error) if backend == ExecutionBackend::Auto => {
                log::warn!("CUDA execution provider unavailable; falling back to CPU: {error}");
                record_active_provider("cpu");
                return Ok((builder, "cpu".to_string()));
            }
            Err(error) => return Err(error.into()),
        }
    }
    let plan = execution_provider_plan(backend, model_dir)?;
    if !plan.providers.is_empty() {
        builder = builder.with_execution_providers(plan.providers)?;
    }
    record_active_provider(&plan.name);
    Ok((builder, plan.name))
}

struct ExecutionProviderPlan {
    name: String,
    providers: Vec<ExecutionProviderDispatch>,
}

fn execution_provider_plan(
    backend: ExecutionBackend,
    model_dir: Option<&Path>,
) -> Result<ExecutionProviderPlan, Box<dyn std::error::Error>> {
    let provider = default_accelerator_provider(backend);

    if provider == Some("cpu") {
        return Ok(ExecutionProviderPlan {
            name: "cpu".to_string(),
            providers: Vec::new(),
        });
    }

    let Some(provider) = provider else {
        return Err("ONNX GPU backend is not available on this platform; enable and select one of: coreml, cuda, directml, tensorrt".to_string()
        .into());
    };

    let strict = backend != ExecutionBackend::Auto;
    let mut dispatch = match provider {
        "cuda" => unreachable!("CUDA is registered explicitly before building the provider plan"),
        "coreml" => coreml_provider(model_dir),
        #[cfg(feature = "onnx-directml")]
        "directml" => Some(DirectMLExecutionProvider::default().build()),
        #[cfg(feature = "onnx-tensorrt")]
        "tensorrt" => Some(TensorRTExecutionProvider::default().build()),
        _ => None,
    };

    let Some(provider_dispatch) = dispatch.take() else {
        return Err(format!("Unknown ONNX execution provider: {}", provider).into());
    };

    let provider_dispatch = if strict {
        provider_dispatch.error_on_failure()
    } else {
        provider_dispatch.fail_silently()
    };
    Ok(ExecutionProviderPlan {
        name: provider.to_string(),
        providers: vec![provider_dispatch],
    })
}

fn default_accelerator_provider(backend: ExecutionBackend) -> Option<&'static str> {
    match backend {
        ExecutionBackend::Cpu => Some("cpu"),
        ExecutionBackend::Auto
            if cfg!(target_os = "windows") && cfg!(feature = "onnx-directml") =>
        {
            Some("directml")
        }
        ExecutionBackend::Auto if cfg!(feature = "onnx-cuda") => Some("cuda"),
        ExecutionBackend::Auto => Some("cpu"),
        ExecutionBackend::Gpu if cfg!(target_os = "windows") && cfg!(feature = "onnx-directml") => {
            Some("directml")
        }
        ExecutionBackend::Gpu if cfg!(target_vendor = "apple") => None,
        ExecutionBackend::Gpu if cfg!(feature = "onnx-cuda") => Some("cuda"),
        ExecutionBackend::Gpu => None,
        ExecutionBackend::CoreMl if cfg!(feature = "onnx-coreml") => Some("coreml"),
        ExecutionBackend::CoreMl => None,
        ExecutionBackend::Cuda if cfg!(feature = "onnx-cuda") => Some("cuda"),
        ExecutionBackend::Cuda => None,
        ExecutionBackend::DirectMl if cfg!(feature = "onnx-directml") => Some("directml"),
        ExecutionBackend::DirectMl => None,
        ExecutionBackend::TensorRt if cfg!(feature = "onnx-tensorrt") => Some("tensorrt"),
        ExecutionBackend::TensorRt => None,
    }
}

#[cfg(feature = "onnx-coreml")]
fn coreml_provider(model_dir: Option<&Path>) -> Option<ExecutionProviderDispatch> {
    let mut provider = CoreMLExecutionProvider::default()
        .with_arbitrary_config("MLComputeUnits", "CPUAndGPU")
        .with_low_precision_accumulation_on_gpu(true);
    if let Some(model_dir) = model_dir {
        let cache_dir = model_dir.join(".coreml-cache");
        let tmp_dir = model_dir.join(".coreml-tmp");
        let _ = std::fs::create_dir_all(&cache_dir);
        let _ = std::fs::create_dir_all(&tmp_dir);
        std::env::set_var("TMPDIR", &tmp_dir);
        provider = provider.with_model_cache_dir(cache_dir.to_string_lossy());
    }
    Some(provider.build())
}

#[cfg(not(feature = "onnx-coreml"))]
fn coreml_provider(_model_dir: Option<&Path>) -> Option<ExecutionProviderDispatch> {
    None
}
