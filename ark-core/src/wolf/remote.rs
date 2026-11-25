//! Wolf Small logits on the pinned TensorRT model behind private Triton.
use super::{LogitOutput, WolfConfig, WolfManifest};
use crate::{
    ml::mmbert_tokenizer::MmbertPairTokenizer, wolf_options::WolfWindows, ScanControl, ScanError,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::Read,
    sync::mpsc,
    time::{Duration, Instant},
};

const MODEL: &str = "wolf_defender_small_e3749b44a0f85268347cdfb6818f4ef39e8ff203_fp16_256";

pub(super) struct RemoteWolf {
    agent: ureq::Agent,
    endpoint: String,
    timeout: Duration,
}

impl RemoteWolf {
    pub(super) fn from_env(
        config: &WolfConfig,
        manifest: &WolfManifest,
        windows: WolfWindows,
    ) -> Result<Option<Self>, ScanError> {
        let endpoint = match std::env::var("PATRONUS_WOLF_TRITON_URL") {
            Ok(value) if value.is_empty() => return Ok(None),
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(error) => return Err(ScanError::Config(error.to_string())),
        };
        let url = url::Url::parse(&endpoint).map_err(config_error)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(ScanError::Config(
                "PATRONUS_WOLF_TRITON_URL must be an HTTP(S) origin".into(),
            ));
        }
        if config.model != super::WolfModel::Small
            || manifest.revision != super::WolfModel::Small.spec().revision
            || manifest.precision != "fp16"
            || manifest.output_name != "logits"
            || !matches!(manifest.output, LogitOutput::BinaryMargin)
            || windows.window_tokens != 256
            || windows.batch_size > 16
        {
            return Err(ScanError::Config("remote Wolf requires pinned Small FP16, 256-token windows and batch size at most 16".into()));
        }
        let timeout_ms = match std::env::var("PATRONUS_WOLF_TRITON_TIMEOUT_MS") {
            Ok(value) => value.parse::<u64>().map_err(config_error)?,
            Err(std::env::VarError::NotPresent) => 1000,
            Err(error) => return Err(config_error(error)),
        };
        if !(1..=30_000).contains(&timeout_ms) {
            return Err(ScanError::Config(
                "remote Wolf timeout must be between 1 and 30000 ms".into(),
            ));
        }
        let remote = Self {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(timeout_ms))
                .redirects(0)
                .build(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            timeout: Duration::from_millis(timeout_ms),
        };
        remote
            .agent
            .get(&format!(
                "{}/v2/models/{MODEL}/versions/1/ready",
                remote.endpoint
            ))
            .call()
            .map_err(inference_error)?;
        Ok(Some(remote))
    }

    pub(super) fn infer_batch(
        &self,
        batch: &[Vec<u32>],
        width: usize,
        tokenizer: &MmbertPairTokenizer,
        pad_id: u32,
        control: &ScanControl,
    ) -> Result<Vec<[f64; 2]>, ScanError> {
        control.check()?;
        if width != 256 || batch.is_empty() || batch.len() > 16 {
            return Err(inference_error("invalid remote Wolf batch"));
        }
        let chunks = batch.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let (ids, mask, _) = crate::ml::tokenizer::assemble_batch_inputs(
            &chunks,
            width,
            (tokenizer.bos(), tokenizer.eos(), pad_id),
            true,
            false,
        )
        .map_err(inference_error)?;
        let body = json!({
            "inputs": [
                {"name": "input_ids", "shape": [batch.len(), width], "datatype": "INT64", "data": ids},
                {"name": "attention_mask", "shape": [batch.len(), width], "datatype": "INT64", "data": mask}
            ],
            "outputs": [{"name": "logits"}]
        });
        let remaining = control
            .deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(self.timeout);
        control.check()?;
        let timeout = self.timeout.min(remaining);
        let agent = self.agent.clone();
        let endpoint = format!("{}/v2/models/{MODEL}/versions/1/infer", self.endpoint);
        let body = body.to_string();
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("wolf-triton-request".into())
            .spawn(move || {
                let result = (|| {
                    let response = agent
                        .post(&endpoint)
                        .timeout(timeout)
                        .set("content-type", "application/json")
                        .send_string(&body)
                        .map_err(inference_error)?;
                    serde_json::from_reader::<_, InferResponse>(
                        response.into_reader().take(64 * 1024),
                    )
                    .map_err(inference_error)
                })();
                let _ = sender.send(result);
            })
            .map_err(inference_error)?;
        await_response(receiver, control)?.validate(batch.len())
    }
}

fn await_response<T>(
    receiver: mpsc::Receiver<Result<T, ScanError>>,
    control: &ScanControl,
) -> Result<T, ScanError> {
    loop {
        control.check()?;
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(result) => {
                control.check()?;
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(inference_error("remote Wolf request worker stopped"));
            }
        }
    }
}

#[derive(Deserialize)]
struct InferResponse {
    model_name: String,
    model_version: String,
    outputs: Vec<Output>,
}

#[derive(Deserialize)]
struct Output {
    name: String,
    datatype: String,
    shape: Vec<usize>,
    data: Vec<f64>,
}

impl InferResponse {
    fn validate(self, batch: usize) -> Result<Vec<[f64; 2]>, ScanError> {
        if self.model_name != MODEL || self.model_version != "1" || self.outputs.len() != 1 {
            return Err(inference_error(
                "unexpected remote Wolf model or output count",
            ));
        }
        let output = &self.outputs[0];
        if output.name != "logits"
            || output.datatype != "FP32"
            || output.shape != [batch, 2]
            || output.data.len() != batch * 2
            || output.data.iter().any(|value| !value.is_finite())
        {
            return Err(inference_error("invalid remote Wolf logits"));
        }
        Ok(output
            .data
            .chunks_exact(2)
            .map(|row| [row[0], row[1]])
            .collect())
    }
}

fn config_error(error: impl std::fmt::Display) -> ScanError {
    ScanError::Config(error.to_string())
}

fn inference_error(error: impl std::fmt::Display) -> ScanError {
    ScanError::Inference(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_triton_model_and_logits() {
        let valid = json!({"model_name": MODEL, "model_version": "1", "outputs": [
            {"name": "logits", "datatype": "FP32", "shape": [2, 2], "data": [0.1, 0.2, 0.3, 0.4]}
        ]});
        let response: InferResponse = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(response.validate(2).unwrap(), [[0.1, 0.2], [0.3, 0.4]]);
        for malformed in [
            json!({"model_name": "lion", "model_version": "1", "outputs": valid["outputs"]}),
            json!({"model_name": MODEL, "model_version": "1", "outputs": [{"name": "logits", "datatype": "FP16", "shape": [2, 2], "data": [0.1, 0.2, 0.3, 0.4]}]}),
            json!({"model_name": MODEL, "model_version": "1", "outputs": [{"name": "logits", "datatype": "FP32", "shape": [2, 1], "data": [0.1, 0.2]}]}),
        ] {
            assert!(serde_json::from_value::<InferResponse>(malformed)
                .unwrap()
                .validate(2)
                .is_err());
        }
    }

    #[test]
    fn remote_wait_obeys_scan_deadline_and_cancellation() {
        let (_sender, receiver) = mpsc::channel::<Result<(), ScanError>>();
        let control = ScanControl::with_timeout(Duration::from_millis(20)).unwrap();
        let start = Instant::now();
        assert!(matches!(
            await_response(receiver, &control),
            Err(ScanError::DeadlineExceeded)
        ));
        assert!(start.elapsed() < Duration::from_millis(500));

        let (_sender, receiver) = mpsc::channel::<Result<(), ScanError>>();
        let control = ScanControl::default();
        let cancelled = control.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancelled.cancel();
        });
        let start = Instant::now();
        assert!(matches!(
            await_response(receiver, &control),
            Err(ScanError::Cancelled)
        ));
        assert!(start.elapsed() < Duration::from_millis(500));
        handle.join().unwrap();
    }
}
