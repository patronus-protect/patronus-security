// SPDX-License-Identifier: GPL-3.0-only
//! Synchronous Unified L3 inference through Triton's HTTP V2 endpoint.
use std::{collections::HashMap, io::Read, path::Path, time::Duration};

use serde::Deserialize;
use serde_json::json;

use super::{
    tokenizer::{RuntimeTokenizer, MODEL_TOKENS},
    unified_onnx::UnifiedRawModelOutput,
};

#[derive(Clone)]
pub(crate) struct RemoteUnified {
    agent: ureq::Agent,
    endpoint: String,
    model: String,
    tokenizer: RuntimeTokenizer,
    heads: Vec<(&'static str, &'static str, usize)>,
}

impl RemoteUnified {
    pub(crate) fn from_env(
        tokenizer_dir: &Path,
        heads: Vec<(&'static str, &'static str, usize)>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let endpoint = match std::env::var("PATRONUS_UNIFIED_TRITON_URL") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let url = url::Url::parse(&endpoint)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err("PATRONUS_UNIFIED_TRITON_URL must be an HTTP(S) origin".into());
        }
        let revision = crate::assets::UNIFIED_L3_ASSET.revision;
        let timeout_ms = match std::env::var("PATRONUS_UNIFIED_TRITON_TIMEOUT_MS") {
            Ok(value) => value.parse::<u64>()?,
            Err(std::env::VarError::NotPresent) => 1000,
            Err(error) => return Err(error.into()),
        };
        if !(1..=30_000).contains(&timeout_ms) {
            return Err("remote Unified timeout must be between 1 and 30000 ms".into());
        }
        Ok(Some(Self {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(timeout_ms))
                .redirects(0)
                .build(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            model: format!("lion_warden_{revision}_fp16_256"),
            tokenizer: RuntimeTokenizer::load(tokenizer_dir)?,
            heads,
        }))
    }

    pub(crate) fn warmup(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.agent
            .get(&format!(
                "{}/v2/models/{}/versions/1/ready",
                self.endpoint, self.model
            ))
            .call()?;
        // Check the real tensor contract before declaring the worker ready.
        self.infer(&[])?;
        Ok(())
    }

    pub(crate) fn infer(
        &self,
        token_ids: &[u32],
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        Ok(self.infer_rows(&[token_ids])?.remove(0))
    }

    pub(crate) fn infer_texts(
        &self,
        texts: &[String],
    ) -> Result<Vec<UnifiedRawModelOutput>, Box<dyn std::error::Error>> {
        let mut outputs = Vec::with_capacity(texts.len());
        for batch in texts.chunks(16) {
            let tokens = batch
                .iter()
                .map(|text| self.tokenizer.single_chunk_ids(text))
                .collect::<Result<Vec<_>, _>>()?;
            let rows = tokens.iter().map(Vec::as_slice).collect::<Vec<_>>();
            outputs.extend(self.infer_rows(&rows)?);
        }
        Ok(outputs)
    }

    fn infer_rows(
        &self,
        rows: &[&[u32]],
    ) -> Result<Vec<UnifiedRawModelOutput>, Box<dyn std::error::Error>> {
        let batch = rows.len();
        if !(1..=16).contains(&batch) {
            return Err("remote batch must contain 1 to 16 chunks".into());
        }
        let (ids, mask, _) = self.tokenizer.batch_inputs(rows, true, false)?;
        let response = self.agent
            .post(&format!("{}/v2/models/{}/versions/1/infer", self.endpoint, self.model))
            .send_json(json!({
                "inputs": [
                    {"name": "input_ids", "shape": [batch, MODEL_TOKENS], "datatype": "INT64", "data": ids},
                    {"name": "attention_mask", "shape": [batch, MODEL_TOKENS], "datatype": "INT64", "data": mask}
                ],
                "outputs": self.heads.iter().map(|(_, output, _)| json!({"name": output})).collect::<Vec<_>>()
            }))?;
        // Bound the response for at most sixteen rows of seven classifier heads.
        let response: InferResponse =
            serde_json::from_reader(response.into_reader().take(16 * 16 * 1024))?;
        response.validate_rows(&self.model, &self.heads, batch)
    }

    pub(crate) fn infer_text(
        &self,
        text: &str,
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        self.infer(&self.tokenizer.single_chunk_ids(text)?)
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
    data: Vec<f32>,
}

impl InferResponse {
    #[cfg(test)]
    fn validate(
        self,
        expected_model: &str,
        expected_heads: &[(&str, &str, usize)],
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        Ok(self
            .validate_rows(expected_model, expected_heads, 1)?
            .remove(0))
    }

    fn validate_rows(
        mut self,
        expected_model: &str,
        expected_heads: &[(&str, &str, usize)],
        batch: usize,
    ) -> Result<Vec<UnifiedRawModelOutput>, Box<dyn std::error::Error>> {
        if self.model_name != expected_model
            || self.model_version != "1"
            || self.outputs.len() != expected_heads.len()
        {
            return Err("unexpected remote Unified model or output count".into());
        }
        let mut rows = (0..batch)
            .map(|_| UnifiedRawModelOutput {
                heads: HashMap::new(),
            })
            .collect::<Vec<_>>();
        for &(head, name, width) in expected_heads {
            let index = self
                .outputs
                .iter()
                .position(|output| output.name == name)
                .ok_or_else(|| format!("missing remote Unified output {name}"))?;
            let output = self.outputs.swap_remove(index);
            if output.datatype != "FP32"
                || output.shape != [batch, width]
                || output.data.len() != batch * width
                || output.data.iter().any(|value| !value.is_finite())
            {
                return Err(format!("invalid remote Unified logits for {head}").into());
            }
            for (row, values) in rows.iter_mut().zip(output.data.chunks_exact(width)) {
                row.heads.insert(head.to_string(), values.to_vec());
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn server(
        status: &str,
        body: &str,
        delay: Duration,
    ) -> (RemoteUnified, std::thread::JoinHandle<serde_json::Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /v2/models/lion/versions/1/infer "));
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            std::thread::sleep(delay);
            let _ = socket.write_all(response.as_bytes());
            serde_json::from_slice(&body).unwrap()
        });
        (
            RemoteUnified {
                agent: ureq::AgentBuilder::new()
                    .timeout(Duration::from_millis(100))
                    .build(),
                endpoint,
                model: "lion".into(),
                tokenizer: super::super::tokenizer::fixture_tokenizer(),
                heads: vec![("test", "logits", 2)],
            },
            thread,
        )
    }

    #[test]
    fn http_batch_preserves_row_boundaries() {
        let body = json!({"model_name":"lion", "model_version":"1", "outputs":[{
            "name":"logits", "datatype":"FP32", "shape":[2,2], "data":[1.0,2.0,3.0,4.0]
        }]})
        .to_string();
        let (remote, server) = server("200 OK", &body, Duration::ZERO);
        let rows = remote.infer_rows(&[&[4, 5], &[6]]).unwrap();
        assert_eq!(rows[0].heads["test"], vec![1.0, 2.0]);
        assert_eq!(rows[1].heads["test"], vec![3.0, 4.0]);
        let request = server.join().unwrap();
        assert_eq!(request["inputs"][0]["shape"], json!([2, 256]));
        assert_eq!(request["inputs"][0]["data"].as_array().unwrap().len(), 512);
        assert_eq!(request["inputs"][1]["data"].as_array().unwrap().len(), 512);
        let invalid: InferResponse = serde_json::from_str(&body).unwrap();
        assert!(invalid
            .validate_rows("lion", &[("test", "logits", 2)], 1)
            .is_err());
    }

    #[test]
    fn http_roundtrip_preserves_token_ids_mask_and_logits() {
        let (remote, server) = server(
            "200 OK",
            r#"{"model_name":"lion","model_version":"1","outputs":[{"name":"logits","datatype":"FP32","shape":[1,2],"data":[1.25,-2.5]}]}"#,
            Duration::ZERO,
        );
        assert_eq!(
            remote.infer(&[7, 8]).unwrap().heads["test"],
            vec![1.25, -2.5]
        );
        let request = server.join().unwrap();
        let inputs = &request["inputs"];
        assert_eq!(inputs[0]["shape"], json!([1, 256]));
        assert_eq!(inputs[0]["data"].as_array().unwrap().len(), 256);
        assert_eq!(
            &inputs[0]["data"].as_array().unwrap()[..5],
            &[json!(1), json!(7), json!(8), json!(2), json!(0)]
        );
        assert_eq!(
            inputs[1]["data"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|value| **value == json!(1))
                .count(),
            4
        );
    }

    #[test]
    fn rejects_server_failure_and_bounds_network_wait() {
        for (status, delay) in [
            ("503 Service Unavailable", Duration::ZERO),
            ("200 OK", Duration::from_millis(250)),
        ] {
            let (remote, server) = server(status, "{}", delay);
            assert!(remote.infer(&[]).is_err());
            server.join().unwrap();
        }
    }

    fn response() -> InferResponse {
        InferResponse {
            model_name: "lion".into(),
            model_version: "1".into(),
            outputs: vec![Output {
                name: "logits".into(),
                datatype: "FP32".into(),
                shape: vec![1, 2],
                data: vec![1.25, -2.5],
            }],
        }
    }

    #[test]
    fn maps_named_heads_independently_of_response_order_and_rejects_missing_heads() {
        let expected = [
            ("injection", "injection_logits", 1),
            ("tool_tags", "tool_tags_logits", 3),
        ];
        let make_response = || InferResponse {
            model_name: "lion".into(),
            model_version: "1".into(),
            outputs: vec![
                Output {
                    name: "tool_tags_logits".into(),
                    datatype: "FP32".into(),
                    shape: vec![1, 3],
                    data: vec![-1.0, 0.0, 2.0],
                },
                Output {
                    name: "injection_logits".into(),
                    datatype: "FP32".into(),
                    shape: vec![1, 1],
                    data: vec![3.0],
                },
            ],
        };
        let result = make_response().validate("lion", &expected).unwrap();
        assert_eq!(result.heads["injection"], vec![3.0]);
        assert_eq!(result.heads["tool_tags"], vec![-1.0, 0.0, 2.0]);
        let mut bad = make_response();
        bad.outputs[1].name = "tool_tags_logits".into();
        assert!(bad.validate("lion", &expected).is_err());
        let mut bad = make_response();
        bad.outputs.pop();
        assert!(bad.validate("lion", &expected).is_err());
    }

    #[test]
    fn preserves_logits_and_rejects_wrong_model_shape_or_nonfinite_values() {
        assert_eq!(
            response()
                .validate("lion", &[("test", "logits", 2)])
                .unwrap()
                .heads["test"],
            vec![1.25, -2.5]
        );
        assert!(response()
            .validate("other-revision", &[("test", "logits", 2)])
            .is_err());
        let mut bad = response();
        bad.outputs[0].shape = vec![2, 1];
        assert!(bad.validate("lion", &[("test", "logits", 2)]).is_err());
        let mut bad = response();
        bad.outputs[0].data[0] = f32::NAN;
        assert!(bad.validate("lion", &[("test", "logits", 2)]).is_err());
        let mut bad = response();
        bad.model_version = "2".into();
        assert!(bad.validate("lion", &[("test", "logits", 2)]).is_err());
    }
}
