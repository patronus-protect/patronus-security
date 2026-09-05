use crate::cube::batching::TextBatch;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

pub struct CubeBatchResult {
    pub jobs: Vec<Value>,
    pub submit_ms: f64,
}

#[derive(Clone)]
pub struct CubeTransport {
    client: Client,
    token: Arc<str>,
}
impl CubeTransport {
    pub fn new(token: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            token: token.into(),
        })
    }
    pub async fn healthy(&self, url: &str) -> bool {
        self.client
            .get(format!("{}/readyz", url.trim_end_matches('/')))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
    pub async fn execute(
        &self,
        url: &str,
        batch: &TextBatch,
        config: Option<&Value>,
        deadline: tokio::time::Instant,
    ) -> Result<CubeBatchResult, String> {
        // One absolute parent deadline bounds POST, response decoding and polls.
        // Cancelling a POST never causes a retry; the Cube retains ownership of
        // any already accepted work after this coordinator releases its lease.
        tokio::time::timeout_at(deadline, self.execute_inner(url, batch, config, deadline))
            .await
            .map_err(|_| "parent_deadline".to_owned())?
    }
    async fn execute_inner(
        &self,
        url: &str,
        batch: &TextBatch,
        config: Option<&Value>,
        deadline: tokio::time::Instant,
    ) -> Result<CubeBatchResult, String> {
        let boundary = format!("ark-{}", uuid::Uuid::new_v4().simple());
        let mut body = Vec::new();
        if let Some(config) = config {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"config\"\r\n\r\n{config}\r\n").as_bytes());
        }
        for chunk in &batch.chunks {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"chunk-{}.txt\"\r\nContent-Type: text/plain\r\n\r\n", chunk.index).as_bytes());
            body.extend_from_slice(chunk.text().as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        // A disconnected POST may already have been accepted: never replay it.
        let submit_started = std::time::Instant::now();
        let response = self
            .client
            .post(format!("{}/v1/scan", url.trim_end_matches('/')))
            .bearer_auth(self.token.as_ref())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .map_err(|_| "cube_submit_transport".to_owned())?;
        if response.status() != reqwest::StatusCode::ACCEPTED {
            return Err(format!("cube_submit_status_{}", response.status().as_u16()));
        }
        let submit_ms = submit_started.elapsed().as_secs_f64() * 1000.0;
        let accepted: Value = response
            .json()
            .await
            .map_err(|_| "cube_submit_invalid_json".to_owned())?;
        let jobs = accepted
            .get("jobs")
            .and_then(Value::as_array)
            .ok_or("cube_submit_missing_jobs")?;
        if jobs.len() != batch.chunks.len() {
            return Err("cube_submit_job_count".into());
        }
        let ids: Vec<String> = jobs
            .iter()
            .map(|job| {
                job.get("job_id")
                    .and_then(Value::as_str)
                    .filter(|s| {
                        !s.is_empty()
                            && s.len() <= 128
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    })
                    .map(str::to_owned)
                    .ok_or_else(|| "cube_submit_invalid_job_id".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let mut results: Vec<Option<Value>> = vec![None; ids.len()];
        loop {
            for (index, id) in ids.iter().enumerate() {
                if results[index].is_some() {
                    continue;
                }
                let response = match self
                    .client
                    .get(format!("{}/v1/scan/{id}", url.trim_end_matches('/')))
                    .bearer_auth(self.token.as_ref())
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => continue,
                };
                let status = response.status();
                if status.is_server_error() {
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("cube_poll_status_{}", status.as_u16()));
                }
                let job = response
                    .json::<Value>()
                    .await
                    .map_err(|_| "cube_poll_invalid_json".to_owned())?;
                if matches!(
                    job.get("status").and_then(Value::as_str),
                    Some("completed" | "failed")
                ) {
                    results[index] = Some(job);
                }
            }
            if results.iter().all(Option::is_some) {
                return Ok(CubeBatchResult {
                    jobs: results.into_iter().map(Option::unwrap).collect(),
                    submit_ms,
                });
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("cube_poll_deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
