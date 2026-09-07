use crate::cube::batching::TextBatch;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

const INITIAL_POLL_DELAY: Duration = Duration::from_millis(1);
const MAX_POLL_DELAY: Duration = Duration::from_millis(25);

fn next_poll_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(MAX_POLL_DELAY)
}

pub struct CubeBatchResult {
    pub jobs: Vec<Value>,
    pub submit_ms: f64,
}

#[derive(Clone)]
pub struct CubeTransport {
    client: Client,
    token: Arc<str>,
    #[cfg(test)]
    poll_delays: Option<Arc<std::sync::Mutex<Vec<Duration>>>>,
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
            #[cfg(test)]
            poll_delays: None,
        })
    }
    async fn sleep_before_poll(&self, delay: Duration) {
        #[cfg(test)]
        if let Some(delays) = &self.poll_delays {
            delays.lock().unwrap().push(delay);
            tokio::task::yield_now().await;
            return;
        }
        tokio::time::sleep(delay).await;
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
        let mut poll_delay = INITIAL_POLL_DELAY;
        loop {
            let mut completed = false;
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
                    completed = true;
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
            if completed {
                poll_delay = INITIAL_POLL_DELAY;
            }
            self.sleep_before_poll(poll_delay).await;
            poll_delay = next_poll_delay(poll_delay);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cube::batching::{batch, split_text};
    use axum::{
        extract::{Path, State},
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    #[test]
    fn poll_delay_starts_short_and_caps_at_twenty_five_milliseconds() {
        let mut delay = INITIAL_POLL_DELAY;
        let mut observed = vec![delay];
        for _ in 0..6 {
            delay = next_poll_delay(delay);
            observed.push(delay);
        }
        assert_eq!(
            observed,
            [
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::from_millis(4),
                Duration::from_millis(8),
                Duration::from_millis(16),
                Duration::from_millis(25),
                Duration::from_millis(25),
            ]
        );
    }

    struct PollMock {
        counts: [AtomicUsize; 2],
    }

    async fn submit() -> (StatusCode, Json<Value>) {
        (
            StatusCode::ACCEPTED,
            Json(json!({"jobs": [
                {"job_id": "job_0", "status_url": "/v1/scan/job_0"},
                {"job_id": "job_1", "status_url": "/v1/scan/job_1"}
            ]})),
        )
    }

    async fn poll(State(state): State<Arc<PollMock>>, Path(id): Path<String>) -> Json<Value> {
        let index = usize::from(id == "job_1");
        let attempt = state.counts[index].fetch_add(1, Ordering::SeqCst);
        let complete_after = if index == 0 { 6 } else { 7 };
        Json(if attempt >= complete_after {
            json!({"job_id": id, "status": "completed"})
        } else {
            json!({"job_id": id, "status": "running"})
        })
    }

    #[tokio::test]
    async fn transport_polls_quickly_and_resets_delay_after_partial_completion() {
        let state = Arc::new(PollMock {
            counts: [AtomicUsize::new(0), AtomicUsize::new(0)],
        });
        let router = Router::new()
            .route("/readyz", get(|| async { StatusCode::OK }))
            .route("/v1/scan", post(submit))
            .route("/v1/scan/:id", get(poll))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let poll_delays = Arc::new(Mutex::new(Vec::new()));
        let mut transport = CubeTransport::new("test-key".into()).unwrap();
        transport.poll_delays = Some(poll_delays.clone());
        let url = format!("http://{address}");
        assert!(transport.healthy(&url).await);
        let text: Arc<str> = Arc::from("abcdefgh");
        let chunks = split_text("parent", text, 4);
        let result = transport
            .execute(
                &url,
                &batch("parent", &chunks, 0, 2),
                None,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        server.abort();

        assert_eq!(result.jobs.len(), 2);
        assert_eq!(state.counts[0].load(Ordering::SeqCst), 7);
        assert_eq!(state.counts[1].load(Ordering::SeqCst), 8);
        assert_eq!(
            *poll_delays.lock().unwrap(),
            [1, 2, 4, 8, 16, 25, 1].map(Duration::from_millis)
        );
    }
}
