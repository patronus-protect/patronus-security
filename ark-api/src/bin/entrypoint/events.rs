use super::*;

pub(super) async fn collect_events(
    state: AppState,
    mut job: Job,
    lease: Arc<WorkerLease>,
    request_id: String,
    submitted: Instant,
    dispatched: Instant,
) {
    let job_id = job.job_id.clone();
    let completed = tokio::time::timeout(
        Duration::from_secs(ACTIVE_TTL_SECS - 10),
        collect_events_inner(
            &state,
            &mut job,
            &lease.worker,
            &request_id,
            submitted,
            dispatched,
        ),
    )
    .await
    .unwrap_or(false);
    if completed {
        lease.finished();
    } else {
        lease.quarantine();
        tracing::error!(job_id, worker = %lease.worker.name, "worker completion unknown; worker quarantined until idle fence");
        // Quarantine immediately; Redis cleanup must not hold this worker lease.
        drop(lease);
        job.status = "failed".into();
        job.completion = Some(json!({"state":"failed", "failures":[{
            "stage":"entrypoint", "kind":"worker_stream_interrupted",
            "message":"Worker did not report completion", "retryable":true
        }]}));
        job.decision = Some("review".into());
        let _ = save_job(&state, &job).await;
    }
    // The shared lease stays held until every job from this submission finishes.
}

pub(super) async fn collect_events_inner(
    state: &AppState,
    job: &mut Job,
    worker: &WorkerConfig,
    request_id: &str,
    submitted: Instant,
    dispatched: Instant,
) -> bool {
    let job_id = job.job_id.clone();
    let started = Instant::now();
    let url = format!(
        "{}/v1/scan/{request_id}/events",
        worker.url.trim_end_matches('/')
    );
    let response = match state
        .client
        .get(url)
        .bearer_auth(&state.worker_token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            tracing::warn!(job_id, status = %response.status(), "worker event stream rejected");
            return false;
        }
        Err(error) => {
            tracing::warn!(job_id, %error, "worker event stream failed");
            return false;
        }
    };

    tracing::debug!(job_id, worker = %worker.name, worker_events_connected_ms = started.elapsed().as_secs_f64() * 1_000.0, "worker event stream connected");

    let mut frames = sse::Frames::default();
    let mut stream = response.bytes_stream();
    let mut event_count = 0usize;
    let mut progress_dirty = false;
    let mut progress_flush = tokio::time::interval(Duration::from_millis(100));
    progress_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let chunk = tokio::select! {
            chunk = stream.next() => match chunk {
                Some(chunk) => chunk,
                None => break,
            },
            _ = progress_flush.tick(), if progress_dirty => {
                if save_job(state, job).await.is_err() {
                    return false;
                }
                progress_dirty = false;
                continue;
            }
        };
        let Ok(chunk) = chunk else { break };
        for frame in frames.push(&chunk) {
            let event = frame.lines().find_map(|line| line.strip_prefix("event: "));
            let data = frame
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .and_then(|data| serde_json::from_str::<Value>(data).ok());
            let (Some(event), Some(data)) = (event, data) else {
                continue;
            };
            event_count += 1;
            if matches!(event, "result" | "provisional") {
                job.timings.observe(&data);
            }
            match event {
                "progress" => {
                    if let Some(category) = data.get("category").and_then(Value::as_str) {
                        job.progress.insert(category.to_string(), data);
                    }
                }
                "result" => {
                    if let Some(category) = data.get("category").and_then(Value::as_str) {
                        tracing::debug!(
                            job_id,
                            worker = %worker.name,
                            category,
                            level = data.get("level").and_then(|value| value.as_str()).unwrap_or("unknown"),
                            model = data.get("model").and_then(|value| value.as_str()).unwrap_or("unknown"),
                            reported_duration_ms = data.get("duration_ms").and_then(|value| value.as_f64()).unwrap_or_default(),
                            event_elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0,
                            "worker result received"
                        );
                        let replace = job
                            .categories
                            .get(category)
                            .is_none_or(|previous| level_rank(&data) >= level_rank(previous));
                        if replace {
                            job.categories
                                .insert(category.to_string(), compact_result(&data));
                        }
                    }
                }
                "finished" => {
                    job.completion = data.get("completion").cloned();
                    job.status = if data.pointer("/completion/state").and_then(Value::as_str)
                        == Some("failed")
                    {
                        "failed".to_string()
                    } else {
                        "completed".to_string()
                    };
                    job.decision = Some(final_decision(job));
                    job.timings.worker_ms = Some(dispatched.elapsed().as_secs_f64() * 1000.0);
                    job.timings.total_ms = Some(submitted.elapsed().as_secs_f64() * 1000.0);
                }
                _ => {}
            }
            if event == "progress" {
                progress_dirty = true;
                continue;
            }
            if save_job(state, job).await.is_err() {
                return false;
            }
            progress_dirty = false;
            if event == "finished" {
                tracing::debug!(job_id, worker = %worker.name, worker_events_finished_ms = started.elapsed().as_secs_f64() * 1_000.0, event_count, "worker event stream finished");
                return true;
            }
        }
    }
    false
}

fn level_rank(result: &Value) -> u8 {
    match result.get("level").and_then(Value::as_str) {
        Some("L3") => 3,
        Some("L2") => 2,
        _ => 1,
    }
}

pub(super) fn compact_result(result: &Value) -> Value {
    let decision_evidence = result
        .get("decision_evidence")
        .filter(|evidence| !evidence.is_null())
        .cloned()
        .or_else(|| {
            result
                .pointer("/decision/decision_evidence")
                .filter(|evidence| !evidence.is_null())
                .cloned()
        })
        .or_else(|| {
            result
                .pointer("/decision/decision_candidate/chunk_evidence")
                .filter(|evidence| !evidence.is_null())
                .cloned()
        })
        .or_else(|| {
            result
                .get("layers")
                .and_then(Value::as_array)
                .and_then(|layers| {
                    layers.iter().rev().find_map(|layer| {
                        layer
                            .pointer("/details/decision_evidence")
                            .filter(|evidence| !evidence.is_null())
                            .cloned()
                    })
                })
        })
        .or_else(|| l2_chunk_evidence(result));
    json!({
        "category": result.get("category"),
        "class_name": result.get("class_name"),
        "confidence": result.get("confidence"),
        "level": result.get("level"),
        "model": result.get("model"),
        "duration_ms": result.get("duration_ms"),
        "accepted": result.pointer("/decision/recommendation/accepted").and_then(Value::as_bool).unwrap_or(false),
        "final_result": result.pointer("/decision/final_result"),
        "decision_evidence": decision_evidence,
        "evidence_spans": result.get("evidence_spans").cloned().unwrap_or_else(|| json!([])),
    })
}

fn l2_chunk_evidence(result: &Value) -> Option<Value> {
    let class_name = result.get("class_name")?.as_str()?;
    if matches!(class_name, "benign" | "safe") {
        return None;
    }
    let chunks = result
        .get("layers")?
        .as_array()?
        .iter()
        .rev()
        .find_map(|layer| layer.pointer("/details/l2_chunk_outputs")?.as_array())?;
    let contributors = chunks
        .iter()
        .enumerate()
        .filter(|(_, chunk)| chunk.get("class_name").and_then(Value::as_str) == Some(class_name))
        .map(|(chunk_id, chunk)| {
            json!({
                "chunk_id": chunk_id,
                "span": chunk.get("span"),
                "source": "l2",
                "class_name": class_name,
                "confidence": chunk.get("confidence"),
            })
        })
        .collect::<Vec<_>>();
    let decisive_chunk = contributors.iter().max_by(|left, right| {
        left.get("confidence")
            .and_then(Value::as_f64)
            .partial_cmp(&right.get("confidence").and_then(Value::as_f64))
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    Some(json!({
        "stage": "l2",
        "contributors": contributors,
        "decisive_chunks": [decisive_chunk],
    }))
}
