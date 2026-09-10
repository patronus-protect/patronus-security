use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use patronus_ark::SecurityLevelReadiness;
use serde_json::json;

use crate::state::AppState;

pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

fn level_ready(readiness: &SecurityLevelReadiness) -> bool {
    !matches!(readiness, SecurityLevelReadiness::NotReady { .. })
}

pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let readiness = state.gateway.runtime_readiness();
    let ready =
        level_ready(&readiness.l1) && level_ready(&readiness.l2) && level_ready(&readiness.l3);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ready": ready,
            "onnx": {
                "available_providers": patronus_ark::ml::onnx::available_execution_providers(),
                "active_providers": patronus_ark::ml::onnx::active_execution_providers(),
            }
        })),
    )
}

/// Only mounted behind service authentication; never exposed by the entrypoint.
pub async fn worker_status(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    status(&state, false)
}

pub async fn recover_worker(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    status(&state, true)
}

fn status(state: &AppState, recover: bool) -> (StatusCode, Json<serde_json::Value>) {
    let readiness = state.gateway.runtime_readiness();
    let ready =
        level_ready(&readiness.l1) && level_ready(&readiness.l2) && level_ready(&readiness.l3);
    let mut admission = state.admission.lock().expect("admission mutex poisoned");
    let active_jobs = state.active_jobs();
    let status = if !ready {
        StatusCode::SERVICE_UNAVAILABLE
    } else if recover && !admission.recover(active_jobs) {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    (
        status,
        Json(json!({
            "instance_id": admission.instance_id,
            "epoch": admission.epoch,
            "ready": ready,
            "active_submissions": admission.active_submissions,
            "active_jobs": active_jobs,
        })),
    )
}
