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
