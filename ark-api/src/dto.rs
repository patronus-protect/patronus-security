//! JSON wire types of request completions (`docs/reference/result-schema.md`).
//!
//! Scan results go out as `patronus_ark`'s own `QueuedSecurityScanResult`;
//! completions spell failure stages and kinds as here.

use patronus_ark::{SecurityFailure, SecurityRequestCompletion};
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CompletionDto {
    Complete,
    Degraded { failures: Vec<FailureDto> },
    Failed { failures: Vec<FailureDto> },
}

#[derive(Serialize)]
pub struct FailureDto {
    pub stage: String,
    pub level: Option<String>,
    pub detector_id: Option<String>,
    pub kind: String,
    pub retryable: bool,
    pub message: String,
}

impl From<SecurityRequestCompletion> for CompletionDto {
    fn from(completion: SecurityRequestCompletion) -> Self {
        match completion {
            SecurityRequestCompletion::Complete => Self::Complete,
            SecurityRequestCompletion::Degraded { failures } => Self::Degraded {
                failures: failures.into_iter().map(Into::into).collect(),
            },
            SecurityRequestCompletion::Failed { failures } => Self::Failed {
                failures: failures.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl From<SecurityFailure> for FailureDto {
    fn from(failure: SecurityFailure) -> Self {
        Self {
            stage: format!("{:?}", failure.stage),
            level: failure.level.map(|level| format!("{level:?}")),
            detector_id: failure.detector_id,
            kind: format!("{:?}", failure.kind),
            retryable: failure.retryable,
            message: failure.message,
        }
    }
}
