// SPDX-License-Identifier: GPL-3.0-only
//! Request-bound cancellation for active Wolf jobs. Never cancel under the registry lock.
use super::{RequestRegistry, RequestRegistryState};
use crate::RequestId;
use patronus_ark_core::ScanControl;
use std::sync::Arc;

pub(super) struct ActiveRun {
    control: ScanControl,
    allows_fallback: bool,
}

#[derive(Debug)]
pub(super) enum Stopped {
    Inactive,
    EarlyExit(String),
}

pub(super) struct ActiveRunGuard {
    requests: Arc<RequestRegistry>,
    request_id: RequestId,
    job_id: u64,
    control: ScanControl,
}

fn admission(
    registry: &RequestRegistryState,
    request_id: &str,
    job_id: u64,
    allows_fallback: bool,
) -> Result<(), Stopped> {
    if !registry.requests.get(request_id).is_some_and(|request| {
        request.completion.is_none() && request.pending_l3_job_ids.contains(&job_id)
    }) {
        return Err(Stopped::Inactive);
    }
    if allows_fallback {
        if let Some(reason) = registry.early_exit_reasons.get(request_id) {
            return Err(Stopped::EarlyExit(reason.clone()));
        }
    }
    Ok(())
}

impl ActiveRunGuard {
    pub(super) fn check_request(
        requests: &RequestRegistry,
        request_id: &str,
        job_id: u64,
        allows_fallback: bool,
    ) -> Result<(), Stopped> {
        admission(
            &requests
                .state
                .lock()
                .expect("request registry mutex poisoned"),
            request_id,
            job_id,
            allows_fallback,
        )
    }

    pub(super) fn register(
        requests: Arc<RequestRegistry>,
        request_id: &str,
        job_id: u64,
        allows_fallback: bool,
        control: ScanControl,
    ) -> Result<Self, Stopped> {
        {
            let mut registry = requests
                .state
                .lock()
                .expect("request registry mutex poisoned");
            admission(&registry, request_id, job_id, allows_fallback)?;
            let key = (request_id.to_owned(), job_id);
            if registry.active_runs.contains_key(&key) {
                return Err(Stopped::Inactive);
            }
            registry.active_runs.insert(
                key,
                ActiveRun {
                    control: control.clone(),
                    allows_fallback,
                },
            );
        }
        Ok(Self {
            requests,
            request_id: request_id.to_owned(),
            job_id,
            control,
        })
    }

    pub(super) fn control(&self) -> &ScanControl {
        &self.control
    }

    pub(super) fn early_exit_reason(&self) -> Option<String> {
        self.requests
            .state
            .lock()
            .expect("request registry mutex poisoned")
            .early_exit_reasons
            .get(&self.request_id)
            .cloned()
    }
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        self.requests
            .state
            .lock()
            .expect("request registry mutex poisoned")
            .active_runs
            .remove(&(self.request_id.clone(), self.job_id));
    }
}

impl RequestRegistry {
    pub(super) fn cancel_early_exit_runs(&self, request_id: &str, reason: &str) {
        let controls = {
            let mut registry = self.state.lock().expect("request registry mutex poisoned");
            if !registry
                .requests
                .get(request_id)
                .is_some_and(|request| request.completion.is_none())
            {
                return;
            }
            // Also reject eligible jobs that have left the queue but are still waiting for a model.
            registry
                .early_exit_reasons
                .insert(request_id.to_owned(), reason.to_owned());
            registry
                .active_runs
                .iter()
                .filter(|((id, _), run)| id == request_id && run.allows_fallback)
                .map(|(_, run)| run.control.clone())
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
    }

    pub(crate) fn cancel_finished_runs(&self, request_id: &str) {
        let controls = {
            let mut registry = self.state.lock().expect("request registry mutex poisoned");
            if registry
                .requests
                .get(request_id)
                .is_some_and(|request| request.completion.is_none())
            {
                return;
            }
            registry.early_exit_reasons.remove(request_id);
            let mut controls = Vec::new();
            registry.active_runs.retain(|(id, _), run| {
                if id == request_id {
                    controls.push(run.control.clone());
                    false
                } else {
                    true
                }
            });
            controls
        };
        for control in controls {
            control.cancel();
        }
    }
}

#[cfg(test)]
mod tests;
