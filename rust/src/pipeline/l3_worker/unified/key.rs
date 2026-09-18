// SPDX-License-Identifier: GPL-3.0-only
use crate::assets::UNIFIED_L3_ASSET;
use crate::{L3ClusteringStrategy, L3EarlyExitMode};

use super::super::{L3JobSpec, L3WorkerInput, L3WorkerJob};

pub(super) fn unified_run_key(spec: &L3JobSpec) -> String {
    unified_key(
        Some(spec.request_id.as_str()),
        &spec.text,
        spec.execution.backend(),
        spec.execution.l3_policy(),
        &spec.l3_candidates,
    )
}

pub(in crate::pipeline::l3_worker) fn run_key_for_job(job: &L3WorkerJob) -> String {
    if let Some(key) = &job.unified_run_key {
        return key.clone();
    }
    unified_job_key(
        Some(job.request_id.as_str()),
        job,
        job.execution.backend(),
        job.execution.l3_policy(),
    )
}

pub(super) fn unified_cache_key(spec: &L3JobSpec) -> String {
    unified_key(
        None,
        &spec.text,
        spec.execution.backend(),
        spec.execution.l3_policy(),
        &spec.l3_candidates,
    )
}

pub(in crate::pipeline::l3_worker) fn cache_key_for_job(job: &L3WorkerJob) -> String {
    if let Some(key) = &job.unified_cache_key {
        return key.clone();
    }
    unified_job_key(
        None,
        job,
        job.execution.backend(),
        job.execution.l3_policy(),
    )
}

fn unified_job_key(
    request_id: Option<&str>,
    job: &L3WorkerJob,
    backend: crate::ExecutionBackend,
    policy: &crate::L3SchedulerPolicy,
) -> String {
    let mut hasher = blake3::Hasher::new();
    match &job.input {
        L3WorkerInput::PlannedChunks(chunks) => {
            hasher.update(&(chunks.len() as u64).to_le_bytes());
            for chunk in chunks {
                hasher.update(&chunk.start_byte.to_le_bytes());
                hasher.update(&chunk.end_byte.to_le_bytes());
                hasher.update(chunk.text.as_bytes());
            }
        }
        L3WorkerInput::Text(text) => {
            hasher.update(text.as_bytes());
        }
    }
    update_unified_key(&mut hasher, policy, &job.l3_candidates);
    finalized_unified_key(request_id, backend, hasher)
}

pub(super) fn unified_key(
    request_id: Option<&str>,
    text: &str,
    backend: crate::ExecutionBackend,
    policy: &crate::L3SchedulerPolicy,
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(text.as_bytes());
    update_unified_key(&mut hasher, policy, candidates);
    finalized_unified_key(request_id, backend, hasher)
}

fn update_unified_key(
    hasher: &mut blake3::Hasher,
    policy: &crate::L3SchedulerPolicy,
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
) {
    hasher.update(unified_policy_key(policy).as_bytes());
    for candidate in candidates {
        hasher.update(&candidate.span.start.to_le_bytes());
        hasher.update(&candidate.span.end.to_le_bytes());
        hasher.update(&candidate.promote_score.to_bits().to_le_bytes());
        hasher.update(&candidate.promote_threshold.to_bits().to_le_bytes());
        hasher.update(candidate.source_pipeline.as_bytes());
    }
}

fn finalized_unified_key(
    request_id: Option<&str>,
    backend: crate::ExecutionBackend,
    hasher: blake3::Hasher,
) -> String {
    let hash = hasher.finalize();
    format!(
        "{}{}:{}:{}",
        request_id
            .map(|value| format!("{value}:"))
            .unwrap_or_default(),
        UNIFIED_L3_ASSET.revision,
        backend.as_str(),
        hash.to_hex()
    )
}

fn unified_policy_key(policy: &crate::L3SchedulerPolicy) -> String {
    let base = match (policy.clustering, policy.early_exit) {
        (L3ClusteringStrategy::Disabled, L3EarlyExitMode::Disabled) => "disabled:no_early_exit",
        (L3ClusteringStrategy::Disabled, L3EarlyExitMode::ClassStable) => "disabled:class_stable",
        (L3ClusteringStrategy::RankOnly, L3EarlyExitMode::Disabled) => "rank_only:no_early_exit",
        (L3ClusteringStrategy::RankOnly, L3EarlyExitMode::ClassStable) => "rank_only:class_stable",
        (L3ClusteringStrategy::Representative, L3EarlyExitMode::Disabled) => {
            "representative:no_early_exit"
        }
        (L3ClusteringStrategy::Representative, L3EarlyExitMode::ClassStable) => {
            "representative:class_stable"
        }
        (L3ClusteringStrategy::VerifyRepresentative, L3EarlyExitMode::Disabled) => {
            "verify_representative:no_early_exit"
        }
        (L3ClusteringStrategy::VerifyRepresentative, L3EarlyExitMode::ClassStable) => {
            "verify_representative:class_stable"
        }
    };
    let mut pipeline_keys = policy.pipelines.keys().collect::<Vec<_>>();
    pipeline_keys.sort();
    let pipelines = pipeline_keys
        .into_iter()
        .map(|key| {
            let value = serde_json::to_string(&policy.pipelines[key])
                .expect("L3 pipeline policy must serialize");
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{base}:reps={}:verify_reps={}:similarity={}:max_cluster={}:pipelines={pipelines}",
        policy.representatives_per_cluster,
        policy.verify_representatives_per_cluster,
        policy.min_cluster_similarity,
        policy.max_cluster_size,
    )
}
