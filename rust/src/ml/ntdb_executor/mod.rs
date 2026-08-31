// SPDX-License-Identifier: GPL-3.0-only
use std::error::Error;
use std::path::PathBuf;

use crate::NtdbOperatingPoint;

mod decision;
mod encoder;
mod heuristics;
mod joint_v3_runtime;
mod lightgbm;
pub mod manifest;
mod package;
mod runtime;
pub(crate) mod tokenizer;

pub use decision::NtdbDecision;
pub(crate) use joint_v3_runtime::aggregate_probabilities;
pub use package::{
    ByteSpan, L2ChunkOutput, L3Candidate, MultiScoreOutput, NtdbMultiPackage, NtdbPackageSpec,
    ScoreOutput,
};
pub(crate) use package::{JointV3CandidatePolicy, JointV3DecisionContext};

/// Internal items re-exported for the integration test suite. Not public API.
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod test_util {
    pub use super::encoder::StaticEncoderStore;
    pub use super::heuristics::{
        global_text_heuristics, local_text_heuristics,
        shared_global_text_heuristics_from_token_stats, TokenIdStats,
    };
    pub use super::lightgbm::Tree;
    pub use super::runtime::unit_left_dot;
    pub use super::tokenizer::RuntimeTokenizer;
}

pub type NtdbResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(crate) fn ntdb_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(std::io::Error::other(message.into()))
}

pub struct NtdbExecutor {
    packages: NtdbMultiPackage,
}

impl NtdbExecutor {
    pub fn load_specs<I>(specs: I) -> NtdbResult<Self>
    where
        I: IntoIterator<Item = NtdbPackageSpec>,
    {
        Ok(Self {
            packages: NtdbMultiPackage::load_specs(specs)?,
        })
    }

    pub fn load<I, P>(packages: I) -> NtdbResult<Self>
    where
        I: IntoIterator<Item = (String, P)>,
        P: Into<PathBuf>,
    {
        Self::load_specs(
            packages
                .into_iter()
                .map(|(id, path)| NtdbPackageSpec::new(id, path.into())),
        )
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub fn model_ids(&self) -> impl Iterator<Item = &str> {
        self.packages.model_ids()
    }

    pub fn model_aggregator_ids(&self, model_id: &str) -> Option<Vec<String>> {
        self.packages.model_aggregator_ids(model_id)
    }

    pub fn score_all(
        &mut self,
        text: &str,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<NtdbDecision>> {
        let outputs = self.packages.score_all_models(text, operating_point)?;
        decisions_from_multi_outputs(outputs)
    }

    /// Scores multiple texts while preserving each package's runtime contract.
    /// Package-v4 executes every prepared chunk as an independent neural row.
    pub fn score_all_batch(
        &mut self,
        texts: &[String],
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<Vec<NtdbDecision>>> {
        self.packages
            .score_all_models_batch(texts, operating_point)?
            .into_iter()
            .map(decisions_from_multi_outputs)
            .collect()
    }

    pub fn score_models<I, S>(
        &mut self,
        model_ids: I,
        text: &str,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<NtdbDecision>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let outputs = self
            .packages
            .score_models(model_ids, text, operating_point)?;
        decisions_from_multi_outputs(outputs)
    }
}

fn decisions_from_multi_outputs(outputs: Vec<MultiScoreOutput>) -> NtdbResult<Vec<NtdbDecision>> {
    outputs
        .into_iter()
        .flat_map(|model| {
            let model_id = model.model_id;
            model
                .outputs
                .into_iter()
                .map(move |output| NtdbDecision::from_score_output(model_id.clone(), output))
        })
        .collect()
}
