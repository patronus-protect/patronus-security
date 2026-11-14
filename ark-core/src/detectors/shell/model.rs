// SPDX-License-Identifier: MIT OR Apache-2.0
//! The K26 shell-risk model: the shared TF-IDF + LR form
//! ([`TfidfLrModel`](crate::detectors::facts_common::model::TfidfLrModel))
//! with the [`kf1`](super::kf1) analyzer (shell tokens, legacy markers and
//! `patronus.facts/1` tokens) as its token block. The text is never executed.

use crate::detectors::facts_common::model::ModelForm;

/// Class name of a flagged command and its evidence spans.
pub const SHELL_RISK_CLASS: &str = "shell_risk";
/// Threshold of the `ask` decision: 1 % FPR on external agent commands.
pub const ASK_THRESHOLD: &str = "external_commands_1pct_fpr";
/// Threshold of the `block` decision: 0.1 % FPR.
pub const BLOCK_THRESHOLD: &str = "block_0_1pct_fpr";

/// The form of a shell-risk `model.json`.
pub const SHELL_MODEL: ModelForm = ModelForm {
    label: "shell risk",
    analyzer: "kf1",
    ask_threshold: ASK_THRESHOLD,
    block_threshold: BLOCK_THRESHOLD,
};
