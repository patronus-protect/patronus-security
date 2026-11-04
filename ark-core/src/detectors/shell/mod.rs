// SPDX-License-Identifier: MIT OR Apache-2.0
//! `shell_command`: the `cat-shell-risk-commander` K26 detector ("Cat").
//!
//! [`shell_risk::ShellRiskPipeline`] loads a verified release bundle and turns
//! a command into a `patronus.verdict/1`: the K26 TF-IDF model over the
//! `kf1` analyzer plus Cedar policies over `patronus.facts/1`. It implements
//! [`NativeDetector`](super::NativeDetector) like every other L1 detector.
//!
//! - [`facts`]: `patronus.facts/1` of a command, with harness context and
//!   the facts of earlier commands (`prior_facts`, kept by the caller).
//! - [`policies`]: the Cedar schema, core / bundle-default / user tiers, user
//!   policies from `.cedar` files and the allowlist.
//! - [`shell_risk`]: the pipeline and the verdict.
//!
//! The text is never executed.

mod bundle;
pub mod facts;
mod kf1;
mod markers;
mod model;
pub mod policies;
mod pyjson;
mod pyre;
pub mod shell_risk;
mod tokens;
mod vocab;

pub use kf1::kf1;
pub use model::{ShellRiskModel, TopFeature, ASK_THRESHOLD, BLOCK_THRESHOLD, SHELL_RISK_CLASS};
