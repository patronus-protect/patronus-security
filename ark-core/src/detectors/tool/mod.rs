// SPDX-License-Identifier: MIT OR Apache-2.0
//! `tool_call`: facts and policies for one agent tool call, shaped like Cat
//! ([`super::shell`]) for shell commands.
//!
//! One call, `{tool, arguments, harness?, description?}`, goes through three
//! fixed steps:
//!
//! 1. [`model`]: the tool-call model reads the tool name and arguments and
//!    gives `paw` (operation), `sight` (tool type), `sinks` (where data goes:
//!    `net_request`, `search`, `message`, `web_form`, `publish`, `agent`,
//!    `remote_exec`) and `sources` (`sensitive`, `untrusted`).
//! 2. [`facts`]: `patronus.tool_facts/1`, the model's labels next to what the
//!    arguments show (paths, hosts, recipients, credentials, SQL, Cat's facts
//!    of a shell command) and what the earlier calls of the session left.
//! 3. [`policies`]: Cedar policies over the facts decide `allow`, `ask` or
//!    `block`: the core set, plus the operator's own `user.*` policies.
//!
//! [`ToolAssessor`] runs all three. The caller keeps the facts of the last
//! [`SESSION_WINDOW`] calls of a session and passes them back (ARK stores
//! nothing). Only the calls are read: no user request, no tool results.
//! Deterministic; nothing is executed.
//!
//! The reference is `toolfacts.py` / `featurize.py` of the tool-call model
//! research; `testdata/goldens.jsonl` holds its outputs.

pub mod facts;
pub mod featurize;
pub mod json;
pub mod model;
pub mod policies;

use std::path::Path;

use crate::detectors::facts_common::block::BlockFile;

use serde_json::{json, Value};

pub use facts::{extract, Session, ToolCall, ToolFacts, TOOL_FACTS_VERSION};
pub use json::Json;
pub use model::{ModelLabels, ModelOutput, ToolModel};
pub use policies::{Decision, PolicyHit, ToolPolicies, ToolPolicyConfig};

/// Earlier calls of the session the policies are tuned for.
pub const SESSION_WINDOW: usize = 5;

/// The result for one call.
#[derive(Clone, Debug)]
pub struct Assessment {
    pub facts: ToolFacts,
    /// Model probabilities per head, when a model ran.
    pub p: Option<std::collections::BTreeMap<String, f32>>,
    pub decision: Decision,
    /// The fired policies, strongest first.
    pub hits: Vec<PolicyHit>,
}

impl Assessment {
    /// `{"decision", "policies": [{"id", "tier", "decision", "title"}], "facts", "p"?}`.
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "decision": self.decision.as_str(),
            "policies": self.hits.iter().map(|h| json!({
                "id": h.id, "tier": h.tier.as_str(), "decision": h.decision.as_str(), "title": h.title,
            })).collect::<Vec<_>>(),
            "facts": self.facts.to_json(),
        });
        if let Some(p) = &self.p {
            out["p"] = json!(p);
        }
        out
    }
}

/// Model, facts and policies for tool calls.
pub struct ToolAssessor {
    model: Option<ToolModel>,
    policies: ToolPolicies,
}

impl ToolAssessor {
    /// With a model; without one, the caller passes the labels to
    /// [`Self::assess_with_labels`].
    pub fn new(model: Option<ToolModel>, policies: ToolPolicies) -> Self {
        Self { model, policies }
    }

    /// Load a release and the `*.cedar` user policies of `policy_dirs`.
    /// `release` is a block file (`block.safetensors`: model and core
    /// policies, `sha256` pins the file) or a bundle directory (`manifest.json`,
    /// `model.json`, `weights.bin`; `sha256` pins the manifest; the
    /// compiled-in core policies).
    pub fn load(
        release: &Path,
        sha256: Option<&str>,
        policy_dirs: &[&Path],
    ) -> Result<Self, String> {
        let mut config = ToolPolicyConfig::default();
        for dir in policy_dirs {
            config.add_cedar_dir(dir)?;
        }
        if release.is_file() {
            return Self::from_block(&BlockFile::open(release, sha256)?, &config);
        }
        Ok(Self::new(
            Some(ToolModel::load(release, sha256)?),
            ToolPolicies::with_config(&config)?,
        ))
    }

    /// Model and core policies of a `tool-call` block. Its Cedar schema and
    /// the shell vocabulary its facts were built with must be the ones this
    /// runtime compiles in, so the block and this runtime read the same facts.
    pub fn from_block(block: &BlockFile, config: &ToolPolicyConfig) -> Result<Self, String> {
        block.require_kind("tool-call")?;
        if block.meta("facts")? != "patronus.tool_facts/1" {
            return Err(format!(
                "block facts {} are not patronus.tool_facts/1",
                block.meta("facts")?
            ));
        }
        if block.meta("schema.cedarschema")? != policies::SCHEMA {
            return Err("block Cedar schema differs from this runtime's".into());
        }
        block.require_embedded(
            "shell_vocab_sha256",
            crate::detectors::shell::vocab::VOCAB_CSV,
        )?;
        Ok(Self::new(
            Some(ToolModel::from_block(block)?),
            ToolPolicies::with_core(block.meta("core.cedar")?, config)?,
        ))
    }

    pub fn policies(&self) -> &ToolPolicies {
        &self.policies
    }

    /// Assess `call`: `prior` are the facts of the earlier calls of the
    /// session (the last [`SESSION_WINDOW`] are used), `known_targets` the
    /// receivers the host approved before.
    pub fn assess(
        &self,
        call: &ToolCall,
        prior: &[ToolFacts],
        known_targets: &[String],
    ) -> Result<Assessment, String> {
        let model = self
            .model
            .as_ref()
            .ok_or("no model loaded: use assess_with_labels")?;
        let out = model.predict(&call.item());
        let mut a = self.assess_with_labels(call, &out.labels, prior, known_targets)?;
        a.p = Some(out.p);
        Ok(a)
    }

    /// Assess `call` with labels the caller already has.
    pub fn assess_with_labels(
        &self,
        call: &ToolCall,
        labels: &ModelLabels,
        prior: &[ToolFacts],
        known_targets: &[String],
    ) -> Result<Assessment, String> {
        let window = &prior[prior.len().saturating_sub(SESSION_WINDOW)..];
        let facts = extract(call, labels, &Session::from_prior(window));
        let (decision, hits) = self.policies.evaluate(&facts, known_targets, |_| true)?;
        Ok(Assessment {
            facts,
            p: None,
            decision,
            hits,
        })
    }
}
