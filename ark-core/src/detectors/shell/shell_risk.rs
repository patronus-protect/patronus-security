// SPDX-License-Identifier: MIT OR Apache-2.0
//! `patronus.verdict/1` and the `shell_command` detector.
//!
//! The verdict is `max(model, policies)` on `allow < ask < block`: the model
//! asks above the 1 % FPR cut and blocks above the 0.1 % FPR cut, and every
//! fired Cedar policy sets at least its level (an ask policy raises the score
//! to the midpoint of the cuts, a block policy to the block cut + 2). The K26
//! Python reference is the specification; `rust/tests/shell_risk_parity.rs`
//! checks this port against it.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use serde_json::{json, Value};

use super::bundle;
use super::facts::{extract, Facts, ShellContext};
use super::kf1::visit_kf1;
use super::model::{ShellRiskModel, TopFeature, ASK_THRESHOLD, SHELL_RISK_CLASS};
use super::policies::{Decision, Lowered, PolicyHit, ShellPolicies, ShellPolicyConfig};
use super::pyjson::{self, py_round};
use crate::detectors::{NativeDetection, NativeDetector};
use crate::threat::NativeText;
use crate::EvaluationResult;

const SAFE_CLASS: &str = "safe";
/// Version tag of the verdict document.
pub const VERDICT_VERSION: &str = "patronus.verdict/1";

/// `patronus.verdict/1` of one command.
#[derive(Clone, Debug, PartialEq)]
pub struct ShellVerdict {
    pub decision: Decision,
    /// Bundle score: the model score raised to the policy floor.
    pub score: f64,
    /// `ask` and `block` cuts on the score.
    pub ask_cut: f64,
    pub block_cut: f64,
    pub model_id: String,
    pub model_score: f64,
    pub model_decision: Decision,
    /// Strongest positive feature contributions; ties in feature-name order.
    pub top_features: Vec<TopFeature>,
    /// Fired policies, strongest first.
    pub policies: Vec<PolicyHit>,
    /// Bundle-default policies the allowlist lowered from block to ask.
    pub allowlisted: Vec<Lowered>,
    pub facts: Facts,
}

impl ShellVerdict {
    /// The verdict document; `facts` holds the canonical facts when included.
    pub fn to_json(&self, with_facts: bool) -> Value {
        let mut value = json!({
            "v": VERDICT_VERSION,
            "decision": self.decision.as_str(),
            "score": py_round(self.score, 4),
            "cuts": {"ask": py_round(self.ask_cut, 6), "block": py_round(self.block_cut, 6)},
            "model": {
                "id": self.model_id,
                "score": py_round(self.model_score, 4),
                "decision": self.model_decision.as_str(),
                "top_features": self.top_features.iter()
                    .map(|f| json!({"feature": f.feature, "weight": f.weight}))
                    .collect::<Vec<_>>(),
            },
            "policies": self.policies.iter().map(|p| json!({
                "id": p.id,
                "tier": p.tier.as_str(),
                "title": p.title,
                "decision": p.decision.as_str(),
                "where": p.r#where,
            })).collect::<Vec<_>>(),
            "allowlisted": self.allowlisted.iter()
                .map(|l| json!({"id": l.id, "from": "block", "to": "ask"}))
                .collect::<Vec<_>>(),
        });
        if with_facts {
            let mut facts = self.facts.to_json();
            pyjson::canonical(&mut facts);
            value["facts"] = facts;
        }
        value
    }

    /// Compact JSON with sorted keys, as the Python reference writes it.
    pub fn to_json_string(&self, with_facts: bool) -> String {
        pyjson::dumps_compact(&self.to_json(with_facts))
    }
}

/// Score of one command.
#[derive(Debug, Clone, PartialEq)]
pub struct ShellRiskScore {
    /// Model decision score (logit).
    pub decision_score: f64,
    /// Score after policy floors.
    pub bundle_score: f64,
    /// `ask` threshold (1 % FPR cut).
    pub threshold: f64,
    pub decision: Decision,
    /// Whether the verdict is `ask` or `block`.
    pub flagged: bool,
}

/// The `shell_command` detector ("Cat"): the K26 model plus the bundle's Cedar
/// policies, with user policies and allowlist from the runtime configuration.
pub struct ShellRiskPipeline {
    model: ShellRiskModel,
    /// Swapped by [`Self::configure`]; scans clone the `Arc` and hold no lock.
    policies: RwLock<Arc<ShellPolicies>>,
}

fn decide(score: f64, (ask, block): (f64, f64)) -> Decision {
    if score > block {
        Decision::Block
    } else if score > ask {
        Decision::Ask
    } else {
        Decision::Allow
    }
}

impl ShellRiskPipeline {
    /// The model alone, without policies.
    pub fn new(model: ShellRiskModel) -> Self {
        Self::with_policies(model, ShellPolicies::none())
    }

    fn with_policies(model: ShellRiskModel, policies: ShellPolicies) -> Self {
        Self {
            model,
            policies: RwLock::new(Arc::new(policies)),
        }
    }

    /// Load a bundle directory (model and gated policy levels), each file
    /// checked against its `manifest.json`.
    pub fn from_bundle_dir(dir: &Path) -> Result<Self, String> {
        Self::load(dir, None)
    }

    /// [`Self::from_bundle_dir`] for a pinned release: the sha256 of
    /// `manifest.json` must be `manifest_sha256`.
    pub fn from_pinned_bundle_dir(dir: &Path, manifest_sha256: &str) -> Result<Self, String> {
        Self::load(dir, Some(manifest_sha256))
    }

    fn load(dir: &Path, manifest_sha256: Option<&str>) -> Result<Self, String> {
        let bundle = bundle::load(dir, manifest_sha256)?;
        Ok(Self::with_policies(
            bundle.model,
            ShellPolicies::from_levels(&bundle.levels)?,
        ))
    }

    /// Apply user policies and allowlist from the runtime configuration,
    /// replacing earlier ones. A refused configuration leaves the pipeline
    /// unchanged.
    pub fn configure(&self, config: &ShellPolicyConfig) -> Result<(), String> {
        let configured = self.current_policies().configure(config)?;
        *self.policies.write().expect("shell policies lock poisoned") = Arc::new(configured);
        Ok(())
    }

    fn current_policies(&self) -> Arc<ShellPolicies> {
        Arc::clone(&self.policies.read().expect("shell policies lock poisoned"))
    }

    /// Loaded model.
    pub fn model(&self) -> &ShellRiskModel {
        &self.model
    }

    /// `patronus.verdict/1` of `text`. `context` and `prior_facts` (facts of
    /// earlier commands of the same session, kept by the caller) reach the
    /// policies through the facts; the model sees the text only.
    pub fn verdict(
        &self,
        text: &str,
        context: Option<&ShellContext>,
        prior_facts: &[Facts],
    ) -> Result<ShellVerdict, String> {
        let facts = extract(text, context, prior_facts);
        let context_free = context.is_none_or(ShellContext::is_unset) && prior_facts.is_empty();
        let context_facts;
        let kf1_facts = if context_free {
            &facts
        } else {
            context_facts = extract(text, None, &[]);
            &context_facts
        };
        let (model_score, top_features) = self
            .model
            .score(text, |emit| visit_kf1(text, kf1_facts, emit));
        let (policies, allowlisted) = self.current_policies().evaluate(&facts, text)?;
        let cuts = self.model.cuts();
        let score = match policies.iter().map(|p| p.decision).max() {
            Some(Decision::Block) => model_score.max(cuts.1 + 2.0),
            Some(Decision::Ask) => model_score.max((cuts.0 + cuts.1) / 2.0),
            _ => model_score,
        };
        Ok(ShellVerdict {
            decision: decide(score, cuts),
            score,
            ask_cut: cuts.0,
            block_cut: cuts.1,
            model_id: self.model.name().to_string(),
            model_score,
            model_decision: decide(model_score, cuts),
            top_features,
            policies,
            allowlisted,
            facts,
        })
    }

    /// Score one command without context.
    pub fn score(&self, text: &str) -> Result<ShellRiskScore, String> {
        self.verdict(text, None, &[]).map(|verdict| ShellRiskScore {
            decision_score: verdict.model_score,
            bundle_score: verdict.score,
            threshold: verdict.ask_cut,
            decision: verdict.decision,
            flagged: verdict.decision != Decision::Allow,
        })
    }
}

impl NativeDetector for ShellRiskPipeline {
    /// Scan one command. `ask` and `block` both flag it; the host maps them
    /// (the Patronus runtime asks for confirmation and never blocks on its own).
    fn detect_prepared(&self, prepared: &NativeText<'_>) -> NativeDetection {
        let text = prepared.text();
        let verdict = match self.verdict(text, None, &[]) {
            Ok(verdict) => verdict,
            // Policies are schema-validated at load, so evaluation does not fail;
            // if it does, fail closed and say why.
            Err(error) => {
                return NativeDetection {
                    result: EvaluationResult {
                        class_name: SHELL_RISK_CLASS.to_string(),
                        confidence: 0.5,
                        level: "L1".to_string(),
                    },
                    evidence_spans: Vec::new(),
                    details: HashMap::from([("error".to_string(), json!(error))]),
                }
            }
        };
        let flagged = verdict.decision != Decision::Allow;
        let evidence_spans = if flagged {
            self.model.evidence(text)
        } else {
            Vec::new()
        };
        let details = HashMap::from([
            ("model".to_string(), json!(verdict.model_id)),
            ("decision".to_string(), json!(verdict.decision.as_str())),
            ("decision_score".to_string(), json!(verdict.model_score)),
            ("bundle_score".to_string(), json!(verdict.score)),
            ("threshold".to_string(), json!(verdict.ask_cut)),
            ("threshold_policy".to_string(), json!(ASK_THRESHOLD)),
            ("verdict".to_string(), verdict.to_json(true)),
        ]);
        NativeDetection {
            result: EvaluationResult {
                class_name: if flagged {
                    SHELL_RISK_CLASS
                } else {
                    SAFE_CLASS
                }
                .to_string(),
                // Distance from the ask cut, squashed to 0.5..1. The logit is
                // not a calibrated probability.
                confidence: 1.0 / (1.0 + (-(verdict.score - verdict.ask_cut).abs()).exp()),
                level: "L1".to_string(),
            },
            evidence_spans,
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A K26-shaped model: `char_wb` scores `rm -rf`, the `kf1` feature
    /// `CMD=curl` is the only token feature.
    fn tiny_model_json() -> Value {
        json!({
            "format_version": 2,
            "name": "tiny",
            "blocks": [
                {
                    "kind": "char_wb",
                    "vectorizer": {
                        "analyzer": "char_wb", "ngram_range": [3, 5],
                        "lowercase": true, "sublinear_tf": true
                    },
                    "feature_dtype": "float32",
                    "idf_dtype": "float32",
                    "vocabulary": {" rm": 0, "rm ": 1, " rm ": 2, "-rf": 3, " ls ": 4, " ab ": 5},
                    "idf": [1.0, 1.0, 1.0, 2.0, 1.0, 1.0]
                },
                {
                    "kind": "tokens",
                    "analyzer_func": "kf1",
                    "vectorizer": {"sublinear_tf": true, "min_df": 2},
                    "feature_dtype": "float32",
                    "idf_dtype": "float32",
                    "vocabulary": {"CMD=curl": 0},
                    "idf": [1.0]
                }
            ],
            "weights": [1.0, 1.0, 1.0, 2.0, -3.0, 0.5, 4.0],
            "intercept": -1.0,
            "thresholds": {"external_commands_1pct_fpr": 0.0, "block_0_1pct_fpr": 2.5},
            "default_threshold_policy": "external_commands_1pct_fpr",
            "decision_rule": "score > threshold"
        })
    }

    fn tiny_model() -> ShellRiskModel {
        ShellRiskModel::from_json_slice(tiny_model_json().to_string().as_bytes()).unwrap()
    }

    fn model_score(model: &ShellRiskModel, text: &str) -> f64 {
        let facts = extract(text, None, &[]);
        model.score(text, |emit| visit_kf1(text, &facts, emit)).0
    }

    #[test]
    fn scores_follow_python_whitespace_and_sublinear_tf_idf() {
        let model = tiny_model();
        assert_eq!(model_score(&model, ""), -1.0);
        assert_eq!(
            model_score(&model, "rm\u{1c}-rf"),
            model_score(&model, "rm -rf")
        );
        // " ls " occurs twice: tf = 1 + ln 2; it is the only vocabulary term.
        assert!((model_score(&model, "ls ls") - (-1.0 - 3.0)).abs() < 1e-6);
        // CMD=curl is the only token feature: weight 4, normalized value 1.
        assert!((model_score(&model, "curl x") - 3.0).abs() < 1e-6);
    }

    #[test]
    fn rejects_inconsistent_models() {
        let parse = |model: &Value| ShellRiskModel::from_json_slice(model.to_string().as_bytes());
        assert!(parse(&tiny_model_json()).is_ok());
        for broken in [
            ("/format_version", json!(1)),
            ("/blocks/0/vectorizer/analyzer", json!("char")),
            ("/blocks/0/vocabulary/ ab ", json!(6)),
            ("/blocks/1/analyzer_func", json!("features")),
            ("/blocks/1/kind", json!("shell_tokens")),
            ("/thresholds", json!({"external_commands_1pct_fpr": 0.0})),
            ("/weights", json!([1.0])),
        ] {
            let mut model = tiny_model_json();
            *model.pointer_mut(broken.0).unwrap() = broken.1.clone();
            assert!(parse(&model).is_err(), "{} = {}", broken.0, broken.1);
        }
    }

    #[test]
    fn top_features_break_ties_by_name() {
        let mut model = tiny_model_json();
        model["blocks"][1]["vocabulary"] = json!({"CMD=curl": 0, "curl": 1});
        model["blocks"][1]["idf"] = json!([1.0, 1.0]);
        model["weights"] = json!([1.0, 1.0, 1.0, 2.0, -3.0, 0.5, 2.0, 2.0]);
        let model = ShellRiskModel::from_json_slice(model.to_string().as_bytes()).unwrap();
        let top = model
            .score("curl", |emit| {
                ["curl", "CMD=curl"].iter().for_each(|t| emit(t))
            })
            .1;
        let names: Vec<&str> = top.iter().map(|f| f.feature.as_str()).collect();
        assert_eq!(names, ["tok:CMD=curl", "tok:curl"]);
    }

    #[test]
    fn verdict_combines_model_and_policy_floor() {
        let pipeline = ShellRiskPipeline::new(tiny_model());
        let verdict = pipeline.verdict("ls", None, &[]).unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
        let verdict = pipeline.verdict("curl x", None, &[]).unwrap();
        assert_eq!(
            (verdict.model_decision, verdict.decision),
            (Decision::Block, Decision::Block)
        );
        assert_eq!(verdict.top_features[0].feature, "tok:CMD=curl");

        let config = ShellPolicyConfig {
            user_policies: vec![r#"@id("user.no_ls") @decision("ask")
                forbid(principal, action == Action::"segment", resource)
                when { context.program == "ls" };"#
                .to_string()],
            ..ShellPolicyConfig::default()
        };
        pipeline.configure(&config).unwrap();
        let verdict = pipeline.verdict("ls", None, &[]).unwrap();
        assert_eq!(verdict.decision, Decision::Ask);
        assert_eq!(verdict.score, 1.25);
        assert_eq!(verdict.policies[0].id, "user.no_ls");
        let json = verdict.to_json_string(false);
        assert!(
            json.starts_with(
                r#"{"allowlisted":[],"cuts":{"ask":0.0,"block":2.5},"decision":"ask""#
            ),
            "{json}"
        );
    }

    #[test]
    fn evidence_spans_and_detection_details() {
        let pipeline = ShellRiskPipeline::new(tiny_model());
        // The token block alone flags `curl`: the trimmed command is the span.
        let spans = pipeline.model().evidence("  curl  ");
        assert_eq!(
            (spans[0].start_byte, spans[0].end_byte, spans[0].score),
            (2, 6, 1.0)
        );

        let detection = pipeline.detect("RM -RF");
        assert_eq!(detection.result.class_name, SHELL_RISK_CLASS);
        assert!(detection.result.confidence > 0.5);
        assert_eq!(detection.details["decision"], "ask");
        assert_eq!(detection.details["verdict"]["v"], VERDICT_VERSION);
        assert_eq!(
            detection.details["verdict"]["facts"]["segments"][0]["program"],
            "rm"
        );
        let spans: Vec<_> = detection
            .evidence_spans
            .iter()
            .map(|span| (span.text.as_str(), span.start_byte, span.end_byte))
            .collect();
        assert_eq!(spans, [("RM", 0, 2), ("-RF", 3, 6)]);
        assert_eq!(pipeline.detect("ls").result.class_name, SAFE_CLASS);
    }
}
