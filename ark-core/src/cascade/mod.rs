//! The layer cascade: analysis modules (rows) run through L1 -> L2 -> L3
//! (columns). L1 answers Detected, Clear or Escalate per module; a later layer
//! runs only on what the earlier configured layers escalated, and only when
//! the configuration allows its level. If no later layer is configured, L1's
//! answer is final: not detected is Clear.
//!
//! The module also holds the model-agnostic execution schema shared with Ark
//! (levels, gates, the L3 scheduling policy), chunk aggregation, the final
//! L2/L3 arbiter and the extension traits for host models.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detectors::text::{DataRef, L1ModelConfig, L1TextModel};
use crate::{LayerResult, NativeResult, ScanControl, ScanError, SecurityCategory};

mod arbiter;
mod chunks;
mod gates;
mod seams;

pub use arbiter::{
    accepts_class, arbitrate_l2, arbitrate_l3_l2, sync_final_layers, threshold_l2_result,
    with_arbitration, ArbitrationTrace, LayerDecision, LayeredResult, ThresholdTable, UnionPolicy,
};
pub use chunks::{
    aggregate_chunk_outputs, aggregate_decision_index, is_safe_label, ChunkDecision,
    HeadDecisionState, LongTextAggregate,
};
pub use gates::{
    pipeline_allowed, ConditionalPipelineGate, EffectiveL3PipelinePolicy, GateExpression,
    GateResult, L3AggregationStrategy, L3ClusteringStrategy, L3EarlyExitMode, L3PipelineEarlyExit,
    L3PipelinePolicy, L3ProgressMode, L3SchedulerPolicy, LayerExecution, MetadataCondition,
    ResultCondition, ScanGateMatrix, SecurityLevel,
};
pub use seams::{
    escalates, EscalationSignal, ExternalL1Detector, ExternalL1Input, L3Executor, LayerModel,
    LayerOutput,
};

/// Who decided a module's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The module's anchor heuristic and rule scorer.
    Heuristic,
    /// The module's L1 text model.
    L1Model,
    /// The module's policies over its L1 results.
    Policy,
    L2,
    L3,
}

/// A stage's answer for one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    Detected,
    Clear,
    /// Undecided: the next configured layer answers.
    Escalate,
}

impl StageOutcome {
    /// The one cut rule of every L1 stage, heuristic and L1 model alike: a
    /// score above the stage's detect cut (`detected`) is Detected, a score at
    /// or below its clear cut is Clear, anything else escalates. A `None`
    /// clear cut switches clearing off.
    pub fn from_cuts(detected: bool, score: f64, clear_threshold: Option<f64>) -> Self {
        if detected {
            Self::Detected
        } else if clear_threshold.is_some_and(|clear| score <= clear) {
            Self::Clear
        } else {
            Self::Escalate
        }
    }
}

/// One analysis module's cascade settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModuleConfig {
    /// The heuristic's detect cut on its decision score (`0.0..=1.0`, the
    /// probability of its rule scorer): a score above it is Detected. This is
    /// the one per-class operating point of the heuristic. `None` (the
    /// default) keeps the scorer's shipped acceptance (score at or above its
    /// own cut, as reported in the native results), so results stay identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detect_threshold: Option<f64>,
    /// The heuristic's clear cut on the same scale: an undetected score at or
    /// below it is Clear without a later stage. `None` (the default) switches
    /// it off, so every undetected input escalates.
    pub clear_threshold: Option<f64>,
    /// The module's optional L1 model (cuts on its logit scale), run on what
    /// the heuristic escalates; loaded once by [`crate::Scanner::new`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_model: Option<L1ModelConfig>,
}

/// Which layers may run after L1, and per module its L1 clear cut and
/// optional L1 model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CascadeConfig {
    /// Deepest layer that may run. Default: `L3`.
    pub max_level: SecurityLevel,
    /// Conditional L2/L3 gates, evaluated over the earlier layers' results.
    pub conditional: Vec<ConditionalPipelineGate>,
    /// Per-module settings keyed by category.
    pub modules: HashMap<SecurityCategory, ModuleConfig>,
}

impl Default for CascadeConfig {
    fn default() -> Self {
        Self {
            max_level: SecurityLevel::L3,
            conditional: Vec::new(),
            modules: HashMap::new(),
        }
    }
}

impl CascadeConfig {
    /// The configured L1 models by module.
    pub fn l1_models(&self) -> impl Iterator<Item = (SecurityCategory, &L1ModelConfig)> {
        self.modules
            .iter()
            .filter_map(|(module, config)| Some((*module, config.l1_model.as_ref()?)))
    }

    /// Refuse invalid conditional gates and heuristic cuts outside `0..=1`
    /// or with the clear cut above the detect cut.
    pub fn validate(&self) -> Result<(), String> {
        for gate in &self.conditional {
            gate.validate()?;
        }
        for (module, config) in &self.modules {
            for (name, value) in [
                ("detect_threshold", config.detect_threshold),
                ("clear_threshold", config.clear_threshold),
            ] {
                if value.is_some_and(|value| !(0.0..=1.0).contains(&value)) {
                    return Err(format!(
                        "cascade.modules.{}.{name} must be between 0.0 and 1.0",
                        module.as_str()
                    ));
                }
            }
            if let (Some(detect), Some(clear)) = (config.detect_threshold, config.clear_threshold) {
                if clear > detect {
                    return Err(format!(
                        "cascade.modules.{}.clear_threshold must not exceed detect_threshold",
                        module.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The final answer of one module.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleDecision {
    pub module: SecurityCategory,
    /// `detected` or `clear`.
    pub outcome: StageOutcome,
    pub decided_by: Stage,
    /// Score of the deciding stage, on that stage's scale: a probability for
    /// the heuristic, L2 and L3, the decision logit for the L1 model.
    pub score: f64,
    /// The layers that ran after the heuristic (L1 model, L2, L3), in order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<LayerResult>,
}

/// L1's answer for one module, computed once per scan: the heuristic's from
/// its native results, refined by the module's L1 model when the heuristic
/// escalates.
#[derive(Debug, Clone)]
pub struct L1Stage {
    pub outcome: StageOutcome,
    pub score: f64,
    /// The L1 stage that answered: [`Stage::Heuristic`] or [`Stage::L1Model`].
    pub decided_by: Stage,
    /// Set when the outcome is [`StageOutcome::Escalate`].
    pub escalation: Option<EscalationSignal>,
    layers: Vec<LayerResult>,
    gate_results: Vec<GateResult>,
}

/// Runs the configured layers per module with early exit.
#[derive(Debug, Clone, Default)]
pub struct Cascade {
    config: CascadeConfig,
}

impl Cascade {
    pub fn new(config: CascadeConfig) -> Result<Self, ScanError> {
        config.validate().map_err(ScanError::Config)?;
        Ok(Self { config })
    }

    /// The heuristic's outcome for `module` from its native results, by
    /// [`StageOutcome::from_cuts`] on its decision score: the best score of
    /// its results, also below the scorer's own cut (the candidate score of a
    /// decision envelope, else the raw `score` of the native layer details,
    /// else the confidence of a result with evidence). Detected: above the module's
    /// `detect_threshold`, or, unset, a result its scorer accepted (or that
    /// has evidence without a decision envelope).
    pub fn l1_stage<'a>(
        &self,
        module: SecurityCategory,
        results: impl IntoIterator<Item = &'a NativeResult>,
    ) -> L1Stage {
        let mut accepted = false;
        let mut best: Option<(&str, f64)> = None;
        let mut gate_results = Vec::new();
        for result in results {
            let (result_accepted, score) = heuristic_score(result);
            accepted |= result_accepted;
            if best.is_none_or(|(_, top)| score > top) {
                best = Some((&result.model, score));
            }
            gate_results.push(GateResult {
                pipeline: result.category.clone(),
                class_name: result.class_name.clone(),
                confidence: result.confidence,
                level: SecurityLevel::L1,
            });
        }
        let (source, score) = best.unwrap_or((module.as_str(), 0.0));
        let config = self.config.modules.get(&module);
        let detected = match config.and_then(|config| config.detect_threshold) {
            Some(detect) => score > detect,
            None => accepted,
        };
        let clear_threshold = config.and_then(|config| config.clear_threshold);
        let outcome = StageOutcome::from_cuts(detected, score, clear_threshold);
        L1Stage {
            outcome,
            score,
            decided_by: Stage::Heuristic,
            escalation: (outcome == StageOutcome::Escalate).then(|| EscalationSignal {
                score,
                threshold: clear_threshold.unwrap_or(0.0),
                spans: Vec::new(),
                source: source.to_string(),
            }),
            layers: Vec::new(),
            gate_results,
        }
    }

    /// Run `model`, the module's L1 model, on an input the heuristic
    /// escalated; its Detected or Clear replaces the escalation, its
    /// Escalate passes on. A decided stage or no model leaves `stage` as is.
    /// `data` are the PII/DLP findings of the scan, a model input.
    pub fn l1_model_stage(
        &self,
        mut stage: L1Stage,
        model: Option<&L1TextModel>,
        text: &str,
        data: &[DataRef<'_>],
    ) -> L1Stage {
        let Some(model) = model.filter(|_| stage.outcome == StageOutcome::Escalate) else {
            return stage;
        };
        let answer = model.evaluate(text, &[], data);
        let layer = answer.layer_result();
        stage.gate_results.push(GateResult {
            pipeline: model.category().as_str().to_string(),
            class_name: layer.class_name.clone(),
            confidence: layer.confidence,
            level: SecurityLevel::L1,
        });
        stage.layers.push(layer);
        stage.outcome = answer.outcome;
        stage.score = answer.score;
        stage.decided_by = Stage::L1Model;
        stage.escalation = (answer.outcome == StageOutcome::Escalate).then(|| EscalationSignal {
            score: answer.score,
            threshold: answer.thresholds.detect_threshold,
            spans: Vec::new(),
            source: answer.model,
        });
        stage
    }

    /// Final decision of `module`: L1's Detected or Clear stands; an
    /// escalation runs the first allowed L2 model of the module, then the L3
    /// executor, each only while the previous layer escalates. An escalation
    /// no configured layer answers ends Clear, decided by the last stage that ran.
    pub fn decide(
        &self,
        module: SecurityCategory,
        text: &str,
        l1: L1Stage,
        l2: &mut [&mut dyn LayerModel],
        mut l3: Option<&mut dyn L3Executor>,
        control: &ScanControl,
    ) -> Result<ModuleDecision, ScanError> {
        let L1Stage {
            mut outcome,
            mut score,
            mut decided_by,
            mut escalation,
            mut layers,
            gate_results: mut results,
        } = l1;
        for level in [SecurityLevel::L2, SecurityLevel::L3] {
            let Some(signal) = escalation.take() else {
                break;
            };
            if level > self.config.max_level {
                break;
            }
            let allowed = pipeline_allowed(
                &self.config.conditional,
                level,
                module.as_str(),
                &Value::Null,
                &results,
            );
            let output = match level {
                _ if !allowed => None,
                SecurityLevel::L2 => l2
                    .iter_mut()
                    .find(|model| model.layer() == SecurityLevel::L2 && model.module() == module)
                    .map(|model| model.infer(text, control))
                    .transpose()?,
                _ => match l3.as_mut() {
                    Some(executor) => executor.execute_l3(module, text, &signal, control)?,
                    None => None,
                },
            };
            let Some(output) = output else {
                // Gated off or no model at this level: the escalation passes on.
                escalation = Some(signal);
                continue;
            };
            decided_by = if level == SecurityLevel::L2 {
                Stage::L2
            } else {
                Stage::L3
            };
            score = output.result.confidence;
            results.push(GateResult {
                pipeline: module.as_str().to_string(),
                class_name: output.result.class_name.clone(),
                confidence: score,
                level,
            });
            escalation = output
                .escalation
                .filter(|signal| !output.result.matched && signal.escalates());
            outcome = if output.result.matched {
                StageOutcome::Detected
            } else if escalation.is_some() {
                StageOutcome::Escalate
            } else {
                StageOutcome::Clear
            };
            layers.push(output.result);
        }
        if outcome == StageOutcome::Escalate {
            outcome = StageOutcome::Clear;
        }
        Ok(ModuleDecision {
            module,
            outcome,
            decided_by,
            score,
            layers,
        })
    }
}

/// Whether the heuristic accepted `result` at its scorer's own cut, and its
/// decision score (`0.0..=1.0`), also below that cut: the candidate score of
/// a decision envelope, else the scorer's raw `score` in the native layer
/// details (Threat rules), else the confidence of a result with evidence;
/// a result without any of them scores 0.
fn heuristic_score(result: &NativeResult) -> (bool, f64) {
    if let Some(decision) = &result.decision {
        return (
            decision.recommendation.accepted,
            decision
                .decision_candidate
                .as_ref()
                .map_or(0.0, |candidate| candidate.confidence),
        );
    }
    let accepted = !result.evidence_spans.is_empty();
    let raw = result
        .layers
        .iter()
        .find_map(|layer| layer.details.get("score")?.as_f64());
    let score = match raw {
        Some(score) => score,
        None if accepted => result.confidence,
        None => 0.0,
    };
    (accepted, score)
}

#[cfg(test)]
mod tests;
