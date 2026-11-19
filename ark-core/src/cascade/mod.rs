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

use crate::{NativeResult, ScanControl, ScanError, SecurityCategory};

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

/// Per-module L1 thresholds of the cascade.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModuleThresholds {
    /// L1 scores below it are Clear without a later layer; `None` (the
    /// default) switches it off, so every undetected input escalates.
    pub clear_threshold: Option<f64>,
}

/// Which layers may run after L1 and when L1 may clear on its own. The detect
/// threshold of each module is its own L1 acceptance threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CascadeConfig {
    /// Deepest layer that may run. Default: `L3`.
    pub max_level: SecurityLevel,
    /// Conditional L2/L3 gates, evaluated over the earlier layers' results.
    pub conditional: Vec<ConditionalPipelineGate>,
    /// Per-module thresholds keyed by category.
    pub modules: HashMap<SecurityCategory, ModuleThresholds>,
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
    /// Refuse invalid conditional gates and clear thresholds outside `0..=1`.
    pub fn validate(&self) -> Result<(), String> {
        for gate in &self.conditional {
            gate.validate()?;
        }
        for (module, thresholds) in &self.modules {
            if thresholds
                .clear_threshold
                .is_some_and(|value| !(0.0..=1.0).contains(&value))
            {
                return Err(format!(
                    "cascade.modules.{}.clear_threshold must be between 0.0 and 1.0",
                    module.as_str()
                ));
            }
        }
        Ok(())
    }
}

/// The final answer of one module.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModuleDecision {
    pub module: SecurityCategory,
    /// `detected` or `clear`.
    pub outcome: StageOutcome,
    pub decided_by: Stage,
    /// Score of the deciding stage.
    pub score: f64,
}

/// L1's answer for one module, computed once per scan from its native results.
#[derive(Debug, Clone)]
pub struct L1Stage {
    pub outcome: StageOutcome,
    pub score: f64,
    /// Set when the outcome is [`StageOutcome::Escalate`].
    pub escalation: Option<EscalationSignal>,
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

    /// L1's outcome for `module` from its native results: Detected when a
    /// result is accepted (or, without a decision envelope, has evidence);
    /// otherwise Escalate unless the score is below the clear threshold.
    pub fn l1_stage<'a>(
        &self,
        module: SecurityCategory,
        results: impl IntoIterator<Item = &'a NativeResult>,
    ) -> L1Stage {
        let mut detected = false;
        let mut best: Option<(&str, f64)> = None;
        let mut gate_results = Vec::new();
        for result in results {
            let (accepted, score) = match &result.decision {
                Some(decision) => (
                    decision.recommendation.accepted,
                    decision
                        .decision_candidate
                        .as_ref()
                        .map_or(0.0, |candidate| candidate.confidence),
                ),
                None if result.evidence_spans.is_empty() => (false, 0.0),
                None => (true, result.confidence),
            };
            detected |= accepted;
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
        if detected {
            return L1Stage {
                outcome: StageOutcome::Detected,
                score,
                escalation: None,
                gate_results,
            };
        }
        let signal = EscalationSignal {
            score,
            threshold: self
                .config
                .modules
                .get(&module)
                .and_then(|thresholds| thresholds.clear_threshold)
                .unwrap_or(0.0),
            spans: Vec::new(),
            source: source.to_string(),
        };
        let escalate = signal.escalates();
        L1Stage {
            outcome: if escalate {
                StageOutcome::Escalate
            } else {
                StageOutcome::Clear
            },
            score,
            escalation: escalate.then_some(signal),
            gate_results,
        }
    }

    /// Final decision of `module`: L1's Detected or Clear stands; an
    /// escalation runs the first allowed L2 model of the module, then the L3
    /// executor, each only while the previous layer escalates. An escalation
    /// no configured layer answers ends Clear.
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
            mut escalation,
            gate_results: mut results,
        } = l1;
        let mut decided_by = Stage::Heuristic;
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
        }
        if outcome == StageOutcome::Escalate {
            outcome = StageOutcome::Clear;
        }
        Ok(ModuleDecision {
            module,
            outcome,
            decided_by,
            score,
        })
    }
}

#[cfg(test)]
mod tests;
