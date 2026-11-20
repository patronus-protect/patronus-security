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

use crate::detectors::text::{Finding, L1ModelConfig, L1TextModel};
use crate::native::ScoreMode;
use crate::{LayerResult, ScanControl, ScanError, SecurityCategory};

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

impl From<SecurityLevel> for Stage {
    /// The stage that answers at `level`; L1's answer is the heuristic's.
    fn from(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::L1 => Self::Heuristic,
            SecurityLevel::L2 => Self::L2,
            SecurityLevel::L3 => Self::L3,
        }
    }
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

/// When a score counts against a cut: the comparison a stage's scorer
/// declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutRule {
    /// `score >= cut`: the heuristic's rule scorers (and Core's native
    /// acceptance).
    AtOrAbove,
    /// `score > cut`: the L1 models, whose files declare
    /// `decision_rule: "score > threshold"`.
    Above,
}

impl CutRule {
    /// Whether `score` counts against `cut`.
    pub fn counts(self, score: f64, cut: f64) -> bool {
        match self {
            Self::AtOrAbove => score >= cut,
            Self::Above => score > cut,
        }
    }
}

impl StageOutcome {
    /// The one cut rule of every L1 stage, heuristic and L1 model alike, under
    /// the stage's [`CutRule`]: a score that counts against the detect cut
    /// (`detected`) is Detected, a score that does not count against the
    /// clear cut is Clear, anything else escalates. A `None` clear cut
    /// switches clearing off.
    pub fn from_cuts(
        detected: bool,
        score: f64,
        clear_threshold: Option<f64>,
        rule: CutRule,
    ) -> Self {
        if detected {
            Self::Detected
        } else if clear_threshold.is_some_and(|clear| !rule.counts(score, clear)) {
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
    /// The heuristic's detect cut on its rule scorer's probability
    /// (`0.0..=1.0`): the injection scorer's candidate score for `injection`
    /// and the rule classes it feeds (rejected candidates included), for the
    /// Threat classes the higher of the document scorer's own probability
    /// (recomputed from `details.matched_rules`, also below its cut) and the
    /// points score of an accepted points rule that kept its evidence, the
    /// confidence of a result with evidence for PII and DLP. A score at or above it is
    /// Detected when the module's score mode admits it. A Threat points rule
    /// accepted on its own (with evidence left after the mode floor) is
    /// Detected regardless. `None` (the default) keeps the scorers' shipped
    /// acceptance as reported in the native results, so results stay
    /// identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detect_threshold: Option<f64>,
    /// The heuristic's clear cut on the same score: an undetected score below
    /// it is Clear without a later stage. `None` (the default) switches it
    /// off, so every undetected input escalates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_threshold: Option<f64>,
    /// The module's optional L1 model (cuts on its logit scale), run on what
    /// the heuristic escalates; loaded once by [`crate::Scanner::new`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_model: Option<L1ModelConfig>,
}

/// The opt-in cascade: which layers run, with early exit between them, and
/// per module its L1 cuts and optional L1 model. Its level keys are the
/// gate keys of [`ScanGateMatrix`] with the same meaning: `max_level` is the
/// ceiling and `l1`, `l2`, `l3` switch a level off (unset: on), so any one
/// layer can run alone (for example `l1: false` leaves Wolf, the injection
/// L3, to answer every input). Per module, the L1 model runs when
/// `l1_model` is configured and the heuristic runs unless its native
/// producers are switched off with the existing `models` gates (for
/// example `native:injection_l1`, `native:threat_l1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CascadeConfig {
    /// Deepest layer that may run. Default: `L3`.
    pub max_level: SecurityLevel,
    /// `false` switches L1 (heuristics and L1 models) off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1: Option<bool>,
    /// `false` switches L2 off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l2: Option<bool>,
    /// `false` switches L3 off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l3: Option<bool>,
    /// Conditional L2/L3 gates, evaluated over the L1 results of every
    /// scanned module and the module's own later results. Core has no
    /// request metadata, so `metadata` conditions are refused.
    pub conditional: Vec<ConditionalPipelineGate>,
    /// Per-module settings keyed by category.
    pub modules: HashMap<SecurityCategory, ModuleConfig>,
}

impl Default for CascadeConfig {
    fn default() -> Self {
        Self {
            max_level: SecurityLevel::L3,
            l1: None,
            l2: None,
            l3: None,
            conditional: Vec::new(),
            modules: HashMap::new(),
        }
    }
}

impl CascadeConfig {
    /// Whether `level` may run: at most `max_level` and not switched off,
    /// the rule of [`ScanGateMatrix`] and [`LayerExecution`].
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        level <= self.max_level && gates::level_switch([self.l1, self.l2, self.l3], level)
    }

    /// The cascade as Ark's gate key `cascade`: Ark takes the levels and
    /// conditional gates from its own gate keys (`max_level`, `l1`, `l2`,
    /// `l3`, `conditional`) and runs no L1 models yet, so only `modules`
    /// with their L1 cuts may be set.
    pub fn validate_for_gates(&self) -> Result<(), String> {
        let levels = Self {
            modules: HashMap::new(),
            ..self.clone()
        };
        if levels != Self::default() {
            return Err(
                "cascade: set max_level, l1, l2, l3 and conditional as gate keys; \
                the cascade key takes only modules"
                    .into(),
            );
        }
        if self.l1_models().next().is_some() {
            return Err("cascade.modules: Ark runs no L1 models (l1_model)".into());
        }
        self.validate()
    }

    /// The configured L1 models by module.
    pub fn l1_models(&self) -> impl Iterator<Item = (SecurityCategory, &L1ModelConfig)> {
        self.modules
            .iter()
            .filter_map(|(module, config)| Some((*module, config.l1_model.as_ref()?)))
    }

    /// Refuse invalid conditional gates, gates over request metadata (Core
    /// scans have none) and heuristic cuts outside `0..=1` or with the clear
    /// cut above the detect cut.
    pub fn validate(&self) -> Result<(), String> {
        for gate in &self.conditional {
            gate.validate()?;
            if gate.when.reads_metadata() {
                return Err(
                    "cascade.conditional: Core scans carry no request metadata; \
                    use result conditions"
                        .into(),
                );
            }
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
    /// Whether an L1 stage ran (not with L1 switched off).
    ran: bool,
}

impl L1Stage {
    /// The module's final decision when L1 answered Detected or Clear;
    /// `None` when it escalates to the next configured layer.
    pub fn decision(&self, module: SecurityCategory) -> Option<ModuleDecision> {
        (self.outcome != StageOutcome::Escalate).then_some(ModuleDecision {
            module,
            outcome: self.outcome,
            decided_by: self.decided_by,
            score: self.score,
            layers: self.layers.clone(),
        })
    }
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

    /// Whether `level` may run in this cascade.
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        self.config.allows_level(level)
    }

    /// L1's answer for `module` when its heuristic did not run (L1 switched
    /// off, or its rules switched off or failed): the input escalates to the
    /// next stage that runs and is never cleared for lack of evidence; if no
    /// stage runs, [`Self::decide`] reports no decision for the module.
    pub fn l1_off(&self, module: SecurityCategory) -> L1Stage {
        L1Stage {
            outcome: StageOutcome::Escalate,
            score: 0.0,
            decided_by: Stage::Heuristic,
            escalation: Some(EscalationSignal::above(0.0, None, module.as_str())),
            layers: Vec::new(),
            ran: false,
        }
    }

    /// Whether conditional gates decide which later layer may run; only then
    /// does [`Self::decide`] read the L1 gate results.
    pub fn has_conditional_gates(&self) -> bool {
        !self.config.conditional.is_empty()
    }

    /// The heuristic's outcome for `module` from its L1 results (see
    /// [`ModuleConfig::detect_threshold`] for the score per module):
    /// Detected for a rule hit that detects on its own, a score at or above
    /// the module's `detect_threshold` that `mode` admits, or, without a
    /// `detect_threshold`, a result its scorer accepted (or that has evidence
    /// without a decision envelope); else Clear below the `clear_threshold`;
    /// else Escalate.
    pub fn l1_stage<'a, R: LayeredResult + 'a>(
        &self,
        module: SecurityCategory,
        mode: ScoreMode,
        results: impl IntoIterator<Item = &'a R>,
    ) -> L1Stage {
        let (mut accepted, mut rule_hit) = (false, false);
        let mut best: Option<(&str, f64)> = None;
        for result in results {
            let score = heuristic_score(result);
            accepted |= score.accepted;
            rule_hit |= score.rule_hit;
            if best.is_none_or(|(_, top)| score.score > top) {
                best = Some((result.model(), score.score));
            }
        }
        let (source, score) = best.unwrap_or((module.as_str(), 0.0));
        let config = self.config.modules.get(&module);
        let rule = CutRule::AtOrAbove;
        let detected = rule_hit
            || match config.and_then(|config| config.detect_threshold) {
                Some(detect) => rule.counts(score, detect) && mode.admits(score),
                None => accepted,
            };
        let clear_threshold = config.and_then(|config| config.clear_threshold);
        let outcome = StageOutcome::from_cuts(detected, score, clear_threshold, rule);
        L1Stage {
            outcome,
            score,
            decided_by: Stage::Heuristic,
            escalation: (outcome == StageOutcome::Escalate)
                .then(|| EscalationSignal::above(score, clear_threshold, source)),
            layers: Vec::new(),
            ran: true,
        }
    }

    /// L1's answer for `module`, shared by the Core scanner and Ark's
    /// gateway: the heuristic ([`Self::l1_stage`]) over the module's results
    /// in `scan` when one of its producers ran (`heuristic`), else
    /// [`Self::l1_off`]; then the module's L1 `model` on an escalation
    /// ([`Self::l1_model_stage`]). `scan` holds every native L1 result of the
    /// scan: the model reads their rule findings, as in training.
    pub fn l1_answer<'a>(
        &self,
        module: SecurityCategory,
        mode: ScoreMode,
        heuristic: bool,
        scan: impl Iterator<Item = &'a crate::NativeResult> + Clone,
        model: Option<&L1TextModel>,
        text: &str,
    ) -> L1Stage {
        let stage = if heuristic {
            self.l1_stage(
                module,
                mode,
                scan.clone()
                    .filter(|result| result.category == module.as_str()),
            )
        } else {
            self.l1_off(module)
        };
        let findings = if model.is_some() && stage.outcome == StageOutcome::Escalate {
            scan.flat_map(|result| &result.layers)
                .flat_map(|layer| crate::detectors::threat::facts_findings(&layer.details))
                .collect()
        } else {
            Vec::new()
        };
        self.l1_model_stage(stage, model, text, &findings)
    }

    /// Run `model`, the module's L1 model, on an input the heuristic
    /// escalated; its Detected or Clear replaces the escalation, its
    /// Escalate passes on. A decided stage or no model leaves `stage` as is.
    /// `findings` are the scan's rule findings as the model is trained on
    /// them (the accepted Threat points findings, see
    /// [`crate::detectors::threat::facts_findings`]).
    pub fn l1_model_stage(
        &self,
        mut stage: L1Stage,
        model: Option<&L1TextModel>,
        text: &str,
        findings: &[Finding<'_>],
    ) -> L1Stage {
        let Some(model) = model.filter(|_| stage.outcome == StageOutcome::Escalate) else {
            return stage;
        };
        let answer = model.evaluate(text, findings, &[]);
        stage.layers.push(answer.layer_result());
        stage.outcome = answer.outcome;
        stage.score = answer.score;
        stage.decided_by = Stage::L1Model;
        stage.ran = true;
        stage.escalation = (answer.outcome == StageOutcome::Escalate).then(|| {
            EscalationSignal::above(
                answer.score,
                answer.thresholds.clear_threshold,
                &answer.model,
            )
        });
        stage
    }

    /// Final decision of `module`: L1's Detected or Clear stands; an
    /// escalation runs the first allowed L2 model of the module, then the L3
    /// executor, each only while the previous layer escalates. An escalation
    /// no configured layer answers ends Clear, decided by the last stage that
    /// ran. `None` when no stage ran at all (L1 switched off and no later
    /// layer answered): the module has no decision.
    /// `l1_results` are the L1 gate results of every scanned module, read
    /// only when [`Self::has_conditional_gates`].
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        module: SecurityCategory,
        text: &str,
        l1: L1Stage,
        l1_results: &[GateResult],
        l2: &mut [&mut dyn LayerModel],
        mut l3: Option<&mut dyn L3Executor>,
        control: &ScanControl,
    ) -> Result<Option<ModuleDecision>, ScanError> {
        if let Some(decision) = l1.decision(module) {
            return Ok(Some(decision));
        }
        let L1Stage {
            mut outcome,
            mut score,
            mut decided_by,
            mut escalation,
            mut layers,
            mut ran,
        } = l1;
        let gated = self.has_conditional_gates();
        let mut results = Vec::new();
        if gated {
            results.extend_from_slice(l1_results);
            results.extend(layers.iter().map(|layer| GateResult {
                pipeline: module.as_str().to_string(),
                class_name: layer.class_name.clone(),
                confidence: layer.confidence,
                level: SecurityLevel::L1,
            }));
        }
        for level in [SecurityLevel::L2, SecurityLevel::L3] {
            let Some(signal) = escalation.take() else {
                break;
            };
            if !self.config.allows_level(level) {
                // Switched off: the escalation passes on.
                escalation = Some(signal);
                continue;
            }
            let allowed = !gated
                || pipeline_allowed(
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
            decided_by = Stage::from(level);
            ran = true;
            score = output.result.confidence;
            if gated {
                results.push(GateResult {
                    pipeline: module.as_str().to_string(),
                    class_name: output.result.class_name.clone(),
                    confidence: score,
                    level,
                });
            }
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
        Ok(ran.then_some(ModuleDecision {
            module,
            outcome,
            decided_by,
            score,
            layers,
        }))
    }
}

/// The gate result of one result for conditional gates (its category, class,
/// confidence and level); `None` for a result without a known level.
pub fn gate_result(result: &impl LayeredResult) -> Option<GateResult> {
    Some(GateResult {
        pipeline: result.category().to_string(),
        class_name: result.class_name().to_string(),
        confidence: result.confidence(),
        level: result.level().parse().ok()?,
    })
}

/// The gate results of L1 results, shared by every host: one per result
/// ([`gate_result`]) and one per injection L1 candidate the scorer rejected,
/// under the pipeline `native:injection_l1`, so a gate can ask for a rule
/// match below the acceptance cut.
pub fn l1_gate_results<'a, R: LayeredResult + 'a>(
    results: impl IntoIterator<Item = &'a R>,
) -> Vec<GateResult> {
    let mut gates = Vec::new();
    let mut rejected = Vec::new();
    for result in results {
        gates.extend(gate_result(result));
        if result.model() != crate::injection_l1::MODEL {
            continue;
        }
        let candidates = result.decision().into_iter().flat_map(|d| &d.candidates);
        rejected.extend(
            candidates
                .filter(|candidate| candidate.source == "l1" && !candidate.accepted)
                .map(|candidate| GateResult {
                    pipeline: crate::injection_l1::MODEL.to_string(),
                    class_name: candidate.class_name.clone(),
                    confidence: candidate.confidence,
                    level: SecurityLevel::L1,
                }),
        );
    }
    gates.extend(rejected);
    gates
}

/// What the heuristic reads from one L1 result.
struct HeuristicScore {
    /// Accepted at the scorer's own cut (with evidence left after the mode
    /// floor).
    accepted: bool,
    /// A rule hit that detects on its own: a Threat points rule accepted
    /// with evidence left after the mode floor.
    rule_hit: bool,
    /// The graded rule score (`0.0..=1.0`), also below the scorer's cut; a
    /// detection never scores 0.
    score: f64,
}

/// The heuristic's view of `result`: with a decision envelope its
/// acceptance and the score of its best candidate (accepted or not); else
/// (Threat rules) the document scorer's probability and accepted points
/// hits, read from the native layer details
/// ([`crate::detectors::threat::cascade_view`]); else evidence as acceptance
/// and the confidence of a result with evidence.
fn heuristic_score(result: &impl LayeredResult) -> HeuristicScore {
    if let Some(decision) = result.decision() {
        return HeuristicScore {
            accepted: decision.recommendation.accepted,
            rule_hit: false,
            score: decision
                .decision_candidate
                .as_ref()
                .map_or(0.0, |candidate| candidate.confidence),
        };
    }
    let evidence = result.has_evidence();
    let threat = result.layers().iter().find_map(|layer| {
        crate::detectors::threat::cascade_view(&layer.details, |start, end| {
            result.has_evidence_at(start, end)
        })
    });
    HeuristicScore {
        accepted: evidence,
        rule_hit: threat.is_some_and(|(_, points_accepted)| points_accepted),
        score: match threat {
            Some((score, _)) => score,
            None if evidence => result.confidence(),
            None => 0.0,
        },
    }
}

#[cfg(test)]
mod tests;
