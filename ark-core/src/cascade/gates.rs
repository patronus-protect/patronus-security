//! Layer gates: the maximum level, the per-level switches, conditional
//! pipeline gates and the L3 scheduling policy, plus their evaluation.
//!
//! The schema is model-agnostic. Hosts that run their own L2/L3 models keep
//! their model tables (priorities, timeouts, costs) on their side; empty maps
//! here mean "use the host default".
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::native::NativeGates;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Maximum scanner depth to run.
pub enum SecurityLevel {
    /// Native rule-based checks only.
    L1 = 1,
    /// Native checks plus L2 model-backed classifiers when assets are available.
    L2 = 2,
    /// Native, L2, and L3 model-backed classifiers when assets are available.
    L3 = 3,
}

impl SecurityLevel {
    /// Return the canonical uppercase level string.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityLevel::L1 => "L1",
            SecurityLevel::L2 => "L2",
            SecurityLevel::L3 => "L3",
        }
    }
}

/// Serializes the canonical [`SecurityLevel::as_str`] name.
impl Serialize for SecurityLevel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Deserializes every name [`str::parse`] accepts (`L1`, `l1`, `1`, ...).
impl<'de> Deserialize<'de> for SecurityLevel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for SecurityLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "1" | "l1" => Ok(SecurityLevel::L1),
            "2" | "l2" => Ok(SecurityLevel::L2),
            "3" | "l3" => Ok(SecurityLevel::L3),
            _ => Err(format!("Unknown security level: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(try_from = "GateConfig")]
/// Caller-controlled execution gates for one scanner execution profile.
///
/// Unspecified rules use the shared credentials/secrets-only DLP default;
/// other execution gates default to enabled. Diagnostic `explain` and the
/// scored PII and DLP modes are opt-in. The maximum level is still enforced by
/// [`LayerExecution`], so a gate can only further restrict the configured scanner.
///
/// Deserializes from the one gate schema of every host (Python
/// `execution_gates`, Ark API `gates`): the native keys `rules`, `models`,
/// `pii_mode`, `dlp_mode`, the attack-class `<category>_mode` keys and
/// `explain`, the level switches `l1`, `l2` and
/// `l3`, `conditional`, the L3 worker policy `l3_policy` and the opt-in
/// `cascade` (L1 early exit and per-module L1 cuts). Unknown keys and
/// out-of-range values are refused.
pub struct ScanGateMatrix {
    /// Native rule, model, mode and `explain` gates, shared with Ark Core.
    pub native: NativeGates,
    /// Optional L1 override. `None` means enabled.
    pub l1: Option<bool>,
    /// Optional L2 override. `None` means enabled.
    pub l2: Option<bool>,
    /// Optional L3 override. `None` means enabled.
    pub l3: Option<bool>,
    /// Request-context and prior-result conditions applied before L2 or L3.
    pub conditional: Vec<ConditionalPipelineGate>,
    /// L3 worker scheduling policy.
    pub l3_policy: L3SchedulerPolicy,
    /// The opt-in cascade: when set, a module L1 decides (or no later layer
    /// can run for) skips L2 and L3 and results carry `decided_by`; its
    /// `modules` set the per-module L1 cuts. `None` (the default) runs L2
    /// and L3 as before. Levels and conditional gates stay the keys above;
    /// see [`super::CascadeConfig::validate_for_gates`].
    pub cascade: Option<super::Cascade>,
}

#[derive(Debug, Clone)]
/// Priority and timeout policy for centrally scheduled L3 work.
///
/// `priority`, `ttl_ms` and `estimated_cost_ms` start empty: a host resolves
/// a pipeline missing from them against its own model table.
pub struct L3SchedulerPolicy {
    /// Whether model L3 work should be centrally queued by scan methods.
    pub enabled: bool,
    /// Ordered category/model priority list. Earlier entries run first.
    /// Empty means the host's default order.
    pub priority: Vec<String>,
    /// Per category/model timeout before an unstarted L3 job degrades.
    pub ttl_ms: HashMap<String, u64>,
    /// Initial execution-cost estimate per category/model. The worker replaces
    /// this gradually with observed wall time while it is running.
    pub estimated_cost_ms: HashMap<String, u64>,
    /// Compute-time credit granted during one fair-scheduling round.
    pub fairness_quantum_ms: u64,
    /// Maximum queue wait before the oldest job bypasses priority and cost.
    pub max_wait_ms: u64,
    /// Multiplier applied to L2 confidence when L3 degrades.
    pub degraded_factor: f64,
    /// Whether L3 may stop once the final class is stable.
    pub early_exit: L3EarlyExitMode,
    /// Whether L3 should emit non-authoritative progress/provisional events.
    pub progress: L3ProgressMode,
    /// Logical chunk ordering strategy. This does not enable tensor batching.
    pub clustering: L3ClusteringStrategy,
    /// Number of high-priority members inferred per similarity cluster for
    /// representative scheduling. Values below 1 are treated as 1.
    pub representatives_per_cluster: usize,
    /// Number of least-similar verification members inferred per cluster for
    /// verify-representative scheduling. Values below 1 are treated as 1.
    pub verify_representatives_per_cluster: usize,
    /// Minimum request-local similarity required to place two chunks in the
    /// same representative cluster.
    pub min_cluster_similarity: f64,
    /// Maximum number of chunks assigned to one representative cluster.
    pub max_cluster_size: usize,
    /// Optional execution-policy overrides keyed by pipeline category or model.
    /// Category keys take precedence over model keys.
    pub pipelines: HashMap<String, L3PipelinePolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Optional per-pipeline overrides for L3 chunk execution.
pub struct L3PipelinePolicy {
    /// Chunk execution strategy. `None` inherits the request-wide default.
    #[serde(default)]
    pub clustering: Option<L3ClusteringStrategy>,
    /// Representatives inferred from the high-priority side of each cluster.
    #[serde(default)]
    pub representatives_per_cluster: Option<usize>,
    /// Least-similar members used to verify a representative cluster.
    #[serde(default)]
    pub verify_representatives_per_cluster: Option<usize>,
    /// Minimum request-local similarity required for cluster membership.
    #[serde(default)]
    pub min_cluster_similarity: Option<f64>,
    /// Maximum number of members allowed in one cluster.
    #[serde(default)]
    pub max_cluster_size: Option<usize>,
    /// Chunk-output aggregation. `None` keeps the pipeline's built-in rule.
    #[serde(default)]
    pub aggregation: Option<L3AggregationStrategy>,
    /// Early-exit scope. `None` inherits the request-wide default semantics.
    #[serde(default)]
    pub early_exit: Option<L3PipelineEarlyExit>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
/// Configurable aggregation for one L3 pipeline.
pub enum L3AggregationStrategy {
    AnyPositiveOrHighest {
        positive_class: String,
        threshold: f64,
    },
    HighestRiskAboveThresholdOrConfidence {
        threshold: f64,
    },
    MajorityVoteOrHighest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Scope at which a stable per-pipeline L3 decision stops work.
pub enum L3PipelineEarlyExit {
    Disabled,
    HeadStable,
    RequestWidePositive,
}

#[derive(Debug, Clone, PartialEq)]
/// Fully resolved execution settings for one pipeline and request.
pub struct EffectiveL3PipelinePolicy {
    pub clustering: L3ClusteringStrategy,
    pub representatives_per_cluster: usize,
    pub verify_representatives_per_cluster: usize,
    pub min_cluster_similarity: f64,
    pub max_cluster_size: usize,
    pub aggregation: Option<L3AggregationStrategy>,
    pub early_exit: L3PipelineEarlyExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3EarlyExitMode {
    Disabled,
    ClassStable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3ProgressMode {
    Disabled,
    Progress,
    Provisional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3ClusteringStrategy {
    Disabled,
    RankOnly,
    Representative,
    VerifyRepresentative,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One conditional L2/L3 pipeline gate.
pub struct ConditionalPipelineGate {
    /// Phase controlled by this gate. L1 is intentionally not supported.
    pub level: SecurityLevel,
    /// Optional category/model selector. `None` applies to every pipeline at the level.
    #[serde(default)]
    pub pipeline: Option<String>,
    /// Condition that enables a normal gate or activates an `l3_policy` override.
    pub when: GateExpression,
    /// Optional L3 execution-policy override applied when `when` matches.
    /// Policy gates do not suppress the pipeline when the condition is false.
    #[serde(default)]
    pub l3_policy: Option<L3PipelinePolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Recursive expression over enqueue metadata and completed L1/L2 results.
pub enum GateExpression {
    All(Vec<GateExpression>),
    Any(Vec<GateExpression>),
    Not(Box<GateExpression>),
    Metadata(MetadataCondition),
    Result(ResultCondition),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Predicate over a dotted path in request metadata.
pub struct MetadataCondition {
    pub path: String,
    #[serde(default)]
    pub equals: Option<Value>,
    #[serde(default, rename = "in")]
    pub in_values: Option<Vec<Value>>,
    #[serde(default)]
    pub exists: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Predicate over a previously completed L1/L2 pipeline result.
pub struct ResultCondition {
    pub pipeline: String,
    #[serde(default)]
    pub classes: Vec<String>,
    #[serde(default)]
    pub min_confidence: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
/// Minimal result view exposed to conditional gate evaluation.
pub struct GateResult {
    pub pipeline: String,
    pub class_name: String,
    pub confidence: f64,
    pub level: SecurityLevel,
}

impl Default for L3SchedulerPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            priority: Vec::new(),
            ttl_ms: HashMap::new(),
            estimated_cost_ms: HashMap::new(),
            fairness_quantum_ms: 50,
            max_wait_ms: 2_000,
            degraded_factor: 0.75,
            early_exit: L3EarlyExitMode::ClassStable,
            progress: L3ProgressMode::Disabled,
            clustering: L3ClusteringStrategy::RankOnly,
            representatives_per_cluster: 1,
            verify_representatives_per_cluster: 1,
            min_cluster_similarity: 0.90,
            max_cluster_size: 8,
            pipelines: HashMap::new(),
        }
    }
}

impl L3SchedulerPolicy {
    /// Resolve request-wide defaults and a category/model override.
    ///
    /// `request_wide_positive` marks a pipeline whose stable positive answers
    /// the whole request (an attack detector); under
    /// [`L3EarlyExitMode::ClassStable`] it inherits
    /// [`L3PipelineEarlyExit::RequestWidePositive`], every other pipeline
    /// [`L3PipelineEarlyExit::HeadStable`].
    pub fn pipeline_policy(
        &self,
        category: &str,
        model: &str,
        request_wide_positive: bool,
    ) -> EffectiveL3PipelinePolicy {
        let pipeline = self
            .pipelines
            .get(category)
            .or_else(|| self.pipelines.get(model));
        let inherited_early_exit = match self.early_exit {
            L3EarlyExitMode::Disabled => L3PipelineEarlyExit::Disabled,
            L3EarlyExitMode::ClassStable if request_wide_positive => {
                L3PipelineEarlyExit::RequestWidePositive
            }
            L3EarlyExitMode::ClassStable => L3PipelineEarlyExit::HeadStable,
        };
        EffectiveL3PipelinePolicy {
            clustering: pipeline
                .and_then(|policy| policy.clustering)
                .unwrap_or(self.clustering),
            representatives_per_cluster: pipeline
                .and_then(|policy| policy.representatives_per_cluster)
                .unwrap_or(self.representatives_per_cluster)
                .max(1),
            verify_representatives_per_cluster: pipeline
                .and_then(|policy| policy.verify_representatives_per_cluster)
                .unwrap_or(self.verify_representatives_per_cluster)
                .max(1),
            min_cluster_similarity: pipeline
                .and_then(|policy| policy.min_cluster_similarity)
                .unwrap_or(self.min_cluster_similarity)
                .clamp(0.0, 1.0),
            max_cluster_size: pipeline
                .and_then(|policy| policy.max_cluster_size)
                .unwrap_or(self.max_cluster_size)
                .max(1),
            aggregation: pipeline.and_then(|policy| policy.aggregation.clone()),
            early_exit: pipeline
                .and_then(|policy| policy.early_exit)
                .unwrap_or(inherited_early_exit),
        }
    }

    /// Refuse out-of-range values: zero counts, costs and fairness quantum,
    /// fractions outside `0..=1` and invalid pipeline overrides.
    pub fn validate(&self) -> Result<(), String> {
        check_count(
            usize::try_from(self.fairness_quantum_ms).unwrap_or(usize::MAX),
            "l3_policy.fairness_quantum_ms",
        )?;
        check_count(
            self.representatives_per_cluster,
            "l3_policy.representatives_per_cluster",
        )?;
        check_count(
            self.verify_representatives_per_cluster,
            "l3_policy.verify_representatives_per_cluster",
        )?;
        check_count(self.max_cluster_size, "l3_policy.max_cluster_size")?;
        check_fraction(self.degraded_factor, "l3_policy.degraded_factor")?;
        check_fraction(
            self.min_cluster_similarity,
            "l3_policy.min_cluster_similarity",
        )?;
        if let Some(name) = self.estimated_cost_ms.iter().find(|(_, &cost)| cost == 0) {
            return Err(format!(
                "l3_policy.estimated_cost_ms.{} must be >= 1",
                name.0
            ));
        }
        for (name, pipeline) in &self.pipelines {
            if name.trim().is_empty() {
                return Err("l3_policy.pipelines keys must not be empty".to_string());
            }
            pipeline
                .validate()
                .map_err(|error| format!("l3_policy.pipelines.{name}.{error}"))?;
        }
        Ok(())
    }
}

impl ScanGateMatrix {
    /// Explicitly enable all native rules, including opt-in DLP content families.
    pub fn all_enabled() -> Self {
        Self {
            native: NativeGates::all_enabled(),
            ..Self::default()
        }
    }

    /// Create a matrix with explicit level gates.
    pub fn levels(l1: bool, l2: bool, l3: bool) -> Self {
        Self {
            l1: Some(l1),
            l2: Some(l2),
            l3: Some(l3),
            ..Self::default()
        }
    }

    /// Set one level gate.
    pub fn set_level(&mut self, level: SecurityLevel, enabled: bool) {
        match level {
            SecurityLevel::L1 => self.l1 = Some(enabled),
            SecurityLevel::L2 => self.l2 = Some(enabled),
            SecurityLevel::L3 => self.l3 = Some(enabled),
        }
    }

    /// Set one model/native scanner gate.
    pub fn set_model(&mut self, model: impl Into<String>, enabled: bool) {
        self.native.models.insert(model.into(), enabled);
    }

    /// Builder-style model/native scanner gate setter.
    pub fn with_model(mut self, model: impl Into<String>, enabled: bool) -> Self {
        self.set_model(model, enabled);
        self
    }

    /// Set one stable rule-id gate.
    pub fn set_rule(&mut self, rule_id: impl Into<String>, enabled: bool) {
        self.native.rules.insert(rule_id.into(), enabled);
    }

    /// Builder-style stable rule-id gate setter.
    pub fn with_rule(mut self, rule_id: impl Into<String>, enabled: bool) -> Self {
        self.set_rule(rule_id, enabled);
        self
    }

    /// Replace request-context and prior-result gates.
    pub fn set_conditional(&mut self, gates: Vec<ConditionalPipelineGate>) -> Result<(), String> {
        for gate in &gates {
            gate.validate()?;
        }
        self.conditional = gates;
        Ok(())
    }

    /// Return whether the level is allowed by this matrix before max-level
    /// enforcement.
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        level_switch([self.l1, self.l2, self.l3], level)
    }

    /// Replace the L3 worker scheduling policy.
    pub fn set_l3_policy(&mut self, policy: L3SchedulerPolicy) {
        self.l3_policy = policy;
    }

    /// Merge the `l3_policy` of every matching L3 policy gate into the
    /// per-pipeline overrides of [`Self::l3_policy`].
    pub fn apply_l3_policy_overrides(&mut self, metadata: &Value, results: &[GateResult]) {
        for gate in &self.conditional {
            let (Some(pipeline), Some(override_policy)) =
                (gate.pipeline.as_ref(), gate.l3_policy.as_ref())
            else {
                continue;
            };
            if gate.level != SecurityLevel::L3 || !gate.when.matches(metadata, results) {
                continue;
            }
            self.l3_policy
                .pipelines
                .entry(pipeline.clone())
                .or_default()
                .apply_override(override_policy);
        }
    }
}

/// Whether every normal gate of `conditional` for `level` that targets
/// `pipeline` (or every pipeline) matches `metadata` and the completed
/// `results`. Policy-override gates never suppress a pipeline.
pub fn pipeline_allowed(
    conditional: &[ConditionalPipelineGate],
    level: SecurityLevel,
    pipeline: &str,
    metadata: &Value,
    results: &[GateResult],
) -> bool {
    conditional
        .iter()
        .filter(|gate| {
            gate.level == level
                && gate.l3_policy.is_none()
                && gate
                    .pipeline
                    .as_deref()
                    .is_none_or(|target| target == pipeline)
        })
        .all(|gate| gate.when.matches(metadata, results))
}

/// The one rule of the per-level switches `l1`, `l2`, `l3` of every host:
/// unset means enabled.
pub(super) fn level_switch(switches: [Option<bool>; 3], level: SecurityLevel) -> bool {
    let index = match level {
        SecurityLevel::L1 => 0,
        SecurityLevel::L2 => 1,
        SecurityLevel::L3 => 2,
    };
    switches[index].unwrap_or(true)
}

/// The serialized [`ScanGateMatrix`]; missing keys keep the defaults.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GateConfig {
    #[serde(flatten)]
    native: NativeGates,
    l1: Option<bool>,
    l2: Option<bool>,
    l3: Option<bool>,
    conditional: Vec<ConditionalPipelineGate>,
    l3_policy: L3PolicyConfig,
    cascade: Option<super::CascadeConfig>,
}

/// The serialized [`L3SchedulerPolicy`]: each key overrides its default;
/// `ttl_ms` and `estimated_cost_ms` entries override the default per key.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct L3PolicyConfig {
    enabled: Option<bool>,
    priority: Option<Vec<String>>,
    ttl_ms: HashMap<String, u64>,
    estimated_cost_ms: HashMap<String, u64>,
    fairness_quantum_ms: Option<u64>,
    max_wait_ms: Option<u64>,
    degraded_factor: Option<f64>,
    early_exit: Option<L3EarlyExitMode>,
    progress: Option<L3ProgressMode>,
    clustering: Option<L3ClusteringStrategy>,
    representatives_per_cluster: Option<usize>,
    verify_representatives_per_cluster: Option<usize>,
    min_cluster_similarity: Option<f64>,
    max_cluster_size: Option<usize>,
    pipelines: HashMap<String, L3PipelinePolicy>,
}

impl TryFrom<GateConfig> for ScanGateMatrix {
    type Error = String;

    fn try_from(config: GateConfig) -> Result<Self, String> {
        let raw = config.l3_policy;
        let mut policy = L3SchedulerPolicy::default();
        macro_rules! set {
            ($($field:ident),*) => {$(
                if let Some(value) = raw.$field {
                    policy.$field = value;
                }
            )*};
        }
        set!(
            enabled,
            priority,
            fairness_quantum_ms,
            max_wait_ms,
            degraded_factor,
            early_exit,
            progress,
            clustering,
            representatives_per_cluster,
            verify_representatives_per_cluster,
            min_cluster_similarity,
            max_cluster_size
        );
        policy.ttl_ms.extend(raw.ttl_ms);
        policy.estimated_cost_ms.extend(raw.estimated_cost_ms);
        policy.pipelines = raw.pipelines;
        policy.validate()?;
        let mut native = config.native;
        native.cascade_details = config.cascade.is_some();
        let mut gates = Self {
            native,
            l1: config.l1,
            l2: config.l2,
            l3: config.l3,
            l3_policy: policy,
            cascade: config
                .cascade
                .map(|cascade| {
                    cascade.validate_for_gates()?;
                    super::Cascade::new(cascade).map_err(|error| error.to_string())
                })
                .transpose()?,
            ..Self::default()
        };
        gates.set_conditional(config.conditional)?;
        Ok(gates)
    }
}

fn check_fraction(value: f64, field: &str) -> Result<(), String> {
    if (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} must be between 0.0 and 1.0"))
    }
}

fn check_count(value: usize, field: &str) -> Result<(), String> {
    if value == 0 {
        Err(format!("{field} must be >= 1"))
    } else {
        Ok(())
    }
}

impl L3PipelinePolicy {
    /// Refuse zero counts, fractions outside `0..=1` and an empty positive class.
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            (
                "representatives_per_cluster",
                self.representatives_per_cluster,
            ),
            (
                "verify_representatives_per_cluster",
                self.verify_representatives_per_cluster,
            ),
            ("max_cluster_size", self.max_cluster_size),
        ] {
            value.map_or(Ok(()), |value| check_count(value, field))?;
        }
        if let Some(value) = self.min_cluster_similarity {
            check_fraction(value, "min_cluster_similarity")?;
        }
        match &self.aggregation {
            Some(L3AggregationStrategy::AnyPositiveOrHighest {
                positive_class,
                threshold,
            }) => {
                if positive_class.trim().is_empty() {
                    return Err("aggregation.positive_class must not be empty".to_string());
                }
                check_fraction(*threshold, "aggregation.threshold")
            }
            Some(L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { threshold }) => {
                check_fraction(*threshold, "aggregation.threshold")
            }
            Some(L3AggregationStrategy::MajorityVoteOrHighest) | None => Ok(()),
        }
    }

    fn apply_override(&mut self, override_policy: &Self) {
        if override_policy.clustering.is_some() {
            self.clustering = override_policy.clustering;
        }
        if override_policy.representatives_per_cluster.is_some() {
            self.representatives_per_cluster = override_policy.representatives_per_cluster;
        }
        if override_policy.verify_representatives_per_cluster.is_some() {
            self.verify_representatives_per_cluster =
                override_policy.verify_representatives_per_cluster;
        }
        if override_policy.min_cluster_similarity.is_some() {
            self.min_cluster_similarity = override_policy.min_cluster_similarity;
        }
        if override_policy.max_cluster_size.is_some() {
            self.max_cluster_size = override_policy.max_cluster_size;
        }
        if override_policy.aggregation.is_some() {
            self.aggregation = override_policy.aggregation.clone();
        }
        if override_policy.early_exit.is_some() {
            self.early_exit = override_policy.early_exit;
        }
    }
}

impl ConditionalPipelineGate {
    pub fn validate(&self) -> Result<(), String> {
        if self.level == SecurityLevel::L1 {
            return Err("conditional gates may only target L2 or L3".to_string());
        }
        if self
            .pipeline
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("conditional gate pipeline must not be empty".to_string());
        }
        if self.l3_policy.is_some() && (self.level != SecurityLevel::L3 || self.pipeline.is_none())
        {
            return Err(
                "conditional l3_policy overrides require level l3 and a pipeline".to_string(),
            );
        }
        if let Some(policy) = &self.l3_policy {
            policy
                .validate()
                .map_err(|error| format!("conditional l3_policy.{error}"))?;
        }
        self.when.validate()
    }
}

impl GateExpression {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::All(items) | Self::Any(items) => {
                if items.is_empty() {
                    return Err("conditional gate all/any must not be empty".to_string());
                }
                for item in items {
                    item.validate()?;
                }
                Ok(())
            }
            Self::Not(item) => item.validate(),
            Self::Metadata(condition) => condition.validate(),
            Self::Result(condition) => condition.validate(),
        }
    }

    /// Whether the expression reads request metadata anywhere.
    pub fn reads_metadata(&self) -> bool {
        match self {
            Self::All(items) | Self::Any(items) => items.iter().any(Self::reads_metadata),
            Self::Not(item) => item.reads_metadata(),
            Self::Metadata(_) => true,
            Self::Result(_) => false,
        }
    }

    /// Evaluate the expression over request metadata and completed results.
    pub fn matches(&self, metadata: &Value, results: &[GateResult]) -> bool {
        match self {
            Self::All(items) => items.iter().all(|item| item.matches(metadata, results)),
            Self::Any(items) => items.iter().any(|item| item.matches(metadata, results)),
            Self::Not(item) => !item.matches(metadata, results),
            Self::Metadata(condition) => {
                let value = value_at_path(metadata, &condition.path);
                if let Some(expected) = condition.exists {
                    return value.is_some() == expected;
                }
                let Some(value) = value else {
                    return false;
                };
                if let Some(expected) = &condition.equals {
                    return value == expected;
                }
                condition
                    .in_values
                    .as_ref()
                    .is_some_and(|values| values.contains(value))
            }
            Self::Result(condition) => results.iter().any(|result| {
                result.pipeline == condition.pipeline
                    && (condition.classes.is_empty()
                        || condition.classes.contains(&result.class_name))
                    && condition
                        .min_confidence
                        .is_none_or(|minimum| result.confidence >= minimum)
            }),
        }
    }
}

fn value_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(root, |value, segment| {
        value.as_object().and_then(|object| object.get(segment))
    })
}

impl MetadataCondition {
    fn validate(&self) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("metadata gate path must not be empty".to_string());
        }
        let predicates = usize::from(self.equals.is_some())
            + usize::from(self.in_values.is_some())
            + usize::from(self.exists.is_some());
        if predicates != 1 {
            return Err(
                "metadata gate must configure exactly one of equals, in, or exists".to_string(),
            );
        }
        if self.in_values.as_ref().is_some_and(Vec::is_empty) {
            return Err("metadata gate in list must not be empty".to_string());
        }
        Ok(())
    }
}

impl ResultCondition {
    fn validate(&self) -> Result<(), String> {
        if self.pipeline.trim().is_empty() {
            return Err("result gate pipeline must not be empty".to_string());
        }
        if self
            .min_confidence
            .is_some_and(|value| !(0.0..=1.0).contains(&value))
        {
            return Err("result gate min_confidence must be between 0.0 and 1.0".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
/// The model-agnostic part of one scan's execution: the maximum level and
/// the gate matrix. Hosts add their runtime settings around it.
pub struct LayerExecution {
    max_level: SecurityLevel,
    gates: ScanGateMatrix,
}

impl LayerExecution {
    /// An execution with shared rule defaults up to `max_level`.
    pub fn new(max_level: SecurityLevel) -> Self {
        Self::with_gates(max_level, ScanGateMatrix::default())
    }

    /// An execution with explicit gates up to `max_level`.
    pub fn with_gates(max_level: SecurityLevel, gates: ScanGateMatrix) -> Self {
        Self { max_level, gates }
    }

    /// Replace the gate matrix.
    pub fn set_gates(&mut self, gates: ScanGateMatrix) {
        self.gates = gates;
    }

    /// Replace the max-level cap.
    pub fn set_max_level(&mut self, max_level: SecurityLevel) {
        self.max_level = max_level;
    }

    /// Whether a level is enabled after max-level enforcement.
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        level <= self.max_level && self.gates.allows_level(level)
    }

    /// The matrix backing this execution.
    pub fn gates(&self) -> &ScanGateMatrix {
        &self.gates
    }

    /// Mutable access to the matrix, for request-local overrides.
    pub fn gates_mut(&mut self) -> &mut ScanGateMatrix {
        &mut self.gates
    }

    /// The L3 worker policy.
    pub fn l3_policy(&self) -> &L3SchedulerPolicy {
        &self.gates.l3_policy
    }

    /// The max-level cap backing this execution.
    pub fn max_level(&self) -> SecurityLevel {
        self.max_level
    }
}

impl Default for LayerExecution {
    fn default() -> Self {
        Self::new(SecurityLevel::L3)
    }
}

#[cfg(test)]
mod tests;
