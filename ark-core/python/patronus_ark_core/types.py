# SPDX-License-Identifier: MIT OR Apache-2.0
"""Python shapes of Core configuration and serialized reports."""
from typing import Literal, NotRequired, Required, TypedDict


class EvidenceSpan(TypedDict):
    label: str
    text: str
    score: float
    start_byte: int
    end_byte: int
    start_char: int
    end_char: int


class LayerResult(TypedDict):
    level: str
    layer_type: str
    class_name: str
    confidence: float
    matched: bool
    duration_ms: float
    thresholds: dict[str, float]
    details: dict[str, object]


class LabelScore(TypedDict):
    label: str
    confidence: float
    matched: bool


NativeCategory = Literal[
    "pii",
    "dlp",
    "injection",
    "jailbreak",
    "prompt_extraction",
    "tool_poisoning",
    "agent_config_tampering",
    "memory_poisoning",
    "exfiltration",
    "unsafe_action",
    "resource_exhaustion",
    "harmful_content",
    "toxic_language",
]


class NativeResult(TypedDict):
    category: NativeCategory
    class_name: str
    confidence: float
    level: str
    model: str
    duration_ms: float
    layers: list[LayerResult]
    evidence_spans: list[EvidenceSpan]
    label_scores: list[LabelScore]
    decision: NotRequired[dict[str, object]]


class WolfResult(TypedDict):
    document_logit: float
    attack_probability: float
    threshold: float
    matched: bool
    windows: int
    model_id: str
    revision: str
    precision: str


Stage = Literal["heuristic", "l1_model", "policy", "l2", "l3"]


class ModuleDecision(TypedDict):
    """Final answer of one scanned module and the stage that decided it."""
    module: str
    outcome: Literal["detected", "clear"]
    decided_by: Stage
    score: float
    layers: NotRequired[list[LayerResult]]


class ScanReport(TypedDict):
    input_bytes: int
    native: list[NativeResult]
    wolf: WolfResult | None
    decision: NotRequired[list[ModuleDecision]]


Decision = Literal["allow", "ask", "block"]


class TopFeature(TypedDict):
    feature: str
    weight: float


class ShellModelVerdict(TypedDict):
    id: str
    score: float
    decision: Decision
    top_features: list[TopFeature]


class PolicyHit(TypedDict):
    id: str
    tier: Literal["core", "bundle-default", "user"]
    title: str
    decision: Decision
    where: list[str]


Lowered = TypedDict("Lowered", {"id": str, "from": Literal["block"], "to": Literal["ask"]})


# `patronus.facts/1` of a command: the `facts` of a verdict made with
# `with_facts=True`, passed back as `prior_facts` of later commands.
ShellFacts = dict[str, object]


ShellVerdict = TypedDict("ShellVerdict", {
    "v": Literal["patronus.verdict/1"],
    "decision": Decision,
    "score": float,
    "cuts": dict[str, float],
    "model": ShellModelVerdict,
    "policies": list[PolicyHit],
    "allowlisted": list[Lowered],
    "facts": NotRequired[ShellFacts],
})


class OnnxRuntimeOptions(TypedDict, total=False):
    intra_threads: int | None
    inter_threads: int | None
    spinning: bool | None


class WolfExecutionOptions(TypedDict, total=False):
    window_tokens: int
    overlap_tokens: int
    batch_size: int


class WolfConfig(TypedDict, total=False):
    """Wolf, the injection L3; an unset `bundle_dir` is the model's directory
    below `cache_root`."""
    bundle_dir: str
    threshold: NotRequired[float]
    model: NotRequired[Literal["base", "small", "edge"]]
    precision: NotRequired[
        Literal["auto", "fp32", "fp16", "mixed", "mixed_x86", "int8_int4", "int8_int4_x86"]
    ]
    execution: NotRequired[WolfExecutionOptions]


class ShellConfig(TypedDict, total=False):
    """Cat, the shell verdict; an unset `bundle_dir` is Cat's directory below
    `cache_root`."""
    bundle_dir: str
    manifest_sha256: NotRequired[str]
    policy_dirs: NotRequired[list[str]]
    policies: NotRequired[list[str]]
    """Inline Cedar user policies, applied after the `policy_dirs` files."""
    allowlist: NotRequired[dict[str, Literal["ask"]]]


ScoreMode = Literal["strict", "balanced", "recall"]


class L1ModelConfig(TypedDict):
    """A module's L1 text model: a pinned release; cuts on its logit scale."""
    bundle_dir: str
    manifest_sha256: str
    detect_threshold: NotRequired[float]
    clear_threshold: NotRequired[float]
    clear_enabled: NotRequired[bool]


class ModuleConfig(TypedDict, total=False):
    """One module's cascade settings; heuristic cuts on its 0..1 rule score."""
    detect_threshold: float | None
    clear_threshold: float | None
    l1_model: L1ModelConfig | None


# Conditional gates and the L3 worker policy of the gate schema (Rust
# `cascade::gates`); key names follow the Rust types.

MetadataCondition = TypedDict("MetadataCondition", {
    "path": Required[str],
    "equals": object,
    "in": list[object],
    "exists": bool,
}, total=False)
"""Predicate over a dotted path in request metadata."""


class ResultCondition(TypedDict, total=False):
    """Predicate over a previously completed L1/L2 pipeline result."""
    pipeline: Required[str]
    classes: list[str]
    min_confidence: float


GateExpression = TypedDict("GateExpression", {
    "all": list["GateExpression"],
    "any": list["GateExpression"],
    "not": "GateExpression",
    "metadata": MetadataCondition,
    "result": ResultCondition,
}, total=False)
"""Exactly one key: a recursive expression over request metadata and
completed L1/L2 results."""

L3ClusteringStrategy = Literal["disabled", "rank_only", "representative", "verify_representative"]
L3EarlyExitMode = Literal["disabled", "class_stable"]
L3PipelineEarlyExit = Literal["disabled", "head_stable", "request_wide_positive"]
L3ProgressMode = Literal["disabled", "progress", "provisional"]


class L3AggregationStrategy(TypedDict, total=False):
    """`positive_class` and `threshold` for `any_positive_or_highest`,
    `threshold` for `highest_risk_above_threshold_or_confidence`."""
    type: Required[Literal[
        "any_positive_or_highest",
        "highest_risk_above_threshold_or_confidence",
        "majority_vote_or_highest",
    ]]
    positive_class: str
    threshold: float


class L3PipelinePolicy(TypedDict, total=False):
    """Per-pipeline overrides for L3 chunk execution."""
    clustering: L3ClusteringStrategy
    representatives_per_cluster: int
    verify_representatives_per_cluster: int
    min_cluster_similarity: float
    max_cluster_size: int
    aggregation: L3AggregationStrategy
    early_exit: L3PipelineEarlyExit


class ConditionalPipelineGate(TypedDict, total=False):
    """One conditional L2/L3 gate: enables the level for `pipeline` (every
    pipeline when absent) when `when` matches, or with `l3_policy` applies
    that policy instead."""
    level: Required[Literal["L2", "L3"]]
    pipeline: str
    when: Required[GateExpression]
    l3_policy: L3PipelinePolicy


class L3SchedulerPolicy(TypedDict, total=False):
    """L3 worker policy; each key overrides its default."""
    enabled: bool
    priority: list[str]
    ttl_ms: dict[str, int]
    estimated_cost_ms: dict[str, int]
    fairness_quantum_ms: int
    max_wait_ms: int
    degraded_factor: float
    early_exit: L3EarlyExitMode
    progress: L3ProgressMode
    clustering: L3ClusteringStrategy
    representatives_per_cluster: int
    verify_representatives_per_cluster: int
    min_cluster_similarity: float
    max_cluster_size: int
    pipelines: dict[str, L3PipelinePolicy]


class CascadeConfig(TypedDict, total=False):
    """The opt-in cascade: per-module L1 cuts and L1 models. The levels that
    run are the gate keys `max_level`, `l1`, `l2`, `l3` and `conditional`."""
    modules: dict[str, ModuleConfig]


class ScanGates(TypedDict, total=False):
    """The one gate type (rules, models, modes, `explain` and the layer keys):
    top-level keys of the Core `ScannerConfig`, of Ark's config and Ark's
    `execution_gates`. Core scans carry no request metadata and run
    no L3 worker, so they read only result `conditional` gates and ignore
    `l3_policy`."""
    rules: dict[str, bool]
    models: dict[str, bool]
    pii_mode: ScoreMode
    dlp_mode: ScoreMode
    injection_mode: ScoreMode
    jailbreak_mode: ScoreMode
    prompt_extraction_mode: ScoreMode
    tool_poisoning_mode: ScoreMode
    agent_config_tampering_mode: ScoreMode
    memory_poisoning_mode: ScoreMode
    exfiltration_mode: ScoreMode
    unsafe_action_mode: ScoreMode
    resource_exhaustion_mode: ScoreMode
    resource_exhaustion_count_threshold: int
    threat_points_acceptance: float
    harmful_content_mode: ScoreMode
    toxic_language_mode: ScoreMode
    explain: bool
    l1: bool
    l2: bool
    l3: bool
    conditional: list[ConditionalPipelineGate]
    l3_policy: L3SchedulerPolicy
    cascade: CascadeConfig | None


class ScannerConfig(ScanGates, total=False):
    """The Core scanner's config; Ark's config is this config plus Ark's keys."""
    categories: list[NativeCategory]
    max_level: Literal["L1", "L2", "L3", "l1", "l2", "l3"]
    max_input_bytes: int | None
    max_findings: int | None
    cache_root: str
    download: Literal["never", "missing"]
    download_categories: list[str] | None
    download_timeout_ms: int
    execution_backend: Literal[
        "auto", "cpu", "gpu", "coreml", "core_ml", "cuda", "directml", "direct_ml", "tensorrt",
        "tensor_rt",
    ]
    onnx_runtime: OnnxRuntimeOptions
    wolf: WolfConfig | None
    shell: ShellConfig | None


