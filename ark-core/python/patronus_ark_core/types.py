# SPDX-License-Identifier: MIT OR Apache-2.0
"""Python shapes of Core's serialized reports."""
from typing import Literal, TypedDict


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


class NativeResult(TypedDict):
    category: Literal["pii", "dlp", "injection"]
    class_name: str
    confidence: float
    level: str
    model: str
    duration_ms: float
    layers: list[LayerResult]
    evidence_spans: list[EvidenceSpan]
    label_scores: list[LabelScore]
    decision: dict[str, object] | None


class WolfResult(TypedDict):
    document_logit: float
    attack_probability: float
    threshold: float
    matched: bool
    windows: int
    model_id: str
    revision: str
    precision: str


class ScanReport(TypedDict):
    input_bytes: int
    native: list[NativeResult]
    wolf: WolfResult | None
