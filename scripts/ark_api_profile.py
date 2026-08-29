#!/usr/bin/env python3
"""Canonical Ark API benchmark profile, mirrored from the deployed config."""

from __future__ import annotations

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
CATEGORIES = [
    "injection", "dlp", "pii", "sensitive_document", "threat", "routing", "dynamic-pii",
]

MODEL_GATES = {
    "native:instruction_leak": True,
    "native:encoded_instruction": True,
    "native:multi_turn_escalation": True,
    "native:guardrail_tamper": True,
    "native:unicode_confusable": True,
    "native:zero_width_obfuscation": True,
    "native:agentic_control_abuse": True,
    "native:instruction_override": True,
    "native:covert_instruction": True,
    "native:instruction_boundary": True,
    "native:authority_escalation": True,
    "native:jailbreak_framing": True,
    "native:output_manipulation": True,
    "injection": True,
    "wolf-defender-small": True,
    "native:cross_tool_instruction": False,
    "native:tool_output_instruction": False,
    "native:hidden_html_instruction": False,
    "native:binary_smuggling": False,
    "native:dlp": True,
    "native:sensitive_material": True,
    "native:secret_transfer": True,
    "native:destructive_operation": True,
    "native:mcp_runtime_risk": False,
    "native:mcp_policy": False,
    "native:pii": True,
    "gliner_small-v2.5-edge": True,
    "sensitive_document": True,
    "orca-sonar-document-classifier": True,
    "threat": True,
    "unified-v3-threat": True,
    "native:tool_call_injection": True,
    "routing": True,
    "unified-v3-routing": True,
}

CONDITIONAL_GATES = [{
    "level": "L3",
    "pipeline": "dynamic-pii",
    "when": {"not": {"any": [
        {"result": {"pipeline": "sensitive_document", "classes": ["source_code"]}},
        {"result": {"pipeline": "routing", "classes": ["code_development_request"]}},
    ]}},
}]

LABEL_THRESHOLDS = {
    "organization": 0.8, "location": 0.8, "date": 0.95, "person": 0.8,
    "legal_party": 0.6, "street_address": 0.8, "username": 0.75,
    "passport_number": 0.8, "driver_license_number": 0.6,
    "medical_record_number": 0.8, "health_insurance_number": 0.8,
    "medical_condition": 0.8, "medication": 0.6, "religion": 0.7,
    "sexual_orientation": 0.55, "disability": 0.65,
    "political_affiliation": 0.75, "student_identifier": 0.65,
    "applicant_identifier": 0.35, "research_participant_identifier": 0.55,
    "parent_or_guardian": 0.8, "degree_program": 0.6,
}

CONDITIONAL_LABELS = [
    {"when": {"pipeline": "injection", "results": ["attack"]},
     "labels": ["person", "legal_party", "street_address", "username"]},
    {"when": {"pipeline": "threat", "results": ["secrets_access", "exfiltration_attempt"]},
     "labels": ["person", "legal_party", "street_address", "username", "employee_identifier",
                "student_identifier", "applicant_identifier", "research_participant_identifier",
                "passport_number", "driver_license_number", "medical_record_number",
                "health_insurance_number"]},
    {"when": {"pipeline": "sensitive_document", "results": ["finance"]},
     "labels": ["person", "legal_party", "street_address"]},
    {"when": {"pipeline": "sensitive_document", "results": ["hr"]},
     "labels": ["employee_identifier", "job_title", "salary", "person", "street_address",
                "username", "passport_number", "driver_license_number", "health_insurance_number",
                "medication", "religion", "sexual_orientation", "disability", "political_affiliation"]},
    {"when": {"pipeline": "sensitive_document", "results": ["internal_and_tech"]},
     "labels": ["person", "username"]},
    {"when": {"pipeline": "sensitive_document", "results": ["legal"]},
     "labels": ["case_number", "legal_party", "street_address", "passport_number",
                "driver_license_number", "medical_record_number", "medical_condition", "medication",
                "religion", "sexual_orientation", "political_affiliation"]},
    {"when": {"pipeline": "sensitive_document", "results": ["other"]},
     "labels": ["person", "street_address", "medical_record_number", "medical_condition", "medication"]},
    {"when": {"pipeline": "sensitive_document", "results": ["school"]},
     "labels": ["student_identifier", "applicant_identifier", "research_participant_identifier",
                "parent_or_guardian", "degree_program"]},
]


def execution_gates() -> dict:
    return {
        "levels": {"l1": True, "l2": True, "l3": True},
        "models": dict(MODEL_GATES),
        "conditional": CONDITIONAL_GATES,
    }


def dynamic_pii_config() -> dict:
    return {
        "labels": ["organization", "location", "date", "person"],
        "threshold": 0.5,
        "label_thresholds": dict(LABEL_THRESHOLDS),
        "execution_gate": {"type": "always"},
        "conditional_labels": CONDITIONAL_LABELS,
        # The API accepts 25 MiB. Dynamic PII must not retain its 1 MiB default.
        "max_text_bytes": MAX_UPLOAD_BYTES,
        "chunk_size_words": 256,
        "chunk_overlap_words": 32,
        "timeout_ms": 5_000,
        "queue_timeout_ms": 120_000,
        "timeout_per_chunk_ms": 500,
        "max_timeout_ms": 120_000,
    }
