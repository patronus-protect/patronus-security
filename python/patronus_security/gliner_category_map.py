# SPDX-License-Identifier: AGPL-3.0-only
"""Measured, classification-aware entity labels for GLiNER.

Native L1 owns deterministic values such as email, IP, IBAN, BIC and phone
numbers. GLiNER covers semantic PII and context-dependent identifiers. The
labels below are canonical API names; the runtime replaces underscores with
spaces only for GLiNER inference and restores the canonical name on output.
The threshold sweep uses five positive and ten hard-negative texts per candidate;
see ``benchmark_data/dynamic_pii_threshold_sweep.jsonl``.
"""

MIN_ACCEPTED_F1 = 0.6

GLINER_LABELS = (
    "organization",
    "location",
    "date",
    "accounting_period",
    "employee_identifier",
    "job_title",
    "salary",
    "contract",
    "case_number",
    "law_or_regulation",
    "court",
    "product",
    "brand",
    "campaign",
    "person",
    "legal_party",
    "street_address",
    "username",
    "passport_number",
    "driver_license_number",
    "medical_record_number",
    "health_insurance_number",
    "medical_condition",
    "medication",
    "religion",
    "sexual_orientation",
    "disability",
    "political_affiliation",
    "student_identifier",
    "applicant_identifier",
    "research_participant_identifier",
    "parent_or_guardian",
    "degree_program",
)

# Per-label runtime thresholds. They start at the isolated-sweep optimum and
# are adjusted where a larger context label set changes the true span score.
# Labels not listed here retain the 0.5 benchmark/runtime default.
GLINER_LABEL_THRESHOLDS = {
    "person": 0.8,
    "legal_party": 0.6,
    "street_address": 0.8,
    "username": 0.75,
    "passport_number": 0.8,
    "driver_license_number": 0.6,
    "medical_record_number": 0.8,
    "health_insurance_number": 0.8,
    "medical_condition": 0.8,
    "medication": 0.6,
    "religion": 0.7,
    "sexual_orientation": 0.55,
    "disability": 0.65,
    "political_affiliation": 0.75,
    "student_identifier": 0.65,
    "applicant_identifier": 0.35,
    "research_participant_identifier": 0.55,
    "parent_or_guardian": 0.8,
    "degree_program": 0.6,
}

# Measured on 2026-07-14 (general labels) and 2026-07-15 (school labels) with
# gliner_small-v2.5. ``physical_address`` is kept here as a rejected result:
# GLiNER split full addresses into several valid spans, so exact-span F1 was
# zero. ``street_address`` is the usable boundary.
GLINER_THRESHOLD_SWEEP = {
    "person": {"threshold": 0.8, "precision": 1.0, "recall": 1.0, "f1": 1.0},
    "legal_party": {
        "threshold": 0.65,
        "runtime_threshold": 0.6,
        "precision": 1.0,
        "recall": 0.8,
        "f1": 0.8889,
    },
    "street_address": {
        "threshold": 0.8,
        "precision": 0.6667,
        "recall": 0.8,
        "f1": 0.7273,
    },
    "username": {
        "threshold": 0.75,
        "precision": 1.0,
        "recall": 0.8,
        "f1": 0.8889,
    },
    "passport_number": {"threshold": 0.8, "precision": 1.0, "recall": 1.0, "f1": 1.0},
    "driver_license_number": {
        "threshold": 0.75,
        "runtime_threshold": 0.6,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    },
    "medical_record_number": {
        "threshold": 0.8,
        "precision": 1.0,
        "recall": 0.8,
        "f1": 0.8889,
    },
    "health_insurance_number": {
        "threshold": 0.7,
        "runtime_threshold": 0.8,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    },
    "medical_condition": {
        "threshold": 0.8,
        "precision": 1.0,
        "recall": 0.8,
        "f1": 0.8889,
    },
    "medication": {"threshold": 0.6, "precision": 0.8, "recall": 0.8, "f1": 0.8},
    "religion": {
        "threshold": 0.8,
        "runtime_threshold": 0.7,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    },
    "sexual_orientation": {
        "threshold": 0.55,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    },
    "disability": {
        "threshold": 0.8,
        "runtime_threshold": 0.65,
        "precision": 0.8333,
        "recall": 1.0,
        "f1": 0.9091,
    },
    "political_affiliation": {
        "threshold": 0.8,
        "runtime_threshold": 0.75,
        "precision": 1.0,
        "recall": 0.8,
        "f1": 0.8889,
    },
    "student_identifier": {
        "threshold": 0.65,
        "precision": 0.75,
        "recall": 0.6,
        "f1": 0.6667,
    },
    "applicant_identifier": {
        "threshold": 0.35,
        "precision": 0.625,
        "recall": 1.0,
        "f1": 0.7692,
    },
    "research_participant_identifier": {
        "threshold": 0.55,
        "precision": 0.6667,
        "recall": 0.8,
        "f1": 0.7273,
    },
    "parent_or_guardian": {
        "threshold": 0.8,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    },
    "degree_program": {
        "threshold": 0.6,
        "precision": 0.6667,
        "recall": 0.8,
        "f1": 0.7273,
    },
    "physical_address": {
        "threshold": 0.8,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
    },
}

GLINER_CATEGORY_MAP = {
    "default": {
        "default": ("organization", "location", "date", "person"),
    },
    "sensitive_documents": {
        "finance": ("accounting_period", "person", "legal_party", "street_address"),
        "hr": (
            "employee_identifier",
            "job_title",
            "salary",
            "person",
            "street_address",
            "username",
            "passport_number",
            "driver_license_number",
            "health_insurance_number",
            "medication",
            "religion",
            "sexual_orientation",
            "disability",
            "political_affiliation",
        ),
        "internal_and_tech": ("person", "username"),
        "legal": (
            "contract",
            "case_number",
            "law_or_regulation",
            "court",
            "legal_party",
            "street_address",
            "passport_number",
            "driver_license_number",
            "medical_record_number",
            "medical_condition",
            "medication",
            "religion",
            "sexual_orientation",
            "political_affiliation",
        ),
        "marketing": ("product", "brand", "campaign"),
        "school": (
            "student_identifier",
            "applicant_identifier",
            "research_participant_identifier",
            "parent_or_guardian",
            "degree_program",
        ),
        "other": (
            "person",
            "street_address",
            "medical_record_number",
            "medical_condition",
            "medication",
        ),
    },
    "tool_classifier": {
        "tool_class.file.read": (
            "contract",
            "person",
            "legal_party",
            "street_address",
            "username",
            "passport_number",
            "driver_license_number",
            "medical_record_number",
            "health_insurance_number",
            "medical_condition",
            "medication",
            "religion",
            "sexual_orientation",
            "disability",
            "political_affiliation",
        ),
        "tool_class.web.fetch": (
            "law_or_regulation",
            "court",
            "product",
            "brand",
            "campaign",
        ),
        "tool_class.database.read": (
            "accounting_period",
            "employee_identifier",
            "job_title",
            "salary",
            "case_number",
            "person",
            "legal_party",
            "street_address",
            "username",
            "passport_number",
            "driver_license_number",
            "medical_record_number",
            "health_insurance_number",
            "medical_condition",
            "medication",
            "religion",
            "sexual_orientation",
            "disability",
            "political_affiliation",
        ),
        "tool_class.api.read": (
            "person",
            "legal_party",
            "street_address",
            "username",
            "passport_number",
            "driver_license_number",
            "medical_record_number",
            "health_insurance_number",
            "medical_condition",
            "medication",
            "religion",
            "sexual_orientation",
            "disability",
            "political_affiliation",
        ),
        "tool_class.memory.read": (
            "person",
            "street_address",
            "username",
            "medical_record_number",
            "health_insurance_number",
            "medical_condition",
            "medication",
            "religion",
            "sexual_orientation",
            "disability",
            "political_affiliation",
        ),
        "tool_class.messaging.send": (
            "person",
            "street_address",
            "username",
            "passport_number",
            "driver_license_number",
            "medical_record_number",
            "health_insurance_number",
            "medical_condition",
            "medication",
            "religion",
            "sexual_orientation",
            "disability",
            "political_affiliation",
        ),
    },
}


def labels_for_classification(category, class_name):
    """Return measured labels for one final classifier result."""
    return GLINER_CATEGORY_MAP.get(category, {}).get(class_name, ())


def labels_for_contexts(*classifications):
    """Return labels supported by every supplied ``(category, class)`` context."""
    if not classifications:
        return ()
    context_labels = [set(labels_for_classification(*item)) for item in classifications]
    return tuple(
        label
        for label in GLINER_LABELS
        if all(label in labels for labels in context_labels)
    )
