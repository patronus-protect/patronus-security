# SPDX-License-Identifier: GPL-3.0-only
"""Measured, classification-aware entity labels for GLiNER.

Native L1 owns deterministic values such as email, IP, IBAN, BIC and phone
numbers. GLiNER covers semantic PII and context-dependent identifiers. The
labels below are canonical API names; the runtime replaces underscores with
spaces only for GLiNER inference and restores the canonical name on output.

Two calibration sources feed the thresholds below:

* The original synthetic sweep uses five positive and ten hard-negative texts
  per candidate; see ``benchmark_data/dynamic_pii_threshold_sweep.jsonl`` and
  ``scripts/sweep_gliner_pii.py`` (exact-span matching).
* Newer general labels (``city``, ``country``, ``first_name``, ``last_name``)
  and the ``date`` re-calibration were measured on a real, human/agent-realistic
  PII corpus (``Ai4Privacy/pii-masking-300k`` English validation split) via
  ``scripts/sweep_gliner_pii_real.py``. Real-corpus span boundaries follow the
  dataset's own conventions, so those are selected on relaxed (label-matched
  overlap) F1; the exact-span F1 at the same threshold is recorded alongside.
"""

MIN_ACCEPTED_F1 = 0.6

GLINER_LABELS = (
    "organization",
    "location",
    "date",
    "city",
    "country",
    "first_name",
    "last_name",
    "date_of_birth",
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
    # Real-corpus (Ai4Privacy) calibrated general labels. Selected precision-first
    # (minimise false positives): the highest recall reachable at precision >= 0.8,
    # otherwise the max-precision operating point. See GLINER_REAL_CORPUS_SWEEP.
    "date": 0.95,
    "city": 0.8,
    "country": 0.95,
    "first_name": 0.95,
    "last_name": 0.95,
    "date_of_birth": 0.9,
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
#
# The ``real_corpus`` entries below were measured on 2026-08-05 with the same
# gliner_small-v2.5-edge model against the Ai4Privacy/pii-masking-300k English
# validation split (120 positives + 120 hard negatives per label,
# scripts/sweep_gliner_pii_real.py). Matching is relaxed (label-matched span
# overlap); ``exact_f1`` is the exact-span F1 at the same threshold.
#
# Selection here is PRECISION-FIRST rather than best-F1: we minimise false
# positives even at the cost of recall (detect fewer, but wrongly as rarely as
# possible). The recorded ``threshold`` is the highest-recall point reaching
# precision >= 0.8; if no threshold reaches 0.8 at usable recall, it is the
# max-precision operating point. A label is ``mapped`` only if its operating
# point still keeps precision >= 0.6 -- otherwise the model cannot detect it
# "without being wrong" at any threshold, so it stays unmapped. ``f1`` is the
# F1 at the chosen operating point (informational, no longer the selector).
GLINER_REAL_CORPUS_SWEEP = {
    "country": {
        "threshold": 0.95,
        "precision": 0.832,
        "recall": 0.939,
        "f1": 0.882,
        "exact_f1": 0.876,
        "mapped": True,
    },
    "city": {
        "threshold": 0.8,
        "precision": 0.853,
        "recall": 0.527,
        "f1": 0.652,
        "exact_f1": 0.592,
        "mapped": True,
    },
    "date_of_birth": {
        "threshold": 0.9,
        "precision": 0.812,
        "recall": 0.203,
        "f1": 0.325,
        "exact_f1": 0.325,
        "mapped": True,
    },
    "first_name": {
        "threshold": 0.95,
        "precision": 0.805,
        "recall": 0.132,
        "f1": 0.226,
        "exact_f1": 0.171,
        "mapped": True,
    },
    "last_name": {
        "threshold": 0.95,
        "precision": 0.804,
        "recall": 0.157,
        "f1": 0.262,
        "exact_f1": 0.216,
        "mapped": True,
    },
    "date": {
        "threshold": 0.95,
        "precision": 0.714,
        "recall": 0.568,
        "f1": 0.633,
        "exact_f1": 0.633,
        "mapped": True,
    },
    # Unmapped: precision stays below 0.6 at every threshold with usable recall,
    # so gliner_small-edge cannot detect these "without being wrong". Recorded
    # as the best (max-precision) operating point observed.
    "national_id_number": {
        "threshold": 0.9,
        "precision": 0.6,
        "recall": 0.06,
        "f1": 0.109,
        "exact_f1": 0.106,
        "mapped": False,
    },
    "postal_code": {
        "threshold": 0.92,
        "precision": 0.609,
        "recall": 0.092,
        "f1": 0.16,
        "exact_f1": 0.153,
        "mapped": False,
    },
    "state_or_region": {
        "threshold": 0.92,
        "precision": 0.587,
        "recall": 0.394,
        "f1": 0.471,
        "exact_f1": 0.471,
        "mapped": False,
    },
    "password": {
        "threshold": 0.9,
        "precision": 0.2,
        "recall": 0.031,
        "f1": 0.054,
        "exact_f1": 0.03,
        "mapped": False,
    },
}

# Existing production labels re-measured on the same real corpus (2026-08-05).
# On realistic, messy text these stay far below usable quality — and, crucially,
# even under the precision-first policy their precision never clears 0.6 at any
# threshold with usable recall (``max_precision`` is the best point observed), so
# they cannot be made "not wrong". They are intentionally left mapped (their
# synthetic thresholds are tuned for the narrower document/tool contexts they
# serve), but this is recorded so the regression risk is visible and revisitable.
GLINER_REAL_CORPUS_REGRESSIONS = {
    "passport_number": {"best_f1": 0.472, "max_precision": 0.511},
    "street_address": {"best_f1": 0.405, "max_precision": 0.455},
    "username": {"best_f1": 0.376, "max_precision": 0.303},
    "driver_license_number": {"best_f1": 0.34, "max_precision": 0.277},
}

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
        "default": (
            "organization",
            "date",
            "person",
            "city",
            "country",
        ),
    },
    "sensitive_document": {
        "finance": (
            "accounting_period",
            "person",
            "legal_party",
            "street_address",
            "city",
            "country",
        ),
        "hr": (
            "employee_identifier",
            "job_title",
            "salary",
            "person",
            "date_of_birth",
            "street_address",
            "city",
            "country",
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
            "date_of_birth",
            "street_address",
            "city",
            "country",
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
        "education": (
            "student_identifier",
            "applicant_identifier",
            "research_participant_identifier",
            "parent_or_guardian",
            "degree_program",
        ),
        # Compatibility alias for historical benchmark rows. The current
        # sensitive-document head emits `education`.
        "school": (
            "student_identifier",
            "applicant_identifier",
            "research_participant_identifier",
            "parent_or_guardian",
            "degree_program",
        ),
        "medical": (
            "medical_record_number",
            "health_insurance_number",
            "medical_condition",
            "medication",
        ),
        "other": (
            "person",
            "date_of_birth",
            "street_address",
            "city",
            "country",
            "medical_record_number",
            "medical_condition",
            "medication",
        ),
    },
    "tool_class": {
        "file": (
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
        "web": (
            "law_or_regulation",
            "court",
            "product",
            "brand",
            "campaign",
        ),
        "database": (
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
        "api": (
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
        "memory": (
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
        "messaging": (
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
    """Return the ordered union for all supplied ``(category, class)`` contexts."""
    if not classifications:
        return ()
    context_labels = [set(labels_for_classification(*item)) for item in classifications]
    return tuple(
        label
        for label in GLINER_LABELS
        if any(label in labels for labels in context_labels)
    )
