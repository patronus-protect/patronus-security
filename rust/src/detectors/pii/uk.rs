// SPDX-License-Identifier: GPL-3.0-only
//! United Kingdom identifiers: National Insurance number.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

pub(super) const NINO: PiiPattern = PiiPattern {
    name: "pii_ni_uk",
    pattern: r"(?i)\b(?:nino|national[ \t]+insurance[ \t]+number|britische[ \t]+sozialversicherungsnummer)\b[ \t]*(?:is[ \t]*)?[:#=\-]?[ \t]*(?P<value>[A-Z]{2}[ ]?\d{6}[ ]?[A-D])\b",
    entity_group: "NATIONALID",
    validator: Some(validators::uk_nino),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: true,
};
