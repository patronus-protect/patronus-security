// SPDX-License-Identifier: GPL-3.0-only
//! VAT identification numbers, part 1 (B01): DE, AT, CH, FR, NL, BE, IT, ES.
//!
//! One label and one check-digit validator per country. Every rule is
//! scored-only (K05): strict stays unchanged, `balanced` and `recall` report the
//! value with its country prefix without a field name, where the prefix, the
//! form and the check digit carry the finding. Uppercase prefixes only; the
//! value must stand alone (`context::stands_alone`). A bare Partita IVA (11
//! digits without `IT`) also needs a VAT term nearby or as its key.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

/// `DE136695976`, `DE 136 695 976`, `DE.136.695.976`, `DE-136-695-976`.
pub(super) const VAT_ID_DE: PiiPattern = PiiPattern {
    name: "pii_vat_id_de",
    pattern: r"\bDE[ .\-]?[0-9]{3}[ .\-]?[0-9]{3}[ .\-]?[0-9]{3}\b",
    entity_group: "VAT_ID_DE",
    validator: Some(validators::de_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `ATU13585627`, `ATU 13585627`.
pub(super) const VAT_ID_AT: PiiPattern = PiiPattern {
    name: "pii_vat_id_at",
    pattern: r"\bATU ?[0-9]{8}\b",
    entity_group: "VAT_ID_AT",
    validator: Some(validators::at_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `CHE-100.155.212`, `CHE100155212`, `CHE 100 155 212`; a trailing `MWST`,
/// `TVA` or `IVA` stays outside the span.
pub(super) const VAT_ID_CH: PiiPattern = PiiPattern {
    name: "pii_vat_id_ch",
    pattern: r"\bCHE[ \-]?[0-9]{3}[ .]?[0-9]{3}[ .]?[0-9]{3}\b",
    entity_group: "VAT_ID_CH",
    validator: Some(validators::ch_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `FR40303265045`, `FR 40 303 265 045`, `FR40 303265045` (numeric key).
pub(super) const VAT_ID_FR: PiiPattern = PiiPattern {
    name: "pii_vat_id_fr",
    pattern: r"\bFR ?[0-9]{2} ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}\b",
    entity_group: "VAT_ID_FR",
    validator: Some(validators::fr_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `NL004495445B01`, `NL 004495445B01`.
pub(super) const VAT_ID_NL: PiiPattern = PiiPattern {
    name: "pii_vat_id_nl",
    pattern: r"\bNL ?[0-9]{9}B[0-9]{2}\b",
    entity_group: "VAT_ID_NL",
    validator: Some(validators::nl_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `BE0403019261`, `BE 0403.019.261`, `BE0403 019 261`.
pub(super) const VAT_ID_BE: PiiPattern = PiiPattern {
    name: "pii_vat_id_be",
    pattern: r"\bBE ?[01][0-9]{3}[ .]?[0-9]{3}[ .]?[0-9]{3}\b",
    entity_group: "VAT_ID_BE",
    validator: Some(validators::be_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `IT00743110157`, `IT 00743110157`.
pub(super) const VAT_ID_IT: PiiPattern = PiiPattern {
    name: "pii_vat_id_it",
    pattern: r"\bIT ?[0-9]{11}\b",
    entity_group: "VAT_ID_IT",
    validator: Some(validators::it_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// A bare Partita IVA, 11 digits without `IT`: "Partita IVA: 00743110157",
/// `{"partita_iva": "00743110157"}`. Eleven digits with a Luhn digit prove too
/// little alone, so the context engine requires a VAT term on either side or
/// as the structural key.
pub(super) const VAT_ID_IT_PROXIMITY: PiiPattern = PiiPattern {
    name: "pii_vat_id_it_proximity",
    pattern: r"\b[0-9]{11}\b",
    entity_group: "VAT_ID_IT",
    validator: Some(validators::it_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: true,
};

/// `ESA13585625` (CIF), `ES54362315K` (DNI), `ESX5253868R` (NIE), `ES B58378431`.
pub(super) const VAT_ID_ES: PiiPattern = PiiPattern {
    name: "pii_vat_id_es",
    pattern: r"\bES ?[0-9A-Z][0-9]{7}[0-9A-Z]\b",
    entity_group: "VAT_ID_ES",
    validator: Some(validators::es_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
