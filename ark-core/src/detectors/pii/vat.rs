// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAT identification numbers, part 1 (B01): DE, AT, CH, FR, NL, BE, IT, ES;
//! part 2 (B02): BG, CY, CZ, DK, EE, EL, FI, HR, HU, IE, LT;
//! part 3 (B16): LU, LV, MT, PL, PT, RO, SE, SI, SK, NO and GB (with `XI` for
//! Northern Ireland, same label and validator).
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

/// `BG175074752` (legal entity), `BG 7523169263` (ten digits: ЕГН, ЛНЧ or other).
pub(super) const VAT_ID_BG: PiiPattern = PiiPattern {
    name: "pii_vat_id_bg",
    pattern: r"\bBG ?[0-9]{9,10}\b",
    entity_group: "VAT_ID_BG",
    validator: Some(validators::bg_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `CY10259033P`, `CY-10259033P`.
pub(super) const VAT_ID_CY: PiiPattern = PiiPattern {
    name: "pii_vat_id_cy",
    pattern: r"\bCY[ \-]?[0-9]{8}[A-Z]\b",
    entity_group: "VAT_ID_CY",
    validator: Some(validators::cy_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `CZ25123891` (legal entity), `CZ640903926` (special), `CZ 7103192745` (birth number).
pub(super) const VAT_ID_CZ: PiiPattern = PiiPattern {
    name: "pii_vat_id_cz",
    pattern: r"\bCZ ?[0-9]{8,10}\b",
    entity_group: "VAT_ID_CZ",
    validator: Some(validators::cz_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `DK13585628`, `DK 13 58 56 28`.
pub(super) const VAT_ID_DK: PiiPattern = PiiPattern {
    name: "pii_vat_id_dk",
    pattern: r"\bDK ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[0-9]{2}\b",
    entity_group: "VAT_ID_DK",
    validator: Some(validators::dk_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `EE100931558`, `EE 100594102`.
pub(super) const VAT_ID_EE: PiiPattern = PiiPattern {
    name: "pii_vat_id_ee",
    pattern: r"\bEE ?[0-9]{9}\b",
    entity_group: "VAT_ID_EE",
    validator: Some(validators::ee_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `EL094259216`, `EL 094259216`, `GR094259216`.
pub(super) const VAT_ID_EL: PiiPattern = PiiPattern {
    name: "pii_vat_id_el",
    pattern: r"\b(?:EL|GR) ?[0-9]{9}\b",
    entity_group: "VAT_ID_EL",
    validator: Some(validators::el_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `FI20774740`, `FI 20774740`.
pub(super) const VAT_ID_FI: PiiPattern = PiiPattern {
    name: "pii_vat_id_fi",
    pattern: r"\bFI ?[0-9]{8}\b",
    entity_group: "VAT_ID_FI",
    validator: Some(validators::fi_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `HR33392005961`, `HR 33392005961`.
pub(super) const VAT_ID_HR: PiiPattern = PiiPattern {
    name: "pii_vat_id_hr",
    pattern: r"\bHR ?[0-9]{11}\b",
    entity_group: "VAT_ID_HR",
    validator: Some(validators::hr_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `HU12892312`, `HU-12892312`.
pub(super) const VAT_ID_HU: PiiPattern = PiiPattern {
    name: "pii_vat_id_hu",
    pattern: r"\bHU[ \-]?[0-9]{8}\b",
    entity_group: "VAT_ID_HU",
    validator: Some(validators::hu_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `IE6433435F`, `IE6433435OA` (since 2013), `IE8D79739I`, `IE8*79739I`,
/// `IE8+79739I` (old form).
pub(super) const VAT_ID_IE: PiiPattern = PiiPattern {
    name: "pii_vat_id_ie",
    pattern: r"\bIE ?(?:[0-9]{7}[A-W][A-W]?|[0-9][A-Z+*][0-9]{5}[A-W])\b",
    entity_group: "VAT_ID_IE",
    validator: Some(validators::ie_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `LT119511515` (legal person), `LT100001919017` (temporary taxpayer).
pub(super) const VAT_ID_LT: PiiPattern = PiiPattern {
    name: "pii_vat_id_lt",
    pattern: r"\bLT ?(?:[0-9]{9}|[0-9]{12})\b",
    entity_group: "VAT_ID_LT",
    validator: Some(validators::lt_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `LU15027442`, `LU 15027442`.
pub(super) const VAT_ID_LU: PiiPattern = PiiPattern {
    name: "pii_vat_id_lu",
    pattern: r"\bLU ?[0-9]{8}\b",
    entity_group: "VAT_ID_LU",
    validator: Some(validators::lu_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `LV40003521600`, `LV 40003521600` (legal entities).
pub(super) const VAT_ID_LV: PiiPattern = PiiPattern {
    name: "pii_vat_id_lv",
    pattern: r"\bLV ?[0-9]{11}\b",
    entity_group: "VAT_ID_LV",
    validator: Some(validators::lv_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `MT11679112`, `MT 1167-9112`.
pub(super) const VAT_ID_MT: PiiPattern = PiiPattern {
    name: "pii_vat_id_mt",
    pattern: r"\bMT ?[0-9]{4}[ \-]?[0-9]{4}\b",
    entity_group: "VAT_ID_MT",
    validator: Some(validators::mt_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `PL8567346215`, `PL 856-734-62-15`, `PL 856-73-46-215`.
pub(super) const VAT_ID_PL: PiiPattern = PiiPattern {
    name: "pii_vat_id_pl",
    pattern: r"\bPL ?[0-9]{3}[ \-]?(?:[0-9]{3}[ \-]?[0-9]{2}[ \-]?[0-9]{2}|[0-9]{2}[ \-]?[0-9]{2}[ \-]?[0-9]{3})\b",
    entity_group: "VAT_ID_PL",
    validator: Some(validators::pl_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `PT501964843`, `PT 501 964 843`.
pub(super) const VAT_ID_PT: PiiPattern = PiiPattern {
    name: "pii_vat_id_pt",
    pattern: r"\bPT ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}\b",
    entity_group: "VAT_ID_PT",
    validator: Some(validators::pt_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `RO18547290`, `RO 18547290`. Six to ten digits: the validator also takes
/// shorter CUIs, but two to five digits prove too little without a field name.
pub(super) const VAT_ID_RO: PiiPattern = PiiPattern {
    name: "pii_vat_id_ro",
    pattern: r"\bRO ?[1-9][0-9]{5,9}\b",
    entity_group: "VAT_ID_RO",
    validator: Some(validators::ro_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `SE556677889901`, `SE 556677-889901`.
pub(super) const VAT_ID_SE: PiiPattern = PiiPattern {
    name: "pii_vat_id_se",
    pattern: r"\bSE ?[0-9]{6}-?[0-9]{4}01\b",
    entity_group: "VAT_ID_SE",
    validator: Some(validators::se_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `SI50223054`, `SI 5022 3054`.
pub(super) const VAT_ID_SI: PiiPattern = PiiPattern {
    name: "pii_vat_id_si",
    pattern: r"\bSI ?[0-9]{4} ?[0-9]{4}\b",
    entity_group: "VAT_ID_SI",
    validator: Some(validators::si_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `SK2022749619`, `SK 202 274 96 19`.
pub(super) const VAT_ID_SK: PiiPattern = PiiPattern {
    name: "pii_vat_id_sk",
    pattern: r"\bSK ?[0-9]{3} ?[0-9]{3} ?[0-9]{2} ?[0-9]{2}\b",
    entity_group: "VAT_ID_SK",
    validator: Some(validators::sk_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `NO995525828MVA`, `NO 995 525 828 MVA`; the `MVA` suffix belongs to the
/// number and to the span.
pub(super) const VAT_ID_NO: PiiPattern = PiiPattern {
    name: "pii_vat_id_no",
    pattern: r"\bNO ?[0-9]{3} ?[0-9]{3} ?[0-9]{3} ?MVA\b",
    entity_group: "VAT_ID_NO",
    validator: Some(validators::no_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};

/// `GB980780684`, `GB 980 7806 84`, a branch `GB 980 7806 84 001`, and the
/// Northern Ireland form `XI 980 7806 84`.
pub(super) const VAT_ID_GB: PiiPattern = PiiPattern {
    name: "pii_vat_id_gb",
    pattern: r"\b(?:GB|XI) ?[0-9]{3} ?[0-9]{4} ?[0-9]{2}(?: ?[0-9]{3})?\b",
    entity_group: "VAT_ID_GB",
    validator: Some(validators::gb_vat_id),
    strength: ValidatorStrength::Checksum,
    base_score: 20,
    captured_value: false,
    requires_context: false,
    scored_only: true,
};
