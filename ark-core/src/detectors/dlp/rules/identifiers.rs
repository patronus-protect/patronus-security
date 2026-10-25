// SPDX-License-Identifier: MIT OR Apache-2.0
//! German and business record identifiers (anchor-bound, default off).
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, ValidatorStrength};

pub(super) const RULES: &[DlpPattern] = &[
    // ── German and business identifiers (anchor-bound) ─────────────────────
    DlpPattern {
        name: "dlp_de_vat_id",
        pattern: r"(?i)\b(?:USt[.-]?IdNr|Umsatzsteuer(?:-Identifikationsnummer)?|VAT[ -]?ID)\.?\s*(?::|=|lautet)?\s*(DE\s?\d{3}\s?\d{3}\s?\d{3})\b",
        entity_group: "dlp.de.vat_id",
        validator: None,
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["ust", "umsatzsteuer", "vat"],
        ),
    },
    DlpPattern {
        name: "dlp_de_commercial_register_number",
        pattern: r"(?i)\b((?:HR[AB]|VR|PR|GnR)\s*\d{1,8})\b",
        entity_group: "dlp.de.commercial_register_number",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["hr", "vr", "pr", "gnr"]),
    },
    DlpPattern {
        name: "dlp_de_facility_number_bsnr",
        pattern: r"(?i)\b(?:BSNR|Betriebsst(?:ä|ae)ttennummer|(?:medical[ \t]+)?facility[ \t]+number)\b\s*(?::|=|lautet)?\s*(\d{9})\b",
        entity_group: "dlp.de.facility_number_bsnr",
        validator: None,
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["bsnr", "betriebsst", "facility"],
        ),
    },
    DlpPattern {
        name: "dlp_record_case_id",
        pattern: r"(?i)\b(?:Aktenzeichen|Fallnummer|Case[ -]?ID|Vorgangsnummer)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.case_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::None,
            "ark",
            &["aktenzeichen", "fallnummer", "case", "vorgangsnummer"],
        ),
    },
    DlpPattern {
        name: "dlp_record_contract_id",
        pattern: r"(?i)\b(?:Vertragsnummer|Vertrags[ -]?ID|Contract[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.contract_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(ValidatorStrength::None, "ark", &["vertrags", "contract"]),
    },
    DlpPattern {
        name: "dlp_record_claim_id",
        pattern: r"(?i)\b(?:Schadennummer|Leistungsfallnummer|Claim[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.claim_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::None,
            "ark",
            &["schadennummer", "leistungsfallnummer", "claim"],
        ),
    },
    DlpPattern {
        name: "dlp_record_order_id",
        pattern: r"(?i)\b(?:Bestellnummer|Auftragsnummer|Order[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.order_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::None,
            "ark",
            &["bestellnummer", "auftragsnummer", "order"],
        ),
    },
    DlpPattern {
        name: "dlp_record_invoice_id",
        pattern: r"(?i)\b(?:Rechnungsnummer|Rechnungs[ -]?ID|Invoice[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.invoice_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(ValidatorStrength::None, "ark", &["rechnungs", "invoice"]),
    },
    DlpPattern {
        name: "dlp_project_id",
        pattern: r"(?i)\b(?:Projekt[ -]?(?:ID|Nummer)|Project[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.project_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(ValidatorStrength::None, "ark", &["projekt", "project"]),
    },
    DlpPattern {
        name: "dlp_organization_id",
        pattern: r"(?i)\b(?:Organisations[ -]?ID|Unternehmens[ -]?ID|Mandanten[ -]?ID|Tenant[ -]?ID|Organization[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.organization_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::None,
            "ark",
            &[
                "organisations",
                "unternehmens",
                "mandanten",
                "tenant",
                "organization",
            ],
        ),
    },
];

fn is_identifier_value(candidate: &str) -> bool {
    candidate.chars().any(|ch| ch.is_ascii_digit())
}
