// SPDX-License-Identifier: AGPL-3.0-only
use crate::EvaluationResult;

use super::validators;
use regex::{Regex, RegexSet};

/// A single PII heuristic pattern.
pub struct PiiPattern {
    /// Unique name used for logging / debugging.
    pub name: &'static str,
    /// Regex pattern string.
    pub pattern: &'static str,
    /// Entity group label used in `NerResult` and `PlaceholderEncoder`.
    pub entity_group: &'static str,
    /// Optional validator called after a regex match to reduce false positives.
    pub validator: Option<fn(&str) -> bool>,
}

pub static PII_PATTERNS: &[PiiPattern] = &[
    // ── Email ────────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_email",
        pattern: r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        entity_group: "EMAIL",
        validator: None,
    },
    // ── IP-Adressen ─────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_ipv4",
        pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
    },
    PiiPattern {
        name: "pii_ipv6_full",
        pattern: r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
    },
    PiiPattern {
        name: "pii_ipv6_compressed",
        pattern: r"\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
    },
    PiiPattern {
        name: "pii_ipv6_loopback",
        pattern: r"::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b",
        entity_group: "IP_ADDRESS",
        validator: Some(validators::ip_address),
    },
    // ── Telefon ──────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_phone_international",
        pattern: r"\+[1-9]\d{6,14}\b",
        entity_group: "PHONE",
        validator: None,
    },
    PiiPattern {
        name: "pii_phone_de",
        pattern: r"(?:\+49|0049)\s?[1-9][\d\s\-\/]{5,12}\d",
        entity_group: "PHONE",
        validator: None,
    },
    PiiPattern {
        name: "pii_phone_us",
        pattern: r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b",
        entity_group: "PHONE",
        validator: None,
    },
    // ── Kreditkarte ──────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_credit_card",
        pattern: r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        entity_group: "CREDITCARD",
        validator: Some(validators::luhn),
    },
    // ── IBAN ─────────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_iban_de",
        pattern: r"\bDE\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{2}\b",
        entity_group: "IBAN",
        validator: Some(validators::mod97),
    },
    PiiPattern {
        name: "pii_iban_generic",
        pattern: r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,26}\b",
        entity_group: "IBAN",
        validator: Some(validators::mod97),
    },
    // ── SWIFT / BIC ─────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_swift_bic_context",
        pattern: r"(?i)\b(?:SWIFT|BIC)(?:\s+code)?(?:\s+is)?\s*[:#\-]?\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        entity_group: "SWIFT_CODE",
        validator: None,
    },
    // ── Deutsche Steuer-IDs ──────────────────────────────────────────────────
    PiiPattern {
        name: "pii_steuer_id_de",
        pattern: r"\b[1-9]\d\s?\d{3}\s?\d{5}\s?\d\b",
        entity_group: "STEUERID",
        validator: Some(validators::steuer_id),
    },
    PiiPattern {
        name: "pii_ust_id_de",
        pattern: r"\bDE\s?\d{3}\s?\d{3}\s?\d{3}\b",
        entity_group: "USTID",
        validator: None,
    },
    // ── Deutsche Ausweise / Sozialversicherung ───────────────────────────────
    PiiPattern {
        name: "pii_rentenversicherung_de",
        pattern: r"\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{2}\s?\d\b",
        entity_group: "SOCIALID",
        validator: None,
    },
    PiiPattern {
        name: "pii_kfz_kennzeichen_de",
        pattern: r"\b[A-ZÄÖÜ]{1,3}[\-\s][A-Z]{1,2}\s?\d{1,4}(?:[EH])?\b",
        entity_group: "LICENSEPLATE",
        validator: None,
    },
    // ── US / UK ──────────────────────────────────────────────────────────────
    PiiPattern {
        name: "pii_ssn_us",
        pattern: r"\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b",
        entity_group: "SSN",
        validator: None,
    },
    PiiPattern {
        name: "pii_ni_uk",
        pattern: r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
        entity_group: "NATIONALID",
        validator: None,
    },
    // ── Datumsformat (nur mit Kontext-Keyword) ───────────────────────────────
    PiiPattern {
        name: "pii_date_dob_context",
        pattern: r"(?i)\b(geburtsdatum|geboren\s+am|date\s+of\s+birth|dob\s*:)\b.{0,30}\b\d{1,2}[.\/\-]\d{1,2}[.\/\-]\d{2,4}\b",
        entity_group: "DOB",
        validator: None,
    },
    // ── PLZ + Stadt (nur als Kombination) ────────────────────────────────────
    PiiPattern {
        name: "pii_plz_stadt_de",
        pattern: r"\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß]{2,}",
        entity_group: "POSTALADDRESS",
        validator: None,
    },
];

pub struct PiiPipeline {
    set: RegexSet,
    regexes: Vec<Regex>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<fn(&str) -> bool>>,
}

impl PiiPipeline {
    pub fn new() -> Self {
        let mut regexes = Vec::new();
        let mut patterns = Vec::new();
        let mut entity_groups = Vec::new();
        let mut validators = Vec::new();

        for p in PII_PATTERNS {
            patterns.push(p.pattern);
            regexes.push(Regex::new(p.pattern).unwrap());
            entity_groups.push(p.entity_group);
            validators.push(p.validator);
        }

        let set = RegexSet::new(patterns).unwrap();
        PiiPipeline {
            set,
            regexes,
            entity_groups,
            validators,
        }
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let matches = self.set.matches(text);
        for idx in matches.iter() {
            if let Some(validator) = self.validators[idx] {
                if let Some(mat) = self.regexes[idx].find(text) {
                    if validator(mat.as_str()) {
                        return EvaluationResult {
                            class_name: self.entity_groups[idx].to_string(),
                            confidence: 1.0,
                            level: "L1".to_string(),
                        };
                    }
                }
            } else {
                return EvaluationResult {
                    class_name: self.entity_groups[idx].to_string(),
                    confidence: 1.0,
                    level: "L1".to_string(),
                };
            }
        }

        EvaluationResult {
            class_name: "safe".to_string(),
            confidence: 1.0,
            level: "L1".to_string(),
        }
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}
