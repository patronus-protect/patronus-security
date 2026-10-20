// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    detectors::{MatchScore, NativeDetection, NativeMatchValidator, NativeRegexDetector},
    EvaluationResult,
};

use super::context::Evidence;
use super::context_anchors::PII_ANCHOR_PATTERNS;
use super::score::{self, PiiMode, ValidatorStrength};
use super::{common, context, de, identifiers, intl, uk, us, validators};
use crate::detectors::anchors;
use regex::Regex;

/// A single PII heuristic pattern.
pub struct PiiPattern {
    /// Stable public rule id used by `ScanGateMatrix::rules`.
    pub name: &'static str,
    /// Regex pattern string.
    pub pattern: &'static str,
    /// Entity group label used in `NerResult` and `PlaceholderEncoder`.
    pub entity_group: &'static str,
    /// Optional validator called after a regex match to reduce false positives.
    pub validator: Option<fn(&str) -> bool>,
    /// What `validator` proves: checksum, format only, or nothing (no validator).
    pub strength: ValidatorStrength,
    /// Score-model points (1–100) for the regex form alone; see [`score`].
    pub base_score: u8,
    /// For anchor-bound patterns, emit only the named `value` capture.
    pub captured_value: bool,
    /// Emit only when the context engine finds a support term of the label near
    /// the value and no nearer counter-context term, in every mode (K03).
    pub requires_context: bool,
}

/// All PII rules in evaluation order. The rules live in regional modules; the
/// order stays here because it is behaviour: the first match sets `class_name`
/// and an earlier rule keeps its span against later same-label overlaps.
pub static PII_PATTERNS: &[PiiPattern] = &[
    common::EMAIL,
    common::IPV4,
    common::IPV6_FULL,
    common::IPV6_COMPRESSED,
    common::IPV6_LOOPBACK,
    common::PHONE_INTERNATIONAL,
    de::PHONE,
    de::PHONE_NATIONAL_CONTEXT,
    de::PHONE_NATIONAL_PROXIMITY,
    us::PHONE,
    common::MAC_ADDRESS,
    intl::IBAN_DE,
    intl::IBAN_GENERIC,
    intl::CREDIT_CARD,
    intl::CREDIT_CARD_CVV,
    intl::CREDIT_CARD_EXPIRY,
    intl::SWIFT_BIC_CONTEXT,
    identifiers::EMPLOYEE_ID,
    identifiers::EMPLOYEE_ID_OCR_FIELD,
    identifiers::EMPLOYEE_ID_PREFIXED,
    identifiers::CUSTOMER_ID,
    identifiers::PATIENT_ID,
    identifiers::STUDENT_ID,
    identifiers::APPLICANT_ID,
    identifiers::USERNAME,
    identifiers::DATE_OF_BIRTH,
    identifiers::DATE_OF_BIRTH_WRITTEN_DAY_FIRST,
    identifiers::DATE_OF_BIRTH_WRITTEN_MONTH_FIRST,
    identifiers::FINANCIAL_ACCOUNT_NUMBER,
    de::STEUER_ID,
    de::STEUERNUMMER,
    de::RENTENVERSICHERUNG,
    de::HEALTH_INSURANCE_NUMBER,
    de::PHYSICIAN_NUMBER_LANR,
    de::PASSPORT_NUMBER,
    de::IDENTITY_CARD_NUMBER,
    de::DRIVER_LICENSE_NUMBER,
    de::KFZ_KENNZEICHEN,
    us::SSN,
    uk::NINO,
];

pub struct PiiPipeline {
    regexes: Vec<Regex>,
    anchor_gates: Vec<crate::detectors::anchor_gate::AnchorGate>,
    prefilters: Vec<Option<Regex>>,
    rule_ids: Vec<&'static str>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<NativeMatchValidator>>,
    capture_groups: Vec<Option<usize>>,
    anchor_regexes: Vec<Regex>,
}

impl Default for PiiPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiPipeline {
    pub fn new() -> Self {
        let mut regexes = Vec::new();
        let mut anchor_gates = Vec::new();
        let mut prefilters = Vec::new();
        let mut entity_groups = Vec::new();
        let mut rule_ids = Vec::new();
        let mut validators = Vec::new();
        let mut capture_groups = Vec::new();

        for p in PII_PATTERNS {
            regexes.push(Regex::new(p.pattern).unwrap());
            anchor_gates.push(crate::detectors::anchor_gate::AnchorGate::regex(
                p.pattern, false,
            ));
            // Audited positive word-boundary assertions only. The relaxed search
            // is a necessary condition; original captures and validators decide.
            prefilters.push(
                matches!(
                    p.name,
                    "pii_ipv4"
                        | "pii_phone_us"
                        | "pii_steuer_id_de"
                        | "pii_steuernummer_de"
                        | "pii_rentenversicherung_de"
                )
                .then(|| Regex::new(&p.pattern.replace(r"\b", "")).unwrap()),
            );
            entity_groups.push(p.entity_group);
            rule_ids.push(p.name);
            validators.push(p.validator);
            capture_groups.push(p.captured_value.then_some(1));
        }

        let anchor_regexes = PII_ANCHOR_PATTERNS
            .iter()
            .map(|anchor| Regex::new(anchor.pattern).unwrap())
            .collect();
        PiiPipeline {
            regexes,
            anchor_gates,
            prefilters,
            rule_ids,
            entity_groups,
            validators,
            capture_groups,
            anchor_regexes,
        }
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }

    /// Detect with an explicit output mode. `PiiMode::Strict` is identical to
    /// the trait's `detect_prepared_with_options`.
    pub(crate) fn detect_prepared_with_mode<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
        mode: PiiMode,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        self.detect_prepared_scored(prepared, allows_rule, explain, mode.min_score())
    }

    /// Context of a match: the field the rule binds, else two-sided proximity.
    fn context(&self, index: usize, text: &str, captures: &regex::Captures<'_>) -> Evidence {
        let pattern = &PII_PATTERNS[index];
        if pattern.captured_value {
            return Evidence::field();
        }
        let value = captures.get(0).unwrap();
        context::evidence(text, (value.start(), value.end()), pattern.entity_group)
    }
}

impl NativeRegexDetector for PiiPipeline {
    fn allows_match(&self, index: usize, text: &str, captures: &regex::Captures<'_>) -> bool {
        let pattern = &PII_PATTERNS[index];
        if pattern.requires_context {
            // Context-bound rules emit the whole match; it is the value.
            let value = captures.get(0).unwrap();
            if !context::supports(text, (value.start(), value.end()), pattern.entity_group) {
                return false;
            }
        }
        match self.rule_ids[index] {
            "pii_swift_bic_context" => {
                let value = captures.name("value").unwrap();
                let field = &text[captures.get(0).unwrap().start()..value.start()];
                // Lowercase values remain valid in explicit assignments. In prose,
                // require conventional uppercase codes, not "Swift code is powerful".
                field.contains([':', '#', '='])
                    || !value.as_str().bytes().any(|byte| byte.is_ascii_lowercase())
            }
            "pii_credit_card_expiry" => {
                let card_index = self
                    .rule_ids
                    .iter()
                    .position(|id| *id == "pii_credit_card")
                    .expect("PII credit-card rule must be present");
                context::payment_expiry(
                    text,
                    captures.get(0).unwrap().start(),
                    &self.regexes[card_index],
                )
            }
            "pii_employee_id" | "pii_employee_id_ocr_field" => {
                let whole = captures.get(0).unwrap();
                let generic_field = self.rule_ids[index] == "pii_employee_id_ocr_field"
                    || whole.as_str().to_lowercase().starts_with("kennung");
                // The OCR regex consumes a leading newline/pipe. That separator
                // must remain a context boundary rather than exposing the prior field.
                let field_start = whole.start()
                    + whole
                        .as_str()
                        .find(|ch: char| !ch.is_whitespace() && ch != '|')
                        .unwrap_or(0);
                !generic_field
                    || context::employee_identifier(
                        text,
                        field_start,
                        captures.name("value").unwrap().as_str(),
                    )
            }
            _ => true,
        }
    }

    fn anchor_gates(&self) -> &[crate::detectors::anchor_gate::AnchorGate] {
        &self.anchor_gates
    }
    fn prefilters(&self) -> Option<&[Option<Regex>]> {
        Some(&self.prefilters)
    }
    fn regexes(&self) -> &[Regex] {
        &self.regexes
    }

    fn entity_groups(&self) -> &[&'static str] {
        &self.entity_groups
    }

    fn rule_ids(&self) -> &[&'static str] {
        &self.rule_ids
    }

    fn validators(&self) -> &[Option<fn(&str) -> bool>] {
        &self.validators
    }

    fn capture_groups(&self) -> Option<&[Option<usize>]> {
        Some(&self.capture_groups)
    }

    fn preserve_cross_label_overlaps(&self) -> bool {
        true
    }

    fn match_score(&self, index: usize, text: &str, captures: &regex::Captures<'_>) -> MatchScore {
        let evidence = self.context(index, text, captures);
        MatchScore {
            score: score::score(&PII_PATTERNS[index], evidence.context),
            context: Some(evidence.to_json()),
        }
    }

    fn finalize_spans(&self, text: &str, spans: &mut Vec<crate::EvidenceSpan>) {
        let card_index = self
            .rule_ids
            .iter()
            .position(|rule_id| *rule_id == "pii_credit_card")
            .expect("PII credit-card rule must be present");
        let has_payment_card = self.regexes[card_index]
            .find_iter(text)
            .any(|matched| validators::luhn(matched.as_str()));
        spans.retain(|span| {
            let coupled_cvv = span.label == "CREDITCARD_CVV" && has_payment_card;
            (span.end_byte - span.start_byte >= 4 || coupled_cvv)
                && (span.label != "CREDITCARD_CVV" || coupled_cvv)
        });
    }

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        anchors::details(text, &self.anchor_regexes, PII_ANCHOR_PATTERNS)
    }
}

#[cfg(test)]
mod prefilter_tests {
    use super::*;
    #[test]
    fn pii_prefilters_preserve_bilingual_results_and_captures() {
        let optimized = PiiPipeline::new();
        let mut reference = PiiPipeline::new();
        reference.prefilters.iter_mut().for_each(|p| *p = None);
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/l1_bilingual_rules.json"
        ))
        .unwrap();
        for case in cases
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["category"] == "pii")
        {
            for language in ["de", "en"] {
                for prefix in ["", "Grüße İ – ", "ö", "_"] {
                    for suffix in ["", "ü", "."] {
                        let text = format!("{prefix}{}{suffix}", case[language].as_str().unwrap());
                        let a = optimized.detect(&text);
                        let b = reference.detect(&text);
                        assert_eq!(a.result.class_name, b.result.class_name, "{text}");
                        assert_eq!(a.details, b.details, "{text}");
                        assert_eq!(
                            serde_json::to_value(&a.evidence_spans).unwrap(),
                            serde_json::to_value(&b.evidence_spans).unwrap(),
                            "{text}"
                        );
                        for (re, pre) in optimized.regexes.iter().zip(&optimized.prefilters) {
                            if let Some(pre) = pre {
                                assert_eq!(pre.as_str(), re.as_str().replace(r"\b", ""));
                                assert!(!re.is_match(&text) || pre.is_match(&text), "{text}");
                            }
                        }
                    }
                }
            }
        }
    }
}
