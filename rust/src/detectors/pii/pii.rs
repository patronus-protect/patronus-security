// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    detectors::{
        MatchScore, NativeDetection, NativeMatchValidator, NativeRegexDetector, StructuredValue,
    },
    EvaluationResult,
};

use super::context::Evidence;
use super::context_anchors::PII_ANCHOR_PATTERNS;
use super::score::{self, PiiMode, ValidatorStrength};
use super::{common, context, de, driver_license, identifiers, intl, overlap, uk, us, vat};
use crate::detectors::anchors;
use crate::detectors::obfuscation::{Deobfuscated, Level};
use crate::EvidenceSpan;
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
    /// Emit only in the scored modes `balanced` and `recall`; `strict` never runs
    /// the rule (K05). Reserved for unbound checksum rules: the bare form of a
    /// value that strict reports only after its field name. The grouped US SSN
    /// is the one format rule here (B-SSN): its separators and SSA ranges stand
    /// in for a check digit.
    pub scored_only: bool,
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
    de::STEUER_ID_CONTEXT_FREE,
    de::STEUERNUMMER,
    de::RENTENVERSICHERUNG,
    de::HEALTH_INSURANCE_NUMBER,
    de::PHYSICIAN_NUMBER_LANR,
    de::PASSPORT_NUMBER,
    de::IDENTITY_CARD_NUMBER,
    driver_license::DE,
    driver_license::US,
    driver_license::IT,
    de::KFZ_KENNZEICHEN,
    us::SSN,
    us::SSN_PROXIMITY,
    us::SSN_CONTEXT_FREE,
    uk::NINO,
    vat::VAT_ID_DE,
    vat::VAT_ID_AT,
    vat::VAT_ID_CH,
    vat::VAT_ID_FR,
    vat::VAT_ID_NL,
    vat::VAT_ID_BE,
    vat::VAT_ID_IT,
    vat::VAT_ID_IT_PROXIMITY,
    vat::VAT_ID_ES,
    vat::VAT_ID_LU,
    vat::VAT_ID_LV,
    vat::VAT_ID_MT,
    vat::VAT_ID_PL,
    vat::VAT_ID_PT,
    vat::VAT_ID_RO,
    vat::VAT_ID_SE,
    vat::VAT_ID_SI,
    vat::VAT_ID_SK,
    vat::VAT_ID_NO,
    vat::VAT_ID_GB,
    de::PASSPORT_NUMBER_CONTEXT_FREE,
    de::PASSPORT_NUMBER_LEGACY,
    de::IDENTITY_CARD_NUMBER_CONTEXT_FREE,
    de::IDENTITY_CARD_NUMBER_LEGACY,
    vat::VAT_ID_BG,
    vat::VAT_ID_CY,
    vat::VAT_ID_CZ,
    vat::VAT_ID_DK,
    vat::VAT_ID_EE,
    vat::VAT_ID_EL,
    vat::VAT_ID_FI,
    vat::VAT_ID_HR,
    vat::VAT_ID_HU,
    vat::VAT_ID_IE,
    vat::VAT_ID_LT,
];

pub struct PiiPipeline {
    regexes: Vec<Regex>,
    anchor_gates: Vec<crate::detectors::anchor_gate::AnchorGate>,
    prefilters: Vec<Option<Regex>>,
    rule_ids: Vec<&'static str>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<NativeMatchValidator>>,
    capture_groups: Vec<Option<usize>>,
    structured_regexes: Vec<Option<Regex>>,
    structured_keys: Vec<Option<Regex>>,
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
        let mut structured_regexes = Vec::new();
        let mut structured_keys = Vec::new();

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
            // Field-bound rules capture their value after the field name, the IPv6
            // rules after what opens the address (B-IP); both name it `value`.
            capture_groups.push(regexes.last().and_then(|regex: &Regex| {
                regex.capture_names().position(|name| name == Some("value"))
            }));
            debug_assert!(!p.captured_value || capture_groups.last() == Some(&Some(1)));
            let structured = p.captured_value.then(|| structured_regexes_of(p.pattern));
            let (value, key) = structured.unzip();
            structured_regexes.push(value);
            structured_keys.push(key);
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
            structured_regexes,
            structured_keys,
            anchor_regexes,
        }
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    /// The verdict with the exact evidence spans (strict mode, every rule).
    pub fn scan(&self, text: &str) -> crate::detectors::RuleScan {
        self.detect(text).into()
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
        let strict = mode.min_score().is_none();
        let allows = |rule_id: &str| {
            allows_rule(rule_id)
                && !(strict
                    && PII_PATTERNS
                        .iter()
                        .any(|pattern| pattern.name == rule_id && pattern.scored_only))
        };
        let detection = self.detect_prepared_scored(prepared, allows, explain, mode.min_score());
        // K06: values behind zero-width, full-width or defanged characters (in
        // `recall` also spelled-out separators and spaced digits) are found in a
        // normalized view and mapped back to the original text.
        let level = if mode == PiiMode::Recall {
            Level::SpelledOut
        } else {
            Level::Invisible
        };
        let mut detection = match Deobfuscated::new(prepared.text(), level) {
            None => detection,
            Some(view) => {
                let normalized = self.detect_prepared_scored(
                    &crate::threat::NativeText::new(&view.text),
                    allows,
                    false,
                    mode.min_score(),
                );
                merge_deobfuscated(prepared.text(), detection, normalized, &view, mode)
            }
        };
        // K07: in the scored modes one value yields one competing label; strict
        // keeps both and marks the card or account inside an IBAN as secondary
        // evidence (decision T07).
        if strict {
            overlap::mark_secondary(&mut detection);
        } else {
            overlap::resolve(prepared.text(), &mut detection);
        }
        detection
    }

    /// Context of a match: the field the rule binds (its own field name or a
    /// structural key), else the structural key of the value, else two-sided
    /// proximity.
    fn context(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
        captures: &regex::Captures<'_>,
    ) -> Evidence {
        let pattern = &PII_PATTERNS[index];
        let text = prepared.text();
        let value = captures
            .get(self.capture_groups[index].unwrap_or(0))
            .unwrap();
        let structure =
            context::structure_evidence(prepared.structure(), value.range(), pattern.entity_group);
        if pattern.captured_value {
            // A regex match includes its field name; a structural match is the value
            // alone, and its key is the field.
            let structural = captures.get(0).unwrap().start() == value.start();
            return structure
                .filter(|evidence| structural && evidence.context.supports())
                .unwrap_or_else(|| Evidence::field_at(structural));
        }
        structure.unwrap_or_else(|| {
            context::evidence(text, (value.start(), value.end()), pattern.entity_group)
        })
    }
}

/// Adds the findings of the normalized view whose original span contains an
/// undone obfuscation (K06); every other finding of the view is already in
/// `detection`. Such a finding replaces the same-label findings it contains and
/// yields to any other same-label overlap. Its `matched_rules` entry carries
/// original offsets and `obfuscation`; findings that only the `recall` level
/// reveals lose [`score::SPELLED_OUT_PENALTY_POINTS`].
fn merge_deobfuscated(
    text: &str,
    mut detection: NativeDetection,
    normalized: NativeDetection,
    view: &Deobfuscated,
    mode: PiiMode,
) -> NativeDetection {
    // (normalized range, original range, label, obfuscation kinds, penalty points)
    let mut added = Vec::new();
    for span in normalized.evidence_spans {
        let range = view.original(span.start_byte..span.end_byte);
        let kinds = view.kinds(range.clone());
        if kinds.is_empty() {
            continue;
        }
        let mut score = span.score;
        let penalty = if kinds.iter().any(|kind| kind.level() == Level::SpelledOut) {
            score::SPELLED_OUT_PENALTY_POINTS
        } else {
            0
        };
        if penalty > 0 {
            score = penalized(span.score, penalty);
            if mode.min_score().is_some_and(|threshold| score < threshold) {
                continue;
            }
        }
        let overlaps = |other: &EvidenceSpan| {
            other.label == span.label
                && other.start_byte < range.end
                && range.start < other.end_byte
        };
        // A plain finding on the same span (spaced card digits) or one that the
        // normalized finding does not contain wins.
        if detection.evidence_spans.iter().any(|other| {
            overlaps(other)
                && ((other.start_byte..other.end_byte) == range
                    || !(range.start <= other.start_byte && other.end_byte <= range.end))
        }) {
            continue;
        }
        detection.evidence_spans.retain(|other| !overlaps(other));
        detection.evidence_spans.push(EvidenceSpan {
            label: span.label.clone(),
            text: text[range.clone()].to_string(),
            score,
            start_byte: range.start,
            end_byte: range.end,
            start_char: 0,
            end_char: 0,
        });
        added.push((
            span.start_byte..span.end_byte,
            range,
            span.label,
            kinds,
            penalty,
        ));
    }
    if added.is_empty() {
        return detection;
    }

    let rules = normalized
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let start = rule["start_byte"].as_u64()? as usize;
            let end = rule["end_byte"].as_u64()? as usize;
            let label = PII_PATTERNS
                .iter()
                .find(|pattern| rule["rule_id"] == pattern.name)?
                .entity_group;
            let (_, original, _, kinds, penalty) =
                added.iter().find(|(range, _, added_label, ..)| {
                    *range == (start..end) && added_label == label
                })?;
            let mut rule = rule.clone();
            rule["start_byte"] = original.start.into();
            rule["end_byte"] = original.end.into();
            for component in rule["components"].as_array_mut().into_iter().flatten() {
                let start = component["start_byte"].as_u64().unwrap_or_default() as usize;
                let end = component["end_byte"].as_u64().unwrap_or_default() as usize;
                if start < end {
                    let range = view.original(start..end);
                    component["start_byte"] = range.start.into();
                    component["end_byte"] = range.end.into();
                }
            }
            rule["obfuscation"] = kinds.iter().map(|kind| kind.as_str()).collect();
            // Each rule keeps its own score (pii_iban_de 0.90, pii_iban_generic 0.80 on
            // the same value); only the recall penalty applies to it.
            if let Some(own) = rule["score"].as_f64() {
                rule["score"] = serde_json::json!(penalized(own, *penalty));
            }
            Some(rule)
        })
        .collect::<Vec<_>>();
    let matched_rules = detection
        .details
        .entry("matched_rules".into())
        .or_insert_with(|| serde_json::json!([]));
    if let Some(matched_rules) = matched_rules.as_array_mut() {
        matched_rules.extend(rules);
    }

    let spans = &mut detection.evidence_spans;
    spans.sort_by_key(|span| (span.start_byte, span.end_byte));
    crate::detectors::populate_char_offsets(text, spans);
    let result = &mut detection.result;
    if !spans.iter().any(|span| span.label == result.class_name) {
        result.class_name = spans[0].label.clone();
    }
    result.confidence = spans.iter().map(|span| span.score).fold(0.0, f64::max);
    detection
}

/// `score` minus `points` hundredths, floored at zero.
fn penalized(score: f64, points: u8) -> f64 {
    f64::from(((score * 100.0).round() as i16 - i16::from(points)).max(0)) / 100.0
}

/// Whether the field part `key` of a rule accepts the normalized structural key
/// `name` (`customer id`), or the key without spaces for compounds that the rule
/// names in one word (`matrikelNummer`, `kunden_nummer`).
fn key_accepts(key: &Regex, name: &str) -> bool {
    key.is_match(&format!("{name}: "))
        || (name.contains(' ') && key.is_match(&format!("{}: ", name.replace(' ', ""))))
}

/// Structural regexes of a field-bound rule (K04): the value regex
/// `(?P<value>…)\z` that a structural value must match in full, with the rule's
/// leading flags, and the key regex: the rule's field part before the value,
/// which must accept `"{key}: "` for a normalized key. A key thus binds a rule
/// only if the rule accepts it as field name; the wider lexicon only scores.
fn structured_regexes_of(pattern: &str) -> (Regex, Regex) {
    let flags = pattern
        .strip_prefix("(?")
        .and_then(|rest| rest.split_once(')'))
        .filter(|(flags, _)| flags.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .map_or(String::new(), |(flags, _)| format!("(?{flags})"));
    let start = pattern
        .find("(?P<value>")
        .expect("field-bound PII rules capture a named value");
    let (mut depth, mut escaped, mut class) = (0usize, false, false);
    let mut end = None;
    for (offset, byte) in pattern.as_bytes()[start..].iter().enumerate() {
        match byte {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'[' if !class => class = true,
            b']' if class => class = false,
            b'(' if !class => depth += 1,
            b')' if !class => {
                depth -= 1;
                if depth == 0 {
                    end = Some(start + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let value = &pattern[start..end.expect("balanced value group")];
    (
        Regex::new(&format!("{flags}{value}\\z")).unwrap(),
        Regex::new(&format!("\\A(?:{})\\z", &pattern[..start])).unwrap(),
    )
}

impl PiiPipeline {
    /// Key of the structural field that holds exactly `value` and binds rule `index`.
    fn structural_key(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
        value: std::ops::Range<usize>,
    ) -> Option<std::ops::Range<usize>> {
        let key = self.structured_keys[index].as_ref()?;
        let fields = prepared.structure();
        fields
            .at(value)
            .find(|field| {
                field
                    .names
                    .iter()
                    .any(|&name| key_accepts(key, &fields.names()[name]))
            })
            .map(|field| field.key.clone())
    }
}

impl NativeRegexDetector for PiiPipeline {
    fn allows_match(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
        captures: &regex::Captures<'_>,
    ) -> bool {
        let pattern = &PII_PATTERNS[index];
        let text = prepared.text();
        if pattern.scored_only && !context::stands_alone(text, captures.get(0).unwrap().range()) {
            return false;
        }
        if pattern.requires_context {
            // Context-bound rules emit the whole match; it is the value. A
            // structural key decides before proximity.
            let value = captures.get(0).unwrap();
            let supported = context::structure_evidence(
                prepared.structure(),
                value.range(),
                pattern.entity_group,
            )
            .map_or_else(
                || context::supports(text, (value.start(), value.end()), pattern.entity_group),
                |evidence| evidence.context.supports(),
            );
            if !supported {
                return false;
            }
        }
        // The field name of a field-bound match: before the value in the match, or
        // the structural key that bound it (K04).
        let field = pattern.captured_value.then(|| {
            let (whole, value) = (captures.get(0).unwrap(), captures.name("value").unwrap());
            if whole.start() < value.start() {
                whole.start()..value.start()
            } else {
                self.structural_key(index, prepared, value.range())
                    .unwrap_or(value.start()..value.start())
            }
        });
        match self.rule_ids[index] {
            "pii_phone_international" | "pii_phone_de" => {
                context::opens_phone_number(text, captures.get(0).unwrap().start())
            }
            "pii_credit_card" => context::card_position(text, captures.get(0).unwrap().range()),
            // An SSN term near the value does not make a fragment of a longer
            // number (`401127789-0`) an SSN.
            "pii_ssn_us_proximity" => context::stands_alone(text, captures.get(0).unwrap().range()),
            "pii_passport_number_de_context_free" | "pii_identity_card_number_de_context_free" => {
                !context::foreign_field(
                    prepared.structure(),
                    text,
                    captures.get(0).unwrap().range(),
                    pattern.entity_group,
                )
            }
            "pii_passport_number_de_legacy" | "pii_identity_card_number_de_legacy" => {
                // A key that names another value overrides a document term
                // found by proximity; a document term inside the key keeps it.
                let value = captures.get(0).unwrap().range();
                let fields = prepared.structure();
                !context::foreign_field(fields, text, value.clone(), pattern.entity_group)
                    || context::key_holds_term(fields, text, value, pattern.entity_group)
            }
            "pii_ipv4" => context::ipv4_position(text, captures.get(0).unwrap().start()),
            "pii_ipv6_full" | "pii_ipv6_compressed" | "pii_ipv6_loopback" => {
                context::ipv6_position(text, captures.name("value").unwrap().end())
            }
            "pii_swift_bic_context" => {
                let value = captures.name("value").unwrap();
                let structural = captures.get(0).unwrap().start() == value.start();
                // Lowercase values remain valid in explicit assignments (and as
                // structural values). In prose, require conventional uppercase
                // codes, not "Swift code is powerful".
                structural
                    || text[field.unwrap()].contains([':', '#', '='])
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
                let field = field.unwrap();
                let field_text = &text[field.clone()];
                let generic_field = self.rule_ids[index] == "pii_employee_id_ocr_field"
                    || field_text.to_lowercase().starts_with("kennung");
                // The OCR regex consumes a leading newline/pipe. That separator
                // must remain a context boundary rather than exposing the prior field.
                let field_start = field.start
                    + field_text
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

    /// The trait's unscored detection is `strict`: scored-only rules stay off.
    fn detect_prepared_with_options<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        self.detect_prepared_with_mode(prepared, allows_rule, explain, PiiMode::Strict)
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

    fn structured_regexes(&self) -> Option<&[Option<Regex>]> {
        Some(&self.structured_regexes)
    }

    fn structured_values(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
    ) -> Vec<StructuredValue> {
        let fields = prepared.structure();
        if fields.is_empty() {
            return Vec::new();
        }
        let Some(key) = &self.structured_keys[index] else {
            return Vec::new();
        };
        let names: Vec<bool> = fields
            .names()
            .iter()
            .map(|name| key_accepts(key, name))
            .collect();
        fields
            .iter()
            .filter(|field| field.names.iter().any(|&name| names[name]))
            .map(|field| StructuredValue {
                key: field.key.clone(),
                value: field.value.clone(),
                carrier: field.carrier.as_str(),
            })
            .collect()
    }

    fn preserve_cross_label_overlaps(&self) -> bool {
        true
    }

    fn match_score(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
        captures: &regex::Captures<'_>,
    ) -> MatchScore {
        let evidence = self.context(index, prepared, captures);
        MatchScore {
            score: score::score(&PII_PATTERNS[index], evidence.context),
            context: Some(evidence.to_json()),
        }
    }

    fn finalize_spans(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        spans: &mut Vec<crate::EvidenceSpan>,
    ) {
        let text = prepared.text();
        let rule_index = |name: &str| {
            self.rule_ids
                .iter()
                .position(|rule_id| *rule_id == name)
                .expect("PII payment-card rules must be present")
        };
        let card_index = rule_index("pii_credit_card");
        let has_payment_card =
            context::has_payment_card(text, 0..text.len(), &self.regexes[card_index]);
        // A table column headed `cvc`/`cvv` types its values; a CVV field elsewhere
        // (`CVV: 123`, a `cvv` key) still needs a reported card.
        let column_cvvs: Vec<_> = if spans.iter().any(|span| span.label == "CREDITCARD_CVV") {
            self.structured_values(rule_index("pii_credit_card_cvv"), prepared)
                .into_iter()
                .filter(|structured| matches!(structured.carrier, "csv" | "table"))
                .map(|structured| structured.value)
                .collect()
        } else {
            Vec::new()
        };
        spans.retain(|span| {
            let coupled_cvv = span.label == "CREDITCARD_CVV"
                && (has_payment_card || column_cvvs.contains(&(span.start_byte..span.end_byte)));
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
