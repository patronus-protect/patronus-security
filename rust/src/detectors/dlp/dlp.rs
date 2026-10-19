// SPDX-License-Identifier: GPL-3.0-only
use crate::detectors::anchors::{self, AnchorPattern};
use crate::{
    detectors::{NativeMatchValidator, NativeRegexDetector},
    EvaluationResult,
};
use regex::Regex;
use std::ops::Range;

use super::rules::{self, ExampleCheck};

/// A single DLP heuristic pattern (credentials / secrets).
#[derive(Clone, Copy)]
pub struct DlpPattern {
    /// Stable public rule id used by `ScanGateMatrix::rules`.
    pub name: &'static str,
    pub pattern: &'static str,
    /// Entity group label — used in `NerResult` and `PlaceholderEncoder`.
    pub entity_group: &'static str,
    /// Optional post-regex validator.
    pub validator: Option<fn(&str) -> bool>,
    /// Optional capture group containing only the actionable value.
    pub span_group: Option<usize>,
}

/// Shared DLP rule defaults for Rust, Python, and HTTP gateway execution.
pub(crate) fn default_rule_enabled(rule_id: &str) -> bool {
    if !rule_id.starts_with("dlp_") {
        return true;
    }
    if matches!(
        rule_id,
        "dlp_mcp_runtime_risk" | "dlp_mcp_policy" | "dlp_destructive_operation"
    ) {
        return false;
    }
    DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .is_none_or(|pattern| {
            matches!(
                pattern.entity_group,
                "API_KEY"
                    | "CLOUD_KEY"
                    | "CREDENTIAL"
                    | "CRYPTO_KEY"
                    | "PASSWORD_HASH"
                    | "PAYMENT_KEY"
                    | "PRIVATE_KEY"
                    | "SECRET_TOKEN"
            )
        })
}

/// Context facts for downstream DLP analysis. Anchors describe nearby content
/// but never become findings by themselves.
static DLP_ANCHOR_PATTERNS: &[AnchorPattern] = &[
    AnchorPattern {
        category: "credentials_secrets",
        strength: "strong",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:passwort|kennwort|zugangsdaten|anmeldedaten|api[ _-]?(?:key|schl(?:ü|ue)ssel)|zugangs[ _-]?schl(?:ü|ue)ssel|access[ _-]?key|secret[ _-]?access[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth(?:entication|orization)?[ _-]?token|client[ _-]?secret|client[ _-]?credentials|service[ _-]?account[ _-]?key|encryption[ _-]?key|master[ _-]?key|signing[ _-]?key|private[ _-]?key|secret[ _-]?key|shared[ _-]?secret|webhook[ _-]?secret|database[ _-]?password|connection[ _-]?string|database[ _-]?url|jdbc[ _-]?url|mongodb[ _-]?uri|credentials?|login[ _-]?credentials?|password|passwd|password[ _-]?hash)\b",
    },
    AnchorPattern {
        category: "credentials_secrets",
        strength: "weak",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:token|secret|schl(?:ü|ue)ssel|credential|login|pwd)\b",
    },
    AnchorPattern {
        category: "credentials_secrets",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?m)\b(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|GITHUB_TOKEN|GITLAB_TOKEN|NPM_TOKEN|SLACK_TOKEN|DB_PASSWORD|DATABASE_URL|WEBHOOK_SECRET|SIGNING_KEY|SESSION_SECRET|PRIVATE_KEY|SECRET_KEY)\b",
    },
    AnchorPattern {
        category: "auth_header_cookie",
        strength: "strong",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:authorization|proxy-authorization|bearer[ 	]+token|basic[ 	]+auth(?:entication)?|x-api-key|cookie|set-cookie|session[ _-]?(?:id|token)|jsessionid|phpsessid|auth[ _-]?cookie|csrf[ _-]?token|xsrf[ _-]?token|x-csrf-token|x-xsrf-token|signed[ _-]?url|x-amz-signature|x-goog-signature)\b",
    },
    AnchorPattern {
        category: "business_record_identifier",
        strength: "strong",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:ust[.-]?(?:idnr|id|ident(?:ifikationsnummer)?)|umsatzsteuer(?:-identifikationsnummer)?|mehrwertsteuer[ _-]?id|vat[ _-]?(?:id|number)|handelsregister(?:nummer|eintrag)|register(?:nummer|zeichen)|hr[ab]|gnr|vereinsregister(?:nummer)?|partnerschaftsregister(?:nummer)?|bsnr|betriebsstättennummer|betriebsstaettennummer|praxisnummer|aktenzeichen|geschäftszeichen|geschaeftszeichen|fallnummer|fall[ _-]?id|vorgangsnummer|vorgangs[ _-]?id|case[ _-]?(?:id|number|reference)|file[ _-]?number|vertragsnummer|vertrags[ _-]?id|contract[ _-]?(?:id|number|reference)|policynummer|policy[ _-]?number|schadennummer|leistungsfallnummer|claim[ _-]?(?:id|number|reference)|bestellnummer|auftragsnummer|order[ _-]?(?:id|number|reference)|purchase[ _-]?order|rechnungsnummer|rechnungs[ _-]?id|invoice[ _-]?(?:id|number|reference)|belegnummer|projekt(?:nummer|[ _-]?id)|project[ _-]?(?:id|number|code)|organisations[ _-]?id|unternehmens[ _-]?(?:id|kennung)|firmenkennung|mandanten[ _-]?(?:id|nummer)|tenant[ _-]?(?:id|number)|organization[ _-]?(?:id|number)|company[ _-]?(?:id|number))\b",
    },
    AnchorPattern {
        category: "internal_business_metric",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:gehalt|jahresgehalt|bruttogehalt|grundgehalt|salary|annual[ _-]?salary|base[ _-]?salary|ebitda[ _-]?marge|ebit[ _-]?marge|rohertragsmarge|deckungsbeitrag|bruttomarge|nettomarge|gross[ _-]?margin|net[ _-]?margin|contribution[ _-]?margin|annual[ _-]?recurring[ _-]?revenue|monthly[ _-]?recurring[ _-]?revenue|arr|mrr|cash[ _-]?burn|burn[ _-]?rate|runway|umsatzplanung|umsatzprognose|revenue[ _-]?forecast|sales[ _-]?forecast|budgetplanung|planwert|istwert|forecast)\b",
    },
    AnchorPattern {
        category: "internal_business_metric",
        strength: "weak",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:marge|umsatz|rohertrag|ebitda|ebit|revenue|margin|budget|target|actuals?)\b",
    },
    AnchorPattern {
        category: "source_code_config",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?m)^[ \t]*(?:```[A-Za-z0-9_+.-]*|#!\s*/(?:usr/)?bin/(?:env[ \t]+)?(?:bash|sh|zsh|python|ruby|node)|(?:pub[ \t]+)?(?:async[ \t]+)?(?:fn|def|function|class|interface|struct|enum)[ \t]+[A-Za-z_][A-Za-z0-9_]*|(?:from[ \t]+[A-Za-z_][A-Za-z0-9_.]*[ \t]+import|import[ \t]+[A-Za-z_$]|use[ \t]+[A-Za-z_]|package[ \t]+[A-Za-z_]|using[ \t]+[A-Za-z_.]+;)|(?:const|let|var)[ \t]+[A-Za-z_$][A-Za-z0-9_$]*[ \t]*(?::[^=\n]+)?=|\$env:[A-Za-z_][A-Za-z0-9_]*|Import-Module\b|apiVersion:[ \t]*[^\n]+|kind:[ \t]*(?:Deployment|StatefulSet|DaemonSet|Service|Secret|ConfigMap)\b|FROM[ \t]+[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?$|(?:RUN|COPY|ADD|ENTRYPOINT|CMD)[ \t]+[^\n]+)$",
    },
    AnchorPattern {
        category: "source_code_config",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:source[ 	]+code|quellcode|codebase|repository|repo|configuration[ 	]+file|config[ 	]+file|konfigurationsdatei|dockerfile|docker[ 	]+compose|kubernetes[ 	]+manifest|helm[ 	]+chart|terraform[ 	]+state)\b",
    },
    AnchorPattern {
        category: "sql_database_dump",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?im)^[ \t]*(?:--[ \t]*(?:PostgreSQL|MySQL|MariaDB|SQLite)[ \t]+database[ \t]+dump|(?:SELECT\b[^;\n]*\bFROM\b|UPDATE\b[^;\n]*\bSET\b|INSERT[ \t]+INTO\b[^;\n]*\bVALUES\b|DELETE[ \t]+FROM\b)|CREATE[ \t]+TABLE\b|COPY[ \t]+[^\n]+[ \t]+FROM[ \t]+stdin|LOCK[ \t]+TABLES\b|PRAGMA[ \t]+foreign_keys\b|pg_dump\b|mysqldump\b)",
    },
    AnchorPattern {
        category: "sql_database_dump",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:database[ 	]+dump|datenbank[ 	]*(?:dump|export|sicherung)|sql[ 	]+dump|schema[ 	]+dump|table[ 	]+dump|backup[ 	]+file)\b",
    },
    AnchorPattern {
        category: "system_log_stacktrace",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?im)^(?:Traceback \(most recent call last\):|thread '[^']+' panicked at|panic: [^\n]+|goroutine[ \t]+\d+[ \t]+\[[^\]]+\]:|Caused by:[ \t]+[^\n]+|[ \t]+at[ \t]+[A-Za-z0-9_.$<>]+\([^\n]+:\d+\)|\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?:ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+)",
    },
    AnchorPattern {
        category: "system_log_stacktrace",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:stack[ 	]*trace|stacktrace|exception[ 	]+trace|fehlerprotokoll|systemprotokoll|application[ 	]+log|server[ 	]+log|crash[ 	]+log|panic[ 	]+report|core[ 	]+dump)\b",
    },
];

/// All DLP rules in registry order. The rules live in `super::rules` by family.
pub static DLP_PATTERNS: &[DlpPattern] = &super::rules::DLP_RULES;

pub struct DlpPipeline {
    regexes: Vec<Regex>,
    anchor_gates: Vec<crate::detectors::anchor_gate::AnchorGate>,
    rule_ids: Vec<&'static str>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<NativeMatchValidator>>,
    span_groups: Vec<Option<usize>>,
    example_checks: Vec<ExampleCheck>,
    placeholder_checks: Vec<bool>,
    anchor_regexes: Vec<Regex>,
}

impl Default for DlpPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl DlpPipeline {
    pub fn new() -> Self {
        let mut regexes = Vec::new();
        let mut anchor_gates = Vec::new();
        let mut entity_groups = Vec::new();
        let mut rule_ids = Vec::new();
        let mut validators = Vec::new();
        let mut span_groups = Vec::new();
        let mut example_checks = Vec::new();
        let mut placeholder_checks = Vec::new();

        for p in DLP_PATTERNS {
            regexes.push(Regex::new(p.pattern).unwrap());
            anchor_gates.push(crate::detectors::anchor_gate::AnchorGate::regex(
                p.pattern, false,
            ));
            entity_groups.push(p.entity_group);
            rule_ids.push(p.name);
            validators.push(p.validator);
            span_groups.push(p.span_group);
            example_checks.push(rules::example_check(p.name));
            placeholder_checks.push(rules::placeholder_check(p.name));
        }

        let anchor_regexes = DLP_ANCHOR_PATTERNS
            .iter()
            .map(|anchor| Regex::new(anchor.pattern).unwrap())
            .collect();

        DlpPipeline {
            regexes,
            anchor_gates,
            rule_ids,
            entity_groups,
            validators,
            span_groups,
            example_checks,
            placeholder_checks,
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

    /// Values that fixed-format rules (provider tokens, keys, hashes) match
    /// inside `range` of `text`, so that a generic rule capturing such a value
    /// applies the fixed-format example check to it (T06). Only the line around
    /// the value is searched.
    fn fixed_format_values<'a>(
        &'a self,
        text: &'a str,
        range: Range<usize>,
    ) -> impl Iterator<Item = (&'static str, Range<usize>)> + 'a {
        let floor = |mut index: usize| {
            while !text.is_char_boundary(index) {
                index -= 1;
            }
            index
        };
        let line_start = text[..range.start].rfind('\n').map_or(0, |index| index + 1);
        let line_end = text[range.end..]
            .find('\n')
            .map_or(text.len(), |index| range.end + index);
        let window_start = floor(line_start.max(range.start.saturating_sub(256)));
        let window_end = floor(line_end.min(range.end + 256));
        let window = &text[window_start..window_end];
        (0..self.regexes.len())
            .filter(|&index| self.example_checks[index] == ExampleCheck::FixedFormat)
            .flat_map(move |index| {
                self.regexes[index]
                    .captures_iter(window)
                    .filter_map(move |captures| captures.get(self.span_groups[index].unwrap_or(0)))
                    .map(move |value| {
                        (
                            self.rule_ids[index],
                            window_start + value.start()..window_start + value.end(),
                        )
                    })
            })
            .filter(move |(_, value)| range.start <= value.start && value.end <= range.end)
    }
}

impl NativeRegexDetector for DlpPipeline {
    fn anchor_gates(&self) -> &[crate::detectors::anchor_gate::AnchorGate] {
        &self.anchor_gates
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
        Some(&self.span_groups)
    }

    fn preserve_cross_label_overlaps(&self) -> bool {
        true
    }

    /// Drops documented example and test values of secret rules (T06) and
    /// placeholders and environment/template references in the value of
    /// value-capturing credential rules (T07).
    fn allows_match(&self, index: usize, text: &str, captures: &regex::Captures<'_>) -> bool {
        let check = self.example_checks[index];
        let placeholder_check = self.placeholder_checks[index];
        if check == ExampleCheck::Off && !placeholder_check {
            return true;
        }
        let Some(value) = captures.get(self.span_groups[index].unwrap_or(0)) else {
            return true;
        };
        if placeholder_check && rules::is_placeholder_match(text, value.range()) {
            return false;
        }
        let rule_id = self.rule_ids[index];
        if rules::is_example_match(check, rule_id, text, value.range()) {
            return false;
        }
        // A generic rule capturing a provider-shaped value applies the
        // provider's fixed-format check to it.
        check != ExampleCheck::Generic
            || !rules::has_low_variety_run(text, value.range())
            || self
                .fixed_format_values(text, value.range())
                .all(|(provider, range)| {
                    !rules::is_example_match(ExampleCheck::FixedFormat, provider, text, range)
                })
    }

    fn finalize_spans(&self, _text: &str, spans: &mut Vec<crate::EvidenceSpan>) {
        let provider_spans = spans
            .iter()
            .filter(|span| {
                matches!(
                    span.label.as_str(),
                    "API_KEY" | "CLOUD_KEY" | "PAYMENT_KEY" | "CRYPTO_KEY" | "PRIVATE_KEY"
                )
            })
            .map(|span| (span.start_byte, span.end_byte))
            .collect::<std::collections::HashSet<_>>();
        let token_spans = spans
            .iter()
            .filter(|span| span.label == "SECRET_TOKEN")
            .map(|span| (span.start_byte, span.end_byte))
            .collect::<std::collections::HashSet<_>>();
        spans.retain(|span| {
            let range = (span.start_byte, span.end_byte);
            match span.label.as_str() {
                "CREDENTIAL" => !provider_spans.contains(&range) && !token_spans.contains(&range),
                "SECRET_TOKEN" => !provider_spans.contains(&range),
                _ => true,
            }
        });
    }

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        anchors::details(text, &self.anchor_regexes, DLP_ANCHOR_PATTERNS)
    }
}
