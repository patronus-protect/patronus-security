// SPDX-License-Identifier: GPL-3.0-only
use crate::detectors::anchors::{self, AnchorPattern};
use crate::{
    detectors::{NativeMatchValidator, NativeRegexDetector},
    EvaluationResult,
};
use regex::Regex;

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
    /// Rule metadata v2: provider, validator strength, keywords, entropy floor,
    /// format source and live/test severity.
    pub meta: RuleMeta,
}

/// How strongly a rule confirms the matched value beyond the keyword context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorStrength {
    /// A check digit or checksum (CRC32, Base58Check, Bech32) is verified.
    Checksum,
    /// The decoded or parsed structure is verified (JWT header, DER, SQL).
    Structure,
    /// Fixed prefix, alphabet, length or syntax shape only.
    Format,
    /// Keyword or context anchor only; the value shape is free.
    None,
}

impl ValidatorStrength {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checksum => "checksum",
            Self::Structure => "structure",
            Self::Format => "format",
            Self::None => "none",
        }
    }
}

/// Whether a secret is a live credential or a provider test/sandbox credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Live,
    Test,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test => "test",
        }
    }
}

/// Rule metadata v2 (K02). Matches report `provider`, `validator_strength`,
/// `source_ref` and, for secret rules, `severity` in `matched_rules`.
#[derive(Clone, Copy, Debug)]
pub struct RuleMeta {
    /// Provider slug for provider-bound formats (`github`, `stripe` …).
    pub provider: Option<&'static str>,
    pub validator_strength: ValidatorStrength,
    /// Lowercase literals of which every match contains at least one (ASCII
    /// case-insensitive); the prefilter keywords. Empty only for rules without
    /// a literal.
    pub keywords: &'static [&'static str],
    /// Minimum Shannon entropy of the value in bits per character; lower
    /// values are dropped.
    pub min_entropy: Option<f64>,
    /// Format source: `gitleaks:<rule-id>`, a vendor/spec `https://` URL, or
    /// `ark` for in-house context rules (`research/dlp/rule_sources.yaml`).
    pub source_ref: &'static str,
    /// Value prefixes of provider test/sandbox credentials (severity `test`).
    pub test_prefixes: &'static [&'static str],
}

impl RuleMeta {
    pub const fn new(
        validator_strength: ValidatorStrength,
        source_ref: &'static str,
        keywords: &'static [&'static str],
    ) -> Self {
        Self {
            provider: None,
            validator_strength,
            keywords,
            min_entropy: None,
            source_ref,
            test_prefixes: &[],
        }
    }

    pub const fn with_provider(self, provider: &'static str) -> Self {
        Self {
            provider: Some(provider),
            ..self
        }
    }

    pub const fn with_min_entropy(self, bits: f64) -> Self {
        Self {
            min_entropy: Some(bits),
            ..self
        }
    }

    pub const fn with_test_prefixes(self, test_prefixes: &'static [&'static str]) -> Self {
        Self {
            test_prefixes,
            ..self
        }
    }

    /// Severity of a matched secret `value`.
    pub fn severity(&self, value: &str) -> Severity {
        if self
            .test_prefixes
            .iter()
            .any(|prefix| value.starts_with(prefix))
        {
            Severity::Test
        } else {
            Severity::Live
        }
    }

    /// Whether `value` reaches the rule's entropy floor.
    pub(crate) fn has_min_entropy(&self, value: &str) -> bool {
        self.min_entropy
            .is_none_or(|bits| shannon_entropy(value) >= bits)
    }
}

/// Shannon entropy of `value` in bits per character.
fn shannon_entropy(value: &str) -> f64 {
    let mut counts = std::collections::HashMap::<char, usize>::new();
    for ch in value.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

/// Entity groups of credential/secret rules: on by default, with severity.
pub(crate) const SECRET_GROUPS: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
];

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
        .is_none_or(|pattern| SECRET_GROUPS.contains(&pattern.entity_group))
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
    metas: Vec<RuleMeta>,
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
        let mut metas = Vec::new();

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
            metas.push(p.meta);
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
            metas,
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

    /// Drops values below the rule's entropy floor (K02), documented example
    /// and test values of secret rules (T06) and placeholders and
    /// environment/template references in the value of value-capturing
    /// credential rules (T07).
    fn allows_match(&self, index: usize, text: &str, captures: &regex::Captures<'_>) -> bool {
        let check = self.example_checks[index];
        let placeholder_check = self.placeholder_checks[index];
        let meta = &self.metas[index];
        if check == ExampleCheck::Off && !placeholder_check && meta.min_entropy.is_none() {
            return true;
        }
        let Some(value) = captures.get(self.span_groups[index].unwrap_or(0)) else {
            return true;
        };
        if !meta.has_min_entropy(value.as_str()) {
            return false;
        }
        if placeholder_check && rules::is_placeholder_match(text, value.range()) {
            return false;
        }
        !rules::is_example_match(check, self.rule_ids[index], text, value.range())
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

    fn match_details(
        &self,
        index: usize,
        value: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let meta = &self.metas[index];
        let mut details = serde_json::Map::new();
        if let Some(provider) = meta.provider {
            details.insert("provider".into(), provider.into());
        }
        details.insert(
            "validator_strength".into(),
            meta.validator_strength.as_str().into(),
        );
        details.insert("source_ref".into(), meta.source_ref.into());
        if SECRET_GROUPS.contains(&self.entity_groups[index]) {
            details.insert("severity".into(), meta.severity(value).as_str().into());
        }
        details
    }

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        anchors::details(text, &self.anchor_regexes, DLP_ANCHOR_PATTERNS)
    }
}
