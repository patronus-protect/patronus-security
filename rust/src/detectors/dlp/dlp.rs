// SPDX-License-Identifier: GPL-3.0-only
use crate::detectors::anchors::{self, AnchorPattern};
use crate::detectors::validators;
use crate::{
    detectors::{MatchScore, NativeDetection, NativeMatchValidator, NativeRegexDetector},
    EvaluationResult,
};
use regex::Regex;
use std::ops::Range;

use super::overlap::OverlapRules;
pub use super::overlap::OverlapTier;
use super::prefilter::{RulePrefilter, ValueClass, ValueRun};
use super::rules::{self, ExampleCheck};
use super::score::DlpMode;
use super::{context, score};

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
    /// Score-model points (1–100) for the regex form alone; see [`super::score`].
    pub base_score: u8,
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

/// Taxonomy v2 (K09): what a credential/secret value is, within its entity
/// group. Matches of secret rules report it as `subtype` in `matched_rules`;
/// the entity groups and span labels stay as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretSubtype {
    /// Provider-issued API or access key.
    ApiKey,
    /// OAuth, personal, bot or bearer access token, JWT.
    AccessToken,
    /// Secret half of a key pair or client credential, signing secret.
    SecretKey,
    /// Asymmetric private key or wallet key.
    PrivateKey,
    /// Mnemonic wallet seed (BIP39, C01).
    SeedPhrase,
    /// Password chosen by a person or system.
    Password,
    PasswordHash,
    /// Any value under a secret-like key or variable name.
    GenericSecret,
    /// Session ID or CSRF token.
    SessionToken,
    /// Signature of a signed URL.
    Signature,
    /// Database or service connection string with credentials (G01).
    ConnectionString,
    /// URL whose query or fragment carries a credential: token parameters,
    /// reset and magic links, OAuth redirects (G09).
    AuthUrl,
    /// Incoming webhook URL that authorizes by itself (P08).
    WebhookUrl,
    /// TOTP/HOTP seed, otpauth URI, recovery codes (G08).
    OtpSecret,
}

impl SecretSubtype {
    pub const ALL: &'static [Self] = &[
        Self::ApiKey,
        Self::AccessToken,
        Self::SecretKey,
        Self::PrivateKey,
        Self::SeedPhrase,
        Self::Password,
        Self::PasswordHash,
        Self::GenericSecret,
        Self::SessionToken,
        Self::Signature,
        Self::ConnectionString,
        Self::AuthUrl,
        Self::WebhookUrl,
        Self::OtpSecret,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::AccessToken => "access_token",
            Self::SecretKey => "secret_key",
            Self::PrivateKey => "private_key",
            Self::SeedPhrase => "seed_phrase",
            Self::Password => "password",
            Self::PasswordHash => "password_hash",
            Self::GenericSecret => "generic_secret",
            Self::SessionToken => "session_token",
            Self::Signature => "signature",
            Self::ConnectionString => "connection_string",
            Self::AuthUrl => "auth_url",
            Self::WebhookUrl => "webhook_url",
            Self::OtpSecret => "otp_secret",
        }
    }

    /// The existing entity groups a rule of this subtype may report.
    pub const fn groups(self) -> &'static [&'static str] {
        match self {
            Self::ApiKey | Self::SecretKey => &["API_KEY", "CLOUD_KEY", "PAYMENT_KEY"],
            Self::AccessToken => &["SECRET_TOKEN", "CLOUD_KEY"],
            Self::PrivateKey => &["PRIVATE_KEY", "CRYPTO_KEY"],
            Self::SeedPhrase => &["CRYPTO_KEY"],
            Self::PasswordHash => &["PASSWORD_HASH"],
            Self::SessionToken => &["SECRET_TOKEN", "CREDENTIAL"],
            Self::WebhookUrl => &["SECRET_TOKEN"],
            Self::Password
            | Self::GenericSecret
            | Self::Signature
            | Self::ConnectionString
            | Self::AuthUrl
            | Self::OtpSecret => &["CREDENTIAL"],
        }
    }
}

/// Rule metadata v2 (K02). Matches report `provider`, `validator_strength`,
/// `source_ref` and, for secret rules, `severity` and `subtype` (K09) in
/// `matched_rules`.
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
    /// Structural prefilter of a rule without keywords (K07): a run of value
    /// characters that every match contains.
    pub value_run: Option<ValueRun>,
    /// Taxonomy v2 subtype of a secret rule (K09); `None` for identifier and
    /// content rules.
    pub subtype: Option<SecretSubtype>,
    /// Token boundary of a prefix rule (T01); `None` for key-anchored,
    /// identifier and content rules.
    pub boundary: Option<TokenBoundary>,
}

/// T01: a prefix rule reports a value only as a whole token. The characters
/// right before and after the value are no `[A-Za-z0-9_]` and none of
/// `alphabet`, and the value is no part of a base64 blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBoundary {
    /// Value characters of the provider beyond `[A-Za-z0-9_]` (`-` for most
    /// base64url-style tokens).
    pub alphabet: &'static str,
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
            value_run: None,
            subtype: None,
            boundary: None,
        }
    }

    /// T01: the value must stand as a whole token; `alphabet` lists the
    /// value characters beyond `[A-Za-z0-9_]`.
    pub const fn with_boundary(self, alphabet: &'static str) -> Self {
        Self {
            boundary: Some(TokenBoundary { alphabet }),
            ..self
        }
    }

    pub const fn with_subtype(self, subtype: SecretSubtype) -> Self {
        Self {
            subtype: Some(subtype),
            ..self
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

    pub const fn with_value_run(self, class: ValueClass, min_len: usize) -> Self {
        Self {
            value_run: Some(ValueRun { class, min_len }),
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
            .is_none_or(|bits| validators::shannon_entropy(value) >= bits)
    }
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

/// K08: the overlap tier of a secret rule (provider > token > hash >
/// credential > generic); `None` for identifier and content rules.
pub fn overlap_tier(rule_id: &str) -> Option<OverlapTier> {
    rules::overlap_tier(rule_id)
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
    tiers: Vec<Option<OverlapTier>>,
    prefilter: RulePrefilter,
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
        let mut tiers = Vec::new();

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
            tiers.push(rules::overlap_tier(p.name));
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
            tiers,
            prefilter: RulePrefilter::new(DLP_PATTERNS),
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

    /// Detect with an explicit output mode. `DlpMode::Strict` is identical to
    /// the trait's `detect_prepared_with_options`.
    ///
    /// A scored mode scores every strict finding first, so that overlap
    /// resolution and provider precedence decide exactly as in `strict`, and
    /// then drops what scores below the mode's threshold. Its spans are thus
    /// always strict spans: a value dropped for its context does not free its
    /// range for a weaker rule (a WIF-shaped run inside a dropped hex hash).
    pub(crate) fn detect_prepared_with_mode<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
        mode: DlpMode,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        let Some(threshold) = mode.min_score() else {
            return self.detect_prepared_with_options(prepared, allows_rule, explain);
        };
        let mut detection = self.detect_prepared_scored(prepared, allows_rule, explain, Some(0.0));
        detection
            .evidence_spans
            .retain(|span| span.score >= threshold);
        let mut first_group = None;
        if let Some(rules) = detection.details.get_mut("matched_rules") {
            if let Some(entries) = rules.as_array_mut() {
                entries.retain(|rule| rule["score"].as_f64().is_some_and(|s| s >= threshold));
                first_group = entries.first().and_then(|rule| {
                    let rule_id = rule["rule_id"].as_str()?;
                    let index = self.rule_ids.iter().position(|id| *id == rule_id)?;
                    Some(self.entity_groups[index])
                });
            }
            if rules.as_array().is_some_and(Vec::is_empty) {
                detection.details.remove("matched_rules");
            }
        }
        let spans = &detection.evidence_spans;
        detection.result = match spans.iter().map(|span| span.score).reduce(f64::max) {
            None => EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: "L1".to_string(),
            },
            // The class of the first surviving rule match, as in the unscored contract.
            Some(confidence) => EvaluationResult {
                class_name: first_group
                    .filter(|group| spans.iter().any(|span| span.label == *group))
                    .map_or_else(|| spans[0].label.clone(), str::to_string),
                confidence,
                level: "L1".to_string(),
            },
        };
        detection
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

    fn rule_scan(&self, text: &str) -> Option<super::prefilter::RuleScan> {
        Some(self.prefilter.scan(text))
    }

    fn rule_captures<'t>(
        &self,
        index: usize,
        regex: &Regex,
        text: &'t str,
        scan: Option<&super::prefilter::RuleScan>,
    ) -> Vec<regex::Captures<'t>> {
        match scan {
            Some(scan) => self.prefilter.captures(index, regex, text, scan),
            None => regex.captures_iter(text).collect(),
        }
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

    /// Drops prefix-rule values that are no whole token (T01), generic
    /// assignments whose key is a URL userinfo (K08), values
    /// below the rule's entropy floor (K02), documented example
    /// and test values of secret rules (T06), vendor-documented example values
    /// (K06) and placeholders and environment/template references in the value
    /// of value-capturing credential rules (T07, K06).
    fn allows_match(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
        captures: &regex::Captures<'_>,
    ) -> bool {
        let text = prepared.text();
        // K08: a generic key that is the userinfo of a URL (`https://token:…@`)
        // belongs to the URL credential, also when that has no value to report.
        if self.tiers[index] == Some(OverlapTier::Generic)
            && captures
                .get(0)
                .is_some_and(|matched| text[..matched.start()].ends_with("://"))
        {
            return false;
        }
        let meta = &self.metas[index];
        // T01: a prefix rule's value inside an identifier, hex run or base64
        // blob is no token.
        if let Some(boundary) = meta.boundary {
            if let Some(value) = captures.get(self.span_groups[index].unwrap_or(0)) {
                if !super::boundary::is_whole_token(text, value.range(), boundary) {
                    return false;
                }
            }
        }
        let check = self.example_checks[index];
        let placeholder_check = self.placeholder_checks[index];
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
        let rule_id = self.rule_ids[index];
        if rules::is_example_match(check, rule_id, text, value.range()) {
            return false;
        }
        if check != ExampleCheck::Off && rules::is_documented_example(rule_id, text, value.range())
        {
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

    fn match_score(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
        captures: &regex::Captures<'_>,
    ) -> MatchScore {
        let pattern = &DLP_PATTERNS[index];
        let value = captures
            .get(self.span_groups[index].unwrap_or(0))
            .unwrap_or_else(|| captures.get(0).unwrap());
        let evidence = context::evidence(pattern, prepared.text(), (value.start(), value.end()));
        MatchScore {
            score: score::score(pattern, evidence.context),
            context: Some(evidence.to_json()),
        }
    }

    /// K08: overlapping secret matches keep one span (see [`super::overlap`]).
    fn resolve_overlaps(
        &self,
        text: &str,
        candidates: Vec<(usize, crate::EvidenceSpan)>,
        matched_rules: &mut [serde_json::Value],
    ) -> Vec<crate::EvidenceSpan> {
        let rules = OverlapRules {
            rule_ids: &self.rule_ids,
            tiers: &self.tiers,
            metas: &self.metas,
        };
        super::overlap::resolve(text, &rules, candidates, matched_rules)
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
            let severity = if rules::is_documented_test_value(value) {
                Severity::Test
            } else {
                meta.severity(value)
            };
            details.insert("severity".into(), severity.as_str().into());
        }
        if let Some(subtype) = meta.subtype {
            details.insert("subtype".into(), subtype.as_str().into());
        }
        details
    }

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        anchors::details(text, &self.anchor_regexes, DLP_ANCHOR_PATTERNS)
    }
}
