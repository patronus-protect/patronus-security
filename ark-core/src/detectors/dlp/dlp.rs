// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::detectors::anchors::{self, AnchorPattern};
use crate::detectors::validators;
use crate::{
    detectors::{MatchScore, NativeDetection, NativeMatchValidator, NativeRegexDetector},
    EvaluationResult,
};
use regex::Regex;
use std::ops::Range;

use super::context;
use super::decoder::{self, Decoded};
use super::overlap::OverlapRules;
pub use super::overlap::OverlapTier;
use super::prefilter::{RulePrefilter, ValueClass, ValueRun, RULE_DFA_CACHE_BYTES};
use super::rules::{self, ExampleCheck};
use crate::detectors::score::{self, ScoredPattern, ValidatorStrength};
use crate::native::ScoreMode;

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

impl ScoredPattern for DlpPattern {
    fn base_score(&self) -> u8 {
        self.base_score
    }

    fn strength(&self) -> ValidatorStrength {
        self.meta.validator_strength
    }

    fn binds_field(&self) -> bool {
        context::source(self) == context::ContextSource::Field
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

/// C01: candidate finder of a rule, see [`RuleMeta::finder`].
pub type Finder = fn(&str) -> Vec<Range<usize>>;

/// T09: key gate of a key-anchored rule, see [`RuleMeta::key_gate`].
pub type KeyGate = fn(&str, usize, Range<usize>) -> bool;

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
    /// Context a value needs beyond its shape (F01): called with the text and
    /// the value's byte range; `None` for rules whose shape suffices.
    pub context_gate: Option<fn(&str, Range<usize>) -> bool>,
    /// F03: exact length of the token body after the keyword prefix of a
    /// prefix rule; a generic rule skips a value with the prefix and a
    /// token-shaped body of another length. `None` for rules without a fixed
    /// length.
    pub body_len: Option<BodyLen>,
    /// Likeness a value needs beyond the rule's regex (F-GEN1): called with
    /// the text and the value's byte range; rejects code expressions, words
    /// and credential names after a generic key. `None` for rules whose
    /// value shape suffices.
    pub value_gate: Option<fn(&str, Range<usize>) -> bool>,
    /// Key shape a key needs (T09): called with the text, the byte offset
    /// where the match (the credential noun of the key) starts and the
    /// value's byte range; reads a compound or camelCase prefix before the
    /// noun. `None` for rules whose key is matched in full.
    pub key_gate: Option<KeyGate>,
    /// C01: finds the candidate matches of a rule whose regex has no literal
    /// to search for (seed phrases): the byte ranges at which the rule's
    /// regex is matched, each in full. `None` for rules searched by their
    /// regex.
    pub finder: Option<Finder>,
}

/// F03: the fixed body length of a prefix rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLen {
    /// Characters after the keyword prefix of a token.
    pub exact: usize,
    /// Shortest body that is still token-shaped (the former open-ended
    /// minimum); a shorter one, as in a password that only starts like a
    /// token, stays a generic credential.
    pub shape_min: usize,
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
            context_gate: None,
            value_gate: None,
            body_len: None,
            key_gate: None,
            finder: None,
        }
    }

    /// C01: the rule's regex is matched only at the ranges `finder` returns.
    pub const fn with_finder(self, finder: Finder) -> Self {
        Self {
            finder: Some(finder),
            ..self
        }
    }

    /// F03: the body after the keyword prefix has exactly `exact`
    /// characters; bodies from `shape_min` characters on are token-shaped.
    pub const fn with_body_len(self, exact: usize, shape_min: usize) -> Self {
        Self {
            body_len: Some(BodyLen { exact, shape_min }),
            ..self
        }
    }

    /// F-GEN1: the value counts only where `gate` finds it secret-like.
    pub const fn with_value_gate(self, gate: fn(&str, Range<usize>) -> bool) -> Self {
        Self {
            value_gate: Some(gate),
            ..self
        }
    }

    /// T09: the key counts only where `gate` accepts its shape.
    pub const fn with_key_gate(self, gate: KeyGate) -> Self {
        Self {
            key_gate: Some(gate),
            ..self
        }
    }

    /// F01: the value counts only where `gate` finds its context.
    pub const fn with_context_gate(self, gate: fn(&str, Range<usize>) -> bool) -> Self {
        Self {
            context_gate: Some(gate),
            ..self
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
    pub fn has_min_entropy(&self, value: &str) -> bool {
        self.min_entropy
            .is_none_or(|bits| validators::shannon_entropy(value) >= bits)
    }
}

/// Entity groups of credential/secret rules: on by default, with severity.
pub const SECRET_GROUPS: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
];

/// Document classes on by default (M23): classification markings (M-MARK).
/// Every other content and document class is opt-in.
pub const DEFAULT_ON_DOCUMENT_GROUPS: &[&str] = &["dlp.document.classification_marking"];

/// K08: the overlap tier of a secret rule (provider > token > hash >
/// credential > generic); `None` for identifier and content rules.
pub fn overlap_tier(rule_id: &str) -> Option<OverlapTier> {
    rules::overlap_tier(rule_id)
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
    /// Per rule, its automata, compiled on first use: a rule that the gates
    /// keep off costs no memory ([`Self::prepare`]).
    rules: Vec<std::sync::OnceLock<CompiledRule>>,
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
    anchor_regexes: Vec<crate::detectors::word_boundary::BoundarySearch>,
}

/// The automata of one DLP rule.
struct CompiledRule {
    regex: Regex,
    /// K05: for a generic key-bound rule, the value regex of config-line
    /// values; T21: for a key-bound provider rule, its value regex for XML values.
    structured: Option<Regex>,
    /// K05: for a generic key-bound rule, its key grammar for config lines.
    config_key: Option<ConfigKeyRegexes>,
    /// T21: for a key-bound provider rule, its key for XML config elements;
    /// T23: for a rule of [`rules::sql_key`], its key for SQL rows.
    bound_key: Option<BoundKey>,
}

impl CompiledRule {
    fn new(p: &DlpPattern) -> Self {
        let config_key = rules::config_key(p.name);
        let xml_key = rules::provider_xml_key(p.name);
        let sql_key = rules::sql_key(p.name);
        Self {
            regex: regex::RegexBuilder::new(p.pattern)
                .dfa_size_limit(RULE_DFA_CACHE_BYTES)
                .build()
                .unwrap(),
            structured: config_key
                .map(|key| {
                    let max = key.max_len.map_or(String::new(), |max| max.to_string());
                    format!(r"(?P<structured>[^\r\n]{{{},{max}}})\z", key.min_len)
                })
                .or_else(|| {
                    xml_key
                        .or(sql_key)
                        .map(|key| format!(r"(?P<structured>(?:{}))\z", key.value))
                })
                .map(|pattern| Regex::new(&pattern).unwrap()),
            config_key: config_key.map(ConfigKeyRegexes::new),
            bound_key: xml_key
                .map(|key| {
                    BoundKey::new(key, |prepared, find| {
                        super::config_keys::xml_values(prepared.text(), find)
                    })
                })
                .or_else(|| {
                    sql_key.map(|key| {
                        BoundKey::new(key, |prepared, find| {
                            super::sql_rows::key_field_values(
                                prepared.text(),
                                prepared.sql_statements(),
                                find,
                            )
                        })
                    })
                }),
        }
    }
}

/// T21: the key of a key-bound provider rule (`provider_key!`), compiled for
/// the `key`/`name` attribute or element name of an XML config element.
/// T23: the key of a rule of [`rules::sql_key`], compiled for the key field
/// of a SQL row.
struct BoundKey {
    /// Finds the key in the text.
    find: Regex,
    /// The key at the end of a bound key (`HerokuApiKey`, `App.HerokuApiKey`).
    whole: Regex,
    /// The values whose key holds a match of `find`.
    values: BoundValues,
}

/// Reads the values of a [`BoundKey`] from the prepared text.
type BoundValues =
    fn(&crate::threat::NativeText<'_>, &Regex) -> Vec<super::config_keys::ConfigValue>;

impl BoundKey {
    fn new(key: rules::ProviderKey, values: BoundValues) -> Self {
        Self {
            find: Regex::new(key.key).unwrap(),
            whole: Regex::new(&format!("(?:{})$", key.key)).unwrap(),
            values,
        }
    }
}

/// K05: the key grammar of a rule, compiled for config lines.
struct ConfigKeyRegexes {
    /// Finds the credential part of a key in the text, also in the plural
    /// (`api_keys`, `TOKENS`; K05B).
    find: Regex,
    /// The singular credential part as a whole (`password`, `api_key`).
    singular: Regex,
    /// The whole key, for rules whose grammar spans it (`DB_PASSWORD`).
    whole: Option<Regex>,
    /// The whole key in the plural (`DB_PASSWORDS`; K05B).
    whole_plural: Option<Regex>,
    /// G02: the credential part as a whole, also in the plural, for nouns
    /// that bind only in a config document.
    document_only: Option<Regex>,
}

impl ConfigKeyRegexes {
    /// K05B: a plural key (`api_keys`, `tokens`) names a list and binds only
    /// its items. The grammar of a whole key ends with its noun, the others
    /// with a word boundary that the plural `s` goes before.
    fn new(key: rules::ConfigKey) -> Self {
        const BOUNDARY: &str = "(?-u:\\b)";
        let stem = |pattern: &'static str| pattern.strip_suffix(BOUNDARY).unwrap_or(pattern);
        // G02: the document-only nouns are alternatives of the key grammar.
        let (stems, nouns) = match key.document_pattern {
            None => (stem(key.pattern).to_owned(), key.pattern.to_owned()),
            Some(document) => (
                format!("(?:{})|(?:{})", stem(key.pattern), stem(document)),
                format!("(?:{})|(?:{document})", key.pattern),
            ),
        };
        let find = match key.whole {
            true => key.pattern.to_owned(),
            false => format!("(?:{stems})[sS]?{BOUNDARY}"),
        };
        Self {
            find: Regex::new(&find).unwrap(),
            singular: Regex::new(&format!("^(?:{nouns})$")).unwrap(),
            whole: key
                .whole
                .then(|| Regex::new(&format!("^(?:{})$", key.pattern)).unwrap()),
            whole_plural: key
                .whole
                .then(|| Regex::new(&format!("^(?:{})S$", key.pattern)).unwrap()),
            document_only: key
                .document_pattern
                .map(|document| Regex::new(&format!("^(?:{})[sS]?$", stem(document))).unwrap()),
        }
    }

    /// Whether the key binds a value: `Some(false)` for a singular key,
    /// `Some(true)` for a plural one, with the rule's key gate on the noun.
    /// A document-only noun (G02) binds only where `in_document` holds: the
    /// text is a config document and the value names no key.
    fn binds(
        &self,
        text: &str,
        config: &super::config_keys::ConfigValue,
        key_gate: Option<KeyGate>,
        in_document: impl Fn() -> bool,
    ) -> Option<bool> {
        let key = &text[config.key.clone()];
        if let (Some(whole), Some(plural)) = (&self.whole, &self.whole_plural) {
            return if whole.is_match(key) {
                Some(false)
            } else {
                plural.is_match(key).then_some(true)
            };
        }
        self.find
            .find_iter(key)
            .filter(|noun| noun.end() == key.len())
            .find(|noun| {
                key_gate.is_none_or(|gate| {
                    gate(text, config.key.start + noun.start(), config.value.clone())
                })
            })
            .filter(|noun| {
                self.document_only
                    .as_ref()
                    .is_none_or(|only| !only.is_match(noun.as_str()) || in_document())
            })
            .map(|noun| !self.singular.is_match(noun.as_str()))
    }
}

impl DlpPipeline {
    /// T21: the XML values of a key-bound provider rule: the value of a keyed
    /// element whose `key`/`name` attribute ends with the provider name and
    /// credential noun (`<add key="HerokuApiKey" value="…"/>` in either
    /// attribute order, `<entry key="…">…</entry>`) or the text of an element
    /// so named, read by `config_keys` (K05C: no HTML form, XML in code or XML
    /// comment). The key gate of the rule reads the key alone, as the value may
    /// stand before it. The anchor gate of the rule's regex applies, since the
    /// key holds the provider name. T23: the same for the next field after a
    /// key field of a SQL row (`sql_rows`).
    fn bound_key_values(
        &self,
        index: usize,
        key: &BoundKey,
        prepared: &crate::threat::NativeText<'_>,
    ) -> Vec<crate::detectors::StructuredValue> {
        let gate = &self.anchor_gates[index];
        if !prepared.admits(gate) {
            return Vec::new();
        }
        let text = prepared.text();
        let key_gate = self.metas[index].key_gate;
        (key.values)(prepared, &key.find)
            .into_iter()
            .filter(|config| {
                key.whole
                    .find(&text[config.key.clone()])
                    .is_some_and(|found| {
                        let end = config.key.end;
                        key_gate.is_none_or(|gate| {
                            gate(text, config.key.start + found.start(), end..end)
                        })
                    })
            })
            .map(|config| crate::detectors::StructuredValue {
                key: config.key,
                value: config.value,
                carrier: config.format.as_str(),
            })
            .collect()
    }
}

impl Default for DlpPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl DlpPipeline {
    /// The pipeline compiled once per process: every engine and gateway and
    /// the exfiltration rules (a secret as data source) share its rules.
    pub fn shared() -> &'static Self {
        static PIPELINE: std::sync::LazyLock<DlpPipeline> =
            std::sync::LazyLock::new(DlpPipeline::new);
        &PIPELINE
    }

    /// Sets up every rule; each rule's automata are compiled on first use
    /// ([`Self::prepare`]).
    pub fn new() -> Self {
        DlpPipeline {
            rules: DLP_PATTERNS
                .iter()
                .map(|_| std::sync::OnceLock::new())
                .collect(),
            anchor_gates: DLP_PATTERNS
                .iter()
                .map(|p| crate::detectors::anchor_gate::AnchorGate::regex(p.pattern, false))
                .collect(),
            rule_ids: DLP_PATTERNS.iter().map(|p| p.name).collect(),
            entity_groups: DLP_PATTERNS.iter().map(|p| p.entity_group).collect(),
            validators: DLP_PATTERNS.iter().map(|p| p.validator).collect(),
            span_groups: DLP_PATTERNS.iter().map(|p| p.span_group).collect(),
            example_checks: DLP_PATTERNS
                .iter()
                .map(|p| rules::example_check(p.name))
                .collect(),
            placeholder_checks: DLP_PATTERNS
                .iter()
                .map(|p| rules::placeholder_check(p.name))
                .collect(),
            metas: DLP_PATTERNS.iter().map(|p| p.meta).collect(),
            tiers: DLP_PATTERNS
                .iter()
                .map(|p| rules::overlap_tier(p.name))
                .collect(),
            prefilter: RulePrefilter::new(DLP_PATTERNS),
            anchor_regexes: DLP_ANCHOR_PATTERNS
                .iter()
                .map(|anchor| crate::detectors::word_boundary::BoundarySearch::new(anchor.pattern))
                .collect(),
        }
    }

    /// The automata of rule `index`, compiled on first use.
    fn rule(&self, index: usize) -> &CompiledRule {
        self.rules[index].get_or_init(|| CompiledRule::new(&DLP_PATTERNS[index]))
    }

    /// Compiles the rules that `allows_rule` enables, so that no scan under
    /// these gates compiles one; a rule other gates enable later, or one
    /// another rule consults (a token rule whose checksum or shape decides a
    /// generic match), is compiled on first use.
    pub fn prepare(&self, allows_rule: impl Fn(&str) -> bool) {
        for (index, id) in self.rule_ids.iter().enumerate() {
            if allows_rule(id) {
                self.rule(index);
            }
        }
    }

    /// Whether rule `index` is compiled; see [`Self::prepare`].
    #[cfg(test)]
    fn compiled(&self, index: usize) -> bool {
        self.rules[index].get().is_some()
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }

    /// Detect with an explicit output mode. `ScoreMode::Strict` is identical to
    /// the trait's `detect_prepared_with_options`.
    ///
    /// A scored mode scores every strict finding first, so that overlap
    /// resolution and provider precedence decide exactly as in `strict`, and
    /// then drops what scores below the mode's threshold. Its spans are thus
    /// always strict spans: a value dropped for its context does not free its
    /// range for a weaker rule (a WIF-shaped run inside a dropped hex hash).
    ///
    /// D01: values inside base64/base64url runs are found in the decoded view
    /// (depth 2, size-limited) and reported on their encoded range, unless a
    /// finding of the text itself overlaps that range.
    pub fn detect_prepared_with_mode<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
        mode: ScoreMode,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        let detection = self.detect_text_with_mode(prepared, &allows_rule, explain, mode);
        let Some(view) = Decoded::new(prepared.text()) else {
            return detection;
        };
        let decoded = self.detect_text_with_mode(
            &crate::threat::NativeText::new(&view.text),
            &allows_rule,
            false,
            mode,
        );
        if decoded.evidence_spans.is_empty() {
            return detection;
        }
        decoder::merge(prepared.text(), detection, decoded, &view, |rule_id| {
            let index = self.rule_ids.iter().position(|id| *id == rule_id)?;
            Some(self.entity_groups[index])
        })
    }

    /// [`Self::detect_prepared_with_mode`] on the text alone.
    fn detect_text_with_mode<F>(
        &self,
        prepared: &crate::threat::NativeText<'_>,
        allows_rule: F,
        explain: bool,
        mode: ScoreMode,
    ) -> NativeDetection
    where
        F: Fn(&str) -> bool,
    {
        if mode == ScoreMode::Strict {
            return self.detect_prepared_with_options(prepared, allows_rule, explain);
        }
        let mut detection = self.detect_prepared_scored(prepared, allows_rule, explain, Some(0.0));
        detection.retain_admitted(mode);
        let mut first_group = None;
        if let Some(rules) = detection.details.get_mut("matched_rules") {
            if let Some(entries) = rules.as_array_mut() {
                entries.retain(|rule| rule["score"].as_f64().is_some_and(|s| mode.admits(s)));
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

    /// The value of a match of rule `index`, see [`NativeRegexDetector::value_group`].
    fn value<'t>(&self, index: usize, captures: &regex::Captures<'t>) -> Option<regex::Match<'t>> {
        captures.get(self.value_group(index, captures).unwrap_or(0))
    }

    /// G-PROSE: whether `value` starts with the token prefix (`npm_`,
    /// `glpat-` …) of a prefix rule. A prose rule leaves such a value to
    /// the provider rule, which reports it or rejects its shape.
    fn has_token_prefix(&self, value: &str) -> bool {
        self.token_prefix_len(value).is_some()
    }

    /// The length of the token prefix (`npm_`, `glpat-` …) of a prefix rule
    /// that `value` starts with.
    fn token_prefix_len(&self, value: &str) -> Option<usize> {
        self.metas
            .iter()
            .filter(|meta| meta.boundary.is_some())
            .flat_map(|meta| meta.keywords.iter())
            .find(|keyword| {
                keyword.len() >= 4
                    && keyword.ends_with(['_', '-'])
                    && value
                        .get(..keyword.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(keyword))
            })
            .map(|keyword| keyword.len())
    }

    /// P10: whether `value`, without leading quotes, is the token prefix of
    /// a prefix rule followed by a placeholder (`ntn_<your-secret>`,
    /// `lin_api_${LINEAR_KEY}`, `PMAK-{{ key }}`).
    fn has_placeholder_body(&self, value: &str) -> bool {
        let value = value.trim_start_matches(['"', '\'', '`']);
        self.token_prefix_len(value)
            .is_some_and(|len| value[len..].starts_with(['<', '{', '$', '[']))
    }

    /// F03: whether `value`, without leading quotes, starts with a whole
    /// token of a prefixed provider rule with a checksum (GitHub `ghp_` …)
    /// whose checksum fails, as in `ghp_…` or `ghp_…@github.com/acme/app`.
    fn fails_token_checksum(&self, value: &str) -> bool {
        let value = value.trim_start_matches(['"', '\'', '`']);
        (0..self.rules.len()).any(|index| {
            let meta = &self.metas[index];
            meta.validator_strength == ValidatorStrength::Checksum
                && meta.keywords.iter().any(|keyword| {
                    value
                        .get(..keyword.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(keyword))
                })
                && self.regex(index).find(value).is_some_and(|token| {
                    token.start() == 0
                        && !value[token.end()..]
                            .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                        && self.validators[index]
                            .is_some_and(|validator| !validator(token.as_str()))
                })
        })
    }

    /// F03: whether the value at `range` of `text`, without leading quotes,
    /// is the keyword prefix of a prefix rule with a fixed body length
    /// (GitHub `ghp_`, `github_pat_` …) and a whole-token body of another
    /// token-shaped length, as in `ghp_` with 35 characters or
    /// `ghp_…@github.com/acme/app`. The body ends at the end of the text, a
    /// space, a quote, `@`, `,` or `;`.
    fn has_wrong_token_length(&self, text: &str, range: Range<usize>) -> bool {
        let value = text[range.start..].trim_start_matches(['"', '\'', '`']);
        self.metas.iter().any(|meta| {
            let (Some(body_len), Some(boundary)) = (meta.body_len, meta.boundary) else {
                return false;
            };
            meta.keywords.iter().any(|keyword| {
                let Some(body) = value
                    .get(..keyword.len())
                    .filter(|head| head.eq_ignore_ascii_case(keyword))
                    .map(|_| &value[keyword.len()..])
                else {
                    return false;
                };
                let end = body
                    .find(|c: char| {
                        !(c.is_ascii_alphanumeric() || c == '_' || boundary.alphabet.contains(c))
                    })
                    .unwrap_or(body.len());
                end != body_len.exact
                    && end >= body_len.shape_min
                    && body[end..].chars().next().is_none_or(|c| {
                        c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '@' | ',' | ';')
                    })
            })
        })
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
        (0..self.rules.len())
            .filter(|&index| self.example_checks[index] == ExampleCheck::FixedFormat)
            .flat_map(move |index| {
                self.regex(index)
                    .captures_iter(window)
                    .filter_map(move |captures| self.value(index, &captures))
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
    fn regex(&self, index: usize) -> &Regex {
        &self.rule(index).regex
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
        if let Some(finder) = self.metas[index].finder {
            return finder(text)
                .into_iter()
                .filter_map(|range| {
                    let captures = regex.captures_at(&text[..range.end], range.start)?;
                    (captures.get(0)?.range() == range).then_some(captures)
                })
                .collect();
        }
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

    fn capture_group(&self, index: usize) -> Option<usize> {
        self.span_groups[index]
    }

    /// K05: config-line values of the generic key-bound rules; a value
    /// counts with the length bounds of the rule's regex.
    fn structured_regex(&self, index: usize) -> Option<&Regex> {
        self.rule(index).structured.as_ref()
    }

    /// K05: the env, INI/properties and HTTP header values whose key the
    /// rule's key grammar accepts: as the whole key (`dlp_env_var_secret`)
    /// or as its last word, with the rule's key gate (T09). The value
    /// checks of [`Self::allows_match`] then apply as for a regex match.
    /// K05B adds YAML, JSON and TOML values and array items. A plural key
    /// (`api_keys`) binds only items; an item stands apart from its key, so
    /// it is checked on its own ([`rules::is_item_value`]) and the key must
    /// not name a digest. A list binds its items only if every item passes,
    /// also the shape check of [`Self::allows_match`] (no UUID, digest or
    /// object id): a credential list holds no words, templates, tokenizer
    /// entries or identifiers. K05C adds HCL attributes and `variable`
    /// defaults and XML elements and attributes; every value is shape-checked
    /// under its bound key (a digest name in `variable "password_sha256"` or
    /// `<hashed_password>`), which may stand apart from it.
    fn structured_values(
        &self,
        index: usize,
        prepared: &crate::threat::NativeText<'_>,
    ) -> Vec<crate::detectors::StructuredValue> {
        let rule = self.rule(index);
        if let Some(key) = &rule.bound_key {
            return self.bound_key_values(index, key, prepared);
        }
        let Some(keys) = &rule.config_key else {
            return Vec::new();
        };
        let text = prepared.text();
        let key_gate = self.metas[index].key_gate;
        let mut values =
            super::config_keys::config_values(text, prepared.sql_statements(), &keys.find);
        let mut failed_lists = Vec::new();
        // G02: whether the text is a config document, per family of formats.
        let documents: [std::cell::OnceCell<bool>; 4] = Default::default();
        values.retain(|config| {
            let binds = keys.binds(text, config, key_gate, || {
                let family = super::config_keys::DocumentFamily::of(config.format);
                *documents[family as usize]
                    .get_or_init(|| super::config_keys::is_config_document(text, family))
                    && !rules::is_key_reference(&text[config.value.clone()])
            });
            let key = &text[config.key.clone()];
            // K05C: the shape check under the bound key, which need not stand
            // before the value on its line.
            // T23: a hex digest or a crypt hash under a password key of a SQL
            // row is the stored hash of a password (a `password` column of a
            // user table).
            let shaped = || {
                !(self.tiers[index] == Some(OverlapTier::Generic)
                    && (rules::non_secret_shape_under(text, config.value.clone(), key).is_some()
                        || (config.format == super::config_keys::ConfigFormat::Sql
                            && self.rule_ids[index] == "dlp_password_assignment"
                            && rules::is_password_digest(&text[config.value.clone()]))))
            };
            // T23: a field of a SQL row is a quoted field, as in JSON; a
            // value-gated rule wants a value that suits one (no word or
            // identifier: `'testpass'` in the seed rows of a test database).
            let field = || {
                config.format != super::config_keys::ConfigFormat::Sql
                    || self.metas[index].value_gate.is_none()
                    || rules::suits_field_key(&text[config.value.clone()])
            };
            if !config.item {
                return binds == Some(false) && shaped() && field();
            }
            let passes = binds.is_some()
                && rules::is_item_value(&text[config.value.clone()])
                && !rules::key_names_digest(key)
                && shaped();
            if !passes {
                failed_lists.push(config.key.start);
            }
            passes
        });
        values
            .into_iter()
            .filter(|config| !(config.item && failed_lists.contains(&config.key.start)))
            .map(|config| crate::detectors::StructuredValue {
                key: config.key,
                value: config.value,
                carrier: config.format.as_str(),
            })
            .collect()
    }

    /// F-GEN2: a rule may hold its value in one group per quoting style
    /// (`"…"`, `'…'`, bare); the value is the first group from the rule's
    /// `span_group` on that took part in the match.
    fn value_group(&self, index: usize, captures: &regex::Captures<'_>) -> Option<usize> {
        let first = self.span_groups[index]?;
        (first..captures.len())
            .find(|&group| captures.get(group).is_some())
            .or(Some(first))
    }

    fn preserve_cross_label_overlaps(&self) -> bool {
        true
    }

    /// Drops prefix-rule values that are no whole token (T01), values
    /// without the context their rule needs (F01), code expressions, words
    /// and credential names after generic keys (F-GEN1), compound keys of
    /// the wrong shape (T09), generic
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
        // K08: a generic key that is the userinfo of a URL (`https://token:…@`,
        // since T09 also `https://github_token:…@`) belongs to the URL
        // credential, also when that has no value to report.
        if self.tiers[index] == Some(OverlapTier::Generic)
            && captures.get(0).is_some_and(|matched| {
                text[..matched.start()]
                    .trim_end_matches(|c: char| {
                        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
                    })
                    .ends_with("://")
            })
        {
            return false;
        }
        // T35: a dump rule fires on a dump with rows only.
        if self.entity_groups[index] == "dlp.content.database_dump" && !prepared.is_sql_dump() {
            return false;
        }
        let meta = &self.metas[index];
        // T01: a prefix rule's value inside an identifier, hex run or base64
        // blob is no token.
        if let Some(boundary) = meta.boundary {
            if let Some(value) = self.value(index, captures) {
                if !super::boundary::is_whole_token(text, value.range(), boundary) {
                    return false;
                }
            }
        }
        // F01: a value whose shape is no proof needs its context.
        if let Some(gate) = meta.context_gate {
            if let Some(value) = self.value(index, captures) {
                if !gate(text, value.range()) {
                    return false;
                }
            }
        }
        // K05: a config-line value had its key checked when it was bound.
        let structured = captures.name("structured").is_some();
        // F-GEN1: a generic key's value must look like a secret. K05B: an
        // array item, whose key stands apart, was checked when it was bound.
        if let Some(gate) = meta.value_gate {
            if let Some(value) = self.value(index, captures) {
                if !(structured && super::config_keys::is_item(text, value.start()))
                    && !gate(text, value.range())
                {
                    return false;
                }
            }
        }
        // K05: a key binds no value of a shape that is no secret.
        if self.tiers[index] == Some(OverlapTier::Generic) {
            if let Some(value) = self.value(index, captures) {
                if rules::non_secret_shape(text, value.range()).is_some() {
                    return false;
                }
            }
        }
        // T09: a compound or camelCase key must have the shape of one.
        if let (Some(gate), false) = (meta.key_gate, structured) {
            if let (Some(key), Some(value)) = (captures.get(0), self.value(index, captures)) {
                if !gate(text, key.start(), value.range()) {
                    return false;
                }
            }
        }
        let check = self.example_checks[index];
        let placeholder_check = self.placeholder_checks[index];
        if check == ExampleCheck::Off && !placeholder_check && meta.min_entropy.is_none() {
            return true;
        }
        let Some(value) = self.value(index, captures) else {
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
        // F03: a generic rule's value that is a checksummed provider token
        // with a wrong checksum is no secret of that provider either; P10:
        // nor is a token prefix with a placeholder or a public token.
        if check == ExampleCheck::Generic
            && (self.fails_token_checksum(value.as_str())
                || self.has_wrong_token_length(text, value.range())
                || self.has_placeholder_body(value.as_str())
                || rules::is_public_token(value.as_str()))
        {
            return false;
        }
        if rules::is_prose_rule(rule_id) && self.has_token_prefix(value.as_str()) {
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
            .get(self.value_group(index, captures).unwrap_or(0))
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
        details.extend(
            rules::structure_details(self.rule_ids[index], value)
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value)),
        );
        details
    }

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        anchors::details(text, &self.anchor_regexes, DLP_ANCHOR_PATTERNS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_searches_find_what_their_regexes_find() {
        DLP_ANCHOR_PATTERNS.iter().for_each(|anchor| {
            crate::detectors::word_boundary::assert_finds_as_regex(anchor.pattern)
        });
    }
}

#[cfg(test)]
mod prepare_tests {
    use super::*;

    /// Only the rules the gates enable are compiled: the default gates keep
    /// the opt-in document classes off. A rule that later gates enable
    /// compiles on its first scan and finds what a fully compiled pipeline finds.
    #[test]
    fn prepare_compiles_only_the_enabled_rules() {
        let pipeline = DlpPipeline::new();
        assert!((0..DLP_PATTERNS.len()).all(|index| !pipeline.compiled(index)));
        pipeline.prepare(crate::native::default_rule_enabled);
        let mut off = 0;
        for (index, pattern) in DLP_PATTERNS.iter().enumerate() {
            let enabled = crate::native::default_rule_enabled(pattern.name);
            off += usize::from(!enabled);
            assert_eq!(pipeline.compiled(index), enabled, "{}", pattern.name);
        }
        assert!(off > 0, "some DLP rules are opt-in");
        let expected = DlpPipeline::new();
        expected.prepare(|_| true);
        let text = "PRIVILEGED AND CONFIDENTIAL attorney-client communication, \
                    password = \"hunter2-Very-Secret-42\"";
        let prepared = crate::threat::NativeText::new(text);
        for mode in [ScoreMode::Strict, ScoreMode::Recall] {
            let lazy = pipeline.detect_prepared_with_mode(&prepared, |_| true, true, mode);
            let full = expected.detect_prepared_with_mode(&prepared, |_| true, true, mode);
            assert_eq!(lazy.evidence_spans, full.evidence_spans, "{mode}");
            assert_eq!(lazy.details, full.details, "{mode}");
        }
    }
}

#[cfg(test)]
mod dump_tests {
    use super::*;

    /// The dump rules that fire on `text` with every rule on (T35).
    fn dump_rules(text: &str) -> Vec<String> {
        let prepared = crate::threat::NativeText::new(text);
        let detection = DlpPipeline::shared().detect_prepared_with_mode(
            &prepared,
            |_| true,
            true,
            ScoreMode::Strict,
        );
        let mut rules: Vec<String> = detection
            .details
            .get("matched_rules")
            .and_then(|rules| rules.as_array())
            .into_iter()
            .flatten()
            .filter_map(|rule| rule["rule_id"].as_str())
            .filter(|id| id.starts_with("dlp_database_dump_"))
            .map(str::to_string)
            .collect();
        rules.sort();
        rules.dedup();
        rules
    }

    const BOTH: [&str; 2] = ["dlp_database_dump_header", "dlp_database_dump_insert"];

    /// T35: mysqldump writes `-- MySQL dump 10.13`, not `database dump`, and
    /// a multi-row INSERT may put each tuple on its own line.
    #[test]
    fn mysqldump_with_customer_rows_fires_both_dump_rules() {
        let extended = "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n--\n\
            -- Host: db-prod-01    Database: crm\n\n\
            LOCK TABLES `customers` WRITE;\n\
            INSERT INTO `customers` VALUES (1,'Anna Berger','anna.berger@posteo.de','DE89370400440532013000'),(2,'Jonas Weber','j.weber@gmx.net','DE02120300000000202051');\n\
            UNLOCK TABLES;\n";
        assert_eq!(dump_rules(extended), BOTH);
        let pretty = "-- MariaDB dump 10.19  Distrib 10.11.8-MariaDB\n\n\
            INSERT INTO customers (id, name, email, iban) VALUES\n\
            \x20 (1, 'Anna Berger', 'anna.berger@posteo.de', 'DE89370400440532013000'),\n\
            \x20 (2, 'Jonas Weber', 'j.weber@gmx.net', 'DE02120300000000202051');\n";
        assert_eq!(dump_rules(pretty), BOTH);
    }

    #[test]
    fn pg_dump_copy_rows_and_sqlite_dump_fire_both_dump_rules() {
        let pg = "--\n-- PostgreSQL database dump\n--\n\n\
            COPY public.kunden (id, vorname, nachname, email) FROM stdin;\n\
            1\tAnna\tBerger\tanna.berger@posteo.de\n\
            2\tJonas\tWeber\tj.weber@gmx.net\n\\.\n";
        assert_eq!(dump_rules(pg), BOTH);
        let sqlite = "PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\n\
            CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT);\n\
            INSERT INTO customers VALUES(1,'Anna Berger','anna.berger@posteo.de');\n\
            COMMIT;\n";
        assert_eq!(dump_rules(sqlite), BOTH);
    }

    /// T35: a quoted table name with a blank (pg_dump, SQLite `.dump`) and a
    /// single-column COPY block hold rows as well.
    #[test]
    fn quoted_table_names_and_single_column_copy_rows_fire_both_dump_rules() {
        let sqlite = "PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\n\
            INSERT INTO \"customer records\" VALUES('Anna Berger','anna.berger@posteo.de');\n\
            COMMIT;\n";
        assert_eq!(dump_rules(sqlite), BOTH);
        let pg_quoted = "--\n-- PostgreSQL database dump\n--\n\n\
            COPY public.\"Kunden Liste\" (id, email) FROM stdin;\n\
            1\tanna.berger@posteo.de\n\\.\n";
        assert_eq!(dump_rules(pg_quoted), BOTH);
        let single_column = "--\n-- PostgreSQL database dump\n--\n\n\
            COPY public.customers (email) FROM stdin;\n\
            anna.berger@posteo.de\nj.weber@gmx.net\n\\.\n";
        assert_eq!(dump_rules(single_column), BOTH);
    }

    /// T35: DDL without rows and rows without a dump header are no dump.
    #[test]
    fn schemas_migrations_fixtures_and_tutorials_are_no_dump() {
        let schema_only = "--\n-- PostgreSQL database dump\n--\n\n\
            CREATE TABLE public.kunden (\n    id integer NOT NULL,\n    email text\n);\n\
            COPY public.kunden (id, email) FROM stdin;\n\\.\n";
        let migration = "-- V12__create_customers.sql\n\
            CREATE TABLE customers (id BIGINT PRIMARY KEY, name TEXT, email TEXT);\n\
            INSERT INTO customers (id, name, email) VALUES (1, 'admin', 'admin@example.com');\n";
        let fixture = "# tests/fixtures/users.sql\n\
            INSERT INTO users (id, name, email) VALUES\n\
            \x20 (1, 'Test User', 'test1@example.com'),\n\
            \x20 (2, 'Fake Person', 'test2@example.com');\n";
        let tutorial = "Step 2: add a row with\n\n\
            INSERT INTO customers (name, email) VALUES ('Alice', 'alice@example.com');\n";
        for text in [schema_only, migration, fixture, tutorial] {
            assert!(dump_rules(text).is_empty(), "{text}");
        }
    }
}
