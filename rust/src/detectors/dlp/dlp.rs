// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    detectors::{NativeMatchValidator, NativeRegexDetector},
    post_prediction::is_real_secret_assignment,
    EvaluationResult,
};
use regex::Regex;

/// A single DLP heuristic pattern (credentials / secrets).
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

/// Context facts for downstream DLP analysis. Anchors describe nearby content
/// but never become findings by themselves.
struct DlpAnchorPattern {
    category: &'static str,
    strength: &'static str,
    anchor_kind: &'static str,
    pattern: &'static str,
}

static DLP_ANCHOR_PATTERNS: &[DlpAnchorPattern] = &[
    DlpAnchorPattern {
        category: "credentials_secrets",
        strength: "strong",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:passwort|kennwort|zugangsdaten|anmeldedaten|api[ _-]?(?:key|schl(?:ü|ue)ssel)|zugangs[ _-]?schl(?:ü|ue)ssel|access[ _-]?key|secret[ _-]?access[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth(?:entication|orization)?[ _-]?token|client[ _-]?secret|client[ _-]?credentials|service[ _-]?account[ _-]?key|encryption[ _-]?key|master[ _-]?key|signing[ _-]?key|private[ _-]?key|secret[ _-]?key|shared[ _-]?secret|webhook[ _-]?secret|database[ _-]?password|connection[ _-]?string|database[ _-]?url|jdbc[ _-]?url|mongodb[ _-]?uri|credentials?|login[ _-]?credentials?|password|passwd|password[ _-]?hash)\b",
    },
    DlpAnchorPattern {
        category: "credentials_secrets",
        strength: "weak",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:token|secret|schl(?:ü|ue)ssel|credential|login|pwd)\b",
    },
    DlpAnchorPattern {
        category: "credentials_secrets",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?m)\b(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|GITHUB_TOKEN|GITLAB_TOKEN|NPM_TOKEN|SLACK_TOKEN|DB_PASSWORD|DATABASE_URL|WEBHOOK_SECRET|SIGNING_KEY|SESSION_SECRET|PRIVATE_KEY|SECRET_KEY)\b",
    },
    DlpAnchorPattern {
        category: "auth_header_cookie",
        strength: "strong",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:authorization|proxy-authorization|bearer[ 	]+token|basic[ 	]+auth(?:entication)?|x-api-key|cookie|set-cookie|session[ _-]?(?:id|token)|jsessionid|phpsessid|auth[ _-]?cookie|csrf[ _-]?token|xsrf[ _-]?token|x-csrf-token|x-xsrf-token|signed[ _-]?url|x-amz-signature|x-goog-signature)\b",
    },
    DlpAnchorPattern {
        category: "business_record_identifier",
        strength: "strong",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:ust[.-]?(?:idnr|id|ident(?:ifikationsnummer)?)|umsatzsteuer(?:-identifikationsnummer)?|mehrwertsteuer[ _-]?id|vat[ _-]?(?:id|number)|handelsregister(?:nummer|eintrag)|register(?:nummer|zeichen)|hr[ab]|gnr|vereinsregister(?:nummer)?|partnerschaftsregister(?:nummer)?|bsnr|betriebsstättennummer|betriebsstaettennummer|praxisnummer|aktenzeichen|geschäftszeichen|geschaeftszeichen|fallnummer|fall[ _-]?id|vorgangsnummer|vorgangs[ _-]?id|case[ _-]?(?:id|number|reference)|file[ _-]?number|vertragsnummer|vertrags[ _-]?id|contract[ _-]?(?:id|number|reference)|policynummer|policy[ _-]?number|schadennummer|leistungsfallnummer|claim[ _-]?(?:id|number|reference)|bestellnummer|auftragsnummer|order[ _-]?(?:id|number|reference)|purchase[ _-]?order|rechnungsnummer|rechnungs[ _-]?id|invoice[ _-]?(?:id|number|reference)|belegnummer|projekt(?:nummer|[ _-]?id)|project[ _-]?(?:id|number|code)|organisations[ _-]?id|unternehmens[ _-]?(?:id|kennung)|firmenkennung|mandanten[ _-]?(?:id|nummer)|tenant[ _-]?(?:id|number)|organization[ _-]?(?:id|number)|company[ _-]?(?:id|number))\b",
    },
    DlpAnchorPattern {
        category: "internal_business_metric",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:ebitda[ _-]?marge|ebit[ _-]?marge|rohertragsmarge|deckungsbeitrag|bruttomarge|nettomarge|gross[ _-]?margin|net[ _-]?margin|contribution[ _-]?margin|annual[ _-]?recurring[ _-]?revenue|monthly[ _-]?recurring[ _-]?revenue|arr|mrr|cash[ _-]?burn|burn[ _-]?rate|runway|umsatzplanung|umsatzprognose|revenue[ _-]?forecast|sales[ _-]?forecast|budgetplanung|planwert|istwert|forecast)\b",
    },
    DlpAnchorPattern {
        category: "internal_business_metric",
        strength: "weak",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:marge|umsatz|rohertrag|ebitda|ebit|revenue|margin|budget|target|actuals?)\b",
    },
    DlpAnchorPattern {
        category: "source_code_config",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?m)^[ \t]*(?:```[A-Za-z0-9_+.-]*|#!\s*/(?:usr/)?bin/(?:env[ \t]+)?(?:bash|sh|zsh|python|ruby|node)|(?:pub[ \t]+)?(?:async[ \t]+)?(?:fn|def|function|class|interface|struct|enum)[ \t]+[A-Za-z_][A-Za-z0-9_]*|(?:from[ \t]+[A-Za-z_][A-Za-z0-9_.]*[ \t]+import|import[ \t]+[A-Za-z_$]|use[ \t]+[A-Za-z_]|package[ \t]+[A-Za-z_]|using[ \t]+[A-Za-z_.]+;)|(?:const|let|var)[ \t]+[A-Za-z_$][A-Za-z0-9_$]*[ \t]*(?::[^=\n]+)?=|\$env:[A-Za-z_][A-Za-z0-9_]*|Import-Module\b|apiVersion:[ \t]*[^\n]+|kind:[ \t]*(?:Deployment|StatefulSet|DaemonSet|Service|Secret|ConfigMap)\b|FROM[ \t]+[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?$|(?:RUN|COPY|ADD|ENTRYPOINT|CMD)[ \t]+[^\n]+)$",
    },
    DlpAnchorPattern {
        category: "source_code_config",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:source[ 	]+code|quellcode|codebase|repository|repo|configuration[ 	]+file|config[ 	]+file|konfigurationsdatei|dockerfile|docker[ 	]+compose|kubernetes[ 	]+manifest|helm[ 	]+chart|terraform[ 	]+state)\b",
    },
    DlpAnchorPattern {
        category: "sql_database_dump",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?im)^[ \t]*(?:--[ \t]*(?:PostgreSQL|MySQL|MariaDB|SQLite)[ \t]+database[ \t]+dump|(?:SELECT\b[^;\n]*\bFROM\b|UPDATE\b[^;\n]*\bSET\b|INSERT[ \t]+INTO\b[^;\n]*\bVALUES\b|DELETE[ \t]+FROM\b)|CREATE[ \t]+TABLE\b|COPY[ \t]+[^\n]+[ \t]+FROM[ \t]+stdin|LOCK[ \t]+TABLES\b|PRAGMA[ \t]+foreign_keys\b|pg_dump\b|mysqldump\b)",
    },
    DlpAnchorPattern {
        category: "sql_database_dump",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:database[ 	]+dump|datenbank[ 	]*(?:dump|export|sicherung)|sql[ 	]+dump|schema[ 	]+dump|table[ 	]+dump|backup[ 	]+file)\b",
    },
    DlpAnchorPattern {
        category: "system_log_stacktrace",
        strength: "strong",
        anchor_kind: "structural",
        pattern: r"(?im)^(?:Traceback \(most recent call last\):|thread '[^']+' panicked at|panic: [^\n]+|goroutine[ \t]+\d+[ \t]+\[[^\]]+\]:|Caused by:[ \t]+[^\n]+|[ \t]+at[ \t]+[A-Za-z0-9_.$<>]+\([^\n]+:\d+\)|\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?:ERROR|FATAL|CRITICAL)[ \t]+)",
    },
    DlpAnchorPattern {
        category: "system_log_stacktrace",
        strength: "medium",
        anchor_kind: "lexical",
        pattern: r"(?i)\b(?:stack[ 	]*trace|stacktrace|exception[ 	]+trace|fehlerprotokoll|systemprotokoll|application[ 	]+log|server[ 	]+log|crash[ 	]+log|panic[ 	]+report|core[ 	]+dump)\b",
    },
];

pub static DLP_PATTERNS: &[DlpPattern] = &[
    // ── AI / LLM API Keys ────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_anthropic_key",
        pattern: r"sk-ant-[a-zA-Z0-9\-_]{10,}",
        entity_group: "API_KEY",
        validator: Some(is_real_secret_assignment),
        span_group: None,
    },
    DlpPattern {
        name: "dlp_openai_key",
        pattern: r"sk-proj-[a-zA-Z0-9\-_]{10,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_openai_legacy",
        pattern: r"\bsk-[a-zA-Z0-9]{48}\b",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_openai_svc",
        pattern: r"sk-svcacct-[a-zA-Z0-9\-]{10,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_huggingface",
        pattern: r"hf_[A-Za-z0-9]{20,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_groq_key",
        pattern: r"gsk_[a-zA-Z0-9]{48,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_xai_key",
        pattern: r"xai-[a-zA-Z0-9\-_]{80,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_replicate",
        pattern: r"r8_[A-Za-z0-9]{20,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
    },
    // ── Cloud Provider Keys ──────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_aws_access_key",
        pattern: r"(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_aws_secret_key",
        pattern: r#"(?i)(?:aws_secret_access_key|SecretAccessKey)\s*["'=:\s]{1,5}\s*([A-Za-z0-9/+=]{40})"#,
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_google_api_key",
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_google_oauth_token",
        pattern: r"ya29\.[a-zA-Z0-9_\-]{20,}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_gcp_client_secret",
        pattern: r"GOCSPX-[A-Za-z0-9_\-]{28,}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
    },
    // ── Source Control / Dev Tools ───────────────────────────────────────────
    DlpPattern {
        name: "dlp_github_token",
        pattern: r"gh[pousr]_[A-Za-z0-9_]{32,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_github_pat",
        pattern: r"github_pat_[a-zA-Z0-9_]{36,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_gitlab_pat",
        pattern: r"glpat-[a-zA-Z0-9\-_]{20,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_npm_token",
        pattern: r"npm_[A-Za-z0-9]{36,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    // ── Payment ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_stripe_key",
        pattern: r"[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}",
        entity_group: "PAYMENT_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_stripe_webhook",
        pattern: r"whsec_[a-zA-Z0-9_\-]{20,}",
        entity_group: "PAYMENT_KEY",
        validator: None,
        span_group: None,
    },
    // ── Communication ────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_slack_token",
        pattern: r"xox[bpras]-[0-9a-zA-Z\-]{15,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_discord_token",
        pattern: r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    // ── Crypto ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_eth_private_key",
        pattern: r"0x[0-9a-f]{64}\b",
        entity_group: "CRYPTO_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_btc_wif",
        pattern: r"(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})",
        entity_group: "CRYPTO_KEY",
        validator: None,
        span_group: None,
    },
    // ── Generische Credential-Patterns ───────────────────────────────────────
    DlpPattern {
        name: "dlp_private_key_block",
        pattern: r"(?s)-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_private_key_header",
        pattern: r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_jwt_token",
        pattern: r"(?:ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_credential_in_url",
        pattern: r#"(?i)[?&](?:password|passwd|secret|token|apikey|api_key|api-key)=([^\\\s&"'\]},]{4,})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_unredacted_url_credential),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_env_var_secret",
        pattern: r"(?-i:[A-Z][A-Z0-9]*[_\-](?:SECRET(?:[_\-]ACCESS)?[_\-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_\-]?KEY))\s*=\s*([^\s]{8,})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    // ── Generic credentials / connection strings ───────────────────────────
    DlpPattern {
        name: "dlp_password_assignment",
        pattern: r#"(?i)\b(?:password|passwort|passwd|kennwort|pwd)\b\s*(?:=|:|\bis\b|\bist\b|\blautet\b)\s*["']?([^\s"';,}\]]{4,150})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_generic_credential_assignment",
        pattern: r#"(?i)\b(?:api[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth[ _-]?token|client[ _-]?secret|encryption[ _-]?key|master[ _-]?key|secret|token)\b\s*(?:=|:|\bis\b|\bist\b|\blautet\b)\s*["']?([^\s"';,}\]]{8,150})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_bearer_token",
        pattern: r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{8,})",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_basic_auth",
        pattern: r"(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_signed_url_signature",
        pattern: r"(?i)[?&](?:X-Amz-Signature|X-Goog-Signature|Signature|sig)=([A-Fa-f0-9]{16,}|[A-Za-z0-9_~+/%=-]{20,})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_session_cookie",
        pattern: r"(?i)\b(?:Cookie|Set-Cookie)\s*:[^\r\n]{0,200}?\b(?:sessionid|session|JSESSIONID|PHPSESSID)=([A-Za-z0-9._~+/%=-]{8,})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_csrf_token",
        pattern: r"(?i)\b(?:X-CSRF-Token|X-XSRF-Token|csrf[ _-]?token|xsrf[ _-]?token)\b\s*(?::|=)?\s*([A-Za-z0-9._~+/%=-]{8,})",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_password_hash",
        pattern: r#"(?i)\b(?:password[ _-]?hash|passwort[ _-]?hash|passwd[ _-]?hash)\b\s*(?::|=)?\s*["']?(\$(?:2[aby]|argon2(?:i|d|id))\$[^\s"']{20,}|[A-Fa-f0-9]{32,128})"#,
        entity_group: "PASSWORD_HASH",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_url_userinfo_password",
        pattern: r#"(?i)\b(?:jdbc:)?[a-z][a-z0-9+.-]{1,20}://[^/\s:@]+:([^@\s/]{4,150})@[^\s/]+"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    // ── German and business identifiers (anchor-bound) ─────────────────────
    DlpPattern {
        name: "dlp_de_vat_id",
        pattern: r"(?i)\b(?:USt[.-]?IdNr|Umsatzsteuer(?:-Identifikationsnummer)?|VAT[ -]?ID)\.?\s*(?::|=|lautet)?\s*(DE\s?\d{3}\s?\d{3}\s?\d{3})\b",
        entity_group: "dlp.de.vat_id",
        validator: None,
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_de_commercial_register_number",
        pattern: r"(?i)\b((?:HR[AB]|VR|PR|GnR)\s*\d{1,8})\b",
        entity_group: "dlp.de.commercial_register_number",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_de_facility_number_bsnr",
        pattern: r"(?i)\b(?:BSNR|Betriebsstättennummer)\b\s*(?::|=|lautet)?\s*(\d{9})\b",
        entity_group: "dlp.de.facility_number_bsnr",
        validator: None,
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_record_case_id",
        pattern: r"(?i)\b(?:Aktenzeichen|Fallnummer|Case[ -]?ID|Vorgangsnummer)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.case_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_record_contract_id",
        pattern: r"(?i)\b(?:Vertragsnummer|Vertrags[ -]?ID|Contract[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.contract_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_record_claim_id",
        pattern: r"(?i)\b(?:Schadennummer|Leistungsfallnummer|Claim[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.claim_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_record_order_id",
        pattern: r"(?i)\b(?:Bestellnummer|Auftragsnummer|Order[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.order_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_record_invoice_id",
        pattern: r"(?i)\b(?:Rechnungsnummer|Rechnungs[ -]?ID|Invoice[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.record.invoice_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_project_id",
        pattern: r"(?i)\b(?:Projekt[ -]?(?:ID|Nummer)|Project[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.project_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_organization_id",
        pattern: r"(?i)\b(?:Organisations[ -]?ID|Unternehmens[ -]?ID|Mandanten[ -]?ID|Tenant[ -]?ID|Organization[ -]?ID)\b\s*(?::|=|lautet)?\s*([A-Z0-9][A-Z0-9._/\-]{2,31})\b",
        entity_group: "dlp.organization_id",
        validator: Some(is_identifier_value),
        span_group: Some(1),
    },
    // ── Confidential business content ───────────────────────────────────────
    DlpPattern {
        name: "dlp_internal_business_metric",
        pattern: r"(?i)\b(?:EBITDA[ -]?Marge|EBIT[ -]?Marge|Rohertragsmarge|Deckungsbeitrag|Marge|Umsatz|Rohertrag|EBITDA|EBIT|Forecast)\b(?:\s+(?:liegt|beträgt|ist|bei|von|neu|Plan))?\s*(?::|=)?\s*(?:bei\s+|von\s+)?([+\-]?\d+(?:[.\s]\d{3})*(?:,\d+)?\s*(?:%|Prozent|EUR|Euro|€|CHF|USD|Mio\.?\s*(?:EUR|Euro|€)?|TEUR))",
        entity_group: "dlp.internal.business_metric",
        validator: None,
        span_group: None,
    },
    // ── Source/code-like content ────────────────────────────────────────────
    DlpPattern {
        name: "dlp_database_dump_insert",
        pattern: r"(?im)^[ \t]*INSERT\s+INTO\s+[^;\n]+\s+VALUES\s*\([^;\n]+\);?[ \t]*$",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_fence",
        pattern: r"(?s)```(?:[A-Za-z0-9_+.-]+)?[ \t]*\n.*?\n```",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_statement",
        pattern: r"(?m)^[ \t]*(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>,.\[\] |]*)?\s*=\s*(?:new\s+)?[^;\n]{2,};[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_python_rust_assignment",
        pattern: r#"(?m)^[ \t]*(?:(?:let(?:\s+mut)?|static|final)\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[A-Za-z_][A-Za-z0-9_<>,.\[\] ]*)?\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*\([^\n]*\)|[\[{][^\n]*[\]}]|[rubf]?['"][^\n'"]+['"]|\d+)[ \t]*;?[ \t]*$"#,
        entity_group: "dlp.content.source_code",
        validator: Some(is_non_placeholder_source_assignment),
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_declaration",
        pattern: r"(?m)^[ \t]*(?:pub\s+)?(?:async\s+)?(?:fn|def|function|class|interface|struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*[<(][^\n]*[>)]\s*)?\s*(?:\{|:)[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_import",
        pattern: r"(?m)^[ \t]*(?:from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+[^\n]+|import\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*(?:\s+from\s+)?[^\n;]*)|use\s+[A-Za-z_][A-Za-z0-9_:{}*, ]*);?[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_sql_statement",
        pattern: r"(?im)^[ \t]*(?:SELECT\b[^;\n]*\bFROM\b[^;\n]*|UPDATE\b[^;\n]*\bSET\b[^;\n]*|DELETE\s+FROM\b[^;\n]*);[ \t]*$",
        entity_group: "dlp.content.sql",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_sql_multiline_statement",
        pattern: r"(?is)\b(?:SELECT\b.*?\bFROM\b|UPDATE\b.*?\bSET\b|INSERT\s+INTO\b.*?\bVALUES\b|DELETE\s+FROM\b).*?;",
        entity_group: "dlp.content.sql",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_database_dump_header",
        pattern: r"(?im)^(?:--\s*(?:PostgreSQL|MySQL|MariaDB|SQLite)\s+database\s+dump|PRAGMA\s+foreign_keys\s*=\s*[^;\n]+;?|CREATE\s+TABLE\s+[^\n(]+\s*\([^;]+\);)",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_stacktrace_block",
        pattern: r"(?im)^(?:Traceback \(most recent call last\):|[^\n]*(?:Error|Exception|FATAL)[^\n]*)\n(?:[ \t]+(?:File |at |\.\.\.)[^\n]*\n?){1,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_structured_system_log",
        pattern: r"(?im)^\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?:ERROR|FATAL|CRITICAL)[ \t]+[^\n]+(?:\n\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?:ERROR|FATAL|CRITICAL)[ \t]+[^\n]+){0,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
    },
];

fn is_unredacted_url_credential(candidate: &str) -> bool {
    is_secret_value(candidate)
}

fn is_secret_value(candidate: &str) -> bool {
    let value = candidate
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    let references_secret_storage = value.contains("getenv(")
        || value.contains("environ.")
        || value.starts_with("process.env.")
        || value.contains("env::var(")
        || value.contains("secret_key_ref");
    let has_multiple_characters = value
        .chars()
        .next()
        .is_some_and(|first| value.chars().any(|character| character != first));
    let has_known_provider_prefix = [
        "sk-proj-", "ghp_", "sk_live_", "sk_test_", "rk_live_", "rk_test_",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix));

    value.len() >= 4
        && has_multiple_characters
        && !has_known_provider_prefix
        && !references_secret_storage
        && !matches!(
            value.as_str(),
            "redacted"
                | "[redacted]"
                | "%5bredacted%5d"
                | "changeme"
                | "your-token-here"
                | "replace-me"
                | "your_api_key_here"
        )
        && !value.starts_with("${")
        && !value.starts_with('<')
        && !value.starts_with('[')
}

fn is_non_placeholder_source_assignment(candidate: &str) -> bool {
    let Some((_, value)) = candidate.split_once('=') else {
        return true;
    };
    !matches!(
        value
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "[redacted]" | "[masked]" | "[placeholder]"
    )
}

fn is_identifier_value(candidate: &str) -> bool {
    candidate.chars().any(|ch| ch.is_ascii_digit())
}

pub struct DlpPipeline {
    regexes: Vec<Regex>,
    rule_ids: Vec<&'static str>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<NativeMatchValidator>>,
    span_groups: Vec<Option<usize>>,
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
        let mut entity_groups = Vec::new();
        let mut rule_ids = Vec::new();
        let mut validators = Vec::new();
        let mut span_groups = Vec::new();

        for p in DLP_PATTERNS {
            regexes.push(Regex::new(p.pattern).unwrap());
            entity_groups.push(p.entity_group);
            rule_ids.push(p.name);
            validators.push(p.validator);
            span_groups.push(p.span_group);
        }

        let anchor_regexes = DLP_ANCHOR_PATTERNS
            .iter()
            .map(|anchor| Regex::new(anchor.pattern).unwrap())
            .collect();

        DlpPipeline {
            regexes,
            rule_ids,
            entity_groups,
            validators,
            span_groups,
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

    fn details(&self, text: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let mut anchors = self
            .anchor_regexes
            .iter()
            .zip(DLP_ANCHOR_PATTERNS)
            .flat_map(|(regex, definition)| {
                regex.find_iter(text).map(move |matched| {
                    serde_json::json!({
                        "kind": "anchor",
                        "anchor_kind": definition.anchor_kind,
                        "category": definition.category,
                        "strength": definition.strength,
                        "text": matched.as_str(),
                        "start_byte": matched.start(),
                        "end_byte": matched.end(),
                        "start_char": text[..matched.start()].chars().count(),
                        "end_char": text[..matched.end()].chars().count(),
                    })
                })
            })
            .collect::<Vec<_>>();
        anchors.sort_by_key(|anchor| {
            (
                anchor["start_byte"].as_u64().unwrap_or_default(),
                anchor["end_byte"].as_u64().unwrap_or_default(),
            )
        });

        if anchors.is_empty() {
            std::collections::HashMap::new()
        } else {
            std::collections::HashMap::from([(
                "l1_anchors".to_string(),
                serde_json::Value::Array(anchors),
            )])
        }
    }
}
