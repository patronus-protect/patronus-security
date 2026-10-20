// SPDX-License-Identifier: GPL-3.0-only
//! Generic credentials: tokens, credential assignments, auth headers,
//! cookies and connection strings.
use crate::detectors::dlp::dlp::DlpPattern;

pub(super) const RULES: &[DlpPattern] = &[
    // ── Generische Credential-Patterns ───────────────────────────────────────
    DlpPattern {
        name: "dlp_jwt_token",
        pattern: r"(?P<anchor_1>ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_credential_in_url",
        pattern: r#"(?i)[?&](?:password|passwd|passwort|kennwort|secret|geheimnis|token|apikey|api_key|api-key)=([^\\\s&"'\]},]{4,})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_unredacted_url_credential),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_env_var_secret",
        pattern: r"(?-i:[A-Z][A-Z0-9]*[_\-](?:SECRET(?:[_\-]ACCESS)?[_\-]?KEY|SECRET|PASSWORD|PASSWD|PASSWORT|KENNWORT|GEHEIMNIS|TOKEN|API[_\-]?KEY))\s*=\s*([^\s]{8,})",
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
        pattern: r#"(?i)\b(?:api[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth[ _-]?token|client[ _-]?secret|encryption[ _-]?key|master[ _-]?key|api[ _-]?schl(?:ü|ue)ssel|zugangstoken|geheimnis|verschl(?:ü|ue)sselungsschl(?:ü|ue)ssel|secret|token)\b\s*(?:=|:|\bis\b|\bist\b|\blautet\b)\s*["']?([^\s"';,}\]]{8,150})"#,
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
];

/// Runs after `hashes::RULES`, see the registry order in `rules/mod.rs`.
pub(super) const URL_USERINFO_RULES: &[DlpPattern] = &[DlpPattern {
    name: "dlp_url_userinfo_password",
    pattern: r#"(?i)\b(?:jdbc:)?[a-z][a-z0-9+.-]{1,20}://[^/\s:@]+:([^@\s/]{4,150})@[^\s/]+"#,
    entity_group: "CREDENTIAL",
    validator: Some(is_secret_value),
    span_group: Some(1),
}];

fn is_unredacted_url_credential(candidate: &str) -> bool {
    is_secret_value(candidate)
}

/// Shared value check of the credential and hash rules.
pub(super) fn is_secret_value(candidate: &str) -> bool {
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
    value.len() >= 4
        && has_multiple_characters
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
