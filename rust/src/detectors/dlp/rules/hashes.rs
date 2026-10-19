// SPDX-License-Identifier: GPL-3.0-only
//! Password hashes.
use super::credentials::is_secret_value;
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, ValidatorStrength};

pub(super) const RULES: &[DlpPattern] = &[DlpPattern {
    name: "dlp_password_hash",
    pattern: r#"(?i)\b(?:password[ _-]?hash|passwort[ _-]?hash|passwd[ _-]?hash)\b\s*(?::|=)?\s*["']?(\$(?:2[aby]|argon2(?:i|d|id))\$[^\s"']{20,}|[A-Fa-f0-9]{32,128})"#,
    entity_group: "PASSWORD_HASH",
    validator: Some(is_secret_value),
    span_group: Some(1),
    meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["passw"]),
}];
