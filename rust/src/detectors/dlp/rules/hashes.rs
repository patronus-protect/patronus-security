// SPDX-License-Identifier: GPL-3.0-only
//! Password hashes.
use super::credentials::is_secret_value;
use super::likeness;
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength};

pub(super) const RULES: &[DlpPattern] = &[DlpPattern {
    name: "dlp_password_hash",
    // T09: key shapes as for the credential assignments.
    pattern: concat!(
        r"(?i)(?:password[ _-]?hash|passwort[ _-]?hash|passwd[ _-]?hash)(?-u:\b)(?:",
        xml_value_attribute!(),
        "|",
        key_suffix!(),
        r#"(?::|=>|=)|)\s*(?:\\?["'])?(\$(?:2[aby]|argon2(?:i|d|id))\$[^\s"'\\]{20,}|[A-Fa-f0-9]{32,128})"#,
    ),
    entity_group: "PASSWORD_HASH",
    validator: Some(is_secret_value),
    span_group: Some(1),
    base_score: 35,
    meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["passw"])
        .with_subtype(SecretSubtype::PasswordHash)
        .with_key_gate(likeness::is_key_prefix),
}];
