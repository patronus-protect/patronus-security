// SPDX-License-Identifier: MIT OR Apache-2.0
//! Password hashes.
use super::credentials::is_secret_value;
use super::likeness;
use super::ProviderKey;
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength};

/// `dlp_password_hash`: the hash's key; T23: SQL key fields bind through it.
macro_rules! password_hash_key {
    () => {
        r"(?i)(?:password[ _-]?hash|passwort[ _-]?hash|passwd[ _-]?hash)(?-u:\b)"
    };
}

/// `dlp_password_hash`: a bcrypt/Argon2 hash or a hex digest.
macro_rules! password_hash_value {
    () => {
        r#"\$(?:2[aby]|argon2(?:i|d|id))\$[^\s"'\\]{20,}|[A-Fa-f0-9]{32,128}"#
    };
}

/// T23: the key field of a SQL settings row that binds the next field
/// (`dlp::sql_rows::key_field_values`) to `dlp_password_hash`. A
/// `password_hash` column of a user table binds nothing.
pub(super) const SQL_KEY: ProviderKey = ProviderKey {
    key: password_hash_key!(),
    value: password_hash_value!(),
};

pub(super) const RULES: &[DlpPattern] = &[DlpPattern {
    name: "dlp_password_hash",
    // T09: key shapes as for the credential assignments.
    pattern: concat!(
        password_hash_key!(),
        "(?:",
        xml_value_attribute!(),
        "|",
        key_suffix!(),
        r#"(?::|=>|=)|)\s*(?:\\?["'])?("#,
        password_hash_value!(),
        ")",
    ),
    entity_group: "PASSWORD_HASH",
    validator: Some(is_secret_value),
    span_group: Some(1),
    base_score: 35,
    meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["passw"])
        .with_subtype(SecretSubtype::PasswordHash)
        .with_key_gate(likeness::is_key_prefix),
}];
