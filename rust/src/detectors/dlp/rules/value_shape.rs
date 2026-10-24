// SPDX-License-Identifier: GPL-3.0-only
//! K05: the value-shape filter of the generic key-bound rules
//! (`dlp_env_var_secret`, `dlp_password_assignment`,
//! `dlp_generic_credential_assignment`). A credential-like key binds the
//! value after it, whether the rule's regex or a config line
//! (`detectors::dlp::config_keys`) reads it; before it counts, shapes that are
//! no secret are rejected:
//!
//! - UUIDs (`550e8400-e29b-41d4-a716-446655440000`, also in braces or as
//!   `urn:uuid:`);
//! - algorithm-prefixed digests whose length fits the algorithm
//!   (`sha256:<64 hex>`, `sha1-<40 hex>`, SRI `sha512-<base64>`, go.sum
//!   `h1:<base64>`);
//! - bare hex digests (32, 40, 56, 64, 96 or 128 hex digits) under a key that
//!   names a digest (`hashed_password`, `gehashtes_passwort`, `SHA256_TOKEN`,
//!   `token-prüfsumme`).
//!   Under a plain credential key a hex string stays a secret: OAuth client
//!   secrets, Flask/Rails secret keys and many API keys are hex;
//! - MongoDB ObjectIds (24 hex digits whose leading timestamp lies between
//!   2009 and 2040);
//! - template and format fields (`{client_secret}`, `{{ token }}`,
//!   `%(password)s`, `%s`, `{0}`, `<%= token %>`, an interpolation inside the
//!   value such as `prefix${SUFFIX}`) and variable references
//!   (`$TOKEN`, `${TOKEN}`, `%PASSWORT%`, `$env:TOKEN`, `env:TOKEN`,
//!   secret-manager references); since K05B also unquoted YAML aliases
//!   (`*default_password`) and values encrypted for the repository (SOPS
//!   `ENC[AES256_GCM,data:…]`, `$ANSIBLE_VAULT;…`);
//! - booleans and null words (`true`, `disabled`, `wahr`, `none`), numbers
//!   with an optional unit (`86400`, `1.5`, `30s`), paths and URLs without
//!   credentials (no userinfo, no secret query parameter).
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::{likeness, placeholders};
use crate::detectors::structure::normalize_key;
use crate::detectors::validators::{base64_decode, Base64Kind};

/// A value shape that is no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonSecretShape {
    Uuid,
    /// A digest after its algorithm name.
    PrefixedDigest,
    /// Hex digits of a digest length under a key that names a digest.
    HexDigest,
    ObjectId,
    /// A template, interpolation or format field.
    Template,
    /// A variable, environment or secret-manager reference.
    Reference,
    Boolean,
    Number,
    Path,
    /// A URL without userinfo or secret query parameter.
    Url,
}

static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?i:urn:uuid:)?\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$")
        .unwrap()
});

/// Algorithm name, separator and digest (`sha256:…`, `SHA-1=…`, `h1:…`).
static PREFIXED_DIGEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?i)(?P<algorithm>md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3-(?:224|256|384|512)",
        r"|blake2b|blake2s|blake3|h1)[:=-](?P<digest>[A-Za-z0-9+/_-]+=*)$",
    ))
    .unwrap()
});

/// A format field as the whole value: printf (`%s`, `%-8d`), Python
/// `%(name)s`, `{}`/`{0}`, ERB/EJS `<%= … %>` and Jinja `{% … %}`.
static FORMAT_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:%[-+ #0]*[0-9]*(?:\.[0-9]+)?[sdvqxXfiruS]",
        r"|%\([A-Za-z_][A-Za-z0-9_.-]*\)[-+ #0]*[0-9]*[sdifrx]",
        r"|\{[0-9]*\}",
        r"|<%=?[^%]*%>",
        r"|\{%[^%]*%\})$",
    ))
    .unwrap()
});

/// Interpolation openers anywhere in a value (`prefix${SUFFIX}`,
/// `{{ host }}-key`): the value is computed, not stored.
const INTERPOLATIONS: &[&str] = &["${", "$(", "{{", "#{", "%(", "<%"];

/// `$env:NAME` (PowerShell), `env:NAME` (Taskfile, Vector, Fluent Bit) and
/// `env.NAME` (GitHub Actions contexts) as the whole value.
static ENV_REFERENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:\$env:|(?i:env)[:.])[A-Za-z_][A-Za-z0-9_]*$").unwrap());

/// An integer or decimal, with digit grouping, exponent and an optional
/// duration, size or percent unit.
/// A SOPS-encrypted value: `ENC[<cipher>,data:…`.
static SOPS_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^ENC\[[A-Z0-9_]+,data:").unwrap());

static NUMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[+-]?[0-9]+(?:[._,][0-9]+)*(?:[eE][+-]?[0-9]+)?(?i:ms|s|m|h|d|w|k|kb|mb|gb|%)?$")
        .unwrap()
});

static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?i)[a-z][a-z0-9+.-]{1,20}://(?P<authority>[^/?#\s]*)(?P<rest>[^\s]*)$").unwrap()
});

/// The host of a URL: a dotted name, `localhost`, an IP address or a single
/// name with a port (`db:5432`), unlike a password after a scheme-like prefix
/// (`opal://Kx7pQ2vL9rT4`).
static URL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:(?:localhost|\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::[0-9]{1,5})?",
        r"|[A-Za-z][A-Za-z0-9-]*:[0-9]{1,5})$",
    ))
    .unwrap()
});

/// Query or fragment parameters that carry a credential in a URL.
static SECRET_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)[?&#;](?:[a-z0-9_.-]*(?:pass|pwd|secret|token|key|sig|signature|auth|credential|code)",
        r"[a-z0-9_.-]*|passwort|kennwort|geheimnis|schluessel|schlüssel)=",
    ))
    .unwrap()
});

/// Booleans and null words of config formats, lower case (EN/DE).
const BOOLEAN_WORDS: &[&str] = &[
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "enabled",
    "disabled",
    "enable",
    "disable",
    "null",
    "none",
    "nil",
    "undefined",
    "empty",
    "ja",
    "nein",
    "wahr",
    "falsch",
    "aktiv",
    "inaktiv",
    "aktiviert",
    "deaktiviert",
    "leer",
];

/// Key words that name a digest rather than the secret itself.
const DIGEST_KEY_WORDS: &[&str] = &[
    "hash",
    "hashed",
    "hashes",
    "digest",
    "checksum",
    "sha",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "md5",
    "fingerprint",
    "integrity",
    "prüfsumme",
    "pruefsumme",
    "hashwert",
    "fingerabdruck",
    "gehasht",
    "gehashte",
    "gehashtes",
    "gehashter",
];

/// Hex digest lengths: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
const HEX_DIGEST_LENGTHS: &[usize] = &[32, 40, 56, 64, 96, 128];

/// ObjectId timestamps from 2009-01-01 (MongoDB's first release) to
/// 2040-01-01, in seconds since the epoch.
const OBJECT_ID_EPOCHS: Range<u32> = 0x495C_0780..0x83AA_7E80;

/// K05: the shape of the value at `range` of `text` that a key binds, if it
/// is no secret. The key is read before the value on its line.
pub(crate) fn non_secret_shape(text: &str, range: Range<usize>) -> Option<NonSecretShape> {
    let value = value_without_terminators(text, range.clone());
    if value.is_empty() {
        return None;
    }
    if UUID.is_match(value) {
        return Some(NonSecretShape::Uuid);
    }
    if is_prefixed_digest(value) {
        return Some(NonSecretShape::PrefixedDigest);
    }
    if is_object_id(value) {
        return Some(NonSecretShape::ObjectId);
    }
    if is_hex_digest(value) && key_before_names_digest(text, range.start) {
        return Some(NonSecretShape::HexDigest);
    }
    if is_variable_reference(value) || is_encrypted_value(value) {
        return Some(NonSecretShape::Reference);
    }
    // K05B: a YAML alias (`password: *default_password`) refers to the
    // anchored value; a quoted `*` starts a password.
    if !text[..range.start].ends_with(['"', '\'', '`'])
        && value.strip_prefix('*').is_some_and(likeness::is_word_like)
    {
        return Some(NonSecretShape::Reference);
    }
    if FORMAT_FIELD.is_match(value)
        || placeholders::is_reference(value)
        || placeholders::is_delimited_variable(value)
        || INTERPOLATIONS.iter().any(|opener| value.contains(opener))
    {
        return Some(NonSecretShape::Template);
    }
    if BOOLEAN_WORDS.contains(&value.to_lowercase().as_str()) {
        return Some(NonSecretShape::Boolean);
    }
    if NUMBER.is_match(value) {
        return Some(NonSecretShape::Number);
    }
    if likeness::is_path(value) {
        return Some(NonSecretShape::Path);
    }
    if is_url_without_credentials(value) {
        return Some(NonSecretShape::Url);
    }
    None
}

/// The value at `range` without what lies outside it in source code: a
/// quoted value loses only the backslash of an escaped closing quote
/// (`\"12345678\"` in a JSON string), since `,`, `;` and `\` inside the
/// quotes belong to the secret; an unquoted value also loses a code
/// terminator (`8107,`).
fn value_without_terminators(text: &str, range: Range<usize>) -> &str {
    const QUOTES: [char; 3] = ['"', '\'', '`'];
    let value = &text[range.clone()];
    let opening = text[..range.start].chars().next_back();
    if let Some(quote) = opening.filter(|c| QUOTES.contains(c)) {
        let closes = text[range.end..].starts_with(quote);
        let backslashes = value.len() - value.trim_end_matches('\\').len();
        return if closes && backslashes % 2 == 1 {
            &value[..value.len() - 1]
        } else {
            value
        };
    }
    value
        .trim()
        .trim_end_matches('\\')
        .trim_end_matches([',', ';'])
}

/// Digest bytes of an algorithm name (lower case, without `-`).
fn digest_bytes(algorithm: &str) -> Option<usize> {
    Some(match algorithm {
        "md5" => 16,
        "sha1" => 20,
        "sha224" | "sha3224" => 28,
        "sha256" | "sha3256" | "blake2s" | "blake3" | "h1" => 32,
        "sha384" | "sha3384" => 48,
        "sha512" | "sha3512" | "blake2b" => 64,
        _ => return None,
    })
}

/// `sha256:<hex>`, `sha1-<hex>`, SRI `sha384-<base64>` or `h1:<base64>`
/// whose digest has the algorithm's length in hex or canonical base64.
fn is_prefixed_digest(value: &str) -> bool {
    let Some(captures) = PREFIXED_DIGEST.captures(value) else {
        return false;
    };
    let algorithm = captures["algorithm"].to_ascii_lowercase().replace('-', "");
    let Some(bytes) = digest_bytes(&algorithm) else {
        return false;
    };
    let digest = &captures["digest"];
    let is_hex = digest.len() == 2 * bytes && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    is_hex
        || [
            Base64Kind::Standard,
            Base64Kind::StandardUnpadded,
            Base64Kind::UrlSafe,
        ]
        .into_iter()
        .any(|kind| base64_decode(digest, kind).is_some_and(|decoded| decoded.len() == bytes))
}

/// Hex digits in one case of a digest length.
fn is_hex_digest(value: &str) -> bool {
    HEX_DIGEST_LENGTHS.contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !(value.bytes().any(|byte| byte.is_ascii_lowercase())
            && value.bytes().any(|byte| byte.is_ascii_uppercase()))
}

/// 24 hex digits in one case whose first four bytes are a plausible
/// ObjectId timestamp.
fn is_object_id(value: &str) -> bool {
    value.len() == 24
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !(value.bytes().any(|byte| byte.is_ascii_lowercase())
            && value.bytes().any(|byte| byte.is_ascii_uppercase()))
        && u32::from_str_radix(&value[..8], 16)
            .is_ok_and(|seconds| OBJECT_ID_EPOCHS.contains(&seconds))
}

/// K05B: a value encrypted for the repository, which holds no plaintext
/// secret: SOPS `ENC[AES256_GCM,data:…,iv:…,tag:…,type:str]` and Ansible
/// Vault `$ANSIBLE_VAULT;1.1;AES256`.
fn is_encrypted_value(value: &str) -> bool {
    SOPS_VALUE.is_match(value) || value.starts_with("$ANSIBLE_VAULT;")
}

/// `$NAME`, `%NAME%`, `!NAME!`, `$env:NAME`, `env:NAME` or a secret-manager
/// reference as the whole value. A `$` before a word with digits
/// (`$ecret2026`) stays a password.
fn is_variable_reference(value: &str) -> bool {
    if ENV_REFERENCE.is_match(value) || placeholders::is_secret_manager_reference(value) {
        return true;
    }
    if let Some(name) = value.strip_prefix('$') {
        return placeholders::is_variable_name(name);
    }
    if let Some(name) = value
        .strip_prefix('%')
        .and_then(|rest| rest.strip_suffix('%'))
    {
        return is_identifier(name);
    }
    false
}

fn is_identifier(name: &str) -> bool {
    name.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// A URL with a host ([`URL_HOST`]) and neither userinfo (`user:pass@`,
/// `token@`) nor a query or fragment parameter that carries a credential.
fn is_url_without_credentials(value: &str) -> bool {
    let Some(captures) = URL.captures(value) else {
        return false;
    };
    URL_HOST.is_match(&captures["authority"]) && !SECRET_PARAMETER.is_match(&captures["rest"])
}

/// Whether the key before the value at `value_start` has a word that names a
/// digest (`hashed_password`, `SHA256_TOKEN`, `token-prüfsumme`).
fn key_before_names_digest(text: &str, value_start: usize) -> bool {
    key_before(text, value_start).is_some_and(key_names_digest)
}

/// Whether `key` has a word that names a digest; K05B checks the key of an
/// array item, which stands apart from it, with this.
pub(crate) fn key_names_digest(key: &str) -> bool {
    normalize_key(key)
        .split(' ')
        .any(|word| DIGEST_KEY_WORDS.contains(&word))
}

/// The key before a value on its line: the identifier before the separator
/// (`=`, `:`, `=>`, prose `is`/`ist`/`lautet` excluded), without quotes,
/// subscripts and blanks around it.
pub(crate) fn key_before(text: &str, value_start: usize) -> Option<&str> {
    let line_start = text[..value_start].rfind('\n').map_or(0, |index| index + 1);
    let head = text[line_start..value_start]
        .trim_end_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '\\'));
    let head = head
        .strip_suffix("=>")
        .or_else(|| head.strip_suffix(['=', ':']))?
        .trim_end_matches(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '\\' | ']' | '[')
        });
    let start = head
        .trim_end_matches(|c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .len();
    let mut key = &head[start..];
    // A line break escaped in a JSON string or notebook cell (`\ngehashtes_passwort`).
    if head[..start].ends_with('\\') && key.len() > 1 && key.starts_with(['n', 't', 'r']) {
        key = &key[1..];
    }
    (!key.is_empty()).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::{key_before, key_names_digest, non_secret_shape, NonSecretShape};

    fn shape(line: &str) -> Option<NonSecretShape> {
        let start = line.find('=').map(|index| index + 1).unwrap();
        let start = start + (line[start..].len() - line[start..].trim_start().len());
        non_secret_shape(line, start..line.len())
    }

    #[test]
    fn uuids_in_every_spelling_and_no_lookalikes() {
        for line in [
            "API_TOKEN=550e8400-e29b-41d4-a716-446655440000",
            "zugangstoken=550E8400-E29B-41D4-A716-446655440000",
            "client_secret={550e8400-e29b-41d4-a716-446655440000}",
            "api_key=urn:uuid:550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert_eq!(shape(line), Some(NonSecretShape::Uuid), "{line}");
        }
        for line in [
            "API_TOKEN=550e8400-e29b-41d4-a716-44665544000",
            "API_TOKEN=550e8400e29b41d4a716446655440000x",
            "API_TOKEN=g50e8400-e29b-41d4-a716-446655440000",
        ] {
            assert_ne!(shape(line), Some(NonSecretShape::Uuid), "{line}");
        }
    }

    #[test]
    fn prefixed_digests_need_the_algorithm_length() {
        let sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let sha1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
        for line in [
            format!("api_key=sha256:{sha256}"),
            format!("SERVICE_SECRET=SHA-256={sha256}"),
            format!("access_token = sha1-{sha1}"),
            "token=md5:5d41402abc4b2a76b9719d911017c592".to_string(),
            // SRI and go.sum digests in base64.
            "secret=sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=".to_string(),
            "token=h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=".to_string(),
        ] {
            assert_eq!(shape(&line), Some(NonSecretShape::PrefixedDigest), "{line}");
        }
        for line in [
            // One hex digit short, a SHA-1 length after sha256, no digest.
            format!("api_key=sha256:{}", &sha256[1..]),
            format!("api_key=sha256:{sha1}"),
            "password=sha1-Kx7pQ2vL9rT4".to_string(),
            "password=md5:Sommer2026!".to_string(),
        ] {
            assert_ne!(shape(&line), Some(NonSecretShape::PrefixedDigest), "{line}");
        }
    }

    #[test]
    fn bare_hex_is_a_digest_only_under_a_digest_key() {
        let hex40 = "e058600160c44518448e682614e37e52e5525e57";
        let hex64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        for line in [
            format!("hashed_password={hex40}"),
            format!("SHA256_TOKEN={hex64}"),
            format!("token-prüfsumme = {hex64}"),
            format!("passwortHash={}", &hex64[..32]),
        ] {
            assert_eq!(shape(&line), Some(NonSecretShape::HexDigest), "{line}");
        }
        for line in [
            format!("client_secret={hex40}"),
            format!("SECRET_KEY={hex64}"),
            format!("API_TOKEN={}", &hex64[..32]),
            // No digest length, mixed case.
            format!("hashed_password={}", &hex40[..38]),
            "hashed_password=E058600160c44518448e682614e37e52e5525e57".to_string(),
        ] {
            assert_eq!(shape(&line), None, "{line}");
        }
    }

    #[test]
    fn object_ids_need_a_plausible_timestamp() {
        // 0x5f8d0c3e is 2020-10-19, 0x65000000 is 2023-09-12.
        for line in [
            "API_TOKEN=5f8d0c3e9b1a2d4c6e8f0a1b",
            "db.password=65000000a1b2c3d4e5f60718",
        ] {
            assert_eq!(shape(line), Some(NonSecretShape::ObjectId), "{line}");
        }
        // 0x10000000 is 1978, 0xf0000000 is 2097; 23 and 25 digits.
        for line in [
            "API_TOKEN=100000009b1a2d4c6e8f0a1b",
            "API_TOKEN=f00000009b1a2d4c6e8f0a1b",
            "API_TOKEN=5f8d0c3e9b1a2d4c6e8f0a1",
            "API_TOKEN=5f8d0c3e9b1a2d4c6e8f0a1b2",
        ] {
            assert_eq!(shape(line), None, "{line}");
        }
    }

    #[test]
    fn templates_references_booleans_numbers_paths_and_urls() {
        let cases = [
            ("client_secret={client_secret}", NonSecretShape::Template),
            ("password=%(db_password)s", NonSecretShape::Template),
            ("API_TOKEN=%s", NonSecretShape::Template),
            ("API_TOKEN={0}", NonSecretShape::Template),
            ("password=<%= @db_password %>", NonSecretShape::Template),
            ("password=${DB_PASSWORD}", NonSecretShape::Template),
            ("passwort={{ lager.passwort }}", NonSecretShape::Template),
            ("token=prefix${SUFFIX}", NonSecretShape::Template),
            (
                "API_TOKEN=lager-{{ umgebung }}-schluessel",
                NonSecretShape::Template,
            ),
            (
                "SERVICE_SECRET=$SERVICE_SECRET_FROM_VAULT",
                NonSecretShape::Reference,
            ),
            ("PASSWORT=%PASSWORT%", NonSecretShape::Reference),
            ("api_key=$env:API_KEY", NonSecretShape::Reference),
            ("api_key=env:LAGER_API_KEY", NonSecretShape::Reference),
            ("API_TOKEN=true", NonSecretShape::Boolean),
            ("kennwort=wahr", NonSecretShape::Boolean),
            ("SERVICE_SECRET=Deaktiviert", NonSecretShape::Boolean),
            ("db_password=12345678901234", NonSecretShape::Number),
            ("API_TOKEN=86400", NonSecretShape::Number),
            ("eatClearTextPassword = 8107,", NonSecretShape::Number),
            ("client_secret=1.5", NonSecretShape::Number),
            ("token_ttl=30s", NonSecretShape::Number),
            ("API_TOKEN=/etc/secrets/api-token", NonSecretShape::Path),
            ("password=C:\\secrets\\db.txt", NonSecretShape::Path),
            ("SERVICE_SECRET=./secrets/service.key", NonSecretShape::Path),
            (
                "API_TOKEN=https://vault.internal/v1/secret/data/api",
                NonSecretShape::Url,
            ),
            ("SERVICE_SECRET=redis://cache:6379/0", NonSecretShape::Url),
            ("api_key=http://localhost:8080/keys", NonSecretShape::Url),
            (
                "client_secret=https://auth.example.org/realms/acme/protocol/openid-connect/token",
                NonSecretShape::Url,
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(shape(line), Some(expected), "{line}");
        }
    }

    #[test]
    fn secrets_keep_their_shape() {
        for line in [
            "DB_PASSWORD=Zllrhzj9796?",
            "SERVICE_SECRET=$ecret2026",
            "password=$kqztrwx4711",
            "client_secret=e058600160c44518448e682614e37e52e5525e57",
            "API_TOKEN=Kq7Zr2Lm9Xw4Tn8Vb3Hd",
            "password=1234abcd!",
            "API_TOKEN={kqztrwx4711}",
            "DATABASE_PASSWORD=https://user:Kq7Zr2Lm9Xw4@db.internal/app",
            "api_key=https://ghp_token@github.com/acme/app.git",
            "EXPORT_TOKEN=https://api.internal/v1/export?api_key=Kq7Zr2Lm9Xw4Tn8Vb3Hd",
            "password=truecolor2026",
            "DB_PASSWORD=opal://Kx7pQ2vL9rT4",
        ] {
            assert_eq!(shape(line), None, "{line}");
        }
    }

    /// The shape of the value between the first and the last `"` of `line`.
    fn quoted_shape(line: &str) -> Option<NonSecretShape> {
        let start = line.find('"').unwrap() + 1;
        let end = line.rfind('"').unwrap();
        non_secret_shape(line, start..end)
    }

    #[test]
    fn punctuation_inside_quotes_belongs_to_the_secret() {
        // `,`, `;` and `\` before the closing quote are part of the value.
        for line in [
            "password = \"12345678;\"",
            "API_TOKEN = \"86400,\"",
            "client_secret = \"550e8400-e29b-41d4-a716-446655440000;\"",
            "api_key = \"$API_KEY,\"",
            "password = \"true,\"",
            "passwort = \"12345678\\\\\"",
        ] {
            assert_eq!(quoted_shape(line), None, "{line}");
        }
        // Quoted shapes without trailing punctuation stay no secrets, also
        // behind an escaped closing quote (`\"12345678\"` in a JSON string).
        for (line, expected) in [
            ("password = \"12345678\"", NonSecretShape::Number),
            (
                "client_secret = \"550e8400-e29b-41d4-a716-446655440000\"",
                NonSecretShape::Uuid,
            ),
            (
                "{\\\"password\\\": \\\"12345678\\\"}",
                NonSecretShape::Number,
            ),
        ] {
            let start = line
                .find(": \\\"")
                .map_or_else(|| line.find('"').unwrap() + 1, |index| index + 4);
            let end = line.rfind('"').unwrap();
            assert_eq!(non_secret_shape(line, start..end), Some(expected), "{line}");
        }
        // Unquoted code terminators lie outside the value.
        assert_eq!(shape("API_TOKEN = 86400;"), Some(NonSecretShape::Number));
    }

    #[test]
    fn the_key_is_read_before_its_separator() {
        for (line, key) in [
            ("hashed_password=x", "hashed_password"),
            ("export SHA256_TOKEN=\"x", "SHA256_TOKEN"),
            ("\"token_sha1\": \"x", "token_sha1"),
            ("os.environ[\"TOKEN_HASH\"] = \"x", "TOKEN_HASH"),
            ("X-Token-Digest: x", "X-Token-Digest"),
            ("'passwort_hash' => 'x", "passwort_hash"),
            ("lager\\ngehashtes_passwort = x", "gehashtes_passwort"),
        ] {
            assert_eq!(key_before(line, line.len() - 1), Some(key), "{line}");
        }
        assert_eq!(key_before("Das Passwort ist x", 17), None);
    }

    #[test]
    fn aliases_and_encrypted_values_are_references() {
        for line in [
            "password: *default_password",
            "pwd: *mut",
            "password: ENC[AES256_GCM,data:Zm9vYmFy,iv:Kx7pQ2,tag:vL9rT4,type:str]",
            "secret: $ANSIBLE_VAULT;1.1;AES256",
        ] {
            let start = line.find(": ").unwrap() + 2;
            assert_eq!(
                non_secret_shape(line, start..line.len()),
                Some(NonSecretShape::Reference),
                "{line}"
            );
        }
        // A `*` with digits or inside quotes starts a password.
        for line in ["password: *Kx7pQ2vL9", "password: \"*default_password\""] {
            let start = line.find(": ").unwrap() + 2;
            let start = start + usize::from(line[start..].starts_with('"'));
            let end = line.len() - usize::from(line.ends_with('"'));
            assert_eq!(non_secret_shape(line, start..end), None, "{line}");
        }
    }

    #[test]
    fn digest_names_in_a_key_of_its_own() {
        for key in ["sha256_tokens", "TOKEN_HASHES", "gehashte_passwoerter"] {
            assert!(key_names_digest(key), "{key}");
        }
        for key in ["api_keys", "tokens", "client_secret"] {
            assert!(!key_names_digest(key), "{key}");
        }
    }
}
