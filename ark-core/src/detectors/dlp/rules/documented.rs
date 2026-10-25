// SPDX-License-Identifier: MIT OR Apache-2.0
//! K06: vendor-documented example values and publicly known test keys,
//! mirrored from `research/dlp/documented_values.yaml`. Exact values are only
//! held as the SHA-256 of their normalized form, so the repository never
//! carries them in clear; documented JWTs are recognised by their claims.
use crate::detectors::validators::{base64_decode, Base64Kind};
use ring::digest;
use serde_json::Value;

/// What a documented value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentedKind {
    /// A documented example without function: no finding.
    Example,
    /// A publicly known test key: a finding with severity `test`.
    Test,
}

struct DocumentedValue {
    /// Entry id and rule of the YAML entry; read by the mirror test only.
    #[cfg_attr(not(feature = "test-util"), allow(dead_code))]
    id: &'static str,
    #[cfg_attr(not(feature = "test-util"), allow(dead_code))]
    rule_id: &'static str,
    kind: DocumentedKind,
    /// SHA-256 of [`normalize`]d value, lower-case hex.
    sha256: &'static str,
}

const DOCUMENTED_VALUES: &[DocumentedValue] = &[
    DocumentedValue {
        id: "aws_access_key_id_docs",
        rule_id: "dlp_aws_access_key",
        kind: DocumentedKind::Example,
        sha256: "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
    },
    DocumentedValue {
        id: "aws_secret_access_key_docs",
        rule_id: "dlp_aws_secret_key",
        kind: DocumentedKind::Example,
        sha256: "78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598",
    },
    DocumentedValue {
        id: "bitcoin_wiki_wif_uncompressed",
        rule_id: "dlp_btc_wif",
        kind: DocumentedKind::Example,
        sha256: "9d6a2b9d1f01d4577cbdce4de6f0834ac6b21d675518ace150009338685b5276",
    },
    DocumentedValue {
        id: "bitcoin_wiki_wif_compressed",
        rule_id: "dlp_btc_wif",
        kind: DocumentedKind::Example,
        sha256: "110040843c3adf0df9dfa12aa89635f8c2a24a7fa0b068d78bc5e5c9f4fe7e30",
    },
    DocumentedValue {
        id: "rfc8410_ed25519_private_key",
        rule_id: "dlp_private_key_block",
        kind: DocumentedKind::Example,
        sha256: "4ff96a60934849a7f7c7733f163824cc22be7da33384bbd0b5de992972ea5586",
    },
    DocumentedValue {
        id: "rfc7617_basic_credentials",
        rule_id: "dlp_basic_auth",
        kind: DocumentedKind::Example,
        sha256: "cf4d418ed3de92d71f767db5391d5a2dacd40e1ce49e75d1137e2ecf4982d844",
    },
    DocumentedValue {
        id: "hardhat_account_0",
        rule_id: "dlp_eth_private_key",
        kind: DocumentedKind::Test,
        sha256: "bc1a50966c9e6486bc4ebf880b51611a2a97fcb8e7a6976e9b81a9e3e8ca0e3c",
    },
    DocumentedValue {
        id: "hardhat_account_1",
        rule_id: "dlp_eth_private_key",
        kind: DocumentedKind::Test,
        sha256: "8335c55334821eefd4334369ff9c04a8594f161013cf9d87f58802d87297837e",
    },
    DocumentedValue {
        id: "hardhat_account_2",
        rule_id: "dlp_eth_private_key",
        kind: DocumentedKind::Test,
        sha256: "b26ab6529d20ebebb4192256f202984754f785481c64b1a1aed58cac93b3617e",
    },
];

/// A documented claim value.
#[derive(Clone, Copy)]
enum Claim {
    Str(&'static str),
    Int(i64),
}

/// Claim sets of documented example JWTs; a token whose claims hold every
/// claim of one set is an example under any header and signature.
const JWT_EXAMPLE_CLAIMS: &[(&str, &[(&str, Claim)])] = &[
    (
        "jwt_io_debugger",
        &[
            ("sub", Claim::Str("1234567890")),
            ("name", Claim::Str("John Doe")),
        ],
    ),
    (
        "rfc7519_example",
        &[("iss", Claim::Str("joe")), ("exp", Claim::Int(1300819380))],
    ),
];

/// The documented kind of `value`, a rule's value (PEM rules: the body).
pub fn documented_kind(value: &str) -> Option<DocumentedKind> {
    let normalized = normalize(value);
    if normalized.len() < 16 {
        return None;
    }
    let fingerprint = sha256_hex(&normalized);
    DOCUMENTED_VALUES
        .iter()
        .find(|documented| documented.sha256 == fingerprint)
        .map(|documented| documented.kind)
        .or_else(|| is_documented_jwt(&normalized).then_some(DocumentedKind::Example))
}

/// Quotes trimmed; `0x` hex lower-case without `0x`; base64 bodies (PEM,
/// with line breaks or JSON escapes) reduced to their base64 characters.
fn normalize(value: &str) -> String {
    let value = value.trim_matches(['"', '\'', '`']);
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .filter(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return hex.to_ascii_lowercase();
    }
    if !value.contains(['\n', '\r', '\\']) {
        return value.to_owned();
    }
    let mut normalized = String::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            // Escaped line breaks (`\n`) of PEM bodies in JSON strings.
            b'\\' => {
                bytes.next();
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => {
                normalized.push(byte as char)
            }
            _ => {}
        }
    }
    normalized
}

fn sha256_hex(value: &str) -> String {
    digest::digest(&digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A compact JWS whose claims hold one documented claim set.
fn is_documented_jwt(value: &str) -> bool {
    let mut segments = value.split('.');
    let (Some(header), Some(claims), Some(_)) = (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    if !header.starts_with("ey") || !claims.starts_with("ey") {
        return false;
    }
    let Some(Value::Object(claims)) = base64_decode(claims, Base64Kind::UrlSafe)
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
    else {
        return false;
    };
    JWT_EXAMPLE_CLAIMS.iter().any(|(_, set)| {
        set.iter()
            .all(|(name, expected)| match (claims.get(*name), expected) {
                (Some(Value::String(found)), Claim::Str(expected)) => found == expected,
                (Some(Value::Number(found)), Claim::Int(expected)) => {
                    found.as_i64() == Some(*expected)
                }
                _ => false,
            })
    })
}

/// Metadata for the repository-level provenance mirror test.
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn documented_reference_metadata() -> Value {
    let values: Vec<Value> = DOCUMENTED_VALUES
        .iter()
        .map(|value| {
            serde_json::json!({
                "id": value.id,
                "rule_id": value.rule_id,
                "sha256": value.sha256,
                "kind": match value.kind {
                    DocumentedKind::Example => "example",
                    DocumentedKind::Test => "test",
                },
            })
        })
        .collect();
    let claims: Vec<Value> = JWT_EXAMPLE_CLAIMS
        .iter()
        .map(|(id, claims)| {
            let fields: serde_json::Map<String, Value> = claims
                .iter()
                .map(|(name, value)| {
                    let value = match value {
                        Claim::Str(value) => serde_json::json!(value),
                        Claim::Int(value) => serde_json::json!(value),
                    };
                    (name.to_string(), value)
                })
                .collect();
            serde_json::json!({"id": id, "claims": fields})
        })
        .collect();
    serde_json::json!({"values": values, "jwt_claims": claims})
}

#[cfg(test)]
mod tests {
    use super::{documented_kind, normalize};

    #[test]
    fn normalization_of_hex_quotes_and_pem_bodies() {
        assert_eq!(normalize("\"0xAB12cd34\""), "ab12cd34");
        assert_eq!(normalize("0x"), "0x");
        assert_eq!(normalize("'Kx7pQ2vL9rT4'"), "Kx7pQ2vL9rT4");
        assert_eq!(normalize("\nMC4CAQ+/\nAw==\n"), "MC4CAQ+/Aw==");
        assert_eq!(normalize("\\nMC4CAQ\\nAw==\\n"), "MC4CAQAw==");
    }

    #[test]
    fn short_and_random_values_are_not_documented() {
        for value in [
            "",
            "abc",
            "0x1234",
            "Kx7pQ2vL9rT4Kx7pQ2vL9rT4",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQ3MTEifQ.c2ln",
        ] {
            assert_eq!(documented_kind(value), None, "{value}");
        }
    }
}
