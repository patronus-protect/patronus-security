// SPDX-License-Identifier: MIT OR Apache-2.0
//! JWT header and compact JWS structure (RFC 7515, RFC 7519).

use serde_json::{Map, Value};

use super::base64::{base64_decode, Base64Kind};

/// A JOSE header with a string `alg`.
#[derive(Clone, Debug, PartialEq)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    /// All header parameters, including `alg` and `typ`.
    pub fields: Map<String, Value>,
}

impl JwtHeader {
    /// Unsecured JWS (`alg` `none`, RFC 7518 section 3.6), case-insensitive.
    pub fn is_unsecured(&self) -> bool {
        self.alg.eq_ignore_ascii_case("none")
    }
}

/// A compact JWS: header, JSON object claims and raw signature bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Jwt {
    pub header: JwtHeader,
    pub claims: Map<String, Value>,
    pub signature: Vec<u8>,
}

fn json_object(segment: &str) -> Option<Map<String, Value>> {
    let raw = base64_decode(segment, Base64Kind::UrlSafe)?;
    match serde_json::from_slice(&raw).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// Parse an unpadded base64url header segment into a JSON object with a
/// string `alg`.
pub fn jwt_header(segment: &str) -> Option<JwtHeader> {
    let fields = json_object(segment)?;
    let alg = fields.get("alg")?.as_str()?.to_owned();
    let typ = fields.get("typ").and_then(Value::as_str).map(str::to_owned);
    Some(JwtHeader { alg, typ, fields })
}

/// Parse a compact JWS `header.claims.signature` whose header has an `alg`
/// and whose claims are a JSON object. The signature may be empty (`alg`
/// `none`); it is decoded, not verified.
pub fn jwt_parse(token: &str) -> Option<Jwt> {
    let mut segments = token.split('.');
    let (header, claims, signature) = (segments.next()?, segments.next()?, segments.next()?);
    if segments.next().is_some() {
        return None;
    }
    Some(Jwt {
        header: jwt_header(header)?,
        claims: json_object(claims)?,
        signature: base64_decode(signature, Base64Kind::UrlSafe)?,
    })
}
