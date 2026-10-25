// SPDX-License-Identifier: MIT OR Apache-2.0
//! F-HTTP (F13 + T11): value gates of the HTTP auth rules. Since the rules
//! also match outside a literal `Authorization:`/`Cookie:` line (keys such as
//! `AUTHORIZATION=`, `"proxy_authorization":`, `sessionCookie:`, logs, and
//! standalone values in chats, tickets and mails), the value itself has to
//! prove its kind:
//!
//! - `Basic`: canonical base64 that decodes to printable `user-id:password`
//!   (RFC 7617) with a chosen password (`likeness::is_chosen_password`), or
//!   with one empty side and a machine-issued token on the other;
//! - `Bearer`: an opaque token (RFC 6750 `b64token`) of at least
//!   [`MIN_TOKEN_LENGTH`] characters that looks machine-issued
//!   (`likeness::is_token_like`) and is no identifier; a JWT is left to
//!   `dlp_jwt_token`, a provider token to its provider rule (K08 tiers);
//! - session cookie: a session ID of at least [`MIN_TOKEN_LENGTH`]
//!   characters that looks machine-issued.
use super::likeness;
use crate::detectors::validators::{base64_decode, jwt_parse, Base64Kind};
use std::ops::Range;

/// Shortest opaque bearer token and session ID. Servers issue 128 bits and
/// more (Tomcat `JSESSIONID` 32 hex, PHP 26 characters, RFC 6750 examples
/// aside); shorter values after `Bearer` are words, test values and
/// truncated examples (`abc123.xyz.789`).
const MIN_TOKEN_LENGTH: usize = 16;

/// `dlp_basic_auth`: whether the base64 at `range` is a whole token that
/// decodes to `user-id:password` with printable text and a chosen password.
pub(super) fn is_basic_credentials(text: &str, range: Range<usize>) -> bool {
    let rest = &text.as_bytes()[range.end..];
    let continues = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
    // The base64 run ends the token: no word character follows, and a dot
    // only as punctuation (`… Basic dXNl….` at the end of a sentence).
    if rest.first().is_some_and(|&byte| continues(byte))
        || (rest.first() == Some(&b'.') && rest.get(1).is_some_and(|&byte| continues(byte)))
    {
        return false;
    }
    let Some(decoded) = base64_decode(&text[range], Base64Kind::Standard)
        .and_then(|raw| String::from_utf8(raw).ok())
    else {
        return false;
    };
    if decoded.chars().any(char::is_control) {
        return false;
    }
    // The user-id cannot contain a colon (RFC 7617 section 2).
    let Some((user, password)) = decoded.split_once(':') else {
        return false;
    };
    match (user.trim().is_empty(), password.trim().is_empty()) {
        (true, true) => false,
        // RFC 7617 allows an empty user-id or password (`token:`, `:token`):
        // the populated side is the secret and has to look machine-issued.
        (true, false) | (false, true) => {
            let token = if user.trim().is_empty() {
                password
            } else {
                user
            };
            !super::placeholders::is_placeholder_value(token) && likeness::is_token_like(token)
        }
        (false, false) => {
            !super::placeholders::is_placeholder_value(password)
                && likeness::is_chosen_password(user, password)
        }
    }
}

/// `dlp_bearer_token`: whether the value at `range` is an opaque token. A
/// value that parses as a JWT and has the shape `dlp_jwt_token` matches
/// belongs to that rule, which checks its entropy and documented examples;
/// a malformed `ey…` value and a JWT outside that shape (empty claims `e30`,
/// a short signature) are judged as opaque tokens.
pub(super) fn is_bearer_token(text: &str, range: Range<usize>) -> bool {
    let value = &text[range];
    if jwt_parse(value).is_some() && has_jwt_rule_shape(value) {
        return false;
    }
    is_issued_token(value.trim_end_matches('='))
}

/// Mirrors the `dlp_jwt_token` pattern: header and claims start with `ey`
/// followed by at least ten characters, the signature has at least ten.
fn has_jwt_rule_shape(value: &str) -> bool {
    let in_class = |segment: &str| {
        segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'='))
    };
    let mut segments = value.split('.');
    let (Some(header), Some(claims), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    [header, claims]
        .iter()
        .all(|segment| segment.starts_with("ey") && segment.len() >= 12 && in_class(segment))
        && signature.len() >= 10
        && in_class(signature)
}

/// `dlp_session_cookie`: whether the cookie value at `range` is a session ID.
pub(super) fn is_session_id(text: &str, range: Range<usize>) -> bool {
    is_issued_token(&text[range])
}

fn is_issued_token(value: &str) -> bool {
    value.len() >= MIN_TOKEN_LENGTH
        && !likeness::is_identifier(value)
        && likeness::is_token_like(value)
}

#[cfg(test)]
mod tests {
    use super::{is_basic_credentials, is_bearer_token, is_session_id};

    fn gate(template: &str, value: &str, gate: fn(&str, std::ops::Range<usize>) -> bool) -> bool {
        let start = template.find("{v}").unwrap();
        let text = template.replace("{v}", value);
        gate(&text, start..start + value.len())
    }

    #[test]
    fn basic_needs_canonical_base64_of_user_and_chosen_password() {
        // lagerdienst:Q7vRz2mXp9Ts, ada:secret-8842
        for value in ["bGFnZXJkaWVuc3Q6UTd2UnoybVhwOVRz", "YWRhOnNlY3JldC04ODQy"] {
            assert!(gate("Basic {v}", value, is_basic_credentials), "{value}");
            assert!(gate("Basic {v}.", value, is_basic_credentials), "{value}");
            assert!(
                gate("\"Basic {v}\"", value, is_basic_credentials),
                "{value}"
            );
        }
        for (value, why) in [
            ("bGFnZXJkaWVuc3Q6UTd2UnoybVhwOVRz-x", "continues"),
            (
                "bGFnZXJkaWVuc3Q6UTd2UnoybVhwOVRz.x",
                "continues after a dot",
            ),
            ("bGFnZXJkaWVuc3Q6UTd2UnoybVhwOVR", "not canonical"),
            ("SGFsbG8gV2VsdCBkYXMgaXN0IGVpbg==", "no colon"),
            ("Og==", "both sides empty"),
            ("bGFnZXJkaWVuc3Q6", "empty password, a word as user-id"),
            ("bGFnZXIBZGllbnN0OlE3dlJ6Mm1YcDlUcw==", "control character"),
            ("dXNlcjpwQHNz", "user:p@ss"),
            ("YXBwbGljYXRpb246c2VjcmV0", "application:secret"),
            ("YWRtaW46YWRtaW4=", "admin:admin"),
            ("Zm9vOmJhcg==", "foo:bar"),
            ("dXNlcm5hbWU6Y2hhbmdlbWU=", "username:changeme"),
        ] {
            let text = format!("Basic {value}");
            assert!(!is_basic_credentials(&text, 6..6 + value.len()), "{why}");
        }
    }

    #[test]
    fn bearer_needs_an_issued_token_and_leaves_jwts_to_their_rule() {
        for value in [
            "Q3vX9kLm2PzR7tWb5NcY8dHf4JsA6gUe",
            "H_6MFQvVkY4iSvnlgrzQTMVBHu3IAq0ZtMDMPM3HVP4",
            "3f9a1c7e4b20d86f5ea9c3172b4d08e6a1b2c3d4",
            "mF_9.B5f-4.1JqMx7Tz8KpL3vWc==",
        ] {
            assert!(gate("Bearer {v}", value, is_bearer_token), "{value}");
        }
        for value in [
            "abc123.xyz.789",
            "secret_token",
            "zugangstoken_lager",
            "accessTokenFromVault",
            "YOUR_ACCESS_TOKEN_HERE",
            "abcdefghijklmnopqrstuvwxyz",
            "12345678901234567890",
            "abcDEfGhIJkl123456",
        ] {
            assert!(!gate("Bearer {v}", value, is_bearer_token), "{value}");
        }
        // Assembled at test time so no JWT literal sits in the source.
        let jwt = [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiI0NzExIn0",
            "c2lnbmF0dXJlLWJ5dGVz",
        ]
        .join(".");
        assert!(!gate("Bearer {v}", &jwt, is_bearer_token), "{jwt}");
        // Valid JWTs `dlp_jwt_token` cannot match stay with the bearer rule:
        // empty claims (`e30`) and a signature shorter than ten characters.
        for jwt in [
            ["eyJhbGciOiJIUzI1NiJ9", "e30", "c2lnbmF0dXJlLWJ5dGVz"].join("."),
            ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiI0NzExIn0", "Q7vRz2"].join("."),
        ] {
            assert!(gate("Bearer {v}", &jwt, is_bearer_token), "{jwt}");
        }
    }

    #[test]
    fn session_ids_need_an_issued_token() {
        for value in [
            "E7DF183BA1A4E35FC76DED44409C4D0A",
            "kfthpsq79t60bno4k6fqjhc82i",
            "s%3AXcCLaR2-hprsOwm4vH14vNd_wp6fHd4s.SATjQ73HlDGwSULeKOS0gc3",
        ] {
            assert!(gate("JSESSIONID={v}", value, is_session_id), "{value}");
        }
        for value in [
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            "12345678901234567890123456789012",
            "testtesttesttesttesttestte",
            "HIER_SESSION_COOKIE_EINTRAGEN",
            "kfthpsq79t60",
        ] {
            assert!(!gate("JSESSIONID={v}", value, is_session_id), "{value}");
        }
    }
}
