// SPDX-License-Identifier: MIT OR Apache-2.0
//! G-URL (F12, G08, G09): credentials in URLs. The gates read the URL around
//! a value (its query parameters and path) and the shape of OTP seeds.
use std::ops::Range;

use super::credentials::{low_variety, LowVariety};
use super::http_auth;
use crate::detectors::validators::shannon_entropy;

/// How far a gate reads around a value for the rest of its URL.
const URL_WINDOW: usize = 2048;

/// Query parameters that mark a `token` parameter as a pagination cursor or
/// a CSRF token (F12).
const PAGINATION_OR_CSRF: &[&str] = &[
    "page",
    "page_size",
    "pagesize",
    "per_page",
    "cursor",
    "offset",
    "limit",
    "after",
    "before",
    "csrf",
    "_csrf",
    "csrf_token",
    "xsrf",
    "_xsrf",
    "authenticity_token",
];

/// Query and fragment parameters of `dlp_auth_url_token` (its regex), whose
/// values that rule checks as issued tokens.
const AUTH_URL_PARAMS: &[&str] = &[
    "access_token",
    "id_token",
    "refresh_token",
    "reset_token",
    "reset_password_token",
    "password_reset_token",
    "magic_token",
    "login_token",
    "invite_token",
    "invitation_token",
    "confirmation_token",
    "verification_token",
];

/// Path words of an OAuth redirect that carries an authorization `code`.
const OAUTH_REDIRECT_PATH: &[&str] = &["callback", "redirect", "oauth", "authorize"];

/// RFC 4648 Base32 characters without padding of an 80-bit TOTP seed.
const MIN_OTP_SECRET_LENGTH: usize = 16;

/// The URL around `range`: the run without whitespace, quotes or angle
/// brackets, at most [`URL_WINDOW`] bytes to each side.
fn url_around(text: &str, range: Range<usize>) -> &str {
    let bytes = text.as_bytes();
    let is_delimiter =
        |byte: u8| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'`' | b'<' | b'>');
    let mut start = range.start;
    while start > range.start.saturating_sub(URL_WINDOW) && !is_delimiter(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = range.end;
    while end < bytes.len().min(range.end + URL_WINDOW) && !is_delimiter(bytes[end]) {
        end += 1;
    }
    while !text.is_char_boundary(start) {
        start += 1;
    }
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[start..end]
}

/// The name of the query or fragment parameter whose value starts at
/// `value_start` (`?name=`, `&name=`, `&amp;name=`, `&#38;name=`, `#name=`).
fn param_name(text: &str, value_start: usize) -> Option<&str> {
    let before = text[..value_start].strip_suffix('=')?;
    let name_start = before.rfind(['?', '&', ';', '#'])? + 1;
    let name = &before[name_start..];
    (!name.is_empty() && !name.contains(|c: char| c.is_whitespace())).then_some(name)
}

/// Whether the query or fragment of `url` has a parameter named like one of
/// `names` (ASCII case-insensitive).
fn has_param(url: &str, names: &[&str]) -> bool {
    url.split(['?', '&', ';', '#']).skip(1).any(|part| {
        part.split_once('=')
            .is_some_and(|(name, _)| names.iter().any(|n| name.eq_ignore_ascii_case(n)))
    })
}

/// `dlp_credential_in_url` and `dlp_generic_credential_assignment` (F12): a
/// URL parameter is no credential when it is a CSRF parameter itself, a
/// `token` next to a pagination, cursor or CSRF parameter, the `secret` of
/// an otpauth:// URI, which `dlp_otp_secret` checks as Base32, or a token
/// parameter of an auth URL, which `dlp_auth_url_token` checks. A value
/// outside a URL query passes.
pub(super) fn is_credential_parameter(text: &str, range: Range<usize>) -> bool {
    let Some(name) = param_name(text, range.start) else {
        return true;
    };
    let is = |names: &[&str]| names.iter().any(|n| name.eq_ignore_ascii_case(n));
    let url = || url_around(text, range.clone());
    !(is(PAGINATION_OR_CSRF)
        || is(AUTH_URL_PARAMS)
        || (is(&["token"]) && has_param(url(), PAGINATION_OR_CSRF))
        || (is(&["secret"]) && url().to_ascii_lowercase().contains("otpauth://")))
}

/// `dlp_signed_url_signature` (F12): the signature parameter stands in a
/// signed-URL query: SigV4 `X-Amz-Signature` and GCS V4 `X-Goog-Signature`
/// with another parameter of their scheme, CloudFront/legacy `Signature` with
/// `Expires`, `Key-Pair-Id`, `Policy`, `AWSAccessKeyId` or `GoogleAccessId`,
/// Azure SAS `sig` with `sv` and `se` or `sp`.
pub(super) fn has_signed_url_structure(text: &str, range: Range<usize>) -> bool {
    let Some(name) = param_name(text, range.start) else {
        return false;
    };
    let url = url_around(text, range);
    let companions: &[&str] = match name.to_ascii_lowercase().as_str() {
        "x-amz-signature" => &[
            "x-amz-algorithm",
            "x-amz-credential",
            "x-amz-date",
            "x-amz-expires",
            "x-amz-signedheaders",
        ],
        "x-goog-signature" => &[
            "x-goog-algorithm",
            "x-goog-credential",
            "x-goog-date",
            "x-goog-expires",
        ],
        "signature" => &[
            "expires",
            "key-pair-id",
            "policy",
            "awsaccesskeyid",
            "googleaccessid",
        ],
        "sig" => return has_param(url, &["sv"]) && has_param(url, &["se", "sp"]),
        _ => return false,
    };
    has_param(url, companions)
}

/// `dlp_auth_url_token` (G09): the token of a reset, magic, invitation or
/// OAuth redirect URL looks issued and is no UUID or hex digest; an
/// authorization `code` needs the
/// redirect's `state` parameter or a callback/redirect path.
pub(super) fn is_auth_url_token(text: &str, range: Range<usize>) -> bool {
    let value = &text[range.clone()];
    // A UUID or hex digest names a record or file, not a session.
    if value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        || !http_auth::is_issued_token(value)
    {
        return false;
    }
    if !param_name(text, range.start).is_some_and(|name| name.eq_ignore_ascii_case("code")) {
        return true;
    }
    let url = url_around(text, range);
    let lower = url.to_ascii_lowercase();
    has_param(url, &["state"]) || OAUTH_REDIRECT_PATH.iter().any(|word| lower.contains(word))
}

/// `dlp_otp_secret` (G08): an RFC 4648 Base32 seed of at least 80 bits with
/// valid padding, as a whole value and with variety.
pub(super) fn is_otp_secret(text: &str, range: Range<usize>) -> bool {
    let value = &text[range.clone()];
    let body = value.trim_end_matches('=');
    let padding = value.len() - body.len();
    let valid_padding = if padding == 0 {
        matches!(body.len() % 8, 0 | 2 | 4 | 5 | 7)
    } else {
        value.len().is_multiple_of(8) && matches!(padding, 1 | 3 | 4 | 6)
    };
    let whole = !text[range.end..]
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '='));
    body.len() >= MIN_OTP_SECRET_LENGTH
        && whole
        && valid_padding
        && body
            .bytes()
            .all(|byte| matches!(byte.to_ascii_uppercase(), b'A'..=b'Z' | b'2'..=b'7'))
        && low_variety(body) == LowVariety::No
        && shannon_entropy(body) >= 3.0
}

#[cfg(test)]
mod tests {
    use super::{
        has_signed_url_structure, is_auth_url_token, is_credential_parameter, is_otp_secret,
    };

    fn gate(template: &str, value: &str, gate: fn(&str, std::ops::Range<usize>) -> bool) -> bool {
        let start = template.find("{v}").unwrap();
        let text = template.replace("{v}", value);
        gate(&text, start..start + value.len())
    }

    const SIGNATURE: &str = "3f5c9a1e7b2d4c6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f";
    const TOKEN: &str = "Q7vRz2mXp9TsLk4WbN8cHy3D";

    #[test]
    fn signature_needs_signed_url_structure() {
        for template in [
            "https://b.s3.amazonaws.com/a.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature={v}",
            "https://b.s3.amazonaws.com/a.pdf?X-Amz-Signature={v}&X-Amz-Date=20261103T000000Z",
            "<a href=\"https://b.s3.amazonaws.com/a?X-Amz-Expires=900&amp;X-Amz-Signature={v}\">",
            "https://storage.googleapis.com/b/o?X-Goog-Credential=svc&X-Goog-Signature={v}",
            "https://d1.cloudfront.net/a.mp4?Expires=1767225600&Signature={v}&Key-Pair-Id=K2",
            "https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&se=2026-12-01&sp=r&sig={v}",
        ] {
            assert!(
                gate(template, SIGNATURE, has_signed_url_structure),
                "{template}"
            );
        }
        for template in [
            "https://api.example.com/items?page=2&sig={v}",
            "https://example.com/webhook?Signature={v}",
            "https://b.s3.amazonaws.com/a.pdf?X-Amz-Signature={v}",
            "https://storage.googleapis.com/b/o?X-Amz-Date=1&X-Goog-Signature={v}",
            "https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&sig={v}",
            "https://api.example.com/feed?se=1&sp=r&sig={v}",
        ] {
            assert!(
                !gate(template, SIGNATURE, has_signed_url_structure),
                "{template}"
            );
        }
    }

    #[test]
    fn token_parameter_next_to_pagination_or_csrf_is_no_credential() {
        for template in [
            "https://api.example.com/items?limit=50&token={v}",
            "https://api.example.com/items?token={v}&page=3",
            "/search?q=x&cursor=abc&token={v}",
            "https://app.example.com/logout?_csrf=1&token={v}",
            "https://app.example.com/form?authenticity_token=x&amp;token={v}",
            "GET /logout?authenticity_token={v} 302",
            "otpauth://totp/ACME:ada?secret={v}&issuer=ACME",
            "https://app.example.com/cb#access_token={v}&token_type=bearer",
        ] {
            assert!(
                !gate(template, TOKEN, is_credential_parameter),
                "{template}"
            );
        }
        for template in [
            "https://intranet.example.de/report?id=7&token={v}",
            "https://app.example.com/login?next=/home&token={v}",
            "https://api.example.com/items?limit=50&api_key={v}",
            "https://api.example.com/items?page=2&password={v}",
            "token={v}",
            "x = 1; token={v}",
        ] {
            assert!(gate(template, TOKEN, is_credential_parameter), "{template}");
        }
    }

    #[test]
    fn auth_url_token_is_issued_and_code_needs_a_redirect() {
        for template in [
            "https://app.example.com/reset-password/{v}",
            "https://app.example.com/cb#access_token={v}&token_type=bearer",
            "https://app.example.com/oauth/callback?code={v}",
            "https://app.example.com/?code={v}&state=af0ifjsldkj",
        ] {
            assert!(gate(template, TOKEN, is_auth_url_token), "{template}");
        }
        for (template, value) in [
            ("https://app.example.com/?code={v}", TOKEN),
            (
                "https://app.example.com/invite/{v}",
                "team-onboarding-welcome-page",
            ),
            (
                "https://app.example.com/reset-password/{v}",
                "AAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            (
                "https://app.example.com/magic-link/{v}",
                "abcdefghijklmnopqrstuvwx",
            ),
            (
                "https://app.example.com/invite/{v}",
                "4f7d2c1e-9a3b-4c5d-8e6f-1a2b3c4d5e6f",
            ),
        ] {
            assert!(!gate(template, value, is_auth_url_token), "{template}");
        }
    }

    #[test]
    fn otp_secret_is_base32_with_valid_padding_and_variety() {
        let template = "otpauth://totp/ACME:ada?secret={v}&issuer=ACME";
        for value in [
            "K5XWQ3TJMV2GC4DFOJ2HE33NNFXGOZLS",
            "k5xwq3tjmv2gc4dfoj2he33nnfxgozls",
            "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE===",
            "GEZDGNBVGY3TQOJQ",
        ] {
            assert!(gate(template, value, is_otp_secret), "{value}");
        }
        for (value, why) in [
            ("GEZDGNBVGY3TQOJ", "below 80 bits"),
            (
                "K5XWQ3TJMV2GC4DFOJ2HE33NNFXGOZ",
                "length without valid padding",
            ),
            (
                "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE2==",
                "padding of no byte group",
            ),
            ("AAAAAAAAAAAAAAAAAAAAAAAA", "low variety"),
            ("ABCDEFGHIJKLMNOPQRSTUVWX", "sequential"),
            ("K5XWQ3TJMV2GC4DFOJ2HE33NNFXGOZL1", "not base32"),
        ] {
            assert!(!gate(template, value, is_otp_secret), "{why}");
        }
        assert!(!gate(
            "TOTP_SECRET={v}8",
            "K5XWQ3TJMV2GC4DFOJ2HE33NNFXGOZLS",
            is_otp_secret
        ));
    }
}
