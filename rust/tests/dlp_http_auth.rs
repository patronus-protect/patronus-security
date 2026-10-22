// SPDX-License-Identifier: GPL-3.0-only
//! F-HTTP (F13 + T11): HTTP auth values outside a literal header line.
//!
//! `dlp_basic_auth` reports a `Basic` value only if its base64 decodes to
//! `user-id:password` (RFC 7617) with printable text and a chosen password;
//! `dlp_bearer_token` reports a `Bearer` value only as a high-entropy opaque
//! token (RFC 6750), a JWT goes to `dlp_jwt_token` and a provider token to its
//! provider rule; `dlp_session_cookie` reports the session cookies of known
//! servers and frameworks (`JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`,
//! `connect.sid`, `laravel_session`, `__Host-`/`__Secure-` names) also
//! without a `Cookie:` line. The values stand under authorization keys in
//! env, JSON, YAML, TOML, XML, properties and code, in logs and alone in
//! chats, tickets and mails. Values are synthetic.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use patronus_ark::{
    golden_recipes::GeneratorSet, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};

fn scan(text: &str) -> SecurityScanResult {
    static SCANNER: OnceLock<SecurityGateway> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            )
        })
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn matched_rules(result: &SecurityScanResult) -> Vec<String> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("suppressed_by").is_none())
                .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// `template` with `value` at `{v}` yields exactly one span, the value, by
/// `rule_id`.
fn assert_exact(template: &str, value: &str, rule_id: &str) {
    let start = template[..template.find("{v}").unwrap()].chars().count();
    let text = template.replace("{v}", value);
    let result = scan(&text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.start_char, span.end_char, span.text.as_str()))
        .collect();
    assert_eq!(
        spans,
        vec![(start, start + value.chars().count(), value)],
        "{rule_id}: {text:?}"
    );
    assert_eq!(
        matched_rules(&result),
        vec![rule_id.to_owned()],
        "{rule_id}: {text:?}"
    );
}

fn assert_silent(texts: &[String]) {
    let reported: Vec<_> = texts
        .iter()
        .filter_map(|text| {
            let result = scan(text);
            (!result.evidence_spans.is_empty()).then(|| {
                let spans: Vec<_> = result.evidence_spans.iter().map(|s| &s.text).collect();
                format!("{text:?} -> {spans:?}")
            })
        })
        .collect();
    assert!(reported.is_empty(), "reported: {reported:#?}");
}

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec loads")
    })
}

/// Padded standard base64 (RFC 4648 section 4) for test-time Basic values.
fn base64(raw: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in raw.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(
                    ALPHABET[((bits >> (18 - 6 * index)) & 63) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Unpadded base64url (RFC 4648 section 5) for test-time JWTs.
fn base64url(raw: &[u8]) -> String {
    base64(raw)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// A synthetic HS256 JWT with random-looking signature bytes.
fn jwt() -> String {
    let signature: Vec<u8> = (0u8..32)
        .map(|i| i.wrapping_mul(73).wrapping_add(19))
        .collect();
    format!(
        "{}.{}.{}",
        base64url(br#"{"alg":"HS256","typ":"JWT"}"#),
        base64url(br#"{"sub":"4711-lager","iat":1767225600}"#),
        base64url(&signature)
    )
}

/// Carriers of an HTTP auth value outside and inside a header line; `{k}`
/// is the key in the convention of the carrier (`snake`, `camel`, `upper`,
/// `header`), `{v}` the full header value (`Bearer …`, `Basic …`) with the
/// reported part marked as `{s}`.
const AUTH_CARRIERS: &[&str] = &[
    "{header}: {v}",
    "curl -sS https://api.example.com/v1/status -H \"{header}: {v}\"",
    "{upper}={v}",
    "export {upper}='{v}'",
    "ENV {upper}=\"{v}\"",
    "      {upper}: \"{v}\"",
    "    {snake}: \"{v}\"",
    "{\n  \"credentials\": {\n    \"{snake}\": \"{v}\"\n  }\n}",
    "[upstream]\n{snake} = \"{v}\"",
    "  <add key=\"{pascal}\" value=\"{v}\" />",
    "  <credentials {camel}=\"{v}\" />",
    "app.{kebab}={v}",
    "{upper} = \"{v}\"",
    "const {camel} = \"{v}\"",
    "export const {camel}: string = \"{v}\";",
    "private static final String {upper} = \"{v}\";",
    "const {upper}: &str = \"{v}\";",
    "  {camel}: \"{v}\",",
    "    \"os.environ[\\\"{upper}\\\"] = \\\"{v}\\\"\\n\",",
    "2026-09-14T08:12:03.902Z DEBUG [main] effective config: region=eu-central-1 {snake}={v} retries=3",
    "[09:43] tom.w: here you go: {v}",
    "[08:17] daniel.r: {v}",
    "as discussed, here are the credentials for the job:\n\n{v}\n\nPlease delete after use.",
    "Laut Konfiguration hinterlegt (Zugangsdaten): {v}\nBitte prüfen.",
];

fn auth_texts(key: &str, scheme: &str, value: &str) -> Vec<(String, String)> {
    let words: Vec<&str> = key.split('_').collect();
    let pascal: String = words
        .iter()
        .map(|word| word[..1].to_uppercase() + &word[1..])
        .collect();
    let camel = words[0].to_owned() + &pascal[words[0].len()..];
    let header = words
        .iter()
        .map(|word| word[..1].to_uppercase() + &word[1..])
        .collect::<Vec<_>>()
        .join("-");
    AUTH_CARRIERS
        .iter()
        .map(|carrier| {
            let template = carrier
                .replace("{header}", &header)
                .replace("{upper}", &key.to_uppercase())
                .replace("{snake}", key)
                .replace("{kebab}", &key.replace('_', "-"))
                .replace("{pascal}", &pascal)
                .replace("{camel}", &camel)
                .replace("{v}", &format!("{scheme} {{v}}"));
            (template, value.to_owned())
        })
        .collect()
}

// ── Basic ────────────────────────────────────────────────────────────────

#[test]
fn basic_values_that_decode_to_user_and_password_are_found_in_every_carrier() {
    for (user, password) in [
        ("lagerdienst", "Q7vRz2mXp9Ts"),
        ("svc-reporting", "k3P!vX9#qL2w"),
        ("ada", "secret-8842"),
    ] {
        let value = base64(format!("{user}:{password}").as_bytes());
        for key in ["authorization", "proxy_authorization"] {
            for (template, value) in auth_texts(key, "Basic", &value) {
                assert_exact(&template, &value, "dlp_basic_auth");
            }
        }
    }
}

#[test]
fn basic_values_without_user_and_password_stay_silent() {
    let values = [
        // No colon, empty user-id or password.
        base64(b"Hallo Welt das ist ein"),
        base64(b":Q7vRz2mXp9Ts"),
        base64(b"lagerdienst:"),
        // Control characters and binary data.
        base64(b"lager\x01dienst:Q7vRz2mXp9Ts"),
        base64(&[
            0x9f, 0x12, 0xc4, 0x3a, 0x81, 0xfe, 0x07, 0x55, 0xd2, 0x3a, 0x6b, 0xe0,
        ]),
        // Not canonical base64: missing padding, bad trailing bits.
        "bGFnZXJkaWVuc3Q6UTd2UnoybVhwOVRzQ".to_owned(),
        "bGFnZXJkaWVuc3Q6UTd2UnoybVhwOVRzQ=".to_owned(),
    ];
    let texts: Vec<String> = values
        .iter()
        .flat_map(|value| {
            [
                format!("Authorization: Basic {value}"),
                format!("PROXY_AUTHORIZATION=Basic {value}"),
                format!("Proxy credentials for the job: Basic {value}"),
            ]
        })
        .collect();
    assert_silent(&texts);
}

#[test]
fn basic_stand_in_and_documented_credentials_stay_silent() {
    let pairs = [
        "user:password",
        "user:p@ss",
        "benutzer:passwort",
        "application:secret",
        "confidentialApplication:topSecret",
        "username:changeme",
        "admin:admin",
        "foo:bar",
        "Aladdin:open sesame",
    ];
    let texts: Vec<String> = pairs
        .iter()
        .flat_map(|pair| {
            let value = base64(pair.as_bytes());
            [
                format!("Authorization: Basic {value}"),
                format!("      .should(\"equal\", \"Basic {value}\")"),
                format!("'header' => 'Proxy-Authorization: Basic {value}',"),
            ]
        })
        .collect();
    assert_silent(&texts);
}

#[test]
fn words_and_references_after_basic_stay_silent() {
    let texts = [
        "Basic usage of the client is documented in docs/usage.md",
        "Basic Authentication is enabled for the proxy",
        "Die basic authentication ist für den Proxy aktiviert.",
        "Basic authorization",
        "PROXY_AUTHORIZATION=Basic ${PROXY_CREDENTIALS}",
        "Authorization: Basic <base64 of user:password>",
        "Authorization: Basic ********",
        "proxy_authorization: \"Basic {{ proxy_credentials }}\"",
    ]
    .map(str::to_owned);
    assert_silent(&texts);
}

// ── Bearer ───────────────────────────────────────────────────────────────

#[test]
fn opaque_bearer_tokens_are_found_in_every_carrier() {
    let generators = generators();
    for seed in [1, 2, 3] {
        let value = generators.generate("bearer_opaque_token", seed).unwrap();
        for key in ["authorization", "proxy_authorization"] {
            for (template, value) in auth_texts(key, "Bearer", &value) {
                assert_exact(&template, &value, "dlp_bearer_token");
            }
        }
    }
    for value in [
        "Q3vX9kLm2PzR7tWb5NcY8dHf4JsA6gUe",
        "Zx81pQm4Rt7vLk2nWb9sYc3dHf6J",
    ] {
        assert_exact("Authorization: Bearer {v}", value, "dlp_bearer_token");
        assert_exact("AUTHORIZATION=Bearer {v}", value, "dlp_bearer_token");
    }
}

#[test]
fn bearer_jwts_and_provider_tokens_go_to_their_own_rules() {
    let token = jwt();
    for template in [
        "Authorization: Bearer {v}",
        "AUTHORIZATION=Bearer {v}",
        "{\"authorization\": \"Bearer {v}\"}",
        "Access token for the job: Bearer {v}",
    ] {
        assert_exact(template, &token, "dlp_jwt_token");
    }
    let github = generators().generate("github_ghp_token", 7).unwrap();
    for template in ["Authorization: Bearer {v}", "AUTHORIZATION=Bearer {v}"] {
        assert_exact(template, &github, "dlp_github_token");
    }
}

#[test]
fn low_entropy_identifiers_and_examples_after_bearer_stay_silent() {
    let texts = [
        // swagger-ui e2e tests
        "    expect(text).to.include(`-H \"Authorization: Bearer abc123.xyz.789\"`)",
        "      .should(\"equal\", \"Bearer secret_token\")",
        "      .contains(\"Authorization: Bearer secret_token\")",
        // Words, identifiers, short values, a single character class.
        "Bearer authentication (also called token authentication) sends a token.",
        "Der Header lautet Bearer gefolgt vom Token aus dem Vault.",
        "AUTHORIZATION=Bearer accessTokenFromVault",
        "authorization = \"Bearer zugangstoken_lager\"",
        "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE",
        "Authorization: Bearer abcd1234",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "Authorization: Bearer 12345678901234567890",
        // Documented values.
        "AUTHORIZATION=Bearer EXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEXA",
        "AUTHORIZATION=Bearer TESTKEYTESTKEYTESTKEYTESTKEYTESTKEYTESTKEYQ",
        // References, templates and format placeholders.
        "AUTHORIZATION=Bearer ${LAGER_TOKEN}",
        "{\"authorization\": \"Bearer {{zugangstoken}}\"}",
        "headers = {\"Authorization\": \"Bearer \" + token}",
        "log.debug(\"authorization=Bearer %s\", token)",
        "Authorization: Bearer <token>",
    ]
    .map(str::to_owned);
    assert_silent(&texts);
}

// ── Session cookies ──────────────────────────────────────────────────────

#[test]
fn known_session_cookies_are_found_without_a_cookie_line() {
    let generators = generators();
    let cookies = [
        (
            "JSESSIONID",
            generators.generate("java_session_id", 5).unwrap(),
        ),
        (
            "PHPSESSID",
            generators.generate("php_session_id", 5).unwrap(),
        ),
        (
            "connect.sid",
            generators.generate("express_session_id", 5).unwrap(),
        ),
        (
            "laravel_session",
            generators.generate("laravel_session", 5).unwrap(),
        ),
        ("ASP.NET_SessionId", "x2vq1k5mzr0ayb3pw4hc5tnd".to_owned()),
        (
            "__Host-session",
            generators.generate("bearer_opaque_token", 5).unwrap(),
        ),
        (
            "__Secure-next-auth.session-token",
            generators.generate("bearer_opaque_token", 6).unwrap(),
        ),
    ];
    for (name, value) in &cookies {
        for carrier in [
            "Cookie: theme=dark; {n}={v}",
            "Set-Cookie: {n}={v}; Path=/; HttpOnly",
            "SESSION_COOKIE={n}={v}",
            "    session_cookie: \"{n}={v}\"",
            "{\"sessionCookie\": \"{n}={v}\"}",
            "private const string SessionCookie = \"{n}={v}\";",
            "2026-09-14 08:12:03,902 DEBUG [main] Sitzung übernommen: mandant=0042 {n}={v} wiederholungen=3",
            "[09:43] tom.w: grabbed it from devtools: {n}={v}",
            "Laut Konfiguration hinterlegt (Session-Cookie): {n}={v}",
            "$ curl -b '{n}={v}' https://shop.example.com/account",
            "https://shop.example.com/konto;{n}={v}",
        ] {
            assert_exact(&carrier.replace("{n}", name), value, "dlp_session_cookie");
        }
    }
}

#[test]
fn generic_session_names_still_need_a_cookie_line() {
    assert_exact(
        "Cookie: sessionid={v}",
        "kQ7vRz2mXp9TsW4nYb3",
        "dlp_session_cookie",
    );
    assert_exact(
        "Cookie: lang=de; session={v}",
        "kQ7vRz2mXp9TsW4nYb3",
        "dlp_session_cookie",
    );
    let texts = [
        "sessionid=kQ7vRz2mXp9TsW4nYb3",
        "session=kQ7vRz2mXp9TsW4nYb3 user=ada",
    ]
    .map(str::to_owned);
    assert_silent(&texts);
}

#[test]
fn placeholder_and_low_variety_session_ids_stay_silent() {
    let texts = [
        "SESSION_COOKIE=JSESSIONID=HIER_SESSION_COOKIE_EINTRAGEN",
        "SESSION_COOKIE=JSESSIONID=DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "SESSION_COOKIE=JSESSIONID=12345678901234567890123456789012",
        "session_cookie=PHPSESSID=testtesttesttesttesttestte retries=3",
        "[08:17] daniel.r: PHPSESSID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "PHPSESSID=changeme",
        "SESSION_COOKIE = \"JSESSIONID=<wird-nachgereicht>\"",
        "session_cookie: \"JSESSIONID=<redacted>\"",
        "Set-Cookie: __Host-session=${SESSION_ID}; Path=/; Secure; HttpOnly",
        "if (cookie.getName().equals(\"JSESSIONID\")) {",
        "document.cookie = \"PHPSESSID=\" + sessionId;",
        "laravel_session=null",
        "connect.sid=s%3A",
    ]
    .map(str::to_owned);
    assert_silent(&texts);
}
