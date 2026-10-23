// SPDX-License-Identifier: GPL-3.0-only
//! K05: config key→value extraction, part 1 (env, INI/properties, HTTP
//! headers) with a value-shape filter.
//!
//! A config line binds its whole value to the generic key-bound rules
//! (`dlp_env_var_secret`, `dlp_password_assignment`,
//! `dlp_generic_credential_assignment`): an unquoted properties, INI or
//! header value with `;`, `,`, `}` or `]` inside runs to the end of the line
//! or to an inline comment. Before a credential-like key binds a value,
//! shapes that are no secret are rejected: UUIDs, algorithm-prefixed digests,
//! hex digests under a key that names a digest, ObjectIds,
//! template/format fields, variable references, booleans, numbers, paths and
//! URLs without credentials. A hex secret under a plain credential key stays
//! a secret. Values are synthetic.

use std::sync::OnceLock;

use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult};

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

/// The unsuppressed `matched_rules` entries: rule id and config format.
fn matched_rules(result: &SecurityScanResult) -> Vec<(String, Option<String>)> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("suppressed_by").is_none())
                .map(|rule| {
                    (
                        rule["rule_id"].as_str().unwrap().to_owned(),
                        rule.get("structure")
                            .and_then(|format| format.as_str())
                            .map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `template` with `value` at `{v}` yields exactly one span, the value, by
/// `rule_id`, bound by a config line of `format` (or by the rule's regex
/// for `None`).
fn assert_exact(template: &str, value: &str, rule_id: &str, format: Option<&str>) {
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
        vec![(rule_id.to_owned(), format.map(str::to_owned))],
        "{rule_id}: {text:?}"
    );
}

fn assert_silent(texts: &[&str]) {
    for text in texts {
        let result = scan(text);
        assert!(
            result.evidence_spans.is_empty(),
            "expected no DLP finding in {text:?}, got {:?}",
            result
                .evidence_spans
                .iter()
                .map(|span| (&span.label, &span.text))
                .collect::<Vec<_>>()
        );
    }
}

/// A password with `;`, `,` and `}` inside, as the generator's
/// `quoted_punctuated_password` shapes it.
const PUNCTUATED: &str = "qe;Tz8Wm4K,93}RV";

#[test]
fn config_lines_bind_the_whole_unquoted_value() {
    for (template, rule_id, format) in [
        (
            "# application.properties\nspring.datasource.url=jdbc:postgresql://db:5432/orders\nspring.datasource.password={v}\n",
            "dlp_password_assignment",
            "properties",
        ),
        (
            "# Lagerverwaltung\nlager.db.passwort={v}\nlager.standort=hamburg\n",
            "dlp_password_assignment",
            "properties",
        ),
        (
            "[smtp]\nhost = mail.internal\npassword = {v} # rotated monthly\n",
            "dlp_password_assignment",
            "properties",
        ),
        (
            "[datenbank]\nbenutzer = lager\npasswort = {v} ; rotiert im September\n",
            "dlp_password_assignment",
            "properties",
        ),
        (
            "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Client-Secret: {v}\nContent-Type: application/json\n",
            "dlp_generic_credential_assignment",
            "http_header",
        ),
        (
            "GET /v1/lieferungen HTTP/1.1\r\nHost: api.lager.intern\r\nX-Zugangstoken: {v}\r\n",
            "dlp_generic_credential_assignment",
            "http_header",
        ),
    ] {
        assert_exact(template, PUNCTUATED, rule_id, Some(format));
    }
    // A bare env value with `;` is left to the shell rules of
    // `dlp_env_var_secret`; `,` and `}` belong to it.
    assert_exact(
        "client_secret={v}\n",
        "Tz8,Wm4K}93RVqe",
        "dlp_generic_credential_assignment",
        Some("env"),
    );
}

#[test]
fn values_the_regex_reads_whole_keep_the_regex_binding() {
    for (template, value, rule_id) in [
        (
            "export REPORT_SERVICE_TOKEN=\"{v}\"  # production\n",
            "Rtwxkzp4821!",
            "dlp_env_var_secret",
        ),
        ("DB_PASSWORD={v}\n", PUNCTUATED, "dlp_env_var_secret"),
        (
            "[database]\npassword = {v}\n",
            "Rtwxkzp4821!",
            "dlp_password_assignment",
        ),
    ] {
        assert_exact(template, value, rule_id, None);
    }
}

#[test]
fn hex_secrets_under_plain_credential_keys_stay_secrets() {
    let hex40 = "7c1e9a4f2b8d6035e1c7a9f4b2d8e6031c5a7f9e";
    let hex64 = "3b9f1c7e5a2d8064f1e3c9a7b5d2086e4f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e";
    assert_exact(
        "BILLING_CLIENT_SECRET={v}\n",
        hex40,
        "dlp_env_var_secret",
        None,
    );
    assert_exact(
        "[oauth]\nclient_secret = {v}\n",
        hex64,
        "dlp_generic_credential_assignment",
        None,
    );
    assert_exact(
        "GET /v1/orders HTTP/1.1\nHost: api.internal\nX-Api-Key: {v}\n",
        &hex64[..32],
        "dlp_generic_credential_assignment",
        None,
    );
    // 24 hex digits whose leading timestamp (1978) is no ObjectId.
    assert_exact(
        "ORDER_SERVICE_TOKEN={v}\n",
        "0f3c9a7e5b1d2c8a4e6f9b03",
        "dlp_env_var_secret",
        None,
    );
}

#[test]
fn uuids_are_no_secrets() {
    assert_silent(&[
        "LAGER_API_TOKEN=3f2a9c4e-7b1d-4e8a-9c2f-5d6e7f8a9b0c\n",
        "lager.zugangstoken={3F2A9C4E-7B1D-4E8A-9C2F-5D6E7F8A9B0C}\n",
        "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Api-Key: 550e8400-e29b-41d4-a716-446655440000\n",
        "[oauth]\nclient_secret = urn:uuid:550e8400-e29b-41d4-a716-446655440000\n",
    ]);
}

#[test]
fn prefixed_digests_are_no_secrets() {
    assert_silent(&[
        "lager.geheimnis=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
        "API_SCHLUESSEL=SHA-256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
        "DEPLOY_SECRET=sha1-2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n",
        "[assets]\naccess_token = sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=\n",
        "api_key=md5:5d41402abc4b2a76b9719d911017c592\n",
    ]);
}

#[test]
fn hex_digests_under_digest_keys_are_no_secrets() {
    assert_silent(&[
        "[konto]\ngehashtes_passwort = 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n",
        "SHA256_RELEASE_TOKEN=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
        "hashed_password=5d41402abc4b2a76b9719d911017c592\n",
        "MD5_API_TOKEN=5D41402ABC4B2A76B9719D911017C592\n",
    ]);
}

#[test]
fn object_ids_are_no_secrets() {
    assert_silent(&[
        "lager.zugangstoken=5f8d0c3e9b1a2d4c6e8f0a1b\n",
        "ORDER_SERVICE_TOKEN=6512bd43d9caa6e02c990b0a\n",
        "GET /v1/orders HTTP/1.1\nHost: api.internal\nX-Auth-Token: 65000000a1b2c3d4e5f60718\n",
    ]);
}

#[test]
fn template_fields_and_variable_references_are_no_secrets() {
    assert_silent(&[
        "[datenbank]\npasswort = {lager_passwort}\n",
        "[oauth]\nclient_secret = %(client_secret)s\n",
        "API_TOKEN=%s\n",
        "app.db.password=<%= @db_password %>\n",
        "passwort={{ lager.passwort }}\n",
        "LAGER_KENNWORT=%LAGER_KENNWORT%\n",
        "export DEPLOY_API_TOKEN=$CI_DEPLOY_API_TOKEN\n",
        "api_key=$env:LAGER_API_KEY\n",
        "client_secret=env:OAUTH_CLIENT_SECRET\n",
    ]);
}

#[test]
fn booleans_and_numbers_are_no_secrets() {
    assert_silent(&[
        "LAGER_GEHEIMNIS=deaktiviert\n",
        "kennwort=wahr\n",
        "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Auth-Token: disabled\n",
        "SERVICE_SECRET=undefined\n",
        "[sicherheit]\npasswort = 20260914\n",
        "oauth.client-secret=86400000\n",
        "DB_PASSWORD=12345678901234\n",
        "Passwort = 12345678\n",
    ]);
}

#[test]
fn paths_and_urls_without_credentials_are_no_secrets() {
    assert_silent(&[
        "LAGER_PASSWORT=/etc/lager/passwort.txt\n",
        "[database]\npassword = C:\\secrets\\orders-db.txt\n",
        "SERVICE_SECRET=./secrets/service.key\n",
        "GET /v1/lieferungen HTTP/1.1\nHost: api.lager.intern\nX-Api-Schluessel: https://tresor.lager.intern/v1/lager/api\n",
        "IDP_CLIENT_SECRET=https://auth.internal/realms/acme/protocol/openid-connect/token\n",
    ]);
}

#[test]
fn code_and_lists_are_no_config_lines() {
    assert_silent(&[
        "        assert request.number > 0\n        token = f\"t{request.number}s0\"\n",
        "password = get_password(user, realm)\n",
        "    password=pw,\n",
        "    eatClearTextPassword = 8107,\n",
        "token = prefix${SUFFIX}\n",
        "- password=dev,test\n",
        "X-Client-Secret: qe;Tz8Wm4K\n",
    ]);
}

#[test]
fn secret_urls_and_dollar_passwords_keep_their_findings() {
    // A URL with userinfo stays with the URL rule; `$` before a word with
    // digits is a password, not a variable.
    let result = scan("DATABASE_PASSWORD_URL=postgres://app:Rtwxkzp4821@db.internal:5432/app\n");
    assert!(!result.evidence_spans.is_empty());
    assert_exact(
        "SERVICE_SECRET={v}\n",
        "$ecretvault2026",
        "dlp_env_var_secret",
        None,
    );
}
