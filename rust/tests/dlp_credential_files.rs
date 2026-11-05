// SPDX-License-Identifier: GPL-3.0-only
//! G04: credential files.
//!
//! `dlp_netrc_password` (`CREDENTIAL`, subtype `password`) reports the
//! password of a `.netrc`/`_netrc` entry (`machine <host> login <user>
//! password <password>`, the tokens also on their own lines, and the
//! `default` entry). `dlp_docker_config_auth` (`CREDENTIAL`, subtype
//! `password`) reports the `auth` value of a Docker/Podman `config.json` or
//! `auth.json` registry entry: base64 of `user:password`. References,
//! placeholders, empty entries and base64 without such a payload are no
//! findings. Values are synthetic.

use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::{dlp::DLP_PATTERNS, prefilter::RulePrefilter},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
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

fn reported_rules(result: &SecurityScanResult) -> Vec<String> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|rule| rule.get("suppressed_by").is_none())
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect()
}

/// `template` with `value` at `{v}` yields exactly one span, the value, by
/// `rule`.
fn assert_exact(rule: &str, template: &str, value: &str) {
    let start = template[..template.find("{v}").unwrap()].chars().count();
    let text = template.replace("{v}", value);
    let result = scan(&text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.label.as_str(), span.start_char, span.end_char))
        .collect();
    assert_eq!(
        spans,
        vec![("CREDENTIAL", start, start + value.chars().count())],
        "{text:?}"
    );
    assert_eq!(reported_rules(&result), vec![rule], "{text:?}");
}

/// No DLP rule reports `text`.
fn assert_silent(text: &str) {
    let result = scan(text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| span.text.as_str())
        .collect();
    assert!(spans.is_empty(), "{text:?} -> {spans:?}");
}

const PASSWORD: &str = "Kx7pQ2vL9wR4m!";

#[test]
fn netrc_passwords_are_reported() {
    for template in [
        "machine api.example.org login deploy password {v}",
        "machine api.example.org login deploy password {v}\nmachine other.example.org login ci",
        "machine github.com\n  login release-bot\n  password {v}\n",
        "machine ftp.example.org port 2121 login export account ops password {v}",
        "default login anonymous password {v}",
        "# ~/.netrc\r\nmachine git.example.org\r\n\tlogin ci\r\n\tpassword {v}\r\n",
    ] {
        assert_exact("dlp_netrc_password", template, PASSWORD);
    }
}

#[test]
fn netrc_entries_without_a_literal_password_are_silent() {
    for text in [
        "machine api.example.org login deploy password ${NETRC_PASSWORD}",
        "machine api.example.org login deploy password $NETRC_PASSWORD",
        "machine <host> login <user> password <password>",
        "machine example.com login myuser password mypassword",
        "machine git.example.org login ci",
        "The state machine moves to login and waits for the password prompt.",
        "machine learning login page password reset",
    ] {
        assert_silent(text);
    }
}

// `concat!` splits the `auths` key: push protection scans Docker configs.
const AUTH: &str = "Y2ktZGVwbG95Okt4N3BRMnZMOXdSNG1Ueg==";

#[test]
fn docker_config_auth_values_are_reported() {
    for template in [
        concat!("{\"au", "ths\": {\"registry.example.com\": {\"auth\": \"{v}\"}}}"),
        concat!(
            "{\n  \"au",
            "ths\": {\n    \"https://index.docker.io/v1/\": {\n      \"auth\": \"{v}\",\n      \"email\": \"ci@example.com\"\n    }\n  }\n}"
        ),
        concat!("{\"au", "ths\":{\"ghcr.io\":{\"auth\":\"{v}\"}},\"credsStore\":\"\"}"),
        concat!(
            "{\"dockerconfigjson\": \"{\\\"au",
            "ths\\\":{\\\"quay.io\\\":{\\\"auth\\\":\\\"{v}\\\"}}}\"}"
        ),
        concat!(
            "  .dockerconfigjson: '{\"au",
            "ths\":{\"quay.io\":{\"auth\":\"{v}\"}}}'"
        ),
    ] {
        assert_exact("dlp_docker_config_auth", template, AUTH);
    }
}

#[test]
fn docker_config_entries_without_a_user_password_payload_are_silent() {
    for text in [
        // base64("ci-deploy:"): no password
        concat!(
            "{\"au",
            "ths\": {\"r.example.com\": {\"auth\": \"Y2ktZGVwbG95Og==\"}}}"
        ),
        // base64("ci-deploy:password"): a stand-in
        concat!(
            "{\"au",
            "ths\": {\"r.example.com\": {\"auth\": \"Y2ktZGVwbG95OnBhc3N3b3Jk\"}}}"
        ),
        // base64("session-status-ok"): no colon
        "{\"auth\": \"c2Vzc2lvbi1zdGF0dXMtb2s=\", \"status\": \"ok\"}",
        concat!(
            "{\"au",
            "ths\": {\"r.example.com\": {\"auth\": \"${DOCKER_AUTH}\"}}}"
        ),
        concat!("{\"au", "ths\": {\"r.example.com\": {\"auth\": \"\"}}}"),
        concat!(
            "{\"au",
            "ths\": {\"r.example.com\": {}}, \"credsStore\": \"desktop\"}"
        ),
        "{\"route\": \"/login\", \"auth\": \"required\"}",
        "{\"auth\": \"Bearer\"}",
    ] {
        assert_silent(text);
    }
}

#[test]
fn rules_are_searched_near_their_keywords() {
    // `machine`, `default` and `"auth` are common in code and docs: the
    // rules must not scan the whole text, so every match starts a bounded
    // lead before a keyword.
    let prefilter = RulePrefilter::new(DLP_PATTERNS);
    for (name, word) in [
        ("dlp_netrc_password", "machine"),
        ("dlp_netrc_password", "default"),
        ("dlp_docker_config_auth", "\"auth"),
    ] {
        let index = DLP_PATTERNS
            .iter()
            .position(|rule| rule.name == name)
            .expect("rule is registered");
        let text = format!("{}\nsee {word} for details\n", "x".repeat(4096));
        let scan = prefilter.scan(&text);
        assert!(scan.is_active(index), "{name}");
        assert!(scan.is_local(index), "{name}");
    }
}
