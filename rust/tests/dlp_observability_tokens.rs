// SPDX-License-Identifier: GPL-3.0-only
//! Observability tokens (P07). Provider prefixes and shapes:
//! `dlp_newrelic_user_api_key` (`NRAK-` and 27), `dlp_newrelic_insert_key`
//! (`NRII-` and 32 or 25), `dlp_newrelic_license_key` (32 hex digits or
//! `eu01xx` and 26, then `FFFFNRAL`), `dlp_sentry_user_token` (`sntryu_` and 64
//! hex digits), `dlp_sentry_org_token` (`sntrys_`, a base64 JSON payload with
//! `iat`, `_` and 43 base64 characters), `dlp_grafana_api_key` (base64 of
//! `{"k","n","id"}`), `dlp_grafana_cloud_token` (`glc_` and a base64 JSON
//! object), `dlp_grafana_service_account_token` (`glsa_`, 32 alphanumerics and
//! a little-endian CRC32) and `dlp_dynatrace_token` (`dt0c01`/`dt0s…`, 24 and
//! 64 characters). Under a provider key that ends in a credential noun or
//! after a provider header: Datadog API and application keys, New Relic
//! license keys without the suffix, legacy Sentry auth tokens, Splunk HEC
//! tokens (`Authorization: Splunk`), Elasticsearch API keys
//! (`Authorization: ApiKey`), Honeycomb keys (`x-honeycomb-team`) and
//! PagerDuty keys (`Token token=` with PagerDuty context). The secret key of a
//! legacy Sentry DSN is a finding, a DSN with the public key only is not.
//! Tokens come from the golden generator or from random bodies built here at
//! test time. Tokens are `SECRET_TOKEN` (subtype `access_token`), keys `API_KEY`.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::dlp::{ValidatorStrength, DLP_PATTERNS},
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Prefix rules: generators, subtype and validator strength.
const PREFIX_RULES: &[(&str, &[&str], &str, ValidatorStrength)] = &[
    (
        "dlp_newrelic_user_api_key",
        &["newrelic_user_api_key"],
        "api_key",
        ValidatorStrength::Format,
    ),
    (
        "dlp_newrelic_insert_key",
        &["newrelic_insert_key"],
        "api_key",
        ValidatorStrength::Format,
    ),
    (
        "dlp_newrelic_license_key",
        &["newrelic_license_key", "newrelic_license_key_eu"],
        "api_key",
        ValidatorStrength::Format,
    ),
    (
        "dlp_sentry_user_token",
        &["sentry_user_token"],
        "access_token",
        ValidatorStrength::Format,
    ),
    (
        "dlp_sentry_org_token",
        &["sentry_org_token"],
        "access_token",
        ValidatorStrength::Structure,
    ),
    (
        "dlp_grafana_api_key",
        &["grafana_api_key"],
        "access_token",
        ValidatorStrength::Structure,
    ),
    (
        "dlp_grafana_cloud_token",
        &["grafana_cloud_token"],
        "access_token",
        ValidatorStrength::Structure,
    ),
    (
        "dlp_grafana_service_account_token",
        &["grafana_service_account_token"],
        "access_token",
        ValidatorStrength::Checksum,
    ),
    (
        "dlp_dynatrace_token",
        &["dynatrace_api_token", "dynatrace_platform_token"],
        "access_token",
        ValidatorStrength::Format,
    ),
];

/// Rules of the entity group `SECRET_TOKEN`; the others are `API_KEY`.
const TOKEN_RULES: &[&str] = &[
    "dlp_sentry_user_token",
    "dlp_sentry_org_token",
    "dlp_sentry_auth_token",
    "dlp_grafana_api_key",
    "dlp_grafana_cloud_token",
    "dlp_grafana_service_account_token",
    "dlp_dynatrace_token",
    "dlp_splunk_hec_token",
];

/// Base64 tokens hold `/` and `+`, so no token boundary applies.
const UNBOUNDED_PREFIX_RULES: &[&str] = &[
    "dlp_sentry_org_token",
    "dlp_grafana_api_key",
    "dlp_grafana_cloud_token",
];

/// Key-anchored rules: generators, a provider key in screaming snake case and
/// subtype.
const KEYED_RULES: &[(&str, &[&str], &str, &str)] = &[
    (
        "dlp_datadog_api_key",
        &["datadog_api_key", "datadog_app_key"],
        "DD_API_KEY",
        "api_key",
    ),
    (
        "dlp_datadog_api_key",
        &["datadog_app_key"],
        "DATADOG_APP_KEY",
        "api_key",
    ),
    (
        "dlp_newrelic_legacy_license_key",
        &["newrelic_legacy_license_key"],
        "NEW_RELIC_LICENSE_KEY",
        "api_key",
    ),
    (
        "dlp_sentry_auth_token",
        &["sentry_auth_token"],
        "SENTRY_AUTH_TOKEN",
        "access_token",
    ),
    (
        "dlp_splunk_hec_token",
        &["splunk_hec_token"],
        "SPLUNK_HEC_TOKEN",
        "access_token",
    ),
    (
        "dlp_elastic_api_key",
        &["elastic_api_key", "elastic_api_key_pair"],
        "ELASTIC_API_KEY",
        "api_key",
    ),
    (
        "dlp_honeycomb_api_key",
        &["honeycomb_api_key", "honeycomb_classic_key"],
        "HONEYCOMB_API_KEY",
        "api_key",
    ),
    (
        "dlp_pagerduty_api_key",
        &[
            "pagerduty_user_token",
            "pagerduty_api_key",
            "pagerduty_integration_key",
        ],
        "PAGERDUTY_API_KEY",
        "api_key",
    ),
];

/// DE and EN carriers of a prefix token: .env, YAML, JSON, TOML, CLI, HTTP
/// header, log and prose.
const CARRIERS: &[&str] = &[
    "# Zugang des Monitoring-Agenten\nMONITORING_TOKEN={}\n",
    "monitoring:\n  token: \"{}\"\n",
    "{\"monitoring\": {\"token\": \"{}\"}}\n",
    "[monitoring]\ntoken = \"{}\"\n",
    "$ agent-cli --token {} --site eu\n",
    "GET /api/v2/status HTTP/1.1\nHost: monitoring.example.com\nAuthorization: Bearer {}\n",
    "2026-10-29T08:12:44Z WARN agent: Token {} wurde abgelehnt\n",
    "Das Token für den Monitoring-Agenten lautet {}, bitte im Tresor ablegen.\n",
    "Hi Sam, here is the token for the monitoring agent: {}\n",
];

/// DE and EN carriers of a key-anchored value; `KEY` is the provider key in
/// screaming snake case, `key` in snake case, `keyCamel` in camelCase.
const KEYED_CARRIERS: &[&str] = &[
    "# Zugang des Monitoring-Agenten\nKEY={}\n",
    "export KEY='{}'\n",
    "env:\n  KEY: \"{}\"\n",
    "{\"key\": \"{}\"}\n",
    "{\\\"key\\\": \\\"{}\\\"}\n",
    "key = \"{}\"\n",
    "const keyCamel = \"{}\";\n",
    "os.environ[\"KEY\"] = \"{}\"\n",
    "2026-10-29T08:12:44Z DEBUG config loaded: key={} retries=3\n",
];

/// The public key of the Sentry DSN carriers (not secret).
const DSN_PUBLIC_KEY: &str = "3f9c1e7a2b4d4c6e8a0b1c2d3e4f5a6b";

const HEX: &str = "0123456789abcdef";
const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

fn generated(gen: &str, seed: u64) -> String {
    materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(gen, seed)],
    )
    .expect("template must materialize")
    .0
}

fn random(seed: u64, alphabet: &str, len: usize) -> String {
    let alphabet = alphabet.as_bytes();
    let mut rng = SplitMix64::new(seed);
    (0..len)
        .map(|_| alphabet[(rng.next_u64() % alphabet.len() as u64) as usize] as char)
        .collect()
}

/// Standard base64 with padding.
fn base64(raw: &[u8]) -> String {
    let alphabet = BASE64.as_bytes();
    raw.chunks(3)
        .flat_map(|chunk| {
            let bits = chunk.iter().enumerate().fold(0u32, |bits, (index, byte)| {
                bits | u32::from(*byte) << (16 - 8 * index)
            });
            (0..4).map(move |index| {
                if index <= chunk.len() {
                    alphabet[(bits >> (18 - 6 * index) & 63) as usize] as char
                } else {
                    '='
                }
            })
        })
        .collect()
}

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

/// The unsuppressed `matched_rules` entry of `rule_id`, if it reported a
/// value.
fn entry(text: &str, rule_id: &str) -> Option<serde_json::Value> {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .and_then(|rules| {
            rules
                .iter()
                .find(|rule| rule["rule_id"] == rule_id && rule.get("suppressed_by").is_none())
                .cloned()
        })
}

/// Whether a span of the rule's entity group covers exactly `value`.
fn reports(text: &str, rule_id: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == group(rule_id) && span.text == value)
}

/// Tokens are `SECRET_TOKEN`, keys and the DSN secret `API_KEY`.
fn group(rule_id: &str) -> &'static str {
    if TOKEN_RULES.contains(&rule_id) {
        "SECRET_TOKEN"
    } else {
        "API_KEY"
    }
}

fn keyed(carrier: &str, key: &str, value: &str) -> String {
    let snake = key.to_ascii_lowercase();
    let camel: String = snake
        .split('_')
        .enumerate()
        .map(|(index, part)| {
            if index == 0 {
                part.to_owned()
            } else {
                part[..1].to_ascii_uppercase() + &part[1..]
            }
        })
        .collect();
    carrier
        .replace("keyCamel", &camel)
        .replace("KEY", key)
        .replace("key", &snake)
        .replace("{}", value)
}

#[test]
fn generated_prefix_tokens_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, gens, subtype, _) in PREFIX_RULES {
        for gen in *gens {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for (index, carrier) in CARRIERS.iter().enumerate() {
                    let text = carrier.replace("{}", &value);
                    assert!(
                        reports(&text, rule_id, &value),
                        "{gen}/{seed}: carrier {index}"
                    );
                    let rule =
                        entry(&text, rule_id).unwrap_or_else(|| panic!("{gen}/{seed}: {index}"));
                    assert_eq!(rule["subtype"], *subtype, "{rule_id}");
                }
            }
        }
        // A sentence may end right after a token.
        let value = generated(gens[0], 7);
        let text = format!("Das Token lautet {value}.");
        assert!(entry(&text, rule_id).is_some(), "{rule_id}");
    }
}

#[test]
fn generated_values_are_reported_under_their_provider_key() {
    for (rule_id, gens, key, subtype) in KEYED_RULES {
        for gen in *gens {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for (index, carrier) in KEYED_CARRIERS.iter().enumerate() {
                    let text = keyed(carrier, key, &value);
                    assert!(
                        reports(&text, rule_id, &value),
                        "{gen}/{seed}: carrier {index}"
                    );
                    let rule =
                        entry(&text, rule_id).unwrap_or_else(|| panic!("{gen}/{seed}: {index}"));
                    assert_eq!(rule["subtype"], *subtype, "{rule_id}");
                }
            }
        }
    }
    // Headers, labels and other spellings of the key.
    for (rule_id, gen, template) in [
        (
            "dlp_datadog_api_key",
            "datadog_app_key",
            "curl -H \"DD-APPLICATION-KEY: {}\" https://api.datadoghq.eu/api/v1/validate",
        ),
        (
            "dlp_datadog_api_key",
            "datadog_api_key",
            "Datadog-API-Schlüssel: {}",
        ),
        (
            "dlp_newrelic_legacy_license_key",
            "newrelic_legacy_license_key",
            "common:\n  newrelic.license_key: '{}'",
        ),
        (
            "dlp_splunk_hec_token",
            "splunk_hec_token",
            "curl -k https://splunk.example.com:8088/services/collector -H \"Authorization: Splunk {}\"",
        ),
        (
            "dlp_splunk_hec_token",
            "splunk_hec_token",
            "headers = {\"Authorization\": \"Splunk {}\"}",
        ),
        (
            "dlp_elastic_api_key",
            "elastic_api_key",
            "GET /_security/_authenticate HTTP/1.1\nAuthorization: ApiKey {}\n",
        ),
        (
            "dlp_elastic_api_key",
            "elastic_api_key_pair",
            "output.elasticsearch:\n  hosts: [\"https://es.example.com:9200\"]\n  elasticsearch.api_key: \"{}\"",
        ),
        (
            "dlp_honeycomb_api_key",
            "honeycomb_api_key",
            "OTEL_EXPORTER_OTLP_HEADERS=\"x-honeycomb-team={},x-honeycomb-dataset=web\"",
        ),
        (
            "dlp_honeycomb_api_key",
            "honeycomb_classic_key",
            "X-Honeycomb-Team: {}",
        ),
        (
            "dlp_pagerduty_api_key",
            "pagerduty_api_key",
            "curl -H \"Authorization: Token token={}\" https://api.pagerduty.com/incidents",
        ),
        (
            "dlp_pagerduty_api_key",
            "pagerduty_integration_key",
            "PAGER_DUTY_ROUTING_KEY={}",
        ),
    ] {
        let value = generated(gen, 3);
        let text = template.replace("{}", &value);
        assert!(entry(&text, rule_id).is_some(), "{rule_id}: {template:?}");
        assert!(reports(&text, rule_id, &value), "{rule_id}: {template:?}");
    }
}

#[test]
fn provider_keys_without_a_credential_noun_hold_no_secret() {
    let hex32 = random(5, HEX, 32);
    let hex40 = random(5, HEX, 40);
    let uuid = generated("splunk_hec_token", 5);
    for (index, (rule_id, text)) in [
        ("dlp_datadog_api_key", format!("DD_TRACE_ID={hex32}")),
        ("dlp_datadog_api_key", format!("DD_VERSION={hex40}")),
        ("dlp_datadog_api_key", format!("datadog_org_id: {hex32}")),
        (
            "dlp_newrelic_legacy_license_key",
            format!("NEW_RELIC_APP_ID={hex40}"),
        ),
        (
            "dlp_sentry_auth_token",
            format!("SENTRY_RELEASE={}", random(5, HEX, 64)),
        ),
        ("dlp_splunk_hec_token", format!("SPLUNK_INDEX_ID={uuid}")),
        (
            "dlp_honeycomb_api_key",
            format!("HONEYCOMB_DATASET={}", random(5, ALNUM, 22)),
        ),
        (
            "dlp_pagerduty_api_key",
            format!("PAGERDUTY_SERVICE_ID={}", random(5, ALNUM, 20)),
        ),
        (
            "dlp_elastic_api_key",
            format!("ELASTIC_CLOUD_ID={}", generated("elastic_api_key", 5)),
        ),
        // The key must end in its noun right before the separator.
        ("dlp_datadog_api_key", format!("DD_API_KEY_ID={hex32}")),
        ("dlp_splunk_hec_token", format!("SPLUNK_TOKEN_NAME={uuid}")),
        // A value without a provider key, or a `dd` inside a word.
        ("dlp_datadog_api_key", format!("API_KEY={hex32}")),
        ("dlp_datadog_api_key", format!("ADDRESS_KEY={hex32}")),
        ("dlp_splunk_hec_token", format!("TOKEN={uuid}")),
        // Another authorization scheme.
        (
            "dlp_splunk_hec_token",
            format!("Authorization: Bearer {uuid}"),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(entry(&text, rule_id).is_none(), "{rule_id}: case {index}");
    }
}

#[test]
fn values_of_another_length_or_alphabet_are_no_token() {
    for seed in 0..8 {
        let cases: Vec<(&str, String)> = vec![
            (
                "dlp_newrelic_user_api_key",
                format!("NRAK-{}", random(seed, UPPER_ALNUM, 26)),
            ),
            (
                "dlp_newrelic_user_api_key",
                format!("NRAK-{}", random(seed, UPPER_ALNUM, 28)),
            ),
            (
                "dlp_newrelic_insert_key",
                format!("NRII-{}", random(seed, ALNUM, 31)),
            ),
            (
                "dlp_newrelic_insert_key",
                format!("NRII-{}", random(seed, ALNUM, 26)),
            ),
            (
                "dlp_newrelic_license_key",
                format!("{}FFFFNRAL", random(seed, HEX, 31)),
            ),
            (
                "dlp_newrelic_license_key",
                format!("{}FFFFNRAL", random(seed, HEX, 33)),
            ),
            (
                "dlp_sentry_user_token",
                format!("sntryu_{}", random(seed, HEX, 63)),
            ),
            (
                "dlp_sentry_user_token",
                format!("sntryu_{}", random(seed, HEX, 65)),
            ),
            (
                "dlp_grafana_service_account_token",
                format!("glsa_{}_{}", random(seed, ALNUM, 31), random(seed, HEX, 8)),
            ),
            (
                "dlp_dynatrace_token",
                format!(
                    "dt0c01.{}.{}",
                    random(seed, UPPER_ALNUM, 23),
                    random(seed, UPPER_ALNUM, 64)
                ),
            ),
            (
                "dlp_dynatrace_token",
                format!(
                    "dt0x01.{}.{}",
                    random(seed, UPPER_ALNUM, 24),
                    random(seed, UPPER_ALNUM, 64)
                ),
            ),
            (
                "dlp_dynatrace_token",
                format!(
                    "dt0c01.{}.{}",
                    random(seed, UPPER_ALNUM, 24),
                    random(seed, UPPER_ALNUM, 63)
                ),
            ),
            (
                "dlp_datadog_api_key",
                format!("DD_API_KEY={}", random(seed, HEX, 31)),
            ),
            (
                "dlp_datadog_api_key",
                format!("DD_CLIENT_TOKEN=pub{}", random(seed, HEX, 32)),
            ),
            (
                "dlp_sentry_auth_token",
                format!("SENTRY_AUTH_TOKEN={}", random(seed, HEX, 63)),
            ),
            (
                "dlp_splunk_hec_token",
                format!(
                    "SPLUNK_HEC_TOKEN={}",
                    &generated("splunk_hec_token", seed)[..35]
                ),
            ),
            (
                "dlp_honeycomb_api_key",
                format!("HONEYCOMB_API_KEY={}", random(seed, ALNUM, 21)),
            ),
            (
                "dlp_pagerduty_api_key",
                format!("PAGERDUTY_API_KEY={}", random(seed, ALNUM, 19)),
            ),
        ];
        for (rule_id, value) in cases {
            for carrier in &CARRIERS[..3] {
                let text = carrier.replace("{}", &value);
                assert!(entry(&text, rule_id).is_none(), "{rule_id}: {carrier:?}");
            }
        }
    }
}

#[test]
fn datadog_client_tokens_are_public() {
    for seed in 0..8 {
        let token = format!("pub{}", random(seed, HEX, 32));
        for text in [
            format!("DD_CLIENT_TOKEN={token}\n"),
            format!(
                "window.DD_RUM.init({{\n  clientToken: '{token}',\n  site: 'datadoghq.eu',\n}});\n"
            ),
            format!("{{\"datadog\": {{\"client_token\": \"{token}\"}}}}\n"),
        ] {
            assert!(scan(&text).evidence_spans.is_empty(), "seed {seed}");
        }
    }
}

#[test]
fn single_case_bodies_are_no_key() {
    let lower = "abcdefghijklmnopqrstuvwxyz0123456789";
    for seed in 0..8 {
        for (rule_id, text) in [
            (
                "dlp_honeycomb_api_key",
                format!("HONEYCOMB_API_KEY={}", random(seed, lower, 22)),
            ),
            (
                "dlp_pagerduty_api_key",
                format!("PAGERDUTY_API_KEY={}", random(seed, lower, 20)),
            ),
            (
                "dlp_elastic_api_key",
                format!(
                    "ELASTIC_API_KEY={}:{}",
                    random(seed, ALNUM, 20),
                    random(seed, lower, 22)
                ),
            ),
        ] {
            assert!(entry(&text, rule_id).is_none(), "{rule_id}");
        }
    }
}

#[test]
fn grafana_service_account_tokens_need_their_crc32() {
    for seed in 0..8 {
        let value = generated("grafana_service_account_token", seed);
        let (key, checksum) = value.rsplit_once('_').expect("glsa_ token");
        assert_eq!(checksum.len(), 8);
        // Big-endian digits, a changed secret character and a changed digit.
        let swapped: String = checksum
            .as_bytes()
            .chunks(2)
            .rev()
            .map(|pair| std::str::from_utf8(pair).expect("hex"))
            .collect();
        let mut changed_key = key.to_owned();
        let last = changed_key.pop().expect("secret");
        changed_key.push(if last == 'a' { 'b' } else { 'a' });
        let flipped = if checksum.starts_with('0') { "1" } else { "0" };
        for wrong in [
            format!("{key}_{swapped}"),
            format!("{changed_key}_{checksum}"),
            format!("{key}_{flipped}{}", &checksum[1..]),
        ] {
            if wrong == value {
                continue;
            }
            let text = format!("GRAFANA_TOKEN={wrong}\n");
            assert!(
                entry(&text, "dlp_grafana_service_account_token").is_none(),
                "seed {seed}"
            );
            // A token shape with a failing checksum is no secret for the
            // generic rules either.
            assert!(scan(&text).evidence_spans.is_empty(), "seed {seed}");
        }
        assert!(entry(
            &format!("GRAFANA_TOKEN={value}\n"),
            "dlp_grafana_service_account_token"
        )
        .is_some());
    }
}

#[test]
fn base64_tokens_need_their_decoded_structure() {
    for seed in 0..8 {
        let key = random(seed, ALNUM, 32);
        let secret = random(seed + 100, BASE64, 43);
        let (id, api_key) = (random(seed + 200, ALNUM, 20), random(seed + 300, ALNUM, 23));
        for (rule_id, value, valid) in [
            (
                "dlp_grafana_api_key",
                base64(format!("{{\"k\":\"{key}\",\"n\":\"deploy\",\"id\":1}}").as_bytes()),
                true,
            ),
            // No org id, or no JSON object.
            (
                "dlp_grafana_api_key",
                base64(format!("{{\"k\":\"{key}\",\"n\":\"deploy\"}}").as_bytes()),
                false,
            ),
            (
                "dlp_grafana_api_key",
                base64(format!("{{\"k\":\"{key}\",\"n\":\"deploy\",\"id\":1").as_bytes()),
                false,
            ),
            (
                "dlp_grafana_cloud_token",
                format!(
                    "glc_{}",
                    base64(format!("{{\"o\":\"1\",\"n\":\"read\",\"k\":\"{key}\"}}").as_bytes())
                ),
                true,
            ),
            (
                "dlp_grafana_cloud_token",
                format!(
                    "glc_{}",
                    base64(format!("{{\"o\":\"1\",\"n\":\"read\",\"x\":\"{key}\"}}").as_bytes())
                ),
                false,
            ),
            (
                "dlp_grafana_cloud_token",
                format!("glc_{}", random(seed, BASE64, 64)),
                false,
            ),
            (
                "dlp_sentry_org_token",
                format!(
                    "sntrys_{}_{secret}",
                    base64(
                        format!("{{\"iat\": 1730000000.5, \"url\": \"https://sentry.io\", \"org\": \"{key}\"}}")
                            .as_bytes()
                    )
                ),
                true,
            ),
            // `iat` must be a number.
            (
                "dlp_sentry_org_token",
                format!(
                    "sntrys_{}_{secret}",
                    base64(
                        format!("{{\"iat\": \"now\", \"url\": \"https://sentry.io\", \"org\": \"{key}\"}}")
                            .as_bytes()
                    )
                ),
                false,
            ),
            (
                "dlp_elastic_api_key",
                format!(
                    "ELASTIC_API_KEY={}",
                    base64(format!("{id}:{}", &api_key[..22]).as_bytes())
                ),
                true,
            ),
            // An api_key of 21 characters or a third field.
            (
                "dlp_elastic_api_key",
                format!(
                    "ELASTIC_API_KEY={}",
                    base64(format!("{id}:{}", &api_key[..21]).as_bytes())
                ),
                false,
            ),
            (
                "dlp_elastic_api_key",
                format!(
                    "ELASTIC_API_KEY={}",
                    base64(format!("{id}:{}:{}", &api_key[..22], &key[..4]).as_bytes())
                ),
                false,
            ),
        ] {
            let text = format!("monitoring:\n  value: \"{value}\"\n");
            assert_eq!(entry(&text, rule_id).is_some(), valid, "{rule_id} seed {seed}");
        }
    }
}

#[test]
fn only_the_secret_key_of_a_legacy_sentry_dsn_is_reported() {
    for seed in 0..8 {
        let secret = generated("sentry_dsn_secret_key", seed);
        for template in [
            "SENTRY_DSN=https://PUB:{}@o450123.ingest.sentry.io/5512345\n",
            "Sentry.init({ dsn: \"https://PUB:{}@sentry.example.com/12\" });\n",
            "sentry_sdk.init(dsn='https://PUB:{}@sentry.intern.example.de:9000/api/7')\n",
            "sentry:\n  dsn: https://PUB:{}@o1.ingest.de.sentry.io/4508\n",
            "Der DSN lautet https://PUB:{}@sentry.example.com/12, bitte rotieren.\n",
        ] {
            let text = template
                .replace("PUB", DSN_PUBLIC_KEY)
                .replace("{}", &secret);
            assert!(
                reports(&text, "dlp_sentry_dsn_secret", &secret),
                "seed {seed}: {template:?}"
            );
            let rule = entry(&text, "dlp_sentry_dsn_secret")
                .unwrap_or_else(|| panic!("seed {seed}: {template:?}"));
            assert_eq!(rule["subtype"], "secret_key");
        }
        for template in [
            // The public key alone is safe to expose.
            "SENTRY_DSN=https://{}@o450123.ingest.sentry.io/5512345\n",
            // No numeric project ID, or a public key of another length.
            "SENTRY_DSN=https://PUB:{}@o450123.ingest.sentry.io/project\n",
            "SENTRY_DSN=https://3f9c1e7a2b4d:{}@o450123.ingest.sentry.io/5512345\n",
        ] {
            let text = template
                .replace("PUB", DSN_PUBLIC_KEY)
                .replace("{}", &secret);
            assert!(
                entry(&text, "dlp_sentry_dsn_secret").is_none(),
                "seed {seed}: {template:?}"
            );
        }
        let public = format!("SENTRY_DSN=https://{secret}@o450123.ingest.sentry.io/5512345\n");
        assert!(scan(&public).evidence_spans.is_empty(), "seed {seed}");
    }
}

#[test]
fn pagerduty_token_scheme_needs_pagerduty_context() {
    for seed in 0..8 {
        let value = generated("pagerduty_api_key", seed);
        for text in [
            format!(
                "curl -H \"Authorization: Token token={value}\" https://api.pagerduty.com/users"
            ),
            format!(
                "# PagerDuty REST client\n\nheaders[\"Authorization\"] = \"Token token={value}\"\n"
            ),
        ] {
            assert!(
                entry(&text, "dlp_pagerduty_api_key").is_some(),
                "seed {seed}"
            );
        }
        for text in [
            // Rails token authentication uses the same scheme.
            format!("curl -H \"Authorization: Token token={value}\" https://shop.example.com/api/orders"),
            // A PagerDuty term six lines above is out of reach.
            format!("# PagerDuty\n\n\n\n\n\nAuthorization: Token token={value}\n"),
        ] {
            assert!(entry(&text, "dlp_pagerduty_api_key").is_none(), "seed {seed}");
        }
    }
}

#[test]
fn every_rule_has_a_provider_a_format_source_and_its_anchor() {
    for (rule_id, _, _, strength) in PREFIX_RULES {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == *rule_id)
            .unwrap_or_else(|| panic!("{rule_id} must be registered"));
        assert_eq!(rule.entity_group, group(rule_id), "{rule_id}");
        assert!(rule.meta.provider.is_some(), "{rule_id}");
        assert_ne!(rule.meta.source_ref, "ark", "{rule_id}");
        assert_eq!(
            rule.meta.boundary.is_some(),
            !UNBOUNDED_PREFIX_RULES.contains(rule_id),
            "{rule_id}"
        );
        assert!(rule.span_group.is_none(), "{rule_id}");
        assert_eq!(rule.meta.validator_strength, *strength, "{rule_id}");
    }
    for rule_id in KEYED_RULES
        .iter()
        .map(|(rule_id, ..)| *rule_id)
        .chain(["dlp_sentry_dsn_secret"])
    {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == rule_id)
            .unwrap_or_else(|| panic!("{rule_id} must be registered"));
        assert_eq!(rule.entity_group, group(rule_id), "{rule_id}");
        assert!(rule.meta.provider.is_some(), "{rule_id}");
        assert_ne!(rule.meta.source_ref, "ark", "{rule_id}");
        assert!(rule.meta.boundary.is_none(), "{rule_id}");
        assert_eq!(rule.span_group, Some(1), "{rule_id}");
    }
}

#[test]
fn example_and_test_fills_are_silent() {
    for (gen, template) in [
        ("newrelic_user_api_key", "NEW_RELIC_API_KEY=<<secret:0>>\n"),
        ("newrelic_insert_key", "NEW_RELIC_INSERT_KEY=<<secret:0>>\n"),
        ("newrelic_license_key", "NEW_RELIC_LICENSE_KEY=<<secret:0>>\n"),
        (
            "newrelic_legacy_license_key",
            "NEW_RELIC_LICENSE_KEY=<<secret:0>>\n",
        ),
        ("sentry_user_token", "SENTRY_AUTH_TOKEN=<<secret:0>>\n"),
        ("sentry_auth_token", "SENTRY_AUTH_TOKEN=<<secret:0>>\n"),
        (
            "sentry_dsn_secret_key",
            "SENTRY_DSN=https://3f9c1e7a2b4d4c6e8a0b1c2d3e4f5a6b:<<secret:0>>@o1.ingest.sentry.io/1\n",
        ),
        (
            "grafana_service_account_token",
            "GRAFANA_TOKEN=<<secret:0>>\n",
        ),
        ("dynatrace_api_token", "DT_API_TOKEN=<<secret:0>>\n"),
        ("datadog_api_key", "DD_API_KEY=<<secret:0>>\n"),
        ("datadog_app_key", "DD_APP_KEY=<<secret:0>>\n"),
        ("splunk_hec_token", "SPLUNK_HEC_TOKEN=<<secret:0>>\n"),
        ("honeycomb_api_key", "HONEYCOMB_API_KEY=<<secret:0>>\n"),
        ("pagerduty_api_key", "PAGERDUTY_API_KEY=<<secret:0>>\n"),
    ] {
        for fill in ["EXAMPLE", "deadbeef", "TESTKEY"] {
            let Ok((text, _)) = materialize(
                generators(),
                template,
                &[SecretRecipe::filled(gen, 0, fill)],
            ) else {
                continue;
            };
            assert!(scan(&text).evidence_spans.is_empty(), "{gen}/{fill}");
        }
    }
}
