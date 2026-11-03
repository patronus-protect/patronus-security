// SPDX-License-Identifier: GPL-3.0-only
//! T20: a provider or CSRF value handed over in a DE/EN chat, ticket or mail
//! after the provider name and a credential noun keeps its provider rule
//! (the G-PROSE grammar: noun on the line or up to two lines before, value
//! after a colon, at the line end or alone). Elastic keeps `id:api_key` as
//! one span. Values come from the golden generator.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

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

/// The unsuppressed rule ids in `text`.
fn rule_ids(text: &str) -> Vec<String> {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("suppressed_by").is_none())
                .filter_map(|rule| rule["rule_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `rule_id` reports exactly `value` in `text`, and no other span.
fn assert_reported(text: &str, rule_id: &str, value: &str) {
    let spans: Vec<String> = scan(text)
        .evidence_spans
        .into_iter()
        .map(|span| span.text)
        .collect();
    assert_eq!(spans, [value], "{text}");
    assert!(rule_ids(text).iter().any(|id| id == rule_id), "{rule_id}: {text} {:?}", rule_ids(text));
}

fn assert_silent(text: &str) {
    assert!(scan(text).evidence_spans.is_empty(), "{text}: {:?}", rule_ids(text));
}

/// Provider rule, generator recipe, EN and DE label.
const PROVIDERS: &[(&str, &str, &str, &str)] = &[
    ("dlp_heroku_legacy_api_key", "heroku_api_key", "Heroku API key", "Heroku-API-Schlüssel"),
    ("dlp_railway_token", "railway_token", "Railway token", "Railway-Token"),
    ("dlp_netlify_legacy_token", "netlify_access_token", "Netlify access token", "Netlify-Zugriffstoken"),
    ("dlp_travis_token", "travisci_access_token", "Travis CI API token", "Travis-CI-API-Token"),
    ("dlp_circleci_legacy_token", "circleci_legacy_token", "CircleCI API token", "CircleCI-API-Token"),
    ("dlp_vercel_legacy_token", "vercel_legacy_token", "Vercel access token", "Vercel-Zugriffstoken"),
    ("dlp_azure_devops_legacy_pat", "azure_devops_legacy_pat", "Azure DevOps PAT", "Azure-DevOps-PAT"),
    ("dlp_cloudflare_api_key", "cloudflare_api_token", "Cloudflare API token", "Cloudflare-API-Token"),
    ("dlp_bitbucket_client_secret", "bitbucket_client_secret", "Bitbucket client secret", "Bitbucket-Client-Secret"),
    ("dlp_datadog_api_key", "datadog_api_key", "Datadog API key", "Datadog-API-Schlüssel"),
    ("dlp_newrelic_legacy_license_key", "newrelic_legacy_license_key", "New Relic license key", "New-Relic-Lizenzschlüssel"),
    ("dlp_sentry_auth_token", "sentry_auth_token", "Sentry auth token", "Sentry-Auth-Token"),
    ("dlp_splunk_hec_token", "splunk_hec_token", "Splunk HEC token", "Splunk-HEC-Token"),
    ("dlp_elastic_api_key", "elastic_api_key_pair", "Elastic API key", "Elastic-API-Schlüssel"),
    ("dlp_honeycomb_api_key", "honeycomb_api_key", "Honeycomb API key", "Honeycomb-API-Schlüssel"),
    ("dlp_pagerduty_api_key", "pagerduty_api_key", "PagerDuty API key", "PagerDuty-API-Schlüssel"),
    ("dlp_csrf_token", "csrf_token", "CSRF token", "CSRF-Token"),
];

/// Chat, ticket and mail handovers in EN and DE.
const CARRIERS: &[(&str, &str)] = &[
    ("en", "[09:41] maria.k: anyone have the {label} for the staging box? CI is red\n[09:43] tom.w: here you go: {}\n[09:43] tom.w: please don't paste it anywhere else\n"),
    ("en", "Note from reporter: the job still uses the old {label}. Current value in the config: {}\n"),
    ("en", "Hi team,\n\nas discussed, here is the {label} for the reporting job:\n\n{}\n\nThanks,\nAlex\n"),
    ("de", "[08:15] lena.s: Kurze Frage: Wie lautet der Wert für „{label}“ in der Testumgebung?\n[08:17] daniel.r: {}\n[08:17] daniel.r: Aber bitte nur lokal verwenden.\n"),
    ("de", "Seit dem Update schlägt der Abruf fehl. Laut Konfiguration hinterlegt ({label}): {}\nBitte prüfen.\n"),
    ("de", "Hallo zusammen,\n\nanbei wie besprochen die Zugangsdaten für den Abschlusslauf ({label}):\n\n{}\n\nViele Grüße\nKatrin\n"),
];

#[test]
fn provider_values_handed_over_in_prose_keep_their_provider_rule() {
    for (index, (rule_id, recipe, en, de)) in PROVIDERS.iter().enumerate() {
        let value = generated(recipe, 2000 + index as u64);
        for (language, carrier) in CARRIERS {
            let label = if *language == "en" { en } else { de };
            let text = carrier.replace("{label}", label).replace("{}", &value);
            assert_reported(&text, rule_id, &value);
        }
    }
}

#[test]
fn elastic_id_and_api_key_stay_one_span_in_prose() {
    let value = generated("elastic_api_key_pair", 7);
    let text = format!("Laut Konfiguration hinterlegt (Elastic-API-Schlüssel): {value}\n");
    assert_reported(&text, "dlp_elastic_api_key", &value);
    assert!(!rule_ids(&text).iter().any(|id| id == "dlp_prose_secret"));
}

#[test]
fn provider_names_without_credential_noun_and_ids_under_them_stay_silent() {
    for text in [
        "[10:02] maria.k: which Heroku app is the staging box?\n[10:03] tom.w: app id: 3f2b8c1e-9d4a-4e7b-8a6c-1b2d3e4f5a6b\n",
        "the Railway token was rotated yesterday. Project id: 7c9e6679-7425-40de-944b-e07fc1f90ae7\n",
        "Das Railway-Token wurde gestern getauscht. Projekt-ID: 7c9e6679-7425-40de-944b-e07fc1f90ae7\n",
        "Datadog dashboard for the checkout service: 4f1c2b9a8e7d6c5b4a3f2e1d0c9b8a7f\n",
        "Der PagerDuty-API-Schlüssel gehört zu diesem Dienst. Service-ID: 0af7651916cd43dd8448eb211c80319c\n",
        "the Splunk HEC token is configured for this index. Request id: 9b2c7e1a-4f3d-4c8b-9e2a-5d6f7a8b9c0d\n",
        "Hi team,\n\nthe Heroku API key for the reporting job:\n\n${HEROKU_API_KEY}\n",
        "[08:17] daniel.r: Das CSRF-Token steht im Formular:\n${CSRF_TOKEN}\n",
        "[09:43] tom.w: the CSRF token comes from the form:\n{{ csrf_token() }}\n",
    ] {
        assert_silent(text);
    }
}

#[test]
fn values_failing_the_provider_format_are_no_provider_finding() {
    for (rule_id, recipe, label) in [
        ("dlp_netlify_legacy_token", "netlify_access_token_short", "Netlify access token"),
        ("dlp_cloudflare_api_key", "cloudflare_api_token_short", "Cloudflare API token"),
        ("dlp_honeycomb_api_key", "honeycomb_api_key_short", "Honeycomb API key"),
        ("dlp_splunk_hec_token", "splunk_hec_token_short", "Splunk HEC token"),
        ("dlp_datadog_api_key", "datadog_api_key_short", "Datadog API key"),
    ] {
        let value = generated(recipe, 3);
        let text = format!("here is the {label} for the collector:\n\n{value}\n");
        assert!(!rule_ids(&text).iter().any(|id| id == rule_id), "{text}");
    }
}
