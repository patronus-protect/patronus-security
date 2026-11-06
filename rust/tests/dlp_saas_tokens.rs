// SPDX-License-Identifier: GPL-3.0-only
//! Productivity/SaaS tokens with an own prefix (P10). Shapes per source:
//! `dlp_atlassian_api_token` (`ATATT3` and 186 characters, gitleaks
//! atlassian-api-token), `dlp_notion_api_token` (`ntn_`, 11 digits and 35
//! alphanumerics, gitleaks notion-api-token), `dlp_linear_api_key`
//! (`lin_api_` and 40 alphanumerics, gitleaks linear-api-key),
//! `dlp_airtable_pat` (`pat`, 14 alphanumerics, `.` and 64 hex digits,
//! gitleaks airtable-personnal-access-token), `dlp_postman_api_key` (`PMAK-`,
//! 24 and 34 hex digits, gitleaks postman-api-token) and
//! `dlp_mapbox_secret_token` (`sk.`, TruffleHog Mapbox; public `pk.` tokens
//! are no secret). Formats without a prefix only count under a key with the
//! provider name and a credential noun: `dlp_atlassian_legacy_api_token` (24
//! alphanumerics), `dlp_linear_client_secret` (32 hex digits, gitleaks
//! linear-client-secret) and `dlp_airtable_api_key` (`key` and 14, gitleaks
//! airtable-api-key). Values come from the golden generator or are built here
//! at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Rules, the key name their carriers use, generators and lookalike
/// generators (wrong length or public token).
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "dlp_atlassian_api_token",
        "JIRA_API_TOKEN",
        "atlassian_api_token",
        "atlassian_api_token_short",
    ),
    (
        "dlp_notion_api_token",
        "NOTION_TOKEN",
        "notion_api_token",
        "notion_api_token_short",
    ),
    (
        "dlp_linear_api_key",
        "LINEAR_API_KEY",
        "linear_api_key",
        "linear_api_key_short",
    ),
    (
        "dlp_airtable_pat",
        "AIRTABLE_TOKEN",
        "airtable_personal_access_token",
        "airtable_personal_access_token_short",
    ),
    (
        "dlp_postman_api_key",
        "POSTMAN_API_KEY",
        "postman_api_token",
        "postman_api_token_short",
    ),
    (
        "dlp_mapbox_secret_token",
        "MAPBOX_SECRET_TOKEN",
        "mapbox_secret_token",
        "mapbox_access_token",
    ),
];

/// DE and EN carriers with the provider's key name `{key}`: .env, YAML, JSON,
/// code, CLI, log and prose.
const CARRIERS: &[&str] = &[
    "# Zugang für die Synchronisation\n{key}={}\n",
    "integration:\n  {key}: \"{}\"\n",
    "{\"integration\": {\"{key}\": \"{}\"}}\n",
    "{key} = \"{}\"\nclient = Client(auth={key})\n",
    "$ export {key}={}\n",
    "2026-11-06T05:12:44Z DEBUG sync: {key}={} geladen\n",
    "Hi Sam, here is the {key}: {}\n",
];

/// A carrier without a key name, where only the shape tells a value apart.
const NEUTRAL_CARRIER: &str = "2026-11-06T05:12:44Z WARN sync: rejected {} (wrong shape)\n";

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

/// Whether `rule_id` reported a value in `text` (unsuppressed).
fn rule_hit(text: &str, rule_id: &str) -> bool {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule["rule_id"] == rule_id && rule.get("suppressed_by").is_none())
        })
}

/// Whether a span covers exactly `value`.
fn reports(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.text == value)
}

fn carrier(template: &str, key: &str, value: &str) -> String {
    template.replace("{key}", key).replace("{}", value)
}

#[test]
fn generated_values_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, key, gen, _) in RULES {
        for seed in 0..6 {
            let value = generated(gen, seed);
            for (index, template) in CARRIERS.iter().enumerate() {
                let text = carrier(template, key, &value);
                assert!(rule_hit(&text, rule_id), "{gen}/{seed}: carrier {index}");
                assert!(reports(&text, &value), "{gen}/{seed}: carrier {index}");
            }
        }
    }
}

#[test]
fn prefixed_values_need_no_key_name() {
    for (rule_id, _, gen, _) in RULES {
        let value = generated(gen, 2);
        let text = NEUTRAL_CARRIER.replace("{}", &value);
        assert!(rule_hit(&text, rule_id), "{gen}: {text}");
        assert!(reports(&text, &value), "{gen}: {text}");
    }
}

#[test]
fn lookalikes_are_not_reported() {
    for (rule_id, key, _, gen) in RULES {
        for seed in 0..8 {
            let value = generated(gen, seed);
            for template in CARRIERS {
                let text = carrier(template, key, &value);
                assert!(!rule_hit(&text, rule_id), "{rule_id}: {gen}/{seed}: {text}");
            }
            let text = NEUTRAL_CARRIER.replace("{}", &value);
            assert!(!rule_hit(&text, rule_id), "{gen}/{seed}: {text}");
        }
    }
}

#[test]
fn public_mapbox_tokens_are_no_secret() {
    // A pk. token ships to the browser; only the sk. scope is a secret.
    let secret = generated("mapbox_secret_token", 4);
    let public = format!("pk.{}", &secret[3..]);
    for text in [
        format!("mapboxgl.accessToken = \"{public}\";\n"),
        format!("NEXT_PUBLIC_MAPBOX_TOKEN={public}\n"),
    ] {
        assert!(!rule_hit(&text, "dlp_mapbox_secret_token"), "{text}");
        // Nor is it a secret for the generic assignment rules.
        assert!(scan(&text).evidence_spans.is_empty(), "{text}");
    }
    let text = format!("MAPBOX_DOWNLOADS_TOKEN={secret}\n");
    assert!(rule_hit(&text, "dlp_mapbox_secret_token"), "{text}");
}

#[test]
fn prefixes_inside_identifiers_are_not_reported() {
    for (rule_id, _, gen, _) in RULES {
        let value = generated(gen, 5);
        let text = format!("const glued = \"x{value}\";\n");
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {text}");
    }
}

#[test]
fn single_case_fills_are_not_reported() {
    let fills = [
        (
            "dlp_atlassian_api_token",
            "JIRA_API_TOKEN",
            format!("ATATT3{}", "abcdef".repeat(31)),
        ),
        (
            "dlp_notion_api_token",
            "NOTION_TOKEN",
            format!("ntn_{}{}", "1".repeat(11), "abcde".repeat(7)),
        ),
        (
            "dlp_linear_api_key",
            "LINEAR_API_KEY",
            format!("lin_api_{}", "ABCDEFGH".repeat(5)),
        ),
        (
            "dlp_airtable_pat",
            "AIRTABLE_TOKEN",
            format!("patAbcdAbcdAbcdAb.{}", "0".repeat(64)),
        ),
        (
            "dlp_postman_api_key",
            "POSTMAN_API_KEY",
            format!("PMAK-{}-{}", "a".repeat(24), "b".repeat(34)),
        ),
        (
            "dlp_mapbox_secret_token",
            "MAPBOX_SECRET_TOKEN",
            format!("sk.{}.{}", "abcdef".repeat(10), "ABCDEFGHIJK".repeat(2)),
        ),
    ];
    for (rule_id, key, value) in &fills {
        let text = format!("{key}={value}\n");
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {value}");
    }
}

/// Rules without an own prefix, their provider key and generator.
const CONTEXT_RULES: &[(&str, &str, &str)] = &[
    (
        "dlp_atlassian_legacy_api_token",
        "JIRA_API_TOKEN",
        "atlassian_api_token_legacy",
    ),
    (
        "dlp_linear_client_secret",
        "LINEAR_CLIENT_SECRET",
        "linear_client_secret",
    ),
    (
        "dlp_airtable_api_key",
        "AIRTABLE_API_KEY",
        "airtable_api_key",
    ),
];

#[test]
fn context_values_are_reported_under_their_provider_key() {
    for (rule_id, key, gen) in CONTEXT_RULES {
        for seed in 0..6 {
            let value = generated(gen, seed);
            for (index, template) in CARRIERS[..6].iter().enumerate() {
                let text = carrier(template, key, &value);
                assert!(rule_hit(&text, rule_id), "{gen}/{seed}: carrier {index}");
                assert!(reports(&text, &value), "{gen}/{seed}: carrier {index}");
            }
        }
    }
}

#[test]
fn context_values_need_their_provider_name() {
    for (rule_id, _, gen) in CONTEXT_RULES {
        let value = generated(gen, 3);
        for text in [
            format!("SERVICE_API_TOKEN={value}\n"),
            NEUTRAL_CARRIER.replace("{}", &value),
            // A provider name without a credential noun names an ID.
            format!("JIRA_ISSUE_ID={value}\nLINEAR_TEAM_ID={value}\nAIRTABLE_BASE={value}\n"),
        ] {
            assert!(!rule_hit(&text, rule_id), "{rule_id}: {text}");
        }
    }
}

#[test]
fn context_fills_without_mixed_characters_are_not_reported() {
    for (rule_id, text) in [
        (
            "dlp_atlassian_legacy_api_token",
            format!("JIRA_API_TOKEN={}\n", "abcdefgh".repeat(3)),
        ),
        (
            "dlp_airtable_api_key",
            format!("AIRTABLE_API_KEY=key{}\n", "abcdefg".repeat(2)),
        ),
        (
            "dlp_linear_client_secret",
            format!("LINEAR_CLIENT_SECRET={}\n", "0".repeat(32)),
        ),
    ] {
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {text}");
    }
}

#[test]
fn token_prefixes_with_a_placeholder_are_no_secret() {
    for text in [
        "notion:\n  token: \"ntn_<your-integration-secret>\"\n",
        "{\"linear\": {\"apiKey\": \"lin_api_${LINEAR_API_KEY}\"}}\n",
        "postman:\n  api_key: \"PMAK-{{ postman_key }}\"\n",
    ] {
        assert!(scan(text).evidence_spans.is_empty(), "{text}");
    }
}
