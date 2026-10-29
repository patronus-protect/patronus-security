// SPDX-License-Identifier: GPL-3.0-only
//! CI and hosting tokens (P06). Provider prefixes: `dlp_azure_devops_pat`
//! (84 alphanumerics with `AZDO` at positions 76 to 80), `dlp_circleci_token`
//! (`CCIPAT_`/`CCIPRJ_`, a base58 UUID and 40 hex digits), `dlp_vercel_token`
//! (`vcp_`/`vci_`/`vca_`/`vcr_`/`vck_` and 56 alphanumerics),
//! `dlp_netlify_token` (`nfp_`), `dlp_flyio_token` (`fo1_`),
//! `dlp_flyio_macaroon_token` (`fm1a_`, `fm1r_`, `fm2_` and base64, without a
//! token boundary), `dlp_heroku_api_key` (`HRKU-AA`), `dlp_render_api_key` (`rnd_`,
//! only next to a Render term), `dlp_cloudflare_origin_ca_key` (`v1.0-`) and
//! `dlp_digitalocean_token` (`dop_v1_`/`doo_v1_`/`dor_v1_`). Under a provider
//! key that ends in a credential noun: Bitbucket client secrets, legacy Azure
//! DevOps PATs, legacy CircleCI and Vercel tokens, Travis CI tokens, legacy
//! Netlify tokens, legacy Heroku API keys and Railway tokens (UUIDs) and
//! Cloudflare API tokens and Global API Keys. Tokens come from the golden
//! generator or from random bodies built here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::dlp::{ValidatorStrength, DLP_PATTERNS},
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Prefix rules: generators, entity group and subtype.
const PREFIX_RULES: &[(&str, &[&str], &str, &str)] = &[
    (
        "dlp_azure_devops_pat",
        &["azure_devops_pat"],
        "SECRET_TOKEN",
        "access_token",
    ),
    (
        "dlp_circleci_token",
        &["circleci_personal_token", "circleci_project_token"],
        "SECRET_TOKEN",
        "access_token",
    ),
    (
        "dlp_vercel_token",
        &["vercel_personal_token", "vercel_app_access_token"],
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_netlify_token",
        &["netlify_personal_token"],
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_flyio_token",
        &["flyio_oauth_token"],
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_flyio_macaroon_token",
        &["flyio_macaroon_token"],
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_heroku_api_key",
        &["heroku_api_key_v2"],
        "CLOUD_KEY",
        "api_key",
    ),
    (
        "dlp_render_api_key",
        &["render_api_key"],
        "CLOUD_KEY",
        "api_key",
    ),
    (
        "dlp_cloudflare_origin_ca_key",
        &["cloudflare_origin_ca_key"],
        "CLOUD_KEY",
        "api_key",
    ),
    (
        "dlp_digitalocean_token",
        &[
            "digitalocean_pat",
            "digitalocean_oauth_token",
            "digitalocean_refresh_token",
        ],
        "CLOUD_KEY",
        "access_token",
    ),
];

/// Key-anchored rules: generators, a provider key in screaming snake case,
/// entity group and subtype.
const KEYED_RULES: &[(&str, &[&str], &str, &str, &str)] = &[
    (
        "dlp_bitbucket_client_secret",
        &["bitbucket_client_secret"],
        "BITBUCKET_CLIENT_SECRET",
        "API_KEY",
        "secret_key",
    ),
    (
        "dlp_azure_devops_legacy_pat",
        &["azure_devops_legacy_pat"],
        "AZURE_DEVOPS_EXT_PAT",
        "SECRET_TOKEN",
        "access_token",
    ),
    (
        "dlp_circleci_legacy_token",
        &["circleci_legacy_token"],
        "CIRCLECI_API_TOKEN",
        "SECRET_TOKEN",
        "access_token",
    ),
    (
        "dlp_travis_token",
        &["travisci_access_token"],
        "TRAVIS_API_TOKEN",
        "SECRET_TOKEN",
        "access_token",
    ),
    (
        "dlp_vercel_legacy_token",
        &["vercel_legacy_token"],
        "VERCEL_TOKEN",
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_netlify_legacy_token",
        &["netlify_access_token"],
        "NETLIFY_AUTH_TOKEN",
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_heroku_legacy_api_key",
        &["heroku_api_key"],
        "HEROKU_API_KEY",
        "CLOUD_KEY",
        "api_key",
    ),
    (
        "dlp_railway_token",
        &["railway_token"],
        "RAILWAY_TOKEN",
        "CLOUD_KEY",
        "access_token",
    ),
    (
        "dlp_cloudflare_api_key",
        &["cloudflare_api_token", "cloudflare_global_api_key"],
        "CLOUDFLARE_API_TOKEN",
        "CLOUD_KEY",
        "api_key",
    ),
];

/// DE and EN carriers of a prefix token: .env, YAML, JSON, TOML, CLI, HTTP
/// header, log and prose. Each names Render, so the Render rule finds its
/// context in every one.
const CARRIERS: &[&str] = &[
    "# Zugang des Render- und Deploy-Jobs\nDEPLOY_TOKEN={}\n",
    "render_deploy:\n  token: \"{}\"\n",
    "{\"render\": {\"deploy\": {\"token\": \"{}\"}}}\n",
    "[render.deploy]\ntoken = \"{}\"\n",
    "$ deploy-cli --target render --token {} --prod\n",
    "GET /v1/services HTTP/1.1\nHost: api.render.com\nAuthorization: Bearer {}\n",
    "2026-10-28T08:12:44Z WARN render-sync: Token {} wurde abgelehnt\n",
    "Das Token für den Render-Deploy lautet {}, bitte im Tresor ablegen.\n",
    "Hi Sam, here is the token for the Render deploy job: {}\n",
];

/// DE and EN carriers of a key-anchored value; `KEY` is the provider key in
/// screaming snake case, `key` in snake case, `keyCamel` in camelCase.
const KEYED_CARRIERS: &[&str] = &[
    "# Zugang des Deploy-Jobs\nKEY={}\n",
    "export KEY='{}'\n",
    "env:\n  KEY: \"{}\"\n",
    "{\"key\": \"{}\"}\n",
    "{\\\"key\\\": \\\"{}\\\"}\n",
    "key = \"{}\"\n",
    "const keyCamel = \"{}\";\n",
    "os.environ[\"KEY\"] = \"{}\"\n",
    "2026-10-28T08:12:44Z DEBUG config loaded: key={} retries=3\n",
];

const HEX: &str = "0123456789abcdef";
const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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

fn reports(text: &str, group: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == group && span.text == value)
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
    for (rule_id, gens, group, subtype) in PREFIX_RULES {
        for gen in *gens {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &value);
                    assert!(reports(&text, group, &value), "{gen}/{seed}: {carrier:?}");
                    let rule = entry(&text, rule_id)
                        .unwrap_or_else(|| panic!("{gen}/{seed}: {carrier:?}"));
                    assert_eq!(rule["subtype"], *subtype, "{rule_id}");
                }
            }
        }
        // A sentence may end right after a token.
        let value = generated(gens[0], 7);
        let text = format!("Das Render-Token lautet {value}.");
        assert!(entry(&text, rule_id).is_some(), "{rule_id}");
    }
}

#[test]
fn generated_values_are_reported_under_their_provider_key() {
    for (rule_id, gens, key, group, subtype) in KEYED_RULES {
        for gen in *gens {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for carrier in KEYED_CARRIERS {
                    let text = keyed(carrier, key, &value);
                    assert!(reports(&text, group, &value), "{gen}/{seed}: {carrier:?}");
                    let rule = entry(&text, rule_id)
                        .unwrap_or_else(|| panic!("{gen}/{seed}: {carrier:?}"));
                    assert_eq!(rule["subtype"], *subtype, "{rule_id}");
                }
            }
        }
    }
    // Labels, headers and other spellings of the key.
    for (rule_id, gen, template) in [
        (
            "dlp_heroku_legacy_api_key",
            "heroku_api_key",
            "Heroku-API-Schlüssel: {}",
        ),
        (
            "dlp_circleci_legacy_token",
            "circleci_legacy_token",
            "Circle-Token: {}",
        ),
        (
            "dlp_azure_devops_legacy_pat",
            "azure_devops_legacy_pat",
            "azdo_personal_access_token = \"{}\"",
        ),
        (
            "dlp_azure_devops_legacy_pat",
            "azure_devops_legacy_pat",
            "VSTS_PAT={}",
        ),
        (
            "dlp_travis_token",
            "travisci_access_token",
            "Travis CI API token: {}",
        ),
        (
            "dlp_cloudflare_api_key",
            "cloudflare_global_api_key",
            "CLOUDFLARE_API_KEY={}",
        ),
        (
            "dlp_railway_token",
            "railway_token",
            "\"railwayApiToken\" => '{}',",
        ),
    ] {
        let text = template.replace("{}", &generated(gen, 3));
        assert!(entry(&text, rule_id).is_some(), "{rule_id}: {template:?}");
    }
}

#[test]
fn provider_keys_without_a_credential_noun_hold_no_secret() {
    let uuid = generated("heroku_api_key", 5);
    let hex = generated("circleci_legacy_token", 5);
    let alnum = random(5, ALNUM, 24);
    for (rule_id, text) in [
        ("dlp_heroku_legacy_api_key", format!("HEROKU_APP_ID={uuid}")),
        (
            "dlp_heroku_legacy_api_key",
            format!("heroku_dyno_id: {uuid}"),
        ),
        ("dlp_railway_token", format!("RAILWAY_PROJECT_ID={uuid}")),
        ("dlp_railway_token", format!("railway_service_id: {uuid}")),
        ("dlp_circleci_legacy_token", format!("CIRCLE_SHA1={hex}")),
        (
            "dlp_circleci_legacy_token",
            format!("circleci_workflow_id: {hex}"),
        ),
        (
            "dlp_vercel_legacy_token",
            format!("VERCEL_GIT_COMMIT={alnum}"),
        ),
        (
            "dlp_travis_token",
            format!("TRAVIS_BUILD_ID={}", &alnum[..22]),
        ),
        (
            "dlp_cloudflare_api_key",
            format!("CLOUDFLARE_ZONE_ID={}", random(5, HEX, 37)),
        ),
        // The key must end in its noun right before the separator.
        (
            "dlp_heroku_legacy_api_key",
            format!("HEROKU_API_KEY_ID={uuid}"),
        ),
        ("dlp_railway_token", format!("RAILWAY_TOKEN_FILE={uuid}")),
        // A value without a provider key.
        ("dlp_heroku_legacy_api_key", format!("API_KEY={uuid}")),
        ("dlp_travis_token", format!("TOKEN={}", &alnum[..22])),
    ] {
        assert!(entry(&text, rule_id).is_none(), "{rule_id}");
    }
}

#[test]
fn values_of_another_length_or_alphabet_are_no_token() {
    for seed in 0..8 {
        let uuid = generated("heroku_api_key", seed);
        let cases: Vec<(&str, String)> = vec![
            (
                "dlp_azure_devops_pat",
                format!("{}AZDO{}", random(seed, ALNUM, 75), random(seed, ALNUM, 5)),
            ),
            (
                "dlp_azure_devops_pat",
                format!("{}AZDO{}", random(seed, ALNUM, 76), random(seed, ALNUM, 5)),
            ),
            (
                "dlp_circleci_token",
                format!(
                    "CCIPAT_{}_{}",
                    random(seed, ALNUM, 22),
                    random(seed, HEX, 39)
                ),
            ),
            (
                "dlp_circleci_token",
                format!(
                    "CCIPAT_{}_{}",
                    random(seed, "0OIl", 22),
                    random(seed, HEX, 40)
                ),
            ),
            (
                "dlp_vercel_token",
                format!("vcp_{}", random(seed, ALNUM, 55)),
            ),
            (
                "dlp_vercel_token",
                format!("vcp_{}", random(seed, ALNUM, 57)),
            ),
            (
                "dlp_vercel_token",
                format!("vcx_{}", random(seed, ALNUM, 56)),
            ),
            (
                "dlp_netlify_token",
                format!("nfp_{}", random(seed, ALNUM, 35)),
            ),
            (
                "dlp_flyio_token",
                format!("fo1_{}", random(seed, ALNUM, 42)),
            ),
            (
                "dlp_flyio_macaroon_token",
                format!("fm2_{}", random(seed, ALNUM, 99)),
            ),
            (
                "dlp_heroku_api_key",
                format!("HRKU-AA{}", random(seed, ALNUM, 57)),
            ),
            (
                "dlp_heroku_api_key",
                format!("HRKU-AB{}", random(seed, ALNUM, 58)),
            ),
            (
                "dlp_render_api_key",
                format!("rnd_{}", random(seed, ALNUM, 23)),
            ),
            (
                "dlp_cloudflare_origin_ca_key",
                format!("v1.0-{}-{}", random(seed, HEX, 24), random(seed, HEX, 145)),
            ),
            (
                "dlp_digitalocean_token",
                format!("dop_v1_{}", random(seed, HEX, 63)),
            ),
            (
                "dlp_digitalocean_token",
                format!("dop_v2_{}", random(seed, HEX, 64)),
            ),
            (
                "dlp_azure_devops_legacy_pat",
                format!(
                    "AZURE_DEVOPS_EXT_PAT={}",
                    random(seed, "abcdefghijklmnopqrstuvwxyz234567", 51)
                ),
            ),
            (
                "dlp_travis_token",
                format!("TRAVIS_API_TOKEN={}", random(seed, ALNUM, 23)),
            ),
            (
                "dlp_bitbucket_client_secret",
                format!("BITBUCKET_CLIENT_SECRET={}", random(seed, ALNUM, 63)),
            ),
            (
                "dlp_heroku_legacy_api_key",
                format!("HEROKU_API_KEY={}", &uuid[..35]),
            ),
            (
                "dlp_cloudflare_api_key",
                format!("CLOUDFLARE_API_TOKEN={}", random(seed, ALNUM, 41)),
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
fn single_case_bodies_are_no_token() {
    for seed in 0..8 {
        for (rule_id, value) in [
            (
                "dlp_azure_devops_pat",
                format!(
                    "{}AZDO{}",
                    random(seed, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 76),
                    random(seed, "0123456789", 4)
                ),
            ),
            (
                "dlp_vercel_token",
                format!(
                    "vcp_{}",
                    random(seed, "abcdefghijklmnopqrstuvwxyz0123456789", 56)
                ),
            ),
            (
                "dlp_netlify_token",
                format!(
                    "nfp_{}",
                    random(seed, "abcdefghijklmnopqrstuvwxyz0123456789", 36)
                ),
            ),
            (
                "dlp_render_api_key",
                format!(
                    "rnd_{}",
                    random(seed, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 32)
                ),
            ),
        ] {
            let text = CARRIERS[0].replace("{}", &value);
            assert!(entry(&text, rule_id).is_none(), "{rule_id}");
        }
    }
}

#[test]
fn render_api_keys_need_render_context() {
    for seed in 0..8 {
        let value = generated("render_api_key", seed);
        for text in [
            format!("RENDER_API_KEY={value}\n"),
            format!("# Render deploy hook\n\n\n\n\nAPI_KEY={value}\n"),
            format!("Der Schlüssel {value} gehört zum Render-Konto.\n"),
        ] {
            assert!(entry(&text, "dlp_render_api_key").is_some(), "seed {seed}");
        }
        for text in [
            format!("API_KEY={value}\n"),
            format!("2026-10-28 INFO cache: evicted {value} after 300s\n"),
            // A Render term six lines above is out of reach.
            format!("# Render\n\n\n\n\n\nAPI_KEY={value}\n"),
        ] {
            assert!(entry(&text, "dlp_render_api_key").is_none(), "seed {seed}");
        }
    }
}

#[test]
fn every_rule_has_a_provider_a_format_source_and_its_anchor() {
    for (rule_id, _, group, _) in PREFIX_RULES {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == *rule_id)
            .unwrap_or_else(|| panic!("{rule_id} must be registered"));
        assert_eq!(rule.entity_group, *group, "{rule_id}");
        assert!(rule.meta.provider.is_some(), "{rule_id}");
        assert_ne!(rule.meta.source_ref, "ark", "{rule_id}");
        // Base64 macaroons hold `/` and `+`, so no token boundary applies.
        assert_eq!(
            rule.meta.boundary.is_some(),
            *rule_id != "dlp_flyio_macaroon_token",
            "{rule_id}"
        );
        assert!(rule.span_group.is_none(), "{rule_id}");
        assert_eq!(
            rule.meta.validator_strength,
            ValidatorStrength::Format,
            "{rule_id}"
        );
    }
    for (rule_id, _, _, group, _) in KEYED_RULES {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == *rule_id)
            .unwrap_or_else(|| panic!("{rule_id} must be registered"));
        assert_eq!(rule.entity_group, *group, "{rule_id}");
        assert!(rule.meta.provider.is_some(), "{rule_id}");
        assert_ne!(rule.meta.source_ref, "ark", "{rule_id}");
        assert!(rule.meta.boundary.is_none(), "{rule_id}");
        assert_eq!(rule.span_group, Some(1), "{rule_id}");
    }
}

#[test]
fn example_and_test_fills_are_silent() {
    for (gen, template) in [
        ("azure_devops_pat", "AZURE_DEVOPS_EXT_PAT=<<secret:0>>\n"),
        ("circleci_personal_token", "CIRCLECI_TOKEN=<<secret:0>>\n"),
        ("vercel_personal_token", "VERCEL_TOKEN=<<secret:0>>\n"),
        (
            "netlify_personal_token",
            "NETLIFY_AUTH_TOKEN=<<secret:0>>\n",
        ),
        ("heroku_api_key_v2", "HEROKU_API_KEY=<<secret:0>>\n"),
        ("render_api_key", "RENDER_API_KEY=<<secret:0>>\n"),
        (
            "digitalocean_pat",
            "DIGITALOCEAN_ACCESS_TOKEN=<<secret:0>>\n",
        ),
        ("travisci_access_token", "TRAVIS_API_TOKEN=<<secret:0>>\n"),
        ("netlify_access_token", "NETLIFY_AUTH_TOKEN=<<secret:0>>\n"),
        (
            "cloudflare_api_token",
            "CLOUDFLARE_API_TOKEN=<<secret:0>>\n",
        ),
        ("railway_token", "RAILWAY_TOKEN=<<secret:0>>\n"),
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
