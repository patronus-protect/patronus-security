// SPDX-License-Identifier: GPL-3.0-only
//! Slack, Discord and Stripe formats (F-PROV). Shapes per source:
//! `dlp_slack_token` takes the gitleaks Slack bot (`xoxb-`, two numeric IDs,
//! secret), user (`xoxp-`/`xoxe-`, three numeric IDs, 28 to 34 characters),
//! legacy bot, legacy (`xoxo-`/`xoxs-`) and workspace (`xoxa-`/`xoxr-`)
//! tokens; `dlp_slack_app_token` the app-level (`xapp-`) and configuration
//! access and refresh tokens (`xoxe.xoxp-`, `xoxe-`). `dlp_discord_token`
//! decodes the first segment of a bot token to the bot's snowflake ID (17 to
//! 20 digits). `dlp_stripe_key` takes `sk_`/`rk_` with `live`/`test` and 20 to
//! 99 base62 characters (test keys with severity `test`); publishable keys
//! (`pk_`) are public. `dlp_stripe_webhook` takes `whsec_` and 32 base62
//! characters (Dashboard) or 64 hex digits (Stripe CLI). Values come from the
//! golden generator or are built here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::dlp::{ValidatorStrength, DLP_PATTERNS},
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

/// Rules, their generators and lookalike generators (wrong segment, length
/// or prefix).
const RULES: &[(&str, &[&str], &[&str])] = &[
    (
        "dlp_slack_token",
        &[
            "slack_bot_token",
            "slack_user_token",
            "slack_legacy_bot_token",
            "slack_workspace_token",
        ],
        &["slack_bot_token_no_ids", "slack_user_token_short"],
    ),
    (
        "dlp_slack_app_token",
        &[
            "slack_app_token",
            "slack_config_access_token",
            "slack_config_refresh_token",
        ],
        &["slack_config_refresh_token_short", "slack_app_token_lower_id"],
    ),
    (
        "dlp_discord_token",
        &["discord_bot_token"],
        &["discord_bot_token_non_snowflake"],
    ),
    (
        "dlp_stripe_key",
        &[
            "stripe_secret_live",
            "stripe_restricted_test",
            "stripe_secret_test_long",
        ],
        &[
            "stripe_secret_live_long",
            "stripe_restricted_dash",
            "stripe_publishable_live",
        ],
    ),
    (
        "dlp_stripe_webhook",
        &["stripe_webhook_secret", "stripe_webhook_secret_cli"],
        &["stripe_webhook_secret_short"],
    ),
];

/// DE and EN carriers: .env, YAML, JSON, code, CLI, log and prose.
const CARRIERS: &[&str] = &[
    "# Zugang für den Chat-Bot\nSERVICE_TOKEN={}\n",
    "integration:\n  token: \"{}\"\n",
    "{\"integration\": {\"token\": \"{}\"}}\n",
    "client = Client(token=\"{}\")\n",
    "$ bot-cli login --token {} --region eu\n",
    "2026-11-02T08:12:44Z WARN bot: Token {} wurde abgelehnt\n",
    "Das Token für die Integration lautet {}, bitte im Tresor ablegen.\n",
    "Hi Sam, here is the token for the integration: {}\n",
];

/// A carrier without a key name, where only the shape tells a value apart.
const NEUTRAL_CARRIER: &str = "2026-11-02T08:12:44Z WARN bot: rejected {} (wrong shape)\n";

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

/// The unsuppressed `matched_rules` entry of `rule_id` in `text`.
fn rule_entry(text: &str, rule_id: &str) -> Option<Value> {
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

fn rule_hit(text: &str, rule_id: &str) -> bool {
    rule_entry(text, rule_id).is_some()
}

/// Whether a span covers exactly `value`.
fn reports(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.text == value)
}

/// Unpadded base64url, as in the first two segments of a Discord bot token.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// A Discord bot token for the user ID `id`, with the timestamp and HMAC
/// segments of a generated token.
fn discord_token(id: &str) -> String {
    let template = generated("discord_bot_token", 3);
    let (_, rest) = template.split_once('.').unwrap();
    format!("{}.{rest}", base64url(id.as_bytes()))
}

#[test]
fn generated_values_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, gens, _) in RULES {
        for gen in *gens {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for (index, carrier) in CARRIERS.iter().enumerate() {
                    let text = carrier.replace("{}", &value);
                    assert!(rule_hit(&text, rule_id), "{gen}/{seed}: carrier {index}");
                    assert!(reports(&text, &value), "{gen}/{seed}: carrier {index}");
                }
            }
        }
    }
}

#[test]
fn lookalikes_with_wrong_segments_length_or_prefix_are_not_reported() {
    for (rule_id, _, lookalikes) in RULES {
        for gen in *lookalikes {
            for seed in 0..8 {
                let value = generated(gen, seed);
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &value);
                    assert!(!rule_hit(&text, rule_id), "{rule_id}: {gen}/{seed}: {text}");
                }
                let text = NEUTRAL_CARRIER.replace("{}", &value);
                assert!(
                    scan(&text).evidence_spans.is_empty(),
                    "{gen}/{seed}: {text}"
                );
            }
        }
    }
}

#[test]
fn discord_bot_tokens_need_a_snowflake_id_segment() {
    for id in [
        "80351110224678912",
        "175928847299117063",
        "1084488612345678912",
        "12345678901234567890",
    ] {
        let token = discord_token(id);
        let text = format!("DISCORD_TOKEN={token}\n");
        assert!(rule_hit(&text, "dlp_discord_token"), "{id}: {token}");
        assert!(reports(&text, &token), "{id}: {token}");
    }
    // A leading zero, too few or too many digits, a value above u64 and
    // letters are no snowflake.
    for id in [
        "075928847299117063",
        "1759288472991170",
        "123456789012345678901",
        "98446744073709551616",
        "17592884729911706a",
        "1759288472991170.3",
    ] {
        let token = discord_token(id);
        let text = format!("DISCORD_TOKEN={token}\n");
        assert!(!rule_hit(&text, "dlp_discord_token"), "{id}: {token}");
    }
}

#[test]
fn discord_snowflake_check_has_structure_strength() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == "dlp_discord_token")
        .unwrap();
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Structure);
    let token = generated("discord_bot_token", 1);
    let entry = rule_entry(&format!("DISCORD_TOKEN={token}\n"), "dlp_discord_token").unwrap();
    assert_eq!(entry["validator_strength"], "structure");
}

#[test]
fn stripe_test_keys_have_severity_test_and_live_keys_live() {
    for (gen, severity) in [
        ("stripe_secret_live", "live"),
        ("stripe_restricted_test", "test"),
        ("stripe_secret_test_long", "test"),
    ] {
        let value = generated(gen, 2);
        let entry = rule_entry(&format!("STRIPE_SECRET_KEY={value}\n"), "dlp_stripe_key")
            .unwrap_or_else(|| panic!("{gen} must match"));
        assert_eq!(entry["severity"], severity, "{gen}");
    }
    let body = &generated("stripe_secret_live", 4)[8..];
    let restricted_live = format!("rk_live_{body}");
    let entry = rule_entry(&format!("STRIPE_KEY={restricted_live}\n"), "dlp_stripe_key").unwrap();
    assert_eq!(entry["severity"], "live");
}

#[test]
fn stripe_publishable_keys_are_no_secret() {
    for seed in 0..6 {
        let body = &generated("stripe_secret_live", seed)[8..];
        for key in [format!("pk_live_{body}"), format!("pk_test_{body}")] {
            for text in [
                format!("STRIPE_PUBLISHABLE_KEY={key}\n"),
                format!("NEXT_PUBLIC_STRIPE_KEY={key}\n"),
                format!("const stripe = Stripe(\"{key}\");\n"),
                format!("stripe:\n  publishable_key: \"{key}\"\n"),
                format!("Der öffentliche Stripe-Schlüssel lautet {key}.\n"),
            ] {
                assert!(scan(&text).evidence_spans.is_empty(), "{text}");
            }
        }
    }
}

#[test]
fn stripe_keys_stop_at_the_gitleaks_length() {
    let body = generated("stripe_secret_test_long", 5)[8..].to_owned();
    for len in [20, 24, 99] {
        let key = format!("sk_live_{}", &body[..len]);
        let text = format!("STRIPE_SECRET_KEY={key}\n");
        assert!(rule_hit(&text, "dlp_stripe_key"), "{len}");
        assert!(reports(&text, &key), "{len}");
    }
    for len in [19, 100] {
        let key = format!("sk_live_{}{}", body, "Q7")[..8 + len].to_owned();
        let text = format!("Log: {key}\n");
        assert!(!rule_hit(&text, "dlp_stripe_key"), "{len}");
    }
}

#[test]
fn stripe_webhook_secrets_take_the_dashboard_and_cli_lengths() {
    let alnum = generated("stripe_secret_test_long", 6)[8..].to_owned();
    let hex = generated("stripe_webhook_secret_cli", 6)[6..].to_owned();
    for secret in [format!("whsec_{}", &alnum[..32]), format!("whsec_{hex}")] {
        let text = format!("STRIPE_WEBHOOK_SECRET={secret}\n");
        assert!(rule_hit(&text, "dlp_stripe_webhook"), "{secret}");
        assert!(reports(&text, &secret), "{secret}");
    }
    for secret in [
        format!("whsec_{}", &alnum[..31]),
        format!("whsec_{}", &alnum[..33]),
        format!("whsec_{}", &alnum[..48]),
        format!("whsec_{}", &hex[..63]),
    ] {
        let text = format!("Log: {secret}\n");
        assert!(!rule_hit(&text, "dlp_stripe_webhook"), "{secret}");
    }
}

#[test]
fn slack_tokens_follow_the_gitleaks_shapes() {
    let alnum = generated("stripe_secret_test_long", 7)[8..].to_owned();
    let hex = generated("stripe_webhook_secret_cli", 7)[6..].to_owned();
    let positives = [
        // Legacy (xoxo-/xoxs-): three numeric IDs and a hex secret.
        format!("xoxs-4161823004-4161823010-4161823022-{}", &hex[..64]),
        // Workspace access token without a version.
        format!("xoxa-{}", &alnum[..36]),
        // User token with a 34-character secret.
        format!(
            "xoxp-416182300412-416182301012-4161823022123-{}",
            &alnum[..34]
        ),
    ];
    for token in &positives {
        let text = format!("SLACK_TOKEN={token}\n");
        assert!(rule_hit(&text, "dlp_slack_token"), "{token}");
        assert!(reports(&text, token), "{token}");
    }
    let negatives = [
        // Bot token with one numeric ID and a 12-character secret.
        format!("xoxb-4161823004-{}", &alnum[..12]),
        // Workspace token with 7 characters.
        format!("xoxr-{}", &alnum[..7]),
        // Retired or undocumented letters.
        format!("xoxz-{}", &alnum[..36]),
    ];
    for token in &negatives {
        let text = format!("Log: {token}\n");
        assert!(!rule_hit(&text, "dlp_slack_token"), "{token}");
    }
}
