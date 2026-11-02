// SPDX-License-Identifier: GPL-3.0-only
//! LLM and Google provider formats (F-LLM). Shapes per source:
//! `dlp_anthropic_key` (`sk-ant-api03-`/`sk-ant-admin01-`, 93 base64url
//! characters and `AA`), `dlp_openai_key` (`sk-proj-`/`sk-admin-`) and
//! `dlp_openai_svc` (`sk-svcacct-`): two halves of 74 or 58 base64url
//! characters around `T3BlbkFJ`; `dlp_openai_legacy` (`sk-`, 20 base62,
//! `T3BlbkFJ`, 20 base62); `dlp_huggingface` (`hf_`/`api_org_` and 34
//! letters), `dlp_groq_key` (`gsk_` and 52 base62), `dlp_replicate` (`r8_` and
//! 37 base62), `dlp_google_api_key` (`AIza` and 35), `dlp_google_oauth_token`
//! (`ya29.`, 30 base64url characters up to 2048 bytes in all) and
//! `dlp_gcp_client_secret` (`GOCSPX-` and 28). OpenAI and Anthropic keys share
//! one validator: their random parts hold upper- and lower-case letters.
//! Values come from the golden generator or are built here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Rules, their generators and lookalike generators (wrong length, marker or
/// alphabet).
const RULES: &[(&str, &[&str], &[&str])] = &[
    (
        "dlp_anthropic_key",
        &["anthropic_api_key", "anthropic_admin_key"],
        &["anthropic_api_key_short", "anthropic_admin_key_long"],
    ),
    (
        "dlp_openai_key",
        &["openai_project_api_key", "openai_admin_key"],
        &["openai_project_key"],
    ),
    (
        "dlp_openai_svc",
        &["openai_service_account_key"],
        &["openai_service_account_key_short"],
    ),
    (
        "dlp_openai_legacy",
        &["openai_legacy_key"],
        &["openai_legacy_key_no_marker"],
    ),
    (
        "dlp_huggingface",
        &["huggingface_token", "huggingface_org_token"],
        &["huggingface_token_digit"],
    ),
    ("dlp_groq_key", &["groq_key"], &["groq_key_short"]),
    (
        "dlp_replicate",
        &["replicate_api_token"],
        &["replicate_api_token_long"],
    ),
    (
        "dlp_google_api_key",
        &["google_api_key"],
        &["google_api_key_long"],
    ),
    (
        "dlp_google_oauth_token",
        &["google_oauth_access_token"],
        &["google_oauth_access_token_short"],
    ),
    (
        "dlp_gcp_client_secret",
        &["gcp_oauth_client_secret"],
        &["gcp_oauth_client_secret_long"],
    ),
];

/// DE and EN carriers: .env, YAML, JSON, code, CLI, log and prose.
const CARRIERS: &[&str] = &[
    "# Zugang für den Modell-Gateway\nPROVIDER_API_KEY={}\n",
    "provider:\n  api_key: \"{}\"\n",
    "{\"provider\": {\"apiKey\": \"{}\"}}\n",
    "client = Client(api_key=\"{}\")\n",
    "$ gateway-cli login --token {} --region eu\n",
    "2026-11-02T08:12:44Z WARN gateway: Schlüssel {} wurde abgelehnt\n",
    "Der Schlüssel für das Modell-Gateway lautet {}, bitte im Tresor ablegen.\n",
    "Hi Sam, here is the key for the model gateway: {}\n",
];

/// A carrier without a key name, where only the shape tells a value apart.
const NEUTRAL_CARRIER: &str = "2026-11-02T08:12:44Z WARN gateway: rejected {} (wrong shape)\n";

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
fn lookalikes_with_wrong_length_marker_or_alphabet_are_not_reported() {
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
fn openai_keys_take_both_documented_half_lengths() {
    // gitleaks openai-api-key: each half has 74 or 58 characters.
    let key = generated("openai_project_api_key", 1);
    let (head, tail) = (&key[8..82], &key[90..164]);
    for (head_len, tail_len) in [(74, 74), (58, 74), (74, 58), (58, 58)] {
        for prefix in ["sk-proj-", "sk-admin-"] {
            let value = format!("{prefix}{}T3BlbkFJ{}", &head[..head_len], &tail[..tail_len]);
            let text = format!("OPENAI_API_KEY={value}\n");
            assert!(rule_hit(&text, "dlp_openai_key"), "{head_len}/{tail_len}");
            assert!(reports(&text, &value), "{head_len}/{tail_len}");
        }
    }
    // 66 characters per half is neither length.
    let value = format!("sk-proj-{}T3BlbkFJ{}", &head[..66], &tail[..66]);
    assert!(!rule_hit(&format!("key {value}\n"), "dlp_openai_key"));
}

#[test]
fn shared_llm_validator_rejects_single_case_fills() {
    // A typed fill in the exact shape: no random part with both cases.
    let fills = [
        (
            "dlp_anthropic_key",
            format!("sk-ant-api03-{}AA", "x".repeat(93)),
        ),
        (
            "dlp_anthropic_key",
            format!("sk-ant-admin01-{}AA", "Y".repeat(93)),
        ),
        (
            "dlp_openai_key",
            format!("sk-proj-{}T3BlbkFJ{}", "a".repeat(74), "b".repeat(74)),
        ),
        (
            "dlp_openai_svc",
            format!("sk-svcacct-{}T3BlbkFJ{}", "a1".repeat(37), "C2".repeat(37)),
        ),
        (
            "dlp_openai_legacy",
            format!("sk-{}T3BlbkFJ{}", "abc12".repeat(4), "ABC12".repeat(4)),
        ),
    ];
    for (rule_id, value) in &fills {
        let text = format!("Wert im Ticket: {value}\n");
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {value}");
    }
    // One random half is not enough: both random parts must look random.
    let random = generated("openai_legacy_key", 4);
    let text = format!("key {}{}\n", &random[..31], "abcde".repeat(4));
    assert!(!rule_hit(&text, "dlp_openai_legacy"), "{text}");
}

#[test]
fn google_access_tokens_stop_at_the_documented_size() {
    // Google OAuth 2.0: access tokens take up to 2048 bytes.
    let body = generated("google_oauth_access_token", 3)[5..].to_owned();
    let longest = format!("ya29.{}", body.repeat(14)[..2043].to_owned());
    let text = format!("Authorization: Bearer {longest}\n");
    assert!(rule_hit(&text, "dlp_google_oauth_token"));
    assert!(reports(&text, &longest));
    let too_long = format!("ya29.{}", body.repeat(14)[..2044].to_owned());
    let text = format!("Log: {too_long}\n");
    assert!(!rule_hit(&text, "dlp_google_oauth_token"));
}
