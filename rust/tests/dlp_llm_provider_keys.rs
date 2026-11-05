// SPDX-License-Identifier: GPL-3.0-only
//! LLM provider keys (P01). Shapes per source: `dlp_perplexity_key` (`pplx-`
//! and 48 base62, gitleaks perplexity-api-key), `dlp_cohere_key` (40 base62
//! under a `cohere` or `CO_API_KEY` key, gitleaks cohere-api-token),
//! `dlp_openrouter_key` (`sk-or-v1-` and 64 lower-case hex digits),
//! `dlp_deepseek_key` (`sk-` and 32 lower-case alphanumerics under a DeepSeek
//! key) and `dlp_fireworks_key` (`fw_` and 20 to 40 base62), the last three
//! per TruffleHog. Gemini/AI Studio keys are Google API keys
//! (`dlp_google_api_key`). P02 adds, per TruffleHog, `dlp_langsmith_key`
//! (`lsv2_pt_`/`lsv2_sk_`, 32 and 10 lower-case hex digits), `dlp_pinecone_key`
//! (`pcsk_`, a 5 or 6 character base62 key ID, `_` and 63 base62) and
//! `dlp_elevenlabs_key` (`sk_` and 48 lower-case hex digits), and the context
//! rules `dlp_azure_openai_key` and `dlp_assemblyai_key` (32 lower-case hex
//! digits), `dlp_wandb_key` and `dlp_deepgram_key` (40 lower-case hex digits)
//! under the provider's key, client call or CLI login. Values come from the
//! golden generator or are built here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Rules, the key name their carriers use, generators and lookalike
/// generators (wrong length).
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "dlp_perplexity_key",
        "PERPLEXITY_API_KEY",
        "perplexity_api_key",
        "perplexity_api_key_short",
    ),
    (
        "dlp_cohere_key",
        "COHERE_API_KEY",
        "cohere_api_key",
        "cohere_api_key_short",
    ),
    (
        "dlp_openrouter_key",
        "OPENROUTER_API_KEY",
        "openrouter_api_key",
        "openrouter_api_key_short",
    ),
    (
        "dlp_deepseek_key",
        "DEEPSEEK_API_KEY",
        "deepseek_api_key",
        "deepseek_api_key_short",
    ),
    (
        "dlp_fireworks_key",
        "FIREWORKS_API_KEY",
        "fireworks_api_key",
        "fireworks_api_key_short",
    ),
    (
        "dlp_langsmith_key",
        "LANGSMITH_API_KEY",
        "langsmith_personal_token",
        "langsmith_api_key_short",
    ),
    (
        "dlp_langsmith_key",
        "LANGCHAIN_API_KEY",
        "langsmith_service_key",
        "langsmith_api_key_short",
    ),
    (
        "dlp_pinecone_key",
        "PINECONE_API_KEY",
        "pinecone_api_key",
        "pinecone_api_key_short",
    ),
    (
        "dlp_elevenlabs_key",
        "ELEVENLABS_API_KEY",
        "elevenlabs_api_key",
        "elevenlabs_api_key_short",
    ),
    (
        "dlp_azure_openai_key",
        "AZURE_OPENAI_API_KEY",
        "azure_openai_api_key",
        "azure_openai_api_key_short",
    ),
    (
        "dlp_wandb_key",
        "WANDB_API_KEY",
        "wandb_api_key",
        "wandb_api_key_short",
    ),
    (
        "dlp_assemblyai_key",
        "ASSEMBLYAI_API_KEY",
        "assemblyai_api_key",
        "assemblyai_api_key_short",
    ),
    (
        "dlp_deepgram_key",
        "DEEPGRAM_API_KEY",
        "deepgram_api_key",
        "deepgram_api_key_short",
    ),
    (
        "dlp_google_api_key",
        "GEMINI_API_KEY",
        "google_api_key",
        "google_api_key_long",
    ),
];

/// DE and EN carriers with the provider's key name `{key}`: .env, YAML, JSON,
/// code, CLI, log and prose.
const CARRIERS: &[&str] = &[
    "# Zugang für den Modell-Gateway\n{key}={}\n",
    "llm:\n  {key}: \"{}\"\n",
    "{\"llm\": {\"{key}\": \"{}\"}}\n",
    "{key} = \"{}\"\nclient = Client(api_key={key})\n",
    "$ export {key}={}\n",
    "2026-11-03T08:12:44Z DEBUG gateway: {key}={} geladen\n",
    "Hi Sam, here is the {key}: {}\n",
];

/// A carrier without a key name, where only the shape tells a value apart.
const NEUTRAL_CARRIER: &str = "2026-11-03T08:12:44Z WARN gateway: rejected {} (wrong shape)\n";

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
fn lookalikes_with_a_wrong_length_are_not_reported() {
    for (rule_id, key, _, gen) in RULES {
        for seed in 0..8 {
            let value = generated(gen, seed);
            for template in CARRIERS {
                let text = carrier(template, key, &value);
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

#[test]
fn prefixed_keys_need_no_key_name() {
    for gen in [
        "perplexity_api_key",
        "openrouter_api_key",
        "fireworks_api_key",
        "langsmith_personal_token",
        "langsmith_service_key",
        "pinecone_api_key",
        "elevenlabs_api_key",
    ] {
        let value = generated(gen, 2);
        let text = NEUTRAL_CARRIER.replace("{}", &value);
        assert!(reports(&text, &value), "{gen}: {text}");
    }
}

#[test]
fn context_keys_need_their_provider_name() {
    // Cohere's 40 alphanumerics, DeepSeek's sk- + 32 and the hex keys of
    // Azure OpenAI, W&B, AssemblyAI and Deepgram have no own marker.
    for (rule_id, gen, other) in [
        ("dlp_cohere_key", "cohere_api_key", "MODEL_API_KEY"),
        ("dlp_deepseek_key", "deepseek_api_key", "PROVIDER_API_KEY"),
        (
            "dlp_azure_openai_key",
            "azure_openai_api_key",
            "OPENAI_API_KEY",
        ),
        (
            "dlp_azure_openai_key",
            "azure_openai_api_key",
            "AZURE_DEVOPS_KEY",
        ),
        ("dlp_wandb_key", "wandb_api_key", "TRACKING_API_KEY"),
        ("dlp_assemblyai_key", "assemblyai_api_key", "SPEECH_API_KEY"),
        ("dlp_deepgram_key", "deepgram_api_key", "STT_API_KEY"),
    ] {
        let value = generated(gen, 3);
        let text = format!("{other}={value}\n");
        assert!(!rule_hit(&text, rule_id), "{text}");
        let text = NEUTRAL_CARRIER.replace("{}", &value);
        assert!(!rule_hit(&text, rule_id), "{text}");
    }
    // CO_API_KEY is Cohere's own variable (gitleaks cohere-api-token).
    let value = generated("cohere_api_key", 4);
    let text = format!("CO_API_KEY={value}\n");
    assert!(rule_hit(&text, "dlp_cohere_key"), "{text}");
}

#[test]
fn single_case_fills_are_not_reported() {
    let fills = [
        (
            "dlp_perplexity_key",
            "PERPLEXITY_API_KEY",
            format!("pplx-{}", "abc123".repeat(8)),
        ),
        ("dlp_cohere_key", "COHERE_API_KEY", "ABCD1234".repeat(5)),
        (
            "dlp_fireworks_key",
            "FIREWORKS_API_KEY",
            format!("fw_{}", "allowoutboundhttps".repeat(2)),
        ),
        (
            "dlp_pinecone_key",
            "PINECONE_API_KEY",
            format!("pcsk_docs1_{}", "abc123def".repeat(7)),
        ),
    ];
    for (rule_id, key, value) in &fills {
        let text = format!("{key}={value}\n");
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {value}");
    }
}

#[test]
fn fireworks_keys_take_20_to_40_characters() {
    // TruffleHog fireworks: fw_ and 20 to 40 alphanumerics.
    let body = format!(
        "{}{}",
        &generated("fireworks_api_key", 5)[3..],
        &generated("fireworks_api_key", 6)[3..]
    );
    for len in [20, 24, 40] {
        let value = format!("fw_{}", &body[..len]);
        let text = format!("FIREWORKS_API_KEY={value}\n");
        assert!(reports(&text, &value), "{len}: {text}");
    }
    let value = format!("fw_{}", &body[..41]);
    let text = format!("FIREWORKS_API_KEY={value}\n");
    assert!(!rule_hit(&text, "dlp_fireworks_key"), "{text}");
}

#[test]
fn langsmith_keys_need_a_known_kind_and_both_hex_parts() {
    // TruffleHog langsmith: lsv2_ and pt (personal) or sk (service).
    let value = generated("langsmith_personal_token", 4);
    for (kind, ok) in [("pt", true), ("sk", true), ("xx", false), ("PT", false)] {
        let candidate = format!("lsv2_{kind}_{}", &value[8..]);
        let text = format!("LANGSMITH_API_KEY={candidate}\n");
        assert_eq!(rule_hit(&text, "dlp_langsmith_key"), ok, "{text}");
    }
    let upper = value
        .to_ascii_uppercase()
        .replacen("LSV2_PT_", "lsv2_pt_", 1);
    let text = format!("LANGSMITH_API_KEY={upper}\n");
    assert!(!rule_hit(&text, "dlp_langsmith_key"), "{text}");
    let text = format!("LANGSMITH_API_KEY={value}0\n");
    assert!(!rule_hit(&text, "dlp_langsmith_key"), "{text}");
}

#[test]
fn pinecone_and_elevenlabs_keys_stand_as_whole_tokens() {
    let value = generated("pinecone_api_key", 5);
    let text = format!("PINECONE_API_KEY={value}X\n");
    assert!(!rule_hit(&text, "dlp_pinecone_key"), "{text}");
    let text = format!("PINECONE_API_KEY=x{value}\n");
    assert!(!rule_hit(&text, "dlp_pinecone_key"), "{text}");
    let value = generated("elevenlabs_api_key", 5);
    let text = format!("ELEVENLABS_API_KEY={value}a\n");
    assert!(!rule_hit(&text, "dlp_elevenlabs_key"), "{text}");
    // Stripe-style sk_live_ / sk_test_ keys are not ElevenLabs keys.
    let text = format!("STRIPE_KEY=sk_live_{}\n", &value[3..]);
    assert!(!rule_hit(&text, "dlp_elevenlabs_key"), "{text}");
}

#[test]
fn pinecone_key_ids_take_5_or_6_characters() {
    // TruffleHog pinecone: pcsk_, a 5 or 6 character key ID, _ and 63.
    let secret = &generated("pinecone_api_key", 6)[11..];
    for (id, ok) in [
        ("aB3dE", true),
        ("aB3dE9", true),
        ("aB3d", false),
        ("aB3dE9x", false),
    ] {
        let value = format!("pcsk_{id}_{secret}");
        for text in [
            format!("PINECONE_API_KEY={value}\n"),
            format!("Pinecone-API-Schlüssel: {value}\n"),
        ] {
            // Generic rules may still report the other lengths under a key.
            assert_eq!(rule_hit(&text, "dlp_pinecone_key"), ok, "key ID {id}");
            assert!(!ok || reports(&text, &value), "key ID {id}");
        }
    }
}

#[test]
fn hex_context_keys_are_read_from_client_calls_and_cli_logins() {
    // TruffleHog Deepgram, WeightsAndBiases, AssemblyAI and AzureOpenAI find
    // these keys by the provider name on the line, not by a key name.
    let deepgram = generated("deepgram_api_key", 7);
    let wandb = generated("wandb_api_key", 7);
    let assemblyai = generated("assemblyai_api_key", 7);
    let azure = generated("azure_openai_api_key", 7);
    for (rule_id, value, text) in [
        (
            "dlp_deepgram_key",
            &deepgram,
            format!("dg = DeepgramClient(\"{deepgram}\")\n"),
        ),
        (
            "dlp_deepgram_key",
            &deepgram,
            format!("deepgram = DeepgramClient(api_key='{deepgram}')\n"),
        ),
        ("dlp_wandb_key", &wandb, format!("$ wandb login {wandb}\n")),
        (
            "dlp_wandb_key",
            &wandb,
            format!("# W&B anmelden\nwandb login --relogin {wandb}\n"),
        ),
        (
            "dlp_wandb_key",
            &wandb,
            format!("wandb.login(key=\"{wandb}\")\n"),
        ),
        (
            "dlp_assemblyai_key",
            &assemblyai,
            format!("import assemblyai as aai\naai.settings.api_key = \"{assemblyai}\"\n"),
        ),
        (
            "dlp_azure_openai_key",
            &azure,
            format!("client = AzureOpenAI(api_key=\"{azure}\", api_version=\"2024-02-01\")\n"),
        ),
        (
            "dlp_azure_openai_key",
            &azure,
            format!("Hallo Kim, hier der Azure-OpenAI-Schlüssel: {azure}\n"),
        ),
    ] {
        assert!(rule_hit(&text, rule_id), "{rule_id}: {text}");
        assert!(reports(&text, value), "{rule_id}: {text}");
    }
}

#[test]
fn hex_context_keys_skip_ids_and_other_shapes() {
    let wandb = generated("wandb_api_key", 8);
    let deepgram = generated("deepgram_api_key", 8);
    for (rule_id, text) in [
        // Run and project IDs under the provider name name no credential.
        ("dlp_wandb_key", format!("WANDB_RUN_ID={wandb}\n")),
        (
            "dlp_deepgram_key",
            format!("DEEPGRAM_PROJECT_ID={deepgram}\n"),
        ),
        // A commit SHA after the login command is not hex of the key length.
        ("dlp_wandb_key", format!("wandb login {}\n", &wandb[..39])),
        // Upper-case hex is no key of these providers.
        (
            "dlp_deepgram_key",
            format!("DeepgramClient(\"{}\")\n", deepgram.to_ascii_uppercase()),
        ),
        // The value continues past the key length.
        (
            "dlp_deepgram_key",
            format!("DEEPGRAM_API_KEY={deepgram}a\n"),
        ),
    ] {
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {text}");
    }
}
