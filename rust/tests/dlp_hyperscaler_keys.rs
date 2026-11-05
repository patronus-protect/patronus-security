// SPDX-License-Identifier: GPL-3.0-only
//! Hyperscaler credentials (P03). Shapes per source:
//! `dlp_azure_storage_account_key` (base64 of 64 bytes after `AccountKey=`,
//! detect-secrets AzureStorageKeyDetector), `dlp_azure_entra_client_secret`
//! (3 characters, a digit, `Q~` and 31 to 34 characters, gitleaks
//! azure-ad-client-secret), `dlp_alibaba_access_key_id` (`LTAI` and 20
//! alphanumerics, gitleaks alibaba-access-key-id), `dlp_alibaba_secret_key`
//! (30 alphanumerics under an Alibaba key, gitleaks alibaba-secret-key),
//! `dlp_aws_bedrock_api_key` (`ABSK` and base64 of `BedrockAPIKey-…`, gitleaks
//! aws-amazon-bedrock-api-key-long-lived) and `dlp_ibm_cloud_api_key` (44
//! characters `[A-Za-z0-9_-]` under an IBM key, detect-secrets
//! IbmCloudIamDetector). Values come from the golden generator or are built
//! here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Rules, the key name their carriers use, generators and lookalike
/// generators (wrong length).
const RULES: &[(&str, &str, &str, Option<&str>)] = &[
    (
        "dlp_azure_storage_account_key",
        "AZURE_STORAGE_CONNECTION_STRING",
        "azure_storage_account_key",
        Some("azure_storage_account_key_short"),
    ),
    (
        "dlp_azure_entra_client_secret",
        "AZURE_CLIENT_SECRET",
        "azure_entra_client_secret",
        Some("azure_entra_client_secret_short"),
    ),
    (
        "dlp_alibaba_access_key_id",
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "alibaba_access_key_id",
        Some("alibaba_access_key_id_short"),
    ),
    (
        "dlp_alibaba_secret_key",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "alibaba_secret_key",
        None,
    ),
    (
        "dlp_aws_bedrock_api_key",
        "AWS_BEARER_TOKEN_BEDROCK",
        "bedrock_api_key",
        Some("bedrock_api_key_short"),
    ),
    (
        "dlp_ibm_cloud_api_key",
        "IBM_CLOUD_API_KEY",
        "ibm_cloud_iam_api_key",
        Some("ibm_cloud_iam_api_key_short"),
    ),
];

/// DE and EN carriers with the provider's key name `{key}`: .env, YAML, JSON,
/// code, CLI, log and prose.
const CARRIERS: &[&str] = &[
    "# Zugang für die Cloud-Pipeline\n{key}={}\n",
    "cloud:\n  {key}: \"{}\"\n",
    "{\"cloud\": {\"{key}\": \"{}\"}}\n",
    "{key} = \"{}\"\nclient = Client(credential={key})\n",
    "$ export {key}={}\n",
    "2026-11-05T08:12:44Z DEBUG deploy: {key}={} geladen\n",
    "Hi Sam, here is the {key}: {}\n",
];

/// A carrier without a key name, where only the shape tells a value apart.
const NEUTRAL_CARRIER: &str = "2026-11-05T08:12:44Z WARN deploy: rejected {} (wrong shape)\n";

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

/// A storage account key stands in a connection string.
fn connection_string(key: &str) -> String {
    format!(
        "DefaultEndpointsProtocol=https;AccountName=stacmedata01;AccountKey={key};EndpointSuffix=core.windows.net"
    )
}

fn carrier(template: &str, rule_id: &str, key: &str, value: &str) -> String {
    let value = if rule_id == "dlp_azure_storage_account_key" {
        connection_string(value)
    } else {
        value.to_string()
    };
    template.replace("{key}", key).replace("{}", &value)
}

#[test]
fn generated_values_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, key, gen, _) in RULES {
        for seed in 0..6 {
            let value = generated(gen, seed);
            for (index, template) in CARRIERS.iter().enumerate() {
                let text = carrier(template, rule_id, key, &value);
                assert!(rule_hit(&text, rule_id), "{gen}/{seed}: carrier {index}");
                assert!(reports(&text, &value), "{gen}/{seed}: carrier {index}");
            }
        }
    }
}

#[test]
fn lookalikes_with_a_wrong_length_are_not_reported() {
    for (rule_id, key, _, gen) in RULES {
        let Some(gen) = gen else { continue };
        for seed in 0..8 {
            let value = generated(gen, seed);
            for template in CARRIERS {
                let text = carrier(template, rule_id, key, &value);
                assert!(!rule_hit(&text, rule_id), "{rule_id}: {gen}/{seed}: {text}");
            }
            let text = NEUTRAL_CARRIER.replace("{}", &value);
            assert!(!rule_hit(&text, rule_id), "{gen}/{seed}: {text}");
        }
    }
}

#[test]
fn structured_values_need_no_key_name() {
    for (rule_id, gen) in [
        ("dlp_azure_entra_client_secret", "azure_entra_client_secret"),
        ("dlp_alibaba_access_key_id", "alibaba_access_key_id"),
        ("dlp_aws_bedrock_api_key", "bedrock_api_key"),
    ] {
        let value = generated(gen, 2);
        let text = NEUTRAL_CARRIER.replace("{}", &value);
        assert!(rule_hit(&text, rule_id), "{gen}: {text}");
        assert!(reports(&text, &value), "{gen}: {text}");
    }
    let value = generated("azure_storage_account_key", 2);
    let text = NEUTRAL_CARRIER.replace("{}", &connection_string(&value));
    assert!(reports(&text, &value), "{text}");
}

#[test]
fn context_keys_need_their_provider_name() {
    // The Alibaba secret and the IBM Cloud API key have no own marker.
    for (rule_id, gen, other) in [
        (
            "dlp_alibaba_secret_key",
            "alibaba_secret_key",
            "SERVICE_SECRET",
        ),
        (
            "dlp_ibm_cloud_api_key",
            "ibm_cloud_iam_api_key",
            "SERVICE_API_KEY",
        ),
    ] {
        let value = generated(gen, 3);
        let text = format!("{other}={value}\n");
        assert!(!rule_hit(&text, rule_id), "{text}");
        let text = NEUTRAL_CARRIER.replace("{}", &value);
        assert!(!rule_hit(&text, rule_id), "{text}");
    }
}

#[test]
fn storage_account_keys_decode_to_64_bytes() {
    // 88 base64 characters that are no canonical encoding of 64 bytes: the
    // last character before the padding carries bits beyond the 64th byte.
    let value = generated("azure_storage_account_key", 4);
    let mut broken = value[..85].to_string();
    broken.push_str("B==");
    assert_ne!(broken, value);
    let text = format!("AccountKey={broken};\n");
    assert!(!rule_hit(&text, "dlp_azure_storage_account_key"), "{text}");
    // The account name alone is no key.
    let text = "DefaultEndpointsProtocol=https;AccountName=stacmedata01;AccountKey=;\n";
    assert!(!rule_hit(text, "dlp_azure_storage_account_key"), "{text}");
}

#[test]
fn bedrock_keys_need_the_bedrock_payload() {
    // ABSK and base64 of another payload is no Bedrock API key.
    let value = generated("bedrock_api_key", 5);
    let body = &value[4..];
    let other: String = body
        .chars()
        .map(|c| match c {
            'A'..='Y' => ((c as u8) + 1) as char,
            other => other,
        })
        .collect();
    let text = format!("AWS_BEARER_TOKEN_BEDROCK=ABSK{other}\n");
    assert!(!rule_hit(&text, "dlp_aws_bedrock_api_key"), "{text}");
}

#[test]
fn single_case_fills_are_not_reported() {
    let fills = [
        (
            "dlp_azure_entra_client_secret",
            "AZURE_CLIENT_SECRET",
            format!("abc1Q~{}", "abcdefgh".repeat(4)),
        ),
        (
            "dlp_alibaba_access_key_id",
            "ALIBABA_CLOUD_ACCESS_KEY_ID",
            format!("LTAI{}", "ABCD".repeat(5)),
        ),
        (
            "dlp_alibaba_secret_key",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
            "abcde12345".repeat(3),
        ),
        (
            "dlp_ibm_cloud_api_key",
            "IBM_CLOUD_API_KEY",
            "abcd_1234_".repeat(4) + "abcd",
        ),
    ];
    for (rule_id, key, value) in &fills {
        let text = format!("{key}={value}\n");
        assert!(!rule_hit(&text, rule_id), "{rule_id}: {value}");
    }
}
