// SPDX-License-Identifier: GPL-3.0-only
//! T01: token boundaries of the prefix rules. A provider token, wallet key or
//! JWT is a finding only as a whole token: the characters right before and
//! after the value are no `[A-Za-z0-9_]` and none of the provider alphabet, so
//! a prefix inside a CamelCase or snake_case identifier, a hex run (Cargo.lock
//! checksum, sha256 digest) or a base64 blob (go.sum, data URI) is no finding.
//! Escapes that end in a letter or digit (`\n`, `%3D`, `"`) still delimit
//! a token. Checksum validation stays with F02–F05; the vectors here only show
//! that a checksum-valid value is no finding when it is glued into a run.
//! Values come from the golden generator and are assembled at test time.

use std::{collections::BTreeMap, path::Path, sync::OnceLock};

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS,
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    EvidenceSpan, SecurityCategory, SecurityGateway, SecurityLevel,
};
use serde::Deserialize;

/// Rules with a fixed prefix or leading shape (provider tokens, wallet keys,
/// JWT) and the value characters beyond `[A-Za-z0-9_]` that also may not
/// border the value.
const BOUNDED: &[(&str, &str)] = &[
    ("dlp_anthropic_key", "-"),
    ("dlp_openai_key", "-"),
    ("dlp_openai_legacy", ""),
    ("dlp_openai_svc", "-"),
    ("dlp_huggingface", ""),
    ("dlp_groq_key", ""),
    ("dlp_xai_key", "-"),
    ("dlp_replicate", ""),
    ("dlp_aws_access_key", ""),
    ("dlp_google_api_key", "-"),
    ("dlp_google_oauth_token", "-"),
    ("dlp_gcp_client_secret", "-"),
    ("dlp_github_token", ""),
    ("dlp_github_pat", ""),
    ("dlp_gitlab_pat", "-"),
    ("dlp_npm_token", ""),
    ("dlp_stripe_key", "-"),
    ("dlp_stripe_webhook", "-"),
    ("dlp_slack_token", "-"),
    ("dlp_discord_token", "-"),
    ("dlp_eth_private_key", ""),
    ("dlp_btc_wif", ""),
    ("dlp_jwt_token", "-"),
];

#[derive(Deserialize)]
struct RuleMap {
    rules: BTreeMap<String, RuleEntry>,
}

#[derive(Deserialize)]
struct RuleEntry {
    generators: Vec<String>,
}

fn root() -> &'static Path {
    static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."))
}

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        GeneratorSet::load(root().join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

fn rule_generators(rule: &str) -> Vec<String> {
    static MAP: OnceLock<RuleMap> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        let raw = std::fs::read_to_string(root().join("python/patronus_ark/dlp_synth/rules.json"))
            .expect("rules.json must exist");
        serde_json::from_str(&raw).expect("valid rules.json")
    });
    map.rules[rule].generators.clone()
}

fn value(generator: &str, seed: u64) -> String {
    materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(generator, seed)],
    )
    .expect("recipe must materialize")
    .0
}

fn spans(text: &str) -> Vec<EvidenceSpan> {
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
        .evidence_spans
}

fn reports(text: &str, value: &str) -> bool {
    spans(text).iter().any(|span| span.text == value)
}

fn assert_silent(text: &str) {
    let found = spans(text);
    assert!(
        found.is_empty(),
        "expected no DLP finding in {text:?}, got {:?}",
        found
            .iter()
            .map(|span| (&span.label, &span.text))
            .collect::<Vec<_>>()
    );
}

/// Every (rule, generator value) pair of the bounded rules, two seeds each.
fn bounded_values() -> Vec<(&'static str, String)> {
    BOUNDED
        .iter()
        .flat_map(|(rule, _)| {
            rule_generators(rule)
                .into_iter()
                .flat_map(move |generator| {
                    (1..=2).map(move |seed| (*rule, value(&generator, 7100 + seed)))
                })
        })
        .collect()
}

/// A base64 run with upper case, lower case and digits, as in a go.sum hash
/// or a data URI.
const BLOB: &str = "Zm9yZWlnbjAxMjM0NTY3ODlRV0VSVFk";

#[test]
fn prefix_rules_declare_their_token_boundary() {
    for pattern in DLP_PATTERNS {
        let expected = BOUNDED
            .iter()
            .find(|(rule, _)| *rule == pattern.name)
            .map(|(_, alphabet)| *alphabet);
        assert_eq!(
            pattern.meta.boundary.map(|boundary| boundary.alphabet),
            expected,
            "{}",
            pattern.name
        );
    }
}

#[test]
fn generated_values_between_delimiters_stay_findings() {
    for (rule, value) in bounded_values() {
        for text in [
            value.clone(),
            format!("KEY={value}\n"),
            format!("token: \"{value}\""),
            format!("token: '{value}';"),
            format!("Der Schlüssel lautet {value}."),
            format!("Use `{value}` (rotated)."),
            format!("<td>{value}</td>"),
            format!("[{value}]"),
            format!("- {value}\n"),
            format!("path: /keys/{value}/rotate"),
            // Escapes that end in a letter or digit still delimit the token.
            format!("GET /cb?next=%2Fhook%3Fkey%3D{value}%26v%3D2"),
            format!("{{\"msg\":\"retrying with\\n{value}\\tok\"}}"),
            format!("{{\"msg\":\"key=\\u0022{value}\\u0022\"}}"),
        ] {
            // F01: a wallet key needs a key term; here on the line above.
            let text = if rule == "dlp_eth_private_key" {
                format!("wallet private key:\n{text}")
            } else {
                text
            };
            assert!(reports(&text, &value), "{rule}: {text:?}");
        }
    }
}

#[test]
fn values_glued_to_word_characters_on_the_left_are_no_findings() {
    for (rule, value) in bounded_values() {
        for text in [
            format!("let handler = Load{value};"),
            format!("call load_{value}(args)"),
            format!("checksum 9{value}"),
        ] {
            assert!(!reports(&text, &value), "{rule}: {text:?}");
            assert_silent(&text);
        }
    }
}

#[test]
fn values_glued_to_word_characters_on_the_right_are_no_findings() {
    // Where the rule's alphabet takes the glued character, the token is the
    // longer run; the generated value alone is never the finding.
    for (rule, value) in bounded_values() {
        for glue in ["_x", "0", "z", "Q"] {
            let text = format!("id = {value}{glue}");
            assert!(!reports(&text, &value), "{rule}: {text:?}");
        }
    }
}

#[test]
fn values_glued_to_their_provider_alphabet_are_no_findings() {
    for (rule, alphabet) in BOUNDED
        .iter()
        .filter(|(_, alphabet)| alphabet.contains('-'))
    {
        for generator in rule_generators(rule) {
            let value = value(&generator, 7105);
            let text = format!("release-{value}");
            assert!(!reports(&text, &value), "{rule} ({alphabet}): {text:?}");
        }
    }
}

#[test]
fn values_inside_base64_blobs_are_no_findings() {
    // Only a value of standard base64 characters can be part of a blob; a
    // value with `-` or `_` (`sk-ant-…`, `ghp_…`) stays a token beside one,
    // and a `/` without a `+` or `=` padding in the blob is a path delimiter.
    for (rule, value) in bounded_values() {
        let in_alphabet = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='));
        if !in_alphabet {
            let text = format!("data:application/octet-stream;base64,{BLOB}+{value}/{BLOB}==");
            assert!(reports(&text, &value), "{rule}: {text:?}");
            continue;
        }
        for text in [
            format!("data:application/octet-stream;base64,{BLOB}+{value}/{BLOB}=="),
            format!("data:application/octet-stream;base64,{BLOB}+{BLOB}/{value}"),
            format!("data:application/octet-stream;base64,{BLOB}/{value}=="),
            format!("h1:{BLOB}+{value}="),
        ] {
            assert!(!reports(&text, &value), "{rule}: {text:?}");
        }
    }
    // A short path segment before the slash is no blob, and neither is a long
    // one without `+` or `=` padding.
    let key = value("aws_access_key_id", 7107);
    assert!(reports(&format!("s3://backup/{key}/"), &key));
    assert!(reports(&format!("https://host/{BLOB}/{key}"), &key));
}

#[test]
fn lockfile_and_digest_lines_are_no_findings() {
    let hex = value("sha256_hex", 7111);
    let wif = value("btc_wif_mainnet_compressed", 7112);
    let eth = value("eth_private_key_hex", 7113);
    let akia = value("aws_access_key_id", 7114);
    for text in [
        // Cargo.lock checksum with a checksum-valid WIF and a 0x key glued in.
        format!(
            "[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}{wif}{}\"\n",
            &hex[..8],
            &hex[8..20]
        ),
        format!("checksum = \"{}{eth}\"\n", &hex[..6]),
        // sha256 digests in a Dockerfile and a compose file.
        format!("FROM python:3.12-slim@sha256:{}{wif}\n", &hex[..13]),
        format!("    image: ghcr.io/acme/api@sha256:{hex}{eth}\n"),
        // go.sum and npm integrity hashes (base64).
        format!("golang.org/x/text v0.14.0 h1:{BLOB}+{akia}Q=\n"),
        format!("\"integrity\": \"sha512-{BLOB}/{akia}{BLOB}==\"\n"),
        // CamelCase and snake_case identifiers.
        format!("const client = new Hf{};", value("huggingface_token", 7115)),
        format!("export function resolve_{}() {{}}", value("npm_access_token", 7116)),
        format!("type Cached{akia}Policy struct{{}}"),
    ] {
        assert_silent(&text);
    }
}

#[test]
fn checksum_vectors_decide_only_at_a_token_boundary() {
    // Valid checksum (Base58Check WIF, CRC32 GitHub/npm): a finding alone, no
    // finding inside a run. Invalid checksum: no finding either way.
    for generator in [
        "btc_wif_mainnet_uncompressed",
        "btc_wif_mainnet_compressed",
        "github_ghp_token",
        "npm_access_token",
    ] {
        for seed in 7120..7124 {
            let valid = value(generator, seed);
            assert!(reports(&format!("key: {valid}\n"), &valid), "{generator}");
            assert!(!reports(&format!("key: a{valid}\n"), &valid), "{generator}");
        }
    }
    for seed in 7130..7134 {
        let valid = value("btc_wif_mainnet_compressed", seed);
        let last = valid.chars().last().unwrap();
        let swapped = if last == 'z' { 'y' } else { 'z' };
        let invalid = format!("{}{swapped}", &valid[..valid.len() - 1]);
        assert!(!reports(&format!("key: {invalid}\n"), &invalid));
    }
}
