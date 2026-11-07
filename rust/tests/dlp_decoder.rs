// SPDX-License-Identifier: GPL-3.0-only
//! D01: decoder pipeline. A provider token that only appears base64- or
//! base64url-encoded (up to two layers) is reported on its encoded range,
//! with `decoded` naming the encodings undone; environment references,
//! placeholders, prose, example values and binary data stay silent after
//! decoding. Values are synthetic.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use patronus_ark::{
    golden_recipes::GeneratorSet, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
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

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec loads")
    })
}

fn generate(name: &str, seed: u64) -> String {
    generators().generate(name, seed).unwrap()
}

/// Padded standard base64 (RFC 4648 section 4).
fn base64(raw: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in raw.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(
                    ALPHABET[((bits >> (18 - 6 * index)) & 63) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Unpadded base64url (RFC 4648 section 5).
fn base64url(raw: &[u8]) -> String {
    base64(raw)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// `template` with `encoded` at `{v}` yields exactly one span, `encoded`
/// itself, by `rule_id` with `decoded` = `encodings`.
fn assert_decoded(template: &str, encoded: &str, rule_id: &str, encodings: &[&str]) {
    let start = template[..template.find("{v}").unwrap()].chars().count();
    let text = template.replace("{v}", encoded);
    let result = scan(&text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.start_char, span.end_char, span.text.as_str()))
        .collect();
    assert_eq!(
        spans,
        vec![(start, start + encoded.chars().count(), encoded)],
        "{rule_id}: {text:?}"
    );
    let rules = result.layers[0].details["matched_rules"].as_array().unwrap();
    let rule = rules
        .iter()
        .find(|rule| rule["rule_id"] == rule_id)
        .unwrap_or_else(|| panic!("{rule_id} missing: {rules:?}"));
    let byte_start = text.find(encoded).unwrap();
    assert_eq!(rule["start_byte"], byte_start);
    assert_eq!(rule["end_byte"], byte_start + encoded.len());
    assert_eq!(rule["decoded"], serde_json::json!(encodings), "{rule:?}");
}

fn assert_silent(texts: &[String]) {
    let reported: Vec<_> = texts
        .iter()
        .filter_map(|text| {
            let result = scan(text);
            (!result.evidence_spans.is_empty()).then(|| {
                let spans: Vec<_> = result.evidence_spans.iter().map(|s| &s.text).collect();
                format!("{text:?} -> {spans:?}")
            })
        })
        .collect();
    assert!(reported.is_empty(), "reported: {reported:#?}");
}

#[test]
fn base64_encoded_provider_tokens_point_to_the_encoded_range() {
    let cases = [
        ("LLM_ZUGANG_B64={v}\nREGION=eu-central-1\n", "anthropic_api_key", "dlp_anthropic_key"),
        ("{\"nutzlast\": \"{v}\", \"kodierung\": \"base64\"}", "openai_project_api_key", "dlp_openai_key"),
        ("2026-11-02 09:12:44 DEBUG upstream header x-goog-blob: {v}\n", "google_api_key", "dlp_google_api_key"),
        ("$ echo {v} | base64 -d > ~/.config/gh/token\n", "github_ghp_token", "dlp_github_token"),
        ("The support log contained {v}, which decodes to the live key.", "stripe_secret_live", "dlp_stripe_key"),
    ];
    for (seed, (template, generator, rule)) in (1..).zip(cases) {
        let token = generate(generator, seed);
        assert_decoded(template, &base64(token.as_bytes()), rule, &["base64"]);
    }
}

#[test]
fn base64url_and_two_layers_decode() {
    // A seed whose encoding needs the url-safe alphabet.
    let encoded = (1..)
        .map(|seed| base64url(format!("token: {}", generate("github_ghp_token", seed)).as_bytes()))
        .find(|encoded| encoded.contains(['-', '_']))
        .unwrap();
    assert_decoded("payload={v}&v=2", &encoded, "dlp_github_token", &["base64url"]);
    let token = generate("github_ghp_token", 7);
    let twice = base64(base64(token.as_bytes()).as_bytes());
    assert_decoded("ci_blob: {v}\n", &twice, "dlp_github_token", &["base64", "base64"]);
}

#[test]
fn a_token_inside_a_longer_encoded_text_maps_to_its_quads() {
    let token = generate("stripe_secret_live", 11);
    let plain = format!("# payment settings\nmode=live\nkey={token}\n");
    let encoded = base64(plain.as_bytes());
    let text = format!("blob: {encoded}\n");
    let result = scan(&text);
    assert_eq!(result.evidence_spans.len(), 1, "{result:?}");
    let span = &result.evidence_spans[0];
    let offset = plain.find(&token).unwrap();
    let start = 6 + offset / 3 * 4;
    let end = 6 + ((offset + token.len()).div_ceil(3) * 4).min(encoded.len());
    assert_eq!((span.start_byte, span.end_byte), (start, end));
    assert!(encoded.contains(&span.text));
}

#[test]
fn three_layers_stay_encoded() {
    let token = generate("github_ghp_token", 3);
    let thrice = base64(base64(base64(token.as_bytes()).as_bytes()).as_bytes());
    assert_silent(&[format!("ci_blob: {thrice}\n")]);
}

#[test]
fn a_plain_finding_keeps_its_span_over_the_decoded_one() {
    // The Basic rule reports the encoded user:password itself.
    let text = format!(
        "Authorization: Basic {}\n",
        base64(b"deploy-user:Wq8#vLz2!pRt5mKx")
    );
    let result = scan(&text);
    let rules = result.layers[0].details["matched_rules"].as_array().unwrap();
    assert!(
        rules.iter().all(|rule| rule.get("decoded").is_none()),
        "{rules:?}"
    );
}

#[test]
fn decoded_non_secrets_stay_silent() {
    let filled = generators()
        .generate_filled("anthropic_api_key", 0, Some("EXAMPLEKEY"))
        .unwrap();
    let binary: Vec<u8> = (0u8..64).map(|i| i.wrapping_mul(53).wrapping_add(7)).collect();
    assert_silent(&[
        format!("LLM_ZUGANG_B64={}\n", base64(b"OPENAI_API_KEY=${OPENAI_API_KEY}")),
        format!("blob: {}\n", base64(b"password=${DB_PASSWORD}")),
        format!("einstellungen: {}\n", base64(b"api_key: BITTE_AENDERN")),
        format!("$ echo {} | base64 -d\n", base64(b"token: YOUR_TOKEN_HERE")),
        format!(
            "Nachricht: {}",
            base64("Hallo Welt, dies ist nur eine Testnachricht ohne Zugangsdaten.".as_bytes())
        ),
        format!(
            "request id {}",
            base64(b"550e8400-e29b-41d4-a716-446655440000")
        ),
        format!("header = \"{}\"", base64url(br#"{"alg":"RS256","typ":"JWT"}"#)),
        format!("LLM_ZUGANG_B64={}\n", base64(filled.as_bytes())),
        format!("{{\"integrity\": \"sha512-{}\"}}", base64(&binary)),
    ]);
}
