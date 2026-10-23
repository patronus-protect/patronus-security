// SPDX-License-Identifier: GPL-3.0-only
//! T06: documented example and test values of secret rules are no findings,
//! while the same shapes with a random body and weak but real credentials
//! stay detected. Values are synthetic shapes without valid checksums; GitHub
//! and npm tokens get their CRC32 suffix here at test time (F03, F04).

use std::sync::OnceLock;

use patronus_ark::{
    detectors::validators::crc32_base62, SecurityCategory, SecurityGateway, SecurityLevel,
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

fn matched_rules(result: &SecurityScanResult) -> Vec<String> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn assert_reported(text: &str, rule_id: &str, value: &str) {
    let result = scan(text);
    assert!(
        result.evidence_spans.iter().any(|span| span.text == value),
        "{rule_id}: missing {value:?} in {text:?}: {result:#?}"
    );
    assert!(
        matched_rules(&result).iter().any(|rule| rule == rule_id),
        "{rule_id}: rule did not fire on {text:?}"
    );
}

fn assert_silent(text: &str) {
    let result = scan(text);
    assert!(
        result.evidence_spans.is_empty(),
        "example value reported in {text:?}: {:#?}",
        result.evidence_spans
    );
}

/// A `ghp_` token whose 30 body characters `body` end in their CRC32 (F03).
fn github_token(body: &str) -> String {
    crc_token("ghp_", body)
}

/// `prefix` and 30 body characters `body` that end in their CRC32 (GitHub
/// F03, npm F04).
fn crc_token(prefix: &str, body: &str) -> String {
    assert_eq!(body.len(), 30, "{body}");
    format!("{prefix}{body}{}", crc32_base62(body))
}

fn fill(word: &str, length: usize) -> String {
    word.chars().cycle().take(length).collect()
}

/// Deterministic pseudo-random string over `alphabet` (SplitMix64).
fn random(seed: u64, alphabet: &str, length: usize) -> String {
    let alphabet = alphabet.as_bytes();
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            mixed ^= mixed >> 31;
            alphabet[(mixed % alphabet.len() as u64) as usize] as char
        })
        .collect()
}

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &str = "0123456789abcdef";
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A provider shape: rule, carrier with `{}` for the value, prefix, body
/// alphabet and length, suffix.
struct Shape {
    rule_id: &'static str,
    carrier_de: &'static str,
    carrier_en: &'static str,
    prefix: &'static str,
    alphabet: &'static str,
    length: usize,
    suffix: &'static str,
}

const SHAPES: &[Shape] = &[
    Shape {
        rule_id: "dlp_anthropic_key",
        carrier_de: "# Zugang\nANTHROPIC_API_KEY={}\n",
        carrier_en: "anthropic:\n  api_key: {}\n",
        prefix: "sk-ant-api03-",
        alphabet: ALNUM,
        length: 93,
        suffix: "AA",
    },
    Shape {
        rule_id: "dlp_openai_key",
        carrier_de: "OPENAI_API_KEY={}",
        carrier_en: "client = OpenAI(api_key=\"{}\")",
        prefix: "sk-proj-",
        alphabet: ALNUM,
        length: 64,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_openai_legacy",
        carrier_de: "Alter Schlüssel im Ticket: {}",
        carrier_en: "openai.api_key = \"{}\"",
        prefix: "sk-",
        alphabet: ALNUM,
        length: 48,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_openai_svc",
        carrier_de: "Service-Account: {}",
        carrier_en: "OPENAI_API_KEY={}",
        prefix: "sk-svcacct-",
        alphabet: ALNUM,
        length: 60,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_huggingface",
        carrier_de: "HF_TOKEN={}",
        carrier_en: "huggingface-cli login --token {}",
        prefix: "hf_",
        alphabet: ALNUM,
        length: 34,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_groq_key",
        carrier_de: "GROQ_API_KEY={}",
        carrier_en: "{\"groq\": {\"api_key\": \"{}\"}}",
        prefix: "gsk_",
        alphabet: ALNUM,
        length: 52,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_xai_key",
        carrier_de: "Grok-Zugang: {}",
        carrier_en: "XAI_API_KEY={}",
        prefix: "xai-",
        alphabet: ALNUM,
        length: 80,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_replicate",
        carrier_de: "Replicate-Token: {}",
        carrier_en: "REPLICATE_API_TOKEN={}",
        prefix: "r8_",
        alphabet: ALNUM,
        length: 37,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_aws_access_key",
        carrier_de: "Zugangs-ID: {}",
        carrier_en: "aws_access_key_id = {}",
        prefix: "AKIA",
        alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        length: 16,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_aws_secret_key",
        carrier_de: "AWS_SECRET_ACCESS_KEY={}",
        carrier_en: "aws_secret_access_key = {}",
        prefix: "",
        alphabet: ALNUM,
        length: 40,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_google_api_key",
        carrier_de: "Maps-Schlüssel: {}",
        carrier_en: "GOOGLE_API_KEY={}",
        prefix: "AIza",
        alphabet: ALNUM,
        length: 35,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_google_oauth_token",
        carrier_de: "Zugriffstoken: {}",
        carrier_en: "{\"access_token\": \"{}\"}",
        prefix: "ya29.",
        alphabet: ALNUM,
        length: 60,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_gcp_client_secret",
        carrier_de: "GOOGLE_CLIENT_SECRET={}",
        carrier_en: "client_secret: {}",
        prefix: "GOCSPX-",
        alphabet: ALNUM,
        length: 28,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_github_token",
        carrier_de: "GITHUB_TOKEN={}",
        carrier_en: "git clone https://x-access-token:{}@github.com/acme/app.git",
        prefix: "ghp_",
        alphabet: ALNUM,
        length: 30,
        suffix: "000000",
    },
    Shape {
        rule_id: "dlp_github_pat",
        carrier_de: "GH_TOKEN={}",
        carrier_en: "token: {}",
        prefix: "github_pat_",
        alphabet: ALNUM,
        length: 82,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_gitlab_pat",
        carrier_de: "GITLAB_TOKEN={}",
        carrier_en: "gitlab:\n  token: {}\n",
        prefix: "glpat-",
        alphabet: ALNUM,
        length: 20,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_gitlab_token",
        carrier_de: "GITLAB_DEPLOY_TOKEN={}",
        carrier_en: "registry:\n  user: gitlab+deploy-token-12\n  token: {}\n",
        prefix: "gldt-",
        alphabet: ALNUM,
        length: 20,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_gitlab_oauth_secret",
        carrier_de: "GITLAB_APP_SECRET={}",
        carrier_en: "{\"application_id\": \"4711\", \"secret\": \"{}\"}",
        prefix: "gloas-",
        alphabet: ALNUM,
        length: 64,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_npm_token",
        carrier_de: "//registry.npmjs.org/:_authToken={}",
        carrier_en: "NPM_TOKEN={}",
        prefix: "npm_",
        alphabet: ALNUM,
        length: 30,
        suffix: "000000",
    },
    Shape {
        rule_id: "dlp_stripe_key",
        carrier_de: "STRIPE_SECRET_KEY={}",
        carrier_en: "stripe.api_key = \"{}\"",
        prefix: "sk_live_",
        alphabet: ALNUM,
        length: 24,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_stripe_key",
        carrier_de: "Stripe (Testmodus): {}",
        carrier_en: "STRIPE_KEY={}",
        prefix: "rk_test_",
        alphabet: ALNUM,
        length: 24,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_stripe_webhook",
        carrier_de: "STRIPE_WEBHOOK_SECRET={}",
        carrier_en: "webhook_secret: {}",
        prefix: "whsec_",
        alphabet: ALNUM,
        length: 32,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_slack_token",
        carrier_de: "SLACK_TOKEN={}",
        carrier_en: "slack:\n  bot_token: {}\n",
        prefix: "xoxb-",
        alphabet: ALNUM,
        length: 40,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_eth_private_key",
        carrier_de: "WALLET_PRIVATE_KEY={}",
        carrier_en: "new Wallet(\"{}\")",
        prefix: "0x",
        alphabet: HEX,
        length: 64,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_btc_wif",
        carrier_de: "WIF-Schlüssel: {}",
        carrier_en: "wif: {}",
        prefix: "5",
        alphabet: BASE58,
        length: 50,
        suffix: "",
    },
    Shape {
        rule_id: "dlp_password_hash",
        carrier_de: "Passwort-Hash: {}",
        carrier_en: "password_hash = {}",
        prefix: "",
        alphabet: HEX,
        length: 64,
        suffix: "",
    },
];

/// Fills of a body alphabet: marker words (`EXAMPLEKEY…`, `TESTKEY…`) and
/// low-variety bodies (repeated chunks, also of sequential runs, and zero
/// runs). A low-variety fill must repeat at least 6 characters within the body:
/// a single sequential run needs example context, see
/// `provider_values_with_one_sequential_run_need_example_context`.
fn example_bodies(alphabet: &str, length: usize) -> (Vec<String>, Vec<String>) {
    let fills = |words: &[&str], min_repeated: usize| {
        words
            .iter()
            .filter(|word| word.chars().all(|character| alphabet.contains(character)))
            .filter(|word| length >= word.len() + min_repeated)
            .map(|word| fill(word, length))
            .collect::<Vec<_>>()
    };
    let markers = fills(
        &[
            "EXAMPLEKEY",
            "TESTKEY",
            "BEISPIEL",
            "MUSTER",
            "DUMMY",
            "FAKE",
        ],
        0,
    );
    let low_variety = fills(
        &[
            "deadbeef",
            "1234567890",
            "0123456789abcdef",
            "ABCDEFGH",
            "0",
            "A",
        ],
        6,
    );
    // Hex bodies cannot hold a marker word; every alphabet has a low-variety fill.
    assert!(!low_variety.is_empty());
    (markers, low_variety)
}

#[test]
fn provider_example_and_test_values_are_silent_in_de_and_en() {
    for shape in SHAPES {
        let (markers, low_variety) = example_bodies(shape.alphabet, shape.length);
        for carrier in [shape.carrier_de, shape.carrier_en] {
            for body in &markers {
                let value = format!("{}{body}{}", shape.prefix, shape.suffix);
                assert_silent(&carrier.replace("{}", &value));
            }
            // Generic assignment rules in the carrier check a provider-shaped
            // value like the provider rule does.
            for body in &low_variety {
                let value = format!("{}{body}{}", shape.prefix, shape.suffix);
                assert_silent(&carrier.replace("{}", &value));
            }
        }
    }
}

#[test]
fn provider_values_with_a_random_body_stay_detected_in_de_and_en() {
    for (index, shape) in SHAPES.iter().enumerate() {
        if shape.rule_id == "dlp_btc_wif" {
            continue; // Base58Check: a random body has no valid checksum (dlp_btc_wif.rs)
        }
        let body = random(index as u64 + 1, shape.alphabet, shape.length);
        let value = match shape.rule_id {
            "dlp_github_token" => github_token(&body),
            "dlp_npm_token" => crc_token("npm_", &body),
            _ => format!("{}{body}{}", shape.prefix, shape.suffix),
        };
        for carrier in [shape.carrier_de, shape.carrier_en] {
            assert_reported(&carrier.replace("{}", &value), shape.rule_id, &value);
        }
    }
}

#[test]
fn documented_vendor_example_values_are_silent() {
    for text in [
        concat!("aws_access_key_id = ", "AKIA", "IOSFODNN7", "EXAMPLE"),
        concat!(
            "aws_secret_access_key = ",
            "wJalrXUtnFEMI/",
            "K7MDENG/bPxRfiCY",
            "EXAMPLEKEY"
        ),
        concat!("Beispiel aus der Doku: ", "AKIA", "Q7TZ4MXK2", "EXAMPLE"),
        concat!(
            "DISCORD_BOT_TOKEN=",
            "MTAxMjM0NTY3ODkwMTIzNDUh",
            ".EXAMPA.",
            "EXAMPLEKEYEXAMPLEKEYEXAMPLE"
        ),
        concat!(
            "ID_TOKEN=",
            "eyJhbGciOiJIUzI1NiJ9",
            ".eyJzdWIiOiJ0ZXN0In0",
            ".TESTSIGNATURE_TESTSIGNATURE"
        ),
        "X-Amz-Signature=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "Cookie: JSESSIONID=12345678901234567890123456789012",
    ] {
        assert_silent(text);
    }
}

#[test]
fn private_key_blocks_with_example_bodies_are_silent() {
    // base64 of "EXAMPLEKEY" and "TESTKEY" repeated, in raw and JSON-escaped form.
    let example = "RVhBTVBMRUtFWUVYQU1QTEVLRVlFWEFNUExFS0VZRVhBTVBMRUtFWUVYQU1QTEVL\n\
                   RVlFWEFNUExFS0VZRVhBTVBMRUtFWUVYQU1QTEVLRVlFWEFNUExFS0VZRVhBTVBM";
    let test = "VEVTVEtFWVRFU1RLRVlURVNUS0VZVEVTVEtFWVRFU1RLRVlURVNUS0VZVEVTVEtF\n\
                WVRFU1RLRVlURVNUS0VZVEVTVEtFWVRFU1RLRVlURVNUS0VZVEVTVEtFWVRFU1RL";
    for body in [example, test] {
        let block = format!(
            concat!(
                "-----BEGIN ",
                "RSA PRIVATE KEY-----",
                "\n{}\n-----END RSA PRIVATE KEY-----"
            ),
            body
        );
        assert_silent(&format!("Schlüsseldatei (Beispiel):\n{block}\n"));
        assert_silent(&format!(
            "{{\"tls_private_key\": \"{}\"}}",
            block.replace('\n', "\\n")
        ));
    }
    let block = format!(
        concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----",
            "\n{}\n{}\n-----END PRIVATE KEY-----"
        ),
        random(42, ALNUM, 64),
        random(43, ALNUM, 40)
    );
    let result = scan(&block);
    assert!(matched_rules(&result)
        .iter()
        .any(|rule| rule == "dlp_private_key_block"));
}

#[test]
fn weak_but_real_credentials_stay_detected() {
    assert_reported(
        "password=abcabcabcabc",
        "dlp_password_assignment",
        "abcabcabcabc",
    );
    assert_reported(
        "Das Passwort lautet abcabcabcabc",
        "dlp_password_assignment",
        "abcabcabcabc",
    );
    let token = format!(
        "{}1234567890abcdef{}",
        random(7, ALNUM, 12),
        random(8, ALNUM, 12)
    );
    assert_reported(
        &format!("client_secret: {token}"),
        "dlp_generic_credential_assignment",
        &token,
    );
    assert_reported(
        &format!("Der API-Schlüssel ist {token}"),
        "dlp_generic_credential_assignment",
        &token,
    );
    assert_reported(
        "DB_PASSWORD=deadbeefdeadbeef",
        "dlp_env_var_secret",
        "deadbeefdeadbeef",
    );
    let github = github_token(&format!(
        "{}Zq7Zq7Zq7Zq7{}",
        random(9, ALNUM, 12),
        random(10, ALNUM, 6)
    ));
    assert_reported(
        &format!("GITHUB_TOKEN={github}"),
        "dlp_github_token",
        &github,
    );
    let stripe = format!("sk_test_{}", random(11, ALNUM, 24));
    assert_reported(
        &format!("STRIPE_SECRET_KEY={stripe}"),
        "dlp_stripe_key",
        &stripe,
    );
}

#[test]
fn generic_low_variety_values_are_silent_only_in_example_context() {
    for text in [
        "# Beispielwerte aus der Doku\npassword=abcabcabcabc",
        "# Example from the docs, not a real secret\ndb:\n  password: abcabcabcabc\n",
        "Musterkonfiguration:\nAPI_KEY=1234567890abcdef1234567890abcdef",
        "token = deadbeefdeadbeefdeadbeef  # dummy",
        "# test fixture\nSERVICE_TOKEN=abcd1234abcd1234abcd1234",
    ] {
        assert_silent(text);
    }
    for text in [
        "base_url: https://api.example.com/v2\npassword: abcabcabcabc",
        "mail: admin@example.org\nPasswort: abcabcabcabc",
    ] {
        assert_reported(text, "dlp_password_assignment", "abcabcabcabc");
    }
}

#[test]
fn generic_marker_values_are_silent_without_context() {
    for text in [
        "password: dummy_password_42",
        "SERVICE_TOKEN=test-token-nur-fuer-ci",
        "client_secret = \"beispiel-geheimnis-2026\"",
        "https://api.example.com/v1/export?api_key=SAMPLEKEY4711",
        "Authorization: Bearer EXAMPLE-TOKEN-4711",
        "Passwort: Musterpasswort2026",
    ] {
        assert_silent(text);
    }
}

#[test]
fn provider_values_with_one_sequential_run_need_example_context() {
    // Hand-typed demo values: one ascending run, no repeated chunk.
    let values = [
        (
            "dlp_aws_access_key",
            concat!("AKIA", "1234567890", "ABCDEF").to_owned(),
        ),
        (
            "dlp_github_token",
            github_token(concat!("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "1234")),
        ),
    ];
    for (rule_id, value) in &values {
        for text in [
            format!("GITHUB_TOKEN={value}"),
            format!("const token = '{value}';"),
            format!("Der Schlüssel lautet {value}"),
        ] {
            assert_reported(&text, rule_id, value);
        }
        for text in [
            format!("# Example from the docs\nGITHUB_TOKEN={value}"),
            format!("Beispielwert: {value}"),
        ] {
            assert_silent(&text);
        }
    }
}

#[test]
fn generic_rules_check_provider_shaped_values_as_fixed_format() {
    for text in [
        concat!(
            "GITHUB_TOKEN=",
            "ghp_",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        concat!("api_key: ", "ghp_", "Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7"),
        concat!("AWS_SECRET_ACCESS_KEY=", "AKIA", "0000000000000000"),
    ] {
        assert_silent(text);
    }
    // The same repetition in a value without a provider format stays a
    // weak but real credential.
    assert_reported(
        "SERVICE_TOKEN=Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7",
        "dlp_env_var_secret",
        "Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7",
    );
}

#[test]
fn long_markers_inside_a_word_are_no_markers() {
    for (text, value) in [
        ("password=resampler2026!", "resampler2026!"),
        ("DB_PASSWORD=Gegenbeispielhaft#77", "Gegenbeispielhaft#77"),
        ("Passwort: Ummusterung-Kx7q", "Ummusterung-Kx7q"),
    ] {
        let result = scan(text);
        assert!(
            result.evidence_spans.iter().any(|span| span.text == value),
            "{value:?} dropped in {text:?}"
        );
    }
    for text in [
        "password=Musterpasswort2026",
        "DB_PASSWORD=counterexample-2026",
        "secret: sample_api_key_9f3a",
    ] {
        assert_silent(text);
    }
}
