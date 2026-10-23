// SPDX-License-Identifier: GPL-3.0-only
//! AWS access key IDs and secret access keys (F05). `dlp_aws_access_key`
//! takes the credential prefixes of the IAM unique-ID table (`AKIA`, `ASIA`,
//! `ABIA`, `ACCA`, legacy `A3T…`) and exactly 16 upper-case letters or digits
//! (Base32 today, legacy IDs also hold 0, 1, 8 and 9); group,
//! user, role and policy IDs (`AGPA`, `AIDA`, `AROA`, `ANPA` …) are no
//! credentials. `dlp_aws_secret_key` takes 40 base64 characters with upper and
//! lower case letters after an AWS key name or label (also in prose, up to two
//! lines on), right after an access key ID, or after a generic secret key name
//! (`secret_key`, `secret-key`, `secretKey`) with AWS context: credentials and
//! `.s3cfg` files, Terraform `provider "aws"`, Spring `cloud.aws`, CLI.
//! Values come from the golden generator or are assembled here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::{
        dlp::{ValidatorStrength, DLP_PATTERNS},
        score::DlpMode,
    },
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const BASE32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

/// An access key ID: `prefix` and 16 random Base32 characters.
fn key_id(prefix: &str, seed: u64) -> String {
    format!("{prefix}{}", random(seed, BASE32, 16))
}

fn mode_scan(text: &str, mode: DlpMode) -> SecurityScanResult {
    static SCANNERS: OnceLock<[SecurityGateway; 3]> = OnceLock::new();
    let scanners = SCANNERS.get_or_init(|| {
        [DlpMode::Strict, DlpMode::Balanced, DlpMode::Recall].map(|mode| {
            let scanner = SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            );
            scanner.set_execution_gates(ScanGateMatrix {
                dlp_mode: mode,
                ..ScanGateMatrix::default()
            });
            scanner
        })
    });
    scanners[mode as usize]
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn scan(text: &str) -> SecurityScanResult {
    mode_scan(text, DlpMode::Strict)
}

/// The unsuppressed `matched_rules` entries of `rule_id` that reported a value.
fn entries(text: &str, rule_id: &str) -> Vec<serde_json::Value> {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule["rule_id"] == rule_id && rule.get("suppressed_by").is_none())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `rule_id` reported exactly `value` as `CLOUD_KEY` in `text`.
fn reports(text: &str, rule_id: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == "CLOUD_KEY" && span.text == value)
        && !entries(text, rule_id).is_empty()
}

/// Whether no AWS rule reported anything in `text`.
fn no_aws_finding(text: &str) -> bool {
    entries(text, "dlp_aws_access_key").is_empty()
        && entries(text, "dlp_aws_secret_key").is_empty()
        && !scan(text)
            .evidence_spans
            .iter()
            .any(|span| span.label == "CLOUD_KEY")
}

/// DE and EN carriers of access key IDs: credentials file, .env, YAML, JSON,
/// code, CLI, CSV, log and prose.
const KEY_ID_CARRIERS: &[&str] = &[
    "[default]\naws_access_key_id = {}\n",
    "AWS_ACCESS_KEY_ID={}\n",
    "env:\n  AWS_ACCESS_KEY_ID: \"{}\"\n",
    "{\"Credentials\": {\"AccessKeyId\": \"{}\", \"Expiration\": \"2026-10-22T10:00:00Z\"}}\n",
    "s3 = boto3.client(\"s3\", aws_access_key_id=\"{}\")\n",
    "$ aws configure set aws_access_key_id {} --profile export\n",
    "Benutzername,Zugriffsschlüssel-ID\nexport-job,{}\n",
    "2026-10-22T08:14:03Z WARN sts: Zugriff mit Schlüssel {} abgelehnt\n",
    "Die alte Access Key ID {} wurde gestern deaktiviert.\n",
    "Hi Sam, the key {} was rotated this morning.\n",
];

#[test]
fn generated_access_key_ids_of_every_credential_prefix_are_reported() {
    for gen in [
        "aws_access_key_id",
        "aws_session_access_key_id",
        "aws_sts_bearer_key_id",
        "aws_context_credential_key_id",
    ] {
        for seed in 0..8 {
            let value = generated(gen, seed);
            assert_eq!(value.len(), 20, "{value}");
            for carrier in KEY_ID_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(
                    reports(&text, "dlp_aws_access_key", &value),
                    "{gen} {seed}: {text:?}"
                );
            }
        }
    }
    // Legacy key IDs: `A3T`, one more upper-case letter or digit, 16 Base32.
    for (seed, fourth) in "AZ09".chars().enumerate() {
        let value = format!("A3T{fourth}{}", random(seed as u64, BASE32, 16));
        let text = format!("AWS_ACCESS_KEY_ID={value}\n");
        assert!(reports(&text, "dlp_aws_access_key", &value), "{text:?}");
    }
}

#[test]
fn unique_ids_of_other_iam_entities_are_no_access_keys() {
    // Group, user, role, instance profile, managed policy, policy version,
    // public key and certificate IDs (IAM unique-ID table).
    for prefix in [
        "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "APKA", "ASCA",
    ] {
        for seed in 0..4 {
            let value = key_id(prefix, seed);
            for text in [
                format!("{{\"userIdentity\": {{\"type\": \"IAMUser\", \"principalId\": \"{value}\"}}}}\n"),
                format!("Die Rollen-ID {value} gehört zu deploy-role.\n"),
            ] {
                assert!(no_aws_finding(&text), "{text:?}: {:?}", scan(&text).evidence_spans);
            }
        }
    }
    for seed in 0..8 {
        let value = generated("aws_iam_user_unique_id", seed);
        let text = format!("\"principalId\": \"{value}\"\n");
        assert!(no_aws_finding(&text), "{text:?}");
    }
}

#[test]
fn legacy_alphanumeric_key_ids_are_reported_and_other_lengths_are_not() {
    for seed in 0..8 {
        let base = key_id("AKIA", seed);
        // Legacy key IDs: a 0, 1, 8 or 9 at the end, in the middle and after
        // the prefix, outside today's Base32 alphabet.
        let mut legacy = vec![generated("aws_access_key_id_non_base32", seed)];
        for (index, digit) in [(19, '0'), (11, '1'), (4, '8'), (15, '9')] {
            let mut chars: Vec<char> = base.chars().collect();
            chars[index] = digit;
            legacy.push(chars.into_iter().collect());
        }
        for (i, value) in legacy.iter().enumerate() {
            for carrier in [
                "2026-10-22T08:14:03Z WARN sts: Schlüssel {} abgelehnt\n",
                "Hi Sam, the key {} was rotated this morning.\n",
                "AWS_ACCESS_KEY_ID={}\n",
            ] {
                let text = carrier.replace("{}", value);
                assert!(
                    reports(&text, "dlp_aws_access_key", value),
                    "legacy key ID {i} of seed {seed}"
                );
            }
        }
        // 21 and 15 Base32 characters.
        for value in [
            generated("aws_access_key_id_long", seed),
            base[..19].to_owned(),
        ] {
            for carrier in [
                "2026-10-22T08:14:03Z WARN sts: Schlüssel {} abgelehnt\n",
                "Hi Sam, the key {} was rotated this morning.\n",
            ] {
                let text = carrier.replace("{}", &value);
                assert!(no_aws_finding(&text), "{text:?}");
            }
            assert!(
                entries(
                    &format!("AWS_ACCESS_KEY_ID={value}\n"),
                    "dlp_aws_access_key"
                )
                .is_empty(),
                "{value}"
            );
        }
    }
    // Lower case is no key ID.
    let text = format!(
        "Hi Sam, the key {} was rotated.\n",
        key_id("AKIA", 1).to_lowercase()
    );
    assert!(no_aws_finding(&text), "{text:?}");
}

/// DE and EN carriers of a secret access key behind an AWS key name or label:
/// credentials file, .env, shell, YAML, JSON (STS), XML, properties, HTTP
/// header, Jupyter, TypeScript, Rust, Java properties, CLI, prose and mail.
const SECRET_CARRIERS: &[&str] = &[
    "[default]\naws_access_key_id = ${AWS_ACCESS_KEY_ID}\naws_secret_access_key = {}\n",
    "AWS_SECRET_ACCESS_KEY={}\n",
    "export AWS_SECRET_ACCESS_KEY=\"{}\"\n",
    "env:\n  AWS_SECRET_ACCESS_KEY: '{}'\n",
    "{\"Credentials\": {\"AccessKeyId\": \"ASIA-redacted\", \"SecretAccessKey\": \"{}\"}}\n",
    "<add key=\"AwsSecretAccessKey\" value=\"{}\" />\n",
    "app.aws-secret-access-key={}\n",
    "Aws-Secret-Access-Key: {}\n",
    "    \"os.environ[\\\"AWS_SECRET_ACCESS_KEY\\\"] = \\\"{}\\\"\\n\",\n",
    "export const awsSecretAccessKey: string = \"{}\";\n",
    "const AWS_SECRET_ACCESS_KEY: &str = \"{}\";\n",
    "aws.secretKey={}\n",
    ":secret_access_key => '{}',\n",
    "$ aws configure set aws_secret_access_key {} --profile export\n",
    "AWS Secret Access Key [None]: {}\nDefault region name [None]: eu-central-1\n",
    "Der AWS-Secret-Access-Key für den Export lautet {}, bitte nach dem Test rotieren.\n",
    "[10:02] jana.k: Hast du den AWS Secret Access Key für Staging?\n[10:03] tim.b: {}\n",
    "Hi team,\n\nhere is the AWS secret access key for the backup job:\n\n{}\n\nThanks\n",
];

/// Carriers of a secret access key behind a generic secret key name with AWS
/// context: Terraform, `.s3cfg`, Spring, credentials next to a key ID name,
/// botocore log.
const CONTEXT_CARRIERS: &[&str] = &[
    "provider \"aws\" {\n  region     = \"eu-central-1\"\n  access_key = var.access_key\n  secret_key = \"{}\"\n}\n",
    "terraform {\n  backend \"s3\" {\n    bucket     = \"tf-state\"\n    secret_key = \"{}\"\n  }\n}\n",
    "[default]\nhost_base = s3.amazonaws.com\nsecret_key = {}\n",
    "cloud:\n  aws:\n    region:\n      static: eu-central-1\n    credentials:\n      secret-key: {}\n",
    "cloud.aws.credentials.secret-key={}\n",
    "storage:\n  accessKeyId: ${ACCESS_KEY_ID}\n  secretKey: \"{}\"\n",
    "2026-10-22T08:01:12Z DEBUG botocore.credentials: secret_key={} from ~/.aws/credentials\n",
];

#[test]
fn generated_secret_keys_are_reported_after_aws_key_names_and_labels() {
    for seed in 0..12 {
        let value = generated("aws_secret_access_key", seed);
        for carrier in SECRET_CARRIERS.iter().chain(CONTEXT_CARRIERS) {
            let text = carrier.replace("{}", &value);
            assert!(
                reports(&text, "dlp_aws_secret_key", &value),
                "{seed}: {text:?}: {:?}",
                scan(&text).evidence_spans
            );
        }
    }
}

#[test]
fn a_secret_key_right_after_its_access_key_id_is_reported() {
    for seed in 0..8 {
        let id = generated("aws_access_key_id", seed);
        let secret = generated("aws_secret_access_key", 100 + seed);
        for (i, text) in [
            // SDK calls, IAM credentials CSV, MinIO client, colon pair.
            format!("AWSCredentials creds = new BasicAWSCredentials(\"{id}\", \"{secret}\");\n"),
            format!("new AWS.Credentials('{id}', '{secret}');\n"),
            format!("Access key ID,Secret access key\n{id},{secret}\n"),
            format!("User name,Access key ID,Secret access key\nexport-job,{id},{secret}\n"),
            format!("$ mc alias set archiv https://s3.eu-central-1.amazonaws.com {id} {secret}\n"),
            format!("Zugang für den Export: {id}:{secret}\n"),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                reports(text, "dlp_aws_secret_key", &secret),
                "secret key in carrier {i} of seed {seed}"
            );
            assert!(
                reports(text, "dlp_aws_access_key", &id),
                "access key ID in carrier {i} of seed {seed}"
            );
        }
    }
}

#[test]
fn generic_secret_keys_without_aws_context_are_no_aws_secret() {
    for seed in 0..8 {
        let value = generated("aws_secret_access_key", seed);
        for carrier in [
            // Django/Flask settings, other providers, no AWS anchor anywhere.
            "# settings.py\nDEBUG = False\nSECRET_KEY = \"{}\"\n",
            "app.secret_key = \"{}\"\n",
            "stripe:\n  secret_key: \"{}\"\n",
            "STRIPE_SECRET_KEY={}\n",
            "jwt:\n  secretKey: \"{}\"\n",
            "Das Passwort für den Export lautet {}.\n",
            "{}\n",
        ] {
            let text = carrier.replace("{}", &value);
            assert!(
                entries(&text, "dlp_aws_secret_key").is_empty(),
                "{text:?}: {:?}",
                scan(&text).evidence_spans
            );
        }
    }
}

#[test]
fn secret_values_of_another_shape_are_no_aws_secret() {
    for seed in 0..8 {
        let value = generated("aws_secret_access_key", seed);
        for bad in [
            generated("aws_secret_access_key_long", seed),
            generated("aws_secret_access_key_hex", seed),
            // 39 characters, padding, one case only, a longer base64 blob.
            value[..39].to_owned(),
            format!("{}=", &value[..39]),
            value.to_uppercase(),
            value.to_lowercase(),
            format!("{value}{}", random(seed, BASE64, 4)),
            format!("{}{value}", random(seed, BASE64, 4)),
        ] {
            for carrier in [
                "aws_secret_access_key = {}\n",
                "{\"SecretAccessKey\": \"{}\"}\n",
                "Removed the AWS secret access key in commit {}.\n",
            ] {
                let text = carrier.replace("{}", &bad);
                assert!(
                    entries(&text, "dlp_aws_secret_key").is_empty(),
                    "{text:?}: {:?}",
                    scan(&text).evidence_spans
                );
            }
        }
    }
}

#[test]
fn a_value_far_from_its_label_or_after_another_key_is_no_aws_secret() {
    let value = generated("aws_secret_access_key", 3);
    for text in [
        // Three lines on, or after an assignment of another key.
        format!("The AWS secret access key is in the vault.\n\n\n\n{value}\n"),
        format!("AWS_SECRET_ACCESS_KEY=\nSERVICE_TOKEN={value}\n"),
        // The label names the key; no value follows.
        "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}\n".to_owned(),
        "secret_key = var.aws_secret_key\n".to_owned(),
    ] {
        assert!(
            entries(&text, "dlp_aws_secret_key").is_empty(),
            "{text:?}: {:?}",
            scan(&text).evidence_spans
        );
    }
}

#[test]
fn aws_rules_keep_format_strength_their_sources_and_subtypes() {
    for (name, subtype) in [
        ("dlp_aws_access_key", "api_key"),
        ("dlp_aws_secret_key", "secret_key"),
    ] {
        let rule = DLP_PATTERNS
            .iter()
            .find(|rule| rule.name == name)
            .expect("rule must exist");
        assert_eq!(rule.meta.validator_strength, ValidatorStrength::Format);
        assert_eq!(rule.meta.provider, Some("aws"));
        assert_eq!(
            rule.meta.subtype.map(|subtype| subtype.as_str()),
            Some(subtype)
        );
    }
    let secret = generated("aws_secret_access_key", 5);
    let entry = &entries(
        &format!("aws_secret_access_key = {secret}\n"),
        "dlp_aws_secret_key",
    )[0];
    assert_eq!(entry["provider"], "aws");
    assert_eq!(entry["subtype"], "secret_key");
    // In balanced, a labelled secret key stays; a bare value is no finding.
    let labelled = format!("aws_secret_access_key = {secret}\n");
    assert!(mode_scan(&labelled, DlpMode::Balanced)
        .evidence_spans
        .iter()
        .any(|span| span.text == secret));
    assert!(mode_scan(&format!("{secret}\n"), DlpMode::Recall)
        .evidence_spans
        .iter()
        .all(|span| span.label != "CLOUD_KEY"));
}
