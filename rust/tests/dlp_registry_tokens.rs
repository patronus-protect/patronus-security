// SPDX-License-Identifier: GPL-3.0-only
//! DevOps and package-registry tokens (P05). `dlp_dockerhub_token` takes
//! `dckr_pat_`/`dckr_oat_` and 27 base64url characters; `dlp_pypi_token`
//! `pypi-` and the base64url of a complete Macaroon V2 for pypi.org or
//! test.pypi.org (severity `test`), at structure strength;
//! `dlp_rubygems_token` `rubygems_` and 48 lower-case hex digits;
//! `dlp_cratesio_token` `cio` and 32 alphanumerics with both cases;
//! `dlp_packagist_token` the Private Packagist prefixes, 60 hex digits and
//! the CRC32 of both, at checksum strength; `dlp_jfrog_token` `AKCp` API keys
//! and `cmVmd` reference tokens; `dlp_terraform_cloud_token` the
//! `.atlasv1.` tokens; `dlp_pulumi_token` `pul-` and 40 hex digits;
//! `dlp_vault_token` `hvs.`/`hvb.` tokens; `dlp_vault_legacy_token` `s.` and
//! 24 characters next to a Vault term; `dlp_doppler_token` every documented
//! Doppler prefix. Tokens come from the golden generator or get their
//! checksum or structure here at test time; no valid token is checked in.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::{
        dlp::{
            dlp::{ValidatorStrength, DLP_PATTERNS},
            score::DlpMode,
        },
        validators::{crc32, BASE64URL},
    },
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Generators of each rule.
const RULE_GENERATORS: &[(&str, &[&str])] = &[
    (
        "dlp_dockerhub_token",
        &["dockerhub_pat", "dockerhub_org_token"],
    ),
    (
        "dlp_pypi_token",
        &["pypi_upload_token", "pypi_test_upload_token"],
    ),
    ("dlp_rubygems_token", &["rubygems_api_key"]),
    ("dlp_cratesio_token", &["cratesio_api_token"]),
    (
        "dlp_packagist_token",
        &["packagist_org_token", "packagist_user_token"],
    ),
    (
        "dlp_jfrog_token",
        &["artifactory_api_key", "artifactory_reference_token"],
    ),
    ("dlp_terraform_cloud_token", &["terraform_cloud_token"]),
    ("dlp_pulumi_token", &["pulumi_access_token"]),
    (
        "dlp_vault_token",
        &["vault_service_token", "vault_batch_token"],
    ),
    ("dlp_vault_legacy_token", &["vault_legacy_service_token"]),
    (
        "dlp_doppler_token",
        &[
            "doppler_personal_token",
            "doppler_service_token",
            "doppler_cli_token",
            "doppler_service_account_token",
            "doppler_scim_token",
            "doppler_audit_token",
        ],
    ),
];

/// DE and EN carriers: .env, YAML, JSON, TOML, CLI, HTTP header, log and
/// prose. Each names the provider, so the legacy Vault rule finds its
/// context in every one.
const CARRIERS: &[&str] = &[
    "# Zugang des Vault-, Registry- und Deploy-Jobs\nRELEASE_TOKEN={}\n",
    "vault_registry:\n  token: \"{}\"\n",
    "{\"vault\": {\"registry\": {\"token\": \"{}\"}}}\n",
    "[vault.registry]\ntoken = \"{}\"\n",
    "$ release-cli --vault --token {} publish\n",
    "GET /v1/registry HTTP/1.1\nHost: vault.example.com\nX-Release-Token: {}\n",
    "2026-10-27T08:12:44Z WARN vault-sync: Token {} wurde abgelehnt\n",
    "Das Vault- und Registry-Token für den Release-Job lautet {}, bitte im Tresor ablegen.\n",
    "Hi Sam, here is the Vault token for the registry job: {}\n",
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

/// A Packagist token: `prefix`, 60 random hex digits and the CRC32 of both.
fn packagist(prefix: &str, seed: u64) -> String {
    let payload = format!("{prefix}{}", random(seed, HEX, 60));
    format!("{payload}{:08x}", crc32(payload.as_bytes()))
}

/// Unpadded base64url of `raw`.
fn base64url(raw: &[u8]) -> String {
    let alphabet = BASE64URL.as_bytes();
    raw.chunks(3)
        .flat_map(|chunk| {
            let bits = chunk.iter().enumerate().fold(0u32, |bits, (index, byte)| {
                bits | u32::from(*byte) << (16 - 8 * index)
            });
            (0..=chunk.len())
                .map(move |index| alphabet[(bits >> (18 - 6 * index) & 63) as usize] as char)
        })
        .collect()
}

/// A PyPI token over a Macaroon V2 with `location`, a UUID-like identifier,
/// one caveat and a signature of `signature` bytes; `tail` is appended to the
/// macaroon bytes.
fn pypi(location: &str, seed: u64, signature: usize, tail: &[u8]) -> String {
    let mut raw = vec![2, 1, location.len() as u8];
    raw.extend_from_slice(location.as_bytes());
    let identifier = random(seed, HEX, 32);
    raw.extend_from_slice(&[2, identifier.len() as u8]);
    raw.extend_from_slice(identifier.as_bytes());
    let caveat = br#"{"version": 1, "permissions": "user"}"#;
    raw.extend_from_slice(&[0, 2, caveat.len() as u8]);
    raw.extend_from_slice(caveat);
    raw.extend_from_slice(&[0, 0, 6, signature as u8]);
    let mut rng = SplitMix64::new(seed ^ 0x5a5a);
    raw.extend((0..signature).map(|_| rng.next_u64() as u8));
    raw.extend_from_slice(tail);
    format!("pypi-{}", base64url(&raw))
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

/// The unsuppressed strict `matched_rules` entry of `rule_id`, if it reported
/// a value.
fn entry(text: &str, rule_id: &str) -> Option<serde_json::Value> {
    mode_scan(text, DlpMode::Strict).layers[0]
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

fn reports(text: &str, value: &str) -> bool {
    mode_scan(text, DlpMode::Strict)
        .evidence_spans
        .iter()
        .any(|span| span.label == "SECRET_TOKEN" && span.text == value)
}

fn assert_no_rule(rule_id: &str, value: &str) {
    for carrier in CARRIERS {
        let text = carrier.replace("{}", value);
        assert!(entry(&text, rule_id).is_none(), "{rule_id}: {text:?}");
    }
}

#[test]
fn generated_tokens_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, gens) in RULE_GENERATORS {
        for gen in *gens {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &value);
                    assert!(reports(&text, &value), "{gen}: {text:?}");
                    let rule = entry(&text, rule_id).unwrap_or_else(|| panic!("{gen}: {text:?}"));
                    assert_eq!(rule["subtype"], "access_token", "{rule_id}");
                }
            }
        }
    }
    // A sentence may end right after a token.
    for (rule_id, gens) in RULE_GENERATORS {
        let value = generated(gens[0], 7);
        let text = format!("Das Vault-Token lautet {value}.");
        assert!(entry(&text, rule_id).is_some(), "{text:?}");
    }
}

#[test]
fn every_rule_has_a_provider_a_format_source_and_a_token_boundary() {
    for (rule_id, _) in RULE_GENERATORS {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == *rule_id)
            .unwrap_or_else(|| panic!("{rule_id} must be registered"));
        assert_eq!(rule.entity_group, "SECRET_TOKEN", "{rule_id}");
        assert!(rule.meta.provider.is_some(), "{rule_id}");
        assert_ne!(rule.meta.source_ref, "ark", "{rule_id}");
        assert!(rule.meta.boundary.is_some(), "{rule_id}");
        let expected = match *rule_id {
            "dlp_packagist_token" => ValidatorStrength::Checksum,
            "dlp_pypi_token" => ValidatorStrength::Structure,
            _ => ValidatorStrength::Format,
        };
        assert_eq!(rule.meta.validator_strength, expected, "{rule_id}");
    }
}

#[test]
fn bodies_of_another_length_or_alphabet_are_no_token() {
    for seed in 0..8 {
        let cases: Vec<(&str, String)> = vec![
            (
                "dlp_dockerhub_token",
                format!("dckr_pat_{}", random(seed, ALNUM, 26)),
            ),
            (
                "dlp_dockerhub_token",
                format!("dckr_oat_{}", random(seed, ALNUM, 28)),
            ),
            (
                "dlp_dockerhub_token",
                format!("dckr_xat_{}", random(seed, ALNUM, 27)),
            ),
            (
                "dlp_rubygems_token",
                format!("rubygems_{}", random(seed, HEX, 47)),
            ),
            (
                "dlp_rubygems_token",
                format!("rubygems_{}", random(seed, HEX, 49)),
            ),
            (
                "dlp_rubygems_token",
                format!("rubygems_{}", random(seed, "0123456789ABCDEF", 48)),
            ),
            (
                "dlp_cratesio_token",
                format!("cio{}", random(seed, ALNUM, 31)),
            ),
            (
                "dlp_cratesio_token",
                format!("cio{}", random(seed, ALNUM, 33)),
            ),
            (
                "dlp_jfrog_token",
                format!("AKCp{}", random(seed, ALNUM, 68)),
            ),
            (
                "dlp_jfrog_token",
                format!("AKCp{}", random(seed, ALNUM, 70)),
            ),
            (
                "dlp_jfrog_token",
                format!("cmVmd{}", random(seed, ALNUM, 58)),
            ),
            (
                "dlp_terraform_cloud_token",
                format!(
                    "{}.atlasv1.{}",
                    random(seed, ALNUM, 14),
                    random(seed, ALNUM, 59)
                ),
            ),
            (
                "dlp_terraform_cloud_token",
                format!(
                    "{}.atlasv1.{}",
                    random(seed, ALNUM, 13),
                    random(seed, ALNUM, 67)
                ),
            ),
            ("dlp_pulumi_token", format!("pul-{}", random(seed, HEX, 39))),
            ("dlp_pulumi_token", format!("pul-{}", random(seed, HEX, 41))),
            (
                "dlp_vault_token",
                format!("hvs.{}", random(seed, ALNUM, 89)),
            ),
            (
                "dlp_vault_token",
                format!("hvb.{}", random(seed, ALNUM, 137)),
            ),
            (
                "dlp_vault_legacy_token",
                format!("s.{}", random(seed, ALNUM, 23)),
            ),
            (
                "dlp_vault_legacy_token",
                format!("s.{}", random(seed, ALNUM, 25)),
            ),
            (
                "dlp_doppler_token",
                format!("dp.pt.{}", random(seed, ALNUM, 39)),
            ),
            (
                "dlp_doppler_token",
                format!("dp.ct.{}", random(seed, ALNUM, 45)),
            ),
            (
                "dlp_doppler_token",
                format!("dp.xx.{}", random(seed, ALNUM, 42)),
            ),
            (
                "dlp_packagist_token",
                packagist("packagist_ort_", seed)[..81].to_owned(),
            ),
            ("dlp_packagist_token", packagist("packagist_xxt_", seed)),
        ];
        for (rule_id, value) in &cases {
            assert_no_rule(rule_id, value);
        }
    }
}

#[test]
fn packagist_tokens_need_their_crc32() {
    for seed in 0..8 {
        for prefix in [
            "packagist_ort_",
            "packagist_out_",
            "packagist_uut_",
            "packagist_cut_",
        ] {
            let value = packagist(prefix, seed);
            assert_eq!(value.len(), 82, "{value}");
            let text = format!("COMPOSER_TOKEN={value}\n");
            assert!(entry(&text, "dlp_packagist_token").is_some(), "{text:?}");
            // A random digit and a checksum digit changed.
            for index in [20, value.len() - 1] {
                let mut broken = value.clone().into_bytes();
                broken[index] = if broken[index] == b'0' { b'1' } else { b'0' };
                let broken = String::from_utf8(broken).unwrap();
                assert_no_rule("dlp_packagist_token", &broken);
                // A generic key does not report a Packagist token whose CRC32 fails.
                let text = format!("password = {broken}\n");
                assert!(
                    mode_scan(&text, DlpMode::Strict).evidence_spans.is_empty(),
                    "{text:?}"
                );
            }
        }
    }
    let strict = entry(
        &format!("COMPOSER_TOKEN={}\n", generated("packagist_user_token", 3)),
        "dlp_packagist_token",
    )
    .expect("token must match");
    assert_eq!(strict["validator_strength"], "checksum");
    assert_eq!(strict["provider"], "packagist");
}

#[test]
fn pypi_tokens_need_a_complete_macaroon_for_pypi() {
    for seed in 0..8 {
        for location in ["pypi.org", "test.pypi.org"] {
            let value = pypi(location, seed, 32, &[]);
            let text = format!("TWINE_PASSWORD={value}\n");
            let rule = entry(&text, "dlp_pypi_token").unwrap_or_else(|| panic!("{text:?}"));
            let severity = if location == "pypi.org" {
                "live"
            } else {
                "test"
            };
            assert_eq!(rule["severity"], severity, "{text:?}");
            assert_eq!(rule["validator_strength"], "structure");
            // A short signature, a trailing byte, another index and a token
            // cut in the middle are no PyPI token.
            for broken in [
                pypi(location, seed, 31, &[]),
                pypi(location, seed, 32, &[0]),
                pypi("pypi.orh", seed, 32, &[]),
                value[..value.len() - 12].to_owned(),
            ] {
                assert_no_rule("dlp_pypi_token", &broken);
            }
        }
    }
    let value = generated("pypi_test_upload_token", 2);
    let rule = entry(&format!("password = {value}\n"), "dlp_pypi_token").expect("test token");
    assert_eq!(rule["severity"], "test");
}

#[test]
fn crates_io_tokens_need_both_cases() {
    for seed in 0..8 {
        let value = generated("cratesio_api_token", seed);
        for single_case in [
            format!("cio{}", value[3..].to_ascii_lowercase()),
            format!("cio{}", value[3..].to_ascii_uppercase()),
        ] {
            assert_no_rule("dlp_cratesio_token", &single_case);
        }
    }
    // An identifier that only starts with `cio` inside a longer word.
    let value = generated("cratesio_api_token", 1);
    assert!(entry(&format!("x = preCiou{value}\n"), "dlp_cratesio_token").is_none());
}

#[test]
fn legacy_vault_tokens_need_vault_context() {
    for seed in 0..8 {
        let value = generated("vault_legacy_service_token", seed);
        for text in [
            format!("VAULT_TOKEN={value}\n"),
            format!("curl -H \"X-Vault-Token: {value}\" https://secrets.example.com/v1/kv\n"),
            format!("# HashiCorp Vault\n\n\n\ntoken: {value}\n"),
            format!("Der Token {value} gehört zum alten Vault-Cluster.\n"),
        ] {
            assert!(entry(&text, "dlp_vault_legacy_token").is_some(), "{text:?}");
        }
        for text in [
            format!("TOKEN={value}\n"),
            format!("2026-10-27 INFO cache: evicted {value} after 300s\n"),
            // A Vault term six lines above is out of reach.
            format!("# Vault\n\n\n\n\n\ntoken: {value}\n"),
            // Part of a longer name, a single-case body.
            format!("import reports.{}\n", &value[2..]),
            format!("VAULT_TOKEN=s.{}\n", value[2..].to_ascii_uppercase()),
        ] {
            assert!(entry(&text, "dlp_vault_legacy_token").is_none(), "{text:?}");
        }
    }
}

#[test]
fn example_and_test_fills_are_silent() {
    for (gen, fill) in [
        ("dockerhub_pat", "EXAMPLE"),
        ("rubygems_api_key", "deadbeef"),
        ("cratesio_api_token", "TESTKEY"),
        ("artifactory_api_key", "EXAMPLEKEY"),
        ("pulumi_access_token", "deadbeef"),
        ("vault_service_token", "EXAMPLE"),
        ("doppler_personal_token", "EXAMPLEKEY"),
        ("packagist_org_token", "deadbeef"),
    ] {
        let (text, _) = materialize(
            generators(),
            "REGISTRY_TOKEN=<<secret:0>>\n",
            &[SecretRecipe::filled(gen, 0, fill)],
        )
        .expect("fill must materialize");
        assert!(
            mode_scan(&text, DlpMode::Strict).evidence_spans.is_empty(),
            "{gen}: {text:?}"
        );
    }
}
