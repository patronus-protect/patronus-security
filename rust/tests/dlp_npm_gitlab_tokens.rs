// SPDX-License-Identifier: GPL-3.0-only
//! npm and GitLab tokens (F04). `dlp_npm_token` takes `npm_` and exactly 36
//! base62 characters: 30 random ones and their CRC32 as six base62 digits. It
//! scores at checksum strength, and a generic rule does not report a
//! token-shaped value whose CRC32 fails. `dlp_gitlab_pat` takes `glpat-` and
//! exactly 20 characters or the routable form (payload, `.`, two-character
//! version, seven base36 characters; or the current form with `.01.` and a
//! two-character length). `dlp_gitlab_token` takes the other documented GitLab
//! prefixes (deploy, runner `glrt-`/`glrtr-` and workspace `glwt-` tokens, also
//! in the current routable form, runner registration, pipeline
//! trigger, feed, incoming mail, Kubernetes agent, CI/CD job, SCIM, feature
//! flag client), `dlp_gitlab_oauth_secret` the OAuth application secret
//! (`gloas-`). Tokens come from the golden generator or get their checksum
//! here at test time; no checksum-valid token is checked in.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::{
        dlp::{
            dlp::{ValidatorStrength, DLP_PATTERNS},
            score::DlpMode,
        },
        validators::{crc32_base62, BASE62},
    },
    golden_recipes::{materialize, GeneratorSet, SecretRecipe, SplitMix64},
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

/// Generators of `dlp_gitlab_token`, one per documented prefix.
const GITLAB_TOKEN_GENERATORS: [&str; 11] = [
    "gitlab_deploy_token",
    "gitlab_runner_token",
    "gitlab_runner_token_routable",
    "gitlab_runner_registration_token",
    "gitlab_trigger_token",
    "gitlab_feed_token",
    "gitlab_incoming_mail_token",
    "gitlab_agent_token",
    "gitlab_cicd_job_token",
    "gitlab_scim_token",
    "gitlab_feature_flag_token",
];

/// Fixed-length GitLab prefixes of `dlp_gitlab_token` and their body length.
const GITLAB_FIXED: [(&str, usize); 8] = [
    ("gldt-", 20),
    ("glrt-", 20),
    ("glft-", 20),
    ("glsoat-", 20),
    ("glffct-", 20),
    ("glimt-", 25),
    ("glagent-", 50),
    ("GR1348941", 20),
];

const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

/// The current routable shape of GitLab's `RoutableToken` generator (HTTP
/// router docs): prefix, a base64url payload of `len` characters, `.01.`, the
/// payload length as two base36 digits and a seven-digit base36 CRC32. The
/// CRC32 is not verified, so a random one stands in here.
fn routable(prefix: &str, seed: u64, len: usize) -> String {
    let length = format!(
        "{}{}",
        BASE36.as_bytes()[len / 36 % 36] as char,
        BASE36.as_bytes()[len % 36] as char
    );
    format!(
        "{prefix}{}.01.{length}{}",
        random(seed, BASE64URL, len),
        random(seed ^ 0x5a5a, BASE36, 7)
    )
}

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

/// `npm_`, a random base62 payload of `len` characters and its CRC32.
fn npm_token(seed: u64, len: usize) -> String {
    let payload = random(seed, BASE62, len);
    format!("npm_{payload}{}", crc32_base62(&payload))
}

/// `value` with the base62 character at `index` replaced by its successor.
fn flip(value: &str, index: usize) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    let position = BASE62.find(chars[index]).expect("base62 character");
    chars[index] = BASE62.as_bytes()[(position + 1) % BASE62.len()] as char;
    chars.into_iter().collect()
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

/// The unsuppressed `matched_rules` entry of `rule_id`, if it reported a value.
fn entry(text: &str, rule_id: &str, mode: DlpMode) -> Option<serde_json::Value> {
    mode_scan(text, mode).layers[0]
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

fn reports(text: &str, label: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == label && span.text == value)
}

/// DE and EN carriers of npm tokens: .npmrc, .env, YAML, JSON, code, CLI, log,
/// prose and a generic assignment.
const NPM_CARRIERS: &[&str] = &[
    "//registry.npmjs.org/:_authToken={}\n",
    "; Registry für interne Pakete\n//npm.pkg.example.com/:_authToken=\"{}\"\nalways-auth=true\n",
    "NPM_TOKEN={}\n",
    "env:\n  NODE_AUTH_TOKEN: {}\n",
    "{\"npmAuthToken\": \"{}\", \"npmRegistryServer\": \"https://registry.npmjs.org\"}\n",
    "const client = new RegClient({ auth: { token: \"{}\" } });\n",
    "$ npm config set //registry.npmjs.org/:_authToken {}\n",
    "2026-10-21T10:02:11Z WARN publish: die Registry hat das Token {} abgelehnt\n",
    "Das npm-Token für den Release-Job lautet {}, bitte im Tresor ablegen.\n",
    "Hi Jo, here is the npm token for the publish job: {}\n",
    "password = {}\n",
];

/// DE and EN carriers of GitLab tokens: .env, YAML, JSON, TOML, HTTP header,
/// CLI, log and prose.
const GITLAB_CARRIERS: &[&str] = &[
    "GITLAB_TOKEN={}\n",
    "gitlab:\n  token: \"{}\"\n",
    "{\"gitlab\": {\"url\": \"https://gitlab.example.com\", \"token\": \"{}\"}}\n",
    "[[runners]]\n  url = \"https://gitlab.example.com\"\n  token = \"{}\"\n",
    "$ curl --header \"PRIVATE-TOKEN: {}\" https://gitlab.example.com/api/v4/projects\n",
    "2026-10-21T10:02:11Z WARN runner: GitLab hat das Token {} abgelehnt\n",
    "Das GitLab-Token für den Release-Job lautet {}, bitte im Tresor ablegen.\n",
    "Hi Jo, here is the GitLab token for the mirror job: {}\n",
];

#[test]
fn generated_npm_tokens_are_reported_in_de_and_en_carriers() {
    for seed in 0..12 {
        let value = generated("npm_access_token", seed);
        assert_eq!(value.len(), 40, "{value}");
        for carrier in NPM_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(reports(&text, "SECRET_TOKEN", &value), "{seed}: {text:?}");
            assert!(
                entry(&text, "dlp_npm_token", DlpMode::Strict).is_some(),
                "{text:?}"
            );
        }
    }
    for seed in 0..16 {
        let value = npm_token(100 + seed, 30);
        let text = format!("NPM_TOKEN={value}\n");
        assert!(reports(&text, "SECRET_TOKEN", &value), "{text:?}");
    }
}

#[test]
fn a_wrong_npm_checksum_character_is_no_finding() {
    for seed in 0..8 {
        let value = generated("npm_access_token", seed);
        // A payload character (the CRC32 no longer matches) and a checksum
        // character.
        for index in [7, value.len() - 1] {
            let broken = flip(&value, index);
            for carrier in NPM_CARRIERS {
                let text = carrier.replace("{}", &broken);
                let result = scan(&text);
                assert!(
                    result.evidence_spans.is_empty(),
                    "{text:?}: {:?}",
                    result.evidence_spans
                );
            }
        }
    }
}

#[test]
fn npm_bodies_of_another_length_are_no_npm_token() {
    for seed in 0..8 {
        // 35 and 37 characters, each ending in the CRC32 of its payload, and
        // 36 random characters without one.
        for value in [
            npm_token(seed, 29),
            npm_token(seed, 31),
            format!("npm_{}", random(seed, BASE62, 36)),
        ] {
            for carrier in NPM_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(
                    entry(&text, "dlp_npm_token", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
        for value in [npm_token(seed, 29), npm_token(seed, 31)] {
            let text = format!("Hi Jo, here is the npm token for the publish job: {value}\n");
            assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
        }
    }
}

#[test]
fn generic_rules_skip_an_npm_token_with_a_wrong_checksum() {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix::default().with_rule("dlp_npm_token", false));
    let scan = |text: &str| {
        scanner
            .scan_category(SecurityCategory::Dlp, text)
            .into_iter()
            .find(|result| result.model == "native:dlp")
            .unwrap()
    };
    for seed in 0..4 {
        let value = generated("npm_access_token", seed);
        let broken = flip(&value, 39);
        for template in ["password = {}\n", "NPM_TOKEN={}\n", "api_key: \"{}\"\n"] {
            let text = template.replace("{}", &value);
            assert!(
                scan(&text)
                    .evidence_spans
                    .iter()
                    .any(|span| span.label == "CREDENTIAL" && span.text == value),
                "{text:?}"
            );
            let text = template.replace("{}", &broken);
            assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
        }
    }
    // A value that only starts like a token stays a generic credential.
    let text = "password = npm_shortButRealPassword\n";
    assert!(!scan(text).evidence_spans.is_empty());
}

#[test]
fn npm_tokens_score_at_checksum_strength() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "dlp_npm_token")
        .unwrap();
    assert_eq!(rule.meta.validator_strength, ValidatorStrength::Checksum);
    let value = generated("npm_access_token", 5);
    let strict = entry(
        &format!("NPM_TOKEN={value}\n"),
        "dlp_npm_token",
        DlpMode::Strict,
    )
    .expect("token must match");
    assert_eq!(strict["validator_strength"], "checksum");
    assert_eq!(strict["severity"], "live");
    assert_eq!(strict["provider"], "npm");
    // Base 50 + checksum 35 without context.
    for mode in [DlpMode::Balanced, DlpMode::Recall] {
        let bare = entry(&value, "dlp_npm_token", mode).expect("bare token");
        assert_eq!(bare["score"].as_f64(), Some(0.85), "{mode:?}");
    }
}

#[test]
fn every_documented_gitlab_prefix_is_reported_in_de_and_en_carriers() {
    for gen in GITLAB_TOKEN_GENERATORS {
        for seed in 0..6 {
            let value = generated(gen, seed);
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports(&text, "SECRET_TOKEN", &value), "{gen}: {text:?}");
                let rule = entry(&text, "dlp_gitlab_token", DlpMode::Strict)
                    .unwrap_or_else(|| panic!("{gen}: {text:?}"));
                assert_eq!(rule["provider"], "gitlab");
                assert_eq!(rule["subtype"], "access_token");
            }
        }
    }
}

#[test]
fn legacy_and_routable_personal_access_tokens_are_reported_whole() {
    for gen in ["gitlab_pat", "gitlab_pat_routable"] {
        for seed in 0..8 {
            let value = generated(gen, seed);
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports(&text, "SECRET_TOKEN", &value), "{gen}: {text:?}");
                assert!(
                    entry(&text, "dlp_gitlab_pat", DlpMode::Strict).is_some(),
                    "{text:?}"
                );
            }
        }
    }
    // A sentence may end right after a legacy token.
    let value = generated("gitlab_pat", 3);
    let text = format!("Das neue Token lautet {value}.");
    assert!(reports(&text, "SECRET_TOKEN", &value), "{text:?}");
}

#[test]
fn gitlab_bodies_of_another_length_are_no_gitlab_token() {
    for seed in 0..8 {
        let mut values = Vec::new();
        for (prefix, length) in GITLAB_FIXED {
            values.push(format!("{prefix}{}", random(seed, BASE64URL, length - 1)));
            values.push(format!("{prefix}{}", random(seed, BASE64URL, length + 1)));
        }
        values.push(format!("glptt-{}", random(seed, "0123456789abcdef", 39)));
        values.push(format!("glptt-{}", random(seed, "0123456789abcdef", 41)));
        // Pipeline trigger tokens are lower-case hex.
        values.push(format!("glptt-{}", random(seed, "0123456789ABCDEF", 40)));
        values.push(format!("glcbt-64_{}", random(seed, BASE64URL, 19)));
        values.push(format!("glcbt-64_{}", random(seed, BASE64URL, 21)));
        for value in &values {
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", value);
                assert!(
                    entry(&text, "dlp_gitlab_token", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
        for value in [
            format!("glpat-{}", random(seed, BASE64URL, 19)),
            format!("glpat-{}", random(seed, BASE64URL, 21)),
            format!("glpat-{}", random(seed, BASE64URL, 38)),
        ] {
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(
                    entry(&text, "dlp_gitlab_pat", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
        for value in [
            format!("gloas-{}", random(seed, BASE64URL, 63)),
            format!("gloas-{}", random(seed, BASE64URL, 65)),
        ] {
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(
                    entry(&text, "dlp_gitlab_oauth_secret", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
    }
}

#[test]
fn a_broken_routable_suffix_is_no_routable_token() {
    for seed in 0..8 {
        let value = generated("gitlab_pat_routable", seed);
        let (head, tail) = value.rsplit_once('.').expect("routable token");
        for broken in [
            // Upper-case check value, a check value of 8 characters, no version.
            format!("{head}.{}", tail.to_uppercase()),
            format!("{head}.{}", &tail[..8]),
            format!("{head}.{}", &tail[2..]),
        ] {
            let text = format!("Hi Jo, here is the GitLab token for the mirror job: {broken}\n");
            assert!(
                entry(&text, "dlp_gitlab_pat", DlpMode::Strict).is_none(),
                "{text:?}"
            );
        }
        let runner = generated("gitlab_runner_token_routable", seed);
        let text = format!("token = \"{}X\"\n", runner);
        assert!(
            entry(&text, "dlp_gitlab_token", DlpMode::Strict).is_none(),
            "{text:?}"
        );
    }
}

#[test]
fn current_routable_runner_and_workspace_tokens_are_reported_whole() {
    for seed in 0..6 {
        for len in [27, 43, 120] {
            // Runner tokens (also created through a registration token) and
            // workspace tokens; `glrt-t<digit>_` is a payload of this shape too.
            for prefix in ["glrt-", "glrtr-", "glwt-", "glrt-t1_"] {
                let value = routable(prefix, seed, len);
                for carrier in GITLAB_CARRIERS {
                    let text = carrier.replace("{}", &value);
                    assert!(reports(&text, "SECRET_TOKEN", &value), "{text:?}");
                    let rule = entry(&text, "dlp_gitlab_token", DlpMode::Strict)
                        .unwrap_or_else(|| panic!("{text:?}"));
                    assert_eq!(rule["provider"], "gitlab");
                    assert_eq!(rule["subtype"], "access_token");
                }
            }
            let value = routable("glpat-", seed, len);
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports(&text, "SECRET_TOKEN", &value), "{text:?}");
                assert!(
                    entry(&text, "dlp_gitlab_pat", DlpMode::Strict).is_some(),
                    "{text:?}"
                );
            }
        }
        // A runner token created through a registration token, legacy length.
        let value = format!("glrtr-{}", random(seed, BASE64URL, 20));
        for carrier in GITLAB_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(reports(&text, "SECRET_TOKEN", &value), "{text:?}");
            assert!(
                entry(&text, "dlp_gitlab_token", DlpMode::Strict).is_some(),
                "{text:?}"
            );
        }
    }
    // A sentence may end right after a routable token.
    let value = routable("glwt-", 9, 40);
    let text = format!("Das Workspace-Token lautet {value}.");
    assert!(reports(&text, "SECRET_TOKEN", &value), "{text:?}");
}

#[test]
fn near_misses_of_the_current_routable_shape_are_no_gitlab_token() {
    for seed in 0..8 {
        let mut values = Vec::new();
        for prefix in ["glrt-", "glrtr-", "glwt-"] {
            let value = routable(prefix, seed, 40);
            let (head, tail) = value.rsplit_once('.').expect("routable token");
            values.extend([
                // Another version, an upper-case check value, a check value
                // of 8 or 10 characters, a payload of 26 characters.
                value.replace(".01.", ".02."),
                format!("{head}.{}", tail.to_uppercase()),
                format!("{head}.{}", &tail[..8]),
                format!("{head}.{tail}x"),
                routable(prefix, seed, 26),
            ]);
        }
        // Undocumented prefixes next to the documented ones, and a workspace
        // token without the routable suffix.
        for prefix in ["glwtr-", "glw-", "glrtrr-", "glrtx-"] {
            values.push(routable(prefix, seed, 40));
        }
        values.push(format!("glwt-{}", random(seed, BASE64URL, 20)));
        for value in &values {
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", value);
                assert!(
                    entry(&text, "dlp_gitlab_token", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
        let value = routable("glpat-", seed, 40);
        for broken in [value.replace(".01.", ".02."), routable("glpat-", seed, 26)] {
            for carrier in GITLAB_CARRIERS {
                let text = carrier.replace("{}", &broken);
                assert!(
                    entry(&text, "dlp_gitlab_pat", DlpMode::Strict).is_none(),
                    "{text:?}"
                );
            }
        }
    }
}

#[test]
fn gitlab_oauth_application_secrets_are_api_keys() {
    for seed in 0..8 {
        let value = generated("gitlab_oauth_app_secret", seed);
        assert_eq!(value.len(), 70, "{value}");
        for carrier in GITLAB_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(reports(&text, "API_KEY", &value), "{text:?}");
            let rule = entry(&text, "dlp_gitlab_oauth_secret", DlpMode::Strict)
                .unwrap_or_else(|| panic!("{text:?}"));
            assert_eq!(rule["provider"], "gitlab");
            assert_eq!(rule["subtype"], "secret_key");
            assert_eq!(rule["source_ref"], "gitleaks:gitlab-oauth-app-secret");
        }
    }
}

#[test]
fn gitlab_rules_have_format_strength_and_a_source() {
    for name in [
        "dlp_gitlab_pat",
        "dlp_gitlab_token",
        "dlp_gitlab_oauth_secret",
    ] {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == name)
            .unwrap_or_else(|| panic!("{name} must be registered"));
        assert_eq!(rule.meta.validator_strength, ValidatorStrength::Format);
        assert_eq!(rule.meta.provider, Some("gitlab"), "{name}");
        assert_ne!(rule.meta.source_ref, "ark", "{name}");
    }
}
