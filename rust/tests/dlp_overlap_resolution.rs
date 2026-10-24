// SPDX-License-Identifier: GPL-3.0-only
//! K08: overlap resolution. Overlapping secret findings keep one span, by tier
//! (provider > token > hash > credential > generic). A fixed-format match inside
//! a longer fixed-format value (a WIF-shaped run inside a Stripe key or a JWT)
//! is a substring artefact, and a value span that only adds quotes or a
//! trailing delimiter to a match of the same tier gives way to the tighter span.
//! Suppressed matches stay in `matched_rules` with `suppressed_by`. Between
//! categories, a DLP secret span owns its range: PII spans that overlap it
//! (a URL password read as e-mail local part, Slack token digits read as a
//! card number) are dropped from the PII result. Values are synthetic.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use patronus_ark::DlpMode;
use patronus_ark::{
    detectors::dlp::dlp::{overlap_tier, OverlapTier, DLP_PATTERNS},
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    EvidenceSpan, ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};

const SECRET_GROUPS: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        GeneratorSet::load(repo_root().join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

/// `template` with `<<secret:0>>` filled from `gen`/`seed`, and the value range in bytes.
fn fill(template: &str, gen: &str, seed: u64) -> (String, std::ops::Range<usize>) {
    let (text, spans) = materialize(generators(), template, &[SecretRecipe::new(gen, seed)])
        .expect("template must materialize");
    let (start, end) = spans[0];
    let byte = |char_index: usize| {
        text.char_indices()
            .nth(char_index)
            .map_or(text.len(), |(index, _)| index)
    };
    let range = byte(start)..byte(end);
    (text, range)
}

fn dlp_gateway() -> &'static SecurityGateway {
    static GATEWAY: OnceLock<SecurityGateway> = OnceLock::new();
    GATEWAY.get_or_init(|| {
        SecurityGateway::with_max_level(vec![SecurityCategory::Dlp], SecurityLevel::L1, None, false)
    })
}

fn scan(text: &str) -> SecurityScanResult {
    dlp_gateway()
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn secret_spans(result: &SecurityScanResult) -> Vec<&EvidenceSpan> {
    result
        .evidence_spans
        .iter()
        .filter(|span| SECRET_GROUPS.contains(&span.label.as_str()))
        .collect()
}

fn matched_rules(result: &SecurityScanResult) -> Vec<serde_json::Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default()
}

/// `(rule_id, start_byte, end_byte, suppressed_by)` of every rule match.
fn rule_matches(result: &SecurityScanResult) -> Vec<(String, usize, usize, Option<String>)> {
    matched_rules(result)
        .iter()
        .map(|rule| {
            (
                rule["rule_id"].as_str().unwrap().to_owned(),
                rule["start_byte"].as_u64().unwrap() as usize,
                rule["end_byte"].as_u64().unwrap() as usize,
                rule.get("suppressed_by")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned),
            )
        })
        .collect()
}

fn assert_no_secret_overlap(text: &str, result: &SecurityScanResult) {
    let spans = secret_spans(result);
    for (index, a) in spans.iter().enumerate() {
        for b in &spans[index + 1..] {
            assert!(
                a.end_byte <= b.start_byte || b.end_byte <= a.start_byte,
                "overlapping secret spans {:?}/{:?} and {:?}/{:?} in {text:?}",
                a.label,
                (a.start_byte, a.end_byte),
                b.label,
                (b.start_byte, b.end_byte)
            );
        }
    }
}

/// The only secret span of `template` filled with `gen` is the value, labelled
/// `label` and attributed to `winner`; `loser` matched as well and names the
/// winner in `suppressed_by`.
fn assert_resolved(template: &str, gen: &str, seed: u64, label: &str, winner: &str, loser: &str) {
    let (text, value) = fill(template, gen, seed);
    let result = scan(&text);
    let spans = secret_spans(&result);
    assert_eq!(
        spans
            .iter()
            .map(|span| (span.label.as_str(), span.start_byte..span.end_byte))
            .collect::<Vec<_>>(),
        vec![(label, value.clone())],
        "{text:?}: {:#?}",
        result.evidence_spans
    );
    let matches = rule_matches(&result);
    assert!(
        matches
            .iter()
            .any(|(rule, start, end, suppressed)| rule == winner
                && (*start..*end) == value
                && suppressed.is_none()),
        "{winner} must win in {text:?}: {matches:?}"
    );
    assert!(
        matches
            .iter()
            .any(|(rule, _, _, suppressed)| rule == loser && suppressed.as_deref() == Some(winner)),
        "{loser} must be suppressed by {winner} in {text:?}: {matches:?}"
    );
}

#[test]
fn every_secret_rule_has_a_tier_and_no_other_rule_has_one() {
    for pattern in DLP_PATTERNS {
        let tier = overlap_tier(pattern.name);
        assert_eq!(
            tier.is_some(),
            SECRET_GROUPS.contains(&pattern.entity_group),
            "{}: tier {tier:?} for group {}",
            pattern.name,
            pattern.entity_group
        );
    }
    assert_eq!(overlap_tier("dlp_no_such_rule"), None);
}

#[test]
fn tiers_follow_provider_token_hash_credential_generic() {
    let expected = [
        ("dlp_anthropic_key", OverlapTier::Provider),
        ("dlp_aws_secret_key", OverlapTier::Provider),
        ("dlp_github_pat", OverlapTier::Provider),
        ("dlp_slack_token", OverlapTier::Provider),
        ("dlp_stripe_key", OverlapTier::Provider),
        ("dlp_btc_wif", OverlapTier::Provider),
        ("dlp_private_key_block", OverlapTier::Provider),
        ("dlp_jwt_token", OverlapTier::Token),
        ("dlp_bearer_token", OverlapTier::Token),
        ("dlp_csrf_token", OverlapTier::Token),
        ("dlp_session_cookie", OverlapTier::Token),
        ("dlp_signed_url_signature", OverlapTier::Token),
        ("dlp_password_hash", OverlapTier::Hash),
        ("dlp_url_userinfo_password", OverlapTier::Credential),
        ("dlp_url_userinfo_token", OverlapTier::Token),
        ("dlp_basic_auth", OverlapTier::Credential),
        ("dlp_credential_in_url", OverlapTier::Credential),
        ("dlp_connection_string_password", OverlapTier::Credential),
        ("dlp_ldap_bind_password", OverlapTier::Credential),
        ("dlp_env_var_secret", OverlapTier::Generic),
        ("dlp_password_assignment", OverlapTier::Generic),
        ("dlp_generic_credential_assignment", OverlapTier::Generic),
    ];
    for (rule, tier) in expected {
        assert_eq!(overlap_tier(rule), Some(tier), "{rule}");
    }
    let order = [
        OverlapTier::Provider,
        OverlapTier::Token,
        OverlapTier::Hash,
        OverlapTier::Credential,
        OverlapTier::Generic,
    ];
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        order.map(OverlapTier::as_str),
        ["provider", "token", "hash", "credential", "generic"]
    );
}

#[test]
fn provider_and_token_spans_win_over_quoted_generic_values() {
    assert_resolved(
        "ENV STRIPE_SECRET_KEY=\"<<secret:0>>\"\n",
        "stripe_secret_test_long",
        15,
        "PAYMENT_KEY",
        "dlp_stripe_key",
        "dlp_env_var_secret",
    );
    assert_resolved(
        "# Sitzung des Abgleichdienstes\nSESSION_TOKEN='<<secret:0>>'\n",
        "jwt_signed_hs256",
        16,
        "SECRET_TOKEN",
        "dlp_jwt_token",
        "dlp_env_var_secret",
    );
    assert_resolved(
        "export ANTHROPIC_API_KEY=\"<<secret:0>>\"\n",
        "anthropic_api_key",
        17,
        "API_KEY",
        "dlp_anthropic_key",
        "dlp_env_var_secret",
    );
}

#[test]
fn same_range_provider_match_keeps_its_label_alone() {
    let (text, value) = fill("SLACK_BOT_TOKEN=<<secret:0>>\n", "slack_bot_token", 17);
    let result = scan(&text);
    let spans = secret_spans(&result);
    assert_eq!(spans.len(), 1, "{:#?}", result.evidence_spans);
    assert_eq!(spans[0].label, "SECRET_TOKEN");
    assert_eq!(spans[0].start_byte..spans[0].end_byte, value);
    assert!(rule_matches(&result)
        .iter()
        .any(|(rule, _, _, suppressed)| {
            rule == "dlp_env_var_secret" && suppressed.as_deref() == Some("dlp_slack_token")
        }));
}

/// A generic key that is the userinfo of a URL (`https://token:…@`) belongs to
/// the URL credential: the URL password is the span, and the generic
/// assignment, which would report the rest of the URL, does not match.
#[test]
fn url_userinfo_credential_owns_a_generic_key_in_the_url() {
    for (template, seed) in [
        (
            "git remote set-url origin https://token:<<secret:0>>@bitbucket.org/acme/repo.git\n",
            31,
        ),
        (
            "[remote \"origin\"]\n  url = https://token:<<secret:0>>@git.example.com/team/app.git\n",
            32,
        ),
    ] {
        let (text, value) = fill(template, "generic_api_secret", seed);
        let result = scan(&text);
        let spans = secret_spans(&result);
        assert_eq!(
            spans
                .iter()
                .map(|span| (span.label.as_str(), span.start_byte..span.end_byte))
                .collect::<Vec<_>>(),
            vec![("CREDENTIAL", value.clone())],
            "{text:?}"
        );
        let matches = rule_matches(&result);
        assert_eq!(
            matches,
            vec![(
                "dlp_url_userinfo_password".to_owned(),
                value.start,
                value.end,
                None
            )],
            "{text:?}"
        );
    }
    // Without a URL password the key still belongs to the URL: no finding.
    for text in [
        "git remote set-url origin https://token:@bitbucket.org/acme/repo.git\n",
        "url = https://password:@git.example.com/team/app.git\n",
    ] {
        let result = scan(text);
        assert!(
            result.evidence_spans.is_empty(),
            "{text:?}: {:#?}",
            result.evidence_spans
        );
    }
    // The same key outside a URL stays a generic assignment.
    let (text, value) = fill("token: <<secret:0>>\n", "generic_api_secret", 33);
    let spans = secret_spans(&scan(&text))
        .iter()
        .map(|span| span.start_byte..span.end_byte)
        .collect::<Vec<_>>();
    assert_eq!(spans, vec![value]);
}

#[test]
fn password_hash_wins_over_a_credential_around_it() {
    assert_resolved(
        "password: passwd_hash=<<secret:0>>\n",
        "bcrypt_2b_hash",
        18,
        "PASSWORD_HASH",
        "dlp_password_hash",
        "dlp_password_assignment",
    );
}

#[test]
fn generic_rules_on_the_same_quoted_value_keep_one_span() {
    // F-GEN2: env_var_secret reports the value without its quotes, so both
    // generic rules match the same span and the first in registry order wins.
    for template in [
        "export CLIENT_SECRET='<<secret:0>>'\n",
        "$ export CLIENT_SECRET=\"<<secret:0>>\"\n$ ./bin/sync --dry-run\n",
    ] {
        assert_resolved(
            template,
            "generic_api_secret",
            14,
            "CREDENTIAL",
            "dlp_env_var_secret",
            "dlp_generic_credential_assignment",
        );
    }
}

#[test]
fn quoted_value_of_a_single_rule_is_the_value_span() {
    // env_var_secret reports the value without the quotes (F-GEN2); since T09
    // password_assignment takes the compound key as well and yields to it on
    // the same span.
    let (text, value) = fill("export DB_PASSWORD='<<secret:0>>'\n", "password", 41);
    let result = scan(&text);
    let spans = secret_spans(&result);
    assert_eq!(spans.len(), 1, "{:#?}", result.evidence_spans);
    assert_eq!(spans[0].start_byte, value.start);
    assert_eq!(spans[0].end_byte, value.end);
    for (rule_id, start, end, suppressed) in rule_matches(&result) {
        assert_eq!((start, end), (value.start, value.end), "{rule_id}");
        match rule_id.as_str() {
            "dlp_env_var_secret" => assert_eq!(suppressed, None),
            "dlp_password_assignment" => {
                assert_eq!(suppressed.as_deref(), Some("dlp_env_var_secret"))
            }
            other => panic!("unexpected rule {other}"),
        }
    }
}

#[test]
fn substring_artefacts_inside_fixed_format_values_are_suppressed() {
    // Long Stripe test keys, Google OAuth tokens and JWTs contain 51-character
    // Base58 runs that start like WIF keys. Such a run is part of the value; the
    // Base58Check validator rejects almost all of them.
    let carriers = [
        (
            "ENV STRIPE_SECRET_KEY=<<secret:0>>\n",
            "stripe_secret_test_long",
        ),
        (
            "lager.google-access-token=<<secret:0>>\n",
            "google_oauth_access_token",
        ),
        ("Authorization: Bearer <<secret:0>>\n", "jwt_signed_rs256"),
    ];
    for (template, gen) in carriers {
        for seed in 0..300 {
            let (text, value) = fill(template, gen, seed);
            let result = scan(&text);
            assert_no_secret_overlap(&text, &result);
            assert!(
                result
                    .evidence_spans
                    .iter()
                    .all(|span| span.label != "CRYPTO_KEY"),
                "{text:?}: {:#?}",
                result.evidence_spans
            );
            assert!(
                result
                    .evidence_spans
                    .iter()
                    .any(|span| (span.start_byte..span.end_byte) == value),
                "{gen}/{seed}: value span missing in {text:?}: {:#?}",
                result.evidence_spans
            );
        }
    }

    // A run that passes the checksum is still an artefact of the longer value:
    // a valid WIF key between non-Base58 characters in a Stripe key body. Glued
    // to the digits around it, it is no whole token, so the WIF rule does not
    // match at all (T01).
    for (seed, gen) in [
        (11, "btc_wif_mainnet_uncompressed"),
        (12, "btc_wif_mainnet_compressed"),
    ] {
        let (wif, _) = fill("<<secret:0>>", gen, seed);
        let (stripe, _) = fill("<<secret:0>>", "stripe_secret_test_long", seed);
        let body = format!("0{wif}0");
        let key = format!("{}{body}{}", &stripe[..18], &stripe[18 + body.len()..]);
        assert_eq!(key.len(), stripe.len());
        let text = format!("ENV STRIPE_SECRET_KEY={key}\n");
        let result = scan(&text);
        let spans = secret_spans(&result);
        assert_eq!(spans.len(), 1, "{text:?}: {:#?}", result.evidence_spans);
        assert_eq!(spans[0].text, key);
        assert!(
            rule_matches(&result)
                .iter()
                .all(|(rule, ..)| rule != "dlp_btc_wif"),
            "WIF run inside a token matched in {text:?}"
        );
    }
}

#[test]
fn a_wif_key_inside_a_longer_generic_value_gives_way_to_the_generic_value() {
    // A keywordless WIF-shaped run that is only part of a longer assigned value is
    // not a key of its own; the assignment keeps the whole value.
    let (wif, _) = fill("<<secret:0>>", "btc_wif_mainnet_compressed", 51);
    let text = format!("client_secret = \"v2.{wif}.rotated\"\n");
    let result = scan(&text);
    let value = format!("v2.{wif}.rotated");
    let spans = secret_spans(&result);
    assert_eq!(spans.len(), 1, "{:#?}", result.evidence_spans);
    assert_eq!(spans[0].text, value);
    assert_eq!(spans[0].label, "CREDENTIAL");
}

#[test]
fn a_standalone_wif_key_and_a_secret_next_to_it_both_stay() {
    let (wif, _) = fill("<<secret:0>>", "btc_wif_mainnet_compressed", 52);
    let (token, _) = fill("<<secret:0>>", "github_ghp_token", 53);
    let text = format!("wallet: {wif}\nGITHUB_TOKEN={token}\n");
    let result = scan(&text);
    let labels = secret_spans(&result)
        .iter()
        .map(|span| (span.label.clone(), span.text.clone()))
        .collect::<Vec<_>>();
    assert!(labels.contains(&("CRYPTO_KEY".into(), wif)), "{labels:?}");
    assert!(
        labels.contains(&("SECRET_TOKEN".into(), token)),
        "{labels:?}"
    );
}

#[test]
fn content_classes_keep_their_spans_over_secrets() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    let mut gates = ScanGateMatrix::default();
    for pattern in DLP_PATTERNS {
        if pattern.entity_group == "dlp.content.source_code" {
            gates.set_rule(pattern.name, true);
        }
    }
    gateway.set_execution_gates(gates);
    let (text, value) = fill(
        "import os\n\nclient = Client(api_key=\"<<secret:0>>\")\n",
        "openai_project_key",
        61,
    );
    let result = gateway
        .scan_category(SecurityCategory::Dlp, &text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .unwrap();
    assert!(result
        .evidence_spans
        .iter()
        .any(|span| span.label == "API_KEY" && (span.start_byte..span.end_byte) == value));
    assert!(
        result
            .evidence_spans
            .iter()
            .any(|span| span.label == "dlp.content.source_code"),
        "{:#?}",
        result.evidence_spans
    );
}

#[test]
fn scored_modes_resolve_overlaps_like_strict() {
    let (text, value) = fill(
        "ENV STRIPE_SECRET_KEY=\"<<secret:0>>\"\n",
        "stripe_secret_test_long",
        15,
    );
    for mode in [DlpMode::Balanced, DlpMode::Recall] {
        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::Dlp],
            SecurityLevel::L1,
            None,
            false,
        );
        gateway.set_execution_gates(ScanGateMatrix {
            dlp_mode: mode,
            ..ScanGateMatrix::default()
        });
        let result = gateway
            .scan_category(SecurityCategory::Dlp, &text)
            .into_iter()
            .find(|result| result.model == "native:dlp")
            .unwrap();
        assert_no_secret_overlap(&text, &result);
        let spans = secret_spans(&result);
        assert!(spans.len() <= 1, "{mode:?}: {:#?}", result.evidence_spans);
        assert!(
            spans.iter().all(
                |span| span.label == "PAYMENT_KEY" && (span.start_byte..span.end_byte) == value
            ),
            "{mode:?}: {:#?}",
            result.evidence_spans
        );
    }
}

#[test]
fn golden_and_fixture_texts_never_report_overlapping_secret_spans() {
    let fixtures: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("rust/tests/fixtures/l1_bilingual_rules.json"))
            .unwrap(),
    )
    .unwrap();
    let mut texts = fixtures
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["category"] == "dlp")
        .flat_map(|case| ["de", "en"].map(|language| case[language].as_str().unwrap().to_owned()))
        .collect::<Vec<_>>();
    let goldens = std::fs::read_to_string(
        repo_root().join("python/patronus_ark/benchmark_data/dlp_l1.jsonl"),
    )
    .unwrap();
    for line in goldens.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let text = match (row.get("template"), row.get("secrets")) {
            (Some(template), Some(secrets)) => {
                let recipes = secrets
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(
                        |secret| match secret.get("fill").and_then(|fill| fill.as_str()) {
                            Some(fill) => SecretRecipe::filled(
                                secret["gen"].as_str().unwrap(),
                                secret["seed"].as_u64().unwrap(),
                                fill,
                            ),
                            None => SecretRecipe::new(
                                secret["gen"].as_str().unwrap(),
                                secret["seed"].as_u64().unwrap(),
                            ),
                        },
                    )
                    .collect::<Vec<_>>();
                match materialize(generators(), template.as_str().unwrap(), &recipes) {
                    Ok((text, _)) => text,
                    // Split secrets are covered by the golden eval.
                    Err(_) => continue,
                }
            }
            _ => row["text"].as_str().unwrap().to_owned(),
        };
        texts.push(text);
    }
    assert!(texts.len() > 500);
    for text in &texts {
        assert_no_secret_overlap(text, &scan(text));
    }
}

// ── DLP vs. PII double labels ────────────────────────────────────────────

fn both_gateway() -> &'static SecurityGateway {
    static GATEWAY: OnceLock<SecurityGateway> = OnceLock::new();
    GATEWAY.get_or_init(|| {
        SecurityGateway::with_max_level(
            vec![SecurityCategory::Dlp, SecurityCategory::Pii],
            SecurityLevel::L1,
            None,
            false,
        )
    })
}

fn spans_of(results: &[SecurityScanResult], category: &str) -> Vec<EvidenceSpan> {
    results
        .iter()
        .filter(|result| result.category == category)
        .flat_map(|result| result.evidence_spans.clone())
        .collect()
}

#[test]
fn url_password_is_not_also_reported_as_an_email_address() {
    for (template, seed) in [
        (
            "DATABASE_URL=postgres://app:<<secret:0>>@db.internal:5432/app\n",
            71,
        ),
        (
            "git:\n  remote: https://deploy:<<secret:0>>@git.example.com/team/app.git\n",
            72,
        ),
        (
            "Die Datenbank erreichst du unter mysql://report:<<secret:0>>@10.0.4.12/berichte.",
            73,
        ),
    ] {
        let (text, value) = fill(template, "url_userinfo_password", seed);
        let pii_alone = SecurityGateway::with_max_level(
            vec![SecurityCategory::Pii],
            SecurityLevel::L1,
            None,
            false,
        )
        .scan_category(SecurityCategory::Pii, &text);
        let results =
            both_gateway().scan_categories(&[SecurityCategory::Dlp, SecurityCategory::Pii], &text);
        let dlp = spans_of(&results, "dlp");
        let pii = spans_of(&results, "pii");
        assert!(
            dlp.iter()
                .any(|span| span.label == "CREDENTIAL" && (span.start_byte..span.end_byte) == value),
            "{text:?}: {dlp:#?}"
        );
        assert!(
            pii.iter()
                .all(|span| span.end_byte <= value.start || value.end <= span.start_byte),
            "PII span overlaps the URL password in {text:?}: {pii:#?}"
        );
        // A PII-only scan has no DLP span to defer to and stays unchanged.
        let alone = spans_of(&pii_alone, "pii");
        assert!(
            alone.iter().all(|span| pii.contains(span)
                || span.start_byte < value.end && value.start < span.end_byte),
            "{text:?}: {alone:#?} vs {pii:#?}"
        );
    }
}

#[test]
fn pii_outside_secret_spans_stays_reported() {
    let (text, value) = fill(
        "Kontakt: max.mustermann@example.org, DB: postgres://app:<<secret:0>>@db.internal/app\n",
        "url_userinfo_password",
        19,
    );
    let results =
        both_gateway().scan_categories(&[SecurityCategory::Dlp, SecurityCategory::Pii], &text);
    let pii = spans_of(&results, "pii");
    assert!(
        pii.iter()
            .any(|span| span.label == "EMAIL" && span.text == "max.mustermann@example.org"),
        "{pii:#?}"
    );
    assert!(pii
        .iter()
        .all(|span| span.end_byte <= value.start || value.end <= span.start_byte));
}

#[test]
fn digits_inside_provider_tokens_are_not_pii() {
    let mut checked = 0;
    for seed in 0..200 {
        let (text, value) = fill("SLACK_BOT_TOKEN=<<secret:0>>\n", "slack_bot_token", seed);
        let results =
            both_gateway().scan_categories(&[SecurityCategory::Dlp, SecurityCategory::Pii], &text);
        let dlp = spans_of(&results, "dlp");
        if !dlp
            .iter()
            .any(|span| (span.start_byte..span.end_byte) == value)
        {
            continue;
        }
        checked += 1;
        let pii = spans_of(&results, "pii");
        assert!(
            pii.iter()
                .all(|span| span.end_byte <= value.start || value.end <= span.start_byte),
            "{text:?}: {pii:#?}"
        );
    }
    assert!(checked > 150, "{checked}");
}

#[test]
fn pii_decision_is_kept_when_its_span_defers_to_dlp() {
    let (text, _) = fill(
        "DATABASE_URL=postgres://app:<<secret:0>>@db.internal:5432/app\n",
        "url_userinfo_password",
        74,
    );
    let pii_alone = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    )
    .scan_category(SecurityCategory::Pii, &text);
    let results =
        both_gateway().scan_categories(&[SecurityCategory::Dlp, SecurityCategory::Pii], &text);
    let class = |results: &[SecurityScanResult]| {
        results
            .iter()
            .filter(|result| result.category == "pii")
            .map(|result| (result.model.clone(), result.class_name.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(class(&pii_alone), class(&results));
}
