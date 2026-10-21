// SPDX-License-Identifier: GPL-3.0-only
//! K09: taxonomy v2. The entity groups stay as they were; every credential/
//! secret rule names a subtype of its group, and `matched_rules` reports it.
//! Connection strings, webhook URLs, auth URLs, OTP secrets and seed phrases
//! are subtypes of existing groups, not groups of their own. Token values are
//! synthetic and assembled at test time.

use std::collections::BTreeSet;

use patronus_ark::{
    detectors::dlp::dlp::{SecretSubtype, DLP_PATTERNS},
    golden_recipes::SplitMix64,
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
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

/// The entity groups of the DLP rules before K09; taxonomy v2 adds none.
const GROUPS_V1: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
    "dlp.content.database_dump",
    "dlp.content.source_code",
    "dlp.content.sql",
    "dlp.content.system_log",
    "dlp.de.commercial_register_number",
    "dlp.de.facility_number_bsnr",
    "dlp.de.vat_id",
    "dlp.internal.business_metric",
    "dlp.organization_id",
    "dlp.project_id",
    "dlp.record.case_id",
    "dlp.record.claim_id",
    "dlp.record.contract_id",
    "dlp.record.invoice_id",
    "dlp.record.order_id",
];

/// Subtype names and the existing groups they may appear in.
const SUBTYPES: &[(&str, &[&str])] = &[
    ("api_key", &["API_KEY", "CLOUD_KEY", "PAYMENT_KEY"]),
    ("access_token", &["SECRET_TOKEN", "CLOUD_KEY"]),
    ("secret_key", &["API_KEY", "CLOUD_KEY", "PAYMENT_KEY"]),
    ("private_key", &["PRIVATE_KEY", "CRYPTO_KEY"]),
    ("seed_phrase", &["CRYPTO_KEY"]),
    ("password", &["CREDENTIAL"]),
    ("password_hash", &["PASSWORD_HASH"]),
    ("generic_secret", &["CREDENTIAL"]),
    ("session_token", &["SECRET_TOKEN", "CREDENTIAL"]),
    ("signature", &["CREDENTIAL"]),
    ("connection_string", &["CREDENTIAL"]),
    ("auth_url", &["CREDENTIAL"]),
    ("webhook_url", &["SECRET_TOKEN"]),
    ("otp_secret", &["CREDENTIAL"]),
];

/// The kinds that K09 was asked to add as groups and their home groups.
const K09_KINDS: &[(&str, &str)] = &[
    ("connection_string", "CREDENTIAL"),
    ("webhook_url", "SECRET_TOKEN"),
    ("auth_url", "CREDENTIAL"),
    ("otp_secret", "CREDENTIAL"),
    ("seed_phrase", "CRYPTO_KEY"),
];

/// Subtype of every credential/secret rule.
const RULE_SUBTYPES: &[(&str, &str)] = &[
    ("dlp_anthropic_key", "api_key"),
    ("dlp_openai_key", "api_key"),
    ("dlp_openai_legacy", "api_key"),
    ("dlp_openai_svc", "api_key"),
    ("dlp_huggingface", "api_key"),
    ("dlp_groq_key", "api_key"),
    ("dlp_xai_key", "api_key"),
    ("dlp_replicate", "api_key"),
    ("dlp_aws_access_key", "api_key"),
    ("dlp_aws_secret_key", "secret_key"),
    ("dlp_google_api_key", "api_key"),
    ("dlp_google_oauth_token", "access_token"),
    ("dlp_gcp_client_secret", "secret_key"),
    ("dlp_github_token", "access_token"),
    ("dlp_github_pat", "access_token"),
    ("dlp_gitlab_pat", "access_token"),
    ("dlp_npm_token", "access_token"),
    ("dlp_stripe_key", "api_key"),
    ("dlp_stripe_webhook", "secret_key"),
    ("dlp_slack_token", "access_token"),
    ("dlp_discord_token", "access_token"),
    ("dlp_eth_private_key", "private_key"),
    ("dlp_btc_wif", "private_key"),
    ("dlp_private_key_block", "private_key"),
    ("dlp_private_key_header", "private_key"),
    ("dlp_jwt_token", "access_token"),
    ("dlp_credential_in_url", "auth_url"),
    ("dlp_env_var_secret", "generic_secret"),
    ("dlp_password_assignment", "password"),
    ("dlp_generic_credential_assignment", "generic_secret"),
    ("dlp_bearer_token", "access_token"),
    ("dlp_basic_auth", "password"),
    ("dlp_signed_url_signature", "signature"),
    ("dlp_session_cookie", "session_token"),
    ("dlp_csrf_token", "session_token"),
    ("dlp_password_hash", "password_hash"),
    ("dlp_url_userinfo_password", "password"),
];

fn scan_with(gates: Option<ScanGateMatrix>, text: &str) -> SecurityScanResult {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    if let Some(gates) = gates {
        gateway.set_execution_gates(gates);
    }
    gateway
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn scan(text: &str) -> SecurityScanResult {
    scan_with(None, text)
}

fn matched_rule(result: &SecurityScanResult, rule_id: &str) -> serde_json::Value {
    result.layers[0].details["matched_rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["rule_id"] == rule_id)
        .cloned()
        .unwrap_or_else(|| panic!("{rule_id} must match"))
}

fn random_body(seed: u64, alphabet: &str, len: usize) -> String {
    let alphabet = alphabet.as_bytes();
    let mut rng = SplitMix64::new(seed);
    (0..len)
        .map(|_| alphabet[(rng.next_u64() % alphabet.len() as u64) as usize] as char)
        .collect()
}

const BASE62: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[test]
fn entity_groups_are_unchanged() {
    let groups: BTreeSet<_> = DLP_PATTERNS.iter().map(|rule| rule.entity_group).collect();
    assert_eq!(groups, GROUPS_V1.iter().copied().collect());
    for (kind, _) in K09_KINDS {
        let group = kind.to_ascii_uppercase();
        assert!(
            DLP_PATTERNS.iter().all(|rule| rule.entity_group != group),
            "{group} must stay a subtype, not a group"
        );
    }
}

#[test]
fn subtype_names_and_groups_are_stable() {
    let declared: Vec<_> = SecretSubtype::ALL
        .iter()
        .map(|subtype| (subtype.as_str(), subtype.groups()))
        .collect();
    assert_eq!(declared, SUBTYPES.to_vec());
    for (name, groups) in SUBTYPES {
        assert!(!groups.is_empty(), "{name}");
        for group in *groups {
            assert!(SECRET_GROUPS.contains(group), "{name}: {group}");
        }
    }
}

#[test]
fn k09_kinds_are_subtypes_of_existing_groups() {
    for (kind, home) in K09_KINDS {
        let subtype = SecretSubtype::ALL
            .iter()
            .find(|subtype| subtype.as_str() == *kind)
            .unwrap_or_else(|| panic!("{kind} must be a subtype"));
        assert_eq!(subtype.groups(), &[*home], "{kind}");
    }
}

#[test]
fn every_secret_rule_declares_a_subtype_of_its_group() {
    for rule in DLP_PATTERNS {
        let subtype = rule.meta.subtype;
        if SECRET_GROUPS.contains(&rule.entity_group) {
            let subtype = subtype.unwrap_or_else(|| panic!("{}: subtype", rule.name));
            assert!(
                subtype.groups().contains(&rule.entity_group),
                "{}: subtype {} is not one of {}",
                rule.name,
                subtype.as_str(),
                rule.entity_group
            );
        } else {
            assert!(subtype.is_none(), "{}: identifier/content rule", rule.name);
        }
    }
    let declared: Vec<_> = DLP_PATTERNS
        .iter()
        .filter_map(|rule| Some((rule.name, rule.meta.subtype?.as_str())))
        .collect();
    let expected: BTreeSet<_> = RULE_SUBTYPES.iter().copied().collect();
    assert_eq!(declared.len(), RULE_SUBTYPES.len());
    assert_eq!(declared.into_iter().collect::<BTreeSet<_>>(), expected);
}

#[test]
fn matched_rules_report_the_subtype() {
    let cases = [
        (
            format!("GITHUB_TOKEN={}{}", "ghp_", random_body(21, BASE62, 36)),
            "dlp_github_token",
            "access_token",
            Some("github"),
        ),
        (
            format!("STRIPE_KEY={}{}", "sk_live_", random_body(22, BASE62, 24)),
            "dlp_stripe_key",
            "api_key",
            Some("stripe"),
        ),
        (
            "Das Passwort lautet Kx9vQ2mLp7Rt".to_string(),
            "dlp_password_assignment",
            "password",
            None,
        ),
        (
            "The password is Rw7nTq3zLm8v".to_string(),
            "dlp_password_assignment",
            "password",
            None,
        ),
        (
            format!(
                "callback: https://app.example.net/auth/verify?token={}",
                random_body(23, BASE62, 32)
            ),
            "dlp_credential_in_url",
            "auth_url",
            None,
        ),
    ];
    for (text, rule_id, subtype, provider) in cases {
        let rule = matched_rule(&scan(&text), rule_id);
        assert_eq!(rule["subtype"], subtype, "{rule_id}: {rule}");
        assert_eq!(
            rule.get("provider").and_then(|p| p.as_str()),
            provider,
            "{rule_id}: {rule}"
        );
    }
}

#[test]
fn identifier_and_content_rules_report_no_subtype() {
    let text = "Fehlerprotokoll:\nTraceback (most recent call last):\n  File \"app.py\", line 3\n";
    let result = scan_with(Some(ScanGateMatrix::all_enabled()), text);
    let rule = matched_rule(&result, "dlp_stacktrace_block");
    assert!(rule.get("subtype").is_none(), "{rule}");
}

#[test]
fn spans_keep_the_group_label() {
    let text = format!("GITHUB_TOKEN={}{}", "ghp_", random_body(24, BASE62, 36));
    let result = scan(&text);
    assert_eq!(result.class_name, "SECRET_TOKEN");
    assert!(result
        .evidence_spans
        .iter()
        .all(|span| span.label == "SECRET_TOKEN"));
}
