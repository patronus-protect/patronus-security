// SPDX-License-Identifier: GPL-3.0-only
//! The order of `DLP_PATTERNS` is observable behaviour: rules run in registry
//! order, the first matching rule sets the result class and `matched_rules`
//! lists matches in that order. Splitting the rule modules must keep it.
use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS, SecurityCategory, SecurityGateway, SecurityLevel,
};
use std::collections::HashSet;

const REGISTRY_ORDER: &[&str] = &[
    // secrets/providers
    "dlp_anthropic_key",
    "dlp_openai_key",
    "dlp_openai_legacy",
    "dlp_openai_svc",
    "dlp_huggingface",
    "dlp_groq_key",
    "dlp_xai_key",
    "dlp_replicate",
    "dlp_aws_access_key",
    "dlp_aws_secret_key",
    "dlp_google_api_key",
    "dlp_google_oauth_token",
    "dlp_gcp_client_secret",
    "dlp_github_token",
    "dlp_github_pat",
    "dlp_gitlab_pat",
    "dlp_gitlab_token",
    "dlp_gitlab_oauth_secret",
    "dlp_npm_token",
    "dlp_stripe_key",
    "dlp_stripe_webhook",
    "dlp_slack_token",
    "dlp_discord_token",
    // crypto
    "dlp_eth_private_key",
    "dlp_btc_wif",
    "dlp_private_key_block",
    "dlp_private_key_header",
    // credentials
    "dlp_jwt_token",
    "dlp_credential_in_url",
    "dlp_env_var_secret",
    "dlp_password_assignment",
    "dlp_generic_credential_assignment",
    "dlp_bearer_token",
    "dlp_basic_auth",
    "dlp_signed_url_signature",
    "dlp_session_cookie",
    "dlp_csrf_token",
    // hashes
    "dlp_password_hash",
    // credentials (URL userinfo runs after the hash rule)
    "dlp_url_userinfo_password",
    // identifiers
    "dlp_de_vat_id",
    "dlp_de_commercial_register_number",
    "dlp_de_facility_number_bsnr",
    "dlp_record_case_id",
    "dlp_record_contract_id",
    "dlp_record_claim_id",
    "dlp_record_order_id",
    "dlp_record_invoice_id",
    "dlp_project_id",
    "dlp_organization_id",
    // content
    "dlp_internal_business_metric",
    "dlp_database_dump_insert",
    "dlp_source_code_fence",
    "dlp_source_code_statement",
    "dlp_source_code_python_rust_assignment",
    "dlp_source_code_declaration",
    "dlp_source_code_import",
    "dlp_sql_statement",
    "dlp_sql_multiline_statement",
    "dlp_database_dump_header",
    "dlp_stacktrace_block",
    "dlp_structured_system_log",
];

#[test]
fn registry_keeps_rule_order_and_unique_ids() {
    let ids = DLP_PATTERNS
        .iter()
        .map(|pattern| pattern.name)
        .collect::<Vec<_>>();
    assert_eq!(ids, REGISTRY_ORDER);
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
}

#[test]
fn first_matching_rule_in_registry_order_sets_the_class() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    // The URL password comes first in the text, but the hash rule comes first in
    // the registry, so the result class is the hash group.
    let text = "DATABASE_DSN=postgres://app:Hx7rQ2pw@db.internal/app\n\
                password_hash = 5f4dcc3b5aa765d61d8327deb882cf99\n";
    let result = gateway
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result");
    assert_eq!(result.class_name, "PASSWORD_HASH");
    let labels = result
        .evidence_spans
        .iter()
        .map(|span| span.label.as_str())
        .collect::<Vec<_>>();
    assert_eq!(labels, ["CREDENTIAL", "PASSWORD_HASH"]);
    let rules = result.layers[0].details["matched_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["rule_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rules, ["dlp_password_hash", "dlp_url_userinfo_password"]);
}
