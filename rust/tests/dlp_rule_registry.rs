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
    "dlp_perplexity_key",
    "dlp_cohere_key",
    "dlp_openrouter_key",
    "dlp_deepseek_key",
    "dlp_fireworks_key",
    "dlp_langsmith_key",
    "dlp_pinecone_key",
    "dlp_elevenlabs_key",
    "dlp_azure_openai_key",
    "dlp_wandb_key",
    "dlp_assemblyai_key",
    "dlp_deepgram_key",
    "dlp_aws_access_key",
    "dlp_aws_secret_key",
    "dlp_google_api_key",
    "dlp_google_oauth_token",
    "dlp_gcp_client_secret",
    "dlp_azure_storage_account_key",
    "dlp_azure_entra_client_secret",
    "dlp_alibaba_access_key_id",
    "dlp_alibaba_secret_key",
    "dlp_aws_bedrock_api_key",
    "dlp_ibm_cloud_api_key",
    "dlp_atlassian_api_token",
    "dlp_atlassian_legacy_api_token",
    "dlp_notion_api_token",
    "dlp_linear_api_key",
    "dlp_linear_client_secret",
    "dlp_airtable_pat",
    "dlp_airtable_api_key",
    "dlp_postman_api_key",
    "dlp_mapbox_secret_token",
    "dlp_github_token",
    "dlp_github_pat",
    "dlp_gitlab_pat",
    "dlp_gitlab_token",
    "dlp_gitlab_oauth_secret",
    "dlp_npm_token",
    "dlp_dockerhub_token",
    "dlp_pypi_token",
    "dlp_rubygems_token",
    "dlp_cratesio_token",
    "dlp_packagist_token",
    "dlp_jfrog_token",
    "dlp_terraform_cloud_token",
    "dlp_pulumi_token",
    "dlp_vault_token",
    "dlp_vault_legacy_token",
    "dlp_doppler_token",
    "dlp_bitbucket_client_secret",
    "dlp_azure_devops_pat",
    "dlp_azure_devops_legacy_pat",
    "dlp_circleci_token",
    "dlp_circleci_legacy_token",
    "dlp_travis_token",
    "dlp_vercel_token",
    "dlp_vercel_legacy_token",
    "dlp_netlify_token",
    "dlp_netlify_legacy_token",
    "dlp_flyio_token",
    "dlp_flyio_macaroon_token",
    "dlp_heroku_api_key",
    "dlp_heroku_legacy_api_key",
    "dlp_render_api_key",
    "dlp_railway_token",
    "dlp_cloudflare_api_key",
    "dlp_cloudflare_origin_ca_key",
    "dlp_digitalocean_token",
    "dlp_datadog_api_key",
    "dlp_newrelic_user_api_key",
    "dlp_newrelic_insert_key",
    "dlp_newrelic_license_key",
    "dlp_newrelic_legacy_license_key",
    "dlp_sentry_user_token",
    "dlp_sentry_org_token",
    "dlp_sentry_auth_token",
    "dlp_sentry_dsn_secret",
    "dlp_grafana_api_key",
    "dlp_grafana_cloud_token",
    "dlp_grafana_service_account_token",
    "dlp_dynatrace_token",
    "dlp_splunk_hec_token",
    "dlp_elastic_api_key",
    "dlp_honeycomb_api_key",
    "dlp_pagerduty_api_key",
    "dlp_stripe_key",
    "dlp_stripe_webhook",
    "dlp_slack_token",
    "dlp_slack_app_token",
    "dlp_discord_token",
    // crypto
    "dlp_eth_private_key",
    "dlp_btc_wif",
    "dlp_bip32_extended_private_key",
    "dlp_eth_keystore_ciphertext",
    "dlp_solana_keypair",
    "dlp_electrum_seed",
    "dlp_monero_seed",
    "dlp_cardano_signing_key",
    "dlp_bip39_seed_phrase",
    "dlp_private_key_block",
    "dlp_private_key_header",
    "dlp_jwk_private_key",
    "dlp_wireguard_private_key",
    "dlp_openvpn_static_key",
    "dlp_ipsec_psk",
    "dlp_symmetric_key",
    "dlp_laravel_app_key",
    "dlp_django_secret_key",
    "dlp_rails_secret_key_base",
    // credentials
    "dlp_jwt_token",
    "dlp_credential_in_url",
    "dlp_auth_url_token",
    "dlp_otp_secret",
    "dlp_env_var_secret",
    "dlp_password_assignment",
    "dlp_generic_credential_assignment",
    "dlp_prose_password",
    "dlp_prose_secret",
    "dlp_bearer_token",
    "dlp_basic_auth",
    "dlp_signed_url_signature",
    "dlp_session_cookie",
    "dlp_csrf_token",
    // hashes
    "dlp_password_hash",
    // credentials (URL userinfo runs after the hash rule)
    "dlp_url_userinfo_password",
    "dlp_url_userinfo_token",
    // credentials (connection strings, G01)
    "dlp_connection_string_password",
    "dlp_ldap_bind_password",
    // credentials (CLI command lines, G03)
    "dlp_cli_password",
    // credentials (credential files, G04)
    "dlp_netrc_password",
    "dlp_docker_config_auth",
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
    "dlp_document_legal_privileged",
    "dlp_document_unpublished_financials",
    "dlp_document_m_and_a",
    "dlp_document_board_minutes",
    "dlp_marking_de_government",
    "dlp_marking_de_corporate",
    "dlp_marking_en_corporate",
    "dlp_marking_tlp",
    "dlp_marking_nato_eu",
    "dlp_document_nda_trade_secret",
    "dlp_document_contract",
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
