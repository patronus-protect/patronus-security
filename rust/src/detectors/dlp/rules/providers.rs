// SPDX-License-Identifier: GPL-3.0-only
//! Provider-bound secret formats (LLM, cloud, source control, payment, chat).
use crate::{
    detectors::dlp::{
        dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
        prefilter::ValueClass,
    },
    detectors::validators::crc32_base62_valid,
    post_prediction::is_real_secret_assignment,
};

/// GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and npm token
/// (`npm_`, F04): after the four-character prefix, 30 random base62
/// characters and their CRC32 as six base62 digits.
fn is_crc32_token(value: &str) -> bool {
    value.len() == 40 && value.get(4..).is_some_and(crc32_base62_valid)
}

pub(super) const RULES: &[DlpPattern] = &[
    // ── AI / LLM API Keys ────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_anthropic_key",
        pattern: r"sk-ant-[a-zA-Z0-9\-_]{10,}",
        entity_group: "API_KEY",
        validator: Some(is_real_secret_assignment),
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:anthropic-api-key",
            &["sk-ant-"],
        )
        .with_provider("anthropic")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_openai_key",
        pattern: r"sk-proj-[a-zA-Z0-9\-_]{10,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:openai-api-key",
            &["sk-proj-"],
        )
        .with_provider("openai")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_openai_legacy",
        pattern: r"sk-[a-zA-Z0-9]{48}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 45,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:openai-api-key",
            &["sk-"],
        )
        .with_provider("openai")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_openai_svc",
        pattern: r"sk-svcacct-[a-zA-Z0-9\-]{10,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:openai-api-key",
            &["sk-svcacct-"],
        )
        .with_provider("openai")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_huggingface",
        pattern: r"hf_[A-Za-z0-9]{20,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 45,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:huggingface-access-token",
            &["hf_"],
        )
        .with_provider("huggingface")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_groq_key",
        pattern: r"gsk_[a-zA-Z0-9]{48,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["gsk_"])
            .with_provider("groq")
            .with_min_entropy(3.0)
            .with_boundary("")
            .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_xai_key",
        pattern: r"xai-[a-zA-Z0-9\-_]{80,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["xai-"])
            .with_provider("xai")
            .with_min_entropy(3.0)
            .with_boundary("-")
            .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_replicate",
        pattern: r"r8_[A-Za-z0-9]{20,}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 45,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["r8_"])
            .with_provider("replicate")
            .with_min_entropy(3.0)
            .with_boundary("")
            .with_subtype(SecretSubtype::ApiKey),
    },
    // ── Cloud Provider Keys ──────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_aws_access_key",
        pattern: r"(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:aws-access-token",
            &[
                "akia", "a3t", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "asia",
            ],
        )
        .with_provider("aws")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_aws_secret_key",
        pattern: r#"(?i)(?:aws_secret_access_key|SecretAccessKey)\s*["'=:\s]{1,5}\s*([A-Za-z0-9/+=]{40})"#,
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 35,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            &["aws_secret_access_key", "secretaccesskey"],
        )
        .with_provider("aws")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::SecretKey),
    },
    DlpPattern {
        name: "dlp_google_api_key",
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(ValidatorStrength::Format, "gitleaks:gcp-api-key", &["aiza"])
            .with_provider("google")
            .with_min_entropy(3.0)
            .with_boundary("-")
            .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_google_oauth_token",
        pattern: r"ya29\.[a-zA-Z0-9_\-]{20,}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["ya29."])
            .with_provider("google")
            .with_min_entropy(3.0)
            .with_boundary("-")
            .with_subtype(SecretSubtype::AccessToken),
    },
    DlpPattern {
        name: "dlp_gcp_client_secret",
        pattern: r"GOCSPX-[A-Za-z0-9_\-]{28,}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["gocspx-"])
            .with_provider("google")
            .with_min_entropy(3.0)
            .with_boundary("-")
            .with_subtype(SecretSubtype::SecretKey),
    },
    // ── Source Control / Dev Tools ───────────────────────────────────────────
    DlpPattern {
        name: "dlp_github_token",
        pattern: r"gh[pousr]_[A-Za-z0-9]{36}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_crc32_token),
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "gitleaks:github-pat",
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        )
        .with_provider("github")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_body_len(36, 32)
        .with_subtype(SecretSubtype::AccessToken),
    },
    DlpPattern {
        name: "dlp_github_pat",
        pattern: r"github_pat_[A-Za-z0-9_]{82}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 60,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:github-fine-grained-pat",
            &["github_pat_"],
        )
        .with_provider("github")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_body_len(82, 36)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // F04: legacy tokens have exactly 20 characters; routable tokens a longer
    // payload, a dot, a two-character version and a seven-character base36
    // check value (gitleaks gitlab-pat, gitlab-pat-routable).
    DlpPattern {
        name: "dlp_gitlab_pat",
        pattern: r"glpat-(?:[A-Za-z0-9_\-]{27,300}\.[0-9a-z]{9}|[A-Za-z0-9_\-]{20})",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:gitlab-pat",
            &["glpat-"],
        )
        .with_provider("gitlab")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // F04: the other documented GitLab token prefixes, with the lengths of the
    // gitleaks rules: deploy, runner (also routable), runner registration,
    // pipeline trigger, feed, incoming mail, Kubernetes agent, CI/CD job, SCIM
    // and feature flag client tokens.
    DlpPattern {
        name: "dlp_gitlab_token",
        pattern: concat!(
            r"(?:glrt-t[0-9]_[A-Za-z0-9_\-]{27,300}\.[0-9a-z]{9}",
            r"|(?:gldt|glrt|glft|glsoat|glffct)-[A-Za-z0-9_\-]{20}",
            r"|glcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_\-]{20}",
            r"|glimt-[A-Za-z0-9_\-]{25}",
            r"|glagent-[A-Za-z0-9_\-]{50}",
            r"|glptt-[0-9a-f]{40}",
            r"|GR1348941[A-Za-z0-9_\-]{20})",
        ),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.gitlab.com/security/tokens/#token-prefixes",
            &[
                "gldt-",
                "glrt-",
                "glft-",
                "glsoat-",
                "glffct-",
                "glcbt-",
                "glimt-",
                "glagent-",
                "glptt-",
                "gr1348941",
            ],
        )
        .with_provider("gitlab")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    DlpPattern {
        name: "dlp_gitlab_oauth_secret",
        pattern: r"gloas-[A-Za-z0-9_\-]{64}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:gitlab-oauth-app-secret",
            &["gloas-"],
        )
        .with_provider("gitlab")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::SecretKey),
    },
    // F04: npm tokens carry a CRC32 like GitHub tokens.
    DlpPattern {
        name: "dlp_npm_token",
        pattern: r"npm_[A-Za-z0-9]{36}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_crc32_token),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "gitleaks:npm-access-token",
            &["npm_"],
        )
        .with_provider("npm")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // ── Payment ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_stripe_key",
        pattern: r"[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}",
        entity_group: "PAYMENT_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:stripe-access-token",
            &["k_live", "k-live", "k_test", "k-test"],
        )
        .with_provider("stripe")
        .with_min_entropy(3.0)
        .with_test_prefixes(&["sk_test", "sk-test", "rk_test", "rk-test"])
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    DlpPattern {
        name: "dlp_stripe_webhook",
        pattern: r"whsec_[a-zA-Z0-9_\-]{20,}",
        entity_group: "PAYMENT_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.stripe.com/webhooks",
            &["whsec_"],
        )
        .with_provider("stripe")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::SecretKey),
    },
    // ── Communication ────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_slack_token",
        pattern: r"xox[bpras]-[0-9a-zA-Z\-]{15,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://api.slack.com/authentication/token-types",
            &["xoxb-", "xoxp-", "xoxr-", "xoxa-", "xoxs-"],
        )
        .with_provider("slack")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    DlpPattern {
        name: "dlp_discord_token",
        pattern: r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 35,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &[])
            .with_provider("discord")
            .with_min_entropy(3.0)
            .with_value_run(ValueClass::Alphanumeric, 24)
            .with_boundary("-")
            .with_subtype(SecretSubtype::AccessToken),
    },
];
