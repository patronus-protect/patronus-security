// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provider-bound secret formats (LLM, cloud, source control, DevOps and
//! package registries, payment, chat).
use crate::{
    detectors::dlp::{
        aws_context::{has_aws_secret_context, is_aws_secret_value, lines_above},
        dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
        prefilter::ValueClass,
    },
    detectors::validators::{
        base64_decode, crc32_base62_valid, crc32_hex_valid, macaroon_v2_parse, Base64Kind,
    },
    post_prediction::is_real_secret_assignment,
};
use std::ops::Range;

/// GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and npm token
/// (`npm_`, F04): after the four-character prefix, 30 random base62
/// characters and their CRC32 as six base62 digits.
fn is_crc32_token(value: &str) -> bool {
    value.len() == 40 && value.get(4..).is_some_and(crc32_base62_valid)
}

/// P05: a PyPI API token is `pypi-` and the unpadded base64url of a complete
/// Macaroon V2 whose location is PyPI or TestPyPI.
fn is_pypi_token(value: &str) -> bool {
    value
        .strip_prefix("pypi-")
        .and_then(|body| base64_decode(body, Base64Kind::UrlSafe))
        .is_some_and(|raw| {
            macaroon_v2_parse(&raw).is_some_and(|macaroon| {
                matches!(
                    macaroon.location,
                    Some(b"pypi.org") | Some(b"test.pypi.org")
                )
            })
        })
}

/// P05: a random base62 body has upper- and lower-case letters (one of them
/// is missing with a chance below 10⁻⁵ for 24 characters); identifiers that
/// only start like a token mostly lack one.
fn has_both_cases(body: &str) -> bool {
    body.bytes().any(|byte| byte.is_ascii_uppercase())
        && body.bytes().any(|byte| byte.is_ascii_lowercase())
}

/// crates.io token: `cio` and a body with both cases.
fn is_cratesio_token(value: &str) -> bool {
    value.strip_prefix("cio").is_some_and(has_both_cases)
}

/// Legacy Vault token: `s.` and a body with both cases.
fn is_vault_legacy_token(value: &str) -> bool {
    value.strip_prefix("s.").is_some_and(has_both_cases)
}

/// Lines above the value's line in which a Vault term counts.
const VAULT_CONTEXT_LINES: usize = 5;

/// P05: a legacy Vault token (`s.` and 24 characters) shares its shape with
/// member accesses and file names, so it needs Vault on its line or up to
/// five lines above it (`VAULT_TOKEN=`, `X-Vault-Token:`, `vault login`, a
/// "Vault token" label).
fn has_vault_context(text: &str, value: Range<usize>) -> bool {
    let start = lines_above(text, value.start, VAULT_CONTEXT_LINES);
    let line_end = text[value.end..]
        .find('\n')
        .map_or(text.len(), |newline| value.end + newline);
    [&text[start..value.start], &text[value.end..line_end]]
        .iter()
        .any(|part| {
            part.as_bytes()
                .windows(5)
                .any(|window| window.eq_ignore_ascii_case(b"vault"))
        })
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
    // F05: credential prefixes of the IAM unique-ID table (long-term AKIA,
    // temporary ASIA, STS bearer ABIA, context-specific ACCA, legacy A3T…)
    // and exactly 16 upper-case letters or digits (Base32 today, legacy IDs
    // also hold 0, 1, 8 and 9). Group, user, role, policy and other
    // unique IDs (AGPA, AIDA, AROA, ANPA …) are no credentials.
    DlpPattern {
        name: "dlp_aws_access_key",
        pattern: r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:aws-access-token",
            &["akia", "asia", "abia", "acca", "a3t"],
        )
        .with_provider("aws")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::ApiKey),
    },
    // F05: 40 base64 characters after an AWS key name or label (also in
    // prose, up to two lines on), an access key ID, or a generic secret key
    // name with AWS context (`aws_context`).
    DlpPattern {
        name: "dlp_aws_secret_key",
        pattern: concat!(
            r"(?:(?i:aws[\s_.-]?secret[\s_.-]?(?:access[\s_.-]?)?key|secret[\s_.-]?access[\s_.-]?key)",
            r"(?:[^\n]{0,100}?|[^\n=]{0,100}\n(?:[^\n=]{0,100}\n)?[^\n=]{0,60}?)",
            r"|(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}[\x22'\\]{0,2}[ \t,;:|]{0,3}",
            r"|\b(?:secret[_-]key|Secret[_-]Key|secretKey|SecretKey)[^\n]{0,30}?)",
            r"[\s\x22'`:=(,>\[|;]([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)",
        ),
        entity_group: "CLOUD_KEY",
        validator: Some(is_aws_secret_value),
        span_group: Some(1),
        base_score: 35,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            &["secret", "akia", "asia", "abia", "acca", "a3t"],
        )
        .with_provider("aws")
        .with_min_entropy(3.0)
        .with_context_gate(has_aws_secret_context)
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
    // check value (gitleaks gitlab-pat, gitlab-pat-routable), or in the
    // current form `.01.` before the two-character length and the check value.
    DlpPattern {
        name: "dlp_gitlab_pat",
        pattern: r"glpat-(?:[A-Za-z0-9_\-]{27,300}\.(?:01\.)?[0-9a-z]{9}|[A-Za-z0-9_\-]{20})",
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
    // gitleaks rules: deploy, runner (`glrt-`, or `glrtr-` when created through
    // a registration token; also routable), workspace (routable only), runner
    // registration, pipeline trigger, feed, incoming mail, Kubernetes agent,
    // CI/CD job, SCIM and feature flag client tokens. The current routable form
    // (GitLab HTTP router, `RoutableToken` generator) is a base64url payload,
    // `.01.`, the payload length as two base36 digits and a seven-digit base36
    // CRC32 (not verified).
    DlpPattern {
        name: "dlp_gitlab_token",
        pattern: concat!(
            r"(?:(?:glrtr?|glwt)-[A-Za-z0-9_\-]{27,300}\.01\.[0-9a-z]{9}",
            r"|glrt-t[0-9]_[A-Za-z0-9_\-]{27,300}\.[0-9a-z]{9}",
            r"|(?:gldt|glrtr?|glft|glsoat|glffct)-[A-Za-z0-9_\-]{20}",
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
                "glrtr-",
                "glwt-",
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
    // ── DevOps / package registries (P05) ────────────────────────────────────
    // Docker Hub personal (`dckr_pat_`) and organization (`dckr_oat_`) access
    // tokens: the prefix and 27 base64url characters.
    DlpPattern {
        name: "dlp_dockerhub_token",
        pattern: r"dckr_(?:pat|oat)_[A-Za-z0-9_\-]{27}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.docker.com/reference/api/hub/latest/",
            &["dckr_pat_", "dckr_oat_"],
        )
        .with_provider("dockerhub")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // PyPI and TestPyPI API tokens: `pypi-` and a base64url Macaroon V2 whose
    // header names the index (`AgEIcHlwaS5vcmc` is `02 01 08 pypi.org`).
    DlpPattern {
        name: "dlp_pypi_token",
        pattern: r"pypi-AgE(?:IcHlwaS5vcmc|NdGVzdC5weXBpLm9yZw)[A-Za-z0-9_\-]{50,1000}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_pypi_token),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "gitleaks:pypi-upload-token",
            &["pypi-age"],
        )
        .with_provider("pypi")
        .with_min_entropy(3.0)
        .with_test_prefixes(&["pypi-AgENdGVzdC5weXBpLm9yZw"])
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    DlpPattern {
        name: "dlp_rubygems_token",
        pattern: r"rubygems_[0-9a-f]{48}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:rubygems-api-token",
            &["rubygems_"],
        )
        .with_provider("rubygems")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // crates.io API tokens: `cio` and 32 random alphanumerics.
    DlpPattern {
        name: "dlp_cratesio_token",
        pattern: r"cio[A-Za-z0-9]{32}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_cratesio_token),
        span_group: None,
        base_score: 45,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/rust-lang/crates.io/blob/main/crates/crates_io_database/src/utils/token.rs",
            &["cio"],
        )
        .with_provider("cratesio")
        .with_min_entropy(3.5)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Private Packagist tokens: a prefix per token kind, 60 hex characters and
    // the CRC32 of both as eight hex digits.
    DlpPattern {
        name: "dlp_packagist_token",
        pattern: r"packagist_(?:ort|out|uut|cut)_[0-9a-f]{68}",
        entity_group: "SECRET_TOKEN",
        validator: Some(crc32_hex_valid),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://packagist.com/docs/composer-authentication",
            &[
                "packagist_ort_",
                "packagist_out_",
                "packagist_uut_",
                "packagist_cut_",
            ],
        )
        .with_provider("packagist")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // JFrog Artifactory API keys (`AKCp`) and reference tokens (`cmVmd`, the
    // base64 of `ref`).
    DlpPattern {
        name: "dlp_jfrog_token",
        pattern: r"AKCp[A-Za-z0-9]{69}|cmVmd[A-Za-z0-9]{59}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:artifactory-api-key",
            &["akcp", "cmvmd"],
        )
        .with_provider("jfrog")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // HCP Terraform (Terraform Cloud/Enterprise) API tokens: 14
    // alphanumerics, `.atlasv1.` and 60 to 70 characters.
    DlpPattern {
        name: "dlp_terraform_cloud_token",
        pattern: r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=\-]{60,70}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:hashicorp-tf-api-token",
            &[".atlasv1."],
        )
        .with_provider("terraform_cloud")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    DlpPattern {
        name: "dlp_pulumi_token",
        pattern: r"pul-[0-9a-f]{40}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:pulumi-api-token",
            &["pul-"],
        )
        .with_provider("pulumi")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // HashiCorp Vault 1.10+ service (`hvs.`) and batch (`hvb.`) tokens with
    // the lengths of the gitleaks rules.
    DlpPattern {
        name: "dlp_vault_token",
        pattern: r"hvs\.[A-Za-z0-9_\-]{90,120}|hvb\.[A-Za-z0-9_\-]{138,300}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:vault-service-token",
            &["hvs.", "hvb."],
        )
        .with_provider("vault")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Vault service tokens before 1.10: `s.` and 24 alphanumerics, only in
    // Vault context.
    DlpPattern {
        name: "dlp_vault_legacy_token",
        pattern: r"s\.[A-Za-z0-9]{24}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_vault_legacy_token),
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:vault-service-token",
            &["s."],
        )
        .with_provider("vault")
        .with_min_entropy(3.5)
        .with_boundary("")
        .with_context_gate(has_vault_context)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Doppler tokens: personal, CLI, service (optionally scoped), service
    // account, service account identity, SCIM and audit tokens with 40 to 44
    // alphanumerics.
    DlpPattern {
        name: "dlp_doppler_token",
        pattern: concat!(
            r"dp\.(?:pt|ct|sa|said|scim|audit)\.[A-Za-z0-9]{40,44}",
            r"|dp\.st\.(?:[a-z0-9_\-]{2,35}\.)?[A-Za-z0-9]{40,44}",
        ),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.doppler.com/reference/auth-token-formats",
            &[
                "dp.pt.",
                "dp.ct.",
                "dp.st.",
                "dp.sa.",
                "dp.said.",
                "dp.scim.",
                "dp.audit.",
            ],
        )
        .with_provider("doppler")
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
