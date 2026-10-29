// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provider-bound secret formats (LLM, cloud, source control, DevOps and
//! package registries, CI and hosting, observability, payment, chat).
use crate::{
    detectors::dlp::{
        aws_context::{has_aws_secret_context, is_aws_secret_value, lines_above},
        dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
        prefilter::ValueClass,
    },
    detectors::validators::{
        base64_decode, crc32, crc32_base62_valid, crc32_hex_valid, macaroon_v2_parse, Base64Kind,
    },
    post_prediction::is_real_secret_assignment,
};
use serde_json::{Map, Value};
use std::{borrow::Cow, ops::Range};

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

/// Lines above the value's line in which a provider term counts.
const TERM_CONTEXT_LINES: usize = 5;

/// Whether `term` (lower-case ASCII) occurs, ASCII case-insensitive, on the
/// value's line or up to five lines above it.
fn has_term_nearby(text: &str, value: Range<usize>, term: &[u8]) -> bool {
    let start = lines_above(text, value.start, TERM_CONTEXT_LINES);
    let line_end = text[value.end..]
        .find('\n')
        .map_or(text.len(), |newline| value.end + newline);
    [&text[start..value.start], &text[value.end..line_end]]
        .iter()
        .any(|part| {
            part.as_bytes()
                .windows(term.len())
                .any(|window| window.eq_ignore_ascii_case(term))
        })
}

/// P05: a legacy Vault token (`s.` and 24 characters) shares its shape with
/// member accesses and file names, so it needs Vault on its line or up to
/// five lines above it (`VAULT_TOKEN=`, `X-Vault-Token:`, `vault login`, a
/// "Vault token" label).
fn has_vault_context(text: &str, value: Range<usize>) -> bool {
    has_term_nearby(text, value, b"vault")
}

/// P06: Render documents the `rnd_` prefix of its API keys but no length, so
/// a `rnd_` value needs Render on its line or up to five lines above it
/// (`RENDER_API_KEY=`, `render login`, a "Render API key" label).
fn has_render_context(text: &str, value: Range<usize>) -> bool {
    has_term_nearby(text, value, b"render")
}

/// P06: a random body after the provider prefix (`vcp_`, `rnd_`) with both
/// cases.
fn has_both_cases_after_prefix(value: &str) -> bool {
    value
        .split_once('_')
        .is_some_and(|(_, body)| has_both_cases(body))
}

/// P07: the JSON object that the standard base64 `body` (padded or not)
/// encodes, the payload of Grafana and Sentry tokens.
fn base64_json_object(body: &str) -> Option<Map<String, Value>> {
    let raw = base64_decode(body, Base64Kind::Standard)
        .or_else(|| base64_decode(body, Base64Kind::StandardUnpadded))?;
    match serde_json::from_slice(&raw).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// P07: a Sentry org auth token is `sntrys_`, the base64 of a JSON payload
/// with a numeric `iat` (issued at), `_` and the secret.
fn is_sentry_org_token(value: &str) -> bool {
    value
        .strip_prefix("sntrys_")
        .and_then(|rest| rest.rsplit_once('_'))
        .and_then(|(payload, _)| base64_json_object(payload))
        .is_some_and(|payload| payload.get("iat").is_some_and(Value::is_number))
}

/// P07: a legacy Grafana API key is the base64 of `{"k": key, "n": name,
/// "id": org id}`.
fn is_grafana_api_key(value: &str) -> bool {
    base64_json_object(value).is_some_and(|key| {
        key.get("k").is_some_and(Value::is_string)
            && key.get("n").is_some_and(Value::is_string)
            && key.get("id").is_some_and(Value::is_number)
    })
}

/// P07: a Grafana Cloud access policy token is `glc_` and the base64 of a JSON
/// object that holds the key in `k`.
fn is_grafana_cloud_token(value: &str) -> bool {
    value
        .strip_prefix("glc_")
        .and_then(base64_json_object)
        .is_some_and(|token| token.get("k").is_some_and(Value::is_string))
}

/// P07: a Grafana service account token is `glsa_`, 32 alphanumerics, `_` and
/// the CRC32 of everything before that `_`, its little-endian bytes as eight
/// lower-case hex digits.
fn is_grafana_service_account_token(value: &str) -> bool {
    value.rsplit_once('_').is_some_and(|(key, checksum)| {
        checksum == format!("{:08x}", crc32(key.as_bytes()).swap_bytes())
    })
}

/// P07: an Elasticsearch API key is `id:api_key` (20 and 22 base64url
/// characters, the `api_key` with both cases), as written in Beats and Logstash
/// configs, or the standard base64 of that pair (the `encoded` key of the
/// `ApiKey` scheme).
fn is_elastic_api_key(value: &str) -> bool {
    let pair = if value.contains(':') {
        Cow::Borrowed(value)
    } else {
        match base64_decode(value, Base64Kind::Standard).and_then(|raw| String::from_utf8(raw).ok())
        {
            Some(pair) => Cow::Owned(pair),
            None => return false,
        }
    };
    let base64url = |part: &str, len: usize| {
        part.len() == len
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    pair.split_once(':')
        .is_some_and(|(id, key)| base64url(id, 20) && base64url(key, 22) && has_both_cases(key))
}

/// P07: a random alphanumeric key (Honeycomb's 22, PagerDuty's 20 characters)
/// has both cases; the 32-digit hex forms are lower-case by format.
fn is_mixed_case_or_hex_key(value: &str) -> bool {
    value.len() == 32 || has_both_cases(value)
}

/// P07: the PagerDuty `Token token=` scheme is also Rails' token scheme, so a
/// value needs PagerDuty on its line or up to five lines above; a PagerDuty
/// key names it already.
fn has_pagerduty_context(text: &str, value: Range<usize>) -> bool {
    [&b"pagerduty"[..], b"pager_duty", b"pager-duty"]
        .iter()
        .any(|term| has_term_nearby(text, value.clone(), term))
}

/// P06: a provider key and its value (gitleaks' keyword rules, tightened): the
/// provider name, up to 30 key characters, a credential noun right before the
/// separator (`TRAVIS_API_TOKEN=`, `"netlify_auth_token":`,
/// `Heroku-API-Schlüssel:`, `Circle-Token:`), an optional opening quote and
/// the value in group 1, which no further value character continues.
/// `HEROKU_APP_ID`, `CIRCLE_SHA1` or `travis_build_id` name no credential.
macro_rules! provider_key {
    ($provider:literal, $value:expr) => {
        concat!(
            "(?i:",
            $provider,
            r")[A-Za-z0-9_.\- ]{0,30}?",
            r"(?i:token|key|secret|pat|password|passwort|kennwort|schlüssel|schluessel)",
            key_suffix!(),
            r"(?:=>|:=|[=:,])[ \t]*\\?[\x22'`]?(",
            $value,
            r")(?:[^A-Za-z0-9_\-+/=]|$)",
        )
    };
}

/// A UUID in either case (legacy Heroku API keys, Railway and Splunk HEC
/// tokens).
macro_rules! uuid {
    () => {
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    };
}

/// P07: the value after an HTTP `Authorization` header and its scheme
/// (`Authorization: Splunk <token>`, `"authorization": "ApiKey <key>"`) in
/// group 1, which no further value character continues.
macro_rules! authorization_scheme {
    ($scheme:literal, $value:expr) => {
        concat!(
            r"(?i:authorization)\\?[\x22']?[ \t]*[:=][ \t]*\\?[\x22']?",
            $scheme,
            r"[ \t]+(",
            $value,
            r")(?:[^A-Za-z0-9_\-+/=]|$)",
        )
    };
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
    // ── CI / hosting (P06) ───────────────────────────────────────────────────
    // Bitbucket OAuth consumer secrets: 64 characters under a Bitbucket key.
    DlpPattern {
        name: "dlp_bitbucket_client_secret",
        pattern: provider_key!("bitbucket", r"[A-Za-z0-9_=\-]{64}"),
        entity_group: "API_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:bitbucket-client-secret",
            &["bitbucket"],
        )
        .with_provider("bitbucket")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::SecretKey),
    },
    // Azure DevOps personal access tokens since 2024: 84 alphanumerics with
    // the fixed signature `AZDO` at positions 76 to 80.
    DlpPattern {
        name: "dlp_azure_devops_pat",
        pattern: r"[A-Za-z0-9]{76}AZDO[A-Za-z0-9]{4}",
        entity_group: "SECRET_TOKEN",
        validator: Some(has_both_cases),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://learn.microsoft.com/en-us/purview/sit-defn-azure-devops-personal-access-token",
            &["azdo"],
        )
        .with_provider("azure_devops")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Azure DevOps personal access tokens before 2024: 52 lower-case
    // alphanumerics, only under an Azure DevOps key (`AZURE_DEVOPS_EXT_PAT`,
    // `AZDO_PERSONAL_ACCESS_TOKEN`, `VSTS_PAT`).
    DlpPattern {
        name: "dlp_azure_devops_legacy_pat",
        pattern: provider_key!(r"azure[_.\- ]?devops|azdo|vsts", r"[a-z0-9]{52}"),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/azuredevopspersonalaccesstoken/azuredevopspersonalaccesstoken.go",
            &["azure", "azdo", "vsts"],
        )
        .with_provider("azure_devops")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // CircleCI personal (`CCIPAT_`) and project (`CCIPRJ_`) API tokens: a
    // base58 UUID, `_` and 40 hex digits.
    DlpPattern {
        name: "dlp_circleci_token",
        pattern: r"CCIP(?:AT|RJ)_[1-9A-HJ-NP-Za-km-z]{21,22}_[0-9a-fA-F]{40}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://circleci.com/changelog/new-format-for-api-access-tokens",
            &["ccipat_", "cciprj_"],
        )
        .with_provider("circleci")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // CircleCI API tokens before the prefixes: 40 hex digits, only under a
    // CircleCI key (`CIRCLE_TOKEN`, `CIRCLECI_CLI_TOKEN`, `Circle-Token:`).
    DlpPattern {
        name: "dlp_circleci_legacy_token",
        pattern: provider_key!("circle", r"[0-9a-fA-F]{40}"),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/circleci/v1/circleci.go",
            &["circle"],
        )
        .with_provider("circleci")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Travis CI API tokens: 22 alphanumerics under a Travis key.
    DlpPattern {
        name: "dlp_travis_token",
        pattern: provider_key!("travis", r"[A-Za-z0-9]{22}"),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:travisci-access-token",
            &["travis"],
        )
        .with_provider("travisci")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Vercel personal (`vcp_`), integration (`vci_`), app access (`vca_`),
    // app refresh (`vcr_`) tokens and API keys (`vck_`) with the 56
    // alphanumerics of the documented tokens.
    DlpPattern {
        name: "dlp_vercel_token",
        pattern: r"vc[pikar]_[A-Za-z0-9]{56}",
        entity_group: "CLOUD_KEY",
        validator: Some(has_both_cases_after_prefix),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://vercel.com/changelog/new-token-formats-and-secret-scanning",
            &["vcp_", "vci_", "vca_", "vcr_", "vck_"],
        )
        .with_provider("vercel")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Vercel access tokens before the prefixes: 24 alphanumerics under a
    // Vercel key.
    DlpPattern {
        name: "dlp_vercel_legacy_token",
        pattern: provider_key!("vercel", r"[A-Za-z0-9]{24}"),
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/vercel/vercel.go",
            &["vercel"],
        )
        .with_provider("vercel")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Netlify personal access tokens: `nfp_` and 36 characters.
    DlpPattern {
        name: "dlp_netlify_token",
        pattern: r"nfp_[A-Za-z0-9_]{36}",
        entity_group: "CLOUD_KEY",
        validator: Some(has_both_cases_after_prefix),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/netlify/v2/netlify_v2.go",
            &["nfp_"],
        )
        .with_provider("netlify")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Netlify access tokens before `nfp_`: 40 to 46 characters under a
    // Netlify key.
    DlpPattern {
        name: "dlp_netlify_legacy_token",
        pattern: provider_key!("netlify", r"[A-Za-z0-9_=\-]{40,46}"),
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:netlify-access-token",
            &["netlify"],
        )
        .with_provider("netlify")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Fly.io OAuth tokens: `fo1_` and 43 base64url characters.
    DlpPattern {
        name: "dlp_flyio_token",
        pattern: r"fo1_[A-Za-z0-9_\-]{43}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:flyio-access-token",
            &["fo1_"],
        )
        .with_provider("flyio")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Fly.io macaroon tokens (`fm1a_`, `fm1r_`, `fm2_`): standard base64, so
    // `/` and `+` belong to the token and no token boundary applies.
    DlpPattern {
        name: "dlp_flyio_macaroon_token",
        pattern: r"fm(?:1[ar]|2)_[A-Za-z0-9+/]{100,4096}={0,3}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:flyio-access-token",
            &["fm1a_", "fm1r_", "fm2_"],
        )
        .with_provider("flyio")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Heroku API keys since 2024: `HRKU-AA` and 58 characters.
    DlpPattern {
        name: "dlp_heroku_api_key",
        pattern: r"HRKU-AA[A-Za-z0-9_\-]{58}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:heroku-api-key-v2",
            &["hrku-aa"],
        )
        .with_provider("heroku")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    // Heroku API keys before `HRKU-`: a UUID under a Heroku key.
    DlpPattern {
        name: "dlp_heroku_legacy_api_key",
        pattern: provider_key!("heroku", uuid!()),
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:heroku-api-key",
            &["heroku"],
        )
        .with_provider("heroku")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // Render API keys: `rnd_` and a random body, only with Render context.
    DlpPattern {
        name: "dlp_render_api_key",
        pattern: r"rnd_[A-Za-z0-9]{24,64}",
        entity_group: "CLOUD_KEY",
        validator: Some(has_both_cases_after_prefix),
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://render.com/docs/cli",
            &["rnd_"],
        )
        .with_provider("render")
        .with_min_entropy(3.5)
        .with_boundary("")
        .with_context_gate(has_render_context)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // Railway account and project tokens: a UUID under a Railway key.
    DlpPattern {
        name: "dlp_railway_token",
        pattern: provider_key!("railway", uuid!()),
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/railwayapp/railwayapp.go",
            &["railway"],
        )
        .with_provider("railway")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Cloudflare API tokens (40 characters) and Global API Keys (37 hex
    // digits) under a Cloudflare key.
    DlpPattern {
        name: "dlp_cloudflare_api_key",
        pattern: provider_key!("cloudflare", r"[A-Za-z0-9_\-]{40}|[0-9a-f]{37}"),
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:cloudflare-api-key",
            &["cloudflare"],
        )
        .with_provider("cloudflare")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // Cloudflare Origin CA keys: `v1.0-`, 24 hex digits, `-` and 146 hex
    // digits.
    DlpPattern {
        name: "dlp_cloudflare_origin_ca_key",
        pattern: r"v1\.0-[0-9a-f]{24}-[0-9a-f]{146}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:cloudflare-origin-ca-key",
            &["v1.0-"],
        )
        .with_provider("cloudflare")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    // DigitalOcean personal access (`dop_v1_`), OAuth access (`doo_v1_`) and
    // refresh tokens (`dor_v1_`) with 64 hex digits.
    DlpPattern {
        name: "dlp_digitalocean_token",
        pattern: r"do[opr]_v1_[0-9a-f]{64}",
        entity_group: "CLOUD_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:digitalocean-pat",
            &["dop_v1_", "doo_v1_", "dor_v1_"],
        )
        .with_provider("digitalocean")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // ── Observability (P07) ──────────────────────────────────────────────────
    // Datadog API keys (32 hex digits) and application keys (40 characters)
    // under a Datadog key (`DD_API_KEY`, `DD-APPLICATION-KEY:`, `ddApiKey`,
    // `datadog_app_key`). A client token (`pub` and 32 hex digits) is public.
    DlpPattern {
        name: "dlp_datadog_api_key",
        pattern: provider_key!(
            r"datadog|(?-u:\b)dd(?:[_\-]|api|app)",
            r"[a-z0-9]{40}|[0-9a-f]{32}"
        ),
        entity_group: "API_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:datadog-access-token",
            &["datadog", "dd_", "dd-", "ddapi", "ddapp"],
        )
        .with_provider("datadog")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // New Relic user API keys: `NRAK-` and 27 alphanumerics.
    DlpPattern {
        name: "dlp_newrelic_user_api_key",
        pattern: r"NRAK-[A-Za-z0-9]{27}",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:new-relic-user-api-key",
            &["nrak-"],
        )
        .with_provider("newrelic")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::ApiKey),
    },
    // New Relic Insights insert keys: `NRII-` and 32 (gitleaks) or 25
    // (TruffleHog) characters.
    DlpPattern {
        name: "dlp_newrelic_insert_key",
        pattern: r"NRII-(?:[A-Za-z0-9_\-]{32}|[A-Za-z0-9_\-]{25})",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:new-relic-insert-key",
            &["nrii-"],
        )
        .with_provider("newrelic")
        .with_min_entropy(3.0)
        .with_boundary("-")
        .with_subtype(SecretSubtype::ApiKey),
    },
    // New Relic license (ingest) keys: 32 hex digits, or `eu01xx` and 26, and
    // the suffix `FFFFNRAL`.
    DlpPattern {
        name: "dlp_newrelic_license_key",
        pattern: r"(?:[0-9a-f]{32}|eu01xx[0-9a-f]{26})FFFFNRAL",
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/newreliclicensekey/newreliclicensekey.go",
            &["ffffnral"],
        )
        .with_provider("newrelic")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::ApiKey),
    },
    // New Relic license keys without the suffix: 40 hex digits under a New
    // Relic key (`NEW_RELIC_LICENSE_KEY`, `newrelic.license_key`).
    DlpPattern {
        name: "dlp_newrelic_legacy_license_key",
        pattern: provider_key!(r"new[_.\- ]?relic", r"[0-9a-f]{40}"),
        entity_group: "API_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
            &["relic"],
        )
        .with_provider("newrelic")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // Sentry user auth tokens: `sntryu_` and 64 hex digits.
    DlpPattern {
        name: "dlp_sentry_user_token",
        pattern: r"sntryu_[0-9a-f]{64}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:sentry-user-token",
            &["sntryu_"],
        )
        .with_provider("sentry")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Sentry org auth tokens: `sntrys_`, the base64 of a JSON payload with
    // `iat`, `_` and 43 base64 characters. Standard base64, so `/` and `+`
    // belong to the token and no token boundary applies.
    DlpPattern {
        name: "dlp_sentry_org_token",
        pattern: r"sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,600}={0,2}_[A-Za-z0-9+/]{43}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_sentry_org_token),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "gitleaks:sentry-org-token",
            &["sntrys_"],
        )
        .with_provider("sentry")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Sentry auth tokens before the prefixes: 64 hex digits under a Sentry key
    // (`SENTRY_AUTH_TOKEN`).
    DlpPattern {
        name: "dlp_sentry_auth_token",
        pattern: provider_key!("sentry", r"[0-9a-f]{64}"),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:sentry-access-token",
            &["sentry"],
        )
        .with_provider("sentry")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // The secret key of a legacy Sentry DSN
    // (`https://<public key>:<secret key>@host/<project id>`). A DSN with the
    // public key only is safe to expose (Sentry docs) and no finding.
    DlpPattern {
        name: "dlp_sentry_dsn_secret",
        pattern: concat!(
            r"https?://[0-9a-f]{32}:([0-9a-f]{32})@[A-Za-z0-9.\-]{1,253}(?::[0-9]{1,5})?",
            r"/(?:[A-Za-z0-9._\-]{1,64}/){0,4}[0-9]{1,20}(?:[^A-Za-z0-9_\-/]|$)",
        ),
        entity_group: "API_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.sentry.io/concepts/key-terms/dsn-explainer/",
            &["://"],
        )
        .with_provider("sentry")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::SecretKey),
    },
    // Legacy Grafana API keys: the base64 of `{"k":…,"n":…,"id":…}`, so they
    // start with `eyJrIjoi`.
    DlpPattern {
        name: "dlp_grafana_api_key",
        pattern: r"eyJrIjoi[A-Za-z0-9+/]{70,400}={0,3}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_grafana_api_key),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "gitleaks:grafana-api-key",
            &["eyjrijoi"],
        )
        .with_provider("grafana")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Grafana Cloud access policy tokens: `glc_` and the base64 of a JSON
    // object with the key.
    DlpPattern {
        name: "dlp_grafana_cloud_token",
        pattern: r"glc_[A-Za-z0-9+/]{32,400}={0,3}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_grafana_cloud_token),
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "gitleaks:grafana-cloud-api-token",
            &["glc_"],
        )
        .with_provider("grafana")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Grafana service account tokens: `glsa_`, 32 alphanumerics, `_` and a
    // CRC32 as eight hex digits.
    DlpPattern {
        name: "dlp_grafana_service_account_token",
        pattern: r"glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_grafana_service_account_token),
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://github.com/grafana/grafana/blob/main/pkg/components/satokengen/tokengen.go",
            &["glsa_"],
        )
        .with_provider("grafana")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Dynatrace access (`dt0c01`) and platform/API tokens (`dt0s01` …
    // `dt0s16`): prefix, 24-character public portion and 64-character secret.
    DlpPattern {
        name: "dlp_dynatrace_token",
        pattern: r"dt0[cs][0-9]{2}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
        base_score: 55,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.dynatrace.com/docs/manage/identity-access-management/access-tokens-and-oauth-clients/access-tokens",
            &["dt0c", "dt0s"],
        )
        .with_provider("dynatrace")
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Splunk HTTP Event Collector tokens: a GUID under a Splunk key or after
    // `Authorization: Splunk`.
    DlpPattern {
        name: "dlp_splunk_hec_token",
        pattern: concat!(
            provider_key!("splunk", uuid!()),
            "|",
            authorization_scheme!("Splunk", uuid!()),
        ),
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
            &["splunk"],
        )
        .with_provider("splunk")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::AccessToken),
    },
    // Elasticsearch API keys under an Elastic key (`id:api_key` or its
    // base64) or after `Authorization: ApiKey`.
    DlpPattern {
        name: "dlp_elastic_api_key",
        pattern: concat!(
            provider_key!(
                "elastic",
                r"[A-Za-z0-9+/]{56,120}={0,2}|[A-Za-z0-9_\-]{20}:[A-Za-z0-9_\-]{22}"
            ),
            "|",
            authorization_scheme!("ApiKey", r"[A-Za-z0-9+/]{56,120}={0,2}"),
        ),
        entity_group: "API_KEY",
        validator: Some(is_elastic_api_key),
        span_group: Some(1),
        base_score: 45,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key",
            &["elastic", "authorization"],
        )
        .with_provider("elastic")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // Honeycomb configuration and ingest keys (22 alphanumerics) and Classic
    // keys (32 hex digits) under a Honeycomb key or in the
    // `x-honeycomb-team` header (also in `OTEL_EXPORTER_OTLP_HEADERS`).
    DlpPattern {
        name: "dlp_honeycomb_api_key",
        pattern: concat!(
            provider_key!("honeycomb", r"[0-9a-f]{32}|[A-Za-z0-9]{22}"),
            r"|(?i:x-honeycomb-team)\\?[\x22']?[ \t]*[:=,][ \t]*\\?[\x22']?",
            r"([0-9a-f]{32}|[A-Za-z0-9]{22})(?:[^A-Za-z0-9_\-+/=]|$)",
        ),
        entity_group: "API_KEY",
        validator: Some(is_mixed_case_or_hex_key),
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/honeycomb/honeycomb.go",
            &["honeycomb"],
        )
        .with_provider("honeycomb")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::ApiKey),
    },
    // PagerDuty REST API keys (20 characters, user tokens `u+…`) and Events
    // API integration keys (32 hex digits) under a PagerDuty key, and REST keys
    // in the `Token token=` scheme with PagerDuty context.
    DlpPattern {
        name: "dlp_pagerduty_api_key",
        pattern: concat!(
            provider_key!(r"pagerduty|pager[_\-]duty", r"[A-Za-z0-9_+\-]{20}|[0-9a-f]{32}"),
            r"|(?i:token)[ \t]+token=\\?[\x22']?([A-Za-z0-9_+\-]{20})(?:[^A-Za-z0-9_\-+/=]|$)",
        ),
        entity_group: "API_KEY",
        validator: Some(is_mixed_case_or_hex_key),
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/pagerdutyapikey/pagerdutyapikey.go",
            &["pagerduty", "pager_duty", "pager-duty", "token="],
        )
        .with_provider("pagerduty")
        .with_min_entropy(3.0)
        .with_context_gate(has_pagerduty_context)
        .with_subtype(SecretSubtype::ApiKey),
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
