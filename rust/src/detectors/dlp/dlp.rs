use crate::EvaluationResult;
use regex::{Regex, RegexSet};

/// A single DLP heuristic pattern (credentials / secrets).
pub struct DlpPattern {
    pub name: &'static str,
    pub pattern: &'static str,
    /// Entity group label — used in `NerResult` and `PlaceholderEncoder`.
    pub entity_group: &'static str,
    /// Optional post-regex validator.
    pub validator: Option<fn(&str) -> bool>,
}

pub static DLP_PATTERNS: &[DlpPattern] = &[
    // ── AI / LLM API Keys ────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_anthropic_key",
        pattern: r"sk-ant-[a-zA-Z0-9\-_]{10,}",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_openai_key",
        pattern: r"sk-proj-[a-zA-Z0-9\-_]{10,}",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_openai_legacy",
        pattern: r"\bsk-[a-zA-Z0-9]{48}\b",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_openai_svc",
        pattern: r"sk-svcacct-[a-zA-Z0-9\-]{10,}",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_huggingface",
        pattern: r"hf_[A-Za-z0-9]{20,}",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_groq_key",
        pattern: r"gsk_[a-zA-Z0-9]{48,}",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_xai_key",
        pattern: r"xai-[a-zA-Z0-9\-_]{80,}",
        entity_group: "API_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_replicate",
        pattern: r"r8_[A-Za-z0-9]{20,}",
        entity_group: "API_KEY",
        validator: None,
    },
    // ── Cloud Provider Keys ──────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_aws_access_key",
        pattern: r"(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}",
        entity_group: "CLOUD_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_aws_secret_key",
        pattern: r#"(?i)(?:aws_secret_access_key|SecretAccessKey)\s*["'=:\s]{1,5}\s*[A-Za-z0-9/+=]{40}"#,
        entity_group: "CLOUD_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_google_api_key",
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        entity_group: "CLOUD_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_google_oauth_token",
        pattern: r"ya29\.[a-zA-Z0-9_\-]{20,}",
        entity_group: "CLOUD_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_gcp_client_secret",
        pattern: r"GOCSPX-[A-Za-z0-9_\-]{28,}",
        entity_group: "CLOUD_KEY",
        validator: None,
    },
    // ── Source Control / Dev Tools ───────────────────────────────────────────
    DlpPattern {
        name: "dlp_github_token",
        pattern: r"gh[pousr]_[A-Za-z0-9_]{36,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    DlpPattern {
        name: "dlp_github_pat",
        pattern: r"github_pat_[a-zA-Z0-9_]{36,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    DlpPattern {
        name: "dlp_gitlab_pat",
        pattern: r"glpat-[a-zA-Z0-9\-_]{20,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    DlpPattern {
        name: "dlp_npm_token",
        pattern: r"npm_[A-Za-z0-9]{36,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    // ── Payment ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_stripe_key",
        pattern: r"[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}",
        entity_group: "PAYMENT_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_stripe_webhook",
        pattern: r"whsec_[a-zA-Z0-9_\-]{20,}",
        entity_group: "PAYMENT_KEY",
        validator: None,
    },
    // ── Communication ────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_slack_token",
        pattern: r"xox[bpras]-[0-9a-zA-Z\-]{15,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    DlpPattern {
        name: "dlp_discord_token",
        pattern: r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    // ── Crypto ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_eth_private_key",
        pattern: r"0x[0-9a-f]{64}\b",
        entity_group: "CRYPTO_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_btc_wif",
        pattern: r"(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})",
        entity_group: "CRYPTO_KEY",
        validator: None,
    },
    // ── Generische Credential-Patterns ───────────────────────────────────────
    DlpPattern {
        name: "dlp_private_key_header",
        pattern: r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
    },
    DlpPattern {
        name: "dlp_jwt_token",
        pattern: r"(?:ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
    },
    DlpPattern {
        name: "dlp_credential_in_url",
        pattern: r"(?i)\b(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*[^\s&]{4,}",
        entity_group: "CREDENTIAL",
        validator: None,
    },
    DlpPattern {
        name: "dlp_env_var_secret",
        pattern: r"(?-i:[A-Z][A-Z0-9]*[_\-](?:SECRET(?:[_\-]ACCESS)?[_\-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_\-]?KEY))\s*=\s*\S{8,}",
        entity_group: "CREDENTIAL",
        validator: None,
    },
];

pub struct DlpPipeline {
    set: RegexSet,
    regexes: Vec<Regex>,
    entity_groups: Vec<&'static str>,
    validators: Vec<Option<fn(&str) -> bool>>,
}

impl DlpPipeline {
    pub fn new() -> Self {
        let mut regexes = Vec::new();
        let mut patterns = Vec::new();
        let mut entity_groups = Vec::new();
        let mut validators = Vec::new();

        for p in DLP_PATTERNS {
            patterns.push(p.pattern);
            regexes.push(Regex::new(p.pattern).unwrap());
            entity_groups.push(p.entity_group);
            validators.push(p.validator);
        }

        let set = RegexSet::new(patterns).unwrap();
        DlpPipeline {
            set,
            regexes,
            entity_groups,
            validators,
        }
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let matches = self.set.matches(text);
        for idx in matches.iter() {
            if let Some(validator) = self.validators[idx] {
                if let Some(mat) = self.regexes[idx].find(text) {
                    if validator(mat.as_str()) {
                        return EvaluationResult {
                            class_name: self.entity_groups[idx].to_string(),
                            confidence: 1.0,
                            level: "L1".to_string(),
                        };
                    }
                }
            } else {
                return EvaluationResult {
                    class_name: self.entity_groups[idx].to_string(),
                    confidence: 1.0,
                    level: "L1".to_string(),
                };
            }
        }

        EvaluationResult {
            class_name: "safe".to_string(),
            confidence: 1.0,
            level: "L1".to_string(),
        }
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}
