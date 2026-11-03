// SPDX-License-Identifier: GPL-3.0-only
//! URL credentials (G-URL: F12, G08, G09). `dlp_credential_in_url` drops a
//! `token` parameter next to pagination, cursor or CSRF parameters;
//! `dlp_signed_url_signature` needs the structure of a signed URL (X-Amz-*,
//! X-Goog-*, CloudFront `Expires`/`Key-Pair-Id`, Azure SAS `sv` with `se` or
//! `sp`). `dlp_auth_url_token` reports the token of reset, magic-link,
//! invitation and OAuth redirect URLs, `dlp_otp_secret` the Base32 seed of an
//! otpauth:// URI or after a TOTP/2FA secret name. Values come from the golden
//! generator.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

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

fn scan(text: &str) -> SecurityScanResult {
    static SCANNER: OnceLock<SecurityGateway> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            )
        })
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

/// The unsuppressed `matched_rules` entry of `rule_id` in `text`.
fn rule_entry(text: &str, rule_id: &str) -> Option<Value> {
    scan(text).layers[0]
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

/// Whether `rule_id` reports exactly `value` in `text`.
fn reports(text: &str, rule_id: &str, value: &str) -> bool {
    rule_entry(text, rule_id).is_some()
        && scan(text)
            .evidence_spans
            .iter()
            .any(|span| span.text == value)
}

fn no_secret(text: &str) -> bool {
    scan(text).evidence_spans.is_empty()
}

/// DE and EN carriers of an otpauth URI or a TOTP seed.
const OTP_CARRIERS: &[&str] = &[
    "# 2FA für den Build-Account\nTOTP_SECRET={}\n",
    "mfa:\n  totp_secret: \"{}\"\n",
    "{\"user\": \"ada\", \"otp_secret\": \"{}\"}\n",
    "QR-Code-Inhalt: otpauth://totp/ACME:ada@example.de?secret={}&issuer=ACME&digits=6\n",
    "<img src=\"/qr?data=otpauth://totp/Shop:ops?issuer=Shop&amp;secret={}\">\n",
    "$ oathtool --totp -b \"$(echo {})\" # otp key: {}\n",
    "2026-11-02T08:12:44Z INFO enroll: otpauth://hotp/Vault:svc?secret={}&counter=0\n",
    "Hier der 2FA-Schlüssel: {} (bitte im Authenticator eintragen)\n",
    "Authenticator key = {}\n",
];

/// DE and EN carriers of an auth URL token.
const AUTH_URL_CARRIERS: &[&str] = &[
    "RESET_LINK=https://app.example.de/reset-password/{}\n",
    "Passwort zurücksetzen: https://konto.example.de/passwort-zuruecksetzen/{}\n",
    "Location: https://app.example.com/callback#access_token={}&token_type=bearer&expires_in=3600\n",
    "{\"redirect\": \"https://app.example.com/oauth/callback?code={}&state=xyz\"}\n",
    "You're invited: https://app.example.com/invitations/accept/{}\n",
    "2026-11-02T08:12:44Z INFO mail: sent magic link https://app.example.com/magic-link/{} to ada\n",
    "curl 'https://app.example.com/verify-email?verification_token={}'\n",
    "Einladung: https://team.example.de/einladung/{}\n",
];

#[test]
fn otp_secrets_are_reported_whole_in_de_and_en_carriers() {
    for seed in 0..6 {
        let value = generated("totp_base32_secret", seed);
        for (index, carrier) in OTP_CARRIERS.iter().enumerate() {
            let text = carrier.replace("{}", &value);
            assert!(
                reports(&text, "dlp_otp_secret", &value),
                "seed {seed}: carrier {index}"
            );
            let entry = rule_entry(&text, "dlp_otp_secret").unwrap();
            assert_eq!(entry["subtype"], "otp_secret");
        }
    }
}

#[test]
fn otp_lookalikes_documented_seed_and_references_are_not_reported() {
    for seed in 0..6 {
        let value = generated("totp_base32_secret_short", seed);
        for carrier in OTP_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(rule_entry(&text, "dlp_otp_secret").is_none(), "seed {seed}");
        }
    }
    for text in [
        // Google Authenticator wiki example seed.
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        "TOTP_SECRET=${TOTP_SECRET}",
        "otpauth://totp/ACME:ada?secret=YOUR_SECRET&issuer=ACME",
        "otp_secret: AAAAAAAAAAAAAAAAAAAAAAAA",
        "totp_key = ABCDEFGHIJKLMNOPQRSTUVWX",
        "otpauth://totp/ACME:ada?secret=e3b0c44298fc1c149afbf4c8996fb924&issuer=ACME",
    ] {
        assert!(rule_entry(text, "dlp_otp_secret").is_none(), "{text}");
    }
}

#[test]
fn auth_url_tokens_are_reported_whole_in_de_and_en_carriers() {
    for seed in 0..6 {
        let value = generated("auth_url_opaque_token", seed);
        for (index, carrier) in AUTH_URL_CARRIERS.iter().enumerate() {
            let text = carrier.replace("{}", &value);
            assert!(
                reports(&text, "dlp_auth_url_token", &value),
                "seed {seed}: carrier {index}"
            );
            let entry = rule_entry(&text, "dlp_auth_url_token").unwrap();
            assert_eq!(entry["subtype"], "auth_url");
        }
    }
}

#[test]
fn auth_url_lookalikes_uuids_and_codes_without_redirect_are_not_reported() {
    for seed in 0..6 {
        let value = generated("auth_url_token_short", seed);
        for carrier in AUTH_URL_CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(
                rule_entry(&text, "dlp_auth_url_token").is_none(),
                "seed {seed}"
            );
        }
    }
    let value = generated("auth_url_opaque_token", 1);
    for text in [
        "https://app.example.com/invite/4f7d2c1e-9a3b-4c5d-8e6f-1a2b3c4d5e6f".to_string(),
        "https://app.example.com/reset-password/team-onboarding-welcome".to_string(),
        "https://app.example.com/reset-password/{{ reset_token }}".to_string(),
        "https://docs.example.com/search?code=print_hello_world_example".to_string(),
        format!("https://playground.example.com/run?code={value}"),
        "https://app.example.com/confirm-email/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
    ] {
        assert!(rule_entry(&text, "dlp_auth_url_token").is_none(), "{text}");
    }
}

#[test]
fn pagination_cursor_and_csrf_token_parameters_are_no_url_credentials() {
    let value = generated("auth_url_opaque_token", 2);
    for template in [
        "\"next\": \"https://api.example.com/v1/items?limit=50&token={}\"",
        "GET /api/v2/search?q=lager&page=3&token={} HTTP/1.1",
        "https://app.example.de/abmelden?_csrf=1&token={}",
        "<a href=\"/orders?cursor=b2Zmc2V0&amp;token={}\">Weiter</a>",
    ] {
        let text = template.replace("{}", &value);
        assert!(
            rule_entry(&text, "dlp_credential_in_url").is_none(),
            "{template}"
        );
    }
    let text =
        format!("Link aus dem Ticket: https://intranet.example.de/report?id=7&token={value}");
    assert!(reports(&text, "dlp_credential_in_url", &value));
}

#[test]
fn signatures_need_signed_url_structure() {
    let value = generated("aws_sigv4_signature", 4);
    for template in [
        "https://b.s3.eu-central-1.amazonaws.com/q3.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature={}",
        "https://storage.googleapis.com/b/o.csv?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature={}",
        "Download-Link (15 Minuten gültig): https://files.example.de/bericht.zip?Expires=1767225600&Signature={}",
        "https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&se=2026-12-01T00%3A00%3A00Z&sp=r&sig={}",
    ] {
        let text = template.replace("{}", &value);
        assert!(reports(&text, "dlp_signed_url_signature", &value), "{template}");
    }
    for template in [
        "https://api.example.com/v1/items?page=2&sig={}",
        "https://hooks.example.com/incoming?Signature={}",
        "Prüfsumme der Datei: https://mirror.example.de/pkg.tar.gz?sig={}",
    ] {
        let text = template.replace("{}", &value);
        assert!(
            rule_entry(&text, "dlp_signed_url_signature").is_none(),
            "{template}"
        );
    }
}

#[test]
fn plain_urls_carry_no_secret() {
    for text in [
        "https://app.example.com/invitations/accept/new",
        "https://api.example.com/v1/items?page=2&per_page=50",
        "otpauth://totp/ACME:ada?issuer=ACME&digits=6",
    ] {
        assert!(no_secret(text), "{text}");
    }
}
