// SPDX-License-Identifier: GPL-3.0-only
//! G02: structure-aware config keys. In a config document (YAML, JSON,
//! TOML, HCL, XML, INI/properties, .env) `dlp_generic_credential_assignment`
//! also binds the credentials, private key, secret key, signing key and
//! passphrase keys and their DE variants (Zugangsdaten, Anmeldedaten,
//! privater/geheimer Schlüssel). In program source these keys keep the base
//! behaviour: object literals, kwargs, struct fields and test fixtures bind
//! nothing, and interpolations, file names, placeholders, expressions and key
//! IDs stay silent in config documents too. Values are synthetic.

use std::sync::OnceLock;

use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult};

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

/// The unsuppressed `matched_rules` entries: rule id and config format.
fn matched_rules(result: &SecurityScanResult) -> Vec<(String, Option<String>)> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("suppressed_by").is_none())
                .map(|rule| {
                    (
                        rule["rule_id"].as_str().unwrap().to_owned(),
                        rule.get("structure")
                            .and_then(|format| format.as_str())
                            .map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `template` with `values` at `{0}`, `{1}` … yields exactly one span per
/// value, each by `rule_id` from a config value of `format` (or from the
/// rule's regex for `None`).
fn assert_values(template: &str, values: &[&str], rule_id: &str, format: Option<&str>) {
    let mut text = template.to_owned();
    for (index, value) in values.iter().enumerate() {
        text = text.replace(&format!("{{{index}}}"), value);
    }
    let mut expected: Vec<_> = values
        .iter()
        .map(|value| {
            let start = text[..text.find(value).unwrap()].chars().count();
            (start, start + value.chars().count(), value.to_string())
        })
        .collect();
    expected.sort();
    let result = scan(&text);
    let mut spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.start_char, span.end_char, span.text.clone()))
        .collect();
    spans.sort();
    assert_eq!(spans, expected, "{rule_id}: {text:?}");
    assert_eq!(
        matched_rules(&result),
        vec![(rule_id.to_owned(), format.map(str::to_owned)); values.len()],
        "{rule_id}: {text:?}"
    );
}

fn assert_silent(texts: &[&str]) {
    for text in texts {
        let result = scan(text);
        assert!(
            result.evidence_spans.is_empty(),
            "expected no DLP finding in {text:?}, got {:?}",
            result
                .evidence_spans
                .iter()
                .map(|span| (&span.label, &span.text))
                .collect::<Vec<_>>()
        );
    }
}

const TOKEN_A: &str = "Tz8Wm4K93RVqe7xAb2Lp";
const TOKEN_B: &str = "Kx7pQ2vL9rT4mN8bW3sD";

const GENERIC: &str = "dlp_generic_credential_assignment";

#[test]
fn document_keys_bind_in_yaml_json_toml_and_properties() {
    assert_values(
        "smtp:\n  host: mail.internal\n  port: 587\n  credentials: {0}\n",
        &[TOKEN_A],
        GENERIC,
        Some("yaml"),
    );
    assert_values(
        "versand:\n  zugangsdaten: \"{0}\" # rotiert\n",
        &[TOKEN_A],
        GENERIC,
        Some("yaml"),
    );
    assert_values(
        "{\n  \"jwt\": {\n    \"privateKey\": \"{0}\"\n  }\n}\n",
        &[TOKEN_A],
        GENERIC,
        Some("json"),
    );
    assert_values(
        "{\"signatur\": {\"geheimer_schluessel\": \"{0}\"}}\n",
        &[TOKEN_A],
        GENERIC,
        Some("json"),
    );
    assert_values(
        "[session]\ncookie_name = \"billing\"\nsecret_key = \"{0}\"\n",
        &[TOKEN_A],
        GENERIC,
        Some("properties"),
    );
    assert_values(
        "[signatur]\nprivate_keys = [\"{0}\", \"{1}\"]\n",
        &[TOKEN_A, TOKEN_B],
        GENERIC,
        Some("toml"),
    );
    assert_values(
        "# billing\nspring.application.name=billing\nbilling.webhook.signing-key={0}\n",
        &[TOKEN_A],
        GENERIC,
        Some("properties"),
    );
    assert_values(
        "# Lagerdienst\nLAGER_UMGEBUNG=produktion\nLAGER_SIGNING_KEY={0}\n",
        &[TOKEN_A],
        GENERIC,
        Some("env"),
    );
}

#[test]
fn document_keys_bind_in_hcl_and_xml() {
    assert_values(
        "provider \"acme\" {\n  server     = \"https://acme.internal/directory\"\n  passphrase = \"{0}\"\n}\n",
        &[TOKEN_A],
        GENERIC,
        Some("hcl"),
    );
    assert_values(
        "<configuration>\n  <signing>\n    <signingKey>{0}</signingKey>\n  </signing>\n</configuration>\n",
        &[TOKEN_A],
        GENERIC,
        Some("xml"),
    );
    assert_values(
        "<properties>\n  <entry key=\"lager.anmeldedaten\">{0}</entry>\n</properties>\n",
        &[TOKEN_A],
        GENERIC,
        Some("xml"),
    );
}

#[test]
fn document_keys_bind_nothing_in_program_source() {
    let token = TOKEN_A;
    assert_silent(&[
        // JS/TS object literals.
        &format!("const client = new Client({{\n  apiKey: process.env.API_KEY,\n  privateKey: \"{token}\",\n  credentials: \"{token}\"\n}});\n"),
        &format!("export const config = {{\n  signingKey: \"{token}\"\n}}\n"),
        &format!("const fixture = {{\n  \"credentials\": \"{token}\",\n  \"privateKey\": \"{token}\"\n}};\n"),
        // Python kwargs and assignments in a module.
        &format!("import os\n\nsigner = Signer(private_key=\"{token}\")\nsecret_key = \"{token}\"\n"),
        &format!("def make_signer():\n    passphrase = \"{token}\"\n    return Signer(passphrase)\n"),
        // Java/Kotlin/Go fields.
        &format!("public final class SigningConfig {{\n    private String secretKey = \"{token}\";\n}}\n"),
        &format!("data class SigningConfig(\n    val privateKey: String = \"{token}\",\n)\n"),
        &format!("type Config struct {{\n\tPrivateKey string\n}}\n\nvar cfg = Config{{\n\tPrivateKey: \"{token}\",\n}}\n"),
        // A test fixture.
        &format!("def test_signer():\n    signer = Signer(private_key=\"{token}\", secret_key=\"{token}\")\n    assert signer\n"),
        // HTML with a script is no XML config.
        &format!("<html>\n<script>\nconst cfg = {{\n  privateKey: \"{token}\"\n}}\n</script>\n</html>\n"),
    ]);
}

#[test]
fn document_keys_reject_non_secret_values_in_config_documents() {
    assert_silent(&[
        "lager:\n  zugangsdaten: ${LAGER_ZUGANGSDATEN}\n  private_key: ./schluessel/lager-signatur.pem\n",
        "{\n  \"privateKey\": \"<HIER_SCHLUESSEL_EINTRAGEN>\",\n  \"signingKey\": \"550e8400-e29b-41d4-a716-446655440000\"\n}\n",
        "provider \"lager\" {\n  passphrase  = var.lager_passphrase\n}\n",
        "app.signing.private-key=classpath:keys/private.pem\napp.session.secret-key=changeme\n",
        "<configuration>\n  <privateKey>${env.PRIVATE_KEY}</privateKey>\n  <credentials>same-origin</credentials>\n</configuration>\n",
        "signing:\n  secret_key: secretKeyRef\n  private_key: signing.privateKey\n",
        "{\"credentials\": \"include\", \"signingKey\": \"sha256:5d41402abc4b2a76b9719d911017c592\"}\n",
    ]);
}
