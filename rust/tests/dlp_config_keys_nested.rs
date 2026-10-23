// SPDX-License-Identifier: GPL-3.0-only
//! K05B: config key→value extraction, part 2 (YAML, JSON, TOML) with the
//! value-shape filter of K05.
//!
//! A key binds its whole value at any nesting depth (indented YAML mappings
//! and list entries, nested JSON objects, TOML tables), and an array under a
//! credential key binds each string item: JSON and TOML arrays (also over
//! several lines), YAML flow and block sequences. A plural key (`api_keys`,
//! `tokens`) binds only items. The K05 shapes that are no secret (UUIDs,
//! prefixed and keyed hex digests, ObjectIds, template fields, references,
//! booleans, numbers, paths, URLs without credentials) stay silent in every
//! format, as values and as items, and so do YAML aliases, SOPS/Ansible
//! Vault values and lists that hold words, templates or tokenizer entries.
//! Values are synthetic.

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

/// A password with `;`, `,` and `}` inside, as the generator's
/// `quoted_punctuated_password` shapes it.
const PUNCTUATED: &str = "qe;Tz8Wm4K,93}RV";
const TOKEN_A: &str = "Tz8Wm4K93RVqe7xAb2Lp";
const TOKEN_B: &str = "Kx7pQ2vL9rT4mN8bW3sD";

#[test]
fn nested_yaml_keys_bind_the_whole_plain_value() {
    for (template, rule_id) in [
        (
            "spring:\n  datasource:\n    url: jdbc:postgresql://db:5432/orders\n    password: {0}\n",
            "dlp_password_assignment",
        ),
        (
            "lager:\n  datenbank:\n    host: db.lager.intern\n    passwort: {0}  # rotiert im September\n",
            "dlp_password_assignment",
        ),
        (
            "services:\n  - name: billing\n    client_secret: {0}\n",
            "dlp_generic_credential_assignment",
        ),
        (
            "versand:\n  - name: paketdienst\n    zugangstoken: {0} # produktiv\n",
            "dlp_generic_credential_assignment",
        ),
        (
            "- password: {0}\n- user: reports\n",
            "dlp_password_assignment",
        ),
    ] {
        assert_values(template, &[PUNCTUATED], rule_id, Some("yaml"));
    }
}

#[test]
fn quoted_json_toml_and_yaml_values_run_past_escapes() {
    let escaped = "Tz8\\\"Wm4K93RV";
    assert_values(
        "{\"db\": {\"host\": \"db.internal\", \"password\": \"{0}\"}}\n",
        &[escaped],
        "dlp_password_assignment",
        Some("json"),
    );
    assert_values(
        "[database]\nhost = \"db.internal\"\npassword = \"{0}\"\n",
        &[escaped],
        "dlp_password_assignment",
        Some("properties"),
    );
    assert_values(
        "lager:\n  passwort: \"{0}\"  # rotiert\n",
        &[escaped],
        "dlp_password_assignment",
        Some("yaml"),
    );
    assert_values(
        "\"api-key\" = \"{0}\"\n",
        &[PUNCTUATED],
        "dlp_generic_credential_assignment",
        None,
    );
}

#[test]
fn arrays_bind_each_item() {
    for (template, format) in [
        ("{\"auth\": {\"api_keys\": [\"{0}\", \"{1}\"]}}\n", "json"),
        (
            "{\n  \"lager\": {\n    \"zugangstokens\": [\n      \"{0}\",\n      \"{1}\"\n    ]\n  }\n}\n",
            "json",
        ),
        ("[auth]\napi_keys = [\"{0}\", '{1}']\n", "toml"),
        (
            "[versand]\ntokens = [\n  \"{0}\",  # primär\n  \"{1}\",\n]\n",
            "toml",
        ),
        ("auth:\n  tokens: [{0}, \"{1}\"]\n", "yaml"),
        ("auth:\n  api_keys:\n    - {0}\n    - \"{1}\" # rotated\n", "yaml"),
        ("api_schluessel:\n- {0}\n\n- {1}\nregion: eu\n", "yaml"),
        ("auth:\n  token:\n    - {0}\n    - {1}\n", "yaml"),
    ] {
        assert_values(
            template,
            &[TOKEN_A, TOKEN_B],
            "dlp_generic_credential_assignment",
            Some(format),
        );
    }
    assert_values(
        "db:\n  passwords:\n    - '{0}'\n  user: reports\n",
        &[PUNCTUATED],
        "dlp_password_assignment",
        Some("yaml"),
    );
    assert_values(
        "environment:\n  SERVICE_TOKENS:\n    - {0}\n",
        &[TOKEN_A],
        "dlp_env_var_secret",
        Some("yaml"),
    );
}

#[test]
fn plural_keys_bind_no_scalar() {
    assert_silent(&[
        "auth:\n  tokens: Tz8Wm4K93RVqe7xAb2Lp\n",
        "{\"api_keys\": \"Tz8Wm4K93RVqe7xAb2Lp\"}\n",
        "passwords = \"qe;Tz8Wm4K,93}RV\"\n",
    ]);
}

#[test]
fn uuids_are_no_secrets_in_any_format() {
    assert_silent(&[
        "lager:\n  api_token: 3f2a9c4e-7b1d-4e8a-9c2f-5d6e7f8a9b0c\n",
        "{\"auth\": {\"client_secret\": \"550e8400-e29b-41d4-a716-446655440000\"}}\n",
        "[auth]\napi_keys = [\"550e8400-e29b-41d4-a716-446655440000\"]\n",
        "tokens:\n  - 3f2a9c4e-7b1d-4e8a-9c2f-5d6e7f8a9b0c\n",
    ]);
}

#[test]
fn digests_and_object_ids_are_no_secrets_in_any_format() {
    assert_silent(&[
        "lager:\n  geheimnis: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
        "{\"assets\": {\"access_token\": \"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"}}\n",
        "[konto]\ngehashtes_passwort = \"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\"\n",
        "account:\n  hashed_password: 5d41402abc4b2a76b9719d911017c592\n",
        "sha256_tokens = [\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"]\n",
        "{\"lager\": {\"zugangstokens\": [\"5f8d0c3e9b1a2d4c6e8f0a1b\", \"5f8d0c3e9b1a2d4c6e8f0a1c\"]}}\n",
        "owner:\n  api_token: 6512bd43d9caa6e02c990b0a\n",
    ]);
}

#[test]
fn templates_and_references_are_no_secrets_in_any_format() {
    assert_silent(&[
        "lager:\n  passwort: \"{{ lager_passwort }}\"\n",
        "{\"oauth\": {\"client_secret\": \"%(client_secret)s\"}}\n",
        "[versand]\ntokens = [\"${VERSAND_TOKEN}\", \"{versand_token}\"]\n",
        "api_schluessel:\n  - $LAGER_API_SCHLUESSEL\n  - \"%LAGER_API_SCHLUESSEL%\"\n",
        "auth:\n  api_key: env:BILLING_API_KEY\n",
        "produktion:\n  passwort: *lager_standard_passwort\n",
        "password: ENC[AES256_GCM,data:Zm9vYmFyYmF6cXV4,iv:Tz8Wm4K93RVq,tag:Kx7pQ2vL,type:str]\n",
        "db:\n  password: !vault |\n    $ANSIBLE_VAULT;1.1;AES256\n",
        "Resources:\n  Config:\n    token: !Sub \"${Token}\"\n",
    ]);
}

#[test]
fn booleans_numbers_paths_and_urls_are_no_secrets_in_any_format() {
    assert_silent(&[
        "verschluesselung:\n  geheimnis: deaktiviert\n",
        "{\"auth\": {\"api_token\": \"disabled\"}}\n",
        "[sicherheit]\ntokens = [86400, 3600]\n",
        "oauth:\n  client_secret: 86400000\n",
        "lager:\n  passwort: /run/secrets/lager_passwort\n",
        "[database]\npasswords = ['C:\\secrets\\orders-db.txt']\n",
        "{\"versand\": {\"api_schluessel\": \"https://tresor.lager.intern/v1/versand\"}}\n",
        "idp:\n  client_secret: https://auth.internal/realms/acme/protocol/openid-connect/token\n",
    ]);
}

#[test]
fn lists_of_words_templates_and_mappings_bind_nothing() {
    assert_silent(&[
        // Tokenizer entries: one item looks like a token, the list does not.
        "{\"tokens\": [\"<|endoftext|>\", \"Ġconstructor\", \"ing</w>\", \"abc12345\"]}\n",
        "{\"tokens\": [\"the\", \"quick\", \"brown\"]}\n",
        "api_keys:\n  - Tz8Wm4K93RVqe7xAb2Lp\n  - YOUR_API_KEY_HERE\n",
        "\"tokens\": [\n    {\"type\": \"word\", \"value\": \"Tz8Wm4K93RVqe7xAb2Lp\"}\n]\n",
        "imagePullSecrets:\n  - name: regcred\n",
        "existingSecrets: [abc123def456]\n",
        "nextTokens: [\"Tz8Wm4K93RVqe7xAb2Lp\"]\n",
        "scopes:\n  - read:org\ntoken_scopes: [\"read:org\", \"repo\"]\n",
        "secrets:\n  - db-password\n  - api-key\n",
        "token: read,write\n",
    ]);
}

#[test]
fn code_is_no_yaml() {
    assert_silent(&[
        "const config = {\n  secret: process.env.SECRET,\n  token: this.token\n}\n",
        "interface Login {\n  password: string;\n  token: string\n}\n",
        "def test():\n    assert parse(\"password: {{ secret }}\")\n",
        "    token: f\"t{request.number}s0\"\n",
        "  password: pre${SUFFIX}\n",
        // Rust raw pointer types read like YAML aliases.
        "pub struct passwd {\n    pub pw_name: *mut c_char,\n    pub pw_passwd: *mut c_char,\n}\n",
        "pub fn getpwnam_r(\n    name: *const c_char,\n    pwd: *mut passwd,\n) -> c_int;\n",
    ]);
}
