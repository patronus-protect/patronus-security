// SPDX-License-Identifier: GPL-3.0-only
//! K05C: config key→value extraction, part 3 (HCL, XML attributes and
//! elements) with the value-shape filter of K05.
//!
//! An attribute in an HCL block binds its quoted string or the items of its
//! array; a bare value there is an expression. A `variable "…"` block binds
//! its `default` through the variable name. An XML element named by the key
//! binds its text (also in CDATA), and a config element whose `key`/`name`
//! attribute holds the key binds its `value` attribute in any order or its
//! text. The K05 shapes that are no secret (UUIDs, prefixed and keyed hex
//! digests, ObjectIds, template fields, references, booleans, numbers, paths,
//! URLs without credentials) stay silent in both formats, also when the key
//! stands apart from the value (`variable "…_sha256"`, `<hashed_password>`).
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
fn hcl_variable_defaults_bind_through_the_variable_name() {
    assert_values(
        "variable \"db_password\" {\n  description = \"Password of the orders database\"\n  type        = string\n  default     = \"{0}\"\n  sensitive   = true\n}\n",
        &[PUNCTUATED],
        "dlp_password_assignment",
        Some("hcl"),
    );
    assert_values(
        "variable \"lager_zugangstoken\" {\n  type    = string\n  validation {\n    condition = length(var.lager_zugangstoken) > 16\n  }\n  default = \"{0}\" # rotiert\n}\n",
        &[TOKEN_A],
        "dlp_generic_credential_assignment",
        Some("hcl"),
    );
    assert_values(
        "variable \"api_tokens\" {\n  type    = list(string)\n  default = [\n    \"{0}\",\n    \"{1}\", // rotated\n  ]\n}\n",
        &[TOKEN_A, TOKEN_B],
        "dlp_generic_credential_assignment",
        Some("hcl"),
    );
}

#[test]
fn hcl_attributes_and_arrays_in_blocks() {
    assert_values(
        "locals {\n  region   = \"eu-central-1\"\n  api_keys = [\"{0}\", \"{1}\"]\n}\n",
        &[TOKEN_A, TOKEN_B],
        "dlp_generic_credential_assignment",
        Some("hcl"),
    );
    assert_values(
        "resource \"vault_generic_secret\" \"versand\" {\n  path = \"secret/versand\"\n  data_json = jsonencode({\n    zugangstokens = [\"{0}\"]\n  })\n}\n",
        &[TOKEN_A],
        "dlp_generic_credential_assignment",
        Some("hcl"),
    );
    // A string attribute is also matched by the rule's regex.
    assert_values(
        "resource \"aws_db_instance\" \"orders\" {\n  username = \"orders\"\n  password = \"{0}\"\n}\n",
        &[PUNCTUATED],
        "dlp_password_assignment",
        None,
    );
}

#[test]
fn xml_elements_bind_their_text() {
    for (template, rule_id) in [
        (
            "<settings>\n  <servers>\n    <server>\n      <id>nexus</id>\n      <password>{0}</password>\n    </server>\n  </servers>\n</settings>\n",
            "dlp_password_assignment",
        ),
        (
            "<lager>\n  <datenbank>\n    <passwort><![CDATA[{0}]]></passwort>\n  </datenbank>\n</lager>\n",
            "dlp_password_assignment",
        ),
        (
            "<config xmlns:db=\"urn:orders\">\n  <db:password> {0} </db:password>\n</config>\n",
            "dlp_password_assignment",
        ),
        (
            "<oauth>\n  <clientSecret>{0}</clientSecret>\n</oauth>\n",
            "dlp_generic_credential_assignment",
        ),
        (
            "<versand>\n  <zugangstoken>{0}</zugangstoken>\n</versand>\n",
            "dlp_generic_credential_assignment",
        ),
    ] {
        let value = if rule_id == "dlp_password_assignment" { PUNCTUATED } else { TOKEN_A };
        assert_values(template, &[value], rule_id, Some("xml"));
    }
}

#[test]
fn xml_keyed_elements_bind_their_value_or_text() {
    for (template, rule_id) in [
        (
            "<hibernate-configuration>\n  <session-factory>\n    <property name=\"hibernate.connection.password\">{0}</property>\n  </session-factory>\n</hibernate-configuration>\n",
            "dlp_password_assignment",
        ),
        (
            "<properties>\n  <entry key=\"client_secret\">{0}</entry>\n</properties>\n",
            "dlp_generic_credential_assignment",
        ),
        (
            "<appSettings>\n  <add value=\"{0}\" key=\"ApiToken\" />\n</appSettings>\n",
            "dlp_generic_credential_assignment",
        ),
        (
            "<resources>\n  <string name=\"lager_api_schluessel\">{0}</string>\n</resources>\n",
            "dlp_generic_credential_assignment",
        ),
    ] {
        assert_values(template, &[TOKEN_A], rule_id, Some("xml"));
    }
}

#[test]
fn hcl_expressions_and_non_secret_shapes_are_silent() {
    assert_silent(&[
        "resource \"aws_db_instance\" \"orders\" {\n  password = var.db_password\n}\n",
        "resource \"aws_db_instance\" \"orders\" {\n  password = random_password.orders.result\n}\n",
        "provider \"vault\" {\n  token = data.vault_generic_secret.ci.data[\"token\"]\n}\n",
        "resource \"x\" \"y\" {\n  password = \"${var.db_password}\"\n}\n",
        "locals {\n  api_keys = [var.primary_key, \"${var.secondary_key}\"]\n}\n",
        "resource \"x\" \"y\" {\n  client_secret = \"550e8400-e29b-41d4-a716-446655440000\"\n}\n",
        "module \"lager\" {\n  source = \"./lager\"\n  zugangstoken = \"6512bd43d9caa6e02c990b0a\"\n}\n",
        "variable \"db_password_sha256\" {\n  default = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n}\n",
        "variable \"lager_passwort\" {\n  default = \"/run/secrets/lager_passwort\"\n}\n",
        "variable \"api_token\" {\n  default = \"https://vault.internal/v1/ci/token\"\n}\n",
        "variable \"db_password\" {\n  default = \"changeme\"\n}\n",
        "variable \"geheimnis\" {\n  default = null\n}\n",
        "variable \"api_tokens\" {\n  default = [\"550e8400-e29b-41d4-a716-446655440000\", \"Tz8Wm4K93RVqe7xAb2Lp\"]\n}\n",
        "variable \"db_password\" {\n  description = \"Passwort der Lagerdatenbank\"\n  type        = string\n  sensitive   = true\n}\n",
    ]);
}

#[test]
fn xml_non_secret_shapes_and_markup_are_silent() {
    assert_silent(&[
        "<server>\n  <password>${env.NEXUS_PASSWORD}</password>\n</server>\n",
        "<datasource>\n  <passwort>@lager.passwort@</passwort>\n</datasource>\n",
        "<PropertyGroup>\n  <ApiToken>$(LagerApiToken)</ApiToken>\n</PropertyGroup>\n",
        "<auth>\n  <client_secret>550e8400-e29b-41d4-a716-446655440000</client_secret>\n</auth>\n",
        "<konto>\n  <hashed_password>5d41402abc4b2a76b9719d911017c592</hashed_password>\n</konto>\n",
        "<appSettings>\n  <add key=\"PasswordSha256\" value=\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\" />\n</appSettings>\n",
        "<owner>\n  <api_token>6512bd43d9caa6e02c990b0a</api_token>\n</owner>\n",
        "<feature>\n  <api_token>disabled</api_token>\n</feature>\n",
        "<session>\n  <token>86400</token>\n</session>\n",
        "<lager>\n  <passwort>/run/secrets/lager_passwort</passwort>\n</lager>\n",
        "<idp>\n  <client_secret>https://auth.internal/realms/acme/protocol/openid-connect/token</client_secret>\n</idp>\n",
        "<entry key=\"client_secret\"><![CDATA[{{ client_secret }}]]></entry>\n",
        "<server>\n  <password></password>\n  <token/>\n</server>\n",
        "<xs:element name=\"password\" type=\"xs:string\"/>\n",
        "<string name=\"password\">Passwort</string>\n<string name=\"api_key\">YOUR_API_KEY</string>\n",
        "/// <param name=\"token\">Tz8Wm4K93RVqe7xAb2Lp</param>\n",
        // XML in strings of code: a test fixture and a concatenation.
        "\t\tRaw:      `<password>Tz8Wm4K93RVqe7xAb2Lp</password>`,\n",
        "\t\t\"<token>\"+generatedToken+\"</token>\",\n",
        "<password>Tz8Wm4K93RVqe7xAb2Lp</passwd>\n",
        "<password>\n  Tz8Wm4K93RVqe7xAb2Lp\n</password>\n",
        "<password><b>Tz8Wm4K93RVqe7xAb2Lp</b></password>\n",
        "<button value=\"Tz8Wm4K93RVqe7xAb2Lp\" name=\"token\">Go</button>\n",
    ]);
}

#[test]
fn hocon_and_code_blocks_are_no_hcl() {
    // HOCON takes bare strings; the K05 properties line stays.
    assert_values(
        "db {\n  password = {0}\n}\n",
        &[TOKEN_A],
        "dlp_password_assignment",
        None,
    );
    assert_silent(&[
        "function connect() {\n  password = getPassword(user)\n}\n",
        "class Login {\n  token = this.session.token\n}\n",
    ]);
}
