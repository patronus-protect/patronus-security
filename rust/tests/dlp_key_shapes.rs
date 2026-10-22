// SPDX-License-Identifier: GPL-3.0-only
//! T09: key shapes of the key-anchored rules (`dlp_password_assignment`,
//! `dlp_generic_credential_assignment`, `dlp_csrf_token`,
//! `dlp_password_hash`, `dlp_aws_secret_key`). Quoted and escaped keys
//! (`"client_secret":`, `'password' =>`, `\"db_password\":`), compound and
//! camelCase keys (`db_password`, `serviceSecret`, `PasswordHash`), typed
//! declarations (`const X: &str =`, `: string =`), subscripts
//! (`os.environ["DB_PASSWORD"] =`), escaped values in JSON strings and
//! notebooks and XML `key="…" value="…"` find their value. Cursor and
//! handle tokens, secret objects, field names and the code expressions of
//! T03 stay silent. Values are synthetic.

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

fn matched_rules(result: &SecurityScanResult) -> Vec<String> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("suppressed_by").is_none())
                .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// `template` with `value` at `{v}` yields exactly one span, the value, by
/// `rule_id`.
fn assert_exact(template: &str, value: &str, rule_id: &str) {
    let start = template[..template.find("{v}").unwrap()].chars().count();
    let text = template.replace("{v}", value);
    let result = scan(&text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.start_char, span.end_char, span.text.as_str()))
        .collect();
    assert_eq!(
        spans,
        vec![(start, start + value.chars().count(), value)],
        "{rule_id}: {text:?}"
    );
    assert_eq!(
        matched_rules(&result),
        vec![rule_id.to_owned()],
        "{rule_id}: {text:?}"
    );
}

fn assert_silent(texts: &[&str]) {
    let reported: Vec<_> = texts
        .iter()
        .filter_map(|text| {
            let result = scan(text);
            (!result.evidence_spans.is_empty()).then(|| {
                let spans: Vec<_> = result.evidence_spans.iter().map(|s| &s.text).collect();
                format!("{text:?} -> {spans:?}")
            })
        })
        .collect();
    assert!(reported.is_empty(), "reported: {reported:#?}");
}

/// Carriers of one value per key shape; `{k}` is the key in the convention
/// of the carrier (`snake`, `camel`, `pascal`, `upper`).
const CARRIERS: &[&str] = &[
    // JSON with a quoted key, also inside a JSON string.
    "{\n  \"credentials\": {\n    \"{snake}\": \"{v}\"\n  }\n}\n",
    "{\"config\": \"{\\\"{snake}\\\": \\\"{v}\\\"}\"}\n",
    // YAML, TOML and HCL with compound and camelCase keys.
    "upstream:\n  base_url: https://api.internal\n  {snake}: \"{v}\"\n",
    "anbindung:\n  spedition:\n    {camel}: \"{v}\"\n",
    "[upstream]\nbasis_url = \"https://api.intern\"\n{snake} = \"{v}\"\n",
    "provider \"acme\" {\n  region  = \"eu-central-1\"\n  {snake} = \"{v}\"\n}\n",
    // XML appSettings and attributes.
    "<appSettings>\n  <add key=\"{pascal}\" value=\"{v}\" />\n</appSettings>\n",
    "<exporter>\n  <credentials {camel}=\"{v}\" />\n</exporter>\n",
    // Typed declarations in TS, Rust, C# and Go, a JS object and PHP.
    "export const {camel}: string = \"{v}\";\n",
    "const {upper}: &str = \"{v}\";\n",
    "private const string {pascal} = \"{v}\";\n",
    "var {camel} string = \"{v}\"\n",
    "const client = new Client({ {camel}: \"{v}\" });\n",
    "return [\n    '{snake}' => '{v}',\n];\n",
    // Jupyter code cells: escaped quotes in the JSON source lines.
    "   \"source\": [\n    \"{snake} = \\\"{v}\\\"\\n\",\n    \"print(1)\"\n   ]\n",
    "   \"source\": [\n    \"os.environ[\\\"{upper}\\\"] = \\\"{v}\\\"\\n\",\n   ]\n",
    // Log lines.
    "2026-09-14T08:12:03Z DEBUG effective config: region=eu-central-1 {snake}={v} retries=3\n",
];

fn carriers(snake: &str, camel: &str) -> Vec<String> {
    let pascal = format!("{}{}", camel[..1].to_uppercase(), &camel[1..]);
    CARRIERS
        .iter()
        .map(|carrier| {
            carrier
                .replace("{snake}", snake)
                .replace("{camel}", camel)
                .replace("{pascal}", &pascal)
                .replace("{upper}", &snake.to_uppercase())
        })
        .collect()
}

#[test]
fn password_keys_in_every_shape() {
    for template in carriers("db_password", "dbPassword") {
        assert_exact(&template, "Kx7!pQ2#vL9@rT4", "dlp_password_assignment");
    }
}

#[test]
fn generic_credential_keys_in_every_shape() {
    for (snake, camel) in [
        ("client_secret", "clientSecret"),
        ("service_secret", "serviceSecret"),
        ("billing_api_key", "billingApiKey"),
    ] {
        for template in carriers(snake, camel) {
            assert_exact(
                &template,
                "Zq8Wm4Rk2Tn7Vb6Xc9Lp",
                "dlp_generic_credential_assignment",
            );
        }
    }
}

#[test]
fn csrf_keys_in_every_shape() {
    let value = ["Mopgc-yqWy-ooRk", "rLrVJDae5widHi", "uoI74R8bTsvyY8"].concat();
    for template in carriers("csrf_token", "csrfToken") {
        assert_exact(&template, &value, "dlp_csrf_token");
    }
}

#[test]
fn password_hash_keys_in_every_shape() {
    let hex = [
        "6669f2ce1be4e4b9",
        "d3f7daea911d4e59",
        "400609d84b91f923",
        "cf8ab6d403c14abc",
    ]
    .concat();
    let bcrypt = [
        "$2b$12$",
        "M5W1MXgRIFnRokMtyzTvxO",
        "RBEgwwymiqzTyHcOS31CVo7y2hlckV2",
    ]
    .concat();
    for template in carriers("password_hash", "passwordHash") {
        assert_exact(&template, &hex, "dlp_password_hash");
        assert_exact(&template, &bcrypt, "dlp_password_hash");
    }
    for template in carriers("admin_password_hash", "adminPasswordHash") {
        assert_exact(&template, &hex, "dlp_password_hash");
    }
}

#[test]
fn aws_secret_key_names_in_every_shape() {
    let value = ["Zq7Lm2Xc9Vb", "Np4/Rt8Wy+Hk", "3Gd6Fs1Jo5Ea", "Ui0Tw"].concat();
    for template in [
        "Aws-Secret-Access-Key: {v}\n",
        "{\n  \"awsSecretAccessKey\": \"{v}\"\n}\n",
        "export const awsSecretAccessKey: string = \"{v}\";\n",
        "const AWS_SECRET_ACCESS_KEY: &str = \"{v}\";\n",
        "<add key=\"AwsSecretAccessKey\" value=\"{v}\" />\n",
        "   \"source\": [\n    \"aws_secret_access_key = \\\"{v}\\\"\\n\",\n   ]\n",
    ] {
        assert_exact(template, &value, "dlp_aws_secret_key");
    }
}

#[test]
fn simple_keys_keep_their_shapes() {
    assert_exact(
        "{\"password\":\"{v}\"}",
        "Kx7!pQ2#vL9@rT4",
        "dlp_password_assignment",
    );
    assert_exact(
        "$db = ['password' => '{v}'];\n",
        "Kx7!pQ2#vL9@rT4",
        "dlp_password_assignment",
    );
    assert_exact(
        "<property name=\"password\" value=\"{v}\"/>\n",
        "Kx7!pQ2#vL9@rT4",
        "dlp_password_assignment",
    );
    assert_exact(
        "PASSWORD: str = \"{v}\"\n",
        "Kx7!pQ2#vL9@rT4",
        "dlp_password_assignment",
    );
}

#[test]
fn cursor_and_handle_tokens_and_secret_objects_are_no_credentials() {
    assert_silent(&[
        "{\"nextPageToken\": \"Q0FVUUFBYTFiMmMz\"}\n",
        "page_token = \"Q0FVUUFBYTFiMmMz\"\n",
        "    continuation_token: \"a8f3k2m9x7q1z5w4\"\n",
        "const cancellationToken: string = \"c4n7k2m9x7q1z5w4\";\n",
        "auth:\n  existingSecret: \"lager-release-auth\"\n",
        "imagePullSecret: regcred-intern-2026\n",
        "tls_secret: \"wildcard-intern-2026\"\n",
    ]);
}

#[test]
fn field_names_and_words_after_compound_keys_are_no_values() {
    assert_silent(&[
        "const routes = { forgotPassword: \"forgot-password\" };\n",
        "const fields = { confirmPassword: \"confirmPassword\" };\n",
        "labels:\n  serviceSecret: \"service-secret\"\n",
        "{\"csrf_token\": \"X-CSRF-Token\"}\n",
        "headers:\n  csrfHeader: X-CSRF-Token\n",
    ]);
}

#[test]
fn references_and_expressions_after_new_key_shapes_stay_silent() {
    assert_silent(&[
        "{\n  \"db_password\": \"${DB_PASSWORD}\"\n}\n",
        "const client = new Client({ dbPassword: process.env.DB_PASSWORD });\n",
        "const DB_PASSWORD: &str = env!(\"DB_PASSWORD\");\n",
        "<add key=\"DbPassword\" value=\"{{DB_PASSWORD}}\" />\n",
        "   \"source\": [\n    \"db_password = getpass.getpass()\\n\",\n   ]\n",
        "export interface Config {\n  dbPassword: string;\n  serviceSecret?: string;\n}\n",
        "pub struct Config {\n    pub db_password: Option<String>,\n}\n",
        "<meta name=\"csrf-token\" content=\"{{ csrf_token() }}\">\n",
        "    csrfToken: request.form.csrf,\n",
        "{\n  \"password_hash\": \"sha256\"\n}\n",
        "services:\n  app:\n    environment:\n      DB_PASSWORD: \"${DB_PASSWORD}\"\n",
    ]);
}

#[test]
fn documented_and_placeholder_values_after_new_key_shapes_stay_silent() {
    assert_silent(&[
        "{\n  \"client_secret\": \"<your client secret>\"\n}\n",
        "<add key=\"ClientSecret\" value=\"YOUR_CLIENT_SECRET\" />\n",
        "export const dbPassword: string = \"changeme\";\n",
        "   \"source\": [\n    \"service_secret = \\\"xxxxxxxxxxxxxxxx\\\"\\n\",\n   ]\n",
        "# Beispielwerte aus der Doku\n[upstream]\nservice_secret = \"abcabcabcabcabc\"\n",
    ]);
}

#[test]
fn code_after_quoted_keys_is_no_value() {
    assert_silent(&[
        "switch(p){case\"apiKey\":u=i.createElement(l,{key:t,schema:e})}\n",
        "$credentials = ['password' => !empty($uri['pass']) ? $uri['pass'] : ''];\n",
        "'password' => (string) $this->io->askAndHideAnswer('Password: '),\n",
        "{\"password\": pwd, \"user\": name}\n",
        "authorizePassword=e=>({authActions:t})=>{t.authorize(e)}\n",
        "export{authorizePassword:()=>authorizePassword,logout:()=>logout}\n",
        "type:C&&\"password\"===C?\"password\":\"text\",className:a\n",
        "  type={format === \\\"password\\\" ? \\\"password\\\" : \\\"text\\\"}\n",
        "<input placeholder=\"Enter the API key\"\n  value={auth?.get(\"key\") || \"\"} />\n",
    ]);
}

#[test]
fn identifiers_versions_and_words_after_field_keys_are_no_values() {
    assert_silent(&[
        "{\"devDependencies\": {\"parse-passwd\": \"^1.0.0\", \"@inquirer/password\": \"^5.2.3\"}}\n",
        "    \"pwd\": \"IPython.core.magics.osm:OSMagics\",\n",
        "{\"http-basic\": {\"repo\": {\"username\": \"bar\", \"password\": \"alpha\"}}}\n",
        "'example.org' => ['username' => 'someone', 'password' => 'little green men'],\n",
        "{\"gitlab.com\": {\"username\": \"gitlabuser\", \"token\": \"privatetoken\"}}\n",
        "    'COPILOT_GITHUB_TOKEN' => 'github-copilot',\n",
        "  const pathToken = \"prefixItems\"\n",
        "  const schemaToken = \"ExtensionKeywords\"\n",
    ]);
    // A passphrase with a capital or digit stays a value after a quoted key.
    assert_exact(
        "{\"db_password\": \"{v}\"}\n",
        "Blau Drache 47 Zaun",
        "dlp_password_assignment",
    );
}

#[test]
fn values_cut_at_the_capture_limit_are_no_values() {
    let jwt = [
        "eyJhbGciOiJIUzI1NiJ9.",
        "eyJzdWIiOiJFWEFNUExFIn0.",
        &"EXAMPLEKEY".repeat(20),
    ]
    .concat();
    assert_silent(&[
        &format!("app.id-token={jwt}\n"),
        &format!("Id-Token: {jwt}\n"),
        &format!("    id_token: \"{jwt}\"\n"),
        &format!("ID_TOKEN={jwt}\n"),
    ]);
}

#[test]
fn token_urls_with_compound_keys_belong_to_the_url_rules() {
    assert_silent(&[
        "https://github_token:x-oauth-basic@github.com/acme/app.git\n",
        "https://YOUR_GITHUB_TOKEN:x-oauth-basic@github.com/acme/app.git\n",
    ]);
}
