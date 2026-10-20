// SPDX-License-Identifier: GPL-3.0-only
//! T07: placeholders and environment/template references in value-capturing
//! rules are no findings, while real values next to them and placeholder-like
//! real passwords stay detected. K06 adds template syntaxes, secret-manager
//! references, DE/EN placeholders and values that only name the credential.
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

fn matched_rules(result: &SecurityScanResult) -> Vec<String> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn assert_reported(text: &str, rule_id: &str, value: &str) {
    let result = scan(text);
    assert!(
        result.evidence_spans.iter().any(|span| span.text == value),
        "{rule_id}: missing {value:?} in {text:?}: {:#?}",
        result.evidence_spans
    );
    assert!(
        matched_rules(&result).iter().any(|rule| rule == rule_id),
        "{rule_id}: rule did not fire on {text:?}"
    );
}

fn silent(texts: &[String]) -> Vec<String> {
    texts
        .iter()
        .filter_map(|text| {
            let result = scan(text);
            (!result.evidence_spans.is_empty()).then(|| {
                let spans: Vec<_> = result.evidence_spans.iter().map(|s| &s.text).collect();
                format!("{text:?} -> {spans:?}")
            })
        })
        .collect()
}

/// Carriers of the value-capturing rules; `{v}` is the value.
const CARRIERS: &[(&str, &str)] = &[
    ("dlp_env_var_secret", "DB_PASSWORD={v}\n"),
    ("dlp_env_var_secret", "export SERVICE_TOKEN=\"{v}\"\n"),
    ("dlp_env_var_secret", "  DB_PASSWORT = '{v}';\n"),
    ("dlp_password_assignment", "password: {v}\n"),
    ("dlp_password_assignment", "Das Passwort lautet {v}."),
    (
        "dlp_generic_credential_assignment",
        "client_secret = \"{v}\"\n",
    ),
    ("dlp_generic_credential_assignment", "API-Schlüssel: {v}"),
    (
        "dlp_credential_in_url",
        "curl \"https://api.example.com/v1/export?format=csv&api_key={v}\"",
    ),
    (
        "dlp_signed_url_signature",
        "https://files.example.de/a.zip?Expires=1767225600&Signature={v}",
    ),
    (
        "dlp_url_userinfo_password",
        "DATABASE_URL=postgres://app:{v}@db.internal:5432/app",
    ),
    ("dlp_csrf_token", "X-CSRF-Token: {v}"),
    ("dlp_bearer_token", "Authorization: Bearer {v}"),
];

fn in_carriers(values: &[&str]) -> Vec<String> {
    CARRIERS
        .iter()
        .flat_map(|(_, carrier)| values.iter().map(|value| carrier.replace("{v}", value)))
        .collect()
}

#[test]
fn placeholders_are_silent_in_de_and_en() {
    let de = [
        "HIER_DB_PASSWORT_EINTRAGEN",
        "HIER_API_SCHLUESSEL_EINTRAGEN",
        "BITTE_AENDERN",
        "BITTE-AENDERN",
        "DEIN_API_TOKEN",
        "dein-api-token-hier",
        "PASSWORT_HIER_EINFUEGEN",
        "TOKEN_HIER_EINTRAGEN",
    ];
    let en = [
        "YOUR_DB_PASSWORD_HERE",
        "YOUR_SIGNED_URL_SIGNATURE_HERE",
        "YOUR-API-TOKEN",
        "your-api-token-here",
        "REPLACE_ME",
        "REPLACE_WITH_YOUR_TOKEN",
        "INSERT_TOKEN_HERE",
        "TODO",
        "CHANGEME",
        "CHANGE_ME",
        "PLACEHOLDER",
        "&lt;your-db-password&gt;",
        "xxxxxxxx-xxxx-xxxx",
    ];
    let mut reported = silent(&in_carriers(&de));
    reported.extend(silent(&in_carriers(&en)));
    // Quoted and terminated values (JSON, code) and JSON-escaped notebook cells.
    reported.extend(silent(&[
        "const DB_PASSWORD = \"xxxxxxxxxxxxxxxxxxxxxxxx\";\n".to_owned(),
        "\"api_key = \\\"********\\\"\\n\",".to_owned(),
        "\"DB_PASSWORD=YOUR_DB_PASSWORD_HERE\\n\",\"negative_reason\":\"x\"".to_owned(),
        "\"token\": \"YOUR_API_TOKEN_HERE\",".to_owned(),
    ]));
    assert!(reported.is_empty(), "placeholders reported: {reported:#?}");
}

#[test]
fn environment_and_template_references_are_silent_in_de_and_en() {
    let texts: Vec<String> = [
        // Shell, compose, Windows, CI
        "export SERVICE_TOKEN=\"$VAULT_SERVICE_TOKEN\"\n",
        "SERVICE_TOKEN=$VAULT_SERVICE_TOKEN\n",
        "curl -H \"Client-Secret: $CLIENT_SECRET\" https://api.example.com/v1/status",
        "curl \"https://api.example.de/v1/export?api_key=$EXPORT_API_KEY\"",
        "password: $db_password\n",
        "password = $dbPassword;\n",
        "DB_PASSWORD=${DB_PASSWORD:?missing}\n",
        "client_secret=%CLIENT_SECRET%\n",
        "<add key=\"ClientSecret\" value=\"%CLIENT_SECRET%\" />",
        "postgres://app:$DB_PASSWORD@db.internal:5432/app",
        "postgres://app:%DB_PASSWORD%@db.internal:5432/app",
        // Templates: Handlebars, Mustache, Jinja, Ruby/Spring interpolation
        "Client-Secret: {{clientSecret}}",
        "client_secret: {{ client_secret }}",
        "password: {{ vault_db_password }}",
        "https://api.example.com/v1/export?token={{exportToken}}",
        "postgres://app:{{db_password}}@db.internal:5432/app",
        "X-CSRF-Token: {{csrfToken}}",
        "client_secret = \"#{CLIENT_SECRET}\"",
        // Terraform/HCL
        "client_secret = var.client_secret\n",
        "password = local.db_password\n",
        "csrf_token = var.csrf_token\n",
        "api_key = data.vault_generic_secret.api.data[\"key\"]\n",
        // Python
        "DB_KENNWORT = os.environ[\"DB_KENNWORT\"]\n",
        "client_secret = os.environ[\"CLIENT_SECRET\"]\n",
        "client_secret = os.environ.get(\"CLIENT_SECRET\")\n",
        "csrf_token = os.environ[\"CSRF_TOKEN\"]\n",
        "\"client_secret = os.environ[\\\"CLIENT_SECRET\\\"]\\n\",",
        // Ruby
        "SERVICE_TOKEN = ENV.fetch(\"SERVICE_TOKEN\")\n",
        "API_TOKEN = ENV[\"API_TOKEN\"]\n",
        "csrf_token = ENV.fetch(\"CSRF_TOKEN\")\n",
        // Go, Java, C#, JS, Rust, PHP
        "var csrfToken = os.Getenv(\"CSRF_TOKEN\")\n",
        "String csrfToken = System.getenv(\"CSRF_TOKEN\");\n",
        "private static readonly string ClientSecret = Environment.GetEnvironmentVariable(\"CLIENT_SECRET\");\n",
        "string csrfToken = Environment.GetEnvironmentVariable(\"CSRF_TOKEN\");\n",
        "const csrfToken = process.env.CSRF_TOKEN;\n",
        "const client_secret = import.meta.env.VITE_CLIENT_SECRET;\n",
        "let SERVICE_TOKEN = std::env::var(\"SERVICE_TOKEN\")?;\n",
        "'password' => env('DB_PASSWORD'),\n",
        "$password = getenv('DB_PASSWORD');\n",
    ]
    .iter()
    .map(|text| (*text).to_owned())
    .collect();
    let reported = silent(&texts);
    assert!(reported.is_empty(), "references reported: {reported:#?}");
}

#[test]
fn real_values_next_to_references_and_placeholder_like_passwords_stay_detected() {
    for (text, rule_id, value) in [
        (
            "# TODO: in den Vault verschieben\nAPI_BASIS=${API_BASIS_URL}\nDB_PASSWORT=Kx7pQ2vL9rT4\n",
            "dlp_env_var_secret",
            "Kx7pQ2vL9rT4",
        ),
        (
            "DB_PASSWORD=ORANGE_KQZTRWX_4711",
            "dlp_env_var_secret",
            "ORANGE_KQZTRWX_4711",
        ),
        (
            "passwort: ORANGE_KQZTRWX_4711\n",
            "dlp_password_assignment",
            "ORANGE_KQZTRWX_4711",
        ),
        (
            "password: $kqztrwx4711\n",
            "dlp_password_assignment",
            "$kqztrwx4711",
        ),
        (
            "Das Passwort lautet YourDog2026! (nicht $DB_PASSWORT).",
            "dlp_password_assignment",
            "YourDog2026!",
        ),
        (
            "password = Here4711Now",
            "dlp_password_assignment",
            "Here4711Now",
        ),
        (
            "api_key = \"f4fcba1c3696bf9b564c7dac9b0062f5097331f9\"  # was os.environ[\"API_KEY\"]",
            "dlp_generic_credential_assignment",
            "f4fcba1c3696bf9b564c7dac9b0062f5097331f9",
        ),
        (
            "GET {{basisUrl}}/v1/export?format=csv&api_key=v4hEjYPi9mxYTH9z3osO1LSK HTTP/1.1",
            "dlp_credential_in_url",
            "v4hEjYPi9mxYTH9z3osO1LSK",
        ),
        (
            "Host: {{host}}\nAuthorization: Bearer r_RP7Jvq4TzDpgn2ey8Zq1WGZKzXDWpMaXsAEBZyTyU\n",
            "dlp_bearer_token",
            "r_RP7Jvq4TzDpgn2ey8Zq1WGZKzXDWpMaXsAEBZyTyU",
        ),
        (
            "username=${USER}&csrf_token=wWdeC7mApXWolmH-wIqoO2Px7ghGnM2sn_c1qyeKhLo",
            "dlp_csrf_token",
            "wWdeC7mApXWolmH-wIqoO2Px7ghGnM2sn_c1qyeKhLo",
        ),
        (
            "postgres://app:B2B6Hwjm1-l_Jt~xzC@db.internal/app # statt $DB_URL",
            "dlp_url_userinfo_password",
            "B2B6Hwjm1-l_Jt~xzC",
        ),
        (
            "client_secret = \"TODOLIST_KQZTRW_4711\"",
            "dlp_generic_credential_assignment",
            "TODOLIST_KQZTRW_4711",
        ),
        (
            "SERVICE_TOKEN=variable.kqztrwx4711",
            "dlp_env_var_secret",
            "variable.kqztrwx4711",
        ),
    ] {
        assert_reported(text, rule_id, value);
    }
}

#[test]
fn k06_template_and_secret_manager_references_are_silent() {
    let texts: Vec<String> = [
        // Python %-format, str.format/f-strings, C#/Rust format strings
        "DSN = \"postgresql://lager:%(passwort)s@db.intern:5432/lager\"\n",
        "password=%(db_password)s\n",
        "DB_PASSWORD=%(db_password)s\n",
        "return f\"postgres://app:{db_password}@db.internal:5432/app\"\n",
        "conn = \"Server=db;Password={password};\"\n",
        "conn = \"Server=db;Passwort={0};\"\n",
        "password = \"{password!r}\"\n",
        "DB_PASSWORD={env:DB_PASSWORD}\n",
        // Ruby/Puppet/Logstash %{…}
        "DB_PASSWORD=%{db_password}\n",
        "password: \"%{[secrets][db]}\"\n",
        // Maven/Gradle/autoconf filter tokens, replace tokens, cmd delayed expansion
        "datenbank.passwort=@db.passwort@\n",
        "spring.datasource.password=@DB_PASSWORD@\n",
        "DB_PASSWORD=__DB_PASSWORD__\n",
        "Authorization: Bearer __ACCESS_TOKEN__\n",
        "set PASSWORD=!DB_PASSWORD!\n",
        // Concourse/BOSH, Home Assistant/ESPHome, CloudFormation
        "passwort: ((lager.db_passwort))\n",
        "password: (( db_password ))\n",
        "password: !secret wlan_passwort\n",
        "password: !Ref DbPassword\n",
        "password: !Sub '{{resolve:secretsmanager:${Db}:SecretString:password}}'\n",
        // Secret managers: 1Password, vals, Azure Key Vault, AWS, GCP, Docker/Kubernetes files
        "DB_PASSWORD=op://Production/postgres/password\n",
        "password: ref+vault://secret/data/app#db_password\n",
        "API_TOKEN=ref+awssecrets://prod/api#token\n",
        "DB_PASSWORT=@Microsoft.KeyVault(SecretUri=https://lager-kv.vault.azure.net/secrets/db-passwort/)\n",
        "SERVICE_TOKEN=arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/service-token-AbCdEf\n",
        "DB_PASSWORD=arn:aws:ssm:eu-central-1:123456789012:parameter/prod/db/password\n",
        "DB_PASSWORD=projects/lager-prod/secrets/db-password/versions/latest\n",
        "DB_PASSWORD=/run/secrets/db_password\n",
        "SERVICE_TOKEN=/var/run/secrets/kubernetes.io/serviceaccount/token\n",
    ]
    .iter()
    .map(|text| (*text).to_owned())
    .collect();
    let reported = silent(&texts);
    assert!(reported.is_empty(), "references reported: {reported:#?}");
}

#[test]
fn k06_placeholders_are_silent_in_de_and_en() {
    let de = [
        "PASSWORT_HIER_EINGEBEN",
        "BITTE_AUSFUELLEN",
        "TOKEN_EINSETZEN",
        "SCHLUESSEL_HIER_HINTERLEGEN",
        "***ENTFERNT***",
        "GESCHWAERZT",
        "MEIN_PASSWORT",
    ];
    let en = [
        "null",
        "None",
        "nil",
        "undefined",
        "changeit",
        "***REMOVED***",
        "**None**",
        "*****REDACTED*****",
        "my-access-token",
        "secret_token",
        "SECRET_PASSWORD",
        "your-password",
    ];
    let mut reported = silent(&in_carriers(&de));
    reported.extend(silent(&in_carriers(&en)));
    reported.extend(silent(&[
        "$ git clone https://x-token-auth:my-access-token@bitbucket.org/acme/repo.git\n".to_owned(),
        "ENV API_KEY=\"**None**\" \\\n".to_owned(),
        "expect(text).to.include('Authorization: Bearer secret_token')\n".to_owned(),
        "keystore.password=changeit\n".to_owned(),
        "database:\n  password: null\n".to_owned(),
    ]));
    assert!(reported.is_empty(), "placeholders reported: {reported:#?}");
}

#[test]
fn k06_lookalike_real_values_stay_detected() {
    for (text, rule_id, value) in [
        // Braces, @, __, !, (( )) around values that look like passwords.
        (
            "password = {kqztrwx4711}\n",
            "dlp_password_assignment",
            "{kqztrwx4711",
        ),
        (
            "password=@kqztrwx4711@\n",
            "dlp_password_assignment",
            "@kqztrwx4711@",
        ),
        (
            "DB_PASSWORD=__Kx7pQ2vL9rT4__\n",
            "dlp_env_var_secret",
            "__Kx7pQ2vL9rT4__",
        ),
        (
            "password=!Kx7pQ2vL9rT4!\n",
            "dlp_password_assignment",
            "!Kx7pQ2vL9rT4!",
        ),
        (
            "password: !Reference2026Kq\n",
            "dlp_password_assignment",
            "!Reference2026Kq",
        ),
        (
            "password=%Kx7(pQ2)vL9\n",
            "dlp_password_assignment",
            "%Kx7(pQ2)vL9",
        ),
        // Words outside the credential-name vocabulary, masks with a real value.
        (
            "https://example.test?password=actual-secret",
            "dlp_credential_in_url",
            "actual-secret",
        ),
        (
            "password: my-dog-rex-2026\n",
            "dlp_password_assignment",
            "my-dog-rex-2026",
        ),
        (
            "Das Passwort lautet geheim-sauce-4711 und gilt bis Freitag.",
            "dlp_password_assignment",
            "geheim-sauce-4711",
        ),
        (
            "password: *Kx7pQ2vL9rT4*\n",
            "dlp_password_assignment",
            "*Kx7pQ2vL9rT4*",
        ),
        (
            "password: nullpointer4711\n",
            "dlp_password_assignment",
            "nullpointer4711",
        ),
        (
            "DB_PASSWORD=opal://Kx7pQ2vL9rT4\n",
            "dlp_env_var_secret",
            "opal://Kx7pQ2vL9rT4",
        ),
        (
            "DB_PASSWORD=projects4711Kq/x\n",
            "dlp_env_var_secret",
            "projects4711Kq/x",
        ),
    ] {
        assert_reported(text, rule_id, value);
    }
}
