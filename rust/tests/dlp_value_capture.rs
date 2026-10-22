// SPDX-License-Identifier: GPL-3.0-only
//! F-GEN2 (T04 + T08): value capture of the generic credential rules. A
//! quoted value of `dlp_password_assignment` and
//! `dlp_generic_credential_assignment` runs to its closing quote (spaces,
//! `;`, `,`, `}` inside, two characters before the first `;`).
//! `dlp_env_var_secret` reports the value without its quotes and without a
//! trailing `;`, also after `KEY:` in YAML/compose env maps. Code constants,
//! the closing quote of a label, messages and references are no values.
//! Values are synthetic.

use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};

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

#[test]
fn quoted_passwords_run_to_the_closing_quote() {
    for (template, value) in [
        ("[datenbank]\npasswort = \"{v}\"\n", "blau Drache 47 Zaun"),
        ("[smtp]\npassword = \"{v}\"\n", "Kx7 pQ2;vL9"),
        ("smtp:\n  password: '{v}'\n", "ab;Kx7pQ,42}Zr"),
        ("conn = connect(host=\"db\", password='{v}')\n", "x9;Lm2#Qp"),
        (
            "const pool = { password: \"{v}\", max: 4 };\n",
            "Kx7, pQ2}vL9",
        ),
        ("password=\"{v}\"\n", "ab;cd"),
        (
            "Das Passwort lautet \"{v}\", bitte ändern.",
            "blau Drache 47 Zaun",
        ),
        (
            "The password is \"{v}\" until Friday.",
            "correct horse battery 42",
        ),
    ] {
        assert_exact(template, value, "dlp_password_assignment");
    }
}

#[test]
fn quoted_generic_credentials_run_to_the_closing_quote() {
    for (template, value) in [
        (
            "const konfig = { token: \"{v}\", region: \"eu\" };\n",
            "kq;Ab3xZq,42}QX",
        ),
        ("oauth:\n  client_secret: '{v}'\n", "Zr8 Lm2;Qp7,Xk4"),
        ("Der API-Schlüssel ist \"{v}\".", "Jabmrq xilats rdrzr 22"),
        ("api_key = \"{v}\"\n", "ab;Kx7pQ2vL9"),
    ] {
        assert_exact(template, value, "dlp_generic_credential_assignment");
    }
}

#[test]
fn bare_values_still_stop_at_separators() {
    assert_exact(
        "password={v}; user=app",
        "Kx7!pQ2#vL9",
        "dlp_password_assignment",
    );
    assert_exact(
        "{password: {v}, user: app}",
        "Kx7pQ2vL9",
        "dlp_password_assignment",
    );
    // An unclosed quote keeps the bare capture.
    assert_exact(
        "password: \"{v} (truncated",
        "Kx7pQ2vL9",
        "dlp_password_assignment",
    );
}

#[test]
fn env_var_values_have_no_quotes_or_trailing_terminator() {
    let value = "Kx7!pQ2#vL9@rT4$";
    for template in [
        "DB_PASSWORD={v}\n",
        "DB_PASSWORD=\"{v}\"\n",
        "$ export DB_PASSWORD='{v}'\n$ ./bin/sync\n",
        "ENV DB_PASSWORD=\"{v}\"\nENTRYPOINT [\"java\"]\n",
        "import requests\n\nDB_PASSWORD = \"{v}\"\n",
        "    private static final String SERVICE_SECRET = \"{v}\";\n",
        "    SERVICE_SECRET = \"{v}\"\n\n    def call(env)\n",
        "services:\n  app:\n    environment:\n      DB_PASSWORD: \"{v}\"\n",
        "    env:\n      SERVICE_SECRET: '{v}'\n    steps:\n",
    ] {
        assert_exact(template, value, "dlp_env_var_secret");
    }
    assert_exact(
        "      DB_PASSWORD: {v}\n      DB_HOST: db\n",
        "Kx7pQ2vL9rT4",
        "dlp_env_var_secret",
    );
    assert_exact(
        "$ SERVICE_SECRET={v}; ./bin/report\n",
        "Kx7pQ2vL9rT4",
        "dlp_env_var_secret",
    );
    // `;` inside a bare `.env` value belongs to it.
    assert_exact("DB_PASSWORD={v}\n", "Kx7;pQ2vL9", "dlp_env_var_secret");
    assert_exact(
        "DB_PASSWORD=\"{v}\"\n",
        "blau Drache 47 Zaun",
        "dlp_env_var_secret",
    );
}

#[test]
fn env_var_code_constants_are_silent() {
    assert_silent(&[
        "const NAME = 'collapse'\nconst DATA_KEY = 'bs.collapse'\nconst DATA_API_KEY = '.data-api'\n",
        "const NAME$3=\"scrollspy\",EVENT_KEY$3=\".bs.scrollspy\",DATA_API_KEY=\".data-api\",EVENT_ACTIVATE=`activate${EVENT_KEY$3}`",
        "const DATA_API_KEY = \".data-api\";\nconst EVENT_SHOW = `show${EVENT_KEY}`;\n",
        "el'\\nconst EVENT_KEY = `.${DATA_KEY}`\\nconst DATA_API_KEY = '.data-api'\\n\\nconst ESCAPE_KEY = 'Escape'",
        "const AUTH_FLOW_IMPLICIT = \"implicit\"\nconst AUTH_FLOW_PASSWORD = \"password\"\n",
        "    const AUTH_FLOW_PASSWORD = \\\"password\\\"\\n    const AUTH_FLOW_APPLICATION = \\\"application\\\"\\n",
        "LOGIN_FORM_PASSWORD = 'passwordField'\n",
        "SECRET_KEY = config.get(\"secret_key\")\n",
        "SERVICE_SECRET = os.environ[\"SERVICE_SECRET\"]\n",
    ]);
}

#[test]
fn env_var_references_and_messages_are_silent() {
    assert_silent(&[
        "    env:\n      DB_PASSWORD: ${{ secrets.DB_PASSWORD }}\n",
        "    environment:\n      DB_PASSWORD: \"${DB_PASSWORD}\"\n",
        "ENV API_TOKEN=\"$(cat /run/secrets/api_token)\"\n",
        "ERROR MISSING_API_KEY: environment variable not set\n",
        "API_KEY=\nDB_HOST=localhost\n",
        "DB_PASSWORD: \"Enter the database password\"\n",
    ]);
}

#[test]
fn closing_quotes_of_labels_open_no_value() {
    assert_silent(&[
        "i.createElement(\"label\",{htmlFor:\"auth_password\"},\"Password:\"),d?i.createElement(\"code\",null,\" ******\")",
        "Re.createElement(\"label\",{htmlFor:`client_secret_${le}`},\"client_secret:\"),fe?Re.createElement(\"code\",null,\" ******\")",
        "login(password = \"\", user = \"admin\", retries = 3)",
    ]);
}

#[test]
fn quoted_messages_placeholders_and_templates_are_silent() {
    assert_silent(&[
        "export default { password: \"Enter your password\", submit: \"Sign in\" };\n",
        "const meldungen = { passwort: \"Bitte geben Sie ein Passwort ein\" };\n",
        "Login failed because the password is \"too short\" for the new policy.\n",
        "password: \"change me\"\n",
        "token: \"Invalid token: %s\"\n",
        "lager:\n  token: \"{{ .Values.lager.token }}\"\n",
        "password: \"$(cat /run/secrets/db)\"\n",
        "oauth:\n  client_secret: \"<your client secret>\"\n",
        "password: \"Must be at least eight characters long.\"\n",
    ]);
}

#[test]
fn marker_words_cut_to_the_field_length_are_examples() {
    assert_silent(&[
        "DB_PASSWORD=Eexampl0123!\n",
        "    env:\n      SERVICE_SECRET: \"Ttestke1234!\"\n",
        "password: Eexampl0123!\n",
    ]);
    // Words that merely contain the letters stay passwords.
    assert_exact("DB_PASSWORD={v}\n", "Testkeller2026!", "dlp_env_var_secret");
}

#[test]
fn long_hex_fill_values_are_examples() {
    let deadbeef = "deadbeef".repeat(5);
    let digits = "1234567890".repeat(4);
    assert_silent(&[
        &format!("    environment:\n      LAGER_API_TOKEN: \"{deadbeef}\"\n"),
        &format!("[oauth]\nclient_secret = \"{digits}\"\n"),
        &format!("CLIENT_SECRET={deadbeef}\n"),
        &format!("    \"curl https://api.example.com/v1?api_key={deadbeef}\\\"\\n\","),
    ]);
    // Short hand-typed repeats stay weak but real passwords.
    assert_exact(
        "DB_PASSWORD={v}\n",
        "deadbeefdeadbeef",
        "dlp_env_var_secret",
    );
}

#[test]
fn env_var_rule_has_a_value_gate() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|rule| rule.name == "dlp_env_var_secret")
        .unwrap();
    assert!(rule.meta.value_gate.is_some());
    assert_eq!(rule.span_group, Some(1));
}
