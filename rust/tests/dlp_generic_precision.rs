// SPDX-License-Identifier: GPL-3.0-only
//! F-GEN1 (F11 + T03 + T10): the values of the generic credential rules need
//! password likeness. Code expressions, type annotations, paths, a shell
//! variable as key, DE/EN prose words, credential names and test-suite
//! stand-ins are no findings; weak but real passwords stay detected, and a
//! token in the username of a URL is reported with the token span. Values
//! are synthetic.

use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::dlp::{overlap_tier, OverlapTier, DLP_PATTERNS},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
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
        "{rule_id}: rule did not fire on {text:?}: {:?}",
        matched_rules(&result)
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
fn rust_code_expressions_are_silent() {
    assert_silent(&[
        "pub fn connect(token: Option<&str>) -> Result<Client> {",
        "struct Login {\n    password: Secret<String>,\n    token: Arc<str>,\n}\n",
        "let token = credentials.token_for(&account)?;",
        "let password = std::env::var(\"DB_PASSWORD\")?;",
        "match tok {\n    Token::Literal(c) => out.push(c),\n    Token::RecursivePrefix => {}\n}\n",
        "Token::Alternates(self.branches.drain(start..).collect())",
        "fn set_password(&mut self, password: &'static str) {}",
    ]);
}

#[test]
fn python_code_expressions_are_silent() {
    assert_silent(&[
        "token = get_token()\n",
        "token = self._authenticator.get_pypi_token(repository_name)\n",
        "password = os.environ[\"DB_PASSWORD\"]\n",
        "password = self.keyring.get_password(repo_name, username)\n",
        "password = values[1]\n",
        "token = values[0]\n",
        "user, password = auth.split(\":\", 1)\n",
        "password = urllib.parse.quote(credential.password, safe=\"\")\n",
        "def set_password(self, name: str, username: str, password: str) -> None:\n",
        "password: Optional[str] = None\n",
        "url, config=config, username=username, password=password\n",
        "logger.debug(\"Found an API token for %s.\", repository_name)\n",
        "token=self._extract_code(text),\n",
        "password = token\n",
        "password=GIT_PASSWORD,\n",
        "conn = connect(dsn, password=%s)\n",
    ]);
}

#[test]
fn typescript_and_javascript_expressions_are_silent() {
    assert_silent(&[
        "const password = this._input!.value\n",
        "const password = this._input.value;\n",
        "password: password.length > 0 ? '***' : ''\n",
        "{strength:n,score:t,password:e.length>0?\"***\":\"\"}",
        "scorer: ((password: string) => number) | null\n",
        "protected _calculateScore(password: string): number {\n",
        "let token = JSON.parse(response.data)\n",
        "auth.token = Object.assign({}, token)\n",
        "let password = security.getIn([\"value\", \"password\"])\n",
        "client_secret: clientSecret,\n",
        "password: passwordGenerator,\n",
        "Y.password=Y.auth.slice($+1),Y.password=encodeURIComponent(decodeURIComponent(Y.password))",
        "_.auth=_.password?_.username+\":\"+_.password:_.username",
        "fixedFields:{password:{$ref:\"#/visitors/document/objects/OAuthFlow\"}}",
    ]);
}

#[test]
fn go_php_and_shell_expressions_are_silent() {
    assert_silent(&[
        // Go
        "token := os.Getenv(\"API_TOKEN\")\n",
        "type Config struct {\n\tToken  string `json:\"token\"`\n\tSecret string\n}\n",
        "client := api.New(api.Config{Token: cfg.Token})\n",
        // PHP
        "$token = $response->decodeJson();\n",
        "$token = $authTokens[$originUrl];\n",
        "$token = trim((string) $this->io->askAndHideAnswer('Token (hidden): '));\n",
        "$password = $this->perforce->queryP4Password();\n",
        "$password = is_array($token) ? $token[\"token\"] : 'private-token';\n",
        "$this->io->writeError(\"Couldn't refresh access token: \".$e->getMessage());\n",
        " * @return array{access_token: non-empty-string, refresh_token: non-empty-string}\n",
        " * @var ?array{username: string, password: string}\n",
        // Shell
        "docker run --rm -v \"$PWD:/work\" -w /work image:1.0\n",
        "volumes:\n  - $PWD:/usr/src/app\n",
        "TOKEN=$(gh auth token)\n",
    ]);
}

#[test]
fn schema_keys_and_paths_are_silent() {
    assert_silent(&[
        "properties:\n  password:\n    type: string\n    format: password\n",
        "paths:\n  /login:\n    password:\n      get:\n        summary: x\n",
        "password_file: /run/secrets/db\npassword: /run/secrets/db_password\n",
        "token: ~/.config/acme/token\n",
        "the fill color token is `--range-track-fill-bg`.",
        "token          = 1*(tchar)\n",
    ]);
}

#[test]
fn de_and_en_prose_is_silent() {
    assert_silent(&[
        "Das Passwort ist falsch. Bitte erneut eingeben.",
        "Das Passwort ist abgelaufen und muss geändert werden.",
        "Das Passwort ist gesperrt, wenden Sie sich an den Support.",
        "Hinweis: Das Token ist ungültig.",
        "Das Passwort ist erforderlich.",
        "If a system keyring is available, the password is stored to and retrieved from the keyring.",
        "Poetry will honor them if a password is configured without it.",
        "Username (required if password is set)",
        "# Token is problematic here as line is already colored",
        "The extraction of token is implemented via splitter heuristic",
        "When a token is embedded in the URL user info, it is masked.",
        "The password is case-sensitive.",
    ]);
}

#[test]
fn credential_names_and_test_stand_ins_are_silent() {
    assert_silent(&[
        "password: \"password\"\n",
        "password: \"pass\"\n",
        "clientSecret: \"topSecret\",\n",
        "clientSecret: \"mySecret\",\n",
        ".should(\"include\", \"password=password\")\n",
        "// e.g. https://api.github.com/repositories/9999999999?access_token=github_token",
        "manager.set_http_password(repo_name=\"exists\", username=\"user\", password=\"password\")\n",
    ]);
}

#[test]
fn test_suite_urls_are_silent() {
    assert_silent(&[
        "$fs->get('https://user:pass@github.com/composer/composer/404');",
        "['https://user:secret@example.com/repo.git'],",
        "['ssh://git.int.example/group/pkg.git', 'ssh://gogs:secret@git.int.example/group/pkg.git'],",
        "['https://x-token-auth:***@bitbucket.org/acme/repo', 'https://x-token-auth:secret@bitbucket.org/acme/repo'],",
        "['https://gitlab-ci-token:***@gitlab.example.org/', 'https://gitlab-ci-token:realtoken@gitlab.example.org/'],",
        "['git@github.com:acme/repo.git', 'MY_GITHUB_TOKEN', 'https://token:MY_GITHUB_TOKEN@github.com/acme/repo.git', 1],",
        "['https://bitbucket.org/acme/repo.git', 'https://x-bitbucket-api-token-auth:ATAT_BITBUCKET_API_TOKEN@bitbucket.org/acme/repo.git'],",
        "authenticator.request(\"get\", \"https://foo001:bar002@foo.bar/files/foo-0.1.0.tar.gz\")",
        "http://user:****@proxy.example.com:3128",
        concat!(
            "['https://ghp***:***@github.com/acme/repo', 'https://ghp_",
            "1234567890abcdefghijklmnopqrstuvwxyzAB",
            ":x-oauth-basic@github.com/acme/repo'],"
        ),
    ]);
}

/// T17: reserved characters of a URL userinfo are percent-encoded, so test
/// credentials such as `p@ss` and `p@ssw$rd` appear as `p%40ss` and
/// `p%40ssw%24rd`; the likeness check reads the decoded password.
#[test]
fn percent_encoded_test_credentials_in_urls_are_silent() {
    assert_silent(&[
        "# percent-encoded authorization\nme%40company:p%40ssw%24rd\n\nscheme://me%40company:p%40ssw%24rd@proxy.com:80\n",
        "Reservierte Zeichen in Benutzer und Passwort werden kodiert:\n\n    http://ich%40firma:p%40ssw%24rd@proxy.example.de:3128\n",
        "'removes-user-pass' => ['http://user:p%40ss@proxy.com:6180', 'http://***:***@proxy.com:6180'],",
        "$server = [\n    'http_proxy' => 'http://user:p%40ss@proxy.com',\n    'no_proxy' => 'other.repo.org',\n];\n",
        "PROXIES = {\"https\": \"http://user:s%33cr%33t@proxy.internal:3128\"}\n",
        "assert redact(\"https://admin:p%40ssw%30rd@db.internal/app\") == \"https://admin:***@db.internal/app\"\n",
        "Beispiel: ftp://anonym:%24ecret@ftp.example.de/pub",
    ]);
}

#[test]
fn percent_encoded_chosen_passwords_keep_the_encoded_span() {
    for (text, value) in [
        (
            "DATABASE_URL=postgres://app:Vkrq%40Tz82%24mLw%3A41@db.internal:5432/app",
            "Vkrq%40Tz82%24mLw%3A41",
        ),
        (
            "Proxy der Filiale: http://lager:Hmt%24pn%3A7731%40qe@proxy.intern:3128",
            "Hmt%24pn%3A7731%40qe",
        ),
        (
            "amqp://worker:Wq9%40ss%24Lr%3Az@mq.internal:5672/jobs",
            "Wq9%40ss%24Lr%3Az",
        ),
    ] {
        assert_reported(text, "dlp_url_userinfo_password", value);
    }
}

#[test]
fn weak_but_real_passwords_stay_detected() {
    for (text, rule_id, value) in [
        ("password: hunter2\n", "dlp_password_assignment", "hunter2"),
        ("password = letmein\n", "dlp_password_assignment", "letmein"),
        (
            "Passwort: abcabcabcabc\n",
            "dlp_password_assignment",
            "abcabcabcabc",
        ),
        (
            "Das Passwort ist Sommer2026!, bitte ändern.",
            "dlp_password_assignment",
            "Sommer2026!",
        ),
        (
            "The password is qwertz123 until Friday.",
            "dlp_password_assignment",
            "qwertz123",
        ),
        (
            "conn = connect(host=\"db\", password=\"sunshine\")\n",
            "dlp_password_assignment",
            "sunshine",
        ),
        (
            "password: P@ssw0rd\n",
            "dlp_password_assignment",
            "P@ssw0rd",
        ),
        (
            "password = ghp_shortButRealPassword\n",
            "dlp_password_assignment",
            "ghp_shortButRealPassword",
        ),
        (
            "const pool = new Pool({ password: \"Kx7pQ2vL9rT4\" });\n",
            "dlp_password_assignment",
            "Kx7pQ2vL9rT4",
        ),
        (
            "client := api.New(api.Config{Token: \"f4fcba1c3696bf9b564c7dac9b0062f5097331f9\"})\n",
            "dlp_generic_credential_assignment",
            "f4fcba1c3696bf9b564c7dac9b0062f5097331f9",
        ),
        (
            "Der API-Schlüssel ist 36a2c526f6fd8efe166da39025b31304587516ef, bitte nicht teilen.",
            "dlp_generic_credential_assignment",
            "36a2c526f6fd8efe166da39025b31304587516ef",
        ),
        (
            "$password = 'Lrtbjnl1660*';\n",
            "dlp_password_assignment",
            "Lrtbjnl1660*",
        ),
        (
            "postgres://app:letmein42@db.internal/app",
            "dlp_url_userinfo_password",
            "letmein42",
        ),
        (
            "https://deploy:Kx7pQ2vL9rT4@git.example.com/team/app.git",
            "dlp_url_userinfo_password",
            "Kx7pQ2vL9rT4",
        ),
    ] {
        assert_reported(text, rule_id, value);
    }
}

#[test]
fn token_in_the_username_is_reported_with_the_token_span() {
    for (text, value) in [
        (
            "$ git clone https://f4fcba1c3696bf9b564c7dac9b0062f5097331f9:x-oauth-basic@github.com/acme/app.git",
            "f4fcba1c3696bf9b564c7dac9b0062f5097331f9",
        ),
        (
            "[remote \"origin\"]\n  url = https://v4hEjYPi9mxYTH9z3osO1LSK:x-oauth-basic@github.com/acme/sync.git\n",
            "v4hEjYPi9mxYTH9z3osO1LSK",
        ),
    ] {
        let result = scan(text);
        assert_eq!(
            result
                .evidence_spans
                .iter()
                .map(|span| (span.label.as_str(), span.text.as_str()))
                .collect::<Vec<_>>(),
            [("SECRET_TOKEN", value)],
            "{text}"
        );
        assert_eq!(matched_rules(&result), ["dlp_url_userinfo_token"], "{text}");
    }
    // The fixed-username forms keep the token in the password position.
    assert_reported(
        "https://x-token-auth:v4hEjYPi9mxYTH9z3osO1LSK@bitbucket.org/acme/repo.git",
        "dlp_url_userinfo_password",
        "v4hEjYPi9mxYTH9z3osO1LSK",
    );
}

#[test]
fn token_in_the_username_needs_token_likeness() {
    assert_silent(&[
        "https://myusername:x-oauth-basic@github.com/acme/app.git",
        "git clone https://$GITHUB_TOKEN:x-oauth-basic@github.com/acme/app.git",
        "git clone https://${{ secrets.GITHUB_TOKEN }}:x-oauth-basic@github.com/acme/app.git",
        "https://<token>:x-oauth-basic@github.com/acme/app.git",
        "https://YOUR_GITHUB_TOKEN:x-oauth-basic@github.com/acme/app.git",
        "https://github_token:x-oauth-basic@github.com/acme/app.git",
        "https://abcdefghijklmnop:x-oauth-basic@github.com/acme/app.git",
    ]);
}

#[test]
fn url_userinfo_token_metadata() {
    let rule = DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "dlp_url_userinfo_token")
        .expect("rule registered");
    assert_eq!(rule.entity_group, "SECRET_TOKEN");
    assert_eq!(rule.meta.keywords, ["x-oauth-basic"]);
    assert!(rule.meta.source_ref.starts_with("https://github.blog/"));
    assert!(rule.meta.value_gate.is_some());
    assert_eq!(
        overlap_tier("dlp_url_userinfo_token"),
        Some(OverlapTier::Token)
    );
    for rule_id in [
        "dlp_password_assignment",
        "dlp_generic_credential_assignment",
        "dlp_url_userinfo_password",
    ] {
        let rule = DLP_PATTERNS
            .iter()
            .find(|pattern| pattern.name == rule_id)
            .unwrap();
        assert!(rule.meta.value_gate.is_some(), "{rule_id}");
        assert!(rule.meta.context_gate.is_none(), "{rule_id}");
    }
}
