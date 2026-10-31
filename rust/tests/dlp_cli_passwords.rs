// SPDX-License-Identifier: GPL-3.0-only
//! G03: passwords on CLI command lines.
//!
//! `dlp_cli_password` (`CREDENTIAL`, subtype `password`) reports the
//! password of `curl -u/--user user:<password>`, the MySQL/MariaDB clients
//! (`-p<password>`, `--password=<password>`), a shell `PGPASSWORD=<password>`
//! (libpq), `sshpass -p`, `docker`/`podman login -p/--password`, `htpasswd`
//! in batch mode (`-b`, the last argument), PowerShell `ConvertTo-SecureString
//! "<password>" -AsPlainText` and `net use \\server\share <password> /user:`.
//! Prompts, stdin and file options, shell and template references and
//! placeholders are no findings. Values are synthetic.

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

fn reported_rules(result: &SecurityScanResult) -> Vec<String> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|rule| rule.get("suppressed_by").is_none())
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect()
}

/// `template` with `value` at `{v}` yields exactly one span, the value, by
/// `dlp_cli_password`.
fn assert_exact(template: &str, value: &str) {
    let start = template[..template.find("{v}").unwrap()].chars().count();
    let text = template.replace("{v}", value);
    let result = scan(&text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.label.as_str(), span.start_char, span.end_char))
        .collect();
    assert_eq!(
        spans,
        vec![("CREDENTIAL", start, start + value.chars().count())],
        "{text:?}"
    );
    assert_eq!(
        reported_rules(&result),
        vec!["dlp_cli_password"],
        "{text:?}"
    );
}

/// No DLP rule reports `text`.
fn assert_silent(text: &str) {
    let result = scan(text);
    let spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| span.text.as_str())
        .collect();
    assert!(spans.is_empty(), "{text:?} -> {spans:?}");
}

const PASSWORD: &str = "Kx7pQ2vL9.wR4m";

#[test]
fn curl_user_passwords_are_reported() {
    // `concat!` splits the command name: push protection rejects the literal credentials.
    for template in [
        concat!(
            "cu",
            "rl -u deploy:{v} -T build.tgz https://nexus.example.com/repository/raw/"
        ),
        concat!(
            "$ cu",
            "rl -s -X POST -u 'deploy:{v}' https://api.example.com/v1/jobs"
        ),
        concat!(
            "cu",
            "rl --user \"release-bot:{v}\" https://artifacts.example.com/api/upload"
        ),
        concat!("cu", "rl --user=deploy:{v} https://api.example.com"),
        concat!("cu", "rl -udeploy:{v} https://api.example.com"),
        concat!(
            "cu",
            "rl https://api.dropbox.com/oauth2/token \\\n  --user c28wlsosanujy2z:{v}"
        ),
        concat!("cu", "rl -u :{v} https://localhost:9200"),
    ] {
        assert_exact(template, PASSWORD);
    }
}

#[test]
fn mysql_and_postgres_client_passwords_are_reported() {
    for template in [
        "mysql -h db.internal -u orders -p{v} orders",
        "mysqldump -u backup -p'{v}' --single-transaction shop > shop.sql",
        "mariadb-dump -u backup -p\"{v}\" shop",
        "mysql -h db.internal -u orders --password={v} orders",
        "mysqladmin -u root --password='{v}' status",
        "PGPASSWORD={v} psql -h db.internal -U orders -d orders",
        "export PGPASSWORD='{v}'",
        "0 3 * * 0 PGPASSWORD=\"{v}\" pg_dump -h db.internal orders > orders.sql",
    ] {
        assert_exact(template, PASSWORD);
    }
}

#[test]
fn sshpass_docker_and_htpasswd_passwords_are_reported() {
    for template in [
        "sshpass -p {v} ssh deploy@10.0.4.12 uptime",
        "sshpass -p'{v}' scp dump.sql backup@backup.internal:/data/",
        "docker login -u ci-bot -p {v} registry.example.com",
        "docker login --username ci-bot --password {v} registry.example.com",
        "podman login --password={v} -u ci-bot quay.io",
        "htpasswd -bc /etc/nginx/.htpasswd admin {v}",
        "htpasswd -b -B /etc/nginx/.htpasswd admin {v}",
        "htpasswd -nbB admin {v} > /etc/nginx/.htpasswd",
        "htpasswd -Bbn admin '{v}'",
    ] {
        assert_exact(template, PASSWORD);
    }
}

#[test]
fn powershell_and_net_use_passwords_are_reported() {
    for template in [
        "$pw = ConvertTo-SecureString \"{v}\" -AsPlainText -Force",
        "$pw = ConvertTo-SecureString -String '{v}' -AsPlainText -Force",
        "(ConvertTo-SecureString '{v}' -Force -AsPlainText)",
        "$pw = '{v}' | ConvertTo-SecureString -AsPlainText -Force",
        "{\"run\": \"$pw = ConvertTo-SecureString \\\"{v}\\\" -AsPlainText -Force\"}",
        "net use Z: \\\\fs01.internal\\finance {v} /user:ACME\\jana /persistent:no",
        "net use \\\\files.internal\\reports /user:ACME\\svc-reports {v}",
        "NET USE \\\\files.internal\\ipc$ \"{v}\" /USER:svc",
    ] {
        assert_exact(template, PASSWORD);
    }
}

#[test]
fn prompts_stdin_files_and_references_are_no_findings() {
    for text in [
        // prompts
        "curl -u deploy -T build.tgz https://nexus.example.com/repository/raw/",
        "curl -u deploy: https://api.example.com",
        "mysql -h db.internal -u orders -p orders",
        "mysql -u root -p",
        "mysql -u root --password orders",
        "htpasswd -c /etc/nginx/.htpasswd admin",
        "htpasswd -B /etc/nginx/.htpasswd admin",
        "net use Z: \\\\fs01.internal\\finance * /user:ACME\\jana",
        "net use Z: \\\\fs01.internal\\finance /user:ACME\\jana",
        // stdin, environment, files
        "echo \"$REGISTRY_PASSWORD\" | docker login -u ci-bot --password-stdin registry.example.com",
        "sshpass -e ssh deploy@10.0.4.12 uptime",
        "sshpass -f /run/secrets/deploy_pw ssh deploy@10.0.4.12 uptime",
        // shell and template references
        "curl -u \"$API_USER:$API_PASSWORD\" https://api.example.com",
        "curl --user \"${{ secrets.USER }}:${{ secrets.PASSWORD }}\" https://api.example.com",
        "docker login -u gitlab-ci-token -p \"$CI_JOB_TOKEN\" \"$CI_REGISTRY\"",
        "mysql -u root -p$MYSQL_ROOT_PASSWORD",
        "PGPASSWORD=\"${DB_PASSWORD}\" psql -h db.internal",
        "sshpass -p \"$SSHPASS\" ssh deploy@host",
        "$plain = ConvertTo-SecureString -String $Password -AsPlainText -Force",
        "$secure = ConvertTo-SecureString $env:SVC_PASSWORD -AsPlainText -Force",
        "net use \\\\files.internal\\reports /user:ACME\\svc %REPORTS_PW%",
        // placeholders and stand-ins
        "curl -u username:password https://api.example.com",
        "curl -u <user>:<password> https://api.example.com",
        "htpasswd -b <file> <user> <password>",
        "mysql -u root -p<password> shop",
        "docker login -u user -p changeme registry.example.com",
    ] {
        assert_silent(text);
    }
}

#[test]
fn secure_string_without_as_plain_text_is_no_finding() {
    // Without `-AsPlainText` the argument is an encrypted standard string.
    assert_silent("$secure = ConvertTo-SecureString \"01000000d08c9ddf0115d1118c7a00c04fc297eb\"");
}

#[test]
fn options_in_prose_are_no_findings() {
    for text in [
        "The -p option of sshpass passes the password on the command line; prefer -e or -f.",
        "Mit mysql -p fragt der Client nach dem Passwort.",
        "Use curl -u with the user name only and curl prompts for the password.",
    ] {
        assert_silent(text);
    }
}

#[test]
fn dotted_arguments_are_passwords_not_member_access() {
    // A shell argument is no code; a `$` reference stays one.
    for template in [
        concat!("cu", "rl -u deploy:{v} https://api.example.com"),
        "sshpass -p {v} ssh deploy@10.0.4.12 uptime",
    ] {
        assert_exact(template, "zXyKqTrBmWvL.HqRtNpm");
    }
    assert_silent("mysql -u root -p$cfg.password shop");
}
