// SPDX-License-Identifier: GPL-3.0-only
//! G01: connection strings per scheme.
//!
//! `dlp_connection_string_password` (`CREDENTIAL`, subtype
//! `connection_string`) reports the password of a `;`-separated key/value
//! connection string with a server, data source, host, DSN, driver or
//! provider key or after a `jdbc:` URL (ADO.NET, ODBC, OLE DB, JDBC SQL
//! Server/DB2 properties), of a libpq keyword/value string, the `password`
//! query parameter of a database or broker URL and the password of an Oracle
//! thin/OCI URL. `dlp_ldap_bind_password` (`CREDENTIAL`, subtype `password`)
//! reports LDAP simple-bind passwords: `ldapsearch … -w`, `bindpw`,
//! `bind_pw`, `bindCredential`, `ldap_default_authtok` and
//! `AuthLDAPBindPassword`. `dlp_url_userinfo_password` takes the Redis
//! password without a username (`redis://:<password>@`). Values are
//! synthetic.

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

fn rule_entries(result: &SecurityScanResult) -> Vec<serde_json::Value> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default()
}

fn reported_rules(result: &SecurityScanResult) -> Vec<String> {
    rule_entries(result)
        .iter()
        .filter(|rule| rule.get("suppressed_by").is_none())
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect()
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
        .map(|span| (span.label.as_str(), span.start_char, span.end_char))
        .collect();
    assert_eq!(
        spans,
        vec![("CREDENTIAL", start, start + value.chars().count())],
        "{rule_id}: {text:?}"
    );
    assert_eq!(
        reported_rules(&result),
        vec![rule_id],
        "{rule_id}: {text:?}"
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

/// `rule_id` does not report `text`.
fn assert_not_reported(text: &str, rule_id: &str) {
    let result = scan(text);
    assert!(
        !reported_rules(&result).iter().any(|rule| rule == rule_id),
        "{rule_id}: {text:?}"
    );
}

const PASSWORD: &str = "Kx7pQ2vL9!";

#[test]
fn key_value_connection_strings_report_the_password() {
    let rule = "dlp_connection_string_password";
    for template in [
        // ADO.NET SqlClient, Npgsql, MySqlConnector, OLE DB
        "Server=sql01.internal;Database=orders;User Id=orders_app;Password={v};",
        "Server=tcp:sql01.internal,1433;Initial Catalog=orders;User ID=orders;Password={v};Encrypt=True",
        "Host=db.internal;Port=5432;Database=orders;Username=orders;Password={v}",
        "Server=db.internal;Port=3306;Database=orders;Uid=orders;Pwd={v};",
        "Provider=SQLOLEDB;Data Source=sql01;Initial Catalog=orders;User Id=sa;Password={v};",
        // password before the server key, spaces around `=`
        "Password={v};Data Source=sql01;Initial Catalog=orders",
        "Data Source = sql01 ; User ID = sa ; Password = {v} ;",
        // quoted values and ODBC braces with `;` inside
        "Data Source=sql01;Initial Catalog=orders;Password='{v}';",
        "Driver={ODBC Driver 18 for SQL Server};Server=sql01;Uid=sa;Pwd={{v}};",
        // JDBC SQL Server and DB2 properties
        "jdbc:sqlserver://sql01.internal:1433;databaseName=orders;user=sa;password={v};",
        "jdbc:db2://db2.internal:50000/ORDERS:user=orders;password={v};",
        // carriers: JSON, XML attribute, escaped JSON string, Python, CRLF
        "{\"ConnectionStrings\": {\"Orders\": \"Server=sql01;Database=orders;User Id=app;Password={v};\"}}",
        "<add name=\"Orders\" connectionString=\"Data Source=sql01;User ID=app;Password={v}\" />",
        "\"cs\": \"\\\"Server=sql01;Database=orders;Password={v}\\\"\"",
        "conn = pyodbc.connect(\"DRIVER={ODBC Driver 18 for SQL Server};SERVER=sql01;UID=sa;PWD={v}\")",
        "ORDERS_DB=Server=sql01;Database=orders;User Id=app;Password={v}\r\nNEXT=1\r\n",
    ] {
        assert_exact(template, PASSWORD, rule);
    }
    // A value with spaces runs to the `;`, also past a ` key=` that would
    // end a libpq value.
    for value in ["Tr0ub4dor & 3", "Kx7pQ2vL9! part=Wm3zR8tQ4yN1"] {
        assert_exact(
            "Server=sql01;Database=orders;User Id=app;Password={v};",
            value,
            rule,
        );
    }
    assert_exact(
        "Server=sql01; Password = {v} ;",
        "Kx7pQ2vL9! part=Wm3zR8tQ4yN1",
        rule,
    );
}

#[test]
fn libpq_keyword_value_strings_report_the_password() {
    let rule = "dlp_connection_string_password";
    for template in [
        "psql \"host=db.internal port=5432 dbname=orders user=orders password={v} sslmode=require\"",
        "host=db.internal dbname=orders user=orders password={v}",
        "PGCONN='host=db.internal user=orders password={v}'",
        "DEBUG pool: host=db.internal port=5432 dbname=orders user=orders password={v} sslmode=require",
    ] {
        assert_exact(template, PASSWORD, rule);
    }
}

#[test]
fn query_passwords_of_database_urls_are_connection_strings() {
    let rule = "dlp_connection_string_password";
    for template in [
        "spring.datasource.url=jdbc:mysql://db:3306/orders?user=orders&password={v}&useSSL=true",
        "jdbc:postgresql://db.internal:5432/orders?user=orders&password={v}",
        "DATABASE_URL=postgresql://db.internal/orders?user=orders&password={v}",
        "SQLALCHEMY_URL=mysql+pymysql://db.internal/orders?user=orders&password={v}",
        "<url>jdbc:mariadb://db/orders?user=orders&amp;password={v}&amp;ssl=true</url>",
        "url: \"mssql://db.internal/orders?pwd={v}\"",
    ] {
        assert_exact(template, PASSWORD, rule);
    }
}

#[test]
fn oracle_thin_urls_report_the_password_after_the_user() {
    let rule = "dlp_connection_string_password";
    assert_exact(
        "String url = \"jdbc:oracle:thin:scott/{v}@//ora01.internal:1521/ORCL\";",
        "Kx7pQ2vL9x",
        rule,
    );
    assert_exact("jdbc:oracle:oci:scott/{v}@ORCL", "Kx7pQ2vL9x", rule);
}

#[test]
fn redis_urls_without_a_username_report_the_password() {
    for template in [
        "REDIS_URL=redis://:{v}@cache.internal:6379/0",
        "cache: rediss://:{v}@cache.internal:6380",
        "redis://default:{v}@cache.internal:6379",
    ] {
        assert_exact(template, "Kx7pQ2vL9x", "dlp_url_userinfo_password");
    }
}

#[test]
fn ldap_bind_passwords_are_reported() {
    let rule = "dlp_ldap_bind_password";
    for template in [
        "ldapsearch -x -H ldaps://ldap.internal -D \"cn=admin,dc=acme,dc=org\" -w {v} -b \"dc=acme,dc=org\"",
        "$ ldapmodify -x -D cn=admin,dc=acme,dc=org -w '{v}' -f change.ldif",
        "ldapwhoami -x -D \"uid=svc,ou=services,dc=acme,dc=org\" -w \"{v}\"",
        "binddn cn=nslcd,ou=services,dc=acme,dc=org\nbindpw {v}\n",
        "  bindpw   {v}",
        "ldap_default_authtok = {v}",
        "AuthLDAPBindPassword \"{v}\"",
        "\"bindCredential\": \"{v}\",",
        "LDAP_BINDPW={v}",
        "ldap:\n  bind_pw: {v}\n",
        "bind-credential: {v}",
    ] {
        assert_exact(template, PASSWORD, rule);
    }
}

#[test]
fn quoted_passwords_that_resemble_code_are_reported() {
    // A quoted literal holds a value even where it reads as member access.
    let value = "Violet.River!82";
    for (template, rule) in [
        ("bindpw \"{v}\"", "dlp_ldap_bind_password"),
        (
            "ldapsearch -x -D cn=admin,dc=acme,dc=org -w '{v}'",
            "dlp_ldap_bind_password",
        ),
        (
            "Server=sql01;Database=orders;User Id=app;Password='{v}';",
            "dlp_connection_string_password",
        ),
        (
            "Driver={ODBC Driver 18 for SQL Server};Server=sql01;Uid=sa;Pwd={{v}};",
            "dlp_connection_string_password",
        ),
    ] {
        assert_exact(template, value, rule);
    }
}

#[test]
fn passwords_outside_a_connection_string_keep_their_rule() {
    // No server key, no `;` or libpq host: a plain assignment.
    let text = format!("Database=orders;User Id=app;Password={PASSWORD};");
    assert_not_reported(&text, "dlp_connection_string_password");
    for text in [
        format!("password={PASSWORD}"),
        format!("user=orders password={PASSWORD}"),
        // keyword arguments of a call are no libpq string
        format!("psycopg2.connect(host=\"db\", user=\"app\", password=\"{PASSWORD}\")"),
        // the query of a web URL is an auth URL
        format!("https://api.example.com/login?user=app&password={PASSWORD}"),
    ] {
        let result = scan(&text);
        assert!(!result.evidence_spans.is_empty(), "{text:?}");
        assert_not_reported(&text, "dlp_connection_string_password");
    }
    // `user/…@` without `jdbc:oracle:thin:` is a CLI credential (G03).
    assert_not_reported(
        &format!("sqlplus scott/{PASSWORD}@ORCL"),
        "dlp_connection_string_password",
    );
}

#[test]
fn references_placeholders_and_stand_ins_are_no_findings() {
    for text in [
        "Server=sql01;Database=orders;User Id=app;Password=${ORDERS_DB_PASSWORD};",
        "Server=sql01;Database=orders;User Id=app;Password=$(DB_PASSWORD);",
        "Data Source=sql01;Initial Catalog=orders;User ID=app;Password=%DB_PASSWORD%;",
        "Server=sql01;Database=orders;User Id=app;Password={{ db_password }};",
        "Server=sql01;Database=orders;User Id=app;Password=<your-password>;",
        "Driver={ODBC Driver 18 for SQL Server};Server=sql01;Uid=sa;Pwd={<your-password>};",
        "Driver={ODBC Driver 18 for SQL Server};Server=sql01;Uid=sa;Pwd={${ODBC_PASSWORD}};",
        "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;",
        "Server=sql01;Database=orders;User Id=sa;Password=password;",
        "Server=sql01;Database=orders;Integrated Security=true;",
        "Server=sql01;Database=orders;User Id=app;Password=;",
        "jdbc:postgresql://db.internal:5432/orders?user=orders&password=${DB_PASSWORD}",
        "jdbc:oracle:thin:scott/<password>@//ora01.internal:1521/ORCL",
        "psql \"host=db.internal dbname=orders user=orders sslmode=require\"",
        "REDIS_URL=redis://:${REDIS_PASSWORD}@cache.internal:6379/0",
        "ldapsearch -x -D \"cn=admin,dc=acme,dc=org\" -W -b \"dc=acme,dc=org\"",
        "ldapsearch -x -D \"cn=admin,dc=acme,dc=org\" -w \"$LDAP_BIND_PW\" -b \"dc=acme,dc=org\"",
        "ldapsearch -x -D \"cn=admin,dc=acme,dc=org\" -w secret -b \"dc=acme,dc=org\"",
        "ldapsearch -x -D <bind-dn> -w <password> -b <base-dn>",
        "bindpw changeme",
        "The bindpw option sets the password that nslcd uses for the simple bind.",
        "Der Parameter bindpw enthält das Passwort für die einfache Bindung.",
        "ldap_default_authtok = ${SSSD_BIND_PASSWORD}",
        // unquoted code holds no value
        "options.BindCredential = configuration[\"Ldap:BindPassword\"];",
        "\"bindCredential\": settings.ldap.password,",
        "var cs = \"Server=sql01;Database=orders;Password=\" + settings.DbPassword + \";\";",
    ] {
        assert_silent(text);
    }
}

#[test]
fn connection_strings_win_over_generic_and_url_parameter_matches() {
    let text = format!("jdbc:mysql://db:3306/orders?user=orders&password={PASSWORD}&useSSL=true");
    let result = scan(&text);
    let entries = rule_entries(&result);
    let winner = entries
        .iter()
        .find(|rule| rule["rule_id"] == "dlp_connection_string_password")
        .expect("connection string match");
    assert!(winner.get("suppressed_by").is_none());
    assert_eq!(winner["subtype"], "connection_string");
    assert_eq!(winner["validator_strength"], "structure");
    for loser in ["dlp_credential_in_url", "dlp_password_assignment"] {
        let entry = entries
            .iter()
            .find(|rule| rule["rule_id"] == loser)
            .unwrap_or_else(|| panic!("{loser} must match"));
        assert_eq!(entry["suppressed_by"], "dlp_connection_string_password");
    }

    let text = format!("ldapsearch -x -D cn=admin,dc=acme,dc=org -w {PASSWORD}");
    let result = scan(&text);
    let entry = rule_entries(&result)
        .into_iter()
        .find(|rule| rule["rule_id"] == "dlp_ldap_bind_password")
        .expect("LDAP bind match");
    assert_eq!(entry["subtype"], "password");
    assert_eq!(entry["severity"], "live");
}
