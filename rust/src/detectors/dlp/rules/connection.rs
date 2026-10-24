// SPDX-License-Identifier: GPL-3.0-only
//! G01: structure of connection strings. `dlp_connection_string_password`
//! matches a `password`/`pwd` key with its value; the value counts only where
//! the key belongs to a connection string:
//!
//! - key/value strings separated by `;` (ADO.NET, ODBC, OLE DB, JDBC SQL
//!   Server/DB2 properties) that name a server, data source, host, DSN,
//!   driver or provider, or follow a `jdbc:` URL;
//! - libpq keyword/value strings separated by whitespace
//!   (`host=db dbname=app user=app password=…`) with a host and a database,
//!   user or port;
//! - a query parameter of a database or broker URL
//!   (`jdbc:mysql://db/app?user=app&password=…`, `postgresql://db/app?password=…`);
//! - Oracle thin/OCI `jdbc:oracle:thin:user/<password>@host`.
use regex::Regex;
use std::{ops::Range, sync::LazyLock};

/// Bytes around a value that its line is searched for the other keys.
const LINE_WINDOW: usize = 512;

/// URL schemes of databases, caches, brokers and directories whose query
/// may carry the password (lower case; `jdbc:` URLs count for any subprotocol,
/// SQLAlchemy `dialect+driver` by its dialect).
const DATABASE_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mysqlx",
    "mariadb",
    "mongodb",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "mssql",
    "sqlserver",
    "oracle",
    "db2",
    "clickhouse",
    "cockroachdb",
    "cassandra",
    "couchbase",
    "neo4j",
    "snowflake",
    "ldap",
    "ldaps",
];

/// A key that names the server of a `;`-separated connection string, or a
/// JDBC URL whose properties follow it.
static SERVER_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:(?:^|[;\s{(=:,>]|\\?[",
        "\"'",
        r"])(?:server|data[ \t]+source|address|addr|network[ \t]+address|host|hostname|hostaddr",
        r"|server[ \t]*name|dsn|driver|provider)[ \t]*=|(?-u:\b)jdbc:[a-z0-9]+:)",
    ))
    .unwrap()
});

/// A libpq keyword with a value (`host=db`, `dbname = app`).
static LIBPQ_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:^|[\s",
        "\"'",
        r"])(host|hostaddr|service|dbname|user|port)[ \t]*=[ \t]*[^\s=;,]",
    ))
    .unwrap()
});

/// `jdbc:oracle:thin:user/` right before the password.
static ORACLE_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)jdbc:oracle:(?:thin|oci8?):[^/\s:@"']{1,64}/\z"#).unwrap());

/// The connection-string key (`password`, `pwd`) and its separator before a
/// value, with an opening quote or brace.
static PASSWORD_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:password|pwd)[ \t]*=[ \t]*["'{]?\z"#).unwrap());

/// Whether the value at `range` of `text` is the password of a connection
/// string, see the module docs.
pub(super) fn is_connection_string(text: &str, range: Range<usize>) -> bool {
    let line_start = floor(text, range.start.saturating_sub(LINE_WINDOW));
    let line_start = text[line_start..range.start]
        .rfind(['\n', '\r'])
        .map_or(line_start, |index| line_start + index + 1);
    let line_end = floor(text, (range.end + LINE_WINDOW).min(text.len()));
    let line_end = text[range.end..line_end]
        .find(['\n', '\r'])
        .map_or(line_end, |index| range.end + index);
    let before = &text[line_start..range.start];
    if ORACLE_USER.is_match(before) {
        return true;
    }
    let Some(key) = PASSWORD_KEY.find(before) else {
        return false;
    };
    let lead = &before[..key.start()];
    if lead.ends_with(['?', '&']) || lead.ends_with("&amp;") {
        return is_database_url(lead);
    }
    let line = &text[line_start..line_end];
    let after = text[range.end..line_end]
        .trim_start_matches(['"', '\'', '}'])
        .trim_start_matches([' ', '\t']);
    let lead_end = lead.trim_end_matches([' ', '\t']);
    if lead_end.ends_with(';') || after.starts_with(';') {
        return SERVER_KEY.is_match(line);
    }
    // libpq separates pairs by whitespace only; `host="db", password=…` is a
    // call with keyword arguments.
    !lead_end.ends_with([',', '(']) && is_libpq(line)
}

/// A libpq keyword/value string: a host or service and a database, user or
/// port.
fn is_libpq(line: &str) -> bool {
    let (mut server, mut target) = (false, false);
    for captures in LIBPQ_KEY.captures_iter(line) {
        match captures[1].to_ascii_lowercase().as_str() {
            "host" | "hostaddr" | "service" => server = true,
            _ => target = true,
        }
    }
    server && target
}

/// Whether the URL that ends in `lead` (up to its `?` or `&`) has a database
/// scheme.
fn is_database_url(lead: &str) -> bool {
    let token_start = lead
        .rfind(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>' | '('))
        .map_or(0, |index| index + 1);
    let token = &lead[token_start..];
    let Some(separator) = token.find("://") else {
        return false;
    };
    let head = &token[..separator];
    let scheme_start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-' | ':')))
        .map_or(0, |index| index + 1);
    let scheme = head[scheme_start..].to_ascii_lowercase();
    if scheme.starts_with("jdbc:") {
        return true;
    }
    let dialect = scheme.split('+').next().unwrap_or_default();
    DATABASE_SCHEMES.contains(&dialect)
}

fn floor(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(text: &str, value: &str) -> bool {
        let start = text.find(value).unwrap();
        is_connection_string(text, start..start + value.len())
    }

    #[test]
    fn key_value_strings_need_a_server_key_and_semicolons() {
        assert!(gate(
            "Server=db.internal;Database=app;User Id=app;Password=Kx7pQ2vL9!;",
            "Kx7pQ2vL9!"
        ));
        assert!(gate(
            "\"Default\": \"Data Source=db;Initial Catalog=app;Password='Kx7 pQ2';\"",
            "Kx7 pQ2"
        ));
        assert!(gate(
            "Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=sa;Pwd={Kx7;pQ2};",
            "Kx7;pQ2"
        ));
        assert!(gate("Password=Kx7pQ2vL9!;Host=db;", "Kx7pQ2vL9!"));
        assert!(gate(
            "jdbc:sqlserver://db:1433;databaseName=app;user=sa;password=Kx7pQ2vL9!;",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate(
            "Database=app;User Id=app;Password=Kx7pQ2vL9!;",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate("password=Kx7pQ2vL9!", "Kx7pQ2vL9!"));
    }

    #[test]
    fn libpq_strings_need_host_and_target_without_call_commas() {
        assert!(gate(
            "psql \"host=db port=5432 dbname=app user=app password=Kx7pQ2vL9!\"",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate(
            "connect(host=\"db\", user=\"app\", password=\"Kx7pQ2vL9!\")",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate("user=app password=Kx7pQ2vL9!", "Kx7pQ2vL9!"));
    }

    #[test]
    fn query_passwords_need_a_database_url() {
        assert!(gate(
            "jdbc:mysql://db:3306/app?user=app&password=Kx7pQ2vL9!",
            "Kx7pQ2vL9!"
        ));
        assert!(gate(
            "DATABASE_URL=postgresql+psycopg://db/app?user=app&password=Kx7pQ2vL9!",
            "Kx7pQ2vL9!"
        ));
        assert!(gate(
            "<url>jdbc:mariadb://db/app?user=app&amp;password=Kx7pQ2vL9!</url>",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate(
            "https://api.example.com/login?user=app&password=Kx7pQ2vL9!",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate("?user=app&password=Kx7pQ2vL9!", "Kx7pQ2vL9!"));
    }

    #[test]
    fn oracle_thin_takes_the_password_after_the_user() {
        assert!(gate(
            "jdbc:oracle:thin:scott/Kx7pQ2vL9!@//db:1521/orcl",
            "Kx7pQ2vL9!"
        ));
        assert!(!gate("scott/Kx7pQ2vL9!@db", "Kx7pQ2vL9!"));
    }
}
