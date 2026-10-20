// SPDX-License-Identifier: GPL-3.0-only
//! Confidential business content and source/SQL/dump/log content classes
//! (default off).
use crate::detectors::dlp::dlp::DlpPattern;

pub(super) const RULES: &[DlpPattern] = &[
    // ── Confidential business content ───────────────────────────────────────
    DlpPattern {
        name: "dlp_internal_business_metric",
        pattern: r"(?i)\b(?P<anchor_7>Jahresgehalt|Bruttogehalt|Grundgehalt|Gehalt|Annual[ -]?Salary|Base[ -]?Salary|Salary|EBITDA[ -]?Marge|EBIT[ -]?Marge|Rohertragsmarge|Deckungsbeitrag|Marge|Umsatz|Rohertrag|EBITDA|EBIT|Revenue|Gross[ -]?Margin|Net[ -]?Margin|Forecast)\b(?:\s+(?P<anchor_6>is|at|liegt|beträgt|ist|bei|von|neu|Plan))?\s*(?P<anchor_5>:|=)?\s*(?P<anchor_4>bei\s+|von\s+)?([+\-]?\d+(?P<anchor_3>[.\s]\d{3})*(?P<anchor_2>,\d+)?\s*(?:%|percent|Prozent|EUR|Euro|€|CHF|USD|Mio\.?\s*(?P<anchor_1>EUR|Euro|€)?|TEUR))",
        entity_group: "dlp.internal.business_metric",
        validator: None,
        span_group: None,
    },
    // ── Source/code-like content ────────────────────────────────────────────
    DlpPattern {
        name: "dlp_database_dump_insert",
        pattern: r"(?im)^[ \t]*INSERT\s+INTO\s+[^;\n]+\s+VALUES\s*\([^;\n]+\);?[ \t]*$",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_fence",
        pattern: r"(?s)```(?P<anchor_1>[A-Za-z0-9_+.-]+)?[ \t]*\n.*?\n```",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_statement",
        pattern: r"(?m)^[ \t]*(?P<anchor_3>const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?P<anchor_2>\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>,.\[\] |]*)?\s*=\s*(?P<anchor_1>new\s+)?[^;\n]{2,};[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_python_rust_assignment",
        pattern: r#"(?m)^[ \t]*(?:(?:let(?P<anchor_3>\s+mut)?|static|final)\s+)?[A-Za-z_][A-Za-z0-9_]*(?P<anchor_2>\s*:\s*[A-Za-z_][A-Za-z0-9_<>,.\[\] ]*)?\s*=\s*(?P<anchor_1>[A-Za-z_][A-Za-z0-9_.]*\s*\([^\n]*\)|[\[{][^\n]*[\]}]|[rubf]?['"][^\n'"]+['"]|\d+)[ \t]*;?[ \t]*$"#,
        entity_group: "dlp.content.source_code",
        validator: Some(is_non_placeholder_source_assignment),
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_declaration",
        pattern: r"(?ms:^[ \t]*package[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\r?\n(?P<anchor_7>[^\r\n]*\r?\n){0,16}?[ \t]*(?:import(?P<anchor_6>[ \t]+|[ \t]*\()|func[ \t]+|type[ \t]+|var[ \t]+|const[ \t]+)[^\r\n]*)|(?m:^[ \t]*(?P<anchor_5>pub\s+)?(?P<anchor_4>async\s+)?(?P<anchor_3>fn|def|function|class|interface|struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*(?P<anchor_2>\s*[<(][^\n]*[>)]\s*)?\s*(?P<anchor_1>\{|:)[ \t]*$)",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_source_code_import",
        pattern: r"(?m)^[ \t]*(?:from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+[^\n]+|import\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*(?P<anchor_1>\s+from\s+)?[^\n;]*)|use\s+[A-Za-z_][A-Za-z0-9_:{}*, ]*);?[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_sql_statement",
        pattern: r"(?ims)^[ \t\r\n]*((?:(?:--[^\r\n]*(?:\r?\n|$)|/\*.*?\*/[ \t]*(?:\r?\n|$))(?:[ \t]*\r?\n)*)*(?:CREATE|ALTER|INSERT|DROP|SET|USE|COMMIT|SELECT|UPDATE|DELETE|TRUNCATE|GRANT|REVOKE|REPLACE|MERGE|CALL|BEGIN)\b(?:[^;\r\n]*\r?\n){0,64}[^;\r\n]*;)[ \t]*$",
        entity_group: "dlp.content.sql",
        validator: Some(is_structured_sql_statement),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_sql_multiline_statement",
        pattern: r"(?is)\b(?P<anchor_1>SELECT\b.*?\bFROM\b|UPDATE\b.*?\bSET\b|INSERT\s+INTO\b.*?\bVALUES\b|DELETE\s+FROM\b).*?;",
        entity_group: "dlp.content.sql",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_database_dump_header",
        pattern: r"(?im)^(?:--\s*(?P<anchor_1>PostgreSQL|MySQL|MariaDB|SQLite)\s+database\s+dump|PRAGMA\s+foreign_keys\s*=\s*[^;\n]+;?|CREATE\s+TABLE\s+[^\n(]+\s*\([^;]+\);)",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_stacktrace_block",
        pattern: r"(?im)^(?:Traceback \(most recent call last\):|[^\n]*(?P<anchor_2>Error|Exception|FATAL|Fehler|Ausnahme)[^\n]*)\n(?:[ \t]+(?P<anchor_1>File |at |\.\.\.)[^\n]*\n?){1,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_structured_system_log",
        pattern: r"(?im)^\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?P<anchor_2>ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+[^\n]+(?:\n\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?P<anchor_1>ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+[^\n]+){0,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
    },
];

fn is_non_placeholder_source_assignment(candidate: &str) -> bool {
    let Some((_, value)) = candidate.split_once('=') else {
        return true;
    };
    !matches!(
        value
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "[redacted]" | "[masked]" | "[placeholder]"
    )
}

fn is_structured_sql_statement(candidate: &str) -> bool {
    if candidate.len() > 8192 {
        return false;
    }
    let mut statement = candidate.trim_start();
    loop {
        if let Some(comment) = statement.strip_prefix("--") {
            let Some(newline) = comment.find('\n') else {
                return false;
            };
            statement = comment[newline + 1..].trim_start();
        } else if let Some(comment) = statement.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else {
                return false;
            };
            statement = comment[end + 2..].trim_start();
        } else {
            break;
        }
    }

    let normalized = statement
        .trim_end()
        .strip_suffix(';')
        .unwrap_or(statement)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let contains_token = |token: &str| normalized.contains(&format!(" {token} "));

    [
        "CREATE DATABASE ",
        "CREATE SCHEMA ",
        "CREATE TABLE ",
        "CREATE VIEW ",
        "CREATE INDEX ",
        "CREATE UNIQUE INDEX ",
        "CREATE SEQUENCE ",
        "CREATE TRIGGER ",
        "CREATE FUNCTION ",
        "CREATE PROCEDURE ",
        "CREATE TYPE ",
        "CREATE ROLE ",
        "CREATE USER ",
        "CREATE OR REPLACE VIEW ",
        "CREATE OR REPLACE FUNCTION ",
        "CREATE OR REPLACE PROCEDURE ",
        "ALTER DATABASE ",
        "ALTER SCHEMA ",
        "ALTER TABLE ",
        "ALTER VIEW ",
        "ALTER INDEX ",
        "ALTER SEQUENCE ",
        "ALTER TYPE ",
        "ALTER ROLE ",
        "ALTER USER ",
        "DROP DATABASE ",
        "DROP SCHEMA ",
        "DROP TABLE ",
        "DROP VIEW ",
        "DROP INDEX ",
        "DROP SEQUENCE ",
        "DROP TRIGGER ",
        "DROP FUNCTION ",
        "DROP PROCEDURE ",
        "DROP TYPE ",
        "DROP ROLE ",
        "DROP USER ",
        "INSERT INTO ",
        "DELETE FROM ",
        "REPLACE INTO ",
        "MERGE INTO ",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
        || (normalized.starts_with("SELECT ") && contains_token("FROM"))
        || (normalized.starts_with("UPDATE ") && contains_token("SET"))
        || (normalized.starts_with("SET ") && normalized.contains('='))
        || matches!(
            normalized.as_str(),
            "COMMIT" | "COMMIT WORK" | "BEGIN" | "BEGIN WORK" | "BEGIN TRANSACTION"
        )
        || normalized.starts_with("TRUNCATE TABLE ")
        || (normalized.starts_with("GRANT ") && contains_token("TO"))
        || (normalized.starts_with("REVOKE ") && contains_token("FROM"))
        || (normalized.starts_with("CALL ")
            && normalized.contains('(')
            && normalized.ends_with(')'))
}
