// SPDX-License-Identifier: MIT OR Apache-2.0
//! Confidential business content and source/SQL/dump/log content classes
//! (default off).
use crate::detectors::dlp::content_class::{ContentClass, Density, Tier};
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, ValidatorStrength};
use std::ops::Range;
use std::sync::LazyLock;

pub(super) const RULES: &[DlpPattern] = &[
    // ── Confidential business content ───────────────────────────────────────
    DlpPattern {
        name: "dlp_internal_business_metric",
        pattern: r"(?i)\b(?P<anchor_7>Jahresgehalt|Bruttogehalt|Grundgehalt|Gehalt|Annual[ -]?Salary|Base[ -]?Salary|Salary|EBITDA[ -]?Marge|EBIT[ -]?Marge|Rohertragsmarge|Deckungsbeitrag|Marge|Umsatz|Rohertrag|EBITDA|EBIT|Revenue|Gross[ -]?Margin|Net[ -]?Margin|Forecast)\b(?:\s+(?P<anchor_6>is|at|liegt|beträgt|ist|bei|von|neu|Plan))?\s*(?P<anchor_5>:|=)?\s*(?P<anchor_4>bei\s+|von\s+)?([+\-]?\d+(?P<anchor_3>[.\s]\d{3})*(?P<anchor_2>,\d+)?\s*(?:%|percent|Prozent|EUR|Euro|€|CHF|USD|Mio\.?\s*(?P<anchor_1>EUR|Euro|€)?|TEUR))",
        entity_group: "dlp.internal.business_metric",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "gehalt",
                "salary",
                "marge",
                "deckungsbeitrag",
                "umsatz",
                "rohertrag",
                "ebit",
                "revenue",
                "margin",
                "forecast",
            ],
        ),
    },
    // ── Source/code-like content ────────────────────────────────────────────
    DlpPattern {
        name: "dlp_database_dump_insert",
        pattern: r"(?im)^[ \t]*INSERT\s+INTO\s+[^;\n]+\s+VALUES\s*\([^;\n]+\);?[ \t]*$",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["insert"]),
    },
    DlpPattern {
        name: "dlp_source_code_fence",
        pattern: r"(?s)```(?P<anchor_1>[A-Za-z0-9_+.-]+)?[ \t]*\n.*?\n```",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["```"]),
    },
    DlpPattern {
        name: "dlp_source_code_statement",
        pattern: r"(?m)^[ \t]*(?P<anchor_3>const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?P<anchor_2>\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>,.\[\] |]*)?\s*=\s*(?P<anchor_1>new\s+)?[^;\n]{2,};[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["const", "let", "var"]),
    },
    DlpPattern {
        name: "dlp_source_code_python_rust_assignment",
        pattern: r#"(?m)^[ \t]*(?:(?:let(?P<anchor_3>\s+mut)?|static|final)\s+)?[A-Za-z_][A-Za-z0-9_]*(?P<anchor_2>\s*:\s*[A-Za-z_][A-Za-z0-9_<>,.\[\] ]*)?\s*=\s*(?P<anchor_1>[A-Za-z_][A-Za-z0-9_.]*\s*\([^\n]*\)|[\[{][^\n]*[\]}]|[rubf]?['"][^\n'"]+['"]|\d+)[ \t]*;?[ \t]*$"#,
        entity_group: "dlp.content.source_code",
        validator: Some(is_non_placeholder_source_assignment),
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["="]),
    },
    DlpPattern {
        name: "dlp_source_code_declaration",
        pattern: r"(?ms:^[ \t]*package[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\r?\n(?P<anchor_7>[^\r\n]*\r?\n){0,16}?[ \t]*(?:import(?P<anchor_6>[ \t]+|[ \t]*\()|func[ \t]+|type[ \t]+|var[ \t]+|const[ \t]+)[^\r\n]*)|(?m:^[ \t]*(?P<anchor_5>pub\s+)?(?P<anchor_4>async\s+)?(?P<anchor_3>fn|def|function|class|interface|struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*(?P<anchor_2>\s*[<(][^\n]*[>)]\s*)?\s*(?P<anchor_1>\{|:)[ \t]*$)",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "package",
                "fn",
                "def",
                "function",
                "class",
                "interface",
                "struct",
                "enum",
            ],
        ),
    },
    DlpPattern {
        name: "dlp_source_code_import",
        pattern: r"(?m)^[ \t]*(?:from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+[^\n]+|import\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*(?P<anchor_1>\s+from\s+)?[^\n;]*)|use\s+[A-Za-z_][A-Za-z0-9_:{}*, ]*);?[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["import", "use"]),
    },
    DlpPattern {
        name: "dlp_sql_statement",
        pattern: r"(?ims)^[ \t\r\n]*((?:(?:--[^\r\n]*(?:\r?\n|$)|/\*.*?\*/[ \t]*(?:\r?\n|$))(?:[ \t]*\r?\n)*)*(?:CREATE|ALTER|INSERT|DROP|SET|USE|COMMIT|SELECT|UPDATE|DELETE|TRUNCATE|GRANT|REVOKE|REPLACE|MERGE|CALL|BEGIN)\b(?:[^;\r\n]*\r?\n){0,64}[^;\r\n]*;)[ \t]*$",
        entity_group: "dlp.content.sql",
        validator: Some(is_structured_sql_statement),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "ark",
            &[
                "create", "alter", "insert", "drop", "set", "use", "commit", "select", "update",
                "delete", "truncate", "grant", "revoke", "replace", "merge", "call", "begin",
            ],
        ),
    },
    DlpPattern {
        name: "dlp_sql_multiline_statement",
        pattern: r"(?is)\b(?P<anchor_1>SELECT\b.*?\bFROM\b|UPDATE\b.*?\bSET\b|INSERT\s+INTO\b.*?\bVALUES\b|DELETE\s+FROM\b).*?;",
        entity_group: "dlp.content.sql",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["select", "update", "insert", "delete"],
        ),
    },
    DlpPattern {
        name: "dlp_database_dump_header",
        pattern: r"(?im)^(?:--\s*(?P<anchor_1>PostgreSQL|MySQL|MariaDB|SQLite)\s+database\s+dump|PRAGMA\s+foreign_keys\s*=\s*[^;\n]+;?|CREATE\s+TABLE\s+[^\n(]+\s*\([^;]+\);)",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["dump", "pragma", "create"],
        ),
    },
    DlpPattern {
        name: "dlp_stacktrace_block",
        pattern: r"(?im)^(?:Traceback \(most recent call last\):|[^\n]*(?P<anchor_2>Error|Exception|FATAL|Fehler|Ausnahme)[^\n]*)\n(?:[ \t]+(?P<anchor_1>File |at |\.\.\.)[^\n]*\n?){1,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "traceback",
                "error",
                "exception",
                "fatal",
                "fehler",
                "ausnahme",
            ],
        ),
    },
    DlpPattern {
        name: "dlp_structured_system_log",
        pattern: r"(?im)^\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?P<anchor_2>ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+[^\n]+(?:\n\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?P<anchor_1>ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+[^\n]+){0,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["error", "fatal", "critical", "fehler", "kritisch"],
        ),
    },
    // ── Document classes (M01 content class engine) ─────────────────────────
    // M01: attorney-client privileged correspondence. The privilege marker is
    // the evidence span; legal terms and letter structure around it make the
    // document (`LEGAL_PRIVILEGED`).
    DlpPattern {
        name: "dlp_document_legal_privileged",
        pattern: r"(?i)\b(?:attorney[- ]client[- ]privileged?|privileged\s+(?:and|&)\s+confidential|attorney\s+work[- ]product|legally\s+privileged|anwalts(?:korrespondenz|geheimnis)|mandats?geheimnis|mandantengeheimnis|anwaltliche[nrs]?\s+(?:berufsgeheimnis|schweigepflicht|korrespondenz)|verteidigerpost)\b",
        entity_group: "dlp.document.legal_privileged",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "privilege",
                "attorney",
                "anwalt",
                "mandat",
                "mandant",
                "verteidigerpost",
            ],
        )
        .with_context_gate(is_legal_privileged_document),
    },
];

/// M01: the anchors of attorney-client privileged correspondence around its
/// privilege marker.
static LEGAL_PRIVILEGED: LazyLock<ContentClass> = LazyLock::new(|| {
    ContentClass::new(
        &[
            ("counsel", Tier::Medium),
            ("opposing counsel", Tier::Medium),
            ("attorney", Tier::Medium),
            ("attorneys", Tier::Medium),
            ("lawyer", Tier::Medium),
            ("lawyers", Tier::Medium),
            ("law firm", Tier::Medium),
            ("legal advice", Tier::Medium),
            ("litigation", Tier::Medium),
            ("lawsuit", Tier::Medium),
            ("settlement", Tier::Medium),
            ("our client", Tier::Medium),
            ("your client", Tier::Medium),
            ("plaintiff", Tier::Medium),
            ("defendant", Tier::Medium),
            ("deposition", Tier::Medium),
            ("court", Tier::Medium),
            ("claim", Tier::Medium),
            ("trial", Tier::Medium),
            ("complaint", Tier::Medium),
            ("pleading", Tier::Medium),
            ("subpoena", Tier::Medium),
            ("rechtsanwalt", Tier::Medium),
            ("rechtsanwältin", Tier::Medium),
            ("rechtsanwälte", Tier::Medium),
            ("anwalt", Tier::Medium),
            ("anwältin", Tier::Medium),
            ("kanzlei", Tier::Medium),
            ("mandant", Tier::Medium),
            ("mandantin", Tier::Medium),
            ("mandanten", Tier::Medium),
            ("mandat", Tier::Medium),
            ("rechtsberatung", Tier::Medium),
            ("rechtsstreit", Tier::Medium),
            ("klage", Tier::Medium),
            ("klageentwurf", Tier::Medium),
            ("klageschrift", Tier::Medium),
            ("vergleich", Tier::Medium),
            ("vergleichsverhandlung", Tier::Medium),
            ("gericht", Tier::Medium),
            ("amtsgericht", Tier::Medium),
            ("landgericht", Tier::Medium),
            ("arbeitsgericht", Tier::Medium),
            ("aktenzeichen", Tier::Medium),
            ("az.", Tier::Medium),
            ("schriftsatz", Tier::Medium),
            ("gegenseite", Tier::Medium),
            ("beklagte", Tier::Medium),
            ("beklagten", Tier::Medium),
            ("kläger", Tier::Medium),
            ("klägerin", Tier::Medium),
            ("verfahren", Tier::Medium),
            ("subject:", Tier::Structural),
            ("re:", Tier::Structural),
            ("from:", Tier::Structural),
            ("to:", Tier::Structural),
            ("cc:", Tier::Structural),
            ("date:", Tier::Structural),
            ("dear", Tier::Structural),
            ("kind regards", Tier::Structural),
            ("best regards", Tier::Structural),
            ("sincerely", Tier::Structural),
            ("betreff:", Tier::Structural),
            ("von:", Tier::Structural),
            ("an:", Tier::Structural),
            ("datum:", Tier::Structural),
            ("sehr geehrte", Tier::Structural),
            ("sehr geehrter", Tier::Structural),
            ("mit freundlichen grüßen", Tier::Structural),
            ("freundliche grüße", Tier::Structural),
            ("viele grüße", Tier::Structural),
            ("beste grüße", Tier::Structural),
            ("unser zeichen", Tier::Structural),
            ("ihr zeichen", Tier::Structural),
            ("example", Tier::Counter),
            ("for example", Tier::Counter),
            ("sample", Tier::Counter),
            ("template", Tier::Counter),
            ("placeholder", Tier::Counter),
            ("e.g.", Tier::Counter),
            ("wikipedia", Tier::Counter),
            ("definition", Tier::Counter),
            ("is defined as", Tier::Counter),
            ("refers to", Tier::Counter),
            ("glossary", Tier::Counter),
            ("tutorial", Tier::Counter),
            ("lecture", Tier::Counter),
            ("lorem ipsum", Tier::Counter),
            ("beispiel", Tier::Counter),
            ("zum beispiel", Tier::Counter),
            ("z. b.", Tier::Counter),
            ("z.b.", Tier::Counter),
            ("muster", Tier::Counter),
            ("vorlage", Tier::Counter),
            ("platzhalter", Tier::Counter),
            ("bezeichnet", Tier::Counter),
            ("glossar", Tier::Counter),
            ("vorlesung", Tier::Counter),
            ("seminar", Tier::Counter),
        ],
        Density {
            window: 1500,
            min_score: 8,
            min_medium: 1,
        },
    )
});

fn is_legal_privileged_document(text: &str, marker: Range<usize>) -> bool {
    LEGAL_PRIVILEGED.holds(text, marker)
}

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

#[cfg(test)]
mod tests {
    use super::is_legal_privileged_document;

    fn gate(text: &str, marker: &str) -> bool {
        let start = text.find(marker).unwrap();
        is_legal_privileged_document(text, start..start + marker.len())
    }

    #[test]
    fn privileged_correspondence_holds_in_de_and_en() {
        assert!(gate(
            "Subject: Settlement\n\nPRIVILEGED AND CONFIDENTIAL\n\nDear Ms. Chen, our counsel advises against it.",
            "PRIVILEGED AND CONFIDENTIAL",
        ));
        assert!(gate(
            "Betreff: Klage\n\nVertrauliche Anwaltskorrespondenz\n\nSehr geehrte Damen und Herren, die Kanzlei rät zum Vergleich.",
            "Anwaltskorrespondenz",
        ));
    }

    #[test]
    fn a_marker_without_legal_anchors_does_not_hold() {
        assert!(!gate(
            "banner: Privileged & Confidential",
            "Privileged & Confidential"
        ));
        // Letter structure alone is no legal document.
        assert!(!gate(
            "Subject: Lunch\nDear team, the label legally privileged is grey.\nKind regards",
            "legally privileged",
        ));
    }

    #[test]
    fn counter_context_vetoes_definitions_and_templates() {
        assert!(!gate(
            "Das Anwaltsgeheimnis bezeichnet die Pflicht des Anwalts; zum Beispiel darf ein Gericht nichts verlangen.",
            "Anwaltsgeheimnis",
        ));
        assert!(!gate(
            "Email template: add PRIVILEGED AND CONFIDENTIAL and the name of your law firm.",
            "PRIVILEGED AND CONFIDENTIAL",
        ));
    }
}
