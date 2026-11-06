// SPDX-License-Identifier: MIT OR Apache-2.0
//! T23: key→value binding in the data rows of SQL dumps (mysqldump,
//! pg_dump, SQLite `.dump`). An `INSERT … VALUES` statement at the start of
//! a line (also `INSERT IGNORE`, `INSERT OR REPLACE`, `REPLACE INTO`, with
//! several tuples on one or more lines) and a `COPY … FROM stdin;` block
//! (tab-separated lines up to `\.`) are read as rows of fields:
//!
//! - a column whose name holds the key binds the field at its position in
//!   every row (`INSERT INTO t (id, zugangsdaten) VALUES (1, '…')`);
//! - a field that holds the key binds the next field of its row, as in a
//!   settings table (`(2,'service_secret','…','2026-…')`); the key field is
//!   a short quoted string, the bound field a quoted string as well.
//!
//! Only quoted strings (`'…'` with `''` or `\'` inside) and COPY fields
//! bind; numbers, `NULL`, `\N` and expressions (`current_setting('…')`) do
//! not. SQL that code builds in a string (`execute("INSERT …")`) does not
//! start its line and binds nothing; DDL holds no rows. Whether the key
//! binds a rule and the value counts, the rules decide, as for the config
//! formats ([`super::config_keys`]).
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::config_keys::{ConfigFormat, ConfigValue};

/// The head of an `INSERT` statement at the start of a line up to the first
/// tuple: table name, optional column list (group 1) and `VALUES`. Matched
/// at the start of a line that holds `INTO` ([`line_starts`]).
static INSERT_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A[ \t]*(?:INSERT(?:[ \t]+(?:IGNORE|OR[ \t]+[A-Z]+))?|REPLACE)[ \t]+INTO[ \t]+[^\s(]+[ \t]*(?:\(([^();]*)\)\s*)?VALUES\s*",
    )
    .unwrap()
});

/// A pg_dump `COPY table (columns) FROM stdin;` line; the rows follow.
static COPY_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\ACOPY[ \t]+[^\s(]+[ \t]*\(([^()\r\n]*)\)[ \t]+FROM[ \t]+stdin;[ \t]*\r?$")
        .unwrap()
});

/// Longest key field in bytes, as for a quoted config key.
const MAX_KEY_FIELD: usize = 64;

/// An `INSERT` or `COPY` statement of a dump, parsed once per text
/// ([`crate::threat::NativeText::sql_statements`]) for every key-bound rule.
pub struct Statement {
    /// The names of the column list; empty without one.
    columns: Vec<Range<usize>>,
    /// Per row, per field the range of a quoted string or COPY field, or
    /// `None` for any other field.
    rows: Vec<Vec<Option<Range<usize>>>>,
    /// The fields of an `INSERT`, where only a quoted key field binds.
    quoted: bool,
}

/// The SQL row values whose column name or key field holds a match of
/// `key`, by statement.
pub fn sql_values(text: &str, statements: &[Statement], key: &Regex) -> Vec<ConfigValue> {
    row_values(text, statements, key, true)
}

/// The SQL row values whose key field holds a match of `key`: a settings
/// row that names its value, not a column of per-row values.
pub fn key_field_values(text: &str, statements: &[Statement], key: &Regex) -> Vec<ConfigValue> {
    row_values(text, statements, key, false)
}

/// The literals of the statement heads; dumps write `INTO` in one case.
static HEAD_LITERAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"INTO|into|COPY ").unwrap());

fn row_values(
    text: &str,
    statements: &[Statement],
    key: &Regex,
    by_column: bool,
) -> Vec<ConfigValue> {
    let mut values = Vec::new();
    for statement in statements {
        let columns = if by_column {
            &statement.columns[..]
        } else {
            &[]
        };
        bind(text, key, columns, statement, &mut values);
    }
    values
}

/// The `INSERT` and `COPY` statements of `text` that hold rows, in order.
/// A statement ends at the next statement head at the latest: every byte is
/// read by one statement only, so many heads without an end (`\.`, `;`, a
/// closing parenthesis) cost linear time, and a malformed statement hides
/// none that follow.
pub fn statements(text: &str) -> Vec<Statement> {
    let heads: Vec<(usize, regex::Captures<'_>, bool)> = line_starts(text)
        .into_iter()
        .filter_map(|line_start| {
            let line = &text[line_start..];
            INSERT_HEAD
                .captures(line)
                .map(|head| (line_start, head, true))
                .or_else(|| {
                    COPY_HEAD
                        .captures(line)
                        .map(|head| (line_start, head, false))
                })
        })
        .collect();
    let mut statements = Vec::new();
    for (index, (line_start, head, insert)) in heads.iter().enumerate() {
        let bounded = &text[..heads.get(index + 1).map_or(text.len(), |next| next.0)];
        let at = line_start + head.get(0).unwrap().end();
        let columns = head.get(1).map_or_else(Vec::new, |columns| {
            column_names(
                text,
                line_start + columns.start()..line_start + columns.end(),
            )
        });
        let statement = Statement {
            columns,
            rows: if *insert {
                insert_rows(bounded, at)
            } else {
                copy_rows(bounded, at)
            },
            quoted: *insert,
        };
        if !statement.rows.is_empty() {
            statements.push(statement);
        }
    }
    statements
}

/// The starts of the lines that hold a statement head literal
/// ([`HEAD_LITERAL`]), in order: the statement regexes run only there,
/// anchored, not over the whole text.
fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let (mut line_start, mut scanned) = (0, 0);
    for found in HEAD_LITERAL.find_iter(text) {
        if let Some(newline) = text[scanned..found.start()].rfind('\n') {
            line_start = scanned + newline + 1;
        }
        scanned = found.start();
        if starts.last() != Some(&line_start) {
            starts.push(line_start);
        }
    }
    starts
}

/// Whether the value at `at` stands on a line that opens an `INSERT`
/// statement, as a field of its rows.
pub fn is_row_value(text: &str, at: usize) -> bool {
    let line_start = text[..at].rfind('\n').map_or(0, |end| end + 1);
    INSERT_HEAD.is_match(&text[line_start..at])
}

/// The values of `statement` bound by a key column of `columns` or a key
/// field.
fn bind(
    text: &str,
    key: &Regex,
    columns: &[Range<usize>],
    statement: &Statement,
    values: &mut Vec<ConfigValue>,
) {
    let value = |key: &Range<usize>, value: &Range<usize>| ConfigValue {
        key: key.clone(),
        value: value.clone(),
        format: ConfigFormat::Sql,
        item: false,
    };
    let key_columns: Vec<(usize, &Range<usize>)> = columns
        .iter()
        .enumerate()
        .filter(|(_, column)| key.is_match(&text[(*column).clone()]))
        .collect();
    let quoted = statement.quoted;
    for row in &statement.rows {
        for &(index, column) in &key_columns {
            if let Some(Some(field)) = row.get(index) {
                values.push(value(column, field));
            }
        }
        for pair in row.windows(2) {
            if let [Some(field), Some(next)] = pair {
                let short =
                    field.len() <= MAX_KEY_FIELD && !(quoted && text[field.clone()].contains('\n'));
                if short && key.is_match(&text[field.clone()]) {
                    values.push(value(field, next));
                }
            }
        }
    }
}

/// The names in a column list, without blanks and identifier quotes
/// (`` `name` ``, `"name"`, `[name]`).
fn column_names(text: &str, list: Range<usize>) -> Vec<Range<usize>> {
    let mut names = Vec::new();
    let mut start = list.start;
    for part in text[list.clone()].split(',') {
        let trimmed = part.trim_start_matches([' ', '\t', '\r', '\n', '`', '"', '[']);
        let from = start + (part.len() - trimmed.len());
        let name = trimmed.trim_end_matches([' ', '\t', '\r', '\n', '`', '"', ']']);
        names.push(from..from + name.len());
        start += part.len() + 1;
    }
    names
}

fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// The tuples of an `INSERT` from `at` (after `VALUES`): per field the range
/// inside a non-empty quoted string, or `None` for any other field. A
/// statement that does not end in `;` after its tuples, as every statement of
/// a dump does, or holds anything malformed has no rows: SQL that code holds
/// in a multi-line string (`` db.Exec(`\nINSERT … VALUES (…)`) ``) binds nothing.
fn insert_rows(text: &str, at: usize) -> Vec<Vec<Option<Range<usize>>>> {
    insert_tuples(text.as_bytes(), at).unwrap_or_default()
}

fn insert_tuples(bytes: &[u8], mut at: usize) -> Option<Vec<Vec<Option<Range<usize>>>>> {
    let mut rows = Vec::new();
    while bytes.get(at) == Some(&b'(') {
        let mut row = Vec::new();
        at += 1;
        loop {
            at = skip_space(bytes, at);
            let field = if bytes.get(at) == Some(&b'\'') {
                let end = string_end(bytes, at)?;
                let content = at + 1..end;
                at = end + 1;
                (!content.is_empty()).then_some(content)
            } else {
                at = expression_end(bytes, at)?;
                None
            };
            row.push(field);
            at = skip_space(bytes, at);
            match bytes.get(at)? {
                b',' => at += 1,
                b')' => {
                    at += 1;
                    break;
                }
                _ => return None,
            }
        }
        rows.push(row);
        at = skip_space(bytes, at);
        if bytes.get(at) != Some(&b',') {
            break;
        }
        at = skip_space(bytes, at + 1);
    }
    (bytes.get(at) == Some(&b';')).then_some(rows)
}

/// The closing quote of the SQL string that opens at `open`: `''` and a
/// backslash escape (mysqldump) stay inside.
fn string_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut at = open + 1;
    loop {
        match bytes.get(at)? {
            b'\\' => at += 2,
            b'\'' if bytes.get(at + 1) == Some(&b'\'') => at += 2,
            b'\'' => return Some(at),
            _ => at += 1,
        }
    }
}

/// The end of a field that is no string (a number, `NULL`, a call): the
/// `,` or `)` at its own nesting depth.
fn expression_end(bytes: &[u8], mut at: usize) -> Option<usize> {
    let mut depth = 0usize;
    loop {
        match bytes.get(at)? {
            b'\'' => at = string_end(bytes, at)?,
            b'(' => depth += 1,
            b')' if depth == 0 => return Some(at),
            b')' => depth -= 1,
            b',' if depth == 0 => return Some(at),
            b';' if depth == 0 => return None,
            _ => {}
        }
        at += 1;
    }
}

/// The rows of a `COPY … FROM stdin;` block from `at` (the end of its head
/// line) up to the `\.` line: tab-separated fields, `\N` and empty fields
/// as `None`.
fn copy_rows(text: &str, at: usize) -> Vec<Vec<Option<Range<usize>>>> {
    let mut rows = Vec::new();
    let mut start = at + text[at..].find('\n').map_or(text.len() - at, |end| end + 1);
    while start < text.len() {
        let end = text[start..]
            .find('\n')
            .map_or(text.len(), |end| start + end);
        let line = start..end - usize::from(text[start..end].ends_with('\r'));
        if &text[line.clone()] == "\\." {
            break;
        }
        let mut from = line.start;
        let mut row = Vec::new();
        for field in text[line].split('\t') {
            let range = from..from + field.len();
            row.push((!field.is_empty() && field != "\\N").then_some(range));
            from += field.len() + 1;
        }
        rows.push(row);
        start = end + 1;
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(&str, &str)> {
        let key = Regex::new(r"(?i)(?:password|secret|token|zugangsdaten)").unwrap();
        sql_values(text, &statements(text), &key)
            .into_iter()
            .map(|value| (&text[value.key], &text[value.value]))
            .collect()
    }

    #[test]
    fn key_fields_bind_the_next_quoted_field() {
        let text = "INSERT INTO `settings` VALUES (1,'export.url','https://x','2026-09-14'),\
                    (2,'service_secret','it''s\\'q','2026-09-14'),(3,'db_password',NULL,'x');\n";
        assert_eq!(pairs(text), vec![("service_secret", "it''s\\'q")]);
        let sqlite = "INSERT INTO app_settings VALUES('api_token','tok-value','2026');\n";
        assert_eq!(pairs(sqlite), vec![("api_token", "tok-value")]);
    }

    #[test]
    fn key_columns_bind_their_field_in_every_row() {
        let text = "INSERT INTO public.t (id, name, zugangsdaten, at) VALUES\n  (1, 'a', 'first', '2026'),\n  (2, 'b', current_setting('erp.x'), '2026'),\n  (3, 'c', 'third', '2026');\n";
        assert_eq!(
            pairs(text),
            vec![("zugangsdaten", "first"), ("zugangsdaten", "third")]
        );
        let quoted = "REPLACE INTO `t` (`id`,`password`) VALUES (1,'pw-one');\n";
        assert_eq!(pairs(quoted), vec![("password", "pw-one")]);
    }

    #[test]
    fn copy_blocks_bind_by_column_and_key_field() {
        let text = "COPY public.cfg (id, name, password) FROM stdin;\n1\tapi_secret\tvalue-one\n2\tother\t\\N\n\\.\n";
        assert_eq!(
            pairs(text),
            vec![("password", "value-one"), ("api_secret", "value-one")]
        );
    }

    #[test]
    fn key_field_values_skip_columns() {
        let key = Regex::new(r"(?i)password[ _-]?hash").unwrap();
        let text = "INSERT INTO users (id, password_hash) VALUES (1, 'digest-one');\n\
                    INSERT INTO settings VALUES ('admin_password_hash', 'digest-two');\n";
        let parsed = statements(text);
        let bound: Vec<_> = key_field_values(text, &parsed, &key)
            .into_iter()
            .map(|value| &text[value.value])
            .collect();
        assert_eq!(bound, vec!["digest-two"]);
        assert_eq!(sql_values(text, &parsed, &key).len(), 2);
    }

    #[test]
    fn statements_end_at_the_next_head() {
        let text =
            "COPY t (password) FROM stdin;\npw-one\nINSERT INTO u (password) VALUES ('pw-two');\n";
        assert_eq!(
            pairs(text),
            vec![("password", "pw-one"), ("password", "pw-two")]
        );
        let text = "INSERT INTO t VALUES ((\nINSERT INTO u (secret) VALUES ('s-one');\n";
        assert_eq!(pairs(text), vec![("secret", "s-one")]);
    }

    #[test]
    fn many_heads_without_an_end_stay_linear() {
        for line in [
            "COPY t (a) FROM stdin;\n",
            "INSERT INTO t VALUES ((((((((((\n",
            "INSERT INTO t VALUES (1),\n",
            "INSERT INTO t VALUES ('a\n",
        ] {
            let text = line.repeat(100 * 1024 / line.len());
            let started = std::time::Instant::now();
            let parsed = statements(&text);
            let elapsed = started.elapsed();
            assert!(parsed.len() <= 1, "{line}");
            assert!(
                elapsed < std::time::Duration::from_millis(100),
                "{line}: {elapsed:?}"
            );
        }
    }

    #[test]
    fn line_starts_of_literals() {
        let text = "a INTO b\nc\nd into e INTO\nCOPY x\nf";
        assert_eq!(line_starts(text), vec![0, 11, 25]);
    }

    #[test]
    fn row_values_stand_on_insert_lines() {
        let text = "-- dump\nINSERT INTO t VALUES (1,'a','b');\nvalue = 'b'\n";
        assert!(is_row_value(text, text.find("'b'").unwrap() + 1));
        assert!(!is_row_value(text, text.rfind("'b'").unwrap() + 1));
    }

    #[test]
    fn code_ddl_and_malformed_statements_bind_nothing() {
        for text in [
            "cursor.execute(\"INSERT INTO users (name, password) VALUES ('bob', 'x1')\")\n",
            "CREATE TABLE users (id int, password text, secret text);\n",
            "query = 'INSERT INTO cfg VALUES (' + key + ', ' + secret + ')'\n",
            "INSERT INTO cfg (name, password) VALUES (%s, %s);\n",
            "INSERT INTO cfg VALUES ('api_secret', ?);\n",
            "INSERT INTO cfg (password) SELECT pw FROM old;\n",
            "db.Exec(`\nINSERT INTO cfg (name, password) VALUES ('a', 'pw-one')`)\n",
            "INSERT INTO cfg (name, password) VALUES ('a', 'pw-one'), ('b', 'pw-two' || x);\n",
        ] {
            assert_eq!(pairs(text), vec![], "{text}");
        }
    }
}
