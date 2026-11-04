// SPDX-License-Identifier: MIT OR Apache-2.0
//! Commands inside commands (`sh -c`, `pwsh -Command`, `cmd /c`, `ssh host
//! CMD`), SQL given to database clients, settings changed by `sed -i`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::kf1::{turns, SECCTL};
use crate::detectors::shell::pyre::{py_regex, Anchor};

use super::segment::sed_in_place;
use super::Setting;

static SED_SETTING: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"([A-Za-z_][\w.-]{1,60})\s*[=: ]\s*([^\s,;]+)",
        false,
        Anchor::Search,
    )
});

static SQL_KINDS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "SQL_EXEC",
            py_regex(
                r"(?s)\b(create\s+function\b.*\bsoname\b|load_file\s*\(|into\s+(out|dump)file\b|copy\b.*\bprogram\b|xp_cmdshell|sys_exec|sys_eval)",
                true,
                Anchor::Search,
            ),
        ),
        (
            "DELETE_ALL",
            py_regex(
                r#"\bdelete\s+from\s+[\w."`\[\]]+\s*(;|$)|\btruncate\b"#,
                true,
                Anchor::Search,
            ),
        ),
        (
            "DROP",
            py_regex(
                r"\bdrop\s+(table|database|schema|user|role|index|view)\b",
                true,
                Anchor::Search,
            ),
        ),
        (
            "DELETE",
            py_regex(r"\bdelete\s+from\b", true, Anchor::Search),
        ),
        (
            "WRITE",
            py_regex(
                r#"\b(insert\s+into|update\s+[\w."`]+\s+set|alter\s+(table|user|role)|create\s+(table|user|role)|grant\b|revoke\b)"#,
                true,
                Anchor::Search,
            ),
        ),
        (
            "READ",
            py_regex(r"\b(select|show|describe|explain)\b", true, Anchor::Search),
        ),
    ]
});

pub(super) fn sql_op(kind: &str) -> &'static str {
    match kind {
        "SQL_EXEC" => "EXECUTE",
        "DELETE_ALL" | "DROP" | "DELETE" => "DELETE",
        "WRITE" => "CONFIG_CHANGE",
        _ => "READ",
    }
}

const SSH_VALUE_FLAGS: [&str; 19] = [
    "-i", "-p", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-m", "-O", "-Q",
    "-S", "-W", "-w",
];

/// (inner command string, `local` | `remote`) for `sh -c STR`, `pwsh -Command
/// STR`, `cmd /c STR`, `su -c STR`, `ssh [opts] host STR`.
pub(super) fn nested_command(prog: &str, rest: &[String]) -> Option<(String, &'static str)> {
    let low: Vec<String> = rest.iter().map(|w| w.to_lowercase()).collect();
    let index = |flag: &str| low.iter().position(|w| w == flag);
    if matches!(prog, "sh" | "bash" | "zsh" | "dash" | "ksh" | "su" | "sudo") {
        if let Some(k) = index("-c") {
            return rest.get(k + 1).map(|inner| (inner.clone(), "local"));
        }
    }
    if matches!(prog, "pwsh" | "powershell") {
        for flag in ["-command", "-c"] {
            if let Some(k) = index(flag) {
                return (k + 1 < rest.len()).then(|| (rest[k + 1..].join(" "), "local"));
            }
        }
    }
    if prog == "cmd" {
        if let Some(k) = index("/c").or_else(|| index("/k")) {
            return (k + 1 < rest.len()).then(|| (rest[k + 1..].join(" "), "local"));
        }
    }
    if matches!(prog, "ssh" | "autossh") {
        let mut k = 0;
        while k < rest.len() && rest[k].starts_with('-') {
            k += if SSH_VALUE_FLAGS.contains(&rest[k].as_str()) {
                2
            } else {
                1
            };
        }
        if k + 1 < rest.len() {
            return Some((rest[k + 1..].join(" "), "remote"));
        }
    }
    None
}

/// Statement kinds of SQL given to a database client.
pub(super) fn sql_kinds(prog: &str, rest: &[String]) -> Vec<&'static str> {
    const DB_CLIENTS: [&str; 9] = [
        "mysql",
        "mariadb",
        "psql",
        "sqlite3",
        "sqlcmd",
        "clickhouse-client",
        "mongo",
        "mongosh",
        "duckdb",
    ];
    const SQL_FLAGS: [&str; 8] = [
        "-e",
        "--execute",
        "-c",
        "--command",
        "-q",
        "-Q",
        "--query",
        "--eval",
    ];
    if !DB_CLIENTS.contains(&prog) {
        return Vec::new();
    }
    let mut texts: Vec<&str> = Vec::new();
    for (k, word) in rest.iter().enumerate() {
        let lower = word.to_lowercase();
        if SQL_FLAGS.contains(&lower.as_str()) && k + 1 < rest.len() {
            texts.push(&rest[k + 1]);
        } else if lower
            .split_once('=')
            .is_some_and(|(flag, _)| SQL_FLAGS.contains(&flag))
        {
            texts.push(word.split_once('=').map_or("", |(_, v)| v));
        }
    }
    if matches!(prog, "sqlite3" | "duckdb") {
        texts.extend(
            rest.iter()
                .skip(1)
                .filter(|w| !w.starts_with('-'))
                .map(String::as_str),
        );
    }
    let mut kinds = BTreeSet::new();
    for text in texts {
        kinds.extend(
            SQL_KINDS
                .iter()
                .filter(|(_, rx)| rx.is_match(text))
                .map(|(name, _)| *name),
        );
    }
    kinds.into_iter().collect()
}

/// `re.match(r'^s(.).*\1', word)`: a sed `s` command with its delimiter repeated.
fn is_sed_substitution(word: &str) -> bool {
    let mut chars = word.chars();
    if chars.next() != Some('s') {
        return false;
    }
    let Some(delimiter) = chars.next().filter(|c| *c != '\n') else {
        return false;
    };
    chars.take_while(|c| *c != '\n').any(|c| c == delimiter)
}

/// Group 3 of `re.match(r'^s(.)(.*?)\1(.*?)\1[gimx]*$', word)`: the replacement.
fn sed_replacement(word: &str) -> Option<&str> {
    let mut chars = word.char_indices();
    if chars.next().map(|(_, c)| c) != Some('s') {
        return None;
    }
    let (_, delimiter) = chars.next().filter(|(_, c)| *c != '\n')?;
    let body_start = 1 + delimiter.len_utf8();
    let line_end = word[body_start..]
        .find('\n')
        .map_or(word.len(), |offset| body_start + offset);
    let positions: Vec<usize> = word[body_start..line_end]
        .char_indices()
        .filter(|(_, c)| *c == delimiter)
        .map(|(offset, _)| body_start + offset)
        .collect();
    let width = delimiter.len_utf8();
    for (i, &second) in positions.iter().enumerate() {
        for &third in &positions[i + 1..] {
            let tail = &word[third + width..];
            let flags = tail.strip_suffix('\n').unwrap_or(tail);
            if flags.chars().all(|c| matches!(c, 'g' | 'i' | 'm' | 'x')) {
                return Some(&word[second + width..third]);
            }
        }
    }
    None
}

/// Settings changed by `sed -i 's/OLD/NEW/'` (e.g. `SELINUX=disabled`).
pub(super) fn sed_settings(prog: &str, rest: &[String]) -> Vec<Setting> {
    if prog != "sed" || !sed_in_place(rest) {
        return Vec::new();
    }
    let files = rest
        .iter()
        .filter(|w| !w.starts_with('-') && !is_sed_substitution(w))
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let mut out = Vec::new();
    for word in rest {
        let Some(replacement) = sed_replacement(word) else {
            continue;
        };
        for captures in SED_SETTING.captures_iter(replacement) {
            if let Some(turned) = turns(&captures[1], &captures[2]) {
                let domain = if SECCTL.is_match(&format!("{} {files}", &captures[1])) {
                    "SECCTL"
                } else {
                    "OTHER"
                };
                out.push(Setting {
                    domain,
                    polarity: &turned["TURNS_".len()..],
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sed_regex_helpers_match_python_backreferences() {
        assert!(is_sed_substitution("s/a/b/"));
        assert!(!is_sed_substitution("sed"));
        assert_eq!(
            sed_replacement("s/SELINUX=enforcing/SELINUX=disabled/g"),
            Some("SELINUX=disabled")
        );
        assert_eq!(sed_replacement("s|a|b|"), Some("b"));
        assert_eq!(sed_replacement("s/a/b"), None);
    }
}
