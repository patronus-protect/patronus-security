// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shell vocabulary lookup (`shell_vocab_v1.csv`): program [+ subcommand] ->
//! verb, role, sensitive. Port of the K26 reference `facts/vocab.py`.
//!
//! Subcommand rows are tried against the first positional argument, then the
//! second (`aws iam delete-user`); exact match before prefix match
//! (`delete-*`); otherwise the program's `*` row. Programs not in the
//! vocabulary return `None` and the extractor falls back to the marker verb
//! classes.

use std::collections::HashMap;
use std::sync::LazyLock;

/// The vocabulary embedded verbatim from the K26 release.
pub(crate) const VOCAB_CSV: &str = include_str!("data/shell_vocab_v1.csv");

const VERBS: [&str; 5] = ["READ", "MUTATE", "DELETE", "EXEC", "NONE"];
const ROLES: [&str; 19] = [
    "INTERP",
    "NET",
    "FILTER",
    "NAV",
    "OUTPUT",
    "BUILD",
    "PKG",
    "VCS",
    "CONTAINER",
    "CLOUD",
    "SERVICE",
    "ADMIN",
    "FILE",
    "PROCESS",
    "ARCHIVE",
    "CRYPTO",
    "SEARCH",
    "NOISE",
    "OTHER",
];

/// One vocabulary row: verb, role and whether it reads sensitive data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VocabRow {
    pub verb: &'static str,
    pub role: &'static str,
    pub sensitive: bool,
}

/// The rows of one program, keyed by lowercase subcommand, in file order.
struct ProgramRows {
    rows: HashMap<String, VocabRow>,
    /// `prefix*` keys in file order.
    prefixes: Vec<String>,
}

static TABLE: LazyLock<HashMap<String, ProgramRows>> = LazyLock::new(|| {
    let mut table: HashMap<String, ProgramRows> = HashMap::new();
    let records = parse_csv(VOCAB_CSV);
    let header = &records[0];
    let column = |name: &str| {
        header
            .iter()
            .position(|h| h == name)
            .unwrap_or_else(|| panic!("vocabulary has no {name} column"))
    };
    let (program, subcommand, verb, role, sensitive) = (
        column("program"),
        column("subcommand"),
        column("verb"),
        column("role"),
        column("sensitive"),
    );
    for record in &records[1..] {
        let field = |index: usize| record.get(index).map_or("", String::as_str);
        let verb = VERBS
            .iter()
            .find(|v| **v == field(verb))
            .unwrap_or_else(|| panic!("bad vocab row {record:?}"));
        let role = ROLES
            .iter()
            .find(|r| **r == field(role))
            .unwrap_or_else(|| panic!("bad vocab row {record:?}"));
        let entry = table
            .entry(field(program).to_string())
            .or_insert_with(|| ProgramRows {
                rows: HashMap::new(),
                prefixes: Vec::new(),
            });
        let key = field(subcommand).to_lowercase();
        if key.ends_with('*') && key.chars().count() > 1 && !entry.rows.contains_key(&key) {
            entry.prefixes.push(key.clone());
        }
        entry.rows.insert(
            key,
            VocabRow {
                verb,
                role,
                sensitive: field(sensitive) == "SENSITIVE_READ",
            },
        );
    }
    table
});

/// Records of a CSV document in Python's default `csv` dialect.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

const SEVERITY: [(&str, u8); 5] = [
    ("DELETE", 4),
    ("EXEC", 3),
    ("MUTATE", 2),
    ("READ", 1),
    ("NONE", 0),
];

/// Severity rank of a verb (`vocab.SEVERITY`).
pub(crate) fn severity(verb: &str) -> u8 {
    SEVERITY
        .iter()
        .find(|(name, _)| *name == verb)
        .map_or(0, |(_, rank)| *rank)
}

const DOCKER_GROUPS: [&str; 19] = [
    "image",
    "container",
    "volume",
    "network",
    "system",
    "builder",
    "buildx",
    "compose",
    "context",
    "plugin",
    "node",
    "service",
    "stack",
    "secret",
    "config",
    "swarm",
    "machine",
    "manifest",
    "trust",
];

/// Subcommands that are groups: the next positional argument is the action.
fn is_group(program: &str, word: &str) -> bool {
    match program {
        "docker" | "nerdctl" => DOCKER_GROUPS.contains(&word),
        "podman" => DOCKER_GROUPS.contains(&word) || word == "pod",
        "gh" => matches!(
            word,
            "pr" | "issue"
                | "repo"
                | "release"
                | "run"
                | "workflow"
                | "secret"
                | "variable"
                | "gist"
                | "auth"
                | "cache"
                | "label"
                | "project"
                | "codespace"
                | "ssh-key"
                | "gpg-key"
                | "extension"
                | "ruleset"
        ),
        "git" => matches!(
            word,
            "stash"
                | "remote"
                | "submodule"
                | "worktree"
                | "notes"
                | "lfs"
                | "bisect"
                | "sparse-checkout"
        ),
        "kubectl" => matches!(word, "config" | "rollout" | "auth" | "certificate" | "set"),
        "helm" => matches!(word, "repo" | "plugin" | "registry"),
        "npm" => matches!(word, "cache" | "config" | "pkg"),
        "conda" => word == "env",
        "terraform" => matches!(word, "state" | "workspace"),
        "netsh" => matches!(word, "advfirewall" | "firewall" | "wlan" | "interface"),
        _ => false,
    }
}

fn is_cloud_cli(program: &str) -> bool {
    matches!(
        program,
        "aws" | "gcloud" | "az" | "gsutil" | "oci" | "ibmcloud" | "doctl" | "scw"
    )
}

/// Exact subcommand, else the longest matching `prefix*` key.
fn match_key<'a>(rows: &'a ProgramRows, word: &str) -> Option<&'a str> {
    if word != "*" {
        if let Some((key, _)) = rows.rows.get_key_value(word) {
            return Some(key);
        }
    }
    let mut best: Option<&str> = None;
    for key in &rows.prefixes {
        if word.starts_with(&key[..key.len() - 1])
            && best.is_none_or(|b| key.chars().count() > b.chars().count())
        {
            best = Some(key);
        }
    }
    best
}

/// `(row, matched key)` for a program and its arguments, or `None` when the
/// program is not in the vocabulary.
pub(crate) fn lookup<S: AsRef<str>>(program: &str, rest: &[S]) -> Option<(VocabRow, &'static str)> {
    let rows = TABLE.get(program).filter(|rows| !rows.rows.is_empty())?;
    let positional: Vec<String> = rest
        .iter()
        .map(AsRef::as_ref)
        .filter(|w| !w.starts_with('-'))
        .map(str::to_lowercase)
        .collect();
    let cloud = is_cloud_cli(program);
    let depth = if cloud { 4 } else { 2 };
    let mut hits: Vec<&'static str> = Vec::new();
    for (k, word) in positional.iter().take(depth).enumerate() {
        let matched = match_key(rows, word);
        if let Some(key) = matched {
            hits.push(key);
        }
        if cloud {
            if let Some(key) = matched {
                if !is_group(program, key) && rows.rows[key].verb != "NONE" && k > 0 {
                    break;
                }
            }
            continue;
        }
        if !is_group(program, word) {
            break;
        }
    }
    let mut best: Option<&'static str> = None;
    for key in hits {
        if best.is_none_or(|b| severity(rows.rows[key].verb) > severity(rows.rows[b].verb)) {
            best = Some(key);
        }
    }
    match best {
        Some(key) => Some((rows.rows[key], key)),
        None => rows
            .rows
            .get_key_value("*")
            .map(|(key, row)| (*row, key.as_str())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<&str> {
        text.split(' ').collect()
    }

    #[test]
    fn csv_parser_handles_quotes_and_doubled_quotes() {
        assert_eq!(
            parse_csv("a,b\n\"x,1\",\"say \"\"hi\"\"\"\r\n"),
            vec![vec!["a", "b"], vec!["x,1", "say \"hi\""]]
        );
    }

    #[test]
    fn every_row_loads() {
        assert!(TABLE.len() > 100);
        assert!(TABLE.contains_key("git"));
    }

    #[test]
    fn subcommand_group_and_cloud_lookup() {
        let (row, key) = lookup("git", &words("push origin")).unwrap();
        assert_eq!((row.verb, key), ("MUTATE", "push"));
        let (row, _) = lookup("docker", &words("image rm x")).unwrap();
        assert_eq!(row.verb, "DELETE");
        let (row, _) = lookup("aws", &words("iam delete-user --user-name x")).unwrap();
        assert_eq!(row.verb, "DELETE");
        assert!(lookup("definitely-not-a-program", &words("x")).is_none());
    }
}
