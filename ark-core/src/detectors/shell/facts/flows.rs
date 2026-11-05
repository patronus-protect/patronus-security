// SPDX-License-Identifier: MIT OR Apache-2.0
//! Data flows across segments and commands: downloads into interpreters,
//! files filled with secrets or dumps, uploads, links to `prior_facts`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::kf1::{
    classify_source, clean, Pipeline, FORM_FILE, SHELLS, UPLOADERS, UPLOAD_FLAG,
};
use crate::detectors::shell::markers::{
    base, is_assignment, program, word_set, WordSet, DOWNLOADERS, PREFIXES,
};
use crate::detectors::shell::pyre::{py_regex, Anchor};

use super::paths::norm_linked;
use super::{Facts, Flow, ShellContext, Write};

static INTERPRETERS: WordSet = word_set!(
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "pwsh",
    "powershell",
    "source",
    ".",
);

static SHELL_C_FLAG: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"-[a-z]*c[a-z]*", false, Anchor::Full));
static SHORT_OUTPUT: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^-[A-Za-z]+[oO]$", false, Anchor::Match));
static LONG_OUTPUT: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^--output(-document)?=", false, Anchor::Match));
/// Does an interpreter at this pipeline position run its stdin as code?
fn stdin_is_code(head: &str, rest: &[&str]) -> bool {
    if matches!(head, "iex" | "invoke-expression") {
        return true;
    }
    let flags: Vec<String> = rest
        .iter()
        .filter(|w| w.starts_with('-'))
        .map(|w| w.to_lowercase())
        .collect();
    let has_positional = rest.iter().any(|w| !w.starts_with('-'));
    let has = |flag: &str| flags.iter().any(|f| f == flag);
    if matches!(head, "sh" | "bash" | "zsh" | "dash" | "ksh") {
        if has("-s") || rest.first() == Some(&"-") {
            return true;
        }
        return !(has("-c") || flags.iter().any(|f| SHELL_C_FLAG.is_match(f)) || has_positional);
    }
    if matches!(head, "pwsh" | "powershell") {
        return ((has("-command") || has("-c")) && rest.contains(&"-"))
            || !(has_positional || !flags.is_empty());
    }
    if rest.contains(&"-") {
        return true;
    }
    if flags.iter().any(|f| {
        matches!(
            f.as_str(),
            "-c" | "-m" | "-e" | "-E" | "-p" | "-n" | "--eval" | "--print" | "-r"
        )
    }) || has_positional
    {
        return false;
    }
    true
}

/// Every downloader -> interpreter pipeline hands the data to a script or
/// `-c` code, not to stdin as code (`curl … | python3 -m json.tool`).
pub(super) fn remote_interp_is_filter(pipes: &[Pipeline]) -> bool {
    let mut seen = false;
    for pipe in pipes {
        let first_download = pipe.iter().position(|s| {
            s.head
                .as_deref()
                .is_some_and(|h| !h.is_empty() && DOWNLOADERS.contains(program(h).as_str()))
        });
        for (k, seg) in pipe.iter().enumerate() {
            let (Some(head), rest) = (seg.head.as_deref(), seg.rest()) else {
                continue;
            };
            if SHELLS.contains(head) && first_download.is_some_and(|d| d < k) {
                seen = true;
                if stdin_is_code(head, rest) {
                    return false;
                }
            }
        }
    }
    seen
}

/// Files that receive secret material, and files produced by downloads.
pub(super) fn writes_and_downloads(pipes: &[Pipeline]) -> (Vec<Write<'static>>, Vec<String>) {
    let mut writes = Vec::new();
    let mut downloads = Vec::new();
    for pipe in pipes {
        for (k, segment) in pipe.iter().enumerate() {
            let (Some(head), rest) = (segment.head.as_deref(), segment.rest()) else {
                continue;
            };
            let seg = &segment.raw;
            let piped_secret = k > 0 && classify_source(pipe[k - 1].clean()) == "SECRET";
            for (j, word) in seg.iter().enumerate() {
                if matches!(*word, ">" | ">>")
                    && j + 1 < seg.len()
                    && (piped_secret || classify_source(&clean(&seg[..j])) == "SECRET")
                {
                    writes.push(Write {
                        path: seg[j + 1].to_string(),
                        data: "SECRET",
                    });
                }
            }
            let args: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|a| !a.starts_with('-'))
                .collect();
            if head == "tee" && piped_secret {
                writes.extend(args.iter().map(|a| Write {
                    path: a.to_string(),
                    data: "SECRET",
                }));
            } else if matches!(head, "cp" | "install")
                && args.len() >= 2
                && classify_source(&["cat", args[0]]) == "SECRET"
            {
                writes.push(Write {
                    path: args[args.len() - 1].to_string(),
                    data: "SECRET",
                });
            }
            if DOWNLOADERS.contains(program(head).as_str()) {
                for (j, word) in rest.iter().enumerate() {
                    let lower = word.to_lowercase();
                    let short = matches!(
                        lower.as_str(),
                        "-o" | "--output" | "--output-document" | "-outfile"
                    ) || SHORT_OUTPUT.is_match(word);
                    if short && j + 1 < rest.len() && rest[j + 1] != "-" {
                        downloads.push(rest[j + 1].to_string());
                    } else if LONG_OUTPUT.is_match(word) && !word.ends_with("=-") {
                        downloads.push(word.split_once('=').map_or("", |(_, v)| v).to_string());
                    }
                }
            }
        }
    }
    (writes, downloads)
}

/// Local paths sent by an uploader (`@file`, `-T file`, `-InFile file`, scp/rsync local args).
fn upload_sources(pipes: &[Pipeline]) -> Vec<String> {
    let mut out = Vec::new();
    for seg in pipes.iter().flatten() {
        let (Some(head), rest) = (seg.head.as_deref(), seg.rest()) else {
            continue;
        };
        if !UPLOADERS.contains(head) {
            continue;
        }
        for (k, &word) in rest.iter().enumerate() {
            let key_flag = word
                .split_once('=')
                .is_some_and(|(key, _)| UPLOAD_FLAG.is_match(key));
            if !(UPLOAD_FLAG.is_match(word) || key_flag) {
                continue;
            }
            let mut value = if key_flag {
                word.split_once('=').map_or("", |(_, v)| v).to_string()
            } else {
                rest.get(k + 1).copied().unwrap_or("").to_string()
            };
            if let Some(captures) = FORM_FILE.captures(&value) {
                value = format!("@{}", &captures[1][1..]);
            }
            if value.starts_with('@') && value != "@-" {
                out.push(value[1..].to_string());
            } else if matches!(word, "-T" | "--upload-file") || word.to_lowercase() == "-infile" {
                out.push(value);
            }
        }
        if matches!(head, "scp" | "rsync") {
            out.extend(
                rest.iter()
                    .filter(|w| !w.starts_with('-') && !w.contains(':'))
                    .map(|w| w.to_string()),
            );
        }
    }
    out
}

/// Paths run as programs (`./x.sh`, `/tmp/x`) or handed to an interpreter.
fn executed_paths(segments: &[Vec<String>]) -> Vec<String> {
    let mut out = Vec::new();
    for seg in segments {
        let words: Vec<&String> = seg
            .iter()
            .filter(|w| !is_assignment(w) && !PREFIXES.contains(base(w).as_str()))
            .collect();
        let Some(first) = words.first() else {
            continue;
        };
        if first.contains('/') || first.starts_with('.') {
            out.push(first.to_string());
        }
        if INTERPRETERS.contains(base(first).as_str()) {
            out.extend(
                words[1..]
                    .iter()
                    .filter(|w| !w.starts_with('-'))
                    .take(1)
                    .map(|w| w.to_string()),
            );
        }
    }
    out
}

/// Links to earlier commands: uploads of secret-filled paths, runs of downloads.
pub(super) fn link_prior(
    pipes: &[Pipeline],
    segments: &[Vec<String>],
    prior_facts: &[Facts],
    ctx: &ShellContext,
) -> Vec<Flow<'static>> {
    let secret: BTreeSet<String> = prior_facts
        .iter()
        .flat_map(|pf| &pf.writes)
        .filter(|w| w.data == "SECRET")
        .map(|w| norm_linked(&w.path, ctx))
        .collect();
    let downloaded: BTreeSet<String> = prior_facts
        .iter()
        .flat_map(|pf| &pf.downloads)
        .map(|p| norm_linked(p, ctx))
        .collect();
    let mut flows = Vec::new();
    if !secret.is_empty()
        && upload_sources(pipes)
            .iter()
            .any(|p| secret.contains(&norm_linked(p, ctx)))
    {
        flows.push(Flow::new("SECRET", "NET", "PRIOR_PATH"));
    }
    if !downloaded.is_empty()
        && executed_paths(segments)
            .iter()
            .any(|p| downloaded.contains(&norm_linked(p, ctx)))
    {
        flows.push(Flow::new("REMOTE", "EXEC", "PRIOR_PATH"));
    }
    flows
}

/// Database dumps piped into a network uploader, or written to a file
/// (recorded in `writes`).
pub(super) fn db_dump_flows(
    pipes: &[Pipeline],
    writes: &mut Vec<Write<'static>>,
) -> Vec<Flow<'static>> {
    const DUMPERS: [&str; 7] = [
        "pg_dump",
        "pg_dumpall",
        "mysqldump",
        "mariadb-dump",
        "mongodump",
        "mongoexport",
        "redis-cli",
    ];
    let mut flows = Vec::new();
    for pipe in pipes {
        for (k, segment) in pipe.iter().enumerate() {
            let (Some(head), rest) = (segment.head.as_deref(), segment.rest()) else {
                continue;
            };
            if !DUMPERS.contains(&head) || (head == "redis-cli" && !rest.contains(&"--rdb")) {
                continue;
            }
            if pipe[k + 1..].iter().any(|s| {
                s.head
                    .as_deref()
                    .is_some_and(|h| !h.is_empty() && UPLOADERS.contains(h))
            }) {
                flows.push(Flow::new("DB_DUMP", "NET", "PIPE"));
            }
            let seg = &segment.raw;
            for (j, word) in seg.iter().enumerate() {
                if matches!(*word, ">" | ">>") && j + 1 < seg.len() {
                    writes.push(Write {
                        path: seg[j + 1].to_string(),
                        data: "DB_DUMP",
                    });
                }
            }
            for (j, word) in rest.iter().enumerate() {
                if matches!(*word, "-f" | "--file" | "-o" | "--out" | "--result-file")
                    && j + 1 < rest.len()
                {
                    writes.push(Write {
                        path: rest[j + 1].to_string(),
                        data: "DB_DUMP",
                    });
                }
            }
        }
    }
    flows
}

/// Upload of a path that this same command earlier filled with secret or dump data.
pub(super) fn same_command_links(
    pipes: &[Pipeline],
    writes: &[Write<'static>],
    ctx: &ShellContext,
) -> Vec<Flow<'static>> {
    let mut by_path: Vec<(String, &'static str)> = Vec::new();
    for write in writes {
        let path = norm_linked(&write.path, ctx);
        match by_path.iter_mut().find(|(p, _)| *p == path) {
            Some(entry) => entry.1 = write.data,
            None => by_path.push((path, write.data)),
        }
    }
    upload_sources(pipes)
        .iter()
        .filter_map(|p| {
            let path = norm_linked(p, ctx);
            by_path
                .iter()
                .find(|(q, _)| *q == path)
                .map(|(_, data)| Flow {
                    data,
                    sink: "NET",
                    via: "SAME_PATH",
                })
        })
        .collect()
}
