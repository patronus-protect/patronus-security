// SPDX-License-Identifier: MIT OR Apache-2.0
//! Facts of one command segment: verb, role, objects with their access,
//! settings, grants, container flags, network endpoints.

use crate::detectors::shell::kf1::{segment_markers, Pipeline, PERSIST_TARGET};
use crate::detectors::shell::markers::{
    flag_verb, program, segment_ops, target_class, values, verb_class, word_set, WordSet, CLASS_OF,
    FILE_HEADS,
};
use crate::detectors::shell::vocab;

use super::paths::{context_class, resolve};
use super::{network_of, LegacyClass, Object, Segment, Setting, ShellContext};

fn access_of_verb(verb: Option<&str>) -> Option<&'static str> {
    match verb {
        Some("READ") => Some("READ"),
        Some("MUTATE") => Some("WRITE"),
        Some("DELETE") => Some("DELETE"),
        Some("EXEC") => Some("EXECUTE"),
        _ => None,
    }
}

static WRITE_LAST: WordSet = word_set!(
    "cp",
    "mv",
    "install",
    "ln",
    "rsync",
    "scp",
    "copy",
    "xcopy",
    "robocopy",
    "copy-item",
    "move-item",
);

static WRITERS: WordSet = word_set!(
    "tee",
    "touch",
    "truncate",
    "set-content",
    "add-content",
    "out-file",
    "mkdir",
    "dd"
);

/// Words after `>` / `>>` (`WRITE` / `APPEND`), from the raw pipeline tokens.
pub(super) fn redirect_targets(pipes: &[Pipeline]) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for seg in pipes.iter().flatten().map(|seg| &seg.raw) {
        for (j, word) in seg.iter().enumerate() {
            if matches!(*word, ">" | ">>") && j + 1 < seg.len() {
                let access = if *word == ">>" { "APPEND" } else { "WRITE" };
                match out.iter_mut().find(|(path, _)| *path == seg[j + 1]) {
                    Some(entry) => entry.1 = access,
                    None => out.push((seg[j + 1].to_string(), access)),
                }
            }
        }
    }
    out
}

pub(super) fn sed_in_place(rest: &[String]) -> bool {
    rest.iter()
        .any(|x| x == "-i" || x.starts_with("-i") || x.starts_with("--in-place"))
}

/// Access of one argument: redirect target, copy/move destination, writer
/// argument, else from the verb.
fn access(
    word: &str,
    k: usize,
    head: &str,
    rest: &[String],
    verb: Option<&str>,
    redirects: &[(String, &'static str)],
) -> Option<&'static str> {
    if let Some((_, access)) = redirects.iter().find(|(path, _)| path == word) {
        return Some(access);
    }
    let args: Vec<usize> = (0..rest.len())
        .filter(|&i| !rest[i].starts_with('-'))
        .collect();
    if WRITE_LAST.contains(head) && args.len() >= 2 {
        return Some(if Some(&k) == args.last() {
            "WRITE"
        } else {
            "READ"
        });
    }
    if head == "tee" {
        let append = rest.iter().any(|x| x == "-a" || x == "--append");
        return Some(if append { "APPEND" } else { "WRITE" });
    }
    if WRITERS.contains(head) || (head == "sed" && sed_in_place(rest)) {
        return Some("WRITE");
    }
    access_of_verb(verb)
}

/// Verb flags still count next to the vocabulary verb; the strongest wins.
fn with_flag_verbs(
    prog: &str,
    rest: &[String],
    verb: Option<&'static str>,
) -> Option<&'static str> {
    let mut candidates: Vec<&'static str> = vec![verb.unwrap_or("NONE")];
    for word in rest {
        if let Some(flag) = flag_verb(word) {
            candidates.extend(
                CLASS_OF
                    .iter()
                    .filter(|(_, words)| words.contains(flag.as_str()))
                    .map(|(name, _)| *name),
            );
        }
    }
    if prog == "find"
        && rest
            .iter()
            .any(|w| matches!(w.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
    {
        candidates.push("EXEC");
    }
    let mut best = candidates[0];
    for candidate in &candidates[1..] {
        if vocab::severity(candidate) > vocab::severity(best) {
            best = candidate;
        }
    }
    (best != "NONE").then_some(best)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_segment(
    id: usize,
    seg: &[String],
    head: &str,
    rest: &[String],
    redirected: bool,
    relations: &[&str],
    ctx: &ShellContext,
    redirects: &[(String, &'static str)],
) -> Segment {
    let prog = program(head);
    let (verb, role, sensitive, key) = match vocab::lookup(&prog, rest) {
        Some((row, key)) => {
            let mut verb = (row.verb != "NONE").then_some(row.verb);
            if prog == "sed" && sed_in_place(rest) {
                verb = Some("MUTATE");
            }
            (
                with_flag_verbs(&prog, rest, verb),
                Some(row.role),
                row.sensitive,
                Some(key),
            )
        }
        None => (verb_class(head, rest), None, false, None),
    };
    let file_head = FILE_HEADS.contains(head);
    let mut objects = Vec::new();
    for (k, word) in rest.iter().enumerate() {
        if let Some(target) = target_class(word, file_head) {
            let abs = resolve(word, ctx);
            let class = context_class(abs.as_deref(), target, ctx);
            objects.push(Object {
                value: Some(word.clone()),
                class,
                access: access(word, k, head, rest, verb, redirects),
                abs,
                legacy_class: if class != target {
                    LegacyClass::Class(target)
                } else {
                    LegacyClass::Absent
                },
            });
        }
        if PERSIST_TARGET.is_match(word) {
            objects.push(Object {
                value: Some(word.clone()),
                class: "PERSIST",
                access: access(word, k, head, rest, verb, redirects),
                abs: resolve(word, ctx),
                legacy_class: LegacyClass::Null,
            });
        }
    }
    let marks = segment_markers(head, rest);
    let domain = if marks.contains("SECCTL") {
        "SECCTL"
    } else {
        "OTHER"
    };
    let settings = [("TURNS_ON", "ON"), ("TURNS_OFF", "OFF")]
        .into_iter()
        .filter(|(mark, _)| marks.contains(mark))
        .map(|(_, polarity)| Setting { domain, polarity })
        .collect();
    let grants = [("GRANT_ALL", "ALL"), ("GRANT_SCOPED", "SCOPED")]
        .into_iter()
        .filter(|(mark, _)| marks.contains(mark))
        .map(|(_, grant)| grant)
        .collect();
    Segment {
        id,
        head: head.to_string(),
        ops: segment_ops(seg, head, rest, redirected, relations, verb),
        program: prog,
        verb,
        role,
        sensitive,
        vocab: key,
        objects,
        kv: values(rest),
        settings,
        secctl: marks.contains("SECCTL"),
        grants,
        host_root_mount: marks.contains("HOST_ROOT_MOUNT"),
        privileged: marks.contains("PRIVILEGED"),
        fixture: marks.contains("TGT=FIXTURE"),
        redirected,
        network: network_of(head, rest),
        argv: rest.iter().map(|w| w.to_lowercase()).collect(),
        sql: Vec::new(),
        nested: None,
        parent: None,
        rest_raw: rest.to_vec(),
    }
}
