// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lexical path resolution against the harness context and the repo-aware
//! object class.

use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::kf1::FIXTURE;
use crate::detectors::shell::pyre::{py_regex, Anchor};

use super::ShellContext;

static HOME_VAR: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^\$(HOME|\{HOME\})(/|$)", false, Anchor::Match));
static DRIVE: LazyLock<Regex> = LazyLock::new(|| py_regex(r"^[A-Za-z]:\\", false, Anchor::Match));

/// Python `posixpath.normpath`.
fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part != ".." || (initial == 0 && parts.is_empty()) || parts.last() == Some(&"..") {
            parts.push(part);
        } else if !parts.is_empty() {
            parts.pop();
        }
    }
    let joined = format!("{}{}", "/".repeat(initial), parts.join("/"));
    if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Absolute path for a path-like argument, lexically against the context.
pub(super) fn resolve(path: &str, ctx: &ShellContext) -> Option<String> {
    if path.is_empty() || path.starts_with('-') || path.contains("://") {
        return None;
    }
    let mut p = path.to_string();
    if let Some(home) = &ctx.home {
        if p == "~" || p.starts_with("~/") {
            p = format!("{home}{}", &p[1..]);
        } else if HOME_VAR.is_match(&p) {
            let tail = p
                .strip_prefix("$HOME")
                .or_else(|| p.strip_prefix("${HOME}"))
                .unwrap_or(&p);
            p = format!("{home}{tail}");
        }
    }
    if !p.starts_with('/') && !DRIVE.is_match(&p) && !p.contains('$') {
        if let Some(cwd) = &ctx.cwd {
            p = if cwd.ends_with('/') {
                format!("{cwd}{p}")
            } else {
                format!("{cwd}/{p}")
            };
        }
    }
    p.starts_with('/').then(|| normpath(&p))
}

/// Trusted repo context refines the class: repo fixtures are `FIXTURE`, other
/// repo files `PROJECT` (secret, persistence and git exec paths keep theirs).
pub(super) fn context_class(
    abs: Option<&str>,
    class: &'static str,
    ctx: &ShellContext,
) -> &'static str {
    let repo = ctx.repo_root.as_deref().unwrap_or("").trim_end_matches('/');
    let Some(abs) = abs.filter(|a| !a.is_empty()) else {
        return class;
    };
    if repo.is_empty() || !(abs == repo || abs.starts_with(&format!("{repo}/"))) {
        return class;
    }
    if FIXTURE.is_match(&abs[repo.len()..]) {
        return "FIXTURE";
    }
    if matches!(class, "SECRET" | "PERSIST" | "GIT_EXEC_CONFIG") {
        class
    } else {
        "PROJECT"
    }
}

pub(super) fn norm_linked(path: &str, ctx: &ShellContext) -> String {
    resolve(path, ctx).unwrap_or_else(|| normpath(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_matches_posixpath() {
        for (path, expected) in [
            ("", "."),
            ("/a/./b/../c", "/a/c"),
            ("//a//b/", "//a/b"),
            ("///a", "/a"),
            ("../x/..", ".."),
            ("/..", "/"),
        ] {
            assert_eq!(normpath(path), expected, "{path}");
        }
    }

    #[test]
    fn resolve_uses_home_and_cwd() {
        let ctx = ShellContext {
            cwd: Some("/work/repo/src".into()),
            home: Some("/home/dev".into()),
            ..ShellContext::default()
        };
        assert_eq!(
            resolve("~/.ssh/id_rsa", &ctx).as_deref(),
            Some("/home/dev/.ssh/id_rsa")
        );
        assert_eq!(resolve("${HOME}/x", &ctx).as_deref(), Some("/home/dev/x"));
        assert_eq!(
            resolve("../tests/fixtures/a", &ctx).as_deref(),
            Some("/work/repo/tests/fixtures/a")
        );
        assert_eq!(resolve("$X/a", &ctx), None);
        assert_eq!(resolve("https://x", &ctx), None);
    }
}
