// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command segments with the parser fixes of `extract.py`: heredoc bodies
//! that are data, shell keywords, PowerShell `$x=` assignments, cmd comments
//! and code lines are not command heads.

use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::markers::{is_separator, unquote, word_set, WordSet};
use crate::detectors::shell::pyre::{is_py_space, py_regex, Anchor};
use crate::detectors::shell::tokens::{
    heredoc_delimiter, heredoc_op_search, heredoc_segment_head, heredoc_segments, is_fd_redirect,
    line_tokens, mask_heredocs_with, HEREDOC_MASK,
};

static SHELL_KEYWORDS: WordSet = word_set!(
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "function", "{", "}", "[[", "]]", "!", "select",
);

static CODE_HEADS: WordSet = word_set!(
    "def", "return", "import", "from", "class", "raise", "pass", "try", "except", "finally",
    "yield", "lambda", "with", "assert", "elif", "else", "self",
);

static DATA_HEREDOC_FILE: LazyLock<Regex> = LazyLock::new(|| {
    // `(?=[\s;&|()<>]|$)` after the file name is checked in `data_heredoc_file`.
    py_regex(
        r#"(?:>>?|\btee(?:\s+-a)?)\s*['"]?[^\s;&|()<>'"]+\.(?:txt|csv|tsv|log|md|rst|xml|html?|conf|in|out|dat|ndjson|jsonl)['"]?"#,
        true,
        Anchor::Search,
    )
});

static PS_ASSIGN_VALUE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"\$[\w:.]+=(.*)", false, Anchor::Full));
static PS_VARIABLE: LazyLock<Regex> = LazyLock::new(|| py_regex(r"\$[\w:.]+", false, Anchor::Full));

static WORD_CHAR: LazyLock<Regex> = LazyLock::new(|| py_regex(r"\w", false, Anchor::Search));

/// `DATA_HEREDOC_FILE.search(segment)` including its trailing lookahead.
fn data_heredoc_file(segment: &str) -> bool {
    let mut from = 0;
    while let Some(found) = DATA_HEREDOC_FILE.find_at(segment, from) {
        // Python backtracks the optional closing quote when the lookahead fails.
        let end = found.end();
        let boundary = |at: usize| {
            segment[at..].chars().next().is_none_or(|c| {
                is_py_space(c) || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>')
            })
        };
        if boundary(end) || (segment[..end].ends_with(['\'', '"']) && boundary(end - 1)) {
            return true;
        }
        from = found.start()
            + segment[found.start()..]
                .chars()
                .next()
                .map_or(1, char::len_utf8);
    }
    false
}

/// `_data_heredoc_delimiter`: a code heredoc, or a cat/tee heredoc into a plain
/// data file.
fn data_heredoc_delimiter(line: &str) -> Option<&str> {
    if !line.contains("<<") {
        return None;
    }
    if let Some(delimiter) = heredoc_delimiter(line) {
        return Some(delimiter);
    }
    for (s, e) in heredoc_segments(line) {
        let segment = &line[s..e];
        if let Some((start, delimiter)) = heredoc_op_search(segment) {
            if !segment[..start].ends_with('<')
                && matches!(heredoc_segment_head(segment).as_str(), "cat" | "tee")
                && data_heredoc_file(segment)
            {
                return Some(delimiter);
            }
        }
    }
    None
}

/// Command segments with the parser fixes: (words, redirected).
pub(super) fn segments_fixed(text: &str) -> Vec<(Vec<String>, bool)> {
    let masked = mask_heredocs_with(text, data_heredoc_delimiter);
    let mut lines: Vec<&str> = Vec::new();
    let mut delimiter: Option<String> = None;
    for line in masked.split('\n') {
        if delimiter
            .as_deref()
            .is_some_and(|d| line.trim_matches([' ', '\t', '\r']) == d)
        {
            delimiter = None;
            continue;
        }
        if line == HEREDOC_MASK {
            continue;
        }
        lines.push(line);
        delimiter = data_heredoc_delimiter(line).map(str::to_string);
    }
    let joined = lines.join("\n");
    let mut out = Vec::new();
    let (mut seg, mut redirect, mut comment) = (Vec::new(), false, false);
    for token in line_tokens(&joined) {
        if comment && token != "\n" {
            continue;
        }
        comment = false;
        if is_separator(token) || token.starts_with('#') {
            if !seg.is_empty() {
                out.push((std::mem::take(&mut seg), redirect));
            }
            redirect = false;
            comment = token.starts_with('#');
            continue;
        }
        if matches!(token, ">" | ">>") || is_fd_redirect(token) {
            redirect = redirect || matches!(token, ">" | ">>");
            continue;
        }
        if token == "<" {
            continue;
        }
        seg.push(unquote(token).to_string());
    }
    if !seg.is_empty() {
        out.push((seg, redirect));
    }
    out
}

/// Words of a segment after shell keywords and `$x=` / `$x =` assignments;
/// empty for code lines and cmd comments, which have no command head.
pub(super) fn strip_fixed(seg: &[String], dialect: &str) -> Vec<String> {
    let mut words: Vec<String> = seg.to_vec();
    while let Some(first) = words.first() {
        if SHELL_KEYWORDS.contains(first.to_lowercase().as_str())
            && !matches!(dialect, "POWERSHELL" | "CMD")
        {
            words.remove(0);
            continue;
        }
        if let Some(captures) = PS_ASSIGN_VALUE.captures(first) {
            let value = captures[1].to_string();
            words.remove(0);
            if !value.is_empty() {
                words.insert(0, value);
            }
            continue;
        }
        if PS_VARIABLE.is_match(first) && words.len() > 1 && words[1] == "=" {
            words.drain(..2);
            continue;
        }
        break;
    }
    let Some(first) = words.first() else {
        return Vec::new();
    };
    if !WORD_CHAR.is_match(first) {
        return Vec::new();
    }
    let lower = first.to_lowercase();
    let lower = lower.trim_end_matches(':');
    if lower == "rem" || first.starts_with("::") || CODE_HEADS.contains(lower) {
        return Vec::new();
    }
    words
}
