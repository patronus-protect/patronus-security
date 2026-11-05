// SPDX-License-Identifier: MIT OR Apache-2.0
//! The live shell-token part of the K26 `kf1` analyzer: a port of
//! `shellrisk/tokens.py` from the `cat-shell-risk-commander` release.
//!
//! A deterministic shell tokenizer splits on whitespace and shell operators,
//! normalizes volatile pieces (quoted strings, URLs, IPs, numbers) to stable
//! placeholders, and emits unigrams, adjacent bigrams and three structural
//! markers (command head, pipe target, redirect target). Relation markers from
//! a small, depth-limited parse of the same tokens say whether downloaded
//! content flows into an interpreter, is executed as a file, or only reaches a
//! file or a pure filter (see [`relations`]). Heredoc bodies that are code
//! for another interpreter are masked first.
//!
//! `features` returns the same multiset of feature strings as the Python
//! reference. The text is never parsed, expanded or run.

use std::borrow::Cow;

mod heredoc;
mod relations;

pub(crate) use heredoc::{
    heredoc_delimiter, heredoc_op_search, heredoc_segment_head, heredoc_segments, mask_heredocs,
    mask_heredocs_with, HEREDOC_MASK,
};
pub(crate) use relations::relations;

/// Operators kept verbatim by [`normalise`] (the Python `OPERATORS` set).
fn is_operator(token: &str) -> bool {
    matches!(
        token,
        "|" | "||" | "&&" | ";" | "&" | "(" | ")" | "$(" | "<" | ">" | ">>"
    )
}

/// Python `str.isspace`/`re` `\s`: Unicode whitespace plus the ASCII
/// information separators U+001C..U+001F, but not U+FEFF.
fn is_shell_whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// A character that ends a bare word run: `[\s|;&<>()'"]`.
fn is_word_boundary(c: char) -> bool {
    is_shell_whitespace(c) || matches!(c, '|' | ';' | '&' | '<' | '>' | '(' | ')' | '\'' | '"')
}

/// Full match of the Python `\d*>&\d*` file-descriptor redirect pattern, e.g.
/// `>&`, `2>&1`, `0>&1`.
pub(crate) fn is_fd_redirect(token: &str) -> bool {
    let bytes = token.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if bytes.get(index) != Some(&b'>') || bytes.get(index + 1) != Some(&b'&') {
        return false;
    }
    index += 2;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    index == bytes.len()
}

/// End byte of a `\d*>&\d*` token starting at `start`, or `None`.
fn scan_fd_redirect(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if bytes.get(index) != Some(&b'>') || bytes.get(index + 1) != Some(&b'&') {
        return None;
    }
    index += 2;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    Some(index)
}

/// End byte of a `"(?:\\.|[^"\\])*"` double-quoted string starting at `start`,
/// mirroring Python's `.` not matching a newline after a backslash.
fn scan_double_quote(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some(index + 1),
            b'\\' => {
                // `\\.`: a backslash must be followed by a non-newline char.
                match bytes.get(index + 1) {
                    None | Some(b'\n') => return None,
                    Some(_) => index += 1 + next_char_len(text, index + 1),
                }
            }
            // `[^"\\]` matches any other character, newline included.
            _ => index += next_char_len(text, index),
        }
    }
    None
}

/// Byte length of the UTF-8 character starting at `index`.
fn next_char_len(text: &str, index: usize) -> usize {
    text[index..].chars().next().map_or(1, char::len_utf8)
}

/// `TOKEN.findall(text)`: the line tokens without the newline tokens.
#[cfg(test)]
fn tokenize(text: &str) -> Vec<&str> {
    let mut tokens = line_tokens(text);
    tokens.retain(|token| *token != "\n");
    tokens
}

/// `re.findall(r'\n|' + TOKEN.pattern, text)`: the tokens plus each newline as
/// its own token. Alternatives are tried in the Python order; an unmatched
/// character (stray quote, whitespace) is skipped.
pub(crate) fn line_tokens(text: &str) -> Vec<&str> {
    tokenize_with(text, TokenMode::Lines)
}

/// Which leading alternatives precede the Python `TOKEN` pattern.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenMode {
    /// `\n|TOKEN`: a newline is its own token (a command separator).
    Lines,
    /// `STRUCT_TOKEN`, used by [`relations`]: `<NAME>` placeholders stay one
    /// token and a newline is its own token.
    Structural,
}

fn tokenize_with(text: &str, mode: TokenMode) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let byte = bytes[pos];
        // `<[A-Za-z_][A-Za-z0-9_-]*>`
        if mode == TokenMode::Structural {
            if let Some(end) = scan_placeholder(bytes, pos) {
                tokens.push(&text[pos..end]);
                pos = end;
                continue;
            }
        }
        // `\n`
        if byte == b'\n' {
            tokens.push(&text[pos..pos + 1]);
            pos += 1;
            continue;
        }
        // Whitespace is never a token; skip the whole character.
        let first = text[pos..].chars().next().unwrap();
        if is_shell_whitespace(first) {
            pos += first.len_utf8();
            continue;
        }
        // `'[^']*'`
        if byte == b'\'' {
            if let Some(close) = text[pos + 1..].find('\'') {
                let end = pos + 1 + close + 1;
                tokens.push(&text[pos..end]);
                pos = end;
                continue;
            }
            pos += 1;
            continue;
        }
        // `"(?:\\.|[^"\\])*"`
        if byte == b'"' {
            if let Some(end) = scan_double_quote(text, pos) {
                tokens.push(&text[pos..end]);
                pos = end;
                continue;
            }
            pos += 1;
            continue;
        }
        // Two-character operators `$(`, `||`, `&&`, `>>`, in Python order.
        let two = bytes.get(pos..pos + 2);
        if matches!(two, Some(b"$(" | b"||" | b"&&" | b">>")) {
            tokens.push(&text[pos..pos + 2]);
            pos += 2;
            continue;
        }
        // `\d*>&\d*`
        if let Some(end) = scan_fd_redirect(bytes, pos) {
            tokens.push(&text[pos..end]);
            pos = end;
            continue;
        }
        // Single-character operators `[|;&<>()]`.
        if matches!(byte, b'|' | b';' | b'&' | b'<' | b'>' | b'(' | b')') {
            tokens.push(&text[pos..pos + 1]);
            pos += 1;
            continue;
        }
        // Bare word `[^\s|;&<>()'"]+`.
        let mut end = pos;
        while end < bytes.len() {
            let ch = text[end..].chars().next().unwrap();
            if is_word_boundary(ch) {
                break;
            }
            end += ch.len_utf8();
        }
        tokens.push(&text[pos..end]);
        pos = end;
    }
    tokens
}

/// End byte of a `<[A-Za-z_][A-Za-z0-9_-]*>` placeholder starting at `start`.
fn scan_placeholder(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'<') {
        return None;
    }
    let first = *bytes.get(start + 1)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut index = start + 2;
    while index < bytes.len()
        && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-'))
    {
        index += 1;
    }
    (bytes.get(index) == Some(&b'>')).then_some(index + 1)
}

/// `^[a-z][a-z0-9+.-]*://` (case-insensitive prefix).
fn is_url(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.first().is_none_or(|b| !b.is_ascii_alphabetic()) {
        return false;
    }
    let mut index = 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'+' | b'.' | b'-'))
    {
        index += 1;
    }
    bytes[index..].starts_with(b"://")
}

/// `^\d{1,3}(\.\d{1,3}){3}(:\d+)?$`.
fn is_ipv4(token: &str) -> bool {
    let bytes = token.as_bytes();
    let mut index = 0;
    let octet = |bytes: &[u8], index: &mut usize| {
        let start = *index;
        while *index < bytes.len() && *index - start < 3 && bytes[*index].is_ascii_digit() {
            *index += 1;
        }
        *index > start
    };
    if !octet(bytes, &mut index) {
        return false;
    }
    for _ in 0..3 {
        if bytes.get(index) != Some(&b'.') {
            return false;
        }
        index += 1;
        if !octet(bytes, &mut index) {
            return false;
        }
    }
    if bytes.get(index) == Some(&b':') {
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

/// `^[a-z0-9.-]+\.[a-z]{2,}:\d+$` (case-insensitive).
fn is_hostport(token: &str) -> bool {
    let Some(colon) = token.rfind(':') else {
        return false;
    };
    let (left, port) = (&token[..colon], &token[colon + 1..]);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // The TLD is letters only, so the host/TLD split is the last dot in `left`.
    let Some(dot) = left.rfind('.') else {
        return false;
    };
    let (host, tld) = (&left[..dot], &left[dot + 1..]);
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return false;
    }
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

/// `^-?\d+$`.
fn is_number(token: &str) -> bool {
    let digits = token.strip_prefix('-').unwrap_or(token);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Normalize one raw token, matching `shell_tokens.normalise`.
fn normalise(token: &str) -> Cow<'_, str> {
    if is_operator(token) || is_fd_redirect(token) {
        return Cow::Borrowed(token);
    }
    let first = token.as_bytes()[0];
    if (first == b'\'' || first == b'"') && token.chars().count() > 1 {
        return Cow::Borrowed("<STR>");
    }
    if is_url(token) {
        return Cow::Borrowed("<URL>");
    }
    if is_ipv4(token) {
        return Cow::Borrowed("<IP>");
    }
    if is_hostport(token) {
        return Cow::Borrowed("<HOSTPORT>");
    }
    if is_number(token) {
        return Cow::Borrowed(if token.starts_with('-') {
            "-<NUM>"
        } else {
            "<NUM>"
        });
    }
    if token.is_ascii() && !token.bytes().any(|b| b.is_ascii_uppercase()) {
        return Cow::Borrowed(token);
    }
    Cow::Owned(token.to_lowercase())
}

/// Command name without its directory, e.g. `/usr/bin/python3` -> `python3`.
fn head(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// The deterministic shell-token features from the line tokens of a masked text,
/// as a multiset in the shape of the Python `tokens.features` (unigrams,
/// adjacent bigrams, the `CMD=`, `PIPE->` and `REDIR->` structural markers,
/// then the `DL->` relation markers of the masked text). The live token part
/// of `kf1`.
pub(crate) fn visit_features(
    line_tokens: &[&str],
    relations: &[&'static str],
    emit: &mut dyn FnMut(&str),
) {
    // `TOKEN.findall`: the line tokens without the newline tokens.
    let norm: Vec<Cow<'_, str>> = line_tokens
        .iter()
        .filter(|token| **token != "\n")
        .map(|token| normalise(token))
        .collect();
    norm.iter().for_each(|value| emit(value));
    let mut buffer = String::new();
    let mut joined = |emit: &mut dyn FnMut(&str), parts: &[&str]| {
        buffer.clear();
        parts.iter().for_each(|part| buffer.push_str(part));
        emit(&buffer);
    };
    for pair in norm.windows(2) {
        joined(emit, &[&pair[0], " ", &pair[1]]);
    }
    let mut at_start = true;
    let mut after: Option<&str> = None;
    for value in &norm {
        let value: &str = value;
        if is_operator(value) || is_fd_redirect(value) {
            at_start = matches!(value, "|" | "||" | "&&" | ";" | "&" | "(" | "$(");
            after = match value {
                "|" => Some("|"),
                ">" => Some(">"),
                ">>" => Some(">>"),
                "<" => Some("<"),
                _ => None,
            };
            continue;
        }
        match after {
            Some("|") => joined(emit, &["PIPE->", head(value)]),
            Some(">") | Some(">>") => emit(if value == "/dev/null" {
                "REDIR->/dev/null"
            } else if value.starts_with("/dev/") {
                "REDIR-><DEV>"
            } else {
                "REDIR-><FILE>"
            }),
            _ => {}
        }
        if at_start {
            joined(emit, &["CMD=", head(value)]);
        }
        at_start = false;
        after = None;
    }
    relations.iter().for_each(|relation| emit(relation));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tokens.features`: mask, tokenize, featurize.
    fn features(text: &str) -> Vec<String> {
        let masked = mask_heredocs(text);
        let mut out = Vec::new();
        visit_features(&line_tokens(&masked), &relations(&masked), &mut |f| {
            out.push(f.to_string())
        });
        out
    }

    fn feats(text: &str) -> Vec<String> {
        features(text)
    }

    #[test]
    fn matches_python_reference_cases() {
        // Golden outputs captured from `tokens.features`.
        assert_eq!(feats("ls -la"), ["ls", "-la", "ls -la", "CMD=ls"]);
        assert_eq!(
            feats("curl -fsSL https://example.com/i.sh | jq ."),
            [
                "curl",
                "-fssl",
                "<URL>",
                "|",
                "jq",
                ".",
                "curl -fssl",
                "-fssl <URL>",
                "<URL> |",
                "| jq",
                "jq .",
                "CMD=curl",
                "PIPE->jq",
                "CMD=jq",
                "DL->PIPE->FILTER"
            ]
        );
        assert_eq!(
            feats("echo 'hi there' > out.txt"),
            [
                "echo",
                "<STR>",
                ">",
                "out.txt",
                "echo <STR>",
                "<STR> >",
                "> out.txt",
                "CMD=echo",
                "REDIR-><FILE>"
            ]
        );
        assert_eq!(
            feats("cat a.txt 2>&1 >> log"),
            [
                "cat",
                "a.txt",
                "2>&1",
                ">>",
                "log",
                "cat a.txt",
                "a.txt 2>&1",
                "2>&1 >>",
                ">> log",
                "CMD=cat",
                "REDIR-><FILE>"
            ]
        );
        assert_eq!(
            feats("foo | bar || baz && qux ; end"),
            [
                "foo",
                "|",
                "bar",
                "||",
                "baz",
                "&&",
                "qux",
                ";",
                "end",
                "foo |",
                "| bar",
                "bar ||",
                "|| baz",
                "baz &&",
                "&& qux",
                "qux ;",
                "; end",
                "CMD=foo",
                "PIPE->bar",
                "CMD=bar",
                "CMD=baz",
                "CMD=qux",
                "CMD=end"
            ]
        );
        assert_eq!(
            feats("/usr/bin/python3 -c 'x'"),
            [
                "/usr/bin/python3",
                "-c",
                "<STR>",
                "/usr/bin/python3 -c",
                "-c <STR>",
                "CMD=python3"
            ]
        );
        // File-descriptor redirects are tokens but emit no CMD/PIPE/REDIR marker.
        assert_eq!(feats("x>&2"), ["x", ">&2", "x >&2", "CMD=x"]);
        assert_eq!(feats("2>&1"), ["2>&1"]);
        assert!(feats("").is_empty());
    }

    #[test]
    fn normalises_volatile_tokens() {
        assert_eq!(normalise("https://e.co/x"), "<URL>");
        assert_eq!(normalise("1.2.3.4"), "<IP>");
        assert_eq!(normalise("1.2.3.4:4444"), "<IP>");
        assert_eq!(normalise("evil.com:8080"), "<HOSTPORT>");
        assert_eq!(normalise("99"), "<NUM>");
        assert_eq!(normalise("-42"), "-<NUM>");
        assert_eq!(normalise("Foo.TXT"), "foo.txt");
        assert_eq!(normalise("2>&1"), "2>&1");
        assert_eq!(normalise(">>"), ">>");
        assert_eq!(normalise("'a b'"), "<STR>");
    }

    #[test]
    fn tokenizes_fd_redirects_and_operators() {
        assert_eq!(tokenize("12>&34 next"), ["12>&34", "next"]);
        assert_eq!(tokenize("a>b"), ["a", ">", "b"]);
        assert_eq!(tokenize(">&2"), [">&2"]);
        assert_eq!(tokenize("$(whoami)"), ["$(", "whoami", ")"]);
        // A stray unterminated quote is skipped, like Python `findall`.
        assert_eq!(
            tokenize("'unterminated and more"),
            ["unterminated", "and", "more"]
        );
    }

    #[test]
    fn escaped_multibyte_character_inside_double_quotes_is_one_step() {
        assert_eq!(tokenize("echo \"\\é\" x"), ["echo", "\"\\é\"", "x"]);
        assert_eq!(tokenize("echo \"\\€"), ["echo", "\\€"]);
    }

    #[test]
    fn splits_on_ascii_information_separators() {
        // U+001C..U+001F count as whitespace, like Python `re` `\s`.
        assert_eq!(tokenize("rm\u{1c}-rf\u{1f}x"), ["rm", "-rf", "x"]);
        assert_eq!(tokenize("a\u{a0}b\u{2003}c"), ["a", "b", "c"]);
    }

    // Relation cases mirror `test_shell_tokens.py` (issue #159).

    #[test]
    fn relations_are_appended_once_after_the_token_features() {
        let feats =
            features("curl -s https://x.example/a | bash; curl -s https://x.example/b | sh");
        assert_eq!(feats.iter().filter(|f| *f == "DL->PIPE->INTERP").count(), 1);
        assert_eq!(feats.last().map(String::as_str), Some("DL->PIPE->INTERP"));
    }

    // Heredoc masking mirrors `test_shell_tokens.py`.

    #[test]
    fn heredoc_bodies_of_non_shell_interpreters_are_masked() {
        let py = "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['ssh','-o','BatchMode=yes','h','uptime'])\nPY\necho done";
        assert_eq!(
            mask_heredocs(py),
            "python3 - <<'PY'\nheredoc_body\nPY\necho done"
        );
        let feats = features(py);
        assert!(feats.iter().any(|f| f == "heredoc_body"));
        assert!(!feats.iter().any(|f| f == "CMD=["));
        assert_eq!(
            mask_heredocs(".venv/bin/python - <<\"EOF\"\nx = [1, 2]\nEOF"),
            ".venv/bin/python - <<\"EOF\"\nheredoc_body\nEOF"
        );
        assert_eq!(
            mask_heredocs("node <<-JS\n\tconsole.log(1)\n\tJS"),
            "node <<-JS\nheredoc_body\n\tJS"
        );
        // Unterminated: masked to the end.
        assert_eq!(
            mask_heredocs("perl <<EOF\nprint 1;"),
            "perl <<EOF\nheredoc_body"
        );
    }
}
