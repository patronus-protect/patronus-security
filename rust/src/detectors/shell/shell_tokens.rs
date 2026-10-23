// SPDX-License-Identifier: GPL-3.0-only
//! Rust port of the `shell_tokens.py` analyzer shipped with the
//! `cat-shell-risk-commander` A1 (`format_version: 2`) model.
//!
//! The model adds a second TF-IDF feature block whose analyzer is a
//! deterministic shell tokenizer: it splits on whitespace and shell operators,
//! normalizes volatile pieces (quoted strings, URLs, IPs, numbers) to stable
//! placeholders, and emits unigrams, adjacent bigrams and three structural
//! markers (command head, pipe target, redirect target). This lets the scorer
//! tell `curl | jq` from `curl | sh` without ever executing the text.
//!
//! This port is bit-exact with the Python reference: `features` here returns
//! the same multiset of feature strings as `shell_tokens.features` there, which
//! is all the downstream TF-IDF vectorizer consumes. The text is never parsed,
//! expanded or run.

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
fn is_fd_redirect(token: &str) -> bool {
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
                    Some(_) => index += 2,
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

/// Split `text` into tokens, matching `shell_tokens.tokens` (the Python
/// `TOKEN.findall`). Alternatives are tried in the Python order; an unmatched
/// character (stray quote, whitespace) is skipped.
fn tokenize(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let byte = bytes[pos];
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
fn normalise(token: &str) -> String {
    if is_operator(token) || is_fd_redirect(token) {
        return token.to_string();
    }
    let first = token.as_bytes()[0];
    if (first == b'\'' || first == b'"') && token.chars().count() > 1 {
        return "<STR>".to_string();
    }
    if is_url(token) {
        return "<URL>".to_string();
    }
    if is_ipv4(token) {
        return "<IP>".to_string();
    }
    if is_hostport(token) {
        return "<HOSTPORT>".to_string();
    }
    if is_number(token) {
        return if token.starts_with('-') {
            "-<NUM>"
        } else {
            "<NUM>"
        }
        .to_string();
    }
    token.to_lowercase()
}

/// Command name without its directory, e.g. `/usr/bin/python3` -> `python3`.
fn head(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// The deterministic shell-token features of `text`, as a multiset in the same
/// shape the Python `shell_tokens.features` produces (unigrams, adjacent
/// bigrams, then the `CMD=`, `PIPE->` and `REDIR->` structural markers).
pub fn features(text: &str) -> Vec<String> {
    let norm: Vec<String> = tokenize(text).into_iter().map(normalise).collect();

    // Unigrams first, then bigrams and markers, in the reference order.
    let mut extra = Vec::with_capacity(norm.len() * 2);
    for pair in norm.windows(2) {
        extra.push(format!("{} {}", pair[0], pair[1]));
    }

    let mut at_start = true;
    let mut after: Option<&str> = None;
    for value in &norm {
        let value = value.as_str();
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
            Some("|") => extra.push(format!("PIPE->{}", head(value))),
            Some(">") | Some(">>") => {
                let target = if value == "/dev/null" {
                    "/dev/null"
                } else if value.starts_with("/dev/") {
                    "<DEV>"
                } else {
                    "<FILE>"
                };
                extra.push(format!("REDIR->{target}"));
            }
            _ => {}
        }
        if at_start {
            extra.push(format!("CMD={}", head(value)));
        }
        at_start = false;
        after = None;
    }
    let mut out = norm;
    out.append(&mut extra);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feats(text: &str) -> Vec<String> {
        features(text)
    }

    #[test]
    fn matches_python_reference_cases() {
        // Golden outputs captured from `shell_tokens.features` in the A1 release.
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
                "CMD=jq"
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
    fn splits_on_ascii_information_separators() {
        // U+001C..U+001F count as whitespace, like Python `re` `\s`.
        assert_eq!(tokenize("rm\u{1c}-rf\u{1f}x"), ["rm", "-rf", "x"]);
        assert_eq!(tokenize("a\u{a0}b\u{2003}c"), ["a", "b", "c"]);
    }
}
