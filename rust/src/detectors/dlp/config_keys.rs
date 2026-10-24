// SPDX-License-Identifier: GPL-3.0-only
//! K05: config key→value extraction, part 1: env (`KEY=value`,
//! `export KEY=value`), INI/properties (`key = value`, `app.db.password=…`)
//! and HTTP header lines (`X-Api-Key: …` in a request or response head).
//!
//! The line grammar is the `key: value`/`key=value` field of the document
//! structure (PII K04, [`structure::key_value_line`]); this module adds the
//! quoting rules of the three formats. A value in quotes runs to its closing
//! quote; a bare value is the rest of the line without an inline comment
//! (`␣# …`, `␣; …`). A bare value with blanks, quotes or an interpolation
//! inside is no value of these formats (a shell would split it, code would
//! compute it: `f"t{n}s0"`, `pre${SUFFIX}`), and a bare env
//! value with `;` is left to the shell rules of `dlp_env_var_secret`. Which
//! keys bind which rule, and which values count, the rules decide
//! (`dlp::DlpPipeline::structured_values`, `rules::value_shape`).
//!
//! K05B, part 2: YAML, JSON and TOML. A key binds its value at any nesting
//! depth (indented YAML mappings and list entries, nested JSON objects, TOML
//! tables), and an array under the key binds each of its string items: JSON
//! and TOML arrays (also over several lines), YAML flow sequences
//! (`[a, "b"]`) and block sequences (`- item` lines below the key). A JSON
//! or TOML string runs to its closing quote past escapes (`\"`); a YAML
//! value is quoted (`'it''s'`, `"…"`) or plain up to an inline comment, and
//! a plain value is none when it starts with a YAML indicator (alias `*`,
//! anchor `&`, tag `!`, block scalar `|`/`>`, flow `{`), holds blanks,
//! quotes or an interpolation, ends with `,`/`;` or lists words
//! (`read,write`). An array whose items are not all strings (numbers,
//! objects, mappings) binds nothing. Items are marked
//! ([`ConfigValue::item`]): their key stands on another line or before
//! other items, so the rules check the item itself ([`is_item`]).
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::structure;

/// The config format of a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigFormat {
    /// `KEY=value`, `export KEY = value`: an identifier key and `=`, without
    /// blanks around it unless after `export`.
    Env,
    /// `key = value`, `app.db.password=value`: a dotted or kebab key and `=`.
    Properties,
    /// `Header-Name: value` in the head of an HTTP request or response.
    HttpHeader,
    /// `key: value` at any indent, `- key: value`, and the items of a flow
    /// or block sequence under `key:` (K05B).
    Yaml,
    /// `"key": "value"` and the string items of `"key": [ … ]` (K05B).
    Json,
    /// `"quoted-key" = "value"` and the string items of `key = [ … ]`
    /// (K05B); a bare key with a scalar is a properties line.
    Toml,
}

impl ConfigFormat {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Properties => "properties",
            Self::HttpHeader => "http_header",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Toml => "toml",
        }
    }
}

/// A value of a config line and the key that binds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConfigValue {
    /// Byte range of the key, without `export `.
    pub key: Range<usize>,
    /// Byte range of the value, without quotes and inline comment.
    pub value: Range<usize>,
    pub format: ConfigFormat,
    /// K05B: the value is an item of an array or sequence under the key.
    pub item: bool,
}

static ENV_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)$").unwrap());

static PROPERTIES_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.-]*$").unwrap());

/// An HTTP field name (RFC 9110 token without the rare symbols).
static HEADER_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9-]*$").unwrap());

/// The request or status line that opens an HTTP message head.
static START_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Z]{3,10} [^ \t]+ HTTP/[0-9](?:\.[0-9])?|HTTP/[0-9](?:\.[0-9])? [0-9]{3}(?: [^\r\n]*)?)\r?$")
        .unwrap()
});

/// Lines above a header field searched for the start line.
const MAX_HEADER_LINES: usize = 100;

/// The config values on the lines where `key` matches, ordered by position.
/// `key` finds the credential part of a key; whether it binds the value the
/// caller decides from [`ConfigValue::key`].
pub(crate) fn config_values(text: &str, key: &Regex) -> Vec<ConfigValue> {
    let mut values = Vec::new();
    let mut last_line = None;
    // A line read as an env, INI/properties or header line: it holds one key.
    let mut config_line_at = None;
    // Header fields need a start line; most texts have none.
    let http = text.starts_with("HTTP/") || text.contains(" HTTP/") || text.contains("\nHTTP/");
    for found in key.find_iter(text) {
        let line = line_at(text, found.start());
        if last_line != Some(line.start) {
            last_line = Some(line.start);
            let value = may_hold_key(text, &line, found.range())
                .then(|| config_line(text, line.clone(), http))
                .flatten();
            if let Some(value) = value {
                config_line_at = Some(line.start);
                if value.key.start <= found.start() && found.end() <= value.key.end {
                    values.push(value);
                }
            }
        }
        if config_line_at != Some(line.start) {
            values.extend(nested_values(text, &line, found.range()));
        }
    }
    values.sort_by_key(|value| (value.value.start, value.key.start));
    values.dedup_by(|a, b| a.value == b.value && a.key == b.key);
    values
}

/// A cheap precondition of [`config_line`] for a key match at `found`: only
/// key characters and blanks stand before the match and between it and the
/// first `=` or `:` of the line, as in every env, INI/properties or header
/// key (`export DB_PASSWORD=`, `app.db.password =`, `X-Api-Key:`).
fn may_hold_key(text: &str, line: &Range<usize>, found: Range<usize>) -> bool {
    let is_key_byte = |byte: &u8| byte.is_ascii_alphanumeric() || b"_.- \t".contains(byte);
    let rest = &text.as_bytes()[found.end..line.end];
    text.as_bytes()[line.start..found.start]
        .iter()
        .all(is_key_byte)
        && rest
            .iter()
            .position(|&byte| byte == b'=' || byte == b':')
            .is_some_and(|separator| rest[..separator].iter().all(is_key_byte))
}

/// The config value of `line`, if the line is an env, INI/properties or
/// HTTP header field; `http` tells whether the text may hold an HTTP
/// message head at all.
pub(crate) fn config_line(text: &str, line: Range<usize>, http: bool) -> Option<ConfigValue> {
    let (key, raw) = structure::key_value_line(text, line.clone())?;
    // The key starts the line (no list bullet); a header field is not indented.
    let indent = &text[line.start..key.start];
    if !indent.chars().all(|c| c == ' ' || c == '\t') {
        return None;
    }
    let separator = text[key.end..raw.start].trim();
    let (key, format) = match separator {
        "=" => {
            // An env line has no blanks around `=` or starts with `export`.
            let tight = key.end == raw.start - 1;
            let name = ENV_KEY
                .captures(&text[key.clone()])
                .and_then(|captures| captures.get(1))
                .filter(|name| tight || name.start() > 0);
            match name {
                Some(name) => (
                    key.start + name.start()..key.start + name.end(),
                    ConfigFormat::Env,
                ),
                None if PROPERTIES_KEY.is_match(&text[key.clone()]) => {
                    (key, ConfigFormat::Properties)
                }
                None => return None,
            }
        }
        ":" if http
            && indent.is_empty()
            && HEADER_KEY.is_match(&text[key.clone()])
            && in_http_head(text, line.start) =>
        {
            (key, ConfigFormat::HttpHeader)
        }
        _ => return None,
    };
    let value = value_of(text, raw, format)?;
    Some(ConfigValue {
        key,
        value,
        format,
        item: false,
    })
}

/// The value inside the raw value of a line: up to the closing quote, or a
/// bare value without inline comment and without blanks.
fn value_of(text: &str, raw: Range<usize>, format: ConfigFormat) -> Option<Range<usize>> {
    let raw_text = &text[raw.clone()];
    let first = raw_text.chars().next()?;
    if matches!(first, '"' | '\'') {
        let bytes = raw_text.as_bytes();
        let mut index = 1;
        let close = loop {
            match bytes.get(index) {
                None => return None,
                Some(b'\\') if first == '"' => index += 2,
                Some(&byte) if byte == first as u8 => break index,
                Some(_) => index += 1,
            }
        };
        let rest = raw_text[close + 1..].trim_start();
        let commented = format != ConfigFormat::HttpHeader
            && raw_text[close + 1..].starts_with([' ', '\t'])
            && rest.starts_with(['#', ';']);
        return (close > 1 && (rest.is_empty() || commented))
            .then_some(raw.start + 1..raw.start + close);
    }
    // `==`, `=>` and `=~` are operators, not separators.
    if matches!(first, '=' | '>' | '~') {
        return None;
    }
    let mut end = raw_text.len();
    if format != ConfigFormat::HttpHeader {
        if let Some(comment) = inline_comment(raw_text) {
            end = comment;
        }
    }
    let value = raw_text[..end].trim_end();
    // Quotes or an interpolation inside a bare value, or a `,`/`;` after it,
    // are code (`f"t{n}s0"`, `pre${SUFFIX}`, `Password = 8107,` in an enum),
    // not a value of the line.
    // K05B: `[` alone opens a TOML array over several lines.
    if value.is_empty()
        || value == "["
        || value.ends_with([',', ';'])
        || value.contains(char::is_whitespace)
        || value.contains(['"', '\'', '`'])
        || ["${", "$(", "{{", "#{", "%("]
            .iter()
            .any(|opener| value.contains(opener))
        || (format == ConfigFormat::Env && value.contains(';'))
    {
        return None;
    }
    Some(raw.start..raw.start + value.len())
}

/// Where a YAML comment (`#` after a blank) starts in a plain value; unlike
/// INI, `;` opens none.
fn yaml_comment(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    (1..bytes.len()).find(|&index| bytes[index] == b'#' && matches!(bytes[index - 1], b' ' | b'\t'))
}

/// Where an inline comment (`#` or `;` after a blank) starts in a bare value.
fn inline_comment(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    (1..bytes.len()).find(|&index| {
        matches!(bytes[index], b'#' | b';') && matches!(bytes[index - 1], b' ' | b'\t')
    })
}

/// K05B: a YAML or TOML key that starts its line, after the indent and a
/// YAML list bullet: the indent, the key and the separator.
static PLAIN_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([ \t]*(?:-[ \t]+)?)([A-Za-z0-9_][A-Za-z0-9_.-]*)[ \t]*([:=])").unwrap()
});

/// K05B: an HTTP field name in its usual spelling (`X-Api-Key`,
/// `Proxy-Authorization-Token`), which a YAML key does not take.
static HEADER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Za-z0-9]*(?:-[A-Z][A-Za-z0-9]*)+$").unwrap());

/// Most items an array or sequence may hold; a longer one is data, not a
/// list of credentials.
const MAX_ITEMS: usize = 64;

/// Lines an array or block sequence may span.
const MAX_ITEM_LINES: usize = 256;

/// Longest quoted key in bytes, as for the document structure.
const MAX_QUOTED_KEY: usize = 64;

/// K05B: the YAML, JSON or TOML values bound by the key that holds `found`
/// on `line`: a scalar, or the string items of an array or sequence.
fn nested_values(text: &str, line: &Range<usize>, found: Range<usize>) -> Vec<ConfigValue> {
    if let Some(key) = quoted_key(text, line, &found) {
        let after = key.end + 1;
        let rest = &text[after..line.end];
        let separator = after + (rest.len() - rest.trim_start_matches([' ', '\t']).len());
        let (format, start) = match text[separator..].chars().next() {
            Some(':') => (ConfigFormat::Json, separator + 1),
            Some('=') if !text[separator..].starts_with("==") => {
                (ConfigFormat::Toml, separator + 1)
            }
            _ => return Vec::new(),
        };
        let start = skip_blanks(text, start, line.end);
        return match text.as_bytes().get(start) {
            Some(b'"') => scalar(
                text,
                key,
                quoted_string(text, start, b'"'),
                line.end,
                format,
            ),
            Some(b'\'') if format == ConfigFormat::Toml => scalar(
                text,
                key,
                quoted_string(text, start, b'\''),
                line.end,
                format,
            ),
            Some(b'[') => array_items(text, key, start, format),
            _ => Vec::new(),
        };
    }
    let Some(captures) = PLAIN_KEY.captures(&text[line.clone()]) else {
        return Vec::new();
    };
    let (Some(indent), Some(name), Some(separator)) =
        (captures.get(1), captures.get(2), captures.get(3))
    else {
        return Vec::new();
    };
    let key = line.start + name.start()..line.start + name.end();
    if !(key.start <= found.start && found.end <= key.end) {
        return Vec::new();
    }
    let after = line.start + separator.end();
    if separator.as_str() == "=" {
        // A TOML array; a scalar after a bare key is a properties line (K05).
        if text[after..].starts_with(['=', '>', '~']) {
            return Vec::new();
        }
        let start = skip_blanks(text, after, line.end);
        return if text[start..].starts_with('[') {
            array_items(text, key, start, ConfigFormat::Toml)
        } else {
            Vec::new()
        };
    }
    // A YAML mapping key is followed by a blank or the end of the line. A
    // header field name (`X-Client-Secret`) outside an HTTP head is none.
    if !(after == line.end || text[after..].starts_with([' ', '\t', '\r']))
        || HEADER_NAME.is_match(name.as_str())
    {
        return Vec::new();
    }
    yaml_value(text, key, after, line.end, indent.as_str().len())
}

/// The range inside the double quotes of a JSON or TOML key that holds
/// `found`: the key opens its line or follows `{`, `,` or a YAML bullet,
/// and is no escaped key inside a string (`\"password\":`).
fn quoted_key(text: &str, line: &Range<usize>, found: &Range<usize>) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    let open = text[line.start..found.start].rfind('"')? + line.start;
    let close = text[found.end..line.end].find('"')? + found.end;
    if close - open > MAX_QUOTED_KEY || text[open + 1..close].contains('\\') {
        return None;
    }
    let head = text[line.start..open].trim_end_matches([' ', '\t']);
    let opens = head.is_empty()
        || head.ends_with(['{', ','])
        || head.trim_start_matches([' ', '\t']) == "-";
    (opens && (open == 0 || bytes[open - 1] != b'\\')).then_some(open + 1..close)
}

fn skip_blanks(text: &str, from: usize, end: usize) -> usize {
    from + (text[from..end].len() - text[from..end].trim_start_matches([' ', '\t']).len())
}

/// The range inside a quoted string that opens at `open` and closes on its
/// line: `"` with backslash escapes (JSON, TOML basic, YAML double-quoted)
/// or `'` without (TOML literal; YAML doubles a quote inside, `''`). A TOML
/// multi-line string (`"""`, `'''`) and an empty string are none.
fn quoted_string(text: &str, open: usize, quote: u8) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    let mut index = open + 1;
    loop {
        match bytes.get(index) {
            None | Some(b'\n' | b'\r') => return None,
            Some(b'\\') if quote == b'"' => {
                // An escape does not continue the string onto the next line.
                if matches!(bytes.get(index + 1), None | Some(b'\n' | b'\r')) {
                    return None;
                }
                index += 2;
            }
            Some(&byte) if byte == quote => {
                if bytes.get(index + 1) == Some(&quote) && quote == b'\'' && index > open + 1 {
                    index += 2;
                    continue;
                }
                break;
            }
            Some(_) => index += 1,
        }
    }
    (index > open + 1).then_some(open + 1..index)
}

/// A quoted scalar that ends its entry: after the closing quote only blanks
/// and a comment (YAML, TOML) or `,`, `}`, `]` (JSON) may follow.
fn scalar(
    text: &str,
    key: Range<usize>,
    value: Option<Range<usize>>,
    line_end: usize,
    format: ConfigFormat,
) -> Vec<ConfigValue> {
    let Some(value) = value else {
        return Vec::new();
    };
    let rest = text[value.end + 1..line_end].trim();
    let ends = rest.is_empty()
        || match format {
            ConfigFormat::Json => rest.starts_with([',', '}', ']']),
            _ => rest.starts_with('#') && text[value.end + 1..line_end].starts_with([' ', '\t']),
        };
    if !ends {
        return Vec::new();
    }
    vec![ConfigValue {
        key,
        value,
        format,
        item: false,
    }]
}

/// The string items of the JSON, TOML or YAML flow array that opens at
/// `open`; none unless every item is a string (or, in YAML, a plain scalar)
/// and the array closes within [`MAX_ITEM_LINES`] and [`MAX_ITEMS`].
fn array_items(
    text: &str,
    key: Range<usize>,
    open: usize,
    format: ConfigFormat,
) -> Vec<ConfigValue> {
    let bytes = text.as_bytes();
    let mut items = Vec::new();
    let mut index = open + 1;
    let mut lines = 0;
    let mut expect_item = true;
    let items = loop {
        // Blanks, line breaks and (TOML, YAML) comments between items.
        while let Some(&byte) = bytes.get(index) {
            match byte {
                b' ' | b'\t' | b'\r' => index += 1,
                b'\n' => {
                    lines += 1;
                    if lines > MAX_ITEM_LINES || format == ConfigFormat::Yaml {
                        // A YAML flow sequence of credentials fits one line.
                        return Vec::new();
                    }
                    index += 1;
                }
                b'#' if format != ConfigFormat::Json => {
                    index = text[index..]
                        .find('\n')
                        .map_or(text.len(), |end| index + end);
                }
                _ => break,
            }
        }
        match bytes.get(index) {
            Some(b']') => break items,
            Some(b',') if !expect_item => {
                expect_item = true;
                index += 1;
            }
            Some(&quote @ (b'"' | b'\'')) if expect_item => {
                if quote == b'\'' && format == ConfigFormat::Json {
                    return Vec::new();
                }
                let Some(value) = quoted_string(text, index, quote) else {
                    return Vec::new();
                };
                index = value.end + 1;
                items.push(value);
                expect_item = false;
            }
            Some(_) if expect_item && format == ConfigFormat::Yaml => {
                let end = text[index..]
                    .find([',', ']', '\n'])
                    .map_or(text.len(), |end| index + end);
                let raw = text[index..end].trim_end();
                if !is_plain_value(raw) {
                    return Vec::new();
                }
                items.push(index..index + raw.len());
                index = end;
                expect_item = false;
            }
            _ => return Vec::new(),
        }
        if items.len() > MAX_ITEMS {
            return Vec::new();
        }
    };
    items
        .into_iter()
        .map(|value| ConfigValue {
            key: key.clone(),
            value,
            format,
            item: true,
        })
        .collect()
}

/// A YAML value after `key:` (at `after`, on a line ending at `line_end`,
/// the key indented by `indent` bytes): a quoted or plain scalar, a flow
/// sequence, or a block sequence on the lines below an empty value.
fn yaml_value(
    text: &str,
    key: Range<usize>,
    after: usize,
    line_end: usize,
    indent: usize,
) -> Vec<ConfigValue> {
    let start = skip_blanks(text, after, line_end);
    let rest = text[start..line_end].trim_end_matches('\r');
    if rest.is_empty() || (rest.starts_with('#') && start > after) {
        return block_sequence(text, key, line_end, indent);
    }
    match rest.as_bytes()[0] {
        quote @ (b'"' | b'\'') => scalar(
            text,
            key,
            quoted_string(text, start, quote),
            line_end,
            ConfigFormat::Yaml,
        ),
        b'[' => array_items(text, key, start, ConfigFormat::Yaml),
        _ => {
            let value = match yaml_comment(rest) {
                Some(comment) => rest[..comment].trim_end(),
                None => rest,
            };
            if !is_plain_value(value) {
                return Vec::new();
            }
            vec![ConfigValue {
                key,
                value: start..start + value.len(),
                format: ConfigFormat::Yaml,
                item: false,
            }]
        }
    }
}

/// The items of a YAML block sequence below a key line that ends at
/// `from`: `- item` lines indented at least as far as the key, up to the
/// first other line. Blank and comment lines between items are skipped. A
/// sequence of mappings (`- name: x`) or nested sequences binds nothing.
fn block_sequence(text: &str, key: Range<usize>, from: usize, indent: usize) -> Vec<ConfigValue> {
    let mut items = Vec::new();
    let mut next = from + 1;
    for _ in 0..MAX_ITEM_LINES {
        if next >= text.len() {
            break;
        }
        let line = line_at(text, next);
        next = line.end + 1;
        let content = text[line.clone()].trim_end_matches('\r');
        let body = content.trim_start_matches([' ', '\t']);
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let Some(item) = body.strip_prefix('-') else {
            break;
        };
        if content.len() - body.len() < indent || !item.starts_with([' ', '\t']) {
            break;
        }
        let start = line.start + (content.len() - item.len());
        let start = skip_blanks(text, start, line.end);
        let value = match text.as_bytes().get(start) {
            Some(&quote @ (b'"' | b'\'')) => {
                let Some(value) = quoted_string(text, start, quote) else {
                    return Vec::new();
                };
                let rest = text[value.end + 1..line.end].trim();
                if !(rest.is_empty() || rest.starts_with('#')) {
                    return Vec::new();
                }
                value
            }
            _ => {
                let raw = text[start..line.end].trim_end_matches('\r');
                let raw = match yaml_comment(raw) {
                    Some(comment) => raw[..comment].trim_end(),
                    None => raw.trim_end(),
                };
                if !is_plain_value(raw) || raw.ends_with(':') {
                    return Vec::new();
                }
                start..start + raw.len()
            }
        };
        items.push(value);
        if items.len() > MAX_ITEMS {
            return Vec::new();
        }
    }
    items
        .into_iter()
        .map(|value| ConfigValue {
            key: key.clone(),
            value,
            format: ConfigFormat::Yaml,
            item: true,
        })
        .collect()
}

/// A YAML plain scalar that may hold a secret: no indicator at its start
/// (alias `*`, anchor `&`, tag `!`, block scalar `|`/`>`, flow `{`/`[`,
/// directive `%`, reserved `@`/`` ` ``, a nested `- ` entry), no blank,
/// quote or interpolation inside, no `,`/`;` at its end (code: `token:
/// abc,`), no mapping (`name: x`) and no list of words or numbers
/// (`read,write`, `admin;ops`).
fn is_plain_value(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };
    !(matches!(
        first,
        '*' | '&' | '!' | '|' | '>' | '{' | '}' | '[' | ']' | '%' | '@' | '`' | '#' | ','
    ) || value == "-"
        || value.contains(char::is_whitespace)
        || value.contains(['"', '\'', '`'])
        || value.contains(": ")
        || value.ends_with([',', ';'])
        || ["${", "$(", "{{", "#{", "%("]
            .iter()
            .any(|opener| value.contains(opener))
        || is_word_list(value))
}

/// Words or numbers separated by `,` or `;`: a list, not a secret.
fn is_word_list(value: &str) -> bool {
    value.contains([',', ';'])
        && value.split([',', ';']).all(|part| {
            !part.is_empty()
                && (part
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
                    || part
                        .chars()
                        .all(|c| c.is_alphabetic() || matches!(c, '_' | '-' | '.')))
        })
}

/// K05B: whether the config value at `value_start` is an item of an array or
/// sequence ([`ConfigValue::item`]): after its opening quote, the text
/// before it ends with `[` or `,`, or its line is a `- ` bullet. A scalar
/// follows its key and `:` or `=`.
pub(crate) fn is_item(text: &str, value_start: usize) -> bool {
    let before = &text[..value_start];
    let before = before.strip_suffix(['"', '\'']).unwrap_or(before);
    let trimmed = before.trim_end();
    if trimmed.ends_with(['[', ',']) {
        return true;
    }
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    before[line_start..].trim() == "-"
}

/// Whether the line at `line_start` lies in the head of an HTTP message:
/// header fields up to a request or status line, without a blank line.
fn in_http_head(text: &str, line_start: usize) -> bool {
    let mut end = line_start;
    for _ in 0..MAX_HEADER_LINES {
        if end == 0 {
            return false;
        }
        let previous = line_at(text, end - 1);
        let line = text[previous.clone()].trim_end_matches('\r');
        if START_LINE.is_match(line) {
            return true;
        }
        let is_field = line
            .split_once(':')
            .is_some_and(|(name, _)| HEADER_KEY.is_match(name));
        if !is_field {
            return false;
        }
        end = previous.start;
    }
    false
}

/// The byte range of the line that holds `offset`, without its line break.
fn line_at(text: &str, offset: usize) -> Range<usize> {
    let start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
    let end = text[offset..]
        .find('\n')
        .map_or(text.len(), |index| offset + index);
    start..end
}

#[cfg(test)]
mod tests {
    use super::{config_line, config_values, is_item, line_at, ConfigFormat};
    use regex::Regex;

    /// K05B: key, value, format and item flag of every config value whose
    /// key holds a credential noun.
    fn nested(text: &str) -> Vec<(&str, &str, ConfigFormat, bool)> {
        let key = Regex::new(r"(?i)(?:password|secret|token|api_key)s?(?-u:\b)").unwrap();
        config_values(text, &key)
            .into_iter()
            .map(|value| {
                (
                    &text[value.key],
                    &text[value.value],
                    value.format,
                    value.item,
                )
            })
            .collect()
    }

    fn parse(text: &str) -> Option<(&str, &str, ConfigFormat)> {
        let line = line_at(text, text.len());
        config_line(text, line, true)
            .map(|value| (&text[value.key], &text[value.value], value.format))
    }

    #[test]
    fn env_lines_with_quotes_comments_and_export() {
        for (text, key, value) in [
            ("DB_PASSWORD=ab,cd}ef", "DB_PASSWORD", "ab,cd}ef"),
            (
                "export SERVICE_SECRET='Kx7 pQ2'",
                "SERVICE_SECRET",
                "Kx7 pQ2",
            ),
            ("API_TOKEN=\"Kx7\\\"pQ2\" # prod", "API_TOKEN", "Kx7\\\"pQ2"),
            ("API_TOKEN=Kx7pQ2vL9 # prod", "API_TOKEN", "Kx7pQ2vL9"),
            ("API_TOKEN=Kx7#pQ2", "API_TOKEN", "Kx7#pQ2"),
        ] {
            assert_eq!(parse(text), Some((key, value, ConfigFormat::Env)), "{text}");
        }
    }

    #[test]
    fn properties_and_ini_lines() {
        let text = "[auth]\nclient_secret = Kx7]pQ2,vL9 ; rotated\n";
        let line = line_at(text, 8);
        let value = config_line(text, line, true).unwrap();
        assert_eq!(&text[value.key], "client_secret");
        assert_eq!(&text[value.value], "Kx7]pQ2,vL9");
        assert_eq!(value.format, ConfigFormat::Properties);
        assert_eq!(
            parse("app.db.password=xy;Ab3dE9,42}QZ"),
            Some((
                "app.db.password",
                "xy;Ab3dE9,42}QZ",
                ConfigFormat::Properties
            ))
        );
    }

    #[test]
    fn header_fields_only_in_an_http_head() {
        let text = "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Client-Secret: Kx7,pQ2vL9";
        assert_eq!(
            parse(text),
            Some(("X-Client-Secret", "Kx7,pQ2vL9", ConfigFormat::HttpHeader))
        );
        let text = "HTTP/1.1 200 OK\r\nSet-Token: Kx7,pQ2vL9";
        assert_eq!(
            parse(text),
            Some(("Set-Token", "Kx7,pQ2vL9", ConfigFormat::HttpHeader))
        );
        for text in [
            "X-Client-Secret: Kx7,pQ2vL9",
            "POST /v1 HTTP/1.1\nHost: api\n\nX-Client-Secret: Kx7,pQ2vL9",
            "client_secret: Kx7,pQ2vL9",
            "POST /v1 HTTP/1.1\n  X-Client-Secret: Kx7,pQ2vL9",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn code_lists_operators_and_blanks_are_no_config_values() {
        for text in [
            "password = get_password(user, realm)",
            "password == \"x\"",
            "'password' => 'x'",
            "password => x",
            "- password=Kx7pQ2",
            "  - token: Kx7pQ2",
            "const password = \"x\";",
            "export API_TOKEN=Kx7;./bin/run",
            "password = \"x\" + suffix",
            "password = \"unclosed",
            "# password=Kx7pQ2",
            "API_TOKEN=",
            "API_TOKEN=\"\"",
            "token = f\"t{request.number}s0\"",
            "API_TOKEN=pre${SUFFIX}",
            "password=b'Kx7pQ2'",
            "    eatClearTextPassword = 8107,",
            "client_secret=Kx7pQ2vL9;",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn values_are_collected_where_the_key_holds_the_match() {
        let key = Regex::new(r"(?i)password").unwrap();
        let text = "user=password\nDB_PASSWORD=Kx7,pQ2\nPASSWORD_POLICY=strict password\n";
        let values: Vec<_> = config_values(text, &key)
            .into_iter()
            .map(|value| (&text[value.key], &text[value.value]))
            .collect();
        assert_eq!(values, vec![("DB_PASSWORD", "Kx7,pQ2")]);
    }

    #[test]
    fn yaml_scalars_at_any_depth() {
        use ConfigFormat::Yaml;
        assert_eq!(
            nested("db:\n  main:\n    password: Kx7;pQ2,v}L # prod\n"),
            vec![("password", "Kx7;pQ2,v}L", Yaml, false)]
        );
        assert_eq!(
            nested("- name: a\n  secret: 'it''s Kx7'\n- token: \"Kx\\\"7\"\n"),
            vec![
                ("secret", "it''s Kx7", Yaml, false),
                ("token", "Kx\\\"7", Yaml, false)
            ]
        );
        for text in [
            "password: *default\n",
            "password: &anchor Kx7\n",
            "password: !vault |\n",
            "password: |\n  Kx7\n",
            "password: {get: db}\n",
            "password: Kx7 pQ2\n",
            "password: Kx7pQ2 ;rotated\n",
            "password: \"Kx7\\\npQ2\"\n",
            "password: Kx7pQ2,\n",
            "password: read,write\n",
            "password: pre${SUFFIX}\n",
            "password:Kx7pQ2\n",
            "password: \"Kx7\" + suffix\n",
            "my password: Kx7pQ2\n",
        ] {
            assert_eq!(nested(text), vec![], "{text}");
        }
    }

    #[test]
    fn json_and_toml_scalars_and_arrays() {
        use ConfigFormat::{Json, Toml};
        assert_eq!(
            nested("{\"a\": {\"password\": \"Kx\\\"7,}\"}, \"tokens\": [\"Ab1\", \"Cd2\"]}"),
            vec![
                ("password", "Kx\\\"7,}", Json, false),
                ("tokens", "Ab1", Json, true),
                ("tokens", "Cd2", Json, true)
            ]
        );
        assert_eq!(
            nested(
                "[auth]\napi_keys = [\n  \"Ab1\", # one\n  'Cd\\2',\n]\n\"api-secret\" = \"Ef3\"\n"
            ),
            vec![
                ("api_keys", "Ab1", Toml, true),
                ("api_keys", "Cd\\2", Toml, true),
                ("api-secret", "Ef3", Toml, false)
            ]
        );
        for text in [
            "{\"tokens\": [\"Ab1\", 3]}",
            "{\"tokens\": [{\"value\": \"Ab1\"}]}",
            "{\"tokens\": ['Ab1']}",
            "tokens = [\"Ab1\"",
            "secret = \"\"\"\nAb1\n\"\"\"",
            "{\\\"password\\\": \\\"Kx7\\\"}",
            "x = \"password\": \"Kx7\"",
        ] {
            assert_eq!(nested(text), vec![], "{text}");
        }
    }

    #[test]
    fn yaml_sequences_under_a_key() {
        use ConfigFormat::Yaml;
        assert_eq!(
            nested("api_keys: [Ab1, \"Cd2\"]\n"),
            vec![
                ("api_keys", "Ab1", Yaml, true),
                ("api_keys", "Cd2", Yaml, true)
            ]
        );
        assert_eq!(
            nested(
                "auth:\n  tokens: # rotated\n  - Ab1\n\n    # old\n  - 'Cd2'\n  user: x\n- Ef3\n"
            ),
            vec![("tokens", "Ab1", Yaml, true), ("tokens", "Cd2", Yaml, true)]
        );
        for text in [
            "tokens:\n  - name: a\n",
            "tokens:\n  - - Ab1\n",
            "tokens:\n  - Ab1 Cd2\n",
            "tokens: [Ab1,\n  Cd2]\n",
            "tokens: [Ab1, {a: b}]\n",
            "  tokens:\n- Ab1\n",
        ] {
            assert_eq!(nested(text), vec![], "{text}");
        }
    }

    #[test]
    fn items_are_told_from_scalars() {
        let text = "tokens: [\"Ab1\", Cd2]\n  - Ef3\npassword: \"Gh4\"\nAPI_TOKEN=Ij5\n";
        for (value, item) in [
            ("Ab1", true),
            ("Cd2", true),
            ("Ef3", true),
            ("Gh4", false),
            ("Ij5", false),
        ] {
            assert_eq!(is_item(text, text.find(value).unwrap()), item, "{value}");
        }
    }

    #[test]
    fn key_precondition_and_http_start_line_gate_the_lines() {
        let key = Regex::new(r"(?i)password|api-key").unwrap();
        let text = "- DB_PASSWORD=Kx7,pQ2\nlog(password)=Kx7,pQ2\n  export DB_PASSWORD=Kx7,pQ3\napp.db.password = Kx7,pQ4\n";
        let values: Vec<_> = config_values(text, &key)
            .into_iter()
            .map(|value| &text[value.value])
            .collect();
        assert_eq!(values, vec!["Kx7,pQ3", "Kx7,pQ4"]);
        let headers = "X-Api-Key: Kx7,pQ2vL9\n";
        assert!(config_values(headers, &key).is_empty());
        let request = format!("GET /v1/items HTTP/1.1\n{headers}");
        let values: Vec<_> = config_values(&request, &key)
            .into_iter()
            .map(|value| (&request[value.key], value.format))
            .collect();
        assert_eq!(values, vec![("X-Api-Key", ConfigFormat::HttpHeader)]);
    }
}
