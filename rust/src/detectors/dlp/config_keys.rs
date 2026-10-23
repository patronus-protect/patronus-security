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
}

impl ConfigFormat {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Properties => "properties",
            Self::HttpHeader => "http_header",
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
    // Header fields need a start line; most texts have none.
    let http = text.starts_with("HTTP/") || text.contains(" HTTP/") || text.contains("\nHTTP/");
    for found in key.find_iter(text) {
        let line = line_at(text, found.start());
        if last_line == Some(line.start) {
            continue;
        }
        last_line = Some(line.start);
        if !may_hold_key(text, &line, found.range()) {
            continue;
        }
        if let Some(value) = config_line(text, line, http) {
            if value.key.start <= found.start() && found.end() <= value.key.end {
                values.push(value);
            }
        }
    }
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
    Some(ConfigValue { key, value, format })
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
    if value.is_empty()
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

/// Where an inline comment (`#` or `;` after a blank) starts in a bare value.
fn inline_comment(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    (1..bytes.len()).find(|&index| {
        matches!(bytes[index], b'#' | b';') && matches!(bytes[index - 1], b' ' | b'\t')
    })
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
    use super::{config_line, config_values, line_at, ConfigFormat};
    use regex::Regex;

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
