// SPDX-License-Identifier: GPL-3.0-only
//! Python `re` patterns on the Rust `regex` crate.
//!
//! The K26 shell-risk reference is written in Python, and the bundle's
//! DefenseClaw rules carry Python patterns. Both are ported verbatim and
//! translated here, so a port never re-spells a pattern by hand. The
//! translation closes the gaps that change results on shell text:
//!
//! - `\s` / `\S`: Python's `str` whitespace also contains U+001C..U+001F.
//! - `\w` / `\W`: Python's word characters are letters, numbers and `_`
//!   (`str.isalnum`), without the marks and connector punctuation Rust adds.
//! - `$` without multiline also matches before a final `\n` in Python.
//! - `\Z` is Rust's `\z`; `{,n}` is `{0,n}`; a `{` that starts no quantifier
//!   is a literal; `\<` / `\>` are literals, not word boundaries.
//! - Inside a class, `[`, `&` and `~` are literals (Rust reads nested classes
//!   and set operations there).
//!
//! `\b` keeps Rust's Unicode word boundary, which differs from Python only
//! next to combining marks, connector punctuation and `No` digits. Look-around,
//! back-references and possessive or atomic groups are refused: the few
//! reference patterns that use them are ported as code.

use regex::Regex;

/// How a pattern is applied, as in Python's `re.search`, `re.match` and
/// `re.fullmatch`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Anchor {
    Search,
    Match,
    Full,
}

const PY_SPACE: &str = r"\s\x1C-\x1F";
const PY_WORD: &str = r"\p{L}\p{N}_";

/// Compile a Python pattern; `ignore_case` is `re.I`. Panics on a pattern
/// outside the supported subset (all callers pass fixed, tested patterns).
pub(crate) fn py_regex(pattern: &str, ignore_case: bool, anchor: Anchor) -> Regex {
    try_py_regex(pattern, ignore_case, anchor)
        .unwrap_or_else(|error| panic!("unsupported Python pattern {pattern:?}: {error}"))
}

/// [`py_regex`] for patterns from data (bundle rules): an error instead of a
/// panic.
pub(crate) fn try_py_regex(
    pattern: &str,
    ignore_case: bool,
    anchor: Anchor,
) -> Result<Regex, String> {
    let body = translate(pattern)?;
    let flags = if ignore_case { "(?i)" } else { "" };
    let full = match anchor {
        Anchor::Search => format!("{flags}{body}"),
        Anchor::Match => format!(r"{flags}\A(?:{body})"),
        Anchor::Full => format!(r"{flags}\A(?:{body})\z"),
    };
    Regex::new(&full).map_err(|error| error.to_string())
}

/// Translate Python `re` syntax to the equivalent `regex` crate syntax.
fn translate(pattern: &str) -> Result<String, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut multiline = false;
    let mut i = 0;
    // Global inline flags may only open a Python pattern.
    if pattern.starts_with("(?") {
        let flags: String = chars[2..]
            .iter()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        if !flags.is_empty() && chars.get(2 + flags.len()) == Some(&')') {
            if let Some(bad) = flags.chars().find(|c| !matches!(c, 'i' | 'm' | 's' | 'x')) {
                return Err(format!("inline flag {bad}"));
            }
            multiline = flags.contains('m');
            out.push_str(&format!("(?{flags})"));
            i = 3 + flags.len();
        }
    }
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                let next = *chars.get(i + 1).ok_or("trailing backslash")?;
                i += 2;
                match next {
                    's' => out.push_str(&format!("[{PY_SPACE}]")),
                    'S' => out.push_str(&format!("[^{PY_SPACE}]")),
                    'w' => out.push_str(&format!("[{PY_WORD}]")),
                    'W' => out.push_str(&format!("[^{PY_WORD}]")),
                    'Z' => out.push_str(r"\z"),
                    '1'..='9' => return Err("back-reference".to_string()),
                    _ => push_escape(&mut out, next),
                }
            }
            '[' => i = class(&chars, i, &mut out)?,
            '$' => {
                out.push_str(if multiline { "$" } else { r"(?:\n?\z)" });
                i += 1;
            }
            '(' if chars.get(i + 1) == Some(&'?') => {
                // `(?:`, `(?P<name>` and scoped flags `(?i:` pass through.
                match chars.get(i + 2) {
                    Some(c) if *c == ':' || c.is_ascii_alphabetic() => out.push_str("(?"),
                    _ => return Err("look-around or atomic group".to_string()),
                }
                i += 2;
            }
            '{' => {
                let (text, next) = brace(&chars, i);
                out.push_str(&text);
                i = next;
            }
            '}' => {
                out.push_str(r"\}");
                i += 1;
            }
            '*' | '+' | '?' if matches!(chars.get(i + 1), Some('+')) => {
                return Err("possessive quantifier".to_string());
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// An escaped character outside the Python shorthand classes.
fn push_escape(out: &mut String, c: char) {
    if c.is_ascii_alphanumeric() {
        // \d \D \b \B \A \n \t \r \f \v \x.. \u.... keep their meaning.
        out.push('\\');
        out.push(c);
    } else {
        out.push_str(&regex::escape(&c.to_string()));
    }
}

/// A `{...}` at `start`: a quantifier when well formed, else a literal brace.
fn brace(chars: &[char], start: usize) -> (String, usize) {
    let close = chars[start..].iter().position(|&c| c == '}');
    if let Some(len) = close {
        let inner: String = chars[start + 1..start + len].iter().collect();
        let (lo, hi) = match inner.split_once(',') {
            Some((lo, hi)) => (lo, Some(hi)),
            None => (inner.as_str(), None),
        };
        let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
        let valid =
            digits(lo) && hi.is_none_or(digits) && !(lo.is_empty() && hi.is_none_or(str::is_empty));
        if valid {
            let lo = if lo.is_empty() { "0" } else { lo };
            let text = match hi {
                Some(hi) => format!("{{{lo},{hi}}}"),
                None => format!("{{{lo}}}"),
            };
            return (text, start + len + 1);
        }
    }
    (r"\{".to_string(), start + 1)
}

/// A character class at `start`; returns the index after its `]`.
fn class(chars: &[char], start: usize, out: &mut String) -> Result<usize, String> {
    let mut i = start + 1;
    out.push('[');
    if chars.get(i) == Some(&'^') {
        out.push('^');
        i += 1;
    }
    // A leading `]` is a literal in Python.
    if chars.get(i) == Some(&']') {
        out.push_str(r"\]");
        i += 1;
    }
    loop {
        let c = *chars.get(i).ok_or("unterminated class")?;
        match c {
            ']' => {
                out.push(']');
                return Ok(i + 1);
            }
            '\\' => {
                let next = *chars.get(i + 1).ok_or("trailing backslash")?;
                i += 2;
                match next {
                    's' => out.push_str(PY_SPACE),
                    'w' => out.push_str(PY_WORD),
                    // A nested class is a union item in Rust.
                    'S' => out.push_str(&format!("[^{PY_SPACE}]")),
                    'W' => out.push_str(&format!("[^{PY_WORD}]")),
                    _ => push_escape(out, next),
                }
            }
            '[' | '&' | '~' => {
                out.push('\\');
                out.push(c);
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
}

/// Python `str.isspace()`: Unicode whitespace plus U+001C..U+001F.
pub(crate) fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python `str.strip()` without arguments.
pub(crate) fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_includes_ascii_separators() {
        let rx = py_regex(r"a\sb", false, Anchor::Search);
        assert!(rx.is_match("a\u{1f}b"));
        assert!(!py_regex(r"a\Sb", false, Anchor::Search).is_match("a\u{1c}b"));
        assert!(py_regex(r"[\s;]", false, Anchor::Full).is_match("\u{1d}"));
    }

    #[test]
    fn word_class_is_letters_numbers_underscore() {
        let rx = py_regex(r"\w+", false, Anchor::Full);
        assert!(rx.is_match("ab_9é²"));
        // U+0301 combining acute and U+203F undertie are \w in Rust only.
        assert!(!rx.is_match("a\u{301}"));
        assert!(!rx.is_match("a\u{203f}"));
        assert!(py_regex(r"[\w.-]+", false, Anchor::Full).is_match("a.b-c"));
    }

    #[test]
    fn dollar_matches_before_a_final_newline() {
        let rx = py_regex(r"^foo$", false, Anchor::Search);
        assert!(rx.is_match("foo\n"));
        assert!(!rx.is_match("foo\n\n"));
        let multi = py_regex(r"(?m)^foo$", false, Anchor::Search);
        assert!(multi.is_match("x\nfoo\ny"));
    }

    #[test]
    fn anchors_follow_match_and_fullmatch() {
        assert!(py_regex("a|ab", false, Anchor::Full).is_match("ab"));
        assert!(!py_regex("b", false, Anchor::Match).is_match("ab"));
        assert!(py_regex("b", false, Anchor::Search).is_match("ab"));
    }

    #[test]
    fn literal_braces_brackets_and_escapes() {
        assert!(py_regex(r"\$\{HOME\}", false, Anchor::Full).is_match("${HOME}"));
        assert!(py_regex(r"x{", false, Anchor::Full).is_match("x{"));
        assert!(py_regex(r"a{,2}", false, Anchor::Full).is_match("aa"));
        assert!(py_regex(r"[[&~]+", false, Anchor::Full).is_match("[&~"));
        assert!(py_regex(r"\<x\>", false, Anchor::Full).is_match("<x>"));
        assert!(py_regex(r"[]a]+", false, Anchor::Full).is_match("]a"));
        assert!(py_regex(r#"[\w."`\[\]]+"#, false, Anchor::Full).is_match("a.\"`[]"));
    }

    #[test]
    fn negated_shorthands_inside_classes() {
        let rx = py_regex(r"[^\S\n]+", false, Anchor::Full);
        assert!(rx.is_match(" \t\u{1c}"));
        assert!(!rx.is_match(" \n"));
        assert!(py_regex(r"[\W\d]+", false, Anchor::Full).is_match("-1 "));
        assert!(!py_regex(r"[\W]", false, Anchor::Full).is_match("_"));
    }

    #[test]
    fn ignore_case_and_inline_flags() {
        assert!(py_regex("abc", true, Anchor::Full).is_match("ABC"));
        assert!(py_regex("(?is)a.b", false, Anchor::Full).is_match("A\nB"));
    }

    #[test]
    fn refuses_unsupported_constructs() {
        for pattern in [r"(?<=a)b", r"(?!a)", r"(a)\1", "a++", "(?>a)"] {
            assert!(
                try_py_regex(pattern, false, Anchor::Search).is_err(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn strip_matches_python() {
        assert_eq!(py_strip("\u{1c} a \u{a0}"), "a");
    }
}
