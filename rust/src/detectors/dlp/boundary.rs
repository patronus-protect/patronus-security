// SPDX-License-Identifier: GPL-3.0-only
//! T01: token boundaries of the prefix rules. A provider token, wallet key or
//! JWT counts only as a whole token, not as a run inside an identifier
//! (`load_hf_…`, `HfAKIA…`), a hex run (Cargo.lock checksum, sha256 digest)
//! or a base64 blob (go.sum hash, data URI).
use super::dlp::TokenBoundary;
use std::ops::Range;

/// Shortest base64 run beside a `+`/`/` neighbour that makes the value part of
/// a blob; shorter runs are path segments (`s3://bucket/AKIA…`).
const MIN_BLOB_RUN: usize = 16;

/// Whether `range` of `text` is a whole token for `boundary`: no word or
/// provider-alphabet character directly before or after it, except at the
/// end of an escape (`\n`, `%3D`, `\uHHHH`), and no base64 blob on a `+`/`/`
/// side.
pub(super) fn is_whole_token(text: &str, range: Range<usize>, boundary: TokenBoundary) -> bool {
    let bytes = text.as_bytes();
    let continues = |byte: u8| {
        byte.is_ascii_alphanumeric() || byte == b'_' || boundary.alphabet.as_bytes().contains(&byte)
    };
    if let Some(&before) = bytes[..range.start].last() {
        if continues(before) && !ends_with_escape(&bytes[..range.start]) {
            return false;
        }
        if matches!(before, b'+' | b'/') && is_blob_run(bytes[..range.start - 1].iter().rev()) {
            return false;
        }
    }
    if let Some(&after) = bytes.get(range.end) {
        if continues(after) {
            return false;
        }
        if matches!(after, b'+' | b'/') && is_blob_run(bytes[range.end + 1..].iter()) {
            return false;
        }
    }
    true
}

/// Whether `head` ends with a character escape whose last character is a
/// letter or digit: `\n`, `\t` …, `\xHH`, `\uHHHH` (with an unescaped
/// backslash) or URL percent-encoding `%HH`.
fn ends_with_escape(head: &[u8]) -> bool {
    let n = head.len();
    let hex = |range: Range<usize>| head[range].iter().all(u8::is_ascii_hexdigit);
    let escaped_at = |index: usize| {
        let backslashes = head[..=index]
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\\')
            .count();
        backslashes % 2 == 1
    };
    (n >= 2 && b"ntrbfv0".contains(&head[n - 1]) && escaped_at(n - 2))
        || (n >= 3 && head[n - 3] == b'%' && hex(n - 2..n))
        || (n >= 4 && head[n - 3] == b'x' && hex(n - 2..n) && escaped_at(n - 4))
        || (n >= 6 && head[n - 5] == b'u' && hex(n - 4..n) && escaped_at(n - 6))
}

/// Whether the base64 characters that `run` yields (beyond the `+`/`/`
/// neighbour, outward from the value) form a blob: at least
/// [`MIN_BLOB_RUN`] of them, with upper case, lower case and digits.
fn is_blob_run<'a>(run: impl Iterator<Item = &'a u8>) -> bool {
    let (mut len, mut upper, mut lower, mut digit) = (0, false, false, false);
    for &byte in
        run.take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        len += 1;
        upper |= byte.is_ascii_uppercase();
        lower |= byte.is_ascii_lowercase();
        digit |= byte.is_ascii_digit();
    }
    len >= MIN_BLOB_RUN && upper && lower && digit
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORD: TokenBoundary = TokenBoundary { alphabet: "" };
    const DASH: TokenBoundary = TokenBoundary { alphabet: "-" };

    fn whole(text: &str, token: &str, boundary: TokenBoundary) -> bool {
        let start = text.find(token).expect("token in text");
        is_whole_token(text, start..start + token.len(), boundary)
    }

    #[test]
    fn delimiters_and_escapes_end_a_token() {
        for text in [
            "tok",
            "=tok;",
            "\"tok\"",
            "(tok)",
            "\\ntok\\t",
            "%3Dtok%26",
            "\\u0022tok",
            "\\x27tok",
            "a/tok/b",
        ] {
            assert!(whole(text, "tok", WORD), "{text:?}");
        }
    }

    #[test]
    fn word_and_alphabet_neighbours_continue_a_token() {
        for text in ["xtok", "tok9", "_tok", "tok_", "\\\\ntok", "%3tok"] {
            assert!(!whole(text, "tok", WORD), "{text:?}");
        }
        assert!(whole("a-tok-b", "tok", WORD));
        assert!(!whole("a-tok", "tok", DASH));
        assert!(!whole("tok-b", "tok", DASH));
    }

    #[test]
    fn base64_blobs_hold_no_token() {
        assert!(!whole("Zm9yZWlnbjAxMjM0NTY3+tok", "tok", WORD));
        assert!(!whole("tok/Zm9yZWlnbjAxMjM0NTY3==", "tok", WORD));
        assert!(whole("s3://bucket/tok/", "tok", WORD));
        assert!(whole("/home/user/projects/tok", "tok", WORD));
        assert!(whole("a+tok", "tok", WORD));
    }
}
