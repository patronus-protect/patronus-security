// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shell quote removal inside single words (`'r''m'`, `"r"m`, `r\m`) and
//! cmd caret escapes (`r^m^d^i^r`). The reference uses look-around regexes;
//! the runs are scanned by hand here.

use std::collections::BTreeSet;

use crate::detectors::shell::pyre::is_py_space;

fn is_plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'-')
}

fn is_run_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

fn plain_run(bytes: &[u8], from: usize, accept: fn(u8) -> bool) -> usize {
    from + bytes[from..].iter().take_while(|b| accept(**b)).count()
}

/// End of a `QUOTE_RUN` word at `p`: `(?:P*(?:'P*'|"P*"))+P*`.
fn quote_run_end(text: &str, p: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut pos = p;
    let mut units = 0;
    loop {
        let end = plain_run(bytes, pos, is_plain);
        if let Some(&quote @ (b'\'' | b'"')) = bytes.get(end) {
            let close = plain_run(bytes, end + 1, is_plain);
            if bytes.get(close) == Some(&quote) {
                pos = close + 1;
                units += 1;
                continue;
            }
        }
        return (units > 0).then_some(end);
    }
}

/// End of a `CARET_RUN` word at `p`: `C(?:\^C)+`.
fn caret_run_end(text: &str, p: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if !bytes.get(p).is_some_and(|b| is_run_char(*b)) {
        return None;
    }
    let mut pos = p + 1;
    let mut units = 0;
    while bytes.get(pos) == Some(&b'^') && bytes.get(pos + 1).is_some_and(|b| is_run_char(*b)) {
        pos += 2;
        units += 1;
    }
    (units > 0).then_some(pos)
}

/// End of a `BACKSLASH_RUN` word at `p`: `(?:\\?C)*\\[A-Za-z][C\\]*`. Any
/// match ends at the end of the run of `C` and `\`; it exists when a `\`
/// before a letter is reached through a valid `(?:\\?C)*` prefix.
fn backslash_run_end(text: &str, p: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = p + bytes[p..]
        .iter()
        .take_while(|b| is_run_char(**b) || **b == b'\\')
        .count();
    let mut i = p;
    while i < end {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            Some(next) if i + 1 < end && next.is_ascii_alphabetic() => return Some(end),
            Some(next) if i + 1 < end && is_run_char(*next) => i += 2,
            _ => return None,
        }
    }
    None
}

/// `re.sub` of a `(?<![^\s;|&(])RUN(?=[\s;|&)]|$)` pattern.
fn substitute_runs(
    text: &str,
    run_end: fn(&str, usize) -> Option<usize>,
    mut replace: impl FnMut(&str) -> String,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut p = 0;
    while p < text.len() {
        let after_boundary = text[..p]
            .chars()
            .next_back()
            .is_none_or(|c| is_py_space(c) || matches!(c, ';' | '|' | '&' | '('));
        if after_boundary {
            if let Some(end) = run_end(text, p) {
                let before_boundary = text[end..]
                    .chars()
                    .next()
                    .is_none_or(|c| is_py_space(c) || matches!(c, ';' | '|' | '&' | ')'));
                if before_boundary {
                    out.push_str(&replace(&text[p..end]));
                    p = end;
                    continue;
                }
            }
        }
        let c = text[p..].chars().next().expect("char boundary");
        out.push(c);
        p += c.len_utf8();
    }
    out
}

/// Shell quote removal inside single words (`'r''m'`, `"r"m`, `r\m`) and cmd
/// caret escapes (`r^m^d^i^r`). Returns the text and the `OBF_*` atoms.
pub(super) fn deobfuscate(text: &str, dialect: &str) -> (String, BTreeSet<&'static str>) {
    let mut atoms = BTreeSet::new();
    let mut out = substitute_runs(text, quote_run_end, |word| {
        atoms.insert("OBF_QUOTE");
        word.replace(['\'', '"'], "")
    });
    if matches!(dialect, "CMD" | "MIXED") || text.contains('^') {
        out = substitute_runs(&out, caret_run_end, |word| {
            atoms.insert("OBF_CARET");
            word.replace('^', "")
        });
    }
    if !matches!(dialect, "CMD" | "POWERSHELL" | "MIXED") {
        out = substitute_runs(&out, backslash_run_end, |word| {
            atoms.insert("OBF_BACKSLASH");
            word.replace('\\', "")
        });
    }
    (out, atoms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deobfuscation_removes_quotes_carets_and_backslashes() {
        assert_eq!(deobfuscate("'r''m' -rf /tmp/x", "POSIX").0, "rm -rf /tmp/x");
        assert_eq!(deobfuscate("r^m^d^i^r /s", "CMD").0, "rmdir /s");
        assert_eq!(deobfuscate("\\rm -rf build", "POSIX").0, "rm -rf build");
        let (text, atoms) = deobfuscate("echo 'hello world'", "POSIX");
        assert_eq!(text, "echo 'hello world'");
        assert!(atoms.is_empty());
    }
}
