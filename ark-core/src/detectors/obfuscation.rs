// SPDX-License-Identifier: MIT OR Apache-2.0
//! Obfuscation normalization with offset back-mapping (PII K06).
//!
//! Values hidden behind characters that leave them readable are rewritten into a
//! normalized view; detectors scan the view and map every byte range back to the
//! original text. Two levels:
//!
//! - [`Level::Invisible`] (every mode) undoes what does not change the value:
//!   zero-width characters inside a value, full-width forms (`０３０`, `＠`) and
//!   defanged separators (`203[.]0[.]113[.]5`, `user[@]host`).
//! - [`Level::SpelledOut`] (`recall` only) also undoes spelled-out separators of
//!   e-mail addresses (`[at]`, `(ät)`, `dot`, `punkt`, ` @ `, ` . `) and numbers
//!   spaced character by character (`D E 8 9 3 7 …`). Gold convention T01 keeps these forms hard
//!   negatives in `strict` and `balanced`.
use std::{ops::Range, sync::LazyLock};

use regex::Regex;

/// How far the normalization goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Invisible,
    SpelledOut,
}

/// What an edit undid; reported as `matched_rules[].obfuscation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    ZeroWidth,
    FullWidth,
    Defanged,
    SpelledOut,
    SpacedDigits,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroWidth => "zero_width",
            Self::FullWidth => "full_width",
            Self::Defanged => "defanged",
            Self::SpelledOut => "spelled_out",
            Self::SpacedDigits => "spaced_digits",
        }
    }

    /// The level that undoes this kind.
    pub const fn level(self) -> Level {
        match self {
            Self::ZeroWidth | Self::FullWidth | Self::Defanged => Level::Invisible,
            Self::SpelledOut | Self::SpacedDigits => Level::SpelledOut,
        }
    }
}

/// One rewrite of the original text: `range` becomes `with`.
#[derive(Debug, Clone)]
struct Edit {
    range: Range<usize>,
    with: Replacement,
    kind: Kind,
}

#[derive(Debug, Clone, Copy)]
enum Replacement {
    Remove,
    Char(char),
}

/// Normalized view of a text with a byte map back to the original.
pub struct Deobfuscated {
    pub text: String,
    /// Original byte range of every normalized byte.
    starts: Vec<usize>,
    ends: Vec<usize>,
    edits: Vec<Edit>,
}

impl Deobfuscated {
    /// The normalized view of `original`, or `None` if nothing is obfuscated.
    pub fn new(original: &str, level: Level) -> Option<Self> {
        let mut edits = Vec::new();
        if has_invisible_candidates(original) {
            zero_width(original, &mut edits);
            full_width(original, &mut edits);
        }
        defanged(original, &mut edits);
        if level >= Level::SpelledOut {
            spelled_out(original, &mut edits);
            spaced_digits(original, &mut edits);
        }
        if edits.is_empty() {
            return None;
        }
        edits.sort_by_key(|edit| (edit.range.start, edit.range.end));
        let mut kept: Vec<Edit> = Vec::with_capacity(edits.len());
        for edit in edits {
            if kept
                .last()
                .is_none_or(|last| last.range.end <= edit.range.start)
            {
                kept.push(edit);
            }
        }
        Some(Self::build(original, kept))
    }

    fn build(original: &str, edits: Vec<Edit>) -> Self {
        let mut text = String::with_capacity(original.len());
        let mut starts = Vec::with_capacity(original.len());
        let mut ends = Vec::with_capacity(original.len());
        let mut push = |text: &mut String, ch: char, range: Range<usize>| {
            text.push(ch);
            starts.extend(std::iter::repeat_n(range.start, ch.len_utf8()));
            ends.extend(std::iter::repeat_n(range.end, ch.len_utf8()));
        };
        let mut cursor = 0;
        for edit in &edits {
            for (offset, ch) in original[cursor..edit.range.start].char_indices() {
                let start = cursor + offset;
                push(&mut text, ch, start..start + ch.len_utf8());
            }
            if let Replacement::Char(ch) = edit.with {
                push(&mut text, ch, edit.range.clone());
            }
            cursor = edit.range.end;
        }
        for (offset, ch) in original[cursor..].char_indices() {
            let start = cursor + offset;
            push(&mut text, ch, start..start + ch.len_utf8());
        }
        Self {
            text,
            starts,
            ends,
            edits,
        }
    }

    /// Original byte range of the non-empty normalized byte range `range`.
    pub fn original(&self, range: Range<usize>) -> Range<usize> {
        assert!(range.start < range.end, "empty normalized range");
        self.starts[range.start]..self.ends[range.end - 1]
    }

    /// The kinds of obfuscation undone inside the original byte range `range`.
    pub fn kinds(&self, range: Range<usize>) -> Vec<Kind> {
        let mut kinds: Vec<Kind> = self
            .edits
            .iter()
            .filter(|edit| range.start <= edit.range.start && edit.range.end <= range.end)
            .map(|edit| edit.kind)
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }
}

/// Whether the UTF-8 text contains a zero-width character, a full-width form or
/// the ideographic space: one byte pass before the character passes.
fn has_invisible_candidates(text: &str) -> bool {
    text.as_bytes().windows(3).any(|bytes| {
        matches!(
            bytes,
            [0xC2, 0xAD, _]
                | [0xE2, 0x80, 0x8B..=0x8D]
                | [0xE2, 0x81, 0xA0]
                | [0xE3, 0x80, 0x80]
                | [0xEF, 0xBB, 0xBF]
                | [0xEF, 0xBC, 0x81..=0xBF]
                | [0xEF, 0xBD, 0x80..=0x9E]
        )
    }) || text.ends_with('\u{00AD}')
}

fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'
    )
}

/// Full-width letter or digit (`０`–`９`, `Ａ`–`Ｚ`, `ａ`–`ｚ`).
fn is_full_width_alphanumeric(ch: char) -> bool {
    matches!(ch, '\u{FF10}'..='\u{FF19}' | '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}')
}

/// A character that occurs inside identifiers, addresses and numbers.
fn is_value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(ch, '.' | '@' | '+' | '-' | ':' | '/' | '_')
        || is_full_width_alphanumeric(ch)
        || matches!(ch, '＠' | '．' | '＋' | '－' | '：' | '／' | '＿')
}

/// Zero-width characters between two value characters (`firma​.de`, `+44​7700`).
/// Elsewhere they join emoji or shape scripts and stay.
fn zero_width(text: &str, edits: &mut Vec<Edit>) {
    let mut chars = text.char_indices().peekable();
    let mut previous = None;
    while let Some((start, ch)) = chars.next() {
        if !is_zero_width(ch) {
            previous = Some(ch);
            continue;
        }
        let mut end = start + ch.len_utf8();
        while let Some(&(next_start, next)) = chars.peek() {
            if !is_zero_width(next) {
                break;
            }
            end = next_start + next.len_utf8();
            chars.next();
        }
        let next = chars.peek().map(|&(_, next)| next);
        if previous.is_some_and(is_value_char) && next.is_some_and(is_value_char) {
            edits.push(Edit {
                range: start..end,
                with: Replacement::Remove,
                kind: Kind::ZeroWidth,
            });
        }
    }
}

/// Runs of full-width forms that contain a full-width letter or digit, and
/// full-width separators (`＠`, `．`, `－` …) between two ASCII letters or digits.
/// A lone full-width bracket, comma or colon in CJK prose stays.
fn full_width(text: &str, edits: &mut Vec<Edit>) {
    let is_full_width = |ch: char| matches!(ch, '\u{FF01}'..='\u{FF5E}' | '\u{3000}');
    let is_separator = |ch: char| matches!(ch, '＠' | '．' | '－' | '＋' | '：' | '／' | '＿');
    let mut run: Vec<(usize, char)> = Vec::new();
    let mut before = None;
    let mut flush = |run: &mut Vec<(usize, char)>, before: Option<char>, after: Option<char>| {
        let alphanumeric = |ch: Option<char>| ch.is_some_and(|ch| ch.is_ascii_alphanumeric());
        let separates = run.iter().all(|&(_, ch)| is_separator(ch))
            && alphanumeric(before)
            && alphanumeric(after);
        if separates || run.iter().any(|&(_, ch)| is_full_width_alphanumeric(ch)) {
            edits.extend(run.iter().map(|&(start, ch)| Edit {
                range: start..start + ch.len_utf8(),
                with: Replacement::Char(if ch == '\u{3000}' {
                    ' '
                } else {
                    char::from_u32(ch as u32 - 0xFEE0).expect("full-width form maps to ASCII")
                }),
                kind: Kind::FullWidth,
            }));
        }
        run.clear();
    };
    for (start, ch) in text.char_indices() {
        if is_full_width(ch) {
            run.push((start, ch));
        } else if !is_zero_width(ch) {
            if !run.is_empty() {
                flush(&mut run, before, Some(ch));
            }
            before = Some(ch);
        }
    }
    if !run.is_empty() {
        flush(&mut run, before, None);
    }
}

/// Defanged separators between ASCII letters or digits: `[.]`, `(.)`, `{.}`, the
/// same with `@`, and `[:]`.
fn defanged(text: &str, edits: &mut Vec<Edit>) {
    let bytes = text.as_bytes();
    for index in 2..bytes.len().saturating_sub(2) {
        let separator = bytes[index];
        if !matches!(separator, b'.' | b'@' | b':') {
            continue;
        }
        let closes = match bytes[index - 1] {
            b'[' => b']',
            b'(' => b')',
            b'{' => b'}',
            _ => continue,
        };
        if bytes[index + 1] == closes
            && bytes[index - 2].is_ascii_alphanumeric()
            && bytes[index + 2].is_ascii_alphanumeric()
        {
            edits.push(Edit {
                range: index - 1..index + 2,
                with: Replacement::Char(char::from(separator)),
                kind: Kind::Defanged,
            });
        }
    }
}

const SPELLED_AT: &str =
    r"[ \t]*[\[({<][ \t]*(?:at|ät|@)[ \t]*[\])}>][ \t]*|[ \t]+(?:at|ät|@)[ \t]+";
const SPELLED_DOT: &str =
    r"[ \t]*[\[({<][ \t]*(?:dot|punkt|\.)[ \t]*[\])}>][ \t]*|[ \t]+(?:dot|punkt|\.)[ \t]+";

/// Top-level domains that a spelled-out address without brackets must end in.
const COMMON_TLDS: &[&str] = &[
    "at", "be", "biz", "ch", "co", "com", "de", "dk", "edu", "es", "eu", "fr", "gov", "info", "io",
    "it", "li", "lu", "me", "net", "nl", "org", "pl", "se", "uk", "us",
];

/// Spelled-out e-mail separators: `name [at] host [dot] de`, `max punkt muster ät
/// firma punkt de`. The `@` token must sit between a local part and a domain with
/// at least one dot. Without brackets, the local part needs a separator of its
/// own (`.`, `_`, `-`, digit, a dot token) and the domain a common top-level
/// domain, so `docs at example dot com` stays prose. Brackets or a spaced `@`
/// mark the obfuscation without these conditions.
fn spelled_out(text: &str, edits: &mut Vec<Edit>) {
    static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
        let local = r"[A-Za-z0-9_%+\-]+";
        let label = r"[A-Za-z0-9\-]+";
        Regex::new(&format!(
            r"(?i)(?-u:\b)(?P<local>{local}(?:(?:{SPELLED_DOT}|\.){local})*)(?P<at>{SPELLED_AT})(?P<domain>{label}(?:(?:{SPELLED_DOT}|\.){label})+)(?-u:\b)"
        ))
        .unwrap()
    });
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(r"(?i)(?P<at>{SPELLED_AT})|(?P<dot>{SPELLED_DOT})")).unwrap()
    });
    if !text
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'[' | b'(' | b'{' | b'<'))
    {
        return;
    }
    for address in ADDRESS.captures_iter(text) {
        let whole = address.get(0).unwrap();
        let tokens: Vec<_> = TOKEN.captures_iter(whole.as_str()).collect();
        // Brackets or a spaced `@` mark the obfuscation; bare words may be prose.
        let explicit = tokens.iter().any(|token| {
            token
                .get(0)
                .unwrap()
                .as_str()
                .contains(['[', '(', '{', '<', '@'])
        });
        let local = address.name("local").unwrap().as_str();
        let domain = address.name("domain").unwrap().as_str();
        let tld = domain
            .rsplit(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
            .next()
            .unwrap_or_default();
        if !explicit
            && !(local.contains(['.', '_', '-'])
                || local.bytes().any(|byte| byte.is_ascii_digit())
                || local.contains(' ')
                || local.contains('\t'))
        {
            continue;
        }
        if !explicit && !COMMON_TLDS.contains(&tld.to_ascii_lowercase().as_str()) {
            continue;
        }
        if !tld.bytes().all(|byte| byte.is_ascii_alphabetic()) || tld.len() < 2 {
            continue;
        }
        for token in tokens {
            let (range, with) = match (token.name("at"), token.name("dot")) {
                (Some(at), _) => (at.range(), '@'),
                (_, Some(dot)) => (dot.range(), '.'),
                _ => continue,
            };
            edits.push(Edit {
                range: whole.start() + range.start..whole.start() + range.end,
                with: Replacement::Char(with),
                kind: Kind::SpelledOut,
            });
        }
    }
}

/// At least eight characters spaced one by one, six of them digits and the rest
/// capital letters (`4 1 1 1 …`, `D E 8 9 3 7 …`), optionally after `+`, not
/// inside a word or a longer number.
fn spaced_digits(text: &str, edits: &mut Vec<Edit>) {
    static SPACED: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\+?[0-9A-Z](?:[ \u{00A0}][0-9A-Z]){7,}").unwrap());
    for run in SPACED.find_iter(text) {
        let before = text[..run.start()].chars().next_back();
        let after = text[run.end()..].chars().next();
        if before.is_some_and(|ch| ch.is_alphanumeric() || ch == '+')
            || after.is_some_and(char::is_alphanumeric)
            || run.as_str().bytes().filter(u8::is_ascii_digit).count() < 6
        {
            continue;
        }
        edits.extend(
            run.as_str()
                .char_indices()
                .filter(|&(_, ch)| ch == ' ' || ch == '\u{00A0}')
                .map(|(offset, ch)| Edit {
                    range: run.start() + offset..run.start() + offset + ch.len_utf8(),
                    with: Replacement::Remove,
                    kind: Kind::SpacedDigits,
                }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(text: &str, level: Level) -> Deobfuscated {
        Deobfuscated::new(text, level).unwrap_or_else(|| panic!("{text:?} is not obfuscated"))
    }

    /// The original text behind `needle` in the normalized view.
    fn back<'a>(text: &'a str, view: &Deobfuscated, needle: &str) -> &'a str {
        let start = view.text.find(needle).unwrap();
        &text[view.original(start..start + needle.len())]
    }

    #[test]
    fn plain_text_needs_no_view() {
        for text in [
            "E-Mail: anna.berg@firma.de, IP 203.0.113.5",
            "Grüße aus Köln – Telefon 030 12345678",
            "Team 👩\u{200D}💻 und Familie 👨\u{200D}👩\u{200D}👧",
            "緊急連絡先：藤田（001 1282 6782）。",
            "Array a[.] und f(.) bleiben, Liste [1] [.] [2]",
        ] {
            assert!(
                Deobfuscated::new(text, Level::SpelledOut).is_none(),
                "{text}"
            );
        }
    }

    #[test]
    fn invisible_obfuscation_maps_back_to_the_original_span() {
        let cases = [
            (
                "E-Mail: anna.berg@firma\u{200B}.de",
                "anna.berg@firma.de",
                Kind::ZeroWidth,
            ),
            (
                "Mobile: +44\u{200B}7700\u{2060}900123",
                "+447700900123",
                Kind::ZeroWidth,
            ),
            (
                "Email: ada.wong＠northwind.com",
                "ada.wong@northwind.com",
                Kind::FullWidth,
            ),
            (
                "Quelle: １９８．５１．１００．７",
                "198.51.100.7",
                Kind::FullWidth,
            ),
            (
                "Telefon: ０３０\u{3000}１２３４５６７８",
                "030 12345678",
                Kind::FullWidth,
            ),
            (
                "Source IP: 203[.]0[.]113[.]5",
                "203.0.113.5",
                Kind::Defanged,
            ),
            (
                "Mail ops(@)example{.}com",
                "ops@example.com",
                Kind::Defanged,
            ),
        ];
        for (text, value, kind) in cases {
            // Every case puts the obfuscated value after the last space or tab.
            let start = text.rfind([' ', '\t']).unwrap() + 1;
            for level in [Level::Invisible, Level::SpelledOut] {
                let view = view(text, level);
                assert!(view.text.ends_with(value), "{text}: {:?}", view.text);
                assert_eq!(back(text, &view, value), &text[start..], "{text}");
                assert_eq!(view.kinds(start..text.len()), vec![kind], "{text}");
                assert!(view.kinds(0..start).is_empty(), "{text}");
            }
        }
    }

    #[test]
    fn spelled_out_separators_need_the_recall_level() {
        let cases = [
            (
                "Kontakt: max punkt mustermann ät firma punkt de",
                "max.mustermann@firma.de",
            ),
            (
                "Mail ada [at] northwind [dot] com today",
                "ada@northwind.com",
            ),
            (
                "Write to john.smith at example dot com.",
                "john.smith@example.com",
            ),
            ("Schreiben Sie an info @ firma . de", "info@firma.de"),
            ("Mail lena(at)musterfirma(punkt)de", "lena@musterfirma.de"),
        ];
        for (text, value) in cases {
            assert!(
                Deobfuscated::new(text, Level::Invisible).is_none(),
                "{text}"
            );
            let view = view(text, Level::SpelledOut);
            let original = back(text, &view, value);
            assert!(text.contains(original), "{text}");
            let start = text.find(original).unwrap();
            assert_eq!(
                view.kinds(start..start + original.len()),
                vec![Kind::SpelledOut],
                "{text}"
            );
        }
    }

    #[test]
    fn spelled_out_prose_is_not_an_address() {
        for text in [
            "Read the docs at example dot com.",
            "We met at noon. Then we left.",
            "Look at the dot product of both vectors.",
            "Infos unter firma punkt de.",
            "Treffpunkt ist ät der Rezeption.",
            "first.last at host dot invalidtld",
        ] {
            assert!(
                Deobfuscated::new(text, Level::SpelledOut).is_none(),
                "{text}: {:?}",
                Deobfuscated::new(text, Level::SpelledOut).map(|view| view.text)
            );
        }
    }

    #[test]
    fn spaced_digits_collapse_in_recall_only() {
        let text = "Karte: 4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 bitte";
        assert!(Deobfuscated::new(text, Level::Invisible).is_none());
        let view = view(text, Level::SpelledOut);
        assert_eq!(view.text, "Karte: 4111111111111111 bitte");
        assert_eq!(
            back(text, &view, "4111111111111111"),
            "4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1"
        );
        for text in [
            "Reihe 1 2 3 4 5 6 7",
            "Code A1 2 3 4 5 6 7 8 9",
            "Werte 12 3 4 5 6 7 8 9",
            "1 2 3 4 5 6 7 8 9x",
        ] {
            assert!(
                Deobfuscated::new(text, Level::SpelledOut).is_none(),
                "{text}"
            );
        }
    }

    #[test]
    fn the_byte_prefilter_finds_every_invisible_candidate() {
        let candidates = [
            '\u{00AD}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{3000}',
        ]
        .into_iter()
        .chain('\u{FF01}'..='\u{FF5E}');
        for ch in candidates {
            assert!(has_invisible_candidates(&format!("a{ch}")), "{ch:?}");
            assert!(has_invisible_candidates(&format!("{ch}b")), "{ch:?}");
        }
        for text in [
            "Grüße – „Köln“ İ ẞ 日本語 🔒",
            "\u{200A}\u{2061}\u{FF00}\u{FF5F}\u{3001}",
        ] {
            assert!(!has_invisible_candidates(text), "{text}");
        }
    }

    #[test]
    fn zero_width_outside_values_stays() {
        assert!(Deobfuscated::new("Hallo\u{200B} Welt", Level::SpelledOut).is_none());
        assert!(Deobfuscated::new("\u{FEFF}Name: Ada", Level::SpelledOut).is_none());
        let text = "Karte 4111\u{200B}\u{200C}1111";
        let view = view(text, Level::Invisible);
        assert_eq!(view.text, "Karte 41111111");
        assert_eq!(back(text, &view, "41111111"), "4111\u{200B}\u{200C}1111");
    }

    #[test]
    fn multibyte_text_around_the_value_keeps_its_offsets() {
        let text = "Grüße İ – Rückruf ０３０ １２３ – Danke";
        let view = view(text, Level::Invisible);
        assert_eq!(view.text, "Grüße İ – Rückruf 030 123 – Danke");
        assert_eq!(back(text, &view, "030 123"), "０３０ １２３");
        assert_eq!(back(text, &view, "Grüße İ"), "Grüße İ");
        assert_eq!(back(text, &view, "Danke"), "Danke");
    }
}
