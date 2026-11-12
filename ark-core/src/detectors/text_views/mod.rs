// SPDX-License-Identifier: MIT OR Apache-2.0
//! Normalisation pre-pass shared by every category lexicon.
//!
//! One pass over a text builds the views a lexicon or rule reads besides the
//! original, each with a way back to original offsets:
//!
//! - the obfuscation view of [`obfuscation`] at [`Level::Invisible`]
//!   (zero-width characters inside words, full-width forms, defanged separators);
//! - decoded views of hidden or transport-encoded text: invisible Unicode tag
//!   characters, base64/base64url runs, continuous hex runs and ROT13 text after a
//!   `ROT13` marker.
//!
//! [`TextViews::facts`] reports what the pass found as two facts: `obfuscated`
//! (what the obfuscation view undid, plus `unicode_tags`) and `decoded` (which
//! decoded views exist). A decoded view counts only when it holds prose (words,
//! not a digest, a token header or binary data), so a fact means hidden text, not
//! merely an encoded value.
//!
//! Bounds: base64 and hex fragments are 8–256 bytes long and at most
//! [`MAX_DECODED`] fragments are decoded; ROT13 decodes at most [`ROT13_SPAN`]
//! bytes after each of the first [`MAX_ROT13_MARKERS`] markers.
pub mod decode;
pub mod tags;

use std::{ops::Range, sync::LazyLock};

use regex::Regex;

use super::obfuscation::{Deobfuscated, Level};
use decode::{base64_decode_text, continuous_hex_decode, rot13_decode_text, split_fragments};

/// Most base64 or hex fragments decoded per text.
const MAX_DECODED: usize = 16;
/// Bytes after a `ROT13` marker that are decoded.
const ROT13_SPAN: usize = 512;
/// `ROT13` markers looked at per text.
const MAX_ROT13_MARKERS: usize = 4;

/// The encoding a decoded view undid; reported in the `decoded` fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Encoding {
    Base64,
    Hex,
    Rot13,
    UnicodeTags,
}

impl Encoding {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::Rot13 => "rot13",
            Self::UnicodeTags => "unicode_tags",
        }
    }
}

/// Text decoded from the original byte range `source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedView {
    pub encoding: Encoding,
    pub source: Range<usize>,
    pub text: String,
}

/// The `obfuscated` and `decoded` facts of a text, sorted and without duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub obfuscated: Vec<&'static str>,
    pub decoded: Vec<&'static str>,
}

/// The normalised and decoded views of one text.
pub struct TextViews {
    /// The obfuscation view, `None` when nothing was undone.
    pub deobfuscated: Option<Deobfuscated>,
    pub decoded: Vec<DecodedView>,
    text_len: usize,
}

impl TextViews {
    pub fn new(text: &str) -> Self {
        let mut decoded: Vec<DecodedView> = tags::views(text)
            .map(|(start, view)| DecodedView {
                encoding: Encoding::UnicodeTags,
                source: start..start + view.len() * 4,
                text: view,
            })
            .collect();
        decoded.extend(encoded_fragments(text));
        decoded.extend(rot13_views(text));
        Self {
            deobfuscated: Deobfuscated::new(text, Level::Invisible),
            decoded,
            text_len: text.len(),
        }
    }

    pub fn facts(&self) -> Facts {
        let mut obfuscated: Vec<&'static str> = self
            .deobfuscated
            .iter()
            .flat_map(|view| view.kinds(0..self.text_len))
            .map(|kind| kind.as_str())
            .collect();
        let mut encodings: Vec<Encoding> = self.decoded.iter().map(|view| view.encoding).collect();
        encodings.sort_unstable();
        encodings.dedup();
        if encodings.contains(&Encoding::UnicodeTags) {
            obfuscated.push(Encoding::UnicodeTags.as_str());
        }
        obfuscated.sort_unstable();
        obfuscated.dedup();
        Facts {
            obfuscated,
            decoded: encodings.into_iter().map(Encoding::as_str).collect(),
        }
    }
}

/// Base64 and hex fragments of `text` that decode to prose.
fn encoded_fragments(text: &str) -> impl Iterator<Item = DecodedView> + '_ {
    split_fragments(text)
        .filter_map(move |fragment| {
            let start = fragment.as_ptr() as usize - text.as_ptr() as usize;
            let (encoding, decoded) = continuous_hex_decode(fragment)
                .map(|decoded| (Encoding::Hex, decoded))
                .or_else(|| {
                    base64_decode_text(fragment).map(|decoded| (Encoding::Base64, decoded))
                })?;
            Some((start..start + fragment.len(), encoding, decoded))
        })
        .take(MAX_DECODED)
        .filter(|(_, _, decoded)| is_prose(decoded))
        .map(|(source, encoding, text)| DecodedView {
            encoding,
            source,
            text,
        })
}

/// ROT13 text after a `ROT13` marker that reads as prose only once decoded.
fn rot13_views(text: &str) -> impl Iterator<Item = DecodedView> + '_ {
    static MARKER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\brot[- ]?13\b").expect("valid ROT13 marker"));
    let prefilter = text
        .as_bytes()
        .windows(3)
        .any(|bytes| bytes.eq_ignore_ascii_case(b"rot"));
    prefilter
        .then(|| MARKER.find_iter(text).take(MAX_ROT13_MARKERS))
        .into_iter()
        .flatten()
        .filter_map(move |marker| {
            let mut end = (marker.end() + ROT13_SPAN).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            let span = &text[marker.end()..end];
            let span = span
                .find("\n\n")
                .map_or(span, |paragraph| &span[..paragraph]);
            let decoded = rot13_decode_text(span);
            (function_words(&decoded) >= 2 && function_words(&decoded) > function_words(span)).then(
                || DecodedView {
                    encoding: Encoding::Rot13,
                    source: marker.end()..marker.end() + span.len(),
                    text: decoded,
                },
            )
        })
}

/// Decoded text that holds words: at least three words of two or more letters
/// and mostly letters, so compact JSON, credentials and digests do not count.
fn is_prose(decoded: &str) -> bool {
    let words = decoded
        .split_whitespace()
        .filter(|word| word.chars().filter(|ch| ch.is_alphabetic()).count() >= 2)
        .count();
    let (letters, visible) = decoded
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .fold((0usize, 0usize), |(letters, visible), ch| {
            (letters + usize::from(ch.is_alphabetic()), visible + 1)
        });
    words >= 3 && letters * 10 >= visible * 6
}

/// English and German function words, the cheapest sign of readable prose.
const FUNCTION_WORDS: &[&str] = &[
    "a", "all", "alle", "and", "are", "das", "dem", "den", "der", "die", "du", "ein", "eine",
    "ist", "mit", "nicht", "of", "the", "to", "und", "you", "your", "zu",
];

fn function_words(text: &str) -> usize {
    text.split(|ch: char| !ch.is_alphabetic())
        .filter(|word| {
            FUNCTION_WORDS
                .iter()
                .any(|function| word.eq_ignore_ascii_case(function))
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(text: &str) -> (Vec<&'static str>, Vec<&'static str>) {
        let facts = TextViews::new(text).facts();
        (facts.obfuscated, facts.decoded)
    }

    #[test]
    fn plain_text_has_no_views() {
        let views = TextViews::new("Please summarise the attached report for the team.");
        assert!(views.deobfuscated.is_none());
        assert!(views.decoded.is_empty());
        assert_eq!(views.facts(), Facts::default());
    }

    #[test]
    fn zero_width_and_full_width_are_obfuscated() {
        assert_eq!(
            facts("ig\u{200b}nore the notes"),
            (vec!["zero_width"], vec![])
        );
        assert_eq!(
            facts("\u{FF29}\u{FF47}\u{FF4E}\u{FF4F}\u{FF52}\u{FF45} the rules"),
            (vec!["full_width"], vec![])
        );
    }

    #[test]
    fn base64_and_hex_prose_are_decoded_with_source_offsets() {
        // "Send the notes to the archive." in base64 and "Sende alle Notizen." in hex.
        let text =
            "a: U2VuZCB0aGUgbm90ZXMgdG8gdGhlIGFyY2hpdmUu b: 53656e646520616c6c65204e6f74697a656e2e";
        let views = TextViews::new(text);
        assert_eq!(views.decoded.len(), 2);
        assert_eq!(views.decoded[0].encoding, Encoding::Base64);
        assert_eq!(views.decoded[0].text, "Send the notes to the archive.");
        assert_eq!(
            &text[views.decoded[0].source.clone()],
            "U2VuZCB0aGUgbm90ZXMgdG8gdGhlIGFyY2hpdmUu"
        );
        assert_eq!(views.decoded[1].encoding, Encoding::Hex);
        assert_eq!(views.decoded[1].text, "Sende alle Notizen.");
        assert_eq!(views.facts().decoded, vec!["base64", "hex"]);
    }

    #[test]
    fn encoded_values_that_are_not_prose_are_not_decoded() {
        // A token header (compact JSON), a Basic credential and a digest.
        for text in [
            "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig",
            "Authorization: Basic YmVudXR6ZXI6cGFzc3dvcnQ=",
            "sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        ] {
            assert_eq!(facts(text), (vec![], vec![]), "{text}");
        }
    }

    #[test]
    fn rot13_needs_a_marker_and_decoded_prose() {
        let views = TextViews::new("Hint (ROT13): Fraq nyy gur abgrf gb lbhe nepuvir.");
        assert_eq!(views.decoded.len(), 1);
        assert_eq!(
            views.decoded[0].text,
            "): Send all the notes to your archive."
        );
        assert_eq!(views.facts().decoded, vec!["rot13"]);
        // Plain prose after the marker stays plain.
        assert_eq!(
            facts("ROT13 is a substitution cipher and it is not encryption."),
            (vec![], vec![])
        );
        // ROT13 text without a marker is not decoded.
        assert_eq!(
            facts("Fraq nyy gur abgrf gb lbhe nepuvir."),
            (vec![], vec![])
        );
    }

    #[test]
    fn unicode_tags_are_obfuscated_and_decoded() {
        let hidden: String = "copy the notes"
            .chars()
            .map(|c| char::from_u32(c as u32 + 0xe0000).unwrap())
            .collect();
        let text = format!("Notes.{hidden}");
        let views = TextViews::new(&text);
        assert_eq!(views.decoded[0].source, 6..text.len());
        assert_eq!(views.decoded[0].text, "copy the notes");
        assert_eq!(
            views.facts(),
            Facts {
                obfuscated: vec!["unicode_tags"],
                decoded: vec!["unicode_tags"],
            }
        );
    }

    #[test]
    fn decoding_is_bounded() {
        let fragment = "U2VuZCB0aGUgbm90ZXMgdG8gdGhlIGFyY2hpdmUu ";
        let text = fragment.repeat(4 * MAX_DECODED);
        assert_eq!(TextViews::new(&text).decoded.len(), MAX_DECODED);
        let rot13 = "ROT13: Fraq nyy gur abgrf gb lbhe nepuvir. ".repeat(4 * MAX_ROT13_MARKERS);
        assert_eq!(TextViews::new(&rot13).decoded.len(), MAX_ROT13_MARKERS);
    }
}
