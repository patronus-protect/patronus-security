// SPDX-License-Identifier: MIT OR Apache-2.0
//! D01: base64/base64url decoder pipeline with offset back-mapping.
//!
//! A secret that only appears transport-encoded (a Kubernetes `data:` value,
//! a CI variable, `echo … | base64 -d`, a JSON payload) is found in a decoded
//! view: every canonical base64 or base64url run whose bytes are printable
//! text is decoded, and runs inside the decoded text are decoded once more
//! (depth [`MAX_DEPTH`]). The DLP rules scan the view once; each finding maps
//! back to the encoded characters that hold its bytes, so a decoded match
//! points to the encoded range of the original text.
//!
//! Bounds: runs shorter than [`MIN_RUN`] or longer than [`MAX_RUN`] characters
//! are not decoded, and the view holds at most [`MAX_VIEW`] bytes.
use std::ops::Range;

use serde_json::Value;

use crate::detectors::validators::{base64_decode, Base64Kind};
use crate::detectors::NativeDetection;
use crate::EvidenceSpan;

/// Decoding layers: the original text decodes once, the decoded text once more.
pub(crate) const MAX_DEPTH: u8 = 2;
/// Shortest decoded run: 24 characters are 18 bytes, shorter than any token
/// format a rule reports on its own.
const MIN_RUN: usize = 24;
/// Longest decoded run (a base64-encoded config file or PEM key fits).
const MAX_RUN: usize = 64 * 1024;
/// Size limit of the decoded view per text.
const MAX_VIEW: usize = 128 * 1024;

/// The alphabet of an encoded run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Base64,
    Base64Url,
}

impl Encoding {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Base64Url => "base64url",
        }
    }
}

/// A decoded run: `view` in the decoded text holds the bytes of `source`, a
/// range of the original text (depth 1) or of the decoded text (depth 2).
#[derive(Debug)]
struct Segment {
    view: Range<usize>,
    source: Range<usize>,
    depth: u8,
    encoding: Encoding,
}

/// The decoded view of a text: its decoded runs, one per line.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub text: String,
    segments: Vec<Segment>,
}

impl Decoded {
    /// The decoded view of `text`, or `None` if no run decodes to text.
    pub fn new(text: &str) -> Option<Self> {
        let mut decoded = Self {
            text: String::new(),
            segments: Vec::new(),
        };
        decoded.decode_layer(text, 0, 1);
        let mut layer = 0..decoded.text.len();
        for depth in 2..=MAX_DEPTH {
            if layer.is_empty() {
                break;
            }
            let source = decoded.text[layer.clone()].to_string();
            let end = decoded.text.len();
            decoded.decode_layer(&source, layer.start, depth);
            layer = end..decoded.text.len();
        }
        (!decoded.segments.is_empty()).then_some(decoded)
    }

    /// Appends the decoded runs of `text`, which starts at `offset` of its
    /// source (the original text for depth 1, else this view).
    fn decode_layer(&mut self, text: &str, offset: usize, depth: u8) {
        for (run, encoding) in runs(text) {
            let Some(plain) = decode_text(&text[run.clone()], encoding) else {
                continue;
            };
            if self.text.len() + plain.len() + 1 > MAX_VIEW {
                return;
            }
            if !self.text.is_empty() {
                self.text.push('\n');
            }
            let start = self.text.len();
            self.text.push_str(&plain);
            self.segments.push(Segment {
                view: start..self.text.len(),
                source: offset + run.start..offset + run.end,
                depth,
                encoding,
            });
        }
    }

    /// The original range of the encoded characters that hold `range` of the
    /// view, with the encodings undone from the outermost; `None` for a range
    /// that is not inside one decoded run.
    pub fn original(&self, range: Range<usize>) -> Option<(Range<usize>, Vec<Encoding>)> {
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.view.start <= range.start && range.end <= segment.view.end)?;
        let start = range.start - segment.view.start;
        let end = range.end - segment.view.start;
        // Every 3 decoded bytes come from 4 encoded characters.
        let encoded = start / 3 * 4..(end.div_ceil(3) * 4).min(segment.source.len());
        let source = segment.source.start + encoded.start..segment.source.start + encoded.end;
        if segment.depth == 1 {
            return Some((source, vec![segment.encoding]));
        }
        let (original, mut encodings) = self.original(source)?;
        encodings.push(segment.encoding);
        Some((original, encodings))
    }
}

const fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// The candidate runs of `text`: maximal runs of base64/base64url characters
/// with up to two `=` of padding, of [`MIN_RUN`]..=[`MAX_RUN`] characters and
/// one alphabet.
fn runs(text: &str) -> impl Iterator<Item = (Range<usize>, Encoding)> + '_ {
    let bytes = text.as_bytes();
    let mut index = 0;
    std::iter::from_fn(move || {
        while index < bytes.len() {
            if !is_run_byte(bytes[index]) {
                index += 1;
                continue;
            }
            let start = index;
            let (mut standard, mut url) = (false, false);
            while index < bytes.len() && is_run_byte(bytes[index]) {
                standard |= matches!(bytes[index], b'+' | b'/');
                url |= matches!(bytes[index], b'-' | b'_');
                index += 1;
            }
            let mut end = index;
            while end < bytes.len() && end - index < 2 && bytes[end] == b'=' {
                end += 1;
            }
            // `key=value`: an `=` followed by more run characters is no padding.
            if end < bytes.len() && is_run_byte(bytes[end]) {
                end = index;
            }
            index = end;
            if (standard && url) || !(MIN_RUN..=MAX_RUN).contains(&(end - start)) {
                continue;
            }
            let encoding = if url {
                Encoding::Base64Url
            } else {
                Encoding::Base64
            };
            return Some((start..end, encoding));
        }
        None
    })
}

/// A byte that printable UTF-8 text may hold.
const fn is_text_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r') || (byte >= 0x20 && byte != 0x7f)
}

/// The decoded text of a canonical run, if it is printable UTF-8.
fn decode_text(run: &str, encoding: Encoding) -> Option<String> {
    // Most runs (identifiers, paths, hashes) decode to binary: their first
    // eight characters already reject them.
    let head = match encoding {
        Encoding::Base64 => Base64Kind::StandardUnpadded,
        Encoding::Base64Url => Base64Kind::UrlSafe,
    };
    if !base64_decode(&run[..8], head)?
        .into_iter()
        .all(is_text_byte)
    {
        return None;
    }
    let bytes = match encoding {
        Encoding::Base64 if run.ends_with('=') || run.len().is_multiple_of(4) => {
            base64_decode(run, Base64Kind::Standard)?
        }
        Encoding::Base64 => base64_decode(run, Base64Kind::StandardUnpadded)?,
        Encoding::Base64Url => base64_decode(run.trim_end_matches('='), Base64Kind::UrlSafe)?,
    };
    let text = String::from_utf8(bytes).ok()?;
    text.chars()
        .all(|ch| !ch.is_control() || matches!(ch, '\t' | '\n' | '\r'))
        .then_some(text)
}

/// A finding of the decoded view added to the detection.
struct Added {
    view: Range<usize>,
    original: Range<usize>,
    label: String,
    encodings: Vec<Encoding>,
}

/// Adds the findings of the decoded view to `detection`, on the encoded range
/// of their value. A finding whose encoded range overlaps a finding of the
/// original text, or an earlier decoded one, yields: the encoded value is
/// already reported. Its `matched_rules` entries carry original offsets and
/// `decoded`, the encodings undone from the outermost. `label_of` names the
/// entity group of a rule id.
pub(crate) fn merge(
    text: &str,
    mut detection: NativeDetection,
    decoded: NativeDetection,
    view: &Decoded,
    label_of: impl Fn(&str) -> Option<&'static str>,
) -> NativeDetection {
    let mut added: Vec<Added> = Vec::new();
    for span in decoded.evidence_spans {
        let Some((range, encodings)) = view.original(span.start_byte..span.end_byte) else {
            continue;
        };
        let overlaps = |start: usize, end: usize| start < range.end && range.start < end;
        if detection
            .evidence_spans
            .iter()
            .any(|other| overlaps(other.start_byte, other.end_byte))
            || added
                .iter()
                .any(|other| overlaps(other.original.start, other.original.end))
        {
            continue;
        }
        added.push(Added {
            view: span.start_byte..span.end_byte,
            original: range.clone(),
            label: span.label.clone(),
            encodings,
        });
        detection.evidence_spans.push(EvidenceSpan {
            text: text[range.clone()].to_string(),
            start_byte: range.start,
            end_byte: range.end,
            start_char: 0,
            end_char: 0,
            ..span
        });
    }
    if added.is_empty() {
        return detection;
    }

    let rules = decoded
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let start = rule["start_byte"].as_u64()? as usize;
            let end = rule["end_byte"].as_u64()? as usize;
            let label = label_of(rule["rule_id"].as_str()?)?;
            let Added {
                original,
                encodings,
                ..
            } = added
                .iter()
                .find(|added| added.view == (start..end) && added.label == label)?;
            let mut rule = rule.clone();
            rule["start_byte"] = original.start.into();
            rule["end_byte"] = original.end.into();
            for component in rule["components"].as_array_mut().into_iter().flatten() {
                let start = component["start_byte"].as_u64().unwrap_or_default() as usize;
                let end = component["end_byte"].as_u64().unwrap_or_default() as usize;
                let range = view
                    .original(start..end)
                    .map_or(original.clone(), |(range, _)| range);
                component["start_byte"] = range.start.into();
                component["end_byte"] = range.end.into();
            }
            rule["decoded"] = encodings.iter().map(|encoding| encoding.as_str()).collect();
            Some(rule)
        })
        .collect::<Vec<_>>();
    let matched_rules = detection
        .details
        .entry("matched_rules".into())
        .or_insert_with(|| serde_json::json!([]));
    if let Some(matched_rules) = matched_rules.as_array_mut() {
        matched_rules.extend(rules);
    }

    let spans = &mut detection.evidence_spans;
    spans.sort_by_key(|span| (span.start_byte, span.end_byte));
    crate::detectors::populate_char_offsets(text, spans);
    let result = &mut detection.result;
    if !spans.iter().any(|span| span.label == result.class_name) {
        result.class_name = spans[0].label.clone();
    }
    result.confidence = spans.iter().map(|span| span.score).fold(0.0, f64::max);
    detection
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64(raw: &[u8]) -> String {
        let mut encoded = String::new();
        for chunk in raw.chunks(3) {
            let bits = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for index in 0..4 {
                if index <= chunk.len() {
                    encoded.push(char::from(
                        ALPHABET[((bits >> (18 - 6 * index)) & 63) as usize],
                    ));
                } else {
                    encoded.push('=');
                }
            }
        }
        encoded
    }

    fn base64url(raw: &[u8]) -> String {
        base64(raw)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }

    #[test]
    fn decoded_ranges_map_back_to_the_encoded_characters() {
        let plain = "config: value=the-decoded-word here";
        let encoded = base64(plain.as_bytes());
        let text = format!("blob: {encoded}\n");
        let view = Decoded::new(&text).unwrap();
        assert_eq!(view.text, plain);
        let word = plain.find("the-decoded-word").unwrap();
        let (range, encodings) = view.original(word..word + 16).unwrap();
        assert_eq!(encodings, vec![Encoding::Base64]);
        // The encoded quads that hold the word: bytes 14..30 lie in quads 4..10.
        assert_eq!(range, 6 + 16..6 + 40);
        let (whole, _) = view.original(0..plain.len()).unwrap();
        assert_eq!(&text[whole], encoded);
    }

    #[test]
    fn base64url_and_unpadded_runs_decode() {
        let plain = "user-config?key=value&other=~~~~~~";
        let url = base64url(plain.as_bytes());
        assert!(url.contains('-') || url.contains('_'));
        let view = Decoded::new(&format!("\"{url}\"")).unwrap();
        assert_eq!(view.text, plain);
        assert_eq!(
            view.original(0..plain.len()).unwrap().1,
            vec![Encoding::Base64Url]
        );
        let unpadded = base64(b"seventeen-byte-text-xx")
            .trim_end_matches('=')
            .to_string();
        assert_eq!(
            Decoded::new(&unpadded).unwrap().text,
            "seventeen-byte-text-xx"
        );
    }

    #[test]
    fn recursion_stops_at_depth_two() {
        let plain = "the innermost plain text value";
        let once = base64(plain.as_bytes());
        let twice = base64(once.as_bytes());
        let thrice = base64(twice.as_bytes());

        let view = Decoded::new(&format!("x {twice} y")).unwrap();
        let inner = view.text.rfind(plain).unwrap();
        let (range, encodings) = view.original(inner..inner + plain.len()).unwrap();
        assert_eq!(encodings, vec![Encoding::Base64, Encoding::Base64]);
        assert_eq!(range, 2..2 + twice.len());

        let view = Decoded::new(&thrice).unwrap();
        assert!(!view.text.contains(plain), "depth 3 must stay encoded");
        assert!(view.text.contains(&once));
    }

    #[test]
    fn binary_short_mixed_and_non_canonical_runs_are_not_decoded() {
        let binary: Vec<u8> = (0u8..48)
            .map(|i| i.wrapping_mul(37).wrapping_add(200))
            .collect();
        let cases = [
            base64(&binary),
            // Too short.
            base64(b"short text"),
            // Identifiers, hex digests and paths decode to binary.
            "ThisIsAVeryLongCamelCaseIdentifierName".to_string(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
            "/usr/local/lib/python3.12/site-packages/patronus".to_string(),
            // Both alphabets in one run.
            "abcdefghijklmnopqrst+uvwxyz-ABCDEFG".to_string(),
            // Non-zero trailing bits.
            format!("{}B", &base64(b"twenty bytes of text")[..26]),
        ];
        for case in cases {
            assert!(Decoded::new(&case).is_none(), "{case:?}");
        }
    }

    #[test]
    fn padding_and_key_value_boundaries() {
        let encoded = base64(b"a value that needs one padding!!");
        assert!(encoded.ends_with('='));
        let text = format!("LONG_ENVIRONMENT_KEY_NAME={encoded}");
        let view = Decoded::new(&text).unwrap();
        assert_eq!(view.text, "a value that needs one padding!!");
        let (range, _) = view.original(0..view.text.len()).unwrap();
        assert_eq!(&text[range], encoded);
    }

    #[test]
    fn the_view_is_size_limited() {
        let run = base64(&[b'a'; 3 * 1024]);
        let text = vec![run; 64].join(" ");
        let view = Decoded::new(&text).unwrap();
        assert!(view.text.len() <= MAX_VIEW);
        assert!(view.segments.len() < 64);
        let long = base64(&vec![b'b'; MAX_RUN]);
        assert!(Decoded::new(&long).is_none());
    }
}
