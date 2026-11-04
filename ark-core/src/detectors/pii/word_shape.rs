// SPDX-License-Identifier: MIT OR Apache-2.0
//! Word shape gate of the PII rules (H06-4).
//!
//! Many PII rules match one whole token: `\b[A-Z]{5}[0-9]{4}[A-Z]\b` (PAN),
//! `\b[A-Z0-9]{18}[0-9]{2}\b` (LEI). Such a match is a maximal run of ASCII
//! word characters (`[0-9A-Za-z_]`) of a bounded length whose characters fall
//! in the rule's kinds (digit, upper, lower, underscore) and that holds the
//! kinds every match holds (the digits of `[0-9]{4}`). One pass over the text
//! records which run lengths occur per kind set ([`WordShapes`]); a rule whose
//! shape ([`WordShape`]) occurs nowhere has no match and is not searched.
use regex_syntax::hir::{Class, Hir, HirKind, Look};

const DIGIT: u8 = 1;
const UPPER: u8 = 2;
const LOWER: u8 = 4;
const UNDERSCORE: u8 = 8;

/// Run lengths from this one on share the last bit of a length set.
const LONG: usize = 63;

/// The kind bit of an ASCII word byte, `0` for any other byte.
const fn kind(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => DIGIT,
        b'A'..=b'Z' => UPPER,
        b'a'..=b'z' => LOWER,
        b'_' => UNDERSCORE,
        _ => 0,
    }
}

const KINDS: [u8; 256] = {
    let mut kinds = [0; 256];
    let mut byte = 0;
    while byte < 256 {
        kinds[byte] = kind(byte as u8);
        byte += 1;
    }
    kinds
};

fn length_bit(len: usize) -> u64 {
    1 << len.min(LONG)
}

/// The maximal ASCII word runs of one text: per set of kinds, the lengths of
/// the runs made of exactly these kinds (bit `n`, lengths from 63 on in bit 63).
pub struct WordShapes {
    lengths: [u64; 16],
}

impl WordShapes {
    pub fn of(text: &str) -> Self {
        let mut lengths = [0; 16];
        let (mut len, mut kinds) = (0, 0);
        for &byte in text.as_bytes() {
            let kind = KINDS[usize::from(byte)];
            if kind == 0 {
                if len > 0 {
                    lengths[usize::from(kinds)] |= length_bit(len);
                    (len, kinds) = (0, 0);
                }
            } else {
                len += 1;
                kinds |= kind;
            }
        }
        if len > 0 {
            lengths[usize::from(kinds)] |= length_bit(len);
        }
        Self { lengths }
    }

    /// Whether a run of `shape` occurs.
    pub fn contain(&self, shape: WordShape) -> bool {
        let max = shape.max.unwrap_or(LONG).min(LONG);
        let wanted = (u64::MAX >> (LONG - max)) & !((1 << shape.min.min(LONG)) - 1);
        self.lengths.iter().enumerate().any(|(kinds, &lengths)| {
            let kinds = kinds as u8;
            kinds & !shape.kinds == 0
                && kinds & shape.required == shape.required
                && lengths & wanted != 0
        })
    }
}

/// A rule that matches exactly one maximal ASCII word run of `min..=max`
/// characters (`None`: unbounded), each of one of `kinds`, with a character
/// of each of `required`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordShape {
    min: usize,
    max: Option<usize>,
    kinds: u8,
    required: u8,
}

/// The shape of the empty part, the start of a concatenation.
const EMPTY: WordShape = WordShape {
    min: 0,
    max: Some(0),
    kinds: 0,
    required: 0,
};

impl WordShape {
    /// The shape of `pattern` if every match is one whole word run: word
    /// boundaries at both ends and only ASCII word characters between them.
    pub fn of(pattern: &str) -> Option<Self> {
        let hir = regex_syntax::parse(pattern).ok()?;
        let HirKind::Concat(parts) = hir.kind() else {
            return None;
        };
        let [first, inner @ .., last] = parts.as_slice() else {
            return None;
        };
        if !boundary(first) || !boundary(last) {
            return None;
        }
        let mut shape = EMPTY;
        for part in inner {
            shape = shape.then(word(part)?);
        }
        (shape.min > 0).then_some(shape)
    }

    fn then(self, next: Self) -> Self {
        Self {
            min: self.min + next.min,
            max: self.max.zip(next.max).map(|(a, b)| a + b),
            kinds: self.kinds | next.kinds,
            required: self.required | next.required,
        }
    }
}

/// A word boundary: next to a word character it is the end of its run.
fn boundary(hir: &Hir) -> bool {
    matches!(
        hir.kind(),
        HirKind::Look(Look::WordAscii | Look::WordUnicode)
    )
}

/// The shape of a part made of ASCII word characters only.
fn word(hir: &Hir) -> Option<WordShape> {
    match hir.kind() {
        HirKind::Literal(literal) => {
            let kinds = literal
                .0
                .iter()
                .try_fold(0, |kinds, &byte| Some(kinds | nonzero(kind(byte))?))?;
            Some(WordShape {
                min: literal.0.len(),
                max: Some(literal.0.len()),
                kinds,
                required: kinds,
            })
        }
        HirKind::Class(class) => {
            let ranges: Vec<(u32, u32)> = match class {
                Class::Unicode(class) => class
                    .ranges()
                    .iter()
                    .map(|range| (range.start() as u32, range.end() as u32))
                    .collect(),
                Class::Bytes(class) => class
                    .ranges()
                    .iter()
                    .map(|range| (u32::from(range.start()), u32::from(range.end())))
                    .collect(),
            };
            let kinds = ranges.iter().try_fold(0, |kinds, &(start, end)| {
                (start..=end).try_fold(kinds, |kinds, code| {
                    Some(kinds | nonzero(kind(u8::try_from(code).ok()?))?)
                })
            })?;
            Some(WordShape {
                min: 1,
                max: Some(1),
                kinds,
                // A class of one kind requires it; a wider one none.
                required: if kinds.is_power_of_two() { kinds } else { 0 },
            })
        }
        HirKind::Capture(capture) => word(&capture.sub),
        HirKind::Repetition(repetition) => {
            let sub = word(&repetition.sub)?;
            Some(WordShape {
                min: sub.min * repetition.min as usize,
                max: repetition
                    .max
                    .zip(sub.max)
                    .map(|(count, max)| count as usize * max),
                kinds: sub.kinds,
                required: if repetition.min > 0 { sub.required } else { 0 },
            })
        }
        HirKind::Concat(parts) => parts
            .iter()
            .try_fold(EMPTY, |shape, part| Some(shape.then(word(part)?))),
        HirKind::Alternation(branches) => {
            let shapes = branches.iter().map(word).collect::<Option<Vec<_>>>()?;
            Some(WordShape {
                min: shapes.iter().map(|shape| shape.min).min()?,
                max: shapes
                    .iter()
                    .map(|shape| shape.max)
                    .try_fold(0, |max, next| Some(max.max(next?))),
                kinds: shapes.iter().fold(0, |kinds, shape| kinds | shape.kinds),
                required: shapes
                    .iter()
                    .fold(u8::MAX, |required, shape| required & shape.required),
            })
        }
        HirKind::Empty | HirKind::Look(_) => None,
    }
}

fn nonzero(kind: u8) -> Option<u8> {
    (kind != 0).then_some(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(min: usize, max: Option<usize>, kinds: u8, required: u8) -> Option<WordShape> {
        Some(WordShape {
            min,
            max,
            kinds,
            required,
        })
    }

    #[test]
    fn whole_token_rules_have_a_shape() {
        assert_eq!(
            WordShape::of(r"(?-u:\b)[A-Z]{5}[0-9]{4}[A-Z](?-u:\b)"),
            shape(10, Some(10), UPPER | DIGIT, UPPER | DIGIT)
        );
        assert_eq!(
            WordShape::of(r"(?-u:\b)(?:[0-9]{3}[A-Z]{2}|[0-9]{10,12})(?-u:\b)"),
            shape(5, Some(12), UPPER | DIGIT, DIGIT)
        );
        assert_eq!(
            WordShape::of(r"\b(?P<value>ab_[0-9]+)\b"),
            shape(
                4,
                None,
                LOWER | UNDERSCORE | DIGIT,
                LOWER | UNDERSCORE | DIGIT
            )
        );
        // Case folding keeps ASCII classes ASCII without Unicode.
        assert_eq!(
            WordShape::of(r"(?i-u)\b[ST][0-9]{7}[A-Z]\b"),
            shape(9, Some(9), UPPER | LOWER | DIGIT, DIGIT)
        );
    }

    #[test]
    fn rules_beyond_one_token_have_no_shape() {
        for pattern in [
            r"(?-u:\b)[0-9]{6}[-+]?[0-9]{4}(?-u:\b)",
            r"(?-u:\b)[0-9]{6}(?-u:\b)[0-9]{4}(?-u:\b)",
            r"[A-Z]{5}[0-9]{4}(?-u:\b)",
            r"(?-u:\b)[A-Z]{5}[0-9]{4}",
            r"(?i)\b[A-Z]{5}\b",
            r"\b\w{5}\b",
            r"\b[0-9]*\b",
        ] {
            assert_eq!(WordShape::of(pattern), None, "{pattern}");
        }
    }

    #[test]
    fn a_shape_occurs_only_as_a_whole_run_of_its_kinds() {
        let pan = WordShape::of(r"(?-u:\b)[A-Z]{5}[0-9]{4}[A-Z](?-u:\b)").unwrap();
        for text in ["PAN ABCDE1234F.", "ABCDE1234F", "x\u{e4}ABCDE1234F\u{e4}"] {
            assert!(WordShapes::of(text).contain(pan), "{text}");
        }
        for text in ["ABCDE1234FG", "ABCDE_1234", "abcde1234f", "ABCDE-1234F", ""] {
            assert!(!WordShapes::of(text).contain(pan), "{text}");
        }
        // Nine letters are no NRIC: the seven digits are missing.
        let nric = WordShape::of(r"(?i-u)\b[ST][0-9]{7}[A-Z]\b").unwrap();
        assert!(WordShapes::of("s1234567d").contain(nric));
        assert!(!WordShapes::of("Steuernummer abcdefghi").contain(nric));
        let long = WordShape::of(r"\b[0-9]{70,80}\b").unwrap();
        assert!(WordShapes::of(&"7".repeat(100)).contain(long));
        assert!(!WordShapes::of(&"7".repeat(62)).contain(long));
        let open = WordShape::of(r"\b[0-9]{2,}\b").unwrap();
        assert!(WordShapes::of("a 12").contain(open));
        assert!(!WordShapes::of("a 1 b").contain(open));
    }
}
