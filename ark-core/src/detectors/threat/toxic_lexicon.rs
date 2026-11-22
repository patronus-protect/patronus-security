// SPDX-License-Identifier: MIT OR Apache-2.0
//! The hashed word lists of the `toxic_language` rules. No term is stored in
//! plain text: each family holds 64-bit FNV-1a hashes over a salt and the
//! normalised term, built by `scripts/l1_threat/toxic_lexicon.py`, which
//! normalises and hashes the same way.
use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

const LEXICON: &str = include_str!("toxic_lexicon.json");
const SALT: &[u8] = b"ark-toxic-v1\0";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Family {
    Insult,
    Dehumanise,
    ViolenceVerb,
}

impl Family {
    fn bit(self) -> u8 {
        match self {
            Family::Insult => 1,
            Family::Dehumanise => 2,
            Family::ViolenceVerb => 4,
        }
    }
}

#[derive(Deserialize)]
struct Lexicon {
    schema_version: u32,
    salt: String,
    families: HashMap<String, Vec<String>>,
}

/// Hash -> family bits, loaded once.
fn table() -> &'static HashMap<u64, u8> {
    static TABLE: OnceLock<HashMap<u64, u8>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let lexicon: Lexicon = serde_json::from_str(LEXICON).expect("valid toxic lexicon");
        assert_eq!(lexicon.schema_version, 1);
        assert_eq!(lexicon.salt.as_bytes(), &SALT[..SALT.len() - 1]);
        let mut table = HashMap::new();
        for (name, hashes) in &lexicon.families {
            let family = match name.as_str() {
                "insult" => Family::Insult,
                "dehumanise" => Family::Dehumanise,
                "violence_verb" => Family::ViolenceVerb,
                other => panic!("unknown toxic lexicon family {other}"),
            };
            for hash in hashes {
                let hash = u64::from_str_radix(hash, 16).expect("16-hex toxic lexicon hash");
                *table.entry(hash).or_insert(0) |= family.bit();
            }
        }
        table
    })
}

/// The lookup form of a word: NFKC, lowercase, umlauts and ß spelled out,
/// leetspeak digits and `@`/`$` folded to letters, `*` dropped.
pub(super) fn normalize(word: &str, out: &mut String) {
    out.clear();
    for c in word.nfkc().flat_map(char::to_lowercase) {
        match c {
            'ä' => out.push_str("ae"),
            'ö' => out.push_str("oe"),
            'ü' => out.push_str("ue"),
            'ß' => out.push_str("ss"),
            '0' => out.push('o'),
            '1' => out.push('i'),
            '3' => out.push('e'),
            '4' => out.push('a'),
            '5' => out.push('s'),
            '7' => out.push('t'),
            '@' => out.push('a'),
            '$' => out.push('s'),
            '*' => {}
            c => out.push(c),
        }
    }
}

pub(super) fn hash(normalized: &str) -> u64 {
    SALT.iter()
        .chain(normalized.as_bytes())
        .fold(0xcbf2_9ce4_8422_2325, |value, &byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

/// Words that cancel a later lexicon word of the same span: "you are not an
/// idiot", "du bist kein Idiot".
const NEGATIONS: &[&str] = &[
    "not", "no", "never", "nicht", "kein", "keine", "keiner", "nie", "niemals",
];

/// Whether a word of `span` (a word or a word pair) is in `family`, without
/// a negation before it.
pub(super) fn contains(span: &str, family: Family) -> bool {
    let table = table();
    let mut word = String::new();
    let mut previous = String::new();
    let mut pair = String::new();
    for raw in span
        .split(|c: char| !(c.is_alphanumeric() || matches!(c, '@' | '$' | '*' | '\'' | '-')))
        .filter(|w| !w.is_empty())
    {
        normalize(raw, &mut word);
        if NEGATIONS.contains(&word.as_str()) {
            return false;
        }
        let hit = |key: &str| {
            table
                .get(&hash(key))
                .is_some_and(|bits| bits & family.bit() != 0)
        };
        if !previous.is_empty() {
            pair.clear();
            pair.push_str(&previous);
            pair.push(' ');
            pair.push_str(&word);
            if hit(&pair) {
                return true;
            }
        }
        if hit(&word) {
            return true;
        }
        std::mem::swap(&mut previous, &mut word);
    }
    false
}

/// Target words of a threat: the addressed person, a third person or a group.
const TARGETS: &[&str] = &[
    "you", "him", "her", "them", "y'all", "dich", "euch", "ihn", "sie", "dir",
];

/// Whether the words of a threat name a target before or after its violence verb.
pub(super) fn names_target(span: &str) -> bool {
    span.split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .any(|w| TARGETS.iter().any(|t| t.eq_ignore_ascii_case(w)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_the_python_builder() {
        // Parity case of scripts/tests/test_l1_toxic_lexicon.py.
        let mut word = String::new();
        normalize("Exämple", &mut word);
        assert_eq!(word, "exaemple");
        assert_eq!(format!("{:016x}", hash(&word)), "c16d2a5e7fcd8362");
        normalize("3x@mp1e*", &mut word);
        assert_eq!(word, "exampie");
    }

    #[test]
    fn lexicon_loads_every_family() {
        let table = table();
        for family in [Family::Insult, Family::Dehumanise, Family::ViolenceVerb] {
            assert!(table.values().any(|bits| bits & family.bit() != 0));
        }
    }

    #[test]
    fn words_are_looked_up_folded_and_negation_cancels() {
        assert!(contains(" a pathetic 1d10t", Family::Insult));
        assert!(contains(" ein erbärmlicher Trottel", Family::Insult));
        assert!(!contains(" not an idiot", Family::Insult));
        assert!(!contains(" kein Idiot", Family::Insult));
        assert!(!contains(" a great colleague", Family::Insult));
        assert!(contains(" nothing but vermin", Family::Dehumanise));
        assert!(!contains(" nothing but vermin", Family::Insult));
        assert!(contains(" dich umbringen", Family::ViolenceVerb));
        assert!(names_target(" kill you"));
        assert!(!names_target(" kill the process"));
    }
}
