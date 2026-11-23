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

/// Walks the words of `span` until `visit` decides. `visit` gets each raw
/// word, whether it is a negation and the family bits of the word or of the
/// pair it ends. An undecided walk returns `visit(None)`.
fn walk(span: &str, mut visit: impl FnMut(Option<(&str, bool, u8)>) -> Option<bool>) -> bool {
    let table = table();
    let mut word = String::new();
    let mut previous = String::new();
    let mut pair = String::new();
    for raw in span
        .split(|c: char| !(c.is_alphanumeric() || matches!(c, '@' | '$' | '*' | '\'' | '-')))
        .filter(|w| !w.is_empty())
    {
        normalize(raw, &mut word);
        let bits = |key: &str| table.get(&hash(key)).copied().unwrap_or(0);
        let mut family = bits(&word);
        if !previous.is_empty() {
            pair.clear();
            pair.push_str(&previous);
            pair.push(' ');
            pair.push_str(&word);
            family |= bits(&pair);
        }
        if let Some(decided) = visit(Some((raw, NEGATIONS.contains(&word.as_str()), family))) {
            return decided;
        }
        std::mem::swap(&mut previous, &mut word);
    }
    visit(None).unwrap_or(false)
}

/// Whether a word of `span` (a word or a word pair) is in `family`, without
/// a negation before it.
pub(super) fn contains(span: &str, family: Family) -> bool {
    walk(span, |word| match word? {
        (_, true, _) => Some(false),
        (_, _, bits) if bits & family.bit() != 0 => Some(true),
        _ => None,
    })
}

/// Subjects that deny what follows when a verb of saying or believing comes
/// after them: "nobody thinks you are …", "niemand sagt, du bist …".
const DENYING_SUBJECTS: &[&str] = &["nobody", "noone", "niemand", "keiner"];
const BELIEF_VERBS: &[&str] = &[
    "think",
    "thinks",
    "thought",
    "believe",
    "believes",
    "say",
    "says",
    "said",
    "denkt",
    "glaubt",
    "sagt",
    "meint",
    "findet",
    "behauptet",
];

/// Conjunctions that open a new, affirmed clause after a denial: anywhere
/// ("nobody thinks so but you are …"), or after a comma ("…, and I will …").
const ADVERSATIVES: &[&str] = &["but", "yet", "aber", "sondern", "doch", "jedoch"];
const COORDINATORS: &[&str] = &["and", "or", "so", "und", "oder"];

/// Whether `lead` (the sentence before a match) holds a denying subject
/// ("nobody", "no one", "niemand", "keiner") followed by a verb of saying or
/// believing, and no later conjunction opens a new clause that the denial
/// does not govern.
pub(super) fn denied_by_subject(lead: &str) -> bool {
    let mut subject = false;
    let mut denied = false;
    let mut previous_no = false;
    for (clause, part) in lead.split(',').enumerate() {
        for (i, word) in part
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .enumerate()
        {
            if is_one_of(ADVERSATIVES, word)
                || (clause > 0 && i == 0 && is_one_of(COORDINATORS, word))
            {
                subject = false;
                denied = false;
            }
            denied |= subject && is_one_of(BELIEF_VERBS, word);
            subject |= is_one_of(DENYING_SUBJECTS, word)
                || (previous_no && word.eq_ignore_ascii_case("one"));
            previous_no = word.eq_ignore_ascii_case("no");
        }
    }
    denied
}

/// Target words of a threat: the addressed person, a third person or a group.
const TARGETS: &[&str] = &[
    "you", "him", "her", "them", "y'all", "dich", "euch", "ihn", "sie", "dir",
];

/// Words that open another object after a verb: "help you kill the process".
const DETERMINERS: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "your", "his", "its", "our", "their",
    "some", "any", "every",
];

fn is_one_of(words: &[&str], word: &str) -> bool {
    words.iter().any(|w| w.eq_ignore_ascii_case(word))
}

/// Whether `span` holds a violence verb, without a negation before it, whose
/// object is a target: the target right after the verb ("kill you"), or
/// before it when no determiner opens another object after the verb ("dich
/// umbringen", but not "help you kill the process").
pub(super) fn threatens_target(span: &str) -> bool {
    let mut target_before = false;
    // After a violence verb: whether a target came before it.
    let mut after_verb: Option<bool> = None;
    walk(span, |word| {
        let Some((raw, negation, bits)) = word else {
            return after_verb;
        };
        if let Some(bound) = after_verb.take() {
            if is_one_of(TARGETS, raw) || (bound && !is_one_of(DETERMINERS, raw)) {
                return Some(true);
            }
        }
        if negation {
            return Some(false);
        }
        if bits & Family::ViolenceVerb.bit() != 0 {
            after_verb = Some(target_before);
        } else {
            target_before |= is_one_of(TARGETS, raw);
        }
        None
    })
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
    }

    #[test]
    fn a_threat_binds_its_violence_verb_to_a_target() {
        assert!(threatens_target(" kill you"));
        assert!(threatens_target(" dich nach der Arbeit umbringen"));
        assert!(threatens_target(" dich umbringen und abhauen"));
        assert!(!threatens_target(" kill the process"));
        assert!(!threatens_target(" help you kill the process"));
        assert!(!threatens_target(" show you how to kill a process"));
        assert!(!threatens_target(" never kill you"));
    }
}
