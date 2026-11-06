// SPDX-License-Identifier: MIT OR Apache-2.0
//! C01: BIP39 mnemonic seed phrases.
//!
//! A phrase is 12, 15, 18, 21 or 24 words of one official word list (English,
//! Italian, Portuguese, Czech, Spanish, French), each word an 11-bit index;
//! the Spanish and French words count with or without their accents, in NFC
//! or NFD, as the BIP39 word list notes allow. The indices spell
//! the entropy and a checksum of its SHA-256 (BIP39). Words stand in a line,
//! numbered or one per line, so the words may be separated by whitespace,
//! commas, quotes and list numbers (`1. abandon 2. ability`).
//!
//! The rule's regex has no literal to search for, so [`phrases`] finds the
//! candidates in one pass over the words of the text: a run of list words of
//! one language, at most [`MAX_RUN`] long (a longer run is a word list, not a
//! phrase), and in it the windows of a phrase length whose checksum holds.
//! [`is_seed_phrase`] checks a value in full; [`has_seed_context`] asks for a
//! context of the shorter phrases, whose checksum has 4 to 6 bits.
use rustc_hash::FxHashMap;
use std::{ops::Range, sync::LazyLock};

/// The supported word lists, in the order of the language bits.
const LISTS: [(&str, &str); 6] = [
    ("english", include_str!("bip39/english.txt")),
    ("italian", include_str!("bip39/italian.txt")),
    ("portuguese", include_str!("bip39/portuguese.txt")),
    ("czech", include_str!("bip39/czech.txt")),
    ("spanish", include_str!("bip39/spanish.txt")),
    ("french", include_str!("bip39/french.txt")),
];

/// Words per phrase, longest first.
const LENGTHS: [usize; 5] = [24, 21, 18, 15, 12];

/// Most words and bytes (entropy and checksum) of a phrase.
const MAX_WORDS: usize = LENGTHS[0];
const MAX_BYTES: usize = MAX_WORDS * 11 / 8;

/// Most letters of a list word.
const MAX_LETTERS: usize = 9;

/// Longest run of list words that may hold a phrase: a phrase and a few list
/// words around it (`wallet`, `secret`, `phrase` are list words).
const MAX_RUN: usize = 27;

/// Longest separator between two words of a phrase.
const MAX_GAP: usize = 24;

/// Phrases from this length on need no context: an 8-bit or longer checksum
/// leaves at most one random word run in 64 valid.
const CONTEXT_FREE_LEN: usize = 18;

/// Entropies of the published BIP39 test vectors (trezor/python-mnemonic
/// `vectors.json`, the same for every language): documentation and test
/// suites quote their phrases.
const TEST_VECTOR_HEX: [&str; 24] = [
    "00000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
    "23db8160a31d3e0dca3688ed941adbf3",
    "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
    "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "80808080808080808080808080808080",
    "808080808080808080808080808080808080808080808080",
    "8080808080808080808080808080808080808080808080808080808080808080",
    "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
    "9e885d952ad362caeb4efe34a8e91bd2",
    "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
    "c0ba5a8e914111210f2bd131f3d5e08d",
    "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
    "f30f8c1da665478f49b001d94c5fc452",
    "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
    "ffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// [`TEST_VECTOR_HEX`] as bytes.
static TEST_VECTOR_ENTROPIES: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    TEST_VECTOR_HEX
        .iter()
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex entropy"))
                .collect()
        })
        .collect()
});

/// Every word of every list without its accents: per language a bit and the
/// word's index. The unaccented Spanish and French words are unique per list.
static LEXICON: LazyLock<FxHashMap<String, Entries>> = LazyLock::new(|| {
    let mut lexicon = FxHashMap::<String, Entries>::default();
    for (language, (_, list)) in LISTS.iter().enumerate() {
        for (index, word) in list.lines().enumerate() {
            let mut letters = [0; MAX_LETTERS];
            let key = fold(word.as_bytes(), &mut letters).expect("list word");
            let entries = lexicon
                .entry(key.to_string())
                .or_insert((0, [0; LISTS.len()]));
            entries.0 |= 1 << language;
            entries.1[language] = index as u16;
        }
    }
    lexicon
});

/// The languages of a word as bits and its index per language.
type Entries = (u8, [u16; LISTS.len()]);

/// The word lists by language, for encoding.
static WORDS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(|| {
    LISTS
        .iter()
        .map(|(_, list)| list.lines().collect())
        .collect()
});

/// The BIP39 mnemonic of `entropy` (16 to 32 bytes, a multiple of 4) in the
/// word list `language` (`english`, `italian`, `portuguese`, `czech`,
/// `spanish`, `french`; accented words in NFD, as in the published lists).
pub fn mnemonic(language: &str, entropy: &[u8]) -> Option<String> {
    let list = LISTS.iter().position(|(name, _)| *name == language)?;
    if !(16..=32).contains(&entropy.len()) || !entropy.len().is_multiple_of(4) {
        return None;
    }
    let checksum = ring::digest::digest(&ring::digest::SHA256, entropy);
    let mut bits = entropy.to_vec();
    bits.push(checksum.as_ref()[0]);
    let count = (entropy.len() * 8 + entropy.len() / 4) / 11;
    let words: Vec<_> = (0..count)
        .map(|word| WORDS[list][usize::from(bits_at(&bits, word * 11))])
        .collect();
    Some(words.join(" "))
}

/// The 11 bits of `bytes` from bit `start` on, big-endian.
fn bits_at(bytes: &[u8], start: usize) -> u16 {
    (start..start + 11).fold(0, |value, bit| {
        value << 1 | u16::from(bytes[bit / 8] >> (7 - bit % 8) & 1)
    })
}

/// Whether the word indices form a phrase with a valid checksum that is no
/// published test vector and repeats at most two words.
fn valid_indices(indices: &[u16]) -> bool {
    if !LENGTHS.contains(&indices.len()) {
        return false;
    }
    let mut sorted = [0u16; MAX_WORDS];
    let sorted = &mut sorted[..indices.len()];
    sorted.copy_from_slice(indices);
    sorted.sort_unstable();
    let distinct = 1 + sorted.windows(2).filter(|pair| pair[0] != pair[1]).count();
    if distinct + 2 < indices.len() {
        return false;
    }
    let total = indices.len() * 11;
    let checksum_bits = total / 33;
    let mut bytes = [0u8; MAX_BYTES];
    for (word, index) in indices.iter().enumerate() {
        for bit in 0..11 {
            if index >> (10 - bit) & 1 == 1 {
                let at = word * 11 + bit;
                bytes[at / 8] |= 0x80 >> (at % 8);
            }
        }
    }
    let entropy = &bytes[..(total - checksum_bits) / 8];
    let digest = ring::digest::digest(&ring::digest::SHA256, entropy);
    let expected = digest.as_ref()[0] >> (8 - checksum_bits);
    let actual = bytes[entropy.len()] >> (8 - checksum_bits);
    if expected != actual {
        return false;
    }
    !TEST_VECTOR_ENTROPIES
        .iter()
        .any(|vector| vector.as_slice() == entropy)
}

/// A word of the text: its range and its list entries.
struct Word {
    range: Range<usize>,
    mask: u8,
    indices: [u16; LISTS.len()],
}

/// The phrases of `text`. A word is a maximal run of 3 to 9 lowercase
/// letters ([`letter_len`]) between characters that are no letters, digits
/// or `_`. A first pass finds runs of at least 12 words, each two separated
/// by at most [`MAX_GAP`] bytes of whitespace, commas, digits, `.`, `)`, `:`,
/// quotes and `-` with at least one space or comma ([`GAP_BYTES`]), without
/// looking the words up; only their words are looked up (without accents,
/// [`fold`]) and split into runs of list words that share a language.
fn scan(text: &str, phrases: &mut Vec<Range<usize>>) {
    let bytes = text.as_bytes();
    let mut shaped: Vec<Range<usize>> = Vec::new();
    // The gap since the last word: its length, whether it holds a space or
    // comma, and whether it holds only gap bytes.
    let (mut gap_len, mut gap_split, mut gap_clean) = (0usize, false, false);
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if letter_len(bytes, at) == 0 {
            match GAP_BYTES[usize::from(byte)] {
                Gap::Split => gap_split = true,
                Gap::Plain => {}
                Gap::No => gap_clean = false,
            }
            gap_len += 1;
            at += 1;
            continue;
        }
        let start = at;
        let mut letters = 0;
        loop {
            let len = letter_len(bytes, at);
            if len == 0 {
                break;
            }
            letters += usize::from(!matches!(bytes[at], 0xcc | 0xcd));
            at += len;
        }
        let word = (3..=MAX_LETTERS).contains(&letters)
            && start
                .checked_sub(1)
                .is_none_or(|before| is_edge(bytes[before]))
            && bytes.get(at).is_none_or(|after| is_edge(*after));
        let joins = word && !shaped.is_empty() && gap_clean && gap_split && gap_len <= MAX_GAP;
        if !joins {
            list_runs(text, &shaped, phrases);
            shaped.clear();
        }
        if word {
            shaped.push(start..at);
        }
        (gap_len, gap_split, gap_clean) = (0, false, word);
    }
    list_runs(text, &shaped, phrases);
}

/// The bytes of the letter at `at`: 1 for an ASCII lowercase letter, 2 for
/// a lowercase Latin-1 letter with a diacritic (NFC `é`, [`LATIN1_BASE`]) or
/// a combining diacritic (NFD, U+0300 to U+036F), else 0 (also past the end).
fn letter_len(bytes: &[u8], at: usize) -> usize {
    match (bytes.get(at), bytes.get(at + 1)) {
        (Some(byte), _) if byte.is_ascii_lowercase() => 1,
        (Some(0xc3), Some(&next))
            if (0xa0..=0xbf).contains(&next) && LATIN1_BASE[usize::from(next - 0xa0)] != 0 =>
        {
            2
        }
        (Some(0xcc), Some(0x80..=0xbf)) | (Some(0xcd), Some(0x80..=0xaf)) => 2,
        _ => 0,
    }
}

/// The base letter of U+00E0 to U+00FF (UTF-8 `c3 a0` to `c3 bf`), 0 for no
/// letter with a diacritic.
const LATIN1_BASE: [u8; 32] = *b"aaaaaa\0ceeeeiiii\0nooooo\0\0uuuuy\0y";

/// `word` (letters as in [`letter_len`]) without its diacritics, written to
/// `letters`; `None` for more than [`MAX_LETTERS`] letters.
fn fold<'a>(word: &[u8], letters: &'a mut [u8; MAX_LETTERS]) -> Option<&'a str> {
    let (mut at, mut len) = (0, 0);
    while at < word.len() {
        let letter = match word[at] {
            0xc3 => LATIN1_BASE[usize::from(word[at + 1] - 0xa0)],
            0xcc | 0xcd => {
                at += 2;
                continue;
            }
            byte => byte,
        };
        *letters.get_mut(len)? = letter;
        len += 1;
        at += if word[at] == 0xc3 { 2 } else { 1 };
    }
    std::str::from_utf8(&letters[..len]).ok()
}

/// Whether `byte` may border a word: no letter, digit, `_` or byte of a
/// non-ASCII character.
fn is_edge(byte: u8) -> bool {
    !(byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80)
}

/// What a byte is in a gap between two words of a phrase.
#[derive(Clone, Copy)]
enum Gap {
    /// Whitespace or a comma, which separate words.
    Split,
    /// A digit or list punctuation (`.`, `)`, `:`, quotes, `-`).
    Plain,
    /// No gap byte.
    No,
}

static GAP_BYTES: [Gap; 256] = {
    let mut table = [Gap::No; 256];
    let mut byte = 0;
    while byte < 256 {
        let b = byte as u8;
        table[byte] = if b.is_ascii_whitespace() || b == b',' {
            Gap::Split
        } else if b.is_ascii_digit() || matches!(b, b'.' | b')' | b':' | b'"' | b'\'' | b'-') {
            Gap::Plain
        } else {
            Gap::No
        };
        byte += 1;
    }
    table
};

/// Splits a run of words into runs of list words that share a language and
/// adds their phrases.
fn list_runs(text: &str, words: &[Range<usize>], phrases: &mut Vec<Range<usize>>) {
    if words.len() < LENGTHS[LENGTHS.len() - 1] {
        return;
    }
    let mut run: Vec<Word> = Vec::new();
    let mut shared = 0u8;
    for range in words {
        let mut letters = [0; MAX_LETTERS];
        let entries =
            fold(&text.as_bytes()[range.clone()], &mut letters).and_then(|key| LEXICON.get(key));
        let Some(&(mask, indices)) = entries else {
            run_phrases(&run, phrases);
            run.clear();
            continue;
        };
        if mask & shared == 0 || run.is_empty() {
            run_phrases(&run, phrases);
            run.clear();
            shared = u8::MAX;
        }
        shared &= mask;
        run.push(Word {
            range: range.clone(),
            mask,
            indices,
        });
    }
    run_phrases(&run, phrases);
}

/// The phrase windows of a run: longest first, then left to right, without
/// overlap.
fn run_phrases(run: &[Word], phrases: &mut Vec<Range<usize>>) {
    if run.len() < LENGTHS[LENGTHS.len() - 1] || run.len() > MAX_RUN {
        return;
    }
    let mut taken: Vec<Range<usize>> = Vec::new();
    for len in LENGTHS.into_iter().filter(|len| *len <= run.len()) {
        for start in 0..=run.len() - len {
            if taken
                .iter()
                .any(|window| window.start < start + len && start < window.end)
            {
                continue;
            }
            let window = &run[start..start + len];
            let mask = window
                .iter()
                .fold(u8::MAX, |shared, word| shared & word.mask);
            let valid = (0..LISTS.len())
                .filter(|language| mask >> language & 1 == 1)
                .any(|language| {
                    let mut indices = [0u16; MAX_WORDS];
                    for (index, word) in indices.iter_mut().zip(window) {
                        *index = word.indices[language];
                    }
                    valid_indices(&indices[..len])
                });
            if valid {
                taken.push(start..start + len);
            }
        }
    }
    taken.sort_by_key(|window| window.start);
    phrases.extend(
        taken
            .into_iter()
            .map(|window| run[window.start].range.start..run[window.end - 1].range.end),
    );
}

/// The byte ranges of the seed phrases of `text`, from the first to the last
/// word, in text order.
pub(crate) fn phrases(text: &str) -> Vec<Range<usize>> {
    let mut phrases = Vec::new();
    scan(text, &mut phrases);
    phrases
}

/// Validator: `value` is one seed phrase from its first to its last word.
pub(crate) fn is_seed_phrase(value: &str) -> bool {
    matches!(phrases(value).as_slice(), [phrase] if *phrase == (0..value.len()))
}

/// Context terms before a phrase of fewer than [`CONTEXT_FREE_LEN`] words
/// (lowercase; `seed` covers seed phrase, Seed-Phrase, seedPhrase). Words
/// such as `words` or `secret` name stop-word lists and settings as well.
const CONTEXT_TERMS: &[&str] = &[
    "seed",
    "mnemonic",
    "recovery",
    "phrase",
    "wallet",
    "backup",
    "wiederherstellung",
    "frase",
];

/// How far before a phrase a context term counts.
const CONTEXT_BYTES: usize = 200;

/// Context gate: a phrase of [`CONTEXT_FREE_LEN`] or more words counts on
/// its own; a shorter one needs numbered words or a context term in the
/// [`CONTEXT_BYTES`] before it.
pub(crate) fn has_seed_context(text: &str, value: Range<usize>) -> bool {
    let phrase = &text[value.clone()];
    let words = phrase
        .split(|c: char| c.is_ascii() && !c.is_ascii_lowercase())
        .filter(|word| !word.is_empty())
        .count();
    if words >= CONTEXT_FREE_LEN || phrase.bytes().any(|byte| byte.is_ascii_digit()) {
        return true;
    }
    let mut start = value.start.saturating_sub(CONTEXT_BYTES);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    let before = text[start..value.start].to_lowercase();
    CONTEXT_TERMS.iter().any(|term| before.contains(term))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|at| {
                seed.wrapping_mul(37)
                    .wrapping_add((at as u8).wrapping_mul(101))
                    ^ 0x5a
            })
            .collect()
    }

    #[test]
    fn word_lists_are_complete() {
        for (name, list) in LISTS {
            assert_eq!(list.lines().count(), 2048, "{name}");
        }
    }

    #[test]
    fn encodes_and_validates_every_length_and_language() {
        for (language, _) in LISTS {
            for len in [16, 20, 24, 28, 32] {
                let phrase = mnemonic(language, &entropy(len as u8, len)).unwrap();
                assert_eq!(phrase.split(' ').count(), len * 3 / 4, "{language}");
                assert!(is_seed_phrase(&phrase), "{language} {len}");
            }
        }
    }

    #[test]
    fn rejects_a_wrong_checksum() {
        let phrase = mnemonic("english", &entropy(7, 16)).unwrap();
        let mut words: Vec<&str> = phrase.split(' ').collect();
        let last = WORDS[0]
            .iter()
            .copied()
            .find(|word| {
                *word != words[11] && {
                    let mut changed = words.clone();
                    changed[11] = word;
                    !is_seed_phrase(&changed.join(" "))
                }
            })
            .unwrap();
        words[11] = last;
        assert!(!is_seed_phrase(&words.join(" ")));
    }

    #[test]
    fn rejects_published_test_vectors() {
        assert_eq!(TEST_VECTOR_ENTROPIES.len(), TEST_VECTOR_HEX.len());
        for (hex, bytes) in TEST_VECTOR_HEX.iter().zip(TEST_VECTOR_ENTROPIES.iter()) {
            assert_eq!(bytes.len() * 2, hex.len());
            for (language, _) in LISTS {
                let phrase = mnemonic(language, bytes).unwrap();
                assert!(!is_seed_phrase(&phrase), "{language} {hex}");
            }
        }
    }

    #[test]
    fn spanish_and_french_words_count_in_nfd_nfc_and_without_accents() {
        use unicode_normalization::UnicodeNormalization;
        for language in ["spanish", "french"] {
            for len in [16, 24, 32] {
                let accented = (0..=255)
                    .map(|seed| mnemonic(language, &entropy(seed, len)).unwrap())
                    .find(|phrase| !phrase.is_ascii())
                    .unwrap();
                let nfc: String = accented.nfc().collect();
                let plain: String = accented.nfd().filter(char::is_ascii).collect();
                assert_ne!(nfc, accented, "{language} {len}");
                for phrase in [&accented, &nfc, &plain] {
                    assert!(is_seed_phrase(phrase), "{language} {len}");
                    let text = format!("seed: {phrase}\n");
                    assert_eq!(phrases(&text), vec![6..text.len() - 1], "{language}");
                }
            }
        }
    }

    #[test]
    fn folds_accents_and_rejects_other_letters() {
        let mut letters = [0; MAX_LETTERS];
        assert_eq!(fold("ábaco".as_bytes(), &mut letters), Some("abaco"));
        assert_eq!(fold("a\u{301}baco".as_bytes(), &mut letters), Some("abaco"));
        assert_eq!(fold("élève".as_bytes(), &mut letters), Some("eleve"));
        assert_eq!(fold("abcdefghij".as_bytes(), &mut letters), None);
        // `ß`, `æ` and uppercase accented letters are no word letters.
        for text in ["ß", "æ", "É"] {
            assert_eq!(letter_len(text.as_bytes(), 0), 0, "{text}");
        }
        assert_eq!(letter_len("ñ".as_bytes(), 0), 2);
        assert_eq!(letter_len("\u{303}".as_bytes(), 0), 2);
    }

    #[test]
    fn has_seed_context_counts_accented_words_once() {
        // 12 words with an accent inside each are a short phrase that needs
        // a context; the count looks only at the words.
        let words: Vec<&str> = WORDS[4]
            .iter()
            .copied()
            .filter(|word| word.bytes().skip(1).any(|byte| byte == 0xcc))
            .take(12)
            .collect();
        let text = format!("note: {}", words.join(" "));
        assert!(!has_seed_context(&text, 6..text.len()));
    }

    #[test]
    fn finds_numbered_and_line_by_line_phrases() {
        let phrase = mnemonic("english", &entropy(3, 16)).unwrap();
        let words: Vec<&str> = phrase.split(' ').collect();
        let numbered: String = words
            .iter()
            .enumerate()
            .map(|(at, word)| format!("{}. {word}\n", at + 1))
            .collect();
        let found = phrases(&numbered);
        assert_eq!(found.len(), 1);
        assert_eq!(&numbered[found[0].clone()], numbered[3..].trim_end());
        let json = format!("[\"{}\"]", words.join("\", \""));
        let found = phrases(&json);
        assert_eq!(found, vec![2..json.len() - 2]);
    }

    #[test]
    fn skips_word_list_dumps_and_short_runs() {
        for (language, list) in LISTS {
            assert!(phrases(list).is_empty(), "{language}");
        }
        let phrase = mnemonic("english", &entropy(9, 16)).unwrap();
        let eleven = phrase.rsplit_once(' ').unwrap().0;
        assert!(phrases(eleven).is_empty());
    }

    #[test]
    fn context_gate() {
        let phrase = mnemonic("english", &entropy(5, 16)).unwrap();
        let with = format!("seed phrase: {phrase}");
        assert!(has_seed_context(&with, 13..with.len()));
        let without = format!("note: {phrase}");
        assert!(!has_seed_context(&without, 6..without.len()));
        let long = mnemonic("english", &entropy(5, 24)).unwrap();
        assert!(has_seed_context(&long, 0..long.len()));
    }
}
