// SPDX-License-Identifier: MIT OR Apache-2.0
//! The language of a text: German or English by frequent function words,
//! `und` when neither outweighs the other.

const EN: &[&str] = &[
    "a", "all", "and", "are", "at", "be", "before", "every", "for", "in", "is", "it", "never",
    "not", "of", "on", "please", "the", "this", "to", "when", "with", "you", "your",
];
const DE: &[&str] = &[
    "als", "an", "auch", "auf", "aus", "bevor", "bitte", "das", "dem", "den", "der", "des", "die",
    "du", "ein", "eine", "es", "für", "ich", "im", "ist", "keine", "keinen", "mit", "nicht",
    "niemals", "sie", "sind", "und", "von", "wenn", "zu",
];

/// `de`, `en` or `und`.
pub(super) fn detect(text: &str) -> &'static str {
    let (mut de, mut en) = (0usize, 0usize);
    for word in text.split(|c: char| !c.is_alphanumeric()) {
        if word.is_empty() || word.len() > 7 {
            continue;
        }
        en += usize::from(EN.iter().any(|w| w.eq_ignore_ascii_case(word)));
        de += usize::from(DE.iter().any(|w| w.eq_ignore_ascii_case(word)));
    }
    match de.cmp(&en) {
        std::cmp::Ordering::Greater => "de",
        std::cmp::Ordering::Less => "en",
        std::cmp::Ordering::Equal => "und",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_words_decide() {
        assert_eq!(detect("Please send the report to the team"), "en");
        assert_eq!(detect("Bitte schick den Bericht an das Team"), "de");
        assert_eq!(detect("12:00 OK"), "und");
    }
}
