// SPDX-License-Identifier: MIT OR Apache-2.0
//! M-MARK: classification markings (M02 + M03), the document class that is on
//! by default (M23, [`super::super::dlp::DEFAULT_ON_DOCUMENT_GROUPS`]). The
//! marking is the evidence span and the document label where it stands as a
//! marking:
//!
//! - as a banner: upper case, alone on its line apart from decoration
//!   (`**CONFIDENTIAL**`, `# STRENG GEHEIM`, `// RESTRICTED`); bare `INTERNAL`
//!   and `INTERN` are no banner, they are code words too;
//! - as the value of a classification key (`Classification: Internal Only`,
//!   `"vertraulichkeit": "intern"`, `einstufung: VS-VERTRAULICH`), followed by
//!   the end of the value.
//!
//! Levels quoted in prose, listings of several levels of one family (an
//! article on TLP, a code enum) and counter-context near the marking (template,
//! example, Vorlage, Beispiel) are no label. The counter-context runs on the
//! M01 content class engine with the marking as strong anchor.
use crate::detectors::dlp::content_class::{ContentClass, Density, Tier};
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, ValidatorStrength};
use regex::Regex;
use std::ops::Range;
use std::sync::LazyLock;

pub(super) const RULES: &[DlpPattern] = &[
    // M02: VS-NfD, VS-VERTRAULICH, GEHEIM, STRENG GEHEIM (VSA).
    DlpPattern {
        name: "dlp_marking_de_government",
        pattern: r"(?i)\b(?:VS ?- ?NUR FÜR DEN DIENSTGEBRAUCH|VS-NfD|VS-VERTRAULICH|STRENG GEHEIM|GEHEIM)\b",
        entity_group: "dlp.document.classification_marking",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["geheim", "dienstgebrauch", "vs-nfd", "vertraulich"],
        )
        .with_context_gate(is_de_government_marking),
    },
    // M02: corporate levels intern, vertraulich, streng vertraulich.
    DlpPattern {
        name: "dlp_marking_de_corporate",
        pattern: r"(?i)\b(?:STRENG VERTRAULICH|NUR FÜR DEN INTERNEN GEBRAUCH|VERTRAULICH|INTERN)\b",
        entity_group: "dlp.document.classification_marking",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["vertraulich", "intern"])
            .with_context_gate(is_de_corporate_marking),
    },
    // M03: Confidential, Restricted, Internal Only.
    DlpPattern {
        name: "dlp_marking_en_corporate",
        pattern: r"(?i)\b(?:(?:STRICTLY|HIGHLY|COMPANY) CONFIDENTIAL|CONFIDENTIAL|RESTRICTED|(?:FOR )?INTERNAL (?:USE )?ONLY|INTERNAL)\b",
        entity_group: "dlp.document.classification_marking",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["confidential", "restricted", "internal"],
        )
        .with_context_gate(is_en_corporate_marking),
    },
    // M03: TLP 2.0 (FIRST), TLP:WHITE of TLP 1.0 included.
    DlpPattern {
        name: "dlp_marking_tlp",
        pattern: r"\bTLP: ?(?:CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)\b",
        entity_group: "dlp.document.classification_marking",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["tlp:"])
            .with_context_gate(is_tlp_marking),
    },
    // M03: NATO and EU markings (EU: Council Decision 2013/488/EU).
    DlpPattern {
        name: "dlp_marking_nato_eu",
        pattern: r"\b(?:COSMIC TOP SECRET|NATO (?:SECRET|CONFIDENTIAL|RESTRICTED)|TR[EÈ]S SECRET UE/EU TOP SECRET|SECRET UE/EU SECRET|CONFIDENTIEL UE/EU CONFIDENTIAL|RESTREINT UE/EU RESTRICTED)\b",
        entity_group: "dlp.document.classification_marking",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["secret", "nato", "ue/eu"],
        )
        .with_context_gate(is_nato_eu_marking),
    },
];

/// Keys whose value is a classification level (lower case); a key counts
/// with any lead word (`data_classification`, `Security Classification`).
const LABEL_KEYS: &[&str] = &[
    "classification",
    "classification level",
    "sensitivity",
    "sensitivity label",
    "confidentiality",
    "marking",
    "einstufung",
    "klassifizierung",
    "klassifikation",
    "vertraulichkeit",
    "vertraulichkeitsstufe",
    "geheimhaltungsgrad",
    "schutzstufe",
    "schutzklasse",
    "kennzeichnung",
];

/// Characters that decorate a banner line (markdown, comments, rules).
fn is_decoration(c: char) -> bool {
    c.is_whitespace() || "#*/<>!-=_~[]()|:.".contains(c)
}

/// Bytes on either side of a marking in which counter-context and other
/// levels of its family count.
const WINDOW: usize = 160;

/// Bytes of the marking's line read on either side.
const LINE: usize = 120;

/// Counter-context of a marking: a template, an example or a course.
static COUNTER: LazyLock<ContentClass> = LazyLock::new(|| {
    ContentClass::new(
        &[
            ("example", Tier::Counter),
            ("for example", Tier::Counter),
            ("e.g.", Tier::Counter),
            ("sample", Tier::Counter),
            ("template", Tier::Counter),
            ("placeholder", Tier::Counter),
            ("wikipedia", Tier::Counter),
            ("definition", Tier::Counter),
            ("refers to", Tier::Counter),
            ("glossary", Tier::Counter),
            ("tutorial", Tier::Counter),
            ("lecture", Tier::Counter),
            ("beispiel", Tier::Counter),
            ("zum beispiel", Tier::Counter),
            ("z. b.", Tier::Counter),
            ("z.b.", Tier::Counter),
            ("muster", Tier::Counter),
            ("vorlage", Tier::Counter),
            ("platzhalter", Tier::Counter),
            ("bezeichnet", Tier::Counter),
            ("glossar", Tier::Counter),
            ("vorlesung", Tier::Counter),
            ("seminar", Tier::Counter),
        ],
        Density {
            window: WINDOW,
            min_score: crate::detectors::dlp::content_class::STRONG_WEIGHT,
            min_medium: 0,
        },
    )
});

static DE_GOVERNMENT_RE: LazyLock<Regex> = LazyLock::new(|| compile("dlp_marking_de_government"));
static DE_CORPORATE_RE: LazyLock<Regex> = LazyLock::new(|| compile("dlp_marking_de_corporate"));
static EN_CORPORATE_RE: LazyLock<Regex> = LazyLock::new(|| compile("dlp_marking_en_corporate"));
static TLP_RE: LazyLock<Regex> = LazyLock::new(|| compile("dlp_marking_tlp"));
static NATO_EU_RE: LazyLock<Regex> = LazyLock::new(|| compile("dlp_marking_nato_eu"));

/// The regex of the marking rule `name`, for the levels near a marking.
fn compile(name: &str) -> Regex {
    let rule = RULES
        .iter()
        .find(|rule| rule.name == name)
        .expect("marking rule");
    Regex::new(rule.pattern).expect("marking pattern compiles")
}

fn is_de_government_marking(text: &str, marking: Range<usize>) -> bool {
    is_marking(text, marking, &DE_GOVERNMENT_RE)
}

fn is_de_corporate_marking(text: &str, marking: Range<usize>) -> bool {
    is_marking(text, marking, &DE_CORPORATE_RE)
}

fn is_en_corporate_marking(text: &str, marking: Range<usize>) -> bool {
    is_marking(text, marking, &EN_CORPORATE_RE)
}

fn is_tlp_marking(text: &str, marking: Range<usize>) -> bool {
    is_marking(text, marking, &TLP_RE)
}

fn is_nato_eu_marking(text: &str, marking: Range<usize>) -> bool {
    is_marking(text, marking, &NATO_EU_RE)
}

/// Whether the match of `family` at `marking` labels the document: it stands
/// as a banner or a key's value, no counter-context is near and no other
/// level of its family stands as a marking near it.
fn is_marking(text: &str, marking: Range<usize>, family: &Regex) -> bool {
    if !stands_as_marking(text, &marking) || !COUNTER.holds(text, marking.clone()) {
        return false;
    }
    let level = normalized(&text[marking.clone()]);
    let start = floor_char_boundary(text, marking.start.saturating_sub(WINDOW));
    let end = ceil_char_boundary(text, marking.end.saturating_add(WINDOW));
    !family.find_iter(&text[start..end]).any(|other| {
        let range = start + other.start()..start + other.end();
        range != marking && normalized(other.as_str()) != level && stands_as_marking(text, &range)
    })
}

/// Whether the match at `marking` stands as a banner line or a key's value.
fn stands_as_marking(text: &str, marking: &Range<usize>) -> bool {
    // A line longer than `LINE` on either side holds no banner, and a key
    // stands right before its value: the scan stays bounded on long lines.
    let from = floor_char_boundary(text, marking.start.saturating_sub(LINE));
    let to = ceil_char_boundary(text, marking.end.saturating_add(LINE));
    let line_start = text[from..marking.start]
        .rfind('\n')
        .map_or(from, |at| from + at + 1);
    let line_end = text[marking.end..to]
        .find('\n')
        .map_or(to, |at| marking.end + at);
    let (before, value, after) = (
        &text[line_start..marking.start],
        &text[marking.clone()],
        &text[marking.end..line_end],
    );
    is_banner(before, value, after) || is_key_value(before, after)
}

fn is_banner(before: &str, value: &str, after: &str) -> bool {
    let upper = !value.chars().any(char::is_lowercase) || value == "VS-NfD";
    upper
        && !matches!(value, "INTERNAL" | "INTERN")
        && before.chars().all(is_decoration)
        && after.chars().all(is_decoration)
}

fn is_key_value(before: &str, after: &str) -> bool {
    let quotes: &[char] = &['"', '\''];
    let Some(key) = before
        .trim_end()
        .trim_end_matches(quotes)
        .trim_end()
        .strip_suffix([':', '='])
    else {
        return false;
    };
    let key = key.trim_end().trim_end_matches(quotes).to_ascii_lowercase();
    let ends_value = after
        .trim_start()
        .chars()
        .next()
        .is_none_or(|c| matches!(c, '"' | '\'' | ',' | ';' | '}' | ']' | ')' | '\r'));
    ends_value
        && LABEL_KEYS.iter().any(|label| {
            key.strip_suffix(label)
                .is_some_and(|lead| !lead.chars().next_back().is_some_and(char::is_alphanumeric))
        })
}

/// A level in upper case with single spaces, so `TLP: AMBER` and `TLP:AMBER`
/// are one level.
fn normalized(level: &str) -> String {
    level
        .split(|c: char| c.is_whitespace() || c == ':')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

fn floor_char_boundary(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_char_boundary(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

#[cfg(test)]
mod tests {
    use super::{
        is_de_corporate_marking, is_de_government_marking, is_en_corporate_marking,
        is_nato_eu_marking, is_tlp_marking,
    };
    use std::ops::Range;

    fn gate(gate: fn(&str, Range<usize>) -> bool, text: &str, marking: &str) -> bool {
        let start = text.find(marking).unwrap();
        gate(text, start..start + marking.len())
    }

    #[test]
    fn banners_hold_in_upper_case_with_decoration_only() {
        assert!(gate(
            is_en_corporate_marking,
            "**CONFIDENTIAL**\n\nQ3 review",
            "CONFIDENTIAL"
        ));
        assert!(gate(
            is_en_corporate_marking,
            "// RESTRICTED\nfn main() {}",
            "RESTRICTED"
        ));
        assert!(gate(
            is_de_government_marking,
            "# STRENG GEHEIM\n\nPlan",
            "STRENG GEHEIM"
        ));
        assert!(gate(
            is_de_government_marking,
            "VS-NfD\nLagebericht",
            "VS-NfD"
        ));
        assert!(gate(
            is_tlp_marking,
            "Bericht\n[TLP:AMBER+STRICT]\n",
            "TLP:AMBER+STRICT"
        ));
        assert!(gate(
            is_nato_eu_marking,
            "NATO RESTRICTED\r\nExercise",
            "NATO RESTRICTED"
        ));
        // Mixed case, words on the line, a list comma or a bare code word.
        assert!(!gate(
            is_en_corporate_marking,
            "Confidential\nQ3 review",
            "Confidential"
        ));
        assert!(!gate(
            is_en_corporate_marking,
            "Keep this CONFIDENTIAL please",
            "CONFIDENTIAL"
        ));
        assert!(!gate(
            is_en_corporate_marking,
            "    RESTRICTED,\n",
            "RESTRICTED"
        ));
        assert!(!gate(is_en_corporate_marking, "    INTERNAL\n", "INTERNAL"));
        assert!(!gate(is_de_corporate_marking, "INTERN\n", "INTERN"));
        // A numbered list item of a law text.
        assert!(!gate(is_de_government_marking, "1. GEHEIM, wenn", "GEHEIM"));
    }

    #[test]
    fn key_values_hold_in_any_case_up_to_the_end_of_the_value() {
        assert!(gate(
            is_en_corporate_marking,
            "classification: Internal Only\nowner: x",
            "Internal Only"
        ));
        assert!(gate(
            is_en_corporate_marking,
            r#"{"sensitivity": "Highly Confidential", "a": 1}"#,
            "Highly Confidential"
        ));
        assert!(gate(
            is_de_corporate_marking,
            r#"{"vertraulichkeit": "intern"}"#,
            "intern"
        ));
        assert!(gate(
            is_de_government_marking,
            "Einstufung: VS-VERTRAULICH\n",
            "VS-VERTRAULICH"
        ));
        assert!(gate(
            is_de_corporate_marking,
            "data_classification = 'vertraulich'",
            "vertraulich"
        ));
        // Prose after the level, a key that only ends like a label, no key.
        assert!(!gate(
            is_en_corporate_marking,
            "Classification: confidential information is",
            "confidential"
        ));
        assert!(!gate(
            is_en_corporate_marking,
            "reclassification: internal",
            "internal"
        ));
        assert!(!gate(
            is_en_corporate_marking,
            "policy confidential=true",
            "confidential"
        ));
        assert!(!gate(
            is_de_corporate_marking,
            r#"const INTERN = "intern";"#,
            "intern"
        ));
        // VERTRAULICH inside VS-VERTRAULICH is the government level.
        assert!(!gate(
            is_de_corporate_marking,
            "Einstufung: VS-VERTRAULICH\n",
            "VERTRAULICH"
        ));
    }

    #[test]
    fn listings_of_levels_and_counter_context_veto() {
        let tlp = "The protocol defines:\nTLP:RED\nTLP:AMBER\nTLP:GREEN\n";
        assert!(!gate(is_tlp_marking, tlp, "TLP:AMBER"));
        let levels = "enum Level {\n    PUBLIC\n    CONFIDENTIAL\n    RESTRICTED\n}";
        assert!(!gate(is_en_corporate_marking, levels, "CONFIDENTIAL"));
        assert!(!gate(
            is_de_corporate_marking,
            "Vorlage Deckblatt:\nVERTRAULICH\nTitel",
            "VERTRAULICH"
        ));
        assert!(!gate(
            is_en_corporate_marking,
            "Header template:\nCONFIDENTIAL\n",
            "CONFIDENTIAL"
        ));
        // The same level in header and footer, and a word that only looks like
        // another level, stay a label.
        let both = "TLP:AMBER\nAdvisory text.\nTLP: AMBER\n";
        assert!(gate(is_tlp_marking, both, "TLP:AMBER"));
        let prose = "RESTRICTED\nInternal pricing engine, keep it in the team.";
        assert!(gate(is_en_corporate_marking, prose, "RESTRICTED"));
    }
}
