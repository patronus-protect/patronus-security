// SPDX-License-Identifier: GPL-3.0-only
//! Local context for PII values.
//!
//! The context engine (K03) looks at both sides of a value for the terms of a
//! DE/EN lexicon: support terms of the value's label and counter-context terms
//! for numbers that are not PII (order, invoice, tracking, ticket, reference,
//! serial numbers). Both come from `anchor_lexicons/pii.json`; this module only
//! maps lexicon IDs to labels. The nearest term decides; see [`proximity`].
//! The older helpers below gate single rules on the preceding clause.
use std::{collections::HashMap, sync::LazyLock};

use regex::Regex;

use super::{score::Context, validators};
use crate::detectors::lexical_anchors::LexicalAnchorScanner;

/// Support lexicon IDs of `pii.json` per PII label.
pub static SUPPORT_LEXICON: &[(&str, &[&str])] = &[
    (
        "PHONE",
        &[
            "pii.telephone",
            "pii.mobile_phone",
            "pii.fax",
            "pii.telephone_extension",
            "pii.phone_reachability",
        ],
    ),
    ("EMAIL", &["pii.email_address"]),
    ("IP_ADDRESS", &["pii.network_address"]),
    ("MAC_ADDRESS", &["pii.hardware_address"]),
    ("IBAN", &["pii.bank_account"]),
    ("CREDITCARD", &["pii.payment_card"]),
    ("CREDITCARD_CVV", &["pii.card_verification"]),
    ("CREDITCARD_EXPIRY", &["pii.card_expiry"]),
    ("SWIFT_CODE", &["pii.bank_identifier"]),
    ("EMPLOYEE_ID", &["pii.employee_identifier"]),
    ("CUSTOMER_ID", &["pii.customer_identifier"]),
    ("PATIENT_ID", &["pii.patient_identifier"]),
    ("STUDENT_ID", &["pii.student_identifier"]),
    ("APPLICANT_ID", &["pii.applicant_identifier"]),
    ("USERNAME", &["pii.user_account"]),
    ("DOB", &["pii.date_of_birth"]),
    (
        "FINANCIAL_ACCOUNT_NUMBER",
        &["pii.bank_account", "pii.brokerage_account"],
    ),
    ("STEUERID", &["pii.tax_identifier"]),
    ("TAX_NUMBER_DE", &["pii.tax_number"]),
    ("SOCIALID", &["pii.social_insurance_number"]),
    ("HEALTH_INSURANCE_NUMBER", &["pii.health_insurance_number"]),
    ("PHYSICIAN_NUMBER_LANR", &["pii.physician_number"]),
    ("PASSPORT_NUMBER", &["pii.passport"]),
    ("IDENTITY_CARD_NUMBER", &["pii.identity_card"]),
    ("DRIVER_LICENSE_NUMBER", &["pii.driver_license"]),
    ("LICENSEPLATE", &["pii.vehicle_registration"]),
    ("SSN", &["pii.social_insurance_number"]),
    ("NATIONALID", &["pii.national_insurance_number"]),
];

/// Counter-context lexicon IDs of `pii.json`: numbers that are not PII.
pub static COUNTER_LEXICON: &[&str] = &[
    "pii.order_number",
    "pii.invoice_number",
    "pii.shipment_number",
    "pii.ticket_number",
    "pii.reference_number",
    "pii.product_number",
];

/// Characters between a term and the value: before it (field names, "erreichbar
/// unter") and after it ("(Handy)", "erreichbar").
pub const BEFORE_WINDOW: usize = 48;
pub const AFTER_WINDOW: usize = 32;

struct Lexicon {
    support: HashMap<&'static str, Regex>,
    counter: Regex,
    /// Characters of the longest term.
    longest: usize,
}

fn lexicon_words(ids: &[&str]) -> Vec<&'static str> {
    let definitions = LexicalAnchorScanner::shared().definitions();
    ids.iter()
        .flat_map(|id| {
            let definition = definitions
                .iter()
                .find(|definition| definition.id == *id)
                .unwrap_or_else(|| panic!("unknown PII lexicon id {id}"));
            definition
                .en
                .iter()
                .chain(&definition.de)
                .chain(&definition.shared)
                .map(String::as_str)
        })
        .collect()
}

/// Case-insensitive alternation of every word of the lexicon IDs, longest first.
fn lexicon_regex(ids: &[&str]) -> Regex {
    let mut words: Vec<_> = lexicon_words(ids).into_iter().map(regex::escape).collect();
    words.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    words.dedup();
    Regex::new(&format!("(?i)(?:{})", words.join("|"))).unwrap()
}

static LEXICON: LazyLock<Lexicon> = LazyLock::new(|| Lexicon {
    support: SUPPORT_LEXICON
        .iter()
        .map(|(label, ids)| (*label, lexicon_regex(ids)))
        .collect(),
    counter: lexicon_regex(COUNTER_LEXICON),
    longest: SUPPORT_LEXICON
        .iter()
        .flat_map(|(_, ids)| lexicon_words(ids))
        .chain(lexicon_words(COUNTER_LEXICON))
        .map(|word| word.chars().count())
        .max()
        .unwrap_or(0),
});

/// Gap in characters between a term and the value, if the term may describe
/// the value. A term never reaches across a line break or past a digit (the
/// value of another field). After the value, the term must also not be the
/// field name of the next value ("…, Telefon: …"): the gap holds no list or
/// field separator and the term is not followed by `:`, `=`, `#` or a digit.
fn term_gap(text: &str, term: (usize, usize), value: (usize, usize)) -> Option<usize> {
    let word = |ch: Option<char>| ch.is_some_and(char::is_alphanumeric);
    let term_text = &text[term.0..term.1];
    // Whole words only where the term starts or ends with a letter or digit.
    if (word(term_text.chars().next()) && word(text[..term.0].chars().next_back()))
        || (word(term_text.chars().next_back()) && word(text[term.1..].chars().next()))
    {
        return None;
    }
    let (gap, window, after) = if term.1 <= value.0 {
        (&text[term.1..value.0], BEFORE_WINDOW, false)
    } else if term.0 >= value.1 {
        (&text[value.1..term.0], AFTER_WINDOW, true)
    } else {
        return None;
    };
    if gap
        .chars()
        .any(|ch| ch == '\n' || ch == '\r' || ch.is_ascii_digit() || matches!(ch, ';' | '|'))
    {
        return None;
    }
    if after {
        let next = text[term.1..]
            .trim_start_matches([' ', '\t'])
            .chars()
            .next();
        if gap.chars().any(|ch| matches!(ch, ',' | ':' | '=' | '#'))
            || next.is_some_and(|ch| matches!(ch, ':' | '=' | '#') || ch.is_ascii_digit())
        {
            return None;
        }
    }
    let gap = gap.chars().count();
    (gap <= window).then_some(gap)
}

/// Byte range around `value` that holds every term whose gap fits the windows:
/// the window plus the longest term on each side, never past a line break.
fn region(text: &str, value: (usize, usize), longest: usize) -> (usize, usize) {
    let start = text[..value.0]
        .char_indices()
        .rev()
        .take(BEFORE_WINDOW + longest)
        .take_while(|(_, ch)| !matches!(ch, '\n' | '\r'))
        .last()
        .map_or(value.0, |(index, _)| index);
    let end = text[value.1..]
        .char_indices()
        .take(AFTER_WINDOW + longest)
        .take_while(|(_, ch)| !matches!(ch, '\n' | '\r'))
        .last()
        .map_or(value.1, |(index, ch)| value.1 + index + ch.len_utf8());
    (start, end)
}

/// Nearest term of `regex` within `region` on either side of `value`.
fn nearest(
    text: &str,
    regex: &Regex,
    region: (usize, usize),
    value: (usize, usize),
) -> Option<usize> {
    regex
        .find_iter(&text[region.0..region.1])
        .filter_map(|term| {
            term_gap(
                text,
                (region.0 + term.start(), region.0 + term.end()),
                value,
            )
        })
        .min()
}

/// Two-sided proximity context of the value at `value` (byte range) for
/// `label`. The nearest support term gives [`Context::Support`] unless a
/// counter-context term is strictly nearer, which gives [`Context::Counter`].
pub fn proximity(text: &str, value: (usize, usize), label: &str) -> Context {
    proximity_with(text, value, label, true)
}

/// Whether the context supports `label` at `value`; skips the counter search
/// when there is no support term at all.
pub(super) fn supports(text: &str, value: (usize, usize), label: &str) -> bool {
    proximity_with(text, value, label, false).supports()
}

fn proximity_with(text: &str, value: (usize, usize), label: &str, always_counter: bool) -> Context {
    let lexicon = &*LEXICON;
    let region = region(text, value, lexicon.longest);
    let support = lexicon
        .support
        .get(label)
        .and_then(|regex| nearest(text, regex, region, value));
    if support.is_none() && !always_counter {
        return Context::None;
    }
    let counter = nearest(text, &lexicon.counter, region, value);
    match (support, counter) {
        (Some(support), Some(counter)) if counter < support => Context::Counter,
        (Some(gap), _) => Context::Support { gap },
        (None, Some(_)) => Context::Counter,
        (None, None) => Context::None,
    }
}

// Context must precede the field in the same clause. A card or employee mention
// elsewhere in a document must not turn unrelated dates or product IDs into PII.
fn preceding_clause(text: &str, field_start: usize) -> &str {
    let mut start = field_start.saturating_sub(128);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    let before = &text[start..field_start];
    let clause_start = before
        .rfind(['\n', '\r', '.', '!', '?', ';', '|'])
        .map_or(0, |index| index + 1);
    &before[clause_start..]
}

pub(super) fn payment_expiry(text: &str, field_start: usize, card_regex: &Regex) -> bool {
    static PAYMENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:credit[ -]?card|debit[ -]?card|payment[ -]?card|kreditkarte|debitkarte|bankkarte|zahlungskarte|visa|mastercard|amex|american[ \t]+express)\b|\b(?:card|karte)[ \t]*[:,-]?[ \t]*$").unwrap()
    });
    let context = preceding_clause(text, field_start);
    PAYMENT.is_match(context)
        || card_regex
            .find_iter(context)
            .any(|matched| validators::luhn(matched.as_str()))
}

pub(super) fn employee_identifier(text: &str, field_start: usize, value: &str) -> bool {
    static EMPLOYMENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:employee|staff|personnel|mitarbeiter|personal|personalnummer)\b")
            .unwrap()
    });
    let prefix = value.split(['-', '_', '/', ' ', '\t']).next().unwrap_or("");
    ["EMP", "HR", "STAFF"]
        .iter()
        .any(|marker| prefix.eq_ignore_ascii_case(marker))
        || EMPLOYMENT.is_match(preceding_clause(text, field_start))
}
