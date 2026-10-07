// SPDX-License-Identifier: GPL-3.0-only
//! Local context for PII fields whose names also occur in ordinary documents.
use std::sync::LazyLock;

use regex::Regex;

use super::validators;

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
