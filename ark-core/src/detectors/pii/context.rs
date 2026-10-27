// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local context for PII values.
//!
//! The context engine (K03) looks at both sides of a value for the terms of a
//! DE/EN lexicon (since T26 also FR/ES/IT/NL field names): support terms of the value's label and counter-context terms
//! for numbers that are not PII (order, invoice, tracking, ticket, reference,
//! serial numbers). Both come from `anchor_lexicons/pii.json`; this module only
//! maps lexicon IDs to labels. The nearest term decides; see [`proximity`].
//! [`evidence`] also names the deciding term for `matched_rules[].context`.
//! Structure (K04): a JSON key, CSV or table header, XML element or `key: value`
//! line that is a term of the lexicon is a field name of the value it holds; see
//! [`key_evidence`]. It outranks proximity: the key names the value, nearby words
//! may name its neighbours.
//! The older helpers below gate single rules on the preceding clause.
use std::{collections::HashMap, ops::Range, sync::LazyLock};

use regex::Regex;

use super::{
    score::{Context, PROXIMITY_CONTEXT_POINTS},
    validators,
};
use crate::detectors::lexical_anchors::LexicalAnchorScanner;
use crate::detectors::structure::{normalize_key, Field, Fields};

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
        &[
            "pii.bank_account",
            "pii.brokerage_account",
            "pii.bank_routing_number",
        ],
    ),
    ("STEUERID", &["pii.tax_identifier"]),
    ("TAX_NUMBER_DE", &["pii.tax_number"]),
    ("SOCIALID", &["pii.social_insurance_number"]),
    ("HEALTH_INSURANCE_NUMBER", &["pii.health_insurance_number"]),
    ("PHYSICIAN_NUMBER_LANR", &["pii.physician_number"]),
    ("FACILITY_NUMBER_BSNR", &["pii.facility_number"]),
    ("PASSPORT_NUMBER", &["pii.passport"]),
    ("IDENTITY_CARD_NUMBER", &["pii.identity_card"]),
    ("DRIVER_LICENSE_NUMBER", &["pii.driver_license"]),
    ("LICENSEPLATE", &["pii.vehicle_registration"]),
    ("SSN", &["pii.social_insurance_number"]),
    ("NATIONALID", &["pii.national_insurance_number"]),
    ("NHS_NUMBER", &["pii.nhs_number"]),
    ("AU_ABN", &["pii.au_business_number"]),
    ("AU_ACN", &["pii.au_company_number"]),
    ("AU_TFN", &["pii.au_tax_file_number"]),
    ("AU_MEDICARE", &["pii.au_medicare_number"]),
    ("SG_NRIC_FIN", &["pii.sg_nric_fin"]),
    ("SG_UEN", &["pii.sg_unique_entity_number"]),
    (
        "SE_PERSONNUMMER",
        &["pii.se_personnummer", "pii.nordic_personal_number"],
    ),
    ("DK_CPR", &["pii.dk_cpr", "pii.nordic_personal_number"]),
    (
        "NO_FODSELSNUMMER",
        &["pii.no_fodselsnummer", "pii.nordic_personal_number"],
    ),
    (
        "FI_PERSONAL_IDENTITY_CODE",
        &["pii.fi_personal_identity_code"],
    ),
    (
        "FR_NIR",
        &[
            "pii.fr_social_security_number",
            "pii.social_insurance_number",
        ],
    ),
    ("FR_SIREN", &["pii.fr_siren"]),
    ("FR_SIRET", &["pii.fr_siret"]),
    ("NL_BSN", &["pii.nl_citizen_service_number"]),
    ("BE_NATIONAL_NUMBER", &["pii.be_national_number"]),
    ("SE_ORGANISATIONSNUMMER", &["pii.se_organisationsnummer"]),
    ("CA_SIN", &["pii.ca_social_insurance_number"]),
    ("TR_NATIONAL_ID", &["pii.tr_national_id"]),
    ("ZA_ID_NUMBER", &["pii.za_id_number"]),
    ("VAT_ID_DE", &["pii.vat_identifier"]),
    ("VAT_ID_AT", &["pii.vat_identifier"]),
    ("VAT_ID_CH", &["pii.vat_identifier"]),
    ("VAT_ID_FR", &["pii.vat_identifier"]),
    ("VAT_ID_NL", &["pii.vat_identifier"]),
    ("VAT_ID_BE", &["pii.vat_identifier"]),
    ("VAT_ID_IT", &["pii.vat_identifier"]),
    ("VAT_ID_ES", &["pii.vat_identifier"]),
    ("VAT_ID_BG", &["pii.vat_identifier"]),
    ("VAT_ID_CY", &["pii.vat_identifier"]),
    ("VAT_ID_CZ", &["pii.vat_identifier"]),
    ("VAT_ID_DK", &["pii.vat_identifier"]),
    ("VAT_ID_EE", &["pii.vat_identifier"]),
    ("VAT_ID_EL", &["pii.vat_identifier"]),
    ("VAT_ID_FI", &["pii.vat_identifier"]),
    ("VAT_ID_HR", &["pii.vat_identifier"]),
    ("VAT_ID_HU", &["pii.vat_identifier"]),
    ("VAT_ID_IE", &["pii.vat_identifier"]),
    ("VAT_ID_LT", &["pii.vat_identifier"]),
    ("VAT_ID_LU", &["pii.vat_identifier"]),
    ("VAT_ID_LV", &["pii.vat_identifier"]),
    ("VAT_ID_MT", &["pii.vat_identifier"]),
    ("VAT_ID_PL", &["pii.vat_identifier"]),
    ("VAT_ID_PT", &["pii.vat_identifier"]),
    ("VAT_ID_RO", &["pii.vat_identifier"]),
    ("VAT_ID_SE", &["pii.vat_identifier"]),
    ("VAT_ID_SI", &["pii.vat_identifier"]),
    ("VAT_ID_SK", &["pii.vat_identifier"]),
    ("VAT_ID_NO", &["pii.vat_identifier"]),
    ("VAT_ID_GB", &["pii.vat_identifier"]),
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
    /// Whole-term matchers per lexicon ID, to name the ID of a found term.
    ids: HashMap<&'static str, Regex>,
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
                .unwrap_or_else(|| panic!("unknown lexicon id {id}"));
            definition.words().map(String::as_str)
        })
        .collect()
}

/// Case-insensitive alternation of every word of the lexicon IDs, longest first.
fn lexicon_regex(ids: &[&str]) -> Regex {
    Regex::new(&format!("(?i)(?:{})", lexicon_alternation(ids))).unwrap()
}

fn lexicon_alternation(ids: &[&str]) -> String {
    let mut words: Vec<_> = lexicon_words(ids).into_iter().map(regex::escape).collect();
    words.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    words.dedup();
    words.join("|")
}

static LEXICON: LazyLock<Lexicon> = LazyLock::new(|| Lexicon {
    support: SUPPORT_LEXICON
        .iter()
        .map(|(label, ids)| (*label, lexicon_regex(ids)))
        .collect(),
    counter: lexicon_regex(COUNTER_LEXICON),
    ids: SUPPORT_LEXICON
        .iter()
        .flat_map(|(_, ids)| ids.iter())
        .chain(COUNTER_LEXICON)
        .map(|id| {
            let words = lexicon_alternation(&[id]);
            (*id, Regex::new(&format!("(?i)^(?:{words})$")).unwrap())
        })
        .collect(),
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

/// Which side of the value a context term stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Before,
    After,
    /// The term is the structural key of the value (K04).
    Key,
}

impl Side {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Key => "key",
        }
    }
}

/// Context of one value and the term that decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub context: Context,
    /// Lexicon ID of the deciding term, or `field` for a field name the rule
    /// binds itself.
    pub anchor: Option<&'static str>,
    pub side: Option<Side>,
    /// Characters between the deciding term and the value.
    pub distance: Option<usize>,
}

impl Evidence {
    /// A value the rule binds to its own field name.
    pub fn field() -> Self {
        Self {
            context: Context::Field,
            anchor: Some("field"),
            ..Self::none()
        }
    }

    /// A value bound to a field name: right before it, or as its structural key
    /// (K04) when `structural`.
    pub fn field_at(structural: bool) -> Self {
        Self {
            side: structural.then_some(Side::Key),
            ..Self::field()
        }
    }

    pub const fn none() -> Self {
        Self {
            context: Context::None,
            anchor: None,
            side: None,
            distance: None,
        }
    }

    /// Context points the score adds.
    pub fn bonus(&self) -> u8 {
        u8::try_from(self.context.points().max(0)).unwrap_or(u8::MAX)
    }

    /// Counter-context points the score subtracts.
    pub fn penalty(&self) -> u8 {
        u8::try_from((-self.context.points()).max(0)).unwrap_or(u8::MAX)
    }

    /// `matched_rules[].context` of a finding in a scored mode.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({"bonus": self.bonus(), "penalty": self.penalty()});
        if let Some(anchor) = self.anchor {
            value["anchor"] = anchor.into();
        }
        if let Some(side) = self.side {
            value["side"] = side.as_str().into();
        }
        if let Some(distance) = self.distance {
            value["distance"] = distance.into();
        }
        value
    }
}

/// A term that may describe the value: its byte range, side and gap.
#[derive(Clone, Copy)]
struct Term {
    range: (usize, usize),
    side: Side,
    gap: usize,
}

/// Nearest term of `regex` within `region` on either side of `value`.
fn nearest(
    text: &str,
    regex: &Regex,
    region: (usize, usize),
    value: (usize, usize),
) -> Option<Term> {
    regex
        .find_iter(&text[region.0..region.1])
        .filter_map(|term| {
            let range = (region.0 + term.start(), region.0 + term.end());
            let side = if range.1 <= value.0 {
                Side::Before
            } else {
                Side::After
            };
            term_gap(text, range, value).map(|gap| Term { range, side, gap })
        })
        .min_by_key(|term| term.gap)
}

/// Two-sided proximity context of the value at `value` (byte range) for
/// `label`. The nearest support term gives [`Context::Support`] unless a
/// counter-context term is strictly nearer, which gives [`Context::Counter`].
pub fn proximity(text: &str, value: (usize, usize), label: &str) -> Context {
    evidence(text, value, label).context
}

/// [`proximity`] with the lexicon ID, side and distance of the deciding term.
pub fn evidence(text: &str, value: (usize, usize), label: &str) -> Evidence {
    proximity_with(text, value, label, true)
}

/// Whether the context supports `label` at `value`; skips the counter search
/// when there is no support term at all.
pub(super) fn supports(text: &str, value: (usize, usize), label: &str) -> bool {
    proximity_with(text, value, label, false).context.supports()
}

fn proximity_with(
    text: &str,
    value: (usize, usize),
    label: &str,
    always_counter: bool,
) -> Evidence {
    let lexicon = &*LEXICON;
    let region = region(text, value, lexicon.longest);
    let support = lexicon
        .support
        .get(label)
        .and_then(|regex| nearest(text, regex, region, value));
    if support.is_none() && !always_counter {
        return Evidence::none();
    }
    let counter = nearest(text, &lexicon.counter, region, value);
    let (context, term, ids) = match (support, counter) {
        (Some(support), Some(counter)) if counter.gap < support.gap => {
            (Context::Counter, counter, COUNTER_LEXICON)
        }
        (Some(support), _) => (
            Context::Support { gap: support.gap },
            support,
            support_ids(label),
        ),
        (None, Some(counter)) => (Context::Counter, counter, COUNTER_LEXICON),
        (None, None) => return Evidence::none(),
    };
    let found = &text[term.range.0..term.range.1];
    Evidence {
        context,
        anchor: ids
            .iter()
            .copied()
            .find(|id| lexicon.ids[id].is_match(found)),
        side: Some(term.side),
        distance: Some(term.gap),
    }
}

/// The proximity rules of this engine over one support and one counter-context
/// lexicon, for the score models of other categories (DLP K04): the same
/// windows, word boundaries and line limits, and the nearest term decides.
pub struct ProximityLexicon {
    support_ids: &'static [&'static str],
    counter_ids: &'static [&'static str],
    support: Regex,
    counter: Regex,
    /// Whole-term matchers per lexicon ID, to name the ID of a found term.
    ids: Vec<(&'static str, Regex)>,
    longest: usize,
}

impl ProximityLexicon {
    pub fn new(support_ids: &'static [&'static str], counter_ids: &'static [&'static str]) -> Self {
        let all = || support_ids.iter().chain(counter_ids);
        Self {
            support_ids,
            counter_ids,
            support: lexicon_regex(support_ids),
            counter: lexicon_regex(counter_ids),
            ids: all()
                .map(|id| {
                    let words = lexicon_alternation(&[id]);
                    (*id, Regex::new(&format!("(?i)^(?:{words})$")).unwrap())
                })
                .collect(),
            longest: lexicon_words(support_ids)
                .into_iter()
                .chain(lexicon_words(counter_ids))
                .map(|word| word.chars().count())
                .max()
                .unwrap_or(0),
        }
    }

    /// Two-sided proximity context of the value at `value` (byte range): the
    /// nearest support term gives [`Context::Support`] unless a counter-context
    /// term is strictly nearer, which gives [`Context::Counter`].
    pub fn evidence(&self, text: &str, value: (usize, usize)) -> Evidence {
        let region = region(text, value, self.longest);
        let support = nearest(text, &self.support, region, value);
        let counter = nearest(text, &self.counter, region, value);
        let (context, term, ids) = match (support, counter) {
            (Some(support), Some(counter)) if counter.gap < support.gap => {
                (Context::Counter, counter, self.counter_ids)
            }
            (Some(support), _) => (
                Context::Support { gap: support.gap },
                support,
                self.support_ids,
            ),
            (None, Some(counter)) => (Context::Counter, counter, self.counter_ids),
            (None, None) => return Evidence::none(),
        };
        let found = &text[term.range.0..term.range.1];
        Evidence {
            context,
            anchor: self
                .ids
                .iter()
                .find(|(id, regex)| ids.contains(id) && regex.is_match(found))
                .map(|(id, _)| *id),
            side: Some(term.side),
            distance: Some(term.gap),
        }
    }
}

fn support_ids(label: &str) -> &'static [&'static str] {
    SUPPORT_LEXICON
        .iter()
        .find(|(known, _)| *known == label)
        .map_or(&[], |(_, ids)| ids)
}

/// Lexicon terms that are no structural key of a label although they support it
/// in prose: an `iban` key holds an IBAN, which `pii_iban_*` reports, not a
/// second finding as account number.
const KEY_EXCLUSIONS: &[(&str, &str)] = &[("FINANCIAL_ACCOUNT_NUMBER", "iban")];

/// Words a key may append to a lexicon term: `passport no`, `ni number`.
const KEY_SUFFIXES: &[&str] = &[" no", " nr", " number", " nummer"];

/// A lexicon term as a structural key: a support term of `label`, or a
/// counter-context term (`label: None`).
#[derive(Debug, Clone, Copy)]
pub(super) struct KeyTerm {
    label: Option<&'static str>,
    id: &'static str,
}

/// Normalized lexicon terms (see [`normalize_key`]) and what they name.
static KEYS: LazyLock<HashMap<String, Vec<KeyTerm>>> = LazyLock::new(|| {
    let mut keys: HashMap<String, Vec<KeyTerm>> = HashMap::new();
    let support = SUPPORT_LEXICON
        .iter()
        .flat_map(|(label, ids)| ids.iter().map(|id| (Some(*label), *id)));
    let counter = COUNTER_LEXICON.iter().map(|id| (None, *id));
    for (label, id) in support.chain(counter) {
        for word in lexicon_words(&[id]) {
            if label.is_some_and(|label| KEY_EXCLUSIONS.contains(&(label, word))) {
                continue;
            }
            let terms = keys.entry(normalize_key(word)).or_default();
            if !terms
                .iter()
                .any(|term| term.label == label && term.id == id)
            {
                terms.push(KeyTerm { label, id });
            }
        }
    }
    keys
});

/// What the normalized key `name` names: its lexicon terms, else those of the
/// key without a generic suffix such as `no` or `nummer`.
fn key_terms(name: &str) -> &'static [KeyTerm] {
    let keys = &*KEYS;
    keys.get(name)
        .or_else(|| {
            KEY_SUFFIXES
                .iter()
                .find_map(|suffix| keys.get(name.strip_suffix(suffix)?))
        })
        .map_or(&[], Vec::as_slice)
}

/// Context that the key of `field` gives a value of `label`: the field context
/// of a support term, else a counter term, else `None` (the key names nothing or
/// another label). The most specific name with lexicon terms decides.
/// `terms` gives the lexicon terms of a name index.
fn key_evidence(
    terms: impl Fn(usize) -> &'static [KeyTerm],
    field: &Field,
    label: &str,
) -> Option<Evidence> {
    let terms = field
        .names
        .iter()
        .map(|&name| terms(name))
        .find(|terms| !terms.is_empty())?;
    let (context, term) = match terms.iter().find(|term| term.label == Some(label)) {
        Some(term) => (Context::Field, term),
        None => (
            Context::Counter,
            terms.iter().find(|term| term.label.is_none())?,
        ),
    };
    Some(Evidence {
        context,
        anchor: Some(term.id),
        side: Some(Side::Key),
        distance: None,
    })
}

/// Structural context (K04) of the value at `value` (byte range) for `label`:
/// [`Context::Field`] if a key of the label names exactly this value,
/// [`Context::Counter`] for a counter-context key, `None` without such a key.
/// Parses the structure of `text` on every call; detection caches it per text.
pub fn key_context(text: &str, value: (usize, usize), label: &str) -> Option<Context> {
    structure_evidence(&Fields::parse(text), value.0..value.1, label)
        .map(|evidence| evidence.context)
}

/// Structural context of the value at `value`: the key of a field whose value
/// it is, if that key names `label` or counter-context.
pub(super) fn structure_evidence(
    fields: &Fields,
    value: Range<usize>,
    label: &str,
) -> Option<Evidence> {
    fields
        .at(value)
        .find_map(|field| key_evidence(|name| key_terms(&fields.names()[name]), field, label))
}

/// Whether a context-free value at `value` (byte range) is the value of a field
/// that names another kind of value (F08): a structural key without a term of
/// `label`, or a field name ending in `:` or `=` right before it without a term
/// of `label` in the nearest proximity window (`DEA-Nummer: RN4135883`,
/// `Codice Fiscale: J3405H901`, a `driver_license_number` column). A bare
/// document check digit (7-3-1 mod 10) fits one in ten letter-led codes; the
/// field says what the code is.
pub(super) fn foreign_field(fields: &Fields, text: &str, value: Range<usize>, label: &str) -> bool {
    if fields.at(value.clone()).next().is_some() {
        return !structure_evidence(fields, value, label)
            .is_some_and(|evidence| evidence.context.supports());
    }
    if !text[..value.start]
        .trim_end_matches([' ', '\t'])
        .ends_with([':', '='])
    {
        return false;
    }
    let own = evidence(text, (value.start, value.end), label);
    !(own.context.supports()
        && own.side == Some(Side::Before)
        && own
            .distance
            .is_some_and(|distance| distance <= PROXIMITY_CONTEXT_POINTS[0].0))
}

/// Whether the structural key of the value at `value` (byte range) holds a term
/// of `label` itself although no key of the lexicon names it (`old passport
/// number: …`, F08). The old numeric serial carries no letter series: a document
/// term on another line (`passport: archived` before `member_code: …`) does not
/// claim it, a term inside its own key does.
pub(super) fn key_holds_term(
    fields: &Fields,
    text: &str,
    value: Range<usize>,
    label: &str,
) -> bool {
    fields.at(value.clone()).any(|field| {
        let own = evidence(text, (value.start, value.end), label);
        own.context.supports()
            && own.side == Some(Side::Before)
            && own.distance.is_some_and(|distance| {
                distance < text[field.key.start..value.start].chars().count()
            })
    })
}

/// Whether the value at `value` (byte range) stands alone rather than continuing
/// a number: no `+` that opens a phone number right before it, no `-`, `/`, `.` or
/// `,` joining it to a digit on either side, and no digit group one space away
/// (`+49 30 123 456 789`). A `+` after a letter or another `+` separates EDIFACT
/// elements (`NAD+SU+341-33-4328`, `LIN+1++…`, B-SSN). A context-free value (K05)
/// has no field name that delimits it. A value that starts with a letter (the
/// country prefix of a VAT ID, B01) is no decimal and no digit group: `,` and a
/// space delimit it, so `…,17810,DE396839779,150279-0487,…` in a CSV row stands alone.
pub(super) fn stands_alone(text: &str, value: Range<usize>) -> bool {
    let digit = |ch: Option<char>| ch.is_some_and(|ch| ch.is_ascii_digit());
    let numeric = digit(text[value.clone()].chars().next());
    let joins = |ch: char| matches!(ch, '-' | '/' | '.') || (numeric && ch == ',');
    let mut before = text[..value.start].chars().rev();
    let mut after = text[value.end..].chars();
    let (prev, prev2) = (before.next(), before.next());
    let (next, next2) = (after.next(), after.next());
    let element_separator = prev2.is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '+');
    !((prev == Some('+') && !element_separator)
        || (prev.is_some_and(joins) && digit(prev2))
        || (next.is_some_and(joins) && digit(next2))
        || (numeric && prev == Some(' ') && digit(prev2))
        || (next == Some(' ') && digit(next2)))
}

/// Whether a card candidate at `value` (byte range) can be a card number by its
/// position (B-PAN): not the digits after the `+` of a phone number
/// (`+44 20 1234 5678`), and not a segment of a token, i.e. joined by `-` or `_`
/// to alphanumerics on both sides (`xoxb-…-485275870833-…`) or, without a space
/// inside, to a run with a letter (`xoxb-249332005873`, `pkg-…`). No card scheme
/// prints 3-3-3-5 groups: that is a French SIRET (`566 618 468 58431`, B-EU1).
pub(super) fn card_position(text: &str, value: Range<usize>) -> bool {
    let joins = |ch: char| matches!(ch, '-' | '_');
    if text[value.clone()]
        .split(' ')
        .map(str::len)
        .eq([3, 3, 3, 5])
    {
        return false;
    }
    let head = &text[..value.start];
    let tail = &text[value.end..];
    if head.ends_with('+') {
        return false;
    }
    // The alphanumeric run joined to the value on each side, if any.
    let before = head
        .strip_suffix(joins)
        .map(|head| {
            let start = head
                .trim_end_matches(|ch: char| ch.is_ascii_alphanumeric())
                .len();
            &head[start..]
        })
        .filter(|run| !run.is_empty());
    let after = tail
        .strip_prefix(joins)
        .map(|tail| {
            let end = tail
                .find(|ch: char| !ch.is_ascii_alphanumeric())
                .unwrap_or(tail.len());
            &tail[..end]
        })
        .filter(|run| !run.is_empty());
    let lettered =
        |run: Option<&str>| run.is_some_and(|run| run.bytes().any(|b| b.is_ascii_alphabetic()));
    // A hyphenated card-field label before the value (`card-…`, `card-number-…`,
    // `kreditkarten-nr-…`) names the card; it is no token prefix.
    let card_label = before.is_some() && card_field_label(head);
    let compact = !text[value].contains(' ');
    !((before.is_some() && after.is_some())
        || (compact && ((lettered(before) && !card_label) || lettered(after))))
}

/// Whether `head` ends with a payment-card field label joined to the value by
/// `-` or `_`: the whole run of alphanumerics, `-` and `_` before the value is
/// a term of the card lexicon as a key (`card`, `card-number`, `kartennummer`).
fn card_field_label(head: &str) -> bool {
    let joins = |ch: char| matches!(ch, '-' | '_');
    let Some(head) = head.strip_suffix(joins) else {
        return false;
    };
    let start = head
        .trim_end_matches(|ch: char| ch.is_ascii_alphanumeric() || joins(ch))
        .len();
    key_terms(&normalize_key(&head[start..]))
        .iter()
        .any(|term| term.label == Some("CREDITCARD"))
}

/// Whether `text[within]` holds a payment card number as the card rule reports
/// it (B-PAN): a match of `card_regex` that passes [`validators::payment_card`]
/// and [`card_position`]. CVV and expiry fields depend on such a card.
pub(super) fn has_payment_card(text: &str, within: Range<usize>, card_regex: &Regex) -> bool {
    card_regex.find_iter(&text[within.clone()]).any(|matched| {
        let value = within.start + matched.start()..within.start + matched.end();
        validators::payment_card(matched.as_str()) && card_position(text, value)
    })
}

/// Whether an e-mail candidate at `start` opens inside the userinfo of a URL
/// (`postgres://user:pass@host`, `ssh://git@host`, T06): the run before it holds
/// only userinfo characters (RFC 3986) and follows `://`. Credentials there are
/// DLP findings; an address in a path or query (`/contact?email=a@b.de`) stays.
pub(super) fn url_userinfo(text: &str, start: usize) -> bool {
    text[..start]
        .trim_end_matches(|ch: char| ch.is_alphanumeric() || "-._~!$&'()*+,;=:%".contains(ch))
        .ends_with("://")
}

/// Whether an IPv4 candidate at `start` stands for itself rather than ending an
/// IPv6 address (B-IP): the `:`-run before it is no IPv6 head (`::ffff:`,
/// `64:ff9b::`, `2001:db8:1:2:3:4:`), so an IPv4-mapped or embedded address is one
/// IPv6 span and an invalid mixed form no IPv4 sub-span. A field name (`IP:`,
/// `web:`) or a SWIFT MT tag at the start of a line (`:25:`, ` :52A:`) stays.
pub(super) fn ipv4_position(text: &str, start: usize) -> bool {
    let head = &text[..start];
    if !head.ends_with(':') {
        return true;
    }
    let run = &head[head
        .trim_end_matches(|ch: char| ch.is_ascii_hexdigit() || ch == ':')
        .len()..];
    let line = head[..head.len() - run.len()].trim_end_matches([' ', '\t']);
    let line_start = line.is_empty() || line.ends_with('\n');
    let run = match swift_tag(run) {
        Some(tag) if line_start => &run[tag..],
        _ => run,
    };
    !(run.contains("::") || run.matches(':').count() >= 2)
}

/// Length of the SWIFT MT tag that opens `run` (`:25:`, `:28C:`), if any.
fn swift_tag(run: &str) -> Option<usize> {
    let bytes = run.as_bytes();
    let digits = bytes.len() >= 4
        && bytes[0] == b':'
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit();
    if !digits {
        return None;
    }
    match bytes[3] {
        b':' => Some(4),
        letter if letter.is_ascii_alphabetic() && bytes.get(4) == Some(&b':') => Some(5),
        _ => None,
    }
}

/// Whether an IPv6 candidate ending at `end` is the whole address (B-IP): no
/// further `:`-group (`380:21:3::90:FRET`, `1::1:550:::EA`), `.`-group
/// (`2001:db8::256.1.1.1`) or zone ID the rule did not take, and no letter, digit
/// or `_` right after it. A prefix length out of range stays outside the span
/// (`2001:db8::1/129`). Where the value may start is part of the rule's regex.
pub(super) fn ipv6_position(text: &str, end: usize) -> bool {
    let mut after = text[end..].chars();
    let (next, next2) = (after.next(), after.next());
    let word = |ch: Option<char>| ch.is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
    match next {
        Some(':') => !(word(next2) || next2 == Some(':')),
        Some('.' | '%') => !word(next2),
        next => !word(next),
    }
}

/// Whether an international phone number at `start` (its `+` or `00`) opens a
/// value rather than continuing an element run (T17): no letter or digit right
/// before it, so not `UNB+UNOC:3+520173321` or `NAD+BY+987654321`. A `+` also
/// does not follow another `+` (`MOA+1++…`) or a tag that starts with a digit
/// and `:` (`{86:+33…}`, `:62F:+…`); a field name and `:` (`Tel.:+49 …`,
/// `tel:+31…`, numbered `tel2:+49 …`) stay. `00` after `+` is the number of an EDIFACT `COM+0049…:TE` segment.
pub(super) fn opens_phone_number(text: &str, start: usize) -> bool {
    let plus = text[start..].starts_with('+');
    let head = &text[..start];
    match head.chars().next_back() {
        Some(ch) if ch.is_alphanumeric() => false,
        Some('+') => !plus,
        Some(':') if plus => {
            let head = &head[..head.len() - 1];
            let name = head
                .trim_end_matches(|ch: char| ch.is_alphanumeric() || ch == '.')
                .len();
            if name == head.len() {
                !head.ends_with([':', '+'])
            } else {
                !head[name..].starts_with(|ch: char| ch.is_ascii_digit())
            }
        }
        _ => true,
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
        || has_payment_card(text, field_start - context.len()..field_start, card_regex)
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

/// Whether a field value of letters continues on its line with a capitalized word
/// that is no further field name: a name, not an account (`Account Name: John Doe`,
/// `Account Name: ACME Inc.`, `Benutzername: Nicolas Lebrun`; Q-CONTACT). An
/// account in a credential line stays (`Username: JSmith Password: …`).
pub(super) fn continues_as_name(text: &str, value: Range<usize>) -> bool {
    let word = &text[value.clone()];
    let rest = &text[value.end..];
    let next = rest.trim_start_matches([' ', '\t']);
    let following = next.split([' ', '\t', '\r', '\n']).next().unwrap_or("");
    word.starts_with(char::is_uppercase)
        && word.chars().all(|ch| ch.is_alphabetic() || ch == '-')
        && next.len() < rest.len()
        && following.starts_with(char::is_uppercase)
        && !following.ends_with([':', '='])
}
