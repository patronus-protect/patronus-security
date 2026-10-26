// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{net::IpAddr, sync::LazyLock};

/// Validate an IPv4 or IPv6 candidate matched by a PII regex. The span may end in a
/// CIDR prefix length (`/0`–`/32`, `/0`–`/128`) and an IPv6 address in a zone ID
/// before it (`fe80::1%eth0`, `2001:db8::%eth0/128`, B-IP). Loopback, unspecified
/// and multicast addresses are rejected, also as the IPv4 part of an IPv4-mapped
/// address (`::ffff:127.0.0.1`).
pub fn ip_address(s: &str) -> bool {
    let (address, prefix) = match s.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (s, None),
    };
    let (address, zone) = match address.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (address, None),
    };
    let Ok(candidate) = address.parse::<IpAddr>() else {
        return false;
    };
    let max_prefix = if candidate.is_ipv4() { 32 } else { 128 };
    if prefix.is_some_and(|prefix| {
        prefix.is_empty()
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
            || prefix
                .parse::<u8>()
                .map_or(true, |length| length > max_prefix)
    }) || zone.is_some_and(|zone| candidate.is_ipv4() || zone.is_empty())
    {
        return false;
    }
    let local = |candidate: IpAddr| {
        candidate.is_loopback() || candidate.is_multicast() || candidate.is_unspecified()
    };
    if local(candidate) {
        return false;
    }
    match candidate {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => {
            if v6
                .to_ipv4_mapped()
                .is_some_and(|mapped| local(IpAddr::V4(mapped)))
            {
                return false;
            }
            let compact = address.trim();
            compact.len() >= 7
                && ((compact.contains("::")
                    && compact.chars().filter(|ch| *ch == ':').count() >= 2)
                    || compact.split(':').filter(|part| !part.is_empty()).count() >= 3)
        }
    }
}

/// The address of an IP span without its zone ID and CIDR prefix length
/// (`fe80::1%eth0` → `fe80::1`, `192.0.2.0/24` → `192.0.2.0`).
pub fn ip_address_part(s: &str) -> &str {
    s.split(['%', '/']).next().unwrap_or(s)
}

/// Luhn algorithm (ISO/IEC 7812) — credit card number validation.
/// Strips whitespace and dashes before checking.
pub fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 12 || digits.len() > 19 || digits.iter().all(|digit| *digit == digits[0]) {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Payment card brand of an IIN range (B-PAN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardBrand {
    AmericanExpress,
    DinersClub,
    Discover,
    Jcb,
    Maestro,
    Mastercard,
    Mir,
    UnionPay,
    Uatp,
    Visa,
}

/// One IIN range of a brand: card numbers whose first `low.len()` digits lie in
/// `low..=high` and whose digit count is one of `lengths`.
#[derive(Debug)]
pub struct CardIinRange {
    pub brand: CardBrand,
    pub low: &'static str,
    pub high: &'static str,
    pub lengths: &'static [usize],
}

const fn iin(
    brand: CardBrand,
    low: &'static str,
    high: &'static str,
    lengths: &'static [usize],
) -> CardIinRange {
    CardIinRange {
        brand,
        low,
        high,
        lengths,
    }
}

const SIXTEEN_TO_NINETEEN: &[usize] = &[16, 17, 18, 19];
const FOURTEEN_TO_NINETEEN: &[usize] = &[14, 15, 16, 17, 18, 19];

/// IIN prefixes and lengths of the card brands (ISO/IEC 7812 issuer ranges as the
/// networks publish them). First match names the brand: Discover and UnionPay come
/// before the wider Maestro ranges. JCB is `35` as test-card generators issue it
/// (the network's own range is 3528–3589), plus the 15-digit `1800`/`2131`.
pub const CARD_IIN_RANGES: &[CardIinRange] = &[
    iin(CardBrand::AmericanExpress, "34", "34", &[15]),
    iin(CardBrand::AmericanExpress, "37", "37", &[15]),
    iin(CardBrand::DinersClub, "300", "305", FOURTEEN_TO_NINETEEN),
    iin(CardBrand::DinersClub, "3095", "3095", FOURTEEN_TO_NINETEEN),
    iin(CardBrand::DinersClub, "36", "36", FOURTEEN_TO_NINETEEN),
    iin(CardBrand::DinersClub, "38", "39", FOURTEEN_TO_NINETEEN),
    iin(CardBrand::Jcb, "35", "35", SIXTEEN_TO_NINETEEN),
    iin(CardBrand::Jcb, "1800", "1800", &[15]),
    iin(CardBrand::Jcb, "2131", "2131", &[15]),
    iin(CardBrand::Mir, "2200", "2204", SIXTEEN_TO_NINETEEN),
    iin(CardBrand::Mastercard, "2221", "2720", &[16]),
    iin(CardBrand::Mastercard, "51", "55", &[16]),
    iin(CardBrand::Visa, "4", "4", &[13, 16, 19]),
    iin(CardBrand::Discover, "6011", "6011", SIXTEEN_TO_NINETEEN),
    iin(CardBrand::Discover, "644", "649", SIXTEEN_TO_NINETEEN),
    iin(CardBrand::Discover, "65", "65", SIXTEEN_TO_NINETEEN),
    iin(CardBrand::UnionPay, "62", "62", SIXTEEN_TO_NINETEEN),
    iin(
        CardBrand::Maestro,
        "50",
        "50",
        &[12, 13, 14, 15, 16, 17, 18, 19],
    ),
    iin(
        CardBrand::Maestro,
        "56",
        "69",
        &[12, 13, 14, 15, 16, 17, 18, 19],
    ),
    iin(CardBrand::Uatp, "1", "1", &[15]),
];

/// Brand of a card number by IIN prefix and length; separators are ignored.
pub fn card_brand(s: &str) -> Option<CardBrand> {
    let digits: String = s.chars().filter(char::is_ascii_digit).collect();
    CARD_IIN_RANGES
        .iter()
        .find(|range| {
            range.lengths.contains(&digits.len())
                && digits
                    .get(..range.low.len())
                    .is_some_and(|prefix| (range.low..=range.high).contains(&prefix))
        })
        .map(|range| range.brand)
}

/// A payment card number: [`luhn`] plus the IIN prefix and a length of a brand
/// ([`CARD_IIN_RANGES`]). Thirteen digits that open with a valid YYMMDD birth date
/// are a national ID (ZA ID number, KR resident registration number), and digits
/// that open with a valid YYYYMMDD date a time stamp, not a card.
pub fn payment_card(s: &str) -> bool {
    if !luhn(s) || card_brand(s).is_none() {
        return false;
    }
    let digits: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    let number = |range: std::ops::Range<usize>| {
        digits[range]
            .iter()
            .fold(0u16, |value, digit| value * 10 + u16::from(*digit))
    };
    let birth_date_id = digits.len() == 13 && {
        let (year, month, day) = (number(0..2), number(2..4), number(4..6));
        // Any century: the two-digit year only decides February 29.
        valid_date(day as u8, month as u8, 2000 + year)
    };
    let time_stamp = matches!(number(0..2), 19 | 20)
        && valid_date(number(6..8) as u8, number(4..6) as u8, number(0..4));
    !birth_date_id && !time_stamp
}

pub fn phone(s: &str) -> bool {
    let digits = s
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<Vec<_>>();
    (7..=15).contains(&digits.len()) && !digits.iter().all(|digit| *digit == digits[0])
}

/// Validate an unanchored phone candidate without treating bare numeric IDs or
/// Unix timestamps as phone numbers. A NANP extension (`x4587`, `ext. 123`, F18)
/// is not part of the number the checks count.
pub fn unanchored_phone(s: &str) -> bool {
    let number = s
        .find(|ch: char| ch.is_ascii_alphabetic())
        .map_or(s, |extension| s[..extension].trim_end());
    phone(number)
        && (number.starts_with('+')
            || number.starts_with("00")
            || number
                .chars()
                .any(|ch| matches!(ch, ' ' | '-' | '.' | '/' | '(' | ')')))
}

/// Top-level domains delegated by IANA, verbatim from
/// <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>: a version comment, then
/// one uppercase domain per line in byte order (punycode as `XN--…`).
const IANA_TLDS: &str = include_str!("iana_tlds.txt");

/// Reserved placeholder TLDs (RFC 2606/6761); gold convention T01 counts their
/// addresses as PII.
const PLACEHOLDER_TLDS: [&str; 4] = ["example", "invalid", "localhost", "test"];

/// Validate an e-mail candidate by its top-level domain (F05): delegated by IANA
/// or a reserved placeholder, in any letter case. `alice@email.note` and
/// `anna@firma.intern` are no addresses.
pub fn email_domain(s: &str) -> bool {
    static TLDS: LazyLock<Vec<&str>> = LazyLock::new(|| {
        IANA_TLDS
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect()
    });
    let Some((address, tld)) = s.rsplit_once('.') else {
        return false;
    };
    address.contains('@')
        && (TLDS
            .binary_search_by(|probe| {
                probe
                    .bytes()
                    .cmp(tld.bytes().map(|byte| byte.to_ascii_uppercase()))
            })
            .is_ok()
            || PLACEHOLDER_TLDS
                .iter()
                .any(|placeholder| placeholder.eq_ignore_ascii_case(tld)))
}

pub fn mac_address(s: &str) -> bool {
    let separator = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return false;
    };
    let parts = s.split(separator).collect::<Vec<_>>();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
        && !parts.iter().all(|part| *part == "00")
}

pub fn cvv(s: &str) -> bool {
    matches!(s.len(), 3 | 4) && s.chars().all(|ch| ch.is_ascii_digit())
}

pub fn card_expiry(s: &str) -> bool {
    let Some((month, year)) = s.split_once(['/', '-']) else {
        return false;
    };
    month
        .parse::<u8>()
        .is_ok_and(|month| (1..=12).contains(&month))
        && matches!(year.len(), 2 | 4)
        && year.chars().all(|ch| ch.is_ascii_digit())
}

pub fn bic(s: &str) -> bool {
    s.is_ascii()
        && matches!(s.len(), 8 | 11)
        && s[..4].chars().all(|ch| ch.is_ascii_alphabetic())
        && s[4..6].chars().all(|ch| ch.is_ascii_alphabetic())
        && s[6..].chars().all(|ch| ch.is_ascii_alphanumeric())
}

pub fn bounded_identifier(s: &str) -> bool {
    (3..=32).contains(&s.len())
        && s.chars().any(|ch| ch.is_ascii_digit())
        && s.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/' | '-'))
        && !s.chars().all(|ch| ch == '0')
}

pub fn bounded_employee_identifier(s: &str) -> bool {
    let compact = s
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    bounded_identifier(&compact)
}

pub fn username(s: &str) -> bool {
    (2..=64).contains(&s.len())
        && s.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '-'))
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "admin" | "root" | "user" | "username"
        )
        && !PROSE_WORDS.contains(&s.to_ascii_lowercase().as_str())
}

/// Words that follow "login"/"username" in documentation and UI text, not account names.
const PROSE_WORDS: &[&str] = &[
    "available",
    "button",
    "case",
    "code",
    "credentials",
    "empty",
    "erforderlich",
    "falsch",
    "feld",
    "field",
    "flow",
    "form",
    "incorrect",
    "invalid",
    "leer",
    "link",
    "maske",
    "missing",
    "none",
    "null",
    "optional",
    "page",
    "password",
    "prompt",
    "required",
    "screen",
    "seite",
    "session",
    "taken",
    "token",
    "unbekannt",
    "unknown",
    "url",
    "valid",
    "wrong",
];

pub fn calendar_date(s: &str) -> bool {
    let parts = s.split(['.', '/', '-']).collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    let (Ok(day), Ok(month), Ok(year)) = (
        parts[0].parse::<u8>(),
        parts[1].parse::<u8>(),
        parts[2].parse::<u16>(),
    ) else {
        return false;
    };
    let year = if parts[2].len() == 2 {
        1900 + year
    } else {
        year
    };
    valid_date(day, month, year)
}

pub fn written_calendar_date(s: &str) -> bool {
    let normalized = s.to_lowercase().replace([',', '.'], " ");
    let parts = normalized.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }

    let parse_day = |part: &str| {
        part.trim_end_matches(|ch: char| ch.is_ascii_alphabetic())
            .parse::<u8>()
            .ok()
    };
    let parse_month = |part: &str| match part {
        "januar" | "january" => Some(1),
        "februar" | "february" => Some(2),
        "märz" | "maerz" | "march" => Some(3),
        "april" => Some(4),
        "mai" | "may" => Some(5),
        "juni" | "june" => Some(6),
        "juli" | "july" => Some(7),
        "august" => Some(8),
        "september" => Some(9),
        "oktober" | "october" => Some(10),
        "november" => Some(11),
        "dezember" | "december" => Some(12),
        _ => None,
    };

    let parsed = if let (Some(day), Some(month), Ok(year)) = (
        parse_day(parts[0]),
        parse_month(parts[1]),
        parts[2].parse::<u16>(),
    ) {
        Some((day, month, year))
    } else if let (Some(month), Some(day), Ok(year)) = (
        parse_month(parts[0]),
        parse_day(parts[1]),
        parts[2].parse::<u16>(),
    ) {
        Some((day, month, year))
    } else {
        None
    };

    parsed.is_some_and(|(day, month, year)| valid_date(day, month, year))
}

fn valid_date(day: u8, month: u8, year: u16) -> bool {
    if !(1900..=2100).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=max_day).contains(&day)
}

pub fn de_tax_number(s: &str) -> bool {
    let digits = s
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<Vec<_>>();
    (10..=13).contains(&digits.len()) && !digits.iter().all(|digit| *digit == digits[0])
}

/// German pension insurance number (Rentenversicherungsnummer, VKVV § 4; B-DE1):
/// area (two digits), birth day (01–31, or 51–81 with the supplementary mark),
/// birth month (01–12), birth year, the initial of the birth name, a serial of two
/// digits and the check digit. The check digit is the sum of the cross sums of the
/// eleven digits, the letter as 01…26 after the eighth, weighted
/// 2-1-2-5-7-1-2-1-2-1-2-1, mod 10. Spaces or tabs may group the value
/// (`15 070649 C 103`); the letter may be lower case after a field name.
pub fn de_social_security_number(s: &str) -> bool {
    let mut value = [0u8; 12];
    let mut len = 0;
    for byte in s.bytes().filter(|byte| !matches!(byte, b' ' | b'\t')) {
        if len == value.len() {
            return false;
        }
        value[len] = byte;
        len += 1;
    }
    if len != value.len()
        || !value[8].is_ascii_alphabetic()
        || !value
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 8 || byte.is_ascii_digit())
    {
        return false;
    }
    let digit = |index: usize| u32::from(value[index] - b'0');
    let (day, month) = (digit(2) * 10 + digit(3), digit(4) * 10 + digit(5));
    if !matches!(day, 1..=31 | 51..=81) || !(1..=12).contains(&month) {
        return false;
    }
    let [tens, ones] = letter_digits(value[8]);
    let digits = [
        digit(0),
        digit(1),
        digit(2),
        digit(3),
        digit(4),
        digit(5),
        digit(6),
        digit(7),
        tens,
        ones,
        digit(9),
        digit(10),
    ];
    weighted_cross_sum(&digits, &[2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1]) % 10 == digit(11)
}

/// German health insurance number (Krankenversichertennummer, KVNR, § 290 SGB V;
/// B-DE1): the initial of the birth name, eight digits and the check digit. The
/// check digit is the sum of the cross sums of the letter as 01…26 and the eight
/// digits, weighted 1-2-1-2…, mod 10. Nine zeros are never issued; the letter may
/// be lower case after a field name.
pub fn de_health_insurance_number(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 10
        || !bytes[0].is_ascii_alphabetic()
        || !bytes[1..].iter().all(u8::is_ascii_digit)
        || bytes[1..].iter().all(|&byte| byte == b'0')
    {
        return false;
    }
    let mut digits = [0; 10];
    digits[..2].copy_from_slice(&letter_digits(bytes[0]));
    for (digit, byte) in digits[2..].iter_mut().zip(&bytes[1..9]) {
        *digit = u32::from(byte - b'0');
    }
    weighted_cross_sum(&digits, &[1, 2, 1, 2, 1, 2, 1, 2, 1, 2]) % 10 == u32::from(bytes[9] - b'0')
}

/// The alphabet position of an ASCII letter as two digits (`A` = 0 1 … `Z` = 2 6),
/// the way the KVNR and the pension insurance number weigh their letter.
fn letter_digits(letter: u8) -> [u32; 2] {
    let position = u32::from(letter.to_ascii_uppercase() - b'A' + 1);
    [position / 10, position % 10]
}

/// Sum of the cross sums of `digits` times `weights`, pairwise.
fn weighted_cross_sum(digits: &[u32], weights: &[u32]) -> u32 {
    digits
        .iter()
        .zip(weights)
        .map(|(digit, weight)| {
            let product = digit * weight;
            product / 10 + product % 10
        })
        .sum()
}

/// Lifelong physician number (Lebenslange Arztnummer, LANR, KBV Arztnummern-
/// Richtlinie; B-DE1): six digits of the physician, the check digit and two digits
/// of the specialty group. The check digit complements the sum of the six digits,
/// weighted 4-9-4-9-4-9, to the next multiple of ten. One repeated digit passes the
/// check but is never issued.
pub fn lanr(s: &str) -> bool {
    grouped_digits::<9>(s).is_some_and(|digits| {
        !one_repeated_digit(&digits)
            && (10 - weighted_sum(&digits[..6], &[4, 9, 4, 9, 4, 9]) % 10) % 10 == digits[6]
    })
}

pub fn de_document_number(s: &str) -> bool {
    const ALPHABET: &str = "0123456789CFGHJKLMNPRTVWXYZ";
    s.len() == 9
        && s.chars()
            .all(|ch| ALPHABET.contains(ch.to_ascii_uppercase()))
}

/// ICAO 9303 (part 3) check digit of an MRZ field: weights 7, 3, 1 repeating,
/// digits at face value, `A`=10 … `Z`=35, the filler `<` is 0; `None` for any
/// other character.
pub fn icao_check_digit(data: &str) -> Option<u32> {
    data.chars()
        .zip([7, 3, 1].into_iter().cycle())
        .try_fold(0, |total, (ch, weight)| {
            let value = match ch {
                '0'..='9' => ch.to_digit(10)?,
                'A'..='Z' => u32::from(ch) - u32::from('A') + 10,
                '<' => 0,
                _ => return None,
            };
            Some(total + value * weight)
        })
        .map(|total| total % 10)
}

/// A German document number with its ICAO 9303 check digit (F08): a letter of
/// `series`, then characters of the ICAO alphabet without vowels and lookalikes
/// (`0-9CFGHJKLMNPRTVWXYZ`), eight in all plus the check digit, or the nine
/// character serial plus the check digit of the MRZ; or the old numeric serial,
/// nine digits plus the check digit. Letters are all upper or all lower case.
fn de_document_check_digit(s: &str, series: &str) -> bool {
    const ALPHABET: &str = "0123456789CFGHJKLMNPRTVWXYZ";
    if !s.is_ascii()
        || !matches!(s.len(), 9 | 10)
        || (s.bytes().any(|byte| byte.is_ascii_uppercase())
            && s.bytes().any(|byte| byte.is_ascii_lowercase()))
    {
        return false;
    }
    let upper = s.to_ascii_uppercase();
    let (data, check) = upper.split_at(upper.len() - 1);
    let first = data.chars().next().unwrap_or_default();
    let numeric = upper.len() == 10 && upper.bytes().all(|byte| byte.is_ascii_digit());
    let lettered = series.contains(first) && data.chars().all(|ch| ALPHABET.contains(ch));
    ((numeric && upper.bytes().any(|byte| byte != b'0')) || lettered)
        && check
            .parse::<u32>()
            .is_ok_and(|digit| icao_check_digit(data) == Some(digit))
}

/// German passport number (Reisepass): series C, F, G, H, J, K, or the old
/// numeric serial, with its ICAO 9303 check digit (F08).
pub fn de_passport_number(s: &str) -> bool {
    de_document_check_digit(s, "CFGHJK")
}

/// German identity card number (Personalausweis): series L, M, N, P, R, T, V,
/// W, X, Y, or the old numeric serial, with its ICAO 9303 check digit (F08).
pub fn de_identity_card_number(s: &str) -> bool {
    de_document_check_digit(s, "LMNPRTVWXY")
}

pub fn de_driver_license_number(s: &str) -> bool {
    s.len() == 11 && s.chars().all(|ch| ch.is_ascii_alphanumeric())
}

/// The US state formats of a driver's licence number (F15), without the hyphens
/// that group its digits: the letter and digit runs that presidio-analyzer's
/// `UsLicenseRecognizer` lists after ntsi.com/drivers-license-format, from one
/// letter and four digits up, and Washington's `WDL` plus nine characters. Six to
/// fourteen digits alone are a format too (New York, Texas, Pennsylvania …).
static US_DRIVER_LICENSE_FORMATS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"\A(?:[A-Z][0-9]{4,14}|[A-Z]{2}[0-9]{3,7}|[0-9]{6,14}|[0-9]{7,9}[A-Z]|[0-9]{8}[A-Z]{2}|[A-Z]{2}[0-9]{6}[A-Z]|[0-9]{3}[A-Z]{2}[0-9]{4}|[0-9]{2}[A-Z]{3}[0-9]{5,6}|WDL[A-Z0-9]{9})\z",
    )
    .unwrap()
});

/// US driver's licence number in a state format (F15). Format only: no state
/// publishes a check digit. A hyphenated calendar date (`2031-04-30`,
/// `30-04-2031`, `04-30-2031`, an expiry next to the field name) is no licence
/// number.
pub fn us_driver_license_number(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let date = match parts[..] {
        [first, second, third] => match (
            first.parse::<u16>(),
            second.parse::<u8>(),
            third.parse::<u16>(),
        ) {
            (Ok(first_value), Ok(month_or_day), Ok(third_value)) => {
                let year = if third.len() == 2 {
                    1900 + third_value
                } else {
                    third_value
                };
                (first.len() == 4
                    && u8::try_from(third_value)
                        .is_ok_and(|day| valid_date(day, month_or_day, first_value)))
                    || u8::try_from(first_value).is_ok_and(|value| {
                        valid_date(value, month_or_day, year)
                            || valid_date(month_or_day, value, year)
                    })
            }
            _ => false,
        },
        _ => false,
    };
    !date && US_DRIVER_LICENSE_FORMATS.is_match(&parts.concat())
}

/// Italian patente (F15): two letters, seven digits and a letter on the card
/// (`RM5512345K`), or `U1`, seven characters without the letters A, I, O, Q and V,
/// and a letter on the paper licence (`U1H34K56LX`). Format only.
pub fn it_driver_license_number(s: &str) -> bool {
    let bytes = s.as_bytes();
    let card = bytes.len() == 10
        && bytes[..2].iter().all(u8::is_ascii_uppercase)
        && bytes[2..9].iter().all(u8::is_ascii_digit)
        && bytes[9].is_ascii_uppercase();
    let paper = bytes.len() == 10
        && bytes.starts_with(b"U1")
        && bytes[2..9]
            .iter()
            .all(|byte| byte.is_ascii_digit() || b"BCDEFGHJKLMNPRSTUWXYZ".contains(byte))
        && bytes[9].is_ascii_uppercase();
    card || paper
}

/// Nine digits, not one repeated digit: the form of a UK passport number (B-UK), as
/// HM Passport Office numbers the 2015 and later designs (`925665416`), and of a BSNR
/// (B-DE1, `721234567`). Neither carries a check digit.
pub fn nine_digits(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 9
        && bytes.iter().all(u8::is_ascii_digit)
        && bytes.iter().any(|&byte| byte != bytes[0])
}

/// Passport number of two letters and seven digits (`PA1234567` Ireland,
/// `TK1234567` Japan). Format only.
pub fn passport_number_two_letters(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 9
        && bytes[..2].iter().all(u8::is_ascii_uppercase)
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

/// UK driving licence number (B-UK): the first five letters of the surname padded
/// with `9`, the decade digit of the birth year, the birth month (plus 50 for
/// women), the day, the year digit, two initials (`9` for none), a digit or letter
/// and two check letters (`MORGA657054SM9IJ`). The DVLA does not publish the
/// check algorithm: format only.
pub fn uk_driver_license_number(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 16 {
        return false;
    }
    let letters = bytes[..5]
        .iter()
        .take_while(|byte| byte.is_ascii_uppercase())
        .count();
    let number = |at: usize| (bytes[at] - b'0') * 10 + (bytes[at + 1] - b'0');
    letters > 0
        && bytes[letters..5].iter().all(|&byte| byte == b'9')
        && bytes[5..11].iter().all(u8::is_ascii_digit)
        && matches!(number(6), 1..=12 | 51..=62)
        && matches!(number(8), 1..=31)
        && bytes[11..13]
            .iter()
            .all(|&byte| byte.is_ascii_uppercase() || byte == b'9')
        && (bytes[13].is_ascii_uppercase() || bytes[13].is_ascii_digit())
        && bytes[14..].iter().all(u8::is_ascii_uppercase)
}

pub fn us_ssn(s: &str) -> bool {
    let digits = s
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.len() != 9 {
        return false;
    }
    let area = &digits[..3];
    let group = &digits[3..5];
    let serial = &digits[5..];
    area != "000"
        && area != "666"
        && !area.starts_with('9')
        && group != "00"
        && serial != "0000"
        && digits != "078051120"
        && digits != "219099999"
}

/// A grouped SSN without an SSN term (B-SSN): the SSA ranges of [`us_ssn`] and
/// none of the placeholder values presidio-analyzer rejects as well, one digit
/// repeated (`111-11-1111`) or the counting sequence `123-45-6789`.
pub fn us_ssn_context_free(s: &str) -> bool {
    let digits = s.bytes().filter(u8::is_ascii_digit).collect::<Vec<_>>();
    us_ssn(s) && digits.iter().any(|&digit| digit != digits[0]) && digits != b"123456789"
}

pub fn uk_nino(s: &str) -> bool {
    let normalized = s.replace(' ', "").to_ascii_uppercase();
    if normalized.len() != 9 {
        return false;
    }
    let bytes = normalized.as_bytes();
    let first = bytes[0] as char;
    let second = bytes[1] as char;
    first.is_ascii_alphabetic()
        && second.is_ascii_alphabetic()
        && !matches!(first, 'D' | 'F' | 'I' | 'Q' | 'U' | 'V')
        && !matches!(second, 'D' | 'F' | 'I' | 'O' | 'Q' | 'U' | 'V')
        && !matches!(
            &normalized[..2],
            "BG" | "GB" | "KN" | "NK" | "NT" | "TN" | "ZZ"
        )
        && normalized[2..8].chars().all(|ch| ch.is_ascii_digit())
        && matches!(bytes[8] as char, 'A' | 'B' | 'C' | 'D')
}

/// A NINO without a field name (B-UK): [`uk_nino`] in one letter case, as a bare
/// identifier is written (`AB123456C`, `hh 01 02 03 d`).
pub fn uk_nino_context_free(s: &str) -> bool {
    let letters = || s.bytes().filter(u8::is_ascii_alphabetic);
    uk_nino(s)
        && (letters().all(|byte| byte.is_ascii_uppercase())
            || letters().all(|byte| byte.is_ascii_lowercase()))
}

/// NHS number (B-UK): ten digits, grouped by spaces or hyphens or not at all,
/// whose sum weighted 10 down to 1 is divisible by 11. A number whose check digit
/// would be 10 is never issued; one repeated digit passes the sum but is no number.
pub fn uk_nhs_number(s: &str) -> bool {
    grouped_digits::<10>(s).is_some_and(|digits| {
        !one_repeated_digit(&digits)
            && weighted_sum(&digits, &[10, 9, 8, 7, 6, 5, 4, 3, 2, 1]).is_multiple_of(11)
    })
}

/// The `N` digits of `s` with spaces and hyphens removed, if `s` holds exactly
/// `N` ASCII digits besides them.
fn grouped_digits<const N: usize>(s: &str) -> Option<[u32; N]> {
    let mut digits = [0u32; N];
    let mut count = 0;
    for byte in s.bytes().filter(|byte| !matches!(byte, b' ' | b'-')) {
        if !byte.is_ascii_digit() || count == N {
            return None;
        }
        digits[count] = u32::from(byte - b'0');
        count += 1;
    }
    (count == N).then_some(digits)
}

/// Whether every digit equals the first: such a value passes many weighted sums
/// but is never issued.
fn one_repeated_digit(digits: &[u32]) -> bool {
    digits.iter().all(|&digit| digit == digits[0])
}

/// Australian Business Number (B-APAC): eleven digits, no leading zero; with one
/// subtracted from the first digit, the sum weighted 10 1 3 5 … 19 is divisible
/// by 89 (the two leading digits are its check digits).
pub fn au_abn(s: &str) -> bool {
    grouped_digits::<11>(s).is_some_and(|mut digits| {
        digits[0] != 0 && {
            digits[0] -= 1;
            weighted_sum(&digits, &[10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]).is_multiple_of(89)
        }
    })
}

/// Australian Company Number (B-APAC): nine digits, the last
/// `(10 − sum of the first eight weighted 8…1 mod 10) mod 10`; one repeated digit
/// is never issued.
pub fn au_acn(s: &str) -> bool {
    grouped_digits::<9>(s).is_some_and(|digits| {
        !one_repeated_digit(&digits)
            && (10 - weighted_sum(&digits[..8], &[8, 7, 6, 5, 4, 3, 2, 1]) % 10) % 10 == digits[8]
    })
}

/// Australian Tax File Number (B-APAC): nine digits whose sum weighted
/// 1 4 3 7 5 8 6 9 10 is divisible by 11; one repeated digit is never issued.
pub fn au_tfn(s: &str) -> bool {
    grouped_digits::<9>(s).is_some_and(|digits| {
        !one_repeated_digit(&digits)
            && weighted_sum(&digits, &[1, 4, 3, 7, 5, 8, 6, 9, 10]).is_multiple_of(11)
    })
}

/// Australian Medicare card number (B-APAC): ten digits starting with 2 to 6; the
/// ninth is the first eight weighted 1 3 7 9 1 3 7 9 mod 10, the tenth the card's
/// issue number.
pub fn au_medicare(s: &str) -> bool {
    grouped_digits::<10>(s).is_some_and(|digits| {
        (2..=6).contains(&digits[0])
            && weighted_sum(&digits[..8], &[1, 3, 7, 9, 1, 3, 7, 9]) % 10 == digits[8]
    })
}

/// Singapore NRIC/FIN (B-APAC): series letter, seven digits, check letter, in
/// either case. The digits weighted 2 7 6 5 4 3 2, plus 4 for the 2000s series
/// `T` and `G` and 3 for `M`, mod 11 index the check letters of the series:
/// `S`/`T` for citizens and permanent residents, `F`/`G`/`M` for foreigners.
pub fn sg_nric_fin(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 9 || !bytes[1..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let (offset, letters): (u32, &[u8; 11]) = match bytes[0].to_ascii_uppercase() {
        b'S' => (0, b"JZIHGFEDCBA"),
        b'T' => (4, b"JZIHGFEDCBA"),
        b'F' => (0, b"XWUTRQPNMLK"),
        b'G' => (4, b"XWUTRQPNMLK"),
        b'M' => (3, b"XWUTRQPNJLK"),
        _ => return false,
    };
    let sum: u32 = bytes[1..8]
        .iter()
        .zip([2, 7, 6, 5, 4, 3, 2])
        .map(|(byte, weight)| u32::from(byte - b'0') * weight)
        .sum();
    let index = (sum + offset) % 11;
    letters[index as usize] == bytes[8].to_ascii_uppercase()
}

/// Entity types of a format-C UEN (`T08LL0001A`), as ACRA issues them.
const UEN_ENTITY_TYPES: [&[u8; 2]; 39] = [
    b"LP", b"LL", b"FC", b"PF", b"RF", b"MQ", b"MM", b"NB", b"CC", b"CS", b"MB", b"FM", b"GS",
    b"DP", b"CP", b"NR", b"CM", b"CD", b"MD", b"HS", b"VH", b"CH", b"MH", b"CL", b"XL", b"CX",
    b"HC", b"RP", b"TU", b"TC", b"FB", b"FN", b"PA", b"PB", b"SS", b"MC", b"SM", b"GA", b"GB",
];

/// Singapore Unique Entity Number (B-APAC), uppercase, in one of three formats
/// with a check letter mod 11: A, businesses, eight digits (weights
/// 10 4 9 3 8 2 7 1, letters `XMKECAWLJDB`); B, local companies, a registration
/// year from 1800 to 2099 and five digits (weights 10 8 6 4 9 7 5 3 1, letters
/// `ZKCMDNERGWH`); C, other entities, `T`/`S`/`R` for the century, two year
/// digits, an entity type and four digits (characters indexed in
/// `ABCDEFGHJKLMNPQRSTUVWX0123456789`, weights 4 3 5 3 10 2 2 5 7, the sum minus 5).
pub fn sg_uen(s: &str) -> bool {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWX0123456789";
    let bytes = s.as_bytes();
    let Some((&check, body)) = bytes.split_last() else {
        return false;
    };
    let numeric = |part: &[u8]| part.iter().all(u8::is_ascii_digit);
    let letter = |letters: &[u8; 11], weights: &[u32]| {
        let sum: u32 = body
            .iter()
            .zip(weights)
            .map(|(byte, weight)| u32::from(byte - b'0') * weight)
            .sum();
        letters[(sum % 11) as usize] == check
    };
    match body.len() {
        8 if numeric(body) => letter(b"XMKECAWLJDB", &[10, 4, 9, 3, 8, 2, 7, 1]),
        9 if numeric(body) => {
            matches!(&body[..2], b"18" | b"19" | b"20")
                && letter(b"ZKCMDNERGWH", &[10, 8, 6, 4, 9, 7, 5, 3, 1])
        }
        9 => {
            if !matches!(body[0], b'T' | b'S' | b'R')
                || !numeric(&body[1..3])
                || !UEN_ENTITY_TYPES.iter().any(|kind| body[3..5] == kind[..])
                || !numeric(&body[5..9])
            {
                return false;
            }
            body.iter()
                .zip([4, 3, 5, 3, 10, 2, 2, 5, 7])
                .map(|(byte, weight)| {
                    let index = ALPHABET.iter().position(|known| known == byte)?;
                    Some(index as u32 * weight)
                })
                .sum::<Option<u32>>()
                .is_some_and(|sum| ALPHABET[((sum + 11 - 5) % 11) as usize] == check)
        }
        _ => false,
    }
}

/// ISO 13616 Mod-97 check — IBAN validation.
/// Strips whitespace before checking.
pub fn mod97(s: &str) -> bool {
    let normalized: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if normalized.len() < 5 {
        return false;
    }
    // Move first 4 characters to end
    let rearranged = format!("{}{}", &normalized[4..], &normalized[..4]);
    // Convert letters A–Z to 10–35
    let numeric: String = rearranged
        .chars()
        .flat_map(|c| {
            if c.is_ascii_uppercase() {
                let n = c as u32 - b'A' as u32 + 10;
                // n is always 10–35, so always two digits
                vec![
                    char::from_digit(n / 10, 10).unwrap(),
                    char::from_digit(n % 10, 10).unwrap(),
                ]
            } else {
                vec![c]
            }
        })
        .collect();

    // Compute mod 97 in chunks to avoid integer overflow
    let mut remainder = 0u64;
    for ch in numeric.chars() {
        if let Some(d) = ch.to_digit(10) {
            remainder = (remainder * 10 + d as u64) % 97;
        }
    }
    remainder == 1
}

/// ISO 7064 MOD 11,10 — German Steueridentifikationsnummer (11 digits).
/// Strips whitespace before checking.
pub fn steuer_id(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 11 {
        return false;
    }
    // First digit must not be 0
    if digits[0] == 0 {
        return false;
    }

    let mut product = 10u32;
    for &digit in &digits[..10] {
        let sum = (digit + product) % 10;
        let sum = if sum == 0 { 10 } else { sum };
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    check == digits[10]
}

/// A Steuer-ID as the BZSt issues it: [`steuer_id`] plus the digit distribution
/// of the first ten digits. Exactly one digit occurs twice or three times, never
/// three times in a row; every other digit occurs at most once.
pub fn steuer_id_issued(s: &str) -> bool {
    if !steuer_id(s) {
        return false;
    }
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_digit).take(10).collect();
    let mut counts = [0u8; 10];
    for digit in &digits {
        counts[usize::from(digit - b'0')] += 1;
    }
    let repeated: Vec<_> = counts.iter().filter(|&&count| count > 1).collect();
    repeated.len() == 1
        && matches!(repeated[0], 2 | 3)
        && !digits
            .windows(3)
            .any(|run| run[0] == run[1] && run[1] == run[2])
}

// ── VAT identification numbers (B01) ──────────────────────────────────────
// One validator per country. Each takes the printed form (`DE 136 695 976`,
// `CHE-100.155.212`) and checks the check digit of the issuing authority.

/// The alphanumerics of `s` in upper case after the country prefix `prefix`:
/// `DE.136.695.976` → `136695976`. A value without the prefix stays whole.
fn vat_body(s: &str, prefix: &str) -> String {
    let compact: String = s
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    match compact.strip_prefix(prefix) {
        Some(body) => body.to_string(),
        None => compact,
    }
}

/// The decimal digits of `s`, if `s` has exactly `len` characters, all digits.
fn vat_digits(s: &str, len: usize) -> Option<Vec<u32>> {
    (s.len() == len && s.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| s.bytes().map(|byte| u32::from(byte - b'0')).collect())
}

/// Luhn checksum of `digits` with the last digit undoubled, in `0..10`.
fn luhn_checksum(digits: &[u32]) -> u32 {
    digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| match index % 2 {
            0 => digit,
            _ if digit > 4 => digit * 2 - 9,
            _ => digit * 2,
        })
        .sum::<u32>()
        % 10
}

/// Sum of `digits` times `weights`, pairwise; the shorter of the two decides.
fn weighted_sum(digits: &[u32], weights: &[u32]) -> u32 {
    digits
        .iter()
        .zip(weights)
        .map(|(digit, weight)| digit * weight)
        .sum()
}

/// The decimal value of `digits`.
fn decimal(digits: &[u32]) -> u64 {
    digits
        .iter()
        .fold(0, |number, &digit| number * 10 + u64::from(digit))
}

/// ISO 7064 MOD 11,10 check digit of `digits`.
fn iso7064_mod11_10(digits: &[u32]) -> u32 {
    let product = digits.iter().fold(10, |product, &digit| {
        let sum = (digit + product) % 10;
        (if sum == 0 { 10 } else { sum }) * 2 % 11
    });
    (11 - product) % 10
}

/// German USt-IdNr.: `DE` and nine digits, no leading zero, the last an
/// ISO 7064 MOD 11,10 check digit.
pub fn de_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "DE"), 9) else {
        return false;
    };
    digits[0] != 0 && iso7064_mod11_10(&digits[..8]) == digits[8]
}

/// Austrian UID: `ATU` and eight digits; the check digit is
/// `(6 − Luhn checksum of the first seven) mod 10`.
pub fn at_vat_id(s: &str) -> bool {
    let body = vat_body(s, "AT");
    let Some(digits) = body.strip_prefix('U').and_then(|body| vat_digits(body, 8)) else {
        return false;
    };
    (16 - luhn_checksum(&digits[..7])) % 10 == digits[7]
}

/// Swiss UID (`CHE-123.456.789`, the MWST number without its `MWST`/`TVA`/`IVA`
/// suffix): nine digits, the last a weighted mod 11 check digit (weights
/// 5 4 3 2 7 6 5 4; remainder 10 is never issued).
pub fn ch_vat_id(s: &str) -> bool {
    let mut body = vat_body(s, "CHE");
    for suffix in ["MWST", "TVA", "IVA", "TPV"] {
        if let Some(stripped) = body.strip_suffix(suffix) {
            body = stripped.to_string();
            break;
        }
    }
    let Some(digits) = vat_digits(&body, 9) else {
        return false;
    };
    let check = (11 - weighted_sum(&digits[..8], &[5, 4, 3, 2, 7, 6, 5, 4]) % 11) % 11;
    check != 10 && check == digits[8]
}

/// French numéro de TVA: `FR`, a two-digit key and the nine-digit SIREN. The key
/// is `(12 + 3 × (SIREN mod 97)) mod 97`; the SIREN passes Luhn except for the
/// Monaco range `000…`. Keys with letters are not accepted.
pub fn fr_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "FR"), 11) else {
        return false;
    };
    let siren = &digits[2..];
    let number = decimal(siren);
    let key = u64::from(digits[0] * 10 + digits[1]);
    (siren[..3] == [0, 0, 0] || luhn_checksum(siren) == 0) && key == (number * 100 + 12) % 97
}

/// Dutch btw-id: `NL`, nine digits, `B` and a branch number `01`–`99`. Either the
/// nine digits pass the mod 11 check of the former format (weights 9…2, minus
/// the last digit) or the whole ID passes ISO 7064 MOD 97-10 (sole traders
/// since 2020).
pub fn nl_vat_id(s: &str) -> bool {
    let body = vat_body(s, "NL");
    if body.len() != 12 || body.as_bytes()[9] != b'B' {
        return false;
    }
    let (Some(digits), Some(branch)) = (vat_digits(&body[..9], 9), vat_digits(&body[10..], 2))
    else {
        return false;
    };
    if digits.iter().all(|&digit| digit == 0) || branch == [0, 0] {
        return false;
    }
    let weighted = digits[..8]
        .iter()
        .zip((2..=9).rev())
        .map(|(digit, weight)| digit * weight)
        .sum::<u32>();
    let mod11 = (weighted + 11 * 9 - digits[8]) % 11 == 0;
    let mod97 = format!("NL{body}")
        .chars()
        .filter_map(|ch| ch.to_digit(36))
        .fold(0u32, |remainder, value| {
            let shift = if value > 9 { 100 } else { 10 };
            (remainder * shift + value) % 97
        })
        == 1;
    mod11 || mod97
}

/// Belgian BTW/TVA number: `BE` and ten digits starting with `0` or `1`; the
/// last two are `97 − (first eight mod 97)`.
pub fn be_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "BE"), 10) else {
        return false;
    };
    let number = decimal(&digits[..8]);
    digits[0] <= 1 && number != 0 && 97 - number % 97 == decimal(&digits[8..])
}

/// Italian Partita IVA, with or without `IT`: eleven digits, a company number
/// that is not zero, a province office code `001`–`100`, `120`, `121`, `888` or
/// `999`, and a Luhn check digit.
pub fn it_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "IT"), 11) else {
        return false;
    };
    let office = digits[7] * 100 + digits[8] * 10 + digits[9];
    digits[..7].iter().any(|&digit| digit != 0)
        && matches!(office, 1..=100 | 120 | 121 | 888 | 999)
        && luhn_checksum(&digits) == 0
}

/// Control letters of the Spanish DNI/NIE by remainder mod 23.
const ES_CONTROL_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spanish NIF-IVA: `ES` and a DNI (eight digits and a control letter), an NIE
/// (`X`/`Y`/`Z`, seven digits, control letter), a NIF of `K`/`L`/`M` or a CIF
/// (entity letter, seven digits and a control digit or letter).
pub fn es_vat_id(s: &str) -> bool {
    let body = vat_body(s, "ES");
    let bytes = body.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    let (first, last) = (bytes[0], bytes[8]);
    let Some(middle) = vat_digits(&body[1..8], 7) else {
        return false;
    };
    let number = decimal(&middle);
    let letter = |number: u64| ES_CONTROL_LETTERS[(number % 23) as usize];
    match first {
        b'0'..=b'9' => last == letter(u64::from(first - b'0') * 10_000_000 + number),
        b'X' | b'Y' | b'Z' => last == letter(u64::from(first - b'X') * 10_000_000 + number),
        b'K' | b'L' | b'M' => last == letter(number),
        b'A'..=b'H' | b'J' | b'N' | b'P'..=b'S' | b'U'..=b'W' => {
            let sum: u32 = middle
                .iter()
                .enumerate()
                .map(|(index, &digit)| match index % 2 {
                    0 => digit * 2 / 10 + digit * 2 % 10,
                    _ => digit,
                })
                .sum();
            let check = (10 - sum % 10) % 10;
            last == b'0' + check as u8 || last == b"JABCDEFGHI"[check as usize]
        }
        _ => false,
    }
}

// ── VAT identification numbers, part 2 (B02) ──────────────────────────────

/// The VAT body of `s` after the first of `prefixes` that opens it.
fn vat_body_of(s: &str, prefixes: &[&str]) -> String {
    let compact = vat_body(s, "");
    prefixes
        .iter()
        .find_map(|prefix| compact.strip_prefix(prefix))
        .unwrap_or(&compact)
        .to_string()
}

/// The decimal digits of `s` if its length is one of `lengths` and not every
/// digit is zero.
fn vat_number(s: &str, lengths: &[usize]) -> Option<Vec<u32>> {
    lengths
        .contains(&s.len())
        .then(|| vat_digits(s, s.len()))
        .flatten()
        .filter(|digits| digits.iter().any(|&digit| digit != 0))
}

/// Bulgarian ИН по ДДС: `BG` and nine digits (legal entity: weights 1…8 mod 11,
/// on remainder 10 weights 3…10) or ten digits that pass one of the three
/// ten-digit checks: an ЕГН with a valid birth date from 1900 on (weights
/// 2 4 8 5 10 9 7 3 6 mod 11), an ЛНЧ of a foreigner (weights 21 19 17 13 11 9 7 3 1 mod 10) or
/// another person (weights 4 3 2 7 6 5 4 3 2, `11 − sum mod 11`).
pub fn bg_vat_id(s: &str) -> bool {
    let Some(digits) = vat_number(&vat_body(s, "BG"), &[9, 10]) else {
        return false;
    };
    if digits.len() == 9 {
        let mut check = weighted_sum(&digits[..8], &[1, 2, 3, 4, 5, 6, 7, 8]) % 11;
        if check == 10 {
            check = weighted_sum(&digits[..8], &[3, 4, 5, 6, 7, 8, 9, 10]) % 11;
        }
        return check % 10 == digits[8];
    }
    let (year, month, day) = (
        digits[0] * 10 + digits[1],
        digits[2] * 10 + digits[3],
        digits[4] * 10 + digits[5],
    );
    let (year, month) = match month {
        41.. => (2000 + year, month - 40),
        21.. => (1800 + year, month - 20),
        _ => (1900 + year, month),
    };
    let birth_date = u8::try_from(day).is_ok_and(|day| {
        u8::try_from(month).is_ok_and(|month| valid_date(day, month, year as u16))
    });
    let egn = birth_date
        && weighted_sum(&digits[..9], &[2, 4, 8, 5, 10, 9, 7, 3, 6]) % 11 % 10 == digits[9];
    let foreigner = weighted_sum(&digits[..9], &[21, 19, 17, 13, 11, 9, 7, 3, 1]) % 10 == digits[9];
    let other =
        (11 - weighted_sum(&digits[..9], &[4, 3, 2, 7, 6, 5, 4, 3, 2]) % 11) % 11 == digits[9];
    egn || foreigner || other
}

/// Cypriot ΦΠΑ number: `CY`, eight digits not starting with `12` and a check
/// letter: the digits at even positions map to 1 0 5 7 9 13 15 17 19 21, the
/// others count as they are, the sum mod 26 is the letter `A`…`Z`.
pub fn cy_vat_id(s: &str) -> bool {
    let body = vat_body(s, "CY");
    let Some((&letter, number)) = body.as_bytes().split_last() else {
        return false;
    };
    let Some(digits) = std::str::from_utf8(number)
        .ok()
        .and_then(|number| vat_number(number, &[8]))
    else {
        return false;
    };
    const EVEN: [u32; 10] = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21];
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(index, &digit)| match index % 2 {
            0 => EVEN[digit as usize],
            _ => digit,
        })
        .sum();
    digits[..2] != [1, 2] && letter == b'A' + (sum % 26) as u8
}

/// Czech DIČ: `CZ` and eight digits of a legal entity (not starting with `9`,
/// weights 8…2, check `(11 − sum mod 11) mod 11`, 0 → 1, 10 → 0), nine digits
/// starting with `6` (special case: weights 8…2 over the middle seven, check
/// `(sum mod 11 + 8) mod 10`) or a ten-digit birth number (rodné číslo) with a
/// valid birth date, divisible by 11 (remainder 10 with check digit 0).
/// Nine-digit birth numbers (before 1954) carry no check digit and are not
/// accepted.
pub fn cz_vat_id(s: &str) -> bool {
    let Some(digits) = vat_number(&vat_body(s, "CZ"), &[8, 9, 10]) else {
        return false;
    };
    let weights = [8, 7, 6, 5, 4, 3, 2];
    match digits.len() {
        8 => {
            let check = (11 - weighted_sum(&digits[..7], &weights) % 11) % 11;
            digits[0] != 9 && (if check == 0 { 1 } else { check }) % 10 == digits[7]
        }
        9 => {
            let check = weighted_sum(&digits[1..8], &weights) % 11;
            digits[0] == 6 && (check + 8) % 10 == digits[8]
        }
        _ => {
            let (year, month, day) = (
                digits[0] * 10 + digits[1],
                digits[2] * 10 + digits[3],
                digits[4] * 10 + digits[5],
            );
            let year = if year >= 54 { 1900 + year } else { 2000 + year };
            matches!(month, 1..=12 | 21..=32 | 51..=62 | 71..=82)
                && valid_date(day as u8, (month % 50 % 20) as u8, year as u16)
                && decimal(&digits[..9]) % 11 % 10 == u64::from(digits[9])
        }
    }
}

/// Danish CVR/SE number: `DK` and eight digits, no leading zero, weights
/// 2 7 6 5 4 3 2 1 sum to a multiple of 11.
pub fn dk_vat_id(s: &str) -> bool {
    vat_number(&vat_body(s, "DK"), &[8]).is_some_and(|digits| {
        digits[0] != 0 && weighted_sum(&digits, &[2, 7, 6, 5, 4, 3, 2, 1]).is_multiple_of(11)
    })
}

/// Estonian KMKR number: `EE` and nine digits starting with `10`, weights
/// 3 7 1 3 7 1 3 7 1 sum to a multiple of 10.
pub fn ee_vat_id(s: &str) -> bool {
    vat_number(&vat_body(s, "EE"), &[9]).is_some_and(|digits| {
        digits[..2] == [1, 0]
            && weighted_sum(&digits, &[3, 7, 1, 3, 7, 1, 3, 7, 1]).is_multiple_of(10)
    })
}

/// Greek ΑΦΜ with the VAT prefix `EL` (also `GR`): nine digits, the last is
/// `(Σ digit × 2^(9 − position)) mod 11 mod 10` over the first eight.
pub fn el_vat_id(s: &str) -> bool {
    vat_number(&vat_body_of(s, &["EL", "GR"]), &[9]).is_some_and(|digits| {
        let sum = digits[..8].iter().fold(0, |sum, &digit| sum * 2 + digit);
        sum * 2 % 11 % 10 == digits[8]
    })
}

/// Finnish ALV number: `FI` and eight digits (the Y-tunnus without its hyphen),
/// weights 7 9 10 5 8 4 2 1 sum to a multiple of 11.
pub fn fi_vat_id(s: &str) -> bool {
    vat_number(&vat_body(s, "FI"), &[8])
        .is_some_and(|digits| weighted_sum(&digits, &[7, 9, 10, 5, 8, 4, 2, 1]).is_multiple_of(11))
}

/// Croatian OIB with the VAT prefix `HR`: eleven digits, the last an ISO 7064
/// MOD 11,10 check digit.
pub fn hr_vat_id(s: &str) -> bool {
    vat_number(&vat_body(s, "HR"), &[11])
        .is_some_and(|digits| iso7064_mod11_10(&digits[..10]) == digits[10])
}

/// Hungarian közösségi adószám: `HU` and eight digits, weights 9 7 3 1 9 7 3 1
/// sum to a multiple of 10.
pub fn hu_vat_id(s: &str) -> bool {
    vat_number(&vat_body(s, "HU"), &[8])
        .is_some_and(|digits| weighted_sum(&digits, &[9, 7, 3, 1, 9, 7, 3, 1]).is_multiple_of(10))
}

/// Check characters of the Irish VAT number by remainder mod 23.
const IE_CHECK_LETTERS: &[u8; 23] = b"WABCDEFGHIJKLMNOPQRSTUV";

/// Irish VAT number: `IE`, seven digits, a check letter and an optional second
/// letter (since 2013), or the old form of a digit, a letter, `+` or `*`, five
/// digits and the check letter (read as `0`, the five digits and the first
/// digit). The check letter is `(Σ weights 8…2 + 9 × value of the second
/// letter) mod 23` over `W A B … V`.
pub fn ie_vat_id(s: &str) -> bool {
    // `vat_body` would drop the `+` or `*` of the old form.
    let compact: String = s
        .chars()
        .filter(|&ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '*'))
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    let body = compact.strip_prefix("IE").unwrap_or(&compact);
    let bytes = body.as_bytes();
    let letter_value = |byte: u8| IE_CHECK_LETTERS.iter().position(|&letter| letter == byte);
    if !matches!(bytes.len(), 8 | 9) || !bytes[7..].iter().all(|&byte| letter_value(byte).is_some())
    {
        return false;
    }
    let (digits, second) = if let Some(digits) = vat_digits(&body[..7], 7) {
        (
            digits,
            bytes
                .get(8)
                .and_then(|&byte| letter_value(byte))
                .unwrap_or(0),
        )
    } else if bytes.len() == 8 && matches!(bytes[1], b'A'..=b'Z' | b'+' | b'*') {
        let Some(tail) = vat_digits(&body[2..7], 5) else {
            return false;
        };
        let Some(first) = vat_digits(&body[..1], 1) else {
            return false;
        };
        ([&[0], &tail[..], &first[..]].concat(), 0)
    } else {
        return false;
    };
    let sum = weighted_sum(&digits, &[8, 7, 6, 5, 4, 3, 2]) + 9 * second as u32;
    digits.iter().any(|&digit| digit != 0) && IE_CHECK_LETTERS[(sum % 23) as usize] == bytes[7]
}

/// Lithuanian PVM mokėtojo kodas: `LT` and nine digits (legal person, eighth
/// digit `1`) or twelve digits (temporary taxpayer, eleventh digit `1`); the
/// check digit uses weights 1…9, 1, 2 … mod 11, on remainder 10 weights shifted
/// by two, and remainder 10 again gives 0.
pub fn lt_vat_id(s: &str) -> bool {
    let Some(digits) = vat_number(&vat_body(s, "LT"), &[9, 12]) else {
        return false;
    };
    let (number, check) = digits.split_at(digits.len() - 1);
    let sum = |shift: usize| -> u32 {
        number
            .iter()
            .enumerate()
            .map(|(index, &digit)| (1 + (index + shift) % 9) as u32 * digit)
            .sum::<u32>()
            % 11
    };
    let mut remainder = sum(0);
    if remainder == 10 {
        remainder = sum(2);
    }
    number[number.len() - 1] == 1 && remainder % 10 == check[0]
}

// ── VAT identification numbers, part 3 (B16) ──────────────────────────────

/// Luxembourg numéro TVA: `LU` and eight digits; the last two are the first six
/// mod 89.
pub fn lu_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "LU"), 8) else {
        return false;
    };
    decimal(&digits[..6]) % 89 == decimal(&digits[6..])
}

/// Latvian PVN number of a legal entity: `LV` and eleven digits, the first `4`–`9`,
/// weighted 9 1 4 8 3 10 2 5 7 6 1 to a remainder mod 11 of 3. The personal codes
/// of natural persons (first digit `0`–`3`) carry no confirmed check digit and
/// are not accepted.
pub fn lv_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "LV"), 11) else {
        return false;
    };
    digits[0] > 3 && weighted_sum(&digits, &[9, 1, 4, 8, 3, 10, 2, 5, 7, 6, 1]) % 11 == 3
}

/// Maltese VAT number: `MT` and eight digits without a leading zero, weighted
/// 3 4 6 7 8 9 10 1 to a multiple of 37.
pub fn mt_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "MT"), 8) else {
        return false;
    };
    digits[0] != 0 && weighted_sum(&digits, &[3, 4, 6, 7, 8, 9, 10, 1]).is_multiple_of(37)
}

/// Polish NIP with `PL`: ten digits, the last the weighted sum of the first nine
/// (6 5 7 2 3 4 5 6 7) mod 11; remainder 10 is never issued.
pub fn pl_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "PL"), 10) else {
        return false;
    };
    weighted_sum(&digits[..9], &[6, 5, 7, 2, 3, 4, 5, 6, 7]) % 11 == digits[9]
}

/// Portuguese NIF with `PT`: nine digits without a leading zero, the last
/// `11 − (weighted sum 9…2 mod 11)`, where 10 and 11 become 0.
pub fn pt_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "PT"), 9) else {
        return false;
    };
    let check = (11 - weighted_sum(&digits[..8], &[9, 8, 7, 6, 5, 4, 3, 2]) % 11) % 11 % 10;
    digits[0] != 0 && check == digits[8]
}

/// Romanian CUI/CIF with `RO`: two to ten digits without a leading zero; the
/// last is `10 × weighted sum mod 11 mod 10` of the others, right-aligned to the
/// weights 7 5 3 2 1 7 5 3 2. A CNP (13 digits) is not accepted.
pub fn ro_vat_id(s: &str) -> bool {
    let body = vat_body(s, "RO");
    if !(2..=10).contains(&body.len()) || body.starts_with('0') {
        return false;
    }
    let Some(digits) = vat_digits(&body, body.len()) else {
        return false;
    };
    let (number, check) = digits.split_at(digits.len() - 1);
    let weights = &[7, 5, 3, 2, 1, 7, 5, 3, 2][9 - number.len()..];
    10 * weighted_sum(number, weights) % 11 % 10 == check[0]
}

/// Swedish momsregistreringsnummer: `SE`, the ten-digit organisation number
/// (Luhn) and `01`.
pub fn se_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "SE"), 12) else {
        return false;
    };
    digits[10..] == [0, 1] && luhn_checksum(&digits[..10]) == 0
}

/// Slovenian ID za DDV: `SI` and eight digits without a leading zero, the last
/// `11 − (weighted sum 8…2 mod 11)`, where 10 becomes 0 and 11 is never issued.
pub fn si_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "SI"), 8) else {
        return false;
    };
    let check = 11 - weighted_sum(&digits[..7], &[8, 7, 6, 5, 4, 3, 2]) % 11;
    digits[0] != 0 && check != 11 && check % 10 == digits[7]
}

/// Slovak IČ DPH: `SK` and ten digits without a leading zero, the third `2`, `3`,
/// `4`, `7`, `8` or `9`, the number a multiple of 11. A birth number (rodné
/// číslo) is not accepted.
pub fn sk_vat_id(s: &str) -> bool {
    let Some(digits) = vat_digits(&vat_body(s, "SK"), 10) else {
        return false;
    };
    digits[0] != 0
        && matches!(digits[2], 2 | 3 | 4 | 7 | 8 | 9)
        && decimal(&digits).is_multiple_of(11)
}

/// Norwegian MVA number: `NO`, the nine-digit organisation number (weights
/// 3 2 7 6 5 4 3 2 1 to a multiple of 11) and `MVA`.
pub fn no_vat_id(s: &str) -> bool {
    let body = vat_body(s, "NO");
    let Some(digits) = body
        .strip_suffix("MVA")
        .and_then(|number| vat_digits(number, 9))
    else {
        return false;
    };
    weighted_sum(&digits, &[3, 2, 7, 6, 5, 4, 3, 2, 1]).is_multiple_of(11)
}

/// UK VAT registration number with `GB`, or `XI` for Northern Ireland: nine
/// digits, optionally followed by a three-digit branch. The first nine weighted
/// 8 7 6 5 4 3 2 10 1 are a multiple of 97, or 42 mod 97 (the "9755" scheme,
/// from `100 0000 00` on). The government department and health authority forms
/// (`GD`, `HA`) carry no check digit and are not accepted.
pub fn gb_vat_id(s: &str) -> bool {
    let body = vat_body(s, "GB");
    let body = body.strip_prefix("XI").unwrap_or(&body);
    let Some(digits) = vat_digits(body, 9).or_else(|| vat_digits(body, 12)) else {
        return false;
    };
    match weighted_sum(&digits, &[8, 7, 6, 5, 4, 3, 2, 10, 1]) % 97 {
        0 => true,
        42 => digits[0] != 0,
        _ => false,
    }
}

pub fn postal_address_de(s: &str) -> bool {
    let mut parts = s.split_whitespace();
    let Some(postal_code) = parts.next() else {
        return false;
    };
    let Some(city) = parts.next() else {
        return false;
    };
    if postal_code == "00000"
        || postal_code.len() != 5
        || !postal_code.chars().all(|ch| ch.is_ascii_digit())
    {
        return false;
    }
    !matches!(
        city.to_ascii_lowercase().as_str(),
        "chunk"
            | "error"
            | "file"
            | "input"
            | "line"
            | "lines"
            | "original"
            | "output"
            | "process"
            | "result"
            | "token"
            | "tokens"
            | "total"
            | "trace"
            | "warning"
    )
}

#[cfg(test)]
mod tests {
    use super::{ip_address, postal_address_de, IANA_TLDS};

    #[test]
    fn iana_tlds_are_uppercase_and_sorted_for_binary_search() {
        let mut lines = IANA_TLDS.lines();
        assert!(lines.next().unwrap().starts_with("# Version "));
        let tlds: Vec<_> = lines.collect();
        assert!(tlds.len() > 1000);
        assert!(tlds.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(tlds.iter().all(|tld| tld
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')));
    }

    #[test]
    fn ip_address_rejects_local_and_tiny_ipv6_literals() {
        assert!(!ip_address("::"));
        assert!(!ip_address("::1"));
        assert!(!ip_address("a::"));
        assert!(!ip_address("on"));
        assert!(ip_address("192.168.10.42"));
        assert!(ip_address("2001:db8::1"));
    }

    #[test]
    fn postal_address_de_rejects_terminal_metadata_words() {
        assert!(postal_address_de("10115 Berlin"));
        assert!(!postal_address_de("00000 Berlin"));
        assert!(!postal_address_de("12345 Output"));
        assert!(!postal_address_de("12345 Tokens"));
    }
}
