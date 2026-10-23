// SPDX-License-Identifier: GPL-3.0-only
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
/// Unix timestamps as phone numbers.
pub fn unanchored_phone(s: &str) -> bool {
    phone(s)
        && (s.starts_with('+')
            || s.starts_with("00")
            || s.chars()
                .any(|ch| matches!(ch, ' ' | '-' | '.' | '/' | '(' | ')')))
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

pub fn de_social_security_number(s: &str) -> bool {
    let normalized = s
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    normalized.len() == 12
        && normalized[..8].chars().all(|ch| ch.is_ascii_digit())
        && normalized[8..9].chars().all(|ch| ch.is_ascii_alphabetic())
        && normalized[9..].chars().all(|ch| ch.is_ascii_digit())
}

pub fn de_health_insurance_number(s: &str) -> bool {
    s.len() == 10
        && s[..1].chars().all(|ch| ch.is_ascii_alphabetic())
        && s[1..].chars().all(|ch| ch.is_ascii_digit())
        && !s[1..].chars().all(|ch| ch == '0')
}

pub fn lanr(s: &str) -> bool {
    s.len() == 9 && s.chars().all(|ch| ch.is_ascii_digit()) && !s.chars().all(|ch| ch == '0')
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
    let sum: u32 = digits[..8]
        .iter()
        .zip([5, 4, 3, 2, 7, 6, 5, 4])
        .map(|(digit, weight)| digit * weight)
        .sum();
    let check = (11 - sum % 11) % 11;
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
    let number = siren
        .iter()
        .fold(0u64, |number, &digit| number * 10 + u64::from(digit));
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
    let number = digits[..8]
        .iter()
        .fold(0u32, |number, &digit| number * 10 + digit);
    digits[0] <= 1 && number != 0 && 97 - number % 97 == digits[8] * 10 + digits[9]
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
    let number = middle
        .iter()
        .fold(0u32, |number, &digit| number * 10 + digit);
    let letter = |number: u32| ES_CONTROL_LETTERS[(number % 23) as usize];
    match first {
        b'0'..=b'9' => last == letter(u32::from(first - b'0') * 10_000_000 + number),
        b'X' | b'Y' | b'Z' => last == letter(u32::from(first - b'X') * 10_000_000 + number),
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
    use super::{ip_address, postal_address_de};

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
