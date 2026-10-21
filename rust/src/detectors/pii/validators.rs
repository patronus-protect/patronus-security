// SPDX-License-Identifier: GPL-3.0-only
use std::net::IpAddr;

/// Validate an IPv4 or IPv6 candidate matched by a PII regex.
pub fn ip_address(s: &str) -> bool {
    let Ok(candidate) = s.parse::<IpAddr>() else {
        return false;
    };
    if candidate.is_loopback() || candidate.is_multicast() || candidate.is_unspecified() {
        return false;
    }
    match candidate {
        IpAddr::V4(_) => true,
        IpAddr::V6(_) => {
            let compact = s.trim();
            compact.len() >= 7
                && ((compact.contains("::")
                    && compact.chars().filter(|ch| *ch == ':').count() >= 2)
                    || compact.split(':').filter(|part| !part.is_empty()).count() >= 3)
        }
    }
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

pub fn de_driver_license_number(s: &str) -> bool {
    s.len() == 11 && s.chars().all(|ch| ch.is_ascii_alphanumeric())
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
