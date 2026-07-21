// SPDX-License-Identifier: GPL-3.0-only
use std::net::IpAddr;

/// Validate an IPv4 or IPv6 candidate matched by a PII regex.
pub fn ip_address(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// Luhn algorithm (ISO/IEC 7812) — credit card number validation.
/// Strips whitespace and dashes before checking.
pub fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
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

    sum % 10 == 0
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
