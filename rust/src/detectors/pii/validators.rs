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
