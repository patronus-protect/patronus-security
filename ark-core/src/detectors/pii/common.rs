// SPDX-License-Identifier: MIT OR Apache-2.0
//! Country-neutral contact and network identifiers: e-mail, IP and MAC addresses, E.164 phone numbers.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── Email ────────────────────────────────────────────────────────────────
// B-EMAIL: a local part holds Unicode letters, digits and marks (RFC 6531) and
// apostrophes between them (`jürgen.müller`, `moeleprêtr`, `o'neil`, never `'@`).
// Chinese and Japanese text puts no spaces between words, so Han, hiragana and
// katakana are no part of such a run; a local part of their own is at most
// three ideographs or katakana (`伟伟许` in `联系邮箱伟伟许@aol.com`). Domain labels hold Unicode letters
// except those scripts, the top-level domain is ASCII letters or punycode
// (`xn--p1ai`) and `validators::email_domain` checks it against IANA (F05). The
// userinfo of a URL is no address (`context::url_userinfo`, T06). Format
// strength plus base 55 keeps the score of 0.70 without context.
pub(super) const EMAIL: PiiPattern = PiiPattern {
    name: "pii_email",
    pattern: r"(?:[\p{L}\p{N}\p{M}._%+\-&&[^\p{Han}\p{Hiragana}\p{Katakana}]]+(?:'[\p{L}\p{N}\p{M}._%+\-&&[^\p{Han}\p{Hiragana}\p{Katakana}]]+)*|[\p{Han}\p{Katakana}]{1,3})@[\p{L}\p{N}\p{M}.\-&&[^\p{Han}\p{Hiragana}\p{Katakana}]]+\.(?:[xX][nN]--[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*|[a-zA-Z]{2,})",
    entity_group: "EMAIL",
    validator: Some(validators::email_domain),
    strength: ValidatorStrength::Format,
    base_score: 55,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

// ── IP-Adressen ─────────────────────────────────────────────────────────
// B-IP: an address span holds its CIDR prefix length and, for IPv6, its zone ID
// (`192.0.2.0/24`, `fe80::1%eth0`, `2001:db8::%eth0/128`); an IPv4-mapped or
// embedded IPv6 address is one span (`::ffff:192.0.2.1`, `64:ff9b::198.51.100.1`).
// `validators::ip_address` checks the whole span. The IPv6 rules capture `value`
// after what opens it: the start of the text or a character that is no word
// character, `.`, `:`, `+` (EDIFACT) or `-`, optionally followed by a field name
// and `:` (`IPv6:`, `IP-Adresse:`), or a SWIFT MT tag at the start of a line
// (`:25:`, ` :52A:`). They never start inside a colon chain (`:28C::52D:`,
// `BGM+380:21:3::90:FRET`); `context::ipv6_position` rejects a value that a
// further `:`-group or `.`-group continues, so an invalid chain or mixed address
// (`2001:db8::256.1.1.1`) yields no sub-span. A prefix length out of range is not
// part of the span (`10.0.0.0/123` → `10.0.0.0`, as in the presidio-analyzer tests).
pub(super) const IPV4: PiiPattern = PiiPattern {
    name: "pii_ipv4",
    pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/(?:3[0-2]|[12]?\d))?\b",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

pub(super) const IPV6_FULL: PiiPattern = PiiPattern {
    name: "pii_ipv6_full",
    pattern: r"(?:(?:^|[^\w.:+\-])(?:[0-9A-Za-z\-]*[G-Zg-z][0-9A-Za-z\-]*:)?|(?m:^)[ \t]*:\d{2}[A-Za-z]?:)(?P<value>(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7})(?:%[0-9A-Za-z]+(?:[._\-][0-9A-Za-z]+)*)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d)\b)?)",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

pub(super) const IPV6_COMPRESSED: PiiPattern = PiiPattern {
    name: "pii_ipv6_compressed",
    pattern: r"(?:(?:^|[^\w.:+\-])(?:[0-9A-Za-z\-]*[G-Zg-z][0-9A-Za-z\-]*:)?|(?m:^)[ \t]*:\d{2}[A-Za-z]?:)(?P<value>[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6}::(?:(?:[0-9A-Fa-f]{1,4}:){0,5}(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?(?:%[0-9A-Za-z]+(?:[._\-][0-9A-Za-z]+)*)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d)\b)?)",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

pub(super) const IPV6_LOOPBACK: PiiPattern = PiiPattern {
    name: "pii_ipv6_loopback",
    pattern: r"(?:(?:^|[^\w.:+\-])(?:[0-9A-Za-z\-]*[G-Zg-z][0-9A-Za-z\-]*:)?|(?m:^)[ \t]*:\d{2}[A-Za-z]?:)(?P<value>::(?:(?:[0-9A-Fa-f]{1,4}:){0,5}(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?:%[0-9A-Za-z]+(?:[._\-][0-9A-Za-z]+)*)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d)\b)?)",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

// ── Telefon ──────────────────────────────────────────────────────────────
pub(super) const PHONE_INTERNATIONAL: PiiPattern = PiiPattern {
    name: "pii_phone_international",
    // No separator is a line break (T18): `+1-123-456-7890\n\n2` ends before it.
    // A `+1` and ten digits take a NANP extension like `pii_phone_us` (F18), so the
    // earlier rule does not keep `+1-604-696` of `+1-604-696-5272x565`; without an
    // extension the second branch matches as before.
    pattern: concat!(
        r"\+(?:1(?:[\s./()\-&&[^\n-\r\x85\x{2028}\x{2029}]]*\d){10}",
        nanp_extension!(),
        r"|[1-9](?:[\s./()\-&&[^\n-\r\x85\x{2028}\x{2029}]]*\d){6,14})\b"
    ),
    entity_group: "PHONE",
    validator: Some(validators::unanchored_phone),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

// ── MAC-Adresse ─────────────────────────────────────────────────────────
pub(super) const MAC_ADDRESS: PiiPattern = PiiPattern {
    name: "pii_mac_address",
    pattern: r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b",
    entity_group: "MAC_ADDRESS",
    validator: Some(validators::mac_address),
    strength: ValidatorStrength::Format,
    base_score: 55,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};
