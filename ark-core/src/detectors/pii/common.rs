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
// after what opens it (`ipv6_opener!`): the start of the text or a character that
// is no word character, `.`, `:`, `+` (EDIFACT) or `-`, optionally followed by a
// field name and `:` (`IPv6:`, `IP-Adresse:`, `eth0:`), or a SWIFT MT tag at the
// start of a line (`:25:`, ` :52A:`). A field name does not end in a hex run of
// three or more characters with a digit: that run is a further `:`-group glued to
// a word (`foo2001:db8::10.0.0.1`, T28). They never start inside a colon chain
// (`:28C::52D:`, `BGM+380:21:3::90:FRET`); `context::ipv6_position` rejects a value that a
// further `:`-group or `.`-group continues, so an invalid chain or mixed address
// (`2001:db8::256.1.1.1`) yields no sub-span. A prefix length out of range is not
// part of the span (`10.0.0.0/123` → `10.0.0.0`, as in the presidio-analyzer tests).
macro_rules! ipv6_opener {
    () => {
        r"(?:(?:^|[^\w.:+\-])(?:[0-9A-Za-z\-]*[G-Zg-z](?:[0-9A-Za-z\-]*[G-Zg-z\-])?(?:[A-Fa-f]+|[0-9A-Fa-f]{1,2})?:)?|(?m:^)[ \t]*:\d{2}[A-Za-z]?:)"
    };
}

// The address forms of the IPv6 rules after `ipv6_opener!`: all eight groups or
// six and an embedded IPv4 address (`ipv6_full!`), groups and `::`
// (`ipv6_compressed!`), each with `$first` as its first group, and an address
// that opens with `::` (`ipv6_loopback!`). `ipv6_suffix!` is the optional zone ID
// and prefix length after any of them.
macro_rules! ipv6_full {
    ($first:literal) => {
        concat!(
            r"(?:",
            $first,
            r":(?:[0-9A-Fa-f]{1,4}:){5}",
            ipv4_dotted!(),
            r"|",
            $first,
            r"(?::[0-9A-Fa-f]{1,4}){7})"
        )
    };
}

macro_rules! ipv6_compressed {
    ($first:literal) => {
        concat!(
            $first,
            r"(?::[0-9A-Fa-f]{1,4}){0,6}::(?:(?:[0-9A-Fa-f]{1,4}:){0,5}",
            ipv4_dotted!(),
            r"|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?"
        )
    };
}

macro_rules! ipv6_loopback {
    () => {
        concat!(
            r"::(?:(?:[0-9A-Fa-f]{1,4}:){0,5}",
            ipv4_dotted!(),
            r"|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
        )
    };
}

macro_rules! ipv4_dotted {
    () => {
        r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    };
}

macro_rules! ipv6_suffix {
    () => {
        r"(?:%[0-9A-Za-z]+(?:[._\-][0-9A-Za-z]+)*)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d)\b)?"
    };
}

pub(super) const IPV4: PiiPattern = PiiPattern {
    name: "pii_ipv4",
    pattern: concat!(r"\b", ipv4_dotted!(), r"(?:/(?:3[0-2]|[12]?\d))?\b"),
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
    pattern: concat!(
        ipv6_opener!(),
        r"(?P<value>",
        ipv6_full!(r"[0-9A-Fa-f]{1,4}"),
        ipv6_suffix!(),
        ")"
    ),
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
    pattern: concat!(
        ipv6_opener!(),
        r"(?P<value>",
        ipv6_compressed!(r"[0-9A-Fa-f]{1,4}"),
        ipv6_suffix!(),
        ")"
    ),
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
    pattern: concat!(
        ipv6_opener!(),
        r"(?P<value>",
        ipv6_loopback!(),
        ipv6_suffix!(),
        ")"
    ),
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: false,
    requires_context: false,
    scored_only: false,
};

/// A loopback or unspecified IPv4 address (`127.0.0.1`, `0.0.0.0`), which
/// `pii_ipv4` rejects (D-IP). Opt-in compatibility rule (T38): off until the
/// `rules` gate enables it (`docs/how-to/pii-presidio-compat.gates.json`), then
/// in every mode like a bare form (D-BARE).
pub(super) const IPV4_LOCAL_COMPAT: PiiPattern = PiiPattern {
    name: "pii_ipv4_local_compat",
    validator: Some(validators::ip_address_local),
    base_score: 35,
    ..IPV4
};

/// A loopback or unspecified IPv6 address, also IPv4-mapped (`::`, `::1`,
/// `::ffff:127.0.0.1`, `::/0`, `0::1`, `0:0:0:0:0:0:0:1`), which the default IPv6
/// rules reject (D-IP). Such an address opens with `::` or a zero group, so the
/// rule takes the forms of the three of them with a zero group first.
/// Opt-in compatibility rule (T38), as [`IPV4_LOCAL_COMPAT`].
pub(super) const IPV6_LOCAL_COMPAT: PiiPattern = PiiPattern {
    name: "pii_ipv6_local_compat",
    pattern: concat!(
        ipv6_opener!(),
        r"(?P<value>(?:",
        ipv6_full!(r"0{1,4}"),
        r"|",
        ipv6_compressed!(r"0{1,4}"),
        r"|",
        ipv6_loopback!(),
        r")",
        ipv6_suffix!(),
        ")"
    ),
    validator: Some(validators::ip_address_local),
    base_score: 35,
    ..IPV6_LOOPBACK
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

// A national number without a trunk or country prefix of its own form (F01): `Mobile:
// 416 60 039`, `call me on 03.93.92.16.85`, `0688 843 79 56 office`. Grouped digits
// alone are as often an order, account or date, so a phone term of the lexicon or a
// structural key must support the value; only then is the number checked against the
// `validators::PHONE_REGIONS` numbering plans (`validators::in_phone_region`). Runs
// after the other phone rules, which keep their spans; scored modes only, `strict`
// stays unchanged.
pub(super) const PHONE_REGIONAL: PiiPattern = PiiPattern {
    name: "pii_phone_regional",
    pattern: r"(?:\([0-9]{2,5}\)[ ]?|(?-u:\b))[0-9]{2,5}(?:[ .\-/][0-9]{2,6}){1,4}(?-u:\b)",
    entity_group: "PHONE",
    validator: Some(validators::regional_phone),
    strength: ValidatorStrength::Format,
    base_score: 20,
    captured_value: false,
    requires_context: true,
    scored_only: true,
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
