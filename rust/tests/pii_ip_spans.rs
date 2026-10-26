// SPDX-License-Identifier: GPL-3.0-only
//! IP address spans (B-IP = T20 + baseline C1, TRIAGE 2026-W43 bucket 5, baseline P3/P9).
//!
//! On Gretel Finance the IPv6 FP were compressed forms inside colon-delimited SWIFT MT
//! and EDIFACT chains (`:28C::52D:`, `:60F::61F::62F:`, `BGM+380:21:3::90:FRET`,
//! `LIN+1::1:550:::EA:20`). On the presidio-analyzer tests ARK reported the IPv4 part of
//! IPv4-mapped and embedded addresses, the address without its zone ID or CIDR prefix
//! length, and `2001:db8::256` inside the invalid `2001:db8::256.1.1.1`. Convention
//! (research README, gold section): an address span holds its zone ID and prefix length,
//! a mapped or embedded IPv6 address is one span, and an invalid chain or mixed form yields
//! no span at all. Loopback and unspecified addresses stay rejected (D-IP, 2026-10-21),
//! also in mapped form and with a prefix length. T28 (TRIAGE 2026-W44 bucket 5): a word
//! ending in a hex group (`foo2001:db8::10.0.0.1`) is a further `:`-group, not a field name,
//! so the address yields no span; `IPv6:`, `inet6:` and `eth0:` still open one.

use patronus_ark::detectors::pii::{score::PiiMode, validators::ip_address};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const MODES: [PiiMode; 2] = [PiiMode::Strict, PiiMode::Balanced];

fn scan(text: &str, mode: PiiMode) -> SecurityScanResult {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix {
        pii_mode: mode,
        ..Default::default()
    });
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

fn ips(text: &str, mode: PiiMode) -> Vec<String> {
    scan(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == "IP_ADDRESS")
        .map(|span| span.text)
        .collect()
}

/// `(rule_id, value)` of every matched rule; offsets are the value's.
fn rules(text: &str, result: &SecurityScanResult) -> Vec<(String, String)> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .into_iter()
        .flatten()
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            (
                rule["rule_id"].as_str().unwrap().to_owned(),
                text[start..end].to_owned(),
            )
        })
        .collect()
}

/// `(text, rule, value)`: `rule` reports exactly `value`, the only IP span, in every mode.
const ONE_SPAN: &[(&str, &str, &str)] = &[
    // IPv4-mapped and embedded IPv6 (baseline P3).
    (
        "Connect to ::ffff:10.0.0.1 now",
        "pii_ipv6_loopback",
        "::ffff:10.0.0.1",
    ),
    (
        "[::ffff:192.168.1.1]:80",
        "pii_ipv6_loopback",
        "::ffff:192.168.1.1",
    ),
    (
        "NAT64: 64:ff9b::198.51.100.1",
        "pii_ipv6_compressed",
        "64:ff9b::198.51.100.1",
    ),
    (
        "2001:db8:85a3::8a2e:192.168.0.1",
        "pii_ipv6_compressed",
        "2001:db8:85a3::8a2e:192.168.0.1",
    ),
    (
        "Adresse: 2001:db8:1:2:3:4:192.0.2.33",
        "pii_ipv6_full",
        "2001:db8:1:2:3:4:192.0.2.33",
    ),
    // Zone ID and CIDR prefix length in the span.
    ("fe80::1%eth0", "pii_ipv6_compressed", "fe80::1%eth0"),
    (
        "Schnittstelle fe80::a1b2%en0.100 aktiv",
        "pii_ipv6_compressed",
        "fe80::a1b2%en0.100",
    ),
    (
        "2001:db8::%eth0/128",
        "pii_ipv6_compressed",
        "2001:db8::%eth0/128",
    ),
    ("Use 2001:db8::/32.", "pii_ipv6_compressed", "2001:db8::/32"),
    ("Subnet: 192.168.1.0/24", "pii_ipv4", "192.168.1.0/24"),
    ("192.168.1.1/32", "pii_ipv4", "192.168.1.1/32"),
    (
        "::ffff:192.168.1.0/96",
        "pii_ipv6_loopback",
        "::ffff:192.168.1.0/96",
    ),
    (
        "Netz 2001:db8:0:0:0:0:0:0/48 gesperrt",
        "pii_ipv6_full",
        "2001:db8:0:0:0:0:0:0/48",
    ),
    // Not after a further `:`-group, but after a field name or a SWIFT MT tag.
    (
        ":20:OOFFFXXX222\n:25:4ec3:7b68:8206:3239:df1c:1822:33e0:71dc\n:28C:0/1",
        "pii_ipv6_full",
        "4ec3:7b68:8206:3239:df1c:1822:33e0:71dc",
    ),
    ("IPv6:2001:db8::7", "pii_ipv6_compressed", "2001:db8::7"),
    (
        "IPv6:2001:db8:85a3::8a2e:198.51.100.23",
        "pii_ipv6_compressed",
        "2001:db8:85a3::8a2e:198.51.100.23",
    ),
    // A field name ending in at most two hex characters or only hex letters is no
    // `:`-group (T28).
    (
        "inet6:2001:db8:85a3::8a2e:370:7334",
        "pii_ipv6_compressed",
        "2001:db8:85a3::8a2e:370:7334",
    ),
    (
        "eth0:fe80::a1b2:3c4d",
        "pii_ipv6_compressed",
        "fe80::a1b2:3c4d",
    ),
    ("ens33:2001:db8::42", "pii_ipv6_compressed", "2001:db8::42"),
    (
        "IP-Adresse:2001:db8::10.0.0.1",
        "pii_ipv6_compressed",
        "2001:db8::10.0.0.1",
    ),
    (
        "2001:db8::10.0.0.1",
        "pii_ipv6_compressed",
        "2001:db8::10.0.0.1",
    ),
    ("IP:203.0.113.42", "pii_ipv4", "203.0.113.42"),
    ("web:203.0.113.42", "pii_ipv4", "203.0.113.42"),
    (":25:203.0.113.42", "pii_ipv4", "203.0.113.42"),
    (
        " :50K:/CITY BANK\n :52A:26.26.5.252\n :57A:LUIGI",
        "pii_ipv4",
        "26.26.5.252",
    ),
    (
        " :52A:2001:db8:85a3:0:0:8a2e:370:7334\n",
        "pii_ipv6_full",
        "2001:db8:85a3:0:0:8a2e:370:7334",
    ),
    // A prefix length out of range is not part of the span (presidio-analyzer tests).
    ("10.0.0.0/123", "pii_ipv4", "10.0.0.0"),
    (
        "Route 2001:db8::1/129 verworfen",
        "pii_ipv6_compressed",
        "2001:db8::1",
    ),
    (
        "SSH to user@2001:db8::1",
        "pii_ipv6_compressed",
        "2001:db8::1",
    ),
    ("'2001:db8::1'", "pii_ipv6_compressed", "2001:db8::1"),
    (
        "Portal: <http://53a3:346c:e839:a47e:8ec9:3ae0:8261:4812/report>",
        "pii_ipv6_full",
        "53a3:346c:e839:a47e:8ec9:3ae0:8261:4812",
    ),
    (
        "Client [2001:db8::1]:443 meldet sich.",
        "pii_ipv6_compressed",
        "2001:db8::1",
    ),
    (
        "Host 2001:db8::1: unreachable",
        "pii_ipv6_compressed",
        "2001:db8::1",
    ),
    (
        "A099::09C0:876A:130B",
        "pii_ipv6_compressed",
        "A099::09C0:876A:130B",
    ),
    (
        "Zugeordnete Adresse: ::ffff:c000:0280",
        "pii_ipv6_loopback",
        "::ffff:c000:0280",
    ),
];

#[test]
fn an_address_is_one_span_with_zone_id_and_prefix_length() {
    for mode in MODES {
        for (text, rule, value) in ONE_SPAN {
            let result = scan(text, mode);
            let spans = result
                .evidence_spans
                .iter()
                .filter(|span| span.label == "IP_ADDRESS")
                .map(|span| span.text.as_str())
                .collect::<Vec<_>>();
            assert_eq!(spans, [*value], "{mode:?}: {text:?}");
            assert!(
                rules(text, &result).contains(&((*rule).to_owned(), (*value).to_owned())),
                "{mode:?}: {text:?}: {:?}",
                rules(text, &result)
            );
        }
    }
}

/// Colon chains and invalid forms: no IP span, also no sub-span.
const NO_SPAN: &[&str] = &[
    // SWIFT MT and EDIFACT colon chains (T20, Gretel dev shapes).
    ":20:MT940 STMT\n:25:Lk-27571\n:28C::52D:20220920\n:60F::STP",
    "Tina Park, Anytown, CA 12345:60F::61F::62F::63F::64F::70:3/31/20220413123456.12GBP/",
    "TOTAL $14,035.00 :71F::72F/140350.00GBP/GBP041316.7",
    "BGM+380:21:3::90:FRET:FRCOMPAGNIE'",
    "LIN+1::1:550:::EA:20'",
    "NAD+SU+::FRCOMPAGNIE::4::2'",
    "RFF+ON:4328::735'",
    // Invalid mixed forms (baseline P9).
    "2001:db8::256.1.1.1",
    "Adresse 2001:db8::1.2.3 ungültig",
    "1:2:3:4:5:6:7:8:9",
    "2001:db8:1:2:3:4:5:6:7",
    "2001:db8::12345",
    // Glued to a word, a dot or a hyphen.
    "text2001:db8::1",
    // A word that ends in a hex group of three or more characters with a digit is a
    // further `:`-group, not a field name (T28): no IPv6 span, no IPv4 tail.
    "foo2001:db8::10.0.0.1",
    "Device host2001:db8:85a3::8a2e:370:7334 blocked",
    "Artikel sku4f00:db8::1:2:3 vergriffen",
    "Node xyz2a02:810d:4b40::52d7 removed",
    "Präfix gwfe80:1::a1b2:3c4d%eth0",
    "Kennung id-2001:db8:85a3::8a2e:370:7334",
    "exchange rate between the U.9101:8c5c:e9b4:50ce:7e5d:ce61:c1d2:d092",
    "ID 341-33-4328::735",
    // Loopback and unspecified stay rejected (D-IP), also mapped and with a prefix.
    "Loopback ::1",
    "Use local ipv6 ::",
    "::/0",
    "::/128",
    "::ffff:127.0.0.1",
    "::ffff:0.0.0.0",
    "IP: 127.0.0.1/8",
    "Uhrzeit: 12:30:45",
    "Timestamp 08:15:30.123",
];

#[test]
fn colon_chains_and_invalid_forms_yield_no_span() {
    for mode in MODES {
        for text in NO_SPAN {
            assert_eq!(ips(text, mode), Vec::<String>::new(), "{mode:?}: {text:?}");
        }
    }
}

#[test]
fn validator_checks_zone_id_and_prefix_length() {
    for valid in [
        "2001:db8::1",
        "fe80::1%eth0",
        "2001:db8::%eth0/128",
        "2001:db8::/32",
        "192.0.2.0/24",
        "192.0.2.1/32",
        "198.51.100.7/0",
        "::ffff:10.0.0.1",
        "::ffff:192.168.1.0/96",
        "64:ff9b::198.51.100.1",
    ] {
        assert!(ip_address(valid), "{valid}");
    }
    for invalid in [
        "2001:db8::1/129",
        "2001:db8::1/",
        "2001:db8::1/1a",
        "192.0.2.0/33",
        "192.0.2.1%eth0",
        "fe80::1%",
        "2001:db8::256.1.1.1",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.251",
        "::/0",
        "::1/128",
        "127.0.0.1/8",
        "0.0.0.0/0",
    ] {
        assert!(!ip_address(invalid), "{invalid}");
    }
}

#[test]
fn private_mapped_and_zoned_addresses_stay_suppressed_in_network_diagnostics() {
    for text in [
        "NetworkState diagnostics: local endpoint ::ffff:192.168.178.96",
        "Interface address fe80::204:61ff:fe9d:f156%eth0",
        "network interface 192.168.178.0/24",
    ] {
        for mode in MODES {
            assert_eq!(ips(text, mode), Vec::<String>::new(), "{mode:?}: {text:?}");
        }
    }
}
