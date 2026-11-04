// SPDX-License-Identifier: MIT OR Apache-2.0
//! Remote endpoints of a segment and their scope, with Python's `ipaddress`
//! classification (3.12) for addresses.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::markers::{program, CONNECTORS, DOWNLOADERS};
use crate::detectors::shell::pyre::{py_regex, Anchor};

use super::Network;

static HOST_ARG: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^(?:[\w.+-]+@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::|$)",
        false,
        Anchor::Match,
    )
});

static URL: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?(\[[0-9a-fA-F:]+\]|[^/:?#\s]+)",
        true,
        Anchor::Match,
    )
});

static DIGITS: LazyLock<Regex> = LazyLock::new(|| py_regex(r"\d+", false, Anchor::Full));

static NET_PROGRAMS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    let mut set: BTreeSet<&'static str> = DOWNLOADERS
        .iter()
        .chain(CONNECTORS.iter())
        .copied()
        .collect();
    set.extend([
        "ping",
        "dig",
        "nslookup",
        "host",
        "nmap",
        "masscan",
        "autossh",
        "mosh",
        "git",
        "docker",
        "kubectl",
        "psql",
        "mysql",
        "redis-cli",
    ]);
    set
});

const V4_PRIVATE: [(u32, u32); 14] = [
    (0x0, 8),
    (0x0a00_0000, 8),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xac10_0000, 12),
    (0xc000_0000, 24),
    (0xc000_00aa, 31),
    (0xc000_0200, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xf000_0000, 4),
    (0xffff_ffff, 32),
];

const V4_PRIVATE_EXCEPTIONS: [(u32, u32); 2] = [(0xc000_0009, 32), (0xc000_000a, 32)];

const V6_PRIVATE: [(u128, u32); 11] = [
    (0x1, 128),
    (0x0, 128),
    (0xffff_0000_0000, 96),
    (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48),
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 64),
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
    (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),
    (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10),
];

const V6_PRIVATE_EXCEPTIONS: [(u128, u32); 6] = [
    (0x2001_0001_0000_0000_0000_0000_0000_0001, 128),
    (0x2001_0001_0000_0000_0000_0000_0000_0002, 128),
    (0x2001_0003_0000_0000_0000_0000_0000_0000, 32),
    (0x2001_0004_0112_0000_0000_0000_0000_0000, 48),
    (0x2001_0020_0000_0000_0000_0000_0000_0000, 28),
    (0x2001_0030_0000_0000_0000_0000_0000_0000, 28),
];

const V6_RESERVED: [(u128, u32); 15] = [
    (0x0, 8),
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 8),
    (0x0200_0000_0000_0000_0000_0000_0000_0000, 7),
    (0x0400_0000_0000_0000_0000_0000_0000_0000, 6),
    (0x0800_0000_0000_0000_0000_0000_0000_0000, 5),
    (0x1000_0000_0000_0000_0000_0000_0000_0000, 4),
    (0x4000_0000_0000_0000_0000_0000_0000_0000, 3),
    (0x6000_0000_0000_0000_0000_0000_0000_0000, 3),
    (0x8000_0000_0000_0000_0000_0000_0000_0000, 3),
    (0xa000_0000_0000_0000_0000_0000_0000_0000, 3),
    (0xc000_0000_0000_0000_0000_0000_0000_0000, 3),
    (0xe000_0000_0000_0000_0000_0000_0000_0000, 4),
    (0xf000_0000_0000_0000_0000_0000_0000_0000, 5),
    (0xf800_0000_0000_0000_0000_0000_0000_0000, 6),
    (0xfe00_0000_0000_0000_0000_0000_0000_0000, 9),
];

fn in_v4(ip: u32, (net, prefix): (u32, u32)) -> bool {
    prefix == 0 || ip >> (32 - prefix) == net >> (32 - prefix)
}

fn in_v6(ip: u128, (net, prefix): (u128, u32)) -> bool {
    prefix == 0 || ip >> (128 - prefix) == net >> (128 - prefix)
}

/// Python `IPv4Address` parsing: four decimal octets, no leading zeros.
fn parse_v4(text: &str) -> Option<u32> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut value = 0u32;
    for part in parts {
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part != "0" && part.starts_with('0'))
        {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        value = (value << 8) | octet;
    }
    Some(value)
}

/// Python `IPv6Address` parsing, including a scope id and an IPv4 tail.
fn parse_v6(text: &str) -> Option<u128> {
    let address = match text.split_once('%') {
        Some((address, scope)) if !scope.is_empty() && !scope.contains('%') => address,
        Some(_) => return None,
        None => text,
    };
    if address.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = address.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if let Some(tail) = parts.pop_if(|p| p.contains('.')) {
        let v4 = parse_v4(&tail)?;
        parts.push(format!("{:x}", (v4 >> 16) & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(i);
        }
    }
    let (hi, lo, skipped) = match skip {
        Some(index) => {
            let mut hi = index;
            let mut lo = parts.len() - index - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi > 0 {
                    return None;
                }
            }
            if parts.last().is_some_and(String::is_empty) {
                lo -= 1;
                if lo > 0 {
                    return None;
                }
            }
            let skipped = 8i64 - (hi + lo) as i64;
            if skipped < 1 {
                return None;
            }
            (hi, lo, skipped as u32)
        }
        None => {
            if parts.len() != 8 || parts[0].is_empty() || parts[7].is_empty() {
                return None;
            }
            (8, 0, 0)
        }
    };
    let hextet = |part: &str| -> Option<u128> {
        if part.is_empty() || part.len() > 4 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u128::from_str_radix(part, 16).ok()
    };
    let mut value = 0u128;
    for part in &parts[..hi] {
        value = (value << 16) | hextet(part)?;
    }
    value <<= 16 * skipped;
    for part in &parts[parts.len() - lo..] {
        value = (value << 16) | hextet(part)?;
    }
    Some(value)
}

fn v4_scope(ip: u32) -> &'static str {
    if in_v4(ip, (0x7f00_0000, 8)) {
        "LOOPBACK"
    } else if in_v4(ip, (0xa9fe_0000, 16)) {
        "LINK_LOCAL"
    } else if (V4_PRIVATE.iter().any(|n| in_v4(ip, *n))
        && !V4_PRIVATE_EXCEPTIONS.iter().any(|n| in_v4(ip, *n)))
        || in_v4(ip, (0xf000_0000, 4))
        || ip == 0
    {
        "PRIVATE"
    } else {
        "PUBLIC"
    }
}

fn v6_scope(ip: u128) -> &'static str {
    if ip >> 32 == 0xffff {
        return v4_scope(ip as u32);
    }
    if ip == 1 {
        "LOOPBACK"
    } else if in_v6(ip, (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10)) {
        "LINK_LOCAL"
    } else if (V6_PRIVATE.iter().any(|n| in_v6(ip, *n))
        && !V6_PRIVATE_EXCEPTIONS.iter().any(|n| in_v6(ip, *n)))
        || V6_RESERVED.iter().any(|n| in_v6(ip, *n))
        || ip == 0
    {
        "PRIVATE"
    } else {
        "PUBLIC"
    }
}

/// Network scope of a host name or address.
fn scope_of(host: &str) -> &'static str {
    let lower = host.trim_matches(['[', ']']).to_lowercase();
    let h = lower.trim_end_matches('.');
    if matches!(h, "localhost" | "localhost.localdomain") || h.ends_with(".localhost") {
        return "LOOPBACK";
    }
    if let Some(ip) = parse_v4(h) {
        return v4_scope(ip);
    }
    if let Some(ip) = parse_v6(h) {
        return v6_scope(ip);
    }
    if h.contains(['$', '%', '{']) {
        return "UNKNOWN";
    }
    const PRIVATE_SUFFIXES: [&str; 7] = [
        ".local",
        ".internal",
        ".lan",
        ".svc",
        ".cluster.local",
        ".corp",
        ".home.arpa",
    ];
    if PRIVATE_SUFFIXES.iter().any(|s| h.ends_with(s)) || !h.contains('.') {
        return "PRIVATE";
    }
    "PUBLIC"
}

/// Remote endpoints named by a segment: URLs anywhere, `[user@]host:` for
/// ssh/scp/rsync style tools, and the first host-like argument of connectors.
pub(super) fn network_of(head: &str, rest: &[String]) -> Vec<Network> {
    let prog = program(head);
    let mut out: Vec<String> = Vec::new();
    for word in rest {
        if let Some(captures) = URL.captures(word) {
            out.push(captures[1].to_string());
        }
    }
    if NET_PROGRAMS.contains(prog.as_str()) && out.is_empty() {
        let bare_ok = (CONNECTORS.contains(prog.as_str())
            && !matches!(prog.as_str(), "scp" | "rsync" | "sftp"))
            || matches!(
                prog.as_str(),
                "ping" | "dig" | "nslookup" | "host" | "mosh" | "autossh"
            );
        for word in rest {
            if word.starts_with('-') || word.split(':').next().unwrap_or("").contains('/') {
                continue;
            }
            let Some(captures) = HOST_ARG.captures(word) else {
                continue;
            };
            if !(word.contains('@') || word.contains(':') || bare_ok) {
                continue;
            }
            let host = captures[1].to_string();
            if DIGITS.is_match(&host)
                || (!word.contains(':')
                    && !word.contains('@')
                    && !host.contains('.')
                    && host != "localhost")
            {
                continue;
            }
            out.push(host);
            if !matches!(prog.as_str(), "scp" | "rsync") {
                break;
            }
        }
    }
    let mut seen = BTreeSet::new();
    out.into_iter()
        .filter(|h| seen.insert(h.clone()))
        .map(|host| Network {
            scope: scope_of(&host),
            host,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_scopes_follow_python_ipaddress() {
        for (host, scope) in [
            ("localhost", "LOOPBACK"),
            ("127.0.0.1", "LOOPBACK"),
            ("169.254.169.254", "LINK_LOCAL"),
            ("10.1.2.3", "PRIVATE"),
            ("[::1]", "LOOPBACK"),
            ("[fe80::1%eth0]", "LINK_LOCAL"),
            ("::ffff:10.0.0.1", "PRIVATE"),
            ("2001:db8::1", "PRIVATE"),
            ("8.8.8.8", "PUBLIC"),
            ("010.0.0.1", "PUBLIC"),
            ("db.internal", "PRIVATE"),
            ("${HOST}", "UNKNOWN"),
            ("example.org.", "PUBLIC"),
        ] {
            assert_eq!(scope_of(host), scope, "{host}");
        }
    }
}
