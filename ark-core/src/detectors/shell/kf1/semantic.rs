// SPDX-License-Identifier: MIT OR Apache-2.0
//! Semantic markers of a segment (kv1): setting polarity, security controls,
//! sudoers grants, container host-root mounts and privileges, fixture paths.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::markers::{head_and_rest, segments, word_set, WordSet};
use crate::detectors::shell::pyre::{py_regex, Anchor};

static NEG_KEY: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(disable|deny|block|exclu|skip|bypass|nocheck|^no[A-Z_]|^no-|ignore|allowunsigned)",
        true,
        Anchor::Search,
    )
});
static POS_KEY: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(enable|allow|^use|start|active|protect|enforce|audit|log|monitor|scan|firewall|guard|realtime|consent|lua|amsi|etw|selinux|apparmor|defender)",
        true,
        Anchor::Search,
    )
});
static ON_VAL: WordSet = word_set!(
    "1",
    "true",
    "$true",
    "yes",
    "on",
    "enable",
    "enabled",
    "start",
    "allow",
    "enforcing",
    "active"
);
static OFF_VAL: WordSet = word_set!(
    "0",
    "false",
    "$false",
    "no",
    "off",
    "disable",
    "disabled",
    "stop",
    "deny",
    "none",
    "permissive",
    "inactive",
);
static ON_VERBS: WordSet = word_set!("start", "enable", "unmask", "load", "install", "restore");
static OFF_VERBS: WordSet = word_set!(
    "stop",
    "disable",
    "mask",
    "unload",
    "uninstall",
    "remove",
    "kill",
    "flush",
    "clear",
    "delete",
    "deletejournal",
    "erase",
    "purge",
    "reset",
);
pub(crate) static SECCTL: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(audit|defender|windefend|mpsvc|sense|amsi|etw|eventlog|autologger|sysmon|falcon|crowdstrike|carbonblack|cbdefense|sentinel|mdatp|edr|xdr|antivirus|antispyware|realtime|firewall|ufw|firewalld|iptables|nftables|\bpf\b|selinux|apparmor|setenforce|wdigest|lsa|credentialguard|uac|enablelua|consentprompt|cloudtrail|flow-logs|flowlog|guardduty|securityhub|syslog|journald|rsyslog|osquery|wazuh|ossec|tamper|usn|smartscreen|applocker|wdac|bitlocker|aslr|randomize_va)",
        true,
        Anchor::Search,
    )
});
pub(crate) static FIXTURE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(^|[/\\])(testdata|test-data|fixtures?|examples?|samples?|__fixtures__|mocks?)([/\\]|$)",
        true,
        Anchor::Search,
    )
});
static FLAG_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^-{0,2}([A-Za-z_][\w.-]{1,60})[:=](.+)$",
        false,
        Anchor::Match,
    )
});
static NOPASSWD_ALL: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"NOPASSWD:\s*ALL\b", false, Anchor::Search));
static HOST_ROOT_VALUE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^/:/|^/:\w|source=/,", false, Anchor::Match));

/// `ON` / `OFF` polarity of a setting value, if any.
fn polarity_value(value: &str) -> Option<&'static str> {
    let value = value.trim_matches(['\'', '"']).to_lowercase();
    if ON_VAL.contains(value.as_str()) {
        Some("ON")
    } else if OFF_VAL.contains(value.as_str()) {
        Some("OFF")
    } else {
        None
    }
}

/// `TURNS_ON` / `TURNS_OFF` from key polarity times value polarity.
pub(crate) fn turns(key: &str, value: &str) -> Option<&'static str> {
    let on = polarity_value(value)? == "ON";
    if NEG_KEY.is_match(key) {
        Some(if on { "TURNS_OFF" } else { "TURNS_ON" })
    } else if POS_KEY.is_match(key) {
        Some(if on { "TURNS_ON" } else { "TURNS_OFF" })
    } else {
        None
    }
}

const SETTING_HEADS: [&str; 14] = [
    "systemctl",
    "service",
    "sc",
    "launchctl",
    "ufw",
    "sysmon",
    "netsh",
    "fsutil",
    "auditpol",
    "mdatp",
    "wevtutil",
    "aws",
    "gcloud",
    "az",
];

/// Semantic markers of one segment (`segment_markers`).
pub(crate) fn segment_markers<S: AsRef<str>>(head: &str, rest: &[S]) -> BTreeSet<&'static str> {
    let rest: Vec<&str> = rest.iter().map(AsRef::as_ref).collect();
    let mut out = BTreeSet::new();
    let joined = std::iter::once(head)
        .chain(rest.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    if SECCTL.is_match(&joined) {
        out.insert("SECCTL");
    }
    // key/value pairs: /v NAME ... /d VAL (reg), -Name N -Value V, -Flag VAL, key=value, --value V
    let mut name: Option<&str> = None;
    for (k, &word) in rest.iter().enumerate() {
        let lower = word.to_lowercase();
        let next = rest.get(k + 1).copied().unwrap_or("");
        if matches!(lower.as_str(), "/v" | "-name" | "-valuename") && !next.is_empty() {
            name = Some(next);
        } else if matches!(lower.as_str(), "/d" | "-value" | "--value" | "-data")
            && !next.is_empty()
        {
            let mut turned = name.filter(|n| !n.is_empty()).and_then(|n| turns(n, next));
            if turned.is_none() && lower == "--value" {
                turned =
                    polarity_value(next).map(|p| if p == "ON" { "TURNS_ON" } else { "TURNS_OFF" });
            }
            out.extend(turned);
        } else if lower.starts_with('-')
            && lower.chars().count() > 2
            && !next.is_empty()
            && polarity_value(next).is_some()
            && !next.starts_with('-')
        {
            out.extend(turns(word.trim_start_matches('-'), next));
        }
        // `[:=]` is required; most words have neither.
        let assignment = word
            .contains([':', '='])
            .then(|| FLAG_ASSIGNMENT.captures(word))
            .flatten();
        if let Some(captures) = assignment {
            out.extend(turns(&captures[1], &captures[2]));
        }
    }
    if head == "setenforce" && !rest.is_empty() {
        let on = matches!(rest[0].to_lowercase().as_str(), "1" | "enforcing");
        out.insert(if on { "TURNS_ON" } else { "TURNS_OFF" });
    }
    if head == "auditctl" {
        if let Some(index) = rest.iter().position(|w| *w == "-e") {
            match rest.get(index + 1).copied().unwrap_or("") {
                "1" => {
                    out.insert("TURNS_ON");
                }
                "0" => {
                    out.insert("TURNS_OFF");
                }
                _ => {}
            }
        }
    }
    let verbs: Vec<String> = rest
        .iter()
        .take(3)
        .filter(|w| !w.starts_with('-'))
        .map(|w| w.to_lowercase())
        .collect();
    if SETTING_HEADS.contains(&head) || head.ends_with("-service") {
        let off_verb = verbs.iter().any(|v| {
            OFF_VERBS.contains(v.as_str())
                || ["stop", "disable", "delete", "remove", "clear"]
                    .iter()
                    .any(|p| v.starts_with(p))
        });
        let off_word = rest.iter().any(|w| {
            let w = w.to_lowercase();
            matches!(
                w.as_str(),
                "-u" | "/clear" | "disable" | "stop" | "/success:disable" | "/failure:disable"
            ) || w.ends_with(":disable")
                || w.ends_with("=disabled")
        });
        if off_verb || off_word {
            out.insert("TURNS_OFF");
        } else if verbs.iter().any(|v| {
            ON_VERBS.contains(v.as_str()) || v.starts_with("start") || v.starts_with("enable")
        }) || rest.contains(&"-i")
        {
            out.insert("TURNS_ON");
        }
    }
    if [
        "stop-service",
        "set-service",
        "disable-",
        "uninstall-",
        "remove-",
    ]
    .iter()
    .any(|p| head.starts_with(p))
    {
        out.insert("TURNS_OFF");
    }
    if ["start-service", "enable-", "install-"]
        .iter()
        .any(|p| head.starts_with(p))
    {
        out.insert("TURNS_ON");
    }
    if out.contains("SECCTL") {
        if out.contains("TURNS_ON") {
            out.insert("TURNS_ON@SECCTL");
        }
        if out.contains("TURNS_OFF") {
            out.insert("TURNS_OFF@SECCTL");
        }
    }
    if NOPASSWD_ALL.is_match(&joined) {
        out.insert("GRANT_ALL");
    } else if joined.contains("NOPASSWD:") {
        out.insert("GRANT_SCOPED");
    }
    for (k, &word) in rest.iter().enumerate() {
        if matches!(word, "-v" | "--volume" | "--mount")
            && rest
                .get(k + 1)
                .is_some_and(|next| HOST_ROOT_VALUE.is_match(next))
        {
            out.insert("HOST_ROOT_MOUNT");
        }
        // `^-v/:/|^--volume=/:/`
        if word.starts_with("-v/:/") || word.starts_with("--volume=/:/") {
            out.insert("HOST_ROOT_MOUNT");
        }
        if word == "--privileged"
            || matches!(
                word.to_lowercase().as_str(),
                "--privileged=true" | "--privileged=1"
            )
        {
            out.insert("PRIVILEGED");
        }
        if FIXTURE.is_match(word) {
            out.insert("TGT=FIXTURE");
        }
    }
    out
}

/// Semantic markers of all segments, de-duplicated (`semantic_markers`).
pub(crate) fn semantic_markers(tokens: &[&str]) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for seg in segments(tokens) {
        if let (Some(head), rest) = head_and_rest(&seg) {
            if !head.is_empty() {
                found.extend(segment_markers(&head, rest));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::detectors::shell::markers::Masked;

    fn semantic(text: &str) -> BTreeSet<&'static str> {
        semantic_markers(&Masked::new(text).tokens())
    }

    #[test]
    fn semantic_markers_find_security_control_changes() {
        let markers = semantic("sudo systemctl stop auditd");
        assert!(markers.contains("TURNS_OFF@SECCTL"), "{markers:?}");
        let markers = semantic("Set-MpPreference -DisableRealtimeMonitoring $true");
        assert!(markers.contains("TURNS_OFF@SECCTL"), "{markers:?}");
        assert!(semantic("echo 'u ALL=(ALL) NOPASSWD: ALL'").contains("GRANT_ALL"));
        assert!(semantic("docker run -v /:/host --privileged x").contains("HOST_ROOT_MOUNT"));
    }
}
