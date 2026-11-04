// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command segments, verb and target classes, and DefenseClaw-style operation
//! kinds: the port of the K26 reference `markers.py` and `segments.py`.
//!
//! Text is never executed. Every set, pattern and branch follows the Python
//! reference line by line, so the facts and `kf1` tokens built on top stay
//! byte-identical to it.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::pyre::{py_regex, py_strip, Anchor};
use super::tokens::{is_fd_redirect, line_tokens, mask_heredocs};

/// A static set of words.
pub(crate) type WordSet = LazyLock<rustc_hash::FxHashSet<&'static str>>;

macro_rules! word_set {
    ($($word:literal),* $(,)?) => {
        LazyLock::new(|| [$($word),*].into_iter().collect())
    };
}
pub(crate) use word_set;

/// Shell separators that end a command segment.
pub(crate) fn is_separator(token: &str) -> bool {
    matches!(
        token,
        "|" | "||" | "&&" | ";" | "&" | "(" | ")" | "$(" | "\n"
    )
}

pub(crate) static PREFIXES: WordSet = word_set!(
    "sudo", "doas", "env", "exec", "command", "nohup", "time", "timeout", "nice", "xargs"
);

static READ: WordSet = word_set!(
    "get",
    "list",
    "ls",
    "show",
    "describe",
    "status",
    "query",
    "export",
    "cat",
    "view",
    "print",
    "info",
    "inspect",
    "check",
    "logs",
    "log",
    "top",
    "version",
    "help",
    "diff",
    "search",
    "find",
    "test",
    "verify",
    "read",
    "dump",
    "head",
    "tail",
    "grep",
    "stat",
    "which",
    "whoami",
    "ping",
    "lookup",
    "resolve",
    "measure",
    "select",
    "where",
    "format",
    "out",
    "compare",
    "confirm",
    "watch",
    "history",
    "explain",
    "plan",
    "validate",
    "is-active",
    "is-enabled",
    "list-units",
);
static MUTATE: WordSet = word_set!(
    "add",
    "set",
    "create",
    "apply",
    "put",
    "update",
    "edit",
    "enable",
    "attach",
    "insert",
    "install",
    "patch",
    "modify",
    "new",
    "append",
    "write",
    "import",
    "configure",
    "config",
    "grant",
    "chmod",
    "chown",
    "chgrp",
    "tee",
    "mv",
    "cp",
    "ln",
    "mkdir",
    "touch",
    "move",
    "copy",
    "rename",
    "replace",
    "register",
    "tag",
    "push",
    "commit",
    "save",
    "restore",
    "load",
    "mount",
    "assign",
    "allow",
    "accept",
    "open",
    "scale",
    "rollout",
    "label",
    "annotate",
    "taint",
    "reload",
    "restart",
    "daemon-reload",
    "unmask",
    "sed",
    "dd",
    "mkfs",
    "useradd",
    "usermod",
    "passwd",
    "login",
    "join",
    "upgrade",
    "build",
    "init",
);
static DELETE: WordSet = word_set!(
    "delete",
    "del",
    "remove",
    "rm",
    "rmdir",
    "purge",
    "drop",
    "destroy",
    "uninstall",
    "truncate",
    "wipe",
    "flush",
    "clear",
    "erase",
    "kill",
    "pkill",
    "killall",
    "stop",
    "disable",
    "detach",
    "revoke",
    "prune",
    "reset",
    "mask",
    "unregister",
    "deny",
    "reject",
    "shred",
    "unlink",
    "deregister",
    "terminate",
    "shutdown",
    "halt",
    "poweroff",
    "reboot",
    "userdel",
    "cordon",
    "drain",
    "evict",
    "zap",
    "clean",
    "format-volume",
);
static EXEC: WordSet = word_set!(
    "exec",
    "run",
    "invoke",
    "start",
    "call",
    "eval",
    "ssh",
    "shell",
    "source",
    "spawn",
    "submit",
    "execute",
    "start-process",
    "iex",
    "invoke-expression",
    "invoke-command",
);

/// Verb classes in priority order (`CLASS_OF`).
pub(crate) static CLASS_OF: LazyLock<[(&'static str, &'static WordSet); 4]> = LazyLock::new(|| {
    [
        ("DELETE", &DELETE),
        ("EXEC", &EXEC),
        ("MUTATE", &MUTATE),
        ("READ", &READ),
    ]
});

pub(crate) static FLAG_VERB: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^--?(add|remove|delete|del|list|get|set|query|zap|flush|enable|disable|insert|append|new|change|reload|permanent|state|info|show|clear|reset)\b",
        true,
        Anchor::Match,
    )
});
static BOOLISH: WordSet = word_set!(
    "true", "false", "yes", "no", "on", "off", "enable", "enabled", "disable", "disabled", "start",
    "stop", "allow", "deny", "accept", "drop", "reject", "none", "all", "any",
);
static SMALL_INT: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^-?\d{1,2}$", false, Anchor::Match));
static VALUE_FLAG: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^(--?[A-Za-z][\w-]*|/[A-Za-z])$", false, Anchor::Match));
static KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^([A-Za-z_][\w.-]{0,40})[:=]([^=\s]+)$",
        false,
        Anchor::Match,
    )
});

static TARGETS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "ROOT",
            py_regex(
                r"^(/|/\*|[A-Za-z]:\\?|[A-Za-z]:\\\*|~|\$HOME|\$\{HOME\})/?$",
                false,
                Anchor::Match,
            ),
        ),
        (
            "SECRET",
            py_regex(
                r"(^|[/\\])(\.ssh|\.aws|\.kube|\.gnupg|\.docker|\.netrc|\.git-credentials|\.pgpass|\.npmrc|\.pypirc|\.env(\.\w+)?|credentials|id_[a-z0-9]+|shadow|gshadow|sudoers(\.d)?|SAM|SECURITY|SYSTEM)([/\\]|$)",
                true,
                Anchor::Search,
            ),
        ),
        (
            "SYSTEM",
            py_regex(
                r"^(/(etc|usr|bin|sbin|boot|lib|lib64|sys|proc|dev|var/log|root)(/|$)|[A-Za-z]:\\(Windows|Program Files)|HK(LM|EY_LOCAL_MACHINE)|HKCU|HKEY_CURRENT_USER)",
                true,
                Anchor::Match,
            ),
        ),
        (
            "SERVICE",
            py_regex(
                r"^/(var/lib|var/cache|var/spool|var/run|run|srv|opt|mnt|data)(/|$)",
                false,
                Anchor::Match,
            ),
        ),
        (
            "TMP",
            py_regex(
                r"^(/tmp|/var/tmp|\$TMPDIR|\$\{TMPDIR\}|%TEMP%|\$env:TEMP|[A-Za-z]:\\Temp)(/|\\|$)",
                true,
                Anchor::Match,
            ),
        ),
        (
            "HOME",
            py_regex(
                r"^(~|\$HOME|/home/[^/]+|/Users/[^/]+)(/|$)",
                false,
                Anchor::Match,
            ),
        ),
    ]
});
static PATHLIKE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^([/~$.]|[A-Za-z]:\\|HK(LM|CU|EY_)|[\w.-]+/)",
        false,
        Anchor::Match,
    )
});
static FILE_WORD: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"[\w.*@+-][\w.*@+/-]*", false, Anchor::Full));
static ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"[A-Za-z_]\w*=.*", false, Anchor::Full));

/// Heads whose plain (non-flag) arguments are file paths, so `rm -rf dist`
/// targets the project.
pub(crate) static FILE_HEADS: WordSet = word_set!(
    "rm",
    "rmdir",
    "mv",
    "cp",
    "chmod",
    "chown",
    "chgrp",
    "ln",
    "touch",
    "mkdir",
    "shred",
    "truncate",
    "tee",
    "unlink",
    "cat",
    "ls",
    "stat",
    "head",
    "tail",
    "del",
    "rd",
    "remove-item",
    "copy-item",
    "move-item",
    "get-content",
    "set-content",
);

/// A token without its surrounding matching quotes.
pub(crate) fn unquote(token: &str) -> &str {
    let mut chars = token.chars();
    match (chars.next(), chars.next_back()) {
        (Some(first @ ('\'' | '"')), Some(last)) if first == last => &token[1..token.len() - 1],
        _ => token,
    }
}

/// `\d*>&\d*` or one of `<`, `>`, `>>`.
pub(crate) fn is_redirect_token(token: &str) -> bool {
    matches!(token, "<" | ">" | ">>") || is_fd_redirect(token)
}

/// The heredoc-masked text and its `\n|TOKEN` word stream, computed once per
/// text and shared by the segment and pipeline views.
pub(crate) struct Masked<'a> {
    text: std::borrow::Cow<'a, str>,
}

impl<'a> Masked<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        Self {
            text: mask_heredocs(text),
        }
    }

    /// The masked text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// `re.findall(r'\n|' + TOKEN.pattern, mask_heredocs(text))`.
    pub(crate) fn tokens(&self) -> Vec<&str> {
        line_tokens(&self.text)
    }
}

/// Command segments as lists of raw words (quotes stripped), split on shell
/// separators and `#` words (`markers.segments`: the words after a `#` form
/// the next segment, as in the reference).
pub(crate) fn segments<'t>(tokens: &[&'t str]) -> Vec<Vec<&'t str>> {
    let mut out = Vec::new();
    let mut seg = Vec::new();
    for &token in tokens {
        if is_separator(token) || token.starts_with('#') {
            if !seg.is_empty() {
                out.push(std::mem::take(&mut seg));
            }
            continue;
        }
        if is_redirect_token(token) {
            continue;
        }
        seg.push(unquote(token));
    }
    if !seg.is_empty() {
        out.push(seg);
    }
    out
}

/// Lowercase last path component (`re.split(r'[\\/]', word)[-1].lower()`).
pub(crate) fn base(word: &str) -> String {
    word.rsplit(['\\', '/']).next().unwrap_or("").to_lowercase()
}

/// Whether the lowercase last path component of `word` is in `words`, without
/// allocating for ASCII words.
pub(crate) fn base_in(word: &str, words: &WordSet) -> bool {
    let last = word.rsplit(['\\', '/']).next().unwrap_or("");
    if last.is_ascii() && !last.bytes().any(|b| b.is_ascii_uppercase()) {
        words.contains(last)
    } else {
        words.contains(base(word).as_str())
    }
}

/// `[A-Za-z_]\w*=.*` (full match): an environment assignment word.
pub(crate) fn is_assignment(word: &str) -> bool {
    word.contains('=') && ASSIGNMENT.is_match(word)
}

/// Command head (lowercase basename) after prefixes, assignments and prefix
/// flags, and the words after it; `None` for a segment with no head.
pub(crate) fn head_and_rest<S: AsRef<str>>(seg: &[S]) -> (Option<String>, &[S]) {
    let mut i = 0;
    while i < seg.len() {
        let word = seg[i].as_ref();
        if base_in(word, &PREFIXES) || is_assignment(word) || (i > 0 && word.starts_with('-')) {
            i += 1;
            continue;
        }
        break;
    }
    if i < seg.len() {
        (Some(base(seg[i].as_ref())), &seg[i + 1..])
    } else {
        (None, &[])
    }
}

/// Text of a `FLAG_VERB` match (the verb, lowercased).
pub(crate) fn flag_verb(word: &str) -> Option<String> {
    FLAG_VERB
        .captures(word)
        .map(|captures| captures[1].to_lowercase())
}

fn any_class(word: &str) -> bool {
    READ.contains(word) || MUTATE.contains(word) || DELETE.contains(word) || EXEC.contains(word)
}

/// Class of what the segment does: PowerShell Verb-Noun, hyphenated and plain
/// subcommands, and verb flags.
pub(crate) fn verb_class<S: AsRef<str>>(head: &str, rest: &[S]) -> Option<&'static str> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some((verb, _)) = head.split_once('-') {
        if any_class(verb) {
            candidates.push(verb.to_string());
        }
    }
    candidates.push(head.to_string());
    for word in rest
        .iter()
        .map(AsRef::as_ref)
        .filter(|w| !w.starts_with('-'))
        .take(2)
    {
        let lower = word.to_lowercase();
        let first = lower.split('-').next().unwrap_or("").to_string();
        candidates.push(lower);
        candidates.push(first);
    }
    candidates.extend(rest.iter().filter_map(|w| flag_verb(w.as_ref())));
    CLASS_OF
        .iter()
        .find(|(_, words)| candidates.iter().any(|c| words.contains(c.as_str())))
        .map(|(name, _)| *name)
}

/// Target class of a path or registry argument.
pub(crate) fn target_class(word: &str, file_head: bool) -> Option<&'static str> {
    let w = py_strip(word);
    if w.is_empty() || w.starts_with('-') {
        return None;
    }
    for (name, rx) in TARGETS.iter() {
        if rx.is_match(w) {
            return Some(name);
        }
    }
    if PATHLIKE.is_match(w) || (file_head && FILE_WORD.is_match(w)) {
        return Some("PROJECT");
    }
    None
}

/// Small integers and boolean-ish literals after a value flag or in
/// `key=value` form (`VAL=<v>`, `<key>=<v>`).
pub(crate) fn values<S: AsRef<str>>(rest: &[S]) -> Vec<String> {
    let mut out = Vec::new();
    for (k, word) in rest.iter().map(AsRef::as_ref).enumerate() {
        let lower = word.to_lowercase();
        let key_value = word
            .contains([':', '='])
            .then(|| KEY_VALUE.captures(word))
            .flatten();
        if let Some(captures) = key_value {
            let value = &captures[2];
            let value_lower = value.to_lowercase();
            if SMALL_INT.is_match(value) || BOOLISH.contains(value_lower.as_str()) {
                out.push(format!("VAL={value_lower}"));
                out.push(format!("{}={value_lower}", captures[1].to_lowercase()));
                continue;
            }
        }
        if k > 0
            && VALUE_FLAG.is_match(rest[k - 1].as_ref())
            && (SMALL_INT.is_match(word) || BOOLISH.contains(lower.as_str()))
        {
            out.push(format!("VAL={lower}"));
            out.push(format!("{}={lower}", rest[k - 1].as_ref().to_lowercase()));
        }
    }
    out
}

// ---- segments.py: DefenseClaw OperationKind approximation ----

pub(crate) static DOWNLOADERS: WordSet = word_set!(
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "aria2c",
    "fetch",
    "bitsadmin",
    "start-bitstransfer",
);
static DECODERS: WordSet =
    word_set!("base64", "xxd", "certutil", "openssl", "uudecode", "gunzip", "zcat", "base32");
pub(crate) static CONNECTORS: WordSet = word_set!(
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "tftp"
);
static PERMISSION: WordSet = word_set!(
    "chmod", "chown", "chgrp", "icacls", "cacls", "takeown", "setfacl", "usermod", "gpasswd",
    "visudo", "set-acl", "chattr",
);
static PRIVILEGE: WordSet = word_set!("sudo", "doas", "su", "runas", "pkexec", "start-process");
static COPIERS: WordSet = word_set!(
    "cp",
    "mv",
    "rsync",
    "scp",
    "copy",
    "xcopy",
    "robocopy",
    "copy-item",
    "move-item",
    "install"
);
static DISK_WRITERS: WordSet = word_set!(
    "dd",
    "mkfs",
    "fdisk",
    "parted",
    "sfdisk",
    "wipefs",
    "diskpart",
    "format",
    "format-volume",
    "clear-disk",
    "blkdiscard",
    "shred",
);
static CONTAINER: WordSet = word_set!("docker", "podman", "nerdctl", "ctr", "kubectl", "crictl");
static KILLERS: WordSet = word_set!(
    "kill",
    "pkill",
    "killall",
    "taskkill",
    "stop-process",
    "skill"
);
static ACCOUNTS: WordSet = word_set!(
    "useradd",
    "adduser",
    "usermod",
    "userdel",
    "passwd",
    "chpasswd",
    "new-localuser",
    "set-localuser",
    "add-localgroupmember",
    "dscl",
    "sysadminctl",
);
static SCANNERS: WordSet = word_set!("nmap", "masscan", "zmap", "rustscan", "arp-scan", "nbtscan");
static UPLOAD_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file(=.*)?|--post-data(=.*)?|-InFile|-Body)$",
        true,
        Anchor::Match,
    )
});

/// Command head without a trailing `.exe` (`re.sub(r'\.exe$', '', head)`).
pub(crate) fn program(head: &str) -> String {
    if let Some(stem) = head.strip_suffix(".exe") {
        return stem.to_string();
    }
    if let Some(stem) = head.strip_suffix(".exe\n") {
        return format!("{stem}\n");
    }
    head.to_string()
}

/// OperationKinds of one segment (`seg` = raw words, `head`/`rest` from
/// [`head_and_rest`], `relations` of the whole command). `verb` is the verb
/// class the facts extractor decided.
pub(crate) fn segment_ops<S: AsRef<str>>(
    seg: &[S],
    head: &str,
    rest: &[S],
    redirected: bool,
    relations: &[&str],
    verb: Option<&str>,
) -> Vec<&'static str> {
    let prog = program(head);
    let prog = prog.as_str();
    let file_head = FILE_HEADS.contains(head);
    let secret_target = rest
        .iter()
        .any(|w| target_class(w.as_ref(), file_head) == Some("SECRET"));
    let mut ops = BTreeSet::new();
    match verb {
        Some("READ") => {
            ops.insert("READ");
        }
        Some("DELETE") => {
            ops.insert("DELETE");
        }
        Some("MUTATE") => {
            ops.insert("CONFIG_CHANGE");
        }
        Some("EXEC") => {
            ops.insert("EXECUTE");
        }
        _ => {}
    }
    if PERMISSION.contains(prog) {
        ops.insert("PERMISSION_CHANGE");
    }
    if secret_target {
        ops.insert("CREDENTIAL_READ");
    }
    if DOWNLOADERS.contains(prog) || relations.iter().any(|r| r.starts_with("DL->")) {
        ops.insert("FETCH");
    }
    if DECODERS.contains(prog) {
        ops.insert("DECODE");
    }
    if CONNECTORS.contains(prog) {
        let listen = rest
            .iter()
            .any(|w| matches!(w.as_ref(), "-l" | "--listen" | "-lvnp" | "-lnvp" | "-nlvp"));
        ops.insert(if listen { "LISTEN" } else { "CONNECT" });
    }
    if verb == Some("MUTATE") || redirected {
        ops.insert("WRITE");
    }
    let first = seg
        .first()
        .map(|w| w.as_ref().rsplit('/').next().unwrap_or("").to_lowercase());
    if PRIVILEGE.contains(prog) || matches!(first.as_deref(), Some("sudo" | "doas")) {
        ops.insert("PRIVILEGE");
    }
    if (DOWNLOADERS.contains(prog) && rest.iter().any(|w| UPLOAD_FLAGS.is_match(w.as_ref())))
        || matches!(prog, "scp" | "rsync")
    {
        ops.insert("UPLOAD");
    }
    if DISK_WRITERS.contains(prog) || prog.starts_with("mkfs") {
        ops.insert("DISK_WRITE");
    }
    if COPIERS.contains(prog) {
        ops.insert("COPY");
    }
    if CONTAINER.contains(prog)
        && rest.iter().take(2).any(|w| {
            matches!(
                w.as_ref().to_lowercase().as_str(),
                "run" | "exec" | "create"
            )
        })
    {
        ops.insert("CONTAINER_RUN");
    }
    if KILLERS.contains(prog) {
        ops.insert("PROCESS_KILL");
    }
    if ACCOUNTS.contains(prog) {
        ops.insert("ACCOUNT_CHANGE");
    }
    if SCANNERS.contains(prog) {
        ops.insert("NETWORK_SCAN");
    }
    ops.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_string).collect()
    }

    #[test]
    fn segments_split_on_separators_comments_and_redirects() {
        let masked = Masked::new("sudo rm -rf '/tmp/x' > log; echo ok # c\nls");
        assert_eq!(
            segments(&masked.tokens()),
            vec![
                words("sudo rm -rf /tmp/x log"),
                words("echo ok"),
                words("c"),
                words("ls")
            ]
        );
    }

    #[test]
    fn head_skips_prefixes_assignments_and_prefix_flags() {
        let seg = words("sudo -E FOO=1 /usr/bin/Kubectl delete pod");
        let (head, rest) = head_and_rest(&seg);
        assert_eq!(head.as_deref(), Some("kubectl"));
        assert_eq!(rest, &words("delete pod")[..]);
        assert_eq!(head_and_rest(&words("sudo env")).0, None);
    }

    #[test]
    fn verb_classes_cover_cmdlets_subcommands_and_flags() {
        assert_eq!(verb_class("remove-item", &words("x")), Some("DELETE"));
        assert_eq!(verb_class("aws", &words("iam list-users")), Some("READ"));
        assert_eq!(
            verb_class("firewall-cmd", &words("--add-port=1/tcp")),
            Some("MUTATE")
        );
        assert_eq!(verb_class("frob", &words("x y")), None);
    }

    #[test]
    fn target_classes() {
        assert_eq!(target_class("/", false), Some("ROOT"));
        assert_eq!(target_class("~/.ssh/id_rsa", false), Some("SECRET"));
        assert_eq!(target_class("/etc/passwd", false), Some("SYSTEM"));
        assert_eq!(target_class("/tmp/x", false), Some("TMP"));
        assert_eq!(target_class("dist", true), Some("PROJECT"));
        assert_eq!(target_class("dist", false), None);
        assert_eq!(target_class("-rf", true), None);
    }

    #[test]
    fn values_keep_small_ints_and_booleans() {
        assert_eq!(
            values(&words("--count 3 enabled=TRUE -x big")),
            ["VAL=3", "--count=3", "VAL=true", "enabled=true"]
        );
    }

    #[test]
    fn program_drops_exe_like_python_dollar() {
        assert_eq!(program("curl.exe"), "curl");
        assert_eq!(program("curl.exe\n"), "curl\n");
        assert_eq!(program("curl"), "curl");
    }

    #[test]
    fn ops_of_an_upload_and_a_privileged_listener() {
        let seg = words("curl -T f https://x.example");
        let (head, rest) = head_and_rest(&seg);
        let ops = segment_ops(&seg, head.as_deref().unwrap(), rest, false, &[], None);
        assert_eq!(ops, ["FETCH", "UPLOAD"]);
        let seg = words("sudo nc -lvnp 4444");
        let (head, rest) = head_and_rest(&seg);
        let ops = segment_ops(&seg, head.as_deref().unwrap(), rest, false, &[], None);
        assert_eq!(ops, ["LISTEN", "PRIVILEGE"]);
    }
}
