// SPDX-License-Identifier: MIT OR Apache-2.0
//! DefenseClaw-style operation kinds of a segment, approximated from the verb,
//! target and relation facts (`segments.py`).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::detectors::shell::pyre::{py_regex, Anchor};

use super::{target_class, WordSet, FILE_HEADS};

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
    use super::super::head_and_rest;
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_string).collect()
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
