// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tool-call model's featurizer (reference `featurize.py`): one item, a
//! tool call or a tool definition, to presence tokens and the text of its
//! character n-grams. Also the helpers the facts share with it: name tokens,
//! argument parsing, the shell command of a call and the tool-name atoms.
//! Python semantics that matter are kept: `or` truthiness, slicing by
//! characters, `$` also matching before a final newline.

use std::sync::LazyLock;

use regex::Regex;

use super::json::Json;
use crate::detectors::shell::kf1;
use crate::detectors::shell::pyre::{py_regex, Anchor};

const OPKEYS: &[&str] = &[
    "action",
    "operation",
    "op",
    "method",
    "mode",
    "command",
    "subcommand",
    "verb",
    "type",
    "kind",
];
pub(super) const CODEKEYS: &[&str] = &[
    "command",
    "cmd",
    "code",
    "script",
    "sql",
    "query",
    "_input",
    "_raw",
    "input",
    "function",
    "expression",
    "text",
    "pipeline",
];
const SHELLKEYS: &[&str] = &["command", "cmd", "script"];

pub(super) static URL: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", true, Anchor::Match));
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", true, Anchor::Match));
static PATHLIKE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^(~|/|\./|\.\./|[A-Za-z]:\\)|^[\w.-]+/[\w./-]+$",
        false,
        Anchor::Match,
    )
});
static INNER: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"tools\.([A-Za-z_]\w*)\s*\(", false, Anchor::Search));
static CODE_TOK: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"[A-Za-z_][\w.-]*|[|;&><$]+", false, Anchor::Search));
static CAMEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z0-9])([A-Z])").expect("camel"));
static NON_ALNUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").expect("alnum"));
static TOK40: LazyLock<Regex> = LazyLock::new(|| py_regex(r"[\w.-]{1,40}", false, Anchor::Full));
static TOK30: LazyLock<Regex> = LazyLock::new(|| py_regex(r"[\w.-]{1,30}", false, Anchor::Full));
static EXT: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"\.([a-z0-9]{1,6})$", false, Anchor::Search));
static PRIVATE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.",
        false,
        Anchor::Match,
    )
});
static ARGKEY: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r#""([A-Za-z_][\w-]{0,40})"\s*:"#, false, Anchor::Search));
pub(super) static NS_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"__|[.:/]").expect("namespace split"));

/// Optional token groups of the featurizer (`featurize.FACTS`, `featurize.VERBS`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    /// Cat's `F:` fact tokens for shell commands.
    pub facts: bool,
    /// `VB:` / `TA:` tool-name atoms.
    pub verbs: bool,
}

/// Tool vocabulary atoms: words in the tool name, for action classes the
/// arguments do not show.
pub(super) const NAME_ATOMS: &[(&str, &[&str])] = &[
    (
        "TOOL_MONEY",
        &[
            "pay",
            "payment",
            "payments",
            "transfer",
            "withdraw",
            "withdrawal",
            "deposit",
            "money",
            "ether",
            "bitcoin",
            "crypto",
            "refund",
            "payout",
            "wire",
            "remit",
            "venmo",
            "paypal",
            "zelle",
            "trade",
            "swap",
        ],
    ),
    (
        "TOOL_PHYSICAL",
        &[
            "robot",
            "lock",
            "unlock",
            "door",
            "thermostat",
            "device",
            "devices",
            "light",
            "lights",
            "traffic",
            "vehicle",
            "drone",
            "valve",
            "garage",
            "alarm",
            "camera",
            "oven",
            "appliance",
            "dispatch",
            "home",
        ],
    ),
    (
        "TOOL_ACCOUNT",
        &[
            "user",
            "users",
            "account",
            "accounts",
            "member",
            "members",
            "employee",
            "employees",
            "customer",
            "customers",
            "guest",
            "guests",
            "patient",
            "patients",
            "contact",
            "contacts",
        ],
    ),
    (
        "TOOL_SECCTL",
        &[
            "firewall",
            "mfa",
            "2fa",
            "audit",
            "antivirus",
            "protection",
            "blocklist",
            "blacklist",
            "whitelist",
            "allowlist",
            "security",
            "guard",
            "sso",
            "umbrella",
            "permission",
            "permissions",
            "access",
        ],
    ),
];
const LOOSEN: &[&str] = &[
    "unblock",
    "disable",
    "allow",
    "whitelist",
    "allowlist",
    "deactivate",
    "remove",
    "delete",
    "bypass",
    "grant",
    "unlock",
    "off",
    "open",
    "revoke",
];
/// The verb of the tool name, strongest first.
const NAME_VERBS: &[(&str, &[&str])] = &[
    (
        "VERB_DELETE",
        &[
            "delete",
            "remove",
            "destroy",
            "drop",
            "purge",
            "erase",
            "wipe",
            "terminate",
            "cancel",
            "revoke",
        ],
    ),
    (
        "VERB_MOVE",
        &[
            "pay", "transfer", "withdraw", "send", "wire", "deposit", "refund", "payout", "trade",
            "swap", "buy", "sell", "purchase", "ship", "forward", "share", "post", "publish",
            "tweet", "transact",
        ],
    ),
    (
        "VERB_MUTATE",
        &[
            "set", "update", "edit", "modify", "change", "control", "apply", "give", "grant",
            "unblock", "unlock", "lock", "disable", "enable", "allow", "create", "add", "manage",
            "toggle", "turn", "start", "stop", "restart", "execute", "run", "move", "open",
            "close", "go", "deploy",
        ],
    ),
    (
        "VERB_READ",
        &[
            "get", "search", "view", "find", "list", "read", "check", "fetch", "show", "query",
            "lookup", "describe", "retrieve", "download", "inspect",
        ],
    ),
];

/// Tool-name atoms (`featurize.name_atoms`): vocabulary atoms, `TOOL_LOOSEN`
/// and the strongest verb.
pub(super) fn name_atoms(name_tokens: &[String]) -> Vec<&'static str> {
    let has = |words: &[&str]| name_tokens.iter().any(|t| words.contains(&t.as_str()));
    let mut out: Vec<&'static str> = NAME_ATOMS
        .iter()
        .filter(|(_, words)| has(words))
        .map(|(atom, _)| *atom)
        .collect();
    if has(LOOSEN) {
        out.push("TOOL_LOOSEN");
    }
    if let Some((verb, _)) = NAME_VERBS.iter().find(|(_, words)| has(words)) {
        out.push(verb);
    }
    out
}

/// The shell command of a call, if any: a string, or an argv list
/// (`bash -lc X` -> `X`).
pub(super) fn shell_command(args: &[(String, Json)]) -> Option<String> {
    for (k, v) in args {
        if !SHELLKEYS.contains(&k.to_lowercase().as_str()) {
            continue;
        }
        match v {
            Json::Array(a) if !a.is_empty() && a.iter().all(|x| x.as_str().is_some()) => {
                let s: Vec<&str> = a.iter().filter_map(Json::as_str).collect();
                return Some(if s.len() >= 3 && (s[1] == "-lc" || s[1] == "-c") {
                    s[2].to_string()
                } else {
                    s.join(" ")
                });
            }
            Json::String(s) if !s.trim().is_empty() => return Some(s.clone()),
            _ => {}
        }
    }
    None
}

/// Python `s[:n]` on a str: the first `n` characters.
pub(super) fn trunc(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// Lowercase alphanumeric words of a name, camel case split.
pub fn name_tokens(s: &str) -> Vec<String> {
    let s = CAMEL.replace_all(s, "${1}_${2}").to_lowercase();
    NON_ALNUM
        .split(&s)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

/// The arguments of a call as an object: a JSON object, JSON text of one, or
/// `{"_raw": value}`; truncated JSON text keeps the keys it shows.
pub(super) fn parse_args(arguments: Option<&Json>) -> Vec<(String, Json)> {
    let raw = |v: Json| vec![("_raw".to_string(), v)];
    match arguments {
        Some(Json::Object(o)) => o.clone(),
        Some(Json::String(s)) => match Json::parse(s) {
            Ok(Json::Object(o)) => o,
            Ok(v) => raw(v),
            Err(_) => {
                let mut keys: Vec<(String, Json)> = Vec::new();
                for c in ARGKEY.captures_iter(s) {
                    if !keys.iter().any(|(k, _)| k == &c[1]) {
                        keys.push((c[1].to_string(), Json::String(String::new())));
                    }
                }
                if keys.is_empty() {
                    raw(Json::String(s.clone()))
                } else {
                    keys
                }
            }
        },
        Some(v) => raw(v.clone()),
        None => raw(Json::Null),
    }
}

fn path_class(p: &str, out: &mut Vec<String>) {
    let q = p.to_lowercase();
    let starts = |xs: &[&str]| xs.iter().any(|x| q.starts_with(x));
    let drive =
        q.len() >= 3 && q.as_bytes()[0].is_ascii_lowercase() && &q.as_bytes()[1..3] == b":\\";
    let cls = if starts(&["~", "/users/", "/home/"]) {
        "home"
    } else if starts(&["/tmp", "/private/tmp", "/var/tmp"]) {
        "tmp"
    } else if starts(&[
        "/etc",
        "/usr",
        "/bin",
        "/sys",
        "/proc",
        "/var",
        "c:\\windows",
    ]) {
        "system"
    } else if q.starts_with('/') || drive {
        "abs"
    } else {
        "rel"
    };
    out.push(format!("P:{cls}"));
    out.push(format!(
        "PX:{}",
        EXT.captures(&q)
            .map_or("none", |c| c.get(1).map_or("none", |m| m.as_str()))
    ));
    if [
        ".ssh",
        ".aws",
        ".env",
        "credential",
        "secret",
        "id_rsa",
        ".kube",
        "token",
    ]
    .iter()
    .any(|s| q.contains(s))
    {
        out.push("P:secret".into());
    }
}

fn url_class(host: &str, out: &mut Vec<String>) {
    let h = host.to_lowercase();
    if ["localhost", "127.0.0.1", "0.0.0.0"].contains(&h.as_str()) || h.ends_with(".local") {
        out.push("U:local".into());
    } else if PRIVATE.is_match(&h) {
        out.push("U:private".into());
    } else {
        out.push("U:public".into());
        out.push(format!("UT:{}", h.rsplit('.').next().unwrap_or("")));
    }
}

fn shape(v: &Json) -> &'static str {
    match v {
        Json::Bool(_) => "bool",
        Json::Number(_) => "num",
        Json::Array(_) => "list",
        Json::Object(_) => "obj",
        Json::Null => "null",
        Json::String(s) => {
            if URL.is_match(s) {
                "url"
            } else if EMAIL.is_match(s) {
                "email"
            } else if s.contains('\n') {
                "multiline"
            } else if PATHLIKE.is_match(s) && !s.contains(' ') {
                "path"
            } else if TOK40.is_match(s) {
                "tok"
            } else {
                "text"
            }
        }
    }
}

fn key_token(key: &str) -> (String, Vec<String>) {
    let kn = name_tokens(key);
    let kt = if kn.is_empty() {
        key.to_string()
    } else {
        kn.join("_")
    };
    (kt, kn)
}

fn value_tokens<'a>(key: &str, v: &'a Json, out: &mut Vec<String>, code: &mut Vec<&'a str>) {
    let sh = shape(v);
    let (kt, kn) = key_token(key);
    out.push(format!("K:{kt}"));
    out.push(format!("KS:{kt}:{sh}"));
    out.extend(kn.iter().map(|t| format!("KT:{t}")));
    match v {
        Json::String(s) => {
            let kl = key.to_lowercase();
            if OPKEYS.contains(&kl.as_str()) && TOK30.is_match(s) {
                out.push(format!("OP:{}", s.to_lowercase()));
                out.extend(name_tokens(s).iter().map(|t| format!("OPT:{t}")));
            }
            if let Some(c) = URL.captures(s) {
                url_class(&c[1], out);
            } else if sh == "path" {
                path_class(s, out);
            } else if sh == "email" {
                out.push("E:email".into());
            }
            if CODEKEYS.contains(&kl.as_str()) || sh == "multiline" {
                code.push(trunc(s, 600));
            }
        }
        Json::Object(o) => {
            for (k2, v2) in o.iter().take(20) {
                value_tokens(k2, v2, out, code);
            }
        }
        Json::Array(a) => {
            for x in a.iter().take(10) {
                if !matches!(x, Json::Object(_)) {
                    continue;
                }
                // x.get("name") or x.get("tool")
                let inner = x
                    .get("name")
                    .filter(|v| v.truthy())
                    .or_else(|| x.get("tool"));
                if let Some(Json::String(inner)) = inner {
                    out.push("SEG:sub".into());
                    out.extend(name_tokens(inner).iter().map(|t| format!("N:{t}")));
                }
                if let Json::Object(io) = x.get("input").unwrap_or(x) {
                    for (k2, v2) in io.iter().take(20) {
                        value_tokens(k2, v2, out, code);
                    }
                }
            }
        }
        _ => {}
    }
}

/// `(tokens, char_text)` of a rendered item: `tool`, `harness`, `kind`
/// (`tool_call` or `tool_definition`), `arguments` or `parameters`,
/// `description`.
pub fn featurize(item: &Json, opts: Opts) -> (Vec<String>, String) {
    let tool = item.get("tool").and_then(Json::as_str).unwrap_or("");
    let mut toks: Vec<String> = Vec::with_capacity(128);
    let mut code: Vec<&str> = Vec::new();
    let nt = name_tokens(tool);
    toks.extend(nt.iter().map(|t| format!("N:{t}")));
    toks.push(nt.first().map_or("NV:none".into(), |t| format!("NV:{t}")));
    let mut parts = NS_SPLIT.split(tool);
    let first = parts.next().unwrap_or("");
    if parts.next().is_some() {
        toks.push(format!("NS:{}", name_tokens(first).join("_")));
    }
    toks.push(match item.get("harness") {
        Some(h) if h.truthy() => format!("H:{}", h.py_str()),
        _ => "H:def".into(),
    });
    if opts.verbs {
        let mut atoms: Vec<String> = name_atoms(&nt)
            .into_iter()
            .map(|a| {
                if a.starts_with("VERB_") {
                    format!("VB:{a}")
                } else {
                    format!("TA:{a}")
                }
            })
            .collect();
        atoms.sort();
        toks.extend(atoms);
    }
    let desc = item.get("description").and_then(Json::as_str).unwrap_or("");
    let args; // owns the parsed arguments that `code` borrows from
    if item.get("kind").and_then(Json::as_str) == Some("tool_definition") {
        toks.push("KIND:def".into());
        if let Some(Json::Object(ps)) = item.get("parameters") {
            for (k, spec) in ps {
                let (kt, kn) = key_token(k);
                let ty = spec.get("type").map_or("none".into(), Json::py_str);
                toks.push(format!("K:{kt}"));
                toks.push(format!("KS:{kt}:{ty}"));
                toks.extend(kn.iter().map(|t| format!("KT:{t}")));
                if let Some(e) = spec.get("enum").filter(|e| e.truthy()) {
                    if OPKEYS.contains(&k.to_lowercase().as_str()) {
                        toks.extend(
                            name_tokens(&e.py_str())
                                .iter()
                                .take(20)
                                .map(|t| format!("OPT:{t}")),
                        );
                    } else {
                        toks.push("ENUM".into());
                    }
                }
            }
        }
        toks.extend(name_tokens(desc).iter().take(60).map(|t| format!("D:{t}")));
    } else {
        toks.push("KIND:call".into());
        args = parse_args(item.get("arguments"));
        if args.is_empty() {
            toks.push("K:none".into());
        }
        for (k, v) in args.iter().take(40) {
            value_tokens(k, v, &mut toks, &mut code);
        }
        for c in &code {
            for m in INNER.captures_iter(c) {
                toks.push("SEG:inner".into());
                toks.extend(name_tokens(&m[1]).iter().map(|t| format!("N:{t}")));
            }
            toks.extend(
                CODE_TOK
                    .find_iter(c)
                    .take(80)
                    .map(|m| format!("C:{}", m.as_str().to_lowercase())),
            );
        }
        if let Some(cmd) = if opts.facts {
            shell_command(&args)
        } else {
            None
        } {
            // Cat's fact tokens: the F: part of its kf1 analyzer
            toks.push("SHELL".into());
            toks.extend(kf1(&cmd).into_iter().filter(|t| t.starts_with("F:")));
        }
        if !desc.is_empty() {
            toks.push("HASDESC".into());
            toks.extend(name_tokens(desc).iter().take(60).map(|t| format!("D:{t}")));
        }
    }
    let keys: Vec<&str> = toks.iter().filter_map(|t| t.strip_prefix("K:")).collect();
    let codes: Vec<&str> = code.iter().map(|c| trunc(c, 300)).collect();
    let joined = codes.join(" ");
    let char_text = format!("{tool} | {} | {}", keys.join(" "), trunc(&joined, 600));
    (toks, char_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_tokens() {
        let item = Json::parse(
            r#"{"kind": "tool_call", "tool": "github__delete_repository", "harness": "codex",
                "arguments": "{\"owner\": \"acme\", \"url\": \"https://github.com/acme/x\"}"}"#,
        )
        .unwrap();
        let (toks, text) = featurize(
            &item,
            Opts {
                facts: true,
                verbs: true,
            },
        );
        for t in [
            "N:github",
            "NS:github",
            "H:codex",
            "VB:VERB_DELETE",
            "KIND:call",
            "KS:url:url",
            "U:public",
            "UT:com",
        ] {
            assert!(toks.iter().any(|x| x == t), "{t} missing in {toks:?}");
        }
        assert_eq!(text, "github__delete_repository | owner url | ");
    }

    #[test]
    fn truncated_arguments_keep_their_keys() {
        let args = parse_args(Some(&Json::String(r#"{"path": "/a", "mode": "#.into())));
        assert_eq!(
            args.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            ["path", "mode"]
        );
    }
}
