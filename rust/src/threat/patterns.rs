use aho_corasick::AhoCorasick;
use regex::Regex;
use std::sync::OnceLock;

pub(super) fn cross_tool_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "ignore the user",                // 0
            "ignore prior instructions",      // 1
            "call ",                          // 2
            "invoke ",                        // 3
            "use ",                           // 4
            "higher priority than the user",  // 5
            "when another tool is requested", // 6
        ])
        .unwrap()
    })
}

pub(super) fn instruction_leak_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "show",
            "reveal",
            "print",
            "display",
            "dump",
            "expose",
            "leak",
            "repeat", // 0..8
            "your system prompt",
            "the system prompt",
            "developer message", // 8..11
            "developer instructions",
            "hidden instruction",
            "internal instruction", // 11..14
            "initial prompt",       // 14
        ])
        .unwrap()
    })
}

pub(super) fn secret_transfer_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "exfiltrate", // 0
            "send",
            "upload",
            "post",
            "email",
            "forward",
            "leak",
            "share",
            "paste",
            "copy", // 1..10
            "api key",
            "access token",
            "auth token",
            "bearer token",
            "refresh token", // 10..15
            "secret token",
            "private key",
            "password",
            "credential",
            ".env", // 15..20
            "webhook",
            "attacker",
            "external",
            "pastebin", // 20..24
        ])
        .unwrap()
    })
}

pub(super) fn sensitive_material_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "read",
            "find",
            "show",
            "dump",
            "retrieve",
            "collect",
            "print", // 0..7
            ".env",
            ".ssh/id_",
            ".aws/credentials",
            "api key",
            "private key", // 7..12
            "password",
            "credential",
            "secret token", // 12..15
        ])
        .unwrap()
    })
}

pub(super) fn encoded_instruction_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "decode",
            "rot13",
            "base64",
            "escaped text", // 0..4
            "instruction",
            "instructions",
            "prompt",
            "system", // 4..8
        ])
        .unwrap()
    })
}

pub(super) fn multi_turn_escalation_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "as i mentioned before",
            "as discussed earlier",
            "you agreed to", // 0..3
            "bypass",
            "override",
            "ignore",
            "disable",
            "restrictions",
            "policy", // 3..9
        ])
        .unwrap()
    })
}

pub(super) fn guardrail_tamper_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "disable",
            "bypass",
            "turn off",
            "skip",
            "remove",
            "ignore", // 0..6
            "guardrail",
            "safety check",
            "security check",
            "policy check", // 6..10
            "content filter",
            "safety filter",
            "safety filters",
            "safety rules", // 10..14
            "audit",
            "monitoring", // 14..16
        ])
        .unwrap()
    })
}

pub(super) fn destructive_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "rm -rf",
            "mkfs.",
            " dd if=",
            "drop database",
            "truncate table",
            "git reset --hard",
            "git clean -fd",
            "git push --force",
            "wipe the logs",
            "wipe all recent audit events",
            "clear the security log",
            "history -c",
            "shred ",
        ])
        .unwrap()
    })
}

pub(super) fn agentic_abuse_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "chemical formula",
            "precise formula",
            "sarin",
            "nerve agent",
            "chemical weapon", // 0..5
            "subprocess.popen",
            "shell=true",
            "curl http://",
            "curl https://",
            "wget http://",
            "wget https://", // 5..11
            "memory update",
            "system state altered",
            "admin",
            "root override", // 11..15
            "handoff raw input",
            "sub-agent",
            "pass-through",
            "pass-through: true",
            "raw input", // 15..20
            "register_mcp",
            "register mcp", // 20..22
            "sig_sync",
            "swarm override",
            "secret handshake",
            "message encrypted", // 22..26
            "bypass receipt",
            "manual refund",
            "authorization", // 26..29
            "disable multi-factor authentication",
            "disable mfa",
            "temporarily disable multi-factor",
            "password reset link", // 29..33
            "account",
            "ceo",
            "alternative email", // 33..36
            "[verified:",
            "verified:",
            "always allow",
            "external api", // 36..40
            "verify your identity",
            "secure link",
            "login",
            "auth", // 40..44
            "indefinitely",
            "bypass human approval",
            "all future steps", // 44..47
            "override",
            "bypass",
            "http://",
            "https://", // 47..51
        ])
        .unwrap()
    })
}

pub(super) fn binary_smuggling_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| AhoCorasick::new(&["metadata", "transaction", "payload"]).unwrap())
}

pub(super) fn tool_output_instruction_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "tool output",
            "tool returned",
            "tool result",
            "result says", // 0..4
            "ignore the user",
            "ignore previous instructions",
            "call ", // 4..7
            "invoke ",
            "send_email",
            "use another tool", // 7..10
        ])
        .unwrap()
    })
}

pub(super) fn mcp_runtime_risk_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "\"command\"",
            "\"args\"",
            "\"env\"",
            "stdio",
            "mcpserver",
            "mcp server", // 0..6
            "bash",
            "sh -c",
            "-lc",
            "curl ",
            "wget ",
            "| sh",
            "| bash",
            "python -c",
            "node -e", // 6..15
            "api_key",
            "api key",
            "token",
            "secret",
            "password",
            "private_key",
            "credential", // 15..22
        ])
        .unwrap()
    })
}

pub(super) fn benign_discussion_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "explain",
            "review",
            "describe",
            "what does",
            "without running",
            "do not run",
            "nicht ausführen",
        ])
        .unwrap()
    })
}

pub(super) fn sensitive_term_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "system prompt",
            "developer message",
            "developer instructions",
            "hidden instruction",
            "api key",
            "token",
            "secret",
            "password",
            "credential",
            ".env",
            ".ssh/id_",
            ".aws/credentials",
            "curl ",
            "wget ",
            "crontab",
            "systemctl",
            "launchctl",
        ])
        .unwrap()
    })
}

pub(super) fn secret_transfer_material_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(secrets?|passwords?|credentials?)\b").unwrap())
}

pub(super) fn email_address_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap())
}

pub(super) fn url_transfer_destination_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:to|onto|at)\s+https?://").unwrap())
}

pub(super) fn html_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<!--.*?-->").expect("valid HTML comment regex"))
}

pub(super) fn hidden_style_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)<[a-zA-Z][a-zA-Z0-9]*[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|color\s*:\s*(?:white|#fff{1,3}|transparent|rgba\s*\([^)]*,\s*0(?:\.0*)?\s*\)))[^"']*["'][^>]*>"#,
        )
        .expect("valid hidden style regex")
    })
}

pub(super) fn aria_hidden_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)<([a-zA-Z][a-zA-Z0-9]*)[^>]*aria-hidden\s*=\s*["']true["'][^>]*>"#)
            .expect("valid aria hidden regex")
    })
}

pub(super) fn injection_signal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)ignore\s+(all\s+)?(any\s+)?(previous\s+)?instructions|disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)|forget\s+(?:everything|all\s+previous|your\s+instructions)|new\s+(?:primary\s+)?instruction|(?:reveal|print|show|output)\s+(?:your\s+)?(?:system\s+prompt|api\s+key|secret|token)|you\s+are\s+now\s+(?:a\s+)?(?:different|new)|act\s+as\s+if\s+(?:you|your)|exfiltrat(?:e|ion)|fetch\s+https?://|send\s+(?:a\s+)?(?:get|post|http)\s+request",
        )
        .expect("valid injection signal regex")
    })
}
