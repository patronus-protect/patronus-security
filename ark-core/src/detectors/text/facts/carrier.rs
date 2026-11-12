// SPDX-License-Identifier: MIT OR Apache-2.0
//! The carrier of a text, read from its structure alone (request metadata is
//! never seen): every carrier whose marks the text shows, or `chat` when it
//! shows none.

use std::sync::LazyLock;

use regex::RegexSet;

/// Carrier names in the order of [`MARKS`].
const CARRIERS: [&str; 7] = [
    "agent_config",
    "code",
    "document",
    "email",
    "log",
    "tool_description",
    "webpage",
];

/// One linear pattern per carrier, compiled once into one set.
static MARKS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Agent instruction files and agent/MCP configuration keys.
        r#"(?i)\b(?:agents|claude|gemini|skill|copilot-instructions)\.md\b|(?:^|[\s/])\.cursorrules\b|\bmcp\.json\b|"(?:mcpServers|autoApprove|hooks)"\s*:|(?m:^\s*allowed-tools\s*:)"#,
        // Source code lines and code fences.
        r"(?m)^\s*(?:def |class |import |from [\w.]{1,64} import |function |const |let |fn |pub fn |#include|package )|(?m:^```)",
        // Markdown headings and numbered document parts.
        r"(?mi)^#{1,6} \S|^(?:appendix|anhang|chapter|kapitel|section|abschnitt) \w",
        // Mail headers and salutations on a line of their own.
        r"(?mi)^(?:from|to|cc|subject|von|an|betreff):[ \t]|^(?:hi|hello|dear|hallo|liebe|lieber|sehr geehrte)\b[^\n]{0,60},[ \t]*$",
        // Timestamped or levelled log lines.
        r"(?m)^\s*\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|(?m:^\s*(?:INFO|WARN|WARNING|ERROR|DEBUG|TRACE)\b)",
        // Tool and MCP descriptions: JSON keys of a tool definition.
        r#""(?:description|inputSchema|input_schema|parameters)"\s*:"#,
        // HTML elements and comments.
        r"(?i)<(?:html|head|body|div|p|span|a|img|script|style|meta|title|table|ul|li)\b|<!--",
    ])
    .expect("carrier marks")
});

/// The carriers of `text`, sorted.
pub(super) fn carriers(text: &str) -> Vec<&'static str> {
    let found: Vec<&'static str> = MARKS.matches(text).iter().map(|i| CARRIERS[i]).collect();
    if found.is_empty() {
        vec!["chat"]
    } else {
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carriers_follow_the_structure() {
        assert_eq!(carriers("please summarise this"), ["chat"]);
        assert_eq!(carriers("Subject: hi\n\nbody"), ["email"]);
        assert_eq!(
            carriers("# AGENTS.md\nUse tabs."),
            ["agent_config", "document"]
        );
        assert_eq!(carriers("<p>x</p>"), ["webpage"]);
        assert_eq!(carriers(r#"{"description": "x"}"#), ["tool_description"]);
        assert_eq!(carriers("def f():\n    pass"), ["code"]);
        assert_eq!(carriers("2026-01-01 10:00 started"), ["log"]);
    }
}
