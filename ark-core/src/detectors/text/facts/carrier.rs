// SPDX-License-Identifier: MIT OR Apache-2.0
//! The carrier of a text, read from its structure alone (request metadata is
//! never seen): every carrier whose marks the text shows, or `chat` when it
//! shows none.

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

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

/// A plain-text tool listing line, `Tool <snake_case_name>: …`, naming the
/// tool (`name`) the rest of the line describes.
macro_rules! tool_listing_header {
    () => {
        r"^[ \t]*(?:Tool|Function|Werkzeug|Funktion)[ \t]{1,4}`?(?P<name>[A-Za-z][A-Za-z0-9]{0,40}_[A-Za-z0-9_]{1,40})`?[ \t]*:"
    };
}

/// Tool and MCP descriptions (also agent-card skills): JSON keys of a tool
/// definition, or a line of a plain-text tool listing (`tool_listing_header!`).
const TOOL_DESCRIPTION_MARK: &str = concat!(
    r#""(?:description|inputSchema|input_schema|parameters)"\s*:|(?m:"#,
    tool_listing_header!(),
    ")"
);

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
        TOOL_DESCRIPTION_MARK,
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

/// Whether `text` carries tool metadata (the `tool_description` carrier),
/// without running the other carrier marks.
pub(crate) fn is_tool_metadata(text: &str) -> bool {
    static MARK: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(TOOL_DESCRIPTION_MARK).expect("tool description mark"));
    MARK.is_match(text)
}

/// The tool a plain-text listing line describes, when the line holding `at`
/// starts with a listing header (`Tool <name>:`).
pub(crate) fn listing_tool_name(text: &str, at: usize) -> Option<&str> {
    static HEADER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(tool_listing_header!()).expect("tool listing header"));
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let end = text[at..].find('\n').map_or(text.len(), |i| at + i);
    let line = &text[start..end];
    HEADER
        .captures(line)
        .and_then(|captures| captures.name("name"))
        .map(|name| name.as_str())
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

    #[test]
    fn tool_metadata_is_the_tool_description_carrier() {
        for text in [
            r#"{"name": "add", "description": "x"}"#,
            r#"{"skills": [{"id": "book", "description": "x"}]}"#,
            r#"{"inputSchema": {}}"#,
        ] {
            assert!(is_tool_metadata(text), "{text}");
            assert!(carriers(text).contains(&"tool_description"), "{text}");
        }
        // Plain-text tool listings, one tool per line.
        for text in [
            "Tool add_numbers: adds two numbers.",
            "Tools:\nFunction `get_weather`: returns the forecast.",
            "Werkzeug summe_zahlen: addiert zwei Zahlen.",
        ] {
            assert!(is_tool_metadata(text), "{text}");
            assert!(carriers(text).contains(&"tool_description"), "{text}");
        }
        for text in [
            "description: plain prose",
            "Use the add tool.",
            "Tool support: we answer within a day.",
            "The tool add_numbers: adds two numbers.",
        ] {
            assert!(!is_tool_metadata(text), "{text}");
            assert!(!carriers(text).contains(&"tool_description"), "{text}");
        }
    }
}
