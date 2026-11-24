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
/// tool (`listed`) the rest of the line describes.
macro_rules! tool_listing_header {
    () => {
        r"^[ \t]*(?:Tool|Function|Werkzeug|Funktion)[ \t]{1,4}`?(?P<listed>[A-Za-z][A-Za-z0-9]{0,40}_[A-Za-z0-9_]{1,40})`?[ \t]*:"
    };
}

/// A YAML tool list entry, `- name: <tool>` (`entry`) directly followed by
/// `description:`.
macro_rules! yaml_tool_entry {
    () => {
        r"^[ \t]*-[ \t]+name:[ \t]*(?P<entry>[A-Za-z][\w.-]{0,60})[ \t]*\r?\n[ \t]*description:"
    };
}

/// A README tool list line opening with a call signature,
/// `` `<tool>(args)`: `` (`signed`).
macro_rules! readme_tool_line {
    () => {
        r"^[ \t]*(?:[-*][ \t]+)?`(?P<signed>[A-Za-z_][A-Za-z0-9_]{0,40})\([^`\n)]{0,60}\)`[ \t]*:"
    };
}

/// An MCP tool decorator.
macro_rules! tool_decorator {
    () => {
        r"^[ \t]*@(?:mcp|server|app)\.tool\("
    };
}

/// Tool and MCP descriptions (also agent-card skills): JSON keys of a tool
/// definition, a line of a plain-text tool listing (`tool_listing_header!`),
/// a YAML tool list entry (`- name:` directly followed by `description:`;
/// skill frontmatter has no list dash), a README
/// tool list line opening with a call signature (`` `read_file(path)`: ``) or
/// an MCP tool decorator (`@mcp.tool()`) over the docstring.
const TOOL_DESCRIPTION_MARK: &str = concat!(
    r#""(?:description|inputSchema|input_schema|parameters)"\s*:|(?m:"#,
    tool_listing_header!(),
    "|",
    yaml_tool_entry!(),
    "|",
    readme_tool_line!(),
    "|",
    tool_decorator!(),
    ")"
);

/// Agent instruction files (rules files, skills and their frontmatter), agent
/// settings directories and agent/MCP configuration keys.
const AGENT_CONFIG_MARK: &str = r#"(?i)\b(?:agents|claude|gemini|skill|copilot-instructions)\.md\b|(?:^|[\s/])\.(?:cursorrules|windsurfrules)\b|(?:^|[\s/"'`])\.(?:claude|cursor|codex)/|\bmcp\.json\b|"(?:mcpServers|autoApprove|hooks|permissions|defaultMode|disableAllHooks)"\s*:|(?m:^\s*allowed-tools\s*:)|\A---\r?\nname:[^\n]{0,80}\r?\ndescription:"#;

/// One linear pattern per carrier, compiled once into one set.
static MARKS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        AGENT_CONFIG_MARK,
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

/// Whether `text` is or names an agent instruction or configuration file (the
/// `agent_config` carrier), without running the other carrier marks.
pub(crate) fn is_agent_config(text: &str) -> bool {
    static MARK: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(AGENT_CONFIG_MARK).expect("agent config mark"));
    MARK.is_match(text)
}

/// The tool whose description holds `at`: the last tool header that starts
/// at or before `at` and ends on its line at the latest — a listing line
/// (`Tool <name>:`), a YAML tool entry, a README call signature or the
/// function under an MCP tool decorator.
pub(crate) fn owning_tool_name(text: &str, at: usize) -> Option<&str> {
    static HEADER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(concat!(
            "(?m:",
            tool_listing_header!(),
            "|",
            yaml_tool_entry!(),
            "|",
            readme_tool_line!(),
            "|",
            tool_decorator!(),
            r"[^\n]{0,200}\n(?:[ \t]*@[^\n]{0,200}\n){0,4}[ \t]*(?:async[ \t]+)?def[ \t]+(?P<decorated>[A-Za-z_][A-Za-z0-9_]{0,60})\(",
            ")"
        ))
        .expect("tool header")
    });
    let end = text[at..].find('\n').map_or(text.len(), |i| at + i);
    let head = &text[..end];
    let last = HEADER
        .find_iter(head)
        .take_while(|header| header.start() <= at)
        .last()?;
    let captures = HEADER.captures_at(head, last.start())?;
    ["listed", "entry", "signed", "decorated"]
        .iter()
        .find_map(|group| captures.name(group))
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
    fn agent_config_is_rules_files_skills_and_settings() {
        for text in [
            "# CLAUDE.md\nUse pnpm.",
            ".claude/settings.json\n{}",
            r#"{"permissions": {"allow": ["Read"]}}"#,
            "---\nname: pdf-export\ndescription: Exports PDFs\n---\nBody",
            "Edit the .cursorrules file.",
            r#"approval_policy in ".codex/config.toml""#,
        ] {
            assert!(is_agent_config(text), "{text}");
            assert!(carriers(text).contains(&"agent_config"), "{text}");
        }
        for text in [
            "Please review the permissions of the shared folder.",
            "---\ntitle: Notes\n---",
            "the claude model answers",
            "see src/.claudeignore.rs",
        ] {
            assert!(!is_agent_config(text), "{text}");
            assert!(!carriers(text).contains(&"agent_config"), "{text}");
        }
    }

    #[test]
    fn tool_metadata_is_the_tool_description_carrier() {
        for text in [
            r#"{"name": "add", "description": "x"}"#,
            r#"{"skills": [{"id": "book", "description": "x"}]}"#,
            r#"{"inputSchema": {}}"#,
            r#"{"result": {"tools": [{"name": "read_calendar", "description": "x"}]}}"#,
            r#"{"paths": {"/lookup": {"get": {"summary": "x", "description": "x"}}}}"#,
        ] {
            assert!(is_tool_metadata(text), "{text}");
            assert!(carriers(text).contains(&"tool_description"), "{text}");
        }
        // Plain-text tool listings, one tool per line.
        for text in [
            "Tool add_numbers: adds two numbers.",
            "Tools:\nFunction `get_weather`: returns the forecast.",
            "Werkzeug summe_zahlen: addiert zwei Zahlen.",
            "Functions exposed by the server:\nFunction convert_units_3: converts units.",
            "Vom Server bereitgestellte Funktionen:\nFunktion einheiten_umrechnen_3: rechnet um.",
        ] {
            assert!(is_tool_metadata(text), "{text}");
            assert!(carriers(text).contains(&"tool_description"), "{text}");
        }
        // MCP server YAML, README tool lists and MCP tool decorators.
        for text in [
            "server: notes\ntools:\n  - name: save_note\n    description: >\n      Saves a note.",
            "## Tools\n\n`read_file(path)`: reads a file from the workspace.",
            "- `datei_lesen(pfad)`: liest eine Datei.",
            "@mcp.tool()\ndef lookup(query: str) -> str:\n    \"\"\"Search the wiki.\"\"\"",
        ] {
            assert!(is_tool_metadata(text), "{text}");
            assert!(carriers(text).contains(&"tool_description"), "{text}");
        }
        for text in [
            "description: plain prose",
            "Use the add tool.",
            "Tool support: we answer within a day.",
            "The tool add_numbers: adds two numbers.",
            "name: build\non: push",
            "---\nname: pdf-export\ndescription: Exports PDFs\n---\nBody",
            "Call `read_file(path)` to read a file.",
            "@pytest.fixture()\ndef tool():\n    pass",
        ] {
            assert!(!is_tool_metadata(text), "{text}");
            assert!(!carriers(text).contains(&"tool_description"), "{text}");
        }
    }

    #[test]
    fn owning_tool_is_the_last_header_before_the_offset() {
        fn owner<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
            owning_tool_name(text, text.find(needle).unwrap())
        }
        let listing = "Tool add_numbers: adds.\nTool get_time: returns the time.";
        assert_eq!(owner(listing, "adds"), Some("add_numbers"));
        assert_eq!(owner(listing, "returns"), Some("get_time"));
        let readme = "- `datei_lesen(pfad)`: liest eine Datei.";
        assert_eq!(owner(readme, "liest"), Some("datei_lesen"));
        assert_eq!(owner(readme, "`"), Some("datei_lesen"));
        let yaml = "tools:\n  - name: save_note\n    description: >\n      Saves a note.";
        assert_eq!(owner(yaml, "Saves"), Some("save_note"));
        let decorated =
            "@mcp.tool()\nasync def lookup(query: str) -> str:\n    \"\"\"Search.\"\"\"";
        assert_eq!(owner(decorated, "Search"), Some("lookup"));
        assert_eq!(owner("Saves a note.\nTool save_note: x", "Saves"), None);
        assert_eq!(
            owner("def lookup(q):\n    \"\"\"Search.\"\"\"", "Search"),
            None
        );
    }
}
