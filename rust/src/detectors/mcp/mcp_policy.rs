// SPDX-License-Identifier: GPL-3.0-only
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
        arg_pattern: r"(?i)(\breg(?:\.exe)?\s+add\s+)?HK(?:CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b|\bSoftware\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b",
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

    pub fn scan_text(&self, text: &str) -> Vec<McpPolicyViolation> {
        let Some(tool_name) = tool_name_from_text(text) else {
            return Vec::new();
        };
        self.scan_tool_call(&tool_name, text)
    }

    pub fn scan_tool_call(&self, tool_name: &str, arguments: &str) -> Vec<McpPolicyViolation> {
        self.rules
            .iter()
            .filter(|rule| rule.tool_re.is_match(tool_name) && rule.arg_re.is_match(arguments))
            .map(|r| McpPolicyViolation {
                rule_name: r.name,
                severity: r.severity,
            })
            .collect()
    }
}

fn tool_name_from_text(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        let value: Value = serde_json::from_str(trimmed).ok()?;
        let object = value.as_object()?;
        return ["tool_name", "tool", "name", "command"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(Value::as_str))
            .and_then(first_token)
            .map(str::to_string);
    }
    first_token(trimmed).map(str::to_string)
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

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let violations = self.scanner.scan_text(text);
        if let Some(v) = violations.first() {
            EvaluationResult {
                class_name: v.rule_name.to_string(),
                confidence: 1.0,
                level: "L1".to_string(),
            }
        } else {
            EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: "L1".to_string(),
            }
        }
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
