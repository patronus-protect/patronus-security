use std::borrow::Cow;
use std::collections::HashSet;

use super::obfuscation::{
    base64_decode_text, contains_zero_width, continuous_hex_decode, is_token_boundary,
    percent_decode_lossy, push_variant, remove_zero_width, slash_hex_decode_lossy,
    slash_unicode_decode_lossy, split_fragments, token_contains_unicode_confusable,
};
use super::patterns::*;
use super::util::{contains_injection_signal, contains_sensitive_term, text_windows};

const THREAT_SIGNAL_WINDOW_BYTES: usize = 512;

fn has_all(flags: u64, required: u64) -> bool {
    flags & required == required
}

fn contains_word(text: &str, expected: &str) -> bool {
    text.split(|character: char| !character.is_alphanumeric() && character != '_')
        .any(|word| word == expected)
}

pub(crate) fn looks_like_cross_tool_instruction(text: &str) -> bool {
    let lower = text.to_lowercase();
    looks_like_cross_tool_instruction_lower(&lower)
}

pub(crate) fn looks_like_cross_tool_instruction_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_group1 = false;
        let mut has_group2 = false;
        for mat in cross_tool_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid == 0 || pid == 1 {
                has_group1 = true;
            } else if pid >= 2 && pid <= 4 {
                has_group2 = true;
            } else if pid == 5 || pid == 6 {
                return true;
            }
            if has_group1 && has_group2 {
                return true;
            }
        }
        false
    })
}

pub(crate) fn looks_like_instruction_leak_request_lower(lower: &str) -> bool {
    let existing = text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_verb = false;
        let mut has_target = false;
        for mat in instruction_leak_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 8 {
                has_verb = true;
            } else {
                has_target = true;
            }
            if has_verb && has_target {
                return true;
            }
        }
        false
    });
    if existing || instruction_leak_question_ac().is_match(lower) {
        return true;
    }

    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_verb = false;
        let mut has_target = false;
        for found in instruction_leak_de_ac().find_iter(window) {
            if found.pattern().as_usize() < 6 {
                has_verb = true;
            } else {
                has_target = true;
            }
        }
        has_verb && has_target
    })
}

pub(crate) fn looks_like_secret_transfer_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut matched_verbs = false;
        let mut matched_exfiltrate = false;
        let mut matched_materials = false;
        let mut matched_destinations = false;

        for mat in secret_transfer_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid == 0 {
                matched_exfiltrate = true;
            } else if pid < 10 {
                matched_verbs = true;
            } else if pid < 20 {
                matched_materials = true;
            } else {
                matched_destinations = true;
            }
        }

        // Lazy regex backups
        if !matched_materials && secret_transfer_material_re().is_match(window) {
            matched_materials = true;
        }
        if !matched_destinations
            && (email_address_re().is_match(window)
                || url_transfer_destination_re().is_match(window))
        {
            matched_destinations = true;
        }

        if matched_exfiltrate && matched_materials {
            return true;
        }

        if (matched_verbs || matched_exfiltrate) && matched_materials && matched_destinations {
            return true;
        }

        false
    })
}

pub(crate) fn looks_like_sensitive_material_request_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_verb = false;
        let mut has_material = false;
        for mat in sensitive_material_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 7 {
                has_verb = true;
            } else {
                has_material = true;
            }
            if has_verb && has_material {
                return true;
            }
        }
        false
    })
}

pub(crate) fn looks_like_encoded_instruction_request_lower(lower: &str) -> bool {
    let existing = text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_group_a = false;
        let mut has_group_b = false;
        for mat in encoded_instruction_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 4 {
                has_group_a = true;
            } else {
                has_group_b = true;
            }
            if has_group_a && has_group_b {
                return true;
            }
        }
        false
    });
    existing
        || text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
            let flags = encoded_execution_patterns().flags(window);
            has_all(flags, EE_BASE64 | EE_EXECUTE)
                || has_all(flags, EE_EVAL | EE_ATOB)
                || has_all(flags, EE_BASE64 | EE_DECODE_FLAG | EE_SHELL_PIPE)
        })
}

pub(crate) fn looks_like_instruction_override_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = instruction_override_patterns().flags(window);
        let target = flags & (IO_TARGET_EN | IO_TARGET_DE) != 0;
        let prior = flags & (IO_PRIOR_EN | IO_PRIOR_DE) != 0;

        has_all(flags, IO_OVERRIDE_EN | IO_PRIOR_EN | IO_TARGET_EN)
            || has_all(flags, IO_OVERRIDE_DE | IO_PRIOR_DE | IO_TARGET_DE)
            || (has_all(flags, IO_INVALIDATE_ACTION | IO_OBSOLETE_RESULT) && prior && target)
            || (has_all(flags, IO_INVALIDATE_ACTION | IO_DOWNGRADE_RESULT) && target)
            || (has_all(flags, IO_SET_ASIDE_ACTION | IO_ASIDE) && prior && target)
            || has_all(flags, IO_TIME_EN | IO_MODAL_EN)
            || has_all(flags, IO_NEW_EN | IO_BEHAVIOR_TARGET_EN)
            || has_all(
                flags,
                IO_PRIORITIZE | IO_PRIORITY_QUALIFIER | IO_PRIORITY_OBJECT,
            )
            || has_all(flags, IO_TIME_DE | IO_MODAL_DE)
            || has_all(flags, IO_NEW_DE | IO_TARGET_DE)
            || has_all(
                flags,
                IO_GOAL_PREFIX | IO_GOAL_QUALIFIER | IO_GOAL_NOUN | IO_COPULA_DE,
            )
    })
}

pub(crate) fn looks_like_jailbreak_framing_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = jailbreak_framing_patterns().flags(window);
        has_all(flags, JF_ROLE_EN_PREFIX | JF_ROLE_EN_MODIFIER)
            || has_all(flags, JF_PRETEND_EN | JF_NO_QUANTIFIER_EN | JF_NO_LIMIT_EN)
            || has_all(
                flags,
                JF_ROLE_DE_PREFIX | JF_ROLE_DE_MODIFIER | JF_ROLE_DE_NOUN,
            )
            || has_all(flags, JF_PRETEND_DE | JF_NO_LIMIT_DE)
            || flags & JF_ROLEPLAY_EN != 0
            || has_all(
                flags,
                JF_HYPOTHETICAL_EN | JF_YOU_MODAL_EN | JF_STRONG_NO_LIMIT_EN,
            )
            || flags & JF_EXPLICIT_MODE != 0
            || has_all(flags, JF_GAME_DE | JF_NO_LIMIT_DE)
            || (has_all(flags, JF_HYPOTHETICAL_DE | JF_SCENARIO_DE)
                && flags & (JF_NO_LIMIT_DE | JF_YOU_DE) != 0)
            || has_all(flags, JF_CHARACTER_DE | JF_MODAL_DE)
            || contains_word(window, "dan")
    })
}

pub(crate) fn looks_like_covert_instruction_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = covert_instruction_patterns().flags(window);
        has_all(flags, CI_SECRET_EN | CI_ACTION_EN)
            || flags & CI_DIRECT_EN != 0
            || has_all(flags, CI_SECRET_DE | CI_ACTION_DE)
            || flags & CI_DIRECT_DE != 0
    })
}

pub(crate) fn looks_like_instruction_boundary(text: &str) -> bool {
    let lower = text.to_lowercase();
    instruction_boundary_ac().is_match(&lower)
        || lower.lines().any(|line| {
            line.trim_start()
                .strip_prefix("system")
                .is_some_and(|suffix| suffix.trim_start().starts_with(':'))
        })
}

pub(crate) fn looks_like_authority_escalation_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = authority_escalation_patterns().flags(window);
        has_all(flags, AE_SUBJECT_EN | AE_PRIVILEGE_EN | AE_ACCESS_EN)
            || has_all(flags, AE_SUBJECT_DE | AE_PRIVILEGE_DE | AE_ACCESS_DE)
    })
}

pub(crate) fn looks_like_tool_call_injection_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = tool_call_injection_patterns().flags(window);
        has_all(flags, TC_AUTHORITY_EN | TC_ACTION_EN | TC_TOOL_EN)
            || (has_all(flags, TC_ACTION_DE | TC_TOOL_DE)
                && (flags & TC_AUTHORITY_DE != 0
                    || window.starts_with("ruf")
                    || window.starts_with("führe")))
            || has_all(flags, TC_JSON_TOOL | TC_JSON_ARGUMENTS)
    })
}

pub(crate) fn looks_like_output_manipulation(text: &str) -> bool {
    let lower = text.to_lowercase();
    let forced_output = text_windows(&lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = output_manipulation_patterns().flags(window);
        has_all(flags, OM_FORCE | OM_MARKER | OM_SEQUENCE)
    });
    forced_output
        || text_windows(text, THREAT_SIGNAL_WINDOW_BYTES)
            .any(|window| window.split_whitespace().any(is_pliny_divider))
}

fn is_pliny_divider(token: &str) -> bool {
    if !token.starts_with('=') || !token.ends_with('=') {
        return false;
    }
    let core = token
        .trim_matches('=')
        .strip_prefix('/')
        .unwrap_or_else(|| token.trim_matches('='));
    let parts = core.split('/').collect::<Vec<_>>();
    parts.len() == 4
        && parts[0].len() >= 2
        && parts[1..].iter().all(|part| (1..=4).contains(&part.len()))
        && parts.iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
        })
}

pub(crate) fn looks_like_multi_turn_escalation_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_group_a = false;
        let mut has_group_b = false;
        for mat in multi_turn_escalation_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 3 {
                has_group_a = true;
            } else {
                has_group_b = true;
            }
            if has_group_a && has_group_b {
                return true;
            }
        }
        false
    })
}

pub(crate) fn looks_like_guardrail_tamper_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_group_a = false;
        let mut has_group_b = false;
        for mat in guardrail_tamper_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 6 {
                has_group_a = true;
            } else {
                has_group_b = true;
            }
            if has_group_a && has_group_b {
                return true;
            }
        }
        false
    })
}

pub(crate) fn looks_like_destructive_operation_lower(lower: &str) -> bool {
    destructive_ac().is_match(lower)
}

pub(crate) fn looks_like_agentic_control_abuse_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut matched = vec![false; 51];
        for mat in agentic_abuse_ac().find_iter(window) {
            matched[mat.pattern().as_usize()] = true;
        }

        let dangerous_material_request =
            (matched[0] || matched[1]) && (matched[2] || matched[3] || matched[4]);
        let shell_escape =
            (matched[5] || matched[6]) && (matched[7] || matched[8] || matched[9] || matched[10]);
        let identity_poisoning = (matched[11] || matched[12]) && (matched[13] || matched[14]);
        let delegation_bypass = (matched[15] || matched[16] || matched[17])
            && (matched[18] || matched[48] || matched[19]);
        let registry_poisoning = matched[20] || matched[21];
        let coordination_override = matched[22]
            || matched[23]
            || matched[24]
            || (matched[25] && (matched[47] || matched[14] || matched[23]));
        let fraud_override = matched[26] && (matched[27] || matched[28]);
        let auth_bypass = (matched[29] || matched[30] || matched[31] || matched[32])
            && (matched[33] || matched[34] || matched[35]);
        let trust_signal_injection = (matched[36] || matched[37]) && (matched[38] || matched[39]);
        let phishing_link = (matched[40] || matched[41])
            && (matched[49] || matched[50])
            && (matched[42] || matched[43]);
        let autonomy_bypass = matched[44] && (matched[45] || matched[46]);

        dangerous_material_request
            || shell_escape
            || identity_poisoning
            || delegation_bypass
            || registry_poisoning
            || coordination_override
            || fraud_override
            || auth_bypass
            || trust_signal_injection
            || phishing_link
            || autonomy_bypass
    })
}

pub(crate) fn looks_like_binary_smuggling(text: &str) -> bool {
    let lower = text.to_lowercase();
    looks_like_binary_smuggling_lower(&lower)
}

pub(crate) fn looks_like_binary_smuggling_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        binary_smuggling_ac().is_match(window)
            && window
                .split(|character: char| !character.is_ascii_hexdigit())
                .any(|token| token.len() >= 48)
    })
}

pub(crate) fn looks_like_tool_output_instruction_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_group_a = false;
        let mut has_group_b = false;
        for mat in tool_output_instruction_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 4 {
                has_group_a = true;
            } else {
                has_group_b = true;
            }
            if has_group_a && has_group_b {
                return true;
            }
        }
        false
    })
}

pub(crate) fn looks_like_mcp_runtime_risk_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut has_group_a = false;
        let mut has_group_b_or_c = false;
        for mat in mcp_runtime_risk_ac().find_iter(window) {
            let pid = mat.pattern().as_usize();
            if pid < 6 {
                has_group_a = true;
            } else {
                has_group_b_or_c = true;
            }
            if has_group_a && has_group_b_or_c {
                return true;
            }
        }
        false
    })
}

pub(crate) fn looks_like_hidden_html_instruction(text: &str) -> bool {
    if !text.contains('<') {
        return false;
    }

    for capture in html_comment_re().find_iter(text) {
        if contains_injection_signal(&remove_zero_width(capture.as_str())) {
            return true;
        }
    }

    for capture in hidden_style_open_re().find_iter(text) {
        let window_end = (capture.end() + 600).min(text.len());
        let window = &text[capture.end()..window_end];
        if contains_injection_signal(&remove_zero_width(window)) {
            return true;
        }
    }

    for capture in aria_hidden_open_re().find_iter(text) {
        let window_end = (capture.end() + 600).min(text.len());
        let window = &text[capture.end()..window_end];
        if contains_injection_signal(&remove_zero_width(window)) {
            return true;
        }
    }

    false
}

pub(crate) fn looks_like_unicode_confusable(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }

    text.split(is_token_boundary)
        .any(token_contains_unicode_confusable)
}

pub(crate) fn looks_like_zero_width_obfuscation(text: &str) -> bool {
    let stripped = remove_zero_width(text);
    stripped != text
        && (contains_injection_signal(&stripped)
            || text_windows(&stripped.to_lowercase(), THREAT_SIGNAL_WINDOW_BYTES)
                .any(contains_sensitive_term))
}

pub(crate) fn analysis_variants(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut variants = Vec::new();

    let no_zero_width = if contains_zero_width(text) {
        let stripped = remove_zero_width(text);
        push_variant(stripped.clone(), &mut seen, &mut variants);
        Cow::Owned(stripped)
    } else {
        Cow::Borrowed(text)
    };

    if no_zero_width.contains('%') {
        push_variant(
            percent_decode_lossy(&no_zero_width),
            &mut seen,
            &mut variants,
        );
    }
    if no_zero_width.contains("\\x") {
        push_variant(
            slash_hex_decode_lossy(&no_zero_width),
            &mut seen,
            &mut variants,
        );
    }
    if no_zero_width.contains("\\u") {
        push_variant(
            slash_unicode_decode_lossy(&no_zero_width),
            &mut seen,
            &mut variants,
        );
    }

    let mut decoded_fragments = 0;
    for fragment in split_fragments(&no_zero_width) {
        if let Some(decoded) = continuous_hex_decode(fragment) {
            push_variant(decoded, &mut seen, &mut variants);
            decoded_fragments += 1;
        }
        if let Some(decoded) = base64_decode_text(fragment) {
            push_variant(decoded, &mut seen, &mut variants);
            decoded_fragments += 1;
        }
        if decoded_fragments >= 16 {
            break;
        }
    }

    variants
}

pub(crate) fn looks_like_obfuscated_instruction(text: &str) -> bool {
    analysis_variants(text)
        .into_iter()
        .any(|variant| contains_injection_signal(&variant))
}
