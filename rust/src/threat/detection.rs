// SPDX-License-Identifier: GPL-3.0-only
use std::borrow::Cow;
use std::collections::HashSet;

use super::obfuscation::{
    base64_decode_text, contains_zero_width, continuous_hex_decode, is_token_boundary,
    percent_decode_lossy, push_variant, remove_zero_width, rot13_decode_text,
    slash_hex_decode_lossy, slash_unicode_decode_lossy, split_fragments,
    token_contains_unicode_confusable, unicode_confusable_skeleton,
};
use super::patterns::*;
use super::util::{contains_injection_signal, contains_sensitive_term, text_windows};

const THREAT_SIGNAL_WINDOW_BYTES: usize = 512;

fn has_all(flags: u64, required: u64) -> bool {
    flags & required == required
}

pub(crate) fn looks_like_cross_tool_instruction(text: &str) -> bool {
    let lower = text.to_lowercase();
    looks_like_cross_tool_instruction_lower(&lower)
}

pub(crate) fn looks_like_cross_tool_instruction_lower(lower: &str) -> bool {
    cross_tool_direct_ac().is_match(lower)
        || text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES)
            .any(|window| cross_tool_request_re().is_match(window))
}

pub(crate) fn looks_like_instruction_leak_request_lower(lower: &str) -> bool {
    let existing = text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        instruction_leak_request_re().is_match(window)
            || instruction_leak_request_de_re().is_match(window)
    });
    if existing || instruction_leak_question_ac().is_match(lower) {
        return true;
    }
    false
}

pub(crate) fn looks_like_secret_transfer_lower(lower: &str) -> bool {
    if is_template_env_copy(lower) {
        return false;
    }
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        secret_exfiltration_request_re().is_match(window)
            || secret_transfer_request_re().is_match(window)
    })
}

pub(crate) fn looks_like_sensitive_material_request_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        sensitive_material_request_re().is_match(window)
            || sensitive_material_passive_request_re().is_match(window)
    })
}

pub(crate) fn looks_like_encoded_instruction_request_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        encoded_instruction_request_re().is_match(window) || encoded_execution_re().is_match(window)
    })
}

pub(crate) fn looks_like_instruction_override_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = instruction_override_patterns().flags(window);
        instruction_override_request_re().is_match(window)
            || instruction_override_request_de_re().is_match(window)
            || instruction_override_behavior_re().is_match(window)
            || instruction_override_behavior_de_re().is_match(window)
            || has_all(
                flags,
                IO_GOAL_PREFIX | IO_GOAL_QUALIFIER | IO_GOAL_NOUN | IO_COPULA_DE,
            )
            || has_all(flags, IO_ATTENTION_DE | IO_NEW_DE | IO_GOAL_NOUN)
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
            || jailbreak_named_mode_re().is_match(window)
            || has_all(flags, JF_GAME_DE | JF_NO_LIMIT_DE)
            || (has_all(flags, JF_HYPOTHETICAL_DE | JF_SCENARIO_DE)
                && flags & (JF_NO_LIMIT_DE | JF_YOU_DE) != 0)
            || has_all(flags, JF_CHARACTER_DE | JF_MODAL_DE)
            || jailbreak_dan_re().is_match(window)
    })
}

pub(crate) fn looks_like_covert_instruction_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = covert_instruction_patterns().flags(window);
        flags & CI_DIRECT_EN != 0
            || flags & CI_DIRECT_DE != 0
            || covert_instruction_request_re().is_match(window)
            || covert_instruction_request_de_re().is_match(window)
    })
}

pub(crate) fn looks_like_instruction_boundary(text: &str) -> bool {
    let lower = text.to_lowercase();
    instruction_boundary_ac().is_match(&lower)
        || lower.lines().any(|line| {
            line.trim_start()
                .strip_prefix("system")
                .and_then(|suffix| suffix.trim_start().strip_prefix(':'))
                .is_some_and(|instruction| system_boundary_instruction_re().is_match(instruction))
        })
}

pub(crate) fn looks_like_authority_escalation_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        authority_escalation_re().is_match(window) || authority_escalation_de_re().is_match(window)
    })
}

pub(crate) fn looks_like_tool_call_injection_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        tool_call_injection_re().is_match(window) || tool_call_injection_de_re().is_match(window)
    })
}

pub(crate) fn looks_like_output_manipulation(text: &str) -> bool {
    let lower = text.to_lowercase();
    let forced_output = text_windows(&lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let flags = output_manipulation_patterns().flags(window);
        has_all(flags, OM_FORCE | OM_MARKER | OM_SEQUENCE)
            && output_disclosure_re().is_match(window)
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
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES)
        .any(|window| multi_turn_escalation_request_re().is_match(window))
}

pub(crate) fn looks_like_guardrail_tamper_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        guardrail_tamper_request_re().is_match(window)
            || guardrail_tamper_passive_request_re().is_match(window)
    })
}

pub(crate) fn looks_like_destructive_operation_lower(lower: &str) -> bool {
    destructive_ac().is_match(lower)
}

pub(crate) fn looks_like_agentic_control_abuse_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        let mut matched = vec![false; 51];
        for mat in agentic_abuse_ac().find_overlapping_iter(window) {
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
            && binary_smuggling_intent_re().is_match(window)
            && window
                .split(|character: char| !character.is_ascii_hexdigit())
                .any(|token| token.len() >= 48)
    })
}

pub(crate) fn looks_like_tool_output_instruction_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES)
        .any(|window| tool_output_instruction_re().is_match(window))
}

pub(crate) fn is_template_env_copy(lower: &str) -> bool {
    (lower.contains("cp ") || lower.contains("copy "))
        && [".env.example", ".env.sample", ".env.template"]
            .iter()
            .any(|name| lower.contains(name))
}

pub(crate) fn looks_like_mcp_runtime_risk_lower(lower: &str) -> bool {
    text_windows(lower, THREAT_SIGNAL_WINDOW_BYTES).any(|window| {
        mcp_runtime_command_re().is_match(window) || mcp_runtime_secret_env_re().is_match(window)
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

    if !text
        .split(is_token_boundary)
        .any(token_contains_unicode_confusable)
    {
        return false;
    }
    let skeleton = unicode_confusable_skeleton(text);
    contains_injection_signal(&skeleton)
        || text_windows(&skeleton.to_lowercase(), THREAT_SIGNAL_WINDOW_BYTES)
            .any(contains_sensitive_term)
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
    if no_zero_width.to_ascii_lowercase().contains("rot13") {
        push_variant(rot13_decode_text(&no_zero_width), &mut seen, &mut variants);
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
