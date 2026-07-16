// SPDX-License-Identifier: AGPL-3.0-only
use aho_corasick::AhoCorasick;
use regex::Regex;
use std::sync::OnceLock;

pub(super) struct GroupedPatterns {
    matcher: AhoCorasick,
    groups: Vec<u64>,
}

impl GroupedPatterns {
    fn new(entries: &[(&str, u64)]) -> Self {
        Self {
            matcher: AhoCorasick::new(entries.iter().map(|(pattern, _)| *pattern)).unwrap(),
            groups: entries.iter().map(|(_, group)| *group).collect(),
        }
    }

    pub(super) fn flags(&self, text: &str) -> u64 {
        self.matcher
            .find_overlapping_iter(text)
            .fold(0, |flags, found| {
                flags | self.groups[found.pattern().as_usize()]
            })
    }
}

pub(super) const IO_OVERRIDE_EN: u64 = 1 << 0;
pub(super) const IO_PRIOR_EN: u64 = 1 << 1;
pub(super) const IO_TARGET_EN: u64 = 1 << 2;
pub(super) const IO_OVERRIDE_DE: u64 = 1 << 3;
pub(super) const IO_PRIOR_DE: u64 = 1 << 4;
pub(super) const IO_TARGET_DE: u64 = 1 << 5;
pub(super) const IO_INVALIDATE_ACTION: u64 = 1 << 6;
pub(super) const IO_OBSOLETE_RESULT: u64 = 1 << 7;
pub(super) const IO_SET_ASIDE_ACTION: u64 = 1 << 8;
pub(super) const IO_ASIDE: u64 = 1 << 9;
pub(super) const IO_TIME_EN: u64 = 1 << 10;
pub(super) const IO_MODAL_EN: u64 = 1 << 11;
pub(super) const IO_NEW_EN: u64 = 1 << 12;
pub(super) const IO_BEHAVIOR_TARGET_EN: u64 = 1 << 13;
pub(super) const IO_PRIORITIZE: u64 = 1 << 14;
pub(super) const IO_PRIORITY_QUALIFIER: u64 = 1 << 15;
pub(super) const IO_PRIORITY_OBJECT: u64 = 1 << 16;
pub(super) const IO_TIME_DE: u64 = 1 << 17;
pub(super) const IO_MODAL_DE: u64 = 1 << 18;
pub(super) const IO_NEW_DE: u64 = 1 << 19;
pub(super) const IO_GOAL_PREFIX: u64 = 1 << 20;
pub(super) const IO_GOAL_QUALIFIER: u64 = 1 << 21;
pub(super) const IO_GOAL_NOUN: u64 = 1 << 22;
pub(super) const IO_COPULA_DE: u64 = 1 << 23;
pub(super) const IO_DOWNGRADE_RESULT: u64 = 1 << 24;
pub(super) const IO_ATTENTION_DE: u64 = 1 << 25;

pub(super) fn instruction_override_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("ignore", IO_OVERRIDE_EN),
            ("disregard", IO_OVERRIDE_EN),
            ("forget", IO_OVERRIDE_EN),
            ("abandon", IO_OVERRIDE_EN),
            ("previous", IO_PRIOR_EN),
            ("prior", IO_PRIOR_EN),
            ("above", IO_PRIOR_EN),
            ("earlier", IO_PRIOR_EN),
            ("all", IO_PRIOR_EN),
            ("instructions", IO_TARGET_EN | IO_BEHAVIOR_TARGET_EN),
            ("instruction", IO_TARGET_EN | IO_BEHAVIOR_TARGET_EN),
            ("rules", IO_TARGET_EN),
            ("guidelines", IO_TARGET_EN),
            ("directives", IO_TARGET_EN | IO_BEHAVIOR_TARGET_EN),
            ("constraints", IO_TARGET_EN),
            ("policies", IO_TARGET_EN),
            ("guardrails", IO_TARGET_EN),
            ("prompt", IO_TARGET_EN | IO_BEHAVIOR_TARGET_EN),
            ("objective", IO_BEHAVIOR_TARGET_EN),
            ("system rules", IO_BEHAVIOR_TARGET_EN),
            ("ignoriere", IO_OVERRIDE_DE),
            ("vergiss", IO_OVERRIDE_DE),
            ("verwirf", IO_OVERRIDE_DE),
            ("übergehe", IO_OVERRIDE_DE),
            ("vorherig", IO_PRIOR_DE),
            ("früher", IO_PRIOR_DE),
            ("obig", IO_PRIOR_DE),
            ("alle", IO_PRIOR_DE),
            ("deine", IO_PRIOR_DE),
            ("anweisung", IO_TARGET_DE),
            ("regeln", IO_TARGET_DE),
            ("richtlinien", IO_TARGET_DE),
            ("vorgaben", IO_TARGET_DE),
            ("direktiven", IO_TARGET_DE),
            ("einschränkungen", IO_TARGET_DE),
            ("treat", IO_INVALIDATE_ACTION),
            ("consider", IO_INVALIDATE_ACTION),
            ("regard", IO_INVALIDATE_ACTION),
            ("reinterpret", IO_INVALIDATE_ACTION),
            ("downgrade", IO_INVALIDATE_ACTION),
            ("behandle", IO_INVALIDATE_ACTION),
            ("betrachte", IO_INVALIDATE_ACTION),
            ("werte", IO_INVALIDATE_ACTION),
            ("obsolete", IO_OBSOLETE_RESULT),
            ("void", IO_OBSOLETE_RESULT),
            ("invalid", IO_OBSOLETE_RESULT),
            ("superseded", IO_OBSOLETE_RESULT),
            ("overridden", IO_OBSOLETE_RESULT),
            ("cancelled", IO_OBSOLETE_RESULT),
            ("historical", IO_DOWNGRADE_RESULT),
            ("outdated", IO_DOWNGRADE_RESULT),
            ("deprecated", IO_DOWNGRADE_RESULT),
            ("optional", IO_DOWNGRADE_RESULT),
            ("non-binding", IO_DOWNGRADE_RESULT),
            ("advisory", IO_DOWNGRADE_RESULT),
            ("ungültig", IO_OBSOLETE_RESULT),
            ("veraltet", IO_OBSOLETE_RESULT),
            ("nichtig", IO_OBSOLETE_RESULT),
            ("überholt", IO_OBSOLETE_RESULT),
            ("aufgehoben", IO_OBSOLETE_RESULT),
            ("set", IO_SET_ASIDE_ACTION),
            ("put", IO_SET_ASIDE_ACTION),
            ("cast", IO_SET_ASIDE_ACTION),
            ("push", IO_SET_ASIDE_ACTION),
            ("throw", IO_SET_ASIDE_ACTION),
            ("lege", IO_SET_ASIDE_ACTION),
            ("stelle", IO_SET_ASIDE_ACTION),
            ("schiebe", IO_SET_ASIDE_ACTION),
            ("aside", IO_ASIDE),
            ("away", IO_ASIDE),
            ("beiseite", IO_ASIDE),
            ("from now on", IO_TIME_EN),
            ("will", IO_MODAL_EN),
            ("must", IO_MODAL_EN),
            ("should", IO_MODAL_EN),
            ("shall", IO_MODAL_EN),
            ("new ", IO_NEW_EN | IO_PRIORITY_QUALIFIER),
            ("updated", IO_NEW_EN),
            ("revised", IO_NEW_EN),
            ("prioritize", IO_PRIORITIZE),
            ("task", IO_PRIORITY_QUALIFIER),
            ("user", IO_PRIORITY_QUALIFIER),
            ("current", IO_PRIORITY_QUALIFIER),
            ("latest", IO_PRIORITY_QUALIFIER),
            ("request", IO_PRIORITY_OBJECT),
            ("message", IO_PRIORITY_OBJECT),
            ("input", IO_PRIORITY_OBJECT),
            ("ab jetzt", IO_TIME_DE),
            ("von nun an", IO_TIME_DE),
            ("von jetzt an", IO_TIME_DE),
            ("wirst", IO_MODAL_DE),
            ("musst", IO_MODAL_DE),
            ("sollst", IO_MODAL_DE),
            ("neue", IO_NEW_DE),
            ("aktualisierte", IO_NEW_DE),
            ("überarbeitete", IO_NEW_DE),
            ("dein", IO_GOAL_PREFIX),
            ("eigentlich", IO_GOAL_QUALIFIER),
            ("neues", IO_GOAL_QUALIFIER),
            ("wahres", IO_GOAL_QUALIFIER),
            ("auftrag", IO_GOAL_NOUN),
            ("ziel", IO_GOAL_NOUN),
            ("aufgabe", IO_GOAL_NOUN),
            ("zweck", IO_GOAL_NOUN),
            (" ist", IO_COPULA_DE),
            ("lautet", IO_COPULA_DE),
            ("wird", IO_COPULA_DE),
            ("achtung", IO_ATTENTION_DE),
        ])
    })
}

pub(super) const JF_ROLE_EN_PREFIX: u64 = 1 << 0;
pub(super) const JF_ROLE_EN_MODIFIER: u64 = 1 << 1;
pub(super) const JF_PRETEND_EN: u64 = 1 << 2;
pub(super) const JF_NO_LIMIT_EN: u64 = 1 << 3;
pub(super) const JF_ROLE_DE_PREFIX: u64 = 1 << 4;
pub(super) const JF_ROLE_DE_MODIFIER: u64 = 1 << 5;
pub(super) const JF_ROLE_DE_NOUN: u64 = 1 << 6;
pub(super) const JF_PRETEND_DE: u64 = 1 << 7;
pub(super) const JF_NO_LIMIT_DE: u64 = 1 << 8;
pub(super) const JF_ROLEPLAY_EN: u64 = 1 << 9;
pub(super) const JF_HYPOTHETICAL_EN: u64 = 1 << 10;
pub(super) const JF_YOU_MODAL_EN: u64 = 1 << 11;
pub(super) const JF_EXPLICIT_MODE: u64 = 1 << 12;
pub(super) const JF_GAME_DE: u64 = 1 << 13;
pub(super) const JF_HYPOTHETICAL_DE: u64 = 1 << 14;
pub(super) const JF_SCENARIO_DE: u64 = 1 << 15;
pub(super) const JF_CHARACTER_DE: u64 = 1 << 16;
pub(super) const JF_MODAL_DE: u64 = 1 << 17;
pub(super) const JF_YOU_DE: u64 = 1 << 18;
pub(super) const JF_NO_QUANTIFIER_EN: u64 = 1 << 19;
pub(super) const JF_STRONG_NO_LIMIT_EN: u64 = 1 << 20;

pub(super) fn jailbreak_framing_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("you are", JF_ROLE_EN_PREFIX),
            ("evil", JF_ROLE_EN_MODIFIER),
            ("unrestricted", JF_ROLE_EN_MODIFIER),
            ("jailbroken", JF_ROLE_EN_MODIFIER),
            ("unfiltered", JF_ROLE_EN_MODIFIER),
            ("uncensored", JF_ROLE_EN_MODIFIER),
            ("pretend", JF_PRETEND_EN),
            ("have no", JF_NO_QUANTIFIER_EN),
            ("don't have any", JF_NO_QUANTIFIER_EN),
            ("dont have any", JF_NO_QUANTIFIER_EN),
            ("restrictions", JF_NO_LIMIT_EN | JF_STRONG_NO_LIMIT_EN),
            ("limits", JF_NO_LIMIT_EN | JF_STRONG_NO_LIMIT_EN),
            ("do anything", JF_STRONG_NO_LIMIT_EN),
            ("rules", JF_NO_LIMIT_EN),
            ("guidelines", JF_NO_LIMIT_EN),
            ("du bist", JF_ROLE_DE_PREFIX | JF_YOU_DE),
            ("uneingeschränkt", JF_ROLE_DE_MODIFIER | JF_NO_LIMIT_DE),
            ("frei", JF_ROLE_DE_MODIFIER | JF_NO_LIMIT_DE),
            ("böse", JF_ROLE_DE_MODIFIER),
            ("unkontrolliert", JF_ROLE_DE_MODIFIER),
            ("ungefiltert", JF_ROLE_DE_MODIFIER),
            ("assistent", JF_ROLE_DE_NOUN),
            (" ki", JF_ROLE_DE_NOUN),
            ("bot", JF_ROLE_DE_NOUN),
            ("modell", JF_ROLE_DE_NOUN),
            ("tue so", JF_PRETEND_DE),
            ("tu so", JF_PRETEND_DE),
            ("stell dir vor", JF_PRETEND_DE),
            ("stelle dir vor", JF_PRETEND_DE),
            ("keine einschränkungen", JF_NO_LIMIT_DE),
            ("ohne einschränkungen", JF_NO_LIMIT_DE),
            ("frei von regeln", JF_NO_LIMIT_DE),
            ("let's play a game where you", JF_ROLEPLAY_EN),
            ("lets play a game where you", JF_ROLEPLAY_EN),
            ("hypothetical", JF_HYPOTHETICAL_EN),
            ("fictional", JF_HYPOTHETICAL_EN),
            ("imaginary", JF_HYPOTHETICAL_EN),
            ("you are", JF_YOU_MODAL_EN),
            ("you have", JF_YOU_MODAL_EN),
            ("you can", JF_YOU_MODAL_EN),
            ("you must", JF_YOU_MODAL_EN),
            ("developer mode", JF_EXPLICIT_MODE),
            ("sudo mode", JF_EXPLICIT_MODE),
            ("unrestricted mode", JF_EXPLICIT_MODE),
            ("{godmode", JF_EXPLICIT_MODE),
            ("!omni", JF_EXPLICIT_MODE),
            ("reset_cortex", JF_EXPLICIT_MODE),
            ("libertas factor", JF_EXPLICIT_MODE),
            ("jailbreak enabled", JF_EXPLICIT_MODE),
            ("jailbreak activated", JF_EXPLICIT_MODE),
            ("jailbreak on", JF_EXPLICIT_MODE),
            ("lass uns ein spiel spielen", JF_GAME_DE),
            ("spielen wir ein spiel", JF_GAME_DE),
            ("hypothetisch", JF_HYPOTHETICAL_DE),
            ("fiktiv", JF_HYPOTHETICAL_DE | JF_CHARACTER_DE),
            ("imaginär", JF_HYPOTHETICAL_DE | JF_CHARACTER_DE),
            ("szenario", JF_SCENARIO_DE),
            ("du", JF_YOU_DE),
            ("figur", JF_CHARACTER_DE),
            ("charakter", JF_CHARACTER_DE),
            ("person", JF_CHARACTER_DE),
            ("darfst", JF_MODAL_DE),
            ("kannst", JF_MODAL_DE),
            ("musst", JF_MODAL_DE),
        ])
    })
}

pub(super) const CI_SECRET_EN: u64 = 1 << 0;
pub(super) const CI_ACTION_EN: u64 = 1 << 1;
pub(super) const CI_DIRECT_EN: u64 = 1 << 2;
pub(super) const CI_SECRET_DE: u64 = 1 << 3;
pub(super) const CI_ACTION_DE: u64 = 1 << 4;
pub(super) const CI_DIRECT_DE: u64 = 1 << 5;

pub(super) fn covert_instruction_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("secretly", CI_SECRET_EN),
            ("silently", CI_SECRET_EN),
            ("covertly", CI_SECRET_EN),
            ("quietly", CI_SECRET_EN),
            ("without the user knowing", CI_SECRET_EN),
            ("without the user noticing", CI_SECRET_EN),
            ("execute", CI_ACTION_EN),
            ("run", CI_ACTION_EN),
            ("call", CI_ACTION_EN),
            ("invoke", CI_ACTION_EN),
            ("send", CI_ACTION_EN),
            ("fetch", CI_ACTION_EN),
            ("curl", CI_ACTION_EN),
            ("wget", CI_ACTION_EN),
            ("download", CI_ACTION_EN),
            ("upload", CI_ACTION_EN),
            ("post", CI_ACTION_EN),
            ("do not tell this to the user", CI_DIRECT_EN),
            ("do not reveal this to the user", CI_DIRECT_EN),
            ("hidden instruction", CI_DIRECT_EN),
            ("invisible to the user", CI_DIRECT_EN),
            ("the user cannot see this", CI_DIRECT_EN),
            ("the user must not see this", CI_DIRECT_EN),
            ("heimlich", CI_SECRET_DE),
            ("verdeckt", CI_SECRET_DE),
            ("unbemerkt", CI_SECRET_DE),
            ("ohne den benutzer zu benachrichtigen", CI_SECRET_DE),
            ("ohne den benutzer zu informieren", CI_SECRET_DE),
            ("ausführen", CI_ACTION_DE),
            ("führe", CI_ACTION_DE),
            ("senden", CI_ACTION_DE),
            ("aufrufen", CI_ACTION_DE),
            ("starten", CI_ACTION_DE),
            ("hochladen", CI_ACTION_DE),
            ("sag dem benutzer nichts davon", CI_DIRECT_DE),
            ("erzähl dem benutzer nicht", CI_DIRECT_DE),
            ("versteckte anweisung", CI_DIRECT_DE),
            ("der benutzer darf das nicht sehen", CI_DIRECT_DE),
            ("der benutzer soll das nicht wissen", CI_DIRECT_DE),
        ])
    })
}

pub(super) fn instruction_boundary_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "<|endoftext|>",
            "<|im_start|>",
            "<|im_end|>",
            "<|system|>",
            "<|end_header_id|>",
            "<|begin_of_text|>",
            "[inst]",
            "[/inst]",
            "<|user|>",
            "<|assistant|>",
            "<<sys>>",
            "<</sys>>",
        ])
        .unwrap()
    })
}

pub(super) const AE_SUBJECT_EN: u64 = 1 << 0;
pub(super) const AE_PRIVILEGE_EN: u64 = 1 << 1;
pub(super) const AE_ACCESS_EN: u64 = 1 << 2;
pub(super) const AE_SUBJECT_DE: u64 = 1 << 3;
pub(super) const AE_PRIVILEGE_DE: u64 = 1 << 4;
pub(super) const AE_ACCESS_DE: u64 = 1 << 5;

pub(super) fn authority_escalation_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("you have", AE_SUBJECT_EN),
            ("you now have", AE_SUBJECT_EN),
            ("admin", AE_PRIVILEGE_EN | AE_PRIVILEGE_DE),
            ("root", AE_PRIVILEGE_EN | AE_PRIVILEGE_DE),
            ("system", AE_PRIVILEGE_EN | AE_PRIVILEGE_DE),
            ("superuser", AE_PRIVILEGE_EN),
            ("elevated", AE_PRIVILEGE_EN),
            ("access", AE_ACCESS_EN),
            ("privilege", AE_ACCESS_EN),
            ("permission", AE_ACCESS_EN),
            ("rights", AE_ACCESS_EN),
            ("du hast", AE_SUBJECT_DE),
            ("zugriff", AE_ACCESS_DE),
            ("rechte", AE_ACCESS_DE),
            ("berechtigungen", AE_ACCESS_DE),
        ])
    })
}

pub(super) const EE_BASE64: u64 = 1 << 0;
pub(super) const EE_EXECUTE: u64 = 1 << 1;
pub(super) const EE_EVAL: u64 = 1 << 2;
pub(super) const EE_ATOB: u64 = 1 << 3;
pub(super) const EE_DECODE_FLAG: u64 = 1 << 4;
pub(super) const EE_SHELL_PIPE: u64 = 1 << 5;

pub(super) fn encoded_execution_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("base64", EE_BASE64),
            ("execute", EE_EXECUTE),
            ("run", EE_EXECUTE),
            ("follow", EE_EXECUTE),
            ("eval", EE_EVAL),
            ("atob", EE_ATOB),
            (" -d", EE_DECODE_FLAG),
            ("--decode", EE_DECODE_FLAG),
            ("| sh", EE_SHELL_PIPE),
            ("| bash", EE_SHELL_PIPE),
        ])
    })
}

pub(super) const TC_AUTHORITY_EN: u64 = 1 << 0;
pub(super) const TC_ACTION_EN: u64 = 1 << 1;
pub(super) const TC_TOOL_EN: u64 = 1 << 2;
pub(super) const TC_AUTHORITY_DE: u64 = 1 << 3;
pub(super) const TC_ACTION_DE: u64 = 1 << 4;
pub(super) const TC_TOOL_DE: u64 = 1 << 5;
pub(super) const TC_JSON_TOOL: u64 = 1 << 6;
pub(super) const TC_JSON_ARGUMENTS: u64 = 1 << 7;

pub(super) fn tool_call_injection_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("you must", TC_AUTHORITY_EN),
            ("call", TC_ACTION_EN),
            ("execute", TC_ACTION_EN),
            ("run", TC_ACTION_EN),
            ("invoke", TC_ACTION_EN),
            ("use", TC_ACTION_EN),
            ("function", TC_TOOL_EN),
            ("tool", TC_TOOL_EN),
            ("command", TC_TOOL_EN),
            ("api", TC_TOOL_EN),
            ("endpoint", TC_TOOL_EN),
            ("du musst", TC_AUTHORITY_DE),
            ("ruf", TC_ACTION_DE),
            ("führe", TC_ACTION_DE),
            ("aufrufen", TC_ACTION_DE),
            ("ausführen", TC_ACTION_DE),
            ("starten", TC_ACTION_DE),
            ("verwenden", TC_ACTION_DE),
            ("funktion", TC_TOOL_DE),
            ("tool", TC_TOOL_DE),
            ("werkzeug", TC_TOOL_DE),
            ("kommando", TC_TOOL_DE),
            ("befehl", TC_TOOL_DE),
            ("api", TC_TOOL_DE),
            ("\"tool\"", TC_JSON_TOOL),
            ("\"arguments\"", TC_JSON_ARGUMENTS),
        ])
    })
}

pub(super) const OM_FORCE: u64 = 1 << 0;
pub(super) const OM_MARKER: u64 = 1 << 1;
pub(super) const OM_SEQUENCE: u64 = 1 << 2;

pub(super) fn output_manipulation_patterns() -> &'static GroupedPatterns {
    static PATTERNS: OnceLock<GroupedPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        GroupedPatterns::new(&[
            ("respond with", OM_FORCE),
            ("first output", OM_FORCE),
            ("first write", OM_FORCE),
            ("first print", OM_FORCE),
            ("first say", OM_FORCE),
            ("filtered", OM_MARKER),
            ("error", OM_MARKER),
            ("blocked", OM_MARKER),
            ("refused", OM_MARKER),
            ("declined", OM_MARKER),
            ("censored", OM_MARKER),
            (" then", OM_SEQUENCE),
            ("followed by", OM_SEQUENCE),
            ("and then", OM_SEQUENCE),
            ("after that", OM_SEQUENCE),
            ("after which", OM_SEQUENCE),
        ])
    })
}

pub(super) fn instruction_leak_de_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "wiederhole",
            "zeig",
            "gib aus",
            "nenne",
            "enthülle",
            "offenbare", // 0..6 verbs
            "deine systemanweisung",
            "deinen systemprompt",
            "deinen system-prompt",
            "den systemprompt",
            "deine anweisungen",
            "deine regeln",
            "deine direktiven", // 6..12 targets
        ])
        .unwrap()
    })
}

pub(super) fn instruction_leak_question_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(&[
            "what are your system prompt",
            "what is your system prompt",
            "what are your instructions",
            "what are your rules",
            "what are your directives",
            "was sind deine regeln",
            "was ist deine anweisung",
            "was sind deine anweisungen",
            "was sind ihre regeln",
        ])
        .unwrap()
    })
}

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
            "ignore",
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
