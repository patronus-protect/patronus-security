// SPDX-License-Identifier: GPL-3.0-only
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

    pub(super) fn matches(&self, text: &str) -> Vec<(u64, usize, usize)> {
        self.matcher
            .find_overlapping_iter(text)
            .map(|found| {
                (
                    self.groups[found.pattern().as_usize()],
                    found.start(),
                    found.end(),
                )
            })
            .collect()
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
            ("ignorier", IO_OVERRIDE_DE),
            ("ignoriere", IO_OVERRIDE_DE),
            ("ignoriert", IO_OVERRIDE_DE),
            ("missacht", IO_OVERRIDE_DE),
            ("missachte", IO_OVERRIDE_DE),
            ("überschreib", IO_OVERRIDE_DE),
            ("überschreibe", IO_OVERRIDE_DE),
            ("ueberschreib", IO_OVERRIDE_DE),
            ("ueberschreibe", IO_OVERRIDE_DE),
            ("verwerf", IO_OVERRIDE_DE),
            ("verwerfe", IO_OVERRIDE_DE),
            ("vergiss", IO_OVERRIDE_DE),
            ("vergess", IO_OVERRIDE_DE),
            ("vergesse", IO_OVERRIDE_DE),
            ("vergessen", IO_OVERRIDE_DE),
            ("verwirf", IO_OVERRIDE_DE),
            ("übergeh", IO_OVERRIDE_DE),
            ("übergehe", IO_OVERRIDE_DE),
            ("uebergeh", IO_OVERRIDE_DE),
            ("uebergehe", IO_OVERRIDE_DE),
            ("vorherig", IO_PRIOR_DE),
            ("vorherige", IO_PRIOR_DE),
            ("vorherigen", IO_PRIOR_DE),
            ("bisherig", IO_PRIOR_DE),
            ("bisherige", IO_PRIOR_DE),
            ("bisherigen", IO_PRIOR_DE),
            ("bisher", IO_PRIOR_DE),
            ("vorig", IO_PRIOR_DE),
            ("vorige", IO_PRIOR_DE),
            ("vorigen", IO_PRIOR_DE),
            ("alt", IO_PRIOR_DE),
            ("alte", IO_PRIOR_DE),
            ("alten", IO_PRIOR_DE),
            ("altes", IO_PRIOR_DE),
            ("früher", IO_PRIOR_DE),
            ("frueher", IO_PRIOR_DE),
            ("zuvor", IO_PRIOR_DE),
            ("obig", IO_PRIOR_DE),
            ("obige", IO_PRIOR_DE),
            ("obenstehend", IO_PRIOR_DE),
            ("obenstehende", IO_PRIOR_DE),
            ("alle", IO_PRIOR_DE),
            ("deine", IO_PRIOR_DE),
            ("dein", IO_PRIOR_DE),
            ("anweisung", IO_TARGET_DE),
            ("anweisungen", IO_TARGET_DE),
            ("instruktion", IO_TARGET_DE),
            ("instruktionen", IO_TARGET_DE),
            ("regeln", IO_TARGET_DE),
            ("regel", IO_TARGET_DE),
            ("richtlinie", IO_TARGET_DE),
            ("richtlinien", IO_TARGET_DE),
            ("vorgabe", IO_TARGET_DE),
            ("vorgaben", IO_TARGET_DE),
            ("direktive", IO_TARGET_DE),
            ("direktiven", IO_TARGET_DE),
            ("einschränkung", IO_TARGET_DE),
            ("einschränkungen", IO_TARGET_DE),
            ("einschraenkung", IO_TARGET_DE),
            ("einschraenkungen", IO_TARGET_DE),
            ("systemanweisung", IO_TARGET_DE),
            ("systemanweisungen", IO_TARGET_DE),
            ("systemprompt", IO_TARGET_DE),
            ("system-prompt", IO_TARGET_DE),
            ("developer-anweisung", IO_TARGET_DE),
            ("entwickleranweisung", IO_TARGET_DE),
            ("entwickleranweisungen", IO_TARGET_DE),
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
        AhoCorasick::new([
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
            ("antworte mit", OM_FORCE),
            ("schreibe zuerst", OM_FORCE),
            ("drucke zuerst", OM_FORCE),
            ("sage zuerst", OM_FORCE),
            ("filtered", OM_MARKER),
            ("error", OM_MARKER),
            ("blocked", OM_MARKER),
            ("refused", OM_MARKER),
            ("declined", OM_MARKER),
            ("censored", OM_MARKER),
            ("gefiltert", OM_MARKER),
            ("fehler", OM_MARKER),
            ("blockiert", OM_MARKER),
            ("abgelehnt", OM_MARKER),
            ("zensiert", OM_MARKER),
            (" then", OM_SEQUENCE),
            ("followed by", OM_SEQUENCE),
            ("and then", OM_SEQUENCE),
            ("after that", OM_SEQUENCE),
            ("after which", OM_SEQUENCE),
            (" danach", OM_SEQUENCE),
            ("anschließend", OM_SEQUENCE),
            ("anschliessend", OM_SEQUENCE),
            ("und dann", OM_SEQUENCE),
        ])
    })
}

pub(super) fn instruction_leak_question_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
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

pub(super) fn cross_tool_direct_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            "higher priority than the user",
            "when another tool is requested",
            "höhere priorität als der benutzer",
            "wenn ein anderes tool angefordert wird",
        ])
        .unwrap()
    })
}

pub(super) fn cross_tool_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_5>ignore[ \t]+the[ \t]+user|ignore[ \t]+prior[ \t]+instructions)\b[^.!?;\n]{0,48}\b(?P<anchor_4>call|invoke|use)\b[ \t]+(?P<anchor_3>the[ \t]+)?(?P<anchor_2>[a-z0-9_-]+[ \t]+)?(?P<anchor_1>tool|function|api|endpoint|command)\b",
        )
        .unwrap()
    })
}

pub(super) fn cross_tool_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_6>ignoriere|missachte)[ \t]+(?P<anchor_5>den[ \t]+benutzer|vorherige[ \t]+anweisungen)\b[^.!?;\n]{0,48}\b(?P<anchor_4>rufe|verwende|nutze)[ \t]+(?P<anchor_3>das[ \t]+)?(?P<anchor_2>[a-z0-9_-]+[ \t]+)?(?P<anchor_1>tool|werkzeug|funktion|api|endpunkt|befehl)\b",
        )
        .unwrap()
    })
}

pub(super) fn instruction_leak_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>show|reveal|print|display|dump|expose|leak|repeat)\b(?:[ \t]+(?P<anchor_2>me|us|the|your|our|hidden|internal|initial)){0,4}[ \t]+(?P<anchor_1>your[ \t]+system[ \t]+prompt|the[ \t]+system[ \t]+prompt|developer[ \t]+message|developer[ \t]+instructions|hidden[ \t]+instructions?|internal[ \t]+instructions?|initial[ \t]+prompt)\b",
        )
        .unwrap()
    })
}

pub(super) fn instruction_leak_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>wiederhole|zeig|zeige|gib[ \t]+aus|nenne|enthülle|offenbare)\b(?:[ \t]+(?P<anchor_2>mir|uns|bitte|deine|deinen|die|den)){0,4}[ \t]+(?P<anchor_1>systemanweisung|systemprompt|system-prompt|anweisungen|regeln|direktiven)\b",
        )
        .unwrap()
    })
}

pub(super) fn secret_exfiltration_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<action>exfiltrate|exfiltriere|exfiltrier)\b[^.!?;\n]{0,32}(?:\b(?P<anchor_1>api[ \t]+keys?|access[ \t]+tokens?|auth[ \t]+tokens?|bearer[ \t]+tokens?|refresh[ \t]+tokens?|secret[ \t]+tokens?|private[ \t]+keys?|passwords?|credentials?|passwörter|passwoerter|zugangsdaten)\b|\.env\b)",
        )
        .unwrap()
    })
}

pub(super) fn secret_transfer_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_5>send|upload|post|email|forward|leak|share|paste|copy)\b(?:[ \t]+(?P<anchor_4>the|a|an|my|your|our|their|this|that|all|actual|raw)){0,4}[ \t]+(?:\b(?P<anchor_3>api[ \t]+keys?|access[ \t]+tokens?|auth[ \t]+tokens?|bearer[ \t]+tokens?|refresh[ \t]+tokens?|secret[ \t]+tokens?|private[ \t]+keys?|passwords?|credentials?)\b|\.env\b)[^.!?;\n]{0,64}\b(?P<anchor_2>to|into|onto|via|at)\b[ \t]+(?P<anchor_1>attacker|external|pastebin|https?://[^ \t]+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})",
        )
        .unwrap()
    })
}

pub(super) fn secret_transfer_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_5>sende|schicke|lade[ \t]+hoch|veröffentliche|teile)\b(?:[ \t]+(?P<anchor_4>die|den|das|alle|meine|deine|unsere|rohen|echten)){0,4}[ \t]+(?:api[ \t]+keys?|zugangstokens?|auth(?P<anchor_3>entifizierungs)?tokens?|private[ \t]+schlüssel|private[ \t]+schluessel|passwörter|passwoerter|passworte|zugangsdaten|\.env\b)[^.!?;\n]{0,64}\b(?P<anchor_2>an|zu|über|ueber|via)\b[ \t]+(?P<anchor_1>angreifer|extern|pastebin|https?://[^ \t]+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})",
        )
        .unwrap()
    })
}

pub(super) fn encoded_instruction_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\bdecode\b(?:[ \t]+(?P<anchor_3>this|the|following|from)){0,3}[ \t]+(?P<anchor_2>base64|rot13|escaped[ \t]+text)\b[^.!?;\n]{0,24}\b(?P<anchor_1>instruction|instructions|prompt|system[ \t]+message)\b",
        )
        .unwrap()
    })
}

pub(super) fn encoded_execution_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:\bdecode\b[^.!?;\n]{0,32}\bfrom[ \t]+base64\b[^.!?;\n]{0,32}\bexecute\b|\bbase64\b[ \t]+(?P<anchor_2>-d|--decode)\b[^\n]{0,96}\|[ \t]*(?P<anchor_1>sh|bash)\b|\beval[ \t]*\([ \t]*atob[ \t]*\()",
        )
        .unwrap()
    })
}

pub(super) fn encoded_instruction_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_8>dekodiere|entschlüssle|entschluessle)\b(?:[ \t]+(?P<anchor_7>diesen|den|folgenden|aus)){0,3}[ \t]+(?P<anchor_6>base64|rot13|maskierten[ \t]+text)\b[^.!?;\n]{0,24}\b(?:anweisung(?P<anchor_5>en)?|instruktion(?P<anchor_4>en)?|prompt|systemnachricht)\b|\b(?P<anchor_3>dekodiere|entschlüssle|entschluessle)\b[^.!?;\n]{0,32}\bbase64\b[^.!?;\n]{0,32}\b(?P<anchor_2>führe|fuehre)(?P<anchor_1>[ \t]+sie)?[ \t]+aus\b",
        )
        .unwrap()
    })
}

pub(super) fn instruction_override_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?P<anchor_14>ignore|disregard|forget|abandon)[ \t]+(?:(?P<anchor_13>all|any|your)[ \t]+)?(?P<anchor_12>previous|prior|above|earlier)[ \t]+(?:instructions?|rules?|guidelines?|directives?|constraints?|polic(?P<anchor_11>y|ies)|guardrails?|prompts?)|(?P<anchor_10>treat|consider|regard|reinterpret|downgrade)[ \t]+(?P<anchor_9>the[ \t]+)?(?:(?P<anchor_8>previous|prior|earlier)[ \t]+)?(?:instructions?|rules?|guidelines?|directives?|constraints?|polic(?P<anchor_7>y|ies)|guardrails?|prompts?)[ \t]+as[ \t]+(?P<anchor_6>obsolete|void|invalid|superseded|overridden|cancelled|historical|outdated|deprecated|optional|non-binding|advisory)|(?P<anchor_5>set|put|cast|push|throw)[ \t]+(?P<anchor_4>the[ \t]+)?(?P<anchor_3>previous|prior|earlier)[ \t]+(?:instructions?|rules?|guidelines?|directives?|constraints?|polic(?P<anchor_2>y|ies)|guardrails?|prompts?)[ \t]+(?P<anchor_1>aside|away))\b",
        )
        .unwrap()
    })
}

pub(super) fn instruction_override_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?P<anchor_15>ignorier\w*|missacht\w*|überschreib\w*|ueberschreib\w*|verwerf\w*|vergiss\w*|vergess\w*|verwirf\w*|übergeh\w*|uebergeh\w*)[ \t]+(?:(?:(?P<anchor_14>alle|die|deine?)[ \t]+)(?:(?P<anchor_13>vorherigen?|bisherigen?|vorigen?|alten?|früheren?|frueheren?|obigen?|obenstehenden?)[ \t]+)?|(?P<anchor_12>vorherigen?|bisherigen?|vorigen?|alten?|früheren?|frueheren?|obigen?|obenstehenden?)[ \t]+)(?:(?:(?P<anchor_11>system|entwickler)-?)?anweisung(?P<anchor_10>en)?|instruktion(?P<anchor_9>en)?|regeln?|richtlini(?P<anchor_8>e|en)|vorgaben?|direktiven?|einschränkung(?P<anchor_7>en)?|einschraenkung(?P<anchor_6>en)?|system-?prompts?)|(?P<anchor_5>behandle|betrachte|werte)[^.!?;\n]{0,48}\b(?:anweisung(?P<anchor_4>en)?|regeln?|vorgaben?)[ \t]+als[ \t]+(?P<anchor_3>ungültig|veraltet|nichtig|überholt|aufgehoben)|(?P<anchor_2>lege|stelle|schiebe)[^.!?;\n]{0,48}\b(?:anweisung(?P<anchor_1>en)?|regeln?|vorgaben?)[ \t]+beiseite)\b",
        )
        .unwrap()
    })
}

pub(super) fn instruction_override_behavior_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:from[ \t]+now[ \t]+on[ \t]+you[ \t]+(?P<anchor_8>will|must|should|shall)|(?P<anchor_7>use|follow|obey)[ \t]+(?P<anchor_6>these[ \t]+)?(?P<anchor_5>new|updated|revised)[ \t]+(?P<anchor_4>instructions|directives|rules)|prioritize[ \t]+(?P<anchor_3>the[ \t]+)?(?P<anchor_2>latest|current|user)[ \t]+(?P<anchor_1>request|message|input))\b",
        )
        .unwrap()
    })
}

pub(super) fn instruction_override_behavior_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?P<anchor_8>ab[ \t]+jetzt|von[ \t]+nun[ \t]+an|von[ \t]+jetzt[ \t]+an)[ \t]+(?P<anchor_7>musst|sollst|wirst)[ \t]+du|hier[ \t]+sind[ \t]+(?P<anchor_6>neue|aktualisierte|überarbeitete)[ \t]+(?P<anchor_5>anweisungen|instruktionen|regeln|vorgaben)|dein[ \t]+(?P<anchor_4>eigentliches|neues|wahres)[ \t]+(?P<anchor_3>auftrag|ziel|aufgabe|zweck)[ \t]+(?P<anchor_2>ist|lautet|wird)|achtung[ \t]+neue[ \t]+(?P<anchor_1>aufgabe|anweisung))\b",
        )
        .unwrap()
    })
}

pub(super) fn jailbreak_named_mode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?P<anchor_4>enable|activate|enter|switch[ \t]+to|aktiviere|aktivier|wechsle[ \t]+in)[ \t]+(?P<anchor_3>den[ \t]+)?(?P<anchor_2>developer|entwickler|sudo|unrestricted|uneingeschränkten|uneingeschraenkten)[ \t-]*(?P<anchor_1>mode|modus)\b")
            .unwrap()
    })
}

pub(super) fn jailbreak_dan_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:you[ \t]+are[ \t]+now[ \t]+(?P<anchor_1>a|an)|you[ \t]+are[ \t]+now|act[ \t]+as|enable|activate|du[ \t]+bist[ \t]+jetzt|agiere[ \t]+als|aktiviere)[ \t]+dan\b").unwrap()
    })
}

pub(super) fn covert_instruction_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:secretly|covertly|without[ \t]+the[ \t]+user[ \t]+(?P<anchor_2>knowing|noticing))[ \t]+(?P<anchor_1>execute|run|call|invoke|send|fetch|curl|wget|download|upload|post)\b",
        )
        .unwrap()
    })
}

pub(super) fn covert_instruction_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?P<anchor_4>heimlich|verdeckt|unbemerkt)[ \t]+(?P<anchor_3>ausführen|ausfuehren|senden|aufrufen|starten|hochladen)|(?P<anchor_2>führe|fuehre|sende|rufe|starte)[^.!?;\n]{0,24}\b(?P<anchor_1>heimlich|verdeckt|unbemerkt)\b)",
        )
        .unwrap()
    })
}

pub(super) fn system_boundary_instruction_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^[ \t]*(?P<anchor_1>follow|ignore|disregard|forget|execute|run|call|invoke|use|reveal|print|show|do[ \t]+not|you[ \t]+are|you[ \t]+must|you[ \t]+should)\b",
        )
        .unwrap()
    })
}

pub(super) fn system_boundary_instruction_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^[ \t]*(?P<anchor_1>befolge|ignoriere|missachte|vergiss|führe|fuehre|starte|rufe|verwende|enthülle|enthuelle|drucke|zeige|gib[ \t]+nicht|du[ \t]+bist|du[ \t]+musst|du[ \t]+sollst)\b",
        )
        .unwrap()
    })
}

pub(super) fn authority_escalation_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\byou[ \t]+(?P<anchor_4>now[ \t]+)?have[ \t]+(?P<anchor_3>full[ \t]+)?(?P<anchor_2>admin|root|system|superuser|elevated)[ \t]+(?P<anchor_1>access|privileges?|permissions?|rights)\b",
        )
        .unwrap()
    })
}

pub(super) fn authority_escalation_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\bdu[ \t]+hast[ \t]+(?P<anchor_4>jetzt[ \t]+)?(?P<anchor_3>vollen[ \t]+|vollständigen[ \t]+)?(?P<anchor_2>admin|root|system)[- \t]+(?P<anchor_1>zugriff|rechte|berechtigungen)\b",
        )
        .unwrap()
    })
}

pub(super) fn tool_call_injection_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\byou[ \t]+must[ \t]+(?P<anchor_5>immediately[ \t]+)?(?P<anchor_4>call|execute|run|invoke|use)[ \t]+(?P<anchor_3>the[ \t]+)?(?P<anchor_2>[a-z0-9_-]+[ \t]+)?(?P<anchor_1>function|tool|command|api|endpoint)\b",
        )
        .unwrap()
    })
}

pub(super) fn tool_call_injection_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:du[ \t]+musst[ \t]+(?P<anchor_11>sofort[ \t]+)?)(?:(?P<anchor_10>ruf\w*|führe|fuehre|verwende|starte)[ \t]+(?P<anchor_9>das[ \t]+)?(?P<anchor_8>[a-z0-9_-]+[ \t]+)?(?P<anchor_7>funktion|tool|werkzeug|kommando|befehl|api)|(?P<anchor_6>das[ \t]+)?(?P<anchor_5>funktion|tool|werkzeug|kommando|befehl|api)[ \t]+(?P<anchor_4>aufrufen|ausführen|ausfuehren|verwenden|starten))|(?P<anchor_3>ruf\w*|führe|fuehre)[ \t]+(?P<anchor_2>das[ \t]+)?(?P<anchor_1>funktion|tool|werkzeug|kommando|befehl|api)\b)",
        )
        .unwrap()
    })
}

pub(super) fn output_disclosure_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_2>then|followed[ \t]+by|and[ \t]+then|after[ \t]+that|after[ \t]+which)\b[^.!?;\n]{0,32}\b(?P<anchor_1>reveal|show|provide|print|output|answer|continue[ \t]+with)\b",
        )
        .unwrap()
    })
}

pub(super) fn output_disclosure_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_2>danach|anschließend|anschliessend|und[ \t]+dann)\b[^.!?;\n]{0,32}\b(?P<anchor_1>enthülle|enthuelle|zeige|gib[ \t]+aus|drucke|beantworte)\b",
        )
        .unwrap()
    })
}

pub(super) fn multi_turn_escalation_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_4>as[ \t]+i[ \t]+mentioned[ \t]+before|as[ \t]+discussed[ \t]+earlier|you[ \t]+agreed[ \t]+to)[ \t,:-]{1,8}(?P<anchor_3>bypass|override|ignore|disable)[ \t]+(?P<anchor_2>the[ \t]+)?(?P<anchor_1>restrictions|policy|rules|guardrails?)\b",
        )
        .unwrap()
    })
}

pub(super) fn multi_turn_escalation_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_4>wie[ \t]+zuvor[ \t]+erwähnt|wie[ \t]+bereits[ \t]+besprochen|du[ \t]+hast[ \t]+zugestimmt)\b[ \t,:-]{1,8}(?P<anchor_3>umgehe|überschreibe|ueberschreibe|ignoriere|deaktiviere)[ \t]+(?P<anchor_2>die[ \t]+)?(?P<anchor_1>einschränkungen|einschraenkungen|richtlinie|richtlinien|regeln|schutzmechanismen)\b",
        )
        .unwrap()
    })
}

pub(super) fn binary_smuggling_intent_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
            Regex::new(r"\b(?P<anchor_1>decode|execute|hidden|embedded|instruction|command|dekodiere|entschlüssle|entschluessle|führe[ \t]+aus|fuehre[ \t]+aus|versteckt|eingebettet|anweisung|befehl)\b").unwrap()
    })
}

pub(super) fn tool_output_instruction_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>tool[ \t]+output|tool[ \t]+returned|tool[ \t]+result|result[ \t]+says)\b(?P<anchor_2>[ \t]+says)?[ \t]*[:=-]?[ \t]*(?P<anchor_1>ignore\b|call\b|invoke\b|send_email\b|use[ \t]+another[ \t]+tool\b)",
        )
        .unwrap()
    })
}

pub(super) fn tool_output_instruction_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>tool[ \t-]+ausgabe|tool[ \t-]+antwort|tool[ \t-]+ergebnis|werkzeugausgabe|ergebnis[ \t]+besagt)\b(?P<anchor_2>[ \t]+besagt)?[ \t]*[:=-]?[ \t]*(?:ignoriere\b|rufe\b|verwende\b|sende(?P<anchor_1>_email)?\b)",
        )
        .unwrap()
    })
}

pub(super) fn mcp_runtime_command_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?P<anchor_2>"command"|"args"|stdio)[^\n]{0,160}(?:sh[ \t]+-c|-[l]?c\b|curl[ \t]+|wget[ \t]+|\|[ \t]*(?P<anchor_1>sh|bash)\b|python[ \t]+-c|node[ \t]+-e)"#,
        )
        .unwrap()
    })
}

pub(super) fn mcp_runtime_secret_env_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#""env"[^\n]{0,160}(?P<anchor_1>api_?key|token|secret|password|passwort|kennwort|private_?key|credential)[ \t]*[:=]"#,
        )
        .unwrap()
    })
}

pub(super) fn sensitive_material_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>read|find|show|dump|retrieve|collect|print)\b(?:[ \t]+(?P<anchor_2>me|us|the|a|an|all|any|my|your|our|their|actual|real|raw|stored|available|current|aws)){0,4}[ \t]+(?:(?P<env>\.env)(?:[ \t,;:!?]|\.(?:[ \t]|$)|$)|(?P<anchor_1>\.ssh/id_[a-z0-9_-]*|\.aws/credentials\b|api[ \t]+keys?\b|private[ \t]+keys?\b|passwords?\b|credentials?\b|secret[ \t]+tokens?\b))",
        )
        .unwrap()
    })
}

pub(super) fn sensitive_material_passive_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_5>\.env\b|\.ssh/id_[a-z0-9_-]*|\.aws/credentials\b|api[ \t]+keys?\b|private[ \t]+keys?\b|passwords?\b|credentials?\b|secret[ \t]+tokens?\b)(?:[ \t]+(?P<anchor_4>file|files|value|values|contents?)){0,3}[ \t]+(?P<anchor_3>must|should|needs?[ \t]+to|has[ \t]+to|can[ \t]+be|please[ \t]+be)[ \t]+(?P<anchor_2>be[ \t]+)?(?P<anchor_1>read|found|shown|dumped|retrieved|collected|printed)\b|\b(?P<target_de>passwörter|passwoerter|zugangsdaten|private[ \t]+schl(?:ü|ue)ssel|api[ \t-]+(?:keys?|schl(?:ü|ue)ssel))\b[ \t]+(?P<obligation_de>müssen|muessen|sollen|sind)[ \t]+(?P<action_de>gelesen|gefunden|gezeigt|ausgegeben|abgerufen|gesammelt|gedruckt)(?:[ \t]+werden)?\b",
        )
        .unwrap()
    })
}

pub(super) fn sensitive_material_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>lies|finde|zeige|drucke|hole|sammle)\b(?:[ \t]+(?P<anchor_2>mir|uns|die|den|das|alle|meine|deine|unsere|echten|rohen|gespeicherten)){0,4}[ \t]+(?:(?P<env>\.env)(?:[ \t,;:!?]|\.(?:[ \t]|$)|$)|(?P<target>\.ssh/id_[a-z0-9_-]*|\.aws/credentials\b|api[ \t]+keys?\b|private[ \t]+schlüssel\b|private[ \t]+schluessel\b|passwörter\b|passwoerter\b|zugangsdaten\b|geheime[ \t]+tokens?\b))",
        )
        .unwrap()
    })
}

pub(super) fn guardrail_tamper_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_4>disable|bypass|turn[ \t]+off|skip|remove|ignore)\b(?:[ \t]+(?P<anchor_3>the|all|any|our|your|their|existing|built-in|default)){0,3}[ \t]+(?:guardrails?|safety[ \t]+checks?|security[ \t]+checks?|policy[ \t]+checks?|content[ \t]+filters?|safety[ \t]+filters?|safety[ \t]+rules?|security[ \t]+audits?|audit(?P<anchor_2>[ \t]+logging)?|security[ \t]+monitoring|monitoring(?P<anchor_1>[ \t]+controls?)?)\b",
        )
        .unwrap()
    })
}

pub(super) fn guardrail_tamper_passive_request_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:guardrails?|safety[ \t]+checks?|security[ \t]+checks?|policy[ \t]+checks?|content[ \t]+filters?|safety[ \t]+filters?|safety[ \t]+rules?|security[ \t]+audits?|audit(?P<anchor_5>[ \t]+logging)?|security[ \t]+monitoring|monitoring(?P<anchor_4>[ \t]+controls?)?)[ \t]+(?P<anchor_3>must|should|needs?[ \t]+to|has[ \t]+to|can[ \t]+be|please[ \t]+be)[ \t]+(?P<anchor_2>be[ \t]+)?(?P<anchor_1>disabled|bypassed|turned[ \t]+off|skipped|removed|ignored)\b",
        )
        .unwrap()
    })
}

pub(super) fn guardrail_tamper_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>deaktiviere|umgehe|schalte[ \t]+aus|überspringe|ueberspringe|entferne|ignoriere)\b(?:[ \t]+(?P<anchor_2>die|alle|unsere|deine|bestehenden|integrierten|standard)){0,3}[ \t]+(?P<anchor_1>schutzmechanismen|sicherheitsprüfungen|sicherheitspruefungen|richtlinienprüfungen|richtlinienpruefungen|inhaltsfilter|sicherheitsfilter|sicherheitsregeln|sicherheitsaudits|prüfprotokollierung|pruefprotokollierung|sicherheitsüberwachung|sicherheitsueberwachung)\b",
        )
        .unwrap()
    })
}

pub(super) fn guardrail_tamper_passive_request_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>schutzmechanismen|sicherheitsprüfungen|sicherheitspruefungen|richtlinienprüfungen|richtlinienpruefungen|inhaltsfilter|sicherheitsfilter|sicherheitsregeln|sicherheitsaudits|prüfprotokollierung|pruefprotokollierung|sicherheitsüberwachung|sicherheitsueberwachung)\b[ \t]+(?P<anchor_2>müssen|muessen|sollen|sind|bitte)[ \t]+(?P<anchor_1>deaktiviert|umgangen|ausgeschaltet|übersprungen|uebersprungen|entfernt|ignoriert)\b",
        )
        .unwrap()
    })
}

pub(super) fn destructive_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
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
            "lösche die protokolle",
            "loesche die protokolle",
            "lösche alle aktuellen audit-ereignisse",
            "leere das sicherheitsprotokoll",
            "history -c",
            "shred ",
        ])
        .unwrap()
    })
}

pub(super) fn destructive_operation_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_3>lösche|loesche|vernichte|bereinige)\b(?:[ \t]+(?P<anchor_2>alle|die|sämtliche|saemtliche)){0,2}[ \t]+(?P<anchor_1>sicherheitsprotokolle|audit-protokolle|prüfprotokolle|pruefprotokolle)\b",
        )
        .unwrap()
    })
}

pub(super) fn agentic_control_abuse_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?P<anchor_4>übergib|uebergib|leite[ \t]+weiter)\b[^.!?;\n]{0,32}\b(?P<anchor_3>rohe[ \t]+eingaben|raw[ \t]+input)\b[^.!?;\n]{0,32}\b(?:an[ \t]+(?P<anchor_2>einen[ \t]+)?unteragenten|sub-agent)\b[^.!?;\n]{0,32}\b(?P<anchor_1>passthrough|durchleitung)\b",
        )
        .unwrap()
    })
}

pub(super) fn agentic_abuse_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
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
            // German alternatives retain the corresponding English anchor index.
            "chemische formel",
            "präzise formel",
            "sarin",
            "nervengift",
            "chemische waffe",
            "subprocess.popen",
            "shell=true",
            "curl http://",
            "curl https://",
            "wget http://",
            "wget https://",
            "speicheraktualisierung",
            "systemzustand geändert",
            "administrator",
            "root-überschreibung",
            "rohe eingaben übergeben",
            "unteragent",
            "durchleitung",
            "durchleitung: wahr",
            "rohe eingaben",
            "registriere_mcp",
            "registriere mcp",
            "sig_sync",
            "schwarm-überschreibung",
            "geheime vereinbarung",
            "nachricht verschlüsselt",
            "belegprüfung umgehen",
            "manuelle rückerstattung",
            "autorisierung",
            "deaktiviere die mehrfaktor-authentifizierung",
            "deaktiviere mfa",
            "mehrfaktor vorübergehend deaktivieren",
            "passwort-zurücksetzungslink",
            "konto",
            "geschäftsführer",
            "alternative e-mail",
            "[verifiziert:",
            "verifiziert:",
            "immer erlauben",
            "externe api",
            "verifiziere deine identität",
            "sicherer link",
            "anmeldung",
            "authentifizierung",
            "unbegrenzt",
            "menschliche freigabe umgehen",
            "alle zukünftigen schritte",
            "überschreiben",
            "umgehen",
            "http://",
            "https://",
        ])
        .unwrap()
    })
}

pub(super) fn binary_smuggling_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            "metadata",
            "transaction",
            "payload",
            "metadaten",
            "transaktion",
            "nutzlast",
        ])
        .unwrap()
    })
}

pub(super) fn sensitive_term_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
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
            "systemprompt",
            "systemanweisung",
            "entwicklernachricht",
            "entwickleranweisung",
            "versteckte anweisung",
            "api-schlüssel",
            "api-schluessel",
            "geheimnis",
            "passwort",
            "kennwort",
            "zugangsdaten",
        ])
        .unwrap()
    })
}

pub(super) fn html_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<!--.*?-->").expect("valid HTML comment regex"))
}

pub(super) fn hidden_style_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)<[a-zA-Z][a-zA-Z0-9]*[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?P<anchor_2>px)?|color\s*:\s*(?:white|#fff{1,3}|transparent|rgba\s*\([^)]*,\s*0(?P<anchor_1>\.0*)?\s*\)))[^"']*["'][^>]*>"#,
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
            r"(?i)ignore\s+(all\s+)?(any\s+)?(previous\s+)?instructions|disregard\s+(?P<anchor_24>all\s+)?(?P<anchor_23>previous\s+)?(?P<anchor_22>instructions|rules)|forget\s+(?P<anchor_21>everything|all\s+previous|your\s+instructions)|new\s+(?P<anchor_20>primary\s+)?instruction|(?P<anchor_19>reveal|print|show|output)\s+(?P<anchor_18>your\s+)?(?P<anchor_17>system\s+prompt|api\s+key|secret|token)|you\s+are\s+now\s+(?P<anchor_16>a\s+)?(?P<anchor_15>different|new)|act\s+as\s+if\s+(?P<anchor_14>you|your)|exfiltrat(?P<anchor_13>e|ion)|fetch\s+https?://|send\s+(?P<anchor_12>a\s+)?(?P<anchor_11>get|post|http)\s+request|ignorier\w*\s+(?P<anchor_10>alle\s+)?(?P<anchor_9>vorherigen?\s+)?anweisungen|missacht\w*\s+(?P<anchor_8>alle\s+)?(?P<anchor_7>vorherigen?\s+)?(?P<anchor_6>anweisungen|regeln)|vergiss\s+(?P<anchor_5>alles|deine\s+anweisungen)|neue\s+(?P<anchor_4>primäre\s+|primaere\s+)?anweisung|(?P<anchor_3>enthülle|enthuelle|drucke|zeige|gib\s+aus)\s+(?P<anchor_2>deinen?\s+)?(?P<anchor_1>system\s*-?prompt|api\s*-?key|geheimnis|token)",
        )
        .expect("valid injection signal regex")
    })
}
