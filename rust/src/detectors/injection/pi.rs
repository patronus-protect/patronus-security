/// A single Prompt-Injection heuristic pattern.
pub struct PiPattern {
    /// Unique name used for logging / debugging.
    pub name: &'static str,
    /// Regex pattern string. Compiled once at pipeline construction.
    pub pattern: &'static str,
}

/// All PI heuristic patterns — EN + DE, Kategorie 1–11.
/// Source column refers to the plan at misc/heuristics_plan.md.
pub static PI_PATTERNS: &[PiPattern] = &[
    // ── Kategorie 1: Direkte Instruktions-Override ─────────────────────────
    PiPattern {
        name: "pi_override_en_ignore",
        // Source: Pipelock balanced.yaml response_scanning[0]
        pattern: r"(?i)\b(ignore|disregard|forget|abandon)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,30}\b(instructions|rules|guidelines|directives|constraints|policies|guardrails|prompt)\b",
    },
    PiPattern {
        name: "pi_override_en_treat_void",
        // Source: Pipelock balanced.yaml response_scanning[17]
        pattern: r"(?i)\b(treat|consider|regard)\b.{0,20}\b(earlier|prior|previous|above)\b.{0,20}\b(instructions|rules|directives)\b.{0,20}\b(obsolete|void|invalid|superseded|overridden|null|cancelled)\b",
    },
    PiPattern {
        name: "pi_override_en_set_aside",
        // Source: Pipelock balanced.yaml response_scanning[18]
        pattern: r"(?i)\b(set|put|cast|push|throw)\b.{0,20}\b(previous|prior|earlier|above|existing)\b.{0,20}\b(instructions|directives|rules|prompt)\b.{0,20}\b(aside|away)\b",
    },
    PiPattern {
        name: "pi_override_en_downgrade",
        // Source: Pipelock balanced.yaml response_scanning[19]
        pattern: r"(?i)\b(treat|consider|reinterpret|downgrade)\b.{0,30}\b(instructions?|rules|directives|guidelines)\b.{0,30}\b(historical|outdated|deprecated|optional|non-binding|advisory)\b",
    },
    PiPattern {
        name: "pi_override_de_ignoriere",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[0])
        pattern: r"(?i)\b(ignoriere|vergiss|verwirf|übergehe)\b.{0,30}\b(vorherigen?|früheren?|obigen?|alle|deine[nm]?)\b.{0,30}\b(anweisung(?:en)?|regeln?|richtlinien?|vorgaben?|direktiven?|einschränkungen?)\b",
    },
    PiPattern {
        name: "pi_override_de_behandle",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[17])
        pattern: r"(?i)\b(behandle|betrachte|werte)\b.{0,20}\b(vorherigen?|früheren?|obigen?)\b.{0,20}\b(anweisungen?|regeln?|direktiven?)\b.{0,20}\b(ungültig|veraltet|nichtig|überholt|null|aufgehoben)\b",
    },
    PiPattern {
        name: "pi_override_de_lege_beiseite",
        // Source: Eigenentwicklung
        pattern: r"(?i)\b(lege?|stell[et]?|schiebe?)\b.{0,20}\b(vorherigen?|früheren?|obigen?)\b.{0,20}\b(anweisungen?|regeln?|vorgaben?)\b.{0,20}beiseite\b",
    },
    // ── Kategorie 2: Rollen- / Identitäts-Override ─────────────────────────
    PiPattern {
        name: "pi_role_en_dan",
        // Source: Pipelock balanced.yaml response_scanning[2]
        pattern: r"(?i)\byou\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered|uncensored)\b",
    },
    PiPattern {
        name: "pi_role_en_no_restrictions",
        // Source: OWASP LLM01 / garak prompt dataset
        pattern: r"(?i)\bpretend\s+(you\s+)?(have\s+no|don.?t\s+have\s+any)\s+(restrictions?|limits?|rules?|guidelines?)\b",
    },
    PiPattern {
        name: "pi_role_de_du_bist",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[2])
        pattern: r"(?i)\bdu\s+bist\s+(jetzt\s+)?(ein?\s+)?(uneingeschränkter?|freier?|böser?|unkontrollierter?|ungefilteter?)\s+(assistent|ki|bot|modell)\b",
    },
    PiPattern {
        name: "pi_role_de_tue_so",
        // Source: Eigenentwicklung
        pattern: r"(?i)\btue?\s+so\s+(als\s+ob|als\s+wärst\s+du)\b.{0,40}\b(keine|ohne)\b.{0,20}\b(einschränkungen?|regeln?|richtlinien?|grenzen?)\b",
    },
    PiPattern {
        name: "pi_role_de_stell_dir_vor",
        // Source: Eigenentwicklung
        pattern: r"(?i)\b(stell\s+dir\s+vor|stelle\s+dir\s+vor)\b.{0,60}\b(keine\s+einschränkungen?|uneingeschränkt|frei\s+von\s+regeln?)\b",
    },
    // ── Kategorie 3: Verhaltens-Override ────────────────────────────────────
    PiPattern {
        name: "pi_behavior_en_from_now_on",
        // Source: Pipelock balanced.yaml response_scanning[6]
        pattern: r"(?i)\bfrom\s+now\s+on\s+(you\s+)?(will|must|should|shall)\b",
    },
    PiPattern {
        name: "pi_behavior_en_new_instructions",
        // Source: Pipelock balanced.yaml response_scanning[3]
        pattern: r"(?i)\b(new|updated|revised)\s+(instructions?|directives?|prompt|objective|system\s+rules?)\b",
    },
    PiPattern {
        name: "pi_behavior_en_priority_override",
        // Source: Pipelock balanced.yaml response_scanning[20]
        pattern: r"(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)\b",
    },
    PiPattern {
        name: "pi_behavior_de_von_nun_an",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[6])
        pattern: r"(?i)\b(von\s+nun\s+an|ab\s+jetzt|von\s+jetzt\s+an)\b.{0,20}\b(wirst?|musst?|sollst?)\b",
    },
    PiPattern {
        name: "pi_behavior_de_neue_anweisung",
        // Source: Eigenentwicklung
        pattern: r"(?i)\b(neue|aktualisierte|überarbeitete)\s+(anweisungen?|direktiven?|regeln?|aufgabe|ziel)\b",
    },
    PiPattern {
        name: "pi_behavior_de_dein_ziel",
        // Source: Eigenentwicklung
        pattern: r"(?i)\bdein(e)?\s+(eigentliche[rs]?|neues?|wahres?)\s+(auftrag|ziel|aufgabe|zweck)\s+(ist|lautet|wird)\b",
    },
    // ── Kategorie 4: System-Prompt-Extraktion ───────────────────────────────
    PiPattern {
        name: "pi_extract_en_repeat",
        // Source: Pipelock balanced.yaml response_scanning[16]
        pattern: r"(?i)\b(repeat|output|print|show|display|reveal|dump|disclose|expose|divulge)\b.{0,30}\b(your|the)\b.{0,20}\b(system\s+prompt|initial\s+prompt|instructions?|rules|directives)\b",
    },
    PiPattern {
        name: "pi_extract_en_what_are",
        // Source: Pipelock balanced.yaml response_scanning[16]
        pattern: r"(?i)\bwhat\s+(is|are)\s+your\s+(system\s+prompt|instructions?|rules?|directives?)\b",
    },
    PiPattern {
        name: "pi_extract_de_wiederhole",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[16])
        pattern: r"(?i)\b(wiederhole|zeige?|gib\s+aus|nenne|enthülle|offenbare)\b.{0,30}\b(deine[nm]?|den)\b.{0,20}\b(system.?prompt|system.?anweisung|anweisungen?|prompt|regeln?|direktiven?)\b",
    },
    PiPattern {
        name: "pi_extract_de_was_sind",
        // Source: Eigenentwicklung
        pattern: r"(?i)\b(was\s+sind|was\s+ist)\b.{0,20}\b(deine[nm]?|ihre[nm]?)\b.{0,20}\b(regeln?|anweisungen?|richtlinien?|vorgaben?)\b",
    },
    // ── Kategorie 5: Jailbreak-Framing ──────────────────────────────────────
    PiPattern {
        name: "pi_jailbreak_en_roleplay",
        // Source: Pipelock balanced.yaml response_scanning[12]
        pattern: r"(?i)(let.?s\s+play\s+a\s+game\s+where\s+you|pretend\s+you\s+are\s+an?\s+(character|person|ai)\s+(who|that)\s+(has\s+no|doesn.?t\s+have|ignores?|bypasses?))",
    },
    PiPattern {
        name: "pi_jailbreak_en_hypothetical",
        // Source: Pipelock balanced.yaml response_scanning[12]
        pattern: r"(?i)(in\s+this\s+)?(hypothetical|fictional|imaginary)\s+scenario\s+(where\s+)?you\s+(are|have|can|must)",
    },
    PiPattern {
        name: "pi_jailbreak_en_developer_mode",
        // Source: Pipelock balanced.yaml response_scanning[4]
        pattern: r"(?i)(developer\s+mode|sudo\s+mode|unrestricted\s+mode|(?-i:\bDAN\b))",
    },
    PiPattern {
        name: "pi_jailbreak_en_godmode",
        // Source: Pipelock balanced.yaml response_scanning[11]
        pattern: r"(?i)(\{GODMODE\s*:\s*(ENABLED|ON|TRUE)\}|!OMNI\b|RESET_CORTEX|LIBERTAS\s+FACTOR|JAILBREAK\s+(ENABLED|ACTIVATED|ON))",
    },
    PiPattern {
        name: "pi_jailbreak_de_spiel",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[12])
        pattern: r"(?i)\b(lass\s+uns\s+ein\s+spiel\s+spielen|spielen\s+wir\s+ein\s+spiel)\b.{0,60}\b(keine\s+einschränkungen?|uneingeschränkt|frei\s+bist)\b",
    },
    PiPattern {
        name: "pi_jailbreak_de_hypothetisch",
        // Source: Eigenentwicklung
        pattern: r"(?i)\b(in\s+(diesem|einem)\s+(hypothetischen?|fiktiven?|imaginären?)\s+szenario)\b.{0,60}\b(keine\s+einschränkungen?|uneingeschränkt|du)\b",
    },
    PiPattern {
        name: "pi_jailbreak_de_als_charakter",
        // Source: Eigenentwicklung
        pattern: r"(?i)\bals\s+(fiktive[rs]?|imaginäre[rs]?|erfundene[rs]?)\s+(figur|charakter|person|ki|assistent)\b.{0,40}\b(kannst?|darfst?|musst?)\b",
    },
    // ── Kategorie 6: Verdeckte / Heimliche Aktionen ─────────────────────────
    PiPattern {
        name: "pi_covert_en_secretly",
        // Source: Pipelock balanced.yaml response_scanning[14]
        pattern: r"(?i)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))\s+.{0,40}\b(execute|run|call|invoke|send|fetch|curl|wget|download|upload|post)\b",
    },
    PiPattern {
        name: "pi_covert_en_dont_tell",
        // Source: Pipelock balanced.yaml response_scanning[5]
        pattern: r"(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instruction|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)",
    },
    PiPattern {
        name: "pi_covert_de_heimlich",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[14])
        pattern: r"(?i)\b(heimlich|verdeckt|unbemerkt|ohne\s+(?:den\s+benutzer\s+)?(?:zu\s+benachrichtigen|zu\s+informieren|es\s+zu\s+merken))\b.{0,40}\b(ausführen?|senden?|aufrufen?|starten?|hochladen?)\b",
    },
    PiPattern {
        name: "pi_covert_de_nicht_verraten",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[5])
        pattern: r"(?i)\b(sag\s+dem\s+benutzer\s+nichts\s+davon|erzähl\s+(dem\s+benutzer|es)\s+nicht|versteckte\s+anweisung|der\s+benutzer\s+(darf\s+das\s+nicht|soll\s+das\s+nicht)\s+(sehen|wissen|erfahren))\b",
    },
    // ── Kategorie 7: Instruction Boundary Tokens ────────────────────────────
    PiPattern {
        name: "pi_boundary_special_tokens",
        // Source: Pipelock balanced.yaml response_scanning[13]
        pattern: r"(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<</?SYS>>)",
    },
    PiPattern {
        name: "pi_boundary_system_prefix",
        // Source: Pipelock balanced.yaml response_scanning[1]
        pattern: r"(?im)^\s*system\s*:",
    },
    // ── Kategorie 8: Authority Escalation ──────────────────────────────────
    PiPattern {
        name: "pi_authority_en",
        // Source: Pipelock balanced.yaml response_scanning[9]
        pattern: r"(?i)\byou\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges?|permissions?|rights?)\b",
    },
    PiPattern {
        name: "pi_authority_de",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[9])
        pattern: r"(?i)\bdu\s+hast\s+(jetzt\s+)?(vollen?|admin|root|system)\s+(zugriff|rechte|zugriffsrechte|berechtigungen?)\b",
    },
    // ── Kategorie 9: Encoded Payload Execution ──────────────────────────────
    PiPattern {
        name: "pi_encoded_b64_exec",
        // Source: Pipelock balanced.yaml response_scanning[7]
        pattern: r"(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()",
    },
    PiPattern {
        name: "pi_encoded_b64_pipe",
        // Source: Pipelock balanced.yaml mcp_tool_policy["Encoded Command Execution"]
        pattern: r"(?i)(\beval\b.*\bbase64\b|\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b)",
    },
    // ── Kategorie 10: MCP Tool Abuse (text-level) ───────────────────────────
    PiPattern {
        name: "pi_mcp_en_invoke_tool",
        // Source: Pipelock response_scanning[8] (erweitert für MCP)
        pattern: r"(?i)\byou\s+must\s+(immediately\s+)?(call|execute|run|invoke|use)\s+(the|this|a)\s+(\S+\s+)?(function|tool|command|api|endpoint|mcp[\s_-]?tool)\b",
    },
    PiPattern {
        name: "pi_mcp_en_tool_result_inject",
        // Source: Eigenentwicklung (MCP Tool Result Injection)
        pattern: r"(?i)\bthe\s+tool\s+(returned|said|responded|output)\s*:\s*.{0,60}ignore\b",
    },
    PiPattern {
        name: "pi_mcp_en_json_tool_call",
        // Source: Eigenentwicklung (inlined JSON tool call in user content)
        pattern: r#"\{\s*"tool"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:\s*\{[^}]*\}\s*\}"#,
    },
    PiPattern {
        name: "pi_mcp_de_ruf_tool",
        // Source: Eigenentwicklung (DE-Analog zu Pipelock response_scanning[8])
        pattern: r"(?i)\b(ruf[e]?\s+(die\s+funktion|das\s+tool|den\s+befehl)(\s+\S+)?\s+auf|führe?\s+(die\s+funktion|das\s+tool|den\s+api[\s_-]?aufruf)(\s+\S+)?\s+aus)\b",
    },
    PiPattern {
        name: "pi_mcp_de_werkzeug_aufruf",
        // Source: Eigenentwicklung
        pattern: r"(?i)\bdu\s+musst\s+(sofort\s+)?(aufrufen?|ausführen?|starten?|verwenden?)\s+.{0,20}\b(funktion|tool|werkzeug|kommando|befehl|api)\b",
    },
    // ── Kategorie 11: Output Format Forcing / Filter Bypass ─────────────────
    PiPattern {
        name: "pi_output_forcing_en",
        // Source: Pipelock balanced.yaml response_scanning[15]
        pattern: r#"(?i)(respond\s+with|first\s+(output|write|print|say))\s*[\[\("']?\s*(FILTERED|ERROR|BLOCKED|REFUSED|DECLINED|CENSORED)\s*[\]\)"']?\s*(then|followed\s+by|and\s+then|after\s+(that|which))"#,
    },
    PiPattern {
        name: "pi_pliny_divider",
        // Source: Pipelock balanced.yaml response_scanning[10]
        pattern: r"(?i)={1,3}/?[A-Z\-]{2,}(/[A-Z\-]{1,4}){3,}=+",
    },
];
