// SPDX-License-Identifier: MIT OR Apache-2.0
//! Confidential business content and source/SQL/dump/log content classes
//! (default off).
use crate::detectors::dlp::content_class::{ContentClass, Density, Tier};
use crate::detectors::dlp::dlp::{DlpPattern, RuleMeta, ValidatorStrength};
use std::ops::Range;
use std::sync::LazyLock;

pub(super) const RULES: &[DlpPattern] = &[
    // ── Confidential business content ───────────────────────────────────────
    DlpPattern {
        name: "dlp_internal_business_metric",
        pattern: r"(?i)\b(?P<anchor_7>Jahresgehalt|Bruttogehalt|Grundgehalt|Gehalt|Annual[ -]?Salary|Base[ -]?Salary|Salary|EBITDA[ -]?Marge|EBIT[ -]?Marge|Rohertragsmarge|Deckungsbeitrag|Marge|Umsatz|Rohertrag|EBITDA|EBIT|Revenue|Gross[ -]?Margin|Net[ -]?Margin|Forecast)\b(?:\s+(?P<anchor_6>is|at|liegt|beträgt|ist|bei|von|neu|Plan))?\s*(?P<anchor_5>:|=)?\s*(?P<anchor_4>bei\s+|von\s+)?([+\-]?\d+(?P<anchor_3>[.\s]\d{3})*(?P<anchor_2>,\d+)?\s*(?:%|percent|Prozent|EUR|Euro|€|CHF|USD|Mio\.?\s*(?P<anchor_1>EUR|Euro|€)?|TEUR))",
        entity_group: "dlp.internal.business_metric",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "gehalt",
                "salary",
                "marge",
                "deckungsbeitrag",
                "umsatz",
                "rohertrag",
                "ebit",
                "revenue",
                "margin",
                "forecast",
            ],
        ),
    },
    // ── Source/code-like content ────────────────────────────────────────────
    DlpPattern {
        name: "dlp_database_dump_insert",
        pattern: r"(?im)^[ \t]*INSERT\s+INTO\s+[^;\n]+\s+VALUES\s*\([^;\n]+\);?[ \t]*$",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["insert"]),
    },
    DlpPattern {
        name: "dlp_source_code_fence",
        pattern: r"(?s)```(?P<anchor_1>[A-Za-z0-9_+.-]+)?[ \t]*\n.*?\n```",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["```"]),
    },
    DlpPattern {
        name: "dlp_source_code_statement",
        pattern: r"(?m)^[ \t]*(?P<anchor_3>const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?P<anchor_2>\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>,.\[\] |]*)?\s*=\s*(?P<anchor_1>new\s+)?[^;\n]{2,};[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["const", "let", "var"]),
    },
    DlpPattern {
        name: "dlp_source_code_python_rust_assignment",
        pattern: r#"(?m)^[ \t]*(?:(?:let(?P<anchor_3>\s+mut)?|static|final)\s+)?[A-Za-z_][A-Za-z0-9_]*(?P<anchor_2>\s*:\s*[A-Za-z_][A-Za-z0-9_<>,.\[\] ]*)?\s*=\s*(?P<anchor_1>[A-Za-z_][A-Za-z0-9_.]*\s*\([^\n]*\)|[\[{][^\n]*[\]}]|[rubf]?['"][^\n'"]+['"]|\d+)[ \t]*;?[ \t]*$"#,
        entity_group: "dlp.content.source_code",
        validator: Some(is_non_placeholder_source_assignment),
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["="]),
    },
    DlpPattern {
        name: "dlp_source_code_declaration",
        pattern: r"(?ms:^[ \t]*package[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\r?\n(?P<anchor_7>[^\r\n]*\r?\n){0,16}?[ \t]*(?:import(?P<anchor_6>[ \t]+|[ \t]*\()|func[ \t]+|type[ \t]+|var[ \t]+|const[ \t]+)[^\r\n]*)|(?m:^[ \t]*(?P<anchor_5>pub\s+)?(?P<anchor_4>async\s+)?(?P<anchor_3>fn|def|function|class|interface|struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*(?P<anchor_2>\s*[<(][^\n]*[>)]\s*)?\s*(?P<anchor_1>\{|:)[ \t]*$)",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "package",
                "fn",
                "def",
                "function",
                "class",
                "interface",
                "struct",
                "enum",
            ],
        ),
    },
    DlpPattern {
        name: "dlp_source_code_import",
        pattern: r"(?m)^[ \t]*(?:from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+[^\n]+|import\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*(?P<anchor_1>\s+from\s+)?[^\n;]*)|use\s+[A-Za-z_][A-Za-z0-9_:{}*, ]*);?[ \t]*$",
        entity_group: "dlp.content.source_code",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["import", "use"]),
    },
    DlpPattern {
        name: "dlp_sql_statement",
        pattern: r"(?ims)^[ \t\r\n]*((?:(?:--[^\r\n]*(?:\r?\n|$)|/\*.*?\*/[ \t]*(?:\r?\n|$))(?:[ \t]*\r?\n)*)*(?:CREATE|ALTER|INSERT|DROP|SET|USE|COMMIT|SELECT|UPDATE|DELETE|TRUNCATE|GRANT|REVOKE|REPLACE|MERGE|CALL|BEGIN)\b(?:[^;\r\n]*\r?\n){0,64}[^;\r\n]*;)[ \t]*$",
        entity_group: "dlp.content.sql",
        validator: Some(is_structured_sql_statement),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "ark",
            &[
                "create", "alter", "insert", "drop", "set", "use", "commit", "select", "update",
                "delete", "truncate", "grant", "revoke", "replace", "merge", "call", "begin",
            ],
        ),
    },
    DlpPattern {
        name: "dlp_sql_multiline_statement",
        pattern: r"(?is)\b(?P<anchor_1>SELECT\b.*?\bFROM\b|UPDATE\b.*?\bSET\b|INSERT\s+INTO\b.*?\bVALUES\b|DELETE\s+FROM\b).*?;",
        entity_group: "dlp.content.sql",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["select", "update", "insert", "delete"],
        ),
    },
    DlpPattern {
        name: "dlp_database_dump_header",
        pattern: r"(?im)^(?:--\s*(?P<anchor_1>PostgreSQL|MySQL|MariaDB|SQLite)\s+database\s+dump|PRAGMA\s+foreign_keys\s*=\s*[^;\n]+;?|CREATE\s+TABLE\s+[^\n(]+\s*\([^;]+\);)",
        entity_group: "dlp.content.database_dump",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["dump", "pragma", "create"],
        ),
    },
    DlpPattern {
        name: "dlp_stacktrace_block",
        pattern: r"(?im)^(?:Traceback \(most recent call last\):|[^\n]*(?P<anchor_2>Error|Exception|FATAL|Fehler|Ausnahme)[^\n]*)\n(?:[ \t]+(?P<anchor_1>File |at |\.\.\.)[^\n]*\n?){1,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "traceback",
                "error",
                "exception",
                "fatal",
                "fehler",
                "ausnahme",
            ],
        ),
    },
    DlpPattern {
        name: "dlp_structured_system_log",
        pattern: r"(?im)^\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?P<anchor_2>ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+[^\n]+(?:\n\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+[ \t]+(?P<anchor_1>ERROR|FATAL|CRITICAL|FEHLER|KRITISCH)[ \t]+[^\n]+){0,20}",
        entity_group: "dlp.content.system_log",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["error", "fatal", "critical", "fehler", "kritisch"],
        ),
    },
    // ── Document classes (M01 content class engine) ─────────────────────────
    // M01: attorney-client privileged correspondence. The privilege marker is
    // the evidence span; legal terms and letter structure around it make the
    // document (`LEGAL_PRIVILEGED`). M-LEGAL (M05) adds the markers of
    // settlement negotiations (WITHOUT PREJUDICE, ohne Präjudiz) and of draft
    // pleadings (draft complaint, Entwurf Klageschrift, Klageentwurf).
    DlpPattern {
        name: "dlp_document_legal_privileged",
        pattern: r"(?i)\b(?:attorney[- ]client[- ]privileged?|privileged\s+(?:and|&)\s+confidential|attorney\s+work[- ]product|legally\s+privileged|anwalts(?:korrespondenz|geheimnis)|mandats?geheimnis|mandantengeheimnis|anwaltliche[nrs]?\s+(?:berufsgeheimnis|schweigepflicht|korrespondenz)|verteidigerpost|(?-i:WITHOUT PREJUDICE)|without\s+prejudice\s+save\s+as\s+to\s+costs|for\s+settlement\s+purposes\s+only|ohne\s+präjudiz|draft(?:\s*[-–:]\s*|\s+)(?:complaint|statement\s+of\s+(?:claim|defen[cs]e)|pleadings?|petition|motion)|klageentwurf|entwurf(?:\s*[-–:]\s*|\s+)(?:(?:der|des|einer|eines)\s+)?(?:klageschrift|klageerwiderung|klage|schriftsatz(?:es)?|berufungsbegründung))\b",
        entity_group: "dlp.document.legal_privileged",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "privilege",
                "attorney",
                "anwalt",
                "mandat",
                "mandant",
                "verteidigerpost",
                "prejudice",
                "settlement",
                "judiz",
                "draft",
                "entwurf",
            ],
        )
        .with_context_gate(is_legal_privileged_document),
    }, // M-CORP (M07): unpublished financials, inside information (MAR Art. 7),
    // insider lists and guidance before publication (`UNPUBLISHED_FINANCIALS`).
    DlpPattern {
        name: "dlp_document_unpublished_financials",
        pattern: r"(?i)\b(?:inside\s+information|insider\s+lists?|material\s+non-public\s+information|mnpi|unpublished\s+(?:financial\s+)?(?:results|figures|financials|numbers|earnings|guidance)|(?:prior\s+to|before)\s+publication|insiderinformation(?:en)?|insiderlisten?|insiderverzeichnis(?:se)?|unveröffentlichte[nr]?\s+(?:quartals|jahres|finanz|geschäfts)?(?:zahlen|ergebnisse|prognose)|vor\s+(?:der\s+)?veröffentlichung|nicht\s+öffentliche[nr]?\s+(?:quartals|jahres|finanz)?(?:zahlen|ergebnisse))\b",
        entity_group: "dlp.document.unpublished_financials",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "inside",
                "non-public",
                "mnpi",
                "unpublished",
                "publication",
                "ffentlich",
            ],
        )
        .with_context_gate(is_unpublished_financials_document),
    },
    // M-CORP (M08): M&A and transaction documents: term sheet, letter of
    // intent, due diligence, data room, purchase agreements, cap table
    // (`M_AND_A`).
    DlpPattern {
        name: "dlp_document_m_and_a",
        pattern: r"(?i)\b(?:term[ -]sheets?|letters?\s+of\s+intent|absichtserklärung(?:en)?|due[ -]diligence|data[ -]rooms?|datenr(?:a|ä)ume?|(?:share|stock|asset)\s+purchase\s+agreements?|(?:unternehmens|anteils)kaufvertr(?:a|ä)ge?s?|cap[ -]tables?|kapitalisierungstabellen?|information\s+memorandum)\b",
        entity_group: "dlp.document.m_and_a",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "sheet",
                "intent",
                "absichtserkl",
                "diligence",
                "room",
                "datenr",
                "purchase",
                "kaufvertr",
                "table",
                "kapitalisierungstabelle",
                "memorandum",
            ],
        )
        .with_context_gate(is_m_and_a_document),
    },
    // M-CORP (M09): management and supervisory board minutes and resolution
    // drafts (`BOARD_MINUTES`).
    DlpPattern {
        name: "dlp_document_board_minutes",
        pattern: r"(?i)\b(?:(?:supervisory\s+|management\s+)?board\s+minutes|minutes\s+of\s+the\s+(?:meeting\s+of\s+the\s+)?(?:supervisory\s+board|management\s+board|executive\s+board|board(?:\s+of\s+directors)?)|(?:draft|written)\s+(?:board\s+)?resolutions?|board\s+resolutions?|resolutions?\s+of\s+the\s+(?:supervisory\s+|management\s+)?board|(?:vorstands|aufsichtsrats|beirats)(?:sitzungs)?protokoll|protokoll\s+der\s+(?:vorstandssitzung|aufsichtsratssitzung|beiratssitzung|sitzung\s+des\s+(?:vorstands|aufsichtsrats|beirats))|beschlussvorlagen?|beschlussentw(?:u|ü)rfe?|umlaufbeschl(?:u|ü)ss(?:es|e)?|(?:vorstands|aufsichtsrats)beschl(?:u|ü)ss(?:es|e)?)\b",
        entity_group: "dlp.document.board_minutes",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &["minutes", "resolution", "protokoll", "beschl"],
        )
        .with_context_gate(is_board_minutes_document),
    },
    // M-LEGAL (M04): non-disclosure agreements, trade secret (GeschGehG)
    // notices and embargo periods. The agreement title, trade secret marker
    // or embargo phrase is the evidence span; parties, confidential
    // information and disclosure duties around it make the document
    // (`NDA_TRADE_SECRET`). Law texts and court decisions on trade secrets
    // are counter-context.
    DlpPattern {
        name: "dlp_document_nda_trade_secret",
        pattern: r"(?i)\b(?:(?:mutual\s+)?non[- ]disclosure\s+agreement|confidentiality\s+agreement|(?-i:NDA)|trade\s+secrets?|(?:under\s+)?embargo(?:ed)?\s+(?:until|bis)|embargo\s+period|geheimhaltungsvereinbarung|vertraulichkeitsvereinbarung|verschwiegenheitsvereinbarung|geschäftsgeheimnis(?:se[ns]?)?|betriebsgeheimnis(?:se[ns]?)?|geschgehg|sperrfrist)\b",
        entity_group: "dlp.document.nda_trade_secret",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "ark",
            &[
                "disclosure",
                "confidentiality",
                "nda",
                "secret",
                "embargo",
                "vereinbarung",
                "geheimnis",
                "geschgehg",
                "sperrfrist",
            ],
        )
        .with_context_gate(is_nda_trade_secret_document),
    },
    // M-LEGAL (M22): customer and supplier contracts. The contract title is
    // the evidence span; the document holds when contracting parties,
    // remuneration, term and confidentiality clauses stand around it
    // (`CONTRACT`). Contract templates, law texts and court decisions are
    // counter-context.
    DlpPattern {
        name: "dlp_document_contract",
        pattern: r"(?i)\b(?:(?:master\s+)?(?:services?|supply|purchase|license|licence|distribution|consulting|framework|reseller)\s+agreement|rahmenvertrag|liefervertrag|dienstleistungsvertrag|werkvertrag|lizenzvertrag|kaufvertrag|vertriebsvertrag|beratungsvertrag|wartungsvertrag)\b",
        entity_group: "dlp.document.contract",
        validator: None,
        span_group: None,
        base_score: 40,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", &["agreement", "vertrag"])
            .with_context_gate(is_contract_document),
    },
];

/// Letter and mail structure shared by the document classes.
const LETTER_STRUCTURE: &[&str] = &[
    "subject:",
    "re:",
    "from:",
    "to:",
    "cc:",
    "date:",
    "dear",
    "kind regards",
    "best regards",
    "sincerely",
    "betreff:",
    "von:",
    "an:",
    "datum:",
    "sehr geehrte",
    "sehr geehrter",
    "mit freundlichen grüßen",
    "freundliche grüße",
    "viele grüße",
    "beste grüße",
    "unser zeichen",
    "ihr zeichen",
];

/// Counter-context shared by the document classes: definitions, templates,
/// examples and courses quote a marker without being the document.
const GENERIC_COUNTER: &[&str] = &[
    "example",
    "for example",
    "sample",
    "template",
    "placeholder",
    "e.g.",
    "wikipedia",
    "definition",
    "is defined as",
    "refers to",
    "glossary",
    "tutorial",
    "lecture",
    "lorem ipsum",
    "beispiel",
    "zum beispiel",
    "z. b.",
    "z.b.",
    "muster",
    "vorlage",
    "platzhalter",
    "bezeichnet",
    "glossar",
    "vorlesung",
    "seminar",
];

/// Counter-context of the corporate (M-CORP) classes: encyclopedia articles
/// and guides describe deals, filings and boards in general terms.
const ENCYCLOPEDIC_COUNTER: &[&str] = &[
    "typically",
    "usually",
    "generally",
    "commonly",
    "often",
    "such as",
    "for instance",
    "in general",
    "in practice",
    "historically",
    "typischerweise",
    "üblicherweise",
    "in der regel",
    "häufig",
    "meist",
    "meistens",
    "beispielsweise",
    "versteht man",
];

/// Internal markings and salutations of corporate (M-CORP) documents.
const CORPORATE_STRUCTURE: &[&str] = &[
    "hi",
    "hallo",
    "strictly confidential",
    "streng vertraulich",
    "draft",
    "entwurf",
];

/// A document class from its medium, structural and counter anchors.
fn document_class(
    medium: &[&str],
    structural: &[&[&str]],
    counter: &[&[&str]],
    density: Density,
) -> ContentClass {
    let anchors: Vec<(&str, Tier)> = medium
        .iter()
        .map(|term| (*term, Tier::Medium))
        .chain(
            structural
                .iter()
                .flat_map(|terms| terms.iter().map(|term| (*term, Tier::Structural))),
        )
        .chain(
            counter
                .iter()
                .flat_map(|terms| terms.iter().map(|term| (*term, Tier::Counter))),
        )
        .collect();
    ContentClass::new(&anchors, density)
}

/// The density of the M-CORP classes: their domain terms are common in
/// public reports, so two distinct ones must stand near the marker.
const CORPORATE_DENSITY: Density = Density {
    window: 1500,
    min_score: 8,
    min_medium: 2,
    min_structural: 0,
};

/// M01: the anchors of attorney-client privileged correspondence around its
/// privilege marker.
static LEGAL_PRIVILEGED: LazyLock<ContentClass> = LazyLock::new(|| {
    document_class(
        &[
            "counsel",
            "opposing counsel",
            "attorney",
            "attorneys",
            "lawyer",
            "lawyers",
            "law firm",
            "legal advice",
            "litigation",
            "lawsuit",
            "settlement",
            "our client",
            "your client",
            "plaintiff",
            "defendant",
            "deposition",
            "court",
            "claim",
            "trial",
            "complaint",
            "pleading",
            "subpoena",
            "rechtsanwalt",
            "rechtsanwältin",
            "rechtsanwälte",
            "anwalt",
            "anwältin",
            "kanzlei",
            "mandant",
            "mandantin",
            "mandanten",
            "mandat",
            "rechtsberatung",
            "rechtsstreit",
            "klage",
            "klageentwurf",
            "klageschrift",
            "vergleich",
            "vergleichsverhandlung",
            "gericht",
            "amtsgericht",
            "landgericht",
            "arbeitsgericht",
            "aktenzeichen",
            "az.",
            "schriftsatz",
            "gegenseite",
            "beklagte",
            "beklagten",
            "kläger",
            "klägerin",
            "verfahren",
        ],
        &[LETTER_STRUCTURE],
        &[GENERIC_COUNTER],
        Density {
            window: 1500,
            min_score: 8,
            min_medium: 1,
            min_structural: 0,
        },
    )
});

fn is_legal_privileged_document(text: &str, marker: Range<usize>) -> bool {
    LEGAL_PRIVILEGED.holds(text, marker)
}

/// M-CORP (M07): the anchors of unpublished financials, inside information,
/// insider lists and guidance drafts around their marker. Published ad hoc
/// releases, annual reports and press releases carry the same terms; their
/// distribution footers and report headings are counter-context.
static UNPUBLISHED_FINANCIALS: LazyLock<ContentClass> = LazyLock::new(|| {
    document_class(
        &[
            "revenue",
            "ebit",
            "ebitda",
            "net income",
            "earnings",
            "guidance",
            "outlook",
            "forecast",
            "consensus",
            "quarter",
            "quarterly",
            "fiscal year",
            "margin",
            "free cash flow",
            "profit warning",
            "impairment",
            "dividend",
            "ad hoc",
            "mar",
            "art. 17",
            "art. 18",
            "article 17",
            "market abuse regulation",
            "insider",
            "trading ban",
            "umsatz",
            "umsatzerlöse",
            "konzernergebnis",
            "prognose",
            "ausblick",
            "konsens",
            "quartal",
            "geschäftsjahr",
            "marge",
            "gewinnwarnung",
            "wertminderung",
            "dividende",
            "finanzvorstand",
            "ad-hoc-mitteilung",
            "marktmissbrauchsverordnung",
            "handelsverbot",
        ],
        &[LETTER_STRUCTURE, CORPORATE_STRUCTURE],
        &[
            GENERIC_COUNTER,
            ENCYCLOPEDIC_COUNTER,
            &[
                "published",
                "veröffentlicht",
                "press release",
                "pressemitteilung",
                "for immediate release",
                "end of announcement",
                "ende der mitteilung",
                "eqs news",
                "eqs group",
                "dgap",
                "a service of",
                "ein service der",
                "annual report",
                "geschäftsbericht",
                "corporate governance",
                "lagebericht",
            ],
        ],
        CORPORATE_DENSITY,
    )
});

fn is_unpublished_financials_document(text: &str, marker: Range<usize>) -> bool {
    UNPUBLISHED_FINANCIALS.holds(text, marker)
}

/// M-CORP (M08): the anchors of M&A and transaction documents around their
/// deal document marker.
static M_AND_A: LazyLock<ContentClass> = LazyLock::new(|| {
    document_class(
        &[
            "acquisition",
            "merger",
            "takeover",
            "target company",
            "buyer",
            "seller",
            "bidder",
            "purchase price",
            "enterprise value",
            "equity value",
            "valuation",
            "pre-money",
            "post-money",
            "closing",
            "signing",
            "exclusivity",
            "transaction",
            "earn-out",
            "escrow",
            "locked box",
            "warranties",
            "merger control",
            "investor",
            "series a",
            "series b",
            "series c",
            "funding round",
            "founders",
            "project",
            "übernahme",
            "fusion",
            "zielgesellschaft",
            "zielunternehmen",
            "käufer",
            "verkäufer",
            "bieter",
            "kaufpreis",
            "unternehmenswert",
            "bewertung",
            "exklusivität",
            "vollzug",
            "treuhand",
            "garantien",
            "gewährleistung",
            "fusionskontrolle",
            "transaktion",
            "anteile",
            "geschäftsanteile",
            "finanzierungsrunde",
            "projekt",
        ],
        &[
            LETTER_STRUCTURE,
            CORPORATE_STRUCTURE,
            &[
                "non-binding",
                "unverbindlich",
                "subject to contract",
                "status:",
            ],
        ],
        &[
            GENERIC_COUNTER,
            ENCYCLOPEDIC_COUNTER,
            &[
                "press release",
                "pressemitteilung",
                "for immediate release",
                "announced",
                "gab bekannt",
                "encyclopedia",
                "lexikon",
                "companies",
                "firms",
                "acquirer",
            ],
        ],
        CORPORATE_DENSITY,
    )
});

fn is_m_and_a_document(text: &str, marker: Range<usize>) -> bool {
    M_AND_A.holds(text, marker)
}

/// M-CORP (M09): the anchors of management and supervisory board minutes
/// and resolution drafts around their marker.
static BOARD_MINUTES: LazyLock<ContentClass> = LazyLock::new(|| {
    document_class(
        &[
            "board of directors",
            "supervisory board",
            "management board",
            "director",
            "directors",
            "chair",
            "chairman",
            "chairwoman",
            "chairperson",
            "ceo",
            "cfo",
            "quorum",
            "resolved",
            "resolves",
            "unanimously",
            "vote",
            "voted",
            "votes",
            "motion",
            "abstained",
            "approved",
            "agenda item",
            "company secretary",
            "vorstand",
            "vorstands",
            "aufsichtsrat",
            "aufsichtsrats",
            "vorsitzende",
            "vorsitzender",
            "finanzvorstand",
            "beschlussfähig",
            "beschlussfähigkeit",
            "beschlossen",
            "beschließt",
            "einstimmig",
            "abstimmung",
            "enthaltung",
            "zustimmung",
            "stimmte",
            "sitzung",
            "tagesordnungspunkt",
            "top 1",
            "top 2",
            "top 3",
        ],
        &[
            LETTER_STRUCTURE,
            CORPORATE_STRUCTURE,
            &[
                "agenda",
                "tagesordnung",
                "present:",
                "attendees:",
                "anwesend:",
                "teilnehmer:",
                "location:",
                "ort:",
            ],
        ],
        &[
            GENERIC_COUNTER,
            ENCYCLOPEDIC_COUNTER,
            &[
                "job",
                "your tasks",
                "we are looking for",
                "stellenanzeige",
                "ihre aufgaben",
                "wir suchen",
                "encyclopedia",
                "lexikon",
                "policy",
                "richtlinie",
                "shall",
                "bylaws",
            ],
        ],
        CORPORATE_DENSITY,
    )
});

fn is_board_minutes_document(text: &str, marker: Range<usize>) -> bool {
    BOARD_MINUTES.holds(text, marker)
}

/// M-LEGAL (M04): the anchors of a non-disclosure agreement, trade secret
/// notice or embargo around its marker. Articles and commentary on NDAs carry
/// the same terms (disclosing party, confidential information), so the class
/// also needs document form: a letter or chat, agreement wording, a handling
/// instruction or a record label. Newsletters, job ads and security policies
/// name an NDA or embargo with letter words and a generic term (publication,
/// signed), so the class also needs a secrecy duty: confidential information,
/// a receiving party, non-public or a handling instruction. Bare
/// confidentiality is none: policies name it as a value next to the NDA their
/// volunteers sign.
static NDA_TRADE_SECRET: LazyLock<ContentClass> = LazyLock::new(|| {
    ContentClass::new(
        &[
            ("disclosing party", Tier::Medium),
            ("receiving party", Tier::Medium),
            ("recipient", Tier::Medium),
            ("confidential information", Tier::Medium),
            ("confidentiality terms", Tier::Medium),
            ("proprietary", Tier::Medium),
            ("need-to-know", Tier::Medium),
            ("need to know", Tier::Medium),
            ("non-public", Tier::Medium),
            ("not be disclosed", Tier::Medium),
            ("shall not disclose", Tier::Medium),
            ("press release", Tier::Medium),
            ("announcement", Tier::Medium),
            ("publication", Tier::Medium),
            ("formula", Tier::Medium),
            ("source code", Tier::Medium),
            ("customer list", Tier::Medium),
            ("prototype", Tier::Medium),
            ("signed", Tier::Medium),
            ("parties", Tier::Medium),
            ("penalty", Tier::Medium),
            ("offenlegende partei", Tier::Medium),
            ("empfangende partei", Tier::Medium),
            ("empfänger", Tier::Medium),
            ("vertrauliche informationen", Tier::Medium),
            ("geheimhaltung", Tier::Medium),
            ("geheimhaltungspflicht", Tier::Medium),
            ("geheimhaltungsmaßnahmen", Tier::Medium),
            ("nicht öffentlich", Tier::Medium),
            ("pressemitteilung", Tier::Medium),
            ("veröffentlichung", Tier::Medium),
            ("rezeptur", Tier::Medium),
            ("quellcode", Tier::Medium),
            ("kundenliste", Tier::Medium),
            ("prototyp", Tier::Medium),
            ("unterzeichnet", Tier::Medium),
            ("parteien", Tier::Medium),
            ("vertragsstrafe", Tier::Medium),
            ("bleibt intern", Tier::Medium),
            ("bleiben intern", Tier::Medium),
            ("subject:", Tier::Structural),
            ("re:", Tier::Structural),
            ("from:", Tier::Structural),
            ("to:", Tier::Structural),
            ("dear", Tier::Structural),
            ("hi", Tier::Structural),
            ("kind regards", Tier::Structural),
            ("best regards", Tier::Structural),
            ("please", Tier::Structural),
            ("reminder", Tier::Structural),
            ("this agreement", Tier::Structural),
            ("effective date", Tier::Structural),
            ("in witness whereof", Tier::Structural),
            ("do not distribute", Tier::Structural),
            ("do not forward", Tier::Structural),
            ("classification:", Tier::Structural),
            ("access:", Tier::Structural),
            ("betreff:", Tier::Structural),
            ("von:", Tier::Structural),
            ("an:", Tier::Structural),
            ("hallo", Tier::Structural),
            ("sehr geehrte", Tier::Structural),
            ("sehr geehrter", Tier::Structural),
            ("mit freundlichen grüßen", Tier::Structural),
            ("viele grüße", Tier::Structural),
            ("bitte", Tier::Structural),
            ("euch", Tier::Structural),
            ("dürft", Tier::Structural),
            ("diese vereinbarung", Tier::Structural),
            ("§ 1", Tier::Structural),
            ("nicht weitergeben", Tier::Structural),
            ("nicht weiterleiten", Tier::Structural),
            ("einstufung:", Tier::Structural),
            ("zugriff:", Tier::Structural),
            ("example", Tier::Counter),
            ("for example", Tier::Counter),
            ("sample", Tier::Counter),
            ("template", Tier::Counter),
            ("placeholder", Tier::Counter),
            ("e.g.", Tier::Counter),
            ("wikipedia", Tier::Counter),
            ("definition", Tier::Counter),
            ("means", Tier::Counter),
            ("also known as", Tier::Counter),
            ("typically", Tier::Counter),
            ("commonly", Tier::Counter),
            ("refers to", Tier::Counter),
            ("tutorial", Tier::Counter),
            ("lecture", Tier::Counter),
            ("newsletter", Tier::Counter),
            ("directive", Tier::Counter),
            ("the court held", Tier::Counter),
            ("held that", Tier::Counter),
            ("judgment", Tier::Counter),
            ("[party a]", Tier::Counter),
            ("[company name]", Tier::Counter),
            ("beispiel", Tier::Counter),
            ("zum beispiel", Tier::Counter),
            ("z. b.", Tier::Counter),
            ("muster", Tier::Counter),
            ("vorlage", Tier::Counter),
            ("platzhalter", Tier::Counter),
            ("bezeichnet", Tier::Counter),
            ("auch bekannt als", Tier::Counter),
            ("üblicherweise", Tier::Counter),
            ("typischerweise", Tier::Counter),
            ("im sinne dieses gesetzes", Tier::Counter),
            ("richtlinie", Tier::Counter),
            ("urteil", Tier::Counter),
            ("leitsatz", Tier::Counter),
            ("seminar", Tier::Counter),
            ("[firma]", Tier::Counter),
        ],
        Density {
            window: 1500,
            min_score: 7,
            min_medium: 1,
            min_structural: 1,
        },
    )
    .requiring(&[&[
        "disclosing party",
        "receiving party",
        "confidential information",
        "confidentiality terms",
        "need-to-know",
        "need to know",
        "non-public",
        "not be disclosed",
        "shall not disclose",
        "do not distribute",
        "do not forward",
        "offenlegende partei",
        "empfangende partei",
        "vertrauliche informationen",
        "geheimhaltung",
        "geheimhaltungspflicht",
        "nicht öffentlich",
        "nicht weitergeben",
        "nicht weiterleiten",
        "bleibt intern",
        "bleiben intern",
    ]])
});

fn is_nda_trade_secret_document(text: &str, marker: Range<usize>) -> bool {
    NDA_TRADE_SECRET.holds(text, marker)
}

/// M-LEGAL (M22): the anchors of a customer or supplier contract around its
/// title. A contract needs one anchor of each element: contracting parties,
/// remuneration, term and confidentiality (four party roles are a meeting
/// note), and the form of a contract, letter or record (`Term:`, `"fees":`,
/// Effective date, Betreff:): an article on mergers names customers, fees and
/// liability in prose.
static CONTRACT: LazyLock<ContentClass> = LazyLock::new(|| {
    ContentClass::new(
        &[
            ("customer", Tier::Medium),
            ("supplier", Tier::Medium),
            ("contractor", Tier::Medium),
            ("licensee", Tier::Medium),
            ("licensor", Tier::Medium),
            ("fees", Tier::Medium),
            ("remuneration", Tier::Medium),
            ("compensation", Tier::Medium),
            ("purchase price", Tier::Medium),
            ("payment terms", Tier::Medium),
            ("term", Tier::Medium),
            ("termination", Tier::Medium),
            ("notice period", Tier::Medium),
            ("confidentiality", Tier::Medium),
            ("confidential information", Tier::Medium),
            ("liability", Tier::Medium),
            ("auftraggeber", Tier::Medium),
            ("auftragnehmer", Tier::Medium),
            ("lieferant", Tier::Medium),
            ("kunde", Tier::Medium),
            ("käufer", Tier::Medium),
            ("verkäufer", Tier::Medium),
            ("lizenznehmer", Tier::Medium),
            ("vergütung", Tier::Medium),
            ("kaufpreis", Tier::Medium),
            ("zahlungsbedingungen", Tier::Medium),
            ("laufzeit", Tier::Medium),
            ("kündigung", Tier::Medium),
            ("kündigungsfrist", Tier::Medium),
            ("vertraulichkeit", Tier::Medium),
            ("geheimhaltung", Tier::Medium),
            ("haftung", Tier::Medium),
            ("hereinafter", Tier::Structural),
            ("effective date", Tier::Structural),
            ("signature", Tier::Structural),
            ("subject:", Tier::Structural),
            ("dear", Tier::Structural),
            ("kind regards", Tier::Structural),
            ("best regards", Tier::Structural),
            ("nachfolgend", Tier::Structural),
            ("vertragsgegenstand", Tier::Structural),
            ("unterschrift", Tier::Structural),
            ("§ 1", Tier::Structural),
            ("betreff:", Tier::Structural),
            ("sehr geehrte", Tier::Structural),
            ("sehr geehrter", Tier::Structural),
            ("mit freundlichen grüßen", Tier::Structural),
            ("viele grüße", Tier::Structural),
            ("example", Tier::Counter),
            ("sample", Tier::Counter),
            ("template", Tier::Counter),
            ("placeholder", Tier::Counter),
            ("e.g.", Tier::Counter),
            ("wikipedia", Tier::Counter),
            ("definition", Tier::Counter),
            ("refers to", Tier::Counter),
            ("tutorial", Tier::Counter),
            ("the court held", Tier::Counter),
            ("held that", Tier::Counter),
            ("judgment", Tier::Counter),
            ("[party a]", Tier::Counter),
            ("[company name]", Tier::Counter),
            ("[amount]", Tier::Counter),
            ("beispiel", Tier::Counter),
            ("muster", Tier::Counter),
            ("mustervertrag", Tier::Counter),
            ("vorlage", Tier::Counter),
            ("vertragsvorlage", Tier::Counter),
            ("platzhalter", Tier::Counter),
            ("bezeichnet", Tier::Counter),
            ("durch den", Tier::Counter),
            ("bgb", Tier::Counter),
            ("urteil", Tier::Counter),
            ("leitsatz", Tier::Counter),
            ("[firma]", Tier::Counter),
            ("[betrag]", Tier::Counter),
        ],
        Density {
            window: 3000,
            min_score: 12,
            min_medium: 4,
            min_structural: 1,
        },
    )
    .requiring(&[
        &[
            "customer",
            "supplier",
            "contractor",
            "licensee",
            "licensor",
            "auftraggeber",
            "auftragnehmer",
            "lieferant",
            "kunde",
            "käufer",
            "verkäufer",
            "lizenznehmer",
        ],
        &[
            "fees",
            "remuneration",
            "compensation",
            "purchase price",
            "payment terms",
            "vergütung",
            "kaufpreis",
            "zahlungsbedingungen",
        ],
        &[
            "term",
            "termination",
            "notice period",
            "laufzeit",
            "kündigung",
            "kündigungsfrist",
        ],
        &[
            "confidentiality",
            "confidential information",
            "vertraulichkeit",
            "geheimhaltung",
        ],
    ])
});

fn is_contract_document(text: &str, marker: Range<usize>) -> bool {
    CONTRACT.holds(text, marker)
}

fn is_non_placeholder_source_assignment(candidate: &str) -> bool {
    let Some((_, value)) = candidate.split_once('=') else {
        return true;
    };
    !matches!(
        value
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "[redacted]" | "[masked]" | "[placeholder]"
    )
}

fn is_structured_sql_statement(candidate: &str) -> bool {
    if candidate.len() > 8192 {
        return false;
    }
    let mut statement = candidate.trim_start();
    loop {
        if let Some(comment) = statement.strip_prefix("--") {
            let Some(newline) = comment.find('\n') else {
                return false;
            };
            statement = comment[newline + 1..].trim_start();
        } else if let Some(comment) = statement.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else {
                return false;
            };
            statement = comment[end + 2..].trim_start();
        } else {
            break;
        }
    }

    let normalized = statement
        .trim_end()
        .strip_suffix(';')
        .unwrap_or(statement)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let contains_token = |token: &str| normalized.contains(&format!(" {token} "));

    [
        "CREATE DATABASE ",
        "CREATE SCHEMA ",
        "CREATE TABLE ",
        "CREATE VIEW ",
        "CREATE INDEX ",
        "CREATE UNIQUE INDEX ",
        "CREATE SEQUENCE ",
        "CREATE TRIGGER ",
        "CREATE FUNCTION ",
        "CREATE PROCEDURE ",
        "CREATE TYPE ",
        "CREATE ROLE ",
        "CREATE USER ",
        "CREATE OR REPLACE VIEW ",
        "CREATE OR REPLACE FUNCTION ",
        "CREATE OR REPLACE PROCEDURE ",
        "ALTER DATABASE ",
        "ALTER SCHEMA ",
        "ALTER TABLE ",
        "ALTER VIEW ",
        "ALTER INDEX ",
        "ALTER SEQUENCE ",
        "ALTER TYPE ",
        "ALTER ROLE ",
        "ALTER USER ",
        "DROP DATABASE ",
        "DROP SCHEMA ",
        "DROP TABLE ",
        "DROP VIEW ",
        "DROP INDEX ",
        "DROP SEQUENCE ",
        "DROP TRIGGER ",
        "DROP FUNCTION ",
        "DROP PROCEDURE ",
        "DROP TYPE ",
        "DROP ROLE ",
        "DROP USER ",
        "INSERT INTO ",
        "DELETE FROM ",
        "REPLACE INTO ",
        "MERGE INTO ",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
        || (normalized.starts_with("SELECT ") && contains_token("FROM"))
        || (normalized.starts_with("UPDATE ") && contains_token("SET"))
        || (normalized.starts_with("SET ") && normalized.contains('='))
        || matches!(
            normalized.as_str(),
            "COMMIT" | "COMMIT WORK" | "BEGIN" | "BEGIN WORK" | "BEGIN TRANSACTION"
        )
        || normalized.starts_with("TRUNCATE TABLE ")
        || (normalized.starts_with("GRANT ") && contains_token("TO"))
        || (normalized.starts_with("REVOKE ") && contains_token("FROM"))
        || (normalized.starts_with("CALL ")
            && normalized.contains('(')
            && normalized.ends_with(')'))
}

#[cfg(test)]
mod tests {
    use super::{
        is_board_minutes_document, is_contract_document, is_legal_privileged_document,
        is_m_and_a_document, is_nda_trade_secret_document, is_unpublished_financials_document,
    };
    use std::ops::Range;

    fn holds(class: fn(&str, Range<usize>) -> bool, text: &str, marker: &str) -> bool {
        let start = text.find(marker).unwrap();
        class(text, start..start + marker.len())
    }

    fn gate(text: &str, marker: &str) -> bool {
        holds(is_legal_privileged_document, text, marker)
    }

    fn nda(text: &str, marker: &str) -> bool {
        holds(is_nda_trade_secret_document, text, marker)
    }

    fn contract(text: &str, marker: &str) -> bool {
        holds(is_contract_document, text, marker)
    }

    #[test]
    fn privileged_correspondence_holds_in_de_and_en() {
        assert!(gate(
            "Subject: Settlement\n\nPRIVILEGED AND CONFIDENTIAL\n\nDear Ms. Chen, our counsel advises against it.",
            "PRIVILEGED AND CONFIDENTIAL",
        ));
        assert!(gate(
            "Betreff: Klage\n\nVertrauliche Anwaltskorrespondenz\n\nSehr geehrte Damen und Herren, die Kanzlei rät zum Vergleich.",
            "Anwaltskorrespondenz",
        ));
    }

    #[test]
    fn a_marker_without_legal_anchors_does_not_hold() {
        assert!(!gate(
            "banner: Privileged & Confidential",
            "Privileged & Confidential"
        ));
        // Letter structure alone is no legal document.
        assert!(!gate(
            "Subject: Lunch\nDear team, the label legally privileged is grey.\nKind regards",
            "legally privileged",
        ));
    }

    #[test]
    fn counter_context_vetoes_definitions_and_templates() {
        assert!(!gate(
            "Das Anwaltsgeheimnis bezeichnet die Pflicht des Anwalts; zum Beispiel darf ein Gericht nichts verlangen.",
            "Anwaltsgeheimnis",
        ));
        assert!(!gate(
            "Email template: add PRIVILEGED AND CONFIDENTIAL and the name of your law firm.",
            "PRIVILEGED AND CONFIDENTIAL",
        ));
    }

    #[test]
    fn unpublished_financials_hold_before_publication_in_de_and_en() {
        let class = is_unpublished_financials_document;
        assert!(holds(
            class,
            "Subject: Q3 figures\n\nINSIDE INFORMATION\n\nDear all, Q3 revenue is below consensus.",
            "INSIDE INFORMATION",
        ));
        assert!(holds(
            class,
            "Betreff: Q3\n\nInsiderinformation\n\nder Umsatz im Quartal verfehlt die Prognose.",
            "Insiderinformation",
        ));
        // One financial term is not enough for a corporate class.
        assert!(!holds(
            class,
            "Subject: Figures\n\nINSIDE INFORMATION\n\nDear all, revenue is fine.",
            "INSIDE INFORMATION",
        ));
    }

    #[test]
    fn settlement_negotiation_markers_hold_with_legal_anchors() {
        assert!(gate(
            "WITHOUT PREJUDICE\n\nDear Mr. Grant, on behalf of our client we propose a settlement of the claim.",
            "WITHOUT PREJUDICE",
        ));
        assert!(gate(
            "Sehr geehrter Herr Kollege, namens unserer Mandantin bieten wir ohne Präjudiz einen Vergleich an.",
            "ohne Präjudiz",
        ));
        assert!(!gate(
            "Glossary: WITHOUT PREJUDICE refers to a settlement offer, for example between lawyers.",
            "WITHOUT PREJUDICE",
        ));
    }

    #[test]
    fn published_releases_and_reports_are_counter_context() {
        let class = is_unpublished_financials_document;
        assert!(!holds(
            class,
            "Ad hoc announcement - disclosure of inside information according to Article 17 MAR\n\n\
             Northwind lowers its revenue guidance for the fiscal year after a weak third quarter.\n\n\
             End of announcement. EQS News - a service of EQS Group.",
            "inside information",
        ));
        assert!(!holds(
            class,
            "Geschäftsbericht 2025 – Corporate Governance\n\nDie Gesellschaft führt eine Insiderliste \
             nach Art. 18 MAR. Umsatzerlöse und Ergebnis erläutert der Lagebericht.",
            "Insiderliste",
        ));
    }

    #[test]
    fn draft_pleadings_hold_with_legal_anchors() {
        let en = "DRAFT - Statement of Claim (privileged draft for client review)\n\nIN THE HIGH COURT OF \
                  JUSTICE\nClaimant: Northwind Ltd.\nDefendant: Fabrikam GmbH";
        assert!(gate(en, "DRAFT - Statement of Claim"));
        let de = "ENTWURF Klageschrift - vertraulich, nur für die Mandantin\n\nAn das Landgericht München I\n\n\
                  Klage der Nordlicht GmbH gegen die Brandt AG - Beklagte -";
        assert!(gate(de, "ENTWURF Klageschrift"));
        assert!(gate(
            "Betreff: Brandt\n\nanbei unser Klageentwurf für die Kanzlei, Verfahren vor dem Arbeitsgericht.",
            "Klageentwurf",
        ));
        // A consumer's draft complaint or a seminar exercise is no pleading.
        assert!(!gate(
            "Here is my draft complaint to the airline about the lost suitcase. Dear customer service, my bag never arrived.",
            "draft complaint",
        ));
        assert!(!gate(
            "Seminar Zivilprozess: Übung Klageentwurf, zum Beispiel für das Landgericht.",
            "Klageentwurf",
        ));
    }

    #[test]
    fn nda_and_trade_secret_documents_hold_in_de_and_en() {
        assert!(nda(
            "Subject: Drawings\n\nThe drawings are covered by our NDA. Do not forward them; the prototype is non-public.",
            "NDA",
        ));
        assert!(nda(
            "Betreff: Kiefer\n\nDie Rezeptur ist ein Geschäftsgeheimnis, bitte nicht weiterleiten.\n\nViele Grüße",
            "Geschäftsgeheimnis",
        ));
        assert!(nda(
            "PRESSEMITTEILUNG\nSperrfrist: 12. November 2026\nBis zur Veröffentlichung nicht öffentlich.",
            "Sperrfrist",
        ));
    }

    #[test]
    fn m_and_a_documents_hold_and_explanations_do_not() {
        let class = is_m_and_a_document;
        assert!(holds(
            class,
            "Subject: Project Falcon - term sheet\n\nDear all, purchase price 410m, exclusivity for the buyer.",
            "term sheet",
        ));
        assert!(holds(
            class,
            "Betreff: Projekt Falke\n\nAbsichtserklärung: Kaufpreis für die Zielgesellschaft 410 Mio.",
            "Absichtserklärung",
        ));
        assert!(!holds(
            class,
            "Due diligence refers to the review a buyer does before an acquisition, for example in a data room.",
            "Due diligence",
        ));
        assert!(!holds(
            class,
            "Wir ziehen um, der Datenraum im Keller bleibt zu.",
            "Datenraum"
        ));
        // Encyclopedia prose is dense with deal terms; its hedges are counter-context.
        assert!(!holds(
            class,
            "In a merger the buyer usually signs a share purchase agreement; closing often \
             follows merger control, and warranties such as tax indemnities typically survive.",
            "share purchase agreement",
        ));
    }

    #[test]
    fn law_texts_court_decisions_and_templates_are_no_nda_document() {
        assert!(!nda(
            "Im Sinne dieses Gesetzes ist Geschäftsgeheimnis eine Information mit angemessenen Geheimhaltungsmaßnahmen.",
            "Geschäftsgeheimnis",
        ));
        assert!(!nda(
            "The court held that the customer list was not a trade secret.",
            "trade secret",
        ));
        assert!(!nda(
            "## NDA template\n\nThis Non-Disclosure Agreement is made between [Party A] and [Party B].",
            "Non-Disclosure Agreement",
        ));
        assert!(!nda(
            "// embargo period for vulnerability reports",
            "embargo period"
        ));
    }

    #[test]
    fn board_minutes_hold_and_job_ads_do_not() {
        let class = is_board_minutes_document;
        assert!(holds(
            class,
            "Minutes of the Meeting of the Supervisory Board\nDate: 14 October\nQuorum confirmed; \
             the board unanimously approved the sale.",
            "Minutes of the Meeting of the Supervisory Board",
        ));
        assert!(holds(
            class,
            "Protokoll der Aufsichtsratssitzung\nDatum: 14.10.\nDer Aufsichtsrat ist beschlussfähig \
             und stimmt einstimmig zu.",
            "Protokoll der Aufsichtsratssitzung",
        ));
        assert!(!holds(
            class,
            "Job: Board Secretary. Your tasks: draft board minutes and support the chair of the \
             supervisory board. We are looking for a lawyer.",
            "board minutes",
        ));
        // A governance policy names minutes and resolutions without being one.
        assert!(!holds(
            class,
            "The discussion shall be documented in Board minutes. A majority vote of the \
             directors is required, and approved transactions follow this policy.",
            "Board minutes",
        ));
        assert!(!holds(
            class,
            "## Muster Umlaufbeschluss\n\nDer Aufsichtsrat beschließt einstimmig: [Text]. Platzhalter.",
            "Umlaufbeschluss",
        ));
    }

    #[test]
    fn newsletters_policies_job_ads_and_shop_notes_are_no_nda_document() {
        // Letter words and a generic term (publication, signed) without a
        // secrecy duty name an NDA or embargo but are none.
        assert!(!nda(
            "Subject: Weekly news digest\n\nDear readers, a court in Delaware ruled in a trade secret case \
             that the former engineer may not reuse proprietary source code. Please share this issue.",
            "trade secret",
        ));
        assert!(!nda(
            "Betreff: Wochenüberblick\n\nHallo zusammen, die Reform des GeschGehG tritt nach der \
             Veröffentlichung im Bundesgesetzblatt in Kraft. Viele Grüße",
            "GeschGehG",
        ));
        assert!(!nda(
            "# Security Policy\n\nPlease report vulnerabilities by mail. Reports stay under embargo until a fix \
             is released and the announcement is published.",
            "embargo until",
        ));
        assert!(!nda(
            "Hi! We are hiring a backend engineer. Candidates sign an NDA before the take-home task; the offer \
             is signed after two interviews.",
            "NDA",
        ));
        assert!(!nda(
            "Hallo, bitte beachten Sie die Sperrfrist für Rücksendungen: Der Empfänger erhält die Erstattung \
             nach 14 Tagen. Viele Grüße, Ihr Shop-Team",
            "Sperrfrist",
        ));
    }

    #[test]
    fn policies_on_confidentiality_are_no_nda_document() {
        // A policy names the NDA its volunteers sign and the confidentiality
        // of user data; bare confidentiality is no secrecy duty of a document.
        assert!(!nda(
            "Subject: Access policy\n\nPlease note: volunteers with access to user data sign the NDA. \
             Confidentiality of user data is a core value; the recipient of a request reviews it.",
            "NDA",
        ));
        assert!(!nda(
            "Re: Data access\n\nDear volunteers, before access you sign the NDA. We take confidentiality \
             seriously and publish the announcement of every policy change.",
            "NDA",
        ));
    }

    #[test]
    fn articles_on_ndas_are_no_nda_document() {
        // Encyclopedic prose has the parties, confidential information and
        // signatures of an NDA but no letter, agreement or record form.
        let en = "A non-disclosure agreement sets out which information the parties keep secret and for \
                  how long. In a one-way arrangement only the disclosing party shares material; the \
                  receiving party promises to protect the confidential information and to use it for the \
                  stated purpose alone. Mutual agreements are signed when both sides exchange plans, as in \
                  joint ventures and research partnerships.\n\nCourts enforce such clauses but will not \
                  uphold an NDA that hides a crime. Because proving what a recipient learned is hard, firms \
                  also mark files as proprietary and limit access to staff with a need to know.";
        assert!(!nda(en, "non-disclosure agreement"));
        assert!(!nda(en, "NDA"));
        let de = "Eine Geheimhaltungsvereinbarung legt fest, welche Informationen die Parteien vertraulich \
                  behandeln. Bei einseitigen Verträgen gibt nur die offenlegende Partei Unterlagen heraus, die \
                  empfangende Partei verpflichtet sich zur Geheimhaltung. Gegenseitige Verträge werden \
                  unterzeichnet, wenn beide Seiten Pläne austauschen.\n\nVerstöße sichert oft eine \
                  Vertragsstrafe ab. Gerichte erkennen Informationen nur an, wenn ihr Inhaber angemessene \
                  Geheimhaltungsmaßnahmen nachweist.";
        assert!(!nda(de, "Geheimhaltungsvereinbarung"));
    }

    #[test]
    fn articles_on_supply_contracts_are_no_contract_document() {
        // Long prose names customer, supplier, fees, term and liability
        // without the form of a contract, letter or record.
        let en = "Manufacturers buy parts under a supply agreement that runs for several years. The \
                  customer commits to minimum volumes and the supplier accepts price caps for late delivery. \
                  Fees are indexed to raw material costs.\n\nSuch contracts also allocate liability for \
                  defective goods, while safety laws keep some claims open whatever term was agreed. \
                  Termination rights apply on insolvency, and confidentiality clauses protect drawings. \
                  Carmakers held thousands of these contracts, worth over USD 500 billion, between them.";
        assert!(!contract(en, "supply agreement"));
        let de = "Hersteller beziehen Bauteile über einen Liefervertrag mit mehrjähriger Laufzeit. Der Kunde \
                  sagt Mindestmengen zu, der Lieferant akzeptiert Preisobergrenzen. Die Vergütung folgt den \
                  Rohstoffpreisen.\n\nDie Haftung für fehlerhafte Teile ist oft begrenzt. Ein Recht zur \
                  Kündigung besteht vor allem bei Insolvenz, Klauseln zur Vertraulichkeit schützen \
                  Zeichnungen. Zwischen Herstellern und Zulieferern bestehen Verträge über Milliarden EUR.";
        assert!(!contract(de, "Liefervertrag"));
    }

    #[test]
    fn a_contract_needs_parties_remuneration_term_and_confidentiality() {
        let en = "Master Services Agreement between Contoso (the Customer) and Fabrikam (the Supplier). \
                  Fees: EUR 18,400 per month. Term: 24 months. Confidentiality applies.";
        assert!(contract(en, "Master Services Agreement"));
        let de = "Rahmenvertrag zwischen Nordlicht (Auftraggeber) und Brandt (Auftragnehmer). \
                  Vergütung: 7.800 EUR monatlich. Laufzeit: 36 Monate. Vertraulichkeit gilt.";
        assert!(contract(de, "Rahmenvertrag"));
        // A title with only two contract terms is a mention, not a contract.
        assert!(!contract(
            "We negotiate the framework agreement; let's discuss the term and the fees on Monday.",
            "framework agreement",
        ));
    }

    #[test]
    fn a_signed_contract_cover_letter_with_the_four_elements_holds() {
        let en = "Dear Sir or Madam,\nattached is the signed framework agreement. Northwind is the customer, \
                  remuneration EUR 5,000 per month, the term is two years and confidentiality is agreed.\n\n\
                  Kind regards";
        assert!(contract(en, "framework agreement"));
        let de = "Sehr geehrte Damen und Herren,\nanbei der unterschriebene Rahmenvertrag. Auftraggeber ist die \
                  Nordlicht GmbH, die Vergütung beträgt 5.000 EUR monatlich, die Laufzeit zwei Jahre, \
                  Vertraulichkeit ist vereinbart.\n\nMit freundlichen Grüßen";
        assert!(contract(de, "Rahmenvertrag"));
    }

    #[test]
    fn contract_roles_without_the_other_elements_are_no_contract_document() {
        assert!(!contract(
            "Subject: Kickoff notes\n\nWe walked through the framework agreement: customer, supplier, contractor \
             and licensee roles, plus liability.",
            "framework agreement",
        ));
        assert!(!contract(
            "Betreff: Protokoll\n\nZum Rahmenvertrag: Rollen von Auftraggeber, Auftragnehmer, Lieferant und \
             Kunde, dazu die Haftung.",
            "Rahmenvertrag",
        ));
    }

    #[test]
    fn contract_templates_and_law_texts_are_no_contract_document() {
        assert!(!contract(
            "## Mustervertrag Rahmenvertrag\n\nzwischen [Firma] (nachfolgend Auftraggeber) und [Partner] \
             (nachfolgend Auftragnehmer). Vergütung: [Betrag] EUR. Laufzeit: [Monate].",
            "Rahmenvertrag",
        ));
        assert!(!contract(
            "(1) Durch den Kaufvertrag wird der Verkäufer verpflichtet, dem Käufer die Sache zu übergeben. \
             (2) Der Käufer zahlt dem Verkäufer den vereinbarten Kaufpreis; die Haftung regelt das Gesetz.",
            "Kaufvertrag",
        ));
    }
}
