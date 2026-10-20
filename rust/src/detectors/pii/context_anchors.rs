// SPDX-License-Identifier: GPL-3.0-only
//! Lexical field anchors reported in PII `details` for Dynamic PII.
use crate::detectors::anchors::AnchorPattern;

/// Context facts that are useful for Dynamic PII but are not findings by
/// themselves. A field name such as `Diagnose` says what a nearby value may be;
/// it does not prove that the text already contains a sensitive value.
pub(super) static PII_ANCHOR_PATTERNS: &[AnchorPattern] = &[
    AnchorPattern {
        anchor_kind: "lexical",
        category: "person_identity",
        strength: "weak",
        pattern: r"(?i)\b(?:vollständige[rs]?[ \t]+name|komplette[rs]?[ \t]+name|vor[-_ \t]?name|ruf[-_ \t]?name|zweite[rs]?[ \t]+vorname|nach[-_ \t]?name|familien[-_ \t]?name|geburts[-_ \t]?name|mädchen[-_ \t]?name|patienten[-_ \t]?name|kunden[-_ \t]?name|mitarbeiter[-_ \t]?name|name|first[-_ \t]+name|given[-_ \t]+name|middle[-_ \t]+name|last[-_ \t]+name|family[-_ \t]+name|full[-_ \t]+name|legal[-_ \t]+name|preferred[-_ \t]+name|maiden[-_ \t]+name|birth[-_ \t]+name|surname|patient[-_ \t]+name|customer[-_ \t]+name|employee[-_ \t]+name)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "person_role",
        strength: "weak",
        pattern: r"(?i)\b(?:ansprechpartner(?:in)?|kontaktperson|notfallkontakt|kontoinhaber(?:in)?|versicherte[rs]?|mitglied|patient(?:in)?|bewerber(?:in)?|kandidat(?:in)?|beschäftigte[rs]?|arbeitnehmer(?:in)?|mitarbeiter(?:in)?|kunde|kundin|contact[-_ \t]+person|emergency[-_ \t]+contact|account[-_ \t]+holder|policy[-_ \t]+holder|insured[-_ \t]+person|insured|member|patient|applicant|candidate|employee|worker|customer|client)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "contact",
        strength: "medium",
        pattern: r"(?i)\b(?:e[-_ ]?mail(?:[-_ ]?adresse)?|mail[-_ ]?adresse|phone(?:[ \t]+number)?|telephone|mobile(?:[ \t]+number)?|telefon(?:[-_ ]?(?:nummer|nr))?|tel(?:efon)?[-_ ]?nr|festnetz(?:[-_ ]?nummer)?|mobil(?:telefon|funk)?(?:[-_ ]?(?:nummer|nr))?|handy(?:[-_ ]?(?:nummer|nr))?|fax(?:[-_ ]?(?:nummer|nr))?|durchwahl|kontakt[-_ ]?nummer|email[-_ \t]+address|email[-_ \t]+id|phone[-_ \t]+number|telephone[-_ \t]+number|contact[-_ \t]+number|mobile[-_ \t]+(?:number|phone)|cell(?:ular)?[-_ \t]+(?:number|phone)|cellphone|home[-_ \t]+phone|work[-_ \t]+phone|fax[-_ \t]+number|extension|emergency[-_ \t]+contact)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "address",
        strength: "weak",
        pattern: r"(?i)\b(?:anschrift|wohn[-_ ]?(?:anschrift|adresse)|melde[-_ ]?(?:anschrift|adresse)|post[-_ ]?(?:anschrift|adresse)|korrespondenz[-_ ]?adresse|zustell[-_ ]?adresse|rechnungs[-_ ]?adresse|liefer[-_ ]?adresse|geschäfts[-_ ]?adresse|heimat[-_ ]?adresse|adresse|straße|strasse|str\.|haus[-_ ]?(?:nummer|nr)|post[-_ ]?leitzahl|plz|postfach|wohnort|address|street[-_ \t]+address|street|house[-_ \t]+number|postal[-_ \t]+code|postcode|zip(?:[-_ \t]+code)?|home[-_ \t]+address|residential[-_ \t]+address|permanent[-_ \t]+address|current[-_ \t]+address|physical[-_ \t]+address|mailing[-_ \t]+address|correspondence[-_ \t]+address|billing[-_ \t]+address|shipping[-_ \t]+address|delivery[-_ \t]+address|business[-_ \t]+address|p\.?[ \t]*o\.?[-_ \t]+box|city|town)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "date_of_birth",
        strength: "strong",
        pattern: r"(?i)\b(?:geburts[-_ ]?datum|geb(?:urts)?[.-]*[ \t]*dat(?:um)?|geburtstag|geboren(?:[-_ \t]+am)?|date[-_ \t]+of[-_ \t]+birth|birth[-_ \t]*date|birthday|born(?:[-_ \t]+on)?|d\.?[ \t]*o\.?[ \t]*b\.?)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "person_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:personal[-_ ]?(?:nummer|nr)|mitarbeiter[-_ ]?(?:nummer|nr|id)|personal[-_ ]?id|beschäftigten[-_ ]?(?:nummer|id)|kund(?:en)?[-_ ]?(?:nummer|nr|id)|debitor(?:en)?[-_ ]?(?:nummer|nr|id)?|patienten[-_ ]?(?:nummer|nr|id)|krankenhaus[-_ ]?(?:nummer|id)|mrn|medical[-_ \t]+record[-_ \t]+(?:number|no)|health[-_ \t]+record[-_ \t]+(?:number|id)|matrikel[-_ ]?(?:nummer|nr)|immatrikulations[-_ ]?nummer|sch(?:ü|ue)ler[-_ ]?(?:nummer|nr|id)|student(?:en)?[-_ ]?(?:id|nummer|nr)|bewerber[-_ ]?(?:nummer|nr|id)|kandidaten[-_ ]?(?:nummer|id)|employee[-_ \t]+(?:id|number|no)|personnel[-_ \t]+(?:id|number|no)|staff[-_ \t]+(?:id|number|no)|customer[-_ \t]+(?:id|number|no)|client[-_ \t]+(?:id|number|no)|debtor[-_ \t]+(?:id|number|no)|patient[-_ \t]+(?:id|number|no)|student[-_ \t]+(?:id|number|no)|pupil[-_ \t]+(?:id|number|no)|applicant[-_ \t]+(?:id|number|no)|application[-_ \t]+(?:id|number|no)|candidate[-_ \t]+(?:id|number|no))\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "account_identifier",
        strength: "medium",
        pattern: r"(?i)\b(?:benutzer[-_ ]?name|benutzer[-_ ]?kennung|benutzer[-_ ]?konto|login[-_ ]?(?:name|kennung)|konto[-_ ]?name|username|user[-_ \t]+name|user[-_ \t]+id|login[-_ \t]+name|login[-_ \t]+id|account[-_ \t]+name|account[-_ \t]+id)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "payment_card",
        strength: "strong",
        pattern: r"(?i)\b(?:cvv2?|cvc2?|karten[-_ ]?prüf[-_ ]?(?:nummer|ziffer)|prüf[-_ ]?ziffer|sicherheits[-_ ]?code|karten[-_ ]?ablauf[-_ ]?(?:datum|date)|ablauf[-_ ]?datum|gültig[-_ ]+bis|card[-_ \t]+verification[-_ \t]+(?:value|code)|card[-_ \t]+security[-_ \t]+code|security[-_ \t]+code|expiry(?:[-_ \t]+date)?|expiration(?:[-_ \t]+date)?|expires)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "financial_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:bic|swift(?:[-_ ]?code)?|bankleitzahl|blz|konto[-_ ]?(?:nummer|nr)|bankkonto[-_ ]?(?:nummer|nr)?|depot[-_ ]?(?:nummer|nr)|account[-_ \t]+number|bank[-_ \t]+account(?:[-_ \t]+number)?|brokerage[-_ \t]+account(?:[-_ \t]+number)?|routing[-_ \t]+number)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "government_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:steuer[-_ ]?(?:id|identifikations[-_ ]?nummer|nummer|nr)|id[-_ ]?nr|st[-_ ]?nr|sozialversicherungs[-_ ]?(?:nummer|nr)|sv[-_ ]?nr|rentenversicherungs[-_ ]?(?:nummer|nr)|rv[-_ ]?nr|krankenversicherungs[-_ ]?(?:nummer|nr)|versicherten[-_ ]?(?:nummer|nr)|kv[-_ ]?nr|kvnr|lanr|lebenslange[-_ \t]+arzt[-_ ]?(?:nummer|nr)|arzt[-_ ]?(?:nummer|nr)|reisepass[-_ ]?(?:nummer|nr)|pass[-_ ]?(?:nummer|nr)|personalausweis[-_ ]?(?:nummer|nr)|ausweis[-_ ]?(?:nummer|nr)|führerschein[-_ ]?(?:nummer|nr)|fahrerlaubnis[-_ ]?(?:nummer|nr)|ssn|social[-_ \t]+security[-_ \t]+(?:number|no)|nino|national[-_ \t]+insurance[-_ \t]+(?:number|no)|passport[-_ \t]+(?:number|no)|identity[-_ \t]+card[-_ \t]+(?:number|no)|id[-_ \t]+card[-_ \t]+(?:number|no)|driver'?s?[-_ \t]+licen[cs]e[-_ \t]+(?:number|no))\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "vehicle_identifier",
        strength: "strong",
        pattern: r"(?i)\b(?:kfz[-_ ]?(?:kennzeichen|nummer)?|kraftfahrzeug[-_ ]?kennzeichen|kennzeichen|nummern[-_ ]?schild|amtliches[-_ ]?kennzeichen|vehicle[-_ \t]+registration(?:[-_ \t]+(?:number|no))?|registration[-_ \t]+(?:number|no)|license[-_ \t]+plate|licence[-_ \t]+plate|number[-_ \t]+plate)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "medical",
        strength: "medium",
        pattern: r"(?i)\b(?:patienten[-_ ]?akte|kranken[-_ ]?akte|gesundheits[-_ ]?akte|elektronische[ \t]+patientenakte|epa|arzt[-_ ]?brief|entlassungs[-_ ]?(?:brief|bericht)|behandlungs[-_ ]?(?:bericht|plan)|behandlung|therapie|verschreibung|verordnung|rezept|symptom(?:e)?|allergie(?:n)?|diagnose(?:n)?|anamnes[ei]|medikation|medikament(?:e)?|befund(?:e)?|labor[-_ ]?(?:wert|ergebnis|befund)(?:e|se)?|icd(?:[-_ ]?10)?|krankheit|erkrankung|gesundheits[-_ ]?zustand|patient[-_ \t]+record|medical[-_ \t]+record|health[-_ \t]+record|electronic[-_ \t]+health[-_ \t]+record|ehr|electronic[-_ \t]+medical[-_ \t]+record|emr|clinical[-_ \t]+note|discharge[-_ \t]+summary|medical[-_ \t]+history|health[-_ \t]+condition|diagnos(?:is|es)|treatment[-_ \t]+plan|treatment|therapy|prescription|symptoms?|allerg(?:y|ies)|lab(?:oratory)?[-_ \t]+(?:result|report|value)s?|medication(?:s)?)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "special_category",
        strength: "medium",
        pattern: r"(?i)\b(?:religion|religions[-_ ]?zugehörigkeit|glaubens[-_ ]?richtung|konfession|weltanschauung|politische[-_ ]+(?:meinung|einstellung)|parteizugehörigkeit|partei[-_ ]?mitgliedschaft|gewerkschafts[-_ ]?(?:zugehörigkeit|mitgliedschaft)|behinderung|schwerbehinderung|sexuelle[-_ ]+(?:orientierung|identität)|geschlechts[-_ ]?identität|ethnische[-_ ]+(?:herkunft|zugehörigkeit)|rassische[-_ ]?herkunft|genetische[-_ ]+daten|biometrische[-_ ]+daten|religious[-_ \t]+beliefs?|religious[-_ \t]+affiliation|philosophical[-_ \t]+beliefs?|political[-_ \t]+opinions?|political[-_ \t]+affiliation|party[-_ \t]+membership|trade[-_ \t]+union(?:[-_ \t]+membership)?|disability[-_ \t]+status|sexual[-_ \t]+orientation|gender[-_ \t]+identity|ethnic[-_ \t]+origin|racial[-_ \t]+origin|genetic[-_ \t]+data|biometric[-_ \t]+data)\b",
    },
    AnchorPattern {
        anchor_kind: "lexical",
        category: "employment_compensation",
        strength: "weak",
        pattern: r"(?i)\b(?:gehalt|grund[-_ ]?gehalt|brutto[-_ ]?gehalt|netto[-_ ]?gehalt|jahres[-_ ]?gehalt|monats[-_ ]?gehalt|vergütung|gesamt[-_ ]?vergütung|entgelt|bezüge|besoldung|lohn|stunden[-_ ]?lohn|provision|prämie|bonus|ziel[-_ ]?bonus|lohn[-_ ]?abrechnung|gehalts[-_ ]?abrechnung|entgelt[-_ ]?abrechnung|personal[-_ ]?akte|salary|base[-_ \t]+salary|gross[-_ \t]+salary|net[-_ \t]+salary|annual[-_ \t]+salary|monthly[-_ \t]+salary|compensation|total[-_ \t]+compensation|remuneration|wages?|hourly[-_ \t]+rate|commission|bonus|target[-_ \t]+bonus|payroll|pay[-_ \t]*slip|salary[-_ \t]+statement|pay[-_ \t]+grade|stock[-_ \t]+options?|restricted[-_ \t]+stock[-_ \t]+units?|rsu|personnel[-_ \t]+file|employee[-_ \t]+file)\b",
    },
];
