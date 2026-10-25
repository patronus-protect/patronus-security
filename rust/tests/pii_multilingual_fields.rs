// SPDX-License-Identifier: GPL-3.0-only
//! FR/ES/IT/NL field names for the existing anchor rules (T26, TRIAGE 2026-W43 bucket 12).
//!
//! Gretel's FR/ES/IT/NL rows hide most of their field-bound values behind field names that
//! only DE/EN rules knew: `Fecha de Nacimiento`, `Data di Nascita`, `date de naissance`,
//! `klantnummer`, `bankrekeningnummer`, `code de sécurité`. The anchor rules for date of
//! birth, customer and employee ID, account number, CVV, US SSN, passport and username now
//! accept those field names in `strict`, as text before the value and as a structural key
//! (K04). The K03 lexicon (`anchor_lexicons/pii.json`) carries the same terms per language
//! for the scored modes. Validators are unchanged: the vectors below pass or fail the
//! validator or checksum they name, whatever the language of the field name.

use std::collections::BTreeMap;

use patronus_ark::detectors::pii::{
    context::{self, SUPPORT_LEXICON},
    score::{Context, PiiMode},
    validators,
};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::Value;

const LANGUAGES: [&str; 4] = ["fr", "es", "it", "nl"];

fn scan(text: &str, mode: PiiMode) -> SecurityScanResult {
    let scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.set_execution_gates(ScanGateMatrix {
        pii_mode: mode,
        ..Default::default()
    });
    scanner
        .scan_category(SecurityCategory::Pii, text)
        .into_iter()
        .find(|result| result.model == "native:pii")
        .expect("native PII result must be present")
}

/// `(label, text)` of every evidence span in `strict`.
fn strict_spans(text: &str) -> Vec<(String, String)> {
    scan(text, PiiMode::Strict)
        .evidence_spans
        .iter()
        .map(|span| (span.label.clone(), span.text.clone()))
        .collect()
}

/// Rule ids that matched in `strict` with the value text they matched.
fn strict_rules(text: &str) -> Vec<(String, String)> {
    let result = scan(text, PiiMode::Strict);
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| {
            let start = rule["start_byte"].as_u64().unwrap() as usize;
            let end = rule["end_byte"].as_u64().unwrap() as usize;
            (
                rule["rule_id"].as_str().unwrap().to_owned(),
                text[start..end].to_owned(),
            )
        })
        .collect()
}

fn assert_reports(rule_id: &str, label: &str, text: &str, value: &str) {
    let rules = strict_rules(text);
    assert!(
        rules
            .iter()
            .any(|(rule, found)| rule == rule_id && found == value),
        "{rule_id} must report {value:?} in {text:?}: {rules:?}"
    );
    assert!(
        strict_spans(text).contains(&(label.to_owned(), value.to_owned())),
        "{label} span {value:?} missing in {text:?}"
    );
}

fn assert_silent(label: &str, text: &str) {
    let spans = strict_spans(text);
    assert!(
        spans.iter().all(|(found, _)| found != label),
        "no {label} expected in {text:?}: {spans:?}"
    );
}

/// `(rule_id, label, language, text, value)`: a field name of the language before the value.
const FIELD_NAMES: &[(&str, &str, &str, &str, &str)] = &[
    // Date of birth.
    (
        "pii_date_of_birth",
        "DOB",
        "fr",
        "Date de naissance : 14/07/1985",
        "14/07/1985",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "fr",
        "Mme Lefèvre, née le 03.11.1979, réside à Lyon.",
        "03.11.1979",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "fr",
        "Né(e) le 21/06/1990",
        "21/06/1990",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "es",
        "Fecha de Nacimiento: 23/08/1975",
        "23/08/1975",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "es",
        "La titular, nacida el 05/09/1990, reside en Sevilla.",
        "05/09/1990",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "it",
        "Data di Nascita: 09/11/1973",
        "09/11/1973",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "it",
        "Il sig. Rossi, nato il 15/04/1981, risiede a Torino.",
        "15/04/1981",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "nl",
        "Geboortedatum: 15-12-1992",
        "15-12-1992",
    ),
    (
        "pii_date_of_birth",
        "DOB",
        "nl",
        "Mevrouw De Vries, geboren op 02-03-1987, woont in Utrecht.",
        "02-03-1987",
    ),
    // Customer ID.
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "fr",
        "Numéro de client : CL-480215",
        "CL-480215",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "fr",
        "Référence client : RC-77310",
        "RC-77310",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "fr",
        "ID de client : CUST69497153",
        "CUST69497153",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "fr",
        "Identifiant de client : CUST71999884",
        "CUST71999884",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "es",
        "Número de cliente: CLI-302948",
        "CLI-302948",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "es",
        "ID de cliente: C-55821",
        "C-55821",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "it",
        "Codice cliente: CC-448210",
        "CC-448210",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "it",
        "ID cliente: V772-Z5548-Ev",
        "V772-Z5548-Ev",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "nl",
        "Klantnummer: KL-501873",
        "KL-501873",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "nl",
        "Klant-id: Bl-87084",
        "Bl-87084",
    ),
    (
        "pii_customer_id",
        "CUSTOMER_ID",
        "nl",
        "Ik ben Rune Johansson, klantnummer CUST14229662.",
        "CUST14229662",
    ),
    // Employee ID.
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "fr",
        "Identifiant d'employé : E-204518",
        "E-204518",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "fr",
        "Numéro d’employé : 88-1042",
        "88-1042",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "es",
        "Número de empleado: E-118204",
        "E-118204",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "es",
        "Número de Identificación del Empleado: Vn-21203",
        "Vn-21203",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "it",
        "ID dipendente: D-55012",
        "D-55012",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "it",
        "Matricola dipendente: 004512",
        "004512",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "nl",
        "Personeelsnummer: P-30411",
        "P-30411",
    ),
    (
        "pii_employee_id",
        "EMPLOYEE_ID",
        "nl",
        "Medewerker-id: H3806711",
        "H3806711",
    ),
    // Account number.
    (
        "pii_financial_account_number",
        "FINANCIAL_ACCOUNT_NUMBER",
        "fr",
        "Numéro de compte : 00012345678",
        "00012345678",
    ),
    (
        "pii_financial_account_number",
        "FINANCIAL_ACCOUNT_NUMBER",
        "fr",
        "Numéro de compte bancaire : CPT-0091827",
        "CPT-0091827",
    ),
    (
        "pii_financial_account_number",
        "FINANCIAL_ACCOUNT_NUMBER",
        "es",
        "Número de cuenta: CTA-20481937",
        "CTA-20481937",
    ),
    (
        "pii_financial_account_number",
        "FINANCIAL_ACCOUNT_NUMBER",
        "it",
        "Numero di conto: CT-0091827",
        "CT-0091827",
    ),
    (
        "pii_financial_account_number",
        "FINANCIAL_ACCOUNT_NUMBER",
        "nl",
        "Bankrekeningnummer: 619867267",
        "619867267",
    ),
    (
        "pii_financial_account_number",
        "FINANCIAL_ACCOUNT_NUMBER",
        "nl",
        "Aanvraag Lena Nilsson, bankrekeningnummer 167619700",
        "167619700",
    ),
    // CVV next to a Luhn-valid card.
    (
        "pii_credit_card_cvv",
        "CREDITCARD_CVV",
        "fr",
        "Carte 4111 1111 1111 1111, code de sécurité de la carte de crédit : 737",
        "737",
    ),
    (
        "pii_credit_card_cvv",
        "CREDITCARD_CVV",
        "fr",
        "Carte 4111 1111 1111 1111, cryptogramme visuel : 214",
        "214",
    ),
    (
        "pii_credit_card_cvv",
        "CREDITCARD_CVV",
        "es",
        "Tarjeta 5555 5555 5555 4444, código de seguridad de la tarjeta: 318",
        "318",
    ),
    (
        "pii_credit_card_cvv",
        "CREDITCARD_CVV",
        "it",
        "Carta 4111 1111 1111 1111, codice di sicurezza della carta di credito: 552",
        "552",
    ),
    (
        "pii_credit_card_cvv",
        "CREDITCARD_CVV",
        "nl",
        "Creditcard 5555 5555 5555 4444, creditcard-beveiligingscode is 713",
        "713",
    ),
    (
        "pii_credit_card_cvv",
        "CREDITCARD_CVV",
        "nl",
        "Creditcard 5555 5555 5555 4444\nCreditcard veiligheidscode: 799",
        "799",
    ),
    // US SSN.
    (
        "pii_ssn_us",
        "SSN",
        "fr",
        "Numéro de sécurité sociale : 536-90-4421",
        "536-90-4421",
    ),
    (
        "pii_ssn_us",
        "SSN",
        "es",
        "Número de seguro social: 412-56-7834",
        "412-56-7834",
    ),
    (
        "pii_ssn_us",
        "SSN",
        "it",
        "Numero di previdenza sociale: 219-45-7781",
        "219-45-7781",
    ),
    (
        "pii_ssn_us",
        "SSN",
        "nl",
        "Sociaal zekerheidsnummer: 523-41-9087",
        "523-41-9087",
    ),
    // Passport (DE document alphabet).
    (
        "pii_passport_number_de",
        "PASSPORT_NUMBER",
        "fr",
        "Numéro de passeport : C01X00T47",
        "C01X00T47",
    ),
    (
        "pii_passport_number_de",
        "PASSPORT_NUMBER",
        "es",
        "Número de pasaporte: P4K7R2M9X",
        "P4K7R2M9X",
    ),
    (
        "pii_passport_number_de",
        "PASSPORT_NUMBER",
        "es",
        "con pasaporte número 141867246",
        "141867246",
    ),
    (
        "pii_passport_number_de",
        "PASSPORT_NUMBER",
        "it",
        "Numero di passaporto: YN8K4T7C2",
        "YN8K4T7C2",
    ),
    (
        "pii_passport_number_de",
        "PASSPORT_NUMBER",
        "nl",
        "Paspoortnummer: NXR4C7T19",
        "NXR4C7T19",
    ),
    (
        "pii_passport_number_de",
        "PASSPORT_NUMBER",
        "nl",
        "Reisdocumentnummer: 140679109",
        "140679109",
    ),
    // Username after an explicit assignment.
    (
        "pii_username",
        "USERNAME",
        "fr",
        "Nom d'utilisateur : claire.martin85",
        "claire.martin85",
    ),
    (
        "pii_username",
        "USERNAME",
        "es",
        "Nombre de usuario: jgarcia_88",
        "jgarcia_88",
    ),
    (
        "pii_username",
        "USERNAME",
        "it",
        "Nome utente: lbianchi77",
        "lbianchi77",
    ),
    (
        "pii_username",
        "USERNAME",
        "nl",
        "Gebruikersnaam: vidal1842",
        "vidal1842",
    ),
];

#[test]
fn anchor_rules_accept_fr_es_it_nl_field_names_in_strict() {
    let mut languages = BTreeMap::<&str, usize>::new();
    for (rule_id, label, language, text, value) in FIELD_NAMES {
        assert_reports(rule_id, label, text, value);
        *languages.entry(language).or_default() += 1;
    }
    for language in LANGUAGES {
        assert!(
            languages.get(language).copied().unwrap_or_default() >= 8,
            "{language}"
        );
    }
}

#[test]
fn structural_keys_in_fr_es_it_nl_bind_the_rule_in_strict() {
    for (rule_id, label, text, value) in [
        (
            "pii_customer_id",
            "CUSTOMER_ID",
            r#"{"numero_client": "CL-99120"}"#,
            "CL-99120",
        ),
        (
            "pii_date_of_birth",
            "DOB",
            r#"{"fecha_de_nacimiento": "12/10/1980"}"#,
            "12/10/1980",
        ),
        (
            "pii_customer_id",
            "CUSTOMER_ID",
            "nome;codice_cliente\nRossi;CC-77125",
            "CC-77125",
        ),
        (
            "pii_customer_id",
            "CUSTOMER_ID",
            r#"{"klant_id": "KL-77120"}"#,
            "KL-77120",
        ),
        (
            "pii_financial_account_number",
            "FINANCIAL_ACCOUNT_NUMBER",
            "<rekeningnummer>RK-55012</rekeningnummer>",
            "RK-55012",
        ),
        (
            "pii_username",
            "USERNAME",
            r#"{"gebruikersnaam": "jdevries"}"#,
            "jdevries",
        ),
    ] {
        assert_reports(rule_id, label, text, value);
    }
}

#[test]
fn fr_es_it_nl_field_names_do_not_relax_validators() {
    for (label, text) in [
        // Impossible calendar dates.
        ("DOB", "Date de naissance : 31/02/1985"),
        ("DOB", "Fecha de nacimiento: 30/02/1990"),
        ("DOB", "Data di nascita: 32/01/1975"),
        ("DOB", "Geboortedatum: 29-02-1991"),
        // SSN ranges that are never issued.
        ("SSN", "Numéro de sécurité sociale : 000-12-3456"),
        ("SSN", "Número de seguro social: 666-12-3456"),
        ("SSN", "Numero di previdenza sociale: 123-00-4567"),
        ("SSN", "Sociaal zekerheidsnummer: 523-41-0000"),
        // Identifiers without a digit or all zeros.
        ("CUSTOMER_ID", "Numéro de client : inconnu"),
        ("FINANCIAL_ACCOUNT_NUMBER", "Número de cuenta: 000000000"),
        ("FINANCIAL_ACCOUNT_NUMBER", "Rekeningnummer: 0000000"),
        ("EMPLOYEE_ID", "ID dipendente: sconosciuto"),
        // Letters outside the document alphabet, and not the UK form of two letters and
        // seven digits (B-UK).
        ("PASSPORT_NUMBER", "Numéro de passeport : AB123456Q"),
        ("PASSPORT_NUMBER", "Paspoortnummer: QQ12345Q7"),
        // A CVV is reported only next to a Luhn-valid card number.
        ("CREDITCARD_CVV", "Code de sécurité de la carte : 737"),
        (
            "CREDITCARD_CVV",
            "Carta 4111 1111 1111 1112, codice di sicurezza della carta: 552",
        ),
        (
            "CREDITCARD_CVV",
            "Creditcard 5555 5555 5555 4445, creditcard-beveiligingscode: 713",
        ),
    ] {
        assert_silent(label, text);
    }
}

#[test]
fn fr_es_it_nl_prose_without_assignment_is_no_finding() {
    for (label, text) in [
        // Usernames need `:`, `=` or `#` after a FR/ES/IT/NL field name.
        (
            "USERNAME",
            "Choisissez un nom d'utilisateur pour votre compte.",
        ),
        ("USERNAME", "Introduzca su nombre de usuario y contraseña."),
        ("USERNAME", "Il nome utente è obbligatorio."),
        ("USERNAME", "Kies een gebruikersnaam voor uw account."),
        // Generic security codes are not card verification codes.
        (
            "CREDITCARD_CVV",
            "Carte 4111 1111 1111 1111. Code de sécurité du bâtiment : 4821",
        ),
        (
            "CREDITCARD_CVV",
            "Creditcard 5555 5555 5555 4444. Beveiligingscode van de app: 9921",
        ),
        // Order numbers and expiry dates are not customer IDs or passport numbers.
        ("CUSTOMER_ID", "Numéro de commande : CMD-480215"),
        ("CUSTOMER_ID", "Número de pedido: PED-302948"),
        (
            "PASSPORT_NUMBER",
            "Fecha de caducidad del pasaporte: 14/05/2030",
        ),
        ("PASSPORT_NUMBER", "Vervaldatum paspoort: 30-06-2032"),
    ] {
        assert_silent(label, text);
    }
}

#[test]
fn iban_checksum_decides_under_fr_es_it_nl_account_names() {
    // Valid MOD-97 vectors: the account finding on the IBAN value is secondary evidence
    // (T07); the IBAN is the primary finding.
    for text in [
        "Numéro de compte : FR7630006000011234567890189",
        "Número de cuenta: ES9121000418450200051332",
        "Numero di conto: IT60X0542811101000000123456",
        "Rekeningnummer: NL91ABNA0417164300",
    ] {
        let value = text.rsplit(' ').next().unwrap();
        assert!(validators::mod97(value), "{value}");
        let result = scan(text, PiiMode::Strict);
        let spans: Vec<_> = result
            .evidence_spans
            .iter()
            .map(|span| (span.label.as_str(), span.text.as_str()))
            .collect();
        assert!(spans.contains(&("IBAN", value)), "{text}: {spans:?}");
        let secondary = result.layers[0].details["secondary_evidence"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            secondary
                .iter()
                .any(|entry| entry["label"] == "FINANCIAL_ACCOUNT_NUMBER"
                    && entry["reason"] == "iban_value"),
            "{text}: {secondary:?}"
        );
    }
    // One changed digit fails MOD-97: no IBAN, the account finding stays primary.
    for text in [
        "Numéro de compte : FR7630006000011234567890180",
        "Número de cuenta: ES9121000418450200051333",
        "Numero di conto: IT60X0542811101000000123457",
        "Rekeningnummer: NL91ABNA0417164301",
    ] {
        let value = text.rsplit(' ').next().unwrap();
        assert!(!validators::mod97(value), "{value}");
        let spans = strict_spans(text);
        assert!(
            spans.iter().all(|(label, _)| label != "IBAN"),
            "{text}: {spans:?}"
        );
        assert!(
            spans.contains(&("FINANCIAL_ACCOUNT_NUMBER".to_owned(), value.to_owned())),
            "{text}: {spans:?}"
        );
    }
}

#[test]
fn validator_vectors_are_language_independent() {
    for (valid, invalid) in [
        ("536-90-4421", "000-12-3456"),
        ("412-56-7834", "666-12-3456"),
    ] {
        assert!(validators::us_ssn(valid) && !validators::us_ssn(invalid));
    }
    assert!(validators::calendar_date("15-12-1992") && !validators::calendar_date("29-02-1991"));
    assert!(validators::calendar_date("29-02-1992"));
    assert!(validators::de_document_number("C01X00T47"));
    assert!(!validators::de_document_number("AB1234567"));
    assert!(validators::luhn("4111 1111 1111 1111") && !validators::luhn("4111 1111 1111 1112"));
}

fn lexicon() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../ark-core/src/detectors/anchor_lexicons/pii.json"
    ))
    .unwrap()
}

/// Lexicon ids of the anchor rules this task extends.
const T26_LEXICON: &[&str] = &[
    "pii.date_of_birth",
    "pii.customer_identifier",
    "pii.employee_identifier",
    "pii.bank_account",
    "pii.card_verification",
    "pii.social_insurance_number",
    "pii.passport",
    "pii.user_account",
];

#[test]
fn k03_lexicon_has_fr_es_it_nl_terms_for_the_anchor_rules() {
    let entries = lexicon();
    for id in T26_LEXICON {
        let entry = entries
            .iter()
            .find(|entry| entry["id"] == *id)
            .unwrap_or_else(|| panic!("{id} missing"));
        for language in LANGUAGES {
            let words = entry[language].as_array().map_or(0, Vec::len);
            assert!(words > 0, "{id} has no {language} terms");
        }
        assert!(
            SUPPORT_LEXICON.iter().any(|(_, ids)| ids.contains(id)),
            "{id} supports no label"
        );
    }
    // Every entry keeps the DE/EN schema; FR/ES/IT/NL are optional lists of strings.
    for entry in &entries {
        for language in ["en", "de", "shared"] {
            assert!(entry[language].is_array(), "{}: {language}", entry["id"]);
        }
        for language in LANGUAGES {
            assert!(
                entry.get(language).is_none_or(Value::is_array),
                "{}: {language}",
                entry["id"]
            );
        }
    }
}

#[test]
fn context_engine_reads_fr_es_it_nl_terms() {
    // Proximity (scored modes): a FR/ES/IT/NL field name before the value supports the label.
    for (text, value, label) in [
        (
            "Date de naissance du client 14/07/1985",
            "14/07/1985",
            "DOB",
        ),
        (
            "Klantnummer van de aanvrager KL-501873",
            "KL-501873",
            "CUSTOMER_ID",
        ),
        (
            "Numero di conto del cliente CT-0091827",
            "CT-0091827",
            "FINANCIAL_ACCOUNT_NUMBER",
        ),
        (
            "Nombre de usuario del titular jgarcia_88",
            "jgarcia_88",
            "USERNAME",
        ),
    ] {
        let start = text.find(value).unwrap();
        let evidence = context::evidence(text, (start, start + value.len()), label);
        assert!(evidence.context.supports(), "{text}: {evidence:?}");
    }
    // Structure (K04): a FR/ES/IT/NL key is a field name of its value.
    for (text, value, label) in [
        (r#"{"klantnummer": "KL-55120"}"#, "KL-55120", "CUSTOMER_ID"),
        (r#"{"data_di_nascita": "09/11/1973"}"#, "09/11/1973", "DOB"),
        (
            r#"{"numero_de_pasaporte": "P4K7R2M9X"}"#,
            "P4K7R2M9X",
            "PASSPORT_NUMBER",
        ),
        (
            r#"{"bankrekeningnummer": "619867267"}"#,
            "619867267",
            "FINANCIAL_ACCOUNT_NUMBER",
        ),
    ] {
        let start = text.find(value).unwrap();
        assert_eq!(
            context::key_context(text, (start, start + value.len()), label),
            Some(Context::Field),
            "{text}"
        );
    }
}

#[derive(Deserialize)]
struct Probe {
    rule_id: String,
    #[serde(default)]
    multilingual: BTreeMap<String, String>,
}

#[test]
fn rule_fixture_probes_fr_es_it_nl_field_names() {
    let probes: Vec<Probe> =
        serde_json::from_str(include_str!("fixtures/l1_bilingual_rules.json")).unwrap();
    let mut probed = 0;
    for probe in probes.iter().filter(|probe| !probe.multilingual.is_empty()) {
        let languages: Vec<_> = probe.multilingual.keys().map(String::as_str).collect();
        assert_eq!(languages, ["es", "fr", "it", "nl"], "{}", probe.rule_id);
        for text in probe.multilingual.values() {
            let rules = strict_rules(text);
            assert!(
                rules.iter().any(|(rule, _)| *rule == probe.rule_id),
                "{} unreachable in {text:?}: {rules:?}",
                probe.rule_id
            );
        }
        probed += 1;
    }
    assert!(probed >= 8, "only {probed} FR/ES/IT/NL probes");
}
