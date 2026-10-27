// SPDX-License-Identifier: GPL-3.0-only
//! Quality pass for contact and account fields (Q-CONTACT, quality floor 2026-10-25).
//!
//! The 2026-10-24 snapshot lists username, customer and employee ID and date of birth
//! below F1 80. The misses are field-bound values that the rules did not bind:
//!
//! - **Username:** `user=<value>` in a log or query line, a form printed as a table
//!   without edge pipes (`Benutzername | jwagner`); `login issues` is no assignment and
//!   a name after `Account Name:` (`John Doe`, `ACME Inc.`) is no account.
//! - **Date of birth:** the ISO order (`1980-11-26`), `geb.`, `born on`, `date of birth
//!   of`, `DateOfBirth=`, a no-break space before the value, ordinal days (`18th December
//!   1983`) and the months of FR/ES/IT/NL (`26 de marzo de 1990`).
//! - **Employee ID:** `EMP821659`, a short uppercase prefix with digits (`PN 201033`),
//!   `ist`/`lautet`, a field closing a parenthesis (`(Personalnummer): E11397`).
//! - **Customer ID:** `a customer ID of …`, `the customer with the ID …`, an example
//!   opener (`customer_id (e.g., …)`, `Kundennummer (z. B. …)`).
//!
//! Validators are not loosened: an impossible date stays negative in every order.

use patronus_ark::detectors::pii::{score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

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

/// `(rule id, matched value, carrier)` of every matched rule.
fn rules(text: &str, mode: PiiMode) -> Vec<(String, String, Option<String>)> {
    scan(text, mode).layers[0]
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
                rule["structure"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

/// `rule_id` reports exactly `value` in `strict` and `balanced`.
fn assert_reports(rule_id: &str, text: &str, value: &str) {
    for mode in [PiiMode::Strict, PiiMode::Balanced] {
        let found = rules(text, mode);
        assert!(
            found
                .iter()
                .any(|(rule, matched, _)| rule == rule_id && matched == value),
            "{mode:?}: {rule_id} must report {value:?} in {text:?}: {found:?}"
        );
    }
}

/// No span of `label` in `strict`, `balanced` or `recall`.
fn assert_silent(label: &str, text: &str) {
    for mode in [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall] {
        let spans: Vec<_> = scan(text, mode)
            .evidence_spans
            .into_iter()
            .filter(|span| span.label == label)
            .map(|span| span.text)
            .collect();
        assert!(spans.is_empty(), "{mode:?}: {text:?} -> {label} {spans:?}");
    }
}

#[test]
fn numeric_birth_dates_accept_the_iso_order_with_valid_dates_only() {
    for valid in [
        "1980-11-26",
        "1926-01-20",
        "2000-02-29",
        "1951/09/12",
        "21.02.1971",
    ] {
        assert!(validators::calendar_date(valid), "{valid}");
    }
    for invalid in [
        "1985-02-30",
        "1985-13-01",
        "1900-02-29",
        "0000-00-00",
        "2001-02-29",
        "31.04.1990",
    ] {
        assert!(!validators::calendar_date(invalid), "{invalid}");
    }
}

#[test]
fn written_birth_dates_read_six_languages_and_ordinals() {
    for valid in [
        "26 de marzo de 1990",
        "8 de octubre de 1915",
        "1er mars 1990",
        "29 février 2000",
        "9 novembre 1973",
        "15 december 1992",
        "18th December 1983",
        "21. Februar 1971",
        "May 5, 1990",
    ] {
        assert!(validators::written_calendar_date(valid), "{valid}");
    }
    for invalid in [
        "31 de abril de 1990",
        "29 février 2001",
        "31 settembre 1980",
        "30 februari 1992",
        "31st February 1990",
        "14 Smarch 1985",
    ] {
        assert!(!validators::written_calendar_date(invalid), "{invalid}");
    }
}

#[test]
fn birth_date_fields_bind_iso_dates_and_new_connectives() {
    for (text, value) in [
        ("Patient: Sophia Davies, DOB 1980-11-26", "1980-11-26"),
        (
            "Aloisia Karz, date of birth: 1926-01-20, joined in 1995.",
            "1926-01-20",
        ),
        (
            "Annette Henck-Bruder, who was born on 2014-12-09.",
            "2014-12-09",
        ),
        (
            "with a date of birth of 2005-04-24, residing here",
            "2005-04-24",
        ),
        ("<address>DateOfBirth=1951-09-12</address>", "1951-09-12"),
        (
            "the date of birth (e.g., 2003-06-14) is not shared",
            "2003-06-14",
        ),
        ("Patientin: Anna Schulz, geb. 03.01.1980", "03.01.1980"),
        ("Geburtsdatum:\u{a0}1972-07-29", "1972-07-29"),
        ("Date de naissance\u{a0}: 01/01/1980", "01/01/1980"),
    ] {
        assert_reports("pii_date_of_birth", text, value);
    }
    for (text, value) in [
        ("Date of Birth: 18th December 1983", "18th December 1983"),
        (
            "Patient: Felix Schäfer, geb. 18. September 1974",
            "18. September 1974",
        ),
        (
            "con fecha de nacimiento del 26 de marzo de 1990 y",
            "26 de marzo de 1990",
        ),
        (
            "Fecha de nacimiento: 15 de mayo de 1998",
            "15 de mayo de 1998",
        ),
        ("Né le 1er mars 1990 à Lyon", "1er mars 1990"),
        ("Data di nascita: 9 novembre 1973", "9 novembre 1973"),
        ("Geboortedatum: 15 december 1992", "15 december 1992"),
    ] {
        assert_reports("pii_date_of_birth_written_day_first", text, value);
    }
}

#[test]
fn birth_date_lookalikes_stay_silent() {
    for text in [
        "Anna Schulz, geb. Müller",
        "Geburtsdatum: 1985-02-30",
        "Date of birth: 2024-13-01",
        "Lieferdatum: 1985-06-12",
        "Shipped on 2014-12-09.",
        "Born on time, the release shipped on 2014-12-09.",
        "Date of Birth: 31st February 1990",
        "Fecha de nacimiento: 31 de abril de 1990",
        "DOB: 0000-00-00",
    ] {
        assert_silent("DOB", text);
    }
}

#[test]
fn a_form_printed_as_a_table_binds_its_key_cells() {
    let text = "Name, Vorname | Harrison, Olivia\nGeburtsdatum | 21. Februar 1971\nBenutzername | jwagner\nPersonalnummer | PN 201033\nKundennummer | KD-88231\n";
    for (rule_id, value) in [
        ("pii_date_of_birth_written_day_first", "21. Februar 1971"),
        ("pii_username", "jwagner"),
        ("pii_employee_id", "PN 201033"),
        ("pii_customer_id", "KD-88231"),
    ] {
        for mode in [PiiMode::Strict, PiiMode::Balanced] {
            assert!(
                rules(text, mode).iter().any(|(rule, matched, carrier)| {
                    rule == rule_id && matched == value && carrier.as_deref() == Some("table")
                }),
                "{mode:?}: {rule_id} {value}"
            );
        }
    }
    // One line is no form, and a key cell holds no digit.
    assert_silent("DOB", "Geburtsdatum | 21. Februar 1971");
    assert_silent("USERNAME", "Benutzername | jwagner");
    assert_silent("USERNAME", "Team 7 | jwagner\nTeam 8 | ohughes");
}

#[test]
fn usernames_in_log_and_query_assignments() {
    for (text, value) in [
        (
            "08:59:59 WARN auth failed user=oeztuerk90 src=host-7",
            "oeztuerk90",
        ),
        (
            "08:34:55 WARN auth failed user=matteo.colombo status=401",
            "matteo.colombo",
        ),
        (
            "GET /api/profile?user=lena.koehler&lang=de HTTP/1.1",
            "lena.koehler",
        ),
        ("Username: JSmith Password: hidden", "JSmith"),
        ("Account name: svc-build-7", "svc-build-7"),
    ] {
        assert_reports("pii_username", text, value);
    }
}

#[test]
fn username_lookalikes_stay_silent() {
    for text in [
        "Troubleshoot the login issues for her accounts.",
        "Login isoliert die Sitzung.",
        "Account Name: John Doe",
        "Account Name: ACME Inc.",
        "Account Name: AI-Generated Synthetic Data",
        "Benutzername: Nicolas Lebrun",
        "Run the job with user=root",
        "Skript läuft mit user=${USER}",
        "The sender's username is provided in tag 50.",
        "superuser=jdoe42",
    ] {
        assert_silent("USERNAME", text);
    }
}

#[test]
fn employee_ids_with_prefix_forms_and_connectives() {
    for (text, value) in [
        ("Personalnummer: PN 201033", "PN 201033"),
        ("Employee ID: PN 912167", "PN 912167"),
        ("Als Mitarbeiternummer ist E76592 hinterlegt.", "E76592"),
        (
            "Ich bestätige folgende Angabe (Personalnummer): E11397.",
            "E11397",
        ),
        (
            "Gestionnaire : Marc D. Smith (employé ID : C7335360)",
            "C7335360",
        ),
        ("Staff number: HR 204518", "HR 204518"),
    ] {
        assert_reports("pii_employee_id", text, value);
    }
    for (text, value) in [
        (
            "Subject: Hardware Failure - Shelia S. Sharp (EMP821659)",
            "EMP821659",
        ),
        ("Shipper's Reference: EMP194928", "EMP194928"),
        ("Mitarbeiter: Gordon Williams (EMP79383)", "EMP79383"),
        ("Kennung EMP-SYN-2048", "EMP-SYN-2048"),
    ] {
        assert_reports("pii_employee_id_prefixed", text, value);
    }
    for text in [
        "Personalnummer: ab 2025",
        "Employee ID: PN",
        "Employee ID: pending",
        "Sensor TEMP12345 offline",
        "emp12345 im Log",
        "EMP1234 reserviert",
        "EMP12345678901 archived",
        ":28C:031025GB22EMP818721",
    ] {
        assert_silent("EMPLOYEE_ID", text);
    }
}

#[test]
fn customer_ids_after_prose_connectives_and_example_openers() {
    for (text, value) in [
        (
            "a customer with a customer ID of C736-6988-309 (\"Customer\")",
            "C736-6988-309",
        ),
        (
            "the customer with the ID Im-29924, named Elaine",
            "Im-29924",
        ),
        (
            "Delivery for the customer with ID A6262C921 from",
            "A6262C921",
        ),
        (
            "such as customer_id (e.g., C352-3474-967), name",
            "C352-3474-967",
        ),
        (
            "Ihre Kundennummer (z. B. J8382610), Ihren Namen",
            "J8382610",
        ),
        (
            "le customer_id (par exemple, A7437434) et le nom",
            "A7437434",
        ),
        ("Die Kundennummer lautet KD-55120.", "KD-55120"),
        ("Die Kundennummer ist C190661-Yu.", "C190661-Yu"),
    ] {
        assert_reports("pii_customer_id", text, value);
    }
    for text in [
        "the customer ID of the account holder",
        "the customer with the ID card",
        "customer_id (e.g., see the export)",
        "The order ID of A6262C921 shipped.",
        "Kundennummer ist unbekannt",
        "Bestellnummer (z. B. J8382610)",
    ] {
        assert_silent("CUSTOMER_ID", text);
    }
}
