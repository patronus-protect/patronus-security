// SPDX-License-Identifier: GPL-3.0-only
//! G-PROSE (G06): chats, tickets and mails hand a credential over after its
//! noun, at the end of a line up to one line further. `dlp_prose_password`
//! reports the value after a password noun, `dlp_prose_secret` after a secret
//! or token noun. Words, references, placeholders, examples, hashes, URLs,
//! dates and the noun in encyclopedia or law prose are no findings. Values
//! are synthetic.

use std::sync::OnceLock;

use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult};

fn scan(text: &str) -> SecurityScanResult {
    static SCANNER: OnceLock<SecurityGateway> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            )
        })
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

/// The rule that reports `value` (not suppressed by another rule).
fn reporting_rule(result: &SecurityScanResult, value: &str) -> Option<String> {
    let span = result.evidence_spans.iter().find(|span| span.text == value)?;
    result.layers[0]
        .details
        .get("matched_rules")?
        .as_array()?
        .iter()
        .find(|rule| {
            rule.get("suppressed_by").is_none()
                && rule["start"].as_u64() == Some(span.start as u64)
                && rule["end"].as_u64() == Some(span.end as u64)
        })
        .and_then(|rule| rule["rule_id"].as_str().map(str::to_owned))
}

fn assert_reported(text: &str, rule_id: &str, value: &str) {
    let result = scan(text);
    assert!(
        result.evidence_spans.iter().any(|span| span.text == value),
        "{rule_id}: missing {value:?} in {text:?}: {:#?}",
        result.evidence_spans
    );
    let rules: Vec<_> = result.layers[0].details["matched_rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule.get("suppressed_by").is_none())
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        rules.iter().any(|rule| rule == rule_id),
        "{rule_id}: rule did not report {value:?} in {text:?}: {rules:?} ({:?})",
        reporting_rule(&result, value)
    );
}

fn assert_silent(texts: &[&str]) {
    let reported: Vec<_> = texts
        .iter()
        .filter_map(|text| {
            let result = scan(text);
            (!result.evidence_spans.is_empty()).then(|| {
                let spans: Vec<_> = result.evidence_spans.iter().map(|s| &s.text).collect();
                format!("{text:?} -> {spans:?}")
            })
        })
        .collect();
    assert!(reported.is_empty(), "false positives: {reported:#?}");
}

#[test]
fn password_handed_over_in_chats_tickets_and_mails() {
    let cases = [
        (
            "[08:15] lena.s: Kurze Frage: Wie lautet der Wert für „Datenbank-Passwort“ in der Testumgebung? 🙏\n[08:17] daniel.r: Krbpqtz3658*\n[08:17] daniel.r: Aber bitte nur lokal verwenden.\n",
            "Krbpqtz3658*",
        ),
        (
            "[09:41] maria.k: anyone have the database password for the staging box? CI is red\n[09:43] tom.w: here you go: Wjslscq0382%\n[09:43] tom.w: please don't paste it anywhere else\n",
            "Wjslscq0382%",
        ),
        (
            "Note from reporter: the job still uses the old database password. Current value in the config: FUQoUXNMiLPyRH.yAx\n",
            "FUQoUXNMiLPyRH.yAx",
        ),
        (
            "Seit dem Update schlägt der Abruf fehl. Laut Konfiguration hinterlegt (Datenbank-Passwort): sdkrf-UuV7xbwiTFQz\nBitte prüfen.\n",
            "sdkrf-UuV7xbwiTFQz",
        ),
        (
            "Hi team,\n\nas discussed, here is the database password for the reporting job:\n\nyPaXtx3Wzc9-DGfN1q\n\nThanks,\nAlex\n",
            "yPaXtx3Wzc9-DGfN1q",
        ),
        (
            "Hallo zusammen,\n\nanbei die Zugangsdaten für den Abschlusslauf (Kennwort):\n\nZllrhzj9796?\n\nViele Grüße\n",
            "Zllrhzj9796?",
        ),
        (
            "Hi Jonas, hier deine Zugangsdaten für das Testsystem: pruefer / Svogpkf0881!\n",
            "Svogpkf0881!",
        ),
        (
            "Your login credentials for the test portal: tester / Yinrwcs9781%\n",
            "Yinrwcs9781%",
        ),
    ];
    for (text, value) in cases {
        assert_reported(text, "dlp_prose_password", value);
    }
}

#[test]
fn secret_and_token_handed_over_in_chats_tickets_and_mails() {
    let cases = [
        (
            "[09:41] maria.k: anyone have the client secret for the staging box?\n[09:43] tom.w: here you go: BmGmOdEW0ixO5vKcNBPwL66q\n",
            "BmGmOdEW0ixO5vKcNBPwL66q",
        ),
        (
            "Laut Konfiguration hinterlegt (Client-Secret): 69275e292564a6fa9870e7631f7fa3499b5d99fa\nBitte prüfen.\n",
            "69275e292564a6fa9870e7631f7fa3499b5d99fa",
        ),
        (
            "anbei wie besprochen die Zugangsdaten für den Abschlusslauf (Dienst-Secret):\n\nb5970eb6b7b70c7e63349a4a3385bb1f797b06fa\n\nBitte nach dem Lauf löschen.\n",
            "b5970eb6b7b70c7e63349a4a3385bb1f797b06fa",
        ),
        (
            "Note from reporter: the job still uses the old CSRF token. Current value in the config: o8spc0Vb3kQyLm2Xr9TzWd4NfHa1uJe6KcPq7Ys5GgE\n",
            "o8spc0Vb3kQyLm2Xr9TzWd4NfHa1uJe6KcPq7Ys5GgE",
        ),
        (
            "Hi team,\n\nhere is the service secret for the reporting job:\n\noSJZqBdybUNn2bYMPZSZ0O1q\n\nThanks\n",
            "oSJZqBdybUNn2bYMPZSZ0O1q",
        ),
    ];
    for (text, value) in cases {
        assert_reported(text, "dlp_prose_secret", value);
    }
}

#[test]
fn credential_nouns_in_prose_without_a_value_are_silent() {
    assert_silent(&[
        // Encyclopedia and law prose.
        "Ein Passwort ist eine Zeichenfolge zur Authentifizierung.\nSiehe auch: Passwortmanager\n",
        "§ 5 Abs. 2: Das Kennwort ist geheim zu halten und nach Kenntnis Dritter zu ändern.\nFundstelle: BGBl.2024-I-117\n",
        "A password is a secret string of characters used to confirm a user's identity.\nISBN: 978-0-13-468599-1\n",
        "Section 3(b): the password shall be changed every 90 days.\nEffective date: 2024-07-01\n",
        "Die PIN-Eingabe wird nach drei Fehlversuchen gesperrt.\nQuelle: Bundesamt für Sicherheit, Version 2.4.1\n",
        "The token has expired.\nStatus: ExpiredToken\n",
        // References, placeholders and documented examples.
        "[08:15] lena.s: Wie lautet das Datenbank-Passwort?\n[08:17] daniel.r: steht als $DB_PASSWORD in der .env\n",
        "Laut Konfiguration hinterlegt (Client-Secret): ${CLIENT_SECRET} aus der Umgebung\n",
        "The client secret rotates nightly; the job reads it from:\n${CLIENT_SECRET}\n",
        "anbei die Zugangsdaten (Client-Secret):\n\nYOUR_CLIENT_SECRET_HERE\n",
        "[09:41] maria.k: anyone have the database password?\n[09:43] tom.w: here you go: changeme\n",
        "here is the client secret for the reporting job:\n\ndeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
        "here is the database password for the reporting job:\n\nEXAMPLEKEYEXAMPLEK\n",
        // Hashes, addresses, URLs, dates and times.
        "Laut Konfiguration hinterlegt (Passwort-Hash): 5f4dcc3b5aa765d61d8327deb882cf99\n",
        "Passwort vergessen? Kontakt:\nservicedesk@example.de\n",
        "Forgot your password? See the guide:\nhttps://example.com/help/reset-password\n",
        "Passwortänderung geplant am:\n14.09.2026\n",
        "Password reset requested\nDate: Mon, 14 Sep 2026 09:12:44 +0200\n",
    ]);
}
