// SPDX-License-Identifier: GPL-3.0-only
//! T23: credentials in the data rows of SQL dumps (mysqldump, MariaDB,
//! pg_dump, SQLite). A key field of a settings row binds the next quoted
//! field of its tuple; a column whose name passes the key gate binds its
//! field in every row of a one-line or multi-row `INSERT` and of a
//! `COPY … FROM stdin` block. The value gates and the value-shape filter
//! apply; a `password_hash` column binds nothing, a container column
//! (`zugangsdaten`) binds only through the row's label. Values are synthetic.

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

/// The unsuppressed `matched_rules` entries: rule id and structure format.
fn matched_rules(result: &SecurityScanResult) -> Vec<(String, Option<String>)> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("suppressed_by").is_none())
                .map(|rule| {
                    (
                        rule["rule_id"].as_str().unwrap().to_owned(),
                        rule.get("structure")
                            .and_then(|format| format.as_str())
                            .map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `template` with `values` at `{0}`, `{1}` … yields exactly one span per
/// value, each by `rule_id` from a SQL row.
fn assert_values(template: &str, values: &[&str], rule_id: &str) {
    let mut text = template.to_owned();
    for (index, value) in values.iter().enumerate() {
        text = text.replace(&format!("{{{index}}}"), value);
    }
    let mut expected: Vec<_> = values
        .iter()
        .map(|value| {
            let start = text[..text.find(value).unwrap()].chars().count();
            (start, start + value.chars().count(), value.to_string())
        })
        .collect();
    expected.sort();
    let result = scan(&text);
    let mut spans: Vec<_> = result
        .evidence_spans
        .iter()
        .map(|span| (span.start_char, span.end_char, span.text.clone()))
        .collect();
    spans.sort();
    assert_eq!(spans, expected, "{rule_id}: {text:?}");
    assert_eq!(
        matched_rules(&result),
        vec![(rule_id.to_owned(), Some("sql".to_owned())); values.len()],
        "{rule_id}: {text:?}"
    );
}

fn assert_silent(texts: &[&str]) {
    for text in texts {
        let result = scan(text);
        assert!(
            result.evidence_spans.is_empty(),
            "expected no DLP finding in {text:?}, got {:?}",
            result
                .evidence_spans
                .iter()
                .map(|span| (&span.label, &span.text))
                .collect::<Vec<_>>()
        );
    }
}

const TOKEN_A: &str = "Tz8Wm4K93RVqe7xAb2Lp";
const TOKEN_B: &str = "Kx7pQ2vL9rT4mN8bW3sD";
const PASSWORD: &str = "Xzvk;fov8032?";

#[test]
fn settings_rows_bind_the_field_after_a_key_field() {
    assert_values(
        "LOCK TABLES `integration_settings` WRITE;\nINSERT INTO `integration_settings` VALUES (1,'export.endpoint','https://api.example.com/v2','2026-09-14 08:12:44'),(2,'service_secret','{0}','2026-09-14 08:12:44'),(3,'export.batch_size','500','2026-09-14 08:12:44');\nUNLOCK TABLES;\n",
        &[TOKEN_A],
        "dlp_generic_credential_assignment",
    );
    assert_values(
        "INSERT INTO `mandanten_konfiguration` (`mandant`, `schluessel`, `wert`) VALUES ('0001','waehrung','EUR'),('0001','db_passwort','{0}');\n",
        &[PASSWORD],
        "dlp_password_assignment",
    );
    assert_values(
        "INSERT INTO public.schnittstellen (id, bezeichnung, zugangsdaten, geaendert_am) VALUES (1, 'Lieferantenportal – Client-Secret', '{0}', '2026-09-14 07:55:10');\n",
        &[TOKEN_A],
        "dlp_generic_credential_assignment",
    );
    assert_values(
        "PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nINSERT INTO app_settings VALUES('csrf_token','{0}','2026-08-30T10:02:11Z');\nCOMMIT;\n",
        &["W3PXXW2ew-wuyXmtdYw7EMrApsQbXyLvvvhrIQXC4PU"],
        "dlp_csrf_token",
    );
    assert_values(
        "INSERT INTO public.schnittstellen (id, bezeichnung, zugangsdaten) VALUES (1, 'Lieferantenportal – Passwort-Hash', '{0}');\n",
        &["27d4f0247d7527b42daef76e64a4db31"],
        "dlp_password_hash",
    );
}

#[test]
fn key_columns_bind_their_field_in_every_row() {
    assert_values(
        "INSERT INTO public.accounts (id, login, password, created_at) VALUES (1, 'svc-export', '{0}', '2026-09-14 07:55:10');\n",
        &[PASSWORD],
        "dlp_password_assignment",
    );
    assert_values(
        "INSERT INTO benutzer (id, anmeldename, kennwort) VALUES\n  (1, 'lager', '{0}'),\n  (2, 'versand', NULL),\n  (3, 'einkauf', '{1}');\n",
        &[PASSWORD, "Qm7;Lp2vN9x!"],
        "dlp_password_assignment",
    );
    assert_values(
        "COPY public.integrations (id, name, client_secret) FROM stdin;\n1\tcrm\t{0}\n2\terp\t{1}\n3\tlegacy\t\\N\n\\.\n",
        &[TOKEN_A, TOKEN_B],
        "dlp_generic_credential_assignment",
    );
}

#[test]
fn dumps_without_credentials_stay_silent() {
    assert_silent(&[
        // Schema DDL holds no rows.
        "CREATE TABLE users (\n  id int NOT NULL,\n  password varchar(255) NOT NULL,\n  api_token varchar(64) DEFAULT NULL\n);\n",
        // A password_hash column of user digests.
        "INSERT INTO `users` (`id`, `email`, `password_hash`) VALUES (1,'ana@example.com','5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');\n",
        // A hex digest in a password column is the stored hash.
        "INSERT INTO `admins` (`admin_id`, `username`, `password`) VALUES\n(1, 'admin', '0b9c2625dc21ef05f6ad4ddf47c5f203837aa32c');\n",
        // Settings keys that name no credential.
        "INSERT INTO `settings` VALUES (1,'export.batch_size','500'),(2,'token_ttl','3600'),(3,'secret_rotation_days','90');\n",
        // SQL that code builds in a string.
        "cursor.execute(\"INSERT INTO users (login, password) VALUES ('svc', '%s')\" % password)\n",
        "def upgrade():\n    op.execute(\n        \"INSERT INTO einstellungen (name, wert) VALUES ('smtp_passwort', '%s')\"\n        % os.environ['SMTP_PASSWORT']\n    )\n",
        // References, expressions, UUIDs and placeholders in dump rows.
        "INSERT INTO app_settings VALUES('api_secret','${API_SECRET}','2026-08-30T10:02:11Z');\n",
        "INSERT INTO public.schnittstellen (id, bezeichnung, zugangsdaten) VALUES (2, 'Lagerverwaltung – Client-Secret', current_setting('erp.client_secret'));\n",
        "INSERT INTO sessions (id, user_id, refresh_token) VALUES (1, 42, '3f2b8c1e-7d4a-4f6b-9e2c-1a5d8b7c9e0f');\n",
        "INSERT INTO public.schnittstellen (id, bezeichnung, zugangsdaten) VALUES (1, 'Lieferantenportal – Access-Token', 'Bearer HIER_AUTHORIZATION_EINTRAGEN');\n",
        "INSERT INTO public.schnittstellen (id, bezeichnung, zugangsdaten) VALUES (1, 'Lieferantenportal – Börsen-API-Secret', 'KUCOIN_API_SECRET=BITTE_AENDERN');\n",
        // A test fill in a settings row.
        concat!(
            "INSERT INTO `integration_settings` VALUES (2,'plaid_secret','access-",
            "production-12345678-1234-1234-1234-123456789012','2026-09-14 08:12:44');\n"
        ),
        // A container column binds only through the row's label.
        "INSERT INTO public.schnittstellen (id, bezeichnung, zugangsdaten) VALUES (1, 'Lieferantenportal – Korrelations-ID', 'tGSxJ-MWP2Rzgb4k80z7_U2sr8ng-WW');\n",
    ]);
}
