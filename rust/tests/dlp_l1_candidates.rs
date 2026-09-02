use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use patronus_ark::{
    detectors::dlp::dlp::DlpPipeline, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};

fn scan(text: &str) -> SecurityScanResult {
    let mut scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    scanner.warmup().unwrap();
    scanner
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

fn assert_span(result: &SecurityScanResult, label: &str, value: &str) {
    let span = result
        .evidence_spans
        .iter()
        .find(|span| span.label == label && span.text == value)
        .unwrap_or_else(|| panic!("missing {label} span {value:?}: {result:#?}"));
    assert_eq!(
        result
            .evidence_spans
            .iter()
            .filter(|candidate| candidate.label == label && candidate.text == value)
            .count(),
        1
    );
    assert_eq!(span.text, value);
}

fn anchors(result: &SecurityScanResult) -> &[serde_json::Value] {
    result.layers[0].details["l1_anchors"]
        .as_array()
        .expect("DLP L1 anchors must be exposed as an array")
}

macro_rules! dlp_golden {
    ($name:ident, $label:literal, $text:expr, $value:expr) => {
        #[test]
        fn $name() {
            assert_span(&scan($text), $label, $value);
        }
    };
}

dlp_golden!(
    detects_openai_api_key,
    "API_KEY",
    "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345",
    "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
);
dlp_golden!(
    detects_password_assignment,
    "CREDENTIAL",
    "passwort = Sommer2026!",
    "Sommer2026!"
);
dlp_golden!(
    detects_connection_string_password,
    "CREDENTIAL",
    "postgres://dbuser:s3cr3t-value@db.internal/app",
    "s3cr3t-value"
);
dlp_golden!(
    detects_url_credential,
    "CREDENTIAL",
    "https://example.test?token=actual-secret",
    "actual-secret"
);
dlp_golden!(
    detects_aws_secret_key,
    "CLOUD_KEY",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
);
dlp_golden!(
    detects_generic_api_key_assignment,
    "CREDENTIAL",
    "api_key = ark-test-value-8842-actual",
    "ark-test-value-8842-actual"
);
dlp_golden!(
    detects_bearer_token,
    "SECRET_TOKEN",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
    "eyJhbGciOiJIUzI1NiJ9.payload.signature"
);
dlp_golden!(
    detects_basic_auth,
    "CREDENTIAL",
    "Authorization: Basic YWRhOnNlY3JldC04ODQy",
    "YWRhOnNlY3JldC04ODQy"
);
dlp_golden!(
    detects_signed_url,
    "CREDENTIAL",
    "https://storage.test/a?X-Amz-Signature=0123456789abcdef0123456789abcdef",
    "0123456789abcdef0123456789abcdef"
);
dlp_golden!(
    detects_session_cookie,
    "CREDENTIAL",
    "Cookie: theme=dark; sessionid=abcDEF0123456789xyz",
    "abcDEF0123456789xyz"
);
dlp_golden!(
    detects_csrf_token,
    "SECRET_TOKEN",
    "X-CSRF-Token: csrf_0123456789abcdef",
    "csrf_0123456789abcdef"
);
dlp_golden!(
    detects_password_hash,
    "PASSWORD_HASH",
    "password_hash = $2b$12$abcdefghijklmnopqrstuuVIXU7y0N7XmxmCN5QYGl1R9vO2",
    "$2b$12$abcdefghijklmnopqrstuuVIXU7y0N7XmxmCN5QYGl1R9vO2"
);

dlp_golden!(
    detects_de_vat_id,
    "dlp.de.vat_id",
    "USt-IdNr.: DE 123 456 789",
    "DE 123 456 789"
);
dlp_golden!(
    detects_de_commercial_register_id,
    "dlp.de.commercial_register_number",
    "Amtsgericht Berlin HRB 12345",
    "HRB 12345"
);
dlp_golden!(
    detects_de_bsnr,
    "dlp.de.facility_number_bsnr",
    "BSNR: 123456789",
    "123456789"
);
dlp_golden!(
    detects_case_id,
    "dlp.record.case_id",
    "Fallnummer: CASE-2026/481",
    "CASE-2026/481"
);
dlp_golden!(
    detects_english_case_id,
    "dlp.record.case_id",
    "Case ID CASE-2026/481",
    "CASE-2026/481"
);
dlp_golden!(
    detects_contract_id,
    "dlp.record.contract_id",
    "Vertragsnummer V-2026-8842",
    "V-2026-8842"
);
dlp_golden!(
    detects_english_contract_id,
    "dlp.record.contract_id",
    "Contract ID CONTRACT-8842",
    "CONTRACT-8842"
);
dlp_golden!(
    detects_claim_id,
    "dlp.record.claim_id",
    "Schadennummer: SCH-44119",
    "SCH-44119"
);
dlp_golden!(
    detects_english_claim_id,
    "dlp.record.claim_id",
    "Claim ID CLAIM-44119",
    "CLAIM-44119"
);
dlp_golden!(
    detects_order_id,
    "dlp.record.order_id",
    "Bestellnummer ORD-77881",
    "ORD-77881"
);
dlp_golden!(
    detects_english_order_id,
    "dlp.record.order_id",
    "Order ID ORD-77881",
    "ORD-77881"
);
dlp_golden!(
    detects_invoice_id,
    "dlp.record.invoice_id",
    "Rechnungsnummer: RE-2026-190",
    "RE-2026-190"
);
dlp_golden!(
    detects_english_invoice_id,
    "dlp.record.invoice_id",
    "Invoice ID INV-2026-190",
    "INV-2026-190"
);
dlp_golden!(
    detects_project_id,
    "dlp.project_id",
    "Projekt-ID P-ARK-2026",
    "P-ARK-2026"
);
dlp_golden!(
    detects_english_project_id,
    "dlp.project_id",
    "Project ID PROJECT-2026",
    "PROJECT-2026"
);
dlp_golden!(
    detects_organization_id,
    "dlp.organization_id",
    "Mandanten-ID: TENANT-742",
    "TENANT-742"
);
dlp_golden!(
    detects_english_organization_id,
    "dlp.organization_id",
    "Organization ID ORG-742",
    "ORG-742"
);

dlp_golden!(
    detects_fenced_source_code,
    "dlp.content.source_code",
    "```python\nprint('internal')\n```",
    "```python\nprint('internal')\n```"
);
dlp_golden!(
    detects_javascript_source,
    "dlp.content.source_code",
    "const client = new Client();",
    "const client = new Client();"
);
dlp_golden!(
    detects_python_source,
    "dlp.content.source_code",
    "def load_customer(id):",
    "def load_customer(id):"
);
dlp_golden!(
    detects_rust_source,
    "dlp.content.source_code",
    "pub struct Customer {",
    "pub struct Customer {"
);
dlp_golden!(
    detects_source_import,
    "dlp.content.source_code",
    "from pathlib import Path",
    "from pathlib import Path"
);
dlp_golden!(
    detects_sql,
    "dlp.content.sql",
    "SELECT * FROM kunden WHERE aktiv = true;",
    "SELECT * FROM kunden WHERE aktiv = true;"
);
dlp_golden!(
    detects_database_dump,
    "dlp.content.database_dump",
    "-- PostgreSQL database dump",
    "-- PostgreSQL database dump"
);
dlp_golden!(
    detects_system_log,
    "dlp.content.system_log",
    "2026-08-30T10:15:00Z ERROR database connection failed",
    "2026-08-30T10:15:00Z ERROR database connection failed"
);
dlp_golden!(
    detects_business_metric,
    "dlp.internal.business_metric",
    "EBITDA-Marge: 6,1 Prozent",
    "EBITDA-Marge: 6,1 Prozent"
);

#[test]
fn credentials_keep_provider_detection_and_select_only_generic_secret_values() {
    let text = concat!(
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345\n",
        "Zugang Testsystem: passwort = Sommer2026!\n",
        "postgres://dbuser:s3cr3t-value@db.internal/app\n",
        "https://example.test?token=actual-secret"
    );
    let result = scan(text);

    assert_span(
        &result,
        "API_KEY",
        "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
    );
    assert_span(&result, "CREDENTIAL", "Sommer2026!");
    assert_span(&result, "CREDENTIAL", "s3cr3t-value");
    assert_span(&result, "CREDENTIAL", "actual-secret");
    for span in &result.evidence_spans {
        assert_eq!(text.get(span.start_byte..span.end_byte), Some(&*span.text));
        assert_eq!(text[..span.start_byte].chars().count(), span.start_char);
        assert_eq!(text[..span.end_byte].chars().count(), span.end_char);
    }

    for safe in [
        "password = ${PASSWORD}",
        "passwort: <your-password>",
        "token = [REDACTED]",
        "password is changeme",
    ] {
        assert!(
            scan(safe)
                .evidence_spans
                .iter()
                .all(|span| !matches!(span.label.as_str(), "CREDENTIAL" | "SECRET_TOKEN")),
            "{safe}"
        );
    }
}

#[test]
fn private_key_finding_covers_the_complete_block() {
    let key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=\n",
        "-----END PRIVATE KEY-----"
    );
    let result = scan(&format!("prefix\n{key}\nsuffix"));
    assert_span(&result, "PRIVATE_KEY", key);

    let header = "-----BEGIN OPENSSH PRIVATE KEY-----";
    assert_span(&scan(header), "PRIVATE_KEY", header);
}

#[test]
fn anchored_business_identifiers_emit_exact_names_and_value_spans() {
    let cases = [
        (
            "USt-IdNr.: DE 123 456 789",
            "dlp.de.vat_id",
            "DE 123 456 789",
        ),
        (
            "Amtsgericht Berlin HRB 12345",
            "dlp.de.commercial_register_number",
            "HRB 12345",
        ),
        (
            "BSNR: 123456789",
            "dlp.de.facility_number_bsnr",
            "123456789",
        ),
        (
            "Fallnummer: CASE-2026/481",
            "dlp.record.case_id",
            "CASE-2026/481",
        ),
        (
            "Vertragsnummer V-2026-8842",
            "dlp.record.contract_id",
            "V-2026-8842",
        ),
        (
            "Schadennummer: SCH-44119",
            "dlp.record.claim_id",
            "SCH-44119",
        ),
        (
            "Bestellnummer ORD-77881",
            "dlp.record.order_id",
            "ORD-77881",
        ),
        (
            "Rechnungsnummer: RE-2026-190",
            "dlp.record.invoice_id",
            "RE-2026-190",
        ),
        ("Projekt-ID P-ARK-2026", "dlp.project_id", "P-ARK-2026"),
        (
            "Mandanten-ID: TENANT-742",
            "dlp.organization_id",
            "TENANT-742",
        ),
    ];

    for (text, label, value) in cases {
        assert_span(&scan(text), label, value);
    }

    for safe in [
        "Die Nummer 123456789 steht allein.",
        "Build 88231 erfolgreich.",
        "Fallnummern werden archiviert.",
        "Vertragsnummer: [REDACTED]",
        "Projekt-ID lautet unbekannt",
    ] {
        assert!(
            scan(safe)
                .evidence_spans
                .iter()
                .all(|span| !matches!(span.label.as_str(), "CREDENTIAL" | "SECRET_TOKEN")),
            "{safe}"
        );
    }
}

#[test]
fn confidential_content_rules_cover_coherent_blocks_and_statements() {
    let fenced = "```python\nprint('internal')\n```";
    assert_span(&scan(fenced), "dlp.content.source_code", fenced);

    let javascript = "const stripe = new Stripe('sk_live_51NxQ2mHk9dLm7pAvR4TzY');";
    let javascript_result = scan(javascript);
    assert_span(
        &javascript_result,
        "PAYMENT_KEY",
        "sk_live_51NxQ2mHk9dLm7pAvR4TzY",
    );
    assert_span(&javascript_result, "dlp.content.source_code", javascript);

    let sql = "SELECT * FROM kunden WHERE jahresumsatz > 100000;";
    assert_span(&scan(sql), "dlp.content.sql", sql);

    let dump = "INSERT INTO kunden (id, name) VALUES (42, 'Ada');";
    assert_span(&scan(dump), "dlp.content.database_dump", dump);

    let trace = "RuntimeError: database failed\n    at service.rs:42\n    at main.rs:9\n";
    assert_span(&scan(trace), "dlp.content.system_log", trace);

    let log = "2026-08-30T10:15:00Z ERROR database connection failed";
    assert_span(&scan(log), "dlp.content.system_log", log);

    for prose in [
        "Die SELECT-Klausel wird im Handbuch erklärt.",
        "Unser Code of Conduct gilt für alle.",
        "Ein INSERT fügt einen Datensatz ein.",
    ] {
        assert!(scan(prose).evidence_spans.is_empty(), "{prose}");
    }
}

#[test]
fn business_metrics_require_anchor_value_relationship_and_keep_context() {
    for text in [
        "Marge liegt bei 38 %",
        "Deckungsbeitrag 22 %",
        "Gehalt 74.500 EUR",
        "Annual salary: 120,000 USD",
        "EBITDA-Marge: 6,1 Prozent",
        "Forecast 40,8 Mio. EUR",
    ] {
        assert_span(&scan(text), "dlp.internal.business_metric", text);
    }

    for safe in [
        "Marge bezeichnet eine betriebswirtschaftliche Kennzahl.",
        "Der Wert beträgt 38 %.",
        "Statuscode 500",
    ] {
        assert!(scan(safe).evidence_spans.is_empty(), "{safe}");
    }
}

#[test]
fn source_and_sql_rules_cover_structural_external_golden_shapes() {
    let go_source = "package detect\n\nimport \"fmt\"";
    assert_span(&scan(go_source), "dlp.content.source_code", go_source);

    let create = concat!(
        "-- Table structure for table `customer`\n",
        "CREATE TABLE IF NOT EXISTS `customer` (\n",
        "  `id` bigint NOT NULL,\n",
        "  PRIMARY KEY (`id`)\n",
        ");"
    );
    assert_span(&scan(create), "dlp.content.sql", create);

    let alter = "ALTER TABLE customer\n  ADD COLUMN active boolean NOT NULL;";
    assert_span(&scan(alter), "dlp.content.sql", alter);

    for prose in [
        "The package main will arrive tomorrow.",
        "package delivery/details",
        "package delivery",
        "package details",
        "Please create a table for the report.",
        "ALTER the schedule after lunch;",
        "Set expectations before lunch;",
        "Begin the migration tomorrow;",
        "Commit changes before release;",
        "Use caution;",
        "Call Alice;",
    ] {
        assert!(scan(prose).evidence_spans.is_empty(), "{prose}");
    }
}

#[test]
fn unterminated_select_lines_have_bounded_runtime_and_emit_no_sql() {
    const SIZE: usize = 100 * 1024;
    let line = "SELECT customer_id FROM customer_records\n";
    let text = line.repeat(SIZE.div_ceil(line.len()));
    let text = &text[..SIZE];
    let pipeline = DlpPipeline::new();
    let started = Instant::now();
    let result = pipeline.evaluate(text);

    assert_eq!(result.class_name, "safe");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn generic_credential_families_emit_only_the_secret_value() {
    let cases = [
        (
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "CLOUD_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        (
            "api_key = ark-test-value-8842-actual",
            "CREDENTIAL",
            "ark-test-value-8842-actual",
        ),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "SECRET_TOKEN",
            "eyJhbGciOiJIUzI1NiJ9.payload.signature",
        ),
        (
            "Authorization: Basic YWRhOnNlY3JldC04ODQy",
            "CREDENTIAL",
            "YWRhOnNlY3JldC04ODQy",
        ),
        (
            "https://storage.test/a?X-Amz-Signature=0123456789abcdef0123456789abcdef",
            "CREDENTIAL",
            "0123456789abcdef0123456789abcdef",
        ),
        (
            "Cookie: theme=dark; sessionid=abcDEF0123456789xyz",
            "CREDENTIAL",
            "abcDEF0123456789xyz",
        ),
        (
            "X-CSRF-Token: csrf_0123456789abcdef",
            "SECRET_TOKEN",
            "csrf_0123456789abcdef",
        ),
        (
            "password_hash = $2b$12$abcdefghijklmnopqrstuuVIXU7y0N7XmxmCN5QYGl1R9vO2",
            "PASSWORD_HASH",
            "$2b$12$abcdefghijklmnopqrstuuVIXU7y0N7XmxmCN5QYGl1R9vO2",
        ),
    ];

    for (text, label, value) in cases {
        assert_span(&scan(text), label, value);
    }

    for safe in [
        "api_key = [REDACTED]",
        "Authorization: Bearer changeme",
        "X-CSRF-Token: replace-me",
        "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}",
    ] {
        assert!(
            scan(safe)
                .evidence_spans
                .iter()
                .all(|span| !matches!(span.label.as_str(), "CREDENTIAL" | "SECRET_TOKEN")),
            "{safe}"
        );
    }
}

#[test]
fn source_sql_and_dump_rules_cover_common_unfenced_structures() {
    for source in [
        "let client = Client::new();",
        "config = {'host': 'db.internal'}",
        "def load_customer(id):",
        "pub struct Customer {",
        "from pathlib import Path",
        "use crate::customer::Repository;",
    ] {
        assert_span(&scan(source), "dlp.content.source_code", source);
    }

    let sql = "SELECT id, email\nFROM customers\nWHERE active = true;";
    assert_span(&scan(sql), "dlp.content.sql", sql);

    let dump = "-- PostgreSQL database dump";
    assert_span(&scan(dump), "dlp.content.database_dump", dump);

    let fenced = concat!(
        "```env\n",
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345\n",
        "```"
    );
    let result = scan(fenced);
    assert_span(&result, "dlp.content.source_code", fenced);
    assert_span(
        &result,
        "API_KEY",
        "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
    );
}

#[test]
fn dlp_anchor_only_fields_remain_safe_and_expose_exact_metadata() {
    let text = "Zugangsdaten; X-API-Key; Geschäftszeichen; Umsatzprognose; Quellcode; Datenbankexport; Fehlerprotokoll";
    let result = scan(text);

    assert_eq!(result.class_name, "safe");
    assert!(result.evidence_spans.is_empty());
    let facts = anchors(&result);
    let categories = facts
        .iter()
        .map(|anchor| anchor["category"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        BTreeSet::from([
            "auth_header_cookie",
            "business_record_identifier",
            "credentials_secrets",
            "internal_business_metric",
            "source_code_config",
            "sql_database_dump",
            "system_log_stacktrace",
        ])
    );

    for anchor in facts {
        assert_eq!(anchor["kind"], "anchor");
        assert!(matches!(
            anchor["anchor_kind"].as_str(),
            Some("lexical" | "structural")
        ));
        assert!(matches!(
            anchor["strength"].as_str(),
            Some("weak" | "medium" | "strong")
        ));
        let start = anchor["start_byte"].as_u64().unwrap() as usize;
        let end = anchor["end_byte"].as_u64().unwrap() as usize;
        assert_eq!(text.get(start..end), anchor["text"].as_str());
        assert_eq!(text[..start].chars().count(), anchor["start_char"]);
        assert_eq!(text[..end].chars().count(), anchor["end_char"]);
    }
}

#[test]
fn structural_dlp_markers_are_context_without_becoming_findings() {
    let text = concat!(
        "Übersicht\n",
        "apiVersion: v1\n",
        "FROM python:3.12\n",
        "LOCK TABLES customer READ;\n",
        "Stacktrace"
    );
    let result = scan(text);

    assert_eq!(result.class_name, "safe");
    assert!(result.evidence_spans.is_empty());
    let facts = anchors(&result);
    assert!(facts.iter().any(|anchor| {
        anchor["category"] == "source_code_config" && anchor["anchor_kind"] == "structural"
    }));
    assert!(facts.iter().any(|anchor| {
        anchor["category"] == "sql_database_dump" && anchor["anchor_kind"] == "structural"
    }));
    assert!(facts.iter().any(|anchor| {
        anchor["category"] == "system_log_stacktrace" && anchor["anchor_kind"] == "lexical"
    }));
    for anchor in facts {
        let start = anchor["start_byte"].as_u64().unwrap() as usize;
        let end = anchor["end_byte"].as_u64().unwrap() as usize;
        assert_eq!(&text[start..end], anchor["text"].as_str().unwrap());
        assert_eq!(text[..start].chars().count(), anchor["start_char"]);
        assert_eq!(text[..end].chars().count(), anchor["end_char"]);
    }
}

#[test]
fn german_and_english_dlp_anchor_variants_cover_existing_rule_contexts() {
    let text = concat!(
        "API-Schlüssel; client credentials; WEBHOOK_SECRET; ",
        "Set-Cookie; session token; X-Goog-Signature; ",
        "Umsatzsteuer-Identifikationsnummer; VAT number; Handelsregisternummer; ",
        "Praxisnummer; Case reference; Vertrags-ID; policy number; Claim number; ",
        "Purchase Order; Invoice reference; Belegnummer; Project code; Company ID; ",
        "Deckungsbeitrag; gross margin; recurring revenue; burn rate; ",
        "Konfigurationsdatei; Kubernetes manifest; database dump; Crash Log"
    );
    let result = scan(text);

    assert_eq!(result.class_name, "safe");
    let categories = anchors(&result)
        .iter()
        .map(|anchor| anchor["category"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        BTreeSet::from([
            "auth_header_cookie",
            "business_record_identifier",
            "credentials_secrets",
            "internal_business_metric",
            "source_code_config",
            "sql_database_dump",
            "system_log_stacktrace",
        ])
    );
}

#[test]
fn broad_dlp_words_are_weak_context_not_findings() {
    let text = "Token Secret Schlüssel Login Marge Umsatz Revenue Budget Target Actual";
    let result = scan(text);

    assert_eq!(result.class_name, "safe");
    assert!(result.evidence_spans.is_empty());
    for anchor in anchors(&result) {
        assert_eq!(anchor["strength"], "weak", "{anchor:#?}");
    }
}
