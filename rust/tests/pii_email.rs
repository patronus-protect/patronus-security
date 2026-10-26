// SPDX-License-Identifier: GPL-3.0-only
//! E-mail addresses (B-EMAIL: T06, T23, F05, baseline bucket P7).
//!
//! `pii_email` took ASCII local parts only: `moeleprêtr@outlook.com` became
//! `tr@outlook.com`, `jürgen.müller@…` became `ller@…`, `o'neil@…` became `neil@…`
//! and `诗向@yahoo.com` was no match. It cut the punycode top-level domain of
//! `a@xn--d1acufc.xn--p1ai` after `.xn`, accepted any letter run as top-level domain
//! (`email.note`) and reported the password of `postgres://user:pass@host` as an
//! address. A local part now holds Unicode letters and inner apostrophes, in text
//! without word spacing at most three ideographs or katakana; the top-level domain
//! is ASCII or punycode and delegated by IANA or reserved as a placeholder (T01);
//! the userinfo of a URL is no address.

use patronus_ark::detectors::pii::{score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

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

/// `(text, start_char, end_char)` of every EMAIL span.
fn email_spans(text: &str, mode: PiiMode) -> Vec<(String, usize, usize)> {
    scan(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == "EMAIL")
        .map(|span| (span.text, span.start_char, span.end_char))
        .collect()
}

const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];

/// `(text, value)`: `value` is the only EMAIL span in every mode.
const FOUND: [(&str, &str); 16] = [
    (
        "E-Mail: jürgen.müller@beispiel.de",
        "jürgen.müller@beispiel.de",
    ),
    (
        "Please confirm by emailing moeleprêtr@outlook.com today.",
        "moeleprêtr@outlook.com",
    ),
    (
        "Écrivez à icez'berg@yahoo.com ou appelez-nous.",
        "icez'berg@yahoo.com",
    ),
    ("Contact: o'neil@example.com", "o'neil@example.com"),
    ("correo electrónico ÐA@gmail.com, gracias", "ÐA@gmail.com"),
    ("Пишите: иван.петров@почта.com", "иван.петров@почта.com"),
    (
        "Bitte an info@müller-bau.de schreiben.",
        "info@müller-bau.de",
    ),
    ("Email: a@xn--d1acufc.xn--p1ai", "a@xn--d1acufc.xn--p1ai"),
    (
        "Mail POST@XN--E1AFMKFD.XN--P1AI now",
        "POST@XN--E1AFMKFD.XN--P1AI",
    ),
    ("通过电子邮件 诗向@yahoo.com 发送。", "诗向@yahoo.com"),
    // Without word spacing the local part is at most three ideographs or katakana.
    ("联系邮箱伟伟许@aol.com，联系电话", "伟伟许@aol.com"),
    ("と田@yahoo.comを共有", "田@yahoo.com"),
    ("Testkonto: qa.bot@shop.test", "qa.bot@shop.test"),
    ("Bounce: noreply@mailer.invalid.", "noreply@mailer.invalid"),
    (
        "Ping dev.lead@northwind.example now",
        "dev.lead@northwind.example",
    ),
    (
        "https://shop.example.com/contact?email=anna.berg@firma.de",
        "anna.berg@firma.de",
    ),
];

#[test]
fn unicode_apostrophe_and_idn_addresses_are_one_span() {
    for mode in MODES {
        for (text, value) in FOUND {
            let spans = email_spans(text, mode);
            let values: Vec<_> = spans.iter().map(|(span, ..)| span.as_str()).collect();
            assert_eq!(values, [value], "{mode}: {text:?}");
        }
    }
}

#[test]
fn spans_are_counted_in_code_points() {
    let text = "联系邮箱伟伟许@aol.com，联系电话";
    assert_eq!(
        email_spans(text, PiiMode::Strict),
        [("伟伟许@aol.com".to_owned(), 4, 15)]
    );
    let text = "Grüße an jürgen.müller@beispiel.de";
    assert_eq!(
        email_spans(text, PiiMode::Balanced),
        [("jürgen.müller@beispiel.de".to_owned(), 9, 34)]
    );
}

/// No EMAIL span in any mode.
const SILENT: [&str; 14] = [
    // T06: the userinfo of a URL, with and without password.
    "postgres://service:DbPassword2026@db.example.com/app",
    "DATABASE_URL=postgres://app:Winter2026@db.example.com:5432/orders",
    "Mirror: ftp://deploy@files.example.net/releases/",
    "git clone ssh://git@git.firma.de/team/app.git",
    "redis://:s3cr3t@cache.example.org:6379/0",
    // T23: an apostrophe opens or ends no local part.
    "Die Adresse wird mit adresse.split('@') zerlegt.",
    "if address.endswith(\"'@example.com\"):",
    "Benutzer 'admin'@'localhost' anlegen.",
    "Tag the playlist rock'n'@roll.com today.",
    // F05: a top-level domain that IANA does not delegate and no placeholder.
    "Sent from alice.williams@email.note",
    "Schreiben Sie an anna.berg@firma.intern",
    "Fehler in a@xn--d1acufc.xn--nope",
    // Unchanged: no domain suffix and spelled-out separators outside recall.
    "E-Mail: anna.beispiel@mailserver",
    "Mail ada [at] northwind [dot] com for access.",
];

#[test]
fn userinfo_quoted_at_signs_and_unknown_domains_stay_silent() {
    for text in SILENT {
        for mode in [PiiMode::Strict, PiiMode::Balanced] {
            assert_eq!(email_spans(text, mode), [], "{mode}: {text:?}");
        }
    }
}

#[test]
fn an_address_after_a_url_keeps_its_span() {
    let text = "See https://example.com/docs and write to ops@example.com.";
    assert_eq!(
        email_spans(text, PiiMode::Strict),
        [("ops@example.com".to_owned(), 42, 57)]
    );
    // A bare `//` (a comment) opens no URL.
    let text = "// owner: ops@example.com";
    assert_eq!(email_spans(text, PiiMode::Strict).len(), 1);
}

#[test]
fn email_domain_accepts_iana_and_placeholder_top_level_domains() {
    for value in [
        "a@b.com",
        "a@b.DE",
        "a@b.museum",
        "a@xn--d1acufc.xn--p1ai",
        "a@b.XN--P1AI",
        "a@b.xn--vermgensberater-ctb",
        "a@shop.test",
        "a@northwind.example",
        "a@mailer.invalid",
        "a@host.localhost",
    ] {
        assert!(validators::email_domain(value), "{value}");
    }
    for value in [
        "a@email.note",
        "a@firma.intern",
        "a@db.internal",
        "a@corp.local",
        "a@b.xn--p1a",
        "a@b.c",
        "a@b",
    ] {
        assert!(!validators::email_domain(value), "{value}");
    }
}
