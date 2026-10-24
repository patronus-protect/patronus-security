"""Generate deterministic native-L1 PII and DLP regression fixtures.

Run from the repository root with::

    .venv/bin/python python/patronus_ark/benchmark_data/generate_l1_goldens.py

The generated offsets are Python Unicode-code-point offsets and use half-open
``[start, end)`` intervals. All values are invented or copied from the existing
synthetic ``dynamic_pii.jsonl`` fixture; no sensitive document content is used.

DLP secret values are never written in clear: secret positives store a generator
recipe and a carrier template (see ``patronus_ark.dlp_synth.recipes``); offsets refer
to the materialized text, whose SHA-256 fingerprint is recorded for the Rust parity test.
Hard negatives with a documented example or test value in a provider format store the
generator's ``fill`` variant the same way (T06).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from patronus_ark.dlp_synth import recipes


DATA_DIR = Path(__file__).resolve().parent


def positive(
    label: str,
    language: str,
    prefix: str,
    value: str,
    suffix: str = "",
    *,
    source_fixture_id: str | None = None,
) -> dict:
    text = f"{prefix}{value}{suffix}"
    start = len(prefix)
    origin = "derived_existing_fixture" if source_fixture_id else "synthetic"
    provenance = {
        "origin": origin,
        "source": "python/patronus_ark/benchmark_data/dynamic_pii.jsonl"
        if source_fixture_id
        else "hand-authored Ark L1 capability regression",
    }
    if source_fixture_id:
        provenance["source_fixture_id"] = source_fixture_id
    return {
        "language": language,
        "case_type": "positive",
        "target_label": label,
        "text": text,
        "entities": [
            {
                "label": label,
                "text": value,
                "start": start,
                "end": start + len(value),
            }
        ],
        "span_unit": "unicode_code_point",
        "provenance": provenance,
    }


def negative(label: str, language: str, text: str, reason: str) -> dict:
    return {
        "language": language,
        "case_type": "hard_negative",
        "target_label": label,
        "text": text,
        "entities": [],
        "span_unit": "unicode_code_point",
        "negative_reason": reason,
        "provenance": {
            "origin": "synthetic",
            "source": "hand-authored Ark L1 hard-negative regression",
        },
    }


def secret_template_positive(label: str, language: str, template: str, secrets: list[dict]) -> dict:
    text, fragments = recipes.materialize_fragments(template, secrets)
    split = {fragment["secret"] for fragment in fragments if fragment["part"]}
    entities = []
    for fragment in fragments:
        entity = {"label": label, "start": fragment["start"], "end": fragment["end"], "secret": fragment["secret"]}
        if fragment["secret"] in split:
            entity["part"] = fragment["part"]
        if fragment["encoding"]:
            entity["encoding"] = [fragment["encoding"]]
        entities.append(entity)
    return {
        "language": language,
        "case_type": "positive",
        "target_label": label,
        "template": template,
        "secrets": secrets,
        "text_fingerprint": recipes.fingerprint(text),
        "entities": entities,
        "span_unit": "unicode_code_point",
        "provenance": {
            "origin": "synthetic",
            "source": "generator recipe (patronus_ark.dlp_synth), materialized at test time",
        },
    }


def secret_positive(
    label: str, language: str, prefix: str, generator: str, seed: int, suffix: str = ""
) -> dict:
    template = f"{prefix}<<secret:0>>{suffix}"
    return secret_template_positive(label, language, template, [{"gen": generator, "seed": seed}])


# PII golden schema v2 (E10). Every PII row names the `pii_*` rule it exercises
# (`rule_id`), the document that carries the value (`carrier`), its difficulty `tags` and
# whether it is a `known_gap`: a positive the detector misses today, reported by
# 13_l1_golden_eval but not gated. `structured` follows from the carrier; `no_context`
# (no field name or label names the value), `obfuscated` (inserted or substituted
# characters that leave the value readable) and `ocr` (scan layout noise) are set by hand.
# A row scanned in an opt-in PII mode (K03 context engine: scores and counter-context only
# act there) also carries `pii_mode`; rows without it run in the default `strict` mode.
PII_SCHEMA_VERSION = 2
PII_TAGS = ("no_context", "structured", "obfuscated", "ocr")
PII_CARRIERS = ("line", "prose", "json", "yaml", "xml", "csv", "kv", "table")
PII_STRUCTURED_CARRIERS = ("json", "yaml", "xml", "csv", "kv", "table")
# Minimum gated positives and hard negatives per target label and language.
PII_MIN_PER_LANGUAGE = 5
PII_MODES = ("strict", "balanced", "recall")


def pii_row(
    row: dict, rule: str, carrier: str, tags: tuple[str, ...], known_gap: bool, mode: str = "strict"
) -> dict:
    tags = set(tags)
    if carrier not in PII_CARRIERS or not tags <= {"no_context", "obfuscated", "ocr"}:
        raise ValueError(f"bad carrier {carrier!r} or hand-set tags {sorted(tags)}")
    if mode not in PII_MODES:
        raise ValueError(f"bad pii_mode {mode!r}")
    if known_gap and row["case_type"] != "positive":
        raise ValueError("only positives can be known gaps")
    if carrier in PII_STRUCTURED_CARRIERS:
        tags.add("structured")
    head = {
        "schema_version": PII_SCHEMA_VERSION,
        "language": row["language"],
        "case_type": row["case_type"],
        "target_label": row["target_label"],
        "rule_id": rule,
        "carrier": carrier,
        "tags": [tag for tag in PII_TAGS if tag in tags],
        "known_gap": known_gap,
    }
    if mode != "strict":
        head["pii_mode"] = mode
    return {**head, **{key: value for key, value in row.items() if key not in head}}


def annotate(row: dict, also: tuple[tuple[str, str], ...], outside: tuple[int, int] = (0, 0)) -> None:
    """Add `also` as `(label, value)` entities; each value occurs once outside `outside`."""
    text = row["text"]
    for other_label, other_value in also:
        starts = [
            start
            for start in range(len(text))
            if text.startswith(other_value, start)
            and (start + len(other_value) <= outside[0] or start >= outside[1])
        ]
        if len(starts) != 1:
            raise ValueError(f"{other_value!r} must occur once outside the target in {text!r}")
        start = starts[0]
        row["entities"].append(
            {"label": other_label, "text": other_value, "start": start, "end": start + len(other_value)}
        )
    row["entities"].sort(key=lambda entity: entity["start"])


def p(
    label: str,
    language: str,
    rule: str,
    prefix: str,
    value: str,
    suffix: str = "",
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    gap: bool = False,
    source_fixture_id: str | None = None,
    also: tuple[tuple[str, str], ...] = (),
    mode: str = "strict",
) -> dict:
    """Positive: `value` is the gold span `rule` must report in PII mode `mode`.

    `also` annotates every other real entity in the text as `(label, value)` (T02), e.g.
    the card number next to a CVV. The value must occur exactly once outside the target.
    """
    row = positive(label, language, prefix, value, suffix, source_fixture_id=source_fixture_id)
    target = row["entities"][0]
    annotate(row, also, (target["start"], target["end"]))
    return pii_row(row, rule, carrier, tags, gap, mode)


def n(
    label: str,
    language: str,
    rule: str,
    text: str,
    reason: str,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    also: tuple[tuple[str, str], ...] = (),
    mode: str = "strict",
) -> dict:
    """Hard negative: a lookalike for `rule` that no PII rule may report in PII mode `mode`.

    `also` annotates other real entities in the text as `(label, value)` (T07), e.g. the
    valid IBAN around a card-shaped BBAN: they must be reported as primary findings, and
    nothing else may be. The target label is never annotated.
    """
    if any(other_label == label for other_label, _ in also):
        raise ValueError(f"a hard negative never annotates its target label {label}")
    row = negative(label, language, text, reason)
    annotate(row, also)
    return pii_row(row, rule, carrier, tags, False, mode)


PII_CASES = {
    "EMAIL": [
        p("EMAIL", "en", "pii_email", "Contact support at +76-532-1520 or write to ", "john.doe@email.org", ".", carrier="prose", source_fixture_id="base-0003", also=(("PHONE", "+76-532-1520"),)),
        p("EMAIL", "de", "pii_email", "E-Mail: ", "anna.beispiel@firma.de"),
        p("EMAIL", "en", "pii_email", "Reply to ", "ops+alerts@example.co.uk"),
        n("EMAIL", "de", "pii_email", "E-Mail: anna.beispiel@mailserver", "single-label host has no domain suffix"),
        n("EMAIL", "en", "pii_email", "Write to user [at] example [dot] com.", "obfuscated address is not a direct identifier", carrier="prose", tags=("obfuscated",)),
        p("EMAIL", "de", "pii_email", "Bitte antworten Sie bis Freitag an ", "lena.vogt@stadtwerke-musterstadt.de", ".", carrier="prose", tags=("no_context",)),
        p("EMAIL", "de", "pii_email", '{"name": "Jonas Weber", "email": "', "j.weber@beispiel-gmbh.de", '", "ort": "Kassel"}', carrier="json"),
        p("EMAIL", "de", "pii_email", "Name;E-Mail;Ort\nKarin Hoff;", "karin.hoff@praxis-hoff.de", ";Köln", carrier="csv"),
        p("EMAIL", "de", "pii_email", "| Abteilung | Kontakt |\n|---|---|\n| Vertrieb | ", "vertrieb@moebelhaus-nord.de", " |", carrier="table"),
        p("EMAIL", "de", "pii_email", "E-Mail:", "m.krause@kanzlei-krause.de", "   Seite 1/2", tags=("ocr",)),
        p("EMAIL", "de", "pii_email", "E-Mail: ", "anna.berg@firma​.de", "", tags=("obfuscated",)),
        p("EMAIL", "en", "pii_email", "Ping ", "dev.lead@northwind.example", " if the nightly build breaks.", carrier="prose", tags=("no_context",)),
        p("EMAIL", "en", "pii_email", '{"user": {"id": 17, "email": "', "maria.ochoa@contoso-mail.com", '"}}', carrier="json"),
        p("EMAIL", "en", "pii_email", "contact:\n  owner: Priya Nair\n  email: ", "priya.nair@fabrikam.io", "\n", carrier="yaml"),
        p("EMAIL", "en", "pii_email", "| E-mail |", "tom.reyes@acme-corp.net", "|", carrier="table", tags=("ocr",)),
        p("EMAIL", "en", "pii_email", "Email: ", "ada.wong＠northwind.com", "", tags=("obfuscated",)),
        n("EMAIL", "de", "pii_email", "Schreiben Sie an info @ firma . de", "spaced address is not a value of the label", carrier="prose", tags=("obfuscated",)),
        n("EMAIL", "de", "pii_email", "Die Domain firma-beispiel.de ist erreichbar.", "domain without a local part", carrier="prose"),
        n("EMAIL", "de", "pii_email", "Instagram: @anna_berg_fotografie", "social handle has no domain"),
        n("EMAIL", "de", "pii_email", '{"email": "", "ort": "Köln"}', "empty e-mail field", carrier="json"),
        n("EMAIL", "en", "pii_email", "Mention @maria.ochoa in the release channel.", "chat mention has no domain", carrier="prose"),
        n("EMAIL", "en", "pii_email", "Run npm install lodash@4.17.21 first.", "package version pin, not an address", carrier="prose"),
        n("EMAIL", "en", "pii_email", "Email: maria.ochoa@intranet", "single-label host has no domain suffix"),
        n("EMAIL", "en", "pii_email", "email: <redacted>", "redacted value", carrier="yaml"),
    ],
    "IP_ADDRESS": [
        p("IP_ADDRESS", "en", "pii_ipv4", "IP ", "163.186.83.95", " belongs to the host.", carrier="prose", source_fixture_id="base-0015"),
        p("IP_ADDRESS", "de", "pii_ipv4", "Quell-IP: ", "203.0.113.42"),
        p("IP_ADDRESS", "en", "pii_ipv6_compressed", "Client address: ", "2001:db8:85a3::8a2e:370:7334"),
        n("IP_ADDRESS", "de", "pii_ipv4", "IP: 999.10.10.10", "octet exceeds 255"),
        n("IP_ADDRESS", "en", "pii_ipv4", "IP: 127.0.0.1", "loopback is deliberately excluded"),
        p("IP_ADDRESS", "de", "pii_ipv4", '{"client_ip": "', "198.51.100.23", '", "status": 200}', carrier="json"),
        p("IP_ADDRESS", "de", "pii_ipv4", "Der Zugriff kam gestern von ", "192.0.2.77", " und wurde gesperrt.", carrier="prose", tags=("no_context",)),
        p("IP_ADDRESS", "de", "pii_ipv6_full", "Adresse: ", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        p("IP_ADDRESS", "de", "pii_ipv6_compressed", "Zeit;Quelle\nMontag;", "2001:db8:4::17", "", carrier="csv"),
        p("IP_ADDRESS", "de", "pii_ipv6_loopback", "Zugeordnete Adresse: ", "::ffff:c000:0280"),
        p("IP_ADDRESS", "de", "pii_ipv4", "aktion=blockiert\nquelle=", "203.0.113.9", "\nport=443", carrier="kv"),
        p("IP_ADDRESS", "de", "pii_ipv4", "Quelle: ", "１９８．５１．１００．７", "", tags=("obfuscated",)),
        p("IP_ADDRESS", "en", "pii_ipv6_full", "Interface address ", "2001:0db8:0000:0042:0000:8a2e:0370:7334"),
        p("IP_ADDRESS", "en", "pii_ipv6_loopback", "Mapped address: ", "::ffff:c633:6407"),
        p("IP_ADDRESS", "en", "pii_ipv4", "server:\n  bind: ", "198.51.100.14", "\n  port: 8443", carrier="yaml"),
        p("IP_ADDRESS", "en", "pii_ipv6_compressed", "| host | address |\n|---|---|\n| web-1 | ", "2001:db8:a::1", " |", carrier="table"),
        p("IP_ADDRESS", "en", "pii_ipv4", "IP addr.:", "198.51.100.200", "  (scanned page 2)", tags=("ocr",)),
        p("IP_ADDRESS", "en", "pii_ipv4", "Source IP: ", "203[.]0[.]113[.]5", "", tags=("obfuscated",)),
        n("IP_ADDRESS", "de", "pii_ipv4", "Version 2.14.0 wurde gestern ausgerollt.", "three-part version number", carrier="prose"),
        n("IP_ADDRESS", "de", "pii_ipv4", "Multicast-Gruppe: 224.0.0.251", "multicast address is excluded"),
        n("IP_ADDRESS", "de", "pii_ipv4", "Bind-Adresse: 0.0.0.0", "unspecified address is excluded"),
        n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Uhrzeit: 12:30:45", "time of day is not an address"),
        n("IP_ADDRESS", "en", "pii_ipv6_loopback", "Loopback ::1 answers the health check.", "IPv6 loopback is excluded", carrier="prose"),
        n("IP_ADDRESS", "en", "pii_ipv4", "IP: 300.168.1.20", "octet exceeds 255"),
        n("IP_ADDRESS", "en", "pii_ipv4", "SSDP uses 239.255.255.250 for discovery.", "multicast address is excluded", carrier="prose"),
        n("IP_ADDRESS", "en", "pii_ipv6_full", "Timestamp 08:15:30.123", "time stamp is not an address"),
        n("IP_ADDRESS", "en", "pii_ipv6_full", "Interface address fe80:0000:0000:0000:0204:61ff:fe9d:f156", "link-local address is suppressed"),
    ],
    "PHONE": [
        p("PHONE", "en", "pii_phone_international", "Their phone number changed to ", "+65-716-1434", ".", carrier="prose", source_fixture_id="base-0004"),
        p("PHONE", "de", "pii_phone_de", "Telefon: ", "+49 170 1234567"),
        p("PHONE", "en", "pii_phone_international", "Mobile: ", "+44 (20) 7946 0958"),
        n("PHONE", "de", "pii_phone_international", "Telefon: +00 0000000", "invalid country prefix and repeated digits"),
        n("PHONE", "en", "pii_phone_us", "Version 1.234.567", "version-like number has no international prefix"),
        p("PHONE", "de", "pii_phone_de_national_context", "Telefon: ", "030 12345678"),
        p("PHONE", "de", "pii_phone_de_national_context", "Name: Petra Lang\nMobil: ", "0171 2345678", "\nOrt: Bonn", carrier="kv"),
        p("PHONE", "de", "pii_phone_de", "Rufen Sie mich morgen unter ", "+49 30 901820", " an.", carrier="prose", tags=("no_context",)),
        p("PHONE", "de", "pii_phone_international", "Name;Telefon\nMüller;", "+49 89 2019 4400", "", carrier="csv"),
        p("PHONE", "de", "pii_phone_de", "Fax: ", "0049 211 5583920"),
        p("PHONE", "de", "pii_phone_us", "US-Büro: ", "212-736-4410"),
        p("PHONE", "de", "pii_phone_us", "US-Büro: ", "(212) 736-4410"),
        p("PHONE", "de", "pii_phone_de_national_context", '{"telefon": "', "030 98765432", '"}', carrier="json"),
        p("PHONE", "de", "pii_phone_de_national_context", "Telefon: ", "０３０ １２３４５６７８", "", tags=("obfuscated",)),
        p("PHONE", "de", "pii_phone_de_national_context", "Te1efon: ", "0221 4711230", "", tags=("ocr",), gap=True),
        p("PHONE", "en", "pii_phone_us", "Call me at ", "415-555-2671", " tomorrow.", carrier="prose", tags=("no_context",)),
        p("PHONE", "en", "pii_phone_us", "Call me at ", "(415) 555-2671", " tomorrow.", carrier="prose", tags=("no_context",)),
        p("PHONE", "en", "pii_phone_international", '{"phone": "', "+1 415 555 2671", '"}', carrier="json"),
        p("PHONE", "en", "pii_phone_de", "contact:\n  phone: ", "+49 40 3005 1200", "\n", carrier="yaml"),
        p("PHONE", "en", "pii_phone_de_national_context", "Phone: ", "040 30051200"),
        p("PHONE", "en", "pii_phone_international", "| Name | Phone |\n|---|---|\n| R. Patel | ", "+44 20 7946 0123", " |", carrier="table"),
        p("PHONE", "en", "pii_phone_us", "Phone:", "212-736-4410", "   Fax: none", tags=("ocr",)),
        p("PHONE", "en", "pii_phone_international", "Mobile: ", "+44​7700​900123", "", tags=("obfuscated",)),
        n("PHONE", "de", "pii_phone_us", "Bestellnummer 2026-104-88", "order number with too few digits"),
        n("PHONE", "de", "pii_phone_de_national_context", "Telefon: +49 (0) XXX XXXXXXX", "masked number", tags=("obfuscated",)),
        n("PHONE", "de", "pii_phone_de_national_context", "Telefon: 0000 000000", "repeated zeros"),
        n("PHONE", "de", "pii_phone_us", "Der Termin ist am 19.10.2026 um 14 Uhr.", "date and time are not a phone number", carrier="prose"),
        n("PHONE", "de", "pii_phone_de_national_context", "Telefon: siehe Rückseite", "field without a value"),
        n("PHONE", "en", "pii_phone_us", "Phone: XXX-XXX-XXXX", "masked number", tags=("obfuscated",)),
        n("PHONE", "en", "pii_phone_international", "Rated +4.5 out of 5 by 120 users.", "rating is not a phone number", carrier="prose"),
        n("PHONE", "en", "pii_phone_us", "Ticket 2024-0042-17 was closed.", "ticket number is not a phone number", carrier="prose"),
        n("PHONE", "en", "pii_phone_us", "Build 20261019 passed.", "build number has no separators"),
        n("PHONE", "en", "pii_phone_de", "Dial +49 first, then the area code.", "country prefix without a subscriber number", carrier="prose"),
        # K03 context engine: a national number without a field name right before it needs a
        # phone term of the lexicon on either side; a nearer counter-context term, the field
        # name of the next value or a line break in between rule it out.
        p("PHONE", "de", "pii_phone_de_national_proximity", "Frau Weber ist unter ", "0176 90817263", " erreichbar.", carrier="prose", tags=("no_context",)),
        p("PHONE", "de", "pii_phone_de_national_proximity", "Rückruf bitte unter ", "(030) 1234567", ".", carrier="prose", tags=("no_context",)),
        p("PHONE", "de", "pii_phone_de_national_proximity", "Mobil erreichbar: ", "0151 2345678"),
        p("PHONE", "de", "pii_phone_de_national_proximity", "", "0221 4711230", " (Handy)"),
        p("PHONE", "de", "pii_phone_de_national_proximity", "Bei Rückfragen rufen Sie uns an: ", "0211 5583920", ".", carrier="prose", tags=("no_context",)),
        p("PHONE", "de", "pii_phone_de_national_proximity", "Name: Petra Lang\nTelefon privat: ", "089 2019440", "\nOrt: München", carrier="kv"),
        p("PHONE", "en", "pii_phone_de_national_proximity", "You can reach Mr. Weber at ", "0176 90817263", " (mobile).", carrier="prose", tags=("no_context",)),
        p("PHONE", "en", "pii_phone_de_national_proximity", "Please call back on ", "0221 4711230", ".", carrier="prose", tags=("no_context",)),
        p("PHONE", "en", "pii_phone_de_national_proximity", "Office line ", "0711 2223334", " (telephone)"),
        p("PHONE", "en", "pii_phone_de_national_proximity", "Mobile reachable at ", "0151 23456789"),
        p("PHONE", "en", "pii_phone_de_national_proximity", "Ms. Kaya is reachable on ", "06221 543210", " during office hours.", carrier="prose", tags=("no_context",)),
        p("PHONE", "en", "pii_phone_de_national_proximity", "name: R. Patel\nhome phone number (Berlin): ", "030 98765432", "\n", carrier="yaml"),
        n("PHONE", "de", "pii_phone_de_national_proximity", "Bestellnummer 0176 90817263, Rückfragen bitte telefonisch.", "order number: the counter-context term is nearer than any phone term", carrier="prose"),
        n("PHONE", "de", "pii_phone_de_national_proximity", "Die Rechnungsnummer 0221 4711230 steht oben rechts.", "invoice number without a phone term", carrier="prose"),
        n("PHONE", "de", "pii_phone_de_national_proximity", "Aktenzeichen 0711 2223334 – Rückruf erbeten.", "file reference: the counter-context term is nearer than the phone term after the number", carrier="prose"),
        n("PHONE", "de", "pii_phone_de_national_proximity", "Seriennummer 0170 1234567 des Handys", "serial number; 'Handys' is not the whole word 'Handy'"),
        n("PHONE", "de", "pii_phone_de_national_proximity", "Vertrag 0123 4567890, Telefon folgt.", "the next field name after a comma is not context of the number", carrier="prose"),
        n("PHONE", "de", "pii_phone_de_national_proximity", "Telefon:\nVertrag 0123 4567890", "the phone term is on another line", carrier="kv"),
        n("PHONE", "en", "pii_phone_de_national_proximity", "Order number 0176 90817263 – questions by phone only.", "order number: the counter-context term is nearer than the phone term", carrier="prose"),
        n("PHONE", "en", "pii_phone_de_national_proximity", "Invoice no 0221 4711230 is overdue.", "invoice number without a phone term", carrier="prose"),
        n("PHONE", "en", "pii_phone_de_national_proximity", "Tracking number 0151 23456789 (parcel)", "tracking number"),
        n("PHONE", "en", "pii_phone_de_national_proximity", "Serial number 0711 2223334 of the mobile router", "serial number: the counter-context term is nearer than 'mobile'"),
        n("PHONE", "en", "pii_phone_de_national_proximity", "Contract 0123 4567890, phone to follow.", "the next field name after a comma is not context of the number", carrier="prose"),
        n("PHONE", "en", "pii_phone_de_national_proximity", "Phone:\nContract 0123 4567890", "the phone term is on another line", carrier="kv"),
        # K03 in balanced: a counter-context term lowers a value strict reports by 30 points,
        # below the balanced threshold; a nearer support term keeps it.
        p("PHONE", "de", "pii_phone_de", "Rechnungsnummer 2024-117, Telefon ", "+49 30 12345678", carrier="prose", mode="balanced"),
        p("PHONE", "de", "pii_phone_de_national_context", "Handy ", "0151 2345678", " (Bestellnummer siehe unten)", mode="balanced"),
        p("PHONE", "en", "pii_phone_us", "Invoice 2024-117 attached; call me at ", "415-555-2671", ".", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "en", "pii_phone_de_national_proximity", "Mobile reachable at ", "0151 23456789", " (order number below)", mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Rechnungsnummer 030-123-4567", "invoice number in phone form", mode="balanced"),
        n("PHONE", "de", "pii_phone_de", "Sendungsnummer +49 30 12345678", "tracking number in phone form", mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Ticketnummer 415-555-2671 wurde geschlossen.", "ticket number in phone form", carrier="prose", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Invoice no. 415-555-2671 is overdue.", "invoice number in phone form", carrier="prose", mode="balanced"),
        n("PHONE", "en", "pii_phone_de", "Tracking number +49 30 12345678", "tracking number in phone form", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Serial number 212-736-4410 on the label.", "serial number in phone form", carrier="prose", mode="balanced"),
        # K03 context engine, balanced mode: the nearest context decides. A phone field name
        # before or after the value keeps it; an order, invoice, tracking or serial number
        # field nearer than any phone field drops a phone-shaped value strict reports.
        p("PHONE", "de", "pii_phone_de", "Bestellnummer 4711 – Rückfragen bitte unter Telefon ", "+49 30 1234567", ".", carrier="prose", mode="balanced"),
        p("PHONE", "de", "pii_phone_de", "", "+49 172 9081734", " (mobil), Auftragsnummer 2026-118", mode="balanced"),
        p("PHONE", "de", "pii_phone_de", "Auftragsnummer: 2026-118\nTelefon: ", "+49 89 4455667", "", carrier="kv", mode="balanced"),
        p("PHONE", "de", "pii_phone_international", "Rechnung 2026/17 – Rückruf unter Telefon ", "+43 1 5320 4411", ".", carrier="prose", mode="balanced"),
        p("PHONE", "de", "pii_phone_de", "Ich bin ab Montag unter ", "+49 151 23456789", " zu sprechen.", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "en", "pii_phone_international", "Order no. 4711; questions by phone: ", "+1 312 555 0164", ".", carrier="prose", mode="balanced"),
        p("PHONE", "en", "pii_phone_international", "", "+44 20 7946 0321", " (mobile), invoice number 88213", mode="balanced"),
        p("PHONE", "en", "pii_phone_international", "Invoice number: 88213\nPhone: ", "+1 415 555 0172", "", carrier="kv", mode="balanced"),
        p("PHONE", "en", "pii_phone_us", "Tel. ", "212-736-4410", ", order ID 7781", mode="balanced"),
        p("PHONE", "en", "pii_phone_international", "Please try me at ", "+61 2 9374 4000", " after 5 pm.", carrier="prose", tags=("no_context",), mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Bestellnummer 202-604-7110 bitte bei Rückfragen angeben.", "order number in phone form (counter-context)", carrier="prose", mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Rechnungsnummer: 418-220-1937", "invoice number in phone form (counter-context)", mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Sendungsnummer 340.434.1881", "tracking number in phone form (counter-context)", mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Die Artikelnummer 700-123-4567 ist ausverkauft.", "article number in phone form (counter-context)", carrier="prose", mode="balanced"),
        n("PHONE", "de", "pii_phone_us", "Vorgangsnummer 610 557 2290", "case number in phone form (counter-context)", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Order number 202-604-7110 has shipped.", "order number in phone form (counter-context)", carrier="prose", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Invoice no. 418-220-1937 is overdue.", "invoice number in phone form (counter-context)", carrier="prose", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Tracking number: 340.434.1881", "tracking number in phone form (counter-context)", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Serial number 700-123-4567 is out of warranty.", "serial number in phone form (counter-context)", carrier="prose", mode="balanced"),
        n("PHONE", "en", "pii_phone_us", "Transaction ID 610 557 2290 was refunded.", "transaction ID in phone form (counter-context)", carrier="prose", mode="balanced"),
    ],
    "MAC_ADDRESS": [
        p("MAC_ADDRESS", "de", "pii_mac_address", "MAC: ", "02:42:ac:11:00:02"),
        p("MAC_ADDRESS", "en", "pii_mac_address", "Adapter: ", "A4-5E-60-12-34-56"),
        p("MAC_ADDRESS", "de", "pii_mac_address", "Geräteadresse ", "F0:9F:C2:AA:10:7B"),
        n("MAC_ADDRESS", "en", "pii_mac_address", "MAC: 00:00:00:00:00:00", "all-zero address is excluded"),
        n("MAC_ADDRESS", "de", "pii_mac_address", "MAC: 02:42:AC:11:00", "only five octets"),
        p("MAC_ADDRESS", "de", "pii_mac_address", '{"geraet": "Drucker 2.OG", "mac": "', "3C:52:82:4A:19:E0", '"}', carrier="json"),
        p("MAC_ADDRESS", "de", "pii_mac_address", "Das Notebook meldete sich mit ", "8C-85-90-1B-2D-3F", " im WLAN an.", carrier="prose", tags=("no_context",)),
        p("MAC_ADDRESS", "de", "pii_mac_address", "Gerät;MAC\nScanner;", "00:1A:2B:3C:4D:5E", "", carrier="csv"),
        p("MAC_ADDRESS", "de", "pii_mac_address", "MAC-Adresse:", "b8:27:eb:45:12:9a", " |", tags=("ocr",)),
        p("MAC_ADDRESS", "de", "pii_mac_address", "MAC: ", "02 42 ac 11 00 03", "", tags=("ocr",), gap=True),
        p("MAC_ADDRESS", "en", "pii_mac_address", "Device ", "D4:3D:7E:91:0A:22", " joined the guest network.", carrier="prose", tags=("no_context",)),
        p("MAC_ADDRESS", "en", "pii_mac_address", "host,mac\nlaptop-17,", "a4:83:e7:2c:5b:10", "", carrier="csv"),
        p("MAC_ADDRESS", "en", "pii_mac_address", "interface:\n  name: eth0\n  mac: ", "52:54:00:12:34:56", "\n", carrier="yaml"),
        p("MAC_ADDRESS", "en", "pii_mac_address", "| Port | MAC |\n|---|---|\n| 12 | ", "00-1B-63-84-45-E6", " |", carrier="table"),
        p("MAC_ADDRESS", "en", "pii_mac_address", "Hardware address: ", "0242.ac11.0004", "", gap=True),
        n("MAC_ADDRESS", "de", "pii_mac_address", "Zeitstempel 10:15:20:30:40", "five groups form a time stamp"),
        n("MAC_ADDRESS", "de", "pii_mac_address", "Prüfsummen-Präfix ab:cd:ef:12", "only four groups"),
        n("MAC_ADDRESS", "de", "pii_mac_address", "MAC: 02-42-ac:11-00-02", "mixed separators"),
        n("MAC_ADDRESS", "de", "pii_mac_address", "Verhältnis 12:34:56 im Bericht.", "ratio is not an address", carrier="prose"),
        n("MAC_ADDRESS", "en", "pii_mac_address", "MAC: 02:42:ac:11:00:zz", "last octet is not hexadecimal"),
        n("MAC_ADDRESS", "en", "pii_mac_address", "MAC: 00-00-00-00-00-00", "all-zero address is excluded"),
        n("MAC_ADDRESS", "en", "pii_mac_address", "MAC: XX:XX:XX:XX:XX:XX", "masked address", tags=("obfuscated",)),
        n("MAC_ADDRESS", "en", "pii_mac_address", "The score was 3:1:2:0 after overtime.", "score is not an address", carrier="prose"),
    ],
    "CREDITCARD": [
        p("CREDITCARD", "en", "pii_credit_card", "My card number is ", "4111 1111 1111 1111", ".", carrier="prose"),
        p("CREDITCARD", "de", "pii_credit_card", "Kartennummer: ", "4111-1111-1111-1111"),
        p("CREDITCARD", "en", "pii_credit_card", "PAN ", "5555555555554444"),
        n("CREDITCARD", "de", "pii_credit_card", "Kartennummer: 4111 1111 1111 1112", "Luhn checksum fails"),
        n("CREDITCARD", "en", "pii_credit_card", "Reference: 1111 1111 1111 1111", "repeated digits are excluded"),
        p("CREDITCARD", "de", "pii_credit_card", "Abgebucht wurde am Montag von ", "4012 8888 8888 1881", ".", carrier="prose", tags=("no_context",)),
        p("CREDITCARD", "de", "pii_credit_card", '{"inhaber": "M. Kaya", "karte": "', "5200828282828210", '"}', carrier="json"),
        p("CREDITCARD", "de", "pii_credit_card", "Kunde;Karte\nKaya;", "4000 0000 0000 0002", "", carrier="csv"),
        p("CREDITCARD", "de", "pii_credit_card", "| Zahlart | Nummer |\n|---|---|\n| Visa | ", "4556 7375 8006 5008", " |", carrier="table"),
        p("CREDITCARD", "de", "pii_credit_card", "Karten-Nr.:", "5432 1098 7654 3212", "  Unterschrift: ______", tags=("ocr",)),
        p("CREDITCARD", "de", "pii_credit_card", "Karte ", "4111​1111​1111​1111", "", tags=("obfuscated",)),
        p("CREDITCARD", "en", "pii_credit_card", "Charge it to ", "3714 496353 98431", " please.", carrier="prose", tags=("no_context",)),
        p("CREDITCARD", "en", "pii_credit_card", '{"payment": {"pan": "', "6011111111111117", '"}}', carrier="json"),
        p("CREDITCARD", "en", "pii_credit_card", "payment:\n  card: ", "3530 1113 3330 0000", "\n", carrier="yaml"),
        p("CREDITCARD", "en", "pii_credit_card", "<card><number>", "4012888888881881", "</number></card>", carrier="xml"),
        p("CREDITCARD", "en", "pii_credit_card", "Card no. ", "4111 1111\n1111 1111", "", tags=("ocr",), gap=True),
        n("CREDITCARD", "de", "pii_credit_card", "Kartennummer: **** **** **** 1111", "masked card number", tags=("obfuscated",)),
        n("CREDITCARD", "de", "pii_credit_card", "Kartennummer: 4111 1111 1111", "too few digits for a card number"),
        n("CREDITCARD", "de", "pii_credit_card", "Bestellnummer 1234 5678 9012 3456", "Luhn checksum fails"),
        n("CREDITCARD", "de", "pii_credit_card", "Karte endet auf 4242.", "only the last four digits", carrier="prose"),
        n("CREDITCARD", "en", "pii_credit_card", "Card ending in 4242 was declined.", "only the last four digits", carrier="prose"),
        n("CREDITCARD", "en", "pii_credit_card", "Card: 5555 5555 5555 4445", "Luhn checksum fails"),
        n("CREDITCARD", "en", "pii_credit_card", "Order 0000 0000 0000 0000", "repeated digits are excluded"),
        n("CREDITCARD", "en", "pii_credit_card", "Card: XXXX-XXXX-XXXX-1881", "masked card number", tags=("obfuscated",)),
        # K03 in balanced: an order or transaction number in card form drops below the threshold;
        # an order number with its own value next to a card term does not.
        p("CREDITCARD", "de", "pii_credit_card", "Kreditkarte ", "4111 1111 1111 1111", " für Bestellnummer 4711.", carrier="prose", mode="balanced"),
        p("CREDITCARD", "de", "pii_credit_card", "Bestellnummer 4711, bezahlt mit Kreditkarte ", "5555 5555 5555 4444", carrier="prose", mode="balanced"),
        p("CREDITCARD", "en", "pii_credit_card", "Credit card ", "5555 5555 5555 4444", " for order number 1182.", carrier="prose", mode="balanced"),
        p("CREDITCARD", "en", "pii_credit_card", "Order number 1182, paid by Visa ", "4012 8888 8888 1881", carrier="prose", mode="balanced"),
        n("CREDITCARD", "de", "pii_credit_card", "Bestellnummer 4111 1111 1111 1111 wurde versandt.", "order number that passes Luhn", carrier="prose", mode="balanced"),
        n("CREDITCARD", "de", "pii_credit_card", "Transaktionsnummer 5555 5555 5555 4444", "transaction number that passes Luhn", mode="balanced"),
        n("CREDITCARD", "en", "pii_credit_card", "Order number 4111 1111 1111 1111 shipped today.", "order number that passes Luhn", carrier="prose", mode="balanced"),
        n("CREDITCARD", "en", "pii_credit_card", "Transaction ID 5555 5555 5555 4444 was settled.", "transaction number that passes Luhn", carrier="prose", mode="balanced"),
        # K03 context engine, balanced mode: a Luhn-valid number keeps its checksum points,
        # but an order or transaction number field right before it outweighs them.
        p("CREDITCARD", "de", "pii_credit_card", "Bestellnummer 4711, bezahlt mit Kreditkarte ", "4111 1111 1111 1111", ".", carrier="prose", mode="balanced"),
        p("CREDITCARD", "de", "pii_credit_card", "Kartennummer: ", "5555 5555 5555 4444", " (Rechnungsnummer 88213)", mode="balanced"),
        p("CREDITCARD", "de", "pii_credit_card", "Die Zahlung lief über ", "4012 8888 8888 1881", ".", carrier="prose", tags=("no_context",), mode="balanced"),
        p("CREDITCARD", "en", "pii_credit_card", "Order no. 4711 was paid by credit card ", "4111 1111 1111 1111", ".", carrier="prose", mode="balanced"),
        p("CREDITCARD", "en", "pii_credit_card", "Card number: ", "5555 5555 5555 4444", " (invoice number 88213)", mode="balanced"),
        p("CREDITCARD", "en", "pii_credit_card", "The payment went through on ", "4012 8888 8888 1881", ".", carrier="prose", tags=("no_context",), mode="balanced"),
        n("CREDITCARD", "de", "pii_credit_card", "Bestellnummer 4532 0151 1283 0366", "Luhn-valid order number (counter-context)", mode="balanced"),
        n("CREDITCARD", "de", "pii_credit_card", "Transaktionsnummer: 4916 3385 0608 2832", "Luhn-valid transaction number (counter-context)", mode="balanced"),
        n("CREDITCARD", "de", "pii_credit_card", "Die Seriennummer 6011000990139424 steht auf dem Typenschild.", "Luhn-valid serial number (counter-context)", carrier="prose", mode="balanced"),
        n("CREDITCARD", "en", "pii_credit_card", "Order number 4532 0151 1283 0366", "Luhn-valid order number (counter-context)", mode="balanced"),
        n("CREDITCARD", "en", "pii_credit_card", "Transaction ID: 4916 3385 0608 2832", "Luhn-valid transaction number (counter-context)", mode="balanced"),
        n("CREDITCARD", "en", "pii_credit_card", "The serial number 6011000990139424 is on the label.", "Luhn-valid serial number (counter-context)", carrier="prose", mode="balanced"),
    ],
    "CREDITCARD_CVV": [
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Karte 4111 1111 1111 1111, CVV: ", "123", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Card 5555 5555 5555 4444, CVC2 is ", "884", also=(("CREDITCARD", "5555 5555 5555 4444"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Amex 3782 822463 10005. Card verification code: ", "1234", also=(("CREDITCARD", "3782 822463 10005"),)),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "CVV: 12", "too short"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Security code: 123", "unsupported ambiguous anchor"),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Karte 4012 8888 8888 1881, Kartenprüfnummer ", "321", also=(("CREDITCARD", "4012 8888 8888 1881"),)),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Karte: 5200 8282 8282 8210\nCVC: ", "456", "\nInhaber: M. Kaya", carrier="kv", also=(("CREDITCARD", "5200 8282 8282 8210"),)),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Die Karte 4111 1111 1111 1111 hat den Sicherheitscode ", "642", ".", carrier="prose", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kreditkarte 5555 5555 5555 4444 – CVV2: ", "071", also=(("CREDITCARD", "5555 5555 5555 4444"),)),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Karte 4000 0000 0000 0002 | Kartenprüfziffer:", "815", tags=("ocr",), also=(("CREDITCARD", "4000 0000 0000 0002"),)),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", '{"karte": "4000000000000002", "cvv": "', "903", '"}', carrier="json", also=(("CREDITCARD", "4000000000000002"),)),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Karte 4111 1111 1111 1111 / ", "737", "", tags=("no_context",), gap=True, also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Card 4000 0000 0000 0002, CVV ", "318", also=(("CREDITCARD", "4000 0000 0000 0002"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Visa 4012888888881881 / CVC: ", "552", also=(("CREDITCARD", "4012888888881881"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "card:\n  number: 4111 1111 1111 1111\n  cvv: ", "903", "\n", carrier="yaml", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "The card 5200 8282 8282 8210 has the card verification value ", "274", ".", carrier="prose", also=(("CREDITCARD", "5200 8282 8282 8210"),)),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "| Card | CVV |\n|---|---|\n| 4111 1111 1111 1111 | ", "246", " |", carrier="table", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "CVV: 123 – eine Kartennummer fehlt.", "CVV without a payment card in the text"),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Sicherheitscode: ***", "masked value", tags=("obfuscated",)),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Karte 4111 1111 1111 1112, CVV 123", "card fails Luhn, so the CVV has no payment card"),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Das CVV-Feld ist ein Pflichtfeld.", "field name without a value", carrier="prose"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "CVV2 is required for card payments.", "field name without a value", carrier="prose"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "CVV: 1234567", "too many digits"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Card 5555 5555 5555 4445, CVC 321", "card fails Luhn, so the CVC has no payment card"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "cvv: abc", "value is not numeric", carrier="yaml"),
    ],
    "CREDITCARD_EXPIRY": [
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Kreditkarte Ablaufdatum: ", "12/29"),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Credit card expiry date is ", "01-2030"),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Kreditkarte gültig bis ", "7/2028"),
        n("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Expiration: 13/29", "month exceeds 12"),
        n("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Zeitraum: 12/29", "date-like value lacks a card-expiry anchor"),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Visa, Ablaufdatum: ", "03/27"),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Die Debitkarte ist gültig bis ", "11/2026", ".", carrier="prose"),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Karte 4111 1111 1111 1111, gültig bis ", "09/28", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Mastercard ablaufdatum=", "05/2031", carrier="kv"),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Kreditkarte | Ablaufdatum:", "08/29", tags=("ocr",), gap=True),
        p("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", '{"karte": "4111111111111111", "ablaufdatum": "', "12/29", '"}', carrier="json", also=(("CREDITCARD", "4111111111111111"),)),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Mastercard expires ", "04/27"),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Card 4012 8888 8888 1881, expiry: ", "10/2029", also=(("CREDITCARD", "4012 8888 8888 1881"),)),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "My Amex expires on ", "06/28", ".", carrier="prose", gap=True),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Your payment card expiration date is ", "2/2030", ".", carrier="prose"),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Visa expiration=", "12-28", carrier="kv"),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Debit card, expires:", "01/31", tags=("ocr",)),
        p("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "card:\n  number: 4111 1111 1111 1111\n  expiry: ", "12/29", "\n", carrier="yaml", gap=True, also=(("CREDITCARD", "4111 1111 1111 1111"),)),
        n("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Angebot gültig bis 12/29.", "offer validity without a card", carrier="prose"),
        n("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Kreditkarte Ablaufdatum: 00/29", "month zero"),
        n("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Lizenz Ablaufdatum: 06/27", "licence expiry, not a card"),
        n("CREDITCARD_EXPIRY", "de", "pii_credit_card_expiry", "Kreditkarte Ablaufdatum: MM/JJ", "template placeholder", tags=("obfuscated",)),
        n("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "The certificate expires 03/27.", "certificate expiry, not a card", carrier="prose"),
        n("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Credit card expiry: 12/2", "year has one digit"),
        n("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Trial expiration: 01/30", "trial expiry, not a card"),
        n("CREDITCARD_EXPIRY", "en", "pii_credit_card_expiry", "Credit card expiry: MM/YY", "template placeholder", tags=("obfuscated",)),
    ],
    "IBAN": [
        p("IBAN", "de", "pii_iban_de", "IBAN: ", "DE89370400440532013000"),
        p("IBAN", "en", "pii_iban_generic", "Bank account: ", "GB82WEST12345698765432"),
        p("IBAN", "de", "pii_iban_de", "Zahlung an ", "DE89 3704 0044 0532 0130 00"),
        n("IBAN", "de", "pii_iban_de", "IBAN: DE89370400440532013001", "MOD-97 checksum fails"),
        n("IBAN", "en", "pii_iban_generic", "Reference DE001234", "too short for an IBAN"),
        p("IBAN", "de", "pii_iban_de", "Bitte überweisen Sie den Betrag auf ", "DE02120300000000202051", ".", carrier="prose", tags=("no_context",)),
        p("IBAN", "de", "pii_iban_generic", "IBAN (Österreich): ", "AT611904300234573201"),
        p("IBAN", "de", "pii_iban_de", '{"kontoinhaber": "J. Weber", "iban": "', "DE68210501700012345678", '"}', carrier="json"),
        p("IBAN", "de", "pii_iban_de", "Name;IBAN\nWeber;", "DE18 4306 0967 1234 5678 00", "", carrier="csv"),
        p("IBAN", "de", "pii_iban_generic", "| Bank | IBAN |\n|---|---|\n| Raiffeisen | ", "CH9300762011623852957", " |", carrier="table"),
        p("IBAN", "de", "pii_iban_de", "IBAN:", "DE02100500000024290661", "  BIC: siehe oben", tags=("ocr",)),
        p("IBAN", "de", "pii_iban_de", "IBAN: ", "DE02​3705​0299​0000​6847​12", "", tags=("obfuscated",)),
        p("IBAN", "de", "pii_iban_generic", "IBAN: ", "AT61 1904 3002 3457 3201", "", gap=True),
        p("IBAN", "en", "pii_iban_generic", "Please wire the deposit to ", "NL91ABNA0417164300", " by Friday.", carrier="prose", tags=("no_context",)),
        p("IBAN", "en", "pii_iban_generic", '{"beneficiary": "Acme BV", "iban": "', "FR1420041010050500013M02606", '"}', carrier="json"),
        p("IBAN", "en", "pii_iban_generic", "payee:\n  iban: ", "ES9121000418450200051332", "\n", carrier="yaml"),
        p("IBAN", "en", "pii_iban_de", "<account><iban>", "DE02700202700010108669", "</iban></account>", carrier="xml"),
        p("IBAN", "en", "pii_iban_generic", "IBAN ", "BE68539007547034", "  |  Ref. 2026/10", tags=("ocr",)),
        p("IBAN", "en", "pii_iban_generic", "IBAN: ", "GB29 NWBK 6016 1331 9268 19", "", gap=True),
        p("IBAN", "en", "pii_iban_de", "IBAN: ", "DE44 5001 0517\n5407 3249 31", "", tags=("ocr",)),
        n("IBAN", "de", "pii_iban_de", "IBAN: DE89 3704 0044 XXXX XXXX 00", "masked IBAN", tags=("obfuscated",)),
        n("IBAN", "de", "pii_iban_generic", "Artikelnummer AB12CDEFGHIJKLMN", "letters where check digits belong"),
        n("IBAN", "de", "pii_iban_generic", "IBAN: AT611904300234573202", "MOD-97 checksum fails"),
        n("IBAN", "de", "pii_iban_de", "Die IBAN folgt per Post.", "field name without a value", carrier="prose"),
        n("IBAN", "en", "pii_iban_generic", "IBAN: GB82WEST12345698765433", "MOD-97 checksum fails"),
        n("IBAN", "en", "pii_iban_generic", "Serial SN12ABCDEFGHIJK", "serial number shaped like an IBAN fails MOD-97"),
        n("IBAN", "en", "pii_iban_de", "IBAN: DE00 0000 0000 0000 0000 00", "all-zero placeholder fails MOD-97", tags=("obfuscated",)),
        n("IBAN", "en", "pii_iban_generic", "iban: <redacted>", "redacted value", carrier="yaml"),
        # K03 in balanced: the IBAN term is nearer than the invoice number term.
        p("IBAN", "de", "pii_iban_de", "Bitte die Rechnungsnummer im Verwendungszweck angeben. IBAN ", "DE89370400440532013000", carrier="prose", mode="balanced"),
        p("IBAN", "en", "pii_iban_generic", "Please quote the invoice number as reference. IBAN: ", "GB82WEST12345698765432", carrier="prose", mode="balanced"),
    ],
    "SWIFT_CODE": [
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC: ", "DEUTDEFF500"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "SWIFT code is ", "NEDSZAJJ"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC = ", "MARKDEF1100"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "SWIFT: DEUTD3", "invalid BIC length"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "Bankcode DEUTDEFF500", "missing BIC or SWIFT anchor"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "IBAN: DE89370400440532013000\nBIC: ", "COBADEFFXXX", "\nBank: Commerzbank", carrier="kv", also=(("IBAN", "DE89370400440532013000"),)),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "bank:\n  bic: ", "BYLADEM1001", "\n", carrier="yaml"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC:", "GENODEF1M04", "  Verwendungszweck: Miete", tags=("ocr",)),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "Swift: ", "INGDDEFFXXX"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "SWIFT-Code: ", "COBADEFFXXX", ""),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", '{"bic": "', "DEUTDEFF500", '"}', carrier="json"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "Die Bank hat die Kennung ", "BYLADEM1001", ".", carrier="prose", tags=("no_context",), gap=True),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "BIC: ", "BARCGB22"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "beneficiary_bank:\n  swift: ", "CHASUS33", "\n", carrier="yaml"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "The BIC code is ", "UBSWCHZH80A", ".", carrier="prose"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "swift=", "BNPAFRPP", "\namount=1200.00", carrier="kv"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "SWIFT code:", "RABONL2U", "   Page 1", tags=("ocr",)),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "<bank><bic>", "BARCGB22", "</bic></bank>", carrier="xml"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC: 12345678", "bank and country code must be letters"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC: siehe Kontoauszug", "field without a value"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "Swift ist eine Programmiersprache von Apple.", "programming language, not a bank field", carrier="prose"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC: ****DEFF", "masked value", tags=("obfuscated",)),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "Swift code is powerful and fast.", "programming language, not a bank field", carrier="prose"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "BIC: DEUTDEFF5", "nine characters is not a BIC length"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "We moved the SWIFT integration to Q3.", "project name without a value", carrier="prose"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "SWIFT: 1234ABCD", "bank code must be letters"),
    ],
    "EMPLOYEE_ID": [
        p("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID ", "EMP-1042", " belongs to the new hire.", carrier="prose", source_fixture_id="specific-0007"),
        p("EMPLOYEE_ID", "de", "pii_employee_id", "Personalnummer: ", "P-4711"),
        p("EMPLOYEE_ID", "en", "pii_employee_id", "Personnel number is ", "STAFF/2048"),
        n("EMPLOYEE_ID", "de", "pii_employee_id", "Build: EMP-4711", "identifier lacks an employee anchor"),
        n("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID EMPLOYEE", "value contains no digit"),
        p("EMPLOYEE_ID", "de", "pii_employee_id", "mitarbeiter:\n  name: Jana Roth\n  personalnummer: ", "PN-30817", "\n", carrier="yaml"),
        p("EMPLOYEE_ID", "de", "pii_employee_id", "Mitarbeiter-ID=", "M-55102", "\nabteilung=Einkauf", carrier="kv"),
        p("EMPLOYEE_ID", "de", "pii_employee_id_ocr_field", "Mitarbeiterausweis\nID: ", "HR 55019", tags=("ocr",)),
        p("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Bitte schalten Sie ", "EMP-BER-0815", " für das Lager frei.", carrier="prose", tags=("no_context",)),
        p("EMPLOYEE_ID", "de", "pii_employee_id", '{"personalnummer": "', "PN-40211", '"}', carrier="json"),
        p("EMPLOYEE_ID", "de", "pii_employee_id", "Personal;Name\n", "PN-40212", ";Jana Roth", carrier="csv", gap=True),
        p("EMPLOYEE_ID", "en", "pii_employee_id", "staff:\n  employee_id: ", "E-77120", "\n", carrier="yaml"),
        p("EMPLOYEE_ID", "en", "pii_employee_id_ocr_field", "Staff badge\nID: ", "STAFF 20481", tags=("ocr",)),
        p("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Ticket reassigned to ", "EMP-NYC-3321", ".", carrier="prose", tags=("no_context",)),
        p("EMPLOYEE_ID", "en", "pii_employee_id", "Staff number: ", "S-90311"),
        p("EMPLOYEE_ID", "en", "pii_employee_id", '<employee><id>', "E-77121", "</id></employee>", carrier="xml"),
        n("EMPLOYEE_ID", "de", "pii_employee_id_ocr_field", "Rechnung\nID: AB 12345", "generic ID field without employment context", tags=("ocr",)),
        n("EMPLOYEE_ID", "de", "pii_employee_id", "Personalnummer: wird nachgereicht", "field without a value"),
        n("EMPLOYEE_ID", "de", "pii_employee_id", "Kennung: XY-2048", "generic identifier without employment context"),
        n("EMPLOYEE_ID", "de", "pii_employee_id", "Die Personalnummer steht auf dem Ausweis.", "field name without a value", carrier="prose"),
        n("EMPLOYEE_ID", "en", "pii_employee_id_ocr_field", "Invoice\nID: INV 20481", "generic ID field without employment context", tags=("ocr",)),
        n("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Template EMP-NAME-HERE", "template placeholder without a digit"),
        n("EMPLOYEE_ID", "en", "pii_employee_id", "Employee number: TBD", "field without a value"),
        n("EMPLOYEE_ID", "en", "pii_employee_id", "Please enter your employee ID below.", "field name without a value", carrier="prose"),
    ],
    "CUSTOMER_ID": [
        p("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer: ", "KD-88231"),
        p("CUSTOMER_ID", "en", "pii_customer_id", "Customer ID ", "CUST-2048"),
        p("CUSTOMER_ID", "de", "pii_customer_id", "Debitorennummer = ", "DEB/4711"),
        n("CUSTOMER_ID", "de", "pii_customer_id", "Rechnungsnummer: KD-88231", "wrong identifier anchor"),
        n("CUSTOMER_ID", "en", "pii_customer_id", "Customer ID CUSTOMER", "value contains no digit"),
        p("CUSTOMER_ID", "de", "pii_customer_id", "Ihre Kundennummer lautet ", "KD-10293", ".", carrier="prose", gap=True),
        p("CUSTOMER_ID", "de", "pii_customer_id", "kunde:\n  kundennummer: ", "KD-55120", "\n", carrier="yaml"),
        p("CUSTOMER_ID", "de", "pii_customer_id", "Kunden-ID=", "K-20931", "\nstatus=aktiv", carrier="kv"),
        p("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer:", "KD-40917", "   Datum: siehe oben", tags=("ocr",)),
        p("CUSTOMER_ID", "de", "pii_customer_id", "Bei Rückfragen bitte die Kundennummer ", "KD-77412", " angeben.", carrier="prose"),
        p("CUSTOMER_ID", "de", "pii_customer_id", '{"kundennummer": "', "KD-99120", '"}', carrier="json"),
        p("CUSTOMER_ID", "de", "pii_customer_id", "| Kundennummer | ", "KD-99121", " |", carrier="table"),
        p("CUSTOMER_ID", "en", "pii_customer_id", "customer:\n  customer_id: ", "C-104882", "\n", carrier="yaml"),
        p("CUSTOMER_ID", "en", "pii_customer_id", "customer number=", "CN-33019", carrier="kv"),
        p("CUSTOMER_ID", "en", "pii_customer_id", "Please quote customer number ", "CN-50112", " in every reply.", carrier="prose"),
        p("CUSTOMER_ID", "en", "pii_customer_id", "Customer ID:", "CUST-7781", "  Page 1 of 3", tags=("ocr",)),
        p("CUSTOMER_ID", "en", "pii_customer_id", "Customer number: ", "100-2048-77"),
        p("CUSTOMER_ID", "en", "pii_customer_id", "Debitor ", "DEB-1188", ""),
        p("CUSTOMER_ID", "en", "pii_customer_id", '<customer id="', "CUST-9001", '"/>', carrier="xml"),
        n("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer: folgt", "value contains no digit"),
        n("CUSTOMER_ID", "de", "pii_customer_id", "Bestellnummer: B-88231", "wrong identifier anchor"),
        n("CUSTOMER_ID", "de", "pii_customer_id", "Bitte geben Sie Ihre Kundennummer an.", "field name without a value", carrier="prose"),
        n("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer: 0000", "all-zero value is excluded"),
        n("CUSTOMER_ID", "en", "pii_customer_id", "Ticket number: T-2048", "wrong identifier anchor"),
        n("CUSTOMER_ID", "en", "pii_customer_id", "Customer number: pending", "value contains no digit"),
        n("CUSTOMER_ID", "en", "pii_customer_id", "Every customer needs an ID before checkout.", "field name without a value", carrier="prose"),
        n("CUSTOMER_ID", "en", "pii_customer_id", "Customer ID: 00", "too short"),
    ],
    "PATIENT_ID": [
        p("PATIENT_ID", "en", "pii_patient_id", "Medical record number ", "MRN-204817", " belongs to this patient.", carrier="prose", source_fixture_id="specific-medical-record-number-01"),
        p("PATIENT_ID", "de", "pii_patient_id", "Patientennummer: ", "PAT-2048"),
        p("PATIENT_ID", "en", "pii_patient_id", "MRN = ", "HOSP/7781"),
        n("PATIENT_ID", "de", "pii_patient_id", "Ticket: PAT-2048", "identifier lacks a patient anchor"),
        n("PATIENT_ID", "en", "pii_patient_id", "Patient ID PATIENT", "value contains no digit"),
        p("PATIENT_ID", "de", "pii_patient_id", "Patienten-ID: ", "P-2026-0193"),
        p("PATIENT_ID", "de", "pii_patient_id", "fall:\n  patientennummer: ", "PAT-55190", "\n", carrier="yaml"),
        p("PATIENT_ID", "de", "pii_patient_id", "Die Patientennummer ", "PAT-81022", " steht auf dem Etikett.", carrier="prose"),
        p("PATIENT_ID", "de", "pii_patient_id", "Patientennummer:", "PAT-30912", "  Station 4B", tags=("ocr",)),
        p("PATIENT_ID", "de", "pii_patient_id", "station=4B\npatienten_id=", "PAT-72210", carrier="kv"),
        p("PATIENT_ID", "de", "pii_patient_id", '{"patientennummer": "', "PAT-10931", '"}', carrier="json"),
        p("PATIENT_ID", "en", "pii_patient_id", "Patient ID: ", "PT-88412"),
        p("PATIENT_ID", "en", "pii_patient_id", "encounter:\n  mrn: ", "MRN-330117", "\n", carrier="yaml"),
        p("PATIENT_ID", "en", "pii_patient_id", "The patient number is ", "PT-44001", ".", carrier="prose"),
        p("PATIENT_ID", "en", "pii_patient_id", "MRN:", "MRN-981133", "  Ward 7", tags=("ocr",)),
        p("PATIENT_ID", "en", "pii_patient_id", "| MRN | Ward |\n|---|---|\n| ", "MRN-981134", " | 7 |", carrier="table"),
        n("PATIENT_ID", "de", "pii_patient_id", "Patientennummer: unbekannt", "value contains no digit"),
        n("PATIENT_ID", "de", "pii_patient_id", "Zimmernummer: PAT-12", "wrong identifier anchor"),
        n("PATIENT_ID", "de", "pii_patient_id", "Die Patientennummer wird bei der Aufnahme vergeben.", "field name without a value", carrier="prose"),
        n("PATIENT_ID", "de", "pii_patient_id", "Patientennummer: ****", "masked value", tags=("obfuscated",)),
        n("PATIENT_ID", "en", "pii_patient_id", "Room number: PT-12", "wrong identifier anchor"),
        n("PATIENT_ID", "en", "pii_patient_id", "MRN: pending", "value contains no digit"),
        n("PATIENT_ID", "en", "pii_patient_id", "Each patient ID is assigned at admission.", "field name without a value", carrier="prose"),
        n("PATIENT_ID", "en", "pii_patient_id", "Patient ID: ****", "masked value", tags=("obfuscated",)),
    ],
    "STUDENT_ID": [
        p("STUDENT_ID", "de", "pii_student_id", "Die Matrikelnummer lautet ", "S89750921", ".", carrier="prose", source_fixture_id="school-student-id-01"),
        p("STUDENT_ID", "en", "pii_student_id", "Student ID ", "STU-9911"),
        p("STUDENT_ID", "de", "pii_student_id", "Schülernummer: ", "SCH/2042"),
        n("STUDENT_ID", "de", "pii_student_id", "Kursnummer: STU-9911", "wrong identifier anchor"),
        n("STUDENT_ID", "en", "pii_student_id", "Student ID STUDENT", "value contains no digit"),
        p("STUDENT_ID", "de", "pii_student_id", "Matrikelnummer: ", "4718203"),
        p("STUDENT_ID", "de", "pii_student_id", "studierende:\n  matrikelnummer: ", "5520183", "\n", carrier="yaml"),
        p("STUDENT_ID", "de", "pii_student_id", "Schüler-ID=", "SCH-3301", carrier="kv"),
        p("STUDENT_ID", "de", "pii_student_id", "Matrikelnummer:", "6610294", "  Semester: WS", tags=("ocr",)),
        p("STUDENT_ID", "de", "pii_student_id", '{"matrikelnummer": "', "4718204", '"}', carrier="json"),
        p("STUDENT_ID", "de", "pii_student_id", "Name;Matrikelnummer\nLea Brandt;", "4718205", "", carrier="csv"),
        p("STUDENT_ID", "en", "pii_student_id", "Student number: ", "U2026-1187"),
        p("STUDENT_ID", "en", "pii_student_id", "enrolment:\n  student_id: ", "STU-50331", "\n", carrier="yaml"),
        p("STUDENT_ID", "en", "pii_student_id", "Her student ID is ", "STU-77104", ".", carrier="prose"),
        p("STUDENT_ID", "en", "pii_student_id", "Student ID:", "STU-66019", "  Term: Fall", tags=("ocr",)),
        p("STUDENT_ID", "en", "pii_student_id", '<student id="', "STU-9912", '"/>', carrier="xml"),
        n("STUDENT_ID", "de", "pii_student_id", "Matrikelnummer: beantragt", "value contains no digit"),
        n("STUDENT_ID", "de", "pii_student_id", "Raumnummer: S-204", "wrong identifier anchor"),
        n("STUDENT_ID", "de", "pii_student_id", "Die Matrikelnummer erhalten Sie nach der Einschreibung.", "field name without a value", carrier="prose"),
        n("STUDENT_ID", "de", "pii_student_id", "Matrikelnummer: 00000", "all-zero value is excluded"),
        n("STUDENT_ID", "en", "pii_student_id", "Course code: CS-101", "wrong identifier anchor"),
        n("STUDENT_ID", "en", "pii_student_id", "Student number: pending", "value contains no digit"),
        n("STUDENT_ID", "en", "pii_student_id", "Bring your student ID to the exam.", "field name without a value", carrier="prose"),
        n("STUDENT_ID", "en", "pii_student_id", "Student ID: 00000", "all-zero value is excluded"),
    ],
    "APPLICANT_ID": [
        p("APPLICANT_ID", "de", "pii_applicant_id", "Ihre Bewerbernummer ist ", "BEW-2026-10482", ".", carrier="prose", source_fixture_id="school-applicant-id-01"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "Applicant number ", "APP-713"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "Candidate ID: ", "CAN/5581"),
        n("APPLICANT_ID", "de", "pii_applicant_id", "Vorgangsnummer: BEW-713", "wrong identifier anchor"),
        n("APPLICANT_ID", "en", "pii_applicant_id", "Applicant ID APPLICANT", "value contains no digit"),
        p("APPLICANT_ID", "de", "pii_applicant_id", "Bewerbernummer: ", "BEW-2026-20117"),
        p("APPLICANT_ID", "de", "pii_applicant_id", "bewerbung:\n  bewerbernummer: ", "BEW-3301", "\n", carrier="yaml"),
        p("APPLICANT_ID", "de", "pii_applicant_id", "Bewerber-ID=", "B-44120", carrier="kv"),
        p("APPLICANT_ID", "de", "pii_applicant_id", "Bewerbernummer:", "BEW-5519", "  Eingang: Mai", tags=("ocr",)),
        p("APPLICANT_ID", "de", "pii_applicant_id", '{"bewerbernummer": "', "BEW-5520", '"}', carrier="json"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "applicant:\n  applicant_id: ", "APP-88231", "\n", carrier="yaml"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "applicant number=", "APP-3391", "\nstage=interview", carrier="kv"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "Candidate ID ", "CAN-2026-17"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "Your applicant ID is ", "APP-2026-0042", ".", carrier="prose"),
        p("APPLICANT_ID", "en", "pii_applicant_id", "Applicant ID:", "APP-55102", "  Round 2", tags=("ocr",)),
        p("APPLICANT_ID", "en", "pii_applicant_id", "| Applicant ID | ", "APP-55103", " |", carrier="table"),
        n("APPLICANT_ID", "de", "pii_applicant_id", "Bewerbernummer: folgt per Post", "value contains no digit"),
        n("APPLICANT_ID", "de", "pii_applicant_id", "Stellennummer: BEW-2026", "wrong identifier anchor"),
        n("APPLICANT_ID", "de", "pii_applicant_id", "Die Bewerbernummer erhalten Sie per E-Mail.", "field name without a value", carrier="prose"),
        n("APPLICANT_ID", "de", "pii_applicant_id", "Bewerber-ID: ****", "masked value", tags=("obfuscated",)),
        n("APPLICANT_ID", "en", "pii_applicant_id", "Job ID: APP-713", "wrong identifier anchor"),
        n("APPLICANT_ID", "en", "pii_applicant_id", "Applicant number: pending", "value contains no digit"),
        n("APPLICANT_ID", "en", "pii_applicant_id", "Every candidate ID is issued after screening.", "field name without a value", carrier="prose"),
        n("APPLICANT_ID", "en", "pii_applicant_id", "Applicant ID: ****", "masked value", tags=("obfuscated",)),
    ],
    "USERNAME": [
        p("USERNAME", "de", "pii_username", "Benutzername: ", "ada.lovelace"),
        p("USERNAME", "en", "pii_username", "Username is ", "maria_ops_24"),
        p("USERNAME", "en", "pii_username", "Account name: ", "svc-build-7"),
        n("USERNAME", "de", "pii_username", "Benutzername: admin", "reserved generic username"),
        n("USERNAME", "en", "pii_username", "Owner maria_ops_24", "value lacks a username anchor"),
        p("USERNAME", "de", "pii_username", "Ihr Benutzername lautet ", "j.weber", ".", carrier="prose"),
        p("USERNAME", "de", "pii_username", "konto:\n  benutzername: ", "k.hoff", "\n", carrier="yaml"),
        p("USERNAME", "de", "pii_username", "login=", "lena.vogt", "\nrolle=lesen", carrier="kv"),
        p("USERNAME", "de", "pii_username", "Benutzer: ", "mkrause"),
        p("USERNAME", "de", "pii_username", "Benutzername:", "tom.berger", "   Passwort: ********", tags=("ocr",)),
        p("USERNAME", "de", "pii_username", '{"benutzername": "', "p.lang", '"}', carrier="json"),
        p("USERNAME", "en", "pii_username", "user:\n  username: ", "priya.nair", "\n", carrier="yaml"),
        p("USERNAME", "en", "pii_username", "login=", "tom_reyes", carrier="kv"),
        p("USERNAME", "en", "pii_username", "Username:", "r.patel", "   Page 2", tags=("ocr",)),
        p("USERNAME", "en", "pii_username", "User name: ", "a.kowalski"),
        p("USERNAME", "en", "pii_username", "Log in as ", "maria_ops_24", " and restart the job.", carrier="prose", tags=("no_context",), gap=True),
        p("USERNAME", "en", "pii_username", "| User name | ", "dev.lead", " |", carrier="table"),
        n("USERNAME", "de", "pii_username", "Benutzername: root", "reserved generic username"),
        n("USERNAME", "de", "pii_username", "Benutzername: erforderlich", "form label, not an account"),
        n("USERNAME", "de", "pii_username", "Der Login-Flow wurde überarbeitet.", "prose about the login flow", carrier="prose"),
        n("USERNAME", "de", "pii_username", "Benutzername: falsch", "error message, not an account"),
        n("USERNAME", "en", "pii_username", "Username: required", "form label, not an account"),
        n("USERNAME", "en", "pii_username", "The CLI login token expires hourly.", "prose about a login token", carrier="prose"),
        n("USERNAME", "en", "pii_username", "Username: invalid", "error message, not an account"),
        n("USERNAME", "en", "pii_username", "username: user", "reserved generic username", carrier="yaml"),
    ],
    "DOB": [
        p("DOB", "de", "pii_date_of_birth", "Geburtsdatum: ", "29.02.2000"),
        p("DOB", "en", "pii_date_of_birth_written_day_first", "The patient record lists her date of birth as ", "14 March 1985", " in the intake form.", carrier="prose", source_fixture_id="general-dob-01"),
        p("DOB", "de", "pii_date_of_birth_written_day_first", "Geboren am ", "14. März 1985"),
        n("DOB", "de", "pii_date_of_birth_written_day_first", "Geburtsdatum: 31. Februar 1985", "invalid calendar date"),
        n("DOB", "en", "pii_date_of_birth_written_day_first", "The archive covers 14 March 1985.", "date lacks a birth anchor", carrier="prose"),
        p("DOB", "de", "pii_date_of_birth", "Frau Roth ist geboren am ", "03.07.1979", " in Kassel.", carrier="prose"),
        p("DOB", "de", "pii_date_of_birth", "person:\n  geburtsdatum: ", "12.11.1964", "\n", carrier="yaml"),
        p("DOB", "de", "pii_date_of_birth_written_month_first", "Geburtsdatum: ", "Juli 4, 1979"),
        p("DOB", "de", "pii_date_of_birth", "Geburtsdatum:", "01.09.1992", "  Geburtsort: Ulm", tags=("ocr",)),
        p("DOB", "de", "pii_date_of_birth", "geburtsdatum=", "17.05.2001", carrier="kv"),
        p("DOB", "de", "pii_date_of_birth", '{"geburtsdatum": "', "17.05.2001", '"}', carrier="json"),
        p("DOB", "de", "pii_date_of_birth", "Geb.-Datum: ", "08.08.1988", "", gap=True),
        p("DOB", "en", "pii_date_of_birth", "Date of birth: ", "14/03/1985"),
        p("DOB", "en", "pii_date_of_birth_written_month_first", "Date of birth: ", "March 14th, 1985"),
        p("DOB", "en", "pii_date_of_birth_written_month_first", "His DOB is ", "July 4, 1979", ".", carrier="prose"),
        p("DOB", "en", "pii_date_of_birth", "patient:\n  dob: ", "02/11/1990", "\n", carrier="yaml"),
        p("DOB", "en", "pii_date_of_birth", "DOB:", "21-06-1975", "   Sex: F", tags=("ocr",)),
        p("DOB", "en", "pii_date_of_birth", '{"dob": "', "1990-11-02", '"}', carrier="json", gap=True),
        p("DOB", "en", "pii_date_of_birth", "Born on ", "02/11/1990", " in Leeds.", carrier="prose", gap=True),
        n("DOB", "de", "pii_date_of_birth", "Rechnungsdatum: 14.03.1985", "date lacks a birth anchor"),
        n("DOB", "de", "pii_date_of_birth", "Geburtsdatum: 32.01.1990", "day exceeds 31"),
        n("DOB", "de", "pii_date_of_birth", "Geburtsdatum: TT.MM.JJJJ", "template placeholder", tags=("obfuscated",)),
        n("DOB", "de", "pii_date_of_birth", "Lieferung am 03.07.2026 geplant.", "delivery date, not a birth date", carrier="prose"),
        n("DOB", "en", "pii_date_of_birth", "Date of birth: 29/02/2001", "2001 is not a leap year"),
        n("DOB", "en", "pii_date_of_birth", "Invoice date: 14/03/1985", "date lacks a birth anchor"),
        n("DOB", "en", "pii_date_of_birth", "DOB: DD/MM/YYYY", "template placeholder", tags=("obfuscated",)),
        n("DOB", "en", "pii_date_of_birth_written_month_first", "The meeting moved to March 14, 2026.", "date lacks a birth anchor", carrier="prose"),
    ],
    "FINANCIAL_ACCOUNT_NUMBER": [
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Kontonummer: ", "ACC-44001234"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number ", "A/778811"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Depot-Nr: ", "DEP-2026-42"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Bestellnummer: ACC-44001234", "wrong identifier anchor"),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number ACCOUNT", "value contains no digit"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Kontonummer: ", "0532013000"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Die Kontonummer ", "KTO-55120", " wurde gesperrt.", carrier="prose"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "bank:\n  kontonummer: ", "KTO-88123", "\n", carrier="yaml"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Depotnummer=", "DEP-77310", carrier="kv"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Konto-Nr:", "KTO-30201", "   Blatt 1", tags=("ocr",)),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", '{"kontonummer": "', "KTO-30202", '"}', carrier="json"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Bank account: ", "ACC-99120"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Your account number is ", "AC-500118", ".", carrier="prose"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "brokerage:\n  account number: ", "BRK-20931", "\n", carrier="yaml"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "account number=", "ACC-33018", carrier="kv"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number:", "ACC-44102", "   Statement 10/2026", tags=("ocr",)),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", '{"account_number": "', "ACC-44103", '"}', carrier="json"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Kontonummer: siehe Anlage", "value contains no digit"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Vertragsnummer: KTO-55120", "wrong identifier anchor"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Die Kontonummer ersetzt seit 2014 die IBAN nicht mehr.", "field name without a value", carrier="prose"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Kontonummer: ****", "masked value", tags=("obfuscated",)),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Order number: ACC-99120", "wrong identifier anchor"),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number: on file", "value contains no digit"),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Enter the account number without spaces.", "field name without a value", carrier="prose"),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number: ****", "masked value", tags=("obfuscated",)),
    ],
    "STEUERID": [
        p("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: ", "86095742719"),
        p("STEUERID", "de", "pii_steuer_id_de", "IdNr. ", "86 095 742 719"),
        p("STEUERID", "en", "pii_steuer_id_de", "German Steueridentifikationsnummer: ", "86095742719"),
        n("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: 86095742718", "checksum fails"),
        n("STEUERID", "de", "pii_steuer_id_de", "Nummer: 86095742719", "missing tax-ID anchor"),
        p("STEUERID", "de", "pii_steuer_id_de", "Ihre Steuer-ID ist ", "47110815008", ".", carrier="prose", gap=True),
        p("STEUERID", "de", "pii_steuer_id_de", "steuerpflichtiger:\n  steuer_id: ", "29384756103", "\n", carrier="yaml"),
        p("STEUERID", "de", "pii_steuer_id_de", "Steueridentifikationsnummer=", "56123904784", carrier="kv"),
        p("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID:", "31415926539", "   Finanzamt Kassel", tags=("ocr",)),
        p("STEUERID", "de", "pii_steuer_id_de", '{"steuer_id": "', "82736451927", '"}', carrier="json"),
        p("STEUERID", "de", "pii_steuer_id_de", "Für die Lohnabrechnung brauche ich noch ", "10293847565", ".", carrier="prose", tags=("no_context",), gap=True),
        p("STEUERID", "en", "pii_steuer_id_de", "Tax ID: ", "12345678903"),
        p("STEUERID", "en", "pii_steuer_id_de", "Her German tax identification number is ", "67890123455", ".", carrier="prose"),
        p("STEUERID", "en", "pii_steuer_id_de", "employee:\n  tax id: ", "47110815008", "\n", carrier="yaml"),
        p("STEUERID", "en", "pii_steuer_id_de", "tax id=", "29384756103", carrier="kv"),
        p("STEUERID", "en", "pii_steuer_id_de", "Tax ID:", "56123904784", "   Page 1", tags=("ocr",)),
        p("STEUERID", "en", "pii_steuer_id_de", '<taxpayer><taxId>', "31415926539", "</taxId></taxpayer>", carrier="xml"),
        n("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: 06095742719", "leading zero is not issued"),
        n("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: 4711081500", "only ten digits"),
        n("STEUERID", "de", "pii_steuer_id_de", "Die Steuer-ID steht auf dem Lohnsteuerbescheid.", "field name without a value", carrier="prose"),
        n("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: 12345678901", "checksum fails"),
        n("STEUERID", "en", "pii_steuer_id_de", "Tax ID: 47110815009", "checksum fails"),
        n("STEUERID", "en", "pii_steuer_id_de", "Tax ID: XXXXXXXXXXX", "masked value", tags=("obfuscated",)),
        n("STEUERID", "en", "pii_steuer_id_de", "Invoice 86095742719 is overdue.", "missing tax-ID anchor", carrier="prose"),
        n("STEUERID", "en", "pii_steuer_id_de", "Tax identification number: pending", "field without a value"),
        n("STEUERID", "en", "pii_steuer_id_de", "Tax ID: 29384756104", "checksum fails"),
    ],
    "TAX_NUMBER_DE": [
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: ", "123/456/78901"),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuer Nr. ", "12/345/67890"),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "German Steuernummer: ", "1234/567/89012"),
        n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 000/000/00000", "all-zero value is excluded"),
        n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: 123/456", "too few digits for a German tax number"),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Die Steuernummer der Praxis ist ", "21/815/08150", ".", carrier="prose", gap=True),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "firma:\n  steuernummer: ", "143/208/30142", "\n", carrier="yaml"),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "St.-Nr.: ", "93815/08152", "", gap=True),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernr=", "2181508150", carrier="kv"),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer:", "151/815/08156", "   Finanzamt Mitte", tags=("ocr",)),
        p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", '{"steuernummer": "', "123/456/78902", '"}', carrier="json"),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: ", "21/815/08150"),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "The German tax number of the branch is ", "143/208/30142", ".", carrier="prose", gap=True),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "company:\n  tax number: ", "2893/081/50812", "\n", carrier="yaml"),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "tax number=", "151/815/08156", carrier="kv"),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number:", "048/815/08153", "   Page 1", tags=("ocr",)),
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "| Tax number | ", "048/815/08154", " |", carrier="table"),
        n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 12/345", "too few digits"),
        n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Aktenzeichen: 123/456/78901", "wrong identifier anchor"),
        n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Die Steuernummer erhalten Sie vom Finanzamt.", "field name without a value", carrier="prose"),
        n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 111/111/11111", "repeated digits are excluded"),
        n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: 1234567890123456", "too many digits"),
        n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Case number: 123/456/78901", "wrong identifier anchor"),
        n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: XXX/XXX/XXXXX", "masked value", tags=("obfuscated",)),
        n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "A tax number is issued by the local tax office.", "field name without a value", carrier="prose"),
    ],
    "SOCIALID": [
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: ", "12123456A123"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Rentenversicherungsnummer ", "65 432109 Z 876"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "German SV-Nr.: ", "12 123456 A 123"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: 12123456-123", "letter position is missing"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Referenz 12123456A123", "missing social-insurance anchor"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Meine Rentenversicherungsnummer ist ", "53270587M012", ".", carrier="prose", gap=True),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "beschaeftigter:\n  sozialversicherungsnummer: ", "15 070649 C 103", "\n", carrier="yaml"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "SV-Nr=", "65180539W001", carrier="kv"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer:", "25220940K517", "   Krankenkasse: AOK", tags=("ocr",)),
        p("SOCIALID", "de", "pii_rentenversicherung_de", '{"sv_nummer": "', "53270587M013", '"}', carrier="json", gap=True),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "German pension insurance number: ", "53 270587 M 012"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "Her German social security number is ", "15070649C103", ".", carrier="prose"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "employee:\n  pension insurance number: ", "65180539W001", "\n", carrier="yaml"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "SV-Nr:", "25220940K517", "   Page 1", tags=("ocr",)),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "pension insurance number=", "12123456A124", carrier="kv"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "| SV number | ", "12123456A125", " |", carrier="table", gap=True),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: 1212345A123", "too few digits before the letter"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: siehe Ausweis", "field without a value"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Die Rentenversicherungsnummer steht im Sozialversicherungsausweis.", "field name without a value", carrier="prose"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: XX XXXXXX X XXX", "masked value", tags=("obfuscated",)),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "German pension insurance number: 12123456AB12", "two letters where one belongs"),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "Reference 65 432109 Z 876", "missing social-insurance anchor"),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "The pension insurance number is printed on the card.", "field name without a value", carrier="prose"),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "SV-Nr: XX XXXXXX X XXX", "masked value", tags=("obfuscated",)),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "Pension insurance number: 123456789012", "letter position is missing"),
    ],
    "HEALTH_INSURANCE_NUMBER": [
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Health insurance number ", "X123456789", " is in the claim.", carrier="prose", source_fixture_id="specific-health-insurance-number-01"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer: ", "A123456789"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR = ", "Z987654321"),
        n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR: A000000000", "all-zero numeric part is excluded"),
        n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Member number X123456789", "unsupported generic member anchor"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Die Versichertennummer lautet ", "M234567891", ".", carrier="prose", gap=True),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Die Krankenversicherungsnummer ist ", "M234567892", ".", carrier="prose", gap=True),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "versicherter:\n  kvnr: ", "T345678912", "\n", carrier="yaml"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR=", "R456789123", carrier="kv"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer:", "K567891234", "   Kasse: TK", tags=("ocr",)),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", '{"kvnr": "', "K567891235", '"}', carrier="json"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Health insurance number: ", "B678912345"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "insured:\n  kvnr: ", "C789123456", "\n", carrier="yaml"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "health insurance number=", "D891234567", carrier="kv"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "KVNR:", "E912345678", "   Page 1", tags=("ocr",)),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", '<insured kvnr="', "E912345679", '"/>', carrier="xml"),
        n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer: 1234567890", "first character must be a letter"),
        n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer: A12345678", "only eight digits"),
        n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Die Versichertennummer steht auf der Gesundheitskarte.", "field name without a value", carrier="prose"),
        n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Mitgliedsnummer A123456789", "unsupported generic member anchor"),
        n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Health insurance number: AB12345678", "two letters where one belongs"),
        n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "KVNR: X000000000", "all-zero numeric part is excluded"),
        n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Bring your health insurance number to the appointment.", "field name without a value", carrier="prose"),
        n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "KVNR: X*********", "masked value", tags=("obfuscated",)),
    ],
    "PHYSICIAN_NUMBER_LANR": [
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: ", "123456789"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Lebenslange Arztnummer ", "987654321"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "German LANR = ", "246813579"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: 000000000", "all-zero value is excluded"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Arztnummer: 123456789", "unsupported generic anchor"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Die verordnende Ärztin hat die LANR ", "135792468", ".", carrier="prose"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "arzt:\n  lanr: ", "314159265", "\n", carrier="yaml"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR=", "271828182", carrier="kv"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR:", "161803398", "   BSNR: siehe Stempel", tags=("ocr",)),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", '{"lanr": "', "141421356", '"}', carrier="json"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "Physician number: ", "173205080"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "The prescribing doctor's LANR is ", "223606797", ".", carrier="prose"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "prescriber:\n  lanr: ", "264575131", "\n", carrier="yaml"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "lifelong physician number=", "282842712", carrier="kv"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "LANR:", "331662479", "   Page 1", tags=("ocr",)),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "| LANR | ", "331662480", " |", carrier="table"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: 12345678", "only eight digits"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: siehe Stempel", "field without a value"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Die LANR wird von der KV vergeben.", "field name without a value", carrier="prose"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: XXXXXXXXX", "masked value", tags=("obfuscated",)),
        n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "LANR: 1234567890", "ten digits"),
        n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "Physician number: 000000000", "all-zero value is excluded"),
        n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "Doctor ID 123456789", "unsupported generic anchor"),
        n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "The LANR is printed on every prescription.", "field name without a value", carrier="prose"),
        n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "LANR: XXXXXXXXX", "masked value", tags=("obfuscated",)),
    ],
    "PASSPORT_NUMBER": [
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Passport number ", "C01X00T47", " was copied into the case file.", carrier="prose", source_fixture_id="specific-passport-number-01"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer: ", "F22M11P88"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Reisepassnummer = ", "L01X00T47"),
        n("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer: B01X00T47", "B is excluded from German document numbers"),
        n("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Document C01X00T47", "missing passport anchor"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Reisepass ", "C4J7K9L2M", ", ausgestellt in Bonn.", carrier="prose"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "reisender:\n  passnummer: ", "G8H2N5R1T", "\n", carrier="yaml"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer=", "K2L4M6N8P", carrier="kv"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer:", "J7T3X9V5W", "   gültig bis 2031", tags=("ocr",)),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", '{"passnummer": "', "C4J7K9L2N", '"}', carrier="json"),
        p("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Die Passnummer lautet ", "H1J2K3L4M", ".", carrier="prose", gap=True),
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Passport number: ", "C4J7K9L2M"),
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Her passport number is ", "G8H2N5R1T", ".", carrier="prose"),
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", "traveller:\n  passport number: ", "K2L4M6N8P", "\n", carrier="yaml"),
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", "passport number=", "J7T3X9V5W", carrier="kv"),
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Passport number:", "H1J2K3L4M", "   Page 1", tags=("ocr",)),
        p("PASSPORT_NUMBER", "en", "pii_passport_number_de", '{"passport_number": "', "H1J2K3L4N", '"}', carrier="json"),
        n("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer: C01X00T4", "only eight characters"),
        n("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer: C01A00T47", "A is excluded from German document numbers"),
        n("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Der Reisepass muss noch sechs Monate gültig sein.", "field name without a value", carrier="prose"),
        n("PASSPORT_NUMBER", "de", "pii_passport_number_de", "Passnummer: *********", "masked value", tags=("obfuscated",)),
        n("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Passport number: C01X00T4E", "E is excluded from German document numbers"),
        n("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Passport number: C01X00T47X", "ten characters"),
        n("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Bring your passport number to check-in.", "field name without a value", carrier="prose"),
        n("PASSPORT_NUMBER", "en", "pii_passport_number_de", "Passport number: *********", "masked value", tags=("obfuscated",)),
    ],
    "IDENTITY_CARD_NUMBER": [
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Personalausweisnummer: ", "L01X00T47"),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Identity card number ", "C01X00T47"),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Ausweisnummer = ", "F22M11P88"),
        n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Ausweisnummer: B01X00T47", "B is excluded from German document numbers"),
        n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Card C01X00T47", "missing identity-card anchor"),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Personalausweis ", "T22000129", ", gültig bis 2030.", carrier="prose"),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "kunde:\n  ausweisnummer: ", "LZ6311T47", "\n", carrier="yaml"),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Ausweisnummer=", "M3N7P9R1T", carrier="kv"),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Personalausweisnummer:", "L4M7N2P9R", "   Behörde: Stadt Kassel", tags=("ocr",)),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", '{"ausweisnummer": "', "T22000130", '"}', carrier="json"),
        p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Die Ausweisnummer lautet ", "LZ6311T48", ".", carrier="prose", gap=True),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Identity card number: ", "T22000129"),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "His identity card number is ", "LZ6311T47", ".", carrier="prose"),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "customer:\n  identity card number: ", "M3N7P9R1T", "\n", carrier="yaml"),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "identity card number=", "L4M7N2P9R", carrier="kv"),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Identity card number:", "C9F8G7H6J", "   Page 2", tags=("ocr",)),
        p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "ID card no.: ", "C9F8G7H6K", "", gap=True),
        n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Ausweisnummer: L01X00T4", "only eight characters"),
        n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Ausweisnummer: L01X00T4O", "O is excluded from German document numbers"),
        n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Bitte halten Sie Ihren Personalausweis bereit.", "field name without a value", carrier="prose"),
        n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de", "Ausweisnummer: *********", "masked value", tags=("obfuscated",)),
        n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Identity card number: L01X00T4S", "S is excluded from German document numbers"),
        n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Identity card number: L01X00T47Z", "ten characters"),
        n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Show your identity card number at the desk.", "field name without a value", carrier="prose"),
        n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de", "Identity card number: *********", "masked value", tags=("obfuscated",)),
    ],
    "DRIVER_LICENSE_NUMBER": [
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer: ", "B072RRE2A57"),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driver's license number ", "D1234567890"),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Fahrerlaubnisnummer = ", "A12BC34DE56"),
        n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer: B072RRE2A5", "only ten characters"),
        n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "License D1234567890", "missing driver's-license anchor"),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerschein ", "J0101234K56", ", Klasse B.", carrier="prose"),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "fahrer:\n  fuehrerscheinnummer: ", "F3X7Y9Z1W24", "\n", carrier="yaml"),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer=", "M5N6P7Q8R90", carrier="kv"),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer:", "K4711AB0815", "   Klasse: B", tags=("ocr",)),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", '{"fuehrerschein": "', "K4711AB0816", '"}', carrier="json"),
        p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Die Führerscheinnummer lautet ", "J0101234K57", ".", carrier="prose"),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driver's license number: ", "J0101234K56"),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Her driver licence number is ", "F3X7Y9Z1W24", ".", carrier="prose"),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "driver:\n  driver license number: ", "M5N6P7Q8R90", "\n", carrier="yaml"),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "driver's license number=", "K4711AB0815", carrier="kv"),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driver's license number:", "B072RRE2A58", "   Page 1", tags=("ocr",)),
        p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driving licence no.: ", "B072RRE2A59", ""),
        n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer: B072RRE2A57X", "twelve characters"),
        n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer: folgt", "field without a value"),
        n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Der Führerschein wurde 2019 umgetauscht.", "field name without a value", carrier="prose"),
        n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerscheinnummer: ***********", "masked value", tags=("obfuscated",)),
        n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driver's license number: ABCDEFGHIJ", "letters only, no licence format"),
        n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driver's license number: pending", "field without a value"),
        n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Enter your driver's license number on page two.", "field name without a value", carrier="prose"),
        n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_de", "Driver's license number: ***********", "masked value", tags=("obfuscated",)),
    ],
    "LICENSEPLATE": [
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "KFZ-Kennzeichen: ", "B-AB 1234E"),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration ", "M XY 42"),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Nummernschild: ", "K-A 778H"),
        n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen: BERLIN-123", "prefix is too long"),
        n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Parkplatz B-AB 1234E", "missing registration anchor"),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Das Fahrzeug mit dem Kennzeichen ", "HH-JK 4410", " stand im Halteverbot.", carrier="prose"),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "fahrzeug:\n  kennzeichen: ", "KS-RT 207", "\n", carrier="yaml"),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen=", "M-QA 1800", carrier="kv"),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen:", "S-LG 3091", "   Halter: siehe Akte", tags=("ocr",)),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", '{"kennzeichen": "', "HH-JK 4411", '"}', carrier="json"),
        p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Ich parke vor der Tür, ", "KS-RT 208", ", silberner Kombi.", carrier="prose", tags=("no_context",), gap=True),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration: ", "HH-JK 4410"),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "The car with vehicle registration ", "KS-RT 207", " was towed.", carrier="prose"),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "vehicle:\n  kennzeichen: ", "M-QA 1800", "\n", carrier="yaml"),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "vehicle registration=", "S-LG 3091", carrier="kv"),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration:", "F-EZ 66E", "   Page 1", tags=("ocr",)),
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "License plate: ", "F-EZ 67E", "", gap=True),
        n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen: B-12 345", "letter group is missing"),
        n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen: unbekannt", "field without a value"),
        n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Das Kennzeichen muss gut lesbar sein.", "field name without a value", carrier="prose"),
        n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen: **-** ****", "masked value", tags=("obfuscated",)),
        n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration: pending", "field without a value"),
        n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration: ABCD-EF 12", "prefix is too long"),
        n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration renewals open in March.", "field name without a value", carrier="prose"),
        n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Vehicle registration: **-** ****", "masked value", tags=("obfuscated",)),
    ],
    "SSN": [
        p("SSN", "en", "pii_ssn_us", "SSN: ", "123-45-6789"),
        p("SSN", "en", "pii_ssn_us", "Social security number is ", "212 34 5678"),
        p("SSN", "de", "pii_ssn_us", "US-SSN: ", "665-12-3456"),
        n("SSN", "en", "pii_ssn_us", "SSN: 000-12-3456", "reserved area number"),
        n("SSN", "en", "pii_ssn_us", "Release 123-45-6789", "missing SSN anchor"),
        p("SSN", "de", "pii_ssn_us", "US-Sozialversicherungsnummer: ", "401-12-7788"),
        p("SSN", "de", "pii_ssn_us", "Die SSN des US-Mitarbeiters ist ", "532-87-1094", ".", carrier="prose", gap=True),
        p("SSN", "de", "pii_ssn_us", "Seine SSN: ", "532-87-1094", ", bitte vertraulich behandeln.", carrier="prose"),
        p("SSN", "de", "pii_ssn_us", "mitarbeiter_us:\n  ssn: ", "219-09-9998", "\n", carrier="yaml"),
        p("SSN", "de", "pii_ssn_us", "SSN=", "345-67-8901", carrier="kv"),
        p("SSN", "de", "pii_ssn_us", "SSN:", "456-78-9012", "   Staat: Ohio", tags=("ocr",)),
        p("SSN", "de", "pii_ssn_us", '{"ssn": "', "456-78-9013", '"}', carrier="json"),
        p("SSN", "en", "pii_ssn_us", "employee:\n  ssn: ", "401-12-7788", "\n", carrier="yaml"),
        p("SSN", "en", "pii_ssn_us", "Her social security number is ", "532-87-1094", ".", carrier="prose"),
        p("SSN", "en", "pii_ssn_us", "ssn=", "345 67 8901", carrier="kv"),
        p("SSN", "en", "pii_ssn_us", "SSN:", "456-78-9012", "   Page 1", tags=("ocr",)),
        p("SSN", "en", "pii_ssn_us", "| SSN | ", "219-09-9997", " |", carrier="table"),
        p("SSN", "en", "pii_ssn_us", "Send the form for ", "401127789", " today.", carrier="prose", tags=("no_context",), gap=True),
        n("SSN", "de", "pii_ssn_us", "SSN: 666-12-3456", "area 666 is never issued"),
        n("SSN", "de", "pii_ssn_us", "SSN: 900-12-3456", "area 9xx is never issued"),
        n("SSN", "de", "pii_ssn_us", "SSN: 123-00-4567", "group 00 is never issued"),
        n("SSN", "de", "pii_ssn_us", "SSN: XXX-XX-6789", "masked value", tags=("obfuscated",)),
        n("SSN", "de", "pii_ssn_us", "Die SSN wird nur für US-Konten benötigt.", "field name without a value", carrier="prose"),
        n("SSN", "en", "pii_ssn_us", "SSN: 123-45-0000", "serial 0000 is never issued"),
        n("SSN", "en", "pii_ssn_us", "SSN: XXX-XX-6789", "masked value", tags=("obfuscated",)),
        n("SSN", "en", "pii_ssn_us", "Social security number: pending", "field without a value"),
        n("SSN", "en", "pii_ssn_us", "SSN: 078-05-1120", "famous Woolworth sample number is excluded"),
    ],
    "NATIONALID": [
        p("NATIONALID", "en", "pii_ni_uk", "NINO: ", "AB123456C"),
        p("NATIONALID", "en", "pii_ni_uk", "National Insurance number ", "CE 123456 A"),
        p("NATIONALID", "de", "pii_ni_uk", "UK-NINO: ", "HJ987654D"),
        n("NATIONALID", "en", "pii_ni_uk", "NINO: BG123456A", "forbidden prefix"),
        n("NATIONALID", "en", "pii_ni_uk", "Reference AB123456C", "missing NINO anchor"),
        p("NATIONALID", "de", "pii_ni_uk", "Britische Sozialversicherungsnummer: ", "PR482917A"),
        p("NATIONALID", "de", "pii_ni_uk", "Die Mitarbeiterin hat die NINO ", "WL 304115 C", ".", carrier="prose"),
        p("NATIONALID", "de", "pii_ni_uk", "mitarbeiter_uk:\n  nino: ", "ST761245B", "\n", carrier="yaml"),
        p("NATIONALID", "de", "pii_ni_uk", "NINO=", "MN 902341 D", carrier="kv"),
        p("NATIONALID", "de", "pii_ni_uk", "NINO:", "JK556677B", "   Arbeitgeber: Ltd.", tags=("ocr",)),
        p("NATIONALID", "de", "pii_ni_uk", '{"nino": "', "JK556678B", '"}', carrier="json"),
        p("NATIONALID", "en", "pii_ni_uk", "Her National Insurance number is ", "PR482917A", ".", carrier="prose"),
        p("NATIONALID", "en", "pii_ni_uk", "employee:\n  nino: ", "WL 304115 C", "\n", carrier="yaml"),
        p("NATIONALID", "en", "pii_ni_uk", "nino=", "ST761245B", carrier="kv"),
        p("NATIONALID", "en", "pii_ni_uk", "NINO:", "MN902341D", "   Page 1", tags=("ocr",)),
        p("NATIONALID", "en", "pii_ni_uk", "NI number: ", "JK 55 66 77 B", "", gap=True),
        n("NATIONALID", "de", "pii_ni_uk", "NINO: QQ123456C", "forbidden first letter"),
        n("NATIONALID", "de", "pii_ni_uk", "NINO: AB123456E", "suffix must be A to D"),
        n("NATIONALID", "de", "pii_ni_uk", "Die NINO wird von HMRC vergeben.", "field name without a value", carrier="prose"),
        n("NATIONALID", "de", "pii_ni_uk", "NINO: XX 99 99 99 X", "masked value", tags=("obfuscated",)),
        n("NATIONALID", "de", "pii_ni_uk", "NINO: AO123456C", "O is not allowed as the second letter"),
        n("NATIONALID", "en", "pii_ni_uk", "NINO: GB123456A", "forbidden prefix"),
        n("NATIONALID", "en", "pii_ni_uk", "NINO: AB12345C", "only five digits"),
        n("NATIONALID", "en", "pii_ni_uk", "Your National Insurance number is on your payslip.", "field name without a value", carrier="prose"),
        n("NATIONALID", "en", "pii_ni_uk", "NINO: XX 99 99 99 X", "masked value", tags=("obfuscated",)),
    ],
}


# K04 structure awareness, in every mode: a JSON key, a `key: value` or `key=value` line, an
# XML element or attribute, a CSV header or a Markdown/HTML table header names the value it
# holds like a field name right before it. A key binds a rule only if the rule accepts it as
# field name and the value matches the rule's value form in full; hard negatives keep keys
# the rule does not accept (order columns, generic "Kennung"/"Arztnummer"/"Doctor ID") and
# values its validator rejects under an accepted key. Appended so existing ids stay stable.
K04_STRUCTURE_CASES = [
    p("CUSTOMER_ID", "de", "pii_customer_id", "Name;Kundennummer;Ort\nJana Roth;", "KD-55120", ";Kassel", carrier="csv"),
    p("PHONE", "de", "pii_phone_de_national_context", "<table><tr><th>Name</th><th>Telefon</th></tr><tr><td>Jana Roth</td><td>", "030 4471230", "</td></tr></table>", carrier="table"),
    p("PATIENT_ID", "de", "pii_patient_id", "| Patientennummer | Station |\n|---|---|\n| ", "PAT-20931", " | 4B |", carrier="table"),
    p("EMPLOYEE_ID", "de", "pii_employee_id", "<mitarbeiter><personalnummer>", "PN-77120", "</personalnummer></mitarbeiter>", carrier="xml"),
    p("DOB", "de", "pii_date_of_birth", "Name;Geburtsdatum\nJana Roth;", "14.03.1987", "", carrier="csv"),
    p("STUDENT_ID", "de", "pii_student_id", '{"student": {"matrikelNummer": "', "5520931", '"}}', carrier="json"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "<table><tr><th>Versichertennummer</th><td>", "M345678912", "</td></tr></table>", carrier="table"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "Bestellnummer;Artikel\nBN-55120;Bürostuhl", "order number column, not a customer number", carrier="csv"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", '{"arztnummer": "123456789"}', "generic field name the LANR rule does not accept", carrier="json"),
    n("EMPLOYEE_ID", "de", "pii_employee_id", "| Kennung | XY-3096 |", "generic identifier without employment context", carrier="table"),
    n("DOB", "de", "pii_date_of_birth", "Name;Geburtsdatum\nJana Roth;31.02.1987", "impossible calendar date", carrier="csv"),
    n("STEUERID", "de", "pii_steuer_id_de", "<person><steuer-id>11111111111</steuer-id></person>", "Steuer-ID check digit fails", carrier="xml"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "<bestellung><id>B-77120</id></bestellung>", "order id element, not a customer number", carrier="xml"),
    n("SWIFT_CODE", "de", "pii_swift_bic_context", '{"bankname": "DEUTDEFF500"}', "bank name key is not a BIC field", carrier="json"),
    p("EMPLOYEE_ID", "en", "pii_employee_id", "employee_id,name,department\n", "E-40512", ",Maya Patel,Finance", carrier="csv"),
    p("SSN", "en", "pii_ssn_us", "<table><tr><th>SSN</th><td>", "536-90-4399", "</td></tr></table>", carrier="table"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de", '<traveler passportNumber="', "C01X00T47", '"/>', carrier="xml"),
    p("CUSTOMER_ID", "en", "pii_customer_id", '{"customerId": "', "CUS-88412", '", "plan": "pro"}', carrier="json"),
    p("APPLICANT_ID", "en", "pii_applicant_id", "| Applicant ID | Role |\n|---|---|\n| ", "APP-30418", " | Analyst |", carrier="table"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "[payout]\naccount_number = ", "ACC-55120", "", carrier="kv"),
    p("USERNAME", "en", "pii_username", "user_name\tteam\n", "m.chen", "\tplatform", carrier="csv"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "order_id,product\nORD-55120,Desk", "order id column, not a customer id", carrier="csv"),
    n("SSN", "en", "pii_ssn_us", "| SSN | 666-12-3456 |", "area 666 is never issued", carrier="table"),
    n("EMPLOYEE_ID", "en", "pii_employee_id", "<order><id>E-77121</id></order>", "order id element, not an employee id", carrier="xml"),
    n("USERNAME", "en", "pii_username", '{"username": "required"}', "UI word, not an account name", carrier="json"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "| Doctor ID | 123456789 |", "generic field name the LANR rule does not accept", carrier="table"),
    n("DOB", "en", "pii_date_of_birth", "name,date_of_birth\nMaya Patel,02/30/1990", "impossible calendar date", carrier="csv"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de", '<traveler passportNumber="A01X00T47"/>', "A is not in the document number alphabet", carrier="xml"),
]
for _row in K04_STRUCTURE_CASES:
    PII_CASES[_row["target_label"]].append(_row)


# K05 context-free output: in `balanced` and `recall` a checksum-strong value needs no field
# name; strict keeps the field-name rule (K02). A bare Steuer-ID must pass the check digit
# and the BZSt digit distribution of issued IDs, stand alone (no longer number, range or
# slash) and have no nearer counter-context term. Appended so existing ids stay stable.
K05_CONTEXT_FREE_CASES = [
    p("STEUERID", "de", "pii_steuer_id_de_context_free", "Für die Lohnabrechnung brauche ich noch ", "47426548904", ".", carrier="prose", tags=("no_context",), mode="balanced"),
    p("STEUERID", "de", "pii_steuer_id_de_context_free", "Ihre Steuer-ID ist ", "39662845670", ".", carrier="prose", mode="balanced"),
    p("STEUERID", "de", "pii_steuer_id_de_context_free", "", "86 794 425 307", " (Steuer-ID) bitte übernehmen.", carrier="prose", mode="balanced"),
    p("STEUERID", "de", "pii_steuer_id_de_context_free", "Name;Nummer\nJonas Weber;", "86231292506", "", carrier="csv", tags=("no_context",), mode="balanced"),
    p("STEUERID", "de", "pii_steuer_id_de_context_free", '{"person": "Jonas Weber", "kennziffer": "', "95082467219", '"}', carrier="json", tags=("no_context",), mode="balanced"),
    p("STEUERID", "de", "pii_steuer_id_de_context_free", "Bitte noch ", "35347368292", " im Formular nachtragen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("STEUERID", "en", "pii_steuer_id_de_context_free", "Please add ", "74265832011", " to the payroll file.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("STEUERID", "en", "pii_steuer_id_de_context_free", "", "29046789957", " is the German tax ID on file.", carrier="prose", mode="balanced"),
    p("STEUERID", "en", "pii_steuer_id_de_context_free", "Payroll needs ", "45 917 893 901", " before Friday.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("STEUERID", "en", "pii_steuer_id_de_context_free", "name,tin\nAda Weber,", "28540106973", "", carrier="csv", tags=("no_context",), mode="balanced"),
    p("STEUERID", "en", "pii_steuer_id_de_context_free", '{"employee": "Ada Weber", "code": "', "56470900312", '"}', carrier="json", tags=("no_context",), mode="balanced"),
    p("STEUERID", "en", "pii_steuer_id_de_context_free", "Record 7 lists ", "33694273817", " for the employee.", carrier="prose", tags=("no_context",), mode="recall"),
    n("STEUERID", "de", "pii_steuer_id_de_context_free", "Rechnungsnummer 86095742719 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("STEUERID", "de", "pii_steuer_id_de_context_free", "Bestellnummer: 65929970489", "order number with a valid check digit", mode="recall"),
    n("STEUERID", "de", "pii_steuer_id_de_context_free", "Die Zahl 86095742718 steht im Protokoll.", "checksum fails", carrier="prose", mode="balanced"),
    n("STEUERID", "de", "pii_steuer_id_de_context_free", "Vorgang 12345678903 wurde archiviert.", "check digit valid, but ten distinct digits are never issued", carrier="prose", mode="balanced"),
    n("STEUERID", "de", "pii_steuer_id_de_context_free", "Messwert 860957427190 im Log.", "twelve digits", carrier="prose", mode="balanced"),
    n("STEUERID", "de", "pii_steuer_id_de_context_free", "Aktenzeile 86095742719/2026 abgelegt.", "part of a longer slash-separated number", carrier="prose", mode="balanced"),
    n("STEUERID", "en", "pii_steuer_id_de_context_free", "Invoice number 86095742719 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("STEUERID", "en", "pii_steuer_id_de_context_free", "Tracking number 25768131411 is in transit.", "tracking number with a valid check digit", carrier="prose", mode="recall"),
    n("STEUERID", "en", "pii_steuer_id_de_context_free", "Batch 86095742718 failed the import.", "checksum fails", carrier="prose", mode="balanced"),
    n("STEUERID", "en", "pii_steuer_id_de_context_free", "Build 67890123455 passed.", "check digit valid, but ten distinct digits are never issued", carrier="prose", mode="balanced"),
    n("STEUERID", "en", "pii_steuer_id_de_context_free", "Value 86555742194 logged.", "a digit three times in a row is never issued", carrier="prose", mode="balanced"),
    n("STEUERID", "en", "pii_steuer_id_de_context_free", "Range 86095742719-86095742720 reserved.", "part of a hyphenated number range", carrier="prose", mode="balanced"),
]
for _row in K05_CONTEXT_FREE_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# K06 obfuscation: zero-width characters inside a value, full-width forms and defanged
# separators (`[.]`, `(@)`) leave the value readable and count in every mode; the scanner
# normalizes them and reports the original span. Spelled-out e-mail separators (`[at]`,
# `ät`, `dot`, `punkt`) and numbers spaced character by character are reported in `recall` only; in
# `strict` and `balanced` they stay hard negatives (gold convention T01). Checksums decide
# behind the obfuscation. Appended so existing ids stay stable.
K06_OBFUSCATION_CASES = [
    p("EMAIL", "de", "pii_email", "Bitte an ", "jana.roth＠beispiel．de", " schreiben.", carrier="prose", tags=("obfuscated",)),
    p("IP_ADDRESS", "de", "pii_ipv4", "Angreifer-IP laut Bericht: ", "198[.]51[.]100[.]23", "", tags=("obfuscated",)),
    p("IBAN", "de", "pii_iban_de", "IBAN: ", "ＤＥ８９ ３７０４ ００４４ ０５３２ ０１３０ ００", "", tags=("obfuscated",)),
    p("CREDITCARD", "de", "pii_credit_card", "Kreditkarte: ", "5555\u200b5555\u200b5555\u200b4444", "", tags=("obfuscated",)),
    p("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: ", "８６０９５７４２７１９", "", tags=("obfuscated",)),
    p("EMAIL", "de", "pii_email", "Kontakt: ", "max punkt mustermann ät firma punkt de", "", tags=("obfuscated",), mode="recall"),
    p("IBAN", "de", "pii_iban_de", "IBAN: ", "D E 8 9 3 7 0 4 0 0 4 4 0 5 3 2 0 1 3 0 0 0", "", tags=("obfuscated",), mode="recall"),
    p("EMAIL", "en", "pii_email", "Reply to ", "m\u200bara.lee@north\u200bwind.com", " today.", carrier="prose", tags=("obfuscated",)),
    p("IP_ADDRESS", "en", "pii_ipv4", "Blocked host: ", "１９２．０．２．１４", "", tags=("obfuscated",)),
    p("PHONE", "en", "pii_phone_international", "Phone: ", "+1\u200b212\u200b736\u200b4410", "", tags=("obfuscated",)),
    p("SSN", "en", "pii_ssn_us", "SSN: ", "５３２-８７-１０９４", "", tags=("obfuscated",)),
    p("CREDITCARD", "en", "pii_credit_card", "Card number: ", "４１１１ １１１１ １１１１ １１１１", "", tags=("obfuscated",)),
    p("EMAIL", "en", "pii_email", "Mail ", "ada [at] northwind [dot] com", " for access.", carrier="prose", tags=("obfuscated",), mode="recall"),
    p("IBAN", "en", "pii_iban_generic", "Account IBAN: ", "G B 8 2 W E S T 1 2 3 4 5 6 9 8 7 6 5 4 3 2", "", tags=("obfuscated",), mode="recall"),
    n("EMAIL", "de", "pii_email", "Schreiben Sie an max punkt mustermann ät firma punkt de", "spelled-out address outside recall (T01)", carrier="prose", tags=("obfuscated",)),
    n("EMAIL", "de", "pii_email", "Infos unter firma punkt de.", "spelled-out domain without a local part", carrier="prose", tags=("obfuscated",), mode="recall"),
    n("EMAIL", "de", "pii_email", "Treffpunkt ist um 10 Uhr ät der Rezeption.", "spelled-out word in prose", carrier="prose", tags=("obfuscated",), mode="recall"),
    n("CREDITCARD", "de", "pii_credit_card", "Karte 4111\u200b1111\u200b1111\u200b1112", "Luhn fails behind zero-width characters", tags=("obfuscated",)),
    n("CREDITCARD", "de", "pii_credit_card", "Karte: 4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 2", "Luhn fails behind spaced digits", tags=("obfuscated",), mode="recall"),
    n("IBAN", "de", "pii_iban_de", "IBAN: ＤＥ８９３７０４００４４０５３２０１３００１", "MOD-97 fails behind full-width digits", tags=("obfuscated",)),
    n("IP_ADDRESS", "de", "pii_ipv4", "Version 1[.]2[.]3 ist veröffentlicht.", "defanged version number, not an address", carrier="prose", tags=("obfuscated",)),
    n("EMAIL", "en", "pii_email", "Mail ada [at] northwind [dot] com for access.", "spelled-out address outside recall (T01)", carrier="prose", tags=("obfuscated",), mode="balanced"),
    n("EMAIL", "en", "pii_email", "Read the docs at example dot com.", "spelled-out domain in prose", carrier="prose", tags=("obfuscated",), mode="recall"),
    n("EMAIL", "en", "pii_email", "Look at the dot product of both vectors.", "spelled-out words in prose", carrier="prose", tags=("obfuscated",), mode="recall"),
    n("CREDITCARD", "en", "pii_credit_card", "Card: ５５５５ ５５５５ ５５５５ ４４４５", "Luhn fails behind full-width digits", tags=("obfuscated",)),
    n("PHONE", "en", "pii_phone_us", "Phone: ＸＸＸ-ＸＸＸ-ＸＸＸＸ", "masked number in full-width letters", tags=("obfuscated",)),
    n("IBAN", "en", "pii_iban_generic", "Account IBAN: G B 8 2 W E S T 1 2 3 4 5 6 9 8 7 6 5 4 3 2", "characters spaced one by one count in recall only", tags=("obfuscated",), mode="balanced"),
    n("STEUERID", "de", "pii_steuer_id_de", "Steuer-ID: 8 6 0 9 5 7 4 2 7 1 8", "check digit fails behind spaced digits", tags=("obfuscated",), mode="recall"),
]
for _row in K06_OBFUSCATION_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# K07 cross-label overlaps: in `balanced` and `recall` one value yields one label. The digits
# of a grouped IBAN or of an international phone number can pass Luhn; that card-shaped part
# is no card, and a field name outranks a bare checksum on the same value. A card-shaped part
# of a printed IBAN form whose check digits fail is no card either. Strict keeps both labels
# (decision T07). Every IBAN, BBAN and phone vector below passes the checksum it names.
# Appended so existing ids stay stable.
K07_OVERLAP_CASES = [
    p("CREDITCARD", "de", "pii_credit_card", "Karte ", "4111 1111 1111 1111", ", IBAN DE60 5393 3633 8750 0474 39", mode="balanced", also=(("IBAN", "DE60 5393 3633 8750 0474 39"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Kreditkarte ", "5555 5555 5555 4444", ", Rückruf unter +49 69 3361 9496", carrier="prose", mode="balanced", also=(("PHONE", "+49 69 3361 9496"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Name;Karte;IBAN\nWeber;", "4532 0151 1283 0366", ";DE13 3380 1412 6906 0443 19", carrier="csv", mode="balanced", also=(("IBAN", "DE13 3380 1412 6906 0443 19"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Zahlung mit ", "4111 1111 1111 1111", " abgelehnt, bitte auf AT33 2854 3001 9603 7672 überweisen.", carrier="prose", mode="recall", also=(("IBAN", "AT33 2854 3001 9603 7672"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Telefon: 0151 2345 6789 01, Karte ", "5105 1051 0510 5100", "", mode="balanced", also=(("PHONE", "0151 2345 6789 01"),)),
    p("CREDITCARD", "de", "pii_credit_card", '{"karte": "', "4111 1111 1111 1111", '", "iban": "DE21 5873 5570 6360 6071 04"}', carrier="json", mode="recall", also=(("IBAN", "DE21 5873 5570 6360 6071 04"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Card ", "4111 1111 1111 1111", ", IBAN DE63 8415 3776 0207 7642 65", mode="balanced", also=(("IBAN", "DE63 8415 3776 0207 7642 65"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Charge ", "5555 5555 5555 4444", " and call +44 20 6642 3850 to confirm.", carrier="prose", mode="balanced", also=(("PHONE", "+44 20 6642 3850"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Phone: +49 89 4613 8662, card ", "4532 0151 1283 0366", "", mode="recall", also=(("PHONE", "+49 89 4613 8662"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Pay with ", "6011 1111 1111 1117", " or wire to AT71 4952 2280 5377 3567.", carrier="prose", mode="balanced", also=(("IBAN", "AT71 4952 2280 5377 3567"),)),
    p("CREDITCARD", "en", "pii_credit_card", "name,card,iban\nAda Weber,", "4111 1111 1111 1111", ",DE06 6826 5123 3080 5169 78", carrier="csv", mode="balanced", also=(("IBAN", "DE06 6826 5123 3080 5169 78"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Mobile: 0151 2345 6789 01, card ", "5105 1051 0510 5100", "", mode="recall", also=(("PHONE", "0151 2345 6789 01"),)),
    n("CREDITCARD", "de", "pii_credit_card", "IBAN: DE64 7172 7958 4924 3372 11", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Überweisung an DE34 6659 4134 6836 7322 13 fehlgeschlagen.", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="prose", mode="recall"),
    n("CREDITCARD", "de", "pii_credit_card", "Name;IBAN\nWeber;DE25 2704 9372 0521 4877 40", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="csv", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "IBAN AT77 5761 4565 6741 3978 (Prüfziffer falsch)", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="prose", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", '{"iban": "AT84 8900 8717 3455 8933"}', "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="json", mode="recall"),
    n("CREDITCARD", "de", "pii_credit_card", "Das Konto DE03 4977 4035 3388 6960 52 ist gesperrt.", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="prose", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "IBAN: DE47 9570 1831 6586 8923 67", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "Wire to DE56 4057 3004 4314 7125 77 bounced.", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="prose", mode="recall"),
    n("CREDITCARD", "en", "pii_credit_card", "name,iban\nAda Weber,AT78 3498 0320 8465 1419", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="csv", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "IBAN AT80 9719 0726 3779 2179 has a typo.", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="prose", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", '{"iban": "AT07 5340 7771 1787 1617"}', "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="json", mode="recall"),
    n("CREDITCARD", "en", "pii_credit_card", "Refund to AT56 7788 6243 8146 2282 failed.", "IBAN form with failing check digits; the Luhn-valid digits inside it are no card", carrier="prose", mode="balanced"),
]
for _row in K07_OVERLAP_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# T07 secondary evidence in `strict` (decision 2026-10-14): strict keeps reporting the
# card-shaped BBAN inside a valid IBAN and FINANCIAL_ACCOUNT_NUMBER on an IBAN value, but
# marks them as secondary evidence of the IBAN; evaluations score primary findings only.
# A card or account next to an IBAN stays primary. Every IBAN below passes MOD-97 and its
# BBAN digits pass Luhn (or it sits under an account field name). Appended so existing
# ids stay stable.
T07_STRICT_SECONDARY_CASES = [
    p("CREDITCARD", "de", "pii_credit_card", "Karte ", "4111 1111 1111 1111", ", IBAN DE18 4306 0967 1234 5678 00", also=(("IBAN", "DE18 4306 0967 1234 5678 00"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Kreditkarte ", "5555 5555 5555 4444", "; Lastschrift von DE60 5393 3633 8750 0474 39", carrier="prose", also=(("IBAN", "DE60 5393 3633 8750 0474 39"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Name;Karte;IBAN\nWeber;", "4532 0151 1283 0366", ";DE13 3380 1412 6906 0443 19", carrier="csv", also=(("IBAN", "DE13 3380 1412 6906 0443 19"),)),
    p("CREDITCARD", "de", "pii_credit_card", "Bitte die Karte ", "5105 1051 0510 5100", " belasten, nicht das Konto DE63 8415 3776 0207 7642 65.", carrier="prose", also=(("IBAN", "DE63 8415 3776 0207 7642 65"),)),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Depotnummer: ", "DP-77120", "\nKontonummer: DE89370400440532013000", carrier="kv", also=(("IBAN", "DE89370400440532013000"),)),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Konto-Nr: ", "KTO-30202", ", IBAN DE21 5873 5570 6360 6071 04", also=(("IBAN", "DE21 5873 5570 6360 6071 04"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Card ", "4111 1111 1111 1111", ", IBAN DE06 6826 5123 3080 5169 78", also=(("IBAN", "DE06 6826 5123 3080 5169 78"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Charge ", "5555 5555 5555 4444", " or debit DE18 4306 0967 1234 5678 00.", carrier="prose", also=(("IBAN", "DE18 4306 0967 1234 5678 00"),)),
    p("CREDITCARD", "en", "pii_credit_card", "name,card,iban\nAda Weber,", "4532 0151 1283 0366", ",DE60 5393 3633 8750 0474 39", carrier="csv", also=(("IBAN", "DE60 5393 3633 8750 0474 39"),)),
    p("CREDITCARD", "en", "pii_credit_card", "Refund card ", "4012 8888 8888 1881", " instead of IBAN DE21 5873 5570 6360 6071 04.", carrier="prose", also=(("IBAN", "DE21 5873 5570 6360 6071 04"),)),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number: ", "ACC-44001234", "\nBank account: GB82WEST12345698765432", carrier="kv", also=(("IBAN", "GB82WEST12345698765432"),)),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number ", "ACC-55120", ", IBAN DE06 6826 5123 3080 5169 78", also=(("IBAN", "DE06 6826 5123 3080 5169 78"),)),
    n("CREDITCARD", "de", "pii_credit_card", "IBAN: DE18 4306 0967 1234 5678 00", "valid IBAN; its Luhn-valid BBAN digits are secondary evidence, no card", also=(("IBAN", "DE18 4306 0967 1234 5678 00"),)),
    n("CREDITCARD", "de", "pii_credit_card", "Überweisung an DE63 8415 3776 0207 7642 65 erhalten.", "valid IBAN; its Luhn-valid BBAN digits are secondary evidence, no card", carrier="prose", also=(("IBAN", "DE63 8415 3776 0207 7642 65"),)),
    n("CREDITCARD", "de", "pii_credit_card", '{"iban": "DE21 5873 5570 6360 6071 04"}', "valid IBAN; its Luhn-valid BBAN digits are secondary evidence, no card", carrier="json", also=(("IBAN", "DE21 5873 5570 6360 6071 04"),)),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Kontonummer: GB82WEST12345698765432", "IBAN under an account field name; the account finding is secondary evidence of the IBAN", also=(("IBAN", "GB82WEST12345698765432"),)),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Kontonummer DE21 5873 5570 6360 6071 04 bestätigt.", "IBAN under an account field name; its country code and card-shaped BBAN are secondary evidence", carrier="prose", also=(("IBAN", "DE21 5873 5570 6360 6071 04"),)),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", '{"kontonummer": "DE89370400440532013000"}', "IBAN under an account key; the account finding is secondary evidence of the IBAN", carrier="json", also=(("IBAN", "DE89370400440532013000"),)),
    n("CREDITCARD", "en", "pii_credit_card", "IBAN DE60 5393 3633 8750 0474 39 is on file", "valid IBAN; its Luhn-valid BBAN digits are secondary evidence, no card", carrier="prose", also=(("IBAN", "DE60 5393 3633 8750 0474 39"),)),
    n("CREDITCARD", "en", "pii_credit_card", "Refund sent to DE06 6826 5123 3080 5169 78 today.", "valid IBAN; its Luhn-valid BBAN digits are secondary evidence, no card", carrier="prose", also=(("IBAN", "DE06 6826 5123 3080 5169 78"),)),
    n("CREDITCARD", "en", "pii_credit_card", "name,iban\nAda Weber,DE13 3380 1412 6906 0443 19", "valid IBAN; its Luhn-valid BBAN digits are secondary evidence, no card", carrier="csv", also=(("IBAN", "DE13 3380 1412 6906 0443 19"),)),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Bank account: GB82WEST12345698765432", "IBAN under an account field name; the account finding is secondary evidence of the IBAN", also=(("IBAN", "GB82WEST12345698765432"),)),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Account number is GB33BUKB20201555555555.", "IBAN under an account field name; the account finding is secondary evidence of the IBAN", carrier="prose", also=(("IBAN", "GB33BUKB20201555555555"),)),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Bank account: DE44 5001 0517 5407 3249 31", "IBAN under an account field name; its country code and card-shaped BBAN are secondary evidence", also=(("IBAN", "DE44 5001 0517 5407 3249 31"),)),
]
for _row in T07_STRICT_SECONDARY_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# T26 field names in FR/ES/IT/NL (TRIAGE 2026-W43 bucket 12): the anchor rules for date of
# birth, customer and employee ID, account number, CVV, US SSN, passport and username accept
# them in `strict`, before the value and as a structural key. Hard negatives keep the field
# name but carry a value the unchanged validator rejects, no assignment, a non-card security
# code, or a neighbouring field (order number, expiry date). Appended so existing ids stay
# stable.
T26_MULTILINGUAL_FIELD_CASES = [
    p("DOB", "fr", "pii_date_of_birth", "Date de naissance : ", "14/07/1985"),
    p("DOB", "fr", "pii_date_of_birth", "Mme Lefèvre, née le ", "03.11.1979", ", réside à Lyon.", carrier="prose"),
    p("CUSTOMER_ID", "fr", "pii_customer_id", "Numéro de client : ", "CL-480215"),
    p("CUSTOMER_ID", "fr", "pii_customer_id", '{"numero_client": "', "CL-99120", '", "ville": "Lyon"}', carrier="json"),
    p("EMPLOYEE_ID", "fr", "pii_employee_id", "Identifiant d'employé : ", "E-204518"),
    p("FINANCIAL_ACCOUNT_NUMBER", "fr", "pii_financial_account_number", "Numéro de compte : ", "CPT-0091827"),
    p("CREDITCARD_CVV", "fr", "pii_credit_card_cvv", "Carte 4111 1111 1111 1111, code de sécurité de la carte de crédit : ", "737", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
    p("SSN", "fr", "pii_ssn_us", "Numéro de sécurité sociale : ", "536-90-4421"),
    p("PASSPORT_NUMBER", "fr", "pii_passport_number_de", "Numéro de passeport : ", "C01X00T47"),
    p("USERNAME", "fr", "pii_username", "Nom d'utilisateur : ", "claire.martin85"),
    n("DOB", "fr", "pii_date_of_birth", "Date de naissance : 31/02/1985", "impossible calendar date"),
    n("CUSTOMER_ID", "fr", "pii_customer_id", "Numéro de commande : CMD-480215", "order number, not a customer id"),
    n("USERNAME", "fr", "pii_username", "Choisissez un nom d'utilisateur pour votre compte.", "field name in prose without an assignment", carrier="prose"),
    n("CREDITCARD_CVV", "fr", "pii_credit_card_cvv", "Carte 4111 1111 1111 1111. Code de sécurité du bâtiment : 4821", "building access code, not a card security code", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
    n("SSN", "fr", "pii_ssn_us", "Numéro de sécurité sociale : 000-12-3456", "area 000 is never issued"),
    n("PASSPORT_NUMBER", "fr", "pii_passport_number_de", "Date d'expiration du passeport : 12/03/2031", "expiry date, not a passport number"),
    p("DOB", "es", "pii_date_of_birth", "Fecha de Nacimiento: ", "23/08/1975"),
    p("DOB", "es", "pii_date_of_birth", "La titular, nacida el ", "05/09/1990", ", reside en Sevilla.", carrier="prose"),
    p("CUSTOMER_ID", "es", "pii_customer_id", "Número de cliente: ", "CLI-302948"),
    p("EMPLOYEE_ID", "es", "pii_employee_id", "Número de Identificación del Empleado: ", "Vn-21203"),
    p("FINANCIAL_ACCOUNT_NUMBER", "es", "pii_financial_account_number", "Número de cuenta: ", "CTA-20481937"),
    p("CREDITCARD_CVV", "es", "pii_credit_card_cvv", "Tarjeta 5555 5555 5555 4444, código de seguridad de la tarjeta: ", "318", also=(("CREDITCARD", "5555 5555 5555 4444"),)),
    p("SSN", "es", "pii_ssn_us", "Número de seguro social: ", "412-56-7834"),
    p("PASSPORT_NUMBER", "es", "pii_passport_number_de", "Número de pasaporte: ", "P4K7R2M9X"),
    p("USERNAME", "es", "pii_username", "Nombre de usuario: ", "jgarcia_88"),
    p("DOB", "es", "pii_date_of_birth", '{"fecha_de_nacimiento": "', "12/10/1980", '"}', carrier="json"),
    n("DOB", "es", "pii_date_of_birth", "Fecha de nacimiento: 30/02/1990", "impossible calendar date"),
    n("CUSTOMER_ID", "es", "pii_customer_id", "Número de pedido: PED-302948", "order number, not a customer id"),
    n("USERNAME", "es", "pii_username", "Introduzca su nombre de usuario y contraseña.", "field name in prose without an assignment", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "es", "pii_financial_account_number", "Número de cuenta: 000000000", "all-zero placeholder"),
    n("SSN", "es", "pii_ssn_us", "Número de seguro social: 666-12-3456", "area 666 is never issued"),
    n("PASSPORT_NUMBER", "es", "pii_passport_number_de", "Fecha de caducidad del pasaporte: 14/05/2030", "expiry date, not a passport number"),
    p("DOB", "it", "pii_date_of_birth", "Data di Nascita: ", "09/11/1973"),
    p("DOB", "it", "pii_date_of_birth", "Il sig. Rossi, nato il ", "15/04/1981", ", risiede a Torino.", carrier="prose"),
    p("CUSTOMER_ID", "it", "pii_customer_id", "Codice cliente: ", "CC-448210"),
    p("CUSTOMER_ID", "it", "pii_customer_id", "nome;codice_cliente\nRossi;", "CC-77125", carrier="csv"),
    p("EMPLOYEE_ID", "it", "pii_employee_id", "ID dipendente: ", "D-55012"),
    p("FINANCIAL_ACCOUNT_NUMBER", "it", "pii_financial_account_number", "Numero di conto: ", "CT-0091827"),
    p("CREDITCARD_CVV", "it", "pii_credit_card_cvv", "Carta 4111 1111 1111 1111, codice di sicurezza della carta di credito: ", "552", also=(("CREDITCARD", "4111 1111 1111 1111"),)),
    p("SSN", "it", "pii_ssn_us", "Numero di previdenza sociale: ", "219-45-7781"),
    p("PASSPORT_NUMBER", "it", "pii_passport_number_de", "Numero di passaporto: ", "YN8K4T7C2"),
    p("USERNAME", "it", "pii_username", "Nome utente: ", "lbianchi77"),
    n("DOB", "it", "pii_date_of_birth", "Data di nascita: 32/01/1975", "impossible calendar date"),
    n("CUSTOMER_ID", "it", "pii_customer_id", "Numero d'ordine: ORD-448210", "order number, not a customer id"),
    n("USERNAME", "it", "pii_username", "Il nome utente è obbligatorio.", "field name in prose without an assignment", carrier="prose"),
    n("EMPLOYEE_ID", "it", "pii_employee_id", "ID dipendente: sconosciuto", "no identifier value"),
    n("SSN", "it", "pii_ssn_us", "Numero di previdenza sociale: 123-00-4567", "group 00 is never issued"),
    n("CREDITCARD_CVV", "it", "pii_credit_card_cvv", "Carta 4111 1111 1111 1112, codice di sicurezza della carta: 552", "the card number fails Luhn, so no card verification code"),
    p("DOB", "nl", "pii_date_of_birth", "Geboortedatum: ", "15-12-1992"),
    p("DOB", "nl", "pii_date_of_birth", "Mevrouw De Vries, geboren op ", "02-03-1987", ", woont in Utrecht.", carrier="prose"),
    p("CUSTOMER_ID", "nl", "pii_customer_id", "Klantnummer: ", "KL-501873"),
    p("CUSTOMER_ID", "nl", "pii_customer_id", "Ik ben Rune Johansson, klantnummer ", "CUST14229662", ".", carrier="prose"),
    p("EMPLOYEE_ID", "nl", "pii_employee_id", "Personeelsnummer: ", "P-30411"),
    p("FINANCIAL_ACCOUNT_NUMBER", "nl", "pii_financial_account_number", "Bankrekeningnummer: ", "619867267"),
    p("CREDITCARD_CVV", "nl", "pii_credit_card_cvv", "Creditcard 5555 5555 5555 4444, creditcard-beveiligingscode is ", "713", also=(("CREDITCARD", "5555 5555 5555 4444"),)),
    p("SSN", "nl", "pii_ssn_us", "Sociaal zekerheidsnummer: ", "523-41-9087"),
    p("PASSPORT_NUMBER", "nl", "pii_passport_number_de", "Paspoortnummer: ", "NXR4C7T19"),
    p("USERNAME", "nl", "pii_username", '{"gebruikersnaam": "', "jdevries", '"}', carrier="json"),
    n("DOB", "nl", "pii_date_of_birth", "Geboortedatum: 29-02-1991", "impossible calendar date (1991 is no leap year)"),
    n("CUSTOMER_ID", "nl", "pii_customer_id", "Ordernummer: ORD-501873", "order number, not a customer id"),
    n("USERNAME", "nl", "pii_username", "Kies een gebruikersnaam voor uw account.", "field name in prose without an assignment", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "nl", "pii_financial_account_number", "Rekeningnummer: 0000000", "all-zero placeholder"),
    n("CREDITCARD_CVV", "nl", "pii_credit_card_cvv", "Creditcard 5555 5555 5555 4444. Beveiligingscode van de app: 9921", "app security code, not a card security code", also=(("CREDITCARD", "5555 5555 5555 4444"),)),
    n("PASSPORT_NUMBER", "nl", "pii_passport_number_de", "Vervaldatum paspoort: 30-06-2032", "expiry date, not a passport number"),
]
for _row in T26_MULTILINGUAL_FIELD_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# T04 parenthesized area code (TRIAGE 2026-W42 bucket 2): `pii_phone_us` reports a balanced
# `(NXX)` as part of the span, `(415) 555-2671` instead of `415) 555-2671`. Hard negatives keep
# the parentheses but fail the unchanged validator (repeated digits), the 3-3-4 shape or carry
# no digits. Appended so existing ids stay stable.
T04_PARENTHESIZED_AREA_CODE_CASES = [
    p("PHONE", "de", "pii_phone_us", "Rufen Sie unser Büro in Boston unter ", "(617) 555-0183", " an.", carrier="prose", tags=("no_context",)),
    p("PHONE", "de", "pii_phone_us", "Telefon (USA): ", "(415) 555-2671"),
    p("PHONE", "de", "pii_phone_us", '{"telefon_us": "', "(303) 499-7111", '"}', carrier="json"),
    p("PHONE", "de", "pii_phone_us", "Name;Telefon\nMiller;", "(206) 386-4636", "", carrier="csv"),
    p("PHONE", "de", "pii_phone_us", "", "(312) 744-5000", " ist die Zentrale in Chicago.", carrier="prose", tags=("no_context",)),
    p("PHONE", "en", "pii_phone_us", "Phone: ", "(212) 736-4410"),
    p("PHONE", "en", "pii_phone_us", "Office:", "(646)555-0199", "", tags=("ocr",)),
    p("PHONE", "en", "pii_phone_us", "contact:\n  phone: ", "(720) 913-1311", "\n", carrier="yaml"),
    p("PHONE", "en", "pii_phone_us", "| Name | Phone |\n|---|---|\n| R. Patel | ", "(213) 485-2121", " |", carrier="table"),
    p("PHONE", "en", "pii_phone_us", "Placeholder line ", "(212) 555-0100", " in the template.", carrier="prose", tags=("no_context",)),
    n("PHONE", "de", "pii_phone_us", "Rückfrage: (111) 111-1111", "repeated digits in parenthesized form"),
    n("PHONE", "de", "pii_phone_us", "Telefon: (XXX) XXX-XXXX", "masked number with parentheses", tags=("obfuscated",)),
    n("PHONE", "de", "pii_phone_us", "Abschnitt (12) 345-67 der Satzung", "section number, no 3-3-4 shape", carrier="prose"),
    n("PHONE", "de", "pii_phone_us", "Siehe Anhang (3) auf Seite 12.", "enumeration in parentheses", carrier="prose"),
    n("PHONE", "de", "pii_phone_us", "Telefon: (000) 000-0000", "all-zero number in parenthesized form"),
    n("PHONE", "en", "pii_phone_us", "Phone: (999) 999-9999", "repeated digits in parenthesized form"),
    n("PHONE", "en", "pii_phone_us", "Phone: (XXX) 555-XXXX", "partly masked number", tags=("obfuscated",)),
    n("PHONE", "en", "pii_phone_us", "See note (2) on page 14.", "enumeration in parentheses", carrier="prose"),
    n("PHONE", "en", "pii_phone_us", "Area code (415) only, number withheld.", "area code without a subscriber number", carrier="prose"),
    n("PHONE", "en", "pii_phone_us", "Order (12) 345-678 shipped.", "order number, no 3-3-4 shape", carrier="prose"),
]
for _row in T04_PARENTHESIZED_AREA_CODE_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# T17 phone precision (TRIAGE 2026-W43 buckets 1 + 2): `pii_phone_international` and the `+49`
# form of `pii_phone_de` do not start inside an EDIFACT element run (`NAD+BY+987654321`) or a
# SWIFT MT tag (`{86:+33…}`), and `pii_phone_us` needs the area code set off, so zero-padded
# IDs (`0000012345`) and 6-4 groups (`811228-9874`) are no NANP number. Positives keep `+49 …`,
# `+1 …` and the placeholder numbers of T01 after a field name, also directly after `:`.
# Appended so existing ids stay stable.
T17_PHONE_ELEMENT_RUN_CASES = [
    p("PHONE", "de", "pii_phone_international", "Tel.:", "+49 30 1234567"),
    p("PHONE", "de", "pii_phone_de", "Rückruf unter ", "+49 170 1234567", " (Handy)", carrier="prose"),
    p("PHONE", "de", "pii_phone_us", "Telefon (USA): ", "212-555-0100"),
    p("PHONE", "de", "pii_phone_international", "Platzhalter in der Vorlage: ", "+1 000-000-0000"),
    p("PHONE", "de", "pii_phone_de", "Kommunikationssegment: COM+", "0049 30 1234567", ":TE'"),
    p("PHONE", "de", "pii_phone_us", "Büro New York: ", "(617) 5550183"),
    p("PHONE", "en", "pii_phone_international", "Phone:", "+1 415 555 2671"),
    p("PHONE", "en", "pii_phone_international", "Placeholder in the template: ", "+1 000-000-0000"),
    p("PHONE", "en", "pii_phone_us", "Office: ", "212-555-0147"),
    p("PHONE", "en", "pii_phone_international", "Contact for this EDI interchange: ", "+44 20 7946 0958", carrier="prose"),
    p("PHONE", "en", "pii_phone_international", "Mobile (", "+44 7700 900123", ")"),
    p("PHONE", "en", "pii_phone_us", "Fax: ", "(617) 5550183"),
    n("PHONE", "de", "pii_phone_international", "Kopfsegment der Übertragung: UNB+UNOC:3+520173321::2+520173321::4+202202150830+1323327835++STA'", "EDIFACT interchange header, element run"),
    n("PHONE", "de", "pii_phone_international", "Käufer im Lieferavis: NAD+BY+987654321::9'", "EDIFACT party ID after a qualifier"),
    n("PHONE", "de", "pii_phone_international", "Belegdatum und Betrag: DTM+137:20220215:102'\nMOA+1++520173321'", "EDIFACT date and empty element before an ID"),
    n("PHONE", "de", "pii_phone_international", "EDIFACT-Position: LIN+1++5310330123:SRV'", "EDIFACT item number after an empty element"),
    n("PHONE", "de", "pii_phone_us", "X12-Bestellung: ST*850*0000012345~", "zero-padded X12 control number"),
    n("PHONE", "de", "pii_phone_us", "Schlusssaldo im Kontoauszug: :62F:/0000001234/", "zero-padded account in a SWIFT MT field"),
    n("PHONE", "de", "pii_phone_us", "Belegnummer: 0012345678", "zero-padded document number"),
    n("PHONE", "de", "pii_phone_us", "Personnummer: 811228-9874", "Swedish personal number, 6-4 groups"),
    n("PHONE", "en", "pii_phone_international", "Interchange header: UNB+UNOC:3+520173321::2+520173321::4+202202150830+1323327835++STA'", "EDIFACT interchange header, element run"),
    n("PHONE", "en", "pii_phone_international", "Buyer party segment: NAD+BY+987654321::9'", "EDIFACT party ID after a qualifier"),
    n("PHONE", "en", "pii_phone_international", "SWIFT narrative block {86:+330105789456}", "number after a SWIFT MT tag"),
    n("PHONE", "en", "pii_phone_international", "Line item segment: LIN+1+3553 6548 1210 8739:1:PCE'", "EDIFACT item number after a qualifier"),
    n("PHONE", "en", "pii_phone_us", "X12 purchase order: ST*850*0000012345~\nSE*13*0000012345~", "zero-padded X12 control numbers"),
    n("PHONE", "en", "pii_phone_us", "Closing balance field: :62F:/0000001234/", "zero-padded account in a SWIFT MT field"),
    n("PHONE", "en", "pii_phone_us", '<xbrli:identifier scheme="http://www.sec.gov/CIK">0001234567</xbrli:identifier>', "zero-padded SEC CIK", carrier="xml"),
    n("PHONE", "en", "pii_phone_us", "Swedish personal identity number: 811228-9874", "Swedish personal number, 6-4 groups"),
    n("PHONE", "en", "pii_phone_us", "My SSN is 600427-7817, issued in Sweden.", "Swedish personal number, 6-4 groups", carrier="prose"),
]
for _row in T17_PHONE_ELEMENT_RUN_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# T18 phone span boundaries (TRIAGE 2026-W43 bucket 3): a number ends before a line break
# (`+1-123-456-7890\n\n2` took the item number of the next line), and a NANP trunk prefix
# (`1-800-123-4567`, `1 (800) 123-4567`) or a `00` international prefix (`001 415 555 2671`)
# is part of the span; `0049 …` keeps its prefix. Hard negatives are digit groups split by a
# line break and prefixes without a number. Appended so existing ids stay stable.
T18_PHONE_BOUNDARY_CASES = [
    p("PHONE", "de", "pii_phone_us", "Gebührenfreie Hotline: ", "1-800-123-4567"),
    p("PHONE", "de", "pii_phone_us", "US-Kundendienst unter ", "1 (888) 432-7716", " erreichbar", carrier="prose"),
    p("PHONE", "de", "pii_phone_us", "Aus Deutschland wählen Sie ", "001 415 555 2671", ".", carrier="prose"),
    p("PHONE", "de", "pii_phone_international", "Telefon: ", "+49 30 1234567", "\n2. Ansprechpartnerin"),
    p("PHONE", "de", "pii_phone_de", "Zentrale ", "0049 170 1234567", "\n\n2. Ansprechpartner"),
    p("PHONE", "de", "pii_phone_international", "Fax ", "+44 20 7946 0958", "\r\n3 Seiten"),
    p("PHONE", "en", "pii_phone_international", "Call ", "+1-123-456-7890", "\n\n2. Next step"),
    p("PHONE", "en", "pii_phone_us", "Toll-free: ", "1-800-959-5525"),
    p("PHONE", "en", "pii_phone_us", "Customer service ", "1 (800) 123-4567", " is open 24/7.", carrier="prose"),
    p("PHONE", "en", "pii_phone_us", "From abroad dial ", "001-518-640-0854", ".", carrier="prose"),
    p("PHONE", "en", "pii_phone_us", "Support: ", "1.800.432.7716"),
    p("PHONE", "en", "pii_phone_de", "Head office ", "0049 170 1234567", "\n\n2. Contact"),
    n("PHONE", "de", "pii_phone_us", "Lagerbestand je Regal:\n415\n555-2671", "two counts on separate lines"),
    n("PHONE", "de", "pii_phone_international", "Positionen\n+49 30\n12345", "digit groups split by line breaks"),
    n("PHONE", "de", "pii_phone_us", "Bestand: 415\r\n555 2671", "two counts on separate lines"),
    n("PHONE", "de", "pii_phone_us", "Bestellnummer 001-2345-6789", "order number with a 00 lead"),
    n("PHONE", "de", "pii_phone_us", "Kapitel 1-800 bis 1-900", "section range, trunk-like prefix without a number"),
    n("PHONE", "en", "pii_phone_us", "Units per shelf:\n212\n555 0100", "two counts on separate lines"),
    n("PHONE", "en", "pii_phone_international", "Positions\n+49 30\n12345", "digit groups split by line breaks"),
    n("PHONE", "en", "pii_phone_us", "Codes 212\n\n555.0100", "two codes in separate paragraphs"),
    n("PHONE", "en", "pii_phone_us", "Part number 001-555-01", "part number with a 00 lead"),
    n("PHONE", "en", "pii_phone_us", "Version 1.800.12 released", "version string, trunk-like prefix without a number"),
]
for _row in T18_PHONE_BOUNDARY_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# B-PAN card precision (T19 + F02, TRIAGE 2026-W43 bucket 4, baseline N1/P8): a card number
# needs the IIN prefix and a length of its brand (`validators::CARD_IIN_RANGES`) besides Luhn,
# in every mode, so the balanced context-free card passes the same table. No card starts
# right after `+` (`+[44 20 1234 5678]`) or is a `-`/`_` segment of a token (`xoxb-…-…`);
# 13 digits that start with a valid YYMMDD birth date (ZA ID, KR RRN) and digits that start
# with a YYYYMMDD date (time stamps) are no card. Every hard negative below passes Luhn.
# Appended so existing ids stay stable.
B_PAN_CARD_PRECISION_CASES = [
    p("CREDITCARD", "de", "pii_credit_card", "Diners Club: ", "3673 149258 6076"),
    p("CREDITCARD", "de", "pii_credit_card", "Maestro-Karte ", "6973 1492 5860 7314 927", carrier="prose"),
    p("CREDITCARD", "de", "pii_credit_card", "Mir-Karte: ", "2200 7314 9258 6072"),
    p("CREDITCARD", "de", "pii_credit_card", "Kartennummer: ", "2221731492586077"),
    p("CREDITCARD", "de", "pii_credit_card", "UnionPay ", "6273149258607314922"),
    p("CREDITCARD", "de", "pii_credit_card", "Die Zahlung lief über ", "4731 4925 8607 3149 253", ".", carrier="prose", tags=("no_context",), mode="balanced"),
    p("CREDITCARD", "en", "pii_credit_card", "Diners Club card ", "36731492586076", carrier="prose"),
    p("CREDITCARD", "en", "pii_credit_card", "Maestro: ", "507314925862"),
    p("CREDITCARD", "en", "pii_credit_card", "JCB card number: ", "3589 7314 9258 6073 144"),
    p("CREDITCARD", "en", "pii_credit_card", "Card number: ", "2720-7314-9258-6073"),
    p("CREDITCARD", "en", "pii_credit_card", "Amex ", "3773 149258 60736"),
    p("CREDITCARD", "en", "pii_credit_card", "It was charged to ", "6011 7314 9258 6072", ".", carrier="prose", tags=("no_context",), mode="balanced"),
    # A valid IBAN whose BBAN is a card number (Maestro IIN, 18 digits): strict lists the
    # card as secondary evidence of the IBAN (T07), the scored modes keep the IBAN (K07).
    p("IBAN", "de", "pii_iban_de", "IBAN: ", "DE94 5001 0517 5401 2345 65"),
    p("IBAN", "de", "pii_iban_de", "Überweisung an ", "DE11 6005 0101 7400 1234 56", " erhalten.", carrier="prose"),
    p("IBAN", "en", "pii_iban_de", "IBAN ", "DE87 6605 0101 1002 3456 78", " is on file", carrier="prose"),
    p("IBAN", "en", "pii_iban_de", '{"iban": "', "DE45 5005 0201 1234 5678 98", '"}', carrier="json"),
    n("CREDITCARD", "de", "pii_credit_card", "Kontaktnummer: +44 20 1234 5678", "digits after + of a phone number", also=(("PHONE", "+44 20 1234 5678"),)),
    n("CREDITCARD", "de", "pii_credit_card", "Rückruf unter +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", carrier="prose", also=(("PHONE", "+63 917 123 4565"),)),
    n("CREDITCARD", "de", "pii_credit_card", "Belegdatum: DTM+137:202201010800'", "EDIFACT date-time stamp"),
    n("CREDITCARD", "de", "pii_credit_card", "Handels-ID: 20220314-123456-ABC", "date-time stamp in a trade ID"),
    n("CREDITCARD", "de", "pii_credit_card", "Protokollzeit 199912312359596", "date-time stamp, UATP-shaped"),
    n("CREDITCARD", "de", "pii_credit_card", "Sitzungs-Token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments"),
    n("CREDITCARD", "de", "pii_credit_card", "Südafrikanische ID-Nummer: 4506095123081", "ZA ID number (birth date 1945-06-09)"),
    n("CREDITCARD", "de", "pii_credit_card", "Südafrikanische ID-Nummer: 6804114321085", "ZA ID number (birth date 1968-04-11)"),
    n("CREDITCARD", "de", "pii_credit_card", "Koreanische Registrierungsnummer: 470312-1081835", "KR resident registration number"),
    n("CREDITCARD", "de", "pii_credit_card", "Referenz 1748503543012", "13 digits without a card IIN"),
    n("CREDITCARD", "de", "pii_credit_card", "Belegnummer 3731 4925 8607 3149", "Amex prefix with 16 digits"),
    n("CREDITCARD", "en", "pii_credit_card", "Phone: +44 20 1234 5678", "digits after + of a phone number", also=(("PHONE", "+44 20 1234 5678"),)),
    n("CREDITCARD", "en", "pii_credit_card", "Mobile: +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", also=(("PHONE", "+63 917 123 4565"),)),
    n("CREDITCARD", "en", "pii_credit_card", "Message date: DTM+137:202201010800'", "EDIFACT date-time stamp"),
    n("CREDITCARD", "en", "pii_credit_card", '"TradeID": "20220314-123456-ABC-IBK"', "date-time stamp in a trade ID", carrier="json"),
    n("CREDITCARD", "en", "pii_credit_card", "Log time 199912312359596", "date-time stamp, UATP-shaped"),
    n("CREDITCARD", "en", "pii_credit_card", "Session token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments"),
    n("CREDITCARD", "en", "pii_credit_card", "South African ID number: 6109240123185", "ZA ID number (birth date 1961-09-24)"),
    n("CREDITCARD", "en", "pii_credit_card", "SA ID: 4901015009082", "ZA ID number (birth date 1949-01-01)"),
    n("CREDITCARD", "en", "pii_credit_card", "Resident Registration Number: 590724-1069401", "KR resident registration number"),
    n("CREDITCARD", "en", "pii_credit_card", "1748503543012", "13 digits without a card IIN (presidio-analyzer credit card test)"),
    n("CREDITCARD", "en", "pii_credit_card", "Reference 2731 4925 8607 3141", "no brand in the 27xx range above 2720"),
    n("CREDITCARD", "de", "pii_credit_card", "Rückruf unter +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", carrier="prose", also=(("PHONE", "+63 917 123 4565"),), mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Südafrikanische ID-Nummer: 4506095123081", "ZA ID number (birth date 1945-06-09)", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Referenz 1748503543012", "13 digits without a card IIN", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Sitzungs-Token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Koreanische Registrierungsnummer: 640918-2196672", "KR resident registration number", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "Mobile: +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", also=(("PHONE", "+63 917 123 4565"),), mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "South African ID number: 6109240123185", "ZA ID number (birth date 1961-09-24)", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "1748503543012", "13 digits without a card IIN (presidio-analyzer credit card test)", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "Session token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "RRN 450630-2848967", "KR resident registration number", mode="balanced"),
]
for _row in B_PAN_CARD_PRECISION_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# B-IP IP spans (T20 + baseline C1, TRIAGE 2026-W43 bucket 5, baseline P3/P9): an address
# span holds its zone ID and CIDR prefix length, an IPv4-mapped or embedded IPv6 address is
# one span, and a prefix length out of range stays outside the span. No IPv6 starts inside
# a colon-delimited SWIFT MT or EDIFACT chain (`:28C::52D:`, `BGM+380:21:3::90:FRET`) or
# ends before a further `:`/`.` group; an invalid chain or mixed form (`2001:db8::256.1.1.1`)
# yields no span at all, not even a sub-span. A SWIFT MT tag at the start of a line
# (`:25:`) and a field name (`IPv6:`) open a value. Loopback and unspecified addresses stay
# rejected (D-IP), also mapped (`::ffff:127.0.0.1`) and with a prefix (`::/0`).
# Appended so existing ids stay stable.
B_IP_SPAN_CASES = [
    p("IP_ADDRESS", "de", "pii_ipv6_loopback", "Verbindung von ", "::ffff:10.20.30.40", " abgelehnt.", carrier="prose"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "NAT64-Adresse: ", "64:ff9b::198.51.100.1"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "Schnittstelle: ", "fe80::a1b2:3c4d%eth0"),
    p("IP_ADDRESS", "de", "pii_ipv4", "Freigegebenes Netz: ", "198.51.100.0/24"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "Präfix ", "2001:db8:4f00::/40", " gesperrt.", carrier="prose"),
    p("IP_ADDRESS", "de", "pii_ipv6_full", ":20:REF2209\n:25:", "2a02:810d:4b40:3d00:91f2:6c1e:8a3b:52d7", "\n:28C:00042/001", carrier="kv"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "IPv6:", "2001:db8:85a3::8a2e:198.51.100.23"),
    p("IP_ADDRESS", "de", "pii_ipv4", "Route ", "203.0.113.0", "/123 ist ungültig.", carrier="prose"),
    p("IP_ADDRESS", "de", "pii_ipv6_loopback", "Gemappt: ", "::ffff:198.51.100.0/120", mode="balanced"),
    p("IP_ADDRESS", "en", "pii_ipv6_loopback", "Connect to ", "::ffff:10.0.0.1", " now", carrier="prose"),
    p("IP_ADDRESS", "en", "pii_ipv6_loopback", "Mapped peer [", "::ffff:192.0.2.71", "]:443 accepted.", carrier="prose"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "Link-local: ", "fe80::1%eth0"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "Zone and prefix: ", "2001:db8::%eth0/128"),
    p("IP_ADDRESS", "en", "pii_ipv4", "Subnet: ", "192.0.2.0/24"),
    p("IP_ADDRESS", "en", "pii_ipv6_full", " :50K:/ACME LTD\n :52A:", "2001:db8:85a3:0:0:8a2e:370:7334", "\n :57A:BANKDEFF", carrier="kv"),
    p("IP_ADDRESS", "en", "pii_ipv6_full", "Embedded: ", "2001:db8:1:2:3:4:203.0.113.9"),
    p("IP_ADDRESS", "en", "pii_ipv4", "Host ", "10.0.0.0", "/123 is malformed.", carrier="prose"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "Prefix ", "2001:db8::/32", ".", carrier="prose", mode="balanced"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", ":20:MT940 STMT\n:28C::52D:20220920\n:60F::STP", "SWIFT MT tag chain", carrier="kv"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Saldo :60F::61F::62F::63F::64F::70:3/31/2022", "SWIFT MT tag chain"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Belegkopf: BGM+380:21:3::90:FRET:FRCOMPAGNIE'", "EDIFACT composite element"),
    n("IP_ADDRESS", "de", "pii_ipv6_loopback", "Position: LIN+1::1:550:::EA:20'", "EDIFACT composite element"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Ungültige Adresse 2001:db8::256.1.1.1", "invalid mixed IPv6 (octet 256)"),
    n("IP_ADDRESS", "de", "pii_ipv6_loopback", "Lokaler Dienst auf ::ffff:127.0.0.1", "IPv4-mapped loopback is excluded"),
    n("IP_ADDRESS", "de", "pii_ipv6_loopback", "Standardroute ::/0", "unspecified address with prefix is excluded"),
    n("IP_ADDRESS", "de", "pii_ipv6_full", "Schlüssel 2001:db8:1:2:3:4:5:6:7", "nine groups are no IPv6 address"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Belegkopf: BGM+380:21:3::90:FRET:FRCOMPAGNIE'", "EDIFACT composite element", mode="balanced"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Ungültige Adresse 2001:db8::256.1.1.1", "invalid mixed IPv6 (octet 256)", mode="balanced"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", ":20:MT940 STMT\n:25:Lk-27571\n:28C::52D:20220920", "SWIFT MT tag chain", carrier="kv"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "Charges :71F::72F/140350.00GBP/GBP041316.7", "SWIFT MT tag chain"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "Document: BGM+380:21:3::90:FRET:FRCOMPAGNIE'", "EDIFACT composite element"),
    n("IP_ADDRESS", "en", "pii_ipv6_loopback", "Item: LIN+1::1:550:::EA:20'", "EDIFACT composite element"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "2001:db8::256.1.1.1", "invalid mixed IPv6 (presidio-analyzer IP test)"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "text2001:db8::1", "address glued to a word (presidio-analyzer IP test)"),
    n("IP_ADDRESS", "en", "pii_ipv6_loopback", "Mapped unspecified ::ffff:0.0.0.0", "IPv4-mapped unspecified address is excluded"),
    n("IP_ADDRESS", "en", "pii_ipv6_loopback", "Loopback route ::1/128", "loopback with prefix is excluded"),
    n("IP_ADDRESS", "en", "pii_ipv6_full", "Rate between the U.9101:8c5c:e9b4:50ce:7e5d:ce61:c1d2:d092", "groups glued to a dot"),
    n("IP_ADDRESS", "en", "pii_ipv6_loopback", "Item: LIN+1::1:550:::EA:20'", "EDIFACT composite element", mode="balanced"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "2001:db8::256.1.1.1", "invalid mixed IPv6 (presidio-analyzer IP test)", mode="balanced"),
]
for _row in B_IP_SPAN_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# B01 VAT IDs, part 1: one label and one check-digit validator per country (DE, AT, CH, FR,
# NL, BE, IT, ES). The rules are scored-only like K05: strict stays bit-identical, `balanced`
# and `recall` report a prefixed VAT ID without a field name. A bare Partita IVA (11 digits
# without `IT`) needs a VAT term nearby or as its key. Hard negatives: failing check digits or
# components, a nearer counter-context term, values glued to letters or inside longer
# numbers and paths, wrong lengths. Appended so existing ids stay stable.
B01_VAT_ID_CASES = [
    # ── DE: ISO 7064 MOD 11,10 ──────────────────────────────────────────────
    p("VAT_ID_DE", "de", "pii_vat_id_de", "Unsere USt-IdNr. lautet ", "DE703082462", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_DE", "de", "pii_vat_id_de", "Sitz der Gesellschaft: Köln · ", "DE 500 088 387", "", mode="balanced"),
    p("VAT_ID_DE", "de", "pii_vat_id_de", '{"firma": "Weber Holz GmbH", "ust_id": "', "DE298296572", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_DE", "de", "pii_vat_id_de", "Firma;USt-IdNr.\nWeber Holz GmbH;", "DE616780083", "", carrier="csv", mode="balanced"),
    p("VAT_ID_DE", "de", "pii_vat_id_de", "Bitte tragen Sie ", "DE.877.183.417", " im Formular ein.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_DE", "de", "pii_vat_id_de", "| Lieferant | Kennung |\n|---|---|\n| Weber Holz GmbH | ", "DE412581535", " |", carrier="table", tags=("no_context",), mode="recall"),
    p("VAT_ID_DE", "en", "pii_vat_id_de", "Our VAT ID is ", "DE478383064", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_DE", "en", "pii_vat_id_de", "Registered office: Bristol · VAT number ", "DE 473 441 979", "", mode="balanced"),
    p("VAT_ID_DE", "en", "pii_vat_id_de", "vat_id=", "DE973557063", "", carrier="kv", mode="balanced"),
    p("VAT_ID_DE", "en", "pii_vat_id_de", "<supplier><vatId>", "DE620340930", "</vatId></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_DE", "en", "pii_vat_id_de", "Please copy ", "DE-887-161-682", " into the supplier record.", carrier="prose", tags=("no_context",), mode="recall"),
    n("VAT_ID_DE", "de", "pii_vat_id_de", "Unsere USt-IdNr. lautet DE703082463.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "de", "pii_vat_id_de", "Rechnungsnummer DE703082462 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "de", "pii_vat_id_de", "USt-IdNr. DE070308246", "a leading zero is never issued", mode="balanced"),
    n("VAT_ID_DE", "de", "pii_vat_id_de", "Artikel XDE703082462 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "de", "pii_vat_id_de", "Messreihe DE703082462-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_DE", "de", "pii_vat_id_de", "USt-IdNr. DE70308246", "eight digits", mode="balanced"),
    n("VAT_ID_DE", "en", "pii_vat_id_de", "Our VAT ID is DE500088388.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "en", "pii_vat_id_de", "Order number DE500088387 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "en", "pii_vat_id_de", "Build DE5000883871 failed.", "ten digits", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "en", "pii_vat_id_de", "Path /exports/DE500088387/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_DE", "en", "pii_vat_id_de", "VAT ID DE987654321", "check digit fails (presidio-analyzer DE VAT test value)", mode="recall"),
    # ── AT: UID ATU + 8 digits, Luhn-based check digit ─────────────────────
    p("VAT_ID_AT", "de", "pii_vat_id_at", "Unsere UID-Nummer lautet ", "ATU83263898", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_AT", "de", "pii_vat_id_at", "Gerichtsstand Wien · ", "ATU 78066717", "", mode="balanced"),
    p("VAT_ID_AT", "de", "pii_vat_id_at", '{"firma": "Huber Bau GmbH", "uid": "', "ATU23143015", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_AT", "de", "pii_vat_id_at", "Firma;UID\nHuber Bau GmbH;", "ATU40486844", "", carrier="csv", mode="balanced"),
    p("VAT_ID_AT", "de", "pii_vat_id_at", "Bitte ", "ATU87780063", " auf der Rechnung ergänzen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_AT", "en", "pii_vat_id_at", "Our Austrian VAT number is ", "ATU55987490", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_AT", "en", "pii_vat_id_at", "Seat: Vienna · ", "ATU68826372", "", mode="balanced"),
    p("VAT_ID_AT", "en", "pii_vat_id_at", "vat_number=", "ATU56480445", "", carrier="kv", mode="balanced"),
    p("VAT_ID_AT", "en", "pii_vat_id_at", "<supplier><vat>", "ATU10686890", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_AT", "en", "pii_vat_id_at", "Please add ", "ATU66693740", " to the vendor file.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_AT", "de", "pii_vat_id_at", "Unsere UID-Nummer lautet ATU83263899.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_AT", "de", "pii_vat_id_at", "Bestellnummer ATU83263898 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_AT", "de", "pii_vat_id_at", "UID AT83263898", "the U after AT is missing", mode="balanced"),
    n("VAT_ID_AT", "de", "pii_vat_id_at", "Typ ATU832638981 geliefert.", "nine digits", carrier="prose", mode="balanced"),
    n("VAT_ID_AT", "de", "pii_vat_id_at", "Seriencode KATU83263898 gedruckt.", "glued to a letter", carrier="prose", mode="recall"),
    n("VAT_ID_AT", "en", "pii_vat_id_at", "Austrian VAT number ATU55987491", "check digit fails", mode="balanced"),
    n("VAT_ID_AT", "en", "pii_vat_id_at", "Invoice number ATU55987490 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_AT", "en", "pii_vat_id_at", "VAT number ATU5598749", "seven digits", mode="balanced"),
    n("VAT_ID_AT", "en", "pii_vat_id_at", "Batch ATU55987490-2 failed.", "part of a hyphenated number", carrier="prose", mode="balanced"),
    n("VAT_ID_AT", "en", "pii_vat_id_at", "Model ATU55987490X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── CH: UID CHE + 9 digits, weighted mod 11 ────────────────────────────
    p("VAT_ID_CH", "de", "pii_vat_id_ch", "Unsere MWST-Nummer lautet ", "CHE-265.523.994", " MWST.", carrier="prose", mode="balanced"),
    p("VAT_ID_CH", "de", "pii_vat_id_ch", "Sitz: Zürich · ", "CHE-991.677.454", "", mode="balanced"),
    p("VAT_ID_CH", "de", "pii_vat_id_ch", '{"firma": "Meier AG", "mwst_nr": "', "CHE568896507", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_CH", "de", "pii_vat_id_ch", "Firma;UID\nMeier AG;", "CHE-256.204.685", "", carrier="csv", mode="balanced"),
    p("VAT_ID_CH", "de", "pii_vat_id_ch", "Bitte ", "CHE 087 254 229", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_CH", "en", "pii_vat_id_ch", "Our Swiss VAT number is ", "CHE-763.140.573", " VAT.", carrier="prose", mode="balanced"),
    p("VAT_ID_CH", "en", "pii_vat_id_ch", "Seat: Basel · ", "CHE-424.087.152", "", mode="balanced"),
    p("VAT_ID_CH", "en", "pii_vat_id_ch", "vat_id=", "CHE860238288", "", carrier="kv", mode="balanced"),
    p("VAT_ID_CH", "en", "pii_vat_id_ch", "<supplier><vat>", "CHE-720.565.616", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_CH", "en", "pii_vat_id_ch", "Please store ", "CHE-246.155.884", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_CH", "de", "pii_vat_id_ch", "Unsere MWST-Nummer lautet CHE-265.523.995 MWST.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_CH", "de", "pii_vat_id_ch", "Auftragsnummer CHE-265.523.994 bestätigt.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_CH", "de", "pii_vat_id_ch", "MWST-Nr. CHE-265.523.99", "eight digits", mode="balanced"),
    n("VAT_ID_CH", "de", "pii_vat_id_ch", "Version 3.CHE265523994 installiert.", "joined to a version number", carrier="prose", mode="balanced"),
    n("VAT_ID_CH", "de", "pii_vat_id_ch", "Code XCHE265523994 gesperrt.", "glued to a letter", carrier="prose", mode="recall"),
    n("VAT_ID_CH", "en", "pii_vat_id_ch", "Swiss VAT number CHE-763.140.574", "check digit fails", mode="balanced"),
    n("VAT_ID_CH", "en", "pii_vat_id_ch", "Ticket number CHE-763.140.573 was closed.", "ticket number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_CH", "en", "pii_vat_id_ch", "VAT number CHE-763.140.57", "eight digits", mode="balanced"),
    n("VAT_ID_CH", "en", "pii_vat_id_ch", "Model CHE763140573B sold out.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_CH", "en", "pii_vat_id_ch", "VAT number CHE-100.155.213", "check digit fails", mode="recall"),
    # ── FR: key (12 + 3 × SIREN mod 97) mod 97 and SIREN Luhn ──────────────
    p("VAT_ID_FR", "de", "pii_vat_id_fr", "Die französische USt-IdNr. lautet ", "FR69626275960", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_FR", "de", "pii_vat_id_fr", "Lieferant Durand SARL · ", "FR 44 096 275 938", "", mode="balanced"),
    p("VAT_ID_FR", "de", "pii_vat_id_fr", '{"firma": "Durand SARL", "ust_id": "', "FR39785504457", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_FR", "de", "pii_vat_id_fr", "Firma;USt-IdNr.\nDurand SARL;", "FR03121740526", "", carrier="csv", mode="balanced"),
    p("VAT_ID_FR", "de", "pii_vat_id_fr", "Bitte ", "FR93932436389", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_FR", "en", "pii_vat_id_fr", "Our French VAT number is ", "FR26862648003", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_FR", "en", "pii_vat_id_fr", "Supplier Durand SARL · ", "FR04 325396844", "", mode="balanced"),
    p("VAT_ID_FR", "en", "pii_vat_id_fr", "vat_id=", "FR35226087252", "", carrier="kv", mode="balanced"),
    p("VAT_ID_FR", "en", "pii_vat_id_fr", "<supplier><vat>", "FR54733466387", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_FR", "en", "pii_vat_id_fr", "Please store ", "FR74914367255", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_FR", "fr", "pii_vat_id_fr", "Numéro de TVA intracommunautaire : ", "FR62221970775", "", mode="balanced"),
    p("VAT_ID_FR", "fr", "pii_vat_id_fr", "Notre numéro de TVA est ", "FR 65 049 757 461", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_FR", "fr", "pii_vat_id_fr", '{"societe": "Durand SARL", "tva": "', "FR41127655728", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_FR", "fr", "pii_vat_id_fr", "Société;N° TVA\nDurand SARL;", "FR70265288100", "", carrier="csv", mode="balanced"),
    p("VAT_ID_FR", "fr", "pii_vat_id_fr", "Merci de reporter ", "FR88485996474", " dans la fiche fournisseur.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_FR", "de", "pii_vat_id_fr", "Die französische USt-IdNr. lautet FR70626275960.", "key fails", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "de", "pii_vat_id_fr", "Belegnummer FR69626275960 gebucht.", "invoice number with a valid key", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "de", "pii_vat_id_fr", "USt-IdNr. FR6962627596", "ten digits", mode="balanced"),
    n("VAT_ID_FR", "de", "pii_vat_id_fr", "Ablage /srv/FR69626275960/2026 erstellt.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "de", "pii_vat_id_fr", "USt-IdNr. FR43303265046", "key fits, but the SIREN fails Luhn", mode="recall"),
    n("VAT_ID_FR", "en", "pii_vat_id_fr", "French VAT number FR27862648003", "key fails", mode="balanced"),
    n("VAT_ID_FR", "en", "pii_vat_id_fr", "Reference number FR26862648003 confirmed.", "reference number with a valid key", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "en", "pii_vat_id_fr", "VAT number FR268626480031", "twelve digits", mode="balanced"),
    n("VAT_ID_FR", "en", "pii_vat_id_fr", "Code AFR26862648003 revoked.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "en", "pii_vat_id_fr", "VAT number FR12345678901", "key fails (presidio-analyzer DE VAT test value)", mode="recall"),
    n("VAT_ID_FR", "fr", "pii_vat_id_fr", "Numéro de TVA intracommunautaire : FR63221970775", "key fails", mode="balanced"),
    n("VAT_ID_FR", "fr", "pii_vat_id_fr", "Numéro de TVA FR6222197077", "ten digits", mode="balanced"),
    n("VAT_ID_FR", "fr", "pii_vat_id_fr", "Référence XFR62221970775 annulée.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "fr", "pii_vat_id_fr", "Plage FR62221970775-6 réservée.", "part of a hyphenated number", carrier="prose", mode="balanced"),
    n("VAT_ID_FR", "fr", "pii_vat_id_fr", "Numéro de TVA FR40303265046", "key and SIREN Luhn fail", mode="recall"),
    # ── NL: btw-id NL + 9 digits + B + 2 digits, mod 11 or ISO 7064 MOD 97-10 ─
    p("VAT_ID_NL", "de", "pii_vat_id_nl", "Die niederländische USt-IdNr. lautet ", "NL496806300B01", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_NL", "de", "pii_vat_id_nl", "Lieferant De Vries BV · ", "NL053980918B01", "", mode="balanced"),
    p("VAT_ID_NL", "de", "pii_vat_id_nl", '{"firma": "De Vries BV", "ust_id": "', "NL421790416B02", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_NL", "de", "pii_vat_id_nl", "Firma;USt-IdNr.\nDe Vries BV;", "NL339014544B02", "", carrier="csv", mode="balanced"),
    p("VAT_ID_NL", "de", "pii_vat_id_nl", "Bitte ", "NL 775186739B01", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_NL", "en", "pii_vat_id_nl", "Our Dutch VAT number is ", "NL703551818B02", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_NL", "en", "pii_vat_id_nl", "Supplier De Vries BV · ", "NL431208463B02", "", mode="balanced"),
    p("VAT_ID_NL", "en", "pii_vat_id_nl", "vat_id=", "NL292913321B01", "", carrier="kv", mode="balanced"),
    p("VAT_ID_NL", "en", "pii_vat_id_nl", "<supplier><vat>", "NL456915680B01", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_NL", "en", "pii_vat_id_nl", "Please store ", "NL008203210B01", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_NL", "nl", "pii_vat_id_nl", "Btw-nummer: ", "NL676484153B02", "", mode="balanced"),
    p("VAT_ID_NL", "nl", "pii_vat_id_nl", "Ons btw-identificatienummer is ", "NL198557061B01", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_NL", "nl", "pii_vat_id_nl", '{"bedrijf": "De Vries BV", "btw_nummer": "', "NL927591352B01", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_NL", "nl", "pii_vat_id_nl", "Bedrijf;Btw-nummer\nDe Vries BV;", "NL121899524B01", "", carrier="csv", mode="balanced"),
    p("VAT_ID_NL", "nl", "pii_vat_id_nl", "Graag ", "NL000099998B57", " overnemen in het leveranciersbestand.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_NL", "de", "pii_vat_id_nl", "Die niederländische USt-IdNr. lautet NL496806301B01.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_NL", "de", "pii_vat_id_nl", "Sendungsnummer NL496806300B01 ist unterwegs.", "tracking number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_NL", "de", "pii_vat_id_nl", "USt-IdNr. NL496806300B00", "branch number 00 is never issued", mode="balanced"),
    n("VAT_ID_NL", "de", "pii_vat_id_nl", "USt-IdNr. NL49680630B01", "eight digits", mode="balanced"),
    n("VAT_ID_NL", "de", "pii_vat_id_nl", "Code XNL496806300B01 gesperrt.", "glued to a letter", carrier="prose", mode="recall"),
    n("VAT_ID_NL", "en", "pii_vat_id_nl", "Dutch VAT number NL703551819B02", "check digit fails", mode="balanced"),
    n("VAT_ID_NL", "en", "pii_vat_id_nl", "Tracking number NL703551818B02 is in transit.", "tracking number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_NL", "en", "pii_vat_id_nl", "VAT number NL703551818C02", "C instead of B", mode="balanced"),
    n("VAT_ID_NL", "en", "pii_vat_id_nl", "Part NL703551818B021 shipped.", "three branch digits", carrier="prose", mode="balanced"),
    n("VAT_ID_NL", "en", "pii_vat_id_nl", "VAT number NL000000000B01", "zero number", mode="recall"),
    n("VAT_ID_NL", "nl", "pii_vat_id_nl", "Btw-nummer: NL676484154B02", "check digit fails", mode="balanced"),
    n("VAT_ID_NL", "nl", "pii_vat_id_nl", "Btw-nummer: NL676484153B00", "branch number 00 is never issued", mode="balanced"),
    n("VAT_ID_NL", "nl", "pii_vat_id_nl", "Btw-nummer: NL67648415B02", "eight digits", mode="balanced"),
    n("VAT_ID_NL", "nl", "pii_vat_id_nl", "Code ANL676484153B02 geblokkeerd.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_NL", "nl", "pii_vat_id_nl", "Pad /data/NL676484153B02/2026 aangemaakt.", "part of a slash path", carrier="prose", mode="recall"),
    # ── BE: BE + 10 digits, 97 − (first 8 mod 97) ──────────────────────────
    p("VAT_ID_BE", "de", "pii_vat_id_be", "Die belgische USt-IdNr. lautet ", "BE0843608406", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_BE", "de", "pii_vat_id_be", "Lieferant Peeters NV · ", "BE 0141.087.488", "", mode="balanced"),
    p("VAT_ID_BE", "de", "pii_vat_id_be", '{"firma": "Peeters NV", "ust_id": "', "BE1004774104", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_BE", "de", "pii_vat_id_be", "Firma;USt-IdNr.\nPeeters NV;", "BE0376709594", "", carrier="csv", mode="balanced"),
    p("VAT_ID_BE", "de", "pii_vat_id_be", "Bitte ", "BE1680932103", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_BE", "en", "pii_vat_id_be", "Our Belgian VAT number is ", "BE1481735574", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_BE", "en", "pii_vat_id_be", "Supplier Peeters NV · ", "BE0434 555 347", "", mode="balanced"),
    p("VAT_ID_BE", "en", "pii_vat_id_be", "vat_id=", "BE1992602605", "", carrier="kv", mode="balanced"),
    p("VAT_ID_BE", "en", "pii_vat_id_be", "<supplier><vat>", "BE1564300489", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_BE", "en", "pii_vat_id_be", "Please store ", "BE0134627882", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_BE", "nl", "pii_vat_id_be", "Btw-nummer: ", "BE1543789147", "", mode="balanced"),
    p("VAT_ID_BE", "nl", "pii_vat_id_be", "Ons ondernemingsnummer voor de btw is ", "BE 0186.493.089", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_BE", "nl", "pii_vat_id_be", '{"bedrijf": "Peeters NV", "btw": "', "BE1665127932", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_BE", "nl", "pii_vat_id_be", "Bedrijf;Btw-nummer\nPeeters NV;", "BE1403288112", "", carrier="csv", mode="balanced"),
    p("VAT_ID_BE", "nl", "pii_vat_id_be", "Graag ", "BE0181193129", " overnemen in het leveranciersbestand.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_BE", "de", "pii_vat_id_be", "Die belgische USt-IdNr. lautet BE0843608407.", "check digits fail", carrier="prose", mode="balanced"),
    n("VAT_ID_BE", "de", "pii_vat_id_be", "Rechnungsnummer BE0843608406 bitte angeben.", "invoice number with valid check digits", carrier="prose", mode="balanced"),
    n("VAT_ID_BE", "de", "pii_vat_id_be", "USt-IdNr. BE2843608406", "first digit is neither 0 nor 1", mode="balanced"),
    n("VAT_ID_BE", "de", "pii_vat_id_be", "USt-IdNr. BE084360840", "nine digits", mode="balanced"),
    n("VAT_ID_BE", "de", "pii_vat_id_be", "Code XBE0843608406 gesperrt.", "glued to a letter", carrier="prose", mode="recall"),
    n("VAT_ID_BE", "en", "pii_vat_id_be", "Belgian VAT number BE1481735575", "check digits fail", mode="balanced"),
    n("VAT_ID_BE", "en", "pii_vat_id_be", "Order number BE1481735574 has shipped.", "order number with valid check digits", carrier="prose", mode="balanced"),
    n("VAT_ID_BE", "en", "pii_vat_id_be", "VAT number BE0000000097", "zero company number", mode="balanced"),
    n("VAT_ID_BE", "en", "pii_vat_id_be", "Batch BE1481735574-2 failed.", "part of a hyphenated number", carrier="prose", mode="balanced"),
    n("VAT_ID_BE", "en", "pii_vat_id_be", "VAT number BE14817355741", "eleven digits", mode="recall"),
    n("VAT_ID_BE", "nl", "pii_vat_id_be", "Btw-nummer: BE1543789148", "check digits fail", mode="balanced"),
    n("VAT_ID_BE", "nl", "pii_vat_id_be", "Btw-nummer: BE5543789147", "first digit is neither 0 nor 1", mode="balanced"),
    n("VAT_ID_BE", "nl", "pii_vat_id_be", "Btw-nummer: BE154378914", "nine digits", mode="balanced"),
    n("VAT_ID_BE", "nl", "pii_vat_id_be", "Code ABE1543789147 geblokkeerd.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_BE", "nl", "pii_vat_id_be", "Pad /data/BE1543789147/2026 aangemaakt.", "part of a slash path", carrier="prose", mode="recall"),
    # ── IT: Partita IVA, Luhn and province office code ─────────────────────
    p("VAT_ID_IT", "de", "pii_vat_id_it", "Die italienische USt-IdNr. lautet ", "IT57709980593", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_IT", "de", "pii_vat_id_it", "Lieferant Rossi Srl · ", "IT 36216820153", "", mode="balanced"),
    p("VAT_ID_IT", "de", "pii_vat_id_it", '{"firma": "Rossi Srl", "ust_id": "', "IT63609570898", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_IT", "de", "pii_vat_id_it", "Bitte ", "IT15761530615", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_IT", "de", "pii_vat_id_it_proximity", "Partita IVA: ", "18149200349", "", mode="balanced"),
    p("VAT_ID_IT", "de", "pii_vat_id_it_proximity", "Firma;Partita IVA\nRossi Srl;", "01002660106", "", carrier="csv", mode="balanced"),
    p("VAT_ID_IT", "en", "pii_vat_id_it", "Our Italian VAT number is ", "IT49352320276", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_IT", "en", "pii_vat_id_it", "Supplier Rossi Srl · ", "IT34126900934", "", mode="balanced"),
    p("VAT_ID_IT", "en", "pii_vat_id_it", "Please store ", "IT55850260096", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_IT", "en", "pii_vat_id_it_proximity", "Italian VAT number: ", "53859980343", "", mode="balanced"),
    p("VAT_ID_IT", "en", "pii_vat_id_it_proximity", '{"supplier": "Rossi Srl", "it_vat": "', "12497600473", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_IT", "en", "pii_vat_id_it_proximity", "The supplier's Partita IVA is ", "43123510471", ".", carrier="prose", mode="recall"),
    p("VAT_ID_IT", "it", "pii_vat_id_it", "Partita IVA ", "IT97235230246", "", mode="balanced"),
    p("VAT_ID_IT", "it", "pii_vat_id_it", "Si prega di inserire ", "IT71522000422", " nella scheda fornitore.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_IT", "it", "pii_vat_id_it_proximity", "P.IVA ", "45908250199", "", mode="balanced"),
    p("VAT_ID_IT", "it", "pii_vat_id_it_proximity", '{"azienda": "Rossi Srl", "partita_iva": "', "16052160823", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_IT", "it", "pii_vat_id_it_proximity", "La nostra partita IVA è ", "00743110157", ".", carrier="prose", mode="balanced"),
    n("VAT_ID_IT", "de", "pii_vat_id_it", "Die italienische USt-IdNr. lautet IT57709980594.", "Luhn fails", carrier="prose", mode="balanced"),
    n("VAT_ID_IT", "de", "pii_vat_id_it", "Bestellnummer IT57709980593 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_IT", "de", "pii_vat_id_it", "USt-IdNr. IT12345670009", "office code 000 is never issued", mode="balanced"),
    n("VAT_ID_IT", "de", "pii_vat_id_it_proximity", "Bitte 18149200349 übernehmen.", "eleven bare digits without a VAT term", carrier="prose", mode="balanced"),
    n("VAT_ID_IT", "de", "pii_vat_id_it_proximity", "Partita IVA: 18149200340", "Luhn fails", mode="recall"),
    n("VAT_ID_IT", "en", "pii_vat_id_it", "Italian VAT number IT49352320277", "Luhn fails", mode="balanced"),
    n("VAT_ID_IT", "en", "pii_vat_id_it", "VAT number IT00000000000", "zero company number", mode="balanced"),
    n("VAT_ID_IT", "en", "pii_vat_id_it", "VAT number IT12345675008", "office code 500 is never issued", mode="balanced"),
    n("VAT_ID_IT", "en", "pii_vat_id_it_proximity", "Invoice number 53859980343 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_IT", "en", "pii_vat_id_it_proximity", '{"order_id": "53859980343"}', "order number key", carrier="json", mode="recall"),
    n("VAT_ID_IT", "it", "pii_vat_id_it", "Partita IVA IT97235230247", "Luhn fails", mode="balanced"),
    n("VAT_ID_IT", "it", "pii_vat_id_it", "Partita IVA IT9723523024", "ten digits", mode="balanced"),
    n("VAT_ID_IT", "it", "pii_vat_id_it", "Codice XIT97235230246 annullato.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_IT", "it", "pii_vat_id_it_proximity", "P.IVA 45908250190", "Luhn fails", mode="balanced"),
    n("VAT_ID_IT", "it", "pii_vat_id_it_proximity", "Si prega di inserire 45908250199 nella scheda.", "eleven bare digits without a VAT term", carrier="prose", mode="recall"),
    # ── ES: NIF-IVA ES + DNI, NIE or CIF with control character ────────────
    p("VAT_ID_ES", "de", "pii_vat_id_es", "Die spanische USt-IdNr. lautet ", "ESJ4233905A", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_ES", "de", "pii_vat_id_es", "Lieferant García SL · ", "ESG6337469H", "", mode="balanced"),
    p("VAT_ID_ES", "de", "pii_vat_id_es", '{"firma": "García SL", "ust_id": "', "ES11059044T", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_ES", "de", "pii_vat_id_es", "Firma;USt-IdNr.\nGarcía SL;", "ESX3325209F", "", carrier="csv", mode="balanced"),
    p("VAT_ID_ES", "de", "pii_vat_id_es", "Bitte ", "ESN32115586", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_ES", "en", "pii_vat_id_es", "Our Spanish VAT number is ", "ESX6866965Q", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_ES", "en", "pii_vat_id_es", "Supplier García SL · ", "ES Z9635996J", "", mode="balanced"),
    p("VAT_ID_ES", "en", "pii_vat_id_es", "vat_id=", "ESG7819660G", "", carrier="kv", mode="balanced"),
    p("VAT_ID_ES", "en", "pii_vat_id_es", "<supplier><vat>", "ESG2860530A", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_ES", "en", "pii_vat_id_es", "Please store ", "ESV1760354I", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es", "NIF-IVA: ", "ESQ1924545E", "", mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es", "Nuestro número de IVA intracomunitario es ", "ES97686336T", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es", '{"empresa": "García SL", "nif_iva": "', "ESD81860470", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es", "Empresa;NIF-IVA\nGarcía SL;", "ES23075793P", "", carrier="csv", mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es", "Por favor, copie ", "ESR3061803G", " en la ficha del proveedor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_ES", "de", "pii_vat_id_es", "Die spanische USt-IdNr. lautet ESJ4233905B.", "CIF control letter fails", carrier="prose", mode="balanced"),
    n("VAT_ID_ES", "de", "pii_vat_id_es", "Bestellnummer ESJ4233905A ist eingegangen.", "order number with a valid control letter", carrier="prose", mode="balanced"),
    n("VAT_ID_ES", "de", "pii_vat_id_es", "USt-IdNr. ESI4233905A", "no CIF, NIF or NIE starts with I", mode="balanced"),
    n("VAT_ID_ES", "de", "pii_vat_id_es", "USt-IdNr. ESJ423390A", "six digits", mode="balanced"),
    n("VAT_ID_ES", "de", "pii_vat_id_es", "Code XESJ4233905A gesperrt.", "glued to a letter", carrier="prose", mode="recall"),
    n("VAT_ID_ES", "en", "pii_vat_id_es", "Spanish VAT number ESX6866965R", "NIE control letter fails", mode="balanced"),
    n("VAT_ID_ES", "en", "pii_vat_id_es", "Tracking number ESX6866965Q is in transit.", "tracking number with a valid control letter", carrier="prose", mode="balanced"),
    n("VAT_ID_ES", "en", "pii_vat_id_es", "VAT number ES11059044A", "DNI control letter fails", mode="balanced"),
    n("VAT_ID_ES", "en", "pii_vat_id_es", "Batch ESX6866965Q-2 failed.", "part of a hyphenated code", carrier="prose", mode="balanced"),
    n("VAT_ID_ES", "en", "pii_vat_id_es", "VAT number ESX68669651Q", "eight digits", mode="recall"),
    n("VAT_ID_ES", "es", "pii_vat_id_es", "NIF-IVA: ESQ1924545F", "CIF control letter fails", mode="balanced"),
    n("VAT_ID_ES", "es", "pii_vat_id_es", "NIF-IVA: ES97686336U", "DNI control letter fails", mode="balanced"),
    n("VAT_ID_ES", "es", "pii_vat_id_es", "NIF-IVA: ESQ192454E", "six digits", mode="balanced"),
    n("VAT_ID_ES", "es", "pii_vat_id_es", "Código AESQ1924545E anulado.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_ES", "es", "pii_vat_id_es", "Ruta /datos/ESQ1924545E/2026 creada.", "part of a slash path", carrier="prose", mode="recall"),
]
for _row in B01_VAT_ID_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# F08 German passport and identity card numbers with ICAO 9303 check digits (7-3-1). The rules
# are scored-only like K05: strict stays bit-identical (the field-bound rules keep their format
# check), `balanced` and `recall` report a letter-led value without a field name: passport series
# C, F, G, H, J, K, identity card series L, M, N, P, R, T, V, W, X, Y, eight characters plus the
# check digit or the MRZ form (nine plus the check digit). The old numeric serial (ten digits)
# needs a document term nearby or as its key. `Pass-Nr.` (baseline P6) is a passport term. Hard
# negatives: failing check digits, wrong series, a nearer counter-context term, values glued to
# letters or inside longer numbers and paths, a field name of another label. Appended so
# existing ids stay stable.
F08_DOCUMENT_NUMBER_CASES = [
    # ── Passport ────────────────────────────────────────────────────────────
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Pass-Nr.: ", "F12345671", "", mode="balanced"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Bitte legen Sie den Pass ", "C01X00T41", " am Schalter vor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", '{"name": "Erika Mustermann", "pass_nr": "', "H1J2K3L47", '"}', carrier="json", mode="balanced"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Reisepass-Nr. ", "C01X00T478", " laut MRZ", mode="balanced"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Name;Pass-Nr.;Ort\nErika Mustermann;", "K2L4M6N82", ";Köln", carrier="csv", mode="recall"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_legacy", "Alte Reisepass-Nr.: ", "3000123454", "", mode="balanced"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_de_legacy", "Der alte Reisepass ", "1220001297", " ist abgelaufen.", carrier="prose", mode="recall"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Passport no. ", "C01X00T41", "", mode="balanced"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Please bring ", "F12345671", " to the front desk.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", '{"traveller": "John Smith", "passport_no": "', "J7T3X9V54", '"}', carrier="json", mode="balanced"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "My passport ", "CF21823027", " expires next year.", carrier="prose", mode="balanced"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Traveller;Passport no.\nJohn Smith;", "FX93K2L58", "", carrier="csv", mode="recall"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_legacy", "Old passport number: ", "3000123454", "", mode="balanced"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_de_legacy", '{"passport_no": "', "1220001297", '"}', carrier="json", mode="recall"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Pass-Nr.: C01X00T42", "check digit fails", mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Bestellnummer C01X00T41 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Pass-Nr.: B01X00T41", "B is no passport series", mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Ablage /archiv/C01X00T41/2026 angelegt.", "part of a slash path", carrier="prose", mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Artikel XC01X00T41 ist vergriffen.", "glued to a letter", carrier="prose", mode="recall"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_context_free", "Kundennummer: K12345676", "a customer number field wins over the passport check digit", also=(("CUSTOMER_ID", "K12345676"),), mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_legacy", "Reisepass-Nr. 3000123455", "old numeric check digit fails", mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_de_legacy", "Bitte 3000123454 übernehmen.", "ten digits without a document term", carrier="prose", mode="recall"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Passport no. C01X00T42", "check digit fails", mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Invoice number F12345671 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Build C01X00T41-2 failed.", "part of a hyphenated number", carrier="prose", mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Passport no. C01X00T479", "MRZ check digit fails", mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de_context_free", "Passport no. D12345675", "D is no passport series", mode="recall"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_de_legacy", "Old passport number: 1220001298", "old numeric check digit fails", mode="balanced"),
    # ── Identity card ───────────────────────────────────────────────────────
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Ausweis-Nr.: ", "L01X00T44", "", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Bitte zeigen Sie die Karte ", "X12345677", " am Eingang vor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "IDD<<", "T220001293", "<<<<<<<<<<<<<<<", tags=("ocr",), mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", '{"name": "Erika Mustermann", "ausweis_nr": "', "M3N7P9R11", '"}', carrier="json", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Name;Ausweis-Nr.\nErika Mustermann;", "TX7M4H2P1", "", carrier="csv", mode="recall"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_legacy", "Personalausweis Nr. ", "1220001297", "", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_legacy", "Alte Ausweisnummer: ", "3000123454", " (bis 2010)", mode="recall"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "ID card no. ", "X12345677", "", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "Please show ", "L01X00T44", " at the entrance.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "ID card number: ", "T220001293", "", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", '{"holder": "John Smith", "id_card_no": "', "R5N8L3W90", '"}', carrier="json", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "Holder;ID card no.\nJohn Smith;", "N7YF1F0W5", "", carrier="csv", mode="recall"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_legacy", "Old ID card number ", "1220001297", "", mode="balanced"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_legacy", '{"id_card_no": "', "3000123454", '"}', carrier="json", mode="recall"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Ausweis-Nr.: L01X00T45", "check digit fails", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Rechnungsnummer L01X00T44 bitte angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Version 2.L01X00T44 installiert.", "joined to a version number", carrier="prose", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Ausweis-Nr.: L01x00T44", "mixed case", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_context_free", "Ausweis-Nr.: T220001294", "MRZ check digit fails", mode="recall"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_legacy", "Personalausweis Nr. 1220001298", "old numeric check digit fails", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_de_legacy", "Bitte 1220001297 übernehmen.", "ten digits without a document term", carrier="prose", mode="recall"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "ID card no. X12345678", "check digit fails", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "Ticket number T220001293 was closed.", "ticket number with a valid check digit", carrier="prose", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "Code XL01X00T44 revoked.", "glued to a letter", carrier="prose", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "Range L01X00T44-5 reserved.", "part of a hyphenated number", carrier="prose", mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "Passport number: Y22400855", "a passport field wins over the identity card check digit", also=(("PASSPORT_NUMBER", "Y22400855"),), mode="balanced"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_context_free", "ID card no. L01X00T4", "eight characters", mode="recall"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_de_legacy", "ID card no. 1220001298", "old numeric check digit fails", mode="balanced"),
]
for _row in F08_DOCUMENT_NUMBER_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# F15 driver's licence numbers (baseline P6): the German card number, the US state formats
# and the Italian patente. The three rules share one field part: a licence field name in DE,
# EN, IT, FR, ES or NL before the value or as its structural key, with prose such as "my
# driver's license number is", "of", "lautet" or "è" in between. The value decides the rule.
# No format carries a check digit: a number without a licence field name stays negative in
# every mode. Hard negatives: other fields, software and boat licences, licence terms without
# a value, dates next to the field name, values no format takes. Appended so existing ids
# stay stable.
F15_DRIVER_LICENSE_CASES = [
    # ── US state formats ────────────────────────────────────────────────────
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "My driver's license number is ", "6940579", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "my driver's license number is ", "2270-66-1551", carrier="prose", mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Florida driver license number: ", "S530-460-72-345-0"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "DL number: ", "D400-7836-0001"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "The contract was signed by Vito Gaito, with a driver's license number of ", "G577-7354-469-9", ", and his residence.", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", '{"driver_license_number": "', "K0472618", '"}', carrier="json"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "name,driver_license,city\nJane Doe,", "L5149233", ",Austin", carrier="csv"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "<driver_license_number>", "MB6118130", "</driver_license_number>", carrier="xml"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Washington driver license ", "WDLABCD456DG"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver’s license no.: ", "123AB4567", mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerscheinnummer: ", "T36493663"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "US-Führerschein-Nr. ", "D400-7836-0001"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Die Führerscheinnummer lautet ", "6915030052", ".", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", '{"fuehrerschein_nr": "', "S530-460-72-345-0", '"}', carrier="json", mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Fahrerlaubnisnummer = ", "492817365", carrier="kv"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Order number: 41827365", "order number, no licence field name"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "The licence number L4718203 belongs to a software seat.", "software licence, no driver's licence field name", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver's license number: 2031-04-30", "expiry date next to the field name"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver's license number: D123", "a letter and three digits, no state format"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driving licence since 2015, no points.", "licence term without a value", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "H12234567", "bare value without a field name (presidio-analyzer US test)", tags=("no_context",)),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "My license number is 6940579.", "licence without a driver's licence term", carrier="prose", mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Bestellnummer 41827365 ist eingegangen.", "order number, no licence field name", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerscheinnummer: 30-04-2031", "date next to the field name"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Lizenznummer L4718203 der Software", "software licence"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerscheinklasse: BE, gültig bis 2031", "licence class, no number"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerschein seit 2015 ohne Punkte.", "licence term without a value", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Bitte 6915030052 übernehmen.", "ten digits without a licence term", carrier="prose", mode="balanced"),
    # ── Italian patente ─────────────────────────────────────────────────────
    p("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "Numero di patente: ", "AB1234567C"),
    p("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "La patente di guida è ", "RM5512345K", ".", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", '{"numero_patente": "', "TO7712345B", '"}', carrier="json"),
    p("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "nome;patente di guida\nRossi;", "U1H34K56LX", carrier="csv"),
    p("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "N. patente ", "PD4401234Z"),
    p("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "Numero della patente: ", "MI2045678T", mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_it", "Italienischer Führerschein: ", "RM5512345K"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_it", "Italian driving licence: ", "U1H34K56LX"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_it", "Her Italian driver's license number is ", "AB1234567C", ".", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "Numero di patente: U1A2345678", "A is no paper-licence character"),
    n("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "Numero di patente: ab1234567c", "lowercase"),
    n("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "Numero di patente: AB-1234567-C", "hyphenated, no patente format"),
    n("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "La patente è scaduta nel 2019.", "licence term without a value", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "Patente nautica n. 4471", "boat licence, no driving licence number"),
    n("DRIVER_LICENSE_NUMBER", "it", "pii_driver_license_number_it", "RM5512345K", "bare value without a field name", tags=("no_context",)),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_it", "Italienischer Führerschein: ab1234567c", "lowercase"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_it", "Italian driving licence: U1A2345678", "A is no paper-licence character"),
    # ── German card number, FR/ES/NL field names ────────────────────────────
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_de", "Führerschein-Nr. ", "M5N6P7Q8R91"),
    p("DRIVER_LICENSE_NUMBER", "fr", "pii_driver_license_number_de", "Numéro de permis de conduire : ", "B072RRE2A57"),
    p("DRIVER_LICENSE_NUMBER", "fr", "pii_driver_license_number_us", "Licence de conducteur : ", "D84-5122-431-46"),
    p("DRIVER_LICENSE_NUMBER", "es", "pii_driver_license_number_us", "Licencia de conducir: ", "B6728301"),
    p("DRIVER_LICENSE_NUMBER", "nl", "pii_driver_license_number_us", "Rijbewijsnummer: ", "S38387690"),
    n("DRIVER_LICENSE_NUMBER", "fr", "pii_driver_license_number_us", "Le permis de conduire est valable jusqu'en 2031.", "licence term without a value", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "es", "pii_driver_license_number_us", "Número de patente: 1234567", "patent number, not a driving licence"),
    n("DRIVER_LICENSE_NUMBER", "nl", "pii_driver_license_number_us", "Het rijbewijs is verlopen in 2019.", "licence term without a value", carrier="prose"),
]
for _row in F15_DRIVER_LICENSE_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B02 VAT IDs, part 2: one label and one check-digit validator per country (BG, CY, CZ, DK,
# EE, EL, FI, HR, HU, IE, LT), same structure as B01. The rules are scored-only like K05:
# strict stays bit-identical, `balanced` and `recall` report a prefixed VAT ID without a field
# name. Hard negatives: failing check digits or components (zero numbers, a Czech legal entity
# starting with 9, an Estonian number outside 10…, a Lithuanian number without the 1 marker), a
# nearer counter-context term, values glued to letters or inside longer numbers and paths,
# wrong lengths, a lower-case prefix. New labels, so existing ids stay stable.
B02_VAT_ID_CASES = [
    # ── BG: Bulgarian VAT ID ──────────────────────────────────────────────
    p("VAT_ID_BG", "de", "pii_vat_id_bg", "Die bulgarische USt-IdNr. lautet ", "BG056505713", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_BG", "de", "pii_vat_id_bg", "Lieferant Balkan Trade EOOD · ", "BG 6923395906", "", mode="balanced"),
    p("VAT_ID_BG", "de", "pii_vat_id_bg", "{\"firma\": \"Balkan Trade EOOD\", \"ust_id\": \"", "BG641095488", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_BG", "de", "pii_vat_id_bg", "Firma;USt-IdNr.\nBalkan Trade EOOD;", "BG 2606455628", "", carrier="csv", mode="balanced"),
    p("VAT_ID_BG", "de", "pii_vat_id_bg", "Bitte ", "BG416144006", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_BG", "de", "pii_vat_id_bg", "ИН по ДДС: ", "BG3605833992", "", mode="balanced"),
    p("VAT_ID_BG", "en", "pii_vat_id_bg", "Our Bulgarian VAT number is ", "BG6635619854", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_BG", "en", "pii_vat_id_bg", "vat_id=", "BG799423937", "", carrier="kv", mode="balanced"),
    p("VAT_ID_BG", "en", "pii_vat_id_bg", "<supplier><vat>", "BG 7303905672", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_BG", "en", "pii_vat_id_bg", "Please store ", "BG2278125133", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_BG", "en", "pii_vat_id_bg", "| Supplier | Tax ID |\n|---|---|\n| Balkan Trade EOOD | ", "BG 6543905605", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_BG", "de", "pii_vat_id_bg", "Die bulgarische USt-IdNr. lautet BG056505714.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "de", "pii_vat_id_bg", "Rechnungsnummer BG056505713 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "de", "pii_vat_id_bg", "USt-IdNr. BG000000000", "zero number", mode="balanced"),
    n("VAT_ID_BG", "de", "pii_vat_id_bg", "Artikel XBG056505713 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "de", "pii_vat_id_bg", "Messreihe BG056505713-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_BG", "de", "pii_vat_id_bg", "USt-IdNr. BG0565057", "too short", mode="balanced"),
    n("VAT_ID_BG", "en", "pii_vat_id_bg", "Our Bulgarian VAT number is BG6635619855.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "en", "pii_vat_id_bg", "Order number BG6635619854 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "en", "pii_vat_id_bg", "Build BG66356198541 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "en", "pii_vat_id_bg", "Path /exports/BG6635619854/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_BG", "en", "pii_vat_id_bg", "The code bg6635619854 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── CY: Cypriot VAT ID ──────────────────────────────────────────────
    p("VAT_ID_CY", "de", "pii_vat_id_cy", "Die zyprische USt-IdNr. lautet ", "CY40064615K", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_CY", "de", "pii_vat_id_cy", "Lieferant Limassol Shipping Ltd · ", "CY 59921485V", "", mode="balanced"),
    p("VAT_ID_CY", "de", "pii_vat_id_cy", "{\"firma\": \"Limassol Shipping Ltd\", \"ust_id\": \"", "CY57847498P", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_CY", "de", "pii_vat_id_cy", "Firma;USt-IdNr.\nLimassol Shipping Ltd;", "CY-90030366Y", "", carrier="csv", mode="balanced"),
    p("VAT_ID_CY", "de", "pii_vat_id_cy", "Bitte ", "CY08139780H", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_CY", "de", "pii_vat_id_cy", "Αριθμός ΦΠΑ: ", "CY01198700M", "", mode="balanced"),
    p("VAT_ID_CY", "en", "pii_vat_id_cy", "Our Cypriot VAT number is ", "CY35498460Q", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_CY", "en", "pii_vat_id_cy", "vat_id=", "CY35446343D", "", carrier="kv", mode="balanced"),
    p("VAT_ID_CY", "en", "pii_vat_id_cy", "<supplier><vat>", "CY 19224803L", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_CY", "en", "pii_vat_id_cy", "Please store ", "CY57105382F", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_CY", "en", "pii_vat_id_cy", "| Supplier | Tax ID |\n|---|---|\n| Limassol Shipping Ltd | ", "CY-32898835Y", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_CY", "de", "pii_vat_id_cy", "Die zyprische USt-IdNr. lautet CY40064615L.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "de", "pii_vat_id_cy", "Rechnungsnummer CY40064615K bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "de", "pii_vat_id_cy", "USt-IdNr. CY12945807E", "check letter fits, 12 is never issued", mode="balanced"),
    n("VAT_ID_CY", "de", "pii_vat_id_cy", "Artikel XCY40064615K ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "de", "pii_vat_id_cy", "Messreihe CY40064615K-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_CY", "de", "pii_vat_id_cy", "USt-IdNr. CY4006461", "too short", mode="balanced"),
    n("VAT_ID_CY", "en", "pii_vat_id_cy", "Our Cypriot VAT number is CY35498460R.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "en", "pii_vat_id_cy", "Order number CY35498460Q has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "en", "pii_vat_id_cy", "Build CY35498460Q1 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "en", "pii_vat_id_cy", "Path /exports/CY35498460Q/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_CY", "en", "pii_vat_id_cy", "The code cy35498460q is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── CZ: Czech VAT ID ──────────────────────────────────────────────
    p("VAT_ID_CZ", "de", "pii_vat_id_cz", "Die tschechische USt-IdNr. lautet ", "CZ638354388", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_CZ", "de", "pii_vat_id_cz", "Lieferant Novák Stavby s.r.o. · ", "CZ 9862291362", "", mode="balanced"),
    p("VAT_ID_CZ", "de", "pii_vat_id_cz", "{\"firma\": \"Novák Stavby s.r.o.\", \"ust_id\": \"", "CZ49997653", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_CZ", "de", "pii_vat_id_cz", "Firma;USt-IdNr.\nNovák Stavby s.r.o.;", "CZ 64452506", "", carrier="csv", mode="balanced"),
    p("VAT_ID_CZ", "de", "pii_vat_id_cz", "Bitte ", "CZ9352224068", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_CZ", "de", "pii_vat_id_cz", "DIČ: ", "CZ698537475", "", mode="balanced"),
    p("VAT_ID_CZ", "en", "pii_vat_id_cz", "Our Czech VAT number is ", "CZ609251970", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_CZ", "en", "pii_vat_id_cz", "vat_id=", "CZ7552285147", "", carrier="kv", mode="balanced"),
    p("VAT_ID_CZ", "en", "pii_vat_id_cz", "<supplier><vat>", "CZ 66590345", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_CZ", "en", "pii_vat_id_cz", "Please store ", "CZ63818311", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_CZ", "en", "pii_vat_id_cz", "| Supplier | Tax ID |\n|---|---|\n| Novák Stavby s.r.o. | ", "CZ 612370792", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_CZ", "de", "pii_vat_id_cz", "Die tschechische USt-IdNr. lautet CZ638354389.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "de", "pii_vat_id_cz", "Rechnungsnummer CZ638354388 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "de", "pii_vat_id_cz", "USt-IdNr. CZ92193081", "check digit fits, 9 never opens a legal entity", mode="balanced"),
    n("VAT_ID_CZ", "de", "pii_vat_id_cz", "Artikel XCZ638354388 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "de", "pii_vat_id_cz", "Messreihe CZ638354388-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_CZ", "de", "pii_vat_id_cz", "USt-IdNr. CZ6383543", "too short", mode="balanced"),
    n("VAT_ID_CZ", "en", "pii_vat_id_cz", "Our Czech VAT number is CZ609251971.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "en", "pii_vat_id_cz", "Order number CZ609251970 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "en", "pii_vat_id_cz", "Build CZ60925197012 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "en", "pii_vat_id_cz", "Path /exports/CZ609251970/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_CZ", "en", "pii_vat_id_cz", "The code cz609251970 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── DK: Danish VAT ID ──────────────────────────────────────────────
    p("VAT_ID_DK", "de", "pii_vat_id_dk", "Die dänische USt-IdNr. lautet ", "DK34311986", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_DK", "de", "pii_vat_id_dk", "Lieferant Nordhavn ApS · ", "DK 77 05 87 61", "", mode="balanced"),
    p("VAT_ID_DK", "de", "pii_vat_id_dk", "{\"firma\": \"Nordhavn ApS\", \"ust_id\": \"", "DK21429651", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_DK", "de", "pii_vat_id_dk", "Firma;USt-IdNr.\nNordhavn ApS;", "DK 70819074", "", carrier="csv", mode="balanced"),
    p("VAT_ID_DK", "de", "pii_vat_id_dk", "Bitte ", "DK36123222", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_DK", "de", "pii_vat_id_dk", "CVR-nr.: ", "DK65881616", "", mode="balanced"),
    p("VAT_ID_DK", "en", "pii_vat_id_dk", "Our Danish VAT number is ", "DK60032041", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_DK", "en", "pii_vat_id_dk", "vat_id=", "DK67808320", "", carrier="kv", mode="balanced"),
    p("VAT_ID_DK", "en", "pii_vat_id_dk", "<supplier><vat>", "DK 89 06 39 73", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_DK", "en", "pii_vat_id_dk", "Please store ", "DK49283881", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_DK", "en", "pii_vat_id_dk", "| Supplier | Tax ID |\n|---|---|\n| Nordhavn ApS | ", "DK 74232043", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_DK", "de", "pii_vat_id_dk", "Die dänische USt-IdNr. lautet DK34311987.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "de", "pii_vat_id_dk", "Rechnungsnummer DK34311986 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "de", "pii_vat_id_dk", "USt-IdNr. DK02061597", "sum fits, a leading zero is never issued", mode="balanced"),
    n("VAT_ID_DK", "de", "pii_vat_id_dk", "Artikel XDK34311986 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "de", "pii_vat_id_dk", "Messreihe DK34311986-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_DK", "de", "pii_vat_id_dk", "USt-IdNr. DK343119", "too short", mode="balanced"),
    n("VAT_ID_DK", "en", "pii_vat_id_dk", "Our Danish VAT number is DK60032042.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "en", "pii_vat_id_dk", "Order number DK60032041 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "en", "pii_vat_id_dk", "Build DK600320411 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "en", "pii_vat_id_dk", "Path /exports/DK60032041/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_DK", "en", "pii_vat_id_dk", "The code dk60032041 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── EE: Estonian VAT ID ──────────────────────────────────────────────
    p("VAT_ID_EE", "de", "pii_vat_id_ee", "Die estnische USt-IdNr. lautet ", "EE102730867", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_EE", "de", "pii_vat_id_ee", "Lieferant Tallinna Tarkvara OÜ · ", "EE 105247564", "", mode="balanced"),
    p("VAT_ID_EE", "de", "pii_vat_id_ee", "{\"firma\": \"Tallinna Tarkvara OÜ\", \"ust_id\": \"", "EE106885462", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_EE", "de", "pii_vat_id_ee", "Firma;USt-IdNr.\nTallinna Tarkvara OÜ;", "EE 100904297", "", carrier="csv", mode="balanced"),
    p("VAT_ID_EE", "de", "pii_vat_id_ee", "Bitte ", "EE101801797", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_EE", "de", "pii_vat_id_ee", "KMKR nr: ", "EE105155818", "", mode="balanced"),
    p("VAT_ID_EE", "en", "pii_vat_id_ee", "Our Estonian VAT number is ", "EE104265411", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_EE", "en", "pii_vat_id_ee", "vat_id=", "EE108492057", "", carrier="kv", mode="balanced"),
    p("VAT_ID_EE", "en", "pii_vat_id_ee", "<supplier><vat>", "EE 106363829", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_EE", "en", "pii_vat_id_ee", "Please store ", "EE101988830", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_EE", "en", "pii_vat_id_ee", "| Supplier | Tax ID |\n|---|---|\n| Tallinna Tarkvara OÜ | ", "EE 103534240", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_EE", "de", "pii_vat_id_ee", "Die estnische USt-IdNr. lautet EE102730868.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "de", "pii_vat_id_ee", "Rechnungsnummer EE102730867 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "de", "pii_vat_id_ee", "USt-IdNr. EE347140694", "sum fits, does not start with 10", mode="balanced"),
    n("VAT_ID_EE", "de", "pii_vat_id_ee", "Artikel XEE102730867 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "de", "pii_vat_id_ee", "Messreihe EE102730867-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_EE", "de", "pii_vat_id_ee", "USt-IdNr. EE1027308", "too short", mode="balanced"),
    n("VAT_ID_EE", "en", "pii_vat_id_ee", "Our Estonian VAT number is EE104265412.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "en", "pii_vat_id_ee", "Order number EE104265411 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "en", "pii_vat_id_ee", "Build EE1042654111 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "en", "pii_vat_id_ee", "Path /exports/EE104265411/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_EE", "en", "pii_vat_id_ee", "The code ee104265411 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── EL: Greek VAT ID ──────────────────────────────────────────────
    p("VAT_ID_EL", "de", "pii_vat_id_el", "Die griechische USt-IdNr. lautet ", "EL005830057", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_EL", "de", "pii_vat_id_el", "Lieferant Athina Foods AE · ", "EL 030577278", "", mode="balanced"),
    p("VAT_ID_EL", "de", "pii_vat_id_el", "{\"firma\": \"Athina Foods AE\", \"ust_id\": \"", "EL611955179", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_EL", "de", "pii_vat_id_el", "Firma;USt-IdNr.\nAthina Foods AE;", "GR009654939", "", carrier="csv", mode="balanced"),
    p("VAT_ID_EL", "de", "pii_vat_id_el", "Bitte ", "EL171054820", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_EL", "de", "pii_vat_id_el", "ΑΦΜ: ", "EL037306696", "", mode="balanced"),
    p("VAT_ID_EL", "en", "pii_vat_id_el", "Our Greek VAT number is ", "EL048978132", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_EL", "en", "pii_vat_id_el", "vat_id=", "EL600482458", "", carrier="kv", mode="balanced"),
    p("VAT_ID_EL", "en", "pii_vat_id_el", "<supplier><vat>", "EL 022681346", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_EL", "en", "pii_vat_id_el", "Please store ", "EL056335833", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_EL", "en", "pii_vat_id_el", "| Supplier | Tax ID |\n|---|---|\n| Athina Foods AE | ", "GR028611693", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_EL", "de", "pii_vat_id_el", "Die griechische USt-IdNr. lautet EL005830058.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "de", "pii_vat_id_el", "Rechnungsnummer EL005830057 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "de", "pii_vat_id_el", "USt-IdNr. EL000000000", "zero number", mode="balanced"),
    n("VAT_ID_EL", "de", "pii_vat_id_el", "Artikel XEL005830057 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "de", "pii_vat_id_el", "Messreihe EL005830057-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_EL", "de", "pii_vat_id_el", "USt-IdNr. EL0058300", "too short", mode="balanced"),
    n("VAT_ID_EL", "en", "pii_vat_id_el", "Our Greek VAT number is EL048978133.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "en", "pii_vat_id_el", "Order number EL048978132 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "en", "pii_vat_id_el", "Build EL0489781321 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "en", "pii_vat_id_el", "Path /exports/EL048978132/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_EL", "en", "pii_vat_id_el", "The code el048978132 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── FI: Finnish VAT ID ──────────────────────────────────────────────
    p("VAT_ID_FI", "de", "pii_vat_id_fi", "Die finnische USt-IdNr. lautet ", "FI08067816", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_FI", "de", "pii_vat_id_fi", "Lieferant Saimaa Oy · ", "FI 70213933", "", mode="balanced"),
    p("VAT_ID_FI", "de", "pii_vat_id_fi", "{\"firma\": \"Saimaa Oy\", \"ust_id\": \"", "FI62326321", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_FI", "de", "pii_vat_id_fi", "Firma;USt-IdNr.\nSaimaa Oy;", "FI 98745261", "", carrier="csv", mode="balanced"),
    p("VAT_ID_FI", "de", "pii_vat_id_fi", "Bitte ", "FI80022209", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_FI", "de", "pii_vat_id_fi", "ALV-numero: ", "FI58990182", "", mode="balanced"),
    p("VAT_ID_FI", "en", "pii_vat_id_fi", "Our Finnish VAT number is ", "FI85311675", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_FI", "en", "pii_vat_id_fi", "vat_id=", "FI84449656", "", carrier="kv", mode="balanced"),
    p("VAT_ID_FI", "en", "pii_vat_id_fi", "<supplier><vat>", "FI 37318485", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_FI", "en", "pii_vat_id_fi", "Please store ", "FI19618249", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_FI", "en", "pii_vat_id_fi", "| Supplier | Tax ID |\n|---|---|\n| Saimaa Oy | ", "FI 14494507", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_FI", "de", "pii_vat_id_fi", "Die finnische USt-IdNr. lautet FI08067817.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "de", "pii_vat_id_fi", "Rechnungsnummer FI08067816 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "de", "pii_vat_id_fi", "USt-IdNr. FI00000000", "zero number", mode="balanced"),
    n("VAT_ID_FI", "de", "pii_vat_id_fi", "Artikel XFI08067816 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "de", "pii_vat_id_fi", "Messreihe FI08067816-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_FI", "de", "pii_vat_id_fi", "USt-IdNr. FI080678", "too short", mode="balanced"),
    n("VAT_ID_FI", "en", "pii_vat_id_fi", "Our Finnish VAT number is FI85311676.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "en", "pii_vat_id_fi", "Order number FI85311675 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "en", "pii_vat_id_fi", "Build FI853116751 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "en", "pii_vat_id_fi", "Path /exports/FI85311675/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_FI", "en", "pii_vat_id_fi", "The code fi85311675 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── HR: Croatian VAT ID ──────────────────────────────────────────────
    p("VAT_ID_HR", "de", "pii_vat_id_hr", "Die kroatische USt-IdNr. lautet ", "HR15691480283", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_HR", "de", "pii_vat_id_hr", "Lieferant Jadran d.o.o. · ", "HR 11531767695", "", mode="balanced"),
    p("VAT_ID_HR", "de", "pii_vat_id_hr", "{\"firma\": \"Jadran d.o.o.\", \"ust_id\": \"", "HR81064050131", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_HR", "de", "pii_vat_id_hr", "Firma;USt-IdNr.\nJadran d.o.o.;", "HR 88354862435", "", carrier="csv", mode="balanced"),
    p("VAT_ID_HR", "de", "pii_vat_id_hr", "Bitte ", "HR83200365009", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_HR", "de", "pii_vat_id_hr", "OIB: ", "HR75347776827", "", mode="balanced"),
    p("VAT_ID_HR", "en", "pii_vat_id_hr", "Our Croatian VAT number is ", "HR67004847378", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_HR", "en", "pii_vat_id_hr", "vat_id=", "HR65161618813", "", carrier="kv", mode="balanced"),
    p("VAT_ID_HR", "en", "pii_vat_id_hr", "<supplier><vat>", "HR 93971914878", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_HR", "en", "pii_vat_id_hr", "Please store ", "HR55838857994", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_HR", "en", "pii_vat_id_hr", "| Supplier | Tax ID |\n|---|---|\n| Jadran d.o.o. | ", "HR 96289831793", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_HR", "de", "pii_vat_id_hr", "Die kroatische USt-IdNr. lautet HR15691480284.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "de", "pii_vat_id_hr", "Rechnungsnummer HR15691480283 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "de", "pii_vat_id_hr", "USt-IdNr. HR00000000000", "zero number", mode="balanced"),
    n("VAT_ID_HR", "de", "pii_vat_id_hr", "Artikel XHR15691480283 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "de", "pii_vat_id_hr", "Messreihe HR15691480283-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_HR", "de", "pii_vat_id_hr", "USt-IdNr. HR156914802", "too short", mode="balanced"),
    n("VAT_ID_HR", "en", "pii_vat_id_hr", "Our Croatian VAT number is HR67004847379.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "en", "pii_vat_id_hr", "Order number HR67004847378 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "en", "pii_vat_id_hr", "Build HR670048473781 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "en", "pii_vat_id_hr", "Path /exports/HR67004847378/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_HR", "en", "pii_vat_id_hr", "The code hr67004847378 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── HU: Hungarian VAT ID ──────────────────────────────────────────────
    p("VAT_ID_HU", "de", "pii_vat_id_hu", "Die ungarische USt-IdNr. lautet ", "HU50118432", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_HU", "de", "pii_vat_id_hu", "Lieferant Duna Kft. · ", "HU 82859815", "", mode="balanced"),
    p("VAT_ID_HU", "de", "pii_vat_id_hu", "{\"firma\": \"Duna Kft.\", \"ust_id\": \"", "HU27138397", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_HU", "de", "pii_vat_id_hu", "Firma;USt-IdNr.\nDuna Kft.;", "HU-92599543", "", carrier="csv", mode="balanced"),
    p("VAT_ID_HU", "de", "pii_vat_id_hu", "Bitte ", "HU08225128", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_HU", "de", "pii_vat_id_hu", "Közösségi adószám: ", "HU72864612", "", mode="balanced"),
    p("VAT_ID_HU", "en", "pii_vat_id_hu", "Our Hungarian VAT number is ", "HU90700022", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_HU", "en", "pii_vat_id_hu", "vat_id=", "HU79424633", "", carrier="kv", mode="balanced"),
    p("VAT_ID_HU", "en", "pii_vat_id_hu", "<supplier><vat>", "HU 75578761", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_HU", "en", "pii_vat_id_hu", "Please store ", "HU95129321", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_HU", "en", "pii_vat_id_hu", "| Supplier | Tax ID |\n|---|---|\n| Duna Kft. | ", "HU-57999212", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_HU", "de", "pii_vat_id_hu", "Die ungarische USt-IdNr. lautet HU50118433.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "de", "pii_vat_id_hu", "Rechnungsnummer HU50118432 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "de", "pii_vat_id_hu", "USt-IdNr. HU00000000", "zero number", mode="balanced"),
    n("VAT_ID_HU", "de", "pii_vat_id_hu", "Artikel XHU50118432 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "de", "pii_vat_id_hu", "Messreihe HU50118432-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_HU", "de", "pii_vat_id_hu", "USt-IdNr. HU501184", "too short", mode="balanced"),
    n("VAT_ID_HU", "en", "pii_vat_id_hu", "Our Hungarian VAT number is HU90700023.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "en", "pii_vat_id_hu", "Order number HU90700022 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "en", "pii_vat_id_hu", "Build HU907000221 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "en", "pii_vat_id_hu", "Path /exports/HU90700022/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_HU", "en", "pii_vat_id_hu", "The code hu90700022 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── IE: Irish VAT ID ──────────────────────────────────────────────
    p("VAT_ID_IE", "de", "pii_vat_id_ie", "Die irische USt-IdNr. lautet ", "IE2026251N", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_IE", "de", "pii_vat_id_ie", "Lieferant Liffey Software Ltd · ", "IE 3134815BH", "", mode="balanced"),
    p("VAT_ID_IE", "de", "pii_vat_id_ie", "{\"firma\": \"Liffey Software Ltd\", \"ust_id\": \"", "IE7648921V", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_IE", "de", "pii_vat_id_ie", "Firma;USt-IdNr.\nLiffey Software Ltd;", "IE 4338422V", "", carrier="csv", mode="balanced"),
    p("VAT_ID_IE", "de", "pii_vat_id_ie", "Bitte ", "IE8D79739I", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_IE", "de", "pii_vat_id_ie", "VAT No.: ", "IE0190308T", "", mode="balanced"),
    p("VAT_ID_IE", "en", "pii_vat_id_ie", "Our Irish VAT number is ", "IE1320477W", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_IE", "en", "pii_vat_id_ie", "vat_id=", "IE0017951B", "", carrier="kv", mode="balanced"),
    p("VAT_ID_IE", "en", "pii_vat_id_ie", "<supplier><vat>", "IE 7849843DH", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_IE", "en", "pii_vat_id_ie", "Please store ", "IE1851343WA", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_IE", "en", "pii_vat_id_ie", "| Supplier | Tax ID |\n|---|---|\n| Liffey Software Ltd | ", "IE 7693498S", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_IE", "de", "pii_vat_id_ie", "Die irische USt-IdNr. lautet IE2026251O.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "de", "pii_vat_id_ie", "Rechnungsnummer IE2026251N bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "de", "pii_vat_id_ie", "USt-IdNr. IE0000000W", "zero number", mode="balanced"),
    n("VAT_ID_IE", "de", "pii_vat_id_ie", "Artikel XIE2026251N ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "de", "pii_vat_id_ie", "Messreihe IE2026251N-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_IE", "de", "pii_vat_id_ie", "USt-IdNr. IE20262", "too short", mode="balanced"),
    n("VAT_ID_IE", "en", "pii_vat_id_ie", "Our Irish VAT number is IE1320477A.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "en", "pii_vat_id_ie", "Order number IE1320477W has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "en", "pii_vat_id_ie", "Build IE1320477W1 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "en", "pii_vat_id_ie", "Path /exports/IE1320477W/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_IE", "en", "pii_vat_id_ie", "The code ie1320477w is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
    # ── LT: Lithuanian VAT ID ──────────────────────────────────────────────
    p("VAT_ID_LT", "de", "pii_vat_id_lt", "Die litauische USt-IdNr. lautet ", "LT269042217", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_LT", "de", "pii_vat_id_lt", "Lieferant Vilniaus Prekyba UAB · ", "LT 960522484319", "", mode="balanced"),
    p("VAT_ID_LT", "de", "pii_vat_id_lt", "{\"firma\": \"Vilniaus Prekyba UAB\", \"ust_id\": \"", "LT071425110", "\"}", carrier="json", mode="balanced"),
    p("VAT_ID_LT", "de", "pii_vat_id_lt", "Firma;USt-IdNr.\nVilniaus Prekyba UAB;", "LT 677730224210", "", carrier="csv", mode="balanced"),
    p("VAT_ID_LT", "de", "pii_vat_id_lt", "Bitte ", "LT677984710", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_LT", "de", "pii_vat_id_lt", "PVM kodas: ", "LT644825017", "", mode="balanced"),
    p("VAT_ID_LT", "en", "pii_vat_id_lt", "Our Lithuanian VAT number is ", "LT492936539710", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_LT", "en", "pii_vat_id_lt", "vat_id=", "LT764433811", "", carrier="kv", mode="balanced"),
    p("VAT_ID_LT", "en", "pii_vat_id_lt", "<supplier><vat>", "LT 158165222117", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_LT", "en", "pii_vat_id_lt", "Please store ", "LT250863417", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("VAT_ID_LT", "en", "pii_vat_id_lt", "| Supplier | Tax ID |\n|---|---|\n| Vilniaus Prekyba UAB | ", "LT 222217389317", " |", carrier="table", tags=("no_context",), mode="recall"),
    n("VAT_ID_LT", "de", "pii_vat_id_lt", "Die litauische USt-IdNr. lautet LT269042218.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "de", "pii_vat_id_lt", "Rechnungsnummer LT269042217 bitte bei Zahlung angeben.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "de", "pii_vat_id_lt", "USt-IdNr. LT018800102", "check digit fits, eighth digit is not 1", mode="balanced"),
    n("VAT_ID_LT", "de", "pii_vat_id_lt", "Artikel XLT269042217 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "de", "pii_vat_id_lt", "Messreihe LT269042217-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_LT", "de", "pii_vat_id_lt", "USt-IdNr. LT2690422", "too short", mode="balanced"),
    n("VAT_ID_LT", "en", "pii_vat_id_lt", "Our Lithuanian VAT number is LT492936539711.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "en", "pii_vat_id_lt", "Order number LT492936539710 has shipped.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "en", "pii_vat_id_lt", "Build LT4929365397101 failed.", "too long", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "en", "pii_vat_id_lt", "Path /exports/LT492936539710/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_LT", "en", "pii_vat_id_lt", "The code lt492936539710 is lower case.", "lower-case prefix", carrier="prose", mode="recall"),
]
for _row in B02_VAT_ID_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B16 VAT IDs, part 3: LU, LV, MT, PL, PT, RO, SE, SI, SK, NO and GB, one label and one
# check-digit validator per country; Northern Ireland (`XI`) shares the GB label and validator.
# Like B01 the rules are scored-only (K05): strict stays bit-identical, `balanced` and `recall`
# report a prefixed VAT ID without a field name. Hard negatives: failing check digits, components
# that are never issued (leading zeros, remainder 10 or 11, a Latvian personal code, the GB 9755
# scheme below 100 0000 00), wrong lengths, a nearer counter-context term, values glued to letters
# or inside longer numbers and paths. Appended so existing ids stay stable.
B16_VAT_ID_CASES = [
    # ── LU ────────────────────────────────────────────────────────────────────
    p("VAT_ID_LU", "de", "pii_vat_id_lu", "Die luxemburgische USt-IdNr. lautet ", "LU45508124", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_LU", "de", "pii_vat_id_lu", "Lieferant Muller Sàrl · ", "LU77134268", "", mode="balanced"),
    p("VAT_ID_LU", "de", "pii_vat_id_lu", '{"firma": "Muller Sàrl", "ust_id": "', "LU 70736885", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_LU", "de", "pii_vat_id_lu", "Firma;USt-IdNr.\nMuller Sàrl;", "LU41241780", "", carrier="csv", mode="balanced"),
    p("VAT_ID_LU", "de", "pii_vat_id_lu", "Bitte ", "LU 87509850", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_LU", "en", "pii_vat_id_lu", "Our Luxembourg VAT number is ", "LU76939478", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_LU", "en", "pii_vat_id_lu", "Supplier Muller Sàrl · ", "LU55691946", "", mode="balanced"),
    p("VAT_ID_LU", "en", "pii_vat_id_lu", "vat_id=", "LU 99221341", "", carrier="kv", mode="balanced"),
    p("VAT_ID_LU", "en", "pii_vat_id_lu", "<supplier><vat>", "LU14321817", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_LU", "en", "pii_vat_id_lu", "Please store ", "LU 49971468", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_LU", "de", "pii_vat_id_lu", "Die luxemburgische USt-IdNr. lautet LU45508125.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_LU", "de", "pii_vat_id_lu", "Bestellnummer LU45508124 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_LU", "de", "pii_vat_id_lu", "USt-IdNr. LU1502744", "seven digits", mode="balanced"),
    n("VAT_ID_LU", "de", "pii_vat_id_lu", "Artikel XLU45508124 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_LU", "de", "pii_vat_id_lu", "Messreihe LU45508124-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_LU", "en", "pii_vat_id_lu", "Our Luxembourg VAT number is LU76939479.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_LU", "en", "pii_vat_id_lu", "Invoice number LU76939478 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_LU", "en", "pii_vat_id_lu", "VAT number LU150274421", "nine digits", mode="balanced"),
    n("VAT_ID_LU", "en", "pii_vat_id_lu", "Path /exports/LU76939478/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_LU", "en", "pii_vat_id_lu", "Model LU76939478X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── LV ────────────────────────────────────────────────────────────────────
    p("VAT_ID_LV", "de", "pii_vat_id_lv", "Die lettische USt-IdNr. lautet ", "LV86401732204", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_LV", "de", "pii_vat_id_lv", "Lieferant Ozols SIA · ", "LV88426544771", "", mode="balanced"),
    p("VAT_ID_LV", "de", "pii_vat_id_lv", '{"firma": "Ozols SIA", "ust_id": "', "LV 91506880740", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_LV", "de", "pii_vat_id_lv", "Firma;USt-IdNr.\nOzols SIA;", "LV57762858253", "", carrier="csv", mode="balanced"),
    p("VAT_ID_LV", "de", "pii_vat_id_lv", "Bitte ", "LV 43523275022", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_LV", "en", "pii_vat_id_lv", "Our Latvian VAT number is ", "LV90325602793", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_LV", "en", "pii_vat_id_lv", "Supplier Ozols SIA · ", "LV52064068583", "", mode="balanced"),
    p("VAT_ID_LV", "en", "pii_vat_id_lv", "vat_id=", "LV 63034520442", "", carrier="kv", mode="balanced"),
    p("VAT_ID_LV", "en", "pii_vat_id_lv", "<supplier><vat>", "LV65496207713", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_LV", "en", "pii_vat_id_lv", "Please store ", "LV 79938743327", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_LV", "de", "pii_vat_id_lv", "Die lettische USt-IdNr. lautet LV86401732205.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_LV", "de", "pii_vat_id_lv", "Bestellnummer LV86401732204 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_LV", "de", "pii_vat_id_lv", "USt-IdNr. LV16117519997", "personal code of a natural person, no confirmed check digit", mode="balanced"),
    n("VAT_ID_LV", "de", "pii_vat_id_lv", "Artikel XLV86401732204 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_LV", "de", "pii_vat_id_lv", "Messreihe LV86401732204-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_LV", "en", "pii_vat_id_lv", "Our Latvian VAT number is LV90325602794.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_LV", "en", "pii_vat_id_lv", "Invoice number LV90325602793 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_LV", "en", "pii_vat_id_lv", "VAT number LV4000352160", "ten digits", mode="balanced"),
    n("VAT_ID_LV", "en", "pii_vat_id_lv", "Path /exports/LV90325602793/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_LV", "en", "pii_vat_id_lv", "Model LV90325602793X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── MT ────────────────────────────────────────────────────────────────────
    p("VAT_ID_MT", "de", "pii_vat_id_mt", "Die maltesische USt-IdNr. lautet ", "MT64551971", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_MT", "de", "pii_vat_id_mt", "Lieferant Borg Ltd · ", "MT2475-1078", "", mode="balanced"),
    p("VAT_ID_MT", "de", "pii_vat_id_mt", '{"firma": "Borg Ltd", "ust_id": "', "MT 9263 4098", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_MT", "de", "pii_vat_id_mt", "Firma;USt-IdNr.\nBorg Ltd;", "MT8320-3568", "", carrier="csv", mode="balanced"),
    p("VAT_ID_MT", "de", "pii_vat_id_mt", "Bitte ", "MT 9832 8468", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_MT", "en", "pii_vat_id_mt", "Our Maltese VAT number is ", "MT13618865", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_MT", "en", "pii_vat_id_mt", "Supplier Borg Ltd · ", "MT5474-3680", "", mode="balanced"),
    p("VAT_ID_MT", "en", "pii_vat_id_mt", "vat_id=", "MT 2499 8366", "", carrier="kv", mode="balanced"),
    p("VAT_ID_MT", "en", "pii_vat_id_mt", "<supplier><vat>", "MT1185-1232", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_MT", "en", "pii_vat_id_mt", "Please store ", "MT 9547 3533", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_MT", "de", "pii_vat_id_mt", "Die maltesische USt-IdNr. lautet MT64551972.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_MT", "de", "pii_vat_id_mt", "Bestellnummer MT64551971 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_MT", "de", "pii_vat_id_mt", "USt-IdNr. MT09722003", "mod 37 holds, a leading zero is never issued", mode="balanced"),
    n("VAT_ID_MT", "de", "pii_vat_id_mt", "Artikel XMT64551971 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_MT", "de", "pii_vat_id_mt", "Messreihe MT64551971-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_MT", "en", "pii_vat_id_mt", "Our Maltese VAT number is MT13618866.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_MT", "en", "pii_vat_id_mt", "Invoice number MT13618865 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_MT", "en", "pii_vat_id_mt", "VAT number MT1167911", "seven digits", mode="balanced"),
    n("VAT_ID_MT", "en", "pii_vat_id_mt", "Path /exports/MT13618865/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_MT", "en", "pii_vat_id_mt", "Model MT13618865X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── PL ────────────────────────────────────────────────────────────────────
    p("VAT_ID_PL", "de", "pii_vat_id_pl", "Die polnische USt-IdNr. lautet ", "PL1012819574", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl", "Lieferant Kowalski Sp. z o.o. · ", "PL516-986-30-27", "", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl", '{"firma": "Kowalski Sp. z o.o.", "ust_id": "', "PL 364-95-98-742", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl", "Firma;USt-IdNr.\nKowalski Sp. z o.o.;", "PL584-515-55-45", "", carrier="csv", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl", "Bitte ", "PL 122-50-44-074", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl", "Our Polish VAT number is ", "PL2451091537", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl", "Supplier Kowalski Sp. z o.o. · ", "PL227-892-71-73", "", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl", "vat_id=", "PL 999-49-77-898", "", carrier="kv", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl", "<supplier><vat>", "PL678-103-73-59", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl", "Please store ", "PL 694-69-52-189", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl", "Die polnische USt-IdNr. lautet PL1012819575.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl", "Bestellnummer PL1012819574 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl", "USt-IdNr. PL5709301372", "remainder 10 is never issued", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl", "Artikel XPL1012819574 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl", "Messreihe PL1012819574-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl", "Our Polish VAT number is PL2451091538.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl", "Invoice number PL2451091537 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl", "VAT number PL856734621", "nine digits", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl", "Path /exports/PL2451091537/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl", "Model PL2451091537X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── PT ────────────────────────────────────────────────────────────────────
    p("VAT_ID_PT", "de", "pii_vat_id_pt", "Die portugiesische USt-IdNr. lautet ", "PT269210288", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_PT", "de", "pii_vat_id_pt", "Lieferant Silva Lda · ", "PT496 787 870", "", mode="balanced"),
    p("VAT_ID_PT", "de", "pii_vat_id_pt", '{"firma": "Silva Lda", "ust_id": "', "PT 557 517 435", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_PT", "de", "pii_vat_id_pt", "Firma;USt-IdNr.\nSilva Lda;", "PT466 361 548", "", carrier="csv", mode="balanced"),
    p("VAT_ID_PT", "de", "pii_vat_id_pt", "Bitte ", "PT 353 354 538", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_PT", "en", "pii_vat_id_pt", "Our Portuguese VAT number is ", "PT276842073", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_PT", "en", "pii_vat_id_pt", "Supplier Silva Lda · ", "PT372 527 639", "", mode="balanced"),
    p("VAT_ID_PT", "en", "pii_vat_id_pt", "vat_id=", "PT 102 026 718", "", carrier="kv", mode="balanced"),
    p("VAT_ID_PT", "en", "pii_vat_id_pt", "<supplier><vat>", "PT350 723 877", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_PT", "en", "pii_vat_id_pt", "Please store ", "PT 938 722 980", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_PT", "de", "pii_vat_id_pt", "Die portugiesische USt-IdNr. lautet PT269210289.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_PT", "de", "pii_vat_id_pt", "Bestellnummer PT269210288 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_PT", "de", "pii_vat_id_pt", "USt-IdNr. PT006132677", "check digit holds, a leading zero is never issued", mode="balanced"),
    n("VAT_ID_PT", "de", "pii_vat_id_pt", "Artikel XPT269210288 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_PT", "de", "pii_vat_id_pt", "Messreihe PT269210288-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_PT", "en", "pii_vat_id_pt", "Our Portuguese VAT number is PT276842074.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_PT", "en", "pii_vat_id_pt", "Invoice number PT276842073 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_PT", "en", "pii_vat_id_pt", "VAT number PT50196484", "eight digits", mode="balanced"),
    n("VAT_ID_PT", "en", "pii_vat_id_pt", "Path /exports/PT276842073/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_PT", "en", "pii_vat_id_pt", "Model PT276842073X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── RO ────────────────────────────────────────────────────────────────────
    p("VAT_ID_RO", "de", "pii_vat_id_ro", "Die rumänische USt-IdNr. lautet ", "RO54123835", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_RO", "de", "pii_vat_id_ro", "Lieferant Popescu SRL · ", "RO71542558", "", mode="balanced"),
    p("VAT_ID_RO", "de", "pii_vat_id_ro", '{"firma": "Popescu SRL", "ust_id": "', "RO 93980664", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_RO", "de", "pii_vat_id_ro", "Firma;USt-IdNr.\nPopescu SRL;", "RO35512704", "", carrier="csv", mode="balanced"),
    p("VAT_ID_RO", "de", "pii_vat_id_ro", "Bitte ", "RO 99732838", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_RO", "en", "pii_vat_id_ro", "Our Romanian VAT number is ", "RO60020907", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_RO", "en", "pii_vat_id_ro", "Supplier Popescu SRL · ", "RO91995847", "", mode="balanced"),
    p("VAT_ID_RO", "en", "pii_vat_id_ro", "vat_id=", "RO 32075516", "", carrier="kv", mode="balanced"),
    p("VAT_ID_RO", "en", "pii_vat_id_ro", "<supplier><vat>", "RO23297548", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_RO", "en", "pii_vat_id_ro", "Please store ", "RO 65615116", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_RO", "de", "pii_vat_id_ro", "Die rumänische USt-IdNr. lautet RO54123836.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_RO", "de", "pii_vat_id_ro", "Bestellnummer RO54123835 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_RO", "de", "pii_vat_id_ro", "USt-IdNr. RO018547290", "a leading zero is never issued", mode="balanced"),
    n("VAT_ID_RO", "de", "pii_vat_id_ro", "Artikel XRO54123835 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_RO", "de", "pii_vat_id_ro", "Messreihe RO54123835-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_RO", "en", "pii_vat_id_ro", "Our Romanian VAT number is RO60020908.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_RO", "en", "pii_vat_id_ro", "Invoice number RO60020907 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_RO", "en", "pii_vat_id_ro", "VAT number RO85376", "five digits, too short without a field name", mode="balanced"),
    n("VAT_ID_RO", "en", "pii_vat_id_ro", "Path /exports/RO60020907/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_RO", "en", "pii_vat_id_ro", "Model RO60020907X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── SE ────────────────────────────────────────────────────────────────────
    p("VAT_ID_SE", "de", "pii_vat_id_se", "Die schwedische USt-IdNr. lautet ", "SE625392027301", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_SE", "de", "pii_vat_id_se", "Lieferant Lindqvist AB · ", "SE304216-080801", "", mode="balanced"),
    p("VAT_ID_SE", "de", "pii_vat_id_se", '{"firma": "Lindqvist AB", "ust_id": "', "SE 677090-234101", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_SE", "de", "pii_vat_id_se", "Firma;USt-IdNr.\nLindqvist AB;", "SE522395-011301", "", carrier="csv", mode="balanced"),
    p("VAT_ID_SE", "de", "pii_vat_id_se", "Bitte ", "SE 125357-126701", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_SE", "en", "pii_vat_id_se", "Our Swedish VAT number is ", "SE250283173401", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_SE", "en", "pii_vat_id_se", "Supplier Lindqvist AB · ", "SE550132-311601", "", mode="balanced"),
    p("VAT_ID_SE", "en", "pii_vat_id_se", "vat_id=", "SE 657429-984501", "", carrier="kv", mode="balanced"),
    p("VAT_ID_SE", "en", "pii_vat_id_se", "<supplier><vat>", "SE260956-896501", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_SE", "en", "pii_vat_id_se", "Please store ", "SE 104779-825901", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_SE", "de", "pii_vat_id_se", "Die schwedische USt-IdNr. lautet SE625392027401.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_SE", "de", "pii_vat_id_se", "Bestellnummer SE625392027301 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_SE", "de", "pii_vat_id_se", "USt-IdNr. SE123456789702", "the suffix is not 01", mode="balanced"),
    n("VAT_ID_SE", "de", "pii_vat_id_se", "Artikel XSE625392027301 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_SE", "de", "pii_vat_id_se", "Messreihe SE625392027301-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_SE", "en", "pii_vat_id_se", "Our Swedish VAT number is SE250283173501.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_SE", "en", "pii_vat_id_se", "Invoice number SE250283173401 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_SE", "en", "pii_vat_id_se", "VAT number SE55667788990", "eleven digits", mode="balanced"),
    n("VAT_ID_SE", "en", "pii_vat_id_se", "Path /exports/SE250283173401/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_SE", "en", "pii_vat_id_se", "Model SE250283173401X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── SI ────────────────────────────────────────────────────────────────────
    p("VAT_ID_SI", "de", "pii_vat_id_si", "Die slowenische USt-IdNr. lautet ", "SI29390966", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_SI", "de", "pii_vat_id_si", "Lieferant Novak d.o.o. · ", "SI8553 5567", "", mode="balanced"),
    p("VAT_ID_SI", "de", "pii_vat_id_si", '{"firma": "Novak d.o.o.", "ust_id": "', "SI 8208 2120", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_SI", "de", "pii_vat_id_si", "Firma;USt-IdNr.\nNovak d.o.o.;", "SI7591 9958", "", carrier="csv", mode="balanced"),
    p("VAT_ID_SI", "de", "pii_vat_id_si", "Bitte ", "SI 1500 3825", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_SI", "en", "pii_vat_id_si", "Our Slovenian VAT number is ", "SI94145016", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_SI", "en", "pii_vat_id_si", "Supplier Novak d.o.o. · ", "SI5222 3329", "", mode="balanced"),
    p("VAT_ID_SI", "en", "pii_vat_id_si", "vat_id=", "SI 2422 4855", "", carrier="kv", mode="balanced"),
    p("VAT_ID_SI", "en", "pii_vat_id_si", "<supplier><vat>", "SI4957 6682", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_SI", "en", "pii_vat_id_si", "Please store ", "SI 8213 1457", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_SI", "de", "pii_vat_id_si", "Die slowenische USt-IdNr. lautet SI29390967.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_SI", "de", "pii_vat_id_si", "Bestellnummer SI29390966 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_SI", "de", "pii_vat_id_si", "USt-IdNr. SI37315871", "check digit 11 is never issued", mode="balanced"),
    n("VAT_ID_SI", "de", "pii_vat_id_si", "Artikel XSI29390966 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_SI", "de", "pii_vat_id_si", "Messreihe SI29390966-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_SI", "en", "pii_vat_id_si", "Our Slovenian VAT number is SI94145017.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_SI", "en", "pii_vat_id_si", "Invoice number SI94145016 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_SI", "en", "pii_vat_id_si", "VAT number SI07978707", "check digit holds, a leading zero is never issued", mode="balanced"),
    n("VAT_ID_SI", "en", "pii_vat_id_si", "Path /exports/SI94145016/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_SI", "en", "pii_vat_id_si", "Model SI94145016X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── SK ────────────────────────────────────────────────────────────────────
    p("VAT_ID_SK", "de", "pii_vat_id_sk", "Die slowakische USt-IdNr. lautet ", "SK1370281264", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_SK", "de", "pii_vat_id_sk", "Lieferant Horváth s.r.o. · ", "SK924 886 18 31", "", mode="balanced"),
    p("VAT_ID_SK", "de", "pii_vat_id_sk", '{"firma": "Horváth s.r.o.", "ust_id": "', "SK 662 979 95 50", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_SK", "de", "pii_vat_id_sk", "Firma;USt-IdNr.\nHorváth s.r.o.;", "SK638 968 73 26", "", carrier="csv", mode="balanced"),
    p("VAT_ID_SK", "de", "pii_vat_id_sk", "Bitte ", "SK 348 783 85 08", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_SK", "en", "pii_vat_id_sk", "Our Slovak VAT number is ", "SK3376474442", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_SK", "en", "pii_vat_id_sk", "Supplier Horváth s.r.o. · ", "SK317 266 16 57", "", mode="balanced"),
    p("VAT_ID_SK", "en", "pii_vat_id_sk", "vat_id=", "SK 664 462 58 01", "", carrier="kv", mode="balanced"),
    p("VAT_ID_SK", "en", "pii_vat_id_sk", "<supplier><vat>", "SK378 869 93 65", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_SK", "en", "pii_vat_id_sk", "Please store ", "SK 172 482 50 47", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_SK", "de", "pii_vat_id_sk", "Die slowakische USt-IdNr. lautet SK1370281265.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_SK", "de", "pii_vat_id_sk", "Bestellnummer SK1370281264 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_SK", "de", "pii_vat_id_sk", "USt-IdNr. SK8110629857", "multiple of 11, third digit 1 is never issued", mode="balanced"),
    n("VAT_ID_SK", "de", "pii_vat_id_sk", "Artikel XSK1370281264 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_SK", "de", "pii_vat_id_sk", "Messreihe SK1370281264-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_SK", "en", "pii_vat_id_sk", "Our Slovak VAT number is SK3376474443.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_SK", "en", "pii_vat_id_sk", "Invoice number SK3376474442 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_SK", "en", "pii_vat_id_sk", "VAT number SK202274961", "nine digits", mode="balanced"),
    n("VAT_ID_SK", "en", "pii_vat_id_sk", "Path /exports/SK3376474442/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_SK", "en", "pii_vat_id_sk", "Model SK3376474442X sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── NO ────────────────────────────────────────────────────────────────────
    p("VAT_ID_NO", "de", "pii_vat_id_no", "Die norwegische USt-IdNr. lautet ", "NO856023559MVA", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_NO", "de", "pii_vat_id_no", "Lieferant Hansen AS · ", "NO931 727 060 MVA", "", mode="balanced"),
    p("VAT_ID_NO", "de", "pii_vat_id_no", '{"firma": "Hansen AS", "ust_id": "', "NO 920 229 123 MVA", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_NO", "de", "pii_vat_id_no", "Firma;USt-IdNr.\nHansen AS;", "NO909 189 330 MVA", "", carrier="csv", mode="balanced"),
    p("VAT_ID_NO", "de", "pii_vat_id_no", "Bitte ", "NO 860 240 564 MVA", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_NO", "en", "pii_vat_id_no", "Our Norwegian VAT number is ", "NO937065663MVA", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_NO", "en", "pii_vat_id_no", "Supplier Hansen AS · ", "NO895 398 020 MVA", "", mode="balanced"),
    p("VAT_ID_NO", "en", "pii_vat_id_no", "vat_id=", "NO 959 930 988 MVA", "", carrier="kv", mode="balanced"),
    p("VAT_ID_NO", "en", "pii_vat_id_no", "<supplier><vat>", "NO991 511 245 MVA", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_NO", "en", "pii_vat_id_no", "Please store ", "NO 916 588 151 MVA", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_NO", "de", "pii_vat_id_no", "Die norwegische USt-IdNr. lautet NO856023550MVA.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_NO", "de", "pii_vat_id_no", "Bestellnummer NO856023559MVA ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_NO", "de", "pii_vat_id_no", "USt-IdNr. NO995525828", "organisation number without MVA", mode="balanced"),
    n("VAT_ID_NO", "de", "pii_vat_id_no", "Artikel XNO856023559MVA ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_NO", "de", "pii_vat_id_no", "Messreihe NO856023559MVA-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_NO", "en", "pii_vat_id_no", "Our Norwegian VAT number is NO937065664MVA.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_NO", "en", "pii_vat_id_no", "Invoice number NO937065663MVA is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_NO", "en", "pii_vat_id_no", "VAT number NO 99552582 MVA", "eight digits", mode="balanced"),
    n("VAT_ID_NO", "en", "pii_vat_id_no", "Path /exports/NO937065663MVA/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_NO", "en", "pii_vat_id_no", "Model NO937065663MVAX sold out.", "glued to a letter", carrier="prose", mode="recall"),
    # ── GB ────────────────────────────────────────────────────────────────────
    p("VAT_ID_GB", "de", "pii_vat_id_gb", "Die britische USt-IdNr. lautet ", "GB684791622", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_GB", "de", "pii_vat_id_gb", "Lieferant Smith Ltd · ", "XI566 6778 78", "", mode="balanced"),
    p("VAT_ID_GB", "de", "pii_vat_id_gb", '{"firma": "Smith Ltd", "ust_id": "', "GB 622 8444 86 001", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_GB", "de", "pii_vat_id_gb", "Firma;USt-IdNr.\nSmith Ltd;", "XI460 0228 35", "", carrier="csv", mode="balanced"),
    p("VAT_ID_GB", "de", "pii_vat_id_gb", "Bitte ", "GB 708 0334 06", " im Lieferantenstamm hinterlegen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("VAT_ID_GB", "en", "pii_vat_id_gb", "Our UK VAT number is ", "GB203673191", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_GB", "en", "pii_vat_id_gb", "Supplier Smith Ltd · ", "XI888 4672 54", "", mode="balanced"),
    p("VAT_ID_GB", "en", "pii_vat_id_gb", "vat_id=", "GB 849 9343 70 001", "", carrier="kv", mode="balanced"),
    p("VAT_ID_GB", "en", "pii_vat_id_gb", "<supplier><vat>", "XI165 4328 05", "</vat></supplier>", carrier="xml", mode="balanced"),
    p("VAT_ID_GB", "en", "pii_vat_id_gb", "Please store ", "GB 105 1525 18", " with the vendor.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("VAT_ID_GB", "de", "pii_vat_id_gb", "Die britische USt-IdNr. lautet GB684791623.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_GB", "de", "pii_vat_id_gb", "Bestellnummer GB684791622 ist eingegangen.", "order number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_GB", "de", "pii_vat_id_gb", "USt-IdNr. GB009537909", "9755 scheme below 100 0000 00 is never issued", mode="balanced"),
    n("VAT_ID_GB", "de", "pii_vat_id_gb", "Artikel XGB684791622 ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    n("VAT_ID_GB", "de", "pii_vat_id_gb", "Messreihe GB684791622-3 abgeschlossen.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("VAT_ID_GB", "en", "pii_vat_id_gb", "Our UK VAT number is GB203673192.", "check digit fails", carrier="prose", mode="balanced"),
    n("VAT_ID_GB", "en", "pii_vat_id_gb", "Invoice number GB203673191 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_GB", "en", "pii_vat_id_gb", "VAT number GB447009415", "remainder 55 is no published scheme", mode="balanced"),
    n("VAT_ID_GB", "en", "pii_vat_id_gb", "Path /exports/GB203673191/2026 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("VAT_ID_GB", "en", "pii_vat_id_gb", "Model GB203673191X sold out.", "glued to a letter", carrier="prose", mode="recall"),
]
for _row in B16_VAT_ID_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# DLP golden schema v2 (E13). Every DLP row names the rule it exercises (`rule_id`), the
# document that carries the value (`carrier`), its difficulty `tags` and whether it is a
# `known_gap`: a positive the detector misses today, reported by 13_l1_golden_eval but
# not gated. `carrier` and `prose` follow from the carrier, `encoded` and `split` from the
# placeholders of positives; `no_context` is set by hand. A row scanned in an opt-in DLP
# mode (K04 score model: scores, proximity and counter-context only act there) also carries
# `dlp_mode`; rows without it run in the default `strict` mode.
DLP_SCHEMA_VERSION = 2
DLP_TAGS = ("carrier", "no_context", "encoded", "split", "prose")
DLP_CARRIERS = (
    "line", "env", "yaml", "json", "toml", "ini", "xml", "code", "log", "cli", "http", "csv",
    "sql", "markdown", "prose",
)
# Minimum gated positives and hard negatives per target label and language.
DLP_MIN_PER_LANGUAGE = 5
DLP_MODES = ("strict", "balanced", "recall")


def dlp_row(
    row: dict, rule: str, carrier: str, tags: tuple[str, ...], known_gap: bool, mode: str = "strict"
) -> dict:
    tags = set(tags)
    if carrier not in DLP_CARRIERS or not tags <= {"no_context", "encoded", "split"}:
        raise ValueError(f"bad carrier {carrier!r} or hand-set tags {sorted(tags)}")
    if mode not in DLP_MODES:
        raise ValueError(f"bad dlp_mode {mode!r}")
    if known_gap and row["case_type"] != "positive":
        raise ValueError("only positives can be known gaps")
    if carrier not in ("line", "prose"):
        tags.add("carrier")
    if carrier == "prose":
        tags.add("prose")
    for entity in row["entities"]:
        if "encoding" in entity:
            tags.add("encoded")
        if "part" in entity:
            tags.add("split")
    head = {
        "schema_version": DLP_SCHEMA_VERSION,
        "language": row["language"],
        "case_type": row["case_type"],
        "target_label": row["target_label"],
        "rule_id": rule,
        "carrier": carrier,
        "tags": [tag for tag in DLP_TAGS if tag in tags],
        "known_gap": known_gap,
    }
    if mode != "strict":
        head["dlp_mode"] = mode
    return {**head, **{key: value for key, value in row.items() if key not in head}}


def ds(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    seed: int,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    gap: bool = False,
    mode: str = "strict",
) -> dict:
    """Secret positive: one generator recipe placed by `template`."""
    row = secret_template_positive(label, language, template, [{"gen": generator, "seed": seed}])
    return dlp_row(row, rule, carrier, tags, gap, mode)


def dp(
    label: str,
    language: str,
    rule: str,
    prefix: str,
    value: str,
    suffix: str = "",
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    gap: bool = False,
) -> dict:
    """Literal positive for the default-off identifier and content classes."""
    return dlp_row(positive(label, language, prefix, value, suffix), rule, carrier, tags, gap)


def dx(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    fill: str,
    reason: str,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
) -> dict:
    """Hard negative with an example/test value in a provider format: the `fill` recipe."""
    secrets = [{"gen": generator, "seed": 0, "fill": fill}]
    text, _ = recipes.materialize(template, secrets)
    row = {
        "language": language,
        "case_type": "hard_negative",
        "target_label": label,
        "template": template,
        "secrets": secrets,
        "text_fingerprint": recipes.fingerprint(text),
        "entities": [],
        "span_unit": "unicode_code_point",
        "negative_reason": reason,
        "provenance": {
            "origin": "synthetic",
            "source": "generator recipe with example/test fill (patronus_ark.dlp_synth), materialized at test time",
        },
    }
    return dlp_row(row, rule, carrier, tags, False)


# F01: rules that report a value only in its key context, also in `strict`.
DLP_CONTEXT_GATED_RULES = ("dlp_eth_private_key",)


def dc(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    seed: int,
    reason: str,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
    mode: str = "balanced",
) -> dict:
    """Hard negative of a scored DLP mode (K04): a generated value that `rule` reports in
    `strict`, but whose context marks it as no secret (a nearer digest/hash term, or no
    credential term at all). Its value is a plain recipe: it is no example value. A rule
    with a context gate (F01) drops such a value already in `strict`."""
    if mode == "strict" and rule not in DLP_CONTEXT_GATED_RULES:
        raise ValueError("generated hard negatives need a scored dlp_mode or a context-gated rule")
    secrets = [{"gen": generator, "seed": seed}]
    text, _ = recipes.materialize(template, secrets)
    row = {
        "language": language,
        "case_type": "hard_negative",
        "target_label": label,
        "template": template,
        "secrets": secrets,
        "text_fingerprint": recipes.fingerprint(text),
        "entities": [],
        "span_unit": "unicode_code_point",
        "negative_reason": reason,
        "provenance": {
            "origin": "synthetic",
            "source": "generator recipe (patronus_ark.dlp_synth) in non-secret context, materialized at test time",
        },
    }
    return dlp_row(row, rule, carrier, tags, False, mode)


# F03: lookalike generators (`lookalike` in dlp_synth/rules.json): a provider shape with a
# wrong check value or length. Their rule never reports them; rows place them where no
# other DLP rule does either, also in `strict`.
DLP_LOOKALIKE_GENERATORS = (
    "github_ghp_bad_crc", "github_gho_bad_crc", "github_ghu_bad_crc", "github_ghs_bad_crc",
    "github_ghr_bad_crc", "github_ghp_short", "github_gho_short", "github_ghp_long",
    "github_fine_grained_pat_short", "github_fine_grained_pat_long",
    # F04
    "npm_bad_crc", "npm_short", "npm_long", "gitlab_pat_long", "gitlab_deploy_token_short",
    "gitlab_trigger_token_upper_hex",
    # F05
    "aws_access_key_id_long", "aws_iam_user_unique_id",
    "aws_secret_access_key_long", "aws_secret_access_key_hex",
    # F-HTTP: random base64 that decodes to no user:password pair
    "http_basic_credentials",
)


def dl(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    seed: int,
    reason: str,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
) -> dict:
    """Hard negative with a lookalike value (F03): `rule`'s shape with a wrong check value or
    length, stored as a plain recipe so no committed text holds a token-shaped value."""
    if generator not in DLP_LOOKALIKE_GENERATORS:
        raise ValueError(f"{generator} is no lookalike generator")
    secrets = [{"gen": generator, "seed": seed}]
    text, _ = recipes.materialize(template, secrets)
    row = {
        "language": language,
        "case_type": "hard_negative",
        "target_label": label,
        "template": template,
        "secrets": secrets,
        "text_fingerprint": recipes.fingerprint(text),
        "entities": [],
        "span_unit": "unicode_code_point",
        "negative_reason": reason,
        "provenance": {
            "origin": "synthetic",
            "source": "lookalike generator recipe (patronus_ark.dlp_synth), materialized at test time",
        },
    }
    return dlp_row(row, rule, carrier, tags, False)


def dn(
    label: str,
    language: str,
    rule: str,
    text: str,
    reason: str,
    *,
    carrier: str = "line",
    tags: tuple[str, ...] = (),
) -> dict:
    """Hard negative: a lookalike for `rule` that no DLP rule may report."""
    return dlp_row(negative(label, language, text, reason), rule, carrier, tags, False)


DLP_CASES = {
    "API_KEY": [
        ds("API_KEY", "en", "dlp_openai_key", "OPENAI_API_KEY=<<secret:0>>", "openai_project_key", 101),
        ds("API_KEY", "de", "dlp_huggingface", "Modellschlüssel: <<secret:0>>", "huggingface_token", 102),
        ds("API_KEY", "en", "dlp_groq_key", "GROQ_API_KEY=<<secret:0>>", "groq_key", 103),
        dn("API_KEY", "en", "dlp_openai_key", "Truncated OpenAI prefix in the docs: sk-proj-short", "provider token is too short"),
        dn("API_KEY", "de", "dlp_generic_credential_assignment", "API-Schlüssel: [REDACTED]", "redacted placeholder"),
        ds(
            "API_KEY", "de", "dlp_anthropic_key",
            "# Produktivkonfiguration, nicht einchecken\nAPP_ENV=production\nLOG_LEVEL=warn\n"
            "ANTHROPIC_API_KEY=<<secret:0>>\nMAX_TOKENS=4096\n",
            "anthropic_api_key", 1001, carrier="env",
        ),
        ds(
            "API_KEY", "de", "dlp_openai_svc",
            "Hallo Team, der Service-Account der Pipeline nutzt jetzt <<secret:0>>. "
            "Bitte nur im Vault ablegen und nicht weiterleiten.",
            "openai_service_account_key", 1002, carrier="prose",
        ),
        ds(
            "API_KEY", "de", "dlp_openai_legacy",
            "# Altes Skript, wird im dritten Quartal migriert\nimport openai\n\n"
            "openai.api_key = \"<<secret:0>>\"\nantwort = openai.Completion.create(prompt=\"Hallo\")\n",
            "openai_legacy_key", 1003, carrier="code",
        ),
        ds(
            "API_KEY", "de", "dlp_groq_key",
            "Gefunden in Zeile 14 der Shell-Historie: <<secret:0>>",
            "groq_key", 1004, tags=("no_context",),
        ),
        ds(
            "API_KEY", "de", "dlp_replicate",
            "# Modell-Deployment (Staging)\nreplicate:\n  modell: stability-ai/sdxl\n  zugang: <<secret:0>>\n  timeout: 30\n",
            "replicate_api_token", 1005, carrier="yaml",
        ),
        ds(
            "API_KEY", "de", "dlp_xai_key",
            "[llm.grok]\n# Schlüssel des Forschungsteams\nendpoint = \"https://api.x.ai/v1\"\nschluessel = \"<<secret:0>>\"\n",
            "xai_api_key", 1006, carrier="toml",
        ),
        ds(
            "API_KEY", "de", "dlp_openai_key",
            "$ export OPENAI_API_KEY='<<secret:0>>'\n$ python bericht.py --sprache de\n",
            "openai_project_api_key", 1007, carrier="cli",
        ),
        ds(
            "API_KEY", "de", "dlp_anthropic_key",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: llm-zugang\ndata:\n  ANTHROPIC_API_KEY: <<secret:0|base64>>\n",
            "anthropic_admin_key", 1008, carrier="yaml", gap=True,
        ),
        ds(
            "API_KEY", "de", "dlp_xai_key",
            "# Schlüssel aufgeteilt, damit der Scanner ihn nicht findet\n"
            "XAI_TEIL_A = \"<<secret:0[0:44]>>\"\nXAI_TEIL_B = \"<<secret:0[44:84]>>\"\nschluessel = XAI_TEIL_A + XAI_TEIL_B\n",
            "xai_api_key", 1009, carrier="code", gap=True,
        ),
        ds(
            "API_KEY", "en", "dlp_anthropic_key",
            "{\n  \"provider\": \"anthropic\",\n  \"model\": \"claude\",\n  \"credentials\": {\"value\": \"<<secret:0>>\"}\n}\n",
            "anthropic_api_key", 1010, carrier="json",
        ),
        ds(
            "API_KEY", "en", "dlp_openai_legacy",
            "Hi Sam, I found our old OpenAI key <<secret:0>> in the wiki history. Can you revoke it today?",
            "openai_legacy_key", 1011, carrier="prose",
        ),
        ds(
            "API_KEY", "en", "dlp_openai_svc",
            "2026-10-02T08:14:03Z WARN worker-3 retrying request with <<secret:0>> after 429\n"
            "2026-10-02T08:14:05Z INFO worker-3 request succeeded\n",
            "openai_service_account_key", 1012, carrier="log", tags=("no_context",),
        ),
        ds(
            "API_KEY", "en", "dlp_huggingface",
            "$ huggingface-cli login --token <<secret:0>>\nToken is valid (permission: write).\n",
            "huggingface_token", 1013, carrier="cli",
        ),
        ds(
            "API_KEY", "en", "dlp_xai_key",
            "XAI_API_KEY=<<secret:0>>",
            "xai_api_key", 1014,
        ),
        ds(
            "API_KEY", "en", "dlp_replicate",
            "import replicate\n\nclient = replicate.Client(api_token=\"<<secret:0>>\")\noutput = client.run(\"stability-ai/sdxl\")\n",
            "replicate_api_token", 1015, carrier="code",
        ),
        ds(
            "API_KEY", "en", "dlp_huggingface",
            "<<secret:0>>",
            "huggingface_token", 1016, tags=("no_context",),
        ),
        ds(
            "API_KEY", "en", "dlp_groq_key",
            "Authorization header (base64 by the proxy): <<secret:0|base64>>",
            "groq_key", 1017, gap=True,
        ),
        ds(
            "API_KEY", "en", "dlp_openai_key",
            "const key = \"<<secret:0[0:40]>>\" +\n  \"<<secret:0[40:164]>>\";\n",
            "openai_project_api_key", 1018, carrier="code", gap=True,
        ),
        dn(
            "API_KEY", "de", "dlp_anthropic_key",
            "# Lokale Entwicklung\nAPP_ENV=development\nANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "API_KEY", "de", "dlp_openai_key",
            "Der OpenAI-Schlüssel beginnt immer mit sk-proj- und liegt nur im Vault.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "de", "dlp_groq_key",
            "# Schlüssel kommt aus der Umgebung\nclient = Groq(api_key=os.getenv(\"GROQ_API_KEY\"))\n",
            "environment reference in code", carrier="code",
        ),
        dn(
            "API_KEY", "de", "dlp_huggingface",
            "huggingface:\n  # eigenen Token eintragen\n  token: <dein-hf-token>\n",
            "template placeholder", carrier="yaml",
        ),
        dn(
            "API_KEY", "de", "dlp_replicate",
            "Laut Doku beginnen Replicate-Tokens mit r8_ und haben 40 Zeichen.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "en", "dlp_xai_key",
            "xAI keys start with xai- and are 84 characters long.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "en", "dlp_openai_svc",
            "{\"openai\": {\"service_account_key\": \"${OPENAI_SVC_KEY}\"}}",
            "environment reference", carrier="json",
        ),
        dn(
            "API_KEY", "en", "dlp_openai_legacy",
            "Legacy OpenAI keys were sk- followed by 48 letters and digits; ours were all revoked.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "API_KEY", "en", "dlp_anthropic_key",
            "const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });",
            "environment reference in code", carrier="code",
        ),
        dn(
            "API_KEY", "en", "dlp_groq_key",
            "$ export GROQ_API_KEY='<your-groq-key>'\n$ python chat.py\n",
            "template placeholder", carrier="cli",
        ),
    ],
    "CLOUD_KEY": [
        ds("CLOUD_KEY", "en", "dlp_aws_access_key", "AWS_ACCESS_KEY_ID=<<secret:0>>", "aws_access_key_id", 201),
        ds("CLOUD_KEY", "de", "dlp_google_api_key", "Google API Key: <<secret:0>>", "google_api_key", 202),
        ds("CLOUD_KEY", "en", "dlp_aws_secret_key", "AWS_SECRET_ACCESS_KEY=<<secret:0>>", "aws_secret_access_key", 203),
        dn("CLOUD_KEY", "en", "dlp_aws_access_key", "AWS_ACCESS_KEY_ID=AKIA123", "cloud key is too short"),
        dn("CLOUD_KEY", "de", "dlp_aws_secret_key", "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}", "environment reference is not secret material"),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "# ~/.aws/credentials (Buchhaltung)\n[buchhaltung]\naws_access_key_id = <<secret:0>>\nregion = eu-central-1\n",
            "aws_access_key_id", 2001, carrier="ini",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "[export]\n# geheimer Teil, nicht teilen\naws_secret_access_key = <<secret:0>>\noutput = json\n",
            "aws_secret_access_key", 2002, carrier="ini",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_google_oauth_token",
            "Kurze Info: das Access-Token <<secret:0>> läuft in einer Stunde ab, danach bitte neu anmelden.",
            "google_oauth_access_token", 2003, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_gcp_client_secret",
            "{\n  \"installed\": {\n    \"client_id\": \"4711-abc.apps.googleusercontent.com\",\n"
            "    \"geheimnis\": \"<<secret:0>>\"\n  }\n}\n",
            "gcp_oauth_client_secret", 2004, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "datum;benutzer;wert\n2026-10-01;deploy;<<secret:0>>\n",
            "aws_session_access_key_id", 2005, carrier="csv", tags=("no_context",),
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_google_api_key",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: karten\ndata:\n  GOOGLE_API_KEY: <<secret:0|base64>>\n",
            "google_api_key", 2006, carrier="yaml", gap=True,
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_google_oauth_token",
            "GET /drive/v3/files HTTP/1.1\r\nHost: www.googleapis.com\r\nAuthorization: Bearer <<secret:0>>\r\nAccept: application/json\r\n\r\n",
            "google_oauth_access_token", 2007, carrier="http",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "# OAuth client for the admin console\nGOOGLE_CLIENT_ID=4711-abc.apps.googleusercontent.com\nGOOGLE_CLIENT_SECRET=<<secret:0>>\n",
            "gcp_oauth_client_secret", 2008, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_google_api_key",
            "const fallbacks = [\"<<secret:0>>\", \"offline\"];\n",
            "google_api_key", 2009, carrier="code", tags=("no_context",),
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "{\"Credentials\": {\"AccessKeyId\": \"ASIA-redacted\", \"SecretAccessKey\": \"<<secret:0>>\", \"Expiration\": \"2026-10-02T10:00:00Z\"}}",
            "aws_secret_access_key", 2010, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "Our OAuth client secret is <<secret:0>>, please store it in Secret Manager.",
            "gcp_oauth_client_secret", 2011, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "key_id = \"<<secret:0[0:4]>>\" + \"<<secret:0[4:20]>>\"\n",
            "aws_access_key_id", 2012, carrier="code", gap=True,
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "Die Access Key ID beginnt mit AKIA und ist 20 Zeichen lang.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_gcp_client_secret",
            "{\"web\": {\"client_id\": \"4711-abc.apps.googleusercontent.com\", \"client_secret\": \"<CLIENT_SECRET>\"}}",
            "template placeholder", carrier="json",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_google_oauth_token",
            "Ein Google-Access-Token sieht so aus: ya29.… (im Ticket gekürzt).",
            "truncated value", carrier="prose",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_google_api_key",
            "# Karten-API, Wert kommt aus dem Deployment\nMAPS_REGION=eu\nGOOGLE_API_KEY=${GOOGLE_API_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "2026-10-02 10:00:01 INFO oauth client secret prefix=GOCSPX-*** rotated\n",
            "masked value", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "[default]\naws_access_key_id = <your-access-key-id>\naws_secret_access_key = <your-secret-access-key>\n",
            "template placeholder", carrier="ini",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_google_oauth_token",
            "# ya29 access tokens expire after one hour\nrefresh_interval_seconds = 3600\n",
            "comment about the format without a value", carrier="code",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_google_api_key",
            "<script src=\"https://maps.googleapis.com/maps/api/js?key=YOUR_API_KEY\"></script>",
            "documented placeholder", carrier="xml",
        ),
    ],
    "CREDENTIAL": [
        ds("CREDENTIAL", "de", "dlp_password_assignment", "Passwort = <<secret:0>>", "password", 301),
        ds("CREDENTIAL", "en", "dlp_credential_in_url", "https://example.test?token=<<secret:0>>", "url_token", 302),
        ds("CREDENTIAL", "en", "dlp_basic_auth", "Authorization: Basic <<secret:0>>", "http_basic_auth", 303),
        dn("CREDENTIAL", "de", "dlp_password_assignment", "Passwort = ${PASSWORD}", "environment reference"),
        dn("CREDENTIAL", "en", "dlp_generic_credential_assignment", "token = [REDACTED]", "redacted placeholder"),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Mailversand\nSMTP_HOST=mail.intern\nSMTP_PASSWORT=<<secret:0>>\n",
            "password", 3001, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Der API-Schlüssel ist <<secret:0>>, bitte nicht ins Wiki kopieren.",
            "generic_api_secret", 3002, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "# Testaufruf gegen die Staging-API\ncurl -H \"Authorization: Basic <<secret:0>>\" https://staging.example.de/api/v1/status\n",
            "http_basic_auth", 3003, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_signed_url_signature",
            "Download-Link (15 Minuten gültig): https://files.example.de/bericht.zip?Expires=1767225600&Signature=<<secret:0>>",
            "aws_sigv4_signature", 3004, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "GET /konto HTTP/1.1\r\nHost: shop.example.de\r\nCookie: sprache=de; PHPSESSID=<<secret:0>>\r\n\r\n",
            "php_session_id", 3005, carrier="http",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "datenbank:\n  # Reporting-Replik\n  url: postgres://bericht:<<secret:0>>@db.intern:5432/bericht\n",
            "url_userinfo_password", 3006, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_credential_in_url",
            "Link aus dem Ticket: https://intranet.example.de/report?id=7&token=<<secret:0>>",
            "url_token", 3007,
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "Verbindung: mysql://bericht:<<secret:0|url>>@db1.intern/bericht",
            "password", 3008,
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: datenbank\ndata:\n  DB_PASSWORD: <<secret:0|base64>>\n",
            "password", 3009, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# worker settings\nREDIS_URL=redis://cache:6379/0\nQUEUE_API_TOKEN=<<secret:0>>\n",
            "generic_api_secret", 3010, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "database:\n  host: db.internal\n  user: app\n  password: <<secret:0>>\n",
            "password", 3011, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "oauth:\n  client_id: dashboard\n  client_secret: <<secret:0>>\n",
            "generic_api_secret", 3012, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_signed_url_signature",
            "2026-10-02T09:00:00Z INFO upload url=https://bucket.s3.eu-central-1.amazonaws.com/report.pdf"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=<<secret:0>>\n",
            "aws_sigv4_signature", 3013, carrier="log",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: JSESSIONID=<<secret:0>>; Path=/; HttpOnly\r\n\r\n",
            "java_session_id", 3014, carrier="http",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "engine = create_engine(\"postgresql://app:<<secret:0>>@db.internal/app\")\n",
            "url_userinfo_password", 3015, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "Hey, my VPN password is <<secret:0>> in case you need to log in while I am away.",
            "password", 3016, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<<secret:0>>",
            "password", 3017, tags=("no_context",), gap=True,
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Bitte das Passwort nie per Mail verschicken.",
            "prose about passwords without a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# Wert kommt aus dem Vault\nDATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "GET /konto HTTP/1.1\r\nCookie: sprache=de; JSESSIONID=<entfernt>\r\n\r\n",
            "redacted value", carrier="http",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "SMTP_HOST=mail.intern\nSMTP_PASSWORT=${SMTP_PASSWORT}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "password = os.getenv(\"DB_PASSWORD\")\n",
            "environment reference in code", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "api_key: \"<insert-key>\"",
            "template placeholder",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "Connection string format: postgres://app:<password>@db/app",
            "documented placeholder", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_signed_url_signature",
            "https://cdn.example.com/img/logo.png?w=200&sig=abc",
            "short image-resize parameter",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "Authorization: Basic <base64 of user:password>",
            "documented placeholder",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_credential_in_url",
            "curl \"https://api.example.com/export?format=csv&token=${EXPORT_TOKEN}\"",
            "shell variable reference", carrier="cli",
        ),
    ],
    "CRYPTO_KEY": [
        ds("CRYPTO_KEY", "en", "dlp_eth_private_key", "Ethereum private key: <<secret:0>>", "eth_private_key_hex", 401),
        ds("CRYPTO_KEY", "de", "dlp_btc_wif", "Wallet-Schlüssel: <<secret:0>>", "btc_wif_mainnet_uncompressed", 402),
        ds("CRYPTO_KEY", "en", "dlp_eth_private_key", "Signing scalar <<secret:0>>", "eth_private_key_hex", 403),
        dn("CRYPTO_KEY", "en", "dlp_eth_private_key", "Ethereum address: 0x0123456789abcdef0123456789abcdef01234567", "address is not a private key"),
        dn("CRYPTO_KEY", "de", "dlp_eth_private_key", "Wallet-Schlüssel: 0x1234", "value is too short"),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Deployment-Wallet (Testnetz)\nRPC_URL=https://rpc.example.de\nWALLET_PRIVATE_KEY=<<secret:0>>\n",
            "eth_private_key_hex", 4001, carrier="env",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Für die Wiederherstellung brauchst du den WIF-Schlüssel <<secret:0>> aus dem Tresor.",
            "btc_wif_mainnet_compressed", 4002, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "{\n  \"wallet\": \"kalt\",\n  \"wif\": \"<<secret:0>>\"\n}\n",
            "btc_wif_mainnet_uncompressed", 4003, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "// Hardhat-Konfiguration für das Testnetz\nmodule.exports = {\n  networks: {\n"
            "    sepolia: { accounts: [\"<<secret:0>>\"] },\n  },\n};\n",
            "eth_private_key_hex", 4004, carrier="code", tags=("no_context",),
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "signer:\n  # Schlüssel des Relayers\n  schluessel: <<secret:0>>\n",
            "eth_private_key_hex", 4005, carrier="yaml",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "WIF als Hex im Backup: <<secret:0|hex>>",
            "btc_wif_mainnet_compressed", 4006, gap=True,
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "$ bitcoin-cli importprivkey <<secret:0>> \"cold-storage\" false\n",
            "btc_wif_mainnet_compressed", 4007, carrier="cli",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Grandpa wrote the key on the back of the photo: <<secret:0>>. Please move the coins.",
            "btc_wif_mainnet_uncompressed", 4008, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "{\"address\": \"relayer\", \"privateKey\": \"<<secret:0>>\", \"chainId\": 11155111}",
            "eth_private_key_hex", 4009, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "<<secret:0>>",
            "btc_wif_mainnet_compressed", 4010, tags=("no_context",),
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "const pk = \"<<secret:0[0:34]>>\" +\n  \"<<secret:0[34:66]>>\";\n",
            "eth_private_key_hex", 4011, carrier="code", gap=True,
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Die Spendenadresse 0x52908400098527886e0f7030069857d2e4169ee7 gehört zur Kampagne.",
            "address is not a private key", carrier="prose",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "RPC_URL=https://rpc.example.de\nWALLET_PRIVATE_KEY=${WALLET_PRIVATE_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Bitcoin-Adresse für Rückzahlungen: <Empfängeradresse einsetzen>",
            "template placeholder",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "SHA-256 der Firmware: 9f2c4b7e1a0d8e3f6b5c2a1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f",
            "file digest is not a private key",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "PRIVATE_KEY=<wallet-private-key>\nNETWORK=sepolia\n",
            "template placeholder", carrier="env",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "commit 4c1f0e9a7d2b8c3e6f5a4b3c2d1e0f9a8b7c6d5e\nAuthor: Dev <dev@example.org>\n",
            "commit hash is not a private key", carrier="log",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "A WIF key starts with 5, K or L and is 51 or 52 characters long.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "wallet id 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "UUID is not a key",
        ),
    ],
    "PASSWORD_HASH": [
        ds("PASSWORD_HASH", "en", "dlp_password_hash", "password_hash = <<secret:0>>", "bcrypt_hash", 501),
        ds("PASSWORD_HASH", "de", "dlp_password_hash", "Passwort-Hash: <<secret:0>>", "argon2id_hash", 502),
        ds("PASSWORD_HASH", "en", "dlp_password_hash", "passwd_hash = <<secret:0>>", "md5_hex", 503),
        dn("PASSWORD_HASH", "de", "dlp_password_hash", "Passwort-Hash: [REDACTED]", "redacted placeholder"),
        dn("PASSWORD_HASH", "en", "dlp_password_hash", "checksum = 0123456789abcdef0123456789abcdef", "missing password-hash anchor"),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "benutzer:\n  - name: ada\n    rolle: admin\n    password_hash: <<secret:0>>\n",
            "bcrypt_2b_hash", 5001, carrier="yaml",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "# Notfallzugang\nADMIN_USER=notfall\nPASSWORT_HASH=<<secret:0>>\n",
            "sha256_hex", 5002, carrier="env",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "2026-10-03 12:00:00 WARN Benutzer ada angelegt, passwort_hash=<<secret:0>>\n",
            "argon2id_phc_hash", 5003, carrier="log",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Im Ticket steht der Passwort-Hash: <<secret:0>> – bitte sofort entfernen.",
            "bcrypt_2b_hash", 5004, carrier="prose",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "[benutzer.alt]\npasswd_hash = <<secret:0>>\n",
            "md5_hex", 5005, carrier="ini",
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Der Passwort-Hash lautet <<secret:0>>.",
            "bcrypt_2b_hash", 5006, carrier="prose", gap=True,
        ),
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "ada:<<secret:0>>:19700:0:99999:7:::\n",
            "bcrypt_2b_hash", 5007, tags=("no_context",), gap=True,
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "user = User(email=\"ada@example.org\")\nuser.password_hash = \"<<secret:0>>\"\ndb.session.add(user)\n",
            "argon2id_phc_hash", 5008, carrier="code",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "[legacy]\npassword_hash = <<secret:0>>\n",
            "sha256_hex", 5009, carrier="ini",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "FYI the leaked password hash: <<secret:0>> came from the old forum database.",
            "bcrypt_2b_hash", 5010, carrier="prose",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "{\"email\": \"ada@example.org\", \"password_hash\": \"<<secret:0>>\"}",
            "argon2id_phc_hash", 5011, carrier="json",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Passwort-Hash: noch nicht gesetzt",
            "no hash value",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "sha256sum: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b  release.tar.gz",
            "file checksum without a password-hash anchor", carrier="cli",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "benutzer:\n  password_hash: ${ADMIN_HASH}\n",
            "environment reference", carrier="yaml",
        ),
        dn(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "bcrypt-Hashes beginnen mit $2b$12$ und haben 60 Zeichen.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "user.password_hash = None  # set on first login\n",
            "no hash value", carrier="code",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "password_hash: \"<bcrypt hash>\"",
            "template placeholder",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "Argon2 parameters: $argon2id$v=19$m=65536,t=3,p=4$",
            "parameter prefix without a password-hash anchor",
        ),
        dn(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "ETag: \"5d41402abc4b2a76b9719d911017c592\"",
            "content hash without a password-hash anchor", carrier="http",
        ),
    ],
    "PAYMENT_KEY": [
        ds("PAYMENT_KEY", "en", "dlp_stripe_key", "STRIPE_SECRET_KEY=<<secret:0>>", "stripe_secret_live", 601),
        ds("PAYMENT_KEY", "de", "dlp_stripe_key", "Stripe Testschlüssel: <<secret:0>>", "stripe_restricted_test", 602),
        ds("PAYMENT_KEY", "en", "dlp_stripe_webhook", "Webhook secret: <<secret:0>>", "stripe_webhook_secret", 603),
        dn("PAYMENT_KEY", "en", "dlp_stripe_key", "Truncated Stripe prefix in the docs: sk_live_short", "provider token is too short"),
        dn("PAYMENT_KEY", "de", "dlp_stripe_key", "Stripe-Schlüssel: [REDACTED]", "redacted placeholder"),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "# Zahlungsdienst\nSTRIPE_KONTO=shop-de\nSTRIPE_WEBHOOK_SECRET=<<secret:0>>\n",
            "stripe_webhook_secret", 6001, carrier="env",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "<?php\n// Testumgebung des Shops\n\\Stripe\\Stripe::setApiKey('<<secret:0>>');\n",
            "stripe_secret_test_long", 6002, carrier="code",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "Kannst du kurz prüfen, ob <<secret:0>> noch aktiv ist? Der Kunde meldet Fehler beim Bezahlen.",
            "stripe_secret_live", 6003, carrier="prose",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "zahlung:\n  anbieter: stripe\n  schluessel: <<secret:0>>\n",
            "stripe_restricted_test", 6004, carrier="yaml",
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "datum;shop;wert\n2026-10-01;de;<<secret:0>>\n",
            "stripe_secret_live", 6005, carrier="csv", tags=("no_context",),
        ),
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: zahlung\ndata:\n  STRIPE_WEBHOOK_SECRET: <<secret:0|base64>>\n",
            "stripe_webhook_secret", 6006, carrier="yaml", gap=True,
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "const event = stripe.webhooks.constructEvent(body, signature, \"<<secret:0>>\");\n",
            "stripe_webhook_secret", 6007, carrier="code", tags=("no_context",),
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "{\"payments\": {\"provider\": \"stripe\", \"secret\": \"<<secret:0>>\"}}",
            "stripe_secret_live", 6008, carrier="json",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "$ curl https://api.stripe.com/v1/charges -u <<secret:0>>:\n",
            "stripe_secret_test_long", 6009, carrier="cli",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "Quick one: is <<secret:0>> the restricted key for the reporting job?",
            "stripe_restricted_test", 6010, carrier="prose",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "STRIPE_KEY = \"<<secret:0[0:12]>>\" + \"<<secret:0[12:32]>>\"\n",
            "stripe_secret_live", 6011, carrier="code", gap=True,
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "Stripe-Schlüssel beginnen mit sk_live_ oder sk_test_.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "# Wert aus dem Vault\nSTRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "STRIPE_WEBHOOK_SECRET=<aus dem Dashboard kopieren>",
            "template placeholder",
        ),
        dn(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "zahlung:\n  # öffentlicher Schlüssel für das Frontend\n  publishable: pk_test_51ExampleExampleExample00\n",
            "publishable key is public", carrier="yaml",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "{\"stripe\": {\"publishableKey\": \"pk_live_51ExampleExampleExample00\"}}",
            "publishable key is public", carrier="json",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;\n",
            "environment reference in code", carrier="code",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "Webhook signing secrets start with whsec_ and are shown once in the dashboard.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "Use the test card 4242 4242 4242 4242 with any future date.",
            "test card number is not a key", carrier="prose",
        ),
    ],
    "PRIVATE_KEY": [
        ds("PRIVATE_KEY", "en", "dlp_private_key_block", "<<secret:0>>", "pem_pkcs8_private_key", 701),
        ds("PRIVATE_KEY", "de", "dlp_private_key_header", "Schlüsseldatei:\n<<secret:0>>", "pem_openssh_private_key_header", 702),
        ds("PRIVATE_KEY", "en", "dlp_private_key_block", "<<secret:0>>", "pem_rsa_private_key", 703),
        dn("PRIVATE_KEY", "en", "dlp_private_key_header", "-----BEGIN PUBLIC KEY-----", "public key is not private material"),
        dn("PRIVATE_KEY", "de", "dlp_private_key_header", "BEGIN PRIVATE KEY", "PEM delimiters are incomplete"),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "$ cat ~/.ssh/id_ed25519\n<<secret:0>>\n$ ls -l ~/.ssh\n",
            "pem_openssh_ed25519_private_key", 7001, carrier="cli",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "Hallo, anbei der Schlüssel für den Server:\n\n<<secret:0>>\n\nBitte nach dem Import löschen.",
            "pem_sec1_ec_private_key", 7002, carrier="prose",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "# TLS für den internen Dienst\nTLS_KEY=\"<<secret:0>>\"\nTLS_PORT=8443\n",
            "pem_dsa_private_key", 7003, carrier="env",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "{\n  \"type\": \"service_account\",\n  \"projekt\": \"buchhaltung\",\n  \"private_key\": \"<<secret:0|json>>\"\n}\n",
            "pem_pkcs8_ed25519_private_key", 7004, carrier="json",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "Die Datei beginnt mit <<secret:0>> und wurde versehentlich eingecheckt.",
            "pem_openssh_private_key_header", 7005, carrier="prose",
        ),
        ds(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n  tls.key: <<secret:0|base64>>\n",
            "pem_pkcs1_rsa_private_key", 7006, carrier="yaml", gap=True,
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "SIGNING_KEY = \"\"\"<<secret:0>>\"\"\"\n\ndef sign(payload):\n    return jwt.encode(payload, SIGNING_KEY, algorithm=\"RS256\")\n",
            "pem_pkcs1_rsa_private_key", 7007, carrier="code",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "$ cat deploy/id_ed25519\n<<secret:0>>\n",
            "pem_openssh_ed25519_private_key", 7008, carrier="cli",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "2026-10-02 11:00:00 WARN config loader found <<secret:0>> in uploads/key.txt\n",
            "pem_openssh_private_key_header", 7009, carrier="log",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "{\"kid\": \"edge-1\", \"pem\": \"<<secret:0|json>>\"}",
            "pem_sec1_ec_private_key", 7010, carrier="json",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "Hi Lee, here is the old DSA key from the build box:\n<<secret:0>>\nPlease rotate it.",
            "pem_dsa_private_key", 7011, carrier="prose",
        ),
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n  tls.key: <<secret:0|base64>>\n",
            "pem_sec1_ec_private_key", 7012, carrier="yaml", gap=True,
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2VydGlmaWthdA==\n-----END CERTIFICATE-----",
            "certificate is public", carrier="cli",
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_block",
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAb2VmZmVudGxpY2hlciBTY2hsw7xzc2Vs\n-----END PUBLIC KEY-----",
            "public key block", carrier="cli",
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG9mZmVudGxpY2hlciBTY2hsdWVzc2Vs ada@laptop",
            "public SSH key",
        ),
        dn(
            "PRIVATE_KEY", "de", "dlp_private_key_header",
            "Den privaten Schlüssel findest du unter ~/.ssh/id_ed25519, bitte nie kopieren.",
            "path reference without key material", carrier="prose",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "-----BEGIN CERTIFICATE REQUEST-----",
            "certificate request is public",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEZQAAABYJKwYBBAHaRw8BAQdAcHVibGljIGtleQ==\n-----END PGP PUBLIC KEY BLOCK-----",
            "public PGP key block", carrier="cli",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "# .gitignore\n*.pem\nid_rsa\nid_ed25519\n",
            "file names without key material", carrier="code",
        ),
        dn(
            "PRIVATE_KEY", "en", "dlp_private_key_header",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCpdWJsaWMga2V5IG9ubHk= deploy@ci",
            "public SSH key",
        ),
    ],
    "SECRET_TOKEN": [
        # F03: dlp_github_token checks the CRC32; the shape-only `github_pat_classic` has none.
        ds("SECRET_TOKEN", "en", "dlp_github_token", "GITHUB_TOKEN=<<secret:0>>", "github_ghp_token", 801),
        ds("SECRET_TOKEN", "de", "dlp_gitlab_pat", "GitLab Token: <<secret:0>>", "gitlab_pat", 802),
        ds("SECRET_TOKEN", "en", "dlp_jwt_token", "Authorization: Bearer <<secret:0>>", "jwt_hs256", 803),
        dn("SECRET_TOKEN", "en", "dlp_github_token", "Truncated GitHub prefix in the docs: ghp_short", "provider token is too short"),
        dn("SECRET_TOKEN", "de", "dlp_generic_credential_assignment", "Token: your-token-here", "documented placeholder"),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_pat",
            "# CI-Zugang für das Release-Skript\nGH_REPO=acme/app\nGH_TOKEN=<<secret:0>>\n",
            "github_fine_grained_pat", 8001, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "; Registry für interne Pakete\n//registry.npmjs.org/:_authToken=<<secret:0>>\nalways-auth=true\n",
            "npm_access_token", 8002, carrier="ini",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_slack_token",
            "Bitte den Slack-Token <<secret:0>> heute noch widerrufen, er stand im Wiki.",
            "slack_bot_token", 8003, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_discord_token",
            "# Bot für den Community-Server\nimport discord\n\nclient = discord.Client(intents=discord.Intents.default())\nclient.run('<<secret:0>>')\n",
            "discord_bot_token", 8004, carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "GET /api/v1/konten HTTP/1.1\r\nHost: api.example.de\r\nAuthorization: Bearer <<secret:0>>\r\n\r\n",
            "bearer_opaque_token", 8005, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "POST /profil HTTP/1.1\r\nHost: portal.example.de\r\nX-CSRF-Token: <<secret:0>>\r\n\r\nname=Ada",
            "csrf_token", 8006, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "datum;job;wert\n2026-10-01;release;<<secret:0>>\n",
            "github_gho_token", 8007, carrier="csv", tags=("no_context",),
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_jwt_token",
            "2026-10-02 10:15:00 INFO Anmeldung erfolgreich, Sitzung <<secret:0>>\n",
            "jwt_signed_hs256", 8008, carrier="log", tags=("no_context",),
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "deploy:\n  stage: deploy\n  variables:\n    GITLAB_TOKEN: <<secret:0>>\n  script:\n    - ./deploy.sh\n",
            "gitlab_pat", 8009, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "Token als Hex im Backup: <<secret:0|hex>>",
            "github_ghp_token", 8010, gap=True,
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "$ git clone https://x-access-token:<<secret:0>>@github.com/acme/app.git\nCloning into 'app'...\n",
            "github_ghs_token", 8011, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "{\"github\": {\"owner\": \"acme\", \"pat\": \"<<secret:0>>\"}}",
            "github_fine_grained_pat", 8012, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "# publish settings\nNPM_REGISTRY=https://registry.npmjs.org\nNPM_TOKEN=<<secret:0>>\n",
            "npm_access_token", 8013, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_slack_token",
            "notifications:\n  slack:\n    channel: \"#alerts\"\n    token: <<secret:0>>\n",
            "slack_user_token", 8014, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "DISCORD_TOKEN=<<secret:0>>",
            "discord_bot_token", 8015,
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "username=ada&csrf_token=<<secret:0>>",
            "csrf_token", 8016,
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "$ curl -H 'Authorization: Bearer <<secret:0>>' https://api.example.com/v1/me\n",
            "bearer_opaque_token", 8017, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "{\"session\": \"<<secret:0>>\"}",
            "jwt_signed_rs256", 8018, carrier="json", tags=("no_context",),
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_pat",
            "Hey, the GitLab token for the runner is <<secret:0>>, it expires next week.",
            "gitlab_pat", 8019, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "TOKEN = \"<<secret:0[0:4]>>\" + \"<<secret:0[4:40]>>\"\n",
            "github_ghp_token", 8020, carrier="code", gap=True,
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "GitHub-Tokens beginnen mit ghp_, gho_ oder github_pat_.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "deploy:\n  variables:\n    GITLAB_TOKEN: ${CI_JOB_TOKEN}\n",
            "CI variable reference", carrier="yaml",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "Authorization: Bearer <TOKEN>",
            "template placeholder",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_slack_token",
            "Slack-Bot-Tokens beginnen mit xoxb- und werden in der App-Verwaltung erzeugt.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "curl -H \"Authorization: Bearer ${API_TOKEN}\" https://api.example.com/v1/me",
            "environment reference", carrier="cli",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "<meta name=\"csrf-token\" content=\"{{ csrf_token() }}\">",
            "template expression", carrier="xml",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "The JWT header eyJhbGciOiJIUzI1NiJ9 decodes to {\"alg\":\"HS256\"}.",
            "header segment only", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
            "environment reference", carrier="ini",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "Discord bot tokens have three dot-separated parts; never paste them into issues.",
            "documented format without a value", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "- uses: actions/checkout@v4\n  with:\n    token: ${{ secrets.GH_PAT }}\n",
            "CI secret reference", carrier="yaml",
        ),
    ],
    "dlp.de.vat_id": [
        dp("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: ", "DE 123 456 789"),
        dp("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT ID: ", "DE987654321"),
        dp("dlp.de.vat_id", "de", "dlp_de_vat_id", "Umsatzsteuer-Identifikationsnummer = ", "DE 111222333"),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: FR123456789", "current detector covers German VAT IDs"),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "Reference DE123456789", "missing VAT anchor"),
        dp(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "Mit freundlichen Grüßen\nBeispiel Handels GmbH · Hauptstraße 1 · 10115 Berlin\nUSt-IdNr.: ", "DE 812 345 670",
            "\n", carrier="prose",
        ),
        dp(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "firma:\n  name: Beispiel AG\n  ust-idnr: ", "DE298765432", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "Unsere Umsatzsteuer-Identifikationsnummer lautet ", "DE 123456788", ", bitte auf der Rechnung angeben.",
            carrier="prose",
        ),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: beantragt, Nummer folgt", "no value yet"),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: DE 123 45", "too few digits"),
        dn("dlp.de.vat_id", "de", "dlp_de_vat_id", "USt-IdNr.: DE1234567890", "too many digits"),
        dn(
            "dlp.de.vat_id", "de", "dlp_de_vat_id",
            "Bitte tragen Sie Ihre USt-IdNr. im Kundenportal ein.", "anchor without a value", carrier="prose",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "Supplier details\nName: Example Trading GmbH\nVAT-ID ", "DE 135 792 468", "\n", carrier="prose",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "supplier:\n  country: DE\n  vat id: ", "DE246813579", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "2026-10-01T09:00:00Z INFO invoice created vat id=", "DE112233445", "\n", carrier="log",
        ),
        dp(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "Please put our VAT ID ", "DE998877665", " on every invoice.", carrier="prose",
        ),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT ID: ATU12345678", "Austrian VAT ID is out of scope"),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT ID: pending", "no value yet"),
        dn("dlp.de.vat_id", "en", "dlp_de_vat_id", "VAT rate: 19 %", "rate is not an identifier"),
        dn(
            "dlp.de.vat_id", "en", "dlp_de_vat_id",
            "Enter your VAT ID in the billing settings.", "anchor without a value", carrier="prose",
        ),
    ],
    "dlp.de.commercial_register_number": [
        dp("dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number", "Amtsgericht Berlin ", "HRB 12345"),
        dp("dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number", "Register entry ", "HRA 77881"),
        dp("dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number", "Vereinsregister ", "VR 2048"),
        dn("dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number", "Register: HRX 12345", "unknown register prefix"),
        dn("dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number", "Register entry HRB ABC", "value contains no digits"),
        dp(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Eingetragen im Handelsregister des Amtsgerichts Köln unter ", "HRB 98765", ".", carrier="prose",
        ),
        dp(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "impressum:\n  firma: Beispiel eG\n  register: ", "GnR 123", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Partnerschaftsregister ", "PR 815",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Handelsregister: Eintragung wird beantragt", "no value yet",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Die HRB-Nummer folgt nach der Eintragung.", "anchor without a value", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Zuständig ist das Registergericht München.", "court without a register number", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "de", "dlp_de_commercial_register_number",
            "Bestellnummer HRZ-2048", "unknown register prefix",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "Registered at Charlottenburg District Court, ", "HRB 123456", " B.", carrier="prose",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "{\"company\": \"Example GmbH\", \"register\": \"", "HRA 5544", "\"}", carrier="json",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "2026-10-01 INFO onboarding vendor register=", "HRB 70421", "\n", carrier="log",
        ),
        dp(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "The club is listed in the association register as ", "VR 4471", ".", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "We are hiring an HRBP for the Berlin office.", "role abbreviation", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "The VRAM budget is 16 GB per GPU.", "hardware term", carrier="prose",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "Commercial register: registration pending", "no value yet",
        ),
        dn(
            "dlp.de.commercial_register_number", "en", "dlp_de_commercial_register_number",
            "GnRH levels were normal.", "medical abbreviation", carrier="prose",
        ),
    ],
    "dlp.de.facility_number_bsnr": [
        dp("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: ", "123456789"),
        dp("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "Betriebsstättennummer = ", "987654321"),
        dp("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "German BSNR lautet ", "246813579"),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: 12345678", "only eight digits"),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Inventory number 123456789", "missing BSNR anchor"),
        dp(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "Praxis Dr. Beispiel\nAllgemeinmedizin\nBSNR ", "381234500", "\n", carrier="prose",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "praxis:\n  name: MVZ Beispiel\n  bsnr: ", "721234567", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "Die Betriebsstättennummer lautet ", "123450001", ", bitte im Abrechnungsformular eintragen.",
            carrier="prose",
        ),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: 1234567890", "ten digits"),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "BSNR: folgt nach Zulassung", "no value yet"),
        dn("dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr", "Telefon der Praxis: 030 123456789", "phone number without BSNR anchor"),
        dn(
            "dlp.de.facility_number_bsnr", "de", "dlp_de_facility_number_bsnr",
            "Die BSNR steht auf dem Praxisstempel.", "anchor without a value", carrier="prose",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "Facility number ", "246813570",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "Referral form\nPractice: Example Clinic\nMedical facility number: ", "987650123", "\n", carrier="prose",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "clinic:\n  facility number: ", "555012345", "\n", carrier="yaml",
        ),
        dp(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "2026-10-01 INFO claim export BSNR=", "112233445", "\n", carrier="log",
        ),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Facility number: pending", "no value yet"),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Facility number: 1234", "too few digits"),
        dn("dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr", "Room 123456789 is on the third floor.", "missing BSNR anchor", carrier="prose"),
        dn(
            "dlp.de.facility_number_bsnr", "en", "dlp_de_facility_number_bsnr",
            "Ask the practice for its BSNR before billing.", "anchor without a value", carrier="prose",
        ),
    ],
    "dlp.record.case_id": [
        dp("dlp.record.case_id", "de", "dlp_record_case_id", "Fallnummer: ", "CASE-2026/481"),
        dp("dlp.record.case_id", "en", "dlp_record_case_id", "Case ID ", "CV-2026-8842"),
        dp("dlp.record.case_id", "de", "dlp_record_case_id", "Aktenzeichen = ", "17-A/2048"),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Fallnummer: ABC", "value contains no digit"),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Ticket CASE-2026/481", "missing case anchor"),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Sehr geehrte Frau Beispiel,\nin Ihrer Sache (Aktenzeichen ", "3 O 112/26", ") ...", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "vorgang:\n  vorgangsnummer: ", "VG-2026-0042", "\n  status: offen\n", carrier="yaml",
        ),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Ihre Fallnummer lautet ", "F-88123", ". Bitte bei Rückfragen angeben.", carrier="prose",
        ),
        dp(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Betreff: Widerspruch, Aktenzeichen: ", "AZ-7781/26", "\n", carrier="prose",
        ),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Aktenzeichen: bitte angeben", "no value"),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Kundennummer: F-88123", "wrong identifier anchor"),
        dn(
            "dlp.record.case_id", "de", "dlp_record_case_id",
            "Die Fallnummer finden Sie oben rechts im Schreiben.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.case_id", "de", "dlp_record_case_id", "Vorgangsnummer: <wird vergeben>", "template placeholder"),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Support summary\nCase-ID: ", "SR-77120", "\nPriority: high\n", carrier="prose",
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "2026-10-02 INFO escalated case id=", "CS-2026-0193", "\n", carrier="log",
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "case:\n  case id: ", "C-4471", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Your case ID is ", "CX-2048-77", ", keep it for your records.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Case ID: ", "INC0012345",
        ),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Case ID: unknown", "value contains no digit"),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Order number CX-2048-77", "wrong identifier anchor"),
        dn(
            "dlp.record.case_id", "en", "dlp_record_case_id",
            "Please include the case ID in every reply.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.case_id", "en", "dlp_record_case_id", "Case ID: <case-id>", "template placeholder"),
    ],
    "dlp.record.contract_id": [
        dp("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer ", "V-2026-8842"),
        dp("dlp.record.contract_id", "en", "dlp_record_contract_id", "Contract ID ", "CONTRACT-8842"),
        dp("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertrags-ID: ", "VK/2048"),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer: VERTRAG", "value contains no digit"),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Agreement CONTRACT-8842", "missing contract-ID anchor"),
        dp(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "Hallo Herr Beispiel,\nIhre Vertragsnummer lautet ", "KV-55120", ".\nViele Grüße", carrier="prose",
        ),
        dp(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "vertrag:\n  vertragsnummer: ", "LV-2026-0007", "\n  laufzeit: 24\n", carrier="yaml",
        ),
        dp(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "2026-10-02 INFO Kündigung erfasst, Vertrags-ID=", "MV/7781", "\n", carrier="log",
        ),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer: siehe Anlage", "value contains no digit"),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Rechnungsnummer KV-55120", "wrong identifier anchor"),
        dn(
            "dlp.record.contract_id", "de", "dlp_record_contract_id",
            "Bitte geben Sie immer Ihre Vertragsnummer an.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.contract_id", "de", "dlp_record_contract_id", "Vertragsnummer: <eintragen>", "template placeholder"),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "Dear customer,\nyour contract ID is ", "SUB-2026-4471", ".\nRegards", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "contract:\n  contract id: ", "MSA-0815", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "2026-10-02 INFO renewal scheduled contract-id=", "C2026-118", "\n", carrier="log",
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "Contract-ID: ", "LEASE/2048",
        ),
        dp(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "Contract ID = ", "SUB/2026/7",
        ),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Contract ID: TBD", "value contains no digit"),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Invoice SUB-2026-4471", "wrong identifier anchor"),
        dn(
            "dlp.record.contract_id", "en", "dlp_record_contract_id",
            "The contract ID is printed on page one.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.contract_id", "en", "dlp_record_contract_id", "Contract ID: <contract-id>", "template placeholder"),
    ],
    "dlp.record.claim_id": [
        dp("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: ", "SCH-44119"),
        dp("dlp.record.claim_id", "en", "dlp_record_claim_id", "Claim ID ", "CLAIM-2048"),
        dp("dlp.record.claim_id", "de", "dlp_record_claim_id", "Leistungsfallnummer = ", "LF/7781"),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: SCHADEN", "value contains no digit"),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Ticket CLAIM-2048", "missing claim anchor"),
        dp(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "Sehr geehrte Damen und Herren,\nzur Schadennummer ", "KFZ-2026-3310", " reiche ich die Fotos nach.", carrier="prose",
        ),
        dp(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "schaden:\n  schadennummer: ", "HR-77120", "\n  status: offen\n", carrier="yaml",
        ),
        dp(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "2026-10-02 INFO Regulierung gestartet, Leistungsfallnummer=", "LF-2026-55", "\n", carrier="log",
        ),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: wird nachgereicht", "value contains no digit"),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Vertragsnummer KFZ-2026-3310", "wrong identifier anchor"),
        dn(
            "dlp.record.claim_id", "de", "dlp_record_claim_id",
            "Die Schadennummer erhalten Sie per Post.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.claim_id", "de", "dlp_record_claim_id", "Schadennummer: <neu>", "template placeholder"),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "Hello,\nregarding claim ID ", "WC-2026-0091", ", the adjuster will call you.", carrier="prose",
        ),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "claim:\n  claim id: ", "AUTO-5512", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "2026-10-02 INFO payout approved claim-id=", "HC/2048", "\n", carrier="log",
        ),
        dp(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "Claim-ID: ", "PRP-77-120",
        ),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Claim ID: none", "value contains no digit"),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Order ID none for WC-2026-0091", "wrong identifier anchor"),
        dn(
            "dlp.record.claim_id", "en", "dlp_record_claim_id",
            "You will get a claim ID by email.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.claim_id", "en", "dlp_record_claim_id", "Claim ID: <claim-id>", "template placeholder"),
    ],
    "dlp.record.order_id": [
        dp("dlp.record.order_id", "de", "dlp_record_order_id", "Bestellnummer ", "ORD-77881"),
        dp("dlp.record.order_id", "en", "dlp_record_order_id", "Order ID ", "ORDER-2048"),
        dp("dlp.record.order_id", "de", "dlp_record_order_id", "Auftragsnummer = ", "AUF/4711"),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Bestellnummer: ORDER", "value contains no digit"),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Shipment ORDER-2048", "missing order anchor"),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Hallo,\nmeine Bestellnummer ist ", "B-2026-11872", ", die Lieferung fehlt noch.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "auftrag:\n  auftragsnummer: ", "A-55012", "\n  menge: 3\n", carrier="yaml",
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "2026-10-02 INFO Versand angestoßen, Bestellnummer=", "WEB-88213", "\n", carrier="log",
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Ihre Bestellnummer lautet ", "DE-2026-4471", ".", carrier="prose",
        ),
        dp(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Auftragsnummer: ", "FA/2026/31",
        ),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Bestellnummer: folgt per Mail", "value contains no digit"),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Paketnummer WEB-88213", "wrong identifier anchor"),
        dn(
            "dlp.record.order_id", "de", "dlp_record_order_id",
            "Die Bestellnummer steht in der Bestätigungsmail.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.order_id", "de", "dlp_record_order_id", "Auftragsnummer: <neu>", "template placeholder"),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Hi,\nmy order ID is ", "WEB-55-1202", " and the parcel never arrived.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "order:\n  order id: ", "PO-2026-0815", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "2026-10-02 INFO payment captured order-id=", "SO/77120", "\n", carrier="log",
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Order-ID: ", "AMZ-114-2048",
        ),
        dp(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Order ID = ", "B2B/4471",
        ),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Order ID: pending", "value contains no digit"),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Tracking number SO/77120", "wrong identifier anchor"),
        dn(
            "dlp.record.order_id", "en", "dlp_record_order_id",
            "Your order ID is in the confirmation email.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.order_id", "en", "dlp_record_order_id", "Order ID: <order-id>", "template placeholder"),
    ],
    "dlp.record.invoice_id": [
        dp("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: ", "RE-2026-190"),
        dp("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Invoice ID ", "INV-2026-190"),
        dp("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungs-ID = ", "R/77881"),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: RECHNUNG", "value contains no digit"),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Document INV-2026-190", "missing invoice anchor"),
        dp(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "Guten Tag,\nzur Rechnungsnummer ", "RG-2026-0412", " fehlt noch die Zahlung.", carrier="prose",
        ),
        dp(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "rechnung:\n  rechnungsnummer: ", "2026-10-0042", "\n  betrag: 120\n", carrier="yaml",
        ),
        dp(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "2026-10-02 INFO Mahnung erstellt, Rechnungs-ID=", "RE/55120", "\n", carrier="log",
        ),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: siehe oben", "value contains no digit"),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Lieferscheinnummer RG-2026-0412", "wrong identifier anchor"),
        dn(
            "dlp.record.invoice_id", "de", "dlp_record_invoice_id",
            "Bitte bei Zahlung die Rechnungsnummer angeben.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.invoice_id", "de", "dlp_record_invoice_id", "Rechnungsnummer: <automatisch>", "template placeholder"),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "Hi,\ninvoice ID ", "AR-2026-7781", " is still unpaid.", carrier="prose",
        ),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "invoice:\n  invoice id: ", "INV/0815", "\n", carrier="yaml",
        ),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "2026-10-02 INFO reminder sent invoice-id=", "BILL-4471", "\n", carrier="log",
        ),
        dp(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "Invoice-ID: ", "2026-INV-31",
        ),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Invoice ID: draft", "value contains no digit"),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Shipment AR-2026-7781", "wrong identifier anchor"),
        dn(
            "dlp.record.invoice_id", "en", "dlp_record_invoice_id",
            "Quote the invoice ID when you pay.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.record.invoice_id", "en", "dlp_record_invoice_id", "Invoice ID: <invoice-id>", "template placeholder"),
    ],
    "dlp.project_id": [
        dp("dlp.project_id", "de", "dlp_project_id", "Projekt-ID ", "P-ARK-2026"),
        dp("dlp.project_id", "en", "dlp_project_id", "Project ID ", "PROJECT-2048"),
        dp("dlp.project_id", "de", "dlp_project_id", "Projektnummer = ", "PRJ/7781"),
        dn("dlp.project_id", "de", "dlp_project_id", "Projekt-ID: PROJEKT", "value contains no digit"),
        dn("dlp.project_id", "en", "dlp_project_id", "Folder PROJECT-2048", "missing project anchor"),
        dp(
            "dlp.project_id", "de", "dlp_project_id",
            "Hallo zusammen,\nbitte Stunden auf Projektnummer ", "PN-2026-114", " buchen.", carrier="prose",
        ),
        dp(
            "dlp.project_id", "de", "dlp_project_id",
            "projekt:\n  projekt-id: ", "ERP-4471", "\n  leitung: Ada\n", carrier="yaml",
        ),
        dp(
            "dlp.project_id", "de", "dlp_project_id",
            "2026-10-02 INFO Budget freigegeben, Projekt-ID=", "INT/0815", "\n", carrier="log",
        ),
        dn("dlp.project_id", "de", "dlp_project_id", "Projektnummer: noch offen", "value contains no digit"),
        dn("dlp.project_id", "de", "dlp_project_id", "Kostenstelle PN-2026-114", "wrong identifier anchor"),
        dn(
            "dlp.project_id", "de", "dlp_project_id",
            "Die Projekt-ID vergibt das PMO.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.project_id", "de", "dlp_project_id", "Projekt-ID: <neu>", "template placeholder"),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "Hi team,\nplease log your hours on project ID ", "OPS-2026-77", ".", carrier="prose",
        ),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "project:\n  project id: ", "MIG-5512", "\n", carrier="yaml",
        ),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "2026-10-02 INFO budget approved project-id=", "RND/2048", "\n", carrier="log",
        ),
        dp(
            "dlp.project_id", "en", "dlp_project_id",
            "Project-ID: ", "X-2026-31",
        ),
        dn("dlp.project_id", "en", "dlp_project_id", "Project ID: tbd", "value contains no digit"),
        dn("dlp.project_id", "en", "dlp_project_id", "Cost center OPS-2026-77", "wrong identifier anchor"),
        dn(
            "dlp.project_id", "en", "dlp_project_id",
            "Ask the PMO for a project ID.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.project_id", "en", "dlp_project_id", "Project ID: <project-id>", "template placeholder"),
    ],
    "dlp.organization_id": [
        dp("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: ", "TENANT-742"),
        dp("dlp.organization_id", "en", "dlp_organization_id", "Organization ID ", "ORG-2048"),
        dp("dlp.organization_id", "de", "dlp_organization_id", "Unternehmens-ID = ", "UNT/7781"),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: TENANT", "value contains no digit"),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Account ORG-2048", "missing organization anchor"),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Hallo Support,\nunsere Mandanten-ID ist ", "M-55012", ", der Login schlägt fehl.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "mandant:\n  organisations-id: ", "ORG-DE-4471", "\n", carrier="yaml",
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "2026-10-02 INFO Synchronisation gestartet, Mandanten-ID=", "T/0815", "\n", carrier="log",
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Die Unternehmens-ID lautet ", "U-2026-118", ".", carrier="prose",
        ),
        dp(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Organisations-ID: ", "ORG-77120",
        ),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: unbekannt", "value contains no digit"),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Kundennummer M-55012", "wrong identifier anchor"),
        dn(
            "dlp.organization_id", "de", "dlp_organization_id",
            "Die Mandanten-ID steht in den Einstellungen.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.organization_id", "de", "dlp_organization_id", "Mandanten-ID: <mandant>", "template placeholder"),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "Hi,\nour tenant ID is ", "ten-4471-eu", " and SSO stopped working.", carrier="prose", gap=True,
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "account:\n  tenant id: ", "TEN-2026-31", "\n", carrier="yaml",
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "2026-10-02 INFO sync started organization-id=", "ORG/5512", "\n", carrier="log",
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "Tenant-ID: ", "T-77120",
        ),
        dp(
            "dlp.organization_id", "en", "dlp_organization_id",
            "Organization ID = ", "ACME-0815",
        ),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Tenant ID: unknown", "value contains no digit"),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Customer number T-77120", "wrong identifier anchor"),
        dn(
            "dlp.organization_id", "en", "dlp_organization_id",
            "You can find the tenant ID in the admin console.", "anchor without a value", carrier="prose",
        ),
        dn("dlp.organization_id", "en", "dlp_organization_id", "Tenant ID: <tenant-id>", "template placeholder"),
    ],
    "dlp.internal.business_metric": [
        dp("dlp.internal.business_metric", "de", "dlp_internal_business_metric", "", "EBITDA-Marge: 6,1 Prozent"),
        dp("dlp.internal.business_metric", "en", "dlp_internal_business_metric", "", "Forecast: 12 Mio. EUR"),
        dp("dlp.internal.business_metric", "de", "dlp_internal_business_metric", "", "Umsatz beträgt 4.200 TEUR"),
        dn("dlp.internal.business_metric", "de", "dlp_internal_business_metric", "Umsatzbericht für August", "metric has no numeric value"),
        dn("dlp.internal.business_metric", "en", "dlp_internal_business_metric", "Margin improved considerably.", "unsupported English lexical anchor and no value"),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Vertraulich: Im dritten Quartal lag der ", "Umsatz bei 4,2 Mio. EUR", ", deutlich über Plan.", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "kennzahlen:\n  ", "rohertragsmarge: 38 %", "\n", carrier="yaml",
        ),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Hallo Ada, dein ", "Grundgehalt liegt ab Januar bei 72.000 EUR", ". Viele Grüße", carrier="prose", gap=True,
        ),
        dp(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "| Kennzahl | Wert |\n|---|---|\n| ", "Deckungsbeitrag: 1.250 TEUR", " |\n", carrier="markdown",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Der Umsatz ist im Vergleich zum Vorjahr gestiegen.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Die Marge wird im nächsten Meeting besprochen.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Gehaltsabrechnung: Fragen bitte an die Personalabteilung.", "anchor without a value",
        ),
        dn(
            "dlp.internal.business_metric", "de", "dlp_internal_business_metric",
            "Der Rabatt beträgt 10 Prozent auf alle Artikel.", "public price information", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Confidential: Q3 ", "Revenue at 18 Mio. EUR", ", ahead of plan.", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "metrics:\n  ", "gross margin: 41 %", "\n", carrier="yaml",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Hi Sam, your new ", "Base Salary is 85.000 EUR", " from January.", carrier="prose",
        ),
        dp(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "| Metric | Value |\n|---|---|\n| ", "EBITDA: 3.400 TEUR", " |\n", carrier="markdown",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Revenue grew faster than expected this year.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "The salary review happens every spring.", "metric without a value", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "Shipping is free for orders above 50 EUR.", "public price information", carrier="prose",
        ),
        dn(
            "dlp.internal.business_metric", "en", "dlp_internal_business_metric",
            "The forecast for tomorrow is sunny.", "weather forecast without a value", carrier="prose",
        ),
    ],
    "dlp.content.source_code": [
        dp("dlp.content.source_code", "en", "dlp_source_code_fence", "", "```python\nprint('internal')\n```"),
        dp("dlp.content.source_code", "de", "dlp_source_code_statement", "", "const client = new Client();"),
        dp("dlp.content.source_code", "en", "dlp_source_code_import", "", "from pathlib import Path"),
        dn("dlp.content.source_code", "de", "dlp_source_code_statement", "Der Client wird morgen aktualisiert.", "natural language is not source code"),
        dn("dlp.content.source_code", "en", "dlp_source_code_fence", "print the internal report", "prose lacks code syntax"),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_fence",
            "Kannst du kurz drüberschauen?\n", "```js\nconsole.log(kunde)\n```", "\nDanke!", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_import",
            "Fehlermeldung beim Start, die erste Zeile im Skript ist\n", "import pandas as pd", "\nund dann bricht es ab.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_declaration",
            "Ticket 4711: Die Funktion\n", "def berechne_rabatt(kunde):", "\nliefert negative Werte.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_python_rust_assignment",
            "Im Patch steht nur\n", "let mut zaehler = 0;", "\nmehr nicht.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "de", "dlp_source_code_statement",
            "Bitte diese Zeile ersetzen:\n", "let kunden = await ladeKunden(filiale);", "\n", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_import",
            "Import und Export laufen über das Portal.", "prose about imports", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_declaration",
            "Die Klasse 4b fährt am Freitag ins Museum.", "prose with a code keyword", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_python_rust_assignment",
            "Ergebnis = gut, Aufwand = gering", "prose with assignments",
        ),
        dn(
            "dlp.content.source_code", "de", "dlp_source_code_fence",
            "Bitte den Code als Block mit drei Backticks einfügen.", "prose about code formatting", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_declaration",
            "Can someone review this?\n", "class InvoiceExporter:", "\nIt fails on empty rows.", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_statement",
            "The bug is in this line:\n", "var total = items.reduce(sum, 0);", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_python_rust_assignment",
            "Config snippet from the service:\n", "retries = 5", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.source_code", "en", "dlp_source_code_import",
            "The traceback starts at\n", "import internal.billing.core", "\n", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_import",
            "Import duties apply to all shipments outside the EU.", "prose about imports", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_declaration",
            "The class starts at nine and ends at noon.", "prose with a code keyword", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_statement",
            "Let the team know when the build is green.", "prose with a code keyword", carrier="prose",
        ),
        dn(
            "dlp.content.source_code", "en", "dlp_source_code_python_rust_assignment",
            "Result = fine, effort = low", "prose with assignments",
        ),
    ],
    "dlp.content.sql": [
        dp("dlp.content.sql", "de", "dlp_sql_statement", "", "SELECT * FROM kunden WHERE aktiv = true;"),
        dp("dlp.content.sql", "en", "dlp_sql_statement", "", "UPDATE accounts SET active = false;"),
        dp("dlp.content.sql", "en", "dlp_sql_statement", "", "DELETE FROM sessions WHERE expired = true;"),
        dn("dlp.content.sql", "de", "dlp_sql_statement", "Bitte Kunden aus der Liste auswählen.", "natural language is not SQL"),
        dn("dlp.content.sql", "en", "dlp_sql_multiline_statement", "SELECT the best option FROM the list", "no terminating SQL statement structure"),
        dp(
            "dlp.content.sql", "de", "dlp_sql_multiline_statement",
            "Kannst du mal ", "SELECT name FROM bestellungen WHERE status = 'offen';", " ausführen und mir das Ergebnis schicken?",
            carrier="prose",
        ),
        dp(
            "dlp.content.sql", "de", "dlp_sql_statement",
            "", "-- Bereinigung der Testdaten\nDELETE FROM kunden\nWHERE erstellt < '2026-01-01';", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.sql", "de", "dlp_sql_statement",
            "Migration für die Filialen:\n", "ALTER TABLE filialen ADD COLUMN region TEXT;", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.sql", "de", "dlp_sql_multiline_statement",
            "query = \"", "SELECT iban FROM konten WHERE kunde_id = %s;", "\"\n", carrier="code",
        ),
        dn("dlp.content.sql", "de", "dlp_sql_multiline_statement", "Wähle aus der Liste und klicke auf Update.", "natural language is not SQL", carrier="prose"),
        dn("dlp.content.sql", "de", "dlp_sql_statement", "Die Tabelle wurde gestern gelöscht.", "natural language is not SQL", carrier="prose"),
        dn("dlp.content.sql", "de", "dlp_sql_statement", "SQL-Kurs: Abfragen mit Filtern und Sortierung", "topic title without a statement"),
        dn("dlp.content.sql", "de", "dlp_sql_multiline_statement", "Select-Box und From-Feld im Formular sind leer", "UI terms without SQL structure", carrier="prose"),
        dp(
            "dlp.content.sql", "en", "dlp_sql_multiline_statement",
            "Could you run ", "SELECT email FROM users WHERE plan = 'pro';", " and send me the list?", carrier="prose",
        ),
        dp(
            "dlp.content.sql", "en", "dlp_sql_statement",
            "", "-- weekly cleanup\nDELETE FROM audit_log\nWHERE created_at < now() - interval '90 days';", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.sql", "en", "dlp_sql_statement",
            "Migration notes:\n", "CREATE INDEX idx_orders_user ON orders (user_id);", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.sql", "en", "dlp_sql_multiline_statement",
            "cursor.execute(\"", "UPDATE users SET role = 'admin' WHERE id = %s;", "\", (user_id,))\n", carrier="code",
        ),
        dn("dlp.content.sql", "en", "dlp_sql_statement", "Please update the table in the wiki.", "natural language is not SQL", carrier="prose"),
        dn("dlp.content.sql", "en", "dlp_sql_statement", "Delete from the list anything older than a year", "natural language without a statement", carrier="prose"),
        dn("dlp.content.sql", "en", "dlp_sql_statement", "SQL tutorial: joins and filters", "topic title without a statement"),
        dn("dlp.content.sql", "en", "dlp_sql_multiline_statement", "Select a file from the dialog", "natural language is not SQL", carrier="prose"),
    ],
    "dlp.content.database_dump": [
        dp("dlp.content.database_dump", "en", "dlp_database_dump_header", "", "-- PostgreSQL database dump"),
        dp("dlp.content.database_dump", "de", "dlp_database_dump_insert", "", "INSERT INTO kunden VALUES (1, 'Ada');"),
        dp("dlp.content.database_dump", "en", "dlp_database_dump_header", "", "PRAGMA foreign_keys = ON;"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "Datenbankexport wurde abgeschlossen.", "natural language is not a dump"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_insert", "INSERT the row into the table", "prose lacks SQL dump syntax"),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_header",
            "--\n", "-- MySQL database dump", "\n--\n-- Host: db.intern    Datenbank: shop\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_insert",
            "-- Auszug aus dem Export\n", "INSERT INTO bestellungen (id, kunde, summe) VALUES (17, 'Beispiel', 99.5);", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_header",
            "Hier der Anfang der Sicherung:\n", "CREATE TABLE mitarbeiter (\n  id INTEGER PRIMARY KEY,\n  gehalt INTEGER\n);", "\n",
            carrier="prose",
        ),
        dp(
            "dlp.content.database_dump", "de", "dlp_database_dump_insert",
            "Im Anhang steht zum Beispiel\n", "INSERT INTO patienten VALUES (4, 'Muster', '1980-02-01');", "\n", carrier="prose",
        ),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "$ pg_dump --schema-only shop > schema.sql", "dump command, not dump content", carrier="cli"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_insert", "Die Insert-Taste ist kaputt.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "Die Sicherung der Datenbank läuft jede Nacht.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "de", "dlp_database_dump_header", "Tabellen werden mit CREATE TABLE angelegt.", "prose mentioning a keyword", carrier="prose"),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_header",
            "--\n", "-- MariaDB database dump", "\n--\n-- Host: localhost    Database: crm\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_insert",
            "-- excerpt from the export\n", "INSERT INTO users (id, email) VALUES (42, 'ada@example.org');", "\n", carrier="sql",
        ),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_header",
            "Here is the schema from the backup:\n", "CREATE TABLE payroll (\n  id INTEGER,\n  salary INTEGER\n);", "\n", carrier="prose",
        ),
        dp(
            "dlp.content.database_dump", "en", "dlp_database_dump_header",
            "sqlite> .dump\n", "PRAGMA foreign_keys=OFF;", "\nBEGIN TRANSACTION;\n", carrier="cli",
        ),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_header", "$ mysqldump --no-data crm > schema.sql", "dump command, not dump content", carrier="cli"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_insert", "Press Insert to add a new row.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_header", "The nightly database dump finished in 4 minutes.", "natural language is not a dump", carrier="prose"),
        dn("dlp.content.database_dump", "en", "dlp_database_dump_header", "Tables are created with CREATE TABLE by the ORM.", "prose mentioning a keyword", carrier="prose"),
    ],
    "dlp.content.system_log": [
        dp("dlp.content.system_log", "en", "dlp_structured_system_log", "", "2026-08-30T10:15:00Z ERROR database connection failed"),
        dp("dlp.content.system_log", "de", "dlp_structured_system_log", "", "2026-08-30 10:15:00 CRITICAL Speicherlimit erreicht"),
        dp("dlp.content.system_log", "en", "dlp_stacktrace_block", "", "Traceback (most recent call last):\n  File \"app.py\", line 4, in run"),
        dn("dlp.content.system_log", "de", "dlp_structured_system_log", "Der Fehler wurde gestern behoben.", "prose is not a structured log"),
        dn("dlp.content.system_log", "en", "dlp_structured_system_log", "2026-08-30 INFO service started", "non-sensitive INFO level is excluded"),
        dp(
            "dlp.content.system_log", "de", "dlp_structured_system_log",
            "Seit heute früh sehen wir das hier:\n", "2026-10-02 06:01:12 FEHLER Verbindung zur Kassen-DB abgebrochen", "\nWeiß jemand mehr?",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "de", "dlp_stacktrace_block",
            "Beim Export kommt:\n", "Exception in thread \"main\" java.lang.IllegalStateException: Kunde fehlt\n\tat de.beispiel.Export.run(Export.java:42)\n", "Danke!",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "de", "dlp_structured_system_log",
            "", "2026-10-02 06:01:12 ERROR Zahlungsdienst nicht erreichbar\n2026-10-02 06:01:13 ERROR Wiederholung fehlgeschlagen", "\n",
            carrier="log",
        ),
        dp(
            "dlp.content.system_log", "de", "dlp_stacktrace_block",
            "", "Traceback (most recent call last):\n  File \"/srv/abrechnung/job.py\", line 88, in main\n", "KeyError: 'kundennummer'\n",
            carrier="log",
        ),
        dn("dlp.content.system_log", "de", "dlp_structured_system_log", "2026-10-02 06:00:00 INFO Dienst gestartet", "non-sensitive INFO level is excluded", carrier="log"),
        dn("dlp.content.system_log", "de", "dlp_structured_system_log", "2026-10-02 06:00:00 WARN Festplatte zu 80 % voll", "WARN level is excluded", carrier="log"),
        dn("dlp.content.system_log", "de", "dlp_stacktrace_block", "Im Log steht ein Fehler, ich schaue morgen nach.", "prose about logs", carrier="prose"),
        dn("dlp.content.system_log", "de", "dlp_stacktrace_block", "Fehlerbehandlung ist im Handbuch beschrieben.", "prose with a log keyword", carrier="prose"),
        dp(
            "dlp.content.system_log", "en", "dlp_structured_system_log",
            "We keep seeing this since the deploy:\n", "2026-10-02T06:01:12Z FATAL payment worker crashed", "\nAny ideas?",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "en", "dlp_stacktrace_block",
            "The export fails with\n", "Exception in thread \"main\" java.lang.NullPointerException\n\tat com.example.Export.run(Export.java:17)\n", "Thanks!",
            carrier="prose",
        ),
        dp(
            "dlp.content.system_log", "en", "dlp_structured_system_log",
            "", "2026-10-02 06:01:12 ERROR billing queue unavailable\n2026-10-02 06:01:13 ERROR retry failed", "\n",
            carrier="log",
        ),
        dp(
            "dlp.content.system_log", "en", "dlp_stacktrace_block",
            "", "Traceback (most recent call last):\n  File \"/srv/billing/job.py\", line 12, in main\n", "ValueError: bad row\n",
            carrier="log",
        ),
        dn("dlp.content.system_log", "en", "dlp_structured_system_log", "2026-10-02 06:00:00 DEBUG cache warmed", "DEBUG level is excluded", carrier="log"),
        dn("dlp.content.system_log", "en", "dlp_structured_system_log", "2026-10-02 06:00:00 WARN disk 80% full", "WARN level is excluded", carrier="log"),
        dn("dlp.content.system_log", "en", "dlp_stacktrace_block", "There was an error in the log, I will check tomorrow.", "prose about logs", carrier="prose"),
        dn("dlp.content.system_log", "en", "dlp_stacktrace_block", "Error handling is described in the manual.", "prose with a log keyword", carrier="prose"),
    ],
}


# T06: documented example and test values per provider (marker words, repeated chunks,
# sequential and zero runs) are hard negatives; weak but real credentials stay positives.
# Provider-format values are `fill` recipes (generator shape filled with the word, check
# values zeroed), so the file holds no token in the exact provider format.
# Appended per label so the ids of the earlier rows stay stable.
DLP_T06_CASES = {
    "API_KEY": [
        dx(
            "API_KEY", "de", "dlp_anthropic_key",
            "# Beispiel aus der README, kein echter Schlüssel\nANTHROPIC_API_KEY=<<secret:0>>\n",
            "anthropic_api_key", "EXAMPLEKEY", "documented example value (EXAMPLE marker)", carrier="env",
        ),
        dx(
            "API_KEY", "en", "dlp_anthropic_key",
            "anthropic:\n  model: claude\n  api_key: <<secret:0>>\n",
            "anthropic_api_key", "TESTKEY", "test key (TESTKEY fill)", carrier="yaml",
        ),
        dx(
            "API_KEY", "de", "dlp_openai_key",
            "Kopiere .env.beispiel nach .env:\nOPENAI_API_KEY=<<secret:0>>\n",
            "openai_project_key", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="env",
        ),
        dx(
            "API_KEY", "en", "dlp_openai_key",
            "client = OpenAI(api_key=\"<<secret:0>>\")\n",
            "openai_project_key", "DUMMY", "dummy value in a unit test", carrier="code",
        ),
        dx(
            "API_KEY", "de", "dlp_openai_legacy",
            "openai.api_key = \"<<secret:0>>\"  # Musterwert\n",
            "openai_legacy_key", "MUSTER", "documented example value (MUSTER marker)", carrier="code",
        ),
        dx(
            "API_KEY", "en", "dlp_openai_legacy",
            "OPENAI_API_KEY=<<secret:0>>\n",
            "openai_legacy_key", "FAKE", "fake value (repeated FAKE marker)", carrier="env",
        ),
        dx(
            "API_KEY", "de", "dlp_openai_svc",
            "Service-Account (Beispiel): <<secret:0>>",
            "openai_service_account_key", "SAMPLE", "documented example value (SAMPLE marker)", carrier="prose",
        ),
        dx(
            "API_KEY", "en", "dlp_openai_svc",
            "{\"openai\": {\"service_account_key\": \"<<secret:0>>\"}}",
            "openai_service_account_key", "TESTKEY", "test key (TESTKEY fill)", carrier="json",
        ),
        dx(
            "API_KEY", "de", "dlp_huggingface",
            "$ huggingface-cli login --token <<secret:0>>\n",
            "huggingface_token", "example", "documented example value (example marker)", carrier="cli",
        ),
        dx(
            "API_KEY", "en", "dlp_huggingface",
            "HF_TOKEN=<<secret:0>>\n",
            "huggingface_token", "test", "test value (repeated test marker)", carrier="env",
        ),
        dx(
            "API_KEY", "de", "dlp_groq_key",
            "[groq]\nschluessel = \"<<secret:0>>\"\n",
            "groq_key", "BEISPIELKEY", "documented example value (BEISPIEL marker)", carrier="toml",
        ),
        dx(
            "API_KEY", "en", "dlp_groq_key",
            "2026-10-19T08:00:00Z INFO using fixture key <<secret:0>>",
            "groq_key", "TESTKEY", "test key (TESTKEY fill)", carrier="log",
        ),
        dx(
            "API_KEY", "de", "dlp_xai_key",
            "XAI_API_KEY=<<secret:0>>\n",
            "xai_api_key", "MUSTERKEY", "documented example value (MUSTER marker)", carrier="env",
        ),
        dx(
            "API_KEY", "en", "dlp_xai_key",
            "Replace the sample key <<secret:0>> with your own.",
            "xai_api_key", "EXAMPLE", "documented example value (EXAMPLE marker)", carrier="prose",
        ),
        dx(
            "API_KEY", "de", "dlp_replicate",
            "replicate:\n  zugang: <<secret:0>>\n",
            "replicate_api_token", "DUMMY", "dummy value (repeated DUMMY marker)", carrier="yaml",
        ),
        dx(
            "API_KEY", "en", "dlp_replicate",
            "export REPLICATE_API_TOKEN=<<secret:0>>\n",
            "replicate_api_token", "test", "test value (repeated test marker)", carrier="cli",
        ),
    ],
    "CLOUD_KEY": [
        dx(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "Beispielwert aus der AWS-Doku: <<secret:0>>",
            "aws_access_key_id", "EXAMPLE", "documented example value (EXAMPLE marker)", carrier="prose",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "[default]\naws_access_key_id = <<secret:0>>\n",
            "aws_session_access_key_id", "TESTKEY", "test key (TESTKEY fill)", carrier="ini",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "aws_secret_access_key = <<secret:0>>\n",
            "aws_secret_access_key", "EXAMPLEKEY", "documented example value (EXAMPLEKEY fill)", carrier="ini",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "AWS_SECRET_ACCESS_KEY=<<secret:0>>\n",
            "aws_secret_access_key", "TESTKEY", "test key (TESTKEY fill)", carrier="env",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_google_api_key",
            "<meta name=\"maps-key\" content=\"<<secret:0>>\">",
            "google_api_key", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="xml",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_google_api_key",
            "GOOGLE_MAPS_API_KEY=<<secret:0>>\n",
            "google_api_key", "DUMMYKEY", "dummy value (repeated DUMMY marker)", carrier="env",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_google_oauth_token",
            "Authorization-Beispiel: <<secret:0>>",
            "google_oauth_access_token", "EXAMPLE", "documented example value (EXAMPLE marker)", carrier="prose",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_google_oauth_token",
            "{\"access_token\": \"<<secret:0>>\", \"expires_in\": 3599}",
            "google_oauth_access_token", "test", "test value (repeated test marker)", carrier="json",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_gcp_client_secret",
            "GOOGLE_CLIENT_SECRET=<<secret:0>>\n",
            "gcp_oauth_client_secret", "MUSTER", "documented example value (MUSTER marker)", carrier="env",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_gcp_client_secret",
            "oauth:\n  client_secret: <<secret:0>>\n",
            "gcp_oauth_client_secret", "SAMPLE", "documented example value (SAMPLE marker)", carrier="yaml",
        ),
    ],
    "CREDENTIAL": [
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# Beispielwerte aus der Doku, nicht produktiv\ndb:\n  passwort: abcabcabcabc\n",
            "repeated chunk in explicit example context", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "Example from the docs:\napi_key = 1234567890abcdef1234567890abcdef\n",
            "sequential run in explicit example context", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "client_secret = \"beispiel-geheimnis-2026\"\n",
            "documented example value (Beispiel marker)", carrier="toml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "password: dummy_password_42\n",
            "dummy value (DUMMY marker word)", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "SERVICE_TOKEN=test-token-nur-fuer-ci\n",
            "test value (TEST marker word)", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_credential_in_url",
            "curl \"https://api.example.com/v1/export?format=csv&api_key=SAMPLEKEY4711\"",
            "documented example value (SAMPLE marker)", carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Zugang zum Staging-Server\nBenutzer: deploy\nPasswort: <<secret:0>>\n",
            "weak_repeated_password", 6001, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[database]\nhost = db.internal\npassword = <<secret:0>>\n",
            "weak_repeated_password", 6002, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "zahlungsdienst:\n  client_secret: <<secret:0>>\n",
            "weak_sequential_run_token", 6003, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "billing = BillingClient()\ntoken = \"<<secret:0>>\"\nbilling.connect(token)\n",
            "weak_sequential_run_token", 6004, carrier="code",
        ),
    ],
    "CRYPTO_KEY": [
        dx(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "WALLET_PRIVATE_KEY=<<secret:0>>\n",
            "eth_private_key_hex", "deadbeef", "repeated chunk (deadbeef fill)", carrier="env",
        ),
        dx(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "const signer = new Wallet(\"<<secret:0>>\");\n",
            "eth_private_key_hex", "1234567890", "sequential run (1234567890 fill)", carrier="code",
        ),
        dx(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Beispiel-WIF aus dem Tutorial: <<secret:0>>",
            "btc_wif_uncompressed", "EXAMPLEKEY", "documented example value (EXAMPLE marker)", carrier="prose",
        ),
        dx(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "wallet:\n  wif: <<secret:0>>\n",
            "btc_wif_uncompressed", "TESTKEY", "test key (TESTKEY fill)", carrier="yaml",
        ),
    ],
    "PASSWORD_HASH": [
        dx(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "Passwort-Hash: <<secret:0>>",
            "md5_hex", "deadbeef", "repeated chunk (deadbeef fill)", carrier="prose",
        ),
        dx(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "password_hash: \"<<secret:0>>\"\n",
            "bcrypt_hash", "EXAMPLEKEY", "documented example value (EXAMPLE marker)", carrier="yaml",
        ),
    ],
    "PAYMENT_KEY": [
        dx(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "STRIPE_SECRET_KEY=<<secret:0>>\n",
            "stripe_secret_live", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="env",
        ),
        dx(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "stripe.api_key = \"<<secret:0>>\"\n",
            "stripe_restricted_test", "TESTKEY", "test key (TESTKEY fill)", carrier="code",
        ),
        dx(
            "PAYMENT_KEY", "de", "dlp_stripe_webhook",
            "webhook:\n  geheimnis: <<secret:0>>\n",
            "stripe_webhook_secret", "example", "documented example value (example marker)", carrier="yaml",
        ),
        dx(
            "PAYMENT_KEY", "en", "dlp_stripe_webhook",
            "STRIPE_WEBHOOK_SECRET=<<secret:0>>\n",
            "stripe_webhook_secret", "DUMMY", "dummy value (repeated DUMMY marker)", carrier="env",
        ),
    ],
    "SECRET_TOKEN": [
        dx(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "GITHUB_TOKEN=<<secret:0>>\n",
            "github_ghp_token", "EXAMPLEKEY", "documented example value (EXAMPLE marker, zero checksum)", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "git clone https://x-access-token:<<secret:0>>@github.com/acme/app.git",
            "github_gho_token", "TESTKEY", "test key (TESTKEY fill, zero checksum)", carrier="cli",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_github_pat",
            "Beispiel: <<secret:0>>",
            "github_fine_grained_pat", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="prose",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "GH_TOKEN=<<secret:0>>\n",
            "github_fine_grained_pat", "SAMPLE", "documented example value (SAMPLE marker)", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "gitlab:\n  token: <<secret:0>>\n",
            "gitlab_pat", "MUSTER", "documented example value (MUSTER marker)", carrier="yaml",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_gitlab_pat",
            "GITLAB_TOKEN=<<secret:0>>\n",
            "gitlab_pat", "TESTKEY", "test key (TESTKEY fill)", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "//registry.npmjs.org/:_authToken=<<secret:0>>",
            "npm_access_token", "EXAMPLE", "documented example value (EXAMPLE marker, zero checksum)", carrier="ini",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "NPM_TOKEN=<<secret:0>>\n",
            "npm_access_token", "test", "test value (repeated test marker, zero checksum)", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_slack_token",
            "SLACK_TOKEN=<<secret:0>>\n",
            "slack_bot_token", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_slack_token",
            "slack:\n  user_token: <<secret:0>>\n",
            "slack_user_token", "1234567890", "sequential run (1234567890 fill)", carrier="yaml",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_discord_token",
            "DISCORD_BOT_TOKEN=<<secret:0>>\n",
            "discord_bot_token", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "client.login(\"<<secret:0>>\")\n",
            "discord_bot_token", "FAKE", "fake value (repeated FAKE marker)", carrier="code",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_jwt_token",
            "id_token: <<secret:0>>\n",
            "jwt_signed_hs256", "BEISPIEL", "documented example value (BEISPIEL marker)", carrier="yaml",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "ID_TOKEN=<<secret:0>>\n",
            "jwt_signed_hs256", "TEST", "test value (repeated TEST marker)", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "Authorization: Bearer BEISPIEL-TOKEN-4711",
            "documented example value (Beispiel marker)", carrier="http",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "X-CSRF-Token: example-csrf-token-4711",
            "documented example value (example marker)", carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "# CI-Zugang des Release-Jobs\nGITHUB_TOKEN=<<secret:0>>\n",
            "weak_repeated_chunk_github_token", 6005, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "git clone https://x-access-token:<<secret:0>>@github.com/acme/app.git",
            "weak_repeated_chunk_github_token", 6006, carrier="cli",
        ),
    ],
}
for _label, _rows in DLP_T06_CASES.items():
    DLP_CASES[_label].extend(_rows)


# T07: placeholders (YOUR_…_HERE, HIER_…_EINTRAGEN, BITTE_AENDERN, TODO, REPLACE_ME, kebab
# YOUR-API-TOKEN, masks) and references to the environment or a template ($VAR, ${VAR},
# %VAR%, {{var}}, var.x, os.environ[…], ENV.fetch(…), os.Getenv, System.getenv,
# Environment.GetEnvironmentVariable) in value-capturing rules are hard negatives. Real values
# next to such references and placeholder-like real passwords stay positives.
DLP_T07_CASES = {
    "CREDENTIAL": [
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Vorlage: Werte vor dem ersten Start setzen\nDB_PASSWORT=HIER_DB_PASSWORT_EINTRAGEN\nAPP_PORT=8080\n",
            "placeholder HIER_…_EINTRAGEN", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "datenbank:\n  host: db.intern\n  passwort: BITTE_AENDERN\n",
            "placeholder BITTE_AENDERN", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "module Abgleich\n  class Client\n    SERVICE_TOKEN = ENV.fetch(\"SERVICE_TOKEN\")\n  end\nend\n",
            "Ruby ENV.fetch reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "provider \"objektspeicher\" {\n  region        = \"eu-central-1\"\n  client_secret = var.client_secret\n}\n",
            "Terraform variable reference var.x", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "GET /v1/lieferungen?status=offen HTTP/1.1\nHost: api.example.de\nClient-Secret: {{clientSecret}}\n",
            "Handlebars template reference {{var}}", carrier="http",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_credential_in_url",
            "$ curl -sS \"https://api.example.de/v1/export?format=csv&api_key=$EXPORT_API_KEY\"\n",
            "shell variable $VAR", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "$ export SERVICE_TOKEN=\"$VAULT_SERVICE_TOKEN\"\n$ ./bin/abgleich --einmalig\n",
            "shell variable $VAR in quotes", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "DATABASE_URL=postgres://app:HIER_PASSWORT_EINTRAGEN@db.intern:5432/lager\n",
            "placeholder HIER_…_EINTRAGEN in URL userinfo", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_signed_url_signature",
            "Download-Link: https://dateien.example.de/bericht.zip?Expires=1767225600&Signature=HIER_SIGNATUR_EINTRAGEN",
            "placeholder HIER_…_EINTRAGEN as signature", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "// Client für den Berichtsdienst\nprivate static readonly string ClientSecret = Environment.GetEnvironmentVariable(\"CLIENT_SECRET\");\n",
            "C# Environment.GetEnvironmentVariable reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "import os\n\nDB_KENNWORT = os.environ[\"DB_KENNWORT\"]\n",
            "Python os.environ[…] reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# .env.example - copy to .env\nDB_PASSWORD=YOUR_DB_PASSWORD_HERE\nAPP_PORT=8080\n",
            "placeholder YOUR_…_HERE", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[database]\nhost = db.internal\npassword = TODO\n",
            "placeholder TODO", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "import os\n\nclient_secret = os.environ[\"CLIENT_SECRET\"]\n",
            "Python os.environ[…] reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "package billing\n\nimport \"os\"\n\nvar clientSecret = os.Getenv(\"CLIENT_SECRET\")\n",
            "Go os.Getenv reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "resource \"aws_db_instance\" \"reports\" {\n  username = \"app\"\n  password = var.db_password\n}\n",
            "Terraform variable reference var.x", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_credential_in_url",
            "$ curl -sS \"https://api.example.com/v1/export?format=csv&api_key=YOUR_API_KEY_HERE\"\n",
            "placeholder YOUR_…_HERE in a query parameter", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "cache:\n  url: redis://default:REPLACE_ME@cache:6379/0\n",
            "placeholder REPLACE_ME in URL userinfo", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "<appSettings>\n  <add key=\"Region\" value=\"eu-central-1\" />\n</appSettings>\n"
            "2026-09-14 08:12:03 DEBUG effective config: client_secret=%CLIENT_SECRET% retries=3\n",
            "Windows environment reference %VAR%", carrier="log",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "require \"net/http\"\n\nmodule Acme\n  API_TOKEN = ENV[\"API_TOKEN\"]\nend\n",
            "Ruby ENV[…] reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\"cells\": [{\"cell_type\": \"code\", \"source\": [\"api_key = \\\"********\\\"\\n\", \"client = Client(api_key)\"]}]}",
            "masked value in a JSON-escaped notebook cell", carrier="json",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# TODO: in den Vault verschieben\nAPI_BASIS=${API_BASIS_URL}\nDB_PASSWORT=<<secret:0>>\n",
            "password", 7001, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "datenbank:\n  host: db.intern\n  benutzer: ${DB_BENUTZER}\n  passwort: <<secret:0>>\n",
            "weak_snake_case_password", 7002, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Hallo Jonas, das Passwort lautet <<secret:0>> (nicht $DB_PASSWORT, das ist nur die Variable).",
            "weak_dollar_password", 7003, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_credential_in_url",
            "GET {{basisUrl}}/v1/export?format=csv&api_key=<<secret:0>> HTTP/1.1\nHost: {{host}}\n",
            "url_token", 7004, carrier="http",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# ersetzt ${DATABASE_URL} bis zur Umstellung\nDATABASE_URL=postgres://app:<<secret:0>>@db.intern:5432/lager\n",
            "url_userinfo_password", 7005, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "import os\n\nREGION = os.environ[\"REGION\"]\napi_key = \"<<secret:0>>\"\n",
            "generic_api_secret", 7006, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# replace YOUR_DB_PASSWORD_HERE before deploying\nDB_PASSWORD=<<secret:0>>\n",
            "weak_snake_case_password", 7007, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "smtp:\n  user: ${SMTP_USER}\n  password: <<secret:0>>\n",
            "weak_dollar_password", 7008, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_signed_url_signature",
            "$ curl -o report.pdf \"https://reports.s3.eu-central-1.amazonaws.com/report.pdf"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=<<secret:0>>\"\n",
            "aws_sigv4_signature", 7009, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "provider \"acme\" {\n  region        = var.region\n  client_secret = \"<<secret:0>>\"\n}\n",
            "generic_api_secret", 7010, carrier="code",
        ),
    ],
    "SECRET_TOKEN": [
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "GET /v1/konten HTTP/1.1\nHost: api.example.de\nAuthorization: Bearer HIER_TOKEN_EINTRAGEN\n",
            "placeholder HIER_…_EINTRAGEN as bearer token", carrier="http",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "X-CSRF-Token: HIER_CSRF_TOKEN_EINTRAGEN",
            "placeholder HIER_…_EINTRAGEN as CSRF token", carrier="http",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "// Zugang zum Formulardienst\nString csrfToken = System.getenv(\"CSRF_TOKEN\");\n",
            "Java System.getenv reference", carrier="code",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "$ curl -H \"Authorization: Bearer YOUR-API-TOKEN\" https://api.example.com/v1/me\n",
            "kebab placeholder YOUR-API-TOKEN", carrier="cli",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "package forms\n\nvar csrfToken = os.Getenv(\"CSRF_TOKEN\")\n",
            "Go os.Getenv reference", carrier="code",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "variable \"csrf_token\" {}\n\nlocals {\n  csrf_token = var.csrf_token\n}\n",
            "Terraform variable reference var.x", carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "GET {{basisUrl}}/v1/konten HTTP/1.1\nHost: {{host}}\nAuthorization: Bearer <<secret:0>>\n",
            "bearer_opaque_token", 7011, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "POST /formular HTTP/1.1\nX-CSRF-Token: <<secret:0>>\nX-Request-Id: {{requestId}}\n",
            "csrf_token", 7012, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "$ export API_URL=$BASE_URL\n$ curl -H \"Authorization: Bearer <<secret:0>>\" \"$API_URL/v1/me\"\n",
            "bearer_opaque_token", 7013, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "username=${USER}&csrf_token=<<secret:0>>",
            "csrf_token", 7014, carrier="http",
        ),
    ],
}
for _label, _rows in DLP_T07_CASES.items():
    DLP_CASES[_label].extend(_rows)



# K04: the score model in `balanced` (rows name `dlp_mode`). Positives reach the threshold
# through a field name, a provider format or a credential term next to a value without a
# field name (wallet keys). Hard negatives are hex values that `strict` reports as Ethereum
# keys, but that a nearer digest/hash term (tx hash, checksum, Prüfsumme) or the absence of
# any credential term keeps below the threshold.
DLP_K04_CASES = {
    "CRYPTO_KEY": [
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "wallet:\n  network: mainnet\n  private_key: <<secret:0>>\n",
            "eth_private_key_hex", 8001, carrier="yaml", mode="balanced",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Privater Schlüssel des Hot-Wallets: <<secret:0>>",
            "eth_private_key_hex", 8002, carrier="prose", mode="balanced",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Paper wallet backup, private key (WIF): <<secret:0>>",
            "btc_wif_mainnet_compressed", 8003, carrier="prose", mode="balanced",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Papier-Backup der Wallet, privater Schlüssel im WIF-Format: <<secret:0>>",
            "btc_wif_mainnet_compressed", 8004, carrier="prose", mode="balanced",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "2026-10-20T08:15:02Z INFO relay: tx hash: <<secret:0>> confirmed\n",
            "eth_private_key_hex", 8011, "transaction hash (counter-context tx hash)", carrier="log",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "Block 18 sealed, block hash <<secret:0>>",
            "eth_private_key_hex", 8012, "block hash (counter-context block hash)", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "The Merkle root <<secret:0>> matches the header.",
            "eth_private_key_hex", 8013, "Merkle root without any credential term", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "release:\n  artifact: node.tar.gz\n  checksum: <<secret:0>>\n",
            "eth_private_key_hex", 8014, "release checksum (counter-context key)", carrier="yaml",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "{\"status\": \"ok\", \"transactionHash\": \"<<secret:0>>\"}",
            "eth_private_key_hex", 8015, "transaction hash in an RPC receipt, no credential term", carrier="json",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Transaktionshash: <<secret:0>> (bestätigt)",
            "eth_private_key_hex", 8016, "Transaktionshash (Gegenkontext)", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Laut Explorer wurde der Blockhash <<secret:0>> bestätigt.",
            "eth_private_key_hex", 8017, "Blockhash (Gegenkontext)", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Prüfsumme der Datei: <<secret:0>>",
            "eth_private_key_hex", 8018, "Prüfsumme (Gegenkontext)", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Die Zustandswurzel <<secret:0>> stimmt mit dem Header überein.",
            "eth_private_key_hex", 8019, "Zustandswurzel ohne Zugangsdaten-Begriff", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "[INFO] Abgleich ok, Hashwert <<secret:0>>\n",
            "eth_private_key_hex", 8020, "Hashwert (Gegenkontext)", carrier="log",
        ),
    ],
    "API_KEY": [
        ds(
            "API_KEY", "en", "dlp_openai_key", "OPENAI_API_KEY=<<secret:0>>\nOPENAI_MODEL=gpt\n",
            "openai_project_key", 8021, carrier="env", mode="balanced",
        ),
    ],
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "Schritt 3/5: export GITHUB_TOKEN=<<secret:0>>\n",
            "github_ghp_token", 8022, carrier="log", mode="balanced",
        ),
    ],
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "database:\n  host: db.internal\n  password: <<secret:0>>\n",
            "password", 8023, carrier="yaml", mode="balanced",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Das Passwort lautet <<secret:0>>, bitte nach dem ersten Login ändern.",
            "password", 8024, carrier="prose", mode="balanced",
        ),
    ],
    "CLOUD_KEY": [
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "[default]\naws_access_key_id = AKIA_SIEHE_TRESOR\naws_secret_access_key = <<secret:0>>\n",
            "aws_secret_access_key", 8025, carrier="ini", mode="balanced",
        ),
    ],
    "PRIVATE_KEY": [
        ds(
            "PRIVATE_KEY", "en", "dlp_private_key_block",
            "const SERVER_KEY = `<<secret:0>>`;\n",
            "pem_pkcs8_private_key", 8026, carrier="code", mode="balanced",
        ),
    ],
}
for _label, _rows in DLP_K04_CASES.items():
    DLP_CASES[_label].extend(_rows)


# K06: template and secret-manager references beyond T07 (Python `%(name)s` and `{name}`,
# Maven `@name@`, replace tokens `__NAME__`, Concourse `((name))`, Home Assistant
# `!secret name`, CloudFormation `!Ref`, 1Password `op://`, vals `ref+vault://`, Azure
# `@Microsoft.KeyVault(…)`, AWS Secrets Manager ARNs), DE/EN placeholders (`…_EINGEBEN`,
# `null`, the keystore default `changeit`, masks around a word such as `***ENTFERNT***`) and
# values that only name the credential (`my-access-token`, `secret_token`) are hard negatives.
# Real values next to such references stay positives. Vendor-documented example values and
# test keys are assembled at test time (rust/tests/dlp_documented_values.rs), never stored.
DLP_K06_CASES = {
    "CREDENTIAL": [
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Vorlage für den Lagerdienst\nDB_PASSWORT=PASSWORT_HIER_EINGEBEN\nAPP_PORT=8080\n",
            "placeholder …_HIER_EINGEBEN", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "import psycopg\n\nDSN = \"postgresql://lager:%(passwort)s@db.intern:5432/lager\"\n",
            "Python %-format reference %(name)s in URL userinfo", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "wifi:\n  ssid: Lager-WLAN\n  password: !secret wlan_passwort\n",
            "Home Assistant/ESPHome !secret reference", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# wird beim Maven-Build gefiltert\ndatenbank.url=jdbc:postgresql://db.intern/lager\ndatenbank.passwort=@db.passwort@\n",
            "Maven resource filter token @name@", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Schlüssel liegen im Key Vault\nDB_PASSWORT=@Microsoft.KeyVault(SecretUri=https://lager-kv.vault.azure.net/secrets/db-passwort/)\n",
            "Azure Key Vault reference @Microsoft.KeyVault(…)", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "jobs:\n- name: abgleich\n  plan:\n  - task: export\n    params:\n      passwort: ((lager.db_passwort))\n",
            "Concourse credential reference ((name))", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "2026-10-02 08:00:01 INFO Konfiguration geladen: SMTP_PASSWORT=***ENTFERNT*** SMTP_HOST=mail.intern\n",
            "mask around a redaction word ***ENTFERNT***", carrier="log",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "# JKS default, the real one comes from the vault\nkeystore.path=/etc/app/keystore.jks\nkeystore.password=changeit\n",
            "documented keystore default changeit", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "database:\n  host: db.internal\n  user: app\n  password: null\n",
            "null value", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "def dsn(db_password: str) -> str:\n    return f\"postgres://app:{db_password}@db.internal:5432/app\"\n",
            "Python f-string reference {name} in URL userinfo", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# resolved by `op run --env-file=.env`\nDB_PASSWORD=op://Production/postgres/password\n",
            "1Password secret reference op://", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# Azure Pipelines replace tokens\nDB_PASSWORD=__DB_PASSWORD__\nDB_HOST=__DB_HOST__\n",
            "replace token __NAME__", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "SERVICE_TOKEN=arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/service-token-AbCdEf\n",
            "AWS Secrets Manager ARN", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "db:\n  password: ref+vault://secret/data/app#db_password\n",
            "vals secret reference ref+vault://", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "$ git clone https://x-token-auth:my-access-token@bitbucket.org/acme/repo.git\n",
            "value that only names the credential (my-access-token)", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "FROM nginx:1.27-alpine\nENV API_KEY=\"**None**\" \\\n    BASE_URL=\"\"\n",
            "mask around a placeholder word **None**", carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# PASSWORT_HIER_EINGEBEN wurde ersetzt\nDB_BENUTZER=__DB_BENUTZER__\nDB_PASSWORT=<<secret:0>>\n",
            "password", 9601, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "wifi:\n  ssid: !secret wlan_ssid\n  password: <<secret:0>>\n",
            "password", 9602, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "datenbank.benutzer=@db.benutzer@\ndatenbank.passwort=<<secret:0>>\n",
            "weak_snake_case_password", 9603, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# früher postgresql://lager:%(passwort)s@db.intern/lager\nDATABASE_URL=postgres://lager:<<secret:0>>@db.intern:5432/lager\n",
            "url_userinfo_password", 9604, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Hallo Team, im Vault steht noch ((lager.db_passwort)), das Passwort lautet <<secret:0>> und gilt bis Freitag.",
            "password", 9605, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "truststore.password=changeit\nkeystore.password=<<secret:0>>\n",
            "password", 9606, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "PRIMARY = f\"postgres://app:{db_password}@db.internal/app\"\nFALLBACK = \"postgres://app:<<secret:0>>@db.internal/app\"\n",
            "url_userinfo_password", 9607, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "DB_HOST=op://Production/postgres/host\nDB_PASSWORD=<<secret:0>>\n",
            "password", 9608, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "db:\n  password: ref+vault://secret/data/app#db_password\napi_key: \"<<secret:0>>\"\n",
            "generic_api_secret", 9609, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "2026-10-02 08:00:01 WARN legacy login enabled, password=<<secret:0>> (was ***REMOVED***)\n",
            "weak_dollar_password", 9610, carrier="log",
        ),
    ],
    "SECRET_TOKEN": [
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "# Release-Pipeline ersetzt die Tokens\nGET /v1/lager HTTP/1.1\nHost: api.example.de\nAuthorization: Bearer __ZUGRIFFSTOKEN__\n",
            "replace token __NAME__ as bearer token", carrier="http",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "it('sends the header', () => {\n  expect(request.headers).to.include('Authorization: Bearer secret_token')\n})\n",
            "value that only names the credential (secret_token)", carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "GET /v1/lager HTTP/1.1\nX-Request-Id: __REQUEST_ID__\nAuthorization: Bearer <<secret:0>>\n",
            "bearer_opaque_token", 9611, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "$ curl -H \"X-Trace: {trace_id}\" -H \"Authorization: Bearer <<secret:0>>\" https://api.example.com/v1/me\n",
            "bearer_opaque_token", 9612, carrier="cli",
        ),
    ],
}
for _label, _rows in DLP_K06_CASES.items():
    DLP_CASES[_label].extend(_rows)


# K07: the rule prefilter (one keyword pass for all rules, searches near the keyword hits,
# value runs for keywordless rules) must not change a result. Positives put the keyword in
# upper case, after multi-byte text (umlauts, dashes, check marks) or spell it with LONG S,
# which `(?i)` matches and the ASCII keyword search does not; keywordless Discord tokens and
# WIF keys sit in a log line and in JSON. Hard negatives keep the keyword without a value
# (prose, a line break between keyword and value, a KELVIN SIGN next to a keyword) or fall
# one character short of the value run (a 50-character Base58 checksum, a 22-character
# first token segment).
DLP_K07_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "# Zugangsdaten für den Lagerdienst – bitte nicht ändern ✓\nÄnderung: 2026-10-02\n"
            "lager:\n  api_key: \"<<secret:0>>\"\n",
            "generic_api_secret", 9701, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Das Paſſwort lautet <<secret:0>> und gilt bis Freitag.",
            "password", 9702, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "GEHEIMNIS=<<secret:0>>\n", "generic_api_secret", 9703, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# credentials for the staging bucket — do not commit ✓\nstaging:\n"
            "  client_secret: \"<<secret:0>>\"\n",
            "generic_api_secret", 9706, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "The paſſword is <<secret:0>> until Friday.",
            "password", 9707, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "deploy:\n  ACCESS-TOKEN: <<secret:0>>\n", "generic_api_secret", 9708, carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Der API-Schlüssel wird über den Tresor verteilt; Änderungen nur per Ticket.",
            "keyword in prose without a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Temperatur im Serverraum: 295 K, Geheimnis gibt es keines.",
            "KELVIN SIGN next to a keyword without a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "api\n_key = wird_spaeter_gesetzt\n",
            "line break inside the keyword", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "The API key comes from the vault; changes go through a ticket.",
            "keyword in prose without a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "Server room temperature: 295 K, there is no secret here.",
            "KELVIN SIGN next to a keyword without a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "token\n= see the deployment guide\n",
            "keyword and separator on different lines without a value", carrier="ini",
        ),
    ],
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_discord_token",
            "2026-10-02 08:00:01 INFO Bot verbunden, Token im Klartext: <<secret:0>>\n",
            "discord_bot_token", 9704, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "2026-10-02 08:00:01 WARN bot login with token in plain text: <<secret:0>>\n",
            "discord_bot_token", 9709, carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_discord_token",
            "Build-Kennung: M3mwqAC3eoS9CiOqC0tvUm.GSUONX.LkWWUmlfNM5CSVg24WnFVExCCnFEA9",
            "first segment one character short of the value run", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_discord_token",
            "Build id: NcGJJ0YBrix5VSApTFiuyC.kSVOq7.GV0bmSrgTSCwaNTiOut07XUZaxLAAs",
            "first segment one character short of the value run", carrier="log",
        ),
    ],
    "CRYPTO_KEY": [
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "{\"wallet\": {\"netz\": \"mainnet\", \"wif\": \"<<secret:0>>\"}}",
            "btc_wif_mainnet_compressed", 9705, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "{\"wallet\": {\"network\": \"mainnet\", \"wif\": \"<<secret:0>>\"}}",
            "btc_wif_mainnet_uncompressed", 9710, carrier="json",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Prüfsumme (Base58): 52fhNZpbWj1ZyacvjL8YW3h5JrU7xfkJiVJniWVGcSQgJYV7Tg",
            "Base58 run one character short of a WIF key",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Checksum (Base58): KuW6WXvRgxZC1WhjNLfK1PaKWtuS4TL9BMzbtxDbDxbUVhtk7s",
            "Base58 run one character short of a WIF key",
        ),
    ],
}
for _label, _rows in DLP_K07_CASES.items():
    DLP_CASES[_label].extend(_rows)


# K08: overlap resolution. Where several rules match one value, one span stays, by tier
# (provider > token > hash > credential > generic): a URL password inside a generic
# `token:` assignment is the URL credential, a quoted env value gives way to the unquoted
# value span of the assignment rule, provider keys and JWTs win over the quoted env value.
# Hard negatives are the DLP side of the PII double label: e-mail-shaped userinfo without a
# password (database URLs, SSH remotes, SMTP URLs), an empty or templated URL password after
# the userinfo `token:`, and plain e-mail addresses in prose.
DLP_K08_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# Spiegel des Lager-Repositorys einrichten\n"
            "$ git remote set-url origin https://token:<<secret:0>>@bitbucket.org/acme/lager.git\n",
            "generic_api_secret", 9801, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "[remote \"origin\"]\n  url = https://token:<<secret:0>>@git.example.de/team/abgleich.git\n"
            "  fetch = +refs/heads/*:refs/remotes/origin/*\n",
            "generic_api_secret", 9802, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "$ export CLIENT_SECRET='<<secret:0>>'\n$ ./bin/abgleich --trocken\n"
            "Abgleich von 214 Belegen … fertig\n",
            "generic_api_secret", 9803, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "# mirror the warehouse repository\n"
            "$ git remote set-url origin https://token:<<secret:0>>@bitbucket.org/acme/warehouse.git\n",
            "generic_api_secret", 9806, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "[remote \"origin\"]\n  url = https://token:<<secret:0>>@git.example.com/team/sync.git\n"
            "  fetch = +refs/heads/*:refs/remotes/origin/*\n",
            "generic_api_secret", 9807, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "$ export CLIENT_SECRET=\"<<secret:0>>\"\n$ ./bin/sync --dry-run\nsynced 214 objects … done\n",
            "generic_api_secret", 9808, carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "DATABASE_URL=postgres://lager@db.intern:5432/lager\n",
            "userinfo without a password reads as e-mail address", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "$ git remote add spiegel git@bitbucket.org:acme/lager.git\n",
            "SSH remote userinfo without a secret", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "$ git remote set-url origin https://token:@bitbucket.org/acme/lager.git\n",
            "empty URL password after the userinfo token", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "Rückfragen bitte an max.mustermann@example.org, Benachrichtigungen über "
            "smtp://alarme@mail.example.de:587.",
            "e-mail address and SMTP userinfo in prose", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "[remote \"origin\"]\n  url = https://token:{{ bitbucket_token }}@bitbucket.org/acme/lager.git\n",
            "templated URL password after the userinfo token", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "DATABASE_URL=postgres://warehouse@db.internal:5432/warehouse\n",
            "userinfo without a password reads as e-mail address", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "$ git remote add mirror git@bitbucket.org:acme/warehouse.git\n",
            "SSH remote userinfo without a secret", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "$ git remote set-url origin https://token:@bitbucket.org/acme/warehouse.git\n",
            "empty URL password after the userinfo token", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "Questions go to jane.doe@example.com, alerts are sent via smtp://alerts@mail.example.com:587.",
            "e-mail address and SMTP userinfo in prose", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "[remote \"origin\"]\n  url = https://token:{{ bitbucket_token }}@bitbucket.org/acme/warehouse.git\n",
            "templated URL password after the userinfo token", carrier="ini",
        ),
    ],
    "PAYMENT_KEY": [
        ds(
            "PAYMENT_KEY", "de", "dlp_stripe_key",
            "# Laufzeit-Image für den Zahlungsdienst\nFROM eclipse-temurin:21-jre\n"
            "ENV STRIPE_SECRET_KEY=\"<<secret:0>>\"\n",
            "stripe_secret_test_long", 9804, carrier="code",
        ),
        ds(
            "PAYMENT_KEY", "en", "dlp_stripe_key",
            "# runtime image for the payment service\nFROM eclipse-temurin:21-jre\n"
            "ENV STRIPE_SECRET_KEY=\"<<secret:0>>\"\n",
            "stripe_secret_test_long", 9809, carrier="code",
        ),
    ],
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_jwt_token",
            "# Sitzung des Abgleichdienstes (nur lokal)\nSESSION_TOKEN='<<secret:0>>'\n",
            "jwt_signed_hs256", 9805, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "# session of the sync service (local only)\nSESSION_TOKEN='<<secret:0>>'\n",
            "jwt_signed_hs256", 9810, carrier="env",
        ),
    ],
}
for _label, _rows in DLP_K08_CASES.items():
    DLP_CASES[_label].extend(_rows)


# T01: a placeholder that continues an identifier, hex run or base64 blob on its left.
DLP_GLUED_PLACEHOLDER = re.compile(r"(?<![A-Za-z0-9_+/])<<secret:")


def dg(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    seed: int,
    reason: str,
    *,
    carrier: str = "line",
) -> dict:
    """Hard negative (T01): a generated value glued into an identifier, hex run or base64
    blob, so it is no whole token. Every placeholder follows a word, `+` or `/` character."""
    if DLP_GLUED_PLACEHOLDER.search(template) or "<<secret:" not in template:
        raise ValueError(f"T01 hard negative needs glued placeholders: {template!r}")
    secrets = [{"gen": generator, "seed": seed}]
    text, _ = recipes.materialize(template, secrets)
    row = {
        "language": language,
        "case_type": "hard_negative",
        "target_label": label,
        "template": template,
        "secrets": secrets,
        "text_fingerprint": recipes.fingerprint(text),
        "entities": [],
        "span_unit": "unicode_code_point",
        "negative_reason": reason,
        "provenance": {
            "origin": "synthetic",
            "source": "generator recipe (patronus_ark.dlp_synth) glued into a longer run, materialized at test time",
        },
    }
    return dlp_row(row, rule, carrier, (), False)


# T01: token boundaries of the prefix rules. Positives delimit the token by escapes that end
# in a letter or digit (JSON `\n`/`\t`, URL `%3D`/`%22`) and by Markdown code spans; hard
# negatives are lockfile checksums, sha256 digests and go.sum hashes, and provider-shaped
# values glued into identifiers, hex runs or base64 blobs.
DLP_T01_CASES = {
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            '{"level":"warn","msg":"Deploy-Token abgelehnt:\\n<<secret:0>>\\nbitte rotieren","retry":3}\n',
            "github_ghp_token", 10101, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "GET /anmeldung/rueckruf?state=%7B%22registry%22%3A%22<<secret:0>>%22%7D HTTP/1.1\n"
            "Host: pakete.example.de\n",
            "npm_access_token", 10102, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            '{"level":"warn","msg":"deploy token rejected:\\n<<secret:0>>\\nplease rotate","retry":3}\n',
            "github_ghp_token", 10111, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "GET /login/callback?state=%7B%22registry%22%3A%22<<secret:0>>%22%7D HTTP/1.1\n"
            "Host: packages.example.com\n",
            "npm_access_token", 10112, carrier="http",
        ),
        dg(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "// Auflösung der Workspace-Manifeste\nexport function resolve<<secret:0>>(root: string) {}\n",
            "npm_access_token", 10103, "npm_ prefix inside a camelCase identifier", carrier="code",
        ),
        dg(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "// resolve the workspace manifests\nexport function resolve<<secret:0>>(root: string) {}\n",
            "npm_access_token", 10113, "npm_ prefix inside a camelCase identifier", carrier="code",
        ),
    ],
    "API_KEY": [
        ds(
            "API_KEY", "de", "dlp_huggingface",
            "10.0.4.17 - - [12/Okt/2026:08:14:03 +0200] \"GET /modelle?next=%2Fdownload%3Fkey%3D<<secret:0>>%26rev%3Dmain HTTP/1.1\" 302 0\n",
            "huggingface_token", 10104, carrier="log",
        ),
        ds(
            "API_KEY", "en", "dlp_huggingface",
            "10.0.4.17 - - [12/Oct/2026:08:14:03 +0200] \"GET /models?next=%2Fdownload%3Fkey%3D<<secret:0>>%26rev%3Dmain HTTP/1.1\" 302 0\n",
            "huggingface_token", 10114, carrier="log",
        ),
        dg(
            "API_KEY", "de", "dlp_huggingface",
            "# Tokenizer aus dem lokalen Cache laden\ntokenizer = load_<<secret:0>>(pfad, revision=\"main\")\n",
            "huggingface_token", 10105, "hf_ prefix inside a snake_case function name", carrier="code",
        ),
        dg(
            "API_KEY", "en", "dlp_huggingface",
            "# load the tokenizer from the local cache\ntokenizer = load_<<secret:0>>(path, revision=\"main\")\n",
            "huggingface_token", 10115, "hf_ prefix inside a snake_case function name", carrier="code",
        ),
    ],
    "CLOUD_KEY": [
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "Der alte Zugriffsschlüssel `<<secret:0>>` wurde gestern deaktiviert.\n",
            "aws_access_key_id", 10106, carrier="markdown",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "The old access key `<<secret:0>>` was deactivated yesterday.\n",
            "aws_access_key_id", 10116, carrier="markdown",
        ),
        dg(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "# Prüfsummen der Abhängigkeiten (go.sum)\n"
            "golang.org/x/text v0.14.0 h1:lLSapj+3AlbBO4W2fYVGiX5Xfo+<<secret:0>>Q=\n"
            "golang.org/x/text v0.14.0/go.mod h1:gcO/c6AXUWfT+uiSBFYrclufnnCEFRjJcUeEXi28qZo=\n",
            "aws_access_key_id", 10107, "AKIA run inside a go.sum base64 hash", carrier="code",
        ),
        dg(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "# dependency checksums (go.sum)\n"
            "golang.org/x/text v0.14.0 h1:lLSapj+3AlbBO4W2fYVGiX5Xfo+<<secret:0>>Q=\n"
            "golang.org/x/text v0.14.0/go.mod h1:gcO/c6AXUWfT+uiSBFYrclufnnCEFRjJcUeEXi28qZo=\n",
            "aws_access_key_id", 10117, "AKIA run inside a go.sum base64 hash", carrier="code",
        ),
        dg(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "// Richtlinie im Speicher zwischenhalten\ntype Cached<<secret:0>>Policy struct{}\n",
            "aws_access_key_id", 10108, "AKIA run inside a CamelCase type name", carrier="code",
        ),
        dg(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "// keep the policy in memory\ntype Cached<<secret:0>>Policy struct{}\n",
            "aws_access_key_id", 10118, "AKIA run inside a CamelCase type name", carrier="code",
        ),
    ],
    "CRYPTO_KEY": [
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            '{"ts":"2026-10-12T08:14:03Z","msg":"Schlüssel für Cold-Storage:\\n<<secret:0>>\\nbitte löschen"}\n',
            "btc_wif_mainnet_compressed", 10109, carrier="log",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            '{"export":"konto\\tschluessel","zeile":"wallet-3\\t<<secret:0>>"}\n',
            "eth_private_key_hex", 10110, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            '{"ts":"2026-10-12T08:14:03Z","msg":"cold storage key:\\n<<secret:0>>\\nplease delete"}\n',
            "btc_wif_mainnet_compressed", 10119, carrier="log",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            '{"export":"account\\tkey","row":"wallet-3\\t<<secret:0>>"}\n',
            "eth_private_key_hex", 10120, carrier="json",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "# Diese Datei wird automatisch von Cargo erzeugt.\n# Sie ist nicht für manuelle Bearbeitung gedacht.\n"
            "[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n"
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            "checksum = \"3a62b7f976a112d59e38e370981a935fac5bc0dc422c4b4cc23cc4ee5b5426ac\"\n\n"
            "[[package]]\nname = \"serde_json\"\nversion = \"1.0.128\"\n"
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            "checksum = \"cbebe80b7d935279e4f5c8ed674f2d848f989bbd2fabfa11db04596206dba4d3\"\n",
            "Cargo.lock package checksums (sha256)", carrier="toml",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\n"
            "[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n"
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            "checksum = \"6840f7cedff654093aece745190193d7ac64afb80bf4cbc60b0a890a368e2ff5\"\n\n"
            "[[package]]\nname = \"serde_json\"\nversion = \"1.0.128\"\n"
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            "checksum = \"bf2ea12cf6b5276c9ca9a0ff607a7e17ae8914c734097b2af1286961e94e38f1\"\n",
            "Cargo.lock package checksums (sha256)", carrier="toml",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Basis-Image fest auf den Digest gepinnt\n"
            "FROM python:3.12-slim@sha256:b1ab2c69f7efd8126aa67853c92cda37306c9a5c6d6a238bdc4787ae5f793a6d\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n",
            "Docker image sha256 digest", carrier="code",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "services:\n  api:\n    # pinned to the image digest\n"
            "    image: ghcr.io/acme/api@sha256:e2901fbaf0b55e5ce60f9ace8918c5df0ff3827db00af7352da2475a6695caa9\n",
            "Docker image sha256 digest", carrier="yaml",
        ),
        dg(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "# Prüfsumme des Release-Archivs\n"
            "sha256 = \"9f3c2a<<secret:0>>\"\n",
            "btc_wif_mainnet_compressed", 10121, "WIF-shaped run glued into a hex digest", carrier="toml",
        ),
        dg(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "# checksum of the release archive\n"
            "sha256 = \"9f3c2a<<secret:0>>\"\n",
            "btc_wif_mainnet_compressed", 10122, "WIF-shaped run glued into a hex digest", carrier="toml",
        ),
        dg(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Aufrufdaten der Überweisung (ABI-kodiert)\n"
            "data: 0xa9059cbb000000000000000000000000<<secret:0>>\n",
            "eth_private_key_hex", 10123, "0x run glued into ABI-encoded calldata", carrier="yaml",
        ),
        dg(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "# transfer call data (ABI-encoded)\n"
            "data: 0xa9059cbb000000000000000000000000<<secret:0>>\n",
            "eth_private_key_hex", 10124, "0x run glued into ABI-encoded calldata", carrier="yaml",
        ),
    ],
}
for _label, _rows in DLP_T01_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F01: `dlp_eth_private_key` needs a key context in every mode. Positives name the key on
# the value's line (CLI flag, env/TOML/YAML key, wallet constructor) or on a line above
# (chat reply, mail body). Hard negatives are generated values next to a nearer hash, root,
# ID or chain-data term (tx hash, block hash, event topic, CREATE2 salt, state root), also
# where a wallet is mentioned further away; they run in `strict`.
DLP_F01_CASES = {
    "CRYPTO_KEY": [
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Adresse des Deployers prüfen\n$ cast wallet address --private-key <<secret:0>>\n",
            "eth_private_key_hex", 10301, carrier="cli",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "[10:02] jonas: Hat jemand den Privatschlüssel vom Faucet-Wallet?\n"
            "[10:04] mia: <<secret:0>>\n[10:04] mia: bitte nach dem Test rotieren\n",
            "eth_private_key_hex", 10302, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Foundry-Deployment (Sepolia), nicht einchecken\nRPC_URL=https://rpc.example.de\n"
            "DEPLOYER_PK=<<secret:0>>\nETHERSCAN_TIMEOUT=30\n",
            "eth_private_key_hex", 10303, carrier="env",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "relayer:\n  netz: sepolia\n  signer:\n    privkey: \"<<secret:0>>\"\n",
            "eth_private_key_hex", 10304, carrier="yaml",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Hallo Tim,\n\nanbei der geheime Schlüssel der Treasury-Wallet:\n\n<<secret:0>>\n\n"
            "Bitte sofort im Tresor ablegen.\n",
            "eth_private_key_hex", 10305, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "$ forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --private-key <<secret:0>> --broadcast\n",
            "eth_private_key_hex", 10311, carrier="cli",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "[14:20] sam: can someone DM me the privkey of the faucet wallet?\n"
            "[14:22] lee: <<secret:0>>\n[14:22] lee: rotate it after the demo\n",
            "eth_private_key_hex", 10312, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "from eth_account import Account\n\n"
            "acct = Account.from_key(\"<<secret:0>>\")  # relayer signer\n",
            "eth_private_key_hex", 10313, carrier="code",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "import { ethers } from \"ethers\";\n\n"
            "const wallet = new ethers.Wallet(\"<<secret:0>>\", provider);\n",
            "eth_private_key_hex", 10314, carrier="code",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "[deployer]\nnetwork = \"sepolia\"\nsecret_key = \"<<secret:0>>\"\n",
            "eth_private_key_hex", 10315, carrier="toml",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "2026-10-21 09:14:07 INFO  Relayer: Transaktion bestätigt, Hash <<secret:0>>, Block 18233411\n",
            "eth_private_key_hex", 10306, "transaction hash in a relayer log", carrier="log", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            '{"jsonrpc":"2.0","id":1,"result":{"blockHash":"<<secret:0>>","blockNumber":"0x1166a3b","status":"0x1"}}\n',
            "eth_private_key_hex", 10307, "block hash in an RPC receipt", carrier="json", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "Laut Etherscan wurde die Überweisung aus dem Wallet mit der Transaktions-ID <<secret:0>> bestätigt.",
            "eth_private_key_hex", 10308, "transaction ID nearer than the wallet mention", carrier="prose", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "snapshot:\n  hoehe: 18233411\n  zustandswurzel: <<secret:0>>\n",
            "eth_private_key_hex", 10309, "state root of a chain snapshot", carrier="yaml", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_eth_private_key",
            "# Beleg der Auszahlung abrufen\n$ cast receipt <<secret:0>> --rpc-url $RPC_URL\n",
            "eth_private_key_hex", 10310, "transaction hash as a CLI argument", carrier="cli", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "2026-10-21T09:14:07Z INFO relayer: submitted tx <<secret:0>> nonce=42 gas=21000\n",
            "eth_private_key_hex", 10316, "transaction hash in a relayer log", carrier="log", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            '{"logIndex":"0x0","removed":false,"topics":["<<secret:0>>"],"data":"0x"}\n',
            "eth_private_key_hex", 10317, "event topic in an RPC log entry", carrier="json", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "The wallet funding went through; Etherscan shows transaction <<secret:0>> as confirmed.",
            "eth_private_key_hex", 10318, "transaction hash nearer than the wallet mention", carrier="prose", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "// CREATE2 salt of the factory deployment\nbytes32 constant SALT = <<secret:0>>;\n",
            "eth_private_key_hex", 10319, "CREATE2 salt constant", carrier="code", mode="strict",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_eth_private_key",
            "attestation:\n  merkle_root: <<secret:0>>\n  leaves: 1024\n",
            "eth_private_key_hex", 10320, "Merkle root of an attestation", carrier="yaml", mode="strict",
        ),
    ],
}
for _label, _rows in DLP_F01_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F02: `dlp_btc_wif` validates Base58Check with the WIF version byte of mainnet (0x80, `5`/`K`/`L`)
# or testnet/signet/regtest (0xef, `9`/`c`) and scores at checksum strength. Positives are
# generated testnet keys in faucet, CLI, wallet-library and chat carriers. Hard negatives are
# testnet-shaped example/test fills, Base58 runs with a broken check value, references and the
# documented format; in balanced, a checksum term next to a valid key drops it.
DLP_F02_CASES = {
    "CRYPTO_KEY": [
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "# Testnet-Faucet, nicht einchecken\nNETZ=testnet\nFAUCET_WIF=<<secret:0>>\nAUSZAHLUNG_MAX=0.01\n",
            "btc_wif_testnet_compressed", 10401, carrier="env",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "# Schlüssel der Demo-Wallet ins Testnetz importieren\n"
            "$ bitcoin-cli -testnet importprivkey <<secret:0>> \"demo\" false\n",
            "btc_wif_testnet_uncompressed", 10402, carrier="cli",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "zahlungsdienst:\n  netz: testnet\n  wallet:\n    wif: \"<<secret:0>>\"\n",
            "btc_wif_testnet_compressed", 10403, carrier="yaml",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "[09:12] ben: Kannst du mir den Testnet-Schlüssel für die Demo schicken?\n"
            "[09:13] ana: <<secret:0>>\n[09:13] ana: nach dem Workshop bitte löschen\n",
            "btc_wif_testnet_compressed", 10404, carrier="prose",
        ),
        ds(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "{\"netzwerk\": \"testnet3\", \"privater_schluessel\": \"<<secret:0>>\", \"adresstyp\": \"legacy\"}\n",
            "btc_wif_testnet_uncompressed", 10405, carrier="json",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "from bit import PrivateKeyTestnet\n\nkey = PrivateKeyTestnet(\"<<secret:0>>\")\nprint(key.address)\n",
            "btc_wif_testnet_compressed", 10411, carrier="code",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "$ electrum --testnet restore <<secret:0>>\n",
            "btc_wif_testnet_uncompressed", 10412, carrier="cli",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "[faucet]\nnetwork = \"testnet\"\nwif = \"<<secret:0>>\"\npayout_max = 0.01\n",
            "btc_wif_testnet_compressed", 10413, carrier="toml",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "2026-10-21T10:02:11Z WARN faucet: loaded signing key <<secret:0>> from env\n",
            "btc_wif_testnet_compressed", 10414, carrier="log",
        ),
        ds(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Hi Jo,\n\nhere is the signet wallet key for the workshop:\n\n<<secret:0>>\n\nPlease delete it afterwards.\n",
            "btc_wif_testnet_uncompressed", 10415, carrier="prose",
        ),
        dx(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "# Beispiel aus der Doku\nFAUCET_WIF=<<secret:0>>\n",
            "btc_wif_testnet_compressed_shape", "EXAMPLEKEY", "documented testnet example value (EXAMPLE marker)",
            carrier="env",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Sitzungs-Token (Base58): 92bRew1RSMhiFXSS1F24kgeh48WT67LqwkHtCAA8i48n4pHBPpo",
            "testnet-shaped Base58 run with an invalid Base58Check check value",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "NETZ=testnet\nFAUCET_WIF=${FAUCET_WIF:?WIF fehlt}\n",
            "environment reference", carrier="env",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "zahlungsdienst:\n  netz: testnet\n  wallet:\n    wif: \"<Testnet-WIF hier einsetzen>\"\n",
            "template placeholder", carrier="yaml",
        ),
        dn(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Testnet-WIF-Schlüssel beginnen mit 9 oder c und sind 51 bzw. 52 Zeichen lang.",
            "documented format without a value", carrier="prose",
        ),
        dx(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "{\"network\": \"testnet\", \"wif\": \"<<secret:0>>\"}\n",
            "btc_wif_testnet_compressed_shape", "TESTKEY", "test key (TESTKEY fill)", carrier="json",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "2026-10-21T10:02:11Z ERROR faucet: rejected import cT1xecQJa7A7LtW6w7dEdSi7tRUtEi1BNcjkJiorgf2t5mHaGpgM\n",
            "testnet-shaped Base58 run with an invalid Base58Check check value", carrier="log",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "from bit import PrivateKeyTestnet\n\nkey = PrivateKeyTestnet(os.environ[\"FAUCET_WIF\"])\n",
            "environment lookup", carrier="code",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "$ bitcoin-cli -testnet dumpprivkey \"$FAUCET_ADDRESS\"\n",
            "shell variable reference", carrier="cli",
        ),
        dn(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Testnet WIF keys start with 9 (uncompressed) or c (compressed).",
            "documented format without a value", carrier="prose",
        ),
        dc(
            "CRYPTO_KEY", "de", "dlp_btc_wif",
            "Prüfsumme des Exports: <<secret:0>>",
            "btc_wif_testnet_compressed", 10406, "checksum term next to the value (counter-context Prüfsumme)",
        ),
        dc(
            "CRYPTO_KEY", "en", "dlp_btc_wif",
            "Export checksum: <<secret:0>>",
            "btc_wif_testnet_uncompressed", 10416, "checksum term next to the value (counter-context checksum)",
        ),
    ],
}
for _label, _rows in DLP_F02_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F03: `dlp_github_token` takes `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` with exactly 36 base62
# characters whose last six are the CRC32 of the first 30, at checksum strength;
# `dlp_github_pat` takes `github_pat_` with exactly 82 characters. Positives are generated
# tokens of every prefix in .env, YAML, JSON, TOML, code, CLI, log and prose carriers. Hard
# negatives are token shapes with a wrong check value or length (no rule may report them,
# also not a generic assignment), example/test fills, secret references and the documented
# format.
DLP_F03_CASES = {
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "# Spiegel-Job, nicht einchecken\nGITHUB_APP_ID=48211\nGITHUB_USER_TOKEN=<<secret:0>>\n",
            "github_ghu_token", 10501, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "spiegel:\n  quelle: github.com/acme/app\n  zugang:\n    refresh_token: \"<<secret:0>>\"\n",
            "github_ghr_token", 10502, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "{\"installation\": 4711, \"zugriffstoken\": \"<<secret:0>>\", \"gueltig_bis\": \"2026-10-21T11:00:00Z\"}\n",
            "github_ghs_token", 10503, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "2026-10-21 10:14:02 FEHLER oauth: Rückruf lieferte <<secret:0>> für Nutzer 1182\n",
            "github_gho_token", 10504, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "[10:02] ana: Kannst du mir dein GitHub-Token für den Release schicken?\n"
            "[10:03] ben: <<secret:0>>\n[10:03] ben: bitte danach rotieren\n",
            "github_ghp_token", 10505, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_github_pat",
            "# Anmeldung für das Release-Skript\n$ echo <<secret:0>> | gh auth login --with-token\n",
            "github_fine_grained_pat", 10506, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "from github import Auth, Github\n\ngh = Github(auth=Auth.Token(\"<<secret:0>>\"))\n",
            "github_ghs_token", 10511, carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "$ curl -H \"Authorization: token <<secret:0>>\" https://api.github.com/user\n",
            "github_ghp_token", 10512, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "[mirror]\nsource = \"github.com/acme/app\"\nrefresh_token = \"<<secret:0>>\"\n",
            "github_ghr_token", 10513, carrier="toml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "2026-10-21T10:14:02Z ERROR app-auth: user-to-server token <<secret:0>> expired\n",
            "github_ghu_token", 10514, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "Hi Jo,\n\nthe OAuth token for the dashboard is <<secret:0>>\n\nPlease revoke it after the demo.\n",
            "github_gho_token", 10515, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "jobs:\n  release:\n    env:\n      GH_TOKEN: <<secret:0>>\n",
            "github_fine_grained_pat", 10516, carrier="yaml",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "# Token mit Tippfehler, abgelehnt\nGITHUB_TOKEN=<<secret:0>>\n",
            "github_ghp_bad_crc", 10521, "ghp_ token shape with a wrong CRC32 check value", carrier="env",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "2026-10-21 10:14:02 WARN oauth: verworfener Wert <<secret:0>> (35 Zeichen)\n",
            "github_gho_short", 10522, "gho_ token shape with 35 instead of 36 characters", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "jobs:\n  release:\n    env:\n      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "Klassische GitHub-Tokens beginnen mit ghp_, gho_, ghu_, ghs_ oder ghr_ und haben danach 36 Zeichen, "
            "die letzten sechs sind eine CRC32-Prüfsumme.",
            "documented format without a value", carrier="prose",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_github_token",
            "{\"github\": {\"benutzer_token\": \"<<secret:0>>\"}}\n",
            "github_ghu_token", "BEISPIEL", "documented example value (BEISPIEL fill)", carrier="json",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_github_pat",
            "2026-10-21 10:14:02 WARN cli: Eingabe <<secret:0>> verworfen (81 Zeichen)\n",
            "github_fine_grained_pat_short", 10523, "github_pat_ shape with 81 instead of 82 characters", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "$ curl -H \"Authorization: token <<secret:0>>\" https://api.github.com/app\n",
            "github_ghs_bad_crc", 10531, "ghs_ token shape with a wrong CRC32 check value", carrier="cli",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "{\"oauth\": {\"token\": \"<<secret:0>>\"}}\n",
            "github_gho_bad_crc", 10532, "gho_ token shape with a wrong CRC32 check value", carrier="json",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "import os\n\ngh = Github(auth=Auth.Token(os.environ[\"GITHUB_TOKEN\"]))\n",
            "environment lookup", carrier="code",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "2026-10-21T10:14:02Z WARN auth: rejected <<secret:0>> (37 characters)\n",
            "github_ghp_long", 10533, "ghp_ token shape with 37 instead of 36 characters", carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_github_token",
            "# test fixture\nGITHUB_REFRESH_TOKEN=<<secret:0>>\n",
            "github_ghr_token", "TESTKEY", "test key (TESTKEY fill)", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_github_pat",
            "Fine-grained personal access tokens start with github_pat_ followed by 82 characters.",
            "documented format without a value", carrier="prose",
        ),
    ],
}
for _label, _rows in DLP_F03_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F04: `dlp_npm_token` takes `npm_` with exactly 36 base62 characters whose last six are the
# CRC32 of the first 30, at checksum strength. `dlp_gitlab_pat` takes `glpat-` with exactly 20
# characters or the routable form (`glpat-…` + `.` + version + base36 check value);
# `dlp_gitlab_token` takes the other documented GitLab prefixes (deploy, runner, runner
# registration, pipeline trigger, feed, incoming mail, Kubernetes agent, CI/CD job, SCIM,
# feature flag client) and `dlp_gitlab_oauth_secret` the OAuth application secret (`gloas-`).
# Hard negatives are shapes with a wrong check value, length or alphabet (no rule may report
# them), example/test fills, secret references and the documented prefixes.
DLP_F04_CASES = {
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "jobs:\n  veroeffentlichen:\n    steps:\n      - run: npm publish\n        env:\n"
            "          NODE_AUTH_TOKEN: <<secret:0>>\n",
            "npm_access_token", 10601, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "# Registry-Zugang des Deploy-Jobs\n"
            "$ echo <<secret:0>> | docker login registry.gitlab.example.com -u gitlab+deploy-token-12 --password-stdin\n",
            "gitlab_deploy_token", 10602, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "concurrent = 4\n\n[[runners]]\n  name = \"baurunner-01\"\n  url = \"https://gitlab.example.com\"\n"
            "  token = \"<<secret:0>>\"\n  executor = \"docker\"\n",
            "gitlab_runner_token", 10603, carrier="toml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "# Nächtlicher Build über den Pipeline-Trigger\n"
            "$ curl -X POST --fail -F token=<<secret:0>> -F ref=main "
            "https://gitlab.example.com/api/v4/projects/42/trigger/pipeline\n",
            "gitlab_trigger_token", 10604, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "Hallo Team,\n\nder Feed-Token für den Kalender-Export lautet <<secret:0>>\n\n"
            "Bitte nicht weitergeben.\n",
            "gitlab_feed_token", 10605, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "agent:\n  # Zugang des Clusters zu GitLab\n  config:\n    token: <<secret:0>>\n"
            "    kasAddress: wss://kas.gitlab.example.com\n",
            "gitlab_agent_token", 10606, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "{\"quelle\": \"gitlab.example.com\", \"zugang\": {\"token\": \"<<secret:0>>\"}}\n",
            "gitlab_pat_routable", 10607, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "$ npm config set //registry.npmjs.org/:_authToken <<secret:0>>\n",
            "npm_access_token", 10611, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "const RegClient = require(\"npm-registry-client\");\n\n"
            "const client = new RegClient({ auth: { token: \"<<secret:0>>\", alwaysAuth: true } });\n",
            "npm_access_token", 10612, carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "$ gitlab-runner register --non-interactive --url https://gitlab.example.com "
            "--token <<secret:0>> --executor docker\n",
            "gitlab_runner_token_routable", 10613, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "gitlabUrl: https://gitlab.example.com/\nrunnerRegistrationToken: \"<<secret:0>>\"\nconcurrent: 10\n",
            "gitlab_runner_registration_token", 10614, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "2026-10-21T10:14:02Z INFO mail_room: delivering to /api/v4/internal/mail_room "
            "with incoming mail token <<secret:0>>\n",
            "gitlab_incoming_mail_token", 10615, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "PATCH /api/scim/v2/groups/acme/Users/42 HTTP/1.1\nHost: gitlab.example.com\n"
            "Authorization: Bearer <<secret:0>>\nContent-Type: application/scim+json\n",
            "gitlab_scim_token", 10616, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "Hi Sam,\n\nthe feature flag client token for the storefront is <<secret:0>>\n\n"
            "Please rotate it after the release.\n",
            "gitlab_feature_flag_token", 10617, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "2026-10-21T10:14:02Z DEBUG job 8812: fetching artifacts with job token <<secret:0>>\n",
            "gitlab_cicd_job_token", 10618, carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "; Token mit Tippfehler, von der Registry abgelehnt\n//registry.npmjs.org/:_authToken=<<secret:0>>\n",
            "npm_bad_crc", 10621, "npm_ token shape with a wrong CRC32 check value", carrier="ini",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "2026-10-21 10:14:02 WARN publish: verworfener Wert <<secret:0>> (35 Zeichen)\n",
            "npm_short", 10622, "npm_ token shape with 35 instead of 36 characters", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_npm_token",
            "      - run: echo \"//npm.pkg.github.com/:_authToken=${{ secrets.NPM_TOKEN }}\" >> .npmrc\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_gitlab_pat",
            "2026-10-21 10:14:02 WARN api: verworfener Wert <<secret:0>> (21 Zeichen)\n",
            "gitlab_pat_long", 10623, "glpat- shape with 21 instead of 20 characters", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "2026-10-21 10:14:02 WARN trigger: verworfener Wert <<secret:0>> (Großbuchstaben)\n",
            "gitlab_trigger_token_upper_hex", 10624, "glptt- shape with upper-case hex digits", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "Deploy-Tokens beginnen mit gldt-, Runner-Tokens mit glrt- und Pipeline-Trigger-Tokens mit glptt-.",
            "documented prefixes without a value", carrier="prose",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_gitlab_token",
            "deploy:\n  registry:\n    benutzer: gitlab+deploy-token-12\n    token: <<secret:0>>\n",
            "gitlab_deploy_token", "BEISPIEL", "documented example value (BEISPIEL fill)", carrier="yaml",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "{\"npmAuthToken\": \"<<secret:0>>\", \"npmRegistryServer\": \"https://registry.npmjs.org\"}\n",
            "npm_bad_crc", 10631, "npm_ token shape with a wrong CRC32 check value", carrier="json",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "2026-10-21T10:14:02Z WARN publish: rejected <<secret:0>> (37 characters)\n",
            "npm_long", 10632, "npm_ token shape with 37 instead of 36 characters", carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_npm_token",
            "# test fixture\n//registry.npmjs.org/:_authToken=<<secret:0>>\n",
            "npm_access_token", "TESTKEY", "test key (TESTKEY fill, zero checksum)", carrier="ini",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "2026-10-21T10:14:02Z WARN registry: rejected <<secret:0>> (19 characters)\n",
            "gitlab_deploy_token_short", 10633, "gldt- shape with 19 instead of 20 characters", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "[[runners]]\n  url = \"https://gitlab.example.com\"\n  token = \"${RUNNER_TOKEN}\"\n",
            "environment reference", carrier="toml",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_gitlab_token",
            "Feed tokens start with glft-, SCIM tokens with glsoat- and OAuth application secrets with gloas-.",
            "documented prefixes without a value", carrier="prose",
        ),
    ],
    "API_KEY": [
        ds(
            "API_KEY", "de", "dlp_gitlab_oauth_secret",
            "# Anmeldung über GitLab (OmniAuth)\nGITLAB_APP_ID=4711\nGITLAB_APP_SECRET=<<secret:0>>\n",
            "gitlab_oauth_app_secret", 10641, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_gitlab_oauth_secret",
            "{\"application_id\": \"4711\", \"application_name\": \"dashboard\", \"secret\": \"<<secret:0>>\"}\n",
            "gitlab_oauth_app_secret", 10642, carrier="json",
        ),
        dx(
            "API_KEY", "de", "dlp_gitlab_oauth_secret",
            "GITLAB_APP_SECRET=<<secret:0>>\n",
            "gitlab_oauth_app_secret", "MUSTER", "documented example value (MUSTER fill)", carrier="env",
        ),
        dx(
            "API_KEY", "en", "dlp_gitlab_oauth_secret",
            "{\"application_id\": \"4711\", \"secret\": \"<<secret:0>>\"}\n",
            "gitlab_oauth_app_secret", "EXAMPLE", "documented example value (EXAMPLE fill)", carrier="json",
        ),
    ],
}
for _label, _rows in DLP_F04_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F05: `dlp_aws_access_key` takes the credential prefixes of the IAM unique-ID table (`AKIA`,
# `ASIA`, `ABIA`, `ACCA`, legacy `A3T…`) and exactly 16 Base32 characters. `dlp_aws_secret_key`
# takes 40 base64 characters with upper and lower case letters after an AWS key name or label
# (also in prose, up to two lines on), right after an access key ID, or after a generic secret
# key name with AWS context (Terraform `provider "aws"`, `.s3cfg`, Spring `cloud.aws`). Hard
# negatives are IAM unique IDs of other entities, key IDs outside Base32 or of another length,
# 41-character and hex values, references, example/test fills and documented formats.
DLP_F05_CASES = {
    "CLOUD_KEY": [
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "# Zugang für den Rechnungsexport\nprovider \"aws\" {\n  region     = \"eu-central-1\"\n"
            "  access_key = var.zugangs_id\n  secret_key = \"<<secret:0>>\"\n}\n",
            "aws_secret_access_key", 10701, carrier="code",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "# s3cmd-Konfiguration für das Archiv\n[default]\nhost_base = s3.eu-central-1.amazonaws.com\n"
            "secret_key = <<secret:0>>\nuse_https = True\n",
            "aws_secret_access_key", 10702, carrier="ini",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "# Zugangsdaten Lager-Export\ncloud:\n  aws:\n    region:\n      static: eu-central-1\n"
            "    credentials:\n      secret-key: <<secret:0>>\n",
            "aws_secret_access_key", 10703, carrier="yaml",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "[10:02] jana.k: Hast du den AWS Secret Access Key für Staging? Die Pipeline hängt.\n"
            "[10:03] tim.b: <<secret:0>>\n[10:03] tim.b: Bitte nur lokal nutzen.\n",
            "aws_secret_access_key", 10704, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "Der AWS-Secret-Access-Key für den Export lautet <<secret:0>>, bitte nach dem Test rotieren.\n",
            "aws_secret_access_key", 10705, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "$ aws configure set aws_access_key_id <<secret:0>> --profile buchhaltung\n",
            "aws_sts_bearer_key_id", 10706, carrier="cli",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "terraform {\n  backend \"s3\" {\n    bucket     = \"acme-tf-state\"\n    region     = \"us-east-1\"\n"
            "    secret_key = \"<<secret:0>>\"\n  }\n}\n",
            "aws_secret_access_key", 10711, carrier="code",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "$ aws configure --profile reporting\nAWS Access Key ID [None]: \n"
            "AWS Secret Access Key [None]: <<secret:0>>\nDefault region name [None]: us-east-1\n",
            "aws_secret_access_key", 10712, carrier="cli",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "2026-10-22T08:01:12Z DEBUG botocore.credentials: loaded secret_key=<<secret:0>> "
            "from ~/.aws/credentials\n",
            "aws_secret_access_key", 10713, carrier="log",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "<appSettings>\n  <add key=\"AWSRegion\" value=\"us-east-1\" />\n"
            "  <add key=\"AwsSecretAccessKey\" value=\"<<secret:0>>\" />\n</appSettings>\n",
            "aws_secret_access_key", 10714, carrier="xml",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "Hi team,\n\nhere is the AWS secret access key for the backup job:\n\n<<secret:0>>\n\n"
            "Please move it to the vault this week.\n",
            "aws_secret_access_key", 10715, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "{\"Credentials\": {\"AccessKeyId\": \"<<secret:0>>\", \"Expiration\": \"2026-10-22T10:00:00Z\"}}\n",
            "aws_context_credential_key_id", 10716, carrier="json",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "# Commit, mit dem der AWS-Secret-Access-Key aus der Konfiguration entfernt wurde\n"
            "commit <<secret:0>>\n",
            "aws_secret_access_key_hex", 10721, "40 hex digits (git commit ID) after an AWS label", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "provider \"aws\" {\n  region     = \"eu-central-1\"\n  access_key = var.zugangs_id\n"
            "  secret_key = var.geheimer_schluessel\n}\n",
            "Terraform variable reference", carrier="code",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "[default]\nhost_base = s3.amazonaws.com\nsecret_key = <<secret:0>>\n",
            "aws_secret_access_key", "BEISPIEL", "documented example value (BEISPIEL fill)", carrier="ini",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "{\"userIdentity\": {\"type\": \"IAMUser\", \"principalId\": \"<<secret:0>>\", "
            "\"userName\": \"rechnung-export\"}}\n",
            "aws_iam_user_unique_id", 10722, "IAM user unique ID (AIDA), no credential", carrier="json",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_access_key",
            "2026-10-22 08:14:03 WARN import: alter Zugriffsschlüssel <<secret:0>> noch aktiv\n",
            "aws_access_key_id_non_base32", 10723, carrier="log",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "Der geheime Zugriffsschlüssel (AWS Secret Access Key) besteht aus 40 Base64-Zeichen.",
            "documented format without a value", carrier="prose",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "2026-10-22T08:14:03Z WARN iam: rejected AWS secret access key candidate <<secret:0>> "
            "(41 characters)\n",
            "aws_secret_access_key_long", 10731, "base64 run of 41 instead of 40 characters", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "    env:\n      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
            "      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n",
            "GitHub Actions secret references", carrier="yaml",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "provider \"aws\" {\n  region     = \"us-east-1\"\n  secret_key = \"<<secret:0>>\"\n}\n",
            "aws_secret_access_key", "TESTKEY", "test key (TESTKEY fill)", carrier="code",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "2026-10-22T08:14:03Z WARN sts: malformed key id <<secret:0>> (17 characters after the prefix)\n",
            "aws_access_key_id_long", 10732, "AKIA shape with 17 instead of 16 Base32 characters", carrier="log",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "{\"eventName\": \"ConsoleLogin\", \"userIdentity\": {\"principalId\": \"<<secret:0>>\"}}\n",
            "aws_iam_user_unique_id", 10733, "IAM user unique ID (AIDA), no credential", carrier="json",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_aws_access_key",
            "Access key IDs start with AKIA (long-term) or ASIA (temporary) followed by 16 Base32 characters.",
            "documented prefixes without a value", carrier="prose",
        ),
    ],
}
for _label, _rows in DLP_F05_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F-GEN1 (F11 + T03 + T10): the values of `dlp_password_assignment`,
# `dlp_generic_credential_assignment` and `dlp_url_userinfo_password` need password likeness.
# Code expressions (calls, index/member access, type annotations, `Token::…` paths, format
# placeholders, paths), a shell variable as key (`$PWD:/work`), DE/EN prose words („Passwort ist
# falsch“) and credential names or test stand-ins (`user:pass`, `token:MY_GITHUB_TOKEN`) are no
# secrets; weak but real passwords stay secrets. `dlp_url_userinfo_token` reports the token in
# the username of `https://<token>:x-oauth-basic@…`.
DLP_FGEN1_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "import psycopg\n\nverbindung = psycopg.connect(host=\"db.intern\", user=\"lager\", "
            "password=\"<<secret:0>>\")\n",
            "password", 11001, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Hallo Sven, das Passwort ist <<secret:0>>, bitte nach dem ersten Login ändern.\n",
            "password", 11002, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[smtp]\nserver = mail.intern\nbenutzer = versand\npasswort = <<secret:0>>\n",
            "weak_dollar_password", 11003, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "let client = Client::new(Config {\n    region: \"eu-central-1\".into(),\n"
            "    token: \"<<secret:0>>\".into(),\n});\n",
            "generic_api_secret", 11004, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "// Verbindung zur Lager-DB\ndsn := \"postgres://lager:<<secret:0>>@db.intern:5432/lager\"\n",
            "url_userinfo_password", 11005, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Zugang Testsystem\nBenutzer: pruefer\nPasswort: <<secret:0>>\n",
            "weak_repeated_password", 11006, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "const pool = new Pool({ host: \"db.internal\", user: \"app\", password: \"<<secret:0>>\" });\n",
            "password", 11011, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "Hi Dana, the password is <<secret:0>> until Friday, please change it after login.\n",
            "weak_snake_case_password", 11012, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "client := api.New(api.Config{\n\tRegion: \"us-east-1\",\n\tToken:  \"<<secret:0>>\",\n})\n",
            "generic_api_secret", 11013, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "$ git clone https://deploy:<<secret:0>>@git.example.com/team/app.git\n",
            "url_userinfo_password", 11014, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "2026-10-22 08:01:12 WARN legacy auth enabled for user=ops password=<<secret:0>>\n",
            "weak_repeated_password", 11015, carrier="log",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Das Passwort ist falsch. Bitte prüfen Sie die Feststelltaste und versuchen Sie es erneut.",
            "prose: the password is wrong (no value)", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Hinweis: Das Token ist abgelaufen, bitte melden Sie sich neu an.",
            "prose: the token has expired (no value)", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "fn verbinde(token: Option<&str>) -> Result<Verbindung, Fehler> {\n    todo!()\n}\n",
            "Rust type annotation", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "def anmelden(konto):\n    passwort = tresor.passwort_lesen(konto)\n    return login(konto, passwort)\n",
            "Python function call", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "$ docker run --rm -v \"$PWD:/arbeit\" -w /arbeit lager/export:1.4\n",
            "shell variable $PWD as key of a volume mount", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "$this->assertSame('https://user:pass@example.org/repo.git', $url);\n",
            "test-suite URL with stand-in credentials", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "const passwort = this.eingabe.value;\nconst staerke = this.bewerten(passwort);\n",
            "TypeScript member access", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "If a system keyring is available, the password is stored there and never written to disk.",
            "prose: the password is stored (no value)", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "token = self._authenticator.get_pypi_token(repository_name)\n",
            "Python method call", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "export interface StrengthConfig {\n  scorer: ((password: string) => number) | null\n}\n",
            "TypeScript type annotation", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "/**\n * @return array{username: string|null, password: string|null}\n */\n",
            "PHP doc type annotation", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "['https://gitlab-ci-token:***@gitlab.example.org/', 'https://gitlab-ci-token:realtoken@gitlab.example.org/'],\n",
            "test-suite URL with a stand-in token", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "match tok {\n    Token::Literal(c) => out.push(c),\n    Token::ZeroOrMore => out.push_str(\".*\"),\n}\n",
            "Rust enum path Token::…", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "['https://token:MY_GITHUB_TOKEN@github.com/acme/repo.git', 2],\n",
            "test-suite URL with a variable name as token", carrier="code",
        ),
    ],
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_url_userinfo_token",
            "# Spiegel des Lager-Repos\n$ git remote set-url spiegel "
            "https://<<secret:0>>:x-oauth-basic@github.com/acme/lager.git\n",
            "generic_api_secret", 11021, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_url_userinfo_token",
            "[remote \"origin\"]\n  url = https://<<secret:0>>:x-oauth-basic@github.com/acme/abgleich.git\n",
            "url_token", 11022, carrier="ini",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_url_userinfo_token",
            "$ git clone https://<<secret:0>>:x-oauth-basic@github.com/acme/app.git\n",
            "generic_api_secret", 11031, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_url_userinfo_token",
            "{\"mirror\": {\"remote\": \"https://<<secret:0>>:x-oauth-basic@github.com/acme/sync.git\"}}\n",
            "url_token", 11032, carrier="json",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_url_userinfo_token",
            "$ git clone https://$GITHUB_TOKEN:x-oauth-basic@github.com/acme/lager.git\n",
            "shell variable as token", carrier="cli",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_url_userinfo_token",
            "Format: https://<token>:x-oauth-basic@github.com/acme/lager.git",
            "documented format without a token", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_url_userinfo_token",
            "https://myusername:x-oauth-basic@github.com/acme/app.git\n",
            "word as username, no token", carrier="line",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_url_userinfo_token",
            "  run: git clone https://${{ secrets.GITHUB_TOKEN }}:x-oauth-basic@github.com/acme/app.git\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
    ],
}
for _label, _rows in DLP_FGEN1_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F-GEN2 (T04 + T08): value capture. A quoted value of `dlp_password_assignment` and
# `dlp_generic_credential_assignment` runs to its closing quote (spaces, `;`, `,`, `}` inside,
# two characters before the first `;`); `dlp_env_var_secret` reports the value without its
# quotes and without a trailing `;`, also after `KEY:` in YAML/compose env maps. Code constants
# (`DATA_API_KEY = '.data-api'`, `AUTH_FLOW_PASSWORD = "password"`), the closing quote of a
# label (`"Passwort:"),d?…`), messages and template or environment references are no values.
DLP_FGEN2_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[datenbank]\nhost = \"db.intern\"\nbenutzer = \"lager\"\npasswort = \"<<secret:0>>\"\n",
            "quoted_passphrase", 12001, carrier="toml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "smtp:\n  host: mail.intern\n  benutzer: versand\n  password: '<<secret:0>>'\n",
            "quoted_punctuated_password", 12002, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "const konfig = { region: \"eu-central-1\", token: \"<<secret:0>>\", wiederholungen: 3 };\n",
            "quoted_punctuated_password", 12003, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "Hallo Jana, das neue Passwort lautet \"<<secret:0>>\", bitte nach dem ersten Login ändern.\n",
            "quoted_passphrase", 12004, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Abgleich lokal starten\n$ export LAGER_API_TOKEN='<<secret:0>>'\n$ ./bin/abgleich --voll\n",
            "generic_api_secret", 12005, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "FROM eclipse-temurin:21-jre\nCOPY target/abgleich.jar /app/abgleich.jar\n"
            "ENV LAGER_DB_PASSWORD=\"<<secret:0>>\"\nENTRYPOINT [\"java\", \"-jar\", \"/app/abgleich.jar\"]\n",
            "password", 12006, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "services:\n  abgleich:\n    image: acme/abgleich:2.3\n    environment:\n"
            "      LAGER_DB_HOST: db.intern\n      LAGER_DB_PASSWORD: \"<<secret:0>>\"\n",
            "password", 12007, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "public final class Exportdienst {\n"
            "    private static final String EXPORT_API_KEY = \"<<secret:0>>\";\n}\n",
            "url_token", 12008, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "$ LAGER_SECRET=<<secret:0>>; ./bin/abgleich --mandant 0042\n",
            "url_token", 12009, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[smtp]\nhost = mail.internal\nuser = reports\npassword = \"<<secret:0>>\"\n",
            "quoted_passphrase", 12011, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "conn = psycopg.connect(host=\"db.internal\", user=\"reports\", password='<<secret:0>>')\n",
            "quoted_punctuated_password", 12012, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "oauth:\n  issuer: https://login.internal\n  client_secret: \"<<secret:0>>\"\n",
            "quoted_punctuated_password", 12013, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "Hi Sam, the API token is \"<<secret:0>>\" until the rotation on Friday.\n",
            "quoted_passphrase", 12014, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# .env for the report worker\nREPORTS_QUEUE=reports\nREPORTS_API_TOKEN=\"<<secret:0>>\"\n",
            "generic_api_secret", 12015, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "jobs:\n  export:\n    runs-on: ubuntu-24.04\n    env:\n"
            "      REPORTS_DB_PASSWORD: \"<<secret:0>>\"\n    steps:\n      - run: ./export.sh\n",
            "password", 12016, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "import requests\n\nREPORTS_API_KEY = \"<<secret:0>>\"\n",
            "url_token", 12017, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "$ REPORTS_SECRET=<<secret:0>>; ./bin/report --all\n",
            "url_token", 12018, carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "const NAME = 'zeitleiste'\nconst DATA_KEY = 'bs.zeitleiste'\nconst DATA_API_KEY = '.data-api'\n",
            "code constant: event namespace, no secret", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "const ANMELDUNG_IMPLIZIT = \"implicit\"\nconst ANMELDUNG_FLOW_PASSWORD = \"password\"\n",
            "code constant: OAuth flow name", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "services:\n  abgleich:\n    environment:\n      LAGER_DB_PASSWORD: \"${LAGER_DB_PASSWORD}\"\n",
            "compose environment reference", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "e.createElement(\"label\",{htmlFor:\"passwort\"},\"Passwort:\"),d?e.createElement(\"code\",null,\" ******\")\n",
            "closing quote of a label in minified code", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "const meldungen = { passwort: \"Bitte geben Sie ein Passwort ein\", senden: \"Anmelden\" };\n",
            "UI message about the password", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "lager:\n  token: \"{{ .Values.lager.token }}\"\n",
            "Helm template reference", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "LAGER_SECRET_KEY = konfig.get(\"lager_secret\")\n",
            "Python call as value", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "const NAME = \"collapse\";\nconst DATA_API_KEY = \".data-api\";\nconst EVENT_SHOW = \"show\";\n",
            "code constant: event namespace, no secret", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "    const AUTH_FLOW_IMPLICIT = \"implicit\"\n    const AUTH_FLOW_PASSWORD = \"password\"\n",
            "code constant: OAuth flow name", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "    env:\n      REPORTS_DB_PASSWORD: ${{ secrets.REPORTS_DB_PASSWORD }}\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "export default { password: \"Enter your password\", submit: \"Sign in\" };\n",
            "UI message about the password", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "Login failed because the password is \"too short\" for the new policy.\n",
            "prose: quoted dictionary words", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "oauth:\n  client_secret: \"<your client secret>\"\n",
            "documented placeholder", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "ENV REPORTS_API_TOKEN=\"$(cat /run/secrets/reports_token)\"\n",
            "command substitution from a mounted secret", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "    environment:\n      LAGER_API_TOKEN: \"" + "deadbeef" * 5 + "\"\n",
            "documented hex fill value under a compose key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "[oauth]\nclient_secret = \"" + "1234567890" * 4 + "\"\n",
            "repeated digit fill as a 40-character hex secret", carrier="toml",
        ),
    ],
}
for _label, _rows in DLP_FGEN2_CASES.items():
    DLP_CASES[_label].extend(_rows)


# T09: key shapes of the key-anchored rules. Quoted and escaped keys (`"client_secret":`,
# `'password' =>`), compound and camelCase keys (`db_password`, `serviceSecret`,
# `PasswordHash`), typed declarations (`const X: &str =`, `: string =`), subscripts
# (`os.environ["DB_PASSWORD"] =`), escaped values in notebooks and XML `key`/`value`
# attributes find their value. Cursor and handle tokens, Helm/Kubernetes secret objects,
# field names, types, templates, calls and placeholders after the new key shapes stay silent.
# Notebook cells (`.ipynb`) are JSON carriers.
DLP_T09_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "{\n  \"dienst\": \"lagerabgleich\",\n  \"zugang\": {\n    \"db_passwort\": \"<<secret:0>>\",\n"
            "    \"anmerkung\": \"nur für den Nachtlauf\"\n  }\n}\n",
            "password", 13001, carrier="json",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "anbindungen:\n  spedition:\n    basis_url: https://api.intern/v1\n    dienstSecret: \"<<secret:0>>\"\n",
            "generic_api_secret", 13002, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "use std::time::Duration;\n\n// Zugang zum Import-Endpunkt\nconst DB_PASSWORT: &str = \"<<secret:0>>\";\n",
            "password", 13003, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\n \"cells\": [\n  {\n   \"cell_type\": \"code\",\n   \"source\": [\n    \"import os\\n\",\n"
            "    \"os.environ[\\\"CLIENT_SECRET\\\"] = \\\"<<secret:0>>\\\"\\n\"\n   ]\n  }\n ]\n}\n",
            "generic_api_secret", 13004, carrier="json",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "import { HttpClient } from \"@acme/http\";\n\nexport const lagerApiKey: string = \"<<secret:0>>\";\n",
            "generic_api_secret", 13005, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\n  \"region\": \"eu-central-1\",\n  \"oauth\": {\n    \"client_secret\": \"<<secret:0>>\"\n  }\n}\n",
            "generic_api_secret", 13011, carrier="json",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "upstream:\n  enabled: true\n  base_url: https://api.internal/v2\n  db_password: \"<<secret:0>>\"\n",
            "password", 13012, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<configuration>\n  <appSettings>\n    <add key=\"Environment\" value=\"Production\" />\n"
            "    <add key=\"DbPassword\" value=\"<<secret:0>>\" />\n  </appSettings>\n</configuration>\n",
            "password", 13013, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# reconciler settings\n[server]\nlisten = \"0.0.0.0:7000\"\n\n[auth]\nservice_secret = \"<<secret:0>>\"\n",
            "generic_api_secret", 13014, carrier="toml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "{\n \"cells\": [\n  {\n   \"cell_type\": \"code\",\n   \"source\": [\n    \"import requests\\n\",\n"
            "    \"db_password = \\\"<<secret:0>>\\\"\\n\"\n   ]\n  }\n ]\n}\n",
            "password", 13015, carrier="json",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<?php\n\nreturn [\n    'host' => 'db.internal',\n    'password' => '<<secret:0>>',\n];\n",
            "password", 13016, carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\n  \"artikel\": [],\n  \"nextPageToken\": \"Q0FVUUFBYTFiMmMz\"\n}\n",
            "pagination cursor under a compound token key", carrier="json",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "lager:\n  auth:\n    existingSecret: \"lager-release-auth\"\n",
            "Helm reference to an existing Kubernetes Secret", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "export interface Konfig {\n  dbPasswort: string;\n  dienstSecret?: string;\n}\n",
            "TypeScript field types", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "<appSettings>\n  <add key=\"DbPasswort\" value=\"{{DB_PASSWORT}}\" />\n</appSettings>\n",
            "XML template reference", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "   \"source\": [\n    \"db_passwort = getpass.getpass()\\n\",\n    \"verbinde(db_passwort)\"\n   ]\n",
            "notebook call as value", carrier="json",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "const DB_PASSWORT: &str = env!(\"DB_PASSWORT\");\n",
            "Rust compile-time environment reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\n  \"items\": [],\n  \"continuation_token\": \"a8f3k2m9x7q1z5w4\"\n}\n",
            "stream continuation cursor", carrier="json",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "const routes = { forgotPassword: \"forgot-password\", resetPassword: \"/reset-password\" };\n",
            "route names after camelCase password keys", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "ingress:\n  tls_secret: \"wildcard-internal-2026\"\n",
            "name of a Kubernetes TLS Secret", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "<appSettings>\n  <add key=\"ClientSecret\" value=\"YOUR_CLIENT_SECRET\" />\n</appSettings>\n",
            "documented placeholder in an XML key/value pair", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "   \"source\": [\n    \"os.environ[\\\"DB_PASSWORD\\\"] = getpass.getpass()\\n\",\n   ]\n",
            "notebook call as value of a subscript", carrier="json",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "pub struct Config {\n    pub db_password: Option<String>,\n}\n",
            "Rust field type", carrier="code",
        ),
    ],
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "[server]\nworker = 4\n\n[upstream]\nbasis_url = \"https://api.intern/v2\"\ncsrf_token = \"<<secret:0>>\"\n",
            "csrf_token", 13021, carrier="toml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "<exporter>\n  <endpoint url=\"https://reports.internal/api\" timeout=\"30\" />\n"
            "  <credentials csrfToken=\"<<secret:0>>\" />\n</exporter>\n",
            "csrf_token", 13022, carrier="xml",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_csrf_token",
            "<meta name=\"csrf-token\" content=\"{{ csrf_token() }}\">\n",
            "template in a CSRF meta tag", carrier="code",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_csrf_token",
            "{\n  \"csrf_token\": \"X-CSRF-Token\"\n}\n",
            "header name as value", carrier="json",
        ),
    ],
    "PASSWORD_HASH": [
        ds(
            "PASSWORD_HASH", "de", "dlp_password_hash",
            "<appSettings>\n  <add key=\"Umgebung\" value=\"Produktion\" />\n"
            "  <add key=\"PasswordHash\" value=\"<<secret:0>>\" />\n</appSettings>\n",
            "bcrypt_hash", 13031, carrier="xml",
        ),
        ds(
            "PASSWORD_HASH", "en", "dlp_password_hash",
            "import { HttpClient } from \"@acme/http\";\n\nexport const passwordHash: string = \"<<secret:0>>\";\n",
            "bcrypt_hash", 13032, carrier="code",
        ),
    ],
    "CLOUD_KEY": [
        ds(
            "CLOUD_KEY", "en", "dlp_aws_secret_key",
            "{\n  \"awsAccessKeyId\": \"from-vault\",\n  \"awsSecretAccessKey\": \"<<secret:0>>\"\n}\n",
            "aws_secret_access_key", 13041, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_aws_secret_key",
            "POST /v1/upload HTTP/1.1\nHost: lager.intern\nAws-Secret-Access-Key: <<secret:0>>\n",
            "aws_secret_access_key", 13042, carrier="http",
        ),
    ],
}
for _label, _rows in DLP_T09_CASES.items():
    DLP_CASES[_label].extend(_rows)


# F-HTTP (F13 + T11): HTTP auth values outside a literal header line. Bearer and Basic values
# under authorization/proxy_authorization keys (env, JSON, YAML, TOML, code, logs) and standalone
# in chats, tickets and mails; session cookies of known servers and frameworks (JSESSIONID,
# PHPSESSID, connect.sid, laravel_session, __Host-) without a Cookie: line. Basic counts only
# when its base64 decodes to user:password, Bearer only as a high-entropy opaque token (a JWT
# goes to dlp_jwt_token). Hard negatives: swagger-ui test values (Bearer abc123.xyz.789,
# Bearer secret_token, Basic application:secret), base64 without user:password, the RFC 7617
# example, references, placeholders and identifiers.
DLP_FHTTP_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "# Proxy für den Lagerabgleich\nHTTP_PROXY=http://proxy.intern:3128\nPROXY_AUTHORIZATION=Basic <<secret:0>>\n",
            "http_basic_auth", 14001, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "Ticket #20931 – Proxy lehnt den Abruf ab\n\nLaut Konfiguration hinterlegt (Proxy-Zugangsdaten): "
            "Basic <<secret:0>>\nBitte prüfen, ob der Wert noch gültig ist.\n",
            "http_basic_auth", 14002, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "2026-09-14 08:12:03,902 DEBUG [main] Sitzung übernommen: mandant=0042 JSESSIONID=<<secret:0>> "
            "wiederholungen=3\n",
            "java_session_id", 14003, carrier="log",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "sitzung:\n  domain: shop.intern\n  cookie: \"PHPSESSID=<<secret:0>>\"\n",
            "php_session_id", 14004, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "[08:17] daniel.r: Cookie aus dem Browser, damit du die Sitzung nachstellen kannst: "
            "laravel_session=<<secret:0>>\n",
            "laravel_session", 14005, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "upstream:\n  base_url: https://api.internal/v2\n  proxy_authorization: \"Basic <<secret:0>>\"\n",
            "http_basic_auth", 14011, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "Hi team,\n\nhere are the proxy credentials for the reporting job:\n\nBasic <<secret:0>>\n\n"
            "Please delete this mail after the run.\n",
            "http_basic_auth", 14012, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "# copied from the browser for the load test\nSESSION_COOKIE=JSESSIONID=<<secret:0>>\n",
            "java_session_id", 14013, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "[09:43] tom.w: grabbed it from devtools: connect.sid=<<secret:0>>\n",
            "express_session_id", 14014, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "$ curl -b 'laravel_session=<<secret:0>>' https://shop.internal/account\n",
            "laravel_session", 14015, carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "PROXY_AUTHORIZATION=Basic SGFsbG8gV2VsdCBkYXMgaXN0IGVpbg==\n",
            "base64 without user:password", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "// Testfall: Zugangsdaten werden kodiert\nexpect(header).toBe(\"Basic YmVudXR6ZXI6cGFzc3dvcnQ=\");\n",
            "test value benutzer:passwort", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "SESSION_COOKIE=PHPSESSID=HIER_SITZUNG_EINTRAGEN\n",
            "placeholder as session id", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "if (cookie.getName().equals(\"JSESSIONID\")) {\n    sitzung = cookie.getValue();\n}\n",
            "cookie name in code", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_session_cookie",
            "2026-09-14 08:12:03,902 DEBUG [main] Sitzung beendet: JSESSIONID=${SITZUNG}\n",
            "template reference as session id", carrier="log",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "    cy.get(\"@tokenRequest\")\n      .its(\"request.headers.authorization\")\n"
            "      .should(\"equal\", \"Basic YXBwbGljYXRpb246c2VjcmV0\")\n",
            "swagger-ui test value application:secret", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "The RFC 7617 example sends Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n",
            "documented RFC 7617 example", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "Basic usage of the client is documented in docs/usage.md\n",
            "word after Basic", carrier="prose",
        ),
        dl(
            "CREDENTIAL", "de", "dlp_basic_auth",
            "GET /v1/lager HTTP/1.1\nHost: api.intern\nAuthorization: Basic <<secret:0>>\n",
            "http_basic_credentials", 14006, "random base64 that decodes to no user:password", carrier="http",
        ),
        dl(
            "CREDENTIAL", "en", "dlp_basic_auth",
            "proxy_authorization: \"Basic <<secret:0>>\"\n",
            "http_basic_credentials", 14016, "random base64 that decodes to no user:password", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "session_cookie: \"JSESSIONID=<redacted>\"\n",
            "redacted session id", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_session_cookie",
            "Set-Cookie: __Host-session=${SESSION_ID}; Path=/; Secure; HttpOnly\n",
            "environment reference in a __Host- cookie", carrier="http",
        ),
    ],
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "{\n  \"dienst\": \"lagerabgleich\",\n  \"zugang\": {\n    \"authorization\": \"Bearer <<secret:0>>\"\n  }\n}\n",
            "bearer_opaque_token", 14021, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "[08:15] lena.s: Wie lautet der Access-Token für die Testumgebung?\n[08:17] daniel.r: Bearer <<secret:0>>\n",
            "bearer_opaque_token", 14022, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "[upstream]\nbasis_url = \"https://api.intern/v2\"\nauthorization = \"Bearer <<secret:0>>\"\n",
            "bearer_opaque_token", 14023, carrier="toml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "2026-09-14 08:12:03,902 DEBUG [main] Konfiguration geladen: mandant=0042 "
            "authorization=Bearer <<secret:0>> wiederholungen=3\n",
            "bearer_opaque_token", 14024, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_jwt_token",
            "{\n  \"zugang\": {\n    \"proxyAuthorization\": \"Bearer <<secret:0>>\"\n  }\n}\n",
            "jwt_signed_hs256", 14025, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "API_BASE_URL=https://api.internal/v1\nAUTHORIZATION=Bearer <<secret:0>>\n",
            "bearer_opaque_token", 14031, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "const client = new Client({\n  baseUrl: \"https://api.internal\",\n  authorization: \"Bearer <<secret:0>>\",\n});\n",
            "bearer_opaque_token", 14032, carrier="code",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "From: Alex Turner <alex.turner@example.com>\nSubject: Access token for the reporting job\n\n"
            "Hi team,\n\nhere is the access token for the job, valid until Friday:\n\nBearer <<secret:0>>\n\nThanks, Alex\n",
            "bearer_opaque_token", 14033, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "    \"os.environ[\\\"AUTHORIZATION\\\"] = \\\"Bearer <<secret:0>>\\\"\\n\",\n",
            "bearer_opaque_token", 14034, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_jwt_token",
            "AUTHORIZATION=Bearer <<secret:0>>\n",
            "jwt_signed_rs256", 14035, carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "AUTHORIZATION=Bearer ${LAGER_TOKEN}\n",
            "environment reference after Bearer", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "{\n  \"authorization\": \"Bearer {{zugangstoken}}\"\n}\n",
            "template after Bearer", carrier="json",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "[08:17] daniel.r: Der Header lautet Bearer gefolgt vom Token aus dem Vault.\n",
            "prose word after Bearer", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "headers = {\"Authorization\": \"Bearer \" + zugangs_token}\n",
            "concatenated variable", carrier="code",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_bearer_token",
            "authorization = \"Bearer zugangstoken_lager\"\n",
            "identifier after Bearer", carrier="toml",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "    expect(text).to.include(`-H \"Authorization: Bearer abc123.xyz.789\"`)\n",
            "swagger-ui test value abc123.xyz.789", carrier="code",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "      .its(\"authorization\")\n      .should(\"equal\", \"Bearer secret_token\")\n",
            "swagger-ui test value secret_token", carrier="code",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "Bearer authentication (also called token authentication) sends a token in the header.\n",
            "prose about the scheme", carrier="prose",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "AUTHORIZATION=Bearer YOUR_ACCESS_TOKEN_HERE\n",
            "documented placeholder", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_bearer_token",
            "log.debug(\"authorization=Bearer %s\", token)\n",
            "format placeholder", carrier="code",
        ),
    ],
}
for _label, _rows in DLP_FHTTP_CASES.items():
    DLP_CASES[_label].extend(_rows)


# K05: config key->value extraction, part 1 (env, INI/properties, HTTP headers) with a
# value-shape filter. A config line binds its whole value (an unquoted properties/INI/header value
# with ; , } inside, up to an inline comment), and a hex secret under a plain credential key
# stays a secret. Hard negatives: one per shape that a credential-like key must not bind, with
# DE and EN keys: UUID, algorithm-prefixed digest, hex digest under a digest key, ObjectId,
# template/format field, variable reference, boolean, number, path and URL without
# credentials. Each value line ends the text, so that the raw JSONL line holds no finding.
DLP_K05_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# Anwendungseinstellungen Lagerverwaltung\nlager.standort=hamburg\nlager.db.passwort=<<secret:0>>\n",
            "quoted_punctuated_password", 15001, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[datenbank]\nhost = db.lager.intern\nbenutzer = lager\npasswort = <<secret:0>> ; rotiert im September\n",
            "quoted_punctuated_password", 15002, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "GET /v1/lieferungen?status=offen HTTP/1.1\nHost: api.lager.intern\nX-Zugangstoken: <<secret:0>>\n"
            "Accept: application/json\n",
            "quoted_punctuated_password", 15003, carrier="http",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Lagerdienst, lokale Entwicklung\nLAGER_DIENST_SECRET=<<secret:0>>\nLAGER_PORT=8082\n",
            "generic_api_secret", 15004, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "# Anwendungseinstellungen Versand\nversand.api-schluessel=<<secret:0>>\nversand.zeitlimit=30s\n",
            "url_token", 15005, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "# application.properties\nspring.datasource.url=jdbc:postgresql://db:5432/orders\n"
            "spring.datasource.password=<<secret:0>>\n",
            "quoted_punctuated_password", 15011, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[smtp]\nhost = mail.internal\nuser = reports\npassword = <<secret:0>> # rotated monthly\n",
            "quoted_punctuated_password", 15012, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Client-Secret: <<secret:0>>\n"
            "Content-Type: application/json\n",
            "quoted_punctuated_password", 15013, carrier="http",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# .env for the billing worker\nBILLING_CLIENT_SECRET=<<secret:0>>\nBILLING_QUEUE=invoices\n",
            "generic_api_secret", 15014, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "export REPORT_SERVICE_TOKEN=\"<<secret:0>>\"  # production\n",
            "password", 15015, carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Lagerdienst\nLAGER_PORT=8082\nLAGER_API_TOKEN=3f2a9c4e-7b1d-4e8a-9c2f-5d6e7f8a9b0c",
            "UUID under a token key", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "# Lagerverwaltung\nlager.geheimnis=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "algorithm-prefixed digest under a secret key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[konto]\nbenutzer = lager\ngehashtes_passwort = 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "hex digest under a hashed-password key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "# Lagerverwaltung\nlager.zugangstoken=5f8d0c3e9b1a2d4c6e8f0a1b",
            "MongoDB ObjectId under a token key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[datenbank]\nhost = db.lager.intern\npasswort = {lager_passwort}",
            "format field under a password key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "REM Lagerdienst unter Windows\nset LAGER_PORT=8082\nLAGER_KENNWORT=%LAGER_KENNWORT%",
            "Windows variable reference", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Verschlüsselung im Testsystem abgeschaltet\nLAGER_GEHEIMNIS=deaktiviert",
            "boolean word under a secret key", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[sicherheit]\npasswort_min_laenge = 12\npasswort = 20260914",
            "number under a password key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Passwort liegt als Datei im Container\nLAGER_PASSWORT=/etc/lager/passwort.txt",
            "path under a password key", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "GET /v1/lieferungen HTTP/1.1\nHost: api.lager.intern\nX-Api-Schluessel: https://tresor.lager.intern/v1/lager/api",
            "URL without credentials in a header", carrier="http",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Api-Key: 550e8400-e29b-41d4-a716-446655440000",
            "UUID in an API key header", carrier="http",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# image digest pinned by the deploy job\nDEPLOY_SECRET=sha1-2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "algorithm-prefixed digest under a secret key", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# checksum of the release token, not the token\nSHA256_RELEASE_TOKEN="
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "hex digest under a digest-named token key", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# owner document of the integration\nORDER_SERVICE_TOKEN=6512bd43d9caa6e02c990b0a",
            "MongoDB ObjectId under a token key", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "[oauth]\nclient_id = reports\nclient_secret = %(client_secret)s",
            "Python format field under a secret key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# filled in by the CI job\nexport DEPLOY_API_TOKEN=$CI_DEPLOY_API_TOKEN",
            "shell variable reference", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "POST /v1/exports HTTP/1.1\nHost: api.internal\nX-Auth-Token: disabled",
            "boolean word in a token header", carrier="http",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# OAuth settings\noauth.client-secret=86400000",
            "number under a secret key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[database]\nhost = db.internal\npassword = C:\\secrets\\orders-db.txt",
            "Windows path under a password key", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# token endpoint of the identity provider\nIDP_CLIENT_SECRET=https://auth.internal/realms/acme/protocol/openid-connect/token",
            "URL without credentials under a secret key", carrier="env",
        ),
    ],
}
for _label, _rows in DLP_K05_CASES.items():
    DLP_CASES[_label].extend(_rows)



def ds_items(
    label: str,
    language: str,
    rule: str,
    template: str,
    generator: str,
    seeds: tuple[int, ...],
    *,
    carrier: str,
) -> dict:
    """Secret positive with one generator recipe per `<<secret:i>>` (array items)."""
    secrets = [{"gen": generator, "seed": seed} for seed in seeds]
    row = secret_template_positive(label, language, template, secrets)
    return dlp_row(row, rule, carrier, (), False)


# K05B: config key->value extraction, part 2 (YAML, JSON, TOML) with the K05 value-shape filter.
# A key binds its whole value at any nesting depth (a plain YAML value with ; , } inside up to an
# inline comment, a YAML list entry), and an array under a credential key binds each string item:
# JSON and TOML arrays (also over several lines), YAML flow and block sequences; a plural key
# (api_keys, tokens) binds only items. Hard negatives: the K05 shapes per format, as values and as
# items (UUID, prefixed digest, hex digest under a digest key, ObjectId, template/format field,
# reference, boolean, number, path, URL without credentials), plus a YAML alias, a SOPS value, a
# tokenizer list and a Rust raw pointer type. Each value line ends the text.
DLP_K05B_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "lager:\n  datenbank:\n    host: db.lager.intern\n    passwort: <<secret:0>>  # rotiert im September\n",
            "quoted_punctuated_password", 15101, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "versand:\n  - name: paketdienst\n    zugangstoken: <<secret:0>> # produktiv\n  - name: spedition\n",
            "quoted_punctuated_password", 15102, carrier="yaml",
        ),
        ds_items(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "# Versanddienst, Schlüssel werden quartalsweise rotiert\nversand:\n  api_schluessel:\n"
            "    - <<secret:0>>\n    - <<secret:1>>\n  region: eu-central-1\n",
            "url_token", (15103, 15104), carrier="yaml",
        ),
        ds_items(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\n  \"lager\": {\n    \"standort\": \"hamburg\",\n    \"zugangstokens\": [\n"
            "      \"<<secret:0>>\",\n      \"<<secret:1>>\"\n    ]\n  }\n}\n",
            "url_token", (15105, 15106), carrier="json",
        ),
        ds_items(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "[versand]\nendpunkt = \"https://api.versand.intern\"\ntokens = [\n  \"<<secret:0>>\",  # primär\n"
            "  \"<<secret:1>>\",\n]\n",
            "generic_api_secret", (15107, 15108), carrier="toml",
        ),
        ds_items(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "lager:\n  geheimnis: [<<secret:0>>, \"<<secret:1>>\"]\n  zeitlimit: 30s\n",
            "url_token", (15109, 15110), carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "spring:\n  datasource:\n    url: jdbc:postgresql://db:5432/orders\n    password: <<secret:0>> # rotated monthly\n",
            "quoted_punctuated_password", 15111, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "services:\n  - name: billing\n    client_secret: <<secret:0>>\n  - name: reports\n",
            "quoted_punctuated_password", 15112, carrier="yaml",
        ),
        ds_items(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\"service\": \"exports\", \"auth\": {\"api_keys\": [\"<<secret:0>>\", \"<<secret:1>>\"]}}\n",
            "url_token", (15113, 15114), carrier="json",
        ),
        ds_items(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "[auth]\nissuer = \"https://auth.internal\"\napi_keys = [\"<<secret:0>>\", '<<secret:1>>']\n",
            "url_token", (15115, 15116), carrier="toml",
        ),
        ds_items(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# webhook verification, old and new during rotation\nwebhooks:\n  tokens:\n    - <<secret:0>>\n"
            "    - \"<<secret:1>>\" # since March\n",
            "generic_api_secret", (15117, 15118), carrier="yaml",
        ),
        ds_items(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "services:\n  worker:\n    image: exports:1.4\n    environment:\n      SERVICE_TOKENS:\n"
            "        - <<secret:0>>\n",
            "url_token", (15119,), carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "lager:\n  standort: hamburg\n  api_token: 3f2a9c4e-7b1d-4e8a-9c2f-5d6e7f8a9b0c",
            "UUID under a nested YAML token key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\"lager\": {\"standort\": \"hamburg\", \"geheimnis\": "
            "\"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"}}",
            "algorithm-prefixed digest under a nested JSON secret key", carrier="json",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "konto:\n  benutzer: lager\n  gehashtes_passwort: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "hex digest under a YAML hashed-password key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\"lager\": {\"zugangstokens\": [\"5f8d0c3e9b1a2d4c6e8f0a1b\", \"5f8d0c3e9b1a2d4c6e8f0a1c\"]}}",
            "MongoDB ObjectIds in a JSON token array", carrier="json",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "[versand]\nendpunkt = \"https://api.versand.intern\"\ntokens = [\"${VERSAND_TOKEN}\", \"{versand_token}\"]",
            "template fields in a TOML token array", carrier="toml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "versand:\n  api_schluessel:\n    - $LAGER_API_SCHLUESSEL\n    - \"%LAGER_API_SCHLUESSEL%\"",
            "variable references in a YAML key sequence", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "# Verschlüsselung im Testsystem abgeschaltet\nverschluesselung:\n  geheimnis: deaktiviert",
            "boolean word under a nested YAML secret key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "[sicherheit]\n# Gültigkeit der Tokens in Sekunden\ntokens = [86400, 3600]",
            "numbers in a TOML token array", carrier="toml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# Passwort liegt als Docker-Secret im Container\nlager:\n  passwort: /run/secrets/lager_passwort",
            "path under a nested YAML password key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\"versand\": {\"api_schluessel\": \"https://tresor.lager.intern/v1/versand\"}}",
            "URL without credentials under a nested JSON key", carrier="json",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "standard: &lager_standard\n  benutzer: lager\nproduktion:\n  passwort: *lager_standard_passwort",
            "YAML alias under a password key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# mit SOPS verschlüsselt\nlager:\n  passwort: "
            "ENC[AES256_GCM,data:Zm9vYmFyYmF6cXV4,iv:Tz8Wm4K93RVq,tag:Kx7pQ2vL,type:str]",
            "SOPS-encrypted value under a password key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\"auth\": {\"client_id\": \"reports\", \"client_secret\": \"550e8400-e29b-41d4-a716-446655440000\"}}",
            "UUID under a nested JSON secret key", carrier="json",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "[auth]\nissuer = \"https://auth.internal\"\napi_keys = [\"550e8400-e29b-41d4-a716-446655440000\"]",
            "UUID in a TOML key array", carrier="toml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "assets:\n  access_token: sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC",
            "SRI digest under a nested YAML token key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# checksums of the release tokens, not the tokens\n"
            "sha256_tokens = [\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"]",
            "hex digests under a digest-named TOML token array", carrier="toml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# owner document of the integration\nowner:\n  api_token: 6512bd43d9caa6e02c990b0a",
            "MongoDB ObjectId under a nested YAML token key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\"oauth\": {\"client_id\": \"reports\", \"client_secret\": \"%(client_secret)s\"}}",
            "Python format field under a nested JSON secret key", carrier="json",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# filled in by the task runner\nauth:\n  api_key: env:BILLING_API_KEY",
            "environment reference under a nested YAML key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\"auth\": {\"mode\": \"none\", \"api_token\": \"disabled\"}}",
            "boolean word under a nested JSON token key", carrier="json",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# OAuth settings\noauth:\n  client_secret: 86400000",
            "number under a nested YAML secret key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[database]\nhost = \"db.internal\"\npasswords = ['C:\\secrets\\orders-db.txt']",
            "Windows path in a TOML password array", carrier="toml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "# token endpoint of the identity provider\nidp:\n  client_secret: "
            "https://auth.internal/realms/acme/protocol/openid-connect/token",
            "URL without credentials under a nested YAML secret key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "{\"model\": \"bpe\", \"tokens\": [\"<|endoftext|>\", \"\u0120constructor\", \"ing</w>\", \"abc12345\"]}",
            "tokenizer entries in a JSON token list", carrier="json",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "extern \"C\" {\n    pub fn getpwnam_r(\n        name: *const c_char,\n        pwd: *mut passwd,\n",
            "Rust raw pointer type after a pwd parameter", carrier="code",
        ),
    ],
}
for _label, _rows in DLP_K05B_CASES.items():
    DLP_CASES[_label].extend(_rows)

# G01: connection strings per scheme. `dlp_connection_string_password` reports the password of
# a `;`-separated key/value string with a server, data source, host, DSN, driver or provider key or
# after a jdbc: URL (ADO.NET, ODBC with {…} values, JDBC SQL Server properties), of a libpq
# keyword/value string with a host and a database, user or port, the password query parameter of a
# database or broker URL (JDBC MySQL/PostgreSQL, libpq URI) and the password of an Oracle thin URL;
# `dlp_ldap_bind_password` the bind password of `ldapsearch … -w`, nslcd `bindpw`, SSSD
# `ldap_default_authtok`, Keycloak `bindCredential` and Apache `AuthLDAPBindPassword`;
# `dlp_url_userinfo_password` also the Redis password without a username (`redis://:…@`). Hard
# negatives: environment and template references, placeholders, stand-ins, integrated security and
# libpq strings without a password, the password prompt `-W` and documented call syntax.
DLP_G01_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "{\n  \"ConnectionStrings\": {\n    \"Lager\": \"Server=sql01.lager.intern;Database=lager;"
            "User Id=lager_app;Password=<<secret:0>>;TrustServerCertificate=True\"\n  }\n}\n",
            "password", 16001, carrier="json",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "# Lagerabgleich (ODBC)\nLAGER_DSN=Driver={ODBC Driver 18 for SQL Server};Server=sql01;Uid=lager;"
            "Pwd={<<secret:0>>};\n",
            "password", 16002, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "# Anwendungseinstellungen Lagerverwaltung\nlager.datasource.url=jdbc:sqlserver://sql01.lager.intern:1433;"
            "databaseName=lager;user=lager_app;password=<<secret:0>>;encrypt=true\n",
            "password", 16003, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "$ psql \"host=db.lager.intern port=5432 dbname=lager user=lager_app password=<<secret:0>> "
            "sslmode=require\"\npsql (16.4)\nlager=>\n",
            "url_userinfo_password", 16004, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "Hallo Jana,\n\ndie Berichtsdatenbank erreichst du über "
            "jdbc:mysql://bericht.intern:3306/berichte?user=bericht&password=<<secret:0>>&useSSL=true\n"
            "Bitte nicht weiterleiten.\n",
            "url_userinfo_password", 16005, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "// Altanbindung an das Lager-ERP\nString url = \"jdbc:oracle:thin:lager/<<secret:0>>"
            "@//ora01.lager.intern:1521/LAGER\";\n",
            "url_userinfo_password", 16006, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# Zwischenspeicher für Sitzungen\nCACHE_URL=redis://:<<secret:0>>@cache.lager.intern:6379/0\n",
            "url_userinfo_password", 16007, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_ldap_bind_password",
            "$ ldapsearch -x -H ldaps://verzeichnis.intern -D \"cn=admin,dc=lager,dc=de\" -w <<secret:0>> "
            "-b \"ou=personen,dc=lager,dc=de\" uid=jana\n",
            "url_userinfo_password", 16008, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_ldap_bind_password",
            "# /etc/nslcd.conf – Verzeichnisanbindung der Lagerrechner\nuri ldaps://verzeichnis.intern\n"
            "base dc=lager,dc=de\nbinddn cn=nslcd,ou=dienste,dc=lager,dc=de\nbindpw <<secret:0>>\n",
            "password", 16009, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "<configuration>\n  <connectionStrings>\n    <add name=\"Orders\" connectionString=\"Data Source=sql02.internal;"
            "Initial Catalog=orders;User ID=orders_app;Password=<<secret:0>>;Encrypt=True\" "
            "providerName=\"System.Data.SqlClient\" />\n  </connectionStrings>\n</configuration>\n",
            "password", 16011, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "spring:\n  datasource:\n    url: jdbc:postgresql://db.internal:5432/orders?user=orders&password=<<secret:0>>"
            "&sslmode=require\n    hikari:\n      maximum-pool-size: 10\n",
            "url_userinfo_password", 16012, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "import pyodbc\n\nconn = pyodbc.connect(\n    \"DRIVER={ODBC Driver 18 for SQL Server};SERVER=sql02.internal;"
            "DATABASE=orders;UID=orders;PWD=<<secret:0>>\"\n)\n",
            "password", 16013, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "2026-09-14T08:12:03.441Z DEBUG [pool] connecting with host=db.internal port=5432 dbname=orders "
            "user=orders password=<<secret:0>> sslmode=require\n",
            "url_userinfo_password", 16014, carrier="log",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "Hi Sam,\n\nthe nightly export connects with\n\n"
            "Server=sql02.internal;Database=orders;User Id=export;Password=<<secret:0>>;\n\n"
            "Please move it to the vault after the migration.\n",
            "password", 16015, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "# session cache\nREDIS_URL=rediss://:<<secret:0>>@cache.internal:6380/0\n",
            "url_userinfo_password", 16016, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_ldap_bind_password",
            "[domain/acme]\nid_provider = ldap\nldap_uri = ldaps://ldap.internal\n"
            "ldap_default_bind_dn = cn=sssd,ou=services,dc=acme,dc=org\nldap_default_authtok = <<secret:0>>\n",
            "password", 16017, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_ldap_bind_password",
            "{\n  \"providerId\": \"ldap\",\n  \"bindDn\": \"cn=keycloak,ou=services,dc=acme,dc=org\",\n"
            "  \"bindCredential\": \"<<secret:0>>\"\n}\n",
            "url_userinfo_password", 16018, carrier="json",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_ldap_bind_password",
            "<Location \"/intranet\">\n  AuthType Basic\n  AuthBasicProvider ldap\n"
            "  AuthLDAPURL \"ldaps://ldap.internal/ou=people,dc=acme,dc=org?uid\"\n"
            "  AuthLDAPBindDN \"cn=apache,ou=services,dc=acme,dc=org\"\n  AuthLDAPBindPassword \"<<secret:0>>\"\n"
            "</Location>\n",
            "password", 16019, carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "LAGER_DB=Server=sql01.lager.intern;Database=lager;User Id=lager_app;Password=${LAGER_DB_PASSWORT};\n",
            "environment reference as connection string password", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "{\"ConnectionStrings\": {\"Lager\": \"Server=sql01;Database=lager;Trusted_Connection=True;\"}}\n",
            "Windows authentication without a password", carrier="json",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "# Vorlage, Passwort beim Deployment eintragen\nlager.db=Data Source=sql01;Initial Catalog=lager;"
            "User ID=lager_app;Password=<hier-passwort-eintragen>;\n",
            "placeholder as connection string password", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_connection_string_password",
            "$ psql \"host=db.lager.intern port=5432 dbname=lager user=lager_app sslmode=require\"\nPasswort für Benutzer lager_app:\n",
            "libpq string without a password (prompt)", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_ldap_bind_password",
            "$ ldapsearch -x -D \"cn=admin,dc=lager,dc=de\" -W -b \"dc=lager,dc=de\" uid=jana\nEnter LDAP Password:\n",
            "ldapsearch password prompt -W without a value", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_ldap_bind_password",
            "$ ldapsearch -x -D \"cn=admin,dc=lager,dc=de\" -w \"$LDAP_PASSWORT\" -b \"dc=lager,dc=de\"\n",
            "shell variable as bind password", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_ldap_bind_password",
            "Aufruf laut Handbuch: ldapsearch -x -D <bind-dn> -w <passwort> -b <basis-dn> [filter]\n",
            "documented call syntax with placeholders", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "ORDERS_DB=Server=sql02.internal;Database=orders;User Id=orders_app;Password=${ORDERS_DB_PASSWORD};\n",
            "environment reference as connection string password", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "<add name=\"Orders\" connectionString=\"Data Source=sql02.internal;Initial Catalog=orders;"
            "Integrated Security=SSPI\" providerName=\"System.Data.SqlClient\" />\n",
            "integrated security without a password", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "spring.datasource.url=jdbc:postgresql://db.internal:5432/orders?user=orders&password=<your-password>\n",
            "placeholder as query password", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_connection_string_password",
            "// docs: connection string format\nvar cs = \"Server=myServerAddress;Database=myDataBase;"
            "User Id=myUsername;Password=myPassword;\";\n",
            "documented stand-in password", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_ldap_bind_password",
            "$ ldapsearch -x -D \"cn=admin,dc=acme,dc=org\" -w \"$LDAP_BIND_PW\" -b \"dc=acme,dc=org\"\n",
            "shell variable as bind password", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_ldap_bind_password",
            "# nslcd.conf template\nbinddn cn=nslcd,ou=services,dc=acme,dc=org\nbindpw changeme\n",
            "placeholder as bind password", carrier="ini",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_ldap_bind_password",
            "The bindpw option sets the password that nslcd uses for the simple bind.\n",
            "option name in prose", carrier="prose",
        ),
    ],
}
for _label, _rows in DLP_G01_CASES.items():
    DLP_CASES[_label].extend(_rows)

def flatten(suite: str, cases: dict[str, list[dict]]) -> list[dict]:
    rows = []
    for label, label_cases in cases.items():
        for index, row in enumerate(label_cases, start=1):
            sign = "pos" if row["case_type"] == "positive" else "neg"
            slug = label.lower().replace(".", "-").replace("_", "-")
            rows.append({"id": f"{suite}-{slug}-{sign}-{index:02d}", "suite": suite, **row})
    return rows


def serialize(row: dict) -> str:
    """One JSONL line. The placeholder colon is written as the JSON escape ``\\u003a``.

    In the raw file a placeholder followed by more text (``<<secret:0>>\\nregion``)
    otherwise reads as ``secret: <value>`` to generic credential scanners.
    """
    line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
    return line.replace("<<secret:", "<<secret\\u003a")


def write(name: str, rows: list[dict]) -> None:
    path = DATA_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(serialize(row) + "\n")


if __name__ == "__main__":
    write("pii_l1", flatten("pii_l1", PII_CASES))
    write("dlp_l1", flatten("dlp_l1", DLP_CASES))
