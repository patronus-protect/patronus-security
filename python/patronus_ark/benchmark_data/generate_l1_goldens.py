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
        # F01: a national number of another numbering plan (AT, CH, FR, BE, NO, DK, BR, JP)
        # with a phone term, valid per the libphonenumber metadata; scored modes only.
        p("PHONE", "de", "pii_phone_regional", "Handy: ", "0688 843 79 56", mode="balanced"),
        p("PHONE", "de", "pii_phone_regional", "Frau Huber ist mobil erreichbar unter ", "0699 868 88 55", ".", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "de", "pii_phone_regional", "Telefon (Zürich): ", "044 668 18 00", mode="balanced"),
        p("PHONE", "de", "pii_phone_regional", "Name;Telefon\nClaire Martin;", "01.84.17.61.18", "", carrier="csv", tags=("no_context",), mode="balanced"),
        p("PHONE", "de", "pii_phone_regional", "Rückruf bitte unter ", "416 60 039", ".", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "en", "pii_phone_regional", "Mobile: ", "03.93.92.16.85", "\nDesk: n/a", mode="balanced"),
        p("PHONE", "en", "pii_phone_regional", "Can someone call me on ", "9472 7916", "? I have some questions.", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "en", "pii_phone_regional", "Please call me at ", "0494 92 82 32", " tomorrow.", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "en", "pii_phone_regional", "Fax: ", "28-64-66-98", mode="balanced"),
        p("PHONE", "en", "pii_phone_regional", "My Japanese phone number is ", "090-1234-5678", carrier="prose", tags=("no_context",), mode="balanced"),
        p("PHONE", "en", "pii_phone_regional", '{"phone": "', "(64) 3591-3246", '"}', carrier="json", mode="balanced"),
        n("PHONE", "de", "pii_phone_regional", "Rechnung 0494 92 82 32 vom Mai", "invoice number without a phone term", mode="balanced"),
        n("PHONE", "de", "pii_phone_regional", "Handy gekauft am 31.12.2024", "a date is not a phone number", mode="balanced"),
        n("PHONE", "de", "pii_phone_regional", "Telefon: 11 11 11 11", "repeated digits", mode="balanced"),
        n("PHONE", "de", "pii_phone_regional", "Ticket 03.93.92.16.85 ist erledigt.", "ticket number without a phone term", carrier="prose", mode="balanced"),
        n("PHONE", "de", "pii_phone_regional", "Telefon: 000 000 000", "zeros are no valid number in any plan", mode="balanced"),
        n("PHONE", "en", "pii_phone_regional", "Order 416 60 039 shipped today.", "order number without a phone term", carrier="prose", mode="balanced"),
        n("PHONE", "en", "pii_phone_regional", "Mobile: 2024-12-31", "an ISO date is not a phone number", mode="balanced"),
        n("PHONE", "en", "pii_phone_regional", "Phone: 12 34", "too few digits", mode="balanced"),
        n("PHONE", "en", "pii_phone_regional", "Phone: 123 456 789 012 345", "too many digits for a national number", mode="balanced"),
        n("PHONE", "en", "pii_phone_regional", "Tel.: 0000 000 0000", "zeros are no valid number in any plan", mode="balanced"),
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
        # Q-FIN: a security code whose field names the card binds without the card number.
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Credit Card Security Code: ", "279"),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "**Credit Card Security Code:** ", "438"),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "The insured has provided the credit card security code ", "545", " for the premium.", carrier="prose"),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Please do not share your credit card security code (", "050", ") with anyone.", carrier="prose"),
        p("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "It shipped with a credit card security code of ", "983", " and a signature.", carrier="prose"),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kreditkarte, Sicherheitscode: ", "123"),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kreditkarte – Kartenprüfnummer: ", "481"),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kreditkarte (Visa), CVV: ", "552"),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Bitte geben Sie zur Kreditkarte den Sicherheitscode ", "907", " an.", carrier="prose"),
        p("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Debitkarte CVC: ", "315"),
        p("CREDITCARD_CVV", "nl", "pii_credit_card_cvv", "Creditcardveiligheidscode: ", "713"),
        p("CREDITCARD_CVV", "fr", "pii_credit_card_cvv", "Code de sécurité de la carte de crédit : ", "965"),
        p("CREDITCARD_CVV", "it", "pii_credit_card_cvv", "Codice di sicurezza della carta di credito: ", "674"),
        p("CREDITCARD_CVV", "es", "pii_credit_card_cvv", "Código de Seguridad de Tarjeta de Crédito: ", "599"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Security code 4821 for the building door.", "security code without a card"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "The alarm security code is 7731.", "alarm code, not a card", carrier="prose"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Gift card balance: 250, security code 123", "card term not in the code's field"),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Credit card security code: ***", "masked value", tags=("obfuscated",)),
        n("CREDITCARD_CVV", "en", "pii_credit_card_cvv", "Credit card on file.\nSecurity code: 445", "card term in another clause"),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Tresor-Sicherheitscode: 9182", "safe code, not a card"),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Sicherheitscode: 4711 (Alarmanlage)", "alarm code, not a card"),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kreditkarte beantragt; Sicherheitscode: 5531", "card term in another clause"),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kreditkarte, Sicherheitscode: ***", "masked value", tags=("obfuscated",)),
        n("CREDITCARD_CVV", "de", "pii_credit_card_cvv", "Kundenkarte, Sicherheitscode 12", "too short"),
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
        p("IBAN", "de", "pii_iban_generic", "IBAN: ", "AT61 1904 3002 3457 3201", ""),
        p("IBAN", "en", "pii_iban_generic", "Please wire the deposit to ", "NL91ABNA0417164300", " by Friday.", carrier="prose", tags=("no_context",)),
        p("IBAN", "en", "pii_iban_generic", '{"beneficiary": "Acme BV", "iban": "', "FR1420041010050500013M02606", '"}', carrier="json"),
        p("IBAN", "en", "pii_iban_generic", "payee:\n  iban: ", "ES9121000418450200051332", "\n", carrier="yaml"),
        p("IBAN", "en", "pii_iban_de", "<account><iban>", "DE02700202700010108669", "</iban></account>", carrier="xml"),
        p("IBAN", "en", "pii_iban_generic", "IBAN ", "BE68539007547034", "  |  Ref. 2026/10", tags=("ocr",)),
        p("IBAN", "en", "pii_iban_generic", "IBAN: ", "GB29 NWBK 6016 1331 9268 19", ""),
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
        # Q-FIN: combined SWIFT/BIC field names, a note in parentheses, BIC before the value in prose.
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "Bank details: IBAN DE89 3704 0044 0532 0130 00, BIC ", "COBADEFFXXX", also=(("IBAN", "DE89 3704 0044 0532 0130 00"),)),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "Swift BIC Code (for international transactions): ", "DEUTDEFF500"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "Payments go to the bank with the SWIFT BIC code ", "BARCGB22", ".", carrier="prose"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "swift_bic_code: ", "CHASUS33", carrier="kv"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "<party><swiftBIC>", "UBSWCHZH80A", "</swiftBIC></party>", carrier="xml"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "Bankverbindung: IBAN DE89370400440532013000, BIC ", "COBADEFFXXX", also=(("IBAN", "DE89370400440532013000"),)),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "Swift/BIC-Code: ", "INGDDEFFXXX"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "Nachtrag zu meinen Daten, BIC ", "WNCCIT6D", ".", carrier="prose"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "SWIFT-BIC: ", "BYLADEM1001"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC (Empfängerbank): ", "GENODEF1M04"),
        p("SWIFT_CODE", "nl", "pii_swift_bic_context", "Swift/BIC-code: ", "RABONL2U"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "SWIFT BIC code missing from the form.", "lowercase word, not a BIC", carrier="prose"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "BIC 1234ABCD", "bank code must be letters"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "We route SWIFT PAYMENTS through the hub.", "SWIFT without a code or BIC field", carrier="prose"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "Swift BIC Code (2 of 3): DEUTDEFF500", "note with a digit is not a field note"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "swift_bic_code: DEUTD3", "invalid BIC length"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC siehe Kontoauszug", "lowercase word, not a BIC", carrier="prose"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "Swift/BIC-Code: ****DEFF", "masked value", tags=("obfuscated",)),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "BIC (Empfängerbank): folgt", "field without a value"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "Wir wickeln SWIFT ZAHLUNG ab.", "SWIFT without a code or BIC field", carrier="prose"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "SWIFT-BIC: DEUTDEFF5", "nine characters is not a BIC length"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", "Swift BIC Code for Bank Transfer: ", "YAOWGBAK845"),
        p("SWIFT_CODE", "en", "pii_swift_bic_context", 'We noted that the swift BIC code "', "DTHCGBRK958", '" is outdated.', carrier="prose"),
        p("SWIFT_CODE", "de", "pii_swift_bic_context", "Als BIC ist ", "QHPABE3KPNM", " hinterlegt.", carrier="prose"),
        p("SWIFT_CODE", "fr", "pii_swift_bic_context", "La banque, dont le code SWIFT est ", "REIUUSJL577", ", confirme.", carrier="prose"),
        p("SWIFT_CODE", "it", "pii_swift_bic_context", "Pagamento con il codice SWIFT ", "FHZZUSBS650", ".", carrier="prose"),
        n("SWIFT_CODE", "en", "pii_swift_bic_context", "Swift BIC Code for 2 banks: DEUTDEFF500", "note with a digit is not a field note"),
        n("SWIFT_CODE", "de", "pii_swift_bic_context", "Als BIC ist folgendes hinterlegt.", "lowercase word, not a BIC", carrier="prose"),
        n("SWIFT_CODE", "fr", "pii_swift_bic_context", "Le code SWIFT est obligatoire.", "lowercase word, not a BIC", carrier="prose"),
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
        p("CUSTOMER_ID", "de", "pii_customer_id", "Ihre Kundennummer lautet ", "KD-10293", ".", carrier="prose"),
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
        p("DOB", "en", "pii_date_of_birth", '{"dob": "', "1990-11-02", '"}', carrier="json"),
        p("DOB", "en", "pii_date_of_birth", "Born on ", "02/11/1990", " in Leeds.", carrier="prose"),
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
        # Q-FIN: abbreviated field with dot and colon, `ist` as assignment, `on file`.
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Zur Zuordnung – Konto-Nr.: ", "192555007", "."),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Als Kontonummer ist ", "17404395", " hinterlegt.", carrier="prose"),
        p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Unsere Unterlagen nennen als Konto-Nr.: ", "9611835706", "."),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "The Bank account on file is ", "20875414", ".", carrier="prose"),
        p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Your account number is ", "207424939751", ".", carrier="prose"),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Permanent Account Number: DNKPL8403R", "Indian PAN, not a bank account", also=(("IN_PAN", "DNKPL8403R"),)),
        n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Permanent Account Number:\tPNHPM1821Q", "Indian PAN, not a bank account", also=(("IN_PAN", "PNHPM1821Q"),)),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Konto-Nr.: folgt", "field without a value"),
        n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Als Kontonummer ist nichts hinterlegt.", "value contains no digit", carrier="prose"),
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
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "German Steuernummer: ", "9181081508155"),
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
        p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "company:\n  tax number: ", "2893/0815/08152", "\n", carrier="yaml"),
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
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: ", "12120356A122"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Rentenversicherungsnummer ", "65 230109 Z 872"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "German SV-Nr.: ", "12 120456 A 123"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: 12123456-123", "letter position is missing"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Referenz 12120356A122", "missing social-insurance anchor"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Meine Rentenversicherungsnummer ist ", "53270587M011", ".", carrier="prose", gap=True),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "beschaeftigter:\n  sozialversicherungsnummer: ", "15 070649 C 103", "\n", carrier="yaml"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "SV-Nr=", "65180539W001", carrier="kv"),
        p("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer:", "25220940K516", "   Krankenkasse: AOK", tags=("ocr",)),
        p("SOCIALID", "de", "pii_rentenversicherung_de", '{"sv_nummer": "', "53270587M022", '"}', carrier="json", gap=True),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "German pension insurance number: ", "53 270587 M 011"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "Her German social security number is ", "15070649C103", ".", carrier="prose"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "employee:\n  pension insurance number: ", "65180539W001", "\n", carrier="yaml"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "SV-Nr:", "25220940K516", "   Page 1", tags=("ocr",)),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "pension insurance number=", "12121156A138", carrier="kv"),
        p("SOCIALID", "en", "pii_rentenversicherung_de", "| SV number | ", "12121156A149", " |", carrier="table", gap=True),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: 1212345A123", "too few digits before the letter"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: siehe Ausweis", "field without a value"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Die Rentenversicherungsnummer steht im Sozialversicherungsausweis.", "field name without a value", carrier="prose"),
        n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: XX XXXXXX X XXX", "masked value", tags=("obfuscated",)),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "German pension insurance number: 12123456AB12", "two letters where one belongs"),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "Reference 65 230109 Z 872", "missing social-insurance anchor"),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "The pension insurance number is printed on the card.", "field name without a value", carrier="prose"),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "SV-Nr: XX XXXXXX X XXX", "masked value", tags=("obfuscated",)),
        n("SOCIALID", "en", "pii_rentenversicherung_de", "Pension insurance number: 123456789012", "letter position is missing"),
    ],
    "HEALTH_INSURANCE_NUMBER": [
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Health insurance number ", "X123456788", " is in the claim.", carrier="prose"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer: ", "A123456780"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR = ", "Z987654321"),
        n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR: A000000000", "all-zero numeric part is excluded"),
        n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Member number X123456788", "unsupported generic member anchor"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Die Versichertennummer lautet ", "M234567898", ".", carrier="prose", gap=True),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Die Krankenversicherungsnummer ist ", "M234568003", ".", carrier="prose", gap=True),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "versicherter:\n  kvnr: ", "T345678916", "\n", carrier="yaml"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR=", "R456789126", carrier="kv"),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer:", "K567891234", "   Kasse: TK", tags=("ocr",)),
        p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", '{"kvnr": "', "K567891309", '"}', carrier="json"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Health insurance number: ", "B678912348"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "insured:\n  kvnr: ", "C789123454", "\n", carrier="yaml"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "health insurance number=", "D891234569", carrier="kv"),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "KVNR:", "E912345676", "   Page 1", tags=("ocr",)),
        p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", '<insured kvnr="', "E912345702", '"/>', carrier="xml"),
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
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: ", "123456601"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Lebenslange Arztnummer ", "987654401"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "German LANR = ", "246813979"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: 000000000", "all-zero value is excluded"),
        n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Arztnummer: 123456789", "unsupported generic anchor"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "Die verordnende Ärztin hat die LANR ", "135792268", ".", carrier="prose"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "arzt:\n  lanr: ", "314159365", "\n", carrier="yaml"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR=", "271828382", carrier="kv"),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR:", "161803998", "   BSNR: siehe Stempel", tags=("ocr",)),
        p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", '{"lanr": "', "141421356", '"}', carrier="json"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "Physician number: ", "173205880"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "The prescribing doctor's LANR is ", "223606497", ".", carrier="prose"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "prescriber:\n  lanr: ", "264575431", "\n", carrier="yaml"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "lifelong physician number=", "282842612", carrier="kv"),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "LANR:", "331662179", "   Page 1", tags=("ocr",)),
        p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "| LANR | ", "331662180", " |", carrier="table"),
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
        p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "License plate: ", "F-EZ 67E", ""),
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
        p("SSN", "de", "pii_ssn_us_proximity", "Die SSN des US-Mitarbeiters ist ", "532-87-1094", ".", carrier="prose"),
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
        p("NATIONALID", "en", "pii_ni_uk", "NI number: ", "JK 55 66 77 B", ""),
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
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "<table><tr><th>Versichertennummer</th><td>", "M345678911", "</td></tr></table>", carrier="table"),
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
# IDs (`0000012345`) and 6-4 groups (`811228-9875`) are no NANP number. Positives keep `+49 …`,
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
    n("PHONE", "de", "pii_phone_us", "Personnummer: 811228-9875", "6-4 groups of a Swedish personal number whose Luhn digit fails (B-NORD reports valid ones)"),
    n("PHONE", "en", "pii_phone_international", "Interchange header: UNB+UNOC:3+520173321::2+520173321::4+202202150830+1323327835++STA'", "EDIFACT interchange header, element run"),
    n("PHONE", "en", "pii_phone_international", "Buyer party segment: NAD+BY+987654321::9'", "EDIFACT party ID after a qualifier"),
    n("PHONE", "en", "pii_phone_international", "SWIFT narrative block {86:+330105789456}", "number after a SWIFT MT tag"),
    n("PHONE", "en", "pii_phone_international", "Line item segment: LIN+1+3553 6548 1210 8739:1:PCE'", "EDIFACT item number after a qualifier"),
    n("PHONE", "en", "pii_phone_us", "X12 purchase order: ST*850*0000012345~\nSE*13*0000012345~", "zero-padded X12 control numbers"),
    n("PHONE", "en", "pii_phone_us", "Closing balance field: :62F:/0000001234/", "zero-padded account in a SWIFT MT field"),
    n("PHONE", "en", "pii_phone_us", '<xbrli:identifier scheme="http://www.sec.gov/CIK">0001234567</xbrli:identifier>', "zero-padded SEC CIK", carrier="xml"),
    n("PHONE", "en", "pii_phone_us", "Swedish personal identity number: 811228-9875", "6-4 groups of a Swedish personal number whose Luhn digit fails (B-NORD reports valid ones)"),
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
    n("CREDITCARD", "de", "pii_credit_card", "Südafrikanische ID-Nummer: 4506095123081", "ZA ID number (birth date 1945-06-09)", also=(("ZA_ID_NUMBER", "4506095123081"),)),
    n("CREDITCARD", "de", "pii_credit_card", "Südafrikanische ID-Nummer: 6804114321085", "ZA ID number (birth date 1968-04-11)", also=(("ZA_ID_NUMBER", "6804114321085"),)),
    n("CREDITCARD", "de", "pii_credit_card", "Koreanische Registrierungsnummer: 470312-1081835", "KR resident registration number", also=(("KR_RRN", "470312-1081835"),)),
    n("CREDITCARD", "de", "pii_credit_card", "Referenz 1748503543012", "13 digits without a card IIN"),
    n("CREDITCARD", "de", "pii_credit_card", "Belegnummer 3731 4925 8607 3149", "Amex prefix with 16 digits"),
    n("CREDITCARD", "en", "pii_credit_card", "Phone: +44 20 1234 5678", "digits after + of a phone number", also=(("PHONE", "+44 20 1234 5678"),)),
    n("CREDITCARD", "en", "pii_credit_card", "Mobile: +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", also=(("PHONE", "+63 917 123 4565"),)),
    n("CREDITCARD", "en", "pii_credit_card", "Message date: DTM+137:202201010800'", "EDIFACT date-time stamp"),
    n("CREDITCARD", "en", "pii_credit_card", '"TradeID": "20220314-123456-ABC-IBK"', "date-time stamp in a trade ID", carrier="json"),
    n("CREDITCARD", "en", "pii_credit_card", "Log time 199912312359596", "date-time stamp, UATP-shaped"),
    n("CREDITCARD", "en", "pii_credit_card", "Session token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments"),
    n("CREDITCARD", "en", "pii_credit_card", "South African ID number: 6109240123185", "ZA ID number (birth date 1961-09-24)", also=(("ZA_ID_NUMBER", "6109240123185"),)),
    n("CREDITCARD", "en", "pii_credit_card", "SA ID: 4901015009082", "ZA ID number (birth date 1949-01-01)", also=(("ZA_ID_NUMBER", "4901015009082"),)),
    n("CREDITCARD", "en", "pii_credit_card", "Resident Registration Number: 590724-1069401", "KR resident registration number", also=(("KR_RRN", "590724-1069401"),)),
    n("CREDITCARD", "en", "pii_credit_card", "1748503543012", "13 digits without a card IIN (presidio-analyzer credit card test)"),
    n("CREDITCARD", "en", "pii_credit_card", "Reference 2731 4925 8607 3141", "no brand in the 27xx range above 2720"),
    n("CREDITCARD", "de", "pii_credit_card", "Rückruf unter +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", carrier="prose", also=(("PHONE", "+63 917 123 4565"),), mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Südafrikanische ID-Nummer: 4506095123081", "ZA ID number (birth date 1945-06-09)", also=(("ZA_ID_NUMBER", "4506095123081"),), mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Referenz 1748503543012", "13 digits without a card IIN", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Sitzungs-Token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments", mode="balanced"),
    n("CREDITCARD", "de", "pii_credit_card", "Koreanische Registrierungsnummer: 640918-2196672", "KR resident registration number", also=(("KR_RRN", "640918-2196672"),), mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "Mobile: +63 917 123 4565", "digits after + of a phone number (Maestro-shaped)", also=(("PHONE", "+63 917 123 4565"),), mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "South African ID number: 6109240123185", "ZA ID number (birth date 1961-09-24)", also=(("ZA_ID_NUMBER", "6109240123185"),), mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "1748503543012", "13 digits without a card IIN (presidio-analyzer credit card test)", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "Session token: sess-507314925862-485275870833-t2VJdhdgBlIo58gou6ZuqmoL", "token segments", mode="balanced"),
    n("CREDITCARD", "en", "pii_credit_card", "RRN 450630-2848967", "KR resident registration number", also=(("KR_RRN", "450630-2848967"),), mode="balanced"),
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

# B-SSN US Social Security Number beyond the field name (T25, F07; baseline P1, TRIAGE W43
# bucket 11). `pii_ssn_us_proximity` reports AAA-GG-SSSS (hyphens, dots or spaces) and nine
# bare digits in every mode when an SSN term stands near the value or is its structural key;
# `pii_ssn_us_context_free` reports the grouped form without a term in balanced and recall
# only. Hard negatives: grouped values without an SSN term in strict, order, reference and
# part numbers (counter-context) in every mode, nine digits without an SSN term, values
# outside the SSA ranges, values that continue a longer number and, without a term,
# placeholder values (one repeated digit, 123-45-6789). Appended so existing
# ids stay stable.
B_SSN_CASES = [
    # ── SSN term near the value or as its key, every mode ──────────────────
    p("SSN", "en", "pii_ssn_us_proximity", "Note: The Social Security Number (SSN) ", "861-18-8883", " is not required for this application.", carrier="prose"),
    p("SSN", "en", "pii_ssn_us_proximity", "The applicant consents to the processing of their Social Security Number (", "800-40-3880", ") for payroll.", carrier="prose"),
    p("SSN", "en", "pii_ssn_us_proximity", "Our records list the Social Security number as ", "404 15 2700", ".", carrier="prose"),
    p("SSN", "en", "pii_ssn_us_proximity", "", "536-90-4421", " is my SSN.", carrier="prose"),
    p("SSN", "en", "pii_ssn_us_proximity", "SSN No.: ", "078.05.1123"),
    p("SSN", "en", "pii_ssn_us_proximity", "My SSN is ", "401127789", ", please keep it on file.", carrier="prose"),
    p("SSN", "en", "pii_ssn_us_proximity", "ssn=", "857016921", carrier="kv"),
    p("SSN", "en", "pii_ssn_us_proximity", '{"ssn": "', "401127789", '"}', carrier="json"),
    p("SSN", "en", "pii_ssn_us_proximity", "<SSN>", "212.34.5678", "</SSN>", carrier="xml"),
    p("SSN", "en", "pii_ssn_us_proximity", "name,ssn,city\nJane Doe,", "401127789", ",Boston", carrier="csv"),
    p("SSN", "en", "pii_ssn_us_proximity", "The SSN on file is ", "401-12-7788", ".", carrier="prose", mode="balanced"),
    p("SSN", "de", "pii_ssn_us_proximity", "Als SSN ist ", "422-68-7360", " hinterlegt.", carrier="prose"),
    p("SSN", "de", "pii_ssn_us_proximity", "Seine SSN lautet ", "401127789", ".", carrier="prose"),
    p("SSN", "de", "pii_ssn_us_proximity", "SSN-Nr. ", "401 12 7788", " liegt vor.", carrier="prose"),
    p("SSN", "de", "pii_ssn_us_proximity", "Sozialversicherungsnummer (USA): ", "212.34.5678"),
    p("SSN", "de", "pii_ssn_us_proximity", '{"ssn_nummer": "', "401127789", '"}', carrier="json"),
    p("SSN", "de", "pii_ssn_us_proximity", "nr;name;ssn\n1;Jonas Weber;", "078.05.1123", "", carrier="csv"),
    p("SSN", "de", "pii_ssn_us_proximity", "Die SSN des Antragstellers lautet ", "861-18-8883", ".", carrier="prose", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_proximity", "Release 523-41-1234 is out.", "grouped value without an SSN term", carrier="prose"),
    n("SSN", "en", "pii_ssn_us_proximity", "Ticket 532-87-1094 was closed.", "grouped value without an SSN term", carrier="prose"),
    n("SSN", "en", "pii_ssn_us_proximity", "From Account: 226-33-7819, To Account: 334-82-1956", "account fields without an SSN term"),
    n("SSN", "en", "pii_ssn_us_proximity", "Send the form for 401127789 today.", "nine digits without an SSN term", carrier="prose", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_proximity", "The SSN request is under order number 401127789.", "order number nearer than the SSN term", carrier="prose", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_proximity", "SSN: 900123456", "area 9xx is never issued"),
    n("SSN", "en", "pii_ssn_us_proximity", "SSN: 4011277890", "ten digits"),
    n("SSN", "de", "pii_ssn_us_proximity", "Artikel 401-12-7788 ist lieferbar.", "grouped value without an SSN term", carrier="prose"),
    n("SSN", "de", "pii_ssn_us_proximity", "Vorgang 123-45-6789 wurde abgeschlossen.", "grouped value without an SSN term", carrier="prose"),
    n("SSN", "de", "pii_ssn_us_proximity", "Artikelnummer 401127789", "nine digits after a part number", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_proximity", "Die SSN folgt, Bestellnummer 401127789.", "order number nearer than the SSN term", carrier="prose", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_proximity", "SSN: 666000000", "area 666 is never issued"),
    n("SSN", "de", "pii_ssn_us_proximity", "SSN: 40112778", "eight digits"),
    # ── grouped value without a term, balanced and recall only ─────────────
    p("SSN", "en", "pii_ssn_us_context_free", "", "078 05 1123", "", tags=("no_context",), mode="balanced"),
    p("SSN", "en", "pii_ssn_us_context_free", "abc ", "078 05 1123", " abc", tags=("no_context",), mode="balanced"),
    p("SSN", "en", "pii_ssn_us_context_free", "", "078.05.1123", "", tags=("no_context",), mode="balanced"),
    p("SSN", "en", "pii_ssn_us_context_free", "NAD+SU+", "341-33-4328", "::735 Kyle Camp+Apt 3", tags=("no_context",), mode="balanced"),
    p("SSN", "en", "pii_ssn_us_context_free", ":19A:20211115/00001/USD/", "399-38-9646", "", tags=("no_context",), mode="balanced"),
    p("SSN", "en", "pii_ssn_us_context_free", "Release ", "212-45-6789", "", tags=("no_context",), mode="recall"),
    p("SSN", "de", "pii_ssn_us_context_free", "Angaben zum US-Mitarbeiter: ", "219-09-9998", "", tags=("no_context",), mode="balanced"),
    p("SSN", "de", "pii_ssn_us_context_free", "Vorgang ", "532-87-1094", " wurde abgeschlossen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SSN", "de", "pii_ssn_us_context_free", "<kennung>", "566-66-2655", "</kennung>", carrier="xml", tags=("no_context",), mode="balanced"),
    p("SSN", "de", "pii_ssn_us_context_free", "Beleg vom 03.02.2026, Person ", "401.12.7788", "", tags=("no_context",), mode="balanced"),
    p("SSN", "de", "pii_ssn_us_context_free", "LIN+1++", "341-33-4328", ":IN+++123456++10.50+EA", tags=("no_context",), mode="recall"),
    n("SSN", "en", "pii_ssn_us_context_free", "Order number 123-45-6789 has shipped.", "order number", carrier="prose", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "Reference number 523-41-1234", "reference number", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "Part number 401-12-7788", "part number", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "Tracking number 401-12-7788 is in transit.", "tracking number", carrier="prose", mode="recall"),
    n("SSN", "en", "pii_ssn_us_context_free", '{"order_id": "123-45-6789"}', "order ID key", carrier="json", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "900-12-3456", "area 9xx is never issued", tags=("no_context",), mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "Range 341-33-4328/2026", "part of a longer number", mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "341-33 4328", "mixed separators", tags=("no_context",), mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Bestellnummer 123-45-6789 ist versandt.", "order number", carrier="prose", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Referenznummer 523-41-1234", "reference number", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Teilenummer 401-12-7788", "part number", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Rechnungsnummer 523-41-1234 ist offen.", "invoice number", carrier="prose", mode="recall"),
    n("SSN", "de", "pii_ssn_us_context_free", "Seriennummer 219-45-7781", "serial number", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "666-12-3456", "area 666 is never issued", tags=("no_context",), mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Gruppe 12 341 33 4328", "digit group one space away", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Bestand 341-33-4328-7", "part of a longer number", mode="balanced"),
    # ── placeholder values without a term (as presidio-analyzer rejects them) ──
    n("SSN", "en", "pii_ssn_us_context_free", "111-11-1111", "one repeated digit", tags=("no_context",), mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "777 77 7777", "one repeated digit", tags=("no_context",), mode="recall"),
    n("SSN", "en", "pii_ssn_us_context_free", "123-45-6789", "counting sequence", tags=("no_context",), mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "abc 555.55.5555 abc", "one repeated digit", tags=("no_context",), mode="balanced"),
    n("SSN", "en", "pii_ssn_us_context_free", "Release 123-45-6789 is out.", "counting sequence", carrier="prose", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Platzhalter 111-11-1111", "one repeated digit", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Beispiel 444 44 4444", "one repeated digit", mode="recall"),
    n("SSN", "de", "pii_ssn_us_context_free", "Muster 123-45-6789", "counting sequence", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Vorgang 123.45.6789 wurde abgeschlossen.", "counting sequence", carrier="prose", mode="balanced"),
    n("SSN", "de", "pii_ssn_us_context_free", "Testwert 222.22.2222", "one repeated digit", mode="balanced"),
]
for _row in B_SSN_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-UK United Kingdom identifiers (A07; baseline P6, candidate C4). `pii_nhs_number_uk`
# reports ten digits with the NHS mod-11 check digit (3-3-4 with spaces or hyphens, or
# bare) in every mode when an NHS term stands near the value or is its key. `pii_ni_uk`
# also reads a NINO in pairs and after `NI number`; `pii_ni_uk_context_free` reports a
# bare NINO in one case in balanced and recall only. `pii_passport_number_uk` reports nine
# digits next to a passport term, `pii_passport_number_two_letters` two letters and seven
# digits (Ireland, Japan). The UK driving licence is bound to a
# licence field name in every mode (`pii_driver_license_number_uk`) and bare in balanced
# and recall (`pii_driver_license_number_uk_context_free`). Hard negatives: failed check
# digits, prefixes HMRC never issues, mixed case without a field name, impossible birth
# dates, values without a term in strict, counter-context and parts of longer values.
# Appended so existing ids stay stable.
B_UK_CASES = [
    # ── NHS number with an NHS term or key, every mode ────────────────────
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS number: ", "9434765919"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS No. ", "943-476-5919", mode="balanced"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "His NHS number is ", "490 830 1662", ".", carrier="prose", mode="balanced"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "", "4908301662", " is her NHS number.", carrier="prose"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "National Health Service number: ", "6351819091"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", '{"nhs_number": "', "452 601 8155", '"}', carrier="json", mode="balanced"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "name,nhs_number,ward\nJane Doe,", "635-181-9091", ",Ward 7", carrier="csv", mode="balanced"),
    p("NHS_NUMBER", "en", "pii_nhs_number_uk", "Patient NHS number ", "4526018155", ", ward 7"),
    p("NHS_NUMBER", "de", "pii_nhs_number_uk", "Die NHS-Nummer lautet ", "737 865 7972", ".", carrier="prose", mode="balanced"),
    p("NHS_NUMBER", "de", "pii_nhs_number_uk", "NHS-Nr. ", "4014710491"),
    p("NHS_NUMBER", "de", "pii_nhs_number_uk", "Britische Patientin, NHS-Nummer ", "485-432-3191", ", Station 4", carrier="prose", mode="balanced"),
    p("NHS_NUMBER", "de", "pii_nhs_number_uk", '{"nhs_nummer": "', "4948757497", '"}', carrier="json"),
    p("NHS_NUMBER", "de", "pii_nhs_number_uk", "<nhsNummer>", "6311862522", "</nhsNummer>", carrier="xml"),
    p("NHS_NUMBER", "de", "pii_nhs_number_uk", "Die NHS-Nummer ", "727 601 8954", " liegt der Überweisung bei.", carrier="prose", mode="balanced"),
    n("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS number: 9434765918", "check digit fails"),
    n("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS number: 1234567890", "check digit would be 10, never issued"),
    n("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS number: 0000000000", "one repeated digit"),
    n("NHS_NUMBER", "en", "pii_nhs_number_uk", "Reference 4526018155 was archived.", "valid check digit without an NHS term", carrier="prose"),
    n("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS trust, order number 4526018155", "order number nearer than the NHS term", mode="balanced"),
    n("NHS_NUMBER", "en", "pii_nhs_number_uk", "NHS number: 943 4765 919", "neither 3-3-4 groups nor ten digits"),
    n("NHS_NUMBER", "de", "pii_nhs_number_uk", "NHS-Nummer: 4526018156", "check digit fails"),
    n("NHS_NUMBER", "de", "pii_nhs_number_uk", "NHS-Nummer: 4444444444", "one repeated digit"),
    n("NHS_NUMBER", "de", "pii_nhs_number_uk", "Vorgang 4908301662 wurde abgeschlossen.", "valid check digit without an NHS term", carrier="prose"),
    n("NHS_NUMBER", "de", "pii_nhs_number_uk", "NHS-Klinik, Bestellnummer 4526018155", "order number nearer than the NHS term", mode="balanced"),
    n("NHS_NUMBER", "de", "pii_nhs_number_uk", "NHS-Nummer: 943/476/5919", "slashes are no NHS grouping"),
    n("NHS_NUMBER", "de", "pii_nhs_number_uk", "NHS-Nummer: 94347659192", "eleven digits"),
    # ── NINO after a field name: pairs, no spaces, lowercase ───────────────
    p("NATIONALID", "en", "pii_ni_uk", "Here is my National Insurance Number ", "YZ 61 48 68 B", carrier="prose"),
    p("NATIONALID", "en", "pii_ni_uk", "NINO: ", "ab123456c"),
    p("NATIONALID", "en", "pii_ni_uk", "National insurance no: ", "hh 01 02 03 d"),
    p("NATIONALID", "en", "pii_ni_uk", "NI No.: ", "tw987654a"),
    p("NATIONALID", "en", "pii_ni_uk", "employee:\n  ni_number: ", "CE 12 34 56 A", "\n", carrier="yaml"),
    p("NATIONALID", "de", "pii_ni_uk", "Britische Sozialversicherungsnummer: ", "ce 12 34 56 a"),
    p("NATIONALID", "de", "pii_ni_uk", "Ihre NINO lautet ", "JK 55 66 77 B", ".", carrier="prose"),
    p("NATIONALID", "de", "pii_ni_uk", "NINO: ", "pr482917a"),
    p("NATIONALID", "de", "pii_ni_uk", '{"ni_nummer": "', "WL 30 41 15 C", '"}', carrier="json"),
    p("NATIONALID", "de", "pii_ni_uk", "NI-Nummer: ", "ST 76 12 45 B"),
    n("NATIONALID", "en", "pii_ni_uk", "National insurance number: FQ 00 00 00 C", "Q is no second letter"),
    n("NATIONALID", "en", "pii_ni_uk", "This isn't a valid national insurance number UV 98 76 54 B", "U and V are never issued", carrier="prose"),
    n("NATIONALID", "en", "pii_ni_uk", "NI number: NT 12 34 56 A", "prefix NT is never issued"),
    n("NATIONALID", "en", "pii_ni_uk", "NI number: AB 12 34 56 E", "suffix must be A to D"),
    n("NATIONALID", "en", "pii_ni_uk", "NI number: AB 12 34 5 C", "only five digits"),
    n("NATIONALID", "de", "pii_ni_uk", "NINO: bg 12 34 56 a", "prefix BG is never issued"),
    n("NATIONALID", "de", "pii_ni_uk", "NINO: ZZ123456A", "prefix ZZ is never issued"),
    n("NATIONALID", "de", "pii_ni_uk", "NINO: DA 12 34 56 B", "D is no first letter"),
    n("NATIONALID", "de", "pii_ni_uk", "NI-Nummer: AB 12 34 56 F", "suffix must be A to D"),
    n("NATIONALID", "de", "pii_ni_uk", "NINO: AB 1234 56 C", "neither pairs nor one block"),
    # ── bare NINO in one case, balanced and recall only ────────────────────
    p("NATIONALID", "en", "pii_ni_uk_context_free", "", "hh 01 02 03 d", "", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "en", "pii_ni_uk_context_free", "", "tw987654a", "", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "en", "pii_ni_uk_context_free", "Employee record: ", "JK 55 66 77 B", "", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "en", "pii_ni_uk_context_free", "<row><value>", "AB123456C", "</value></row>", carrier="xml", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "en", "pii_ni_uk_context_free", "Please file ", "CE 123456 A", " with payroll.", carrier="prose", tags=("no_context",), mode="recall"),
    p("NATIONALID", "de", "pii_ni_uk_context_free", "Mitarbeiterin ", "PR 482917 A", ", Standort London", carrier="prose", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "de", "pii_ni_uk_context_free", "Bitte ", "wl304115c", " in der Lohnabrechnung ergänzen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "de", "pii_ni_uk_context_free", "Personalakte: ", "ST 76 12 45 B", "", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "de", "pii_ni_uk_context_free", "name;notiz\nJones;", "MN902341D", "", carrier="csv", tags=("no_context",), mode="balanced"),
    p("NATIONALID", "de", "pii_ni_uk_context_free", "Vermerk ", "hj 98 76 54 d", "", tags=("no_context",), mode="recall"),
    n("NATIONALID", "en", "pii_ni_uk_context_free", "AB123456C", "bare value in strict", tags=("no_context",)),
    n("NATIONALID", "en", "pii_ni_uk_context_free", "Ab123456C", "mixed case without a field name", tags=("no_context",), mode="balanced"),
    n("NATIONALID", "en", "pii_ni_uk_context_free", "GB123456A", "prefix GB is never issued", tags=("no_context",), mode="balanced"),
    n("NATIONALID", "en", "pii_ni_uk_context_free", "Order number AB123456C", "order number", mode="balanced"),
    n("NATIONALID", "en", "pii_ni_uk_context_free", "Part XAB123456C is out of stock.", "glued to a letter", carrier="prose", mode="recall"),
    n("NATIONALID", "en", "pii_ni_uk_context_free", "Batch AB123456C-7", "part of a hyphenated number", mode="balanced"),
    n("NATIONALID", "de", "pii_ni_uk_context_free", "hh 01 02 03 d", "bare value in strict", tags=("no_context",)),
    n("NATIONALID", "de", "pii_ni_uk_context_free", "hH 01 02 03 d", "mixed case without a field name", tags=("no_context",), mode="balanced"),
    n("NATIONALID", "de", "pii_ni_uk_context_free", "QQ 12 34 56 C", "Q is no first letter", tags=("no_context",), mode="balanced"),
    n("NATIONALID", "de", "pii_ni_uk_context_free", "Bestellnummer ab123456c", "order number", mode="balanced"),
    n("NATIONALID", "de", "pii_ni_uk_context_free", "Artikelnummer AB123456C", "part number", mode="recall"),
    n("NATIONALID", "de", "pii_ni_uk_context_free", "Charge AB123456D-2 gesperrt", "part of a hyphenated number", mode="balanced"),
    # ── UK passport with a passport term, every mode ───────────────────────
    p("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "Passport number: ", "925665416"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "Her UK passport ", "123456789", " expires in 2031.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "My passport is ", "107185703", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_uk", '{"passport_number": "', "761204958", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "name,passport,nationality\nJane Doe,", "548812306", ",British", carrier="csv"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "Reisepass-Nr. ", "925665416", " (Vereinigtes Königreich)"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "Der britische Reisepass ", "533401372", " ist gültig.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "Passnummer: ", "548812306"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_uk", '{"reisepass": "', "761204958", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "<reisepassnummer>", "107185703", "</reisepassnummer>", carrier="xml"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "925665416", "bare value without a passport term", tags=("no_context",), mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "Her UK passport 12345678901 expires in 2031.", "eleven digits", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "My passport is 12345678", "only eight digits", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "Ticket 925665416 was closed.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "Passport photo order number 925665416", "order number nearer than the passport term", mode="balanced"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "Vorgang 925665416 abgeschlossen.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "My passport is 999999999", "one repeated digit", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "Der britische Pass 1234567890 ist gültig.", "ten digits", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_uk", "Reisepass-Foto, Bestellnummer 925665416", "order number nearer than the passport term", mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_uk", "Her UK passport 925665416-2 expires in 2031.", "part of a hyphenated number", carrier="prose"),
    # ── UK driving licence after a licence field name, every mode ──────────
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "Driving licence number: ", "MORGA657054SM9IJ"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "My driving licence is ", "SMIT9801015JK2CD", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", '{"driving_licence": "', "JONES710238HA3DX", '"}', carrier="json"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "name,driver_license,city\nAmy Lee,", "LEE99802123JA9MN", ",Leeds", carrier="csv"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "DL number: ", "SMITH862310AB1CD"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerscheinnummer: ", "SMITH851010AB1CD"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Der britische Führerschein ", "MORGA657054SM9IJ", " ist gültig.", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Fahrerlaubnis-Nr. ", "JONES710238HA3DX"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", '{"fuehrerschein": "', "LEE99802123JA9MN", '"}', carrier="json"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerschein-Nr.: ", "SMIT9801015JK2CD"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "Driving licence number: SMITH813010AB1CD", "month 13"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "Driving licence number: SMITH801320AB1CD", "day 32"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "Driving licence number: 99999801015JK2CD", "surname of nines only"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "Driving licence number: SM1TH851010AB1CD", "digit inside the surname"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk", "Driving licence number: morga657054sm9ij", "lowercase"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerscheinnummer: SMITH863010AB1CD", "month 63"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerscheinnummer: SMITH851000AB1CD", "day 00"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerscheinnummer: 9MITH851010AB1CD", "a nine before the surname letters"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerscheinnummer: SMITH851010AB112", "check letters are digits"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk", "Führerscheinnummer: SMITH851010AB1C", "fifteen characters"),
    # ── bare UK driving licence, balanced and recall only ──────────────────
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "", "MORGA657054SM9IJ", "", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "Licence: ", "MORGA607054SM9IJ", " ok", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "", "SMITH862310AB1CD", "", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "<row><value>", "JONES710238HA3DX", "</value></row>", carrier="xml", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "Hire car released to ", "LEE99802123JA9MN", " today.", carrier="prose", tags=("no_context",), mode="recall"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "Fahrer ", "LEE99802123JA9MN", ", Depot Leeds", carrier="prose", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "Mietwagen an ", "SMIT9801015JK2CD", " übergeben.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "name;dokument\nMorgan;", "MORGA657054SM9IJ", "", carrier="csv", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "Vermerk: ", "SMITH851010AB1CD", "", tags=("no_context",), mode="balanced"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "Kopie ", "JONES710238HA3DX", " liegt vor.", carrier="prose", tags=("no_context",), mode="recall"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "MORGA657054SM9IJ", "bare value in strict", tags=("no_context",)),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "SMITH813010AB1CD", "month 13", tags=("no_context",), mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "morga657054sm9ij", "lowercase", tags=("no_context",), mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "Order number MORGA657054SM9IJ", "order number", mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_uk_context_free", "Build MORGA657054SM9IJ-2 passed.", "part of a hyphenated number", carrier="prose", mode="recall"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "SMITH851010AB1CD", "bare value in strict", tags=("no_context",)),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "99999801015JK2CD", "surname of nines only", tags=("no_context",), mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "SMITH801320AB1CD", "day 32", tags=("no_context",), mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "Bestellnummer MORGA657054SM9IJ", "order number", mode="balanced"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_uk_context_free", "Artikel XMORGA657054SM9IJ ist vergriffen.", "glued to a letter", carrier="prose", mode="balanced"),
    # ── passport of two letters and seven digits (Ireland, Japan) next to a passport term ──
    p("PASSPORT_NUMBER", "en", "pii_passport_number_two_letters", "Passport number: ", "PA1234567"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_two_letters", "Witness: Darusman Ratulangi (Passport No. ", "SG9943897", ")", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_two_letters", '{"passport_number": "', "TK1234567", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_two_letters", "Der irische Reisepass ", "PA1234567", " ist gültig.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_two_letters", '{"passnummer": "', "KB1572986", '"}', carrier="json"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_two_letters", "Ticket PA1234567 was closed.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_two_letters", "Her passport PA1234567-2 expires in 2031.", "part of a hyphenated number", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_two_letters", "Vorgang PA1234567 abgeschlossen.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_two_letters", "Der Reisepass pa1234567 ist gültig.", "lowercase", carrier="prose"),
]
for _row in B_UK_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-APAC Australian and Singaporean identifiers (A08, A10), one label each, all with a
# check digit or letter: ABN (mod 89), ACN (weighted mod 10), TFN (weighted mod 11),
# Medicare (1-3-7-9 mod 10), NRIC/FIN (check letter per series S/T/F/G/M) and UEN
# (check letter per format A/B/C). `pii_*_au`/`pii_*_sg` report the value in every mode
# when a term of the label stands near it or is its key. In balanced and recall the
# forms whose shape adds to the check digit are reported bare (K05): ABN 2-3-3-3,
# Medicare 4-5-1, an uppercase NRIC/FIN, a UEN of format B or C. ACN, TFN, bare digit
# runs and UEN format A always need a term. Hard negatives: failed check digits, values
# without a term, lowercase without a term, counter-context and parts of longer values.
# Appended so existing ids stay stable.
B_APAC_CASES = [
    # ── ABN ────────────────────────────────────────────────────────────────
    p("AU_ABN", "en", "pii_abn_au", "ABN: ", "51 824 753 556"),
    p("AU_ABN", "en", "pii_abn_au", "Our Australian Business Number is ", "38370676645", ".", carrier="prose"),
    p("AU_ABN", "en", "pii_abn_au", '{"abn": "', "19 702 452 268", '"}', carrier="json"),
    p("AU_ABN", "en", "pii_abn_au_context_free", "Please invoice ", "46 211 369 704", " by Friday.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("AU_ABN", "en", "pii_abn_au_context_free", "", "82 093 544 717", "", tags=("no_context",), mode="balanced"),
    p("AU_ABN", "en", "pii_abn_au", "supplier,abn\nAcme Pty Ltd,", "70 338 658 623", "", carrier="csv", mode="balanced"),
    p("AU_ABN", "de", "pii_abn_au", "Die ABN lautet ", "48 582 779 294", ".", carrier="prose"),
    p("AU_ABN", "de", "pii_abn_au", "ABN: ", "78329521562"),
    p("AU_ABN", "de", "pii_abn_au", "Australische Unternehmensnummer (ABN) ", "80 268 925 250", ""),
    p("AU_ABN", "de", "pii_abn_au_context_free", "Bitte an ", "41 268 295 369", " fakturieren.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("AU_ABN", "de", "pii_abn_au_context_free", "Lieferant Sydney, ", "28 043 314 954", "", tags=("no_context",), mode="recall"),
    n("AU_ABN", "en", "pii_abn_au", "ABN: 51 824 753 557", "check digits fail"),
    n("AU_ABN", "en", "pii_abn_au", "Reference 51824753556 was archived.", "eleven bare digits without an ABN term", carrier="prose", mode="balanced"),
    n("AU_ABN", "en", "pii_abn_au", "ABN: 01 824 753 556", "leading zero is never issued"),
    n("AU_ABN", "en", "pii_abn_au_context_free", "Invoice number 46 211 369 704", "counter-context nearer", mode="balanced"),
    n("AU_ABN", "en", "pii_abn_au_context_free", "Dial 1 51 824 753 556 now.", "part of a longer number", carrier="prose", mode="balanced"),
    n("AU_ABN", "de", "pii_abn_au", "ABN: 52 824 753 556", "check digits fail"),
    n("AU_ABN", "de", "pii_abn_au", "Vorgang 78329521562 wurde abgeschlossen.", "eleven bare digits without an ABN term", carrier="prose", mode="balanced"),
    n("AU_ABN", "de", "pii_abn_au_context_free", "Rechnungsnummer 41 268 295 369", "counter-context nearer", mode="balanced"),
    n("AU_ABN", "de", "pii_abn_au_context_free", "Bitte 41 268 295 368 prüfen.", "check digits fail", carrier="prose", mode="balanced"),
    n("AU_ABN", "de", "pii_abn_au", "ABN-Nummer: 4126829536", "ten digits"),
    # ── ACN ────────────────────────────────────────────────────────────────
    p("AU_ACN", "en", "pii_acn_au", "ACN: ", "006 249 976"),
    p("AU_ACN", "en", "pii_acn_au", "Australian Company Number ", "666412077", ""),
    p("AU_ACN", "en", "pii_acn_au", "My Australian Company Number is ", "021 809 165", ".", carrier="prose", mode="balanced"),
    p("AU_ACN", "en", "pii_acn_au", '{"acn": "', "591 818 398", '"}', carrier="json"),
    p("AU_ACN", "en", "pii_acn_au", "company,acn\nAcme Pty Ltd,", "110 702 700", "", carrier="csv", mode="balanced"),
    p("AU_ACN", "de", "pii_acn_au", "Als ACN ist ", "300 008 146", " hinterlegt.", carrier="prose"),
    p("AU_ACN", "de", "pii_acn_au", "ACN: ", "276261593"),
    p("AU_ACN", "de", "pii_acn_au", "Bitte verwenden Sie für Rückfragen ACN ", "440 945 880", ".", carrier="prose", mode="balanced"),
    p("AU_ACN", "de", "pii_acn_au", "| Firma | ACN |\n|---|---|\n| Acme Pty Ltd | ", "842 629 823", " |", carrier="table"),
    p("AU_ACN", "de", "pii_acn_au", '{"acn": "', "626259747", '"}', carrier="json", mode="balanced"),
    n("AU_ACN", "en", "pii_acn_au", "ACN: 824 753 557", "check digit fails"),
    n("AU_ACN", "en", "pii_acn_au", "Order 006249976 shipped.", "valid check digit without an ACN term", carrier="prose", mode="balanced"),
    n("AU_ACN", "en", "pii_acn_au", "ACN: 000 000 000", "one repeated digit"),
    n("AU_ACN", "en", "pii_acn_au", "ACN Pty Ltd, order number 006249976", "order number nearer than the ACN term", mode="balanced"),
    n("AU_ACN", "en", "pii_acn_au", "ACN: 006 249 976 5", "part of a longer number"),
    n("AU_ACN", "de", "pii_acn_au", "ACN: 135 506 072", "check digit fails"),
    n("AU_ACN", "de", "pii_acn_au", "Vorgang 135 506 071 wurde abgeschlossen.", "valid check digit without an ACN term", carrier="prose", mode="balanced"),
    n("AU_ACN", "de", "pii_acn_au", "ACN-Gruppe, Bestellnummer 666412077", "order number nearer than the ACN term", mode="balanced"),
    n("AU_ACN", "de", "pii_acn_au", "ACN: 13550607", "eight digits"),
    n("AU_ACN", "de", "pii_acn_au", "Artikel 763 946 792", "valid check digit without an ACN term", mode="recall"),
    # ── TFN ────────────────────────────────────────────────────────────────
    p("AU_TFN", "en", "pii_tfn_au", "TFN: ", "876 543 210"),
    p("AU_TFN", "en", "pii_tfn_au", "Tax File Number: ", "966913591"),
    p("AU_TFN", "en", "pii_tfn_au", "Her tax file number is ", "686 366 777", ".", carrier="prose", mode="balanced"),
    p("AU_TFN", "en", "pii_tfn_au", '{"tfn": "', "606 327 470", '"}', carrier="json", mode="balanced"),
    p("AU_TFN", "en", "pii_tfn_au", "name,tfn\nJane Doe,", "209 106 082", "", carrier="csv"),
    p("AU_TFN", "de", "pii_tfn_au", "Die TFN lautet ", "399 064 894", ".", carrier="prose"),
    p("AU_TFN", "de", "pii_tfn_au", "TFN: ", "606250599"),
    p("AU_TFN", "de", "pii_tfn_au", "Australische Steuerdateinummer (TFN): ", "805 086 785", "", mode="balanced"),
    p("AU_TFN", "de", "pii_tfn_au", '{"tfn": "', "658973397", '"}', carrier="json"),
    p("AU_TFN", "de", "pii_tfn_au", "Unsere Unterlagen nennen als TFN: ", "849 621 777", ".", carrier="prose", mode="balanced"),
    n("AU_TFN", "en", "pii_tfn_au", "TFN: 876 543 211", "check sum fails"),
    n("AU_TFN", "en", "pii_tfn_au", "Call 876 543 210 today.", "valid sum without a TFN term", carrier="prose", mode="balanced"),
    n("AU_TFN", "en", "pii_tfn_au", "TFN: 111 111 111", "one repeated digit"),
    n("AU_TFN", "en", "pii_tfn_au", "TFN letter, invoice number 842781633", "invoice number nearer than the TFN term", mode="balanced"),
    n("AU_TFN", "en", "pii_tfn_au", "TFN: 876-543-210-4", "part of a longer number"),
    n("AU_TFN", "de", "pii_tfn_au", "TFN: 966 913 592", "check sum fails"),
    n("AU_TFN", "de", "pii_tfn_au", "Vorgang 842781633 wurde abgeschlossen.", "valid sum without a TFN term", carrier="prose", mode="balanced"),
    n("AU_TFN", "de", "pii_tfn_au", "TFN-Schreiben, Rechnungsnummer 515961343", "invoice number nearer than the TFN term", mode="balanced"),
    n("AU_TFN", "de", "pii_tfn_au", "TFN: 87654321", "eight digits"),
    n("AU_TFN", "de", "pii_tfn_au", "Artikel 515 961 343", "valid sum without a TFN term", mode="recall"),
    # ── Medicare ───────────────────────────────────────────────────────────
    p("AU_MEDICARE", "en", "pii_medicare_au", "Medicare number: ", "2123 45670 1"),
    p("AU_MEDICARE", "en", "pii_medicare_au", "Medicare card ", "2459455777", ""),
    p("AU_MEDICARE", "en", "pii_medicare_au", '{"medicare_number": "', "4615877208", '"}', carrier="json", mode="balanced"),
    p("AU_MEDICARE", "en", "pii_medicare_au_context_free", "Card ", "2292 79739 9", " is on file.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("AU_MEDICARE", "en", "pii_medicare_au_context_free", "", "3421 85418 9", "", tags=("no_context",), mode="recall"),
    p("AU_MEDICARE", "en", "pii_medicare_au", "Correction to my details: Medicare number ", "4677140160", ".", carrier="prose"),
    p("AU_MEDICARE", "de", "pii_medicare_au", "Australische Medicare-Nummer: ", "4773046508"),
    p("AU_MEDICARE", "de", "pii_medicare_au", "Die Medicare-Nummer lautet ", "4009 75894 6", ".", carrier="prose"),
    p("AU_MEDICARE", "de", "pii_medicare_au", '{"medicare": "', "2587507282", '"}', carrier="json", mode="balanced"),
    p("AU_MEDICARE", "de", "pii_medicare_au_context_free", "Karte ", "6538 99356 7", " liegt vor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("AU_MEDICARE", "de", "pii_medicare_au_context_free", "Patientin aus Perth, ", "4298 66179 1", "", tags=("no_context",), mode="balanced"),
    n("AU_MEDICARE", "en", "pii_medicare_au", "Medicare number: 2123 25870 1", "check digit fails"),
    n("AU_MEDICARE", "en", "pii_medicare_au", "Reference 2459455777 was archived.", "ten bare digits without a Medicare term", carrier="prose", mode="balanced"),
    n("AU_MEDICARE", "en", "pii_medicare_au", "Medicare number: 7123456701", "first digit outside 2-6"),
    n("AU_MEDICARE", "en", "pii_medicare_au_context_free", "Order number 2292 79739 9", "counter-context nearer", mode="balanced"),
    n("AU_MEDICARE", "en", "pii_medicare_au_context_free", "Card 2292 79739 9 2 is on file.", "part of a longer number", carrier="prose", mode="balanced"),
    n("AU_MEDICARE", "de", "pii_medicare_au", "Medicare-Nummer: 4773046518", "check digit fails"),
    n("AU_MEDICARE", "de", "pii_medicare_au", "Vorgang 4773046508 wurde abgeschlossen.", "ten bare digits without a Medicare term", carrier="prose", mode="balanced"),
    n("AU_MEDICARE", "de", "pii_medicare_au", "Medicare-Klinik, Bestellnummer 2587507282", "order number nearer than the Medicare term", mode="balanced"),
    n("AU_MEDICARE", "de", "pii_medicare_au_context_free", "Karte 6538 99357 7 liegt vor.", "check digit fails", carrier="prose", mode="balanced"),
    n("AU_MEDICARE", "de", "pii_medicare_au", "Medicare-Nummer: 477304650", "nine digits"),
    # ── NRIC/FIN ───────────────────────────────────────────────────────────
    p("SG_NRIC_FIN", "en", "pii_nric_fin_sg", "NRIC: ", "S0642712Z"),
    p("SG_NRIC_FIN", "en", "pii_nric_fin_sg", "The FIN on file is ", "G8091588N", ".", carrier="prose"),
    p("SG_NRIC_FIN", "en", "pii_nric_fin_sg", "NRIC ", "s8669842j", ""),
    p("SG_NRIC_FIN", "en", "pii_nric_fin_sg_context_free", "Applicant ", "F2346401L", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SG_NRIC_FIN", "en", "pii_nric_fin_sg_context_free", "", "M6471671Q", "", tags=("no_context",), mode="balanced"),
    p("SG_NRIC_FIN", "en", "pii_nric_fin_sg", '{"nric": "', "G6075301L", '"}', carrier="json", mode="balanced"),
    p("SG_NRIC_FIN", "de", "pii_nric_fin_sg", "NRIC: ", "S0977066F"),
    p("SG_NRIC_FIN", "de", "pii_nric_fin_sg", "Unsere Unterlagen nennen als NRIC: ", "M7428958K", ".", carrier="prose"),
    p("SG_NRIC_FIN", "de", "pii_nric_fin_sg", "name;nric;ort\nTan Wei;", "M5043779L", ";Singapur", carrier="csv", mode="balanced"),
    p("SG_NRIC_FIN", "de", "pii_nric_fin_sg_context_free", "Antragsteller ", "G7439090R", " wurde genehmigt.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SG_NRIC_FIN", "de", "pii_nric_fin_sg_context_free", "Besucher aus Singapur: ", "F2720248U", "", tags=("no_context",), mode="recall"),
    n("SG_NRIC_FIN", "en", "pii_nric_fin_sg", "NRIC: S0642712A", "check letter fails"),
    n("SG_NRIC_FIN", "en", "pii_nric_fin_sg", "NRIC: B1234567Z", "no NRIC/FIN series"),
    n("SG_NRIC_FIN", "en", "pii_nric_fin_sg_context_free", "Order number F2346401L", "counter-context nearer", mode="balanced"),
    n("SG_NRIC_FIN", "en", "pii_nric_fin_sg_context_free", "Applicant f2346401l was approved.", "lowercase without a term", carrier="prose", mode="balanced"),
    n("SG_NRIC_FIN", "en", "pii_nric_fin_sg_context_free", "Build XS0642712Z is out.", "part of a longer token", carrier="prose", mode="balanced"),
    n("SG_NRIC_FIN", "de", "pii_nric_fin_sg", "NRIC: G1122144L", "check letter fails"),
    n("SG_NRIC_FIN", "de", "pii_nric_fin_sg", "FIN: F0642712Z", "S/T letter on an F number"),
    n("SG_NRIC_FIN", "de", "pii_nric_fin_sg_context_free", "Bestellnummer G7439090R", "counter-context nearer", mode="balanced"),
    n("SG_NRIC_FIN", "de", "pii_nric_fin_sg_context_free", "Antragsteller g7439090r wurde genehmigt.", "lowercase without a term", carrier="prose", mode="balanced"),
    n("SG_NRIC_FIN", "de", "pii_nric_fin_sg_context_free", "Teil G7439090R-2 ist lieferbar.", "part of a hyphenated token", carrier="prose", mode="balanced"),
    # ── UEN ────────────────────────────────────────────────────────────────
    p("SG_UEN", "en", "pii_uen_sg", "UEN: ", "53125226D"),
    p("SG_UEN", "en", "pii_uen_sg", "The Unique Entity Number on file is ", "53478891B", ".", carrier="prose"),
    p("SG_UEN", "en", "pii_uen_sg", '{"uen": "', "201936647D", '"}', carrier="json", mode="balanced"),
    p("SG_UEN", "en", "pii_uen_sg_context_free", "Supplier ", "S57TU0392K", ", Singapore", tags=("no_context",), mode="balanced"),
    p("SG_UEN", "en", "pii_uen_sg_context_free", "", "202200372K", "", tags=("no_context",), mode="balanced"),
    p("SG_UEN", "en", "pii_uen_sg", "UEN ", "T91NB3366F", ""),
    p("SG_UEN", "de", "pii_uen_sg", "UEN: ", "35324838W"),
    p("SG_UEN", "de", "pii_uen_sg", "Ich bestätige folgende Angabe (UEN): ", "199370979Z", ".", carrier="prose"),
    p("SG_UEN", "de", "pii_uen_sg", "firma;uen;ort\nTan Pte Ltd;", "16966710C", ";Singapur", carrier="csv", mode="balanced"),
    p("SG_UEN", "de", "pii_uen_sg_context_free", "Firma ", "199626206N", ", Singapur", tags=("no_context",), mode="balanced"),
    p("SG_UEN", "de", "pii_uen_sg_context_free", "Lieferant ", "S33CX8199H", " bestätigt.", carrier="prose", tags=("no_context",), mode="recall"),
    n("SG_UEN", "en", "pii_uen_sg", "UEN: 53125226E", "check letter fails"),
    n("SG_UEN", "en", "pii_uen_sg", "Reference 53125226D was archived.", "format A without a UEN term", carrier="prose", mode="balanced"),
    n("SG_UEN", "en", "pii_uen_sg_context_free", "Order number 202200372K", "counter-context nearer", mode="balanced"),
    n("SG_UEN", "en", "pii_uen_sg_context_free", "Supplier S57ZZ0392K, Singapore", "unknown entity type", mode="balanced"),
    n("SG_UEN", "en", "pii_uen_sg_context_free", "Supplier s57tu0392k, Singapore", "lowercase", mode="balanced"),
    n("SG_UEN", "de", "pii_uen_sg", "UEN: 201434292E", "check letter fails"),
    n("SG_UEN", "de", "pii_uen_sg", "Vorgang 35324838W abgeschlossen.", "format A without a UEN term", carrier="prose", mode="balanced"),
    n("SG_UEN", "de", "pii_uen_sg_context_free", "Bestellnummer 199626206N", "counter-context nearer", mode="balanced"),
    n("SG_UEN", "de", "pii_uen_sg_context_free", "Firma 123456789A, Singapur", "registration year before 1800", mode="balanced"),
    n("SG_UEN", "de", "pii_uen_sg", "UEN: 5312522D", "seven digits"),
]
for _row in B_APAC_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# F18 NANP extensions (baseline bucket P5, candidate C3): an extension right after a NANP
# number (`345-899-3560x4587`, `ext. 123`, `extension 12`) belongs to the span of
# `pii_phone_us`, and a `+1` number with ten digits keeps it in `pii_phone_international`
# (`+1-604-696-5272x565` was cut to `+1-604-696`). A bare `x` or `ext` without digits ends
# the span before it. Hard negatives are letters attached to a number, extensions without a
# number and numbers the unchanged validator rejects. Appended so existing ids stay stable.
F18_PHONE_EXTENSION_CASES = [
    p("PHONE", "de", "pii_phone_us", "Telefon (USA): ", "345-899-3560x4587"),
    p("PHONE", "de", "pii_phone_us", "Büro New York: ", "212-736-4410 Ext. 123"),
    p("PHONE", "de", "pii_phone_us", "Rückruf unter ", "+1-604-696-5272x565", " erbeten.", carrier="prose"),
    p("PHONE", "de", "pii_phone_us", '{"telefon_us": "', "(303) 499-7111 ext 42", '"}', carrier="json"),
    p("PHONE", "de", "pii_phone_us", "Name;Telefon\nMiller;", "206-386-4636x7", "", carrier="csv"),
    p("PHONE", "de", "pii_phone_us", "US-Hotline: ", "1-800-123-4567", " Ext. bitte erfragen"),
    p("PHONE", "en", "pii_phone_us", "Phone: ", "345-899-3560x4587"),
    p("PHONE", "en", "pii_phone_us", "Call me at ", "+1-604-696-5272x565", " tomorrow.", carrier="prose", tags=("no_context",)),
    p("PHONE", "en", "pii_phone_us", "Office: ", "(212) 736-4410 ext 204"),
    p("PHONE", "en", "pii_phone_us", "Support line ", "1-800-959-5525 extension 12", " is open 24/7.", carrier="prose"),
    p("PHONE", "en", "pii_phone_us", "Fax: ", "(579)888-3058x12"),
    p("PHONE", "en", "pii_phone_us", "Phone: ", "646-273-9915", " ext (ask reception)"),
    n("PHONE", "de", "pii_phone_us", "Artikelcode 212-736-4410XL", "size suffix attached to a number"),
    n("PHONE", "de", "pii_phone_us", "Durchwahl: ext. 4587", "extension without a number"),
    n("PHONE", "de", "pii_phone_us", "Telefon: (111) 111-1111 x12", "repeated digits with an extension"),
    n("PHONE", "de", "pii_phone_us", "Bestellnummer 2026-104-88x12", "order number with too few digits and a suffix"),
    n("PHONE", "de", "pii_phone_us", "Bildschirm mit 1920x1080 Pixeln", "resolution, not an extension", carrier="prose"),
    n("PHONE", "en", "pii_phone_us", "SKU 646-273-9915xl", "size suffix attached to a number"),
    n("PHONE", "en", "pii_phone_us", "Extension x4587 only", "extension without a number"),
    n("PHONE", "en", "pii_phone_us", "Phone: 999-999-9999 ext. 12", "repeated digits with an extension"),
    n("PHONE", "en", "pii_phone_us", "Phone: XXX-XXX-XXXX x123", "masked number with an extension", tags=("obfuscated",)),
    n("PHONE", "en", "pii_phone_us", "Ticket 1800-123-4567x5", "ticket number without NANP grouping"),
]
for _row in F18_PHONE_EXTENSION_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# B-DE1 (F10, F11, F12): the KVNR (§ 290 SGB V), the pension insurance number (VKVV § 4) and the
# LANR (KBV, 4-9 weights) are reported only with a valid check digit, in every mode. In
# `balanced`/`recall` an uppercase KVNR and an RVNR, bare or in its printed groups, need no field
# name (K05); a LANR (nine digits, mod 10) needs a LANR term near it or as its key. The BSNR has no
# check digit: nine digits with a BSNR term in every mode. Appended so existing ids stay stable.
B_DE1_CASES = [
    # ── check digits of the field-bound rules ─────────────────────────────
    n("SOCIALID", "de", "pii_rentenversicherung_de", "Sozialversicherungsnummer: 15070649C100", "check digit fails"),
    n("SOCIALID", "de", "pii_rentenversicherung_de", "Rentenversicherungsnummer: 15071349C107", "check digit valid, but month 13 is no birth month"),
    n("SOCIALID", "en", "pii_rentenversicherung_de", "Pension insurance number: 15070049C103", "check digit valid, but day 00 is no birth day"),
    n("SOCIALID", "en", "pii_rentenversicherung_de", "SV-Nr: 65 180539 W 002", "check digit fails"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "Versichertennummer: A123456789", "check digit fails"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de", "KVNR: S000000000", "nine zeros pass the check digit but are never issued"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "Health insurance number X123456789 is in the claim.", "check digit fails", carrier="prose"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de", "KVNR: M123456789", "check digit fails"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: 123456789", "check digit fails"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de", "LANR: 111111111", "one repeated digit passes the check digit but is never issued"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "Physician number: 234567601", "check digit fails"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de", "LANR: 222222222", "one repeated digit passes the check digit but is never issued"),
    # ── RVNR without a field name (balanced/recall) ───────────────────────
    p("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Bitte ", "15070649C103", " im Personalbogen eintragen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "", "65 180539 W 001", "", tags=("no_context",), mode="balanced"),
    p("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Meine Rentenversicherungsnummer ist ", "53270587M011", ".", carrier="prose", mode="balanced"),
    p("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Name;Nummer\nJonas Weber;", "12570356A128", "", carrier="csv", tags=("no_context",), mode="recall"),
    p("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Neue Angabe: ", "38 150462 K 141", " (bitte übernehmen).", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Please file ", "65070803A019", " with HR.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "", "25 220940 K 516", "", tags=("no_context",), mode="recall"),
    p("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Her pension insurance number reads ", "12120356A122", ".", carrier="prose", mode="balanced"),
    p("SOCIALID", "en", "pii_rentenversicherung_de_context_free", '{"employee": "Ada Weber", "code": "', "42011183B050", '"}', carrier="json", tags=("no_context",), mode="balanced"),
    p("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Record 7 lists ", "20290271D123", " for the employee.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Rechnungsnummer 15070649C103", "counter-context nearer", mode="balanced"),
    n("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Bitte 15070649C100 prüfen.", "check digit fails", carrier="prose", mode="balanced"),
    n("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Seriennummer 65180539W001", "counter-context nearer", mode="recall"),
    n("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Charge 15073249C102 gesperrt.", "check digit valid, but day 32 is no birth day", carrier="prose", mode="balanced"),
    n("SOCIALID", "de", "pii_rentenversicherung_de_context_free", "Code 15070649c103 eingegeben.", "lowercase letter without a field name", carrier="prose", mode="balanced"),
    n("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Batch 15070049C103 shipped.", "check digit valid, but day 00 is no birth day", carrier="prose", mode="balanced"),
    n("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Ticket number 65070803A019", "counter-context nearer", mode="balanced"),
    n("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Ref 15070649C103-2 archived.", "part of a longer value", carrier="prose", mode="balanced"),
    n("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Lot 15078249C100 recalled.", "check digit valid, but day 82 is no birth day", carrier="prose", mode="balanced"),
    n("SOCIALID", "en", "pii_rentenversicherung_de_context_free", "Value 15071349C107 logged.", "check digit valid, but month 13 is no birth month", carrier="prose", mode="recall"),
    # ── KVNR without a field name (balanced/recall) ───────────────────────
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Bitte ", "A123456780", " auf das Rezept übertragen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "", "B123456782", "", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Die Versichertennummer lautet ", "M234567898", ".", carrier="prose", mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Für Jonas Weber gilt ab heute ", "L654321095", ".", carrier="prose", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Neue Angabe ", "P102938475", " bitte übernehmen.", carrier="prose", tags=("no_context",), mode="recall"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Please add ", "Z987654321", " to the claim.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "", "Z000000005", "", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Her health insurance number, ", "W564738296", ", is new.", carrier="prose", mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Record 7 lists ", "R123405676", " for the patient.", carrier="prose", tags=("no_context",), mode="recall"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Claim filed for ", "B987654320", " yesterday.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Bitte A123456789 prüfen.", "check digit fails", carrier="prose", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Rechnungsnummer A123456780", "counter-context nearer", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Auftragscode: A123456780", "the field names another value", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Code a123456781 eingegeben.", "check digit fails", carrier="prose", mode="recall"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Teil AB123456780 geliefert.", "part of a longer value", carrier="prose", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Order number Z987654321", "counter-context nearer", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Batch M123456789 shipped.", "check digit fails", carrier="prose", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Code a123456781 entered.", "check digit fails", carrier="prose", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", '{"order_code": "B123456782"}', "the key names another value", carrier="json", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Value S000000000 logged.", "nine zeros are never issued", carrier="prose", mode="balanced"),
    # ── LANR with a term (balanced/recall) ────────────────────────────────
    p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Arztnummer ", "987654401", " auf dem Rezept.", carrier="prose", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Die LANR des Hausarztes lautet ", "123456601", ".", carrier="prose", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Rezept ausgestellt von Dr. Weber (Arzt-Nr. ", "234567701", ")", carrier="prose", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", '{"arztnummer": "', "765432203", '"}', carrier="json", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Als Arztnummer ist ", "314159323", " hinterlegt.", carrier="prose", mode="recall"),
    p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "The physician number on the prescription is ", "999999901", ".", carrier="prose", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "LANR of the prescriber: ", "271828334", "", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "| Doctor | Arzt-Nr |\n|---|---|\n| Dr. Weber | ", "161803944", " |", carrier="table", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "Prescribed by LANR holder ", "577215251", " last week.", carrier="prose", mode="balanced"),
    p("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "physician_number,name\n", "414213060", ",Dr. Weber", carrier="csv", mode="recall"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Bestellnummer 123456601", "valid check digit without a LANR term", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Arztnummer: 123456789", "check digit fails", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Arztnummer 111111111", "one repeated digit is never issued", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Arztnummer 123456601-2", "part of a longer number", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "de", "pii_physician_number_lanr_de_proximity", "Vorgang 234567701 wurde abgeschlossen.", "valid check digit without a LANR term", carrier="prose", mode="recall"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "Order 234567701 shipped.", "valid check digit without a LANR term", carrier="prose", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "LANR: 234567601", "check digit fails", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "Physician number 1234566019", "ten digits", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "Physician number, order number 123456601", "order number nearer than the LANR term", mode="balanced"),
    n("PHYSICIAN_NUMBER_LANR", "en", "pii_physician_number_lanr_de_proximity", "234567701", "valid check digit without a LANR term", mode="balanced"),
    # ── BSNR: format and a BSNR term, every mode ──────────────────────────
    p("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "BSNR: ", "721234567"),
    p("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "Betriebsstättennummer: ", "021234568"),
    p("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "BSNR ", "711234567", " der Praxis.", carrier="prose"),
    p("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", '{"bsnr": "', "381789045", '"}', carrier="json"),
    p("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "praxis:\n  betriebsstaettennummer: ", "463015565", "\n", carrier="yaml"),
    p("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "Als BSNR ist ", "781819850", " hinterlegt.", carrier="prose", mode="balanced"),
    p("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "BSNR: ", "201234561"),
    p("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "My practice number is ", "613645811", ".", carrier="prose"),
    p("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "German practice site number (BSNR) ", "521234567", ""),
    p("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "practice,bsnr\nDr. Weber,", "981234560", "", carrier="csv"),
    p("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", '<practice bsnr="', "171234565", '"/>', carrier="xml", mode="balanced"),
    n("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "BSNR: 000000000", "one repeated digit"),
    n("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "BSNR: 72123456", "eight digits"),
    n("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "Bestellnummer 721234567", "nine digits without a BSNR term", mode="balanced"),
    n("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "BSNR: siehe Stempel", "field without a value"),
    n("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "Die BSNR steht auf dem Stempel.", "field name without a value", carrier="prose"),
    n("FACILITY_NUMBER_BSNR", "de", "pii_facility_number_bsnr_de", "BSNR: 7212345670", "ten digits"),
    n("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "BSNR: 111111111", "one repeated digit"),
    n("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "Order 721234567 shipped.", "nine digits without a BSNR term", carrier="prose", mode="balanced"),
    n("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "Practice number 721234567-2", "part of a longer number"),
    n("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "BSNR, order number 721234567", "order number nearer than the BSNR term", mode="balanced"),
    n("FACILITY_NUMBER_BSNR", "en", "pii_facility_number_bsnr_de", "021234568", "nine bare digits", mode="balanced"),
]
for _row in B_DE1_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-EMAIL (T06, T23, F05): a local part holds Unicode letters (RFC 6531) and inner apostrophes
# (`jürgen.müller`, `moeleprêtr`, `o'neil`); in text without word spacing it is at most three
# ideographs or katakana, so the words before it stay outside (`联系邮箱伟伟许@aol.com`). Domain
# labels hold Unicode letters, the top-level domain is ASCII or punycode (`xn--p1ai`) and must be
# delegated by IANA or reserved as a placeholder (RFC 2606/6761: `.test`, `.example`, `.invalid`,
# `.localhost`, gold convention T01). The userinfo of a URL (`scheme://user:pass@host`) is no
# address; credentials there stay DLP. Appended so existing ids stay stable.
B_EMAIL_CASES = [
    p("EMAIL", "de", "pii_email", "E-Mail: ", "jürgen.müller@beispiel.de"),
    p("EMAIL", "de", "pii_email", "Bitte antworten Sie an ", "info@müller-bau.de", ".", carrier="prose"),
    p("EMAIL", "de", "pii_email", "Kontakt: ", "d'souza.anita@praxis-nord.de"),
    p("EMAIL", "de", "pii_email", "E-Mail (Moskau): ", "post@xn--e1afmkfd.xn--p1ai"),
    p("EMAIL", "de", "pii_email", "Ansprechpartnerin in Peking: ", "王芳@163.com", ", Telefon folgt.", carrier="prose"),
    p("EMAIL", "de", "pii_email", "Testkonto: ", "qa.bot@shop.test"),
    n("EMAIL", "de", "pii_email", "Datenbank: postgres://lager:Sommer2026@db.firma.de:5432/lager", "credentials in URL userinfo stay DLP"),
    n("EMAIL", "de", "pii_email", "Repository: ssh://git@git.firma.de/team/app.git", "user in URL userinfo"),
    n("EMAIL", "de", "pii_email", "Die Adresse wird mit adresse.split('@') zerlegt.", "quoted at sign in code", carrier="prose"),
    n("EMAIL", "de", "pii_email", "Schreiben Sie an anna.berg@firma.intern", "top-level domain not delegated by IANA"),
    n("EMAIL", "de", "pii_email", "Benutzer 'admin'@'localhost' anlegen.", "quoted MySQL account, not an address", carrier="prose"),
    p("EMAIL", "en", "pii_email", "Contact: ", "o'neil@example.com"),
    p("EMAIL", "en", "pii_email", "Please confirm by emailing ", "moeleprêtr@outlook.com", " or calling us.", carrier="prose", tags=("no_context",)),
    p("EMAIL", "en", "pii_email", "Email: ", "a@xn--d1acufc.xn--p1ai"),
    p("EMAIL", "en", "pii_email", "The card will be sent by email to ", "诗向@yahoo.com", ".", carrier="prose"),
    p("EMAIL", "en", "pii_email", "Chinese form, field 联系邮箱", "伟伟许@aol.com", "，phone to follow.", carrier="prose"),
    p("EMAIL", "en", "pii_email", "Bounce address: ", "noreply@mailer.invalid"),
    n("EMAIL", "en", "pii_email", "DATABASE_URL=postgres://app:Winter2026@db.northwind.com:5432/orders", "credentials in URL userinfo stay DLP"),
    n("EMAIL", "en", "pii_email", "Mirror: ftp://deploy@files.northwind.net/releases/", "user in URL userinfo"),
    n("EMAIL", "en", "pii_email", "if address.endswith(\"'@example.com\"):", "quoted at sign in code"),
    n("EMAIL", "en", "pii_email", "Sent from alice.williams@email.note", "top-level domain not delegated by IANA"),
    n("EMAIL", "en", "pii_email", "Tag the playlist rock'n'@roll.com today.", "apostrophe before the at sign", carrier="prose"),
]
for _row in B_EMAIL_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# B-NORD (B12, B13) Nordic personal identity numbers, one label each: the Swedish personnummer
# (Luhn), the Danish CPR number (weighted mod 11), the Norwegian fødselsnummer (two digits mod 11)
# and the Finnish personal identity code (check character mod 31), all starting with the birth date.
# `pii_*_se`/`_dk`/`_no`/`_fi` report the value in every mode when a term of the label stands near
# it or is its key. In balanced and recall the printed forms are reported bare (K05):
# `YYMMDD-NNNC`, `DDMMYY-SSSS`, `DDMMYY NNNKK` and the henkilötunnus with its century sign. Bare
# digit runs always need a term. Hard negatives: failed checks, impossible dates, values without
# a term, counter-context and parts of longer values. Appended so existing ids stay stable.
B_NORD_CASES = [
    # ── SE personnummer ────────────────────────────────────────────────────
    p("SE_PERSONNUMMER", "en", "pii_personnummer_se", "Personnummer: ", "510723-4287"),
    p("SE_PERSONNUMMER", "en", "pii_personnummer_se", "Here's my personnummer ", "200109022392", ".", carrier="prose"),
    p("SE_PERSONNUMMER", "en", "pii_personnummer_se", '{"personnummer": "', "6608272214", '"}', carrier="json"),
    p("SE_PERSONNUMMER", "en", "pii_personnummer_se", "name,personnummer\nAstrid Berg,", "19900906-5179", "", carrier="csv", mode="balanced"),
    p("SE_PERSONNUMMER", "en", "pii_personnummer_se_context_free", "Customer ", "970426-0034", " from Malmö", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SE_PERSONNUMMER", "en", "pii_personnummer_se_context_free", "", "310619-4388", "", tags=("no_context",), mode="recall"),
    p("SE_PERSONNUMMER", "de", "pii_personnummer_se", "Die schwedische Personennummer lautet ", "380326-7693", ".", carrier="prose"),
    p("SE_PERSONNUMMER", "de", "pii_personnummer_se", "Personnummer: ", "5904230439"),
    p("SE_PERSONNUMMER", "de", "pii_personnummer_se", "| Name | Personnummer |\n|---|---|\n| Astrid Berg | ", "851225-8966", " |", carrier="table"),
    p("SE_PERSONNUMMER", "de", "pii_personnummer_se", "Als Personnummer ist ", "470401-6270", " hinterlegt.", carrier="prose", mode="balanced"),
    p("SE_PERSONNUMMER", "de", "pii_personnummer_se_context_free", "Kunde ", "870323-1236", " aus Malmö", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SE_PERSONNUMMER", "de", "pii_personnummer_se_context_free", "Neue Angabe: ", "740208-2759", "", tags=("no_context",), mode="recall"),
    n("SE_PERSONNUMMER", "en", "pii_personnummer_se", "Personnummer: 510723-4288", "Luhn check digit fails"),
    n("SE_PERSONNUMMER", "en", "pii_personnummer_se", "Personnummer: 19001309-2393", "month 13 is no birth month"),
    n("SE_PERSONNUMMER", "en", "pii_personnummer_se", "Reference 6608272214 was archived.", "ten bare digits without a personnummer term", carrier="prose", mode="balanced"),
    n("SE_PERSONNUMMER", "en", "pii_personnummer_se_context_free", "Invoice number 970426-0034", "counter-context nearer", mode="balanced"),
    n("SE_PERSONNUMMER", "en", "pii_personnummer_se_context_free", "Build 20241026-1529 is out.", "date stamp and time (Luhn-valid) without a term", carrier="prose", mode="balanced"),
    n("SE_PERSONNUMMER", "de", "pii_personnummer_se", "Personnummer: 380326-7694", "Luhn check digit fails"),
    n("SE_PERSONNUMMER", "de", "pii_personnummer_se", "Personnummer: 200504422381", "day 42 is no birth day"),
    n("SE_PERSONNUMMER", "de", "pii_personnummer_se", "Vorgang 5904230439 wurde abgeschlossen.", "ten bare digits without a personnummer term", carrier="prose", mode="balanced"),
    n("SE_PERSONNUMMER", "de", "pii_personnummer_se_context_free", "Rechnungsnummer 870323-1236", "counter-context nearer", mode="balanced"),
    n("SE_PERSONNUMMER", "de", "pii_personnummer_se_context_free", "Teil 870323-1236-2 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    # ── DK CPR ─────────────────────────────────────────────────────────────
    p("DK_CPR", "en", "pii_cpr_dk", "CPR number: ", "180875-3002"),
    p("DK_CPR", "en", "pii_cpr_dk", "Her Danish CPR number is ", "1802712053", ".", carrier="prose"),
    p("DK_CPR", "en", "pii_cpr_dk", '{"cpr": "', "220594-0270", '"}', carrier="json"),
    p("DK_CPR", "en", "pii_cpr_dk", "name,cpr\nMads Jensen,", "210677-1025", "", carrier="csv", mode="balanced"),
    p("DK_CPR", "en", "pii_cpr_dk_context_free", "Patient ", "260881-0407", " from Aarhus", carrier="prose", tags=("no_context",), mode="balanced"),
    p("DK_CPR", "en", "pii_cpr_dk_context_free", "", "061088-1025", "", tags=("no_context",), mode="recall"),
    p("DK_CPR", "de", "pii_cpr_dk", "CPR-Nummer: ", "141143-1408"),
    p("DK_CPR", "de", "pii_cpr_dk", "Die dänische Personennummer lautet ", "1606642896", ".", carrier="prose"),
    p("DK_CPR", "de", "pii_cpr_dk", "patient:\n  cpr_nr: ", "181076-3775", "\n", carrier="yaml"),
    p("DK_CPR", "de", "pii_cpr_dk", "Als CPR-Nr. ist ", "060664-2644", " hinterlegt.", carrier="prose", mode="balanced"),
    p("DK_CPR", "de", "pii_cpr_dk_context_free", "Patientin ", "020852-2965", " aus Aarhus", carrier="prose", tags=("no_context",), mode="balanced"),
    p("DK_CPR", "de", "pii_cpr_dk_context_free", "Neue Angabe: ", "060147-0594", "", tags=("no_context",), mode="recall"),
    n("DK_CPR", "en", "pii_cpr_dk", "CPR number: 180875-3003", "mod-11 sum fails"),
    n("DK_CPR", "en", "pii_cpr_dk", "CPR number: 300275-3002", "30 February is no birth date"),
    n("DK_CPR", "en", "pii_cpr_dk", "Order 1802712053 shipped.", "ten bare digits without a CPR term", carrier="prose", mode="balanced"),
    n("DK_CPR", "en", "pii_cpr_dk_context_free", "Order number 260881-0407", "counter-context nearer", mode="balanced"),
    n("DK_CPR", "en", "pii_cpr_dk_context_free", "Ref 1/260881-0407 archived.", "part of a slash path", carrier="prose", mode="balanced"),
    n("DK_CPR", "de", "pii_cpr_dk", "CPR-Nummer: 141143-1409", "mod-11 sum fails"),
    n("DK_CPR", "de", "pii_cpr_dk", "CPR-Nummer: 141343-1408", "month 13 is no birth month"),
    n("DK_CPR", "de", "pii_cpr_dk", "Vorgang 1606642896 wurde abgeschlossen.", "ten bare digits without a CPR term", carrier="prose", mode="balanced"),
    n("DK_CPR", "de", "pii_cpr_dk_context_free", "Bestellnummer 020852-2965", "counter-context nearer", mode="balanced"),
    n("DK_CPR", "de", "pii_cpr_dk_context_free", "Teil 020852-2965-1 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    # ── NO fødselsnummer ───────────────────────────────────────────────────
    p("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", "Fødselsnummer: ", "05126504685"),
    p("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", "My Norwegian national identity number is ", "131059 38068", ".", carrier="prose"),
    p("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", '{"fodselsnummer": "', "04088748951", '"}', carrier="json"),
    p("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", "name,fnr\nIngrid Dahl,", "14125010564", "", carrier="csv", mode="balanced"),
    p("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no_context_free", "Member ", "120683 32824", " from Bergen", carrier="prose", tags=("no_context",), mode="balanced"),
    p("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no_context_free", "", "071177 13398", "", tags=("no_context",), mode="recall"),
    p("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", "Fødselsnummer: ", "11014526309"),
    p("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", "Die norwegische Personennummer lautet ", "22035625988", ".", carrier="prose"),
    p("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", "Als D-Nummer ist ", "53077117233", " hinterlegt.", carrier="prose"),
    p("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", '{"foedselsnummer": "', "280973 07840", '"}', carrier="json", mode="balanced"),
    p("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no_context_free", "Mitglied ", "120952 44287", " aus Bergen", carrier="prose", tags=("no_context",), mode="balanced"),
    p("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no_context_free", "Neue Angabe: ", "170178 16489", "", tags=("no_context",), mode="recall"),
    n("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", "Fødselsnummer: 05126504686", "second check digit fails"),
    n("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", "Fødselsnummer: 05126504675", "first check digit fails"),
    n("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no", "Reference 04088748951 was archived.", "eleven bare digits without a fødselsnummer term", carrier="prose", mode="balanced"),
    n("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no_context_free", "Invoice number 120683 32824", "counter-context nearer", mode="balanced"),
    n("NO_FODSELSNUMMER", "en", "pii_fodselsnummer_no_context_free", "Lot 120683 32824-7 was recalled.", "part of a longer value", carrier="prose", mode="balanced"),
    n("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", "Fødselsnummer: 11014526308", "second check digit fails"),
    n("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", "Fødselsnummer: 32014526309", "day 32 is no birth day"),
    n("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no", "Vorgang 22035625988 wurde abgeschlossen.", "eleven bare digits without a fødselsnummer term", carrier="prose", mode="balanced"),
    n("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no_context_free", "Bestellnummer 120952 44287", "counter-context nearer", mode="balanced"),
    n("NO_FODSELSNUMMER", "de", "pii_fodselsnummer_no_context_free", "Teil 120952 44287 1 ist lieferbar.", "part of a longer number", carrier="prose", mode="balanced"),
    # ── FI personal identity code ──────────────────────────────────────────
    p("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "HETU: ", "151052X036A"),
    p("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "Here's my henkilötunnus ", "230869U120Y", ".", carrier="prose"),
    p("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "hetu ", "050147-760n", ""),
    p("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "row,amount,hetu\n1,42,", "150115E166P", "", carrier="csv", mode="balanced"),
    p("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi_context_free", "Applicant ", "130693Y4989", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi_context_free", "", "021123B483N", "", tags=("no_context",), mode="recall"),
    p("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", "Finnische Personenkennung: ", "070409F691B"),
    p("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", "Die HETU lautet ", "241096-074P", ".", carrier="prose"),
    p("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", '{"hetu": "', "021093X717F", '"}', carrier="json"),
    p("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", "nr;name;hetu;betrag\n1;Aino Virtanen;", "090678W190W", ";5,00 €", carrier="csv", mode="balanced"),
    p("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi_context_free", "Antragsteller ", "171139X147M", " wurde genehmigt.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi_context_free", "Neue Angabe: ", "231134W191M", "", tags=("no_context",), mode="recall"),
    n("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "HETU: 151052X036B", "check character fails"),
    n("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "HETU: 111111-111A", "check character fails"),
    n("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi", "HETU: 151052+036A", "the 1800s sign names nobody alive"),
    n("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi_context_free", "Order number 130693Y4989", "counter-context nearer", mode="balanced"),
    n("FI_PERSONAL_IDENTITY_CODE", "en", "pii_hetu_fi_context_free", "Build X130693Y4989 is out.", "part of a longer token", carrier="prose", mode="balanced"),
    n("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", "HETU: 070409F691C", "check character fails"),
    n("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", "HETU: 311109F691B", "31 November is no birth date"),
    n("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi", "HETU: 070409G691B", "no century sign"),
    n("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi_context_free", "Bestellnummer 171139X147M", "counter-context nearer", mode="balanced"),
    n("FI_PERSONAL_IDENTITY_CODE", "de", "pii_hetu_fi_context_free", "Teil 171139X147M-2 ist lieferbar.", "part of a hyphenated token", carrier="prose", mode="balanced"),
]
for _row in B_NORD_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# T28 (TRIAGE 2026-W44 bucket 5): a field name opens an IPv6 address (`IPv6:`, `inet6:`,
# `eth0:`) unless it ends in a hex run of three or more characters with a digit; such a run is
# a further `:`-group glued to a word (`foo2001:db8::10.0.0.1`), and the address yields no span,
# neither IPv6 nor its IPv4 tail (B-IP "no partial match"). Appended so existing ids stay stable.
T28_IP_CASES = [
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "Gegenstelle ", "2001:db8::10.0.0.1", " antwortet.", carrier="prose"),
    p("IP_ADDRESS", "de", "pii_ipv6_loopback", "Gemappte Adresse: ", "::ffff:10.0.0.1"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "Schnittstelle ", "fe80::1%eth0", " ist aktiv.", carrier="prose"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "inet6:", "2001:db8:85a3::8a2e:370:7334", carrier="kv"),
    p("IP_ADDRESS", "de", "pii_ipv6_compressed", "eth0:", "fe80::a1b2:3c4d", carrier="kv", mode="balanced"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Kennung foo2001:db8::10.0.0.1 ungültig", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Gerät host2001:db8:85a3::8a2e:370:7334 gesperrt", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Artikel sku4f00:db8::1:2:3 vergriffen", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Knoten xyz2a02:810d:4b40::52d7 entfernt", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "de", "pii_ipv6_compressed", "Kennung foo2001:db8::10.0.0.1 ungültig", "IPv6 group glued to a word", mode="balanced"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "", "2001:db8::10.0.0.1"),
    p("IP_ADDRESS", "en", "pii_ipv6_loopback", "Peer ", "::ffff:10.0.0.1", " connected.", carrier="prose"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "", "fe80::1%eth0"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "IPv6:", "2001:db8::10.0.0.1", carrier="kv"),
    p("IP_ADDRESS", "en", "pii_ipv6_compressed", "inet6:", "2001:db8:4f00::17", carrier="kv", mode="balanced"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "foo2001:db8::10.0.0.1", "IPv6 group glued to a word (presidio-analyzer IP test)"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "Device host2001:db8:85a3::8a2e:370:7334 blocked", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "Item sku4f00:db8::1:2:3 sold out", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "Node xyz2a02:810d:4b40::52d7 removed", "IPv6 group glued to a word"),
    n("IP_ADDRESS", "en", "pii_ipv6_compressed", "foo2001:db8::10.0.0.1", "IPv6 group glued to a word (presidio-analyzer IP test)", mode="balanced"),
]
for _row in T28_IP_CASES:
    PII_CASES[_row["target_label"]].append(_row)

# Q-DE: in `balanced`/`recall` a bare KVNR may carry a lowercase letter (the check digit counts
# it like the uppercase one, as the presidio-analyzer tests do), and a bare Steuernummer in the
# slashed groups of the Länder (2/3/5, 3/3/5, 3/4/4) needs no field name. The 13-digit ELSTER
# form stays field-bound: bare, it is as often a timestamp in milliseconds. Appended so existing
# ids stay stable.
Q_DE_CASES = [
    # ── KVNR with a lowercase letter, no field name ────────────────────────
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "", "a123456780", "", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Code ", "m234567898", " eingegeben.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Die Versichertennummer lautet ", "k987654329", ".", carrier="prose", mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Name;Versichertennummer\nJonas Weber;", "t345678916", "", carrier="csv", mode="recall"),
    p("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Neue Angabe ", "h204816321", " bitte übernehmen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "", "b123456782", "", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Code ", "w564738296", " entered.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Her health insurance number is ", "l654321095", ".", carrier="prose", mode="balanced"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Record 7 lists ", "r123405676", " for the patient.", carrier="prose", tags=("no_context",), mode="recall"),
    p("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Ada Weber brought ", "p102938475", " to the desk.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "m234567899", "check digit fails", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Rechnungsnummer k987654329", "counter-context nearer", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Auftragscode: t345678916", "the field names another value", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Teil ab123456780 geliefert.", "part of a longer value", carrier="prose", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "de", "pii_health_insurance_number_de_context_free", "Wert s000000000 protokolliert.", "nine zeros are never issued", carrier="prose", mode="recall"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "b123456783", "check digit fails", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Order number w564738296", "counter-context nearer", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", '{"order_code": "r123405676"}', "the key names another value", carrier="json", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Hash 3fa123456780e9 logged.", "part of a longer value", carrier="prose", mode="balanced"),
    n("HEALTH_INSURANCE_NUMBER", "en", "pii_health_insurance_number_de_context_free", "Build x123456789 shipped.", "check digit fails", carrier="prose", mode="recall"),
    # ── Steuernummer in slashed groups, no field name ──────────────────────
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "", "123/456/78901", "", tags=("no_context",), mode="balanced"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Bitte ", "151/815/08156", " im Formular eintragen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Die Steuernummer der Praxis ist ", "143/208/30142", ".", carrier="prose", mode="balanced"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Name;Steuernummer\nJonas Weber;", "133/8150/8159", "", carrier="csv", mode="recall"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Neue Angabe (", "21/815/08150", ") bitte übernehmen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Please file ", "21/815/08150", " with the return.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "", "048/815/08153", "", tags=("no_context",), mode="balanced"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "The German tax number on file is ", "133/8150/8159", ".", carrier="prose", mode="balanced"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "name,tax_number\nAda Weber,", "22/943/46701", "", carrier="csv", mode="recall"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Record 7 lists ", "166/492/23547", " for the branch.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Aktenzeichen: 123/456/78901", "the field names another value", mode="balanced"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Rechnungsnummer 151/815/08156", "counter-context nearer", mode="balanced"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Bitte 111/111/11111 prüfen.", "repeated digits are never issued", carrier="prose", mode="balanced"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "Pfad 2026/123/456/78901", "part of a longer path", carrier="prose", mode="recall"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de_context_free", "0181508150000", "13 digits without slashes", mode="balanced"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Case number: 21/815/08150", "the field names another value", mode="balanced"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Invoice number 048/815/08153", "counter-context nearer", mode="balanced"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Please check 123/456/7890.", "too few digits in the last group", carrier="prose", mode="balanced"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Ref 123/456/78901-2 archived.", "part of a longer value", carrier="prose", mode="balanced"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de_context_free", "Timestamp 1698234567890", "13 digits without slashes", mode="recall"),
]
for _row in Q_DE_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-ACCT (A04, F14): the ABA routing number (Federal Reserve routing symbol, 3-7-1 check digit) is
# reported in every mode with a routing or account term near it or as its key; nine bare digits pass
# the check one time in ten. Only the printed 4-4-1 form is reported bare, in `balanced`/`recall`
# (K05). The field-bound account rule also binds the BBAN, the routing number (with or without its
# check digit) and `acct` fields, before the value and as structural keys, and the customer ID rule
# takes `customer_id`/`customer-number`. Appended so existing ids stay stable.
B_ACCT_CASES = [
    # ── ABA routing number with a term, every mode ────────────────────────
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "Die Routingnummer der US-Bank lautet ", "021000021", ".", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "Überweisung über ABA ", "121000358", " an die Filiale in Boston.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "Bitte ", "011000015", " (ABA-Nummer) für die Gutschrift verwenden.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", '{"aba": "', "053000196", '"}', carrier="json"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "rtn;betrag\n", "061000052", ";42,00", carrier="csv"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "Für die Lastschrift gilt die ABA ", "0711-0130-7", ".", carrier="prose", mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "The bank's ABA routing number is ", "026009593", ".", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "Wire to ", "111000025", " (bank routing number) by Friday.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "We may also collect bank routing numbers, such as ", "322271627", ".", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "rtn,amount\n", "091000019", ",42", carrier="csv"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "Lender: First Bank, ABA ", "256074974", ", Boston", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "Payments clear through RTN ", "3222-7162-7", " only.", carrier="prose", mode="recall"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "Bestellnummer 121000358", "valid check digit without a routing term"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "Vorgang 021000021 wurde abgeschlossen.", "valid check digit without a routing term", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "ABA 121000359", "check digit fails"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "ABA 901000358", "check digit valid, but 90 is no routing symbol", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us", "ABA 1210003580", "ten digits"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "Order 021000021 shipped.", "valid check digit without a routing term", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "ABA 421042111", "check digit and routing symbol fail (presidio-analyzer negative)", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "ABA, order number 121000358", "order number nearer than the routing term", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "ABA 000000000", "one repeated digit"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us", "ABA 121000358-2", "part of a longer number"),
    # ── bare 4-4-1 form (balanced/recall) ─────────────────────────────────
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Bitte überweisen Sie an ", "0260-0959-3", ".", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "", "0711-0130-7", "", tags=("no_context",), mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Gutschrift über ", "0210-0002-1", " ist erfolgt.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Neue Angabe: ", "1110-0002-5", "", tags=("no_context",), mode="recall"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Die ABA-Nummer ", "0530-0019-6", " liegt vor.", carrier="prose", mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Please send the wire to ", "1210-0035-8", " today.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "", "3222-7162-7", "", tags=("no_context",), mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Transfer via ", "0110-0001-5", ", thanks.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Record 7 lists ", "0610-0005-2", " for the payee.", carrier="prose", tags=("no_context",), mode="recall"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "", "0910-0001-9", " is the routing number.", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Rechnungsnummer 0711-0130-7", "counter-context nearer", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Bitte 0711-0130-8 prüfen.", "check digit fails", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Teil 4210-4211-3 geliefert.", "check digit valid, but 42 is no routing symbol", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "Serie 0711-0130-75 gesperrt.", "part of a longer value", carrier="prose", mode="recall"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_aba_routing_number_us_context_free", "121000358", "nine bare digits", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Ticket number 3222-7162-7", "counter-context nearer", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Batch 1210-0035-9 shipped.", "check digit fails", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Part X0711-0130-7 ordered.", "part of a longer value", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "Lot 9010-0035-8 recalled.", "check digit valid, but 90 is no routing symbol", carrier="prose", mode="recall"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_aba_routing_number_us_context_free", "0711-0130-7", "strict never reports the bare form"),
    # ── BBAN, routing and acct fields, every mode ─────────────────────────
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "BBAN: ", "19617962324057605069"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Routing-Nummer: ", "512345678"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", '{"bban": "', "ADXO08034447307440", '"}', carrier="json"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "name;bank_routing_number\nIsidora Cordero;", "577522835", "", carrier="csv"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "<Konto>\n<AcctNumber>", "823754616", "</AcctNumber>\n</Konto>", carrier="xml"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "konto:\n  bban: ", "36641600086542880045", "\n", carrier="yaml"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "| Name | BBAN |\n|---|---|\n| Jonas Weber | ", "147235766578281277", " |", carrier="table"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "BBAN: ", "ZFJR88590163492773"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Bank Routing Number: ", "932049652"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "My bank routing number is ", "885327936", ", as requested.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Carr, with the BBAN number ", "NQTZ73395804946160", ", resides here.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "<RoutingNumber>", "174518479", "</RoutingNumber>", carrier="xml"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Acct No: ", "55120443"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "routing_number: ", "259255680", "", carrier="kv"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "<AcctId>", "H0873491448510040803748", "</AcctId>", carrier="xml"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "BBAN: siehe Anlage", "field without a value"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Die BBAN ist Teil der IBAN.", "field name without a value", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Routing-Nummer: ****", "masked value", tags=("obfuscated",)),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Bestellnummer: 932049652", "wrong identifier anchor"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_financial_account_number", "Die Routing-Tabelle wurde für 10 Hosts aktualisiert.", "network routing, no field", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Bank routing number: on file", "field without a value"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Routing number: ****", "masked value", tags=("obfuscated",)),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Enter the routing number without dashes.", "field name without a value", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Network routing table updated for 10 hosts.", "network routing, no field", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_financial_account_number", "Routing number for direct deposit is printed on the cheque.", "field name without a value", carrier="prose"),
    # ── customer IDs under customer_id / customer-number ──────────────────
    p("CUSTOMER_ID", "de", "pii_customer_id", "Datensatz: customer_id: ", "K7430771", ""),
    p("CUSTOMER_ID", "de", "pii_customer_id", "57=customer_id:", "Xt70626-Z", "|57=passwort:x", carrier="kv"),
    p("CUSTOMER_ID", "de", "pii_customer_id", "Laut Export customer-number = ", "C150-5439-416", "", carrier="kv"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "Services: braces. Customer_ID: ", "T-397878-G", ""),
    p("CUSTOMER_ID", "en", "pii_customer_id", "57=customer_id:", "K7430771", "|57=password:x", carrier="kv"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "customer-number = ", "C150-5439-416", "", carrier="kv"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "customer_id: keine Angabe", "field without a value"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "customer_id=42", "value too short", carrier="kv"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "customer_id: none", "field without a value"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "customer-number = ****", "masked value", carrier="kv", tags=("obfuscated",)),
]
for _row in B_ACCT_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-EU1 (B09, B10, B11): French NIR (key mod 97), SIREN and SIRET (Luhn, La Poste by digit
# sum), Dutch BSN (11-proof) and Belgian national number (mod 97), one label each.
# `pii_*_fr`/`_nl`/`_be` report the value in every mode when a term of the label stands near
# it or is its key. In balanced and recall the forms whose shape adds to the check digit are
# reported bare (K05): the NIR printed 1-2-2-2-3-3-2 or as fifteen characters of sex 1 or 2,
# the SIRET in 3-3-3-5 groups, the BSN printed 1234.56.782, the national number printed
# 85.07.30-033.28. The SIREN, nine bare digits (BSN), eleven (national number) and fourteen
# (SIRET) always need a term. FR and NL rows add the national field names. Hard negatives:
# failed checks, impossible fields, values without a term, counter-context and parts of
# longer values. Appended so existing ids stay stable.
B_EU1_CASES = [
    # ── FR NIR ─────────────────────────────────────────────────────────────
    p("FR_NIR", "en", "pii_nir_fr", "NIR: ", "250092B86543121"),
    p("FR_NIR", "en", "pii_nir_fr", "Her French social security number is ", "2 65 09 75 590 230 87", ".", carrier="prose"),
    p("FR_NIR", "en", "pii_nir_fr", '{"nir": "', "106124490968794", '"}', carrier="json"),
    p("FR_NIR", "en", "pii_nir_fr", "name,insee_number\nLuc Martin,", "191105948214616", "", carrier="csv", mode="balanced"),
    p("FR_NIR", "en", "pii_nir_fr_context_free", "Patient ", "2 29 02 31 691 481 34", " was admitted.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FR_NIR", "en", "pii_nir_fr_context_free", "", "271072B56281996", "", tags=("no_context",), mode="recall"),
    p("FR_NIR", "de", "pii_nir_fr", "Die französische Sozialversicherungsnummer lautet ", "2 51 07 2A 302 852 86", ".", carrier="prose"),
    p("FR_NIR", "de", "pii_nir_fr", "NIR-Nummer: ", "201011367290483"),
    p("FR_NIR", "de", "pii_nir_fr", '{"insee": "', "266083394420567", '"}', carrier="json", mode="balanced"),
    p("FR_NIR", "de", "pii_nir_fr_context_free", "Versicherte ", "2 88 08 31 524 786 04", " wurde aufgenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FR_NIR", "de", "pii_nir_fr_context_free", "Patientin aus Lyon, ", "255097585229821", "", tags=("no_context",), mode="balanced"),
    p("FR_NIR", "fr", "pii_nir_fr", "Numéro de sécurité sociale : ", "2 58 02 31 706 734 44"),
    p("FR_NIR", "fr", "pii_nir_fr", "N° INSEE ", "257035986374663", ""),
    p("FR_NIR", "fr", "pii_nir_fr", "Merci d'indiquer votre numéro de sécu : ", "2 08 11 2B 925 511 37", ".", carrier="prose"),
    n("FR_NIR", "en", "pii_nir_fr", "NIR: 250092B86543122", "key fails"),
    n("FR_NIR", "en", "pii_nir_fr", "NIR: 185137800608425", "key valid, but month 13 is no birth month"),
    n("FR_NIR", "en", "pii_nir_fr", "Reference 385057800608488 was archived.", "sex 3 needs a NIR term", carrier="prose", mode="balanced"),
    n("FR_NIR", "en", "pii_nir_fr_context_free", "Order number 2 29 02 31 691 481 34", "counter-context nearer", mode="balanced"),
    n("FR_NIR", "en", "pii_nir_fr_context_free", "Batch 265097559023087-2 was archived.", "part of a longer number", carrier="prose", mode="balanced"),
    n("FR_NIR", "de", "pii_nir_fr", "NIR: 2 51 07 2A 302 852 87", "key fails"),
    n("FR_NIR", "de", "pii_nir_fr", "NIR: 585057800608485", "key valid, but sex 5 does not exist"),
    n("FR_NIR", "de", "pii_nir_fr", "NIR: 185050000608463", "key valid, but département 00 does not exist"),
    n("FR_NIR", "de", "pii_nir_fr_context_free", "Bestellnummer 255097585229821", "counter-context nearer", mode="balanced"),
    n("FR_NIR", "de", "pii_nir_fr_context_free", "Versicherte 2 51 07 2a 302 852 86 wurde aufgenommen.", "lowercase Corsica code", carrier="prose", mode="balanced"),
    n("FR_NIR", "fr", "pii_nir_fr", "Numéro de sécurité sociale : 2 58 02 31 706 734 45", "key fails"),
    n("FR_NIR", "fr", "pii_nir_fr", "N° INSEE 18545780060845", "fourteen characters"),
    # ── FR SIREN ───────────────────────────────────────────────────────────
    p("FR_SIREN", "en", "pii_siren_fr", "SIREN: ", "259 880 003"),
    p("FR_SIREN", "en", "pii_siren_fr", "The SIREN of the supplier is ", "528804834", ".", carrier="prose"),
    p("FR_SIREN", "en", "pii_siren_fr", '{"siren": "', "774465223", '"}', carrier="json"),
    p("FR_SIREN", "en", "pii_siren_fr", "company,siren\nAcme SAS,", "786 956 813", "", carrier="csv", mode="balanced"),
    p("FR_SIREN", "en", "pii_siren_fr", "French company number (SIREN) ", "968654681", "", mode="recall"),
    p("FR_SIREN", "en", "pii_siren_fr", "Please register SIREN ", "237 756 846", " for the contract.", carrier="prose", mode="balanced"),
    p("FR_SIREN", "de", "pii_siren_fr", "Die SIREN-Nummer lautet ", "399687458", ".", carrier="prose"),
    p("FR_SIREN", "de", "pii_siren_fr", "SIREN: ", "906 689 682"),
    p("FR_SIREN", "de", "pii_siren_fr", "| Firma | SIREN |\n|---|---|\n| Acme SAS | ", "934141847", " |", carrier="table"),
    p("FR_SIREN", "de", "pii_siren_fr", '{"siren": "', "847 000 874", '"}', carrier="json", mode="balanced"),
    p("FR_SIREN", "de", "pii_siren_fr", "Als SIREN ist ", "664539830", " hinterlegt.", carrier="prose", mode="balanced"),
    p("FR_SIREN", "fr", "pii_siren_fr", "Numéro SIREN : ", "868 488 842"),
    p("FR_SIREN", "fr", "pii_siren_fr", "La société est immatriculée sous le n° SIREN ", "835260084", ".", carrier="prose"),
    n("FR_SIREN", "en", "pii_siren_fr", "SIREN: 259 880 004", "Luhn fails"),
    n("FR_SIREN", "en", "pii_siren_fr", "Order 528804834 shipped.", "valid Luhn without a SIREN term", carrier="prose", mode="balanced"),
    n("FR_SIREN", "en", "pii_siren_fr", "SIREN: 000 000 000", "one repeated digit"),
    n("FR_SIREN", "en", "pii_siren_fr", "SIREN letter, invoice number 774465223", "invoice number nearer than the SIREN term", mode="balanced"),
    n("FR_SIREN", "en", "pii_siren_fr", "SIREN: 786 956 813 5", "part of a longer number"),
    n("FR_SIREN", "de", "pii_siren_fr", "SIREN: 399687459", "Luhn fails"),
    n("FR_SIREN", "de", "pii_siren_fr", "Vorgang 906 689 682 wurde abgeschlossen.", "valid Luhn without a SIREN term", carrier="prose", mode="balanced"),
    n("FR_SIREN", "de", "pii_siren_fr", "SIREN-Gruppe, Bestellnummer 934141847", "order number nearer than the SIREN term", mode="balanced"),
    n("FR_SIREN", "de", "pii_siren_fr", "SIREN: 84700087", "eight digits"),
    n("FR_SIREN", "de", "pii_siren_fr", "Artikel 664 539 830", "valid Luhn without a SIREN term", mode="recall"),
    n("FR_SIREN", "fr", "pii_siren_fr", "Numéro SIREN : 868 488 843", "Luhn fails"),
    n("FR_SIREN", "fr", "pii_siren_fr", "SIREN/SIRET : 868 488 842 00017", "a valid SIREN inside a longer number"),
    # ── FR SIRET ───────────────────────────────────────────────────────────
    p("FR_SIRET", "en", "pii_siret_fr", "SIRET: ", "887 214 955 72261"),
    p("FR_SIRET", "en", "pii_siret_fr", "Our SIRET number is ", "42203407400415", ".", carrier="prose"),
    p("FR_SIRET", "en", "pii_siret_fr", '{"siret": "', "92437103213222", '"}', carrier="json", mode="balanced"),
    p("FR_SIRET", "en", "pii_siret_fr_context_free", "Supplier ", "248 628 075 47067", ", Paris", tags=("no_context",), mode="balanced"),
    p("FR_SIRET", "en", "pii_siret_fr_context_free", "", "231 602 657 73676", "", tags=("no_context",), mode="recall"),
    p("FR_SIRET", "en", "pii_siret_fr", "branch,siret\nLyon,", "11542004480321", "", carrier="csv"),
    p("FR_SIRET", "de", "pii_siret_fr", "Als SIRET ist ", "52175656934442", " hinterlegt.", carrier="prose"),
    p("FR_SIRET", "de", "pii_siret_fr", "SIRET-Nummer: ", "633 136 171 41206"),
    p("FR_SIRET", "de", "pii_siret_fr", "Die SIRET der Filiale (La Poste) lautet ", "35600000049837", ".", carrier="prose", mode="balanced"),
    p("FR_SIRET", "de", "pii_siret_fr_context_free", "Lieferant ", "566 618 468 58431", ", Paris", tags=("no_context",), mode="balanced"),
    p("FR_SIRET", "de", "pii_siret_fr_context_free", "Neue Filiale ", "605 121 029 84144", " bitte anlegen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("FR_SIRET", "fr", "pii_siret_fr", "N° SIRET : ", "955 929 880 12508"),
    p("FR_SIRET", "fr", "pii_siret_fr", "Établissement enregistré sous le numéro SIRET ", "55686986514693", ".", carrier="prose"),
    n("FR_SIRET", "en", "pii_siret_fr", "SIRET: 887 214 955 72262", "Luhn fails"),
    n("FR_SIRET", "en", "pii_siret_fr", "SIRET: 12345678901234", "form placeholder, Luhn fails"),
    n("FR_SIRET", "en", "pii_siret_fr", "Reference 42203407400415 was archived.", "fourteen bare digits without a SIRET term", carrier="prose", mode="balanced"),
    n("FR_SIRET", "en", "pii_siret_fr_context_free", "Invoice number 248 628 075 47067", "counter-context nearer", mode="balanced"),
    n("FR_SIRET", "en", "pii_siret_fr_context_free", "Dial 1 248 628 075 47067 now.", "part of a longer number", carrier="prose", mode="balanced"),
    n("FR_SIRET", "de", "pii_siret_fr", "SIRET: 73282932100064", "the fourteen digits pass Luhn, the SIREN part does not"),
    n("FR_SIRET", "de", "pii_siret_fr", "SIRET: 35600000010013", "La Poste: Luhn without the digit sum"),
    n("FR_SIRET", "de", "pii_siret_fr", "Vorgang 52175656934442 wurde abgeschlossen.", "fourteen bare digits without a SIRET term", carrier="prose", mode="balanced"),
    n("FR_SIRET", "de", "pii_siret_fr_context_free", "Rechnungsnummer 566 618 468 58431", "counter-context nearer", mode="balanced"),
    n("FR_SIRET", "de", "pii_siret_fr_context_free", "Lieferant 566 618 468 58432, Paris", "Luhn fails", mode="balanced"),
    n("FR_SIRET", "fr", "pii_siret_fr", "N° SIRET : 955 929 880 12509", "Luhn fails"),
    n("FR_SIRET", "fr", "pii_siret_fr", "N° SIRET : 9559298801250", "thirteen digits"),
    # ── NL BSN ─────────────────────────────────────────────────────────────
    p("NL_BSN", "en", "pii_bsn_nl", "BSN: ", "713976044"),
    p("NL_BSN", "en", "pii_bsn_nl", "Her citizen service number is ", "289 097 149", ".", carrier="prose"),
    p("NL_BSN", "en", "pii_bsn_nl", '{"bsn": "', "965429258", '"}', carrier="json", mode="balanced"),
    p("NL_BSN", "en", "pii_bsn_nl_context_free", "Applicant ", "8750.04.519", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("NL_BSN", "en", "pii_bsn_nl_context_free", "", "5147.31.047", "", tags=("no_context",), mode="recall"),
    p("NL_BSN", "en", "pii_bsn_nl", "name,bsn\nJan de Vries,", "133204522", "", carrier="csv"),
    p("NL_BSN", "de", "pii_bsn_nl", "Die BSN lautet ", "595054845", ".", carrier="prose"),
    p("NL_BSN", "de", "pii_bsn_nl", "Niederländische Bürgerservicenummer: ", "5879.38.122"),
    p("NL_BSN", "de", "pii_bsn_nl", '{"bsn": "', "718 841 062", '"}', carrier="json", mode="balanced"),
    p("NL_BSN", "de", "pii_bsn_nl_context_free", "Antragsteller ", "2217.14.273", " wurde genehmigt.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("NL_BSN", "de", "pii_bsn_nl_context_free", "Mieterin aus Utrecht, ", "6352.24.495", "", tags=("no_context",), mode="balanced"),
    p("NL_BSN", "nl", "pii_bsn_nl", "Burgerservicenummer: ", "886137147"),
    p("NL_BSN", "nl", "pii_bsn_nl", "Mijn BSN is ", "8441.68.890", ".", carrier="prose"),
    p("NL_BSN", "nl", "pii_bsn_nl", "naam;bsn;woonplaats\nJan de Vries;", "769015086", ";Utrecht", carrier="csv", mode="balanced"),
    n("NL_BSN", "en", "pii_bsn_nl", "BSN: 713976045", "11-proof fails"),
    n("NL_BSN", "en", "pii_bsn_nl", "Call 289 097 149 today.", "valid 11-proof without a BSN term", carrier="prose", mode="balanced"),
    n("NL_BSN", "en", "pii_bsn_nl", "BSN: 111111111", "one repeated digit"),
    n("NL_BSN", "en", "pii_bsn_nl_context_free", "Order number 8750.04.519", "counter-context nearer", mode="balanced"),
    n("NL_BSN", "en", "pii_bsn_nl_context_free", "Version 5147.31.047.2 released.", "part of a longer value", carrier="prose", mode="balanced"),
    n("NL_BSN", "de", "pii_bsn_nl", "BSN: 595054846", "11-proof fails"),
    n("NL_BSN", "de", "pii_bsn_nl", "Vorgang 718841062 wurde abgeschlossen.", "valid 11-proof without a BSN term", carrier="prose", mode="balanced"),
    n("NL_BSN", "de", "pii_bsn_nl", "BSN-Schreiben, Rechnungsnummer 133204522", "invoice number nearer than the BSN term", mode="balanced"),
    n("NL_BSN", "de", "pii_bsn_nl", "BSN: 59505484", "eight digits"),
    n("NL_BSN", "de", "pii_bsn_nl_context_free", "Antragsteller 2217.14.274 wurde genehmigt.", "11-proof fails", carrier="prose", mode="balanced"),
    n("NL_BSN", "nl", "pii_bsn_nl", "Burgerservicenummer: 886137148", "11-proof fails"),
    n("NL_BSN", "nl", "pii_bsn_nl", "Ordernummer 886137147 is verzonden.", "valid 11-proof without a BSN term", carrier="prose", mode="balanced"),
    # ── BE national number ─────────────────────────────────────────────────
    p("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", "National register number: ", "45102620431"),
    p("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", "His Belgian national number is ", "190125-560.95", ".", carrier="prose"),
    p("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", '{"insz": "', "82111215919", '"}', carrier="json", mode="balanced"),
    p("BE_NATIONAL_NUMBER", "en", "pii_national_number_be_context_free", "Client ", "21.10.19-788.55", ", Brussels", tags=("no_context",), mode="balanced"),
    p("BE_NATIONAL_NUMBER", "en", "pii_national_number_be_context_free", "", "95.08.23-738.41", "", tags=("no_context",), mode="recall"),
    p("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", "name,national_number\nLuc Peeters,", "74041660314", "", carrier="csv"),
    p("BE_NATIONAL_NUMBER", "de", "pii_national_number_be", "Belgische Nationalregisternummer: ", "19121729892"),
    p("BE_NATIONAL_NUMBER", "de", "pii_national_number_be", "Die Nationalnummer lautet ", "21.03.05-803.23", ".", carrier="prose"),
    p("BE_NATIONAL_NUMBER", "de", "pii_national_number_be", '{"rijksregisternummer": "', "77051742241", '"}', carrier="json", mode="balanced"),
    p("BE_NATIONAL_NUMBER", "de", "pii_national_number_be_context_free", "Kunde ", "49.09.26-202.13", ", Brüssel", tags=("no_context",), mode="balanced"),
    p("BE_NATIONAL_NUMBER", "de", "pii_national_number_be_context_free", "Antrag von ", "46.07.03-053.96", " liegt vor.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("BE_NATIONAL_NUMBER", "fr", "pii_national_number_be", "Numéro de registre national : ", "81.06.25-968.25"),
    p("BE_NATIONAL_NUMBER", "fr", "pii_national_number_be", "NISS ", "16081170070", ""),
    p("BE_NATIONAL_NUMBER", "nl", "pii_national_number_be", "Rijksregisternummer: ", "60.02.16-972.16"),
    p("BE_NATIONAL_NUMBER", "nl", "pii_national_number_be", "Mijn rijksregisternummer is ", "79030560651", ".", carrier="prose"),
    n("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", "National register number: 45102620432", "check fails"),
    n("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", "Reference 82111215919 was archived.", "eleven bare digits without a term", carrier="prose", mode="balanced"),
    n("BE_NATIONAL_NUMBER", "en", "pii_national_number_be", "National register number: 85133003370", "check valid, but month 13 is no birth month"),
    n("BE_NATIONAL_NUMBER", "en", "pii_national_number_be_context_free", "Order number 21.10.19-788.55", "counter-context nearer", mode="balanced"),
    n("BE_NATIONAL_NUMBER", "en", "pii_national_number_be_context_free", "Client 21.10.19-788.55-2, Brussels", "part of a longer value", mode="balanced"),
    n("BE_NATIONAL_NUMBER", "de", "pii_national_number_be", "Nationalregisternummer: 19121729893", "check fails"),
    n("BE_NATIONAL_NUMBER", "de", "pii_national_number_be", "Nationalregisternummer: 85073000061", "check valid, but serial 000 is never issued"),
    n("BE_NATIONAL_NUMBER", "de", "pii_national_number_be", "Vorgang 77051742241 wurde abgeschlossen.", "eleven bare digits without a term", carrier="prose", mode="balanced"),
    n("BE_NATIONAL_NUMBER", "de", "pii_national_number_be_context_free", "Rechnungsnummer 49.09.26-202.13", "counter-context nearer", mode="balanced"),
    n("BE_NATIONAL_NUMBER", "de", "pii_national_number_be_context_free", "Kunde 49.09.32-202.13, Brüssel", "day 32 is no birth day", mode="balanced"),
    n("BE_NATIONAL_NUMBER", "fr", "pii_national_number_be", "Numéro de registre national : 81.06.25-968.26", "check fails"),
    n("BE_NATIONAL_NUMBER", "nl", "pii_national_number_be", "Rijksregisternummer: 60.02.16-972.17", "check fails"),
]
for _row in B_EU1_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# Q-CONTACT (quality floor 2026-10-25): field-bound contact and account values that the rules
# missed. Usernames in `user=` log and query assignments; a form printed as a table without edge
# pipes (`Geburtsdatum | 21. Februar 1971`, a structural key for every field-bound rule); birth
# dates in the ISO order, after `geb.`, `born on`, `date of birth of`, a no-break space or an
# example opener, with ordinal days and FR/ES/IT/NL months; employee IDs `EMP821659` and
# `PN 201033`; customer IDs after `a customer ID of`, `the customer with the ID` and
# `(e.g., …)`. Hard negatives: impossible dates, `login issues`, a name after `Account Name:`,
# other fields and glued or lowercase prefixes. Appended so existing ids stay stable.
Q_CONTACT_CASES = [
    # ── usernames ─────────────────────────────────────────────────────────
    p("USERNAME", "de", "pii_username", "08:59:59 WARN auth failed user=", "oeztuerk90", " src=host-7"),
    p("USERNAME", "de", "pii_username", "Name, Vorname | Wagner, Jonas\nBenutzername | ", "jwagner", "\nOrt | Hamburg", carrier="table"),
    p("USERNAME", "de", "pii_username", "Name | Kaya, Burak\nLogin | ", "wisniewski53", "", carrier="table"),
    p("USERNAME", "de", "pii_username", "GET /api/profile?user=", "lena.koehler", "&lang=de HTTP/1.1"),
    p("USERNAME", "de", "pii_username", "Als Benutzername ist ", "lefevre87", " hinterlegt.", carrier="prose", mode="balanced"),
    n("USERNAME", "de", "pii_username", "Login isoliert die Sitzung.", "no assignment: `is` starts a word", carrier="prose"),
    n("USERNAME", "de", "pii_username", "Benutzername: Nicolas Lebrun", "a person's name, not an account"),
    n("USERNAME", "de", "pii_username", "Prozess gestartet mit user=root", "generic system account"),
    n("USERNAME", "de", "pii_username", "Skript läuft mit user=${USER}", "template variable", carrier="prose"),
    n("USERNAME", "de", "pii_username", "superuser=1", "`user` inside another key", carrier="kv", mode="balanced"),
    p("USERNAME", "en", "pii_username", "08:20:52 WARN auth failed user=", "perez49", " status=401"),
    p("USERNAME", "en", "pii_username", "Full name | Grace Taylor\nUsername | ", "grace.taylor", "\nCity | Leeds", carrier="table"),
    p("USERNAME", "en", "pii_username", "Name | Oliver Hughes\nLogin | ", "ohughes", "", carrier="table", mode="balanced"),
    p("USERNAME", "en", "pii_username", "GET /reset?user=", "isla.clarke", "&lang=en HTTP/1.1"),
    p("USERNAME", "en", "pii_username", "Username: ", "JSmith", " Password: hidden"),
    n("USERNAME", "en", "pii_username", "Troubleshoot the login issues for her accounts.", "no assignment: `is` starts a word", carrier="prose"),
    n("USERNAME", "en", "pii_username", "Account Name: John Doe", "account holder's name, not an account"),
    n("USERNAME", "en", "pii_username", "Account Name: ACME Inc.", "company name, not an account"),
    n("USERNAME", "en", "pii_username", "Run the job with user=root", "generic system account", carrier="prose"),
    n("USERNAME", "en", "pii_username", "The sender's username is provided in tag 50.", "UI word, not an account", carrier="prose", mode="balanced"),
    # ── dates of birth, numeric ───────────────────────────────────────────
    p("DOB", "de", "pii_date_of_birth", "Patientin: Anna Schulz, geb. ", "03.01.1980", "", carrier="prose"),
    p("DOB", "de", "pii_date_of_birth", "Geburtsdatum: ", "1972-07-29"),
    p("DOB", "de", "pii_date_of_birth", "Name, Vorname | Fuß, Lukas\nGeburtsdatum | ", "20.10.1948", "\nOrt | Bonn", carrier="table"),
    p("DOB", "de", "pii_date_of_birth", "Geburtsdatum: ", "01/01/1980"),
    p("DOB", "de", "pii_date_of_birth", '{"geburtsdatum": "', "1985-06-12", '"}', carrier="json", mode="balanced"),
    n("DOB", "de", "pii_date_of_birth", "Anna Schulz, geb. Müller", "maiden name, no date", carrier="prose"),
    n("DOB", "de", "pii_date_of_birth", "Geburtsdatum: 1985-02-30", "impossible date"),
    n("DOB", "de", "pii_date_of_birth", "Geburtsdatum: 2024-13-01", "impossible month"),
    n("DOB", "de", "pii_date_of_birth", "Lieferdatum: 1985-06-12", "date under another field"),
    n("DOB", "de", "pii_date_of_birth", "geb. 32.01.1980", "impossible day", mode="balanced"),
    p("DOB", "en", "pii_date_of_birth", "Patient: Sophia Davies, DOB ", "1980-11-26"),
    p("DOB", "en", "pii_date_of_birth", "Aloisia Karz, date of birth: ", "1926-01-20", ", joined in 1995.", carrier="prose"),
    p("DOB", "en", "pii_date_of_birth", "Annette Henck-Bruder, who was born on ", "2014-12-09", ".", carrier="prose"),
    p("DOB", "en", "pii_date_of_birth", "Gianluigi Sagese, with a date of birth of ", "2005-04-24", ", residing here.", carrier="prose"),
    p("DOB", "en", "pii_date_of_birth", "<address>DateOfBirth=", "1951-09-12", "</address>", carrier="xml"),
    p("DOB", "en", "pii_date_of_birth", "We will not share the date of birth (e.g., ", "2003-06-14", ").", carrier="prose", mode="balanced"),
    n("DOB", "en", "pii_date_of_birth", "Date of birth: 1985-02-30", "impossible date"),
    n("DOB", "en", "pii_date_of_birth", "Date of birth: 1985-13-01", "impossible month"),
    n("DOB", "en", "pii_date_of_birth", "Shipped on 2014-12-09.", "date without a birth field", carrier="prose"),
    n("DOB", "en", "pii_date_of_birth", "Born on time, the release shipped on 2014-12-09.", "`born on` without a date", carrier="prose"),
    n("DOB", "en", "pii_date_of_birth", "DOB: 0000-00-00", "zero date", mode="balanced"),
    p("DOB", "fr", "pii_date_of_birth", "Date de naissance : ", "01/01/1980"),
    # ── dates of birth, written ───────────────────────────────────────────
    p("DOB", "de", "pii_date_of_birth_written_day_first", "Name, Vorname | Harrison, Olivia\nGeburtsdatum | ", "21. Februar 1971", "", carrier="table"),
    p("DOB", "de", "pii_date_of_birth_written_day_first", "Patient: Felix Schäfer, geb. ", "18. September 1974", "", carrier="prose"),
    p("DOB", "de", "pii_date_of_birth_written_day_first", "Patientin: Zofia Kowalski, geb. ", "8. Januar 1992", "", carrier="prose", mode="balanced"),
    p("DOB", "de", "pii_date_of_birth_written_day_first", "Geburtsdatum (z. B. ", "14. Juli 1980", ")", carrier="prose"),
    p("DOB", "de", "pii_date_of_birth_written_day_first", "Sie ist geboren am ", "16. April 1975", ".", carrier="prose"),
    n("DOB", "de", "pii_date_of_birth_written_day_first", "Geburtsdatum: 31. April 1990", "impossible date"),
    n("DOB", "de", "pii_date_of_birth_written_day_first", "geb. 30. Februar 1971", "impossible date"),
    n("DOB", "de", "pii_date_of_birth_written_day_first", "Geliefert am 18. September 1974.", "date without a birth field", carrier="prose"),
    n("DOB", "de", "pii_date_of_birth_written_day_first", "Geburtsdatum | 21. Februar 1971", "one line is no form", carrier="table"),
    n("DOB", "de", "pii_date_of_birth_written_day_first", "Geburtsdatum: 14. Smarch 1985", "no month name", mode="balanced"),
    p("DOB", "en", "pii_date_of_birth_written_day_first", "Date of Birth: ", "18th December 1983"),
    p("DOB", "en", "pii_date_of_birth_written_day_first", "Full name | Elena Pérez\nDOB | ", "21 March 1979", "", carrier="table"),
    p("DOB", "en", "pii_date_of_birth_written_day_first", "She was born on ", "4th July 1976", ".", carrier="prose"),
    p("DOB", "en", "pii_date_of_birth_written_day_first", "Date of birth: ", "2nd May 1990", "", mode="balanced"),
    p("DOB", "en", "pii_date_of_birth_written_day_first", "Patient: Harry Wright, DOB ", "27 June 1970", "", carrier="prose"),
    n("DOB", "en", "pii_date_of_birth_written_day_first", "Date of Birth: 31st February 1990", "impossible date"),
    n("DOB", "en", "pii_date_of_birth_written_day_first", "Delivered 18th December 1983.", "date without a birth field", carrier="prose"),
    n("DOB", "en", "pii_date_of_birth_written_day_first", "Date of birth: 31 September 1990", "impossible date"),
    n("DOB", "en", "pii_date_of_birth_written_day_first", "DOB | 21 March 1979", "one line is no form", carrier="table"),
    n("DOB", "en", "pii_date_of_birth_written_day_first", "Born on 4th July, the project shipped.", "no year", carrier="prose", mode="balanced"),
    p("DOB", "es", "pii_date_of_birth_written_day_first", "con fecha de nacimiento del ", "26 de marzo de 1990", " y domicilio", carrier="prose"),
    p("DOB", "es", "pii_date_of_birth_written_day_first", "Fecha de nacimiento: ", "15 de mayo de 1998"),
    p("DOB", "fr", "pii_date_of_birth_written_day_first", "Né le ", "1er mars 1990", " à Lyon", carrier="prose"),
    p("DOB", "it", "pii_date_of_birth_written_day_first", "Data di nascita: ", "9 novembre 1973"),
    p("DOB", "nl", "pii_date_of_birth_written_day_first", "Geboortedatum: ", "15 december 1992"),
    n("DOB", "es", "pii_date_of_birth_written_day_first", "Fecha de nacimiento: 31 de abril de 1990", "impossible date"),
    # ── employee IDs ──────────────────────────────────────────────────────
    p("EMPLOYEE_ID", "de", "pii_employee_id", "Personalnummer: ", "PN 201033"),
    p("EMPLOYEE_ID", "de", "pii_employee_id", "Als Mitarbeiternummer ist ", "E76592", " hinterlegt.", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id", "Ich bestätige folgende Angabe (Personalnummer): ", "E11397", ".", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id", '{"personalnummer": "', "PN 325128", '"}', carrier="json"),
    p("EMPLOYEE_ID", "de", "pii_employee_id", "Name | Weber, Jonas\nPersonalnummer | ", "E-40512", "", carrier="table", mode="balanced"),
    n("EMPLOYEE_ID", "de", "pii_employee_id", "Personalnummer: ab 2025", "no identifier, a date phrase"),
    n("EMPLOYEE_ID", "de", "pii_employee_id", "Personalnummer: PN", "prefix without digits"),
    n("EMPLOYEE_ID", "de", "pii_employee_id", "Die Mitarbeiternummer ist unbekannt.", "field without a value", carrier="prose"),
    n("EMPLOYEE_ID", "de", "pii_employee_id", "Bestellnummer: PN 201033", "wrong identifier anchor"),
    n("EMPLOYEE_ID", "de", "pii_employee_id", "Personalnummer (siehe Anlage)", "field without a value", carrier="prose", mode="balanced"),
    p("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID: ", "PN 912167"),
    p("EMPLOYEE_ID", "en", "pii_employee_id", "employee_id,name\n", "PN 062520", ",Pablo Garcia", carrier="csv"),
    p("EMPLOYEE_ID", "en", "pii_employee_id", "Full name | Grace Taylor\nEmployee ID | ", "E-77121", "", carrier="table"),
    p("EMPLOYEE_ID", "en", "pii_employee_id", "Staff number: ", "HR 204518"),
    p("EMPLOYEE_ID", "en", "pii_employee_id", "Please confirm the following (Employee ID): ", "E11397", ".", carrier="prose", mode="balanced"),
    n("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID: pending", "field without a value"),
    n("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID: PN", "prefix without digits"),
    n("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID: ab 1234", "lowercase words, no identifier"),
    n("EMPLOYEE_ID", "en", "pii_employee_id", "Order number: PN 912167", "wrong identifier anchor"),
    n("EMPLOYEE_ID", "en", "pii_employee_id", "Employee ID (see attachment)", "field without a value", carrier="prose", mode="balanced"),
    p("EMPLOYEE_ID", "fr", "pii_employee_id", "Gestionnaire : Marc D. Smith (employé ID : ", "C7335360", ")", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Mitarbeiter: Gordon Williams (", "EMP79383", ")", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Ticket von Shelia Sharp (", "EMP821659", ") ist offen.", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Gezeichnet: Marcelle Pottier (", "EMP856143", ")", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Freigabe durch ", "EMP194928", ".", carrier="prose"),
    p("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Darlehensnehmer: Margaret Hall [", "EMP164599", "]", carrier="prose", mode="balanced"),
    n("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "emp12345 im Log", "lowercase prefix", carrier="prose"),
    n("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "EMP1234 reserviert", "four digits"),
    n("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", ":28C:031025GB22EMP818721", "glued to a longer token", carrier="kv"),
    n("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "EMP12345678901 archiviert", "eleven digits"),
    n("EMPLOYEE_ID", "de", "pii_employee_id_prefixed", "Fühler TEMP12345 ausgefallen", "part of another word", carrier="prose", mode="balanced"),
    p("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Subject: Hardware Failure - Shelia S. Sharp (", "EMP821659", ")"),
    p("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Shipper's Reference: ", "EMP194928"),
    p("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Approved by ", "EMP99120", ".", carrier="prose"),
    p("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "the name (Margaret Sarah Hall) and the employee identifier (", "EMP229184", ").", carrier="prose"),
    p("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Signed: Gordon Rebecca Williams (", "EMP79383", ")", carrier="prose", mode="balanced"),
    n("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Sensor TEMP12345 offline", "part of another word", carrier="prose"),
    n("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "EMP1234 reserved", "four digits"),
    n("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "emp12345 in the log", "lowercase prefix", carrier="prose"),
    n("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "EMP12345678901 archived", "eleven digits"),
    n("EMPLOYEE_ID", "en", "pii_employee_id_prefixed", "Code XEMP123456 issued", "glued to a longer token", carrier="prose", mode="balanced"),
    # ── customer IDs ──────────────────────────────────────────────────────
    p("CUSTOMER_ID", "de", "pii_customer_id", "Wir erfassen Daten wie Ihre Kundennummer (z. B. ", "J8382610", "), Ihren Namen.", carrier="prose"),
    p("CUSTOMER_ID", "de", "pii_customer_id", "Die Kundennummer lautet ", "KD-55120", ".", carrier="prose"),
    p("CUSTOMER_ID", "de", "pii_customer_id", "Name, Vorname | Roth, Jana\nKundennummer | ", "KD-88231", "", carrier="table"),
    p("CUSTOMER_ID", "de", "pii_customer_id", "Die Kundennummer ist ", "C190661-Yu", ".", carrier="prose"),
    p("CUSTOMER_ID", "de", "pii_customer_id", "Bitte geben Sie die Kundennummer (z. B. ", "KD-99120", ") an.", carrier="prose", mode="balanced"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer (z. B. siehe Anlage)", "example without a value", carrier="prose"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "Die Kundennummer ist unbekannt.", "field without a value", carrier="prose"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "Bestellnummer (z. B. J8382610)", "wrong identifier anchor", carrier="prose"),
    n("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer lautet: ****", "masked value", tags=("obfuscated",)),
    n("CUSTOMER_ID", "de", "pii_customer_id", "Kundennummer ist 42", "value too short", mode="balanced"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "a customer with a customer ID of ", "C736-6988-309", ' ("Customer")', carrier="prose"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "This is a Delivery Confirmation for the customer with the ID ", "Im-29924", ", named Elaine.", carrier="prose"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "such as customer_id (e.g., ", "C352-3474-967", "), name", carrier="prose"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "an Execution Report for the customer with ID ", "A6262C921", " from the company.", carrier="prose"),
    p("CUSTOMER_ID", "en", "pii_customer_id", "Name | Owen Robinson\nCustomer ID | ", "Y8385737", "", carrier="table", mode="balanced"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "Enter the customer ID of the account holder.", "field without a value", carrier="prose"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "Please bring the customer with the ID card.", "field without a value", carrier="prose"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "customer_id (e.g., see the export)", "example without a value", carrier="prose"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "The order ID of A6262C921 shipped.", "wrong identifier anchor", carrier="prose"),
    n("CUSTOMER_ID", "en", "pii_customer_id", "Customer ID: none", "field without a value", mode="balanced"),
    p("CUSTOMER_ID", "fr", "pii_customer_id", "le customer_id (par exemple, ", "A7437434", ") et le nom", carrier="prose"),
]
for _row in Q_CONTACT_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# T29: the GB BBAN (four letters of the bank code, sort code, account: `ZFJR88590163492773`) has
# no check digit. `pii_bban_gb` reports it in every mode with a BBAN or account term near it or as
# its structural key, also where the field-bound account rule does not bind the value (prose such
# as `bank account number (BBAN) …`, a term after the value, keys like `bankkonto`); a value
# without such a term stays negative in every mode. Appended so existing ids stay stable.
T29_CASES = [
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Unsere Bankverbindung (BBAN) lautet ", "ZFJR88590163492773", ".", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Bankkonto des Mieters: ", "KALL90112673253892"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Die Miete geht auf ", "GJVV72375316777262", " (BBAN) der Hausverwaltung.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", '{"bankkonto": "', "RVHC19892216923275", '"}', carrier="json"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "name;bankkonto\nJonas Weber;", "YANH21973098530363", "", carrier="csv"),
    p("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Laut Vertrag ist das Bankkonto, ", "JAID26257597742110", ", zu belasten.", carrier="prose", mode="balanced"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Our bank account number, ", "SIWP73662924611856", ", reflects our growth.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "The premium is debited from the bank account number ", "SBMJ80180092602358", ".", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "We store the bank account number (BBAN) ", "SYIL09843639680686", " of the payee.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Refunds go to ", "ULHM05476453653182", " (BBAN) within five days.", carrier="prose"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", '{"bankingAccount": "', "OLYQ16400516534625", '"}', carrier="json"),
    p("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "payee,banking account\nAda Weber,", "VAEZ76028829777902", "", carrier="csv", mode="recall"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Bestellnummer: ABCD12345678901234", "order number, no account term"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Referenznummer QWER55501234567890 bitte angeben.", "reference number, no account term", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Sendungsnummer: DHLP00340434161094", "tracking number, no account term"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Fahrgestellnummer (VIN): WDBA12345678901234", "vehicle identification, no account term", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Bankkonto geprüft, Bestellnummer ABCD12345678901234", "order number nearer than the account term", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "Die Bankverbindung (BBAN) ZFJR00000000000000 ist ein Platzhalter.", "account of zeros", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "de", "pii_bban_gb", "ZFJR88590163492773", "bare value without an account term", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Order number: ABCD12345678901234", "order number, no account term"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Please quote reference number QWER55501234567890.", "reference number, no account term", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Tracking number: DHLP00340434161094", "tracking number, no account term"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "VIN: WDBA12345678901234", "vehicle identification, no account term", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Bank account verified, order number ABCD12345678901234", "order number nearer than the account term", carrier="prose", mode="balanced"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "The bank account number (BBAN) ZFJR11111111111111 is a placeholder.", "one repeated digit", carrier="prose"),
    n("FINANCIAL_ACCOUNT_NUMBER", "en", "pii_bban_gb", "Consignee: Katy Thompson CECS05573529734512", "bare value without an account term", carrier="prose", mode="recall"),
]
for _row in T29_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# T30: licence plates are format only (no check digit, no district-code list: F16 stays deferred).
# Both plate rules share one field part: the DE/EN plate field names (`Kfz-Kennzeichen`,
# `Number plate`, `licence plate`, `car reg`, `My car, registration …`) before the value or as its
# structural key (`kennzeichen`, `license_plate`, `licensePlate`), joined by `:`, `|`, a tab, `is`,
# `ist`, `as` or `on file is`. The DE value may carry a hyphen before the digits (`K-MH-2476`)
# and the `E`/`H` suffix; the UK current form (`AB51 ABC`) needs an issued age identifier
# (02–29, 51–79). A bare value without a plate term stays negative in every mode. Appended so
# existing ids stay stable.
T30_CASES = [
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", '{"kennzeichen": "', "K-MZ-2471", '"}', carrier="json"),
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", '{"fahrzeug": {"kfzKennzeichen": "', "H-J-6816E", '"}}', carrier="json"),
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen:\t", "E-L-3329", ""),
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kfz-Kennzeichen | ", "HH-M 2329H", ""),
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Ich bestätige folgende Angabe (Kennzeichen): ", "AC-F-1472", ".", carrier="prose"),
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Als Kennzeichen ist ", "BÖ-GR-3109E", " hinterlegt.", carrier="prose", mode="balanced"),
    p("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "nr;name;kennzeichen;betrag\n1;Jonas Weber;", "DD-S-4935", ";12,50 €", carrier="csv"),
    p("LICENSEPLATE", "de", "pii_vehicle_registration_uk", "Kennzeichen: ", "LW02 ULG", ""),
    p("LICENSEPLATE", "de", "pii_vehicle_registration_uk", '{"kennzeichen": "', "KS54 WLT", '"}', carrier="json", mode="balanced"),
    p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", '{"license_plate": "', "F-RF-8364H", '"}', carrier="json"),
    p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "My car, registration ", "FÜ-EJ 3282H", ", was parked outside.", carrier="prose"),
    p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Number plate: ", "FÜ-CB 3877", ""),
    p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Our records list the Number plate as ", "MA-A 1880H", ".", carrier="prose", mode="balanced"),
    p("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "row,name,license_plate,amount\n1,Ada Weber,", "HH AW 7915H", ",£12.50", carrier="csv"),
    p("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "The Vehicle registration on file is ", "LW02 ULG", ".", carrier="prose"),
    p("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "My car, registration ", "YB68 TXN", ", was parked outside.", carrier="prose"),
    p("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "My car reg is ", "AB51 ABD", " and it expires in May.", carrier="prose"),
    p("LICENSEPLATE", "en", "pii_vehicle_registration_uk", '{"licensePlate": "', "KS54 WLT", '"}', carrier="json"),
    p("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "Number plate | ", "BD62XYZ", "", mode="balanced"),
    n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "K-MZ-2471", "bare value without a plate term", mode="balanced"),
    n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Bestellnummer: AB-CD-1234", "order number, no plate term"),
    n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Das Kennzeichen ist am 12. Mai abgelaufen.", "words after the field name, no plate", carrier="prose", mode="balanced"),
    n("LICENSEPLATE", "de", "pii_kfz_kennzeichen_de", "Kennzeichen: K-MZ-24710", "five digits"),
    n("LICENSEPLATE", "de", "pii_vehicle_registration_uk", "Kennzeichen: AB00 ABC", "age identifier 00 is never issued"),
    n("LICENSEPLATE", "de", "pii_vehicle_registration_uk", "Bestellnummer: AB51 ABC", "order number, no plate term", mode="balanced"),
    n("LICENSEPLATE", "de", "pii_vehicle_registration_uk", "AB51 ABC", "bare value without a plate term", mode="recall"),
    n("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "AB51 ABC", "bare value without a plate term", mode="balanced"),
    n("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "Order number: AB51 ABC", "order number, no plate term"),
    n("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "Vehicle registration: AB80 ABC", "age identifier 80 is not issued yet", mode="balanced"),
    n("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "Number plate: IB51 ABC", "I is no area letter"),
    n("LICENSEPLATE", "en", "pii_vehicle_registration_uk", "Licence plate: AB51 ABCD", "four random letters"),
    n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "Order number: K-MZ-2471", "order number, no plate term", mode="balanced"),
    n("LICENSEPLATE", "en", "pii_kfz_kennzeichen_de", "My car registration is overdue.", "plate term without a value", carrier="prose"),
]
for _row in T30_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-LUHN (T13, T09): Swedish organisationsnummer (third digit >= 2, Luhn), Canadian SIN (Luhn,
# first digit not 0 or 8), Turkish T.C. Kimlik No (two check digits) and South African ID number
# (birth date, citizenship 0-2, 8 or 9, Luhn), one label each. `pii_*_se`/`_ca`/`_tr`/`_za`
# report the value in every mode when a term of the label stands near it or is its key. In
# balanced and recall the printed forms are also reported bare (K05): the organisationsnummer
# `NNNNNN-NNNN`, the SIN in hyphenated 3-3-3 groups and the thirteen digits of a South African ID.
# Ten bare digits (organisationsnummer), nine (SIN, also in 3-3-3 groups by spaces like a SIREN or
# a BSN) and the eleven of a T.C. Kimlik No always need a term.
# SV, TR and FR rows add the national field names. Hard negatives: failed checks, impossible
# fields, values without a term, counter-context and parts of longer values. Appended so
# existing ids stay stable.
B_LUHN_CASES = [
    # ── SE organisationsnummer ─────────────────────────────────────────────
    p("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", "Organisation number: ", "556703-7485"),
    p("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", "The Swedish company number on file is ", "5560160680", ".", carrier="prose"),
    p("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", '{"org_number": "', "212000-0142", '"}', carrier="json"),
    p("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", "company,orgnr\nNordvik AB,", "728018-1590", "", carrier="csv", mode="balanced"),
    p("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se_context_free", "Supplier ", "285016-6139", " from Gothenburg", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se_context_free", "", "288091-3906", "", tags=("no_context",), mode="recall"),
    p("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "Die schwedische Organisationsnummer lautet ", "823948-2196", ".", carrier="prose"),
    p("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "Organisationsnummer: ", "5785797548"),
    p("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "| Firma | Organisationsnummer |\n|---|---|\n| Nordvik AB | ", "525194-8757", " |", carrier="table"),
    p("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "Als Organisationsnummer ist ", "862189-5559", " hinterlegt.", carrier="prose", mode="balanced"),
    p("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se_context_free", "Lieferant ", "593703-4238", " aus Göteborg", carrier="prose", tags=("no_context",), mode="balanced"),
    p("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se_context_free", "Neue Angabe: ", "252109-2813", "", tags=("no_context",), mode="recall"),
    p("SE_ORGANISATIONSNUMMER", "sv", "pii_organisationsnummer_se", "Organisationsnummer: ", "716852-5389"),
    p("SE_ORGANISATIONSNUMMER", "sv", "pii_organisationsnummer_se", "Bolagets org.nr är ", "5895004744", ".", carrier="prose"),
    p("SE_ORGANISATIONSNUMMER", "sv", "pii_organisationsnummer_se", "Företagsnummer ", "578579-7548", ""),
    n("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", "Organisation number: 556703-7486", "Luhn check digit fails"),
    n("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", "Organisation number: 551303-7480", "third digit 1 is the place of a birth month"),
    n("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se", "Reference 5560160680 was archived.", "ten bare digits without an organisationsnummer term", carrier="prose", mode="balanced"),
    n("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se_context_free", "Invoice number 285016-6139", "counter-context nearer", mode="balanced"),
    n("SE_ORGANISATIONSNUMMER", "en", "pii_organisationsnummer_se_context_free", "Part 285016-6139-2 is in stock.", "part of a longer value", carrier="prose", mode="balanced"),
    n("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "Organisationsnummer: 823948-2197", "Luhn check digit fails"),
    n("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "Organisationsnummer: 82394821961", "eleven digits"),
    n("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se", "Vorgang 5785797548 wurde abgeschlossen.", "ten bare digits without an organisationsnummer term", carrier="prose", mode="balanced"),
    n("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se_context_free", "Rechnungsnummer 593703-4238", "counter-context nearer", mode="balanced"),
    n("SE_ORGANISATIONSNUMMER", "de", "pii_organisationsnummer_se_context_free", "Teil 593703-4238-1 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("SE_ORGANISATIONSNUMMER", "sv", "pii_organisationsnummer_se", "Organisationsnummer: 716852-5388", "Luhn check digit fails"),
    n("SE_ORGANISATIONSNUMMER", "sv", "pii_organisationsnummer_se", "Ärende 7168525389 är avslutat.", "ten bare digits without an organisationsnummer term", carrier="prose"),
    # ── CA SIN ─────────────────────────────────────────────────────────────
    p("CA_SIN", "en", "pii_sin_ca", "SIN: ", "130 692 544"),
    p("CA_SIN", "en", "pii_sin_ca", "My SIN number is ", "435418165", ".", carrier="prose"),
    p("CA_SIN", "en", "pii_sin_ca", '{"sin": "', "731-530-150", '"}', carrier="json"),
    p("CA_SIN", "en", "pii_sin_ca", "name,sin\nÉmilie Tremblay,", "751676123", "", carrier="csv", mode="balanced"),
    p("CA_SIN", "en", "pii_sin_ca_context_free", "Employee ", "220-297-295", " starts on Monday.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("CA_SIN", "en", "pii_sin_ca_context_free", "", "797-528-825", "", tags=("no_context",), mode="recall"),
    p("CA_SIN", "de", "pii_sin_ca", "Die kanadische SIN lautet ", "143 483 956", ".", carrier="prose"),
    p("CA_SIN", "de", "pii_sin_ca", "Kanadische SIN-Nummer: ", "386205793"),
    p("CA_SIN", "de", "pii_sin_ca", "mitarbeiter:\n  sin: ", "786-828-285", "\n", carrier="yaml"),
    p("CA_SIN", "de", "pii_sin_ca", "Als SIN ist ", "507290229", " hinterlegt.", carrier="prose", mode="balanced"),
    p("CA_SIN", "de", "pii_sin_ca_context_free", "Antragstellerin ", "279-180-582", " wurde genehmigt.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("CA_SIN", "de", "pii_sin_ca_context_free", "Neue Angabe: ", "587-180-332", "", tags=("no_context",), mode="recall"),
    p("CA_SIN", "fr", "pii_sin_ca", "Numéro d'assurance sociale : ", "301 878 013"),
    p("CA_SIN", "fr", "pii_sin_ca", "Mon NAS est le ", "459-898-342", ".", carrier="prose"),
    p("CA_SIN", "fr", "pii_sin_ca", "NAS : ", "488783846"),
    n("CA_SIN", "en", "pii_sin_ca", "SIN: 130 692 545", "Luhn check digit fails"),
    n("CA_SIN", "en", "pii_sin_ca", "SIN: 046 454 286", "Luhn valid, but no SIN starts with 0"),
    n("CA_SIN", "en", "pii_sin_ca", "Order 435418165 shipped.", "nine bare digits without a SIN term", carrier="prose", mode="balanced"),
    n("CA_SIN", "en", "pii_sin_ca_context_free", "Invoice number 220-297-295", "counter-context nearer", mode="balanced"),
    n("CA_SIN", "en", "pii_sin_ca_context_free", "Employee 220 297 295 starts on Monday.", "3-3-3 groups by spaces without a SIN term (also a SIREN or a BSN)", carrier="prose", mode="balanced"),
    n("CA_SIN", "en", "pii_sin_ca_context_free", "Supplier DE 220 297 295, Hamburg", "the digits of a VAT ID after its country code", mode="balanced"),
    n("CA_SIN", "en", "pii_sin_ca_context_free", "Dial 1 220-297-295 now.", "part of a longer number", carrier="prose", mode="balanced"),
    n("CA_SIN", "de", "pii_sin_ca", "Kanadische SIN: 143 483 957", "Luhn check digit fails"),
    n("CA_SIN", "de", "pii_sin_ca", "Kanadische SIN: 813 069 259", "Luhn valid, but no SIN starts with 8"),
    n("CA_SIN", "de", "pii_sin_ca", "Vorgang 386205793 wurde abgeschlossen.", "nine bare digits without a SIN term", carrier="prose", mode="balanced"),
    n("CA_SIN", "de", "pii_sin_ca_context_free", "Bestellnummer 279-180-582", "counter-context nearer", mode="balanced"),
    n("CA_SIN", "de", "pii_sin_ca_context_free", "Antragstellerin 279 180 582 wurde genehmigt.", "3-3-3 groups by spaces without a SIN term (also a SIREN or a BSN)", carrier="prose", mode="balanced"),
    n("CA_SIN", "de", "pii_sin_ca_context_free", "Teil 279-180-582-1 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("CA_SIN", "fr", "pii_sin_ca", "Numéro d'assurance sociale : 301 878 014", "Luhn check digit fails"),
    n("CA_SIN", "fr", "pii_sin_ca", "Commande 459898342 expédiée.", "nine bare digits without a SIN term", carrier="prose"),
    # ── TR T.C. Kimlik No ──────────────────────────────────────────────────
    p("TR_NATIONAL_ID", "en", "pii_national_id_tr", "T.C. Kimlik No: ", "10000000146"),
    p("TR_NATIONAL_ID", "en", "pii_national_id_tr", "My Turkish ID number is ", "79059236630", ".", carrier="prose"),
    p("TR_NATIONAL_ID", "en", "pii_national_id_tr", '{"tc_kimlik": "', "96828890954", '"}', carrier="json"),
    p("TR_NATIONAL_ID", "en", "pii_national_id_tr", "name,tckn\nAyşe Yılmaz,", "41002516762", "", carrier="csv", mode="balanced"),
    p("TR_NATIONAL_ID", "en", "pii_national_id_tr", "Turkish national ID ", "90083740764", "", mode="recall"),
    p("TR_NATIONAL_ID", "en", "pii_national_id_tr", "Please register TCKN ", "28818174188", " for the contract.", carrier="prose", mode="balanced"),
    p("TR_NATIONAL_ID", "de", "pii_national_id_tr", "Türkische Identitätsnummer: ", "53337761724"),
    p("TR_NATIONAL_ID", "de", "pii_national_id_tr", "Die T.C. Kimlik No. lautet ", "50931925408", ".", carrier="prose"),
    p("TR_NATIONAL_ID", "de", "pii_national_id_tr", "| Name | TCKN |\n|---|---|\n| Ayşe Yılmaz | ", "59920707414", " |", carrier="table"),
    p("TR_NATIONAL_ID", "de", "pii_national_id_tr", '{"tr_id": "', "23748477798", '"}', carrier="json", mode="balanced"),
    p("TR_NATIONAL_ID", "de", "pii_national_id_tr", "Als türkische Identitätsnummer ist ", "28341704784", " hinterlegt.", carrier="prose", mode="balanced"),
    p("TR_NATIONAL_ID", "tr", "pii_national_id_tr", "T.C. Kimlik Numarası: ", "28746331936"),
    p("TR_NATIONAL_ID", "tr", "pii_national_id_tr", "Başvuru sahibinin TCKN numarası ", "22845298404", " olarak tescil edilmiştir.", carrier="prose"),
    p("TR_NATIONAL_ID", "tr", "pii_national_id_tr", "Kimlik no: ", "25377602046"),
    n("TR_NATIONAL_ID", "en", "pii_national_id_tr", "T.C. Kimlik No: 10000000147", "second check digit fails"),
    n("TR_NATIONAL_ID", "en", "pii_national_id_tr", "T.C. Kimlik No: 02531814694", "leading zero"),
    n("TR_NATIONAL_ID", "en", "pii_national_id_tr", "T.C. Kimlik No: 11111111110", "checks valid, but one repeated digit is never issued"),
    n("TR_NATIONAL_ID", "en", "pii_national_id_tr", "Reference 79059236630 was archived.", "eleven bare digits without a T.C. Kimlik term", carrier="prose", mode="balanced"),
    n("TR_NATIONAL_ID", "en", "pii_national_id_tr", "TCKN letter, invoice number 96828890954", "invoice number nearer than the TCKN term", mode="balanced"),
    n("TR_NATIONAL_ID", "de", "pii_national_id_tr", "Türkische Identitätsnummer: 53337761725", "second check digit fails"),
    n("TR_NATIONAL_ID", "de", "pii_national_id_tr", "Türkische Identitätsnummer: 5333776172", "ten digits"),
    n("TR_NATIONAL_ID", "de", "pii_national_id_tr", "Vorgang 50931925408 wurde abgeschlossen.", "eleven bare digits without a T.C. Kimlik term", carrier="prose", mode="balanced"),
    n("TR_NATIONAL_ID", "de", "pii_national_id_tr", "TCKN-Schreiben, Bestellnummer 59920707414", "order number nearer than the TCKN term", mode="balanced"),
    n("TR_NATIONAL_ID", "de", "pii_national_id_tr", "TCKN: 23748477798-1", "part of a longer value"),
    n("TR_NATIONAL_ID", "tr", "pii_national_id_tr", "T.C. Kimlik Numarası: 28746331937", "second check digit fails"),
    n("TR_NATIONAL_ID", "tr", "pii_national_id_tr", "Sipariş 22845298404 kargoya verildi.", "eleven bare digits without a T.C. Kimlik term", carrier="prose"),
    # ── ZA ID number ───────────────────────────────────────────────────────
    p("ZA_ID_NUMBER", "en", "pii_id_number_za", "South African ID number: ", "8001015009087"),
    p("ZA_ID_NUMBER", "en", "pii_id_number_za", "My South African ID is ", "9202201234088", ".", carrier="prose"),
    p("ZA_ID_NUMBER", "en", "pii_id_number_za", '{"za_id": "', "7809193140180", '"}', carrier="json"),
    p("ZA_ID_NUMBER", "en", "pii_id_number_za", "name,sa_id\nThabo Nkosi,", "7304269847082", "", carrier="csv", mode="balanced"),
    p("ZA_ID_NUMBER", "en", "pii_id_number_za", "RSA ID: ", "921221 5036 080"),
    p("ZA_ID_NUMBER", "en", "pii_id_number_za_context_free", "Applicant ", "8011273970185", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("ZA_ID_NUMBER", "en", "pii_id_number_za_context_free", "", "0704184047089", "", tags=("no_context",), mode="recall"),
    p("ZA_ID_NUMBER", "de", "pii_id_number_za", "Südafrikanische ID-Nummer: ", "7204226952183"),
    p("ZA_ID_NUMBER", "de", "pii_id_number_za", "Die südafrikanische Identitätsnummer lautet ", "6908025538180", ".", carrier="prose"),
    p("ZA_ID_NUMBER", "de", "pii_id_number_za", "| Name | SA ID |\n|---|---|\n| Thabo Nkosi | ", "8611133245080", " |", carrier="table"),
    p("ZA_ID_NUMBER", "de", "pii_id_number_za", "Als südafrikanische ID-Nummer ist ", "7712288271086", " hinterlegt.", carrier="prose", mode="balanced"),
    p("ZA_ID_NUMBER", "de", "pii_id_number_za_context_free", "Antragsteller ", "6608075107080", " wurde genehmigt.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("ZA_ID_NUMBER", "de", "pii_id_number_za_context_free", "Neue Angabe: ", "6908084342185", "", tags=("no_context",), mode="recall"),
    n("ZA_ID_NUMBER", "en", "pii_id_number_za", "South African ID number: 8001015000076", "Luhn check digit fails"),
    n("ZA_ID_NUMBER", "en", "pii_id_number_za", "South African ID number: 8001015009384", "Luhn valid, but citizenship digit 3 does not exist"),
    n("ZA_ID_NUMBER", "en", "pii_id_number_za", "South African ID number: 8013015009082", "Luhn valid, but month 13 is no birth month"),
    n("ZA_ID_NUMBER", "en", "pii_id_number_za_context_free", "Order number 8011273970185", "counter-context nearer", mode="balanced"),
    n("ZA_ID_NUMBER", "en", "pii_id_number_za", "SA ID 80010150090870", "fourteen digits"),
    n("ZA_ID_NUMBER", "de", "pii_id_number_za", "Südafrikanische ID-Nummer: 7204226952184", "Luhn check digit fails"),
    n("ZA_ID_NUMBER", "de", "pii_id_number_za", "Südafrikanische ID-Nummer: 7204226952175", "Luhn valid, but the twelfth digit must be 8 or 9"),
    n("ZA_ID_NUMBER", "de", "pii_id_number_za_context_free", "Bestellnummer 6608075107080", "counter-context nearer", mode="balanced"),
    n("ZA_ID_NUMBER", "de", "pii_id_number_za_context_free", "Teil 6908084342185-2 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("ZA_ID_NUMBER", "de", "pii_id_number_za", "Südafrikanische ID-Nummer: AB8001015009087CD", "inside a code with letters"),
]
for _row in B_LUHN_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-EU2 (B06, B07, B14): Austrian social security number (weighted mod 11), Swiss AHV number
# (756 and EAN-13), Portuguese NIF (the mod-11 check of the PT VAT ID, a label of its own) and
# Irish PPS number (the check letter of the IE VAT number), one label each. `pii_*_at`/`_ch`/
# `_pt`/`_ie` report the value in every mode when a term of the label stands near it or is its
# key. In balanced and recall the printed forms are also reported bare (K05): the Austrian
# `NNNN DDMMYY` with a calendar date and the Swiss `756.NNNN.NNNN.NN`. Ten bare digits, thirteen
# bare digits (an EAN-13), the nine of a NIF and seven digits with a letter (PPSN) always need a
# term. FR rows add the Swiss and PT rows the Portuguese field names. Hard negatives: failed
# checks, values without a term, counter-context, the digits of a PT VAT ID and parts of longer
# values. Appended so existing ids stay stable.
B_EU2_CASES = [
    # ── AT social security number ──────────────────────────────────────────
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "Sozialversicherungsnummer: ", "1237 010180"),
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "Die österreichische Versicherungsnummer lautet ", "4523080773", ".", carrier="prose"),
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", '{"svnr": "', "7273140596", '"}', carrier="json"),
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "| Name | SV-Nummer |\n|---|---|\n| Anna Huber | ", "9811 190881", " |", carrier="table"),
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "name,vsnr\nAnna Huber,", "4950260883", "", carrier="csv", mode="balanced"),
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at_context_free", "Patientin ", "6000 070495", " wurde aufgenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at_context_free", "Neue Angabe: ", "7491 120462", "", tags=("no_context",), mode="recall"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "Austrian social security number: ", "4106 251295"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "My Austrian social insurance number is ", "6522240797", ".", carrier="prose"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", '{"svnr": "', "9710020680", '"}', carrier="json"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "employee:\n  svnr: ", "7488 280270", "\n", carrier="yaml"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "The Austrian social security number on file is ", "7071070681", ".", carrier="prose", mode="balanced"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at_context_free", "Patient ", "8226 080759", " was admitted.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at_context_free", "", "4523 080773", "", tags=("no_context",), mode="recall"),
    n("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "Sozialversicherungsnummer: 4520 080773", "check digit fails"),
    n("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "Sozialversicherungsnummer: 1240 010180", "remainder 10 is never issued"),
    n("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at", "Vorgang 7273140596 wurde abgeschlossen.", "ten bare digits without a social security term", carrier="prose", mode="balanced"),
    n("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at_context_free", "Bestellnummer 6000 070495", "counter-context nearer", mode="balanced"),
    n("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at_context_free", "Teil 6000 070495-2 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("AT_SOCIAL_SECURITY_NUMBER", "de", "pii_social_security_number_at_context_free", "Vorgang 6788 320946 wurde abgeschlossen.", "day 32 is no calendar day without a term", carrier="prose", mode="balanced"),
    n("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "Austrian social security number: 7270 140596", "check digit fails"),
    n("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "Austrian social security number: 45230807731", "eleven digits"),
    n("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at", "Reference 9710020680 was archived.", "ten bare digits without a social security term", carrier="prose", mode="balanced"),
    n("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at_context_free", "Invoice number 8226 080759", "counter-context nearer", mode="balanced"),
    n("AT_SOCIAL_SECURITY_NUMBER", "en", "pii_social_security_number_at_context_free", "Part 8226 080759-1 is in stock.", "part of a longer value", carrier="prose", mode="balanced"),
    # ── CH AHV number ──────────────────────────────────────────────────────
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "AHV-Nummer: ", "756.1221.2706.25"),
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "Die AHV-Nr. der Mitarbeiterin lautet ", "7567969558506", ".", carrier="prose"),
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", '{"ahv": "', "756 2502 4600 94", '"}', carrier="json"),
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "| Name | Sozialversicherungsnummer |\n|---|---|\n| Lea Meier | ", "756.6869.3403.10", " |", carrier="table"),
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "name,ahv\nLea Meier,", "7567846513666", "", carrier="csv", mode="balanced"),
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch_context_free", "Mitarbeiterin ", "756.7362.9355.60", " beginnt am Montag.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("CH_AHV_NUMBER", "de", "pii_ahv_number_ch_context_free", "Neue Angabe: ", "756.7363.2073.69", "", tags=("no_context",), mode="recall"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "AHV number: ", "756.1970.4597.08"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "Her Swiss social security number is ", "7561453135853", ".", carrier="prose"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", '{"ahv_number": "', "756.3692.2461.16", '"}', carrier="json"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "employee:\n  ahvn13: ", "756 4660 4474 67", "\n", carrier="yaml"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "Please register AHV ", "7561506388854", " for the payroll.", carrier="prose", mode="balanced"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch_context_free", "Employee ", "756.9467.6038.25", " starts on Monday.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("CH_AHV_NUMBER", "en", "pii_ahv_number_ch_context_free", "", "756.8191.3878.10", "", tags=("no_context",), mode="recall"),
    p("CH_AHV_NUMBER", "fr", "pii_ahv_number_ch", "Numéro AVS : ", "756.4525.2195.12"),
    p("CH_AHV_NUMBER", "fr", "pii_ahv_number_ch", "Le numéro d'assuré de l'employée est le ", "7560296180723", ".", carrier="prose"),
    p("CH_AHV_NUMBER", "fr", "pii_ahv_number_ch", "N° AVS ", "756 1221 2706 25", ""),
    n("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "AHV-Nummer: 756.1221.2706.26", "EAN-13 check digit fails"),
    n("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "AHV-Nummer: 757.1221.2706.24", "EAN-13 valid, but not the Swiss prefix 756"),
    n("CH_AHV_NUMBER", "de", "pii_ahv_number_ch", "Artikelnummer 7567969558506 ist lieferbar.", "thirteen bare digits without an AHV term (an EAN-13)", carrier="prose", mode="balanced"),
    n("CH_AHV_NUMBER", "de", "pii_ahv_number_ch_context_free", "Bestellnummer 756.7362.9355.60", "counter-context nearer", mode="balanced"),
    n("CH_AHV_NUMBER", "de", "pii_ahv_number_ch_context_free", "Version 756.7362.9355.60.1 ist installiert.", "part of a longer value", carrier="prose", mode="balanced"),
    n("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "AHV number: 756.1970.4597.09", "EAN-13 check digit fails"),
    n("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "AHV number: 75619704597080", "fourteen digits"),
    n("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "Item 7561453135853 is in stock.", "thirteen bare digits without an AHV term (an EAN-13)", carrier="prose", mode="balanced"),
    n("CH_AHV_NUMBER", "en", "pii_ahv_number_ch", "Barcode 756 1453 1358 53 printed.", "digit groups by spaces without an AHV term", carrier="prose", mode="balanced"),
    n("CH_AHV_NUMBER", "en", "pii_ahv_number_ch_context_free", "Order number 756.9467.6038.25", "counter-context nearer", mode="balanced"),
    n("CH_AHV_NUMBER", "fr", "pii_ahv_number_ch", "Numéro AVS : 756.4525.2195.13", "EAN-13 check digit fails"),
    n("CH_AHV_NUMBER", "fr", "pii_ahv_number_ch", "Article 7560296180723 en stock.", "thirteen bare digits without an AHV term", carrier="prose"),
    # ── PT NIF ─────────────────────────────────────────────────────────────
    p("PT_NIF", "de", "pii_nif_pt", "Portugiesische Steuernummer: ", "134566513"),
    p("PT_NIF", "de", "pii_nif_pt", "Die NIF des Lieferanten lautet ", "307 709 809", ".", carrier="prose"),
    p("PT_NIF", "de", "pii_nif_pt", '{"nif": "', "243676735", '"}', carrier="json"),
    p("PT_NIF", "de", "pii_nif_pt", "| Name | NIF |\n|---|---|\n| João Silva | ", "350287317", " |", carrier="table"),
    p("PT_NIF", "de", "pii_nif_pt", "Als portugiesische Steuernummer ist ", "236589075", " hinterlegt.", carrier="prose", mode="balanced"),
    p("PT_NIF", "en", "pii_nif_pt", "NIF: ", "310664535"),
    p("PT_NIF", "en", "pii_nif_pt", "The Portuguese tax number on file is ", "107595117", ".", carrier="prose"),
    p("PT_NIF", "en", "pii_nif_pt", "name,nif\nJoão Silva,", "200576917", "", carrier="csv", mode="balanced"),
    p("PT_NIF", "en", "pii_nif_pt", "customer:\n  nif: ", "227-812-069", "\n", carrier="yaml"),
    p("PT_NIF", "en", "pii_nif_pt", "Portuguese taxpayer number ", "184785677", "", mode="recall"),
    p("PT_NIF", "pt", "pii_nif_pt", "Número de contribuinte: ", "254369995"),
    p("PT_NIF", "pt", "pii_nif_pt", "O NIF do cliente é ", "266 194 435", ".", carrier="prose"),
    p("PT_NIF", "pt", "pii_nif_pt", "Contribuinte n.º ", "501964843", ""),
    n("PT_NIF", "de", "pii_nif_pt", "Portugiesische Steuernummer: 134566514", "check digit fails"),
    n("PT_NIF", "de", "pii_nif_pt", "Portugiesische Steuernummer: 034566513", "leading zero"),
    n("PT_NIF", "de", "pii_nif_pt", "Vorgang 307709809 wurde abgeschlossen.", "nine bare digits without a NIF term", carrier="prose", mode="balanced"),
    n("PT_NIF", "de", "pii_nif_pt", "NIF-Schreiben, Bestellnummer 243676735", "order number nearer than the NIF term", mode="balanced"),
    n("PT_NIF", "de", "pii_nif_pt", "NIF: 350287317-1", "part of a longer value"),
    n("PT_NIF", "en", "pii_nif_pt", "NIF: 310664536", "check digit fails"),
    n("PT_NIF", "en", "pii_nif_pt", "NIF: 3106645351", "ten digits"),
    n("PT_NIF", "en", "pii_nif_pt", "Order 107595117 shipped.", "nine bare digits without a NIF term", carrier="prose", mode="balanced"),
    n("PT_NIF", "en", "pii_nif_pt", "NIF letter, invoice number 200576917", "invoice number nearer than the NIF term", mode="balanced"),
    n("PT_NIF", "en", "pii_nif_pt", "NIF: PT 501 964 843", "the digits of a PT VAT ID after its country code", also=(("VAT_ID_PT", "PT 501 964 843"),), mode="balanced"),
    n("PT_NIF", "pt", "pii_nif_pt", "Número de contribuinte: 254369996", "check digit fails"),
    n("PT_NIF", "pt", "pii_nif_pt", "Encomenda 266194435 enviada.", "nine bare digits without a NIF term", carrier="prose"),
    # ── IE PPSN ────────────────────────────────────────────────────────────
    p("IE_PPSN", "de", "pii_ppsn_ie", "Irische PPS-Nummer: ", "3218735P"),
    p("IE_PPSN", "de", "pii_ppsn_ie", "Die PPS-Nummer des Mitarbeiters lautet ", "6608166LA", ".", carrier="prose"),
    p("IE_PPSN", "de", "pii_ppsn_ie", '{"ppsn": "', "4794814N", '"}', carrier="json"),
    p("IE_PPSN", "de", "pii_ppsn_ie", "| Name | PPSN |\n|---|---|\n| Seán Murphy | ", "9299804DA", " |", carrier="table"),
    p("IE_PPSN", "de", "pii_ppsn_ie", "Als PPS-Nummer ist ", "0343155FA", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IE_PPSN", "en", "pii_ppsn_ie", "PPS Number: ", "8133989PB"),
    p("IE_PPSN", "en", "pii_ppsn_ie", "My PPSN is ", "6913752R", ".", carrier="prose"),
    p("IE_PPSN", "en", "pii_ppsn_ie", "name,ppsn\nSeán Murphy,", "9002189HB", "", carrier="csv", mode="balanced"),
    p("IE_PPSN", "en", "pii_ppsn_ie", "Personal Public Service Number ", "5805926N", ""),
    p("IE_PPSN", "en", "pii_ppsn_ie", "Please quote your PPS number ", "3141592SW", " on the form.", carrier="prose", mode="recall"),
    n("IE_PPSN", "de", "pii_ppsn_ie", "Irische PPS-Nummer: 3218735Q", "check letter fails"),
    n("IE_PPSN", "de", "pii_ppsn_ie", "Irische PPS-Nummer: 6608166LC", "second letter C is never issued"),
    n("IE_PPSN", "de", "pii_ppsn_ie", "Vorgang 4794814N wurde abgeschlossen.", "seven digits and a letter without a PPSN term", carrier="prose", mode="balanced"),
    n("IE_PPSN", "de", "pii_ppsn_ie", "PPSN-Schreiben, Bestellnummer 9299804DA", "order number nearer than the PPSN term", mode="balanced"),
    n("IE_PPSN", "de", "pii_ppsn_ie", "PPSN: AB0343155FA", "inside a code with letters"),
    n("IE_PPSN", "en", "pii_ppsn_ie", "PPS Number: 8133989PA", "check letter fails"),
    n("IE_PPSN", "en", "pii_ppsn_ie", "PPS Number: 69137520R", "eight digits"),
    n("IE_PPSN", "en", "pii_ppsn_ie", "Reference 6913752R was archived.", "seven digits and a letter without a PPSN term", carrier="prose", mode="balanced"),
    n("IE_PPSN", "en", "pii_ppsn_ie", "PPSN letter, order number 5805926N", "order number nearer than the PPSN term", mode="balanced"),
    n("IE_PPSN", "en", "pii_ppsn_ie", "PPS Number: 0000000W", "seven zeros are never issued"),
]
for _row in B_EU2_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-KR (A14, T12): Korean resident registration number (RRN, sex and century digit 1-4),
# foreigner registration number (FRN, 5-8), both `YYMMDD-GHHSSSC` with a birth date, a region
# code up to 95 and a check digit mod 11, and business registration number (BRN, `NNN-NN-NNNNN`,
# weighted check digit mod 10), one label each. `pii_*_kr` report the value in every mode when a
# term of the label stands near it or is its key. In balanced and recall the hyphenated forms are
# also reported bare (K05). Thirteen bare digits (RRN, FRN) and ten (BRN) always need a term.
# KO rows add the Korean field names. Hard negatives: failed checks, impossible dates, the other
# registration number, values without a term, counter-context and parts of longer values.
# Appended so existing ids stay stable.
B_KR_CASES = [
    # ── KR RRN ─────────────────────────────────────────────────────────────
    p("KR_RRN", "en", "pii_rrn_kr", "Resident Registration Number: ", "660607-1248425"),
    p("KR_RRN", "en", "pii_rrn_kr", "His RRN is ", "9601211021413", ".", carrier="prose"),
    p("KR_RRN", "en", "pii_rrn_kr", '{"rrn": "', "190908-3734834", '"}', carrier="json"),
    p("KR_RRN", "en", "pii_rrn_kr", "name,rrn\nJi-woo Park,", "5705161185690", "", carrier="csv", mode="balanced"),
    p("KR_RRN", "en", "pii_rrn_kr_context_free", "Applicant ", "901117-1350297", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("KR_RRN", "en", "pii_rrn_kr_context_free", "", "810326-1648554", "", tags=("no_context",), mode="recall"),
    p("KR_RRN", "de", "pii_rrn_kr", "Die koreanische Bürgernummer lautet ", "740311-2150890", ".", carrier="prose"),
    p("KR_RRN", "de", "pii_rrn_kr", "Koreanische Resident Registration Number: ", "8505182262311"),
    p("KR_RRN", "de", "pii_rrn_kr", "| Name | RRN |\n|---|---|\n| Min-jun Kim | ", "620203-1895734", " |", carrier="table"),
    p("KR_RRN", "de", "pii_rrn_kr", "Als koreanische Registrierungsnummer ist ", "781023-1128592", " hinterlegt.", carrier="prose", mode="balanced"),
    p("KR_RRN", "de", "pii_rrn_kr_context_free", "Bewerber ", "951207-2110974", " wurde angenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("KR_RRN", "de", "pii_rrn_kr_context_free", "Neue Angabe: ", "860827-1689962", "", tags=("no_context",), mode="recall"),
    p("KR_RRN", "ko", "pii_rrn_kr", "주민등록번호: ", "560515-1449594"),
    p("KR_RRN", "ko", "pii_rrn_kr", "주민번호 ", "8301272749686", ""),
    n("KR_RRN", "en", "pii_rrn_kr", "Resident Registration Number: 660607-1248426", "check digit fails"),
    n("KR_RRN", "en", "pii_rrn_kr", "RRN: 001332-1234567", "month 13"),
    n("KR_RRN", "en", "pii_rrn_kr", "Reference 6606071248425 was archived.", "thirteen bare digits without an RRN term", carrier="prose", mode="balanced"),
    n("KR_RRN", "en", "pii_rrn_kr_context_free", "Invoice number 901117-1350297", "counter-context nearer", mode="balanced"),
    n("KR_RRN", "en", "pii_rrn_kr_context_free", "Part 901117-1350297-2 is in stock.", "part of a longer value", carrier="prose", mode="balanced"),
    n("KR_RRN", "en", "pii_rrn_kr_context_free", "960121+1021413", "plus instead of a hyphen (presidio-analyzer negative)", mode="balanced"),
    n("KR_RRN", "de", "pii_rrn_kr", "Koreanische Bürgernummer: 740311-2150891", "check digit fails"),
    n("KR_RRN", "de", "pii_rrn_kr", "Koreanische Bürgernummer: 740311-2960892", "region code above 95"),
    n("KR_RRN", "de", "pii_rrn_kr", "Vorgang 7403112150890 wurde abgeschlossen.", "thirteen bare digits without an RRN term", carrier="prose", mode="balanced"),
    n("KR_RRN", "de", "pii_rrn_kr_context_free", "Rechnungsnummer 951207-2110974", "counter-context nearer", mode="balanced"),
    n("KR_RRN", "de", "pii_rrn_kr_context_free", "Teil 951207-2110974-1 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("KR_RRN", "ko", "pii_rrn_kr", "주민등록번호: 560515-1449595", "check digit fails"),
    # ── KR FRN ─────────────────────────────────────────────────────────────
    p("KR_FRN", "en", "pii_frn_kr", "Foreigner Registration Number: ", "801221-5183058"),
    p("KR_FRN", "en", "pii_frn_kr", "Please quote FRN ", "650222-6148847", " in all letters.", carrier="prose"),
    p("KR_FRN", "en", "pii_frn_kr", '{"frn": "', "0002227652089", '"}', carrier="json"),
    p("KR_FRN", "en", "pii_frn_kr", "name,frn\nGrace Roberts,", "8302016459457", "", carrier="csv", mode="balanced"),
    p("KR_FRN", "en", "pii_frn_kr_context_free", "Applicant ", "980719-5078132", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("KR_FRN", "en", "pii_frn_kr_context_free", "", "800325-5890087", "", tags=("no_context",), mode="recall"),
    p("KR_FRN", "de", "pii_frn_kr", "Koreanische Ausländerregistrierungsnummer: ", "740804-5302677"),
    p("KR_FRN", "de", "pii_frn_kr", "Die Ausländerregistrierungsnummer lautet ", "6302065190255", ".", carrier="prose"),
    p("KR_FRN", "de", "pii_frn_kr", "| Name | FRN |\n|---|---|\n| Sanne de Vries | ", "530422-6737290", " |", carrier="table"),
    p("KR_FRN", "de", "pii_frn_kr", "Als koreanische Ausländerregistrierungsnummer ist ", "961014-6642746", " hinterlegt.", carrier="prose", mode="balanced"),
    p("KR_FRN", "de", "pii_frn_kr_context_free", "Bewerberin ", "880216-6375537", " wurde angenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("KR_FRN", "de", "pii_frn_kr_context_free", "Neue Angabe: ", "670515-5026069", "", tags=("no_context",), mode="recall"),
    p("KR_FRN", "ko", "pii_frn_kr", "외국인등록번호: ", "810202-5941441"),
    p("KR_FRN", "ko", "pii_frn_kr", "외국인번호 ", "0207067853937", ""),
    n("KR_FRN", "en", "pii_frn_kr", "Foreigner Registration Number: 801221-5183059", "check digit fails"),
    n("KR_FRN", "en", "pii_frn_kr", "FRN: 760413-1212134", "a resident's sex digit (presidio-analyzer negative)"),
    n("KR_FRN", "en", "pii_frn_kr", "Reference 8012215183058 was archived.", "thirteen bare digits without an FRN term", carrier="prose", mode="balanced"),
    n("KR_FRN", "en", "pii_frn_kr_context_free", "Invoice number 980719-5078132", "counter-context nearer", mode="balanced"),
    n("KR_FRN", "en", "pii_frn_kr_context_free", "Part 980719-5078132-2 is in stock.", "part of a longer value", carrier="prose", mode="balanced"),
    n("KR_FRN", "de", "pii_frn_kr", "Koreanische Ausländerregistrierungsnummer: 740804-5302678", "check digit fails"),
    n("KR_FRN", "de", "pii_frn_kr", "Koreanische Ausländerregistrierungsnummer: 740231-5302677", "31 February"),
    n("KR_FRN", "de", "pii_frn_kr", "Vorgang 7408045302677 wurde abgeschlossen.", "thirteen bare digits without an FRN term", carrier="prose", mode="balanced"),
    n("KR_FRN", "de", "pii_frn_kr_context_free", "Rechnungsnummer 880216-6375537", "counter-context nearer", mode="balanced"),
    n("KR_FRN", "de", "pii_frn_kr_context_free", "Teil 880216-6375537-1 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("KR_FRN", "ko", "pii_frn_kr", "외국인등록번호: 810202-5941442", "check digit fails"),
    # ── KR BRN ─────────────────────────────────────────────────────────────
    p("KR_BRN", "en", "pii_brn_kr", "Business Registration Number: ", "104-82-13138"),
    p("KR_BRN", "en", "pii_brn_kr", "My BRN is ", "1048656659", ".", carrier="prose"),
    p("KR_BRN", "en", "pii_brn_kr", '{"brn": "', "534-57-86882", '"}', carrier="json"),
    p("KR_BRN", "en", "pii_brn_kr", "company,brn\nHanbit Co.,", "2503998996", "", carrier="csv", mode="balanced"),
    p("KR_BRN", "en", "pii_brn_kr_context_free", "Supplier ", "646-84-14125", " from Seoul", carrier="prose", tags=("no_context",), mode="balanced"),
    p("KR_BRN", "en", "pii_brn_kr_context_free", "", "080-91-24253", "", tags=("no_context",), mode="recall"),
    p("KR_BRN", "de", "pii_brn_kr", "Koreanische Geschäftsregistrierungsnummer: ", "089-96-14155"),
    p("KR_BRN", "de", "pii_brn_kr", "Die Geschäftsregistrierungsnummer lautet ", "7900727682", ".", carrier="prose"),
    p("KR_BRN", "de", "pii_brn_kr", "| Firma | BRN |\n|---|---|\n| Hanbit Co. | ", "160-10-62044", " |", carrier="table"),
    p("KR_BRN", "de", "pii_brn_kr", "Als koreanische Geschäftsregistrierungsnummer ist ", "942-81-10860", " hinterlegt.", carrier="prose", mode="balanced"),
    p("KR_BRN", "de", "pii_brn_kr_context_free", "Lieferant ", "812-73-89552", " aus Seoul", carrier="prose", tags=("no_context",), mode="balanced"),
    p("KR_BRN", "de", "pii_brn_kr_context_free", "Neue Angabe: ", "733-79-69686", "", tags=("no_context",), mode="recall"),
    p("KR_BRN", "ko", "pii_brn_kr", "사업자등록번호: ", "361-39-45561"),
    p("KR_BRN", "ko", "pii_brn_kr", "사업자번호 ", "3885345320", ""),
    n("KR_BRN", "en", "pii_brn_kr", "Business Registration Number: 104-82-13139", "check digit fails"),
    n("KR_BRN", "en", "pii_brn_kr", "BRN: 110-81-4127A", "letter in place of a digit (presidio-analyzer negative)"),
    n("KR_BRN", "en", "pii_brn_kr", "Reference 1048656659 was archived.", "ten bare digits without a BRN term", carrier="prose", mode="balanced"),
    n("KR_BRN", "en", "pii_brn_kr_context_free", "Invoice number 646-84-14125", "counter-context nearer", mode="balanced"),
    n("KR_BRN", "en", "pii_brn_kr_context_free", "Part 646-84-14125-2 is in stock.", "part of a longer value", carrier="prose", mode="balanced"),
    n("KR_BRN", "de", "pii_brn_kr", "Koreanische Geschäftsregistrierungsnummer: 089-96-14156", "check digit fails"),
    n("KR_BRN", "de", "pii_brn_kr", "Koreanische Geschäftsregistrierungsnummer: 000-00-00000", "one repeated digit"),
    n("KR_BRN", "de", "pii_brn_kr", "Vorgang 0899614155 wurde abgeschlossen.", "ten bare digits without a BRN term", carrier="prose", mode="balanced"),
    n("KR_BRN", "de", "pii_brn_kr_context_free", "Rechnungsnummer 812-73-89552", "counter-context nearer", mode="balanced"),
    n("KR_BRN", "de", "pii_brn_kr_context_free", "Teil 812-73-89552-1 ist lieferbar.", "part of a longer value", carrier="prose", mode="balanced"),
    n("KR_BRN", "ko", "pii_brn_kr", "사업자등록번호: 361-39-45562", "check digit fails"),
]
for _row in B_KR_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-ESIT (A11, A12): Spanish DNI/NIF (ES_NIF, eight digits and a control letter mod 23), NIE (ES_NIE,
# X/Y/Z, seven digits and the same control letter), Italian codice fiscale (IT_FISCAL_CODE,
# sixteen characters with omocodia and a check letter) and the bare Spanish CIF without the `ES`
# prefix (VAT_ID_ES). `pii_nif_es`, `pii_nie_es` and `pii_fiscal_code_it` report the value in every
# mode when a term of the label stands near it or is its key; in balanced and recall the bare
# uppercase values are also reported (`*_context_free`). The bare CIF needs a term or key and is
# balanced/recall only (`pii_vat_id_es_proximity`). ES and IT rows add the national field names.
# Hard negatives: failed control letters, impossible months and days, the presidio-analyzer
# negatives, values without a term in strict and parts of longer values. Appended so existing ids
# stay stable.
B_ESIT_CASES = [
    # ── ES NIF ─────────────────────────────────────────────────────────────
    p("ES_NIF", "en", "pii_nif_es", "NIF: ", "26187118P"),
    p("ES_NIF", "en", "pii_nif_es", "His Spanish tax ID is ", "13887981-Y", ".", carrier="prose"),
    p("ES_NIF", "en", "pii_nif_es", '{"dni": "', "41293901t", '"}', carrier="json"),
    p("ES_NIF", "en", "pii_nif_es", "name,nif\nLucía García,", "05583042E", "", carrier="csv", mode="balanced"),
    p("ES_NIF", "en", "pii_nif_es_context_free", "Applicant ", "90228694Q", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("ES_NIF", "en", "pii_nif_es_context_free", "", "99035597N", "", tags=("no_context",), mode="recall"),
    p("ES_NIF", "de", "pii_nif_es", "Spanische Steuernummer: ", "35539592S"),
    p("ES_NIF", "de", "pii_nif_es", "Die spanische Ausweisnummer (DNI) lautet ", "58375903-V", ".", carrier="prose"),
    p("ES_NIF", "de", "pii_nif_es", "| Name | NIF |\n|---|---|\n| Lucía García | ", "88981932S", " |", carrier="table"),
    p("ES_NIF", "de", "pii_nif_es", "Als spanische Steuernummer ist ", "20769085Q", " hinterlegt.", carrier="prose", mode="balanced"),
    p("ES_NIF", "de", "pii_nif_es_context_free", "Bewerberin ", "88435808A", " wurde angenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("ES_NIF", "de", "pii_nif_es_context_free", "Neue Angabe: ", "54782632J", "", tags=("no_context",), mode="recall"),
    p("ES_NIF", "es", "pii_nif_es", "Número de identificación fiscal: ", "55555555K"),
    p("ES_NIF", "es", "pii_nif_es", "Documento nacional de identidad ", "12345678Z", ""),
    p("ES_NIF", "es", "pii_nif_es", '{"nombre": "Lucía García", "nif": "', "90025128T", '"}', carrier="json"),
    n("ES_NIF", "en", "pii_nif_es", "NIF: 26187118Q", "control letter fails"),
    n("ES_NIF", "en", "pii_nif_es", "DNI: 12345678a", "control letter fails (presidio-analyzer negative)"),
    n("ES_NIF", "en", "pii_nif_es", "Reference 26187118P was archived.", "bare value without a NIF term in strict", carrier="prose"),
    n("ES_NIF", "en", "pii_nif_es_context_free", "Applicant 90228694q has been approved.", "lowercase bare value without a NIF term", carrier="prose", mode="balanced"),
    n("ES_NIF", "en", "pii_nif_es_context_free", "Ticket X90228694QA was closed.", "part of a longer token", carrier="prose", mode="balanced"),
    n("ES_NIF", "de", "pii_nif_es", "Spanische Steuernummer: 35539592T", "control letter fails"),
    n("ES_NIF", "de", "pii_nif_es", "DNI: 3553959S", "seven digits whose control letter fails"),
    n("ES_NIF", "de", "pii_nif_es", "Vorgang 35539592S wurde abgeschlossen.", "bare value without a NIF term in strict", carrier="prose"),
    n("ES_NIF", "de", "pii_nif_es_context_free", "Teil A88435808AB ist lieferbar.", "part of a longer token", carrier="prose", mode="balanced"),
    n("ES_NIF", "de", "pii_nif_es_context_free", "Bewerberin 88435808B wurde angenommen.", "control letter fails", carrier="prose", mode="recall"),
    n("ES_NIF", "es", "pii_nif_es", "Número de identificación fiscal: 55555555J", "control letter fails"),
    # ── ES NIE ─────────────────────────────────────────────────────────────
    p("ES_NIE", "en", "pii_nie_es", "NIE: ", "Z7904705R"),
    p("ES_NIE", "en", "pii_nie_es", "Her foreigner identity number is ", "Y-9159146-P", ".", carrier="prose"),
    p("ES_NIE", "en", "pii_nie_es", '{"nie": "', "x3952965r", '"}', carrier="json"),
    p("ES_NIE", "en", "pii_nie_es", "name,nie\nAnna Novak,", "Z2930123C", "", carrier="csv", mode="balanced"),
    p("ES_NIE", "en", "pii_nie_es_context_free", "Applicant ", "Y7120454J", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("ES_NIE", "en", "pii_nie_es_context_free", "", "Y6822343M", "", tags=("no_context",), mode="recall"),
    p("ES_NIE", "de", "pii_nie_es", "Spanische Ausländer-Identifikationsnummer: ", "Z3116796W"),
    p("ES_NIE", "de", "pii_nie_es", "Die NIE der Mieterin lautet ", "X6046833H", ".", carrier="prose"),
    p("ES_NIE", "de", "pii_nie_es", "| Name | NIE |\n|---|---|\n| Anna Novak | ", "Y0903749R", " |", carrier="table"),
    p("ES_NIE", "de", "pii_nie_es", "Als NIE ist ", "X1699369Z", " hinterlegt.", carrier="prose", mode="balanced"),
    p("ES_NIE", "de", "pii_nie_es_context_free", "Bewerberin ", "X2418332C", " wurde angenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("ES_NIE", "de", "pii_nie_es_context_free", "Neue Angabe: ", "Y4889065S", "", tags=("no_context",), mode="recall"),
    p("ES_NIE", "es", "pii_nie_es", "Número de identidad de extranjero: ", "X9613851N"),
    p("ES_NIE", "es", "pii_nie_es", "NIE ", "Y8063915Z", ""),
    p("ES_NIE", "es", "pii_nie_es", '{"nombre": "Anna Novak", "nie": "', "Z8078221M", '"}', carrier="json"),
    n("ES_NIE", "en", "pii_nie_es", "NIE: Z7904705S", "control letter fails"),
    n("ES_NIE", "en", "pii_nie_es", "NIE: Y806391Q", "six digits (presidio-analyzer negative)"),
    n("ES_NIE", "en", "pii_nie_es", "NIE: W8063915Q", "W is no NIE prefix (presidio-analyzer negative)"),
    n("ES_NIE", "en", "pii_nie_es", "Reference Z7904705R was archived.", "bare value without a NIE term in strict", carrier="prose"),
    n("ES_NIE", "en", "pii_nie_es_context_free", "Ticket AY7120454JB was closed.", "part of a longer token", carrier="prose", mode="balanced"),
    n("ES_NIE", "de", "pii_nie_es", "Spanische Ausländer-Identifikationsnummer: Z3116796X", "control letter fails"),
    n("ES_NIE", "de", "pii_nie_es", "NIE: W3116796W", "W is no NIE prefix"),
    n("ES_NIE", "de", "pii_nie_es", "Vorgang X6046833H wurde abgeschlossen.", "bare value without a NIE term in strict", carrier="prose"),
    n("ES_NIE", "de", "pii_nie_es_context_free", "Bewerberin x2418332c wurde angenommen.", "lowercase bare value without a NIE term", carrier="prose", mode="balanced"),
    n("ES_NIE", "de", "pii_nie_es_context_free", "Teil BX2418332CA ist lieferbar.", "part of a longer token", carrier="prose", mode="recall"),
    n("ES_NIE", "es", "pii_nie_es", "Número de identidad de extranjero: X9613851M", "control letter fails"),
    # ── IT codice fiscale ──────────────────────────────────────────────────
    p("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "Italian fiscal code: ", "BNCGLI80A41H501C"),
    p("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "His Italian tax code is ", "vrdlcu72e15l219u", ".", carrier="prose"),
    p("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", '{"codice_fiscale": "', "RSSMRA85T10A56NH", '"}', carrier="json"),
    p("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "name,fiscal code\nGiulia Bianchi,", "GRCLRA77P63L736M", "", carrier="csv", mode="balanced"),
    p("IT_FISCAL_CODE", "en", "pii_fiscal_code_it_context_free", "Applicant ", "FRRPLA65C52D969N", " has been approved.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("IT_FISCAL_CODE", "en", "pii_fiscal_code_it_context_free", "", "PLLNDR83B12C351T", "", tags=("no_context",), mode="recall"),
    p("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Italienische Steuernummer: ", "CLMGNN58M70G273P"),
    p("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Die Steuernummer Italien des Kunden lautet ", "BRNMRC90H22F839W", ".", carrier="prose"),
    p("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "| Name | Codice fiscale |\n|---|---|\n| Giulia Bianchi | ", "SPSNTN95L60H50MY", " |", carrier="table"),
    p("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Als italienische Steuernummer ist ", "DMCSFN69R50A944K", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IT_FISCAL_CODE", "de", "pii_fiscal_code_it_context_free", "Bewerberin ", "NRIFNC88A01D612F", " wurde angenommen.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("IT_FISCAL_CODE", "de", "pii_fiscal_code_it_context_free", "Neue Angabe: ", "MNTLSN92T45Z1Q4D", "", tags=("no_context",), mode="recall"),
    p("IT_FISCAL_CODE", "it", "pii_fiscal_code_it", "Codice fiscale: ", "RSSMRA85T10A562S"),
    p("IT_FISCAL_CODE", "it", "pii_fiscal_code_it", "C.F. ", "MRTMTT91D08F205J", ""),
    p("IT_FISCAL_CODE", "it", "pii_fiscal_code_it", '{"nome": "Giulia Bianchi", "codice_fiscale": "', "GRCLRA77P63L736M", '"}', carrier="json"),
    n("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "Italian fiscal code: BNCGLI80A41H501D", "check letter fails"),
    n("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "Fiscal code: RSSMRA85F10A562R", "F is no month letter"),
    n("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "Fiscal code: AAAAAA - 00B11C333N", "spaced dash inside the value (presidio-analyzer negative)"),
    n("IT_FISCAL_CODE", "en", "pii_fiscal_code_it", "Reference BNCGLI80A41H501C was archived.", "bare value without a fiscal code term in strict", carrier="prose"),
    n("IT_FISCAL_CODE", "en", "pii_fiscal_code_it_context_free", "Ticket XFRRPLA65C52D969N was closed.", "part of a longer token", carrier="prose", mode="balanced"),
    n("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Italienische Steuernummer: CLMGNN58M70G273Q", "check letter fails"),
    n("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Italienische Steuernummer: VRDLCU72I15L219E", "I is no month letter"),
    n("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Italienische Steuernummer: GRCLRA77P93L736P", "day 93"),
    n("IT_FISCAL_CODE", "de", "pii_fiscal_code_it", "Vorgang CLMGNN58M70G273P wurde abgeschlossen.", "bare value without a fiscal code term in strict", carrier="prose"),
    n("IT_FISCAL_CODE", "de", "pii_fiscal_code_it_context_free", "Bewerberin nrifnc88a01d612f wurde angenommen.", "lowercase bare value without a fiscal code term", carrier="prose", mode="balanced"),
    n("IT_FISCAL_CODE", "it", "pii_fiscal_code_it", "Codice fiscale: RSSMRA85T10A562T", "check letter fails"),
    # ── ES CIF without the ES prefix ───────────────────────────────────────
    p("VAT_ID_ES", "en", "pii_vat_id_es_proximity", "CIF: ", "A58818501", "", mode="balanced"),
    p("VAT_ID_ES", "en", "pii_vat_id_es_proximity", "The supplier's Spanish company tax ID is ", "Q2826000H", ".", carrier="prose", mode="recall"),
    p("VAT_ID_ES", "de", "pii_vat_id_es_proximity", "Spanischer Lieferant, CIF ", "B58378431", "", mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es_proximity", "Código de identificación fiscal: ", "A13585625", "", mode="balanced"),
    p("VAT_ID_ES", "es", "pii_vat_id_es_proximity", '{"empresa": "García SL", "cif": "', "B82123456", '"}', carrier="json", mode="balanced"),
    n("VAT_ID_ES", "en", "pii_vat_id_es_proximity", "CIF: A58818502", "CIF control digit fails", mode="balanced"),
    n("VAT_ID_ES", "en", "pii_vat_id_es_proximity", "Reference A58818501 was archived.", "bare CIF without a term", carrier="prose", mode="recall"),
    n("VAT_ID_ES", "de", "pii_vat_id_es_proximity", "CIF: I58378431", "no CIF starts with I", mode="balanced"),
]
for _row in B_ESIT_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# A13: Polish PESEL (PL_PESEL, eleven digits with the birth date, the century in the month and a
# weighted check digit 1-3-7-9 mod 10), REGON (PL_REGON, nine digits weighted mod 11 or fourteen
# whose first nine are a REGON of their own) and the bare NIP without the `PL` prefix (VAT_ID_PL,
# the B16 validator). `pii_pesel_pl` and `pii_regon_pl` report the value in every mode when a term
# of the label stands near it or is its key; bare digits always need the term. The bare NIP needs
# a NIP term or key (a generic VAT term is not enough) and is balanced/recall only (`pii_vat_id_pl_proximity`). PL rows add
# the Polish field names. Hard negatives: failed check digits, impossible dates, a fourteen-digit
# REGON with a wrong first nine, values without a term and parts of longer values. Appended so
# existing ids stay stable.
A13_CASES = [
    # ── PL PESEL ───────────────────────────────────────────────────────────
    p("PL_PESEL", "en", "pii_pesel_pl", "PESEL: ", "02070803628"),
    p("PL_PESEL", "en", "pii_pesel_pl", "Her PESEL number is ", "90110536890", ".", carrier="prose"),
    p("PL_PESEL", "en", "pii_pesel_pl", '{"pesel": "', "88030387058", '"}', carrier="json"),
    p("PL_PESEL", "en", "pii_pesel_pl", "name,pesel\nAnna Nowak,", "72052773904", "", carrier="csv", mode="balanced"),
    p("PL_PESEL", "en", "pii_pesel_pl", "Polish national identification number: ", "05241690065", mode="recall"),
    p("PL_PESEL", "de", "pii_pesel_pl", "PESEL-Nummer: ", "50052724038"),
    p("PL_PESEL", "de", "pii_pesel_pl", "Die polnische Personenkennzahl lautet ", "01252230429", ".", carrier="prose"),
    p("PL_PESEL", "de", "pii_pesel_pl", "| Name | PESEL |\n|---|---|\n| Jan Kowalski | ", "88082272643", " |", carrier="table"),
    p("PL_PESEL", "de", "pii_pesel_pl", "Als PESEL ist ", "90100831864", " hinterlegt.", carrier="prose", mode="balanced"),
    p("PL_PESEL", "de", "pii_pesel_pl", "Polnische Identifikationsnummer: ", "05310456684", mode="recall"),
    p("PL_PESEL", "pl", "pii_pesel_pl", "Numer PESEL: ", "88050729397"),
    p("PL_PESEL", "pl", "pii_pesel_pl", "PESEL ", "90030370310", ""),
    n("PL_PESEL", "en", "pii_pesel_pl", "PESEL: 02070803629", "check digit fails"),
    n("PL_PESEL", "en", "pii_pesel_pl", "PESEL: 02130803627", "month 13"),
    n("PL_PESEL", "en", "pii_pesel_pl", "Reference 02070803628 was archived.", "eleven bare digits without a PESEL term", carrier="prose", mode="balanced"),
    n("PL_PESEL", "en", "pii_pesel_pl", "PESEL: 02070803628-1", "part of a longer value", mode="balanced"),
    n("PL_PESEL", "en", "pii_pesel_pl", "90110536890", "eleven bare digits", mode="recall"),
    n("PL_PESEL", "de", "pii_pesel_pl", "PESEL-Nummer: 50052724039", "check digit fails"),
    n("PL_PESEL", "de", "pii_pesel_pl", "PESEL-Nummer: 50023004039", "30 February"),
    n("PL_PESEL", "de", "pii_pesel_pl", "Vorgang 50052724038 wurde abgeschlossen.", "eleven bare digits without a PESEL term", carrier="prose", mode="balanced"),
    n("PL_PESEL", "de", "pii_pesel_pl", "PESEL-Nummer: 50052724038-1", "part of a longer value", mode="balanced"),
    n("PL_PESEL", "de", "pii_pesel_pl", "Neue Angabe: 01252230429", "eleven bare digits", mode="recall"),
    n("PL_PESEL", "pl", "pii_pesel_pl", "Numer PESEL: 88050729398", "check digit fails"),
    # ── PL REGON ───────────────────────────────────────────────────────────
    p("PL_REGON", "en", "pii_regon_pl", "REGON: ", "123456785"),
    p("PL_REGON", "en", "pii_regon_pl", "The company's REGON number is ", "732065814", ".", carrier="prose"),
    p("PL_REGON", "en", "pii_regon_pl", '{"regon": "', "12345678512347", '"}', carrier="json"),
    p("PL_REGON", "en", "pii_regon_pl", "company,regon\nPolmex Sp. z o.o.,", "926240204", "", carrier="csv", mode="balanced"),
    p("PL_REGON", "en", "pii_regon_pl", "Polish statistical number: ", "95217292048588", mode="recall"),
    p("PL_REGON", "de", "pii_regon_pl", "REGON-Nummer: ", "797289256"),
    p("PL_REGON", "de", "pii_regon_pl", "Die REGON des Lieferanten lautet ", "14394440582149", ".", carrier="prose"),
    p("PL_REGON", "de", "pii_regon_pl", "| Firma | REGON |\n|---|---|\n| Polmex | ", "144609442", " |", carrier="table"),
    p("PL_REGON", "de", "pii_regon_pl", "Als REGON ist ", "536764277", " hinterlegt.", carrier="prose", mode="balanced"),
    p("PL_REGON", "de", "pii_regon_pl", "Polnische Statistiknummer: ", "30774240023989", mode="recall"),
    p("PL_REGON", "pl", "pii_regon_pl", "Numer REGON: ", "215521652"),
    p("PL_REGON", "pl", "pii_regon_pl", "REGON ", "43446023435254", ""),
    n("PL_REGON", "en", "pii_regon_pl", "REGON: 123456786", "check digit fails"),
    n("PL_REGON", "en", "pii_regon_pl", "REGON: 12345678612342", "fourteen digits whose first nine fail"),
    n("PL_REGON", "en", "pii_regon_pl", "Reference 732065814 was archived.", "nine bare digits without a REGON term", carrier="prose", mode="balanced"),
    n("PL_REGON", "en", "pii_regon_pl", "REGON: 000000000", "one repeated digit"),
    n("PL_REGON", "en", "pii_regon_pl", "12345678512347", "fourteen bare digits", mode="recall"),
    n("PL_REGON", "de", "pii_regon_pl", "REGON-Nummer: 797289257", "check digit fails"),
    n("PL_REGON", "de", "pii_regon_pl", "REGON-Nummer: 14394440582148", "check digit of the fourteen fails"),
    n("PL_REGON", "de", "pii_regon_pl", "Vorgang 797289256 wurde abgeschlossen.", "nine bare digits without a REGON term", carrier="prose", mode="balanced"),
    n("PL_REGON", "de", "pii_regon_pl", "REGON-Nummer: 797289256-1", "part of a longer value", mode="balanced"),
    n("PL_REGON", "de", "pii_regon_pl", "Neue Angabe: 144609442", "nine bare digits", mode="recall"),
    n("PL_REGON", "pl", "pii_regon_pl", "Numer REGON: 215521653", "check digit fails"),
    # ── PL NIP (VAT_ID_PL without the prefix) ──────────────────────────────
    p("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "NIP: ", "5260250995", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "Our Polish tax identification number is ", "943-16-38-485", ".", carrier="prose", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", '{"supplier": "Polmex", "nip": "', "2143864618", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "Polish VAT number: ", "984-055-15-28", mode="recall"),
    p("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "NIP ", "3233229145", "", mode="recall"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "NIP-Nummer: ", "4106325383", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "Polnische Steuernummer (NIP): ", "497-305-06-10", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", '{"lieferant": "Polmex", "nip": "', "1343644803", '"}', carrier="json", mode="balanced"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "Die NIP des Lieferanten lautet ", "2311045017", ".", carrier="prose", mode="recall"),
    p("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "Firma;NIP\nPolmex;", "4695147471", "", carrier="csv", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "NIP: 5260250996", "check digit fails", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "Reference 5260250995 was archived.", "ten bare digits without a NIP term", carrier="prose", mode="recall"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "NIP: 5260250995-1", "part of a longer value", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "Invoice number 2143864618 is overdue.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "NIP: 9840551520", "check digit fails", mode="recall"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "NIP-Nummer: 4106325384", "check digit fails", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "Bitte 4106325383 übernehmen.", "ten bare digits without a NIP term", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "NIP-Nummer: 4106325383-1", "part of a longer value", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "Rechnungsnummer 1343644803 ist offen.", "invoice number with a valid check digit", carrier="prose", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "NIP-Nummer: 497-305-06-11", "check digit fails", mode="recall"),
    n("VAT_ID_PL", "en", "pii_vat_id_pl_proximity", "VAT number: 5260250995", "generic VAT term without a NIP term", mode="balanced"),
    n("VAT_ID_PL", "de", "pii_vat_id_pl_proximity", "USt-IdNr.: 2143864618", "generic VAT term without a NIP term", mode="balanced"),
]
for _row in A13_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-IBAN (T05, T21, F03): an IBAN needs a country of the SWIFT IBAN registry, exactly that
# country's length and MOD-97; both IBAN rules read it compact or in blocks of four, letters
# included, in upper or lower case. A grouped IBAN ends at its registry length, so a following
# word or block of four is not part of it. SEPA creditor identifiers (`DE98ZZZ09999999999`) pass
# MOD-97 by chance but have no IBAN length and stay negative in every mode.
B_IBAN_CASES = [
    p("IBAN", "en", "pii_iban_generic", "IBAN: ", "GB82 WEST 1234 5698 7654 32"),
    p("IBAN", "en", "pii_iban_generic", "Please wire the deposit to ", "nl91 abna 0417 1643 00", " by Friday.", carrier="prose", tags=("no_context",)),
    p("IBAN", "en", "pii_iban_generic", "Account: ", "mt84malt011000012345mtlcast001s"),
    p("IBAN", "en", "pii_iban_generic", "IBAN ", "BE68 5390 0754 7034", " and BIC GEBABEBB", carrier="prose", also=(("SWIFT_CODE", "GEBABEBB"),)),
    p("IBAN", "en", "pii_iban_generic", '{"iban": "', "FR14 2004 1010 0505 0001 3M02 606", '"}', carrier="json"),
    p("IBAN", "en", "pii_iban_generic", "payee:\n  iban: ", "no93 8601 1117 947", "\n", carrier="yaml", mode="balanced"),
    p("IBAN", "en", "pii_iban_de", "IBAN: ", "de89 3704 0044 0532 0130 00"),
    p("IBAN", "de", "pii_iban_generic", "IBAN (Österreich): ", "at61 1904 3002 3457 3201"),
    p("IBAN", "de", "pii_iban_generic", "Bitte überweisen Sie auf ", "CH93 0076 2011 6238 5295 7", " bis Freitag.", carrier="prose", tags=("no_context",)),
    p("IBAN", "de", "pii_iban_generic", "Konto ", "IT60 X054 2811 1010 0000 0123 456", " und Name", carrier="prose"),
    p("IBAN", "de", "pii_iban_generic", "Name;IBAN\nRossi;", "es91 2100 0418 4502 0005 1332", "", carrier="csv"),
    p("IBAN", "de", "pii_iban_de", "Kontoverbindung: ", "de02120300000000202051", mode="balanced"),
    p("IBAN", "de", "pii_iban_generic", "| Bank | IBAN |\n|---|---|\n| Erste | ", "AT61 1904 3002 3457 3201", " |", carrier="table", mode="recall"),
    n("IBAN", "en", "pii_iban_generic", "Creditor identifier: DE30ZZZ56545348553", "SEPA creditor ID passes MOD-97 but has no IBAN length"),
    n("IBAN", "en", "pii_iban_generic", "SEPA direct debit from creditor ID DE98ZZZ00001140336 on 1 Nov.", "SEPA creditor ID in prose", carrier="prose", mode="balanced"),
    n("IBAN", "en", "pii_iban_generic", "IBAN: gb82 west 1234 5698 7654 33", "lowercase IBAN whose MOD-97 fails"),
    n("IBAN", "en", "pii_iban_generic", "Account PH12 3456 7890 1234 5678 90", "country without IBAN", mode="recall"),
    n("IBAN", "en", "pii_iban_generic", "Ref GB82WEST12345698765432XYZ", "IBAN glued to more characters"),
    n("IBAN", "en", "pii_iban_generic", "IBAN: GB82 WEST 1234 5698 7654 3", "one character short of the GB length"),
    n("IBAN", "de", "pii_iban_generic", "Gläubiger-Identifikationsnummer: DE30ZZZ56545348553", "SEPA creditor ID passes MOD-97 but has no IBAN length"),
    n("IBAN", "de", "pii_iban_generic", "SEPA-Lastschrift, Gläubiger-ID DE13ZZZ00001013632, Mandatsreferenz M-2026-17", "SEPA creditor ID in prose", carrier="prose", mode="balanced"),
    n("IBAN", "de", "pii_iban_generic", "Gläubiger-ID: DE57ZZZ00001061146", "SEPA creditor ID", mode="recall"),
    n("IBAN", "de", "pii_iban_generic", "IBAN: at61 1904 3002 3457 3202", "lowercase IBAN whose MOD-97 fails"),
    n("IBAN", "de", "pii_iban_generic", "Commit de89a7f3c2b1e4d5f6a7b8c9 ist gemergt.", "hex hash with a country prefix", carrier="prose"),
    n("IBAN", "de", "pii_iban_generic", "IBAN: Gb82 West 1234 5698 7654 32", "mixed case is no printed IBAN"),
]
for _row in B_IBAN_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-PASS passport and identity card numbers by field name (T24, A05, B08, T10; baseline P6).
# `pii_passport_number_field` reports six to nine letters and digits, at least five digits,
# right after an explicit passport field name in English, German, Spanish, French, Italian or
# Dutch, in every mode. Format only: one or two letters and exactly six digits is no passport form,
# German document forms stay with the German rules, one repeated digit and
# a run of seven ascending digits are placeholders. With a document term near the value or as
# its key: the US letter form (`pii_passport_number_us`, one letter and eight digits), the
# Austrian and Swiss passport and identity card (`pii_passport_number_at_ch`,
# `pii_identity_card_number_at_ch`, one letter and seven digits), the Italian carta
# d'identità (`pii_identity_card_number_it`) and the Spanish pasaporte
# (`pii_passport_number_es`, three letters and six digits). Appended so existing ids stay stable.
B_PASS_CASES = [
    # ── Passport number after a passport field name, every mode ───────────
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport Number: ", "S17933286"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Witness: Darusman Ratulangi (Passport No. ", "SG9943897", ")", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Please send a copy of your passport (", "206237033", ") for verification.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport_number ", "621475562", ", a customer reference", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", '{"passport_number": "', "X45929398", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", "my travel passport is ", "A12803456", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_field", "passport no. ", "52918734", ""),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Reisepassnummer: ", "O0606527"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Bitte führen Sie Ihren Reisepass (", "D5832368", ") mit.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Pass-Nr.: ", "S17933286"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_field", "reisender:\n  reisepass_nr: ", "PA9172604", "\n", carrier="yaml"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Die Passnummer lautet ", "419027365", ".", carrier="prose"),
    p("PASSPORT_NUMBER", "es", "pii_passport_number_field", "Número de pasaporte: ", "X45929398"),
    p("PASSPORT_NUMBER", "es", "pii_passport_number_field", "Mi pasaporte es ", "AAA482913", carrier="prose"),
    p("PASSPORT_NUMBER", "fr", "pii_passport_number_field", "le passeport numéro ", "07RY12580", " doit être présenté.", carrier="prose"),
    p("PASSPORT_NUMBER", "fr", "pii_passport_number_field", "Numéro de passeport : ", "ZK3189109"),
    p("PASSPORT_NUMBER", "it", "pii_passport_number_field", "Avviso: presentare passaporto n. ", "M0572847", " e tessera sanitaria.", carrier="prose"),
    p("PASSPORT_NUMBER", "nl", "pii_passport_number_field", "Reisdocumentnummer: ", "140679109"),
    p("PASSPORT_NUMBER", "nl", "pii_passport_number_field", "Paspoortnummer: ", "NX4127095"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport number: A482913", "one letter and exactly six digits is no passport form"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "passport number B740261", "one letter and exactly six digits is no passport form", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "passport no. NZ137286", "two letters and exactly six digits is no passport form"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport number: 482913X7", "letters inside the digits are no passport form outside German documents"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport no. 777777777", "one repeated digit"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport no. F48291367", "German passport form whose ICAO check digit fails"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport photo 48291366 attached.", "no passport field name before the value", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_field", "Passport no. 4829", "too short"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Reisepassnummer: K482913", "one letter and exactly six digits is no passport form"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Pass-Nr.: 1234567890", "ten digits"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Pass-Nr.: G48291366", "German passport form whose ICAO check digit fails"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Reisepass: 00000000", "one repeated digit"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_field", "Kompass 4829136 eingetroffen.", "pass inside another word", carrier="prose"),
    n("PASSPORT_NUMBER", "es", "pii_passport_number_field", "Número de pasaporte: B740261", "one letter and exactly six digits is no passport form"),
    n("PASSPORT_NUMBER", "es", "pii_passport_number_field", "Pasaporte caducado desde 2031", "expiry year, not a passport number", carrier="prose"),
    # ── US passport, letter form, with a passport term ────────────────────
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "US passport ", "Z12803456", " expires in 2031.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "name,passport,nationality\nJane Doe,", "A48291036", ",American", carrier="csv"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "The applicant's passport, ", "E70412958", ", was renewed.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Passport (USA): ", "A90381274"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", '{"passport": "', "M30941826", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Der US-Reisepass ", "A48291036", " ist gültig.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisepass (USA): ", "Z90381274"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Order A48291036 has shipped.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "US passport A4829 expires in 2031.", "only four digits after the letter", carrier="prose", mode="balanced"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "US passport A48291036-2 expires.", "part of a hyphenated number", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "US passport A00000000", "one repeated digit"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "My passport is A12345678", "placeholder run of ascending digits", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Rechnung A48291036 ist offen.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisepass (USA): A4829103612", "eleven characters"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisepass (USA): C48291036", "German passport form whose ICAO check digit fails"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisepass (USA): A11111111", "one repeated digit"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Artikel A48291036 im Pass-Shop", "an article number, the term is part of a name", carrier="prose", mode="balanced"),
    # ── AT/CH passport and identity card with a document term ─────────────
    p("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Österreichischer Reisepass ", "P4366918", ", ausgestellt in Wien.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Schweizer Pass Nr. ", "X0217453"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", '{"reisepass": "', "U5093176", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Name;Reisepass;Ort\nAnna Huber;", "P8120547", ";Graz", carrier="csv"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Der Reisepass ", "S0418362", " ist abgelaufen.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Austrian passport ", "P4366918", " issued in Vienna.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Swiss passport no ", "X0217453"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "name,passport\nAnna Huber,", "P8120547", carrier="csv"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Her passport ", "S0418362", " expires next year.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", '{"passport": "', "U5093176", '"}', carrier="json"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Identitätskarte ", "E3092741", ", Kanton Bern.", carrier="prose"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Personalausweis (Österreich): ", "A7418205"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", '{"ausweisnummer": "', "E5207193", '"}', carrier="json"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Name;Ausweisnr;Ort\nAnna Huber;", "A2093716", ";Linz", carrier="csv"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Die Identitätskarte ", "C3810467", " ist gültig.", carrier="prose"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Swiss identity card ", "E3092741", " issued in Bern.", carrier="prose"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "ID card number: ", "A7418205"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", '{"id_card_number": "', "E5207193", '"}', carrier="json"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "name,id card\nAnna Huber,", "A2093716", carrier="csv"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Her identity card ", "C3810467", " is valid.", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Bestellung P4366918 ist eingegangen.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Reisepass P436691", "one letter and six digits"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Reisepass P4444444", "one repeated digit"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Reisepass P4366918-3 gesperrt", "part of a hyphenated number", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_at_ch", "Ticket X0217453 geschlossen.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Order P4366918 has shipped.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Swiss passport p4366918", "lower-case letter"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Swiss passport P5555555", "one repeated digit"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Swiss passport P4366918/2", "part of a slash number", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_at_ch", "Ticket X0217453 closed.", "no passport term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Lieferschein E3092741 liegt bei.", "no identity card term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Identitätskarte E309274", "one letter and six digits"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Identitätskarte E3333333", "one repeated digit"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Identitätskarte E3092741-7", "part of a hyphenated number"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_at_ch", "Rechnung A7418205 offen.", "no identity card term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Invoice E3092741 is due.", "no identity card term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Identity card E309274", "one letter and six digits"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Identity card E3333333", "one repeated digit"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Identity card e3092741", "lower-case letter"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_at_ch", "Build A7418205 failed.", "no identity card term", carrier="prose"),
    # ── IT carta d'identità and ES pasaporte with a document term ─────────
    p("IDENTITY_CARD_NUMBER", "it", "pii_identity_card_number_it", "Carta d'identità n. ", "CA48213EF"),
    p("IDENTITY_CARD_NUMBER", "it", "pii_identity_card_number_it", "Numero carta d'identità: ", "CD71592HL"),
    p("IDENTITY_CARD_NUMBER", "it", "pii_identity_card_number_it", "La carta di identità ", "CB90217KD", " è valida.", carrier="prose"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_it", "Italienische Identitätskarte ", "CA48213EF", carrier="prose"),
    p("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_it", "Ausweisnummer (Italien): ", "CB90217KD"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_it", "Italian identity card ", "CA48213EF", " issued in Rome.", carrier="prose"),
    p("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_it", '{"id_card_number": "', "CB90217KD", '"}', carrier="json"),
    n("IDENTITY_CARD_NUMBER", "it", "pii_identity_card_number_it", "Ordine CA48213EF spedito.", "no identity card term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "it", "pii_identity_card_number_it", "Carta d'identità CA4821EF", "only four digits"),
    n("IDENTITY_CARD_NUMBER", "it", "pii_identity_card_number_it", "Carta d'identità CA00000EF", "one repeated digit"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_it", "Artikel CA48213EF vergriffen.", "no identity card term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "de", "pii_identity_card_number_it", "Identitätskarte CA48213EF7", "glued to a digit"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_it", "Order CA48213EF has shipped.", "no identity card term", carrier="prose"),
    n("IDENTITY_CARD_NUMBER", "en", "pii_identity_card_number_it", "Identity card ca48213ef", "lower case"),
    p("PASSPORT_NUMBER", "es", "pii_passport_number_es", "El pasaporte ", "PAA482913", " caduca en 2031.", carrier="prose"),
    p("PASSPORT_NUMBER", "es", "pii_passport_number_es", "nombre,pasaporte\nLucía Pérez,", "XDA902174", carrier="csv"),
    p("PASSPORT_NUMBER", "es", "pii_passport_number_es", '{"pasaporte": "', "PAB730261", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_es", "Spanischer Reisepass ", "PAA482913", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_es", "Der Reisepass ", "XDA902174", " ist gültig.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_es", "Spanish passport ", "PAA482913", " issued in Madrid.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_es", "name,passport\nLucía Pérez,", "PAB730261", carrier="csv"),
    n("PASSPORT_NUMBER", "es", "pii_passport_number_es", "Pedido PAA482913 enviado.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "es", "pii_passport_number_es", "El pasaporte PAA000000", "one repeated digit"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_es", "Bestellung PAA482913 ist da.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_es", "Reisepass PAA4829", "only four digits"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_es", "Order PAA482913 has shipped.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_es", "Spanish passport paa482913", "lower case"),
]
for _row in B_PASS_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# Q-ID quality pass for driver's licence and passport numbers. A note in parentheses between a
# licence field name and the value (`Führerscheinnummer (falls relevant): …`) and a value in
# parentheses after the field name (`licencia de conducir (M45114072)`) keep the binding; a note
# with a digit is no note and the value keeps its state format. `travel document`,
# `Reisedokument` and the Korean `여권` are passport terms of the lexicon. Appended so existing
# ids stay stable.
Q_ID_CASES = [
    # ── Licence field name with a note or a value in parentheses ─────────
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "10. Führerscheinnummer (falls relevant): ", "3330234369", "\n11. Adresse: Gemsfairen 6"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerschein (Klasse B): ", "B6728301"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Bitte legen Sie Ihren Führerschein (", "S38387690", ") vor.", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Fahrerlaubnis-Nr. (optional): ", "D4007836"),
    p("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Die Führerscheinnummer (siehe Kopie) lautet ", "T36493663", ".", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver's license number (optional): ", "D4007836"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "a copy of your driver's licence (", "S38387690", ").", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver License No. (if any): ", "G37722093"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Her driving licence (", "M45114072", ") was scanned.", carrier="prose"),
    p("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "DL number (state of issue): ", "6940579"),
    p("DRIVER_LICENSE_NUMBER", "es", "pii_driver_license_number_us", "5. Número de licencia de conducir (opcional): ", "G37722093"),
    p("DRIVER_LICENSE_NUMBER", "es", "pii_driver_license_number_us", "Guarde la licencia de conducir (", "M45114072", ") en un bolso.", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerschein (Klasse B) gültig bis 30-04-2031", "the note is followed by an expiry date"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerscheinnummer (Anlage 3): ABCDEFG", "a note with a digit is no note, the value no state format"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Bitte den Führerschein (ND8CD4YGQ3) mitbringen.", "random letters and digits are no state format", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerschein (Abschnitt 4) 41827365", "the parentheses hold a number, not a note"),
    n("DRIVER_LICENSE_NUMBER", "de", "pii_driver_license_number_us", "Führerschein (12)", "too short"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "a valid driver's licence (ND8CD4YGQ3) is required.", "random letters and digits are no state format", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver's license (front side) scanned.", "a note without a value", carrier="prose"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver's license (section 4) 41827365", "the parentheses hold a number, not a note"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "Driver's license (expires): 2031-04-30", "a calendar date is no licence number"),
    n("DRIVER_LICENSE_NUMBER", "en", "pii_driver_license_number_us", "driver's licence (12)", "too short"),
    # ── Passport terms: travel document, Reisedokument, 여권 ─────────────
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "my travel document is ", "A12803456", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Travel document number: ", "Z12803456"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Please bring the travel document ", "B48291036", " to the gate.", carrier="prose"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", "name,travel_document\nJane Doe,", "A48291036", carrier="csv"),
    p("PASSPORT_NUMBER", "en", "pii_passport_number_us", '{"travel_document": "', "E70391842", '"}', carrier="json"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisedokument ", "A48291036", " liegt vor.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisedokument: ", "Z12803456"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Das Reisedokument ", "E70391842", " ist bis 2031 gültig.", carrier="prose"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "name,reisedokument\nJana Roth,", "A48291036", carrier="csv"),
    p("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Koreanischer Pass: 대한민국 여권 ", "S87654321", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "my travel document is A128034", "one letter and six digits"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Travel document 12345678 attached.", "eight digits without a letter", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "travel document a12803456", "lower case"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Order S87654321 shipped.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "en", "pii_passport_number_us", "Travel document A12345678", "placeholder run of eight ascending digits"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisedokument A12345678", "placeholder run of eight ascending digits"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisedokument A128034", "one letter and six digits"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Bestellung S87654321 ist da.", "no passport term", carrier="prose"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "여권 S876543", "one letter and six digits"),
    n("PASSPORT_NUMBER", "de", "pii_passport_number_us", "Reisedokument A00000000", "one repeated digit"),
]
for _row in Q_ID_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-IN: Indian identifiers. The Aadhaar number (IN_AADHAAR, twelve digits, first digit 2-9, plain
# or grouped 4-4-4 with spaces, hyphens or colons, Verhoeff check digit) and the GSTIN (IN_GSTIN,
# state code, the PAN of the holder, entity number, `Z` and a mod-36 check character) carry a real
# check; the PAN (IN_PAN, five letters with the holder type as the fourth, four digits, a letter)
# and the voter ID (IN_VOTER, EPIC: three letters and seven digits) are format and context only.
# Every label is reported in every mode when a term of the label stands near it or is its key; in
# balanced/recall the grouped Aadhaar number and the GSTIN are also reported bare (K05). Hard
# negatives: failed check digits, a leading 0 or 1, a state code outside 01-38/97/99, a fourth
# letter that is no PAN holder type, values without a term and parts of longer values.
B_IN_CASES = [
    # ── IN Aadhaar ─────────────────────────────────────────────────────────
    p("IN_AADHAAR", "en", "pii_aadhaar_in", "Aadhaar number: ", "5915 3375 9365"),
    p("IN_AADHAAR", "en", "pii_aadhaar_in", "My Aadhaar is ", "599979610811", ".", carrier="prose"),
    p("IN_AADHAAR", "en", "pii_aadhaar_in", '{"aadhaar": "', "8797-7332-6157", '"}', carrier="json"),
    p("IN_AADHAAR", "en", "pii_aadhaar_in", "name,aadhaar\nRavi Kumar,", "406928830752", "", carrier="csv", mode="balanced"),
    p("IN_AADHAAR", "en", "pii_aadhaar_in", "UIDAI Aadhaar no. ", "4041 6225 6822", mode="recall"),
    p("IN_AADHAAR", "en", "pii_aadhaar_in_context_free", "Applicant ", "5352 4277 1202", " joined in May.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("IN_AADHAAR", "en", "pii_aadhaar_in_context_free", "", "6532-0568-8226", "", tags=("no_context",), mode="recall"),
    p("IN_AADHAAR", "de", "pii_aadhaar_in", "Aadhaar-Nummer: ", "4294 5428 4060"),
    p("IN_AADHAAR", "de", "pii_aadhaar_in", "Die Aadhaar-Nummer des Antragstellers lautet ", "398288889437", ".", carrier="prose"),
    p("IN_AADHAAR", "de", "pii_aadhaar_in", "| Name | Aadhaar |\n|---|---|\n| Priya Shah | ", "8759 3369 7434", " |", carrier="table"),
    p("IN_AADHAAR", "de", "pii_aadhaar_in", "Als Aadhaar ist ", "675872747324", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IN_AADHAAR", "de", "pii_aadhaar_in", "Indische Identifikationsnummer (Aadhaar): ", "5753 5139 3956", mode="recall"),
    p("IN_AADHAAR", "de", "pii_aadhaar_in_context_free", "Bewerber ", "3090 2961 0020", " aus Pune", carrier="prose", tags=("no_context",), mode="balanced"),
    n("IN_AADHAAR", "en", "pii_aadhaar_in", "Aadhaar number: 5915 3375 9366", "check digit fails"),
    n("IN_AADHAAR", "en", "pii_aadhaar_in", "Aadhaar number: 1234 5678 9010", "leading 1 with a valid check digit"),
    n("IN_AADHAAR", "en", "pii_aadhaar_in", "Reference 599979610811 was archived.", "twelve bare digits without an Aadhaar term", carrier="prose", mode="balanced"),
    n("IN_AADHAAR", "en", "pii_aadhaar_in", "Aadhaar number: 5915 3375 9365 7", "part of a longer value", mode="balanced"),
    n("IN_AADHAAR", "en", "pii_aadhaar_in_context_free", "Applicant 5352 4277 1203 joined in May.", "grouped digits whose check digit fails", carrier="prose", mode="recall"),
    n("IN_AADHAAR", "de", "pii_aadhaar_in", "Aadhaar-Nummer: 4294 5428 4061", "check digit fails"),
    n("IN_AADHAAR", "de", "pii_aadhaar_in", "Aadhaar-Nummer: 0294 5428 4068", "leading 0 with a valid check digit"),
    n("IN_AADHAAR", "de", "pii_aadhaar_in", "Vorgang 398288889437 wurde abgeschlossen.", "twelve bare digits without an Aadhaar term", carrier="prose", mode="balanced"),
    n("IN_AADHAAR", "de", "pii_aadhaar_in", "Aadhaar-Nummer: 4294-5428-4060-1", "part of a longer value", mode="balanced"),
    n("IN_AADHAAR", "de", "pii_aadhaar_in", "Aadhaar-Nummer: 4294 54284060", "mixed grouping", mode="recall"),
    # ── IN GSTIN ───────────────────────────────────────────────────────────
    p("IN_GSTIN", "en", "pii_gstin_in", "GSTIN: ", "10BAGFF2439K3ZL"),
    p("IN_GSTIN", "en", "pii_gstin_in", "Our GST number is ", "20DWWHC5119Y4Z0", ".", carrier="prose"),
    p("IN_GSTIN", "en", "pii_gstin_in", '{"gstin": "', "06CXKCD8583B3Z4", '"}', carrier="json"),
    p("IN_GSTIN", "en", "pii_gstin_in", "supplier,gstin\nTata Traders,", "30IDYTH1820Z4Z7", "", carrier="csv", mode="balanced"),
    p("IN_GSTIN", "en", "pii_gstin_in", "GST registration: ", "17ZUXFU2907C2Z3", mode="recall"),
    p("IN_GSTIN", "en", "pii_gstin_in_context_free", "Invoice from ", "25OLGTA9304C8ZW", " is due.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("IN_GSTIN", "en", "pii_gstin_in_context_free", "", "28MHVAN9845P9Z6", "", tags=("no_context",), mode="recall"),
    p("IN_GSTIN", "de", "pii_gstin_in", "GSTIN: ", "36RWETR6874M6ZT"),
    p("IN_GSTIN", "de", "pii_gstin_in", "Die GSTIN des Lieferanten lautet ", "16KGICL5894M8ZW", ".", carrier="prose"),
    p("IN_GSTIN", "de", "pii_gstin_in", "| Firma | GSTIN |\n|---|---|\n| Mehta Exports | ", "17TTXFN2493I3ZV", " |", carrier="table"),
    p("IN_GSTIN", "de", "pii_gstin_in", "Als indische GST-Nummer ist ", "14SXZAK2035H1ZO", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IN_GSTIN", "de", "pii_gstin_in", "GST-Nummer: ", "32FPCPC1785F4Z5", mode="recall"),
    p("IN_GSTIN", "de", "pii_gstin_in_context_free", "Lieferant ", "15JEDHV3851A1ZZ", " aus Mumbai", carrier="prose", tags=("no_context",), mode="balanced"),
    n("IN_GSTIN", "en", "pii_gstin_in", "GSTIN: 10BAGFF2439K3ZM", "check character fails"),
    n("IN_GSTIN", "en", "pii_gstin_in", "GSTIN: 00BAGFF2439K3ZM", "state code 00 with a valid check character"),
    n("IN_GSTIN", "en", "pii_gstin_in", "GSTIN: 27ABCDE1234F1Y5", "no Z in the fourteenth place"),
    n("IN_GSTIN", "en", "pii_gstin_in_context_free", "Invoice from 25OLGTA9304C8ZX is due.", "bare form whose check character fails", carrier="prose", mode="balanced"),
    n("IN_GSTIN", "en", "pii_gstin_in", "GSTIN: 10BAGFF2439K3ZL5", "part of a longer value", mode="recall"),
    n("IN_GSTIN", "de", "pii_gstin_in", "GSTIN: 36RWETR6874M6ZU", "check character fails"),
    n("IN_GSTIN", "de", "pii_gstin_in", "GSTIN: 45RWETR6874M6ZU", "state code 45 with a valid check character"),
    n("IN_GSTIN", "de", "pii_gstin_in", "GSTIN: 36RWETR6874M0ZZ", "entity number 0 with a valid check character"),
    n("IN_GSTIN", "de", "pii_gstin_in_context_free", "Lieferant 15JEDHV3851A1Z0 aus Mumbai", "bare form whose check character fails", carrier="prose", mode="balanced"),
    n("IN_GSTIN", "de", "pii_gstin_in", "GSTIN: X36RWETR6874M6ZT", "part of a longer value", mode="recall"),
    # ── IN PAN ─────────────────────────────────────────────────────────────
    p("IN_PAN", "en", "pii_pan_in", "PAN: ", "BNZPM2501F"),
    p("IN_PAN", "en", "pii_pan_in", "The Permanent Account Number on file is ", "AFZPK7190K", ".", carrier="prose"),
    p("IN_PAN", "en", "pii_pan_in", '{"pan_number": "', "AAACR5055K", '"}', carrier="json"),
    p("IN_PAN", "en", "pii_pan_in", "name,pan\nAnil Rao,", "CQWPS4821L", "", carrier="csv", mode="balanced"),
    p("IN_PAN", "en", "pii_pan_in", "Income tax PAN card: ", "AAFFS9921J", mode="recall"),
    p("IN_PAN", "de", "pii_pan_in", "Indische PAN: ", "DKLPR3307N"),
    p("IN_PAN", "de", "pii_pan_in", "Die PAN-Nummer des Kunden lautet ", "EHTPV5562Q", ".", carrier="prose"),
    p("IN_PAN", "de", "pii_pan_in", "| Name | PAN |\n|---|---|\n| Neha Iyer | ", "GJMPT8834H", " |", carrier="table"),
    p("IN_PAN", "de", "pii_pan_in", "Als indische PAN ist ", "BYXPA1290D", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IN_PAN", "de", "pii_pan_in", "Permanent Account Number: ", "KRTPG4410M", mode="recall"),
    n("IN_PAN", "en", "pii_pan_in", "PAN: BNZXM2501F", "fourth letter is no holder type"),
    n("IN_PAN", "en", "pii_pan_in", "PAN: BNZPM0000F", "serial 0000"),
    n("IN_PAN", "en", "pii_pan_in", "Reference BNZPM2501F was archived.", "PAN form without a PAN term", carrier="prose", mode="balanced"),
    n("IN_PAN", "en", "pii_pan_in", "PAN: BNZPM2501F7", "part of a longer value", mode="recall"),
    n("IN_PAN", "en", "pii_pan_in", "PAN: BNZPM25010", "digit in the last place"),
    n("IN_PAN", "de", "pii_pan_in", "Indische PAN: DKLQR3307N", "fourth letter is no holder type"),
    n("IN_PAN", "de", "pii_pan_in", "Indische PAN: DKLPR0000N", "serial 0000"),
    n("IN_PAN", "de", "pii_pan_in", "Vorgang DKLPR3307N wurde abgeschlossen.", "PAN form without a PAN term", carrier="prose", mode="balanced"),
    n("IN_PAN", "de", "pii_pan_in", "Indische PAN: XDKLPR3307N", "part of a longer value", mode="recall"),
    n("IN_PAN", "de", "pii_pan_in", "Indische PAN: DKLP3307N", "four letters"),
    # ── IN voter ID (EPIC) ─────────────────────────────────────────────────
    p("IN_VOTER", "en", "pii_voter_id_in", "Voter ID: ", "KLT4471920"),
    p("IN_VOTER", "en", "pii_voter_id_in", "You can vote with your EPIC number ", "WBX0938264", ".", carrier="prose"),
    p("IN_VOTER", "en", "pii_voter_id_in", '{"voter_id": "', "DLH5520731", '"}', carrier="json"),
    p("IN_VOTER", "en", "pii_voter_id_in", "name,epic\nSunil Das,", "MHR1186402", "", carrier="csv", mode="balanced"),
    p("IN_VOTER", "en", "pii_voter_id_in", "Electoral photo identity card: ", "GJA7739015", mode="recall"),
    p("IN_VOTER", "de", "pii_voter_id_in", "Indische Wähler-ID: ", "TNV2048837"),
    p("IN_VOTER", "de", "pii_voter_id_in", "Die EPIC-Nummer der Antragstellerin lautet ", "UPK6610294", ".", carrier="prose"),
    p("IN_VOTER", "de", "pii_voter_id_in", "| Name | Wähler-ID |\n|---|---|\n| Arjun Nair | ", "KAR3307518", " |", carrier="table"),
    p("IN_VOTER", "de", "pii_voter_id_in", "Als EPIC-Nummer ist ", "BRS9921046", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IN_VOTER", "de", "pii_voter_id_in", "Indischer Wählerausweis: ", "PBJ4458210", mode="recall"),
    n("IN_VOTER", "en", "pii_voter_id_in", "Voter ID: KLT447192", "six digits"),
    n("IN_VOTER", "en", "pii_voter_id_in", "Voter ID: KL44719201", "two letters"),
    n("IN_VOTER", "en", "pii_voter_id_in", "Reference KLT4471920 was archived.", "EPIC form without a voter term", carrier="prose", mode="balanced"),
    n("IN_VOTER", "en", "pii_voter_id_in", "Voter ID: KLT4471920-1", "part of a longer value", mode="recall"),
    n("IN_VOTER", "en", "pii_voter_id_in", "Voter ID: 1234567890", "digits only"),
    n("IN_VOTER", "de", "pii_voter_id_in", "Indische Wähler-ID: TNV204883", "six digits"),
    n("IN_VOTER", "de", "pii_voter_id_in", "Indische Wähler-ID: TN20488371", "two letters"),
    n("IN_VOTER", "de", "pii_voter_id_in", "Vorgang TNV2048837 wurde abgeschlossen.", "EPIC form without a voter term", carrier="prose", mode="balanced"),
    n("IN_VOTER", "de", "pii_voter_id_in", "Indische Wähler-ID: XTNV2048837", "part of a longer value", mode="recall"),
    n("IN_VOTER", "de", "pii_voter_id_in", "Indische Wähler-ID: TNV20488370", "eight digits"),
]
for _row in B_IN_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# A06: US medical licence numbers. The DEA registration number (MEDICAL_LICENSE, a registrant type
# letter, the initial of the last name or 9, seven digits, the last the units digit of
# d1 + d3 + d5 + 2 x (d2 + d4 + d6)) and the National Provider Identifier (US_NPI, ten digits, first
# 1 or 2, plain or grouped 4-3-3, Luhn check digit behind the prefix 80840) are reported in every
# mode when a term of the label stands near them or is their key; in balanced/recall the grouped NPI
# is also reported bare (K05). Hard negatives: failed check digits, a letter that is no registrant
# type, an NPI led by another digit, values without a term and parts of longer values.
A06_CASES = [
    # ── US DEA registration number ─────────────────────────────────────────
    p("MEDICAL_LICENSE", "en", "pii_dea_number_us", "DEA number: ", "DC2758689"),
    p("MEDICAL_LICENSE", "en", "pii_dea_number_us", "The prescriber's DEA registration is ", "UE8031976", ".", carrier="prose"),
    p("MEDICAL_LICENSE", "en", "pii_dea_number_us", '{"dea_number": "', "HG5334189", '"}', carrier="json"),
    p("MEDICAL_LICENSE", "en", "pii_dea_number_us", "name,dea\nEmily Harrison,", "SB6596312", "", carrier="csv", mode="balanced"),
    p("MEDICAL_LICENSE", "en", "pii_dea_number_us", "Drug Enforcement Administration registration: ", "X95988285", mode="recall"),
    p("MEDICAL_LICENSE", "de", "pii_dea_number_us", "DEA-Nummer: ", "UM5770513"),
    p("MEDICAL_LICENSE", "de", "pii_dea_number_us", "Die DEA-Registrierungsnummer der Praxis lautet ", "TR8988808", ".", carrier="prose"),
    p("MEDICAL_LICENSE", "de", "pii_dea_number_us", "| Name | DEA-Nummer |\n|---|---|\n| Dr. Jonas Weber | ", "FH8867686", " |", carrier="table"),
    p("MEDICAL_LICENSE", "de", "pii_dea_number_us", "Als DEA-Nummer ist ", "TS3434468", " hinterlegt.", carrier="prose", mode="balanced"),
    p("MEDICAL_LICENSE", "de", "pii_dea_number_us", "nr;name;dea_nummer\n1;Javier Sánchez;", "XC8504688", "", carrier="csv", mode="recall"),
    n("MEDICAL_LICENSE", "en", "pii_dea_number_us", "DEA number: DC2758680", "check digit fails"),
    n("MEDICAL_LICENSE", "en", "pii_dea_number_us", "DEA number: IC2758689", "I is no registrant type"),
    n("MEDICAL_LICENSE", "en", "pii_dea_number_us", "Reference DC2758689 was archived.", "DEA form without a DEA term", carrier="prose", mode="balanced"),
    n("MEDICAL_LICENSE", "en", "pii_dea_number_us", "DEA number: DC2758689-2", "part of a longer value", mode="recall"),
    n("MEDICAL_LICENSE", "en", "pii_dea_number_us", "DEA number: D12758689", "a digit other than 9 as the second character"),
    n("MEDICAL_LICENSE", "de", "pii_dea_number_us", "DEA-Nummer: UM5770514", "check digit fails"),
    n("MEDICAL_LICENSE", "de", "pii_dea_number_us", "DEA-Nummer: WM5770513", "W is no registrant type"),
    n("MEDICAL_LICENSE", "de", "pii_dea_number_us", "Vorgang UM5770513 wurde abgeschlossen.", "DEA form without a DEA term", carrier="prose", mode="balanced"),
    n("MEDICAL_LICENSE", "de", "pii_dea_number_us", "DEA-Nummer: XUM5770513", "part of a longer value", mode="recall"),
    n("MEDICAL_LICENSE", "de", "pii_dea_number_us", "DEA-Nummer: UM577051", "six digits"),
    # ── US National Provider Identifier ────────────────────────────────────
    p("US_NPI", "en", "pii_npi_us", "NPI: ", "1565277724"),
    p("US_NPI", "en", "pii_npi_us", "The National Provider Identifier on file is ", "1405651617", ".", carrier="prose"),
    p("US_NPI", "en", "pii_npi_us", '{"npi": "', "2817-380-837", '"}', carrier="json"),
    p("US_NPI", "en", "pii_npi_us", "provider,npi\nDr. Emily Harrison,", "1669526901", "", carrier="csv", mode="balanced"),
    p("US_NPI", "en", "pii_npi_us", "Provider identifier ", "1286155159", mode="recall"),
    p("US_NPI", "en", "pii_npi_us_context_free", "Referral to ", "1054-355-379", " is pending.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("US_NPI", "en", "pii_npi_us_context_free", "", "1517 978 007", "", tags=("no_context",), mode="recall"),
    p("US_NPI", "de", "pii_npi_us", "NPI-Nummer: ", "1072090842"),
    p("US_NPI", "de", "pii_npi_us", "Die NPI des behandelnden Arztes lautet ", "2016802532", ".", carrier="prose"),
    p("US_NPI", "de", "pii_npi_us", "| Name | NPI |\n|---|---|\n| Dr. Jonas Weber | ", "2204 957 684", " |", carrier="table"),
    p("US_NPI", "de", "pii_npi_us", "Als NPI ist ", "2636189260", " hinterlegt.", carrier="prose", mode="balanced"),
    p("US_NPI", "de", "pii_npi_us", "nr;name;plz;npi;betrag\n1;Anna Schäfer;30317;", "2591358629", ";1.943,29 €", carrier="csv", mode="recall"),
    p("US_NPI", "de", "pii_npi_us_context_free", "Überweisung an ", "2500-030-897", " folgt.", carrier="prose", tags=("no_context",), mode="balanced"),
    n("US_NPI", "en", "pii_npi_us", "NPI: 1565277725", "check digit fails"),
    n("US_NPI", "en", "pii_npi_us", "NPI: 3850184615", "first digit 3 with a valid check digit"),
    n("US_NPI", "en", "pii_npi_us", "Reference 1565277724 was archived.", "ten bare digits without an NPI term", carrier="prose", mode="balanced"),
    n("US_NPI", "en", "pii_npi_us", "NPI: 15652777241", "part of a longer value", mode="recall"),
    n("US_NPI", "en", "pii_npi_us_context_free", "Referral to 1054-355-370 is pending.", "grouped digits whose check digit fails", carrier="prose", mode="balanced"),
    n("US_NPI", "de", "pii_npi_us", "NPI-Nummer: 1072090843", "check digit fails"),
    n("US_NPI", "de", "pii_npi_us", "NPI-Nummer: 1111111112", "one repeated digit before the check digit"),
    n("US_NPI", "de", "pii_npi_us", "Vorgang 1072090842 wurde abgeschlossen.", "ten bare digits without an NPI term", carrier="prose", mode="balanced"),
    n("US_NPI", "de", "pii_npi_us", "NPI-Nummer: 1072-090-842-5", "part of a longer value", mode="recall"),
    n("US_NPI", "de", "pii_npi_us_context_free", "Überweisung an 2500-030 897 folgt.", "mixed grouping", carrier="prose", mode="recall"),
]
for _row in A06_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-DEFMT: German format identifiers. The Steuernummer (TAX_NUMBER_DE) after its field name follows
# the groups of one Land (FF/BBB/UUUUP, FFBBB/UUUUP for BW, FFF/BBB/UUUUP, FFF/BBBB/UUUP for NW)
# or the 13-digit ELSTER form: the Bundesfinanzamtsnummer with its Land prefix, a 0, district and
# serial, or the two-digit Land code 01-16 and eleven digits (F13). The commercial register number (COMMERCIAL_REGISTER_DE, HRA or
# HRB, one to six digits, an optional court suffix such as B for Berlin) is reported in every mode
# with a register or local court term near it or as its key, and bare in balanced/recall (B03).
# Hard negatives: twelve digits, no Land prefix or no 0 behind the Finanzamt number, groups no Land
# prints, other register prefixes, lower case, a leading zero and parts of longer tokens.
B_DEFMT_CASES = [
    # ── Steuernummer: forms of the Länder and ELSTER ───────────────────────
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: ", "2893081508152"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: ", "75 815 08152", "   Finanzamt Bremen", tags=("ocr",)),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", '{"steuernummer": "', "5133081508159", '"}', carrier="json"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernr=", "18181508155", carrier="kv", mode="balanced"),
    p("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: ", "3201012312340", mode="recall"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: ", "2475081508152"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "German tax number: ", "013 815 08153"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "company:\n  tax number: ", "4151081508156", "\n", carrier="yaml"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "tax number=", "324/0307/4258", carrier="kv", mode="balanced"),
    p("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: ", "1121081508150", mode="recall"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 0081508150001", "no Land prefix 00 in the ELSTER form"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 2893181508152", "no 0 behind the Finanzamt number"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 12/34/56789", "groups no Land prints"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Steuernummer: 028150815012", "twelve digits", mode="balanced"),
    n("TAX_NUMBER_DE", "de", "pii_steuernummer_de", "Bitte 5133081508159 übernehmen.", "13 bare digits without a field name", carrier="prose", mode="recall"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "German Steuernummer: 1234/567/89012", "twelve digits in groups no Land prints"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "company:\n  tax number: 2893/081/50812\n", "twelve digits behind an ELSTER prefix", carrier="yaml"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: 1781508150001", "no Land prefix 17 in the ELSTER form"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: 9381081508155", "no Land prefix 93 in the ELSTER form"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Tax number: 2181/508/150", "ten digits in groups no Land prints", mode="balanced"),
    n("TAX_NUMBER_DE", "en", "pii_steuernummer_de", "Timestamp 2893081508152 logged.", "13 bare digits without a field name", carrier="prose", mode="recall"),
    # ── Handelsregister ────────────────────────────────────────────────────
    p("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Amtsgericht München, ", "HRB 123456"),
    p("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Registergericht: Amtsgericht Charlottenburg ", "HRB 98765 B"),
    p("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Die Firma ist im Handelsregister unter ", "HRB 44020", " eingetragen.", carrier="prose"),
    p("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "nr;name;handelsregister\n1;Grace Davies;", "HRB 32461", "", carrier="csv", mode="balanced"),
    p("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Registernummer: ", "HRA 2136", mode="recall"),
    p("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de_context_free", "Die Schmidt GmbH (", "HRB 71234", ") liefert.", carrier="prose", tags=("no_context",), mode="balanced"),
    p("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de", "Commercial register: ", "HRB 208472"),
    p("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de", "Registered at the local court of Hamburg, ", "HRB 32375", ".", carrier="prose"),
    p("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de", '{"commercial_register": "', "HRB 143241", '"}', carrier="json"),
    p("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de", "Register court Kiel, ", "HRB 1234 KI", mode="balanced"),
    p("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de_context_free", "", "HRA12345", "", tags=("no_context",), mode="balanced"),
    p("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de_context_free", "Supplier ", "HRA 9012", " confirmed the order.", carrier="prose", tags=("no_context",), mode="recall"),
    n("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Amtsgericht München HRC 12345", "HRC is no commercial register"),
    n("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Amtsgericht München HR 12345", "HR without A or B"),
    n("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Amtsgericht München hrb 12345", "lower-case prefix"),
    n("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de", "Amtsgericht München HRB 012345", "leading zero", mode="balanced"),
    n("COMMERCIAL_REGISTER_DE", "de", "pii_commercial_register_de_context_free", "Aktenzeichen: HRB 12345", "the field names another value", mode="balanced"),
    n("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de", "Commercial register: HRB 1234567", "seven digits"),
    n("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de", "Commercial register: XHRB 12345", "part of a longer token"),
    n("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de_context_free", "HRC 12345", "HRC is no commercial register", mode="balanced"),
    n("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de_context_free", "Ticket HRB-12345", "part of a hyphenated token", mode="recall"),
    n("COMMERCIAL_REGISTER_DE", "en", "pii_commercial_register_de_context_free", "Build HR 12345 failed.", "HR without A or B", carrier="prose", mode="balanced"),
]
for _row in B_DEFMT_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-DEVID: mobile device and SIM identifiers. The IMEI (IMEI, fifteen digits, plain or grouped
# 2-6-6-1, Luhn check digit), the MEID (MEID, fourteen hex digits led by a regional code A0-FF and
# a hex Luhn check digit), the ICCID (ICCID, 19 or 20 digits led by the telecom prefix 89, plain or
# in blocks of four, Luhn check digit) and the IMSI (IMSI, fifteen digits led by a mobile country
# code 2xx-7xx, no check digit) are reported in every mode only when a term of their label stands
# near them or is their key: a bare fifteen-digit Luhn number is one number in ten. Hard negatives:
# failed check digits, other prefixes, a decimal MEID, lengths, values without a term and parts of
# longer values.
B_DEVID_CASES = [
    # ── IMEI ───────────────────────────────────────────────────────────────
    p("IMEI", "en", "pii_imei", "IMEI: ", "356352080572311"),
    p("IMEI", "en", "pii_imei", "The IMEI of the lost phone is ", "86-292765-624217-0", ".", carrier="prose"),
    p("IMEI", "en", "pii_imei", '{"imei": "', "015023733203876", '"}', carrier="json"),
    p("IMEI", "en", "pii_imei", "device,imei\nPixel 8,", "358076867817262", "", carrier="csv", mode="balanced"),
    p("IMEI", "en", "pii_imei", "Device IMEI ", "99 022640 218816 6", mode="recall"),
    p("IMEI", "de", "pii_imei", "IMEI-Nummer: ", "354536580759590"),
    p("IMEI", "de", "pii_imei", "Die IMEI des gestohlenen Handys lautet ", "869962546895674", ".", carrier="prose"),
    p("IMEI", "de", "pii_imei", "| Gerät | IMEI |\n|---|---|\n| Galaxy S23 | ", "35-046365-005387-5", " |", carrier="table"),
    p("IMEI", "de", "pii_imei", "Als Gerätenummer (IMEI) ist ", "014180420583308", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IMEI", "de", "pii_imei", "nr;gerät;imei\n1;iPhone 15;", "356726082749946", "", carrier="csv", mode="recall"),
    n("IMEI", "en", "pii_imei", "IMEI: 356352080572312", "check digit fails"),
    n("IMEI", "en", "pii_imei", "IMEI: 35635208057231", "fourteen digits"),
    n("IMEI", "en", "pii_imei", "Order 356352080572311 was shipped.", "fifteen bare digits without an IMEI term", carrier="prose", mode="balanced"),
    n("IMEI", "en", "pii_imei", "IMEI: 3563520805723115", "part of a longer value", mode="recall"),
    n("IMEI", "en", "pii_imei", "IMEI: 35-635208 057231-1", "mixed grouping"),
    n("IMEI", "de", "pii_imei", "IMEI-Nummer: 354536580759591", "check digit fails"),
    n("IMEI", "de", "pii_imei", "IMEI-Nummer: 000000000000000", "one repeated digit"),
    n("IMEI", "de", "pii_imei", "Vorgang 354536580759590 wurde abgeschlossen.", "fifteen bare digits without an IMEI term", carrier="prose", mode="balanced"),
    n("IMEI", "de", "pii_imei", "IMEI-Nummer: 354536580759590-2", "part of a longer value", mode="recall"),
    n("IMEI", "de", "pii_imei", "IMEI-Nummer: 3545365807595", "thirteen digits"),
    # ── MEID ───────────────────────────────────────────────────────────────
    p("MEID", "en", "pii_meid", "MEID: ", "A1000000929602E"),
    p("MEID", "en", "pii_meid", "The MEID printed on the handset is ", "A0000031FF6A115", ".", carrier="prose"),
    p("MEID", "en", "pii_meid", '{"meid": "', "A10000370B1E426", '"}', carrier="json"),
    p("MEID", "en", "pii_meid", "device,meid\nMoto G,", "A1000049A51C336", "", carrier="csv", mode="balanced"),
    p("MEID", "en", "pii_meid", "Mobile Equipment Identifier ", "AF0123450ABCDEC", mode="recall"),
    p("MEID", "de", "pii_meid", "MEID-Nummer: ", "A000001D57B3085"),
    p("MEID", "de", "pii_meid", "Die MEID des CDMA-Geräts lautet ", "A1000012CA4F07D", ".", carrier="prose"),
    p("MEID", "de", "pii_meid", "| Gerät | MEID |\n|---|---|\n| Galaxy S9 | ", "A0000067E21A55B", " |", carrier="table"),
    p("MEID", "de", "pii_meid", "Als MEID ist ", "A100002B7C9D403", " hinterlegt.", carrier="prose", mode="balanced"),
    p("MEID", "de", "pii_meid", "nr;gerät;meid\n1;Moto G;", "A1ACBBECCAC596C", "", carrier="csv", mode="recall"),
    n("MEID", "en", "pii_meid", "MEID: A1000000929602F", "check digit fails"),
    n("MEID", "en", "pii_meid", "MEID: 990000864321010", "a decimal regional code is an IMEI"),
    n("MEID", "en", "pii_meid", "Commit A1000000929602E was merged.", "MEID form without a MEID term", carrier="prose", mode="balanced"),
    n("MEID", "en", "pii_meid", "MEID: A1000000929602E7", "part of a longer value", mode="recall"),
    n("MEID", "en", "pii_meid", "MEID: a1000000929602e", "lower-case hex"),
    n("MEID", "de", "pii_meid", "MEID-Nummer: A000001D57B3086", "check digit fails"),
    n("MEID", "de", "pii_meid", "MEID-Nummer: A000001D57B308", "fourteen hex digits without a check digit"),
    n("MEID", "de", "pii_meid", "Prüfsumme A000001D57B3085 stimmt.", "MEID form without a MEID term", carrier="prose", mode="balanced"),
    n("MEID", "de", "pii_meid", "MEID-Nummer: 0xA000001D57B3085", "part of a longer value", mode="recall"),
    n("MEID", "de", "pii_meid", "MEID-Nummer: G000001D57B3085", "G is no hex digit"),
    # ── ICCID ──────────────────────────────────────────────────────────────
    p("ICCID", "en", "pii_iccid", "ICCID: ", "89495988234014706821"),
    p("ICCID", "en", "pii_iccid", "The SIM card number is ", "8944184652734537308", ".", carrier="prose"),
    p("ICCID", "en", "pii_iccid", '{"iccid": "', "89014454193125595750", '"}', carrier="json"),
    p("ICCID", "en", "pii_iccid", "line,iccid\n1,", "8933762633143822658", "", carrier="csv", mode="balanced"),
    p("ICCID", "en", "pii_iccid", "SIM serial number ", "8941 9503 6778 5996 7302", mode="recall"),
    p("ICCID", "de", "pii_iccid", "ICCID: ", "89491819323779737016"),
    p("ICCID", "de", "pii_iccid", "Die SIM-Kartennummer lautet ", "8944862465073468475", ".", carrier="prose"),
    p("ICCID", "de", "pii_iccid", "| Vertrag | ICCID |\n|---|---|\n| 4711 | ", "89490592962799664299", " |", carrier="table"),
    p("ICCID", "de", "pii_iccid", "Als SIM-Nummer ist ", "8901 8028 3604 6233 0459", " hinterlegt.", carrier="prose", mode="balanced"),
    p("ICCID", "de", "pii_iccid", "nr;tarif;iccid\n1;Prepaid;", "89430370932852231108", "", carrier="csv", mode="recall"),
    n("ICCID", "en", "pii_iccid", "ICCID: 89495988234014706822", "check digit fails"),
    n("ICCID", "en", "pii_iccid", "ICCID: 79495988234014706823", "no telecom prefix 89"),
    n("ICCID", "en", "pii_iccid", "Tracking 89495988234014706821 was delivered.", "ICCID form without a SIM term", carrier="prose", mode="balanced"),
    n("ICCID", "en", "pii_iccid", "ICCID: 894959882340147068213", "part of a longer value", mode="recall"),
    n("ICCID", "en", "pii_iccid", "ICCID: 894959882340147068", "eighteen digits"),
    n("ICCID", "de", "pii_iccid", "ICCID: 89491819323779737017", "check digit fails"),
    n("ICCID", "de", "pii_iccid", "ICCID: 8949 1819 3237 79737016", "broken grouping"),
    n("ICCID", "de", "pii_iccid", "Sendung 89491819323779737016 wurde zugestellt.", "ICCID form without a SIM term", carrier="prose", mode="balanced"),
    n("ICCID", "de", "pii_iccid", "ICCID: 89491819323779737016-1", "part of a longer value", mode="recall"),
    n("ICCID", "de", "pii_iccid", "ICCID: 8949181932377973702", "nineteen digits whose check digit fails"),
    # ── IMSI ───────────────────────────────────────────────────────────────
    p("IMSI", "en", "pii_imsi", "IMSI: ", "310150123456789"),
    p("IMSI", "en", "pii_imsi", "The subscriber's IMSI is ", "234302345678901", ".", carrier="prose"),
    p("IMSI", "en", "pii_imsi", '{"imsi": "', "310260987654321", '"}', carrier="json"),
    p("IMSI", "en", "pii_imsi", "name,imsi\nGrace Davies,", "234150918273645", "", carrier="csv", mode="balanced"),
    p("IMSI", "en", "pii_imsi", "International Mobile Subscriber Identity ", "440101234567890", mode="recall"),
    p("IMSI", "de", "pii_imsi", "IMSI: ", "262011234567890"),
    p("IMSI", "de", "pii_imsi", "Die IMSI der SIM-Karte lautet ", "262073901234567", ".", carrier="prose"),
    p("IMSI", "de", "pii_imsi", "| Anschluss | IMSI |\n|---|---|\n| Mobil | ", "262029876543210", " |", carrier="table"),
    p("IMSI", "de", "pii_imsi", "Als Teilnehmerkennung (IMSI) ist ", "228011234598765", " hinterlegt.", carrier="prose", mode="balanced"),
    p("IMSI", "de", "pii_imsi", "nr;tarif;imsi\n1;Prepaid;", "208011712345678", "", carrier="csv", mode="recall"),
    n("IMSI", "en", "pii_imsi", "IMSI: 810150123456789", "no mobile country code 8xx"),
    n("IMSI", "en", "pii_imsi", "IMSI: 31015012345678", "fourteen digits"),
    n("IMSI", "en", "pii_imsi", "Order 310150123456789 was shipped.", "fifteen bare digits without an IMSI term", carrier="prose", mode="balanced"),
    n("IMSI", "en", "pii_imsi", "IMSI: 3101501234567890", "part of a longer value", mode="recall"),
    n("IMSI", "en", "pii_imsi", "IMSI: 333333333333333", "one repeated digit"),
    n("IMSI", "de", "pii_imsi", "IMSI: 162011234567891", "no mobile country code 1xx"),
    n("IMSI", "de", "pii_imsi", "IMSI: 26201123456789", "fourteen digits"),
    n("IMSI", "de", "pii_imsi", "Vorgang 262011234567890 wurde abgeschlossen.", "fifteen bare digits without an IMSI term", carrier="prose", mode="balanced"),
    n("IMSI", "de", "pii_imsi", "IMSI: 262011234567890-1", "part of a longer value", mode="recall"),
    n("IMSI", "de", "pii_imsi", "IMSI: 962011234567890", "no mobile country code 9xx"),
]
for _row in B_DEVID_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# B-FIN: vehicle, securities, legal entity and pharmaceutical identifiers. The VIN (VIN, seventeen
# characters without I, O and Q, the last four digits; the North American check digit in the ninth
# place for pii_vin, none for the European form of pii_vin_format), the ISIN (ISIN, Luhn over the
# expanded letters), the LEI (LEI, ISO 7064 MOD 97-10) and the PZN (DE_PZN, eight digits weighted
# 1 to 7 mod 11) are reported in every mode with a term of their label near them or as their key.
# Hard negatives: failed checks, characters outside the alphabet, values without a term, parts of
# longer values and the PZN listed after a drug with blanks only (E05 medication lines).
B_FIN_CASES = [
    # ── VIN ─────────────────────────────────────────────────────────────────
    p("VIN", "en", "pii_vin", "VIN: ", "1HGFTJZE5EP534519"),
    p("VIN", "en", "pii_vin", "The vehicle identification number of the car is ", "1FTYAZLW1VF876758", ".", carrier="prose"),
    p("VIN", "en", "pii_vin", '{"vin": "', "4T1L9WS0XVU072449", '"}', carrier="json"),
    p("VIN", "en", "pii_vin_format", "Chassis number: ", "YV11X0RYFMH595605", mode="balanced"),
    p("VIN", "en", "pii_vin", "model,vin,km\nCivic,", "JHMVE4N49XR023470", ",42000", carrier="csv", mode="recall"),
    p("VIN", "de", "pii_vin_format", "Fahrgestellnummer: ", "WAU2UZ3JU8F857800"),
    p("VIN", "de", "pii_vin_format", "Die Fahrzeug-Identifizierungsnummer des Wagens lautet ", "TMBGF1JBV2B896295", ".", carrier="prose"),
    p("VIN", "de", "pii_vin", "| Modell | VIN |\n|---|---|\n| Kombi 2.0 | ", "1G1D5PT18YL049160", " |", carrier="table"),
    p("VIN", "de", "pii_vin_format", "Als FIN-Nummer ist ", "SALWU3C0LLB741051", " eingetragen.", carrier="prose", mode="balanced"),
    p("VIN", "de", "pii_vin", "nr;modell;vin\n1;Kombi;", "2HGG991D3CE249096", "", carrier="csv", mode="recall"),
    n("VIN", "en", "pii_vin", "VIN: 1HGFTJZE5EP53451O", "O is no VIN character"),
    n("VIN", "en", "pii_vin", "VIN: 1HGFTJZE5EP5345A9", "the serial number ends in a letter"),
    n("VIN", "en", "pii_vin", "Reference 1FTYAZLW1VF876758 was archived.", "VIN form without a VIN term", carrier="prose", mode="balanced"),
    n("VIN", "en", "pii_vin", "VIN: 1HGFTJZE5EP534519-2", "part of a longer value", mode="recall"),
    n("VIN", "en", "pii_vin", "VIN: 1HGFTJZE5EP53451", "sixteen characters"),
    n("VIN", "de", "pii_vin_format", "Fahrgestellnummer: WAU2UZ3JU8F85780Q", "Q is no VIN character"),
    n("VIN", "de", "pii_vin_format", "Fahrgestellnummer: WAU2UZ3JU8F857800A", "eighteen characters"),
    n("VIN", "de", "pii_vin_format", "Vorgang TMBGF1JBV2B896295 wurde abgeschlossen.", "VIN form without a VIN term", carrier="prose", mode="balanced"),
    n("VIN", "de", "pii_vin_format", "FIN-Nummer: SALWU3C0LLB741051/2", "part of a longer value", mode="recall"),
    n("VIN", "de", "pii_vin_format", "Fahrgestellnummer: 12345678901234567", "seventeen digits without a letter"),
    # ── ISIN ────────────────────────────────────────────────────────────────
    p("ISIN", "en", "pii_isin", "ISIN: ", "GB0002634946"),
    p("ISIN", "en", "pii_isin", "The fund holds the security with ISIN ", "IE3525623045", ".", carrier="prose"),
    p("ISIN", "en", "pii_isin", '{"isin": "', "NL2352443521", '"}', carrier="json"),
    p("ISIN", "en", "pii_isin", "isin,quantity\n", "XS1329094590", ",120", carrier="csv", mode="balanced"),
    p("ISIN", "en", "pii_isin", "ISIN code ", "CHULWSB5XU52", mode="recall"),
    p("ISIN", "de", "pii_isin", "ISIN: ", "DE7228763334"),
    p("ISIN", "de", "pii_isin", "Verkauft wurde die Aktie mit der ISIN ", "FR1223189416", ".", carrier="prose"),
    p("ISIN", "de", "pii_isin", "| Wertpapier | ISIN |\n|---|---|\n| Anleihe 2031 | ", "AT6166969107", " |", carrier="table"),
    p("ISIN", "de", "pii_isin", "Als ISIN-Code ist ", "IT3GCN258XN6", " hinterlegt.", carrier="prose", mode="balanced"),
    p("ISIN", "de", "pii_isin", "nr;isin;stueck\n1;", "LUXAKBZCCAX4", ";250", carrier="csv", mode="recall"),
    n("ISIN", "en", "pii_isin", "ISIN: GB0002634947", "check digit fails"),
    n("ISIN", "en", "pii_isin", "ISIN: 1B0002634946", "no country letters"),
    n("ISIN", "en", "pii_isin", "Order IE3525623045 was shipped.", "ISIN form without an ISIN term", carrier="prose", mode="balanced"),
    n("ISIN", "en", "pii_isin", "ISIN: NL23524435210", "part of a longer value", mode="recall"),
    n("ISIN", "en", "pii_isin", "ISIN: gb0002634946", "lower case"),
    n("ISIN", "de", "pii_isin", "ISIN: DE7228763335", "check digit fails"),
    n("ISIN", "de", "pii_isin", "ISIN: FR122318941A", "a letter as the check digit"),
    n("ISIN", "de", "pii_isin", "Vorgang AT6166969107 wurde abgeschlossen.", "ISIN form without an ISIN term", carrier="prose", mode="balanced"),
    n("ISIN", "de", "pii_isin", "ISIN: XDE7228763334", "part of a longer value", mode="recall"),
    n("ISIN", "de", "pii_isin", "ISIN: DE722876333", "eleven characters"),
    # ── LEI ─────────────────────────────────────────────────────────────────
    p("LEI", "en", "pii_lei", "LEI: ", "81560042JW51AN87A254"),
    p("LEI", "en", "pii_lei", "The legal entity identifier of the counterparty is ", "815600M0W75W3BJWUV36", ".", carrier="prose"),
    p("LEI", "en", "pii_lei", '{"lei": "', "549300JL6ZVW23MGSR49", '"}', carrier="json"),
    p("LEI", "en", "pii_lei", "counterparty,lei\nAcme Ltd,", "969500UG15EANCZRWH49", "", carrier="csv", mode="balanced"),
    p("LEI", "en", "pii_lei", "LEI code ", "529900LCZHRKL96TYZ92", mode="recall"),
    p("LEI", "de", "pii_lei", "LEI-Code: ", "969500Z4ZSZDSW2GJB24"),
    p("LEI", "de", "pii_lei", "Die Rechtsträgerkennung des Emittenten lautet ", "391200TMJW531CNZZ653", ".", carrier="prose"),
    p("LEI", "de", "pii_lei", "| Gegenpartei | LEI |\n|---|---|\n| Muster AG | ", "391200M29C53T2LL8138", " |", carrier="table"),
    p("LEI", "de", "pii_lei", "Als LEI ist ", "969500Z2447U9E8Z0P22", " hinterlegt.", carrier="prose", mode="balanced"),
    p("LEI", "de", "pii_lei", "nr;firma;lei\n1;Beispiel GmbH;", "2138000KYLEGFCD44P43", "", carrier="csv", mode="recall"),
    n("LEI", "en", "pii_lei", "LEI: 81560042JW51AN87A255", "check digits fail"),
    n("LEI", "en", "pii_lei", "LEI: 81560042JW51AN87A2X4", "a letter in the check digits"),
    n("LEI", "en", "pii_lei", "Reference 815600M0W75W3BJWUV36 was archived.", "LEI form without an LEI term", carrier="prose", mode="balanced"),
    n("LEI", "en", "pii_lei", "LEI: 549300JL6ZVW23MGSR491", "part of a longer value", mode="recall"),
    n("LEI", "en", "pii_lei", "LEI: 81560042JW51AN87A25", "nineteen characters"),
    n("LEI", "de", "pii_lei", "LEI-Code: 969500Z4ZSZDSW2GJB42", "check digits fail"),
    n("LEI", "de", "pii_lei", "LEI-Code: 969500z4zszdsw2gjb24", "lower case"),
    n("LEI", "de", "pii_lei", "Vorgang 391200TMJW531CNZZ653 wurde abgeschlossen.", "LEI form without an LEI term", carrier="prose", mode="balanced"),
    n("LEI", "de", "pii_lei", "LEI-Code: X969500Z4ZSZDSW2GJB24", "part of a longer value", mode="recall"),
    n("LEI", "de", "pii_lei", "LEI-Code: 00000000000000000000", "zeros"),
    # ── PZN ─────────────────────────────────────────────────────────────────
    p("DE_PZN", "en", "pii_pzn_de", "PZN: ", "41339609"),
    p("DE_PZN", "en", "pii_pzn_de", "The pharmaceutical central number of the product is ", "62072079", ".", carrier="prose"),
    p("DE_PZN", "en", "pii_pzn_de", '{"pzn": "', "80137730", '"}', carrier="json"),
    p("DE_PZN", "en", "pii_pzn_de", "product,pzn,qty\nIbuprofen 400,", "40746011", ",2", carrier="csv", mode="balanced"),
    p("DE_PZN", "en", "pii_pzn_de", "PZN-", "27027889", mode="recall"),
    p("DE_PZN", "de", "pii_pzn_de", "PZN: ", "32426396"),
    p("DE_PZN", "de", "pii_pzn_de", "Die Pharmazentralnummer des Präparats lautet ", "92407821", ".", carrier="prose"),
    p("DE_PZN", "de", "pii_pzn_de", "| Präparat | PZN |\n|---|---|\n| Pantoprazol 40 mg | ", "62121903", " |", carrier="table"),
    p("DE_PZN", "de", "pii_pzn_de", "Als PZN-Nummer ist ", "32504452", " hinterlegt.", carrier="prose", mode="balanced"),
    p("DE_PZN", "de", "pii_pzn_de", "nr;praeparat;pzn;menge\n1;Metformin 500 mg;", "41039882", ";3", carrier="csv", mode="recall"),
    n("DE_PZN", "en", "pii_pzn_de", "PZN: 41339600", "check digit fails"),
    n("DE_PZN", "en", "pii_pzn_de", "PZN: 00000000", "one repeated digit"),
    n("DE_PZN", "en", "pii_pzn_de", "Order 62072079 was shipped.", "eight digits without a PZN term", carrier="prose", mode="balanced"),
    n("DE_PZN", "en", "pii_pzn_de", "PZN: 80137730-4", "part of a longer value", mode="recall"),
    n("DE_PZN", "en", "pii_pzn_de", "Medication: Ibuprofen 400 mg, PZN 40746011", "PZN listed after a drug with blanks only"),
    n("DE_PZN", "de", "pii_pzn_de", "PZN: 32426397", "check digit fails"),
    n("DE_PZN", "de", "pii_pzn_de", "PZN: 324263961", "nine digits"),
    n("DE_PZN", "de", "pii_pzn_de", "Vorgang 92407821 wurde abgeschlossen.", "eight digits without a PZN term", carrier="prose", mode="balanced"),
    n("DE_PZN", "de", "pii_pzn_de", "PZN: 4/62121903", "part of a longer value", mode="recall"),
    n("DE_PZN", "de", "pii_pzn_de", "Medikation: Pantoprazol 40 mg, PZN 32504452", "PZN listed after a drug with blanks only"),
]
for _row in B_FIN_CASES:
    PII_CASES.setdefault(_row["target_label"], []).append(_row)

# A02: crypto wallet addresses (CRYPTO). Bitcoin (P2PKH 1…, P2SH 3…, segwit bc1… in Bech32 or
# Bech32m) and Litecoin (L…, M…, ltc1…) carry a Base58Check or Bech32 checksum, Ethereum addresses
# in mixed case the EIP-55 checksum; these are reported bare in every mode. A lower-case Ethereum
# address carries no checksum and is reported only with a wallet term near it or as its key.
# Hard negatives: failed checksums, the wrong version or human-readable part, mixed case in
# Bech32, a single letter case without a wallet term, 64 hex digits and parts of longer tokens.
A02_CASES = [
    p("CRYPTO", "en", "pii_crypto_btc", "Please send the payment to ", "1FMesZMcejdnbx7L39utq2RCTm98eTrVcj", " by Friday.", carrier="prose"),
    p("CRYPTO", "en", "pii_crypto_btc", "BTC address: ", "bc1qd5knetdnv6wt658pvhjrgfya3wpf7sgkyvx29a"),
    p("CRYPTO", "en", "pii_crypto_btc", '{"payout": "', "bc1pgnnpmx4npl9sdfkp4k8jjph8x2cs7ndh38f4af5vpz9t8ajgsx9sg7jx8m", '"}', carrier="json", mode="balanced"),
    p("CRYPTO", "en", "pii_crypto_ltc", "Litecoin deposit address: ", "LSCL2hJdHouk8JH5nksh1fQ3xWAvwN812i"),
    p("CRYPTO", "en", "pii_crypto_eth", "Refunds go to ", "0xAE40A235A49990Ab85A85844fE7Eaab34998c8eF", ".", carrier="prose", mode="recall"),
    p("CRYPTO", "en", "pii_crypto_eth_unchecked", "name,wallet\nAlice,", "0xd8fafcaeaba5e5a5576f47127302f09be3ef8da2", "", carrier="csv"),
    p("CRYPTO", "de", "pii_crypto_btc", "Bitte überweisen Sie den Betrag an ", "3AmUfjkQBVsEoLYMFuytaeiKBazDe4wdfY", ".", carrier="prose"),
    p("CRYPTO", "de", "pii_crypto_btc", "Bitcoin-Adresse: ", "bc1qgxas6jejm4faft5fa6s85n6hnchl0t8zc8ff3h8srj29e06eekfsus07fl"),
    p("CRYPTO", "de", "pii_crypto_ltc", "| Kunde | Wallet |\n|---|---|\n| Muster | ", "ltc1qmepg342p53j4m6dj5v5sstkytefstu66yw2x27", " |", carrier="table", mode="balanced"),
    p("CRYPTO", "de", "pii_crypto_ltc", "Auszahlung an ", "MStBHi1syUuuutxx4viMacU78B2rnRrR4b", " erfolgt.", carrier="prose"),
    p("CRYPTO", "de", "pii_crypto_eth", "Ethereum-Adresse: ", "0xf8Fa223F1999b7BE7bd2B58F686aFA89bC084343", mode="recall"),
    p("CRYPTO", "de", "pii_crypto_eth_unchecked", "Die Wallet-Adresse lautet ", "0x064c3cbf796da795c7d6ad6d75b8d7e5f0696295", ".", carrier="prose", mode="balanced"),
    n("CRYPTO", "en", "pii_crypto_btc", "BTC address: 1FMesZMcejdnbx7L39utq2RCTm98eTrVck", "Base58Check checksum fails"),
    n("CRYPTO", "en", "pii_crypto_btc", "Wallet: bc1qd5knetdnv6wt658pvhjrgfya3wpf7sgkyvx29A", "mixed case in Bech32", mode="balanced"),
    n("CRYPTO", "en", "pii_crypto_ltc", "Litecoin address: LSCL2hJdHouk8JH5nksh1fQ3xWAvwN812j", "Base58Check checksum fails", mode="recall"),
    n("CRYPTO", "en", "pii_crypto_eth_unchecked", "Commit 0xd8fafcaeaba5e5a5576f47127302f09be3ef8da2 was merged.", "lower-case address form without a wallet term", carrier="prose", mode="balanced"),
    n("CRYPTO", "en", "pii_crypto_eth", "Tx hash: 0x9ac64c6fca067d28a33c277459afd400cc472df49ac64c6fca067d28a33c2774", "64 hex digits, a hash", mode="recall"),
    n("CRYPTO", "de", "pii_crypto_btc", "Bitcoin-Adresse: 3AmUfjkQBVsEoLYMFuytaeiKBazDe4wdfZ", "Base58Check checksum fails"),
    n("CRYPTO", "de", "pii_crypto_btc", "Testnetz-Adresse: tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet human-readable part", mode="balanced"),
    n("CRYPTO", "de", "pii_crypto_ltc", "Litecoin-Adresse: ltc1qmepg342p53j4m6dj5v5sstkytefstu66yw2x28", "Bech32 checksum fails", mode="recall"),
    n("CRYPTO", "de", "pii_crypto_eth", "Ethereum-Adresse: 0xf8Fa223F1999b7BE7bd2B58F686aFA89bC084344", "EIP-55 checksum fails"),
    n("CRYPTO", "de", "pii_crypto_btc", "Token x3AmUfjkQBVsEoLYMFuytaeiKBazDe4wdfY wurde gesperrt.", "part of a longer token", carrier="prose", mode="balanced"),
]
for _row in A02_CASES:
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
    "sql", "markdown", "prose", "hcl",
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


# F01: rules that report a value only in its key context, also in `strict` (P05: legacy Vault
# tokens only next to a Vault term; P06: Render API keys only next to a Render term).
DLP_CONTEXT_GATED_RULES = ("dlp_eth_private_key", "dlp_vault_legacy_token", "dlp_render_api_key")


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
    # P05
    "dockerhub_pat_short", "pypi_upload_token_truncated", "pypi_upload_token_no_signature",
    "artifactory_api_key_short",
    "rubygems_api_key_upper_hex", "cratesio_api_token_short", "packagist_token_bad_crc",
    "terraform_cloud_token_short", "pulumi_access_token_short", "vault_legacy_service_token_short",
    "doppler_personal_token_short", "doppler_cli_token_long",
    # P06
    "azure_devops_pat_shifted", "azure_devops_legacy_pat_short", "circleci_personal_token_short",
    "travisci_access_token_short", "bitbucket_client_secret_short", "vercel_personal_token_short",
    "netlify_personal_token_short", "netlify_access_token_short", "flyio_oauth_token_short",
    "heroku_api_key_v2_short", "render_api_key_short", "cloudflare_api_token_short", "cloudflare_origin_ca_key_short",
    "digitalocean_pat_short",
    # P07
    "datadog_api_key_short", "datadog_client_token", "newrelic_user_api_key_short", "newrelic_insert_key_short",
    "newrelic_license_key_short", "sentry_user_token_short", "sentry_org_token_no_iat", "grafana_api_key_unterminated",
    "grafana_cloud_token_random", "grafana_service_account_token_bad_crc", "dynatrace_api_token_short",
    "splunk_hec_token_short", "elastic_api_key_short", "honeycomb_api_key_short", "pagerduty_api_key_short",
    # G03: a shell variable reference in the password position
    "cli_password_env_ref",
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
            "CREDENTIAL", "de", "dlp_password_assignment",
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
            "CREDENTIAL", "de", "dlp_password_assignment",
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
            "CREDENTIAL", "en", "dlp_password_assignment",
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
            "CREDENTIAL", "de", "dlp_password_assignment",
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
            "CREDENTIAL", "en", "dlp_password_assignment",
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
            "CREDENTIAL", "de", "dlp_password_assignment",
            "FROM eclipse-temurin:21-jre\nCOPY target/abgleich.jar /app/abgleich.jar\n"
            "ENV LAGER_DB_PASSWORD=\"<<secret:0>>\"\nENTRYPOINT [\"java\", \"-jar\", \"/app/abgleich.jar\"]\n",
            "password", 12006, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
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
            "CREDENTIAL", "en", "dlp_password_assignment",
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


# K05C: config key->value extraction, part 3 (HCL, XML attributes and elements) with the K05
# value-shape filter. An attribute in an HCL block binds its quoted string or array items (a bare
# value is an expression), and a variable "..." block binds its default through the variable name.
# An XML element named by the key binds its text (also in CDATA), and a config element whose
# key/name attribute holds the key binds its value attribute in any order or its text. Hard
# negatives: the K05 shapes per format, also under a key apart from the value (a digest-named
# variable or element), HCL expressions, build-tool placeholders and XML in strings of code. Each
# value line ends the text.
DLP_K05C_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "<lager>\n  <datenbank>\n    <host>db.lager.intern</host>\n    <passwort><<secret:0>></passwort>\n"
            "  </datenbank>\n</lager>\n",
            "quoted_punctuated_password", 15201, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "<!-- Zugang zur Lagerdatenbank, rotiert im September -->\n<datenbank>\n"
            "  <kennwort><![CDATA[<<secret:0>>]]></kennwort>\n</datenbank>\n",
            "quoted_punctuated_password", 15202, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "<properties>\n  <entry key=\"versand.endpunkt\">https://api.versand.intern</entry>\n"
            "  <entry key=\"versand.zugangstoken\"><<secret:0>></entry>\n</properties>\n",
            "url_token", 15203, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "<appSettings>\n  <add value=\"<<secret:0>>\" key=\"LagerApiToken\" />\n</appSettings>\n",
            "url_token", 15204, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "variable \"lager_passwort\" {\n  description = \"Passwort der Lagerdatenbank\"\n  type        = string\n"
            "  default     = \"<<secret:0>>\"\n  sensitive   = true\n}\n",
            "quoted_punctuated_password", 15205, carrier="hcl",
        ),
        ds_items(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "locals {\n  region         = \"eu-central-1\"\n  api_schluessel = [\"<<secret:0>>\", \"<<secret:1>>\"]\n}\n",
            "generic_api_secret", (15206, 15207), carrier="hcl",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<settings>\n  <servers>\n    <server>\n      <id>nexus-releases</id>\n      <username>deploy</username>\n"
            "      <password><<secret:0>></password>\n    </server>\n  </servers>\n</settings>\n",
            "quoted_punctuated_password", 15211, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<hibernate-configuration>\n  <session-factory>\n"
            "    <property name=\"hibernate.connection.password\"><<secret:0>></property>\n"
            "  </session-factory>\n</hibernate-configuration>\n",
            "quoted_punctuated_password", 15212, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "<resources>\n  <string name=\"app_name\">Billing</string>\n"
            "  <string name=\"billing_api_secret\"><<secret:0>></string>\n</resources>\n",
            "generic_api_secret", 15213, carrier="xml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "variable \"db_password\" {\n  type      = string\n  default   = \"<<secret:0>>\" # rotated monthly\n"
            "  sensitive = true\n}\n",
            "quoted_punctuated_password", 15214, carrier="hcl",
        ),
        ds_items(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "variable \"webhook_tokens\" {\n  type    = list(string)\n  default = [\n    \"<<secret:0>>\",\n"
            "    \"<<secret:1>>\", // since March\n  ]\n}\n",
            "url_token", (15215, 15216), carrier="hcl",
        ),
        ds_items(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "resource \"vault_generic_secret\" \"exports\" {\n  path = \"secret/exports\"\n  data_json = jsonencode({\n"
            "    api_keys = [\"<<secret:0>>\"]\n  })\n}\n",
            "url_token", (15217,), carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "<lager>\n  <standort>hamburg</standort>\n  <api_token>3f2a9c4e-7b1d-4e8a-9c2f-5d6e7f8a9b0c</api_token>",
            "UUID in an XML token element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "<konto>\n  <benutzer>lager</benutzer>\n  <gehashtes_passwort>2fd4e1c67a2d28fced849ee1bb76e7391b93eb12</gehashtes_passwort>",
            "hex digest in an XML hashed-password element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "<!-- Maven-Resource-Filtering setzt den Wert beim Build -->\n<datenbank>\n  <passwort>@lager.passwort@</passwort>",
            "Maven filter placeholder in an XML password element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "<!-- Verschlüsselung im Testsystem abgeschaltet -->\n<verschluesselung>\n  <geheimnis>deaktiviert</geheimnis>",
            "boolean word in an XML secret element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "resource \"aws_db_instance\" \"lager\" {\n  username = \"lager\"\n  password = var.lager_passwort",
            "HCL variable reference under a password attribute", carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "variable \"lager_passwort_sha256\" {\n  type    = string\n"
            "  default = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"",
            "hex digest as the default of a digest-named HCL variable", carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# Passwort liegt als Docker-Secret im Container\nvariable \"lager_passwort\" {\n"
            "  default = \"/run/secrets/lager_passwort\"",
            "path as the default of an HCL password variable", carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "module \"versand\" {\n  source       = \"./module/versand\"\n  zugangstoken = \"6512bd43d9caa6e02c990b0a\"",
            "MongoDB ObjectId under an HCL token attribute", carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<server>\n  <id>nexus-releases</id>\n  <password>${env.NEXUS_PASSWORD}</password>",
            "environment placeholder in a Maven password element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "<PropertyGroup>\n  <Configuration>Release</Configuration>\n  <ApiToken>$(BillingApiToken)</ApiToken>",
            "MSBuild property reference in a token element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "<appSettings>\n  <add key=\"PasswordSha256\" "
            "value=\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\" />",
            "hex digest in the value attribute of a digest-named key", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "<!-- token endpoint of the identity provider -->\n<idp>\n"
            "  <client_secret>https://auth.internal/realms/acme/protocol/openid-connect/token</client_secret>",
            "URL without credentials in an XML secret element", carrier="xml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "func TestMavenSettings(t *testing.T) {\n\tfragment := Fragment{\n\t\tRaw: `<password>s3cr3tValue9</password>`,",
            "XML in a string of Go test code", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "resource \"aws_db_instance\" \"orders\" {\n  username = \"orders\"\n"
            "  password = random_password.orders.result",
            "HCL resource reference under a password attribute", carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "resource \"kubernetes_secret\" \"exports\" {\n  data = {\n"
            "    client_secret = \"550e8400-e29b-41d4-a716-446655440000\"",
            "UUID under a nested HCL secret attribute", carrier="hcl",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "provider \"vault\" {\n  address = \"https://vault.internal\"\n  token   = \"${var.vault_token}\"",
            "HCL interpolation under a token attribute", carrier="hcl",
        ),
    ],
}
for _label, _rows in DLP_K05C_CASES.items():
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

# T17: `dlp_url_userinfo_password` reads the userinfo password percent-decoded before the F-GEN1
# likeness check, so test credentials whose reserved characters are encoded (`p%40ss`,
# `p%40ssw%24rd`, `s%33cr%33t`) are stand-ins as in plain text: composer documentation, PHP data
# providers and Python tests. Chosen passwords with the reserved characters @ $ : stay findings
# with the encoded span.
DLP_T17_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "LAGER_DB_URL=postgres://lager:<<secret:0|url>>@db.lager.intern:5432/lager\n",
            "reserved_char_password", 17001, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "proxy:\n  # Filial-Proxy, Sonderzeichen im Passwort kodiert\n  url: http://filiale:<<secret:0|url>>@proxy.intern:3128\n",
            "reserved_char_password", 17002, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "{\n  \"warteschlange\": \"amqp://lager:<<secret:0|url>>@mq.intern:5672/belege\"\n}\n",
            "reserved_char_password", 17003, carrier="json",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "$ git clone https://bauer:<<secret:0|url>>@git.example.de/team/abgleich.git\nKlone nach 'abgleich' …\n",
            "reserved_char_password", 17004, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "Hallo Team, die neue Replik ist erreichbar unter mysql://bericht:<<secret:0|url>>@db2.intern/bericht – bitte nicht weitergeben.",
            "reserved_char_password", 17005, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "DATABASE_URL=postgres://app:<<secret:0|url>>@db.internal:5432/app\n",
            "reserved_char_password", 17006, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "services:\n  worker:\n    environment:\n      BROKER_URL: amqp://worker:<<secret:0|url>>@mq.internal:5672/jobs\n",
            "reserved_char_password", 17007, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "engine = create_engine(\"postgresql://report:<<secret:0|url>>@db1.internal/report\")\n",
            "reserved_char_password", 17008, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "2026-10-26T08:14:02Z INFO connecting to redis://cache:<<secret:0|url>>@cache.internal:6379/0\n",
            "reserved_char_password", 17009, carrier="log",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "[http]\n  proxy = http://build:<<secret:0|url>>@proxy.internal:3128\n",
            "reserved_char_password", 17010, carrier="ini",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "### Autorisierung\n\nReservierte Zeichen in Benutzername und Passwort werden prozentkodiert:\n\n```\nuser: ich@firma\npass: p@ssw$rd\n\nhttp://ich%40firma:p%40ssw%24rd@proxy.example.de:3128\n```\n",
            "percent-encoded documentation example p@ssw$rd", carrier="markdown",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "Beispiel für einen anonymen Zugang: ftp://anonym:%24ecret@ftp.example.de/pub",
            "percent-encoded stand-in $ecret in prose", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "$server = [\n    'http_proxy' => 'http://benutzer:p%40ss@proxy.example.de',\n    'no_proxy' => 'intern.example.de',\n];\n",
            "PHP test array with percent-encoded test credential p@ss", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "# Testfall: Passwort wird maskiert\nassert maskiere(\"https://admin:p%40ssw%30rd@db.intern/app\") == \"https://admin:***@db.intern/app\"\n",
            "Python test with percent-encoded test credential p@ssw0rd", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_url_userinfo_password",
            "PROXY_URL=http://pruefer:s%33cr%33t@proxy.intern:3128\n",
            "percent-encoded leetspeak stand-in s3cr3t", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "### Authorization\n\nReserved URL characters in the user name or password must be percent-encoded:\n\n```\nuser:  me@company\npass:  p@ssw$rd\n\nscheme://me%40company:p%40ssw%24rd@proxy.com:80\n```\n",
            "percent-encoded documentation example p@ssw$rd", carrier="markdown",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "            'removes-user-pass' => ['http://user:p%40ss@proxy.com:6180', 'http://***:***@proxy.com:6180'],\n",
            "PHP data provider with percent-encoded test credential p@ss", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "PROXIES = {\"https\": \"http://user:s%33cr%33t@proxy.internal:3128\"}\n",
            "Python test proxy with percent-encoded stand-in s3cr3t", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "def test_redacts_password():\n    assert redact(\"https://admin:p%40ssw%30rd@db.internal/app\") == \"https://admin:***@db.internal/app\"\n",
            "Python test with percent-encoded test credential p@ssw0rd", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_url_userinfo_password",
            "For anonymous access use ftp://anonymous:%24ecret@ftp.example.com/pub as shown in the setup guide.",
            "percent-encoded stand-in $ecret in prose", carrier="prose",
        ),
    ],
}
for _label, _rows in DLP_T17_CASES.items():
    DLP_CASES[_label].extend(_rows)

# T15: attribution in the generic tier. A password under an upper-case variable name
# (`DB_PASSWORD=…`, `ENV DB_PASSWORD=…`, `export`, CI `env:`, code constants) matches both
# `dlp_env_var_secret` (generic_secret) and `dlp_password_assignment` (password) on the same
# value span; the password rule keeps it. API keys, tokens and client secrets under the same
# kind of name stay `dlp_env_var_secret`. Hard negatives: references, placeholders, documented
# stand-ins, vault lookups and UUIDs under password variables.
DLP_T15_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# .env Lagerverwaltung (lokal)\nLAGER_DB_HOST=db.lager.intern\nLAGER_DB_USER=lager_app\n"
            "LAGER_DB_PASSWORD=<<secret:0>>\nLAGER_DB_PORT=5432\n",
            "password", 17001, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "FROM postgres:16-alpine\nENV POSTGRES_USER=lager\nENV POSTGRES_PASSWORD=\"<<secret:0>>\"\n"
            "COPY init.sql /docker-entrypoint-initdb.d/\n",
            "password", 17002, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# Migration gegen die Testdatenbank\n$ export LAGER_DB_PASSWORT='<<secret:0>>'\n$ ./bin/migrate --ziel test\n",
            "password", 17003, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "abgleich:\n  stage: test\n  variables:\n    LAGER_DB_HOST: db.lager.intern\n"
            "    LAGER_DB_PASSWORD: \"<<secret:0>>\"\n  script:\n    - ./bin/abgleich --pruefen\n",
            "password", 17004, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "public final class Lagerzugang {\n    private static final String DB_KENNWORT = \"<<secret:0>>\";\n}\n",
            "password", 17005, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# .env Lagerverwaltung (lokal)\nLAGER_DB_HOST=db.lager.intern\nLAGER_API_KEY=<<secret:0>>\n",
            "generic_api_secret", 17006, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "# .env for the orders service\nORDERS_DB_HOST=db.internal\nORDERS_DB_USER=orders\n"
            "ORDERS_DB_PASSWORD=<<secret:0>>\n",
            "password", 17011, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "FROM mysql:8.4\nENV MYSQL_DATABASE=orders\nENV MYSQL_ROOT_PASSWORD=<<secret:0>>\nEXPOSE 3306\n",
            "password", 17012, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "$ export SMTP_PASSWORD=\"<<secret:0>>\"\n$ ./bin/send-digest --dry-run\n",
            "password", 17013, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "jobs:\n  integration:\n    runs-on: ubuntu-24.04\n    env:\n      ORDERS_DB_USER: orders\n"
            "      ORDERS_DB_PASSWORD: '<<secret:0>>'\n    steps:\n      - run: make it\n",
            "password", 17014, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "import psycopg\n\nORDERS_DB_PASSWORD = \"<<secret:0>>\"\nconn = psycopg.connect(host=\"db.internal\")\n",
            "password", 17015, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "# .env for the orders service\nORDERS_DB_HOST=db.internal\nOAUTH_CLIENT_SECRET=\"<<secret:0>>\"\n",
            "generic_api_secret", 17016, carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# .env Lagerverwaltung\nLAGER_DB_PASSWORD=${LAGER_DB_PASSWORD}\n",
            "environment reference under a password variable", carrier="env",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "FROM postgres:16-alpine\nENV POSTGRES_PASSWORD=\"<hier-passwort-eintragen>\"\n",
            "placeholder under a password variable", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "$ export LAGER_DB_PASSWORT=\"$(vault kv get -field=passwort secret/lager/db)\"\n",
            "command substitution from a vault", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "abgleich:\n  variables:\n    LAGER_DB_PASSWORD: $LAGER_DB_PASSWORD_CI\n",
            "CI variable reference", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# .env Lagerverwaltung\nLAGER_DB_PASSWORD=3f2b8c1e-7d4a-4e9b-a6c2-91d0e5f4b7a8",
            "UUID under a password variable", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "# .env.example\nORDERS_DB_PASSWORD=changeme\n",
            "documented stand-in password", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "FROM mysql:8.4\nENV MYSQL_ROOT_PASSWORD=\"${MYSQL_ROOT_PASSWORD}\"\n",
            "build argument reference", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "    env:\n      ORDERS_DB_PASSWORD: ${{ secrets.ORDERS_DB_PASSWORD }}\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "ORDERS_DB_PASSWORD = os.environ[\"ORDERS_DB_PASSWORD\"]\n",
            "environment lookup in code", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "$ export SMTP_PASSWORD=<your-smtp-password>\n",
            "placeholder under a password variable", carrier="cli",
        ),
    ],
}
for _label, _rows in DLP_T15_CASES.items():
    DLP_CASES[_label].extend(_rows)


# P05: DevOps and package-registry tokens. `dlp_dockerhub_token` (`dckr_pat_`/`dckr_oat_` and 27
# base64url characters), `dlp_pypi_token` (`pypi-` and a base64url Macaroon V2 for pypi.org or
# test.pypi.org that must parse completely), `dlp_rubygems_token`, `dlp_cratesio_token` (`cio`
# and 32 alphanumerics with both cases), `dlp_packagist_token` (Private Packagist prefixes, 60 hex
# characters and their CRC32 at checksum strength), `dlp_jfrog_token` (`AKCp` API keys and
# `cmVmd` reference tokens), `dlp_terraform_cloud_token` (`.atlasv1.`), `dlp_pulumi_token`,
# `dlp_vault_token` (`hvs.`/`hvb.`), `dlp_vault_legacy_token` (`s.` and 24 characters, only with
# Vault context) and `dlp_doppler_token` (all documented Doppler prefixes). Hard negatives are
# shapes with a wrong length, alphabet, structure or check value, example/test fills, references,
# documented prefixes and a legacy-Vault shape without Vault context.
DLP_P05_CASES = {
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_dockerhub_token",
            "# Zugang zum Docker Hub für den Release-Job\nDOCKERHUB_USERNAME=acmebuild\n"
            "DOCKERHUB_TOKEN=<<secret:0>>\n",
            "dockerhub_pat", 17101, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_dockerhub_token",
            "      - name: Log in to Docker Hub\n        run: echo \"<<secret:0>>\" | "
            "docker login -u acme --password-stdin\n",
            "dockerhub_org_token", 17102, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_pypi_token",
            "# ~/.pypirc für den Paket-Upload\n[pypi]\nusername = __token__\npassword = <<secret:0>>\n",
            "pypi_upload_token", 17103, carrier="ini",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_pypi_token",
            "$ TWINE_USERNAME=__token__ TWINE_PASSWORD=<<secret:0>> twine upload dist/*\n",
            "pypi_upload_token", 17104, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_pypi_token",
            "[testpypi]\nrepository = https://test.pypi.org/legacy/\nusername = __token__\n"
            "password = <<secret:0>>\n",
            "pypi_test_upload_token", 17105, carrier="ini",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_rubygems_token",
            "# ~/.gem/credentials\n---\n:rubygems_api_key: <<secret:0>>\n",
            "rubygems_api_key", 17106, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_rubygems_token",
            "      - run: gem push pkg/*.gem\n        env:\n          GEM_HOST_API_KEY: <<secret:0>>\n",
            "rubygems_api_key", 17107, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_cratesio_token",
            "# ~/.cargo/credentials.toml, nur auf dem Release-Server\n[registry]\ntoken = \"<<secret:0>>\"\n",
            "cratesio_api_token", 17108, carrier="toml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_cratesio_token",
            "$ cargo login <<secret:0>>\n       Login token for `crates-io` saved\n",
            "cratesio_api_token", 17109, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_packagist_token",
            "{\n    \"http-basic\": {\n        \"repo.packagist.com\": {\n            \"username\": \"token\",\n"
            "            \"password\": \"<<secret:0>>\"\n        }\n    }\n}\n",
            "packagist_org_token", 17110, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_packagist_token",
            "$ composer config --global --auth http-basic.repo.packagist.com token <<secret:0>>\n",
            "packagist_user_token", 17111, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_jfrog_token",
            "2026-10-27T08:12:44Z WARN artifactory: Upload mit API-Key <<secret:0>> abgelehnt (403)\n",
            "artifactory_api_key", 17112, carrier="log",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_jfrog_token",
            "GET /artifactory/api/repositories HTTP/1.1\nHost: acme.jfrog.io\n"
            "Authorization: Bearer <<secret:0>>\n",
            "artifactory_reference_token", 17113, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_terraform_cloud_token",
            "# ~/.terraformrc für den Build-Agenten\ncredentials \"app.terraform.io\" {\n"
            "  token = \"<<secret:0>>\"\n}\n",
            "terraform_cloud_token", 17114, carrier="hcl",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_terraform_cloud_token",
            "TF_TOKEN_app_terraform_io=<<secret:0>>\nTF_WORKSPACE=prod-eu\n",
            "terraform_cloud_token", 17115, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_pulumi_token",
            "Hallo Team,\n\ndas Pulumi-Token für den Stack prod lautet <<secret:0>>\n\n"
            "Bitte nach dem Rollout rotieren.\n",
            "pulumi_access_token", 17116, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_pulumi_token",
            "env:\n  PULUMI_ACCESS_TOKEN: <<secret:0>>\n  PULUMI_STACK: acme/prod\n",
            "pulumi_access_token", 17117, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_vault_token",
            "# Anmeldung am Tresor vor dem Deploy\n$ vault login <<secret:0>>\n",
            "vault_service_token", 17118, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_vault_token",
            "GET /v1/secret/data/payments HTTP/1.1\nHost: vault.example.com\n"
            "X-Vault-Token: <<secret:0>>\n",
            "vault_batch_token", 17119, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_vault_legacy_token",
            "# Vault (alter Cluster, 1.8)\nVAULT_ADDR=https://vault.example.com:8200\nVAULT_TOKEN=<<secret:0>>\n",
            "vault_legacy_service_token", 17120, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_vault_legacy_token",
            "Hi Sam,\n\nthe Vault root token from the old cluster is still <<secret:0>>\n\n"
            "Please revoke it after the migration.\n",
            "vault_legacy_service_token", 17121, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_doppler_token",
            "services:\n  api:\n    environment:\n      # Service-Token der Konfiguration prd\n"
            "      DOPPLER_TOKEN: <<secret:0>>\n",
            "doppler_service_token", 17122, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_doppler_token",
            "$ doppler secrets download --no-file --format env --token <<secret:0>>\n",
            "doppler_cli_token", 17123, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_doppler_token",
            "{\"doppler\": {\"project\": \"billing\", \"token\": \"<<secret:0>>\"}}\n",
            "doppler_personal_token", 17124, carrier="json",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_dockerhub_token",
            "2026-10-27 08:12:44 WARN login: verworfener Wert <<secret:0>> (26 Zeichen)\n",
            "dockerhub_pat_short", 17131, "dckr_pat_ shape with 26 instead of 27 characters", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_pypi_token",
            "2026-10-27 08:12:44 WARN upload: abgeschnittener Wert <<secret:0>>\n",
            "pypi_upload_token_truncated", 17132, "pypi- shape cut after the macaroon location", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_rubygems_token",
            "RubyGems-API-Schlüssel beginnen mit rubygems_ und haben 48 Hex-Ziffern.",
            "documented prefix without a value", carrier="prose",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_cratesio_token",
            "2026-10-27 08:12:44 WARN publish: verworfener Wert <<secret:0>> (31 Zeichen)\n",
            "cratesio_api_token_short", 17133, "cio shape with 31 instead of 32 characters", carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_packagist_token",
            "{\"http-basic\": {\"repo.packagist.com\": {\"username\": \"token\", \"password\": \"<<secret:0>>\"}}}\n",
            "packagist_org_token", "deadbeef", "test value (deadbeef fill, zero checksum)", carrier="json",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_jfrog_token",
            "# Beispiel aus der Doku\nARTIFACTORY_API_KEY=<<secret:0>>\n",
            "artifactory_api_key", "BEISPIEL", "documented example value (BEISPIEL fill)", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_terraform_cloud_token",
            "credentials \"app.terraform.io\" {\n  # kommt aus dem Tresor\n  token = var.tfe_token\n}\n",
            "variable reference", carrier="hcl",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_pulumi_token",
            "2026-10-27 08:12:44 WARN pulumi: verworfener Wert <<secret:0>> (39 Ziffern)\n",
            "pulumi_access_token_short", 17134, "pul- shape with 39 instead of 40 hex digits", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_vault_token",
            "# Token kommt zur Laufzeit aus dem Agenten\nexport VAULT_TOKEN=\"$(cat /vault/secrets/token)\"\n",
            "command substitution", carrier="cli",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_vault_legacy_token",
            "2026-10-27 08:12:44 WARN vault: verworfener Wert <<secret:0>> (23 Zeichen)\n",
            "vault_legacy_service_token_short", 17135, "legacy s. shape with 23 instead of 24 characters",
            carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_doppler_token",
            "2026-10-27 08:12:44 WARN doppler: verworfener Wert <<secret:0>> (36 Zeichen)\n",
            "doppler_personal_token_short", 17136, "dp.pt. shape with 36 instead of 40 to 44 characters",
            carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_dockerhub_token",
            "# docs example\nDOCKERHUB_TOKEN=<<secret:0>>\n",
            "dockerhub_pat", "EXAMPLE", "documented example value (EXAMPLE fill)", carrier="env",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_pypi_token",
            "2026-10-27T08:12:44Z WARN twine: rejected <<secret:0>> (signature too short)\n",
            "pypi_upload_token_no_signature", 17141, "pypi- macaroon with a 31-byte signature", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_rubygems_token",
            "2026-10-27T08:12:44Z WARN gem: rejected <<secret:0>> (upper-case hex)\n",
            "rubygems_api_key_upper_hex", 17142, "rubygems_ shape with upper-case hex digits", carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_cratesio_token",
            "# test fixture\n[registry]\ntoken = \"<<secret:0>>\"\n",
            "cratesio_api_token", "TESTKEY", "test key (TESTKEY fill)", carrier="toml",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_packagist_token",
            "2026-10-27T08:12:44Z WARN composer: rejected <<secret:0>> (bad checksum)\n",
            "packagist_token_bad_crc", 17143, "packagist_ort_ shape with a wrong CRC32", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_jfrog_token",
            "      - run: jf rt upload \"dist/*.tgz\" npm-local/\n        env:\n"
            "          JFROG_CLI_API_KEY: ${{ secrets.ARTIFACTORY_API_KEY }}\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_terraform_cloud_token",
            "2026-10-27T08:12:44Z WARN tfe: rejected <<secret:0>> (59 characters after .atlasv1.)\n",
            "terraform_cloud_token_short", 17144, ".atlasv1. shape with 59 characters after the marker",
            carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_pulumi_token",
            "Pulumi access tokens start with pul- followed by 40 hex digits.",
            "documented prefix without a value", carrier="prose",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_vault_token",
            "# example from the runbook\nexport VAULT_TOKEN=<<secret:0>>\n",
            "vault_service_token", "EXAMPLE", "documented example value (EXAMPLE fill)", carrier="cli",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_vault_legacy_token",
            "2026-10-27T08:12:44Z INFO export: wrote reports.Qm7Kx2Lp9Rt4Vb8Nw3Yz6Jh1 (300 rows)\n",
            "s. token shape at the end of a file name", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_doppler_token",
            "2026-10-27T08:12:44Z WARN doppler: rejected <<secret:0>> (45 characters)\n",
            "doppler_cli_token_long", 17145, "dp.ct. shape with 45 instead of at most 44 characters",
            carrier="log",
        ),
        dc(
            "SECRET_TOKEN", "de", "dlp_vault_legacy_token",
            "2026-10-27 08:12:44 INFO cache: Eintrag <<secret:0>> nach 300 s verworfen\n",
            "vault_legacy_service_token", 17151, "s. token shape without a Vault term", carrier="log",
            mode="strict",
        ),
        dc(
            "SECRET_TOKEN", "en", "dlp_vault_legacy_token",
            "2026-10-27T08:12:44Z INFO cache: evicted <<secret:0>> after 300s\n",
            "vault_legacy_service_token", 17152, "s. token shape without a Vault term", carrier="log",
            mode="strict",
        ),
    ],
}
for _label, _rows in DLP_P05_CASES.items():
    DLP_CASES[_label].extend(_rows)


# P06: CI and hosting tokens. Provider prefixes: `dlp_azure_devops_pat` (84 alphanumerics with
# `AZDO` at positions 76 to 80), `dlp_circleci_token` (`CCIPAT_`/`CCIPRJ_`), `dlp_vercel_token`
# (`vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`), `dlp_netlify_token` (`nfp_`), `dlp_flyio_token`
# (`fo1_`), `dlp_flyio_macaroon_token` (`fm1a_`, `fm1r_`, `fm2_`), `dlp_heroku_api_key` (`HRKU-AA`), `dlp_render_api_key` (`rnd_`, only with
# Render context), `dlp_cloudflare_origin_ca_key` (`v1.0-`) and `dlp_digitalocean_token`
# (`dop_v1_`/`doo_v1_`/`dor_v1_`). Under a provider key with a credential noun: Bitbucket client
# secrets, legacy Azure DevOps PATs, legacy CircleCI tokens, Travis CI tokens, legacy Vercel and
# Netlify tokens, legacy Heroku API keys and Railway tokens (UUIDs) and Cloudflare API tokens and
# Global API Keys. Hard negatives are shapes with a wrong length or signature position,
# example/test fills, references, documented prefixes, IDs under provider keys without a
# credential noun (`HEROKU_APP_ID`, `CIRCLE_SHA1`, `RAILWAY_PROJECT_ID`) and a Render-shaped key
# without Render context.
DLP_P06_CASES = {
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_azure_devops_pat",
            "# Azure-DevOps-CLI auf dem Build-Agenten\nAZURE_DEVOPS_EXT_PAT=<<secret:0>>\n"
            "AZURE_DEVOPS_ORG=https://dev.azure.com/acme\n",
            "azure_devops_pat", 18101, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_azure_devops_pat",
            "$ git clone https://build:<<secret:0>>@dev.azure.com/acme/shop/_git/api\n"
            "Cloning into 'api'...\n",
            "azure_devops_pat", 18102, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_azure_devops_legacy_pat",
            "variables:\n  # PAT des Dienstkontos, läuft im März ab\n  AZURE_DEVOPS_EXT_PAT: <<secret:0>>\n",
            "azure_devops_legacy_pat", 18103, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_azure_devops_legacy_pat",
            "provider \"azuredevops\" {\n  org_service_url       = \"https://dev.azure.com/acme\"\n"
            "  azdo_personal_access_token = \"<<secret:0>>\"\n}\n",
            "azure_devops_legacy_pat", 18104, carrier="hcl",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_circleci_token",
            "# Persönliches CircleCI-Token für das Release-Skript\nCIRCLECI_TOKEN=<<secret:0>>\n",
            "circleci_personal_token", 18105, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_circleci_token",
            "GET /api/v2/project/gh/acme/shop/pipeline HTTP/1.1\nHost: circleci.com\n"
            "Circle-Token: <<secret:0>>\n",
            "circleci_project_token", 18106, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_circleci_legacy_token",
            "# Alter CircleCI-Zugang des Deploy-Bots\nCIRCLE_TOKEN=<<secret:0>>\nCIRCLE_PROJECT=gh/acme/shop\n",
            "circleci_legacy_token", 18107, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_circleci_legacy_token",
            "$ curl -s -H \"Circle-Token: <<secret:0>>\" https://circleci.com/api/v1.1/me\n",
            "circleci_legacy_token", 18108, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_travis_token",
            "# Zugang zur Travis-API für das Statusskript\nTRAVIS_API_TOKEN=<<secret:0>>\n",
            "travisci_access_token", 18109, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_travis_token",
            "{\n  \"ci\": {\n    \"provider\": \"travis\",\n    \"travis_token\": \"<<secret:0>>\"\n  }\n}\n",
            "travisci_access_token", 18110, carrier="json",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_azure_devops_pat",
            "2026-10-28 08:12:44 WARN azdo: verworfener Wert <<secret:0>> (Signatur an falscher Stelle)\n",
            "azure_devops_pat_shifted", 18131, "84-character shape with AZDO at positions 75 to 79", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_azure_devops_legacy_pat",
            "variables:\n  AZURE_DEVOPS_EXT_PAT: $(System.AccessToken)\n",
            "pipeline variable reference", carrier="yaml",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_circleci_token",
            "2026-10-28 08:12:44 WARN circleci: verworfener Wert <<secret:0>> (39 Hex-Ziffern)\n",
            "circleci_personal_token_short", 18132, "CCIPAT_ shape with 39 instead of 40 hex digits", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_circleci_legacy_token",
            "# vom Job gesetzt\nCIRCLE_SHA1=4f1c2e9a7b3d5f60718293a4b5c6d7e8f9012345\nCIRCLE_BUILD_NUM=4711\n",
            "commit SHA under a CircleCI key without a credential noun", carrier="env",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_travis_token",
            "# Beispiel aus der Doku\nTRAVIS_API_TOKEN=<<secret:0>>\n",
            "travisci_access_token", "BEISPIEL", "documented example value (BEISPIEL fill)", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_azure_devops_pat",
            "Azure DevOps PATs are 84 characters long and carry the signature AZDO at positions 76 to 80.",
            "documented format without a value", carrier="prose",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_azure_devops_legacy_pat",
            "2026-10-28T08:12:44Z WARN az: rejected <<secret:0>> (51 characters)\n",
            "azure_devops_legacy_pat_short", 18133, "legacy PAT shape with 51 instead of 52 characters", carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "en", "dlp_circleci_token",
            "# docs example\nCIRCLECI_TOKEN=<<secret:0>>\n",
            "circleci_personal_token", "EXAMPLE", "documented example value (EXAMPLE fill)", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_circleci_legacy_token",
            "      - run: curl -H \"Circle-Token: $CIRCLE_TOKEN\" https://circleci.com/api/v2/me\n",
            "environment reference", carrier="yaml",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_travis_token",
            "2026-10-28T08:12:44Z WARN travis: rejected <<secret:0>> (21 characters)\n",
            "travisci_access_token_short", 18134, "Travis token shape with 21 instead of 22 characters", carrier="log",
        ),
    ],
    "API_KEY": [
        ds(
            "API_KEY", "de", "dlp_bitbucket_client_secret",
            "# OAuth-Consumer für den Bitbucket-Import\nBITBUCKET_CLIENT_ID=acme-import\n"
            "BITBUCKET_CLIENT_SECRET=<<secret:0>>\n",
            "bitbucket_client_secret", 18111, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_bitbucket_client_secret",
            "importer:\n  source: bitbucket\n  bitbucket_client_id: acme-import\n"
            "  bitbucket_client_secret: \"<<secret:0>>\"\n",
            "bitbucket_client_secret", 18112, carrier="yaml",
        ),
        dn(
            "API_KEY", "de", "dlp_bitbucket_client_secret",
            "BITBUCKET_CLIENT_SECRET=${BITBUCKET_CLIENT_SECRET:?fehlt}\n",
            "environment reference", carrier="env",
        ),
        dl(
            "API_KEY", "en", "dlp_bitbucket_client_secret",
            "2026-10-28T08:12:44Z WARN oauth: rejected <<secret:0>> (63 characters)\n",
            "bitbucket_client_secret_short", 18135, "Bitbucket secret shape with 63 instead of 64 characters",
            carrier="log",
        ),
    ],
    "CLOUD_KEY": [
        ds(
            "CLOUD_KEY", "de", "dlp_vercel_token",
            "# Deploy-Token des Teams (persönlich)\nVERCEL_TOKEN=<<secret:0>>\nVERCEL_ORG_ID=team_acme\n",
            "vercel_personal_token", 18113, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_vercel_token",
            "2026-10-28T08:12:44Z DEBUG oauth: exchanged code, access_token=<<secret:0>> expires_in=3600\n",
            "vercel_app_access_token", 18114, carrier="log",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_vercel_legacy_token",
            "{\n  \"projekt\": \"shop\",\n  \"vercelToken\": \"<<secret:0>>\"\n}\n",
            "vercel_legacy_token", 18115, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_vercel_legacy_token",
            "      - run: npx vercel deploy --prod\n        env:\n          VERCEL_TOKEN: <<secret:0>>\n",
            "vercel_legacy_token", 18116, carrier="yaml",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_netlify_token",
            "$ netlify deploy --prod --dir dist --auth <<secret:0>>\nDeploy is live!\n",
            "netlify_personal_token", 18117, carrier="cli",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_netlify_token",
            "[build.environment]\n  NETLIFY_AUTH_TOKEN = \"<<secret:0>>\"\n",
            "netlify_personal_token", 18118, carrier="toml",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_netlify_legacy_token",
            "# Netlify-Zugang (altes Token)\nNETLIFY_AUTH_TOKEN=<<secret:0>>\nNETLIFY_SITE_ID=shop-prod\n",
            "netlify_access_token", 18119, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_netlify_legacy_token",
            "deploy:\n  provider: netlify\n  netlify_access_token: '<<secret:0>>'\n",
            "netlify_access_token", 18120, carrier="yaml",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_flyio_token",
            "# Fly.io Deploy-Token\nFLY_API_TOKEN=<<secret:0>>\n",
            "flyio_oauth_token", 18121, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_flyio_token",
            "$ flyctl deploy --app shop-api --access-token <<secret:0>>\n",
            "flyio_oauth_token", 18122, carrier="cli",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_flyio_macaroon_token",
            "# Deploy-Token der App (fly tokens create deploy)\nFLY_API_TOKEN=<<secret:0>>\n",
            "flyio_macaroon_token", 18148, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_flyio_macaroon_token",
            "GET /v1/apps/shop-api/machines HTTP/1.1\nHost: api.machines.dev\nAuthorization: FlyV1 <<secret:0>>\n",
            "flyio_macaroon_token", 18149, carrier="http",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_heroku_api_key",
            "Hallo Team,\n\nder neue Heroku-API-Schlüssel für die Pipeline lautet <<secret:0>>\n\n"
            "Bitte den alten widerrufen.\n",
            "heroku_api_key_v2", 18123, carrier="prose",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_heroku_api_key",
            "GET /apps HTTP/1.1\nHost: api.heroku.com\nAccept: application/vnd.heroku+json; version=3\n"
            "Authorization: Bearer <<secret:0>>\n",
            "heroku_api_key_v2", 18124, carrier="http",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_heroku_legacy_api_key",
            "# Heroku-Zugang des Deploy-Jobs\nHEROKU_API_KEY=<<secret:0>>\nHEROKU_APP_NAME=shop-prod\n",
            "heroku_api_key", 18125, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_heroku_legacy_api_key",
            "{\"deploy\": {\"heroku_api_key\": \"<<secret:0>>\", \"app\": \"shop-prod\"}}\n",
            "heroku_api_key", 18126, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_render_api_key",
            "# Render-CLI im Build-Container\nRENDER_API_KEY=<<secret:0>>\n",
            "render_api_key", 18127, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_render_api_key",
            "GET /v1/services HTTP/1.1\nHost: api.render.com\nAuthorization: Bearer <<secret:0>>\n",
            "render_api_key", 18128, carrier="http",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_railway_token",
            "# Projekt-Token für den Railway-Deploy\nRAILWAY_TOKEN=<<secret:0>>\n",
            "railway_token", 18129, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_railway_token",
            "const client = new RailwayClient({\n  railwayApiToken: \"<<secret:0>>\",\n});\n",
            "railway_token", 18130, carrier="code",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_cloudflare_api_key",
            "# DNS-Automatisierung\nCLOUDFLARE_API_TOKEN=<<secret:0>>\nCLOUDFLARE_ZONE=acme.example\n",
            "cloudflare_api_token", 18141, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_cloudflare_api_key",
            "provider \"cloudflare\" {\n  email   = \"ops@example.com\"\n"
            "  cloudflare_api_key = \"<<secret:0>>\"\n}\n",
            "cloudflare_global_api_key", 18142, carrier="hcl",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_cloudflare_origin_ca_key",
            "# Origin-CA-Schlüssel für cert-manager\nCLOUDFLARE_API_USER_SERVICE_KEY=<<secret:0>>\n",
            "cloudflare_origin_ca_key", 18143, carrier="env",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_cloudflare_origin_ca_key",
            "POST /client/v4/certificates HTTP/1.1\nHost: api.cloudflare.com\n"
            "X-Auth-User-Service-Key: <<secret:0>>\n",
            "cloudflare_origin_ca_key", 18144, carrier="http",
        ),
        ds(
            "CLOUD_KEY", "de", "dlp_digitalocean_token",
            "$ doctl auth init --context prod --access-token <<secret:0>>\n",
            "digitalocean_pat", 18145, carrier="cli",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_digitalocean_token",
            "{\"access_token\": \"<<secret:0>>\", \"token_type\": \"bearer\", \"expires_in\": 2592000}\n",
            "digitalocean_oauth_token", 18146, carrier="json",
        ),
        ds(
            "CLOUD_KEY", "en", "dlp_digitalocean_token",
            "DIGITALOCEAN_REFRESH_TOKEN=<<secret:0>>\n",
            "digitalocean_refresh_token", 18147, carrier="env",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_vercel_token",
            "2026-10-28 08:12:44 WARN vercel: verworfener Wert <<secret:0>> (55 Zeichen)\n",
            "vercel_personal_token_short", 18151, "vcp_ shape with 55 instead of 56 characters", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_vercel_legacy_token",
            "VERCEL_PROJECT_ID=prj_9Xk2Lm4Np6Qr8St0Uv2Wx4Yz\nVERCEL_ORG_ID=team_3Fh7Jk9Lm1Np3Qr5\n",
            "IDs under Vercel keys without a credential noun", carrier="env",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_netlify_token",
            "2026-10-28 08:12:44 WARN netlify: verworfener Wert <<secret:0>> (35 Zeichen)\n",
            "netlify_personal_token_short", 18152, "nfp_ shape with 35 instead of 36 characters", carrier="log",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_netlify_legacy_token",
            "# Beispiel aus der Doku\nNETLIFY_AUTH_TOKEN=<<secret:0>>\n",
            "netlify_access_token", "BEISPIEL", "documented example value (BEISPIEL fill)", carrier="env",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_flyio_token",
            "2026-10-28 08:12:44 WARN fly: verworfener Wert <<secret:0>> (42 Zeichen)\n",
            "flyio_oauth_token_short", 18153, "fo1_ shape with 42 instead of 43 characters", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_heroku_legacy_api_key",
            "# von Heroku gesetzt\nAPP_ID=3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f8a9b0c\n"
            "RELEASE_VERSION=v42\n",
            "UUID in Heroku app metadata without a credential noun", carrier="env",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_render_api_key",
            "2026-10-28 08:12:44 WARN render: verworfener Wert <<secret:0>> (20 Zeichen)\n",
            "render_api_key_short", 18154, "rnd_ shape with 20 instead of at least 24 characters", carrier="log",
        ),
        dc(
            "CLOUD_KEY", "de", "dlp_render_api_key",
            "2026-10-28 08:12:44 INFO cache: Eintrag <<secret:0>> nach 300 s verworfen\n",
            "render_api_key", 18155, "rnd_ shape without a Render term", carrier="log", mode="strict",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_railway_token",
            "RAILWAY_PROJECT_ID=3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f8a9b0c\n"
            "RAILWAY_SERVICE_ID=7a1d4c2b-6e8f-4a9b-8c3d-2e1f0a9b8c7d\n",
            "UUIDs under Railway keys without a credential noun", carrier="env",
        ),
        dl(
            "CLOUD_KEY", "de", "dlp_cloudflare_origin_ca_key",
            "2026-10-28 08:12:44 WARN cf: verworfener Wert <<secret:0>> (145 Hex-Ziffern)\n",
            "cloudflare_origin_ca_key_short", 18156, "Origin CA key shape with 145 instead of 146 hex digits",
            carrier="log",
        ),
        dx(
            "CLOUD_KEY", "de", "dlp_digitalocean_token",
            "# Beispiel aus der Doku\nDIGITALOCEAN_ACCESS_TOKEN=<<secret:0>>\n",
            "digitalocean_pat", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_vercel_token",
            "# docs example\nVERCEL_TOKEN=<<secret:0>>\n",
            "vercel_personal_token", "EXAMPLE", "documented example value (EXAMPLE fill)", carrier="env",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_vercel_legacy_token",
            "      - run: npx vercel deploy --prod --token ${{ secrets.VERCEL_TOKEN }}\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dn(
            "CLOUD_KEY", "de", "dlp_flyio_macaroon_token",
            "Fly.io-Deploy-Tokens beginnen mit FlyV1 fm2_ und einem Base64-Macaroon.",
            "documented prefix without a value", carrier="prose",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_netlify_token",
            "Netlify personal access tokens start with nfp_ followed by 36 characters.",
            "documented prefix without a value", carrier="prose",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_netlify_legacy_token",
            "2026-10-28T08:12:44Z WARN netlify: rejected <<secret:0>> (39 characters)\n",
            "netlify_access_token_short", 18157, "Netlify token shape with 39 instead of 40 to 46 characters",
            carrier="log",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_heroku_api_key",
            "2026-10-28T08:12:44Z WARN heroku: rejected <<secret:0>> (57 characters after HRKU-AA)\n",
            "heroku_api_key_v2_short", 18158, "HRKU-AA shape with 57 instead of 58 characters", carrier="log",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_heroku_legacy_api_key",
            "heroku:\n  app_id: 3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f8a9b0c\n  api_key: ${HEROKU_API_KEY}\n",
            "app UUID and environment reference", carrier="yaml",
        ),
        dc(
            "CLOUD_KEY", "en", "dlp_render_api_key",
            "2026-10-28T08:12:44Z INFO cache: evicted <<secret:0>> after 300s\n",
            "render_api_key", 18159, "rnd_ shape without a Render term", carrier="log", mode="strict",
        ),
        dx(
            "CLOUD_KEY", "en", "dlp_railway_token",
            "# docs example\nRAILWAY_TOKEN=<<secret:0>>\n",
            "railway_token", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_cloudflare_api_key",
            "2026-10-28T08:12:44Z WARN cloudflare: rejected <<secret:0>> (39 characters)\n",
            "cloudflare_api_token_short", 18160, "Cloudflare API token shape with 39 instead of 40 characters",
            carrier="log",
        ),
        dn(
            "CLOUD_KEY", "en", "dlp_cloudflare_api_key",
            "cloudflare_zone_id = \"0123456789abcdef0123456789abcdef\"\n"
            "cloudflare_account_id = \"fedcba9876543210fedcba9876543210\"\n",
            "IDs under Cloudflare keys without a credential noun", carrier="hcl",
        ),
        dl(
            "CLOUD_KEY", "en", "dlp_digitalocean_token",
            "2026-10-28T08:12:44Z WARN doctl: rejected <<secret:0>> (63 hex digits)\n",
            "digitalocean_pat_short", 18161, "dop_v1_ shape with 63 instead of 64 hex digits", carrier="log",
        ),
    ],
}
for _label, _rows in DLP_P06_CASES.items():
    DLP_CASES[_label].extend(_rows)


# P07: observability tokens. Provider prefixes and shapes: `dlp_newrelic_user_api_key` (`NRAK-`),
# `dlp_newrelic_insert_key` (`NRII-`), `dlp_newrelic_license_key` (32 hex digits or `eu01xx` and 26,
# then `FFFFNRAL`), `dlp_sentry_user_token` (`sntryu_`), `dlp_sentry_org_token` (`sntrys_` and a base64
# JSON payload with `iat`), `dlp_grafana_api_key` (base64 of `{"k","n","id"}`),
# `dlp_grafana_cloud_token` (`glc_` and a base64 JSON object), `dlp_grafana_service_account_token`
# (`glsa_` with a little-endian CRC32) and `dlp_dynatrace_token` (`dt0c01`/`dt0s…`). Under a provider
# key with a credential noun or after a provider header: Datadog API and application keys, New Relic
# license keys without the suffix, legacy Sentry auth tokens, Splunk HEC tokens
# (`Authorization: Splunk`), Elasticsearch API keys (`Authorization: ApiKey`), Honeycomb keys
# (`x-honeycomb-team`) and PagerDuty keys. The secret key of a legacy Sentry DSN is a finding. Hard
# negatives are lookalikes (wrong length, checksum or decoded structure), example/test fills,
# references, documented formats, IDs under provider keys without a credential noun (`DD_TRACE_ID`,
# `SENTRY_RELEASE`, `PAGERDUTY_SERVICE_ID`), the public Datadog client token and a DSN with the public
# key only.
DSN_PUBLIC_KEY = "3f9c1e7a2b4d4c6e8a0b1c2d3e4f5a6b"
DLP_P07_CASES = {
    "SECRET_TOKEN": [
        ds(
            "SECRET_TOKEN", "de", "dlp_sentry_user_token",
            "# Token für Release-Uploads (sentry-cli)\nSENTRY_AUTH_TOKEN=<<secret:0>>\nSENTRY_ORG=acme\n",
            "sentry_user_token", 18213, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_sentry_user_token",
            "$ sentry-cli --auth-token <<secret:0>> releases new 2026.10.29\n",
            "sentry_user_token", 18214, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_sentry_org_token",
            "# .sentryclirc des Build-Servers\n[auth]\ntoken=<<secret:0>>\n",
            "sentry_org_token", 18215, carrier="toml",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_sentry_org_token",
            "      - uses: getsentry/action-release@v1\n        env:\n          SENTRY_AUTH_TOKEN: <<secret:0>>\n",
            "sentry_org_token", 18216, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_sentry_auth_token",
            "{\n  \"sentry\": {\n    \"sentryAuthToken\": \"<<secret:0>>\",\n    \"org\": \"acme\"\n  }\n}\n",
            "sentry_auth_token", 18217, carrier="json",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_sentry_auth_token",
            "# legacy integration token\nSENTRY_AUTH_TOKEN=<<secret:0>>\n",
            "sentry_auth_token", 18218, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_grafana_api_key",
            "# Alter API-Schlüssel für das Provisioning\nGRAFANA_API_KEY=<<secret:0>>\n",
            "grafana_api_key", 18221, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_grafana_api_key",
            "GET /api/dashboards/uid/ops HTTP/1.1\nHost: grafana.example.com\nAuthorization: Bearer <<secret:0>>\n",
            "grafana_api_key", 18222, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_grafana_cloud_token",
            "Hallo Team,\n\nder Grafana-Cloud-Token für Prometheus-Remote-Write lautet <<secret:0>>\n\n"
            "Bitte nur im Tresor ablegen.\n",
            "grafana_cloud_token", 18223, carrier="prose",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_grafana_cloud_token",
            "remote_write:\n  - url: https://prometheus-prod-24-prod-eu-west-2.grafana.net/api/prom/push\n"
            "    basic_auth:\n      username: \"1234567\"\n      password: <<secret:0>>\n",
            "grafana_cloud_token", 18224, carrier="yaml",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_grafana_service_account_token",
            "$ curl -H \"Authorization: Bearer <<secret:0>>\" https://grafana.example.de/api/search\n",
            "grafana_service_account_token", 18225, carrier="cli",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_grafana_service_account_token",
            "provider \"grafana\" {\n  url  = \"https://grafana.example.com\"\n  auth = \"<<secret:0>>\"\n}\n",
            "grafana_service_account_token", 18226, carrier="hcl",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_dynatrace_token",
            "# OneAgent-Operator\nDT_API_TOKEN=<<secret:0>>\nDT_ENV_URL=https://abc12345.live.dynatrace.com\n",
            "dynatrace_api_token", 18227, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_dynatrace_token",
            "GET /api/v2/metrics HTTP/1.1\nHost: abc12345.live.dynatrace.com\nAuthorization: Api-Token <<secret:0>>\n",
            "dynatrace_platform_token", 18228, carrier="http",
        ),
        ds(
            "SECRET_TOKEN", "de", "dlp_splunk_hec_token",
            "# HEC-Ausgabe des Log-Shippers\nSPLUNK_HEC_TOKEN=<<secret:0>>\nSPLUNK_HEC_URL=https://splunk.example.de:8088\n",
            "splunk_hec_token", 18229, carrier="env",
        ),
        ds(
            "SECRET_TOKEN", "en", "dlp_splunk_hec_token",
            "$ curl -k https://splunk.example.com:8088/services/collector/event \\\n"
            "    -H \"Authorization: Splunk <<secret:0>>\" -d '{\"event\": \"deploy finished\"}'\n",
            "splunk_hec_token", 18230, carrier="cli",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_sentry_org_token",
            "2026-10-29 08:12:44 WARN sentry-cli: verworfener Wert <<secret:0>> (kein iat)\n",
            "sentry_org_token_no_iat", 18254, "sntrys_ shape whose payload has no iat", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_grafana_service_account_token",
            "2026-10-29 08:12:44 WARN grafana: verworfener Wert <<secret:0>> (Prüfsumme falsch)\n",
            "grafana_service_account_token_bad_crc", 18255, "glsa_ shape with a wrong CRC32", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "de", "dlp_grafana_api_key",
            "2026-10-29 08:12:44 WARN grafana: verworfener Wert <<secret:0>> (kein JSON)\n",
            "grafana_api_key_unterminated", 18256, "eyJrIjoi shape with an unterminated JSON payload", carrier="log",
        ),
        dx(
            "SECRET_TOKEN", "de", "dlp_dynatrace_token",
            "# Beispiel aus der Doku\nDT_API_TOKEN=<<secret:0>>\n",
            "dynatrace_api_token", "EXAMPLE", "documented example value (EXAMPLE fill)", carrier="env",
        ),
        dn(
            "SECRET_TOKEN", "de", "dlp_splunk_hec_token",
            "SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN:?fehlt}\nSPLUNK_INDEX_ID=3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f8a9b0c\n",
            "environment reference and an index ID without a credential noun", carrier="env",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_sentry_user_token",
            "2026-10-29T08:12:44Z WARN sentry-cli: rejected <<secret:0>> (63 hex digits)\n",
            "sentry_user_token_short", 18260, "sntryu_ shape with 63 instead of 64 hex digits", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_sentry_auth_token",
            "SENTRY_RELEASE=4f1c2e9a7b3d5f60718293a4b5c6d7e8f9012345\nSENTRY_ENVIRONMENT=production\n",
            "release commit SHA under a Sentry key without a credential noun", carrier="env",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_grafana_cloud_token",
            "2026-10-29T08:12:44Z WARN agent: rejected <<secret:0>> (not a JSON token)\n",
            "grafana_cloud_token_random", 18261, "glc_ shape whose base64 decodes to no JSON object", carrier="log",
        ),
        dn(
            "SECRET_TOKEN", "en", "dlp_grafana_service_account_token",
            "Grafana service account tokens start with glsa_ followed by 32 characters and a checksum.",
            "documented prefix without a value", carrier="prose",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_dynatrace_token",
            "2026-10-29T08:12:44Z WARN oneagent: rejected <<secret:0>> (63-character secret)\n",
            "dynatrace_api_token_short", 18262, "dt0c01. token with a 63-character secret portion", carrier="log",
        ),
        dl(
            "SECRET_TOKEN", "en", "dlp_splunk_hec_token",
            "2026-10-29T08:12:44Z WARN hec: rejected token <<secret:0>> (malformed GUID)\n",
            "splunk_hec_token_short", 18263, "GUID-shaped HEC token with 11 digits in the last group", carrier="log",
        ),
    ],
    "API_KEY": [
        ds(
            "API_KEY", "de", "dlp_datadog_api_key",
            "# Datadog-Agent im Container\nDD_API_KEY=<<secret:0>>\nDD_SITE=datadoghq.eu\n",
            "datadog_api_key", 18201, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_datadog_api_key",
            "$ curl -X GET https://api.datadoghq.com/api/v1/monitor \\\n"
            "    -H \"DD-API-KEY: ${DD_API_KEY}\" \\\n    -H \"DD-APPLICATION-KEY: <<secret:0>>\"\n",
            "datadog_app_key", 18202, carrier="cli",
        ),
        ds(
            "API_KEY", "de", "dlp_datadog_api_key",
            "datadog:\n  # Anwendungsschlüssel für das Dashboard-Skript\n  datadog_app_key: \"<<secret:0>>\"\n",
            "datadog_app_key", 18203, carrier="yaml",
        ),
        ds(
            "API_KEY", "en", "dlp_datadog_api_key",
            "const tracer = initTracer({\n  service: \"checkout\",\n  ddApiKey: \"<<secret:0>>\",\n});\n",
            "datadog_api_key", 18204, carrier="code",
        ),
        ds(
            "API_KEY", "de", "dlp_newrelic_user_api_key",
            "# New-Relic-NerdGraph für das Reporting\nNEW_RELIC_API_KEY=<<secret:0>>\nNEW_RELIC_ACCOUNT_ID=3141592\n",
            "newrelic_user_api_key", 18205, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_newrelic_user_api_key",
            "POST /graphql HTTP/1.1\nHost: api.eu.newrelic.com\nContent-Type: application/json\n"
            "API-Key: <<secret:0>>\n",
            "newrelic_user_api_key", 18206, carrier="http",
        ),
        ds(
            "API_KEY", "de", "dlp_newrelic_insert_key",
            "{\n  \"exporter\": \"newrelic\",\n  \"insertKey\": \"<<secret:0>>\"\n}\n",
            "newrelic_insert_key", 18207, carrier="json",
        ),
        ds(
            "API_KEY", "en", "dlp_newrelic_insert_key",
            "2026-10-29T08:12:44Z DEBUG nr-exporter: posting 42 events with X-Insert-Key: <<secret:0>>\n",
            "newrelic_insert_key", 18208, carrier="log",
        ),
        ds(
            "API_KEY", "de", "dlp_newrelic_license_key",
            "common: &default_settings\n  # Lizenzschlüssel des Kontos\n  license_key: '<<secret:0>>'\n"
            "  app_name: Shop (Produktion)\n",
            "newrelic_license_key", 18209, carrier="yaml",
        ),
        ds(
            "API_KEY", "en", "dlp_newrelic_license_key",
            "$ docker run -d -e NRIA_LICENSE_KEY=<<secret:0>> newrelic/infrastructure:latest\n",
            "newrelic_license_key_eu", 18210, carrier="cli",
        ),
        ds(
            "API_KEY", "de", "dlp_newrelic_legacy_license_key",
            "# Alter New-Relic-Lizenzschlüssel\nNEW_RELIC_LICENSE_KEY=<<secret:0>>\nNEW_RELIC_APP_NAME=shop\n",
            "newrelic_legacy_license_key", 18211, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_newrelic_legacy_license_key",
            "[newrelic]\nnewrelic.license_key = \"<<secret:0>>\"\nnewrelic.appname = \"billing\"\n",
            "newrelic_legacy_license_key", 18212, carrier="toml",
        ),
        ds(
            "API_KEY", "de", "dlp_sentry_dsn_secret",
            f"# Alter DSN mit Secret Key (vor Sentry 9)\nSENTRY_DSN=https://{DSN_PUBLIC_KEY}:<<secret:0>>@sentry.intern.example.de/12\n",
            "sentry_dsn_secret_key", 18219, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_sentry_dsn_secret",
            f"import sentry_sdk\n\nsentry_sdk.init(\n    dsn=\"https://{DSN_PUBLIC_KEY}:<<secret:0>>@o450123.ingest.sentry.io/5512345\",\n)\n",
            "sentry_dsn_secret_key", 18220, carrier="code",
        ),
        ds(
            "API_KEY", "de", "dlp_elastic_api_key",
            "output.elasticsearch:\n  hosts: [\"https://es.example.de:9200\"]\n  # API-Schlüssel id:api_key\n"
            "  elasticsearch.api_key: \"<<secret:0>>\"\n",
            "elastic_api_key_pair", 18231, carrier="yaml",
        ),
        ds(
            "API_KEY", "en", "dlp_elastic_api_key",
            "const client = new Client({\n  node: \"https://es.example.com:9200\",\n"
            "  headers: { Authorization: \"ApiKey <<secret:0>>\" },\n});\n",
            "elastic_api_key", 18232, carrier="code",
        ),
        ds(
            "API_KEY", "en", "dlp_elastic_api_key",
            "ELASTIC_API_KEY=<<secret:0>>\nELASTIC_URL=https://es.example.com:9200\n",
            "elastic_api_key", 18233, carrier="env",
        ),
        ds(
            "API_KEY", "de", "dlp_honeycomb_api_key",
            "# OpenTelemetry-Export zu Honeycomb\nOTEL_EXPORTER_OTLP_ENDPOINT=https://api.eu1.honeycomb.io\n"
            "OTEL_EXPORTER_OTLP_HEADERS=\"x-honeycomb-team=<<secret:0>>\"\n",
            "honeycomb_api_key", 18234, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_honeycomb_api_key",
            "beeline.init({\n  writeKey: process.env.HC_KEY,\n  honeycombApiKey: \"<<secret:0>>\",\n});\n",
            "honeycomb_classic_key", 18235, carrier="code",
        ),
        ds(
            "API_KEY", "de", "dlp_pagerduty_api_key",
            "# Alarmierung über die Events API v2\nPAGERDUTY_ROUTING_KEY=<<secret:0>>\n",
            "pagerduty_integration_key", 18236, carrier="env",
        ),
        ds(
            "API_KEY", "en", "dlp_pagerduty_api_key",
            "$ curl -H \"Authorization: Token token=<<secret:0>>\" -H \"Accept: application/json\" "
            "https://api.pagerduty.com/incidents\n",
            "pagerduty_api_key", 18237, carrier="cli",
        ),
        ds(
            "API_KEY", "de", "dlp_pagerduty_api_key",
            "pagerduty:\n  # Benutzer-Token des On-Call-Bots\n  pagerduty_token: \"<<secret:0>>\"\n",
            "pagerduty_user_token", 18238, carrier="yaml",
        ),
        dl(
            "API_KEY", "de", "dlp_datadog_api_key",
            "2026-10-29 08:12:44 WARN dd-agent: verworfener Wert <<secret:0>> (31 Hex-Ziffern)\n",
            "datadog_api_key_short", 18251, "Datadog key shape with 31 instead of 32 hex digits", carrier="log",
        ),
        dl(
            "API_KEY", "de", "dlp_datadog_api_key",
            "window.DD_RUM.init({\n  clientToken: '<<secret:0>>',\n  site: 'datadoghq.eu',\n});\n",
            "datadog_client_token", 18252, "public Datadog client token (pub + 32 hex) for browser SDKs",
            carrier="code",
        ),
        dn(
            "API_KEY", "de", "dlp_datadog_api_key",
            "# vom Tracer gesetzt\nDD_TRACE_ID=4f1c2e9a7b3d5f60718293a4b5c6d7e8\nDD_ENV=produktion\n",
            "trace ID under a Datadog key without a credential noun", carrier="env",
        ),
        dl(
            "API_KEY", "de", "dlp_newrelic_user_api_key",
            "2026-10-29 08:12:44 WARN nerdgraph: verworfener Wert <<secret:0>> (26 Zeichen)\n",
            "newrelic_user_api_key_short", 18253, "NRAK- shape with 26 instead of 27 characters", carrier="log",
        ),
        dx(
            "API_KEY", "de", "dlp_newrelic_license_key",
            "# Beispiel aus der Doku\nNEW_RELIC_LICENSE_KEY=<<secret:0>>\n",
            "newrelic_license_key", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dn(
            "API_KEY", "de", "dlp_sentry_dsn_secret",
            f"# DSN ohne Secret Key, laut Sentry öffentlich\nSENTRY_DSN=https://{DSN_PUBLIC_KEY}@o450123.ingest.sentry.io/5512345\n",
            "DSN with the public key only", carrier="env",
        ),
        dl(
            "API_KEY", "de", "dlp_honeycomb_api_key",
            "2026-10-29 08:12:44 WARN otel: verworfener Wert <<secret:0>> (21 Zeichen)\n",
            "honeycomb_api_key_short", 18257, "Honeycomb key shape with 21 instead of 22 characters", carrier="log",
        ),
        dn(
            "API_KEY", "de", "dlp_pagerduty_api_key",
            "pagerduty:\n  service_id: PX7QK2M\n  escalation_policy_id: P9ZQ3RT\n",
            "PagerDuty IDs without a credential noun", carrier="yaml",
        ),
        dx(
            "API_KEY", "en", "dlp_datadog_api_key",
            "# docs example\nDD_API_KEY=<<secret:0>>\n",
            "datadog_api_key", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dn(
            "API_KEY", "en", "dlp_datadog_api_key",
            "      - run: datadog-ci sourcemaps upload ./dist\n        env:\n"
            "          DATADOG_API_KEY: ${{ secrets.DATADOG_API_KEY }}\n",
            "GitHub Actions secret reference", carrier="yaml",
        ),
        dl(
            "API_KEY", "en", "dlp_newrelic_insert_key",
            "2026-10-29T08:12:44Z WARN nr-exporter: rejected <<secret:0>> (31 characters)\n",
            "newrelic_insert_key_short", 18258, "NRII- shape with 31 characters", carrier="log",
        ),
        dl(
            "API_KEY", "en", "dlp_newrelic_license_key",
            "2026-10-29T08:12:44Z WARN infra-agent: rejected <<secret:0>> (39 characters)\n",
            "newrelic_license_key_short", 18259, "license key shape with 31 hex digits before FFFFNRAL", carrier="log",
        ),
        dn(
            "API_KEY", "en", "dlp_newrelic_legacy_license_key",
            "NEW_RELIC_APP_ID=4f1c2e9a7b3d5f60718293a4b5c6d7e8f9012345\nNEW_RELIC_ACCOUNT_ID=3141592\n",
            "IDs under New Relic keys without a credential noun", carrier="env",
        ),
        dl(
            "API_KEY", "en", "dlp_elastic_api_key",
            "2026-10-29T08:12:44Z WARN es-client: rejected ApiKey value <<secret:0>>\n",
            "elastic_api_key_short", 18264, "base64 of id:api_key with a 21-character api_key", carrier="log",
        ),
        dx(
            "API_KEY", "en", "dlp_honeycomb_api_key",
            "# docs example\nHONEYCOMB_API_KEY=<<secret:0>>\n",
            "honeycomb_classic_key", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dl(
            "API_KEY", "en", "dlp_pagerduty_api_key",
            "2026-10-29T08:12:44Z WARN pd-client: rejected <<secret:0>> (19 characters)\n",
            "pagerduty_api_key_short", 18265, "PagerDuty key shape with 19 instead of 20 characters", carrier="log",
        ),
        dn(
            "API_KEY", "en", "dlp_pagerduty_api_key",
            "curl -H \"Authorization: Token token=$PAGERDUTY_TOKEN\" https://api.pagerduty.com/users\n",
            "environment reference in the Token scheme", carrier="cli",
        ),
    ],
}
for _label, _rows in DLP_P07_CASES.items():
    DLP_CASES[_label].extend(_rows)

# T18: providers without an ARK rule (GOLD-D2 baseline entities) issue values with a hex, digit or
# base62 run next to a short prefix or suffix (`SK…`, `…-us10`, `shippo_live_…`, dash-separated
# hex groups). The generic rules apply the fixed-format repetition check to that run, so
# documented example and test fills are hard negatives even without example context; the same
# shapes with a random run stay findings. Fills are recipes, as for T06.
DLP_T18_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Telefonie (Hotline)\nTWILIO_REGION=de1\nTWILIO_API_KEY=<<secret:0>>\n",
            "twilio_api_key", 18101, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "newsletter:\n  liste: kunden-de\n  api_key: <<secret:0>>\n",
            "mailchimp_api_key", 18102, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\n  \"versand\": {\n    \"anbieter\": \"shippo\",\n    \"api_token\": \"<<secret:0>>\"\n  }\n}\n",
            "shippo_live_token", 18103, carrier="json",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "$ export DATABRICKS_TOKEN=<<secret:0>>\n$ databricks clusters list\n",
            "databricks_api_token", 18104, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Hallo Team, für Sonar gilt ab heute: der API-Schlüssel ist <<secret:0>> – bitte im Tresor ablegen.",
            "sonar_user_token", 18105, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "MAILGUN_DOMAIN=mg.example.com\nMAILGUN_API_KEY=<<secret:0>>\n",
            "mailgun_private_api_key", 18106, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "[sonar]\nhost = \"https://sonar.internal\"\ntoken = \"<<secret:0>>\"\n",
            "sonar_project_token", 18107, carrier="toml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "2026-10-29T08:14:02Z DEBUG deploy: publishing with api_key=<<secret:0>>\n",
            "clojars_deploy_token", 18108, carrier="log",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "deploy:\n  stage: release\n  variables:\n    SRC_ACCESS_TOKEN: <<secret:0>>\n",
            "sourcegraph_local_access_token", 18109, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "client = Client(\n    api_key=\"<<secret:0>>\",\n)\n",
            "twilio_api_key", 18110, carrier="code",
        ),
        dx(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "# Telefonie (Hotline)\nTWILIO_REGION=de1\nTWILIO_API_KEY=<<secret:0>>\n",
            "twilio_api_key", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dx(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "newsletter:\n  liste: kunden-de\n  api_key: <<secret:0>>\n",
            "mailchimp_api_key", "1234567890", "test value (1234567890 fill)", carrier="yaml",
        ),
        dx(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "{\n  \"versand\": {\n    \"anbieter\": \"shippo\",\n    \"api_token\": \"<<secret:0>>\"\n  }\n}\n",
            "shippo_live_token", "deadbeef", "test value (deadbeef fill)", carrier="json",
        ),
        dx(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "$ export DATABRICKS_TOKEN=<<secret:0>>\n$ databricks clusters list\n",
            "databricks_api_token", "0123456789", "test value (0123456789 fill)", carrier="cli",
        ),
        dx(
            "CREDENTIAL", "de", "dlp_generic_credential_assignment",
            "Hallo Team, für Sonar gilt ab heute: der API-Schlüssel ist <<secret:0>> – bitte im Tresor ablegen.",
            "sonar_user_token", "1234567890", "test value (1234567890 fill)", carrier="prose",
        ),
        dx(
            "CREDENTIAL", "de", "dlp_env_var_secret",
            "MAILGUN_API_KEY=<<secret:0>>\n",
            "mailgun_private_api_key", "0123456789", "test value (0123456789 fill)", carrier="env",
        ),
        dx(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "MAILGUN_DOMAIN=mg.example.com\nMAILGUN_API_KEY=<<secret:0>>\n",
            "mailgun_private_api_key", "deadbeef", "test value (deadbeef fill)", carrier="env",
        ),
        dx(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "[sonar]\nhost = \"https://sonar.internal\"\ntoken = \"<<secret:0>>\"\n",
            "sonar_project_token", "1234567890", "test value (1234567890 fill)", carrier="toml",
        ),
        dx(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "2026-10-29T08:14:02Z DEBUG deploy: publishing with api_key=<<secret:0>>\n",
            "clojars_deploy_token", "deadbeef", "test value (deadbeef fill)", carrier="log",
        ),
        dx(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "deploy:\n  stage: release\n  variables:\n    SRC_ACCESS_TOKEN: <<secret:0>>\n",
            "sourcegraph_local_access_token", "1234567890", "test value (1234567890 fill)", carrier="yaml",
        ),
        dx(
            "CREDENTIAL", "en", "dlp_generic_credential_assignment",
            "client = Client(\n    api_key=\"<<secret:0>>\",\n)\n",
            "twilio_api_key", "0123456789", "test value (0123456789 fill)", carrier="code",
        ),
        dx(
            "CREDENTIAL", "en", "dlp_env_var_secret",
            "SLACK_APP_TOKEN=<<secret:0>>\n",
            "slack_app_token", "1234567890", "test value (1234567890 fill)", carrier="env",
        ),
    ],
}
for _label, _rows in DLP_T18_CASES.items():
    DLP_CASES[_label].extend(_rows)


# G-PROSE (G06): chats, tickets and mails hand a value over after the credential noun, at the end
# of a line up to one line further: `dlp_prose_password` for password nouns (Passwort, Kennwort,
# Zugangsdaten, passphrase), `dlp_prose_secret` for secret and token nouns (client secret,
# Dienst-Secret, CSRF token). The value must look chosen or issued; words, references,
# placeholders, examples, hashes and the noun in encyclopedia or law prose are no secrets.
DLP_GPROSE_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_prose_password",
            "[08:15] lena.s: Wie lautet das Datenbank-Passwort für die Testumgebung?\n"
            "[08:17] daniel.r: <<secret:0>>\n[08:17] daniel.r: Bitte nur lokal verwenden.\n",
            "password", 12001, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_prose_password",
            "Hallo zusammen,\n\nanbei die Zugangsdaten für den Abschlusslauf (Kennwort):\n\n<<secret:0>>\n\n"
            "Bitte nach dem Lauf löschen.\n",
            "password", 12002, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_prose_password",
            "Ticket #4711: Login schlägt fehl. Laut Konfiguration hinterlegt (Datenbank-Passwort): <<secret:0>>\n",
            "password", 12003, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_prose_password",
            "Hi Jonas, hier deine Zugangsdaten für das Testsystem: pruefer / <<secret:0>>\n",
            "password", 12004, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_prose_secret",
            "Laut Konfiguration hinterlegt (Client-Secret): <<secret:0>>\nBitte prüfen, ob der Wert noch gilt.\n",
            "generic_api_secret", 12005, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_prose_secret",
            "[09:01] mia: hat jemand das Dienst-Secret für Staging?\n[09:02] ole: klar:\n<<secret:0>>\n",
            "password", 12006, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_prose_password",
            "[09:41] maria.k: anyone have the database password for the staging box?\n"
            "[09:43] tom.w: here you go: <<secret:0>>\n[09:43] tom.w: please don't paste it anywhere else\n",
            "password", 12011, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_prose_password",
            "Hi team,\n\nas discussed, here is the database password for the reporting job:\n\n<<secret:0>>\n\n"
            "Thanks,\nAlex\n",
            "password", 12012, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_prose_password",
            "Note from reporter: the job still uses the old password. Current value in the config: <<secret:0>>\n",
            "password", 12013, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_prose_password",
            "Your login credentials for the test portal: tester / <<secret:0>>\n",
            "password", 12014, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_prose_secret",
            "Hi team,\n\nhere is the client secret for the reporting job:\n\n<<secret:0>>\n\nThanks,\nAlex\n",
            "generic_api_secret", 12015, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_prose_secret",
            "Note from reporter: the job still uses the old CSRF token. Current value in the config: <<secret:0>>\n",
            "csrf_token", 12016, carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_prose_password",
            "Ein Passwort ist eine Zeichenfolge zur Authentifizierung.\nSiehe auch: Passwortmanager\n",
            "encyclopedia prose about passwords (no value)", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_prose_password",
            "§ 5 Abs. 2: Das Kennwort ist geheim zu halten und nach Kenntnis Dritter zu ändern.\n"
            "Fundstelle: BGBl.2024-I-117\n",
            "law prose about passwords (no value)", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_prose_password",
            "[08:15] lena.s: Wie lautet das Datenbank-Passwort?\n[08:17] daniel.r: steht als $DB_PASSWORD in der .env\n",
            "environment reference instead of a value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_prose_password",
            "Laut Konfiguration hinterlegt (Passwort-Hash): 5f4dcc3b5aa765d61d8327deb882cf99\n",
            "password hash, not a password", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_prose_secret",
            "anbei die Zugangsdaten (Client-Secret):\n\nYOUR_CLIENT_SECRET_HERE\n",
            "placeholder", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_prose_password",
            "Passwort vergessen? Kontakt:\nservicedesk@example.de\n",
            "e-mail address after a password mention", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_prose_password",
            "A password is a secret string of characters used to confirm a user's identity.\n"
            "ISBN: 978-0-13-468599-1\n",
            "encyclopedia prose with a reference number", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_prose_password",
            "Section 3(b): the password shall be changed every 90 days.\nEffective date: 2024-07-01\n",
            "law prose with a date", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_prose_password",
            "[09:41] maria.k: anyone have the database password?\n[09:43] tom.w: here you go: changeme\n",
            "placeholder password", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_prose_secret",
            "Hi team,\n\nhere is the client secret for the reporting job:\n\n"
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
            "documented example value", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_prose_password",
            "Forgot your password? See the guide:\nhttps://example.com/help/reset-password\n",
            "URL after a password mention", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_prose_secret",
            "The client secret rotates nightly; the job reads it from:\n${CLIENT_SECRET}\n",
            "template reference", carrier="prose",
        ),
    ],
}
for _label, _rows in DLP_GPROSE_CASES.items():
    DLP_CASES[_label].extend(_rows)

# Q-DLP-PW: a chosen password whose letter runs, dots and `~` read like a member access
# (`Name.Abc~…`, `a.Bcdefg.hij42`) is a value of `dlp_password_assignment`; only a member access
# that code can end (end of value, `;`, `,`, `)`, an operator) is code. Hard negatives: member
# access chains, PHP property chains, environment references and documented example values.
DLP_Q_DLP_PW_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# .env Versand-Worker (aus .env.example kopiert)\nVERSAND_QUEUE=belege\nVERSAND_DB_PASSWORT=<<secret:0>>\nSENTRY_ENVIRONMENT=staging\n",
            "dotted_tilde_password", 6801, carrier="env",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "[abgleich]\nbasis_url = \"https://api.example.de/v2\"\ndb_passwort = \"<<secret:0>>\"\n",
            "dotted_digit_password", 6802, carrier="toml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "lager:\n  datenbank:\n    host: db.lager.intern\n    passwort: <<secret:0>>\n",
            "dotted_tilde_password", 6803, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "// Zugang zum Import-Endpunkt\nconst DB_KENNWORT: &str = \"<<secret:0>>\";\n",
            "dotted_digit_password", 6804, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "lager.datenbank.url=jdbc:postgresql://db.lager.intern/lager\nlager.datenbank.passwort=<<secret:0>>\n",
            "dotted_tilde_password", 6805, carrier="ini",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "# .env for the report worker (copied from .env.example)\nWORKER_QUEUE=reports\nDB_PASSWORD=<<secret:0>>\nSENTRY_ENVIRONMENT=staging\n",
            "dotted_tilde_password", 6806, carrier="env",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "[auth]\ndb_password = \"<<secret:0>>\"\n",
            "dotted_digit_password", 6807, carrier="toml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "POST /v2/exports HTTP/1.1\nAccept: application/json\nDb-Password: <<secret:0>>\n\n",
            "dotted_tilde_password", 6808, carrier="http",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "$ export SMTP_PASSWORD=<<secret:0>>\n$ ./bin/send-digest\n",
            "dotted_digit_password", 6809, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "2026-10-30T09:12:44Z DEBUG connect host=db.internal user=report password=<<secret:0>>\n",
            "dotted_tilde_password", 6810, carrier="log",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "passwort = konto.zugang.passwort;\n",
            "member access chain under a password key", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "const kennwort = this.formular.kennwort.value;\n",
            "member access chain in JavaScript", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "$passwort = $anfrage->eingabe->passwort;\n",
            "PHP property chain under a password key", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "lager:\n  passwort: ${LAGER_DB_PASSWORT}\n",
            "environment reference under a password key", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_password_assignment",
            "# Beispiel aus der Doku\npasswort: beispiel.Passwort~\n",
            "documented example value with a member-access shape", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "password = settings.database.password\n",
            "member access chain under a password key", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "if (password.length > 0) { submit(user.password); }\n",
            "member access in a condition", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "$password = $request->input->password;\n",
            "PHP property chain under a password key", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "DB_PASSWORD=${DB_PASSWORD}\n",
            "environment reference under a password variable", carrier="env",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_password_assignment",
            "# documented sample\npassword: example.Password~\n",
            "documented example value with a member-access shape", carrier="yaml",
        ),
    ],
}
for _label, _rows in DLP_Q_DLP_PW_CASES.items():
    DLP_CASES[_label].extend(_rows)


# G03: passwords on CLI command lines. `dlp_cli_password` reports the password of `curl -u/--user
# user:…`, the MySQL/MariaDB clients `-p…`/`--password=…`, a shell `PGPASSWORD=…` (libpq),
# `sshpass -p`, `docker`/`podman login -p/--password`, `htpasswd -b…` (the last argument),
# PowerShell `ConvertTo-SecureString "…" -AsPlainText` and `net use \\server\share … /user:`. Hard
# negatives: prompts (`curl -u user`, `mysql -p db`, `-W`, `net use … *`), `--password-stdin`,
# `sshpass -e/-f`, shell and template references, placeholders and documented call syntax.
DLP_G03_CASES = {
    "CREDENTIAL": [
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "$ curl -u lager-deploy:<<secret:0>> -T lager-2026.10.tgz https://nexus.lager.intern/repository/raw/\n"
            "  % Total    % Received % Xferd\n",
            "curl_user_password", 19001, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "#!/bin/bash\n# Nächtliche Sicherung der Lagerdatenbank\nmysqldump -h db.lager.intern -u sicherung "
            "-p<<secret:0>> --single-transaction lager > /sicherung/lager.sql\n",
            "curl_user_password", 19002, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "sicherung:\n  stage: deploy\n  script:\n    - sshpass -p '<<secret:0>>' scp dump.sql "
            "sicherung@backup.lager.intern:/daten/\n",
            "password", 19003, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "2026-09-14 08:12:03 INFO deploy.sh: + docker login -u lager-ci -p <<secret:0>> registry.lager.intern\n"
            "2026-09-14 08:12:04 INFO deploy.sh: Login Succeeded\n",
            "curl_user_password", 19004, carrier="log",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "Hallo Jana,\n\nden Zugang für das Lager-Dashboard habe ich so angelegt:\n"
            "htpasswd -bc /etc/nginx/.htpasswd jana <<secret:0>>\nBitte nach dem ersten Login ändern.\n",
            "curl_user_password", 19005, carrier="prose",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "# Laufwerk der Buchhaltung verbinden\n$sicher = ConvertTo-SecureString \"<<secret:0>>\" -AsPlainText -Force\n"
            "$zugang = New-Object System.Management.Automation.PSCredential('LAGER\\jana', $sicher)\n",
            "password", 19006, carrier="code",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "C:\\> net use Z: \\\\fs01.lager.intern\\buchhaltung <<secret:0>> /user:LAGER\\jana /persistent:no\n"
            "Der Befehl wurde erfolgreich ausgeführt.\n",
            "curl_user_password", 19007, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "de", "dlp_cli_password",
            "# Wartung jeden Sonntag\n0 3 * * 0 PGPASSWORD=<<secret:0>> psql -h db.lager.intern -U lager -d lager "
            "-c \"VACUUM ANALYZE\"\n",
            "curl_user_password", 19008, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "      - name: Publish release\n        run: |\n          curl --user \"release-bot:<<secret:0>>\" "
            "-X POST https://artifacts.example.com/api/upload\n",
            "curl_user_password", 19011, carrier="yaml",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "$ mysql -h db.internal -u orders --password=<<secret:0>> orders\n"
            "Welcome to the MySQL monitor.  Commands end with ; or \\g.\n",
            "curl_user_password", 19012, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "2026-09-14T08:12:03Z + sshpass -p<<secret:0>> ssh deploy@10.0.4.12 'systemctl restart api'\n",
            "curl_user_password", 19013, carrier="log",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "#!/bin/sh\nset -eu\necho \"logging in to the registry\"\ndocker login --username ci-bot --password "
            "<<secret:0>> registry.example.com\ndocker push registry.example.com/api:latest\n",
            "curl_user_password", 19014, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "FROM nginx:1.27-alpine\nRUN apk add --no-cache apache2-utils \\\n"
            " && htpasswd -nbB admin <<secret:0>> > /etc/nginx/.htpasswd\n",
            "curl_user_password", 19015, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "$cred = New-Object System.Management.Automation.PSCredential('svc-deploy', "
            "(ConvertTo-SecureString -String '<<secret:0>>' -AsPlainText -Force))\n",
            "password", 19016, carrier="code",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "@echo off\nREM map the reports share\nnet use \\\\files.internal\\reports /user:ACME\\svc-reports "
            "<<secret:0>>\n",
            "curl_user_password", 19017, carrier="cli",
        ),
        ds(
            "CREDENTIAL", "en", "dlp_cli_password",
            "Hi Sam,\n\nthe backup job runs\n\nPGPASSWORD='<<secret:0>>' pg_dump -h db.internal -U orders orders "
            "> orders.sql\n\nPlease rotate it after the migration.\n",
            "password", 19018, carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_cli_password",
            "$ curl -u lager-deploy -T lager.tgz https://nexus.lager.intern/repository/raw/\n"
            "Enter host password for user 'lager-deploy':\n",
            "curl user name without a password (prompt)", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_cli_password",
            "#!/bin/bash\nmysqldump -h db.lager.intern -u sicherung -p lager > /sicherung/lager.sql\n",
            "mysql -p with a space is the prompt, lager the database", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_cli_password",
            "sicherung:\n  script:\n    - sshpass -e scp dump.sql sicherung@backup.lager.intern:/daten/\n"
            "    - echo \"$REGISTRY_PASSWORT\" | docker login -u lager-ci --password-stdin registry.lager.intern\n",
            "password from the environment and stdin", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_cli_password",
            "# Laufwerk verbinden\n$sicher = ConvertTo-SecureString $env:LAGER_KENNWORT -AsPlainText -Force\n"
            "net use Z: \\\\fs01.lager.intern\\buchhaltung * /user:LAGER\\jana\n",
            "environment reference and the password prompt *", carrier="code",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_cli_password",
            "Aufruf laut Handbuch: htpasswd -b <datei> <benutzer> <passwort> oder curl -u <benutzer>:<passwort> <url>\n",
            "documented call syntax with placeholders", carrier="prose",
        ),
        dn(
            "CREDENTIAL", "de", "dlp_cli_password",
            "# Wartung\nPGPASSWORD=\"${LAGER_DB_PASSWORT}\" psql -h db.lager.intern -U lager -d lager\n",
            "shell variable as PGPASSWORD", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_cli_password",
            "      - name: Publish release\n        run: curl --user \"${{ secrets.RELEASE_USER }}:${{ secrets.RELEASE_PASSWORD }}\" "
            "-X POST https://artifacts.example.com/api/upload\n",
            "CI secret references as curl credentials", carrier="yaml",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_cli_password",
            "$ mysql -h db.internal -u orders -p orders\nEnter password:\n",
            "mysql password prompt", carrier="cli",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_cli_password",
            "docker login -u gitlab-ci-token -p \"$CI_JOB_TOKEN\" \"$CI_REGISTRY\"\n"
            "sshpass -f /run/secrets/deploy_pw ssh deploy@10.0.4.12 uptime\n",
            "CI variable and password file", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_cli_password",
            "# usage\n#   curl -u username:password https://api.example.com/v1/me\n"
            "#   htpasswd -nb user password\n",
            "documented stand-in credentials", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_cli_password",
            "$secure = ConvertTo-SecureString $encrypted -Key $key\n"
            "$plain = ConvertTo-SecureString -String $Password -AsPlainText -Force\n",
            "PowerShell variables, no literal", carrier="code",
        ),
        dn(
            "CREDENTIAL", "en", "dlp_cli_password",
            "The -p option of sshpass passes the password on the command line; prefer -e or -f.\n",
            "option name in prose", carrier="prose",
        ),
    ],
}
for _label, _rows in DLP_G03_CASES.items():
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
