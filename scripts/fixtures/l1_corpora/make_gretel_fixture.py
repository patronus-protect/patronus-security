#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Regenerate the synthetic Gretel-shaped Parquet shards used by test_l1_prepare_corpora.py.

Handwritten rows, no upstream data. The two shards cover what the pure-Python reader of
prepare_corpora.py must handle in the pinned Gretel files (pyarrow 14 writer, Snappy,
optional flat byte-array columns, dictionary and plain pages, several row groups) plus
data page v2 and nulls. Needs pyarrow, which the gate venv deliberately does not have:

    .venv/bin/python scripts/fixtures/l1_corpora/make_gretel_fixture.py
"""

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

HERE = Path(__file__).resolve().parent

TEMPLATES = [
    ("English", "Wire Transfer Form", "Send the payment to IBAN {iban} and confirm via {email}."),
    ("English", "Customer Support Ticket", "User {user} reported a lockout; callback number {phone}."),
    ("English", "Loan Application", "Applicant SSN {ssn}, contact {email}, café account ok."),
    ("German", "Überweisungsauftrag", "Bitte überweisen Sie auf IBAN {iban}; Rückfragen an {email}."),
    ("German", "Kundenanfrage", "Kundin erreichbar unter {phone}, Benutzer {user} – danke!"),
    ("German", "Kreditantrag", "Antragsteller: Jörg Müller, Telefon {phone}, Grüße 😀."),
]
VALUES = {
    "iban": ["DE89370400440532013000", "GB82WEST12345698765432", "FR1420041010050500013M02606"],
    "email": ["ada@example.test", "jo.mueller@example.test", "support@bank.example"],
    "user": ["ada_l", "jmueller", "x9-admin"],
    "phone": ["+1 415 555 0100", "+49 30 1234567", "(030) 765 4321"],
    "ssn": ["078-05-1120", "219-09-9999", "457-55-5462"],
}
COLUMNS = ("document_type", "expanded_type", "language", "generated_text", "pii_spans")
LABELS = {"iban": "IBAN", "email": "EMAIL", "user": "user_name", "phone": "phone_number", "ssn": "ssn"}


def rows(variant: int) -> list[dict]:
    out = []
    for index, (language, kind, template) in enumerate(TEMPLATES * 2):
        text, spans = "", []
        for part in template.replace("}", "{").split("{"):
            if part in VALUES:
                value = VALUES[part][(index + variant) % 3]
                spans.append({"start": len(text), "end": len(text) + len(value), "label": LABELS[part]})
                text += value
            else:
                text += part
        out.append(
            {
                "document_type": kind,
                "expanded_type": f"{kind} v{variant}.{index % 4}",
                "language": language,
                "generated_text": text,
                "pii_spans": json.dumps(spans),
                "quality_score": None if index % 5 == 0 else index,
                "pii_types": [span["label"] for span in spans],
            }
        )
    return out


def main() -> None:
    first = pa.Table.from_pylist(rows(0))
    second = rows(1)
    second[3]["document_type"] = None
    # Dictionary pages for the short columns, plain pages for the long ones, three row groups.
    pq.write_table(
        first,
        HERE / "gretel_v1_test.parquet",
        compression="snappy",
        use_dictionary=["document_type", "expanded_type", "language"],
        row_group_size=5,
    )
    pq.write_table(
        pa.Table.from_pylist(second),
        HERE / "gretel_v2_test.parquet",
        compression="snappy",
        data_page_version="2.0",
        row_group_size=8,
    )
    expected = {
        name: [{key: row[key] for key in COLUMNS} for row in table]
        for name, table in (("gretel_v1_test.parquet", first.to_pylist()), ("gretel_v2_test.parquet", second))
    }
    (HERE / "gretel_expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
