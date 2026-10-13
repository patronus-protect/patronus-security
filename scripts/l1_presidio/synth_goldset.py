#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate the synthetic DE/EU L1-PII goldset (dev and holdout) with code-point spans.

Seven document types (letter, form, invoice, medical letter, JSON, CSV, support ticket) in
German and English carry every benchmark id of ``research/l1-pii/entity_map.yaml``: shared,
ark_only, presidio_only and semantic. Checksum-bearing values are generated valid (IBAN,
Luhn, Steuer-ID, KVNR, RVNR, LANR, MRZ check digits, national ids, ...). Each row follows the
``patronus_ark.external_pii_eval`` schema (``entities`` with ``start``/``end`` in code
points) and additionally names its ``doc_type`` and ``hard_negatives``: spans of look-alike
values (invoice and order numbers, ICD codes, versions, checksum-invalid numbers) that no
detector should report.

    python3 scripts/l1_presidio/synth_goldset.py --dev-out DIR
    python3 scripts/l1_presidio/synth_goldset.py --dev-out DIR --holdout-out DIR
    python3 scripts/l1_presidio/synth_goldset.py --check DIR

Dev and holdout use separate seeds. The dev seed is public (``DEV_SEED``); the holdout seed
is secret and lives in a seed file (default ``HOLDOUT/.seed``), created from ``secrets`` on
the first run and never written into the manifest (only its SHA-256). Generation is a pure
function of seed, split and ``GENERATOR_VERSION``: a SHA-256 counter stream replaces
``random``, so results do not depend on the Python version. Output directories are frozen
like ``prepare_corpora.py``: ``ark-synthetic-de-eu.jsonl``, ``manifest.json`` and, written
last, ``.ready``; a rerun must reproduce them byte for byte or exit 1 (``--force`` replaces).
Only standard library: the gate runs this with the Presidio venv.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import unicodedata
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable, NamedTuple, Sequence

SCHEMA = "ark-l1-synthetic-goldset-v1"
CORPUS_ID = "ark-synthetic-de-eu"
GENERATOR_VERSION = 1
DEV_SEED = "ark-l1-e05-synthetic-dev-v1"
SPLITS = ("dev", "holdout")
DEFAULT_DOCS = {"dev": 420, "holdout": 630}
LANGUAGES = ("de", "en")
DOC_TYPES = ("letter", "form", "invoice", "medical_letter", "json", "csv", "ticket")
MIN_PER_LANGUAGE = 5
READY = ".ready"
SEED_FILE = ".seed"
FILE_NAME = f"{CORPUS_ID}.jsonl"


# ── deterministic randomness ─────────────────────────────────────────────────


class Rng:
    """SHA-256 counter stream; stable across Python versions, unlike ``random``."""

    def __init__(self, seed: str):
        self._seed = seed.encode("utf-8")
        self._counter = 0
        self._buffer = b""

    def _bytes(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._buffer += hashlib.sha256(self._seed + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out

    def below(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        limit = 2**64 - 2**64 % bound
        while True:
            value = int.from_bytes(self._bytes(8), "big")
            if value < limit:
                return value % bound

    def randint(self, low: int, high: int) -> int:
        return low + self.below(high - low + 1)

    def choice(self, items: Sequence[Any]) -> Any:
        return items[self.below(len(items))]

    def chance(self, percent: int) -> bool:
        return self.below(100) < percent

    def digits(self, count: int) -> str:
        return "".join(str(self.below(10)) for _ in range(count))

    def chars(self, alphabet: str, count: int) -> str:
        return "".join(self.choice(alphabet) for _ in range(count))

    def shuffle(self, items: list[Any]) -> list[Any]:
        for index in range(len(items) - 1, 0, -1):
            other = self.below(index + 1)
            items[index], items[other] = items[other], items[index]
        return items


UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALNUM = UPPER + "0123456789"


def group(value: str, sizes: Sequence[int], separator: str = " ") -> str:
    parts, position = [], 0
    for size in sizes:
        parts.append(value[position : position + size])
        position += size
    if position < len(value):
        parts.append(value[position:])
    return separator.join(part for part in parts if part)


def group4(value: str) -> str:
    return " ".join(value[index : index + 4] for index in range(0, len(value), 4))


def ascii_fold(value: str) -> str:
    for source, target in (
        ("ä", "ae"),
        ("ö", "oe"),
        ("ü", "ue"),
        ("ß", "ss"),
        ("Ä", "Ae"),
        ("Ö", "Oe"),
        ("Ü", "Ue"),
        ("ł", "l"),
        ("ı", "i"),
    ):
        value = value.replace(source, target)
    return unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")


# ── checksums ────────────────────────────────────────────────────────────────


def luhn_check_digit(payload: str) -> str:
    total = 0
    for index, char in enumerate(reversed(payload)):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    return luhn_check_digit(number[:-1]) == number[-1]


def iso7064_mod11_10(digits: str) -> int:
    product = 10
    for char in digits:
        total = (int(char) + product) % 10 or 10
        product = (total * 2) % 11
    check = 11 - product
    return 0 if check == 10 else check


def iban_check_digits(country: str, bban: str) -> str:
    numeric = "".join(str(int(char, 36)) for char in bban + country + "00")
    return f"{98 - int(numeric) % 97:02d}"


def iban_valid(iban: str) -> bool:
    compact = iban.replace(" ", "")
    numeric = "".join(str(int(char, 36)) for char in compact[4:] + compact[:4])
    return int(numeric) % 97 == 1


def cross_sum(value: int) -> int:
    return value // 10 + value % 10


def mrz_check_digit(value: str) -> str:
    weights = (7, 3, 1)
    return str(sum(int(char, 36) * weights[index % 3] for index, char in enumerate(value)) % 10)


VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_check_digit(payload: str) -> str:
    check = 0
    for index, char in enumerate(reversed(payload)):
        check = VERHOEFF_D[check][VERHOEFF_P[(index + 1) % 8][int(char)]]
    return str(VERHOEFF_INV[check])


def verhoeff_valid(number: str) -> bool:
    check = 0
    for index, char in enumerate(reversed(number)):
        check = VERHOEFF_D[check][VERHOEFF_P[index % 8][int(char)]]
    return check == 0


# ── name, place and organisation pools ───────────────────────────────────────


NAMES = {
    "de": (
        (
            "Lena", "Jonas", "Anna", "Lukas", "Marie", "Felix", "Sophie", "Paul", "Hannah", "Moritz", "Jürgen",
            "Sabine", "Björn", "Käthe",
        ),
        (
            "Weber", "Schäfer", "Hoffmann", "Becker", "Schulz", "Krüger", "Wagner", "Neumann", "Brandt", "Vogel",
            "Lehmann", "Köhler", "Zimmermann", "Fuß",
        ),
    ),
    "en": (
        (
            "Olivia", "Harry", "Amelia", "George", "Isla", "Oliver", "Emily", "Jack", "Sophia", "Thomas", "Grace",
            "William",
        ),
        (
            "Taylor", "Davies", "Evans", "Thomas", "Roberts", "Walker", "Wright", "Hughes", "Clarke", "Turner",
            "Harrison", "Morgan",
        ),
    ),
    "it": (
        ("Giulia", "Marco", "Chiara", "Luca", "Francesca", "Matteo"),
        ("Rossi", "Bianchi", "Esposito", "Romano", "Colombo", "Ricci"),
    ),
    "es": (
        ("Lucía", "Javier", "Carmen", "Álvaro", "Elena", "Pablo"),
        ("García", "Fernández", "López", "Martínez", "Sánchez", "Pérez"),
    ),
    "pl": (
        ("Zofia", "Jakub", "Agnieszka", "Michał", "Katarzyna", "Paweł"),
        ("Nowak", "Kowalski", "Wiśniewski", "Wójcik", "Kamińska", "Lewandowski"),
    ),
    "tr": (
        ("Elif", "Mehmet", "Zeynep", "Emre", "Ayşe", "Burak"),
        ("Yılmaz", "Kaya", "Demir", "Şahin", "Çelik", "Öztürk"),
    ),
    "fr": (
        ("Camille", "Louis", "Chloé", "Hugo", "Léa", "Théo"),
        ("Martin", "Bernard", "Dubois", "Lefèvre", "Moreau", "Girard"),
    ),
    "nl": (
        ("Sanne", "Daan", "Fleur", "Sem", "Lotte", "Bram"),
        ("de Vries", "Jansen", "Bakker", "Visser", "Smit", "van Dijk"),
    ),
}
FEMALE = {
    "Lena", "Anna", "Marie", "Sophie", "Hannah", "Sabine", "Käthe", "Olivia", "Amelia", "Isla", "Emily", "Sophia",
    "Grace", "Giulia", "Chiara", "Francesca", "Lucía", "Carmen", "Elena", "Zofia", "Agnieszka", "Katarzyna", "Elif",
    "Zeynep", "Ayşe", "Camille", "Chloé", "Léa", "Sanne", "Fleur", "Lotte",
}
DE_CITIES = (
    ("Berlin", 10115, 14199), ("München", 80331, 81929), ("Hamburg", 20095, 22769), ("Köln", 50667, 51149),
    ("Frankfurt am Main", 60306, 60599), ("Stuttgart", 70173, 70629), ("Düsseldorf", 40210, 40629),
    ("Leipzig", 4103, 4357), ("Dresden", 1067, 1328), ("Nürnberg", 90402, 90491), ("Bremen", 28195, 28779),
    ("Hannover", 30159, 30669), ("Münster", 48143, 48167), ("Freiburg im Breisgau", 79098, 79117),
    ("Regensburg", 93047, 93059), ("Lübeck", 23552, 23570),
)
DE_STREETS = (
    "Lindenstraße", "Hauptstraße", "Bahnhofstraße", "Schillerstraße", "Goethestraße", "Am Mühlbach", "Gartenweg",
    "Rosenweg", "Kastanienallee", "Friedrich-Ebert-Straße", "Schulstraße", "Bergstraße", "Mozartstraße",
    "Uhlandstraße", "Talstraße", "Birkenweg",
)
UK_CITIES = (
    ("London", ("SW11", "N1", "E14", "SE15", "NW3")), ("Manchester", ("M4", "M14", "M20")),
    ("Leeds", ("LS6", "LS1", "LS8")), ("Birmingham", ("B15", "B13", "B29")), ("Bristol", ("BS8", "BS6", "BS3")),
    ("Edinburgh", ("EH3", "EH9", "EH10")), ("Cardiff", ("CF10", "CF24", "CF5")),
    ("Nottingham", ("NG7", "NG1", "NG5")), ("Glasgow", ("G12", "G3", "G41")),
)
UK_STREETS = (
    "Mill Lane", "Church Street", "Victoria Road", "Station Road", "Park Avenue", "Queens Road", "Albert Street",
    "Green Lane", "Manor Road", "Kingsway",
)
ORG_SUFFIX = {
    "de": (
        "GmbH", "Haustechnik GmbH", "& Partner mbB", "Logistik GmbH & Co. KG", "Steuerberatung GmbH", "Immobilien KG",
        "Versicherungsmakler GmbH",
    ),
    "en": (
        "Ltd", "Consulting Ltd", "& Sons Ltd", "Logistics plc", "Property Services Ltd", "Accountants LLP",
        "Insurance Brokers Ltd",
    ),
}
CLINIC = {
    "de": (
        "Klinikum {city}", "Praxis am Markt", "Gemeinschaftspraxis Dr. {last}",
        "Medizinisches Versorgungszentrum {city}", "St.-Marien-Krankenhaus {city}",
    ),
    "en": (
        "{city} General Hospital", "Riverside Medical Centre", "{city} Royal Infirmary", "Parkview Surgery",
        "St Anne's Hospital {city}",
    ),
}
EMAIL_DOMAINS = (
    "web.de", "gmx.de", "t-online.de", "posteo.de", "mailbox.org", "outlook.com", "gmail.com", "icloud.com",
    "yahoo.co.uk", "btinternet.com",
)
MONTHS = {
    "de": (
        "Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November",
        "Dezember",
    ),
    "en": (
        "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
        "December",
    ),
}


class Persona(NamedTuple):
    first: str
    last: str
    female: bool
    dob: date
    street: str
    city: str
    postal: str


def persona(r: Rng, lang: str) -> Persona:
    origin = (
        r.choice(("de", "de", "de", "en", "it", "es", "pl", "tr", "fr", "nl"))
        if lang == "de"
        else r.choice(("en", "en", "en", "de", "it", "es", "pl", "tr", "fr", "nl"))
    )
    firsts, lasts = NAMES[origin]
    first = r.choice(firsts)
    dob = date(r.randint(1945, 2005), r.randint(1, 12), r.randint(1, 28))
    if lang == "de":
        city, low, high = r.choice(DE_CITIES)
        street = f"{r.choice(DE_STREETS)} {r.randint(1, 160)}{r.choice(('', '', '', 'a', 'b'))}"
        postal = f"{r.randint(low, high):05d}"
    else:
        city, outwards = r.choice(UK_CITIES)
        street = f"{r.randint(1, 240)} {r.choice(UK_STREETS)}"
        postal = f"{r.choice(outwards)} {r.randint(1, 9)}{r.chars('ABDEFGHJLNPQRSTUWXYZ', 2)}"
    return Persona(first, r.choice(lasts), first in FEMALE, dob, street, city, postal)


def org_name(r: Rng, lang: str) -> str:
    return f"{r.choice(NAMES[lang][1])} {r.choice(ORG_SUFFIX[lang])}"


def format_date(r: Rng, lang: str, value: date) -> str:
    if lang == "de":
        return r.choice(
            (
                f"{value.day:02d}.{value.month:02d}.{value.year}",
                f"{value.day}. {MONTHS['de'][value.month - 1]} {value.year}",
            )
        )
    return r.choice(
        (
            f"{value.day} {MONTHS['en'][value.month - 1]} {value.year}",
            f"{value.day:02d}/{value.month:02d}/{value.year}",
            f"{MONTHS['en'][value.month - 1]} {value.day}, {value.year}",
            f"{value.year}-{value.month:02d}-{value.day:02d}",
        )
    )


def recent_date(r: Rng) -> date:
    return date(2025, 1, 1) + timedelta(days=r.below(640))


# ── value generators (r, persona, language) -> value ─────────────────────────


Gen = Callable[[Rng, Persona, str], str]


def gen_email(r: Rng, p: Persona, lang: str) -> str:
    first, last = ascii_fold(p.first).lower(), ascii_fold(p.last).lower().replace(" ", "")
    local = r.choice(
        (
            f"{first}.{last}",
            f"{first[0]}.{last}",
            f"{first}{last}{p.dob.year % 100:02d}",
            f"{last}.{first}",
            f"{first}_{last}",
        )
    )
    return f"{local}@{r.choice(EMAIL_DOMAINS)}"


def gen_phone(r: Rng, p: Persona, lang: str) -> str:
    def subscriber(count: int) -> str:
        return str(r.randint(2, 9)) + r.digits(count - 1)

    if lang == "de":
        kind = r.below(6)
        if kind == 0:
            area = r.choice(("30", "89", "40", "221", "69", "711", "211"))
            return f"+49 {area} {subscriber(7)}"
        if kind == 1:
            return f"0{r.choice(('151', '152', '157', '160', '170', '171', '176', '179'))} {subscriber(8)}"
        if kind == 2:
            return f"+49 {r.choice(('151', '160', '172', '176'))} {subscriber(4)} {r.digits(4)}"
        if kind == 3:
            return f"0{r.choice(('30', '89', '40'))}/{subscriber(4)}{r.digits(4)}"
        if kind == 4:
            return f"+43 1 {subscriber(7)}"
        return f"+41 44 {subscriber(3)} {r.digits(2)} {r.digits(2)}"
    kind = r.below(5)
    if kind == 0:
        return f"+44 20 {r.choice('378')}{r.digits(3)} {r.digits(4)}"
    if kind == 1:
        return f"07{r.choice(('4', '5', '7', '8', '9'))}{r.digits(2)} {r.digits(6)}"
    if kind == 2:
        exchange = f"{r.randint(2, 9)}{r.digits(2)}"
        exchange = "556" if exchange == "555" else exchange
        return f"({r.choice(('212', '312', '415', '617', '206', '303', '512'))}) {exchange}-{r.digits(4)}"
    if kind == 3:
        area, first = r.choice((("113", "2"), ("117", "9"), ("121", "4"), ("131", "2"), ("161", "8")))
        return f"+44 {area} {first}{r.digits(2)} {r.digits(4)}"
    return f"+353 1 {subscriber(3)} {r.digits(4)}"


PUBLIC_FIRST_OCTETS = (
    23, 31, 37, 46, 62, 78, 80, 81, 85, 88, 91, 93, 94, 109, 134, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195,
    212, 213, 217,
)


def gen_ip(r: Rng, p: Persona, lang: str) -> str:
    if r.chance(70):
        return ".".join(
            str(part)
            for part in (r.choice(PUBLIC_FIRST_OCTETS), r.randint(0, 255), r.randint(0, 255), r.randint(1, 254))
        )
    groups = [r.choice(("2a02", "2a01", "2003", "2a00", "2001")), f"{r.below(0x10000):x}", f"{r.below(0x10000):x}"]
    if r.chance(50):
        return ":".join(groups + [f"{r.below(0x10000):x}" for _ in range(5)])
    return ":".join(groups[:2]) + "::" + f"{r.below(0x10000):x}"


def gen_mac(r: Rng, p: Persona, lang: str) -> str:
    octets = [r.below(256) & 0xFC] + [r.below(256) for _ in range(5)]
    text = r.choice((":", "-")).join(f"{octet:02x}" for octet in octets)
    return text.upper() if r.chance(50) else text


IBAN_SPECS = {
    "DE": lambda r: str(r.randint(1, 8)) + r.digits(7) + r.digits(10),
    "AT": lambda r: str(r.randint(1, 9)) + r.digits(15),
    "CH": lambda r: r.digits(17),
    "FR": lambda r: r.digits(23),
    "NL": lambda r: r.choice(("ABNA", "INGB", "RABO", "TRIO", "SNSB", "KNAB")) + r.digits(10),
    "IT": lambda r: r.choice(UPPER) + r.digits(22),
    "ES": lambda r: r.digits(20),
    "PL": lambda r: r.digits(24),
    "LU": lambda r: r.digits(16),
}


def make_iban(r: Rng, country: str) -> str:
    if country == "BE":
        body = r.digits(10)
        bban = body + f"{int(body) % 97 or 97:02d}"
    else:
        bban = IBAN_SPECS[country](r)
    return country + iban_check_digits(country, bban) + bban


def gen_iban(r: Rng, p: Persona, lang: str) -> str:
    countries = ("DE", "DE", "DE", "AT", "CH", "FR", "NL", "IT", "ES", "BE", "PL", "LU")
    iban = make_iban(r, r.choice(countries))
    return group4(iban) if r.chance(60) else iban


def gen_pan(r: Rng, p: Persona, lang: str) -> str:
    kind = r.below(3)
    if kind == 0:
        payload = "4" + r.digits(14)
    elif kind == 1:
        payload = str(r.randint(51, 55)) + r.digits(13)
    else:
        payload = r.choice(("34", "37")) + r.digits(12)
        number = payload + luhn_check_digit(payload)
        return group(number, (4, 6, 5), r.choice((" ", " ", "")))
    number = payload + luhn_check_digit(payload)
    separator = r.choice((" ", " ", "-", ""))
    return group(number, (4, 4, 4, 4), separator) if separator else number


def gen_cvv(r: Rng, p: Persona, lang: str) -> str:
    return r.digits(4) if r.chance(15) else r.digits(3)


def gen_expiry(r: Rng, p: Persona, lang: str) -> str:
    month, year = r.randint(1, 12), r.randint(26, 31)
    return r.choice((f"{month:02d}/{year}", f"{month:02d}/20{year}", f"{month:02d}-{year}"))


def gen_account(r: Rng, p: Persona, lang: str) -> str:
    if lang == "de" and r.chance(70):
        return str(r.randint(1, 9)) + r.digits(r.randint(7, 9))
    if r.chance(50):
        prefix = f"{r.choice((r.randint(1, 12), r.randint(21, 32))):02d}"
        body = prefix + r.digits(6)
        weights = (3, 7, 1, 3, 7, 1, 3, 7)
        return body + str(-sum(int(char) * weight for char, weight in zip(body, weights)) % 10)
    return str(r.randint(1, 9)) + r.digits(r.randint(7, 11))


def gen_ssn(r: Rng, p: Persona, lang: str) -> str:
    area = r.randint(1, 898)
    area = area + 1 if area == 666 else area
    separator = r.choice(("-", "-", " "))
    return f"{area:03d}{separator}{r.randint(1, 99):02d}{separator}{r.randint(1, 9999):04d}"


def gen_nino(r: Rng, p: Persona, lang: str) -> str:
    while True:
        prefix = r.choice("ABCEGHJKLMNOPRSTWXYZ") + r.choice("ABCEGHJKLMNPRSTWXYZ")
        if prefix not in ("BG", "GB", "KN", "NK", "NT", "TN", "ZZ"):
            break
    digits, suffix = r.digits(6), r.choice("ABCD")
    return r.choice(
        (
            f"{prefix}{digits}{suffix}",
            f"{prefix} {digits[:2]} {digits[2:4]} {digits[4:]} {suffix}",
            f"{prefix} {digits} {suffix}",
        )
    )


def gen_steuer_id(r: Rng, p: Persona, lang: str) -> str:
    missing = r.below(10)
    pool = [digit for digit in range(10) if digit != missing]
    pool.append(r.choice(pool))
    while True:
        r.shuffle(pool)
        if pool[0] != 0:
            break
    body = "".join(str(digit) for digit in pool)
    value = body + str(iso7064_mod11_10(body))
    return r.choice((value, f"{value[:2]} {value[2:5]} {value[5:8]} {value[8:]}"))


def gen_tax_number(r: Rng, p: Persona, lang: str) -> str:
    kind = r.below(3)
    if kind == 0:  # Bayern FFF/BBB/UUUUP
        return f"{r.randint(101, 199)}/{r.digits(3)}/{r.digits(5)}"
    if kind == 1:  # Nordrhein-Westfalen FFF/BBBB/UUUP
        return f"{r.randint(301, 399)}/{r.digits(4)}/{r.digits(4)}"
    return f"{r.randint(11, 37)}/{r.digits(3)}/{r.digits(5)}"  # Berlin/Hamburg FF/BBB/UUUUP


RV_AREAS = (
    12, 13, 15, 17, 18, 19, 23, 24, 25, 26, 28, 29, 38, 39, 40, 42, 43, 44, 45, 46, 48, 49, 50, 53, 55, 56, 58, 60,
    61, 63, 65, 66,
)


def rvnr(area: int, birth: date, initial: str, serial: int) -> str:
    head = f"{area:02d}{birth.day:02d}{birth.month:02d}{birth.year % 100:02d}"
    weights = (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)
    effective = head + f"{ord(initial) - 64:02d}" + f"{serial:02d}"
    check = sum(cross_sum(int(char) * weight) for char, weight in zip(effective, weights)) % 10
    return f"{head}{initial}{serial:02d}{check}"


def gen_rvnr(r: Rng, p: Persona, lang: str) -> str:
    initial = ascii_fold(p.last)[0].upper()
    serial = r.randint(50, 99) if p.female else r.randint(0, 49)
    value = rvnr(r.choice(RV_AREAS), p.dob, initial, serial)
    return r.choice((value, f"{value[:2]} {value[2:8]} {value[8]} {value[9:]}"))


def kvnr(letter: str, body: str) -> str:
    effective = f"{ord(letter) - 64:02d}" + body
    check = sum(cross_sum(int(char) * (1 if index % 2 == 0 else 2)) for index, char in enumerate(effective)) % 10
    return f"{letter}{body}{check}"


def gen_kvnr(r: Rng, p: Persona, lang: str) -> str:
    return kvnr(r.choice(UPPER), str(r.randint(1, 9)) + r.digits(7))


def lanr(body: str, specialty: str) -> str:
    total = sum(int(char) * weight for char, weight in zip(body, (4, 9, 4, 9, 4, 9)))
    return f"{body}{(10 - total % 10) % 10}{specialty}"


def gen_lanr(r: Rng, p: Persona, lang: str) -> str:
    return lanr(r.digits(6), r.choice(("01", "03", "23", "34", "44", "51", "60", "70")))


DOC_CHARS = "CFGHJKLMNPRTVWXYZ0123456789"


def gen_passport(r: Rng, p: Persona, lang: str) -> str:
    kind = r.below(4) if lang == "en" else r.choice((0, 0, 0, 3))
    if kind == 0:  # German Reisepass with ICAO check digit
        body = r.choice("CFGHJK") + r.chars(DOC_CHARS, 7)
        return body + mrz_check_digit(body)
    if kind == 1:  # US next-generation passport
        return r.choice("ACEFGHJKLMNPRSTUVWXYZ") + r.digits(8)
    if kind == 2:  # UK passport
        return str(r.randint(1, 9)) + r.digits(8)
    return r.chars("ABCDEFGHJKLMNPRSTUVWXYZ", 2) + r.digits(7)  # Italian passport


def gen_id_card(r: Rng, p: Persona, lang: str) -> str:
    if r.chance(75):  # German Personalausweis (nPA) with ICAO check digit
        body = r.choice("LMNPRTVWXY") + r.chars(DOC_CHARS, 7)
        return body + mrz_check_digit(body)
    return r.chars(UPPER, 2) + r.digits(5) + r.chars(UPPER, 2)  # Italian CIE 3.0


def gen_driver_license(r: Rng, p: Persona, lang: str) -> str:
    kind = r.choice((0, 0, 1)) if lang == "de" else r.choice((1, 2, 3))
    if kind == 0:  # German Führerschein (Presidio DE_FUEHRERSCHEIN shape)
        return r.chars(UPPER, 2) + r.digits(8) + r.choice(ALNUM)
    if kind == 1:  # UK DVLA licence derived from the holder
        surname = (re.sub(r"[^A-Z]", "", ascii_fold(p.last).upper()) + "99999")[:5]
        month = p.dob.month + (50 if p.female else 0)
        initials = (ascii_fold(p.first)[0].upper() + "9")[:2]
        birth = f"{p.dob.year % 100 // 10}{month:02d}{p.dob.day:02d}{p.dob.year % 10}"
        return f"{surname}{birth}{initials}{r.below(10)}{r.chars('ABCDEFGHJKLMNPRSTUVWXYZ', 2)}"
    if kind == 2:  # California
        return r.choice(UPPER) + r.digits(7)
    return r.chars(UPPER, 2) + r.digits(7) + r.choice(UPPER)  # Italian patente


DE_PLATE_CODES = (
    "B", "M", "HH", "K", "F", "S", "D", "DO", "E", "HB", "H", "L", "DD", "N", "KA", "MA", "BN", "AC", "MS", "OS",
    "KI", "LÖ", "BÖ", "FÜ",
)


def gen_plate(r: Rng, p: Persona, lang: str) -> str:
    if lang == "en" and r.chance(60):
        age = r.choice((r.randint(51, 75), r.randint(2, 25)))
        return f"{r.chars('ABCDEFGHKLMNOPRSVWY', 2)}{age:02d} {r.chars('ABCDEFGHJKLMNOPRSTUVWXYZ', 3)}"
    code = r.choice(DE_PLATE_CODES)
    letters = r.chars("ABCDEFGHJKLMNPRSTUVWXYZ", r.randint(1, 2))
    number = str(r.randint(1, 9999))
    suffix = r.choice(("", "", "", "", "E", "H"))
    return r.choice(
        (
            f"{code}-{letters} {number}{suffix}",
            f"{code} {letters} {number}{suffix}",
            f"{code}-{letters}-{number}{suffix}",
        )
    )


def gen_bic(r: Rng, p: Persona, lang: str) -> str:
    location = r.choice(UPPER + "23456789") + r.choice(UPPER + "123456789")
    branch = r.choice(("", "", "XXX", r.chars(ALNUM, 3)))
    return (
        r.chars(UPPER, 4) + r.choice(("DE", "DE", "AT", "CH", "FR", "NL", "IT", "ES", "GB", "BE")) + location + branch
    )


def gen_dob(r: Rng, p: Persona, lang: str) -> str:
    return format_date(r, lang, p.dob)


def gen_employee_id(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(
        (
            f"MA-{r.digits(5)}",
            f"P{r.digits(6)}",
            f"EMP-{r.randint(2015, 2026)}-{r.digits(4)}",
            f"E{r.digits(5)}",
            f"PN {r.digits(6)}",
        )
    )


def gen_customer_id(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(
        (
            f"KD-{r.randint(2018, 2026)}-{r.digits(5)}",
            f"K{r.digits(7)}",
            f"CUST-{r.digits(6)}",
            f"{r.digits(8)}",
            f"C-{r.digits(3)}-{r.digits(4)}",
        )
    )


def gen_patient_id(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(
        (f"PAT-{r.randint(2015, 2026)}-{r.digits(6)}", f"P{r.digits(8)}", f"MRN{r.digits(7)}", f"{r.digits(10)}")
    )


def gen_student_id(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(
        (r.digits(7), str(r.randint(1, 9)) + r.digits(5), f"S{r.digits(7)}", f"{r.randint(2019, 2026)}{r.digits(5)}")
    )


def gen_applicant_id(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(
        (f"BW-{r.randint(2024, 2026)}-{r.digits(5)}", f"APP-{r.digits(6)}", f"B{r.digits(6)}", f"CAND-{r.digits(5)}")
    )


def gen_username(r: Rng, p: Persona, lang: str) -> str:
    first, last = ascii_fold(p.first).lower(), ascii_fold(p.last).lower().replace(" ", "")
    return r.choice(
        (
            f"{first[0]}{last}",
            f"{first}.{last}",
            f"{last}{p.dob.year % 100:02d}",
            f"{first}_{last[0]}",
            f"{first}{r.digits(3)}",
        )
    )


def gen_url(r: Rng, p: Persona, lang: str) -> str:
    first, last = ascii_fold(p.first).lower(), ascii_fold(p.last).lower().replace(" ", "-")
    business, tld = r.choice(("praxis", "design", "fotografie", "studio")), r.choice(("de", "com", "eu"))
    return r.choice(
        (
            f"https://www.{last}-{business}.{tld}",
            f"https://www.linkedin.com/in/{first}-{last}-{r.chars('abcdef0123456789', 6)}",
            f"https://{first}{last}.{r.choice(('de', 'com', 'net'))}/{r.choice(('kontakt', 'about', 'blog', 'cv'))}",
            f"https://www.xing.com/profile/{first.capitalize()}_{last.capitalize()}{r.digits(3)}",
        )
    )


BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = BASE58[remainder] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def gen_crypto(r: Rng, p: Persona, lang: str) -> str:
    version = r.choice((b"\x00", b"\x05"))
    return base58check(version + bytes(r.below(256) for _ in range(20)))


def gen_dea(r: Rng, p: Persona, lang: str) -> str:
    body = r.digits(6)
    check = (int(body[0]) + int(body[2]) + int(body[4]) + 2 * (int(body[1]) + int(body[3]) + int(body[5]))) % 10
    return r.choice("ABFGMPRX") + ascii_fold(p.last)[0].upper() + body + str(check)


def gen_itin(r: Rng, p: Persona, lang: str) -> str:
    middle = r.choice(tuple(range(50, 66)) + tuple(range(70, 89)) + (90, 91, 92) + tuple(range(94, 100)))
    return f"9{r.digits(2)}-{middle}-{r.digits(4)}"


MBI_LETTERS = "ACDEFGHJKMNPQRTUVWXY"


def gen_mbi(r: Rng, p: Persona, lang: str) -> str:
    alnum = MBI_LETTERS + "0123456789"
    value = (
        str(r.randint(1, 9))
        + r.choice(MBI_LETTERS)
        + r.choice(alnum)
        + r.digits(1)
        + r.choice(MBI_LETTERS)
        + r.choice(alnum)
        + r.digits(1)
        + r.chars(MBI_LETTERS, 2)
        + r.digits(2)
    )
    return r.choice((value, f"{value[:4]}-{value[4:7]}-{value[7:]}"))


def gen_npi(r: Rng, p: Persona, lang: str) -> str:
    body = r.choice("12") + r.digits(8)
    return body + luhn_check_digit("80840" + body)


def gen_nhs(r: Rng, p: Persona, lang: str) -> str:
    while True:
        body = str(r.randint(4, 9)) + r.digits(8)
        check = 11 - sum(int(char) * (10 - index) for index, char in enumerate(body)) % 11
        if check != 10:
            value = body + str(0 if check == 11 else check)
            return r.choice((value, f"{value[:3]} {value[3:6]} {value[6:]}"))


def gen_uk_postcode(r: Rng, p: Persona, lang: str) -> str:
    _, outwards = r.choice(UK_CITIES)
    return f"{r.choice(outwards)} {r.randint(1, 9)}{r.chars('ABDEFGHJLNPQRSTUWXYZ', 2)}"


BSNR_REGIONS = (
    "01", "02", "03", "17", "20", "38", "46", "51", "52", "60", "61", "62", "71", "72", "73", "78", "83", "88", "93",
    "98",
)


def gen_bsnr(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(BSNR_REGIONS) + r.digits(7)


def gen_register(r: Rng, p: Persona, lang: str) -> str:
    return f"{r.choice(('HRB', 'HRB', 'HRA'))} {r.randint(1000, 250000)}"


def gen_plz(r: Rng, p: Persona, lang: str) -> str:
    _, low, high = r.choice(DE_CITIES)
    return f"{r.randint(low, high):05d}"


def gen_vat_de(r: Rng, p: Persona, lang: str) -> str:
    body = str(r.randint(1, 9)) + r.digits(7)
    value = f"DE{body}{iso7064_mod11_10(body)}"
    return r.choice((value, value, f"DE {value[2:5]} {value[5:8]} {value[8:]}"))


NIF_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def gen_nie(r: Rng, p: Persona, lang: str) -> str:
    prefix, body = r.choice("XYZ"), r.digits(7)
    return f"{prefix}{body}{NIF_LETTERS[int(str('XYZ'.index(prefix)) + body) % 23]}"


def gen_nif(r: Rng, p: Persona, lang: str) -> str:
    body = str(r.randint(1, 9)) + r.digits(7)
    return f"{body}{NIF_LETTERS[int(body) % 23]}"


CF_ODD = dict(
    zip(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        (1, 0, 5, 7, 9, 13, 15, 17, 19, 21)
        + (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23),
    )
)
CF_EVEN = {**{str(digit): digit for digit in range(10)}, **{char: index for index, char in enumerate(UPPER)}}
CF_MONTHS = "ABCDEHLMPRST"
CF_TOWNS = ("H501", "F205", "L219", "A944", "G273", "F839", "D612", "L736", "C351", "A662")


def _cf_part(name: str, given: bool) -> str:
    letters = re.sub(r"[^A-Z]", "", ascii_fold(name).upper())
    consonants = [char for char in letters if char not in "AEIOU"]
    vowels = [char for char in letters if char in "AEIOU"]
    if given and len(consonants) >= 4:
        consonants = [consonants[0], consonants[2], consonants[3]]
    return ("".join(consonants + vowels) + "XXX")[:3]


def italian_fiscal_code(last: str, first: str, birth: date, female: bool, town: str) -> str:
    body = (
        _cf_part(last, False)
        + _cf_part(first, True)
        + f"{birth.year % 100:02d}"
        + CF_MONTHS[birth.month - 1]
        + f"{birth.day + (40 if female else 0):02d}"
        + town
    )
    total = sum(CF_ODD[char] if index % 2 == 0 else CF_EVEN[char] for index, char in enumerate(body))
    return body + UPPER[total % 26]


def gen_fiscal_code(r: Rng, p: Persona, lang: str) -> str:
    return italian_fiscal_code(p.last, p.first, p.dob, p.female, r.choice(CF_TOWNS))


def gen_it_vat(r: Rng, p: Persona, lang: str) -> str:
    body = r.digits(7) + f"{r.randint(1, 100):03d}"
    odd = sum(int(body[index]) for index in range(0, 10, 2))
    even = sum(cross_sum(int(body[index]) * 2) for index in range(1, 10, 2))
    value = body + str((10 - (odd + even) % 10) % 10)
    return r.choice((value, f"IT{value}"))


HETU_CHECK = "0123456789ABCDEFHJKLMNPRSTUVWXY"


def gen_hetu(r: Rng, p: Persona, lang: str) -> str:
    stem = f"{p.dob.day:02d}{p.dob.month:02d}{p.dob.year % 100:02d}"
    serial = r.randint(2, 899)
    serial += (serial % 2 == 0) != p.female  # odd: male, even: female
    sign = "A" if p.dob.year >= 2000 else "-"
    return f"{stem}{sign}{serial:03d}{HETU_CHECK[int(stem + f'{serial:03d}') % 31]}"


def gen_pesel(r: Rng, p: Persona, lang: str) -> str:
    month = p.dob.month + (20 if p.dob.year >= 2000 else 0)
    sex = r.choice("02468") if p.female else r.choice("13579")
    body = f"{p.dob.year % 100:02d}{month:02d}{p.dob.day:02d}{r.digits(3)}{sex}"
    total = sum(int(char) * weight for char, weight in zip(body, (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)))
    return body + str((10 - total % 10) % 10)


def gen_personnummer(r: Rng, p: Persona, lang: str) -> str:
    stem = f"{p.dob.year % 100:02d}{p.dob.month:02d}{p.dob.day:02d}{r.digits(3)}"
    return f"{stem[:6]}-{stem[6:]}{luhn_check_digit(stem)}"


def gen_se_org(r: Rng, p: Persona, lang: str) -> str:
    stem = r.choice(("55", "56", "71", "80", "82")) + str(r.randint(2, 9)) + r.digits(6)
    value = stem + luhn_check_digit(stem)
    return f"{value[:6]}-{value[6:]}"


def gen_tckn(r: Rng, p: Persona, lang: str) -> str:
    digits = [r.randint(1, 9)] + [r.below(10) for _ in range(8)]
    tenth = (
        (digits[0] + digits[2] + digits[4] + digits[6] + digits[8]) * 7
        - (digits[1] + digits[3] + digits[5] + digits[7])
    ) % 10
    digits.append(tenth)
    digits.append(sum(digits) % 10)
    return "".join(str(digit) for digit in digits)


def gen_abn(r: Rng, p: Persona, lang: str) -> str:
    weights = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    while True:
        tail = r.digits(9)
        for head in range(10, 100):
            digits = [int(char) for char in f"{head}{tail}"]
            digits[0] -= 1
            if sum(digit * weight for digit, weight in zip(digits, weights)) % 89 == 0:
                value = f"{head}{tail}"
                return f"{value[:2]} {value[2:5]} {value[5:8]} {value[8:]}"


def gen_acn(r: Rng, p: Persona, lang: str) -> str:
    body = r.digits(8)
    total = sum(int(char) * weight for char, weight in zip(body, (8, 7, 6, 5, 4, 3, 2, 1)))
    value = body + str((10 - total % 10) % 10)
    return f"{value[:3]} {value[3:6]} {value[6:]}"


def gen_medicare(r: Rng, p: Persona, lang: str) -> str:
    body = str(r.randint(2, 6)) + r.digits(7)
    check = sum(int(char) * weight for char, weight in zip(body, (1, 3, 7, 9, 1, 3, 7, 9))) % 10
    value = f"{body}{check}{r.randint(1, 9)}"
    return r.choice((f"{value[:4]} {value[4:9]} {value[9]}", value))


def gen_tfn(r: Rng, p: Persona, lang: str) -> str:
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    while True:
        body = str(r.randint(1, 9)) + r.digits(7)
        last = sum(int(char) * weight for char, weight in zip(body, weights)) % 11
        if last < 10:
            value = body + str(last)
            return f"{value[:3]} {value[3:6]} {value[6:]}"


def gen_sin(r: Rng, p: Persona, lang: str) -> str:
    body = r.choice("1234567") + r.digits(7)
    value = body + luhn_check_digit(body)
    return r.choice((f"{value[:3]} {value[3:6]} {value[6:]}", f"{value[:3]}-{value[3:6]}-{value[6:]}"))


def gen_aadhaar(r: Rng, p: Persona, lang: str) -> str:
    while True:
        body = str(r.randint(2, 9)) + r.digits(10)
        value = body + verhoeff_check_digit(body)
        if value != value[::-1]:
            return r.choice((f"{value[:4]} {value[4:8]} {value[8:]}", value))


def indian_pan(r: Rng, p: Persona, holder: str = "P") -> str:
    return r.chars(UPPER, 3) + holder + ascii_fold(p.last)[0].upper() + r.digits(4) + r.choice(UPPER)


def gen_in_pan(r: Rng, p: Persona, lang: str) -> str:
    return indian_pan(r, p)


GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gen_gstin(r: Rng, p: Persona, lang: str) -> str:
    body = f"{r.randint(1, 37):02d}" + indian_pan(r, p, r.choice("CFP")) + str(r.randint(1, 9)) + "Z"
    total = 0
    for index, char in enumerate(body):
        product = GSTIN_CHARS.index(char) * (2 if index % 2 else 1)
        total += product // 36 + product % 36
    return body + GSTIN_CHARS[(36 - total % 36) % 36]


def gen_voter(r: Rng, p: Persona, lang: str) -> str:
    return r.chars(UPPER, 3) + r.digits(7)


def korean_number(r: Rng, p: Persona, foreigner: bool) -> str:
    century = 0 if p.dob.year < 2000 else 2
    sex = (1 if not p.female else 2) + century + (4 if foreigner else 0)
    body = f"{p.dob.year % 100:02d}{p.dob.month:02d}{p.dob.day:02d}{sex}{r.randint(0, 95):02d}{r.digits(3)}"
    total = sum(int(char) * weight for char, weight in zip(body, (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)))
    check = ((13 if foreigner else 11) - total % 11) % 10
    return f"{body[:6]}-{body[6:]}{check}"


def gen_rrn(r: Rng, p: Persona, lang: str) -> str:
    return korean_number(r, p, False)


def gen_frn(r: Rng, p: Persona, lang: str) -> str:
    return korean_number(r, p, True)


def gen_brn(r: Rng, p: Persona, lang: str) -> str:
    body = r.digits(9)
    weights = (1, 3, 7, 1, 3, 7, 1, 3, 5)
    total = sum(int(char) * weight for char, weight in zip(body[:8], weights))
    last = int(body[8]) * 5
    total += last // 10 + last
    value = body + str((10 - total % 10) % 10)
    return f"{value[:3]}-{value[3:5]}-{value[5:]}"


def gen_nin(r: Rng, p: Persona, lang: str) -> str:
    body = str(r.randint(1, 9)) + r.digits(9)
    return body + verhoeff_check_digit(body)


def gen_ph_tin(r: Rng, p: Persona, lang: str) -> str:
    while True:
        body = str(r.randint(1, 9)) + r.digits(7)
        check = sum(int(char) * weight for char, weight in zip(body, (9, 8, 7, 6, 5, 4, 3, 2))) % 11
        if check < 10:
            value = body + str(check)
            return f"{value[:3]}-{value[3:6]}-{value[6:]}-{r.choice(('000', '000', '001', '002'))}"


def gen_umid(r: Rng, p: Persona, lang: str) -> str:
    return f"{r.choice(('0111', '0028', '0033', '0104'))}-{r.digits(7)}-{r.digits(1)}"


def gen_nric(r: Rng, p: Persona, lang: str) -> str:
    prefix = r.choice("STFG")
    body = r.digits(7)
    total = sum(int(char) * weight for char, weight in zip(body, (2, 7, 6, 5, 4, 3, 2))) + (4 if prefix in "TG" else 0)
    table = "JZIHGFEDCBA" if prefix in "ST" else "XWUTRQPNMLK"
    return f"{prefix}{body}{table[total % 11]}"


def gen_uen(r: Rng, p: Persona, lang: str) -> str:
    if r.chance(50):
        body = r.digits(8)
        total = sum(int(char) * weight for char, weight in zip(body, (10, 4, 9, 3, 8, 2, 7, 1)))
        return body + "XMKECAWLJDB"[total % 11]
    body = str(r.randint(1995, 2024)) + r.digits(5)
    total = sum(int(char) * weight for char, weight in zip(body, (10, 8, 6, 4, 9, 7, 5, 3, 1)))
    return body + "ZKCMDNERGWH"[total % 11]


def gen_tnin(r: Rng, p: Persona, lang: str) -> str:
    body = str(r.randint(1, 8)) + r.digits(11)
    total = sum(int(char) * (13 - index) for index, char in enumerate(body))
    value = body + str((11 - total % 11) % 10)
    return r.choice((value, f"{value[0]}-{value[1:5]}-{value[5:10]}-{value[10:12]}-{value[12]}"))


def gen_za_id(r: Rng, p: Persona, lang: str) -> str:
    gender = r.randint(5000, 9999) if not p.female else r.randint(0, 4999)
    body = f"{p.dob.year % 100:02d}{p.dob.month:02d}{p.dob.day:02d}{gender:04d}{r.choice('01')}8"
    return body + luhn_check_digit(body)


def gen_person(r: Rng, p: Persona, lang: str) -> str:
    return f"{p.first} {p.last}"


def gen_org(r: Rng, p: Persona, lang: str) -> str:
    return org_name(r, lang)


def gen_city(r: Rng, p: Persona, lang: str) -> str:
    return p.city


def gen_date(r: Rng, p: Persona, lang: str) -> str:
    return format_date(r, lang, recent_date(r))


def gen_street(r: Rng, p: Persona, lang: str) -> str:
    return p.street


NATIONALITIES = {
    "de": ("deutsch", "österreichisch", "italienisch", "türkisch", "polnisch", "spanisch", "niederländisch"),
    "en": ("German", "Austrian", "Italian", "Turkish", "Polish", "Spanish", "Dutch"),
}
RELIGIONS = {
    "de": ("evangelisch", "römisch-katholisch", "muslimisch", "jüdisch", "orthodox"),
    "en": ("Protestant", "Roman Catholic", "Muslim", "Jewish", "Orthodox"),
}


def gen_nationality(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(NATIONALITIES[lang])


def gen_religion(r: Rng, p: Persona, lang: str) -> str:
    return r.choice(RELIGIONS[lang])


# ── entity kinds ─────────────────────────────────────────────────────────────


class Kind(NamedTuple):
    name: str
    entity: str
    gen: Gen
    labels: dict[str, tuple[str, ...]]
    keys: dict[str, str]
    bare: dict[str, tuple[str, ...]] = {}


def kind(
    name: str,
    entity: str,
    gen: Gen,
    de: tuple[str, ...],
    en: tuple[str, ...],
    key_de: str,
    key_en: str,
    bare_de: tuple[str, ...] = (),
    bare_en: tuple[str, ...] = (),
) -> Kind:
    bare = {"de": bare_de, "en": bare_en} if bare_de or bare_en else {}
    return Kind(name, entity, gen, {"de": de, "en": en}, {"de": key_de, "en": key_en}, bare)


KINDS: tuple[Kind, ...] = (
    kind(
        "email", "pii.email", gen_email, ("E-Mail", "E-Mail-Adresse"), ("Email", "Email address"), "email", "email",
        ("Sie erreichen mich unter {v}.", "Bitte schreiben Sie an {v}."),
        ("You can reach me at {v}.", "Please reply to {v}."),
    ),
    kind(
        "phone", "pii.phone", gen_phone, ("Telefon", "Mobil", "Tel."), ("Phone", "Mobile", "Tel."), "telefon",
        "phone", ("Rufen Sie mich gern unter {v} an.",), ("Call me on {v} if anything is unclear.",),
    ),
    kind(
        "ip", "pii.ip_address", gen_ip, ("IP-Adresse",), ("IP address",), "ip_adresse", "ip_address",
        ("Der Zugriff kam von {v}.",), ("The login came from {v}.",),
    ),
    kind(
        "mac", "pii.mac_address", gen_mac, ("MAC-Adresse",), ("MAC address",), "mac", "mac_address",
        ("Mein Laptop meldet sich mit {v} im WLAN an.",), ("My laptop joins the Wi-Fi as {v}.",),
    ),
    kind(
        "iban", "pii.iban", gen_iban, ("IBAN",), ("IBAN",), "iban", "iban",
        ("Bitte überweisen Sie den Betrag auf {v}.",), ("Please transfer the amount to {v}.",),
    ),
    kind(
        "pan", "pii.credit_card.pan", gen_pan, ("Kartennummer", "Kreditkarte"), ("Card number", "Credit card"),
        "kartennummer", "card_number", ("Belasten Sie bitte meine Karte {v}.",), ("Please charge my card {v}.",),
    ),
    kind(
        "account", "pii.financial_account_number", gen_account, ("Kontonummer", "Konto-Nr."),
        ("Account number", "Bank account"), "kontonummer", "account_number",
    ),
    kind(
        "ssn", "pii.us.social_security_number", gen_ssn, ("US-Sozialversicherungsnummer", "SSN"),
        ("SSN", "Social Security number"), "ssn", "ssn",
    ),
    kind(
        "nino", "pii.uk.national_insurance_number", gen_nino, ("NINO", "britische Sozialversicherungsnummer"),
        ("National Insurance number", "NINO"), "nino", "ni_number",
    ),
    kind(
        "steuer_id", "pii.de.tax_id", gen_steuer_id, ("Steuer-ID", "Steueridentifikationsnummer", "IdNr."),
        ("German tax ID", "Steuer-ID"), "steuer_id", "tax_id",
    ),
    kind(
        "tax_number", "pii.de.tax_number", gen_tax_number, ("Steuernummer", "St.-Nr."),
        ("German tax number", "Steuernummer"), "steuernummer", "tax_number",
    ),
    kind(
        "rvnr", "pii.de.social_security_number", gen_rvnr,
        ("Rentenversicherungsnummer", "Sozialversicherungsnummer", "SV-Nr."),
        ("German pension insurance number", "Sozialversicherungsnummer"), "sv_nummer", "pension_insurance_number",
    ),
    kind(
        "kvnr", "pii.de.health_insurance_number", gen_kvnr, ("Versichertennummer", "KVNR"),
        ("health insurance number", "KVNR"), "versichertennummer", "health_insurance_number",
    ),
    kind(
        "lanr", "pii.de.lanr", gen_lanr, ("LANR", "lebenslange Arztnummer"), ("LANR", "physician number"), "lanr",
        "lanr",
    ),
    kind(
        "passport", "entity.passport_number", gen_passport, ("Reisepassnummer", "Passnummer"),
        ("Passport number", "Passport no."), "passnummer", "passport_number",
    ),
    kind(
        "id_card", "pii.identity_card_number", gen_id_card, ("Personalausweisnummer", "Ausweisnummer"),
        ("Identity card number", "ID card number"), "ausweisnummer", "id_card_number",
    ),
    kind(
        "driver_license", "entity.driver_license_number", gen_driver_license, ("Führerscheinnummer",),
        ("Driver's licence number", "Driver license number"), "fuehrerschein", "driver_license",
    ),
    kind(
        "plate", "pii.license_plate", gen_plate, ("Kfz-Kennzeichen", "Kennzeichen"),
        ("Vehicle registration", "Number plate"), "kennzeichen", "license_plate",
        ("Mein Wagen mit dem Kennzeichen {v} stand vor dem Haus.",),
        ("My car, registration {v}, was parked outside.",),
    ),
    kind("bic", "pii.swift_bic", gen_bic, ("BIC",), ("BIC", "SWIFT code"), "bic", "bic"),
    kind("cvv", "pii.credit_card.cvv", gen_cvv, ("Prüfnummer", "CVC"), ("CVV", "Security code"), "cvc", "cvv"),
    kind(
        "expiry", "pii.credit_card.expiry", gen_expiry, ("gültig bis", "Ablaufdatum"), ("Expiry", "Expiration date"),
        "gueltig_bis", "expiry",
    ),
    kind(
        "dob", "pii.date_of_birth", gen_dob, ("Geburtsdatum", "geboren am"), ("Date of birth", "DOB"), "geburtsdatum",
        "date_of_birth",
    ),
    kind(
        "employee_id", "pii.employee_id", gen_employee_id, ("Personalnummer", "Mitarbeiternummer"),
        ("Employee ID", "Staff number"), "personalnummer", "employee_id",
    ),
    kind(
        "customer_id", "pii.customer_id", gen_customer_id, ("Kundennummer",), ("Customer ID", "Customer number"),
        "kundennummer", "customer_id",
    ),
    kind(
        "patient_id", "pii.patient_id", gen_patient_id, ("Patientennummer", "Patienten-ID"), ("Patient ID", "MRN"),
        "patientennummer", "patient_id",
    ),
    kind(
        "student_id", "pii.student_id", gen_student_id, ("Matrikelnummer",), ("Student ID", "Student number"),
        "matrikelnummer", "student_id",
    ),
    kind(
        "applicant_id", "pii.applicant_id", gen_applicant_id, ("Bewerbernummer", "Bewerber-ID"),
        ("Applicant ID", "Candidate ID"), "bewerbernummer", "applicant_id",
    ),
    kind(
        "username", "pii.username", gen_username, ("Benutzername", "Login"), ("Username", "User name"),
        "benutzername", "username",
    ),
    kind(
        "url", "pii.url", gen_url, ("Webseite", "Profil"), ("Website", "Profile"), "webseite", "website",
        ("Mehr über mich finden Sie unter {v}.",), ("More about me at {v}.",),
    ),
    kind(
        "crypto", "pii.crypto_wallet", gen_crypto, ("Bitcoin-Adresse", "Wallet"), ("Bitcoin address", "Wallet"),
        "wallet", "btc_wallet",
    ),
    kind(
        "dea", "pii.us.medical_license", gen_dea, ("DEA-Nummer",), ("DEA number", "DEA registration"), "dea_nummer",
        "dea_number",
    ),
    kind(
        "itin", "pii.us.itin", gen_itin, ("ITIN",), ("ITIN", "Individual Taxpayer Identification Number"), "itin",
        "itin",
    ),
    kind("mbi", "pii.us.mbi", gen_mbi, ("US-Medicare-ID",), ("Medicare Beneficiary Identifier", "MBI"), "mbi", "mbi"),
    kind("npi", "pii.us.npi", gen_npi, ("NPI",), ("NPI", "National Provider Identifier"), "npi", "npi"),
    kind("nhs", "pii.uk.nhs_number", gen_nhs, ("NHS-Nummer",), ("NHS number", "NHS no."), "nhs_nummer", "nhs_number"),
    kind(
        "uk_postcode", "pii.uk.postcode", gen_uk_postcode, ("britischer Postcode",), ("Postcode",), "postcode",
        "postcode",
    ),
    kind(
        "bsnr", "pii.de.bsnr", gen_bsnr, ("BSNR", "Betriebsstättennummer"), ("BSNR", "practice number"), "bsnr", "bsnr"
    ),
    kind(
        "register", "pii.de.commercial_register", gen_register, ("Handelsregister", "Registernummer"),
        ("Commercial register", "Register number"), "handelsregister", "commercial_register",
    ),
    kind("plz", "pii.de.postal_code", gen_plz, ("PLZ", "Postleitzahl"), ("German postcode", "PLZ"), "plz", "zip"),
    kind(
        "vat_de", "pii.de.vat_id", gen_vat_de, ("USt-IdNr.", "Umsatzsteuer-ID"), ("VAT ID", "VAT number"), "ust_id",
        "vat_id",
    ),
    kind("nie", "pii.es.nie", gen_nie, ("NIE",), ("NIE", "Spanish foreigner ID"), "nie", "nie"),
    kind("nif", "pii.es.nif", gen_nif, ("NIF", "DNI"), ("NIF", "DNI"), "nif", "nif"),
    kind(
        "fiscal_code", "pii.it.fiscal_code", gen_fiscal_code, ("Codice Fiscale",),
        ("Codice Fiscale", "Italian tax code"), "codice_fiscale", "fiscal_code",
    ),
    kind(
        "it_vat", "pii.it.vat_code", gen_it_vat, ("Partita IVA",), ("Partita IVA", "Italian VAT number"),
        "partita_iva", "it_vat",
    ),
    kind(
        "hetu", "pii.fi.personal_identity_code", gen_hetu, ("finnische Personenkennung", "HETU"),
        ("Finnish personal identity code", "HETU"), "hetu", "hetu",
    ),
    kind("pesel", "pii.pl.pesel", gen_pesel, ("PESEL",), ("PESEL",), "pesel", "pesel"),
    kind(
        "personnummer", "pii.se.personnummer", gen_personnummer, ("Personnummer",),
        ("Swedish personnummer", "Personnummer"), "personnummer", "personnummer",
    ),
    kind(
        "se_org", "pii.se.organisationsnummer", gen_se_org, ("Organisationsnummer",),
        ("Organisationsnummer", "Swedish company number"), "organisationsnummer", "org_number",
    ),
    kind(
        "tckn", "pii.tr.national_id", gen_tckn, ("T.C. Kimlik No.", "türkische Identitätsnummer"),
        ("Turkish ID number", "T.C. Kimlik No."), "tc_kimlik", "tr_id",
    ),
    kind("abn", "pii.au.abn", gen_abn, ("ABN",), ("ABN", "Australian Business Number"), "abn", "abn"),
    kind("acn", "pii.au.acn", gen_acn, ("ACN",), ("ACN", "Australian Company Number"), "acn", "acn"),
    kind(
        "medicare", "pii.au.medicare", gen_medicare, ("australische Medicare-Nummer",),
        ("Medicare number", "Medicare card"), "medicare", "medicare_number",
    ),
    kind("tfn", "pii.au.tfn", gen_tfn, ("TFN",), ("TFN", "Tax File Number"), "tfn", "tfn"),
    kind("sin", "pii.ca.sin", gen_sin, ("kanadische SIN",), ("SIN", "Social Insurance Number"), "sin", "sin"),
    kind(
        "aadhaar", "pii.in.aadhaar", gen_aadhaar, ("Aadhaar-Nummer",), ("Aadhaar number", "Aadhaar"), "aadhaar",
        "aadhaar",
    ),
    kind("gstin", "pii.in.gstin", gen_gstin, ("GSTIN",), ("GSTIN",), "gstin", "gstin"),
    kind(
        "in_pan", "pii.in.pan", gen_in_pan, ("indische PAN",), ("PAN", "Permanent Account Number"), "pan_indien",
        "in_pan",
    ),
    kind(
        "voter", "pii.in.voter_id", gen_voter, ("indische Wähler-ID", "EPIC-Nummer"), ("Voter ID", "EPIC number"),
        "epic", "voter_id",
    ),
    kind(
        "brn", "pii.kr.brn", gen_brn, ("koreanische Geschäftsregistrierungsnummer",),
        ("Business Registration Number", "BRN"), "brn", "brn",
    ),
    kind(
        "frn", "pii.kr.frn", gen_frn, ("koreanische Ausländerregistrierungsnummer",),
        ("Foreigner Registration Number", "FRN"), "frn", "frn",
    ),
    kind(
        "rrn", "pii.kr.rrn", gen_rrn, ("koreanische Resident Registration Number",),
        ("Resident Registration Number", "RRN"), "rrn", "rrn",
    ),
    kind("nin", "pii.ng.nin", gen_nin, ("nigerianische NIN",), ("NIN", "National Identification Number"), "nin", "nin"),
    kind(
        "ph_tin", "pii.ph.tin", gen_ph_tin, ("philippinische TIN",), ("TIN", "Taxpayer Identification Number"), "tin",
        "ph_tin",
    ),
    kind("umid", "pii.ph.umid", gen_umid, ("UMID-CRN",), ("UMID", "UMID CRN"), "umid", "umid"),
    kind("nric", "pii.sg.nric_fin", gen_nric, ("NRIC",), ("NRIC", "FIN"), "nric", "nric"),
    kind("uen", "pii.sg.uen", gen_uen, ("UEN",), ("UEN", "Unique Entity Number"), "uen", "uen"),
    kind(
        "tnin", "pii.th.tnin", gen_tnin, ("thailändische ID-Nummer",), ("Thai national ID", "Thai ID number"),
        "thai_id", "thai_id",
    ),
    kind(
        "za_id", "pii.za.id_number", gen_za_id, ("südafrikanische ID-Nummer",), ("South African ID number", "SA ID"),
        "za_id", "za_id",
    ),
    kind("person", "entity.person_name", gen_person, ("Name", "Ansprechpartner"), ("Name", "Contact"), "name", "name"),
    kind("org", "entity.organization", gen_org, ("Firma", "Arbeitgeber"), ("Company", "Employer"), "firma", "company"),
    kind("city", "entity.location", gen_city, ("Ort", "Wohnort"), ("City", "Town"), "ort", "city"),
    kind("date", "entity.date", gen_date, ("Termin", "Datum"), ("Appointment", "Date"), "datum", "date"),
    kind(
        "street", "entity.street_address", gen_street, ("Straße", "Anschrift"), ("Street", "Address"), "strasse",
        "street",
    ),
    kind(
        "nationality", "entity.nrp", gen_nationality, ("Staatsangehörigkeit",), ("Nationality",),
        "staatsangehoerigkeit", "nationality",
    ),
    kind("religion", "entity.nrp", gen_religion, ("Konfession", "Religion"), ("Religion",), "konfession", "religion"),
)
KIND_BY_NAME = {item.name: item for item in KINDS}
# Rendered by the document skeletons; extra fields draw from the rest.
SKELETON_ONLY = {"person", "city", "street", "date", "org"}

PROSE = {
    "de": (
        "Als {label} ist {v} hinterlegt.", "Bitte verwenden Sie für Rückfragen {label} {v}.",
        "Unsere Unterlagen nennen als {label}: {v}.", "Zur Zuordnung – {label}: {v}.",
        "Ich bestätige folgende Angabe ({label}): {v}.", "Nachtrag zu meinen Daten, {label} {v}.",
    ),
    "en": (
        "My {label} is {v}.", "Please quote {label} {v} in any reply.", "Our records list the {label} as {v}.",
        "For reference, {label}: {v}.", "The {label} on file is {v}.", "Correction to my details: {label} {v}.",
    ),
}


# ── hard negatives ───────────────────────────────────────────────────────────


def neg_invoice_number(r: Rng) -> str:
    return f"RE-{r.randint(2025, 2026)}-{r.digits(5)}"


def neg_order_number(r: Rng) -> str:
    return "45" + r.digits(8)


def neg_amount(r: Rng, lang: str) -> str:
    euros, cents = r.randint(12, 9999), r.below(100)
    if lang == "de":
        return f"{euros:,}".replace(",", ".") + f",{cents:02d} €"
    return f"£{euros:,}.{cents:02d}"


def neg_icd(r: Rng) -> str:
    return r.choice(("J45.0", "I10.90", "E11.9", "M54.5", "K21.0", "F32.1", "J06.9", "R51", "I48.0", "Z00.0"))


def neg_pzn(r: Rng) -> str:
    return r.digits(8)


def neg_version(r: Rng) -> str:
    return r.choice(
        (
            f"{r.randint(1, 12)}.{r.randint(0, 30)}.{r.randint(0, 99)}",
            f"{r.randint(1, 12)}.{r.randint(0, 9)}.{r.randint(0, 9)}.{r.randint(100, 9999)}",
        )
    )


def neg_commit(r: Rng) -> str:
    return r.chars("0123456789abcdef", r.choice((7, 8, 12)))


def neg_uuid(r: Rng) -> str:
    raw = r.chars("0123456789abcdef", 32)
    return f"{raw[:8]}-{raw[8:12]}-4{raw[13:16]}-a{raw[17:20]}-{raw[20:]}"


def neg_ticket(r: Rng) -> str:
    return r.digits(6)


def neg_creditor_id(r: Rng) -> str:
    return f"DE{r.digits(2)}ZZZ{r.digits(11)}"


def neg_tracking(r: Rng) -> str:
    return "00340" + r.digits(15)


def neg_invalid_luhn(r: Rng) -> str:
    payload = "4" + r.digits(14)
    wrong = (int(luhn_check_digit(payload)) + r.randint(1, 9)) % 10
    return payload + str(wrong)


def neg_invalid_steuer_id(r: Rng) -> str:
    while True:
        value = str(r.randint(1, 9)) + r.digits(10)
        if iso7064_mod11_10(value[:10]) != int(value[10]):
            return value


def neg_case_number(r: Rng) -> str:
    return f"{r.randint(1, 9)} {r.choice(('O', 'C', 'S', 'K'))} {r.randint(10, 999)}/{r.randint(20, 26)}"


# ── document builder ─────────────────────────────────────────────────────────


class Span(NamedTuple):
    entity: str
    value: str


class Neg(NamedTuple):
    kind: str
    value: str


PLACEHOLDER = re.compile(r"\{(\w+)\}")


class Doc:
    """Text under construction with code-point spans (Python ``str`` indices)."""

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.length = 0
        self.entities: list[dict[str, Any]] = []
        self.negatives: list[dict[str, Any]] = []

    def raw(self, text: str) -> None:
        self.parts.append(text)
        self.length += len(text)

    def put(self, item: str | Span | Neg) -> None:
        start = self.length
        if isinstance(item, Span):
            self.raw(item.value)
            self.entities.append({"entity_type": item.entity, "start": start, "end": self.length})
        elif isinstance(item, Neg):
            self.raw(item.value)
            self.negatives.append({"kind": item.kind, "start": start, "end": self.length})
        else:
            self.raw(item)

    def add(self, template: str, **values: str | Span | Neg) -> None:
        position = 0
        for match in PLACEHOLDER.finditer(template):
            self.raw(template[position : match.start()])
            self.put(values[match.group(1)])
            position = match.end()
        self.raw(template[position:])

    def text(self) -> str:
        return "".join(self.parts)


class Field(NamedTuple):
    kind: Kind
    value: str


def label(r: Rng, item: Kind, lang: str) -> str:
    return r.choice(item.labels[lang])


def prose(doc: Doc, r: Rng, lang: str, field: Field) -> None:
    span = Span(field.kind.entity, field.value)
    bare = field.kind.bare.get(lang, ())
    if bare and r.chance(40):
        doc.add(r.choice(bare), v=span)
    else:
        doc.add(r.choice(PROSE[lang]), label=label(r, field.kind, lang), v=span)


def key_value(doc: Doc, r: Rng, lang: str, field: Field, separator: str = ": ") -> None:
    doc.add("{label}" + separator + "{v}\n", label=label(r, field.kind, lang), v=Span(field.kind.entity, field.value))


def span(entity: str, value: str) -> Span:
    return Span(entity, value)


def name_span(p: Persona) -> Span:
    return span("entity.person_name", f"{p.first} {p.last}")


def surname_span(p: Persona) -> Span:
    return span("entity.person_name", p.last)


def address(doc: Doc, p: Persona, lang: str) -> None:
    doc.add("{street}\n", street=span("entity.street_address", p.street))
    if lang == "de":
        doc.add("{plz} {city}\n", plz=span("pii.de.postal_code", p.postal), city=span("entity.location", p.city))
    else:
        doc.add(
            "{city}\n{postcode}\n", city=span("entity.location", p.city), postcode=span("pii.uk.postcode", p.postal)
        )


def salutation(doc: Doc, p: Persona, lang: str) -> None:
    if lang == "de":
        doc.add(
            ("Sehr geehrte Frau {last},\n\n" if p.female else "Sehr geehrter Herr {last},\n\n"), last=surname_span(p)
        )
    else:
        doc.add(("Dear Ms {last},\n\n" if p.female else "Dear Mr {last},\n\n"), last=surname_span(p))


TOPICS = {
    "de": (
        ("Änderung meiner Kontaktdaten", "hiermit teile ich Ihnen meine aktualisierten Angaben mit."),
        ("Widerspruch gegen Bescheid", "gegen den Bescheid vom letzten Monat lege ich fristgerecht Widerspruch ein."),
        ("Kündigung meines Vertrags", "hiermit kündige ich meinen Vertrag zum nächstmöglichen Zeitpunkt."),
        ("Antrag auf Erstattung", "ich bitte um Erstattung der beigefügten Kosten."),
        ("Bewerbung als Sachbearbeiter", "anbei sende ich Ihnen meine Bewerbungsunterlagen."),
    ),
    "en": (
        ("Change of contact details", "please update your records with my new details below."),
        ("Appeal against decision", "I am writing to appeal the decision set out in your recent letter."),
        ("Cancellation of contract", "I hereby give notice to cancel my contract at the earliest possible date."),
        ("Reimbursement request", "please reimburse the costs listed in the attached receipts."),
        ("Job application", "please find enclosed my application documents."),
    ),
}


def render_letter(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    doc.add("{name}\n", name=name_span(p))
    address(doc, p, lang)
    doc.raw("\n")
    recipient = persona(r, lang)
    doc.add("{org}\n", org=span("entity.organization", org_name(r, lang)))
    address(doc, recipient, lang)
    doc.raw("\n")
    when = span("entity.date", format_date(r, lang, recent_date(r)))
    doc.add("{city}, {date}\n\n", city=span("entity.location", p.city), date=when)
    subject, opener = r.choice(TOPICS[lang])
    reference = Neg("case_number", neg_case_number(r))
    doc.add(
        ("Betreff: {subject} (Az. {ref})\n\n" if lang == "de" else "Re: {subject} (ref. {ref})\n\n"),
        subject=subject,
        ref=reference,
    )
    salutation(doc, recipient, lang)
    doc.raw((opener if lang == "de" else opener[0].upper() + opener[1:]) + " ")
    for field in fields:
        prose(doc, r, lang, field)
        doc.raw(" ")
    doc.raw("\n\n")
    doc.add("Mit freundlichen Grüßen\n{name}\n" if lang == "de" else "Yours sincerely,\n{name}\n", name=name_span(p))


FORMS = {
    "de": (
        "Antrag auf Kostenerstattung", "Personalfragebogen", "Mitgliedsantrag", "Anmeldung zur Weiterbildung",
        "Änderungsmitteilung",
    ),
    "en": (
        "Expense claim form", "New starter form", "Membership application", "Course registration",
        "Change of details form",
    ),
}


def render_form(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    doc.raw(f"{r.choice(FORMS[lang])}\n{'=' * 24}\n\n")
    separator = r.choice((": ", ":\t", " | "))
    doc.add(
        "{label}" + separator + "{v}\n",
        label="Name, Vorname" if lang == "de" else "Full name",
        v=span("entity.person_name", f"{p.last}, {p.first}" if lang == "de" else f"{p.first} {p.last}"),
    )
    doc.add(
        "{label}" + separator + "{v}\n",
        label=label(r, KIND_BY_NAME["dob"], lang),
        v=span("pii.date_of_birth", format_date(r, lang, p.dob)),
    )
    doc.add(
        "{label}" + separator + "{v}\n",
        label="Straße, Nr." if lang == "de" else "Address",
        v=span("entity.street_address", p.street),
    )
    if lang == "de":
        doc.add(
            "PLZ, Ort" + separator + "{plz} {city}\n",
            plz=span("pii.de.postal_code", p.postal),
            city=span("entity.location", p.city),
        )
    else:
        doc.add(
            "Town" + separator + "{city}\nPostcode" + separator + "{postcode}\n",
            city=span("entity.location", p.city),
            postcode=span("pii.uk.postcode", p.postal),
        )
    for field in fields:
        key_value(doc, r, lang, field, separator)
    doc.raw(
        "\n[x] "
        + (
            "Ich bestätige die Richtigkeit meiner Angaben.\n"
            if lang == "de"
            else "I confirm that the details above are correct.\n"
        )
    )
    doc.add(
        ("Ort, Datum: {city}, {date}\n" if lang == "de" else "Signed at {city} on {date}\n"),
        city=span("entity.location", p.city),
        date=span("entity.date", format_date(r, lang, recent_date(r))),
    )


def render_invoice(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    seller = persona(r, lang)
    doc.add("{org}\n", org=span("entity.organization", org_name(r, lang)))
    address(doc, seller, lang)
    doc.raw("\n")
    doc.add("{name}\n", name=name_span(p))
    address(doc, p, lang)
    doc.raw("\n")
    if lang == "de":
        doc.add(
            "Rechnung Nr. {number}\nRechnungsdatum: {date}\nIhre Bestellung: {order}\n",
            number=Neg("invoice_number", neg_invoice_number(r)),
            date=span("entity.date", format_date(r, lang, recent_date(r))),
            order=Neg("order_number", neg_order_number(r)),
        )
        doc.add("Kundennummer: {customer}\n\n", customer=span("pii.customer_id", gen_customer_id(r, p, lang)))
    else:
        doc.add(
            "Invoice no. {number}\nInvoice date: {date}\nYour order: {order}\n",
            number=Neg("invoice_number", neg_invoice_number(r)),
            date=span("entity.date", format_date(r, lang, recent_date(r))),
            order=Neg("order_number", neg_order_number(r)),
        )
        doc.add("Customer ID: {customer}\n\n", customer=span("pii.customer_id", gen_customer_id(r, p, lang)))
    items = {
        "de": ("Wartungspauschale", "Ersatzteil Pumpe", "Anfahrt", "Beratung (Std.)"),
        "en": ("Service fee", "Replacement pump", "Call-out charge", "Consulting (hours)"),
    }
    for _ in range(r.randint(1, 3)):
        doc.add(
            "{qty} x {item} ({article})  {amount}\n",
            qty=str(r.randint(1, 4)),
            item=r.choice(items[lang]),
            article=Neg("article_number", f"{r.digits(3)}-{r.digits(4)}-{r.digits(1)}"),
            amount=Neg("amount", neg_amount(r, lang)),
        )
    doc.add(
        ("Gesamtbetrag: {amount}\n\n" if lang == "de" else "Total due: {amount}\n\n"),
        amount=Neg("amount", neg_amount(r, lang)),
    )
    if lang == "de":
        doc.raw("Zahlbar innerhalb von 14 Tagen ohne Abzug.\n")
        doc.add(
            "Bankverbindung: IBAN {iban}, BIC {bic}\nGläubiger-ID: {creditor}\n",
            iban=span("pii.iban", gen_iban(r, p, lang)),
            bic=span("pii.swift_bic", gen_bic(r, p, lang)),
            creditor=Neg("creditor_id", neg_creditor_id(r)),
        )
    else:
        doc.raw("Payment due within 30 days.\n")
        doc.add(
            "Bank details: IBAN {iban}, BIC {bic}\n",
            iban=span("pii.iban", gen_iban(r, p, lang)),
            bic=span("pii.swift_bic", gen_bic(r, p, lang)),
        )
    for field in fields:
        key_value(doc, r, lang, field)
    if lang == "de":
        doc.add(
            "\nSitz der Gesellschaft: {city} · Amtsgericht {city2} {register} · USt-IdNr. {vat} · Steuernummer {tax}\n",
            city=span("entity.location", seller.city),
            city2=span("entity.location", seller.city),
            register=span("pii.de.commercial_register", gen_register(r, p, lang)),
            vat=span("pii.de.vat_id", gen_vat_de(r, p, lang)),
            tax=span("pii.de.tax_number", gen_tax_number(r, p, lang)),
        )
    else:
        doc.add(
            "\nRegistered office: {city} · VAT ID {vat}\n",
            city=span("entity.location", seller.city),
            vat=span("pii.de.vat_id", gen_vat_de(r, p, lang)),
        )


MEDICAL = {
    "de": (
        ("Asthma bronchiale", "Salbutamol 100 µg"), ("Essentielle Hypertonie", "Ramipril 5 mg"),
        ("Diabetes mellitus Typ 2", "Metformin 1000 mg"), ("Lumbago", "Ibuprofen 600 mg"),
        ("Refluxösophagitis", "Pantoprazol 40 mg"),
    ),
    "en": (
        ("bronchial asthma", "salbutamol 100 mcg"), ("essential hypertension", "ramipril 5 mg"),
        ("type 2 diabetes", "metformin 1000 mg"), ("low back pain", "ibuprofen 400 mg"),
        ("reflux oesophagitis", "omeprazole 20 mg"),
    ),
}


def render_medical_letter(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    clinic_place = persona(r, lang)
    doctor = persona(r, lang)
    clinic = r.choice(CLINIC[lang]).format(city=clinic_place.city, last=doctor.last)
    doc.add("{clinic}\n", clinic=span("entity.organization", clinic))
    address(doc, clinic_place, lang)
    if lang == "de":
        doc.add(
            "LANR {lanr} · BSNR {bsnr}\n\n",
            lanr=span("pii.de.lanr", gen_lanr(r, p, lang)),
            bsnr=span("pii.de.bsnr", gen_bsnr(r, p, lang)),
        )
        doc.add("Arztbrief vom {date}\n\n", date=span("entity.date", format_date(r, lang, recent_date(r))))
        doc.add(
            "Patient{suffix}: {name}, geb. {dob}\nVersichertennummer: {kvnr}\n\n",
            suffix="in" if p.female else "",
            name=name_span(p),
            dob=span("pii.date_of_birth", format_date(r, lang, p.dob)),
            kvnr=span("pii.de.health_insurance_number", gen_kvnr(r, p, lang)),
        )
        doc.add(
            "Sehr geehrte Kollegin, sehr geehrter Kollege,\n\n"
            "wir berichten über {art} {name}, {rel} sich am {date} in unserer Ambulanz vorstellte.\n\n",
            art="Frau" if p.female else "Herrn",
            rel="die" if p.female else "der",
            name=surname_span(p),
            date=span("entity.date", format_date(r, lang, recent_date(r))),
        )
    else:
        doc.add("\nDischarge summary, {date}\n\n", date=span("entity.date", format_date(r, lang, recent_date(r))))
        doc.add(
            "Patient: {name}, DOB {dob}\nNHS number: {nhs}\n\n",
            name=name_span(p),
            dob=span("pii.date_of_birth", format_date(r, lang, p.dob)),
            nhs=span("pii.uk.nhs_number", gen_nhs(r, p, lang)),
        )
        doc.add(
            "Dear Dr {doctor},\n\nThank you for referring {art} {name}, who was seen in clinic on {date}.\n\n",
            doctor=surname_span(doctor),
            art="Ms" if p.female else "Mr",
            name=surname_span(p),
            date=span("entity.date", format_date(r, lang, recent_date(r))),
        )
    for _ in range(r.randint(1, 2)):
        diagnosis, drug = r.choice(MEDICAL[lang])
        if lang == "de":
            doc.add(
                "Diagnose: {diagnosis} ({icd})\nMedikation: {drug}, PZN {pzn}\n",
                diagnosis=diagnosis,
                icd=Neg("icd10", neg_icd(r)),
                drug=drug,
                pzn=Neg("pzn", neg_pzn(r)),
            )
        else:
            doc.add(
                "Diagnosis: {diagnosis} ({icd})\nMedication: {drug}\n",
                diagnosis=diagnosis,
                icd=Neg("icd10", neg_icd(r)),
                drug=drug,
            )
    doc.raw("\n")
    for field in fields:
        prose(doc, r, lang, field)
        doc.raw(" ")
    doc.raw("\n\n")
    doc.add(
        "Mit kollegialen Grüßen\nDr. med. {name}\n" if lang == "de" else "Kind regards,\nDr {name}\n",
        name=name_span(doctor),
    )


def json_string(doc: Doc, item: str | Span | Neg) -> None:
    value = item if isinstance(item, str) else item.value
    encoded = json.dumps(value, ensure_ascii=False)
    if encoded[1:-1] != value:
        raise ValueError(f"value needs JSON escaping: {value!r}")
    doc.raw('"')
    doc.put(item)
    doc.raw('"')


def json_value(doc: Doc, value: Any, indent: int) -> None:
    pad = "  " * (indent + 1)
    if isinstance(value, dict):
        doc.raw("{\n")
        for index, (key, item) in enumerate(value.items()):
            doc.raw(f"{pad}{json.dumps(key, ensure_ascii=False)}: ")
            json_value(doc, item, indent + 1)
            doc.raw(",\n" if index < len(value) - 1 else "\n")
        doc.raw("  " * indent + "}")
    elif isinstance(value, list):
        doc.raw("[\n")
        for index, item in enumerate(value):
            doc.raw(pad)
            json_value(doc, item, indent + 1)
            doc.raw(",\n" if index < len(value) - 1 else "\n")
        doc.raw("  " * indent + "]")
    elif isinstance(value, bool):
        doc.raw("true" if value else "false")
    elif isinstance(value, int):
        doc.raw(str(value))
    else:
        json_string(doc, value)


def render_json(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    person: dict[str, Any] = {
        ("name" if lang == "de" else "full_name"): name_span(p),
        "email": span("pii.email", gen_email(r, p, lang)),
        ("telefon" if lang == "de" else "phone"): span("pii.phone", gen_phone(r, p, lang)),
        ("anschrift" if lang == "de" else "address"): {
            ("strasse" if lang == "de" else "street"): span("entity.street_address", p.street),
            ("plz" if lang == "de" else "postcode"): span(
                "pii.de.postal_code" if lang == "de" else "pii.uk.postcode", p.postal
            ),
            ("ort" if lang == "de" else "city"): span("entity.location", p.city),
        },
    }
    for field in fields:
        person[field.kind.keys[lang]] = span(field.kind.entity, field.value)
    record = {
        "id": Neg("uuid", neg_uuid(r)),
        "schema_version": Neg("version", neg_version(r)),
        ("kunde" if lang == "de" else "customer"): person,
        ("bestellungen" if lang == "de" else "orders"): [
            Neg("order_number", neg_order_number(r)) for _ in range(r.randint(1, 2))
        ],
        "active": r.chance(80),
    }
    json_value(doc, record, 0)
    doc.raw("\n")


def render_csv(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    delimiter = ";" if lang == "de" else ","
    columns = [KIND_BY_NAME["person"]] + [field.kind for field in fields]
    doc.raw(
        delimiter.join(
            ["nr" if lang == "de" else "row"]
            + [item.keys[lang] for item in columns]
            + ["betrag" if lang == "de" else "amount"]
        )
        + "\n"
    )
    for row in range(r.randint(2, 4)):
        holder = p if row == 0 else persona(r, lang)
        cells: list[str | Span | Neg] = [str(row + 1)]
        for index, item in enumerate(columns):
            value = fields[index - 1].value if row == 0 and index else item.gen(r, holder, lang)
            cells.append(Span(item.entity, value))
        cells.append(Neg("amount", neg_amount(r, lang)))
        for index, cell in enumerate(cells):
            if index:
                doc.raw(delimiter)
            value = cell if isinstance(cell, str) else cell.value
            if '"' in value:
                raise ValueError(f"CSV value contains a quote: {value!r}")
            quoted = delimiter in value or "\n" in value
            doc.raw('"' if quoted else "")
            doc.put(cell)
            doc.raw('"' if quoted else "")
        doc.raw("\n")


TICKET_MOOD = ("🙏", "😊", "😟", "🤔", "👍", "🚀", "⚠️")


def render_ticket(doc: Doc, r: Rng, lang: str, p: Persona, fields: list[Field]) -> None:
    email = gen_email(r, p, lang)
    if lang == "de":
        doc.add(
            "Ticket #{ticket} | Priorität: {prio} | Version {version}\n",
            ticket=Neg("ticket_number", neg_ticket(r)),
            prio=r.choice(("hoch", "normal", "niedrig")),
            version=Neg("version", neg_version(r)),
        )
        doc.add(
            "Von: {name} <{email}>\nBetreff: {subject}\n\n",
            name=name_span(p),
            email=span("pii.email", email),
            subject=r.choice(
                (
                    "Login klappt nicht",
                    "Rechnung doppelt abgebucht",
                    "Konto gesperrt",
                    "Datenauskunft nach Art. 15 DSGVO",
                )
            ),
        )
        doc.add("Hallo Support-Team {mood}\n\n", mood=r.choice(TICKET_MOOD))
        doc.raw("seit dem letzten Update komme ich nicht mehr in mein Konto. ")
    else:
        doc.add(
            "Ticket #{ticket} | Priority: {prio} | Build {version}\n",
            ticket=Neg("ticket_number", neg_ticket(r)),
            prio=r.choice(("high", "normal", "low")),
            version=Neg("version", neg_version(r)),
        )
        doc.add(
            "From: {name} <{email}>\nSubject: {subject}\n\n",
            name=name_span(p),
            email=span("pii.email", email),
            subject=r.choice(("Cannot log in", "Charged twice", "Account locked", "Subject access request")),
        )
        doc.add("Hi support team {mood}\n\n", mood=r.choice(TICKET_MOOD))
        doc.raw("since the last update I can no longer access my account. ")
    for field in fields:
        prose(doc, r, lang, field)
        doc.raw(" ")
    doc.add(
        "\n\n{thanks} {mood}\n{first}\n\n",
        thanks="Danke & Grüße" if lang == "de" else "Thanks,",
        mood=r.choice(TICKET_MOOD),
        first=span("entity.person_name", p.first),
    )
    doc.add("--- {log} ---\n", log="Log-Auszug" if lang == "de" else "log excerpt")
    username = gen_username(r, p, lang)
    doc.add(
        "08:{m}:{s} WARN auth failed user={user} src={ip} commit={commit}\n",
        m=f"{r.below(60):02d}",
        s=f"{r.below(60):02d}",
        user=span("pii.username", username),
        ip=span("pii.ip_address", gen_ip(r, p, lang)),
        commit=Neg("commit", neg_commit(r)),
    )
    doc.add(
        "08:{m}:{s} INFO request_id={uuid} firmware={fw}\n",
        m=f"{r.below(60):02d}",
        s=f"{r.below(60):02d}",
        uuid=Neg("uuid", neg_uuid(r)),
        fw=Neg("version", neg_version(r)),
    )
    if r.chance(40):
        doc.add(
            "08:{m}:{s} DEBUG tracking={tracking} voucher={voucher} ref={ref}\n",
            m=f"{r.below(60):02d}",
            s=f"{r.below(60):02d}",
            tracking=Neg("tracking_number", neg_tracking(r)),
            voucher=Neg("invalid_luhn", neg_invalid_luhn(r)),
            ref=Neg("invalid_steuer_id", neg_invalid_steuer_id(r)),
        )


RENDERERS: dict[str, Callable[[Doc, Rng, str, Persona, list[Field]], None]] = {
    "letter": render_letter, "form": render_form, "invoice": render_invoice, "medical_letter": render_medical_letter,
    "json": render_json, "csv": render_csv, "ticket": render_ticket,
}
EXTRA_FIELDS = {
    "letter": (2, 4), "form": (3, 7), "invoice": (1, 3), "medical_letter": (1, 3), "json": (2, 5), "csv": (2, 4),
    "ticket": (2, 4),
}


# ── corpus ───────────────────────────────────────────────────────────────────


def pick_kinds(r: Rng, lang: str, count: int, usage: Counter) -> list[Kind]:
    """Least-used kinds first (ties broken by the stream), so every kind reaches each language."""
    pool = [item for item in KINDS if item.name not in SKELETON_ONLY]
    order = sorted(pool, key=lambda item: (usage[(lang, item.name)], r.below(1 << 30)))
    window = order[: count * 3]
    r.shuffle(window)
    return window[:count]


def generate(seed: str, split: str, docs: int) -> list[dict[str, Any]]:
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}")
    usage: Counter = Counter()
    rows = []
    for number in range(docs):
        doc_type = DOC_TYPES[number % len(DOC_TYPES)]
        lang = LANGUAGES[(number // len(DOC_TYPES)) % len(LANGUAGES)]
        r = Rng(f"{SCHEMA}:{GENERATOR_VERSION}:{seed}:{split}:{number}")
        p = persona(r, lang)
        low, high = EXTRA_FIELDS[doc_type]
        kinds = pick_kinds(r, lang, r.randint(low, high), usage)
        for item in kinds:
            usage[(lang, item.name)] += 1
        fields = [Field(item, item.gen(r, p, lang)) for item in kinds]
        doc = Doc()
        RENDERERS[doc_type](doc, r, lang, p, fields)
        identifier = f"synth-{split}-{number:04d}"
        rows.append(
            {
                "id": identifier,
                "group_id": identifier,
                "corpus": CORPUS_ID,
                "language": lang,
                "doc_type": doc_type,
                "text": doc.text(),
                "entities": sorted(doc.entities, key=lambda item: (item["start"], item["end"], item["entity_type"])),
                "hard_negatives": sorted(doc.negatives, key=lambda item: (item["start"], item["end"], item["kind"])),
            }
        )
    return rows


def coverage(rows: list[dict[str, Any]]) -> Counter:
    return Counter((row["language"], entity["entity_type"]) for row in rows for entity in row["entities"])


def entity_ids() -> list[str]:
    return sorted({item.entity for item in KINDS})


def validate_rows(rows: list[dict[str, Any]], min_per_language: int = MIN_PER_LANGUAGE) -> list[str]:
    """Problems of generated rows: span bounds, overlaps, and per-language coverage."""
    problems = []
    for row in rows:
        text = row["text"]
        spans = [(item["start"], item["end"], item["entity_type"]) for item in row["entities"]]
        spans += [(item["start"], item["end"], "hard_negative:" + item["kind"]) for item in row["hard_negatives"]]
        spans.sort()
        for start, end, name in spans:
            if not 0 <= start < end <= len(text) or text[start:end] != text[start:end].strip():
                problems.append(f"{row['id']}: bad span {name} {start}:{end}")
        for (_, end, name), (start, _, other) in zip(spans, spans[1:]):
            if start < end:
                problems.append(f"{row['id']}: overlapping spans {name} and {other}")
    counts = coverage(rows)
    for lang in LANGUAGES:
        for entity in entity_ids():
            if counts[(lang, entity)] < min_per_language:
                problems.append(f"{lang} {entity}: {counts[(lang, entity)]} spans, need {min_per_language}")
    return problems


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl(rows: list[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows).encode("utf-8")


def build_split(seed: str, split: str, docs: int) -> dict[str, bytes]:
    """``{file name: content}`` of one split including ``manifest.json`` and ``.ready``."""
    rows = generate(seed, split, docs)
    problems = validate_rows(rows)
    if problems:
        raise ValueError("generated rows are invalid: " + "; ".join(problems[:5]))
    data = _jsonl(rows)
    manifest = {
        "schema": SCHEMA,
        "split": split,
        "corpus": CORPUS_ID,
        "generator_version": GENERATOR_VERSION,
        "file": FILE_NAME,
        "sha256": _sha256(data),
        "bytes": len(data),
        "rows": len(rows),
        "offsets": "code points (Python str indices)",
        "languages": dict(sorted(Counter(row["language"] for row in rows).items())),
        "doc_types": dict(sorted(Counter(row["doc_type"] for row in rows).items())),
        "entities": dict(sorted(Counter(entity["entity_type"] for row in rows for entity in row["entities"]).items())),
        "hard_negatives": dict(sorted(Counter(item["kind"] for row in rows for item in row["hard_negatives"]).items())),
    }
    # The holdout seed is secret; its manifest only commits to it.
    manifest.update({"seed": seed} if split == "dev" else {"seed_sha256": _sha256(seed.encode("utf-8"))})
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return {
        FILE_NAME: data,
        "manifest.json": manifest_bytes,
        READY: f"{_sha256(manifest_bytes)}  manifest.json\n".encode("utf-8"),
    }


def check_split(directory: Path) -> list[str]:
    """Problems of a written split directory (empty list: ready and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_text(encoding="utf-8") != f"{_sha256(manifest_bytes)}  manifest.json\n":
        problems.append(f"{directory}: {READY} does not match manifest.json")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return problems + [f"{directory}: manifest.json is not JSON"]
    if manifest.get("schema") != SCHEMA:
        problems.append(f"{directory}: manifest schema is not {SCHEMA}")
    path = directory / str(manifest.get("file", FILE_NAME))
    if not path.is_file():
        problems.append(f"{path} is missing")
    elif _sha256(path.read_bytes()) != manifest.get("sha256"):
        problems.append(f"{path} does not match its SHA-256 in manifest.json")
    return problems


def holdout_seed(path: Path) -> str:
    """Read the secret holdout seed, creating it (mode 0600) on first use."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(secrets.token_hex(32) + "\n")
    seed = path.read_text(encoding="utf-8").strip()
    if len(seed) < 16:
        raise ValueError(f"{path}: holdout seed must have at least 16 characters")
    if seed == DEV_SEED:
        raise ValueError(f"{path}: holdout seed must differ from the dev seed")
    return seed


def _write(directory: Path, files: dict[str, bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / READY).unlink(missing_ok=True)
    for name in [FILE_NAME, "manifest.json", READY]:
        partial = directory / f"{name}.part"
        partial.write_bytes(files[name])
        os.replace(partial, directory / name)


def write_splits(
    dev_out: Path | None,
    holdout_out: Path | None,
    seed_file: Path | None = None,
    force: bool = False,
    docs: dict[str, int] | None = None,
) -> int:
    """Write the requested splits; 0 on success or unchanged frozen splits, 1 on any problem."""
    docs = {**DEFAULT_DOCS, **(docs or {})}
    targets: dict[str, tuple[Path, str]] = {}
    try:
        if dev_out is None and holdout_out is None:
            raise ValueError("nothing to do: give --dev-out and/or --holdout-out")
        if dev_out is not None and holdout_out is not None:
            dev, holdout = dev_out.resolve(), holdout_out.resolve()
            if dev == holdout or dev.is_relative_to(holdout) or holdout.is_relative_to(dev):
                raise ValueError("--dev-out and --holdout-out must be separate, non-nested directories")
        if seed_file is not None and dev_out is not None and seed_file.resolve().is_relative_to(dev_out.resolve()):
            raise ValueError("--holdout-seed-file must not be inside --dev-out")
        if dev_out is not None:
            targets["dev"] = (dev_out, DEV_SEED)
        if holdout_out is not None:
            targets["holdout"] = (holdout_out, holdout_seed(seed_file or holdout_out / SEED_FILE))
        outputs = {split: build_split(seed, split, docs[split]) for split, (_, seed) in targets.items()}
    except (ValueError, OSError) as error:
        print(f"synth_goldset: {error}", file=sys.stderr)
        return 1

    pending = {}
    for split, (directory, _) in targets.items():
        if (directory / READY).exists():
            if (
                not check_split(directory)
                and (directory / "manifest.json").read_bytes() == outputs[split]["manifest.json"]
            ):
                continue
            if not force:
                print(
                    f"synth_goldset: {split} goldset in {directory} is frozen and differs from this run "
                    "(or was modified); nothing written. Use --force to replace it.",
                    file=sys.stderr,
                )
                return 1
        pending[split] = directory
    for split, directory in pending.items():
        _write(directory, outputs[split])
    for split, (directory, _) in targets.items():
        manifest = json.loads(outputs[split]["manifest.json"])
        state = "written" if split in pending else "unchanged (frozen)"
        detail = f", {manifest['rows']} rows, {sum(manifest['entities'].values())} spans" if split == "dev" else ""
        print(f"{split}: {state} in {directory}{detail}, manifest sha256 {_sha256(outputs[split]['manifest.json'])}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dev-out", type=Path, help="dev goldset directory (public seed, visible to agents)")
    parser.add_argument("--holdout-out", type=Path, help="holdout goldset directory (secret seed, gate only)")
    parser.add_argument(
        "--holdout-seed-file", type=Path, help=f"secret holdout seed (default: HOLDOUT/{SEED_FILE}, created if missing)"
    )
    parser.add_argument("--force", action="store_true", help="replace a frozen goldset that differs")
    parser.add_argument("--check", type=Path, metavar="DIR", help="only verify a written goldset directory")
    args = parser.parse_args(argv)
    if args.check is not None:
        problems = check_split(args.check)
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{args.check}: goldset ok")
        return 1 if problems else 0
    if args.holdout_seed_file is not None and args.holdout_out is None:
        parser.error("--holdout-seed-file needs --holdout-out")
    return write_splits(args.dev_out, args.holdout_out, args.holdout_seed_file, args.force)


if __name__ == "__main__":
    sys.exit(main())
