# SPDX-License-Identifier: GPL-3.0-only
"""Carrier documents for synthetic DLP values (E04).

``build(split, seed)`` embeds generator values (``recipes``) in the carrier families of
one split (``carrier_templates.FAMILIES``): config files, code in eight languages, CI,
notebooks, logs, HTTP and DE/EN chat, tickets and mail. Dev and holdout use disjoint
families; the holdout additionally uses a secret seed (E09).

For each family and value rule (``rules.json``) a row is produced per variant. Baseline
entities (``baseline_entities`` in ``rules.json``, GOLD-D2: entities that only gitleaks,
TruffleHog or detect-secrets detect today) get the same rows with ``rule_id`` None, so
every tool is measured on them before ARK has a rule:

* ``positive``: the generated value, wrapped by the rule profile (``Bearer …``, URL
  userinfo …) and escaped by the family. The entity span covers only the value, in
  Unicode code points of ``text``; ``encoding`` lists the escapes applied to it, inner
  first, so ``text[start:end]`` decodes to the generator output.
* hard negatives without entities: ``placeholder`` (``<your-…>``, ``changeme`` …),
  ``env_ref`` (``${KEY}``, ``os.environ[…]``, ``${{ secrets.KEY }}`` …), ``doc_example``
  and ``test_key`` (the generator shape filled with ``EXAMPLE``/``TEST`` words, checksums
  zeroed; encoded values keep their encoded prefix and length and only break checksum or
  decoded structure, so the rule pattern still matches while validation fails), and for
  baseline entities ``lookalike`` (the entity's shape with a wrong prefix, length or
  character set, such as a public sibling ID).

Rows only exist in memory or in files written outside the repository; never commit
them, they contain checksum-valid synthetic tokens.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from functools import lru_cache
from typing import Iterable, Iterator

from . import recipes, rules
from .carrier_templates import FAMILIES, FILL_WORDS, LOOKALIKE_KEY, PLACEHOLDERS, PROFILES, Family, Profile


CARRIER_VERSION = 1
SPLITS = ("dev", "holdout")
LANGUAGES = ("de", "en")
VARIANTS = ("positive", "placeholder", "env_ref", "doc_example", "test_key", "lookalike")
FORMATS = (
    "env", "yaml", "json", "toml", "hcl", "xml", "properties", "shell", "dockerfile",
    "ci_yaml", "jupyter", "log", "http", "code", "chat", "ticket", "mail",
)
KINDS = ("secret", "identifier", "fragment")
ESCAPES = ("json", "xml", "indent")
KEY_MARKERS = ("KEY", "key", "keyCamel", "KeyPascal", "key-kebab", "Key-Header")
MARKERS = frozenset({"value", "label", *KEY_MARKERS})
MARKER_RE = re.compile(r"<<([A-Za-z][A-Za-z-]*)>>")
ENCODED_ALPHABETS = {
    "hex": "hex_lower",
    "base64": "base64",
    "base64_unpadded": "base64",
    "base64url": "base64url",
    "bcrypt64": "bcrypt",
    "base58check": "base58",
}


class CarrierError(ValueError):
    """Raised for malformed families, unknown rules or variants."""


def validate_family(family: Family) -> None:
    def fail(reason: str) -> None:
        raise CarrierError(f"{family.id}: {reason}")

    if family.split not in SPLITS or family.language not in LANGUAGES or family.format not in FORMATS:
        fail("unknown split, language or format")
    if family.template.count("<<value>>") != 1:
        fail("template needs exactly one <<value>>")
    old, new = family.env_ref
    if "<<value>>" not in old or old not in family.template or "<<value>>" in new:
        fail("env_ref must replace a template part containing <<value>>")
    for text in (family.template, new):
        unknown = set(MARKER_RE.findall(text)) - MARKERS
        if unknown:
            fail(f"unknown markers {sorted(unknown)}")
    if not set(family.escape) <= set(ESCAPES) or ("indent" in family.escape) != (family.indent > 0):
        fail("invalid escape")
    if not family.accepts or not set(family.accepts) <= set(KINDS):
        fail("invalid accepted kinds")
    if (family.format == "code") != (family.code_language is not None):
        fail("code families need a code language")


@lru_cache(maxsize=1)
def _families() -> tuple[Family, ...]:
    ids = set()
    for family in FAMILIES:
        validate_family(family)
        if family.id in ids:
            raise CarrierError(f"duplicate family {family.id}")
        ids.add(family.id)
    return FAMILIES


def families(split: str | None = None) -> list[Family]:
    if split is not None and split not in SPLITS:
        raise CarrierError(f"unknown split {split!r}")
    return [family for family in _families() if split is None or family.split == split]


def _family(family_id: str) -> Family:
    for family in _families():
        if family.id == family_id:
            return family
    raise CarrierError(f"unknown family {family_id!r}")


@lru_cache(maxsize=1)
def _baseline_entities() -> frozenset[str]:
    return frozenset(rules.baseline_entities())


@lru_cache(maxsize=1)
def _profiles() -> dict[str, Profile]:
    keys = set(rules.load_rule_map()) | _baseline_entities()
    if set(PROFILES) != keys:
        raise CarrierError(
            f"profiles must cover exactly the value rules and baseline entities: {sorted(set(PROFILES) ^ keys)}"
        )
    for key, profile in PROFILES.items():
        if key in _baseline_entities() and profile.entity != key:
            raise CarrierError(f"{key}: a baseline entity profile must name its own entity")
        if profile.kind not in KINDS:
            raise CarrierError(f"{key}: unknown kind {profile.kind!r}")
        wraps = profile.wrap.values() if isinstance(profile.wrap, dict) else [profile.wrap or "<<value>>"]
        if any(wrap.count("<<value>>") != 1 for wrap in wraps):
            raise CarrierError(f"{key}: wrap needs exactly one <<value>>")
    return PROFILES


def profiles() -> dict[str, Profile]:
    return dict(_profiles())


def key_forms(key: str) -> dict[str, str]:
    words = key.split("_")
    return {
        "KEY": key.upper(),
        "key": key,
        "keyCamel": words[0] + "".join(word.capitalize() for word in words[1:]),
        "KeyPascal": "".join(word.capitalize() for word in words),
        "key-kebab": "-".join(words),
        "Key-Header": "-".join(word.capitalize() for word in words),
    }


def escape_value(text: str, escapes: Iterable[str], indent: int = 0) -> str:
    """Apply escapes inner first (``("json", "json")`` is a string in a JSON string)."""
    for escape in escapes:
        if escape == "json":
            text = json.dumps(text, ensure_ascii=False)[1:-1]
        elif escape == "xml":
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        elif escape == "indent":
            text = text.replace("\n", "\n" + " " * indent)
        else:
            raise CarrierError(f"unknown escape {escape!r}")
    return text


def _fill(alphabet: str, length: int, variant: str) -> str:
    for word in FILL_WORDS[variant]:
        if set(word) <= set(alphabet):
            return (word * (length // len(word) + 1))[:length]
    return alphabet[0] * length


def hard_negative_value(generator: str, variant: str) -> str:
    """The generator shape with literals kept and random parts filled (doc example, test key).

    Check values are zeros (ones if zeros happen to be valid). Encoded segments keep
    their encoded prefix, alphabet and length and only break the checksum or decoded
    structure (``_hard_negative_encoded``), so the value still matches the detector
    pattern while checksum, Base58Check, DER, OpenSSH and JWT checks fail.
    """
    if variant not in FILL_WORDS:
        raise CarrierError(f"no fill words for variant {variant!r}")
    alphabets = recipes.load_alphabets()
    try:
        segments = recipes.load_generators()[generator]["segments"]
    except KeyError:
        raise CarrierError(f"unknown generator {generator!r}") from None
    parts = []
    since_literal = ""
    for segment in segments:
        if "lit" in segment:
            parts.append(segment["lit"])
            since_literal = ""
            continue
        if "alphabet" in segment:
            parts.append(_fill(alphabets[segment["alphabet"]], segment["len"], variant))
        elif "checksum" in segment:
            check = "0" * recipes.CHECKSUM_LENGTHS[segment["checksum"]]
            valid = (
                recipes.crc32_base62(since_literal)
                if segment["checksum"] == "crc32_base62"
                else recipes.iso7064_mod11_10(since_literal)
            )
            parts.append(check if check != valid else "1" * len(check))
        else:
            parts.append(_hard_negative_encoded(segment, alphabets, variant))
        since_literal += parts[-1]
    return "".join(parts)


def _hard_negative_encoded(segment: dict, alphabets: dict, variant: str) -> str:
    """An encoded segment that keeps its detector shape but fails decoding checks.

    Segments of random bytes only have no structure to break; they become fill words in
    the output alphabet, kept canonical (no stray trailing bits). Otherwise the byte string is built with constant parts kept,
    alphabet parts filled from their alphabet and random bytes as fill-word bytes, then
    encoded, so prefix (``5``/``K``/``L``, ``eyJ``, ``MI``, ``b3Bl``), alphabet and length
    stay those of a real value. Only the checksum or decoded structure is broken:
    Base58Check gets a wrong check value, binary layouts (leading hex part: DER) a wrong
    outer tag, text layouts (JSON, ``user:password``, OpenSSH padding, snowflake digits)
    an invalid last non-random byte.
    """
    encoding = segment["encode"]
    parts = segment["bytes"]
    if all("random" in part for part in parts):
        unwrapped = dict(segment)
        unwrapped.pop("wrap", None)
        encoded = _fill(alphabets[ENCODED_ALPHABETS[encoding]], recipes._encoded_length(unwrapped), variant)
        if encoding == "hex":
            return encoded
        # Decode leniently and re-encode, so the last character carries no stray bits
        # and the segment stays canonical (only its last character may change).
        if encoding == "bcrypt64":
            encoded = encoded.translate({new: old for old, new in recipes._BCRYPT64.items()})
        encoded = encoded.replace("-", "+").replace("_", "/")
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4))[: recipes._byte_length(parts)]
        return recipes.encode_bytes(raw, encoding, segment.get("wrap"))
    word = FILL_WORDS[variant][0].encode("ascii")
    raw = bytearray()
    last_constant = last_alphabet = None
    for part in parts:
        if "hex" in part:
            raw += bytes.fromhex(part["hex"])
            last_constant = len(raw) - 1
        elif "utf8" in part:
            raw += part["utf8"].encode("ascii")
            last_constant = len(raw) - 1
        elif "random" in part:
            raw += (word * (part["random"] // len(word) + 1))[: part["random"]]
        else:
            raw += _fill(alphabets[part["alphabet"]], part["len"], variant).encode("ascii")
            last_alphabet = len(raw) - 1
    if encoding == "base58check":
        check = recipes.base58check_sum(bytes(raw))
        return recipes.base58(bytes(raw) + bytes(byte ^ 0xFF for byte in check))
    if "hex" in parts[0]:
        raw[0] ^= 0x01
    else:
        index = last_constant if last_constant is not None else last_alphabet
        raw[index] = ord("?") if raw[index] == ord("!") else ord("!")
    return recipes.encode_bytes(bytes(raw), encoding, segment.get("wrap"))


def _derive(*parts: object) -> int:
    """Unsigned 64-bit value from SHA-256 over the parts (seeds and choices)."""
    digest = hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


@lru_cache(maxsize=None)
def _is_multiline(generator: str) -> bool:
    return "\n" in recipes.generate(generator, 0)


def _wrap(profile: Profile, generator: str) -> tuple[str, str]:
    wrap = profile.wrap.get(generator) if isinstance(profile.wrap, dict) else profile.wrap
    prefix, _, suffix = (wrap or "<<value>>").partition("<<value>>")
    return prefix, suffix


def _substitute(text: str, forms: dict[str, str]) -> str:
    return MARKER_RE.sub(lambda match: forms.get(match.group(1), match.group(0)), text)


def render(family_id: str, key: str, variant: str, seed: int) -> dict | None:
    """One carrier row, or ``None`` if the family does not take the values of ``key``.

    ``key`` is a value rule or a baseline entity; ``lookalike`` rows exist only for
    baseline entities.
    """
    family = _family(family_id)
    try:
        profile = _profiles()[key]
    except KeyError:
        raise CarrierError(f"no carrier profile for rule {key!r}") from None
    if variant not in VARIANTS:
        raise CarrierError(f"unknown variant {variant!r}")
    if profile.kind not in family.accepts:
        return None
    candidates = rules.baseline_lookalikes(key) if variant == "lookalike" else rules.generators_for(key)
    generators = [name for name in candidates if family.multiline or not _is_multiline(name)]
    if variant in FILL_WORDS:
        # A constant value (a bare PEM header) has no example or test form of its own.
        generators = [name for name in generators if recipes.is_random(name)]
    if not generators:
        return None
    # A lookalike draws from its own seed, so it shares no run with the positive of the row.
    lookalike = variant == "lookalike"
    generator = generators[_derive("lookalike" if lookalike else "generator", seed, family.id, key) % len(generators)]
    value_seed = _derive("lookalike-value" if lookalike else "value", seed, family.id, key)
    # A lookalike sits under a neutral key: under the entity's own key a value of the wrong
    # shape is still a credential of unknown format, so only the shape tells it apart.
    key_name, label_en, label_de = LOOKALIKE_KEY if lookalike else (profile.key, profile.label_en, profile.label_de)
    forms = key_forms(key_name)
    forms["label"] = label_de if family.language == "de" else label_en

    template = family.template
    if variant == "env_ref":
        old, new = family.env_ref
        template = template.replace(old, new, 1)
    if variant == "positive" or lookalike:
        value = recipes.generate(generator, value_seed)
    elif variant == "placeholder":
        options = PLACEHOLDERS[family.language]
        value = _substitute(options[_derive("placeholder", seed, family.id, key) % len(options)], forms)
    elif variant != "env_ref":
        value = hard_negative_value(generator, variant)
    prefix, suffix = _wrap(profile, generator)

    pieces = []
    length = 0
    span = None
    cursor = 0
    for match in MARKER_RE.finditer(template):
        name = match.group(1)
        if name not in MARKERS:
            continue
        pieces.append(template[cursor : match.start()])
        length += match.start() - cursor
        if name == "value":
            head = escape_value(prefix, family.escape, family.indent)
            body = escape_value(value, family.escape, family.indent)
            tail = escape_value(suffix, family.escape, family.indent)
            span = (length + len(head), length + len(head) + len(body))
            piece = head + body + tail
        else:
            piece = forms[name]
        pieces.append(piece)
        length += len(piece)
        cursor = match.end()
    pieces.append(template[cursor:])
    text = "".join(pieces)

    rule_id = None if key in _baseline_entities() else key
    entities = []
    if variant == "positive":
        entities.append(
            {
                "label": profile.group,
                "entity": profile.entity,
                "rule_id": rule_id,
                "start": span[0],
                "end": span[1],
                "text": text[span[0] : span[1]],
                "encoding": list(family.escape),
            }
        )
    return {
        "id": f"dlp_carrier-{family.id}-{key}-{variant}",
        "suite": "dlp_carrier",
        "split": family.split,
        "family": family.id,
        "format": family.format,
        "code_language": family.code_language,
        "language": family.language,
        "variant": variant,
        "case_type": "positive" if variant == "positive" else "hard_negative",
        "rule_id": rule_id,
        "entity": profile.entity,
        "group": profile.group,
        "generator": generator,
        "seed": value_seed,
        "text": text,
        "entities": entities,
        "content_labels": list(family.content),
        "span_unit": "unicode_code_point",
        "provenance": {
            "origin": "synthetic",
            "source": f"patronus_ark.dlp_synth.carriers v{CARRIER_VERSION}",
        },
    }


def iter_rows(
    split: str, seed: int, rules: Iterable[str] | None = None, variants: Iterable[str] = VARIANTS
) -> Iterator[dict]:
    selected = list(_profiles()) if rules is None else list(rules)
    variants = list(variants)
    for family in families(split):
        for key in selected:
            for variant in variants:
                row = render(family.id, key, variant, seed)
                if row is not None:
                    yield row


def build(
    split: str, seed: int, rules: Iterable[str] | None = None, variants: Iterable[str] = VARIANTS
) -> list[dict]:
    """All rows of one split, ordered by family, rule (then baseline entity) and variant."""
    return list(iter_rows(split, seed, rules, variants))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=SPLITS, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--rule", action="append", help="limit to these value rules or baseline entities (repeatable)")
    parser.add_argument("--variant", action="append", choices=VARIANTS, help="limit to these variants")
    parser.add_argument("--out", help="JSONL output file (default: stdout)")
    args = parser.parse_args(argv)
    rows = iter_rows(args.split, args.seed, args.rule, args.variant or VARIANTS)
    handle = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    finally:
        if args.out:
            handle.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
