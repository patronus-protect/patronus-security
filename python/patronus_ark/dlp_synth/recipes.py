# SPDX-License-Identifier: GPL-3.0-only
"""Deterministic materialization of secret-safe golden recipes.

Goldens store secret values as ``{"gen": "<generator>", "seed": <int>}`` recipes and a
carrier ``template`` with ``<<secret:N>>`` placeholders. The generator spec lives in
``generators.json`` and is shared with the Rust materializer
(``patronus_ark::golden_recipes``), so both produce byte-identical text:

* PRNG: SplitMix64 seeded with the recipe seed (unsigned 64 bit).
* Alphabets are lists of string chunks, concatenated in order.
* Segments are emitted in order:

  - ``{"lit": s}`` copies ``s``.
  - ``{"alphabet": a, "len": n}`` draws ``n`` characters, each
    ``alphabet[next_u64() % len(alphabet)]``.
  - ``{"checksum": kind}`` appends a check value computed over the text emitted since
    the most recent literal segment: ``crc32_base62`` (CRC-32/ISO-HDLC as 6 base62
    digits ``0-9A-Za-z``, zero-padded; GitHub/npm token layout), ``crc32_hex``
    (CRC-32/ISO-HDLC of the most recent literal and that text as 8 lower-case hex digits;
    Packagist tokens), ``crc32_hex_le`` (CRC-32/ISO-HDLC of everything emitted before the
    most recent literal, as the 8 lower-case hex digits of its little-endian bytes; Grafana
    service account tokens, whose separator ``_`` is that literal), ``iso7064_mod11_10`` (one check digit; German USt-IdNr.) or ``bech32`` (the six
    BIP 173 checksum characters of that text as Bech32 data, with the human-readable part
    taken from the most recent literal, which ends in the separator ``1``; upper case if
    that literal is; age keys).
  - ``{"encode": enc, "bytes": [parts], "wrap"?: n}`` builds a byte string from parts
    (``{"hex": s}``, ``{"utf8": s}`` with ASCII ``s``, ``{"random": n}`` drawing
    ``next_u64() % 256`` per byte, ``{"alphabet": a, "len": n}`` as above) and encodes it
    as ``hex``, ``base64`` (padded), ``base64_unpadded``, ``base64url`` (unpadded),
    ``bcrypt64`` (OpenBSD radix-64, unpadded) or ``base58check`` (double SHA-256).
    ``wrap`` inserts a newline every ``n`` characters (base64 only, PEM bodies).

A generator may set ``"entropy_above": h`` (a number below ``log2`` of its length): while
the Shannon entropy of the value (bits per character, ``-sum(p * log2(p))`` over its
characters in code point order) is not above ``h``, the generator draws the whole value
again from the same PRNG. Values for an entropy-limited detector (detect-secrets
``Base64HighEntropyString`` and ``HexHighEntropyString``) thus clear the limit for every
seed. Fill recipes are not redrawn.

Placeholders (golden schema v2, E13) may transform the value they insert:

* ``<<secret:N>>`` inserts the value of ``secrets[N]`` once.
* ``<<secret:N|enc>>`` inserts it once, transport-encoded with ``enc``: ``base64``
  (padded, over UTF-8), ``hex`` (lower case, over UTF-8), ``url`` (RFC 3986 percent
  encoding of everything except unreserved characters, upper-case hex) or ``json``
  (JSON string escaping without quotes: ``\\"``, ``\\\\``, ``\\n``, ``\\r``,
  ``\\t``, ``\\b``, ``\\f``, other control characters as ``\\u00XX``). The encoding
  must change the value, otherwise the row would not test an encoded secret.
* ``<<secret:N[a:b]>>`` inserts the code points ``a`` to ``b`` (half-open) of the value.
  A split secret uses only slices, at least two, in template order, and they cover the
  value exactly: the first starts at 0, each next one where the previous ended, the
  last ends at the value length.

Base58Check generators start with constant bytes so their length stays fixed. Every
generator therefore has one length, which ``generator_length`` reports.

A recipe may add ``"fill": word`` (T06): the documented example or test variant of the
generator's shape for hard negatives (``EXAMPLEKEY``, ``TESTKEY``, ``deadbeef``,
``1234567890`` …). Literals stay; every alphabet segment or part whose alphabet holds all
characters of ``word`` repeats ``word`` to its length (restarting per segment), the others
are drawn as usual; check values are zeros (ones if zeros happen to be valid). An encoded
segment of random bytes only repeats ``word`` over its encoded characters (padding and line
breaks kept) if its output alphabet holds ``word``; otherwise random bytes become the bytes
of ``word`` repeated before encoding. Base58Check segments reject a fill (the check value
would be valid), and a fill that fits no segment is an error. The value keeps the length
and prefix of the generator, so the rule pattern still matches.

Values are synthetic. Generators listed as ``shape_only`` in ``rules.json`` predate E03
and carry no valid checksum or structure; all others are format-, structure- and
checksum-valid fakes (``dlp_synth.checks`` verifies them independently).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
import zlib
from collections import Counter
from functools import lru_cache
from pathlib import Path


GENERATORS_PATH = Path(__file__).resolve().parent / "generators.json"
PLACEHOLDER_RE = re.compile(
    r"<<secret:(0|[1-9][0-9]*)(?:\|([a-z0-9]+)|\[(0|[1-9][0-9]*):([1-9][0-9]*)\])?>>"
)
TRANSFORMS = ("base64", "hex", "url", "json")
_URL_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_JSON_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}
_MASK = (1 << 64) - 1
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CHECKSUM_LENGTHS = {"crc32_base62": 6, "crc32_hex": 8, "crc32_hex_le": 8, "iso7064_mod11_10": 1, "bech32": 6}
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
ENCODINGS = {"hex", "base64", "base64_unpadded", "base64url", "bcrypt64", "base58check"}
_BCRYPT64 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
)
# Output alphabets of the encodings that a fill word may repeat over (T06).
_ENCODED_ALPHABETS = {
    "hex": "0123456789abcdef",
    "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "base64_unpadded": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "base64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "bcrypt64": "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
}


class RecipeError(ValueError):
    """Raised for unknown generators, malformed recipes, or invalid templates."""


class SplitMix64:
    def __init__(self, seed: int) -> None:
        if type(seed) is not int or not 0 <= seed <= _MASK:
            raise RecipeError(f"seed must be an unsigned 64-bit integer, got {seed!r}")
        self._state = seed

    def next_u64(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK
        return z ^ (z >> 31)


def _valid_count(value) -> bool:
    return type(value) is int and value > 0


def _valid_part(part, alphabets: dict) -> bool:
    if not isinstance(part, dict):
        return False
    if set(part) == {"hex"}:
        try:
            bytes.fromhex(part["hex"])
        except (TypeError, ValueError):
            return False
        return bool(part["hex"])
    if set(part) == {"utf8"}:
        return isinstance(part["utf8"], str) and bool(part["utf8"]) and part["utf8"].isascii()
    if set(part) == {"random"}:
        return _valid_count(part["random"])
    return set(part) == {"alphabet", "len"} and part["alphabet"] in alphabets and _valid_count(part["len"])


def _valid_entropy_limit(generator: dict) -> bool:
    """An optional ``entropy_above`` is a positive number below ``log2`` of the length of a random generator."""
    if "entropy_above" not in generator:
        return True
    limit = generator["entropy_above"]
    length = sum(_segment_length(segment) for segment in generator["segments"])
    return (
        type(limit) in (int, float)
        and 0 < limit < math.log2(length)
        and _draws_randomly(generator["segments"])
    )


def _valid_segment(segment, alphabets: dict) -> bool:
    if not isinstance(segment, dict):
        return False
    keys = set(segment)
    if keys == {"lit"}:
        return isinstance(segment["lit"], str) and bool(segment["lit"]) and segment["lit"].isascii()
    if keys == {"alphabet", "len"}:
        return segment["alphabet"] in alphabets and _valid_count(segment["len"])
    if keys == {"checksum"}:
        return segment["checksum"] in CHECKSUM_LENGTHS
    if keys in ({"encode", "bytes"}, {"encode", "bytes", "wrap"}):
        parts = segment["bytes"]
        if segment["encode"] not in ENCODINGS or not isinstance(parts, list) or not parts:
            return False
        if "wrap" in segment and (segment["encode"] != "base64" or not _valid_count(segment["wrap"])):
            return False
        if not all(_valid_part(part, alphabets) for part in parts):
            return False
        # Base58Check needs a constant non-zero lead byte for a fixed length.
        return segment["encode"] != "base58check" or (
            "hex" in parts[0] and bytes.fromhex(parts[0]["hex"])[0] != 0
        )
    return False


@lru_cache(maxsize=1)
def _spec() -> dict:
    spec = json.loads(GENERATORS_PATH.read_text(encoding="utf-8"))
    if spec.get("version") != 2 or spec.get("prng") != "splitmix64":
        raise RecipeError("unsupported generator spec")
    for name, generator in spec["generators"].items():
        for segment in generator["segments"]:
            if not _valid_segment(segment, spec["alphabets"]):
                raise RecipeError(f"{name}: invalid segment {segment!r}")
        if not _valid_entropy_limit(generator):
            raise RecipeError(f"{name}: invalid entropy_above {generator['entropy_above']!r}")
    alphabets = {}
    for name, chunks in spec["alphabets"].items():
        if not isinstance(chunks, list) or not all(isinstance(chunk, str) for chunk in chunks):
            raise RecipeError(f"alphabet {name} must be a list of strings")
        alphabet = "".join(chunks)
        if not alphabet or not alphabet.isascii() or len(set(alphabet)) != len(alphabet):
            raise RecipeError(f"alphabet {name} must be non-empty, ASCII and duplicate-free")
        alphabets[name] = alphabet
    spec["alphabets"] = alphabets
    return spec


def load_generators() -> dict:
    return copy.deepcopy(_spec()["generators"])


def load_alphabets() -> dict:
    return dict(_spec()["alphabets"])


def _generator(name: str) -> dict:
    try:
        return _spec()["generators"][name]
    except KeyError:
        raise RecipeError(f"unknown generator {name!r}") from None


def _byte_length(parts: list[dict]) -> int:
    total = 0
    for part in parts:
        if "hex" in part:
            total += len(part["hex"]) // 2
        elif "utf8" in part:
            total += len(part["utf8"])
        elif "random" in part:
            total += part["random"]
        else:
            total += part["len"]
    return total


def _encoded_length(segment: dict) -> int:
    size = _byte_length(segment["bytes"])
    encoding = segment["encode"]
    if encoding == "hex":
        return 2 * size
    if encoding == "base64":
        length = 4 * math.ceil(size / 3)
        return length + (length - 1) // segment["wrap"] if "wrap" in segment else length
    if encoding == "base58check":
        # Constant leading bytes keep the value in one base58 digit range.
        return math.ceil((size + 4) * 8 / math.log2(58))
    return math.ceil(size * 4 / 3)


def _segment_length(segment: dict) -> int:
    if "lit" in segment:
        return len(segment["lit"])
    if "alphabet" in segment:
        return segment["len"]
    if "checksum" in segment:
        return CHECKSUM_LENGTHS[segment["checksum"]]
    return _encoded_length(segment)


def generator_length(name: str) -> int:
    return sum(_segment_length(segment) for segment in _generator(name)["segments"])


def _draws_randomly(segments: list[dict]) -> bool:
    return any(
        "alphabet" in segment
        or any("random" in part or "alphabet" in part for part in segment.get("bytes", []))
        for segment in segments
    )


def is_random(name: str) -> bool:
    return _draws_randomly(_generator(name)["segments"])


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character (summed in code point order)."""
    length = len(value)
    return -sum(count / length * math.log2(count / length) for _, count in sorted(Counter(value).items()))


def crc32_base62(text: str) -> str:
    checksum = zlib.crc32(text.encode("ascii"))
    digits = ""
    while checksum:
        checksum, remainder = divmod(checksum, 62)
        digits = BASE62[remainder] + digits
    return digits.rjust(6, "0")


def iso7064_mod11_10(digits: str) -> str:
    product = 10
    for digit in digits:
        total = (int(digit) + product) % 10 or 10
        product = 2 * total % 11
    return str((11 - product) % 10)


def bech32_checksum(literal: str, data: str) -> str:
    """BIP 173 checksum of ``data`` (Bech32 characters) under the HRP that ``literal`` ends with."""
    hrp, separator, rest = literal.rpartition("1")
    if not separator or not hrp or rest:
        raise RecipeError(f"a bech32 checksum needs a preceding literal ending in HRP + '1', got {literal!r}")
    try:
        values = [BECH32.index(char) for char in data.lower()]
    except ValueError:
        raise RecipeError(f"bech32 data {data!r} has a character outside the Bech32 alphabet") from None
    hrp = hrp.lower()
    check = 1
    for value in [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp] + values + [0] * 6:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for bit, generator in enumerate(_BECH32_GENERATOR):
            if top >> bit & 1:
                check ^= generator
    check ^= 1
    digits = "".join(BECH32[check >> 5 * (5 - index) & 31] for index in range(6))
    return digits.upper() if literal.isupper() else digits


def checksum(kind: str, data: str, literal: str, before_literal: str = "") -> str:
    """The check value of ``kind`` over ``data``, the text since ``literal`` (the most recent literal).

    ``before_literal`` is the text emitted before that literal (``crc32_hex_le``).
    """
    if kind == "crc32_base62":
        return crc32_base62(data)
    if kind == "crc32_hex":
        return f"{zlib.crc32((literal + data).encode('ascii')):08x}"
    if kind == "crc32_hex_le":
        return zlib.crc32(before_literal.encode("ascii")).to_bytes(4, "little").hex()
    if kind == "iso7064_mod11_10":
        return iso7064_mod11_10(data)
    return bech32_checksum(literal, data)


def base58check_sum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def base58check(payload: bytes) -> str:
    return base58(payload + base58check_sum(payload))


def base58(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58[remainder] + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded


def _draw(rng: SplitMix64, alphabet: str, count: int) -> str:
    return "".join(alphabet[rng.next_u64() % len(alphabet)] for _ in range(count))


def _encode(segment: dict, rng: SplitMix64, alphabets: dict) -> str:
    raw = bytearray()
    for part in segment["bytes"]:
        if "hex" in part:
            raw += bytes.fromhex(part["hex"])
        elif "utf8" in part:
            raw += part["utf8"].encode("ascii")
        elif "random" in part:
            raw += bytes(rng.next_u64() % 256 for _ in range(part["random"]))
        else:
            raw += _draw(rng, alphabets[part["alphabet"]], part["len"]).encode("ascii")
    return encode_bytes(bytes(raw), segment["encode"], segment.get("wrap"))


def encode_bytes(raw: bytes, encoding: str, wrap: int | None = None) -> str:
    """Encode ``raw`` like an ``encode`` segment (``wrap`` only applies to ``base64``)."""
    if encoding == "hex":
        return raw.hex()
    if encoding == "base58check":
        return base58check(raw)
    if encoding == "base64url":
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    encoded = base64.b64encode(raw).decode("ascii")
    if encoding == "base64_unpadded":
        return encoded.rstrip("=")
    if encoding == "bcrypt64":
        return encoded.rstrip("=").translate(_BCRYPT64)
    if wrap:
        encoded = "\n".join(encoded[start : start + wrap] for start in range(0, len(encoded), wrap))
    return encoded


def _repeat(word: str, length: int) -> str:
    return (word * (length // len(word) + 1))[:length]


def _fits(word: str, alphabet: str) -> bool:
    return set(word) <= set(alphabet)


def _encode_filled(segment: dict, rng: SplitMix64, alphabets: dict, fill: str) -> tuple[str, bool]:
    """An encoded segment of a ``fill`` recipe and whether the fill word went into it."""
    encoding = segment["encode"]
    parts = segment["bytes"]
    if encoding == "base58check":
        raise RecipeError("a fill recipe cannot use Base58Check segments (the check value stays valid)")
    if all("random" in part for part in parts) and _fits(fill, _ENCODED_ALPHABETS[encoding]):
        shape = encode_bytes(bytes(_byte_length(parts)), encoding, segment.get("wrap"))
        characters = iter(_repeat(fill, len(shape)))
        return "".join(char if char in "=\n" else next(characters) for char in shape), True
    raw = bytearray()
    filled = False
    for part in parts:
        if "hex" in part:
            raw += bytes.fromhex(part["hex"])
        elif "utf8" in part:
            raw += part["utf8"].encode("ascii")
        elif "random" in part:
            raw += _repeat(fill, part["random"]).encode("ascii")
            filled = True
        elif _fits(fill, alphabets[part["alphabet"]]):
            raw += _repeat(fill, part["len"]).encode("ascii")
            filled = True
        else:
            raw += _draw(rng, alphabets[part["alphabet"]], part["len"]).encode("ascii")
    return encode_bytes(bytes(raw), encoding, segment.get("wrap")), filled


def _valid_fill(fill) -> bool:
    return isinstance(fill, str) and bool(fill) and fill.isascii() and fill.isalnum()


def generate_segments(name: str, seed: int, fill: str | None = None) -> list[str]:
    """Return the generated value split by segment (``"".join`` gives ``generate``).

    ``fill`` yields the example/test variant described in the module docstring.
    """
    if fill is not None and not _valid_fill(fill):
        raise RecipeError(f"fill must be a non-empty ASCII alphanumeric word, got {fill!r}")
    generator = _generator(name)
    rng = SplitMix64(seed)
    parts = _draw_segments(name, generator, rng, fill)
    # Fill recipes are low-entropy hard negatives by design and are never redrawn.
    limit = None if fill is not None else generator.get("entropy_above")
    while limit is not None and shannon_entropy("".join(parts)) <= limit:
        parts = _draw_segments(name, generator, rng, fill)
    return parts


def _draw_segments(name: str, generator: dict, rng: SplitMix64, fill: str | None) -> list[str]:
    alphabets = _spec()["alphabets"]
    parts: list[str] = []
    since_literal = literal = before_literal = ""
    filled = False
    for segment in generator["segments"]:
        if "lit" in segment:
            before_literal = "".join(parts)
            part = literal = segment["lit"]
        elif "alphabet" in segment:
            alphabet = alphabets[segment["alphabet"]]
            if fill is not None and _fits(fill, alphabet):
                part = _repeat(fill, segment["len"])
                filled = True
            else:
                part = _draw(rng, alphabet, segment["len"])
        elif "checksum" in segment:
            part = checksum(segment["checksum"], since_literal, literal, before_literal)
            if fill is not None:
                zeros = "0" * len(part)
                part = zeros if zeros != part else "1" * len(part)
        elif fill is not None:
            part, filled_segment = _encode_filled(segment, rng, alphabets, fill)
            filled = filled or filled_segment
        else:
            part = _encode(segment, rng, alphabets)
        since_literal = "" if "lit" in segment else since_literal + part
        parts.append(part)
    if fill is not None and not filled:
        raise RecipeError(f"fill {fill!r} fits no segment of {name}")
    return parts


def generate(name: str, seed: int, fill: str | None = None) -> str:
    return "".join(generate_segments(name, seed, fill))


def transform(value: str, encoding: str) -> str:
    """Encode ``value`` like a ``<<secret:N|encoding>>`` placeholder."""
    raw = value.encode("utf-8")
    if encoding == "base64":
        return base64.b64encode(raw).decode("ascii")
    if encoding == "hex":
        return raw.hex()
    if encoding == "url":
        return "".join(
            chr(byte) if chr(byte) in _URL_UNRESERVED else f"%{byte:02X}" for byte in raw
        )
    if encoding == "json":
        return "".join(
            _JSON_ESCAPES.get(char) or (f"\\u{ord(char):04x}" if ord(char) < 0x20 else char)
            for char in value
        )
    raise RecipeError(f"unknown placeholder encoding {encoding!r}")


def materialize_fragments(template: str, secrets: list[dict]) -> tuple[str, list[dict]]:
    """Return the materialized text and every inserted fragment, in text order.

    A fragment is ``{"secret": N, "part": k, "start": s, "end": e, "encoding": enc}``:
    ``part`` counts the fragments of secret ``N`` (always 0 unless it is split),
    ``start``/``end`` are code points in the text and ``encoding`` is the placeholder
    encoding or None.
    """
    for secret in secrets:
        if not isinstance(secret, dict) or set(secret) - {"fill"} != {"gen", "seed"}:
            raise RecipeError(f"recipe must be {{gen, seed}} plus an optional fill, got {secret!r}")
    matches = list(PLACEHOLDER_RE.finditer(template))
    if not matches or template.count("<<secret:") != len(matches):
        raise RecipeError(f"template has malformed or no placeholders: {template!r}")
    values: dict[int, str] = {}
    placements: dict[int, list[re.Match]] = {}
    for match in matches:
        index = int(match.group(1))
        if index >= len(secrets):
            raise RecipeError(f"placeholder {index} has no recipe in {template!r}")
        placements.setdefault(index, []).append(match)
    if sorted(placements) != list(range(len(secrets))):
        raise RecipeError(f"template must use each of {len(secrets)} secrets: {template!r}")
    for index, uses in placements.items():
        recipe = secrets[index]
        value = values[index] = generate(recipe["gen"], recipe["seed"], recipe.get("fill"))
        slices = [(int(use.group(3)), int(use.group(4))) for use in uses if use.group(3) is not None]
        if not slices:
            if len(uses) != 1:
                raise RecipeError(f"secret {index} used more than once in {template!r}")
            continue
        bounds = [0, *(end for _, end in slices)]
        if (
            len(slices) != len(uses)
            or len(slices) < 2
            or [start for start, _ in slices] != bounds[:-1]
            or any(start >= end for start, end in slices)
            or bounds[-1] != len(value)
        ):
            raise RecipeError(f"slices of secret {index} must split it in order: {template!r}")
    text: list[str] = []
    fragments: list[dict] = []
    parts = dict.fromkeys(placements, 0)
    length = 0
    cursor = 0
    for match in matches:
        index = int(match.group(1))
        text.append(template[cursor : match.start()])
        length += match.start() - cursor
        value, encoding = values[index], match.group(2)
        if match.group(3) is not None:
            value = value[int(match.group(3)) : int(match.group(4))]
        elif encoding is not None:
            encoded = transform(value, encoding)
            if encoded == value:
                raise RecipeError(f"encoding {encoding!r} leaves secret {index} unchanged")
            value = encoded
        fragments.append(
            {"secret": index, "part": parts[index], "start": length, "end": length + len(value), "encoding": encoding}
        )
        parts[index] += 1
        text.append(value)
        length += len(value)
        cursor = match.end()
    text.append(template[cursor:])
    return "".join(text), fragments


def materialize(template: str, secrets: list[dict]) -> tuple[str, list[tuple[int, int]]]:
    """Return the materialized text and the code-point span of each secret, by index.

    Split secrets have no single span; use ``materialize_fragments`` for them.
    """
    text, fragments = materialize_fragments(template, secrets)
    if any(fragment["part"] for fragment in fragments):
        raise RecipeError(f"template splits a secret, use materialize_fragments: {template!r}")
    spans = [(0, 0)] * len(secrets)
    for fragment in fragments:
        spans[fragment["secret"]] = (fragment["start"], fragment["end"])
    return text, spans


def fingerprint(text: str) -> str:
    """First 24 hex digits (96 bit) of SHA-256 over UTF-8 ``text``.

    Short on purpose: a full 64-hex digest is itself a lookalike for hex/Base58 key
    rules, and the checked-in goldens must stay free of DLP findings.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def materialize_row(row: dict) -> dict:
    """Return a copy of a golden row with ``text`` and entity ``text`` materialized.

    Rows without a ``template`` are literal and returned unchanged (as a copy).
    """
    materialized = copy.deepcopy(row)
    if "template" not in row:
        return materialized
    text, _ = materialize_fragments(row["template"], row["secrets"])
    del materialized["template"], materialized["secrets"]
    materialized.pop("text_fingerprint", None)
    materialized["text"] = text
    for entity in materialized["entities"]:
        entity["text"] = text[entity["start"] : entity["end"]]
    return materialized
