# SPDX-License-Identifier: GPL-3.0-only
"""Deterministic materialization of secret-safe golden recipes.

Goldens store secret values as ``{"gen": "<generator>", "seed": <int>}`` recipes and a
carrier ``template`` with ``<<secret:N>>`` placeholders. The generator spec lives in
``generators.json`` and is shared with the Rust materializer
(``patronus_ark::golden_recipes``), so both produce byte-identical text:

* PRNG: SplitMix64 seeded with the recipe seed (unsigned 64 bit).
* Alphabets are lists of string chunks, concatenated in order.
* Segments are emitted in order. ``{"lit": s}`` copies ``s``; ``{"alphabet": a, "len": n}``
  draws ``n`` characters, each ``alphabet[next_u64() % len(alphabet)]``.

Generated values are synthetic and format-shaped only; they carry no valid provider
checksum. Checksum-valid fakes are E03 (``dlp_synth`` generators).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path


GENERATORS_PATH = Path(__file__).resolve().parent / "generators.json"
PLACEHOLDER_RE = re.compile(r"<<secret:(0|[1-9][0-9]*)>>")
_MASK = (1 << 64) - 1


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


@lru_cache(maxsize=1)
def _spec() -> dict:
    spec = json.loads(GENERATORS_PATH.read_text(encoding="utf-8"))
    if spec.get("version") != 1 or spec.get("prng") != "splitmix64":
        raise RecipeError("unsupported generator spec")
    for name, generator in spec["generators"].items():
        for segment in generator["segments"]:
            if "lit" in segment:
                if set(segment) != {"lit"} or not segment["lit"].isascii():
                    raise RecipeError(f"{name}: invalid literal segment")
            elif set(segment) != {"alphabet", "len"} or segment["alphabet"] not in spec["alphabets"]:
                raise RecipeError(f"{name}: invalid alphabet segment")
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


def generator_length(name: str) -> int:
    return sum(
        len(segment["lit"]) if "lit" in segment else segment["len"]
        for segment in _generator(name)["segments"]
    )


def is_random(name: str) -> bool:
    return any("alphabet" in segment for segment in _generator(name)["segments"])


def generate(name: str, seed: int) -> str:
    generator = _generator(name)
    alphabets = _spec()["alphabets"]
    rng = SplitMix64(seed)
    parts = []
    for segment in generator["segments"]:
        if "lit" in segment:
            parts.append(segment["lit"])
        else:
            alphabet = alphabets[segment["alphabet"]]
            parts.extend(alphabet[rng.next_u64() % len(alphabet)] for _ in range(segment["len"]))
    return "".join(parts)


def materialize(template: str, secrets: list[dict]) -> tuple[str, list[tuple[int, int]]]:
    """Return the materialized text and the code-point span of each secret, by index."""
    for secret in secrets:
        if not isinstance(secret, dict) or set(secret) != {"gen", "seed"}:
            raise RecipeError(f"recipe must be exactly {{gen, seed}}, got {secret!r}")
    matches = list(PLACEHOLDER_RE.finditer(template))
    indices = [int(match.group(1)) for match in matches]
    if sorted(indices) != list(range(len(secrets))) or template.count("<<secret:") != len(matches):
        raise RecipeError(
            f"template must use each of {len(secrets)} placeholders exactly once: {template!r}"
        )
    text = []
    spans: list[tuple[int, int] | None] = [None] * len(secrets)
    length = 0
    cursor = 0
    for match, index in zip(matches, indices):
        text.append(template[cursor : match.start()])
        length += match.start() - cursor
        value = generate(secrets[index]["gen"], secrets[index]["seed"])
        spans[index] = (length, length + len(value))
        text.append(value)
        length += len(value)
        cursor = match.end()
    text.append(template[cursor:])
    return "".join(text), spans


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
    text, _ = materialize(row["template"], row["secrets"])
    del materialized["template"], materialized["secrets"]
    materialized.pop("text_fingerprint", None)
    materialized["text"] = text
    for entity in materialized["entities"]:
        entity["text"] = text[entity["start"] : entity["end"]]
    return materialized
