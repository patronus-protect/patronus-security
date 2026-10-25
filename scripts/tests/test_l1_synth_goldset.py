from __future__ import annotations

import importlib.util
import json
import re
import stat
import subprocess
import sys
from datetime import date
from collections import Counter
from functools import lru_cache
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "synth_goldset.py"
ENTITY_MAP_PATH = ROOT / "research" / "l1-pii" / "entity_map.yaml"
SPEC = importlib.util.spec_from_file_location("l1_synth_goldset", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

# Loaded by path: the package __init__ needs the native module, the evaluator does not.
EVAL_SPEC = importlib.util.spec_from_file_location("l1_external_pii_eval", ROOT / "python" / "patronus_ark" / "external_pii_eval.py")
external_pii_eval = importlib.util.module_from_spec(EVAL_SPEC)
assert EVAL_SPEC.loader is not None
EVAL_SPEC.loader.exec_module(external_pii_eval)


HOLDOUT_SEED = "test-holdout-seed-0123456789abcdef"


@lru_cache(maxsize=None)
def dev_rows() -> tuple[dict, ...]:
    return tuple(MODULE.generate(MODULE.DEV_SEED, "dev", MODULE.DEFAULT_DOCS["dev"]))


@lru_cache(maxsize=None)
def holdout_rows() -> tuple[dict, ...]:
    return tuple(MODULE.generate(HOLDOUT_SEED, "holdout", MODULE.DEFAULT_DOCS["holdout"]))


def map_ids() -> set[str]:
    return {entity["id"] for entity in yaml.safe_load(ENTITY_MAP_PATH.read_text(encoding="utf-8"))["entities"]}


def values(rows, entity_type):
    return [row["text"][e["start"] : e["end"]] for row in rows for e in row["entities"] if e["entity_type"] == entity_type]


def compact(value: str) -> str:
    return re.sub(r"[\s\-./]", "", value)


# ── coverage ─────────────────────────────────────────────────────────────────


def test_goldsets_cover_exactly_the_entity_map_ids():
    # Ids added to the map after the E05 freeze get a goldset of their own or are listed as not generated.
    de_eu, vat = set(MODULE.entity_ids()), set(MODULE.vat_entity_ids())
    assert de_eu | vat == map_ids() - MODULE.NOT_GENERATED
    assert MODULE.NOT_GENERATED <= map_ids()
    assert not de_eu & vat and not MODULE.NOT_GENERATED & (de_eu | vat)
    assert {name: goldset.entity_ids() for name, goldset in MODULE.GOLDSETS.items()} == {
        "de-eu": MODULE.entity_ids(),
        "vat-1": MODULE.vat_entity_ids(),
    }


@pytest.mark.parametrize("rows", [dev_rows, holdout_rows], ids=["dev", "holdout"])
def test_every_entity_map_id_appears_in_both_languages(rows):
    counts = MODULE.coverage(list(rows()))
    missing = {
        (language, entity): counts[(language, entity)]
        for language in ("de", "en")
        for entity in MODULE.entity_ids()
        if counts[(language, entity)] < MODULE.MIN_PER_LANGUAGE
    }
    assert missing == {}
    assert {entity for _, entity in counts} == set(MODULE.entity_ids())


def test_every_document_type_appears_in_both_languages():
    seen = {(row["doc_type"], row["language"]) for row in dev_rows()}
    assert seen == {(doc_type, language) for doc_type in MODULE.DOC_TYPES for language in ("de", "en")}
    assert set(MODULE.DOC_TYPES) == {"letter", "form", "invoice", "medical_letter", "json", "csv", "ticket"}


def test_hard_negatives_are_present_and_never_overlap_gold():
    kinds = {item["kind"] for row in dev_rows() for item in row["hard_negatives"]}
    assert {"invoice_number", "order_number", "icd10", "version", "uuid", "invalid_luhn", "invalid_steuer_id"} <= kinds
    for row in dev_rows():
        for negative in row["hard_negatives"]:
            for entity in row["entities"]:
                assert negative["end"] <= entity["start"] or entity["end"] <= negative["start"], row["id"]


# ── spans ────────────────────────────────────────────────────────────────────


def test_rows_follow_the_external_pii_eval_schema():
    for row in dev_rows():
        assert row["corpus"] == MODULE.CORPUS_ID
        assert row["group_id"] == row["id"]
        assert row["language"] in ("de", "en")
        assert set(row) == {"id", "group_id", "corpus", "language", "doc_type", "text", "entities", "hard_negatives"}
    assert MODULE.validate_rows(list(dev_rows())) == []
    assert len({row["id"] for row in dev_rows()}) == len(dev_rows())


def test_spans_are_code_point_offsets():
    # Emoji outside the BMP before a span make code-point, UTF-16 and UTF-8 offsets differ.
    shifted = [
        (row, entity)
        for row in dev_rows()
        for entity in row["entities"]
        if any(ord(char) > 0xFFFF for char in row["text"][: entity["start"]])
    ]
    assert shifted, "no row exercises non-BMP characters before a span"
    row, entity = shifted[0]
    prefix = row["text"][: entity["start"]]
    assert len(prefix.encode("utf-16-le")) // 2 != entity["start"] != len(prefix.encode("utf-8"))
    email = MODULE.Doc()
    email.add("Grüße 🙏 an {v}", v=MODULE.Span("pii.email", "jürgen@web.de"))
    assert email.entities == [{"entity_type": "pii.email", "start": 11, "end": 24}]
    assert email.text()[11:24] == "jürgen@web.de"


def test_json_and_csv_spans_exclude_quotes():
    for row in dev_rows():
        if row["doc_type"] not in ("json", "csv"):
            continue
        if row["doc_type"] == "json":
            json.loads(row["text"])
        for entity in row["entities"]:
            value = row["text"][entity["start"] : entity["end"]]
            assert not value.startswith('"') and not value.endswith('"')
    doc = MODULE.Doc()
    MODULE.json_value(doc, {"email": MODULE.Span("pii.email", "a.b@web.de")}, 0)
    assert json.loads(doc.text()) == {"email": "a.b@web.de"}
    with pytest.raises(ValueError):
        MODULE.json_value(MODULE.Doc(), {"x": MODULE.Span("pii.email", 'a"b@web.de')}, 0)


def test_gold_scores_perfectly_against_itself_in_external_pii_eval():
    rows = list(dev_rows())[:50]
    predictions = [
        {"id": row["id"], "evidence_spans": [
            {"label": e["entity_type"], "start_char": e["start"], "end_char": e["end"]} for e in row["entities"]
        ]}
        for row in rows
    ]
    report = external_pii_eval.exact_span_metrics(external_pii_eval.attach_ark_predictions(rows, predictions))
    assert report["overall"]["f1"] == 1.0
    assert report["per_corpus"][MODULE.CORPUS_ID]["overall"]["gold"] == sum(len(row["entities"]) for row in rows)


# ── seeds and determinism ────────────────────────────────────────────────────


def test_rng_is_pinned_and_independent_of_the_random_module():
    rng = MODULE.Rng("ark")
    assert [rng.below(1000) for _ in range(5)] == PINNED_RNG
    assert "import random" not in SCRIPT.read_text(encoding="utf-8")


PINNED_RNG = [550, 941, 341, 944, 951]


def test_generation_is_deterministic():
    assert MODULE.generate(MODULE.DEV_SEED, "dev", 21) == MODULE.generate(MODULE.DEV_SEED, "dev", 21)


# A frozen holdout only reproduces if the generator does: any output change needs a new
# GENERATOR_VERSION (and a deliberately re-frozen holdout), not a silent drift.
PINNED_DEV = (1, "ca27d5ae035cc0a2fbe41720eb8edf00e2409f4b1cd110dac6f99d29536f07ae")


def test_dev_output_is_pinned_to_the_generator_version():
    digest = MODULE._sha256(MODULE._jsonl(list(dev_rows())))
    assert (MODULE.GENERATOR_VERSION, digest) == PINNED_DEV


def test_dev_and_holdout_seeds_give_disjoint_documents():
    dev_texts = {row["text"] for row in dev_rows()}
    holdout_texts = {row["text"] for row in holdout_rows()}
    assert not dev_texts & holdout_texts
    assert not {row["id"] for row in dev_rows()} & {row["id"] for row in holdout_rows()}
    dev_values = {row["text"][e["start"] : e["end"]] for row in dev_rows() for e in row["entities"] if e["entity_type"] == "pii.iban"}
    holdout_values = {row["text"][e["start"] : e["end"]] for row in holdout_rows() for e in row["entities"] if e["entity_type"] == "pii.iban"}
    assert not dev_values & holdout_values


def test_split_name_alone_changes_the_documents():
    same_seed = MODULE.generate(MODULE.DEV_SEED, "holdout", 14)
    assert [row["text"] for row in same_seed] != [row["text"] for row in MODULE.generate(MODULE.DEV_SEED, "dev", 14)]


def test_holdout_seed_file_is_created_secret_and_reused(tmp_path):
    seed_file = tmp_path / "holdout" / ".seed"
    first = MODULE.holdout_seed(seed_file)
    assert len(first) >= 32
    assert stat.S_IMODE(seed_file.stat().st_mode) == 0o600
    assert MODULE.holdout_seed(seed_file) == first


def test_holdout_seed_must_differ_from_the_dev_seed(tmp_path):
    seed_file = tmp_path / "seed"
    seed_file.write_text(MODULE.DEV_SEED + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="differ"):
        MODULE.holdout_seed(seed_file)
    seed_file.write_text(MODULE.VAT_DEV_SEED + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="differ"):
        MODULE.holdout_seed(seed_file)
    seed_file.write_text("short\n", encoding="utf-8")
    with pytest.raises(ValueError, match="16"):
        MODULE.holdout_seed(seed_file)


# ── writing, freezing, CLI ───────────────────────────────────────────────────


def seed_file(tmp_path: Path) -> Path:
    path = tmp_path / "secret.seed"
    path.write_text(HOLDOUT_SEED + "\n", encoding="utf-8")
    return path


def test_write_splits_freezes_both_directories(tmp_path, capsys):
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.write_splits(dev, holdout, seed_file(tmp_path)) == 0
    for directory in (dev, holdout):
        assert sorted(path.name for path in directory.iterdir()) == [".ready", MODULE.FILE_NAME, "manifest.json"]
        assert MODULE.check_split(directory) == []
    dev_manifest = json.loads((dev / "manifest.json").read_text(encoding="utf-8"))
    holdout_manifest = json.loads((holdout / "manifest.json").read_text(encoding="utf-8"))
    assert dev_manifest["seed"] == MODULE.DEV_SEED
    assert "seed" not in holdout_manifest
    assert HOLDOUT_SEED not in (holdout / "manifest.json").read_text(encoding="utf-8")
    assert holdout_manifest["rows"] == MODULE.DEFAULT_DOCS["holdout"]
    assert set(dev_manifest["entities"]) == set(MODULE.entity_ids())
    output = capsys.readouterr().out
    assert "dev: written" in output and "holdout: written" in output
    before = {path: path.read_bytes() for directory in (dev, holdout) for path in directory.iterdir()}
    assert MODULE.write_splits(dev, holdout, seed_file(tmp_path)) == 0
    assert {path: path.read_bytes() for path in before} == before
    assert "unchanged (frozen)" in capsys.readouterr().out


def test_frozen_split_refuses_a_different_seed_unless_forced(tmp_path):
    holdout = tmp_path / "holdout"
    assert MODULE.write_splits(None, holdout, seed_file(tmp_path)) == 0
    other = tmp_path / "other.seed"
    other.write_text("another-secret-seed-fedcba9876543210\n", encoding="utf-8")
    manifest = (holdout / "manifest.json").read_bytes()
    assert MODULE.write_splits(None, holdout, other) == 1
    assert (holdout / "manifest.json").read_bytes() == manifest
    assert MODULE.write_splits(None, holdout, other, force=True) == 0
    assert (holdout / "manifest.json").read_bytes() != manifest


def test_tampered_split_fails_check_and_blocks_rewrite(tmp_path):
    dev = tmp_path / "dev"
    assert MODULE.write_splits(dev, None) == 0
    with (dev / MODULE.FILE_NAME).open("a", encoding="utf-8") as handle:
        handle.write("{}\n")
    assert any("SHA-256" in problem for problem in MODULE.check_split(dev))
    assert MODULE.write_splits(dev, None) == 1
    assert MODULE.write_splits(dev, None, force=True) == 0
    assert MODULE.check_split(dev) == []


def test_rejects_nested_directories_and_seed_inside_dev(tmp_path):
    assert MODULE.write_splits(tmp_path / "dev", tmp_path / "dev" / "holdout", seed_file(tmp_path)) == 1
    assert MODULE.write_splits(tmp_path / "dev", tmp_path / "holdout", tmp_path / "dev" / "seed") == 1
    assert not (tmp_path / "dev").exists()
    assert MODULE.write_splits(None, None) == 1


def test_default_holdout_seed_lives_in_the_holdout_directory(tmp_path):
    holdout = tmp_path / "holdout"
    assert MODULE.write_splits(None, holdout) == 0
    seed = (holdout / MODULE.SEED_FILE).read_text(encoding="utf-8").strip()
    manifest = json.loads((holdout / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["seed_sha256"] == MODULE._sha256(seed.encode("utf-8"))
    assert MODULE.write_splits(None, holdout) == 0  # same seed file: unchanged


def test_cli_writes_and_checks(tmp_path):
    dev = tmp_path / "dev"
    run = subprocess.run([sys.executable, str(SCRIPT), "--dev-out", str(dev)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    assert "420 rows" in run.stdout
    check = subprocess.run([sys.executable, str(SCRIPT), "--check", str(dev)], capture_output=True, text=True, check=False)
    assert check.returncode == 0 and "goldset ok" in check.stdout
    (dev / ".ready").write_text("0\n", encoding="utf-8")
    check = subprocess.run([sys.executable, str(SCRIPT), "--check", str(dev)], capture_output=True, text=True, check=False)
    assert check.returncode == 1


# ── checksum vectors ─────────────────────────────────────────────────────────


def test_checksum_helpers_match_public_vectors():
    assert MODULE.luhn_check_digit("411111111111111") == "1"
    assert MODULE.luhn_valid("4111111111111111") and not MODULE.luhn_valid("4111111111111112")
    assert MODULE.iban_check_digits("DE", "370400440532013000") == "89"
    assert MODULE.iban_valid("DE89 3704 0044 0532 0130 00") and not MODULE.iban_valid("DE88370400440532013000")
    assert MODULE.iban_valid("BE68539007547034") and MODULE.iban_valid("GB82WEST12345698765432")
    assert MODULE.iso7064_mod11_10("8609574271") == 9  # Steuer-ID 86095742719
    assert MODULE.iso7064_mod11_10("13669597") == 6  # USt-IdNr. DE136695976
    assert MODULE.verhoeff_check_digit("236") == "3"
    assert MODULE.verhoeff_valid("2363") and not MODULE.verhoeff_valid("2364")
    assert MODULE.mrz_check_digit("C01X00T4") == "1"  # Reisepass C01X00T41
    assert MODULE.kvnr("A", "12345678") == "A123456780"
    assert MODULE.rvnr(15, date(1949, 6, 7), "C", 10) == "15070649C103"
    assert MODULE.lanr("123456", "01") == "123456601"
    assert MODULE.italian_fiscal_code("Rossi", "Mario", date(1985, 12, 10), False, "A562") == "RSSMRA85T10A562S"
    assert MODULE.base58check(bytes(21)) == "1111111111111111111114oLvT2"


@pytest.mark.parametrize(
    ("generator", "valid"),
    [
        ("gen_iban", MODULE.iban_valid),
        ("gen_pan", lambda value: MODULE.luhn_valid(compact(value))),
        ("gen_steuer_id", lambda value: MODULE.iso7064_mod11_10(compact(value)[:10]) == int(compact(value)[10])),
        ("gen_vat_de", lambda value: MODULE.iso7064_mod11_10(compact(value)[2:10]) == int(compact(value)[10])),
        ("gen_kvnr", lambda value: MODULE.kvnr(value[0], value[1:9]) == value),
        ("gen_lanr", lambda value: MODULE.lanr(value[:6], value[7:]) == value),
        ("gen_aadhaar", lambda value: MODULE.verhoeff_valid(compact(value))),
        ("gen_nin", MODULE.verhoeff_valid),
        ("gen_npi", lambda value: MODULE.luhn_valid("80840" + value)),
        ("gen_sin", lambda value: MODULE.luhn_valid(compact(value))),
        ("gen_za_id", MODULE.luhn_valid),
        ("gen_id_card", lambda value: not value[-1].isdigit() or MODULE.mrz_check_digit(value[:8]) == value[8]),
    ],
)
def test_generated_checksum_values_are_valid(generator, valid):
    for number in range(300):
        rng = MODULE.Rng(f"vector:{generator}:{number}")
        language = ("de", "en")[number % 2]
        value = getattr(MODULE, generator)(rng, MODULE.persona(rng, language), language)
        assert valid(value), value


def test_hard_negative_lookalikes_fail_their_checksums():
    for row in dev_rows():
        for item in row["hard_negatives"]:
            value = row["text"][item["start"] : item["end"]]
            if item["kind"] == "invalid_luhn":
                assert not MODULE.luhn_valid(value)
            if item["kind"] == "invalid_steuer_id":
                assert MODULE.iso7064_mod11_10(value[:10]) != int(value[10])


def test_positives_avoid_reserved_placeholder_values():
    """Placeholders would be gold positives (T01), but E05 is frozen: its positives keep avoiding them."""
    for email in values(dev_rows(), "pii.email"):
        assert not re.search(r"(?:^|[@.])(example\.(?:com|org|net)|[^@]*\.(?:invalid|test|example|localhost))$", email)
    for phone in values(dev_rows(), "pii.phone"):
        assert not re.search(r"555[ -]?01\d\d|000[ -]?000", phone)
        assert not compact(phone).startswith("+447700900")
    for address in values(dev_rows(), "pii.ip_address"):
        assert not address.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "10.", "192.168.", "2001:db8"))



def test_hard_negatives_never_hold_reserved_placeholder_values():
    """T01: reserved placeholders are PII, so no hard-negative span may contain one."""
    for row in dev_rows():
        for item in row["hard_negatives"]:
            value = row["text"][item["start"] : item["end"]]
            assert not re.search(r"@|555[ -]?01\d\d|000[ -]?000[ -]?0000", value), (item["kind"], value)

# ── cross-checks against Presidio and phonenumbers (optional) ────────────────


def presidio_available() -> bool:
    return importlib.util.find_spec("presidio_analyzer") is not None


@pytest.mark.skipif(not presidio_available(), reason="presidio_analyzer is not installed")
def test_no_generated_value_fails_a_presidio_validator():
    import inspect

    import regex  # Presidio's regex engine: inline flags such as \b(?i) are valid there
    from presidio_analyzer import PatternRecognizer, predefined_recognizers

    entity_map = yaml.safe_load(ENTITY_MAP_PATH.read_text(encoding="utf-8"))["entities"]
    presidio = {entity["id"]: set(entity["presidio"]) for entity in entity_map}
    recognizers: dict[str, list] = {}
    for name in dir(predefined_recognizers):
        cls = getattr(predefined_recognizers, name)
        if inspect.isclass(cls) and issubclass(cls, PatternRecognizer) and cls is not PatternRecognizer:
            instance = cls()
            for entity in instance.supported_entities:
                recognizers.setdefault(entity, []).append(instance)
    failures = []
    checked = 0
    for row in dev_rows():
        for entity in row["entities"]:
            value = row["text"][entity["start"] : entity["end"]]
            verdicts = []
            for presidio_entity in presidio[entity["entity_type"]]:
                for recognizer in recognizers.get(presidio_entity, []):
                    flags = recognizer.global_regex_flags or 0
                    if any(regex.fullmatch(pattern.regex, value, flags) for pattern in recognizer.patterns):
                        verdicts.append(recognizer.validate_result(value) is not False and recognizer.invalidate_result(value) is not True)
            # Several recognizers can share an id (ABA routing vs. bank account): one acceptance suffices.
            if verdicts:
                checked += 1
                if not any(verdicts):
                    failures.append((entity["entity_type"], value))
    assert checked > 1000
    assert failures == []


@pytest.mark.skipif(importlib.util.find_spec("phonenumbers") is None, reason="phonenumbers is not installed")
def test_generated_phone_numbers_are_valid():
    import phonenumbers

    for row in dev_rows():
        for value in values([row], "pii.phone"):
            region = "US" if value.startswith("(") else ("DE" if row["language"] == "de" else "GB")
            assert phonenumbers.is_valid_number(phonenumbers.parse(value, region)), value


# ── VAT goldset part 1 (GOLD-VAT1) ───────────────────────────────────────────

VAT = MODULE.GOLDSETS["vat-1"]
VAT_IDS = {
    f"pii.{country}.vat_id"
    for country in ("at", "be", "bg", "ch", "cy", "cz", "dk", "ee", "es", "fi", "fr", "gr", "hr", "hu")
}
VAT_NEGATIVES = {"vat_check_digit", "vat_length", "vat_postcode"}

# Loaded by path like test_l1_scoreboard.py: the Python ports of the Rust VAT validators.
SCOREBOARD_SPEC = importlib.util.spec_from_file_location("scoreboard", ROOT / "scripts" / "l1_presidio" / "scoreboard.py")
scoreboard = sys.modules.get("scoreboard") or importlib.util.module_from_spec(SCOREBOARD_SPEC)
if "scoreboard" not in sys.modules:
    sys.modules["scoreboard"] = scoreboard
    assert SCOREBOARD_SPEC.loader is not None
    SCOREBOARD_SPEC.loader.exec_module(scoreboard)


@lru_cache(maxsize=None)
def vat_dev_rows() -> tuple[dict, ...]:
    return tuple(VAT.generate(VAT.dev_seed, "dev", VAT.docs["dev"]))


@lru_cache(maxsize=None)
def vat_holdout_rows() -> tuple[dict, ...]:
    return tuple(VAT.generate(HOLDOUT_SEED, "holdout", VAT.docs["holdout"]))


@lru_cache(maxsize=None)
def vat_validators() -> dict:
    """The checksum ports of every VAT id, by the PII_PATTERNS registry and ``checksums.ark``."""
    names = scoreboard.gold_validators(scoreboard.entity_map_module.load())
    return {
        entity: [scoreboard.CHECKSUM_PORTS[name] for name in names[entity]]
        for entity in VAT_IDS
    }


def vat_valid(entity: str, value: str) -> bool:
    return any(port(value) for port in vat_validators()[entity])


def vat_id_of(row: dict) -> str:
    (entity,) = {e["entity_type"] for e in row["entities"] if e["entity_type"].endswith(".vat_id")}
    return entity


def test_vat_goldset_lists_exactly_the_part_one_ids():
    assert set(MODULE.vat_entity_ids()) == VAT_IDS
    assert VAT.corpus == "ark-synthetic-vat-1" != MODULE.CORPUS_ID
    assert VAT.dev_seed != MODULE.DEV_SEED and VAT.file_name == "ark-synthetic-vat-1.jsonl"


@pytest.mark.parametrize("rows", [vat_dev_rows, vat_holdout_rows], ids=["dev", "holdout"])
def test_vat_ids_have_positives_and_hard_negatives_in_every_carrier_and_language(rows):
    positives, negatives, carriers = Counter(), Counter(), set()
    for row in rows():
        entity = vat_id_of(row)
        carriers.add((entity, row["language"], row["doc_type"]))
        positives[(entity, row["language"])] += sum(e["entity_type"] == entity for e in row["entities"])
        for item in row["hard_negatives"]:
            negatives[(entity, row["language"], item["kind"])] += 1
    assert carriers == {
        (entity, language, doc_type) for entity in VAT_IDS for language in ("de", "en") for doc_type in MODULE.VAT_DOC_TYPES
    }
    for entity in VAT_IDS:
        assert positives[(entity, "de")] + positives[(entity, "en")] >= 10
        for language in ("de", "en"):
            assert positives[(entity, language)] >= MODULE.MIN_PER_LANGUAGE
            assert sum(negatives[(entity, language, kind)] for kind in VAT_NEGATIVES) >= MODULE.MIN_PER_LANGUAGE
            assert all(negatives[(entity, language, kind)] for kind in VAT_NEGATIVES), (entity, language)
    assert {kind for _, _, kind in negatives} == VAT_NEGATIVES


@pytest.mark.parametrize("rows", [vat_dev_rows, vat_holdout_rows], ids=["dev", "holdout"])
def test_vat_positives_pass_and_hard_negatives_fail_the_validator_ports(rows):
    for row in rows():
        entity = vat_id_of(row)
        for value in values([row], entity):
            assert vat_valid(entity, value), value
        for item in row["hard_negatives"]:
            assert not vat_valid(entity, row["text"][item["start"] : item["end"]]), item


def test_vat_generators_issue_valid_numbers_and_hard_negatives_miss_them():
    for country in MODULE.VAT_COUNTRIES:
        for number in range(200):
            rng = MODULE.Rng(f"vector:{country.entity}:{number}")
            person = MODULE.persona(rng, ("de", "en")[number % 2])
            compact = country.legal(rng)
            assert compact.startswith(country.prefix) and len(compact) - len(country.prefix) in country.lengths
            assert vat_valid(country.entity, compact), compact
            assert vat_valid(country.entity, MODULE.vat_value(rng, country, person).value)
            if country.person:
                assert vat_valid(country.entity, country.person(rng, person))
            wrong = MODULE.vat_wrong_check(rng, country).value
            assert not vat_valid(country.entity, wrong), wrong
            short_or_long = MODULE.vat_wrong_length(rng, country).value
            assert len(short_or_long) - len(country.prefix) in (min(country.lengths) - 1, max(country.lengths) + 1)
            assert not vat_valid(country.entity, short_or_long)


def test_vat_checksum_vectors():
    """Published numbers satisfy the check-digit rules the generators use."""
    assert (6 - MODULE.luhn_sum("1358562")) % 10 == 7  # ATU13585627
    assert 97 - 4030192 % 97 == 61  # BE0403019261
    assert MODULE.weighted_sum("20774740", (7, 9, 10, 5, 8, 4, 2, 1)) % 11 == 0  # FI20774740
    assert MODULE.weighted_sum("13585628", (2, 7, 6, 5, 4, 3, 2, 1)) % 11 == 0  # DK13585628
    assert MODULE.weighted_sum("12892312", (9, 7, 3, 1) * 2) % 10 == 0  # HU12892312
    assert MODULE.weighted_sum("100931558", (3, 7, 1) * 3) % 10 == 0  # EE100931558
    assert MODULE.iso7064_mod11_10("3339200596") == 1  # HR33392005961
    assert MODULE.luhn_sum("303265045") == 0 and (12 + 3 * (303265045 % 97)) % 97 == 40  # FR40303265045
    for value in ("ATU13585627", "BE0403019261", "BG175074752", "CHE-100.155.212", "CY10259033P", "CZ25123891",
                  "DK13585628", "EE100931558", "ESA13585625", "FI20774740", "FR40303265045", "EL094259216",
                  "HR33392005961", "HU12892312"):
        entity = next(country.entity for country in MODULE.VAT_COUNTRIES if value.startswith(country.prefix[:2]))
        assert vat_valid(entity, value), value


def test_vat_rows_follow_the_schema_and_carriers_parse():
    rows = list(vat_dev_rows())
    assert MODULE.validate_rows(rows, MODULE.vat_entity_ids()) == []
    assert len({row["id"] for row in rows}) == len(rows) == VAT.docs["dev"]
    for row in rows:
        assert row["corpus"] == VAT.corpus and row["group_id"] == row["id"] and row["id"].startswith("synth-vat1-dev-")
        assert set(row) == {"id", "group_id", "corpus", "language", "doc_type", "text", "entities", "hard_negatives"}
        if row["doc_type"] == "json":
            json.loads(row["text"])
        if row["doc_type"] == "csv":
            lines = row["text"].splitlines()
            assert len({len(line.split(";" if row["language"] == "de" else ",")) for line in lines}) == 1
        for item in row["entities"] + row["hard_negatives"]:
            value = row["text"][item["start"] : item["end"]]
            assert value == value.strip() and not value.startswith('"') and not value.endswith('"')


def test_vat_generation_is_pinned_and_split_by_seed():
    assert VAT.generate(VAT.dev_seed, "dev", 16) == list(vat_dev_rows())[:16]
    assert MODULE._sha256(MODULE._jsonl(list(vat_dev_rows()))) == PINNED_VAT_DEV[1]
    assert VAT.version == PINNED_VAT_DEV[0]
    dev = {compact(value) for entity in VAT_IDS for value in values(vat_dev_rows(), entity)}
    holdout = {compact(value) for entity in VAT_IDS for value in values(vat_holdout_rows(), entity)}
    assert dev and holdout and not dev & holdout
    assert not {row["text"] for row in vat_dev_rows()} & {row["text"] for row in vat_holdout_rows()}


# Any output change needs a new VAT_GENERATOR_VERSION and a deliberately re-frozen holdout.
PINNED_VAT_DEV = (1, "2abe305d33559fe4c17c7f8b12d9da60e8a1b8fbbf293be41cab34e5628ddaf4")


def test_vat_hard_negatives_never_hold_reserved_placeholder_values():
    for row in vat_dev_rows():
        for item in row["hard_negatives"]:
            assert not re.search(r"@|555[ -]?01\d\d", row["text"][item["start"] : item["end"]])


def test_write_splits_freezes_the_vat_goldset(tmp_path, capsys):
    dev, holdout = tmp_path / "synthetic-vat-1" / "dev", tmp_path / "synthetic-vat-1" / "holdout"
    assert MODULE.write_splits(dev, holdout, seed_file(tmp_path), goldset=VAT) == 0
    for directory in (dev, holdout):
        assert sorted(path.name for path in directory.iterdir()) == [".ready", VAT.file_name, "manifest.json"]
        assert MODULE.check_split(directory) == []
    manifest = json.loads((dev / "manifest.json").read_text(encoding="utf-8"))
    assert (manifest["corpus"], manifest["file"], manifest["seed"]) == (VAT.corpus, VAT.file_name, VAT.dev_seed)
    assert (manifest["rows"], manifest["generator_version"]) == (VAT.docs["dev"], VAT.version)
    assert set(manifest["entities"]) == VAT_IDS | {"entity.organization", "entity.location", "entity.person_name"}
    assert set(manifest["hard_negatives"]) == VAT_NEGATIVES
    assert json.loads((holdout / "manifest.json").read_text(encoding="utf-8"))["rows"] == VAT.docs["holdout"]
    assert MODULE.write_splits(dev, holdout, seed_file(tmp_path), goldset=VAT) == 0
    assert "unchanged (frozen)" in capsys.readouterr().out


def test_cli_writes_the_vat_goldset(tmp_path):
    dev = tmp_path / "dev"
    run = subprocess.run(
        [sys.executable, str(SCRIPT), "--goldset", "vat-1", "--dev-out", str(dev)], capture_output=True, text=True, check=False
    )
    assert run.returncode == 0, run.stderr
    assert f"{VAT.docs['dev']} rows" in run.stdout
    assert (dev / VAT.file_name).is_file() and not (dev / MODULE.FILE_NAME).exists()
