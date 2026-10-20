from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "prepare_corpora.py"
FIXTURES = ROOT / "scripts" / "fixtures" / "l1_corpora"
EXTERNAL_FIXTURES = ROOT / "python" / "patronus_ark" / "benchmark_data" / "external_pii" / "fixtures"
SPEC = importlib.util.spec_from_file_location("l1_prepare_corpora", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

GRETEL = "gretel-synthetic-pii-finance"
OPENPII = "ai4privacy-openpii-nano-1k"
TAB = "tab"
GRETEL_SHARDS = ("gretel_v1_test.parquet", "gretel_v2_test.parquet")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Snappy and Parquet ───────────────────────────────────────────────────────


def test_snappy_literal_and_overlapping_copy():
    # length 12; literal "abcd"; copy (1-byte offset form) len 8 offset 4 -> "abcd" repeated.
    compressed = bytes([12, (4 - 1) << 2]) + b"abcd" + bytes([((8 - 4) << 2) | 1, 4])
    assert MODULE.snappy_decompress(compressed) == b"abcdabcdabcd"


def test_snappy_two_byte_offset_copy_and_long_literal():
    literal = bytes(range(100))
    # literal of 100 bytes uses the 1-extra-byte length form (tag 60), then copy 2-byte offset len 10 offset 100.
    compressed = bytes([110]) + bytes([60 << 2, 99]) + literal + bytes([((10 - 1) << 2) | 2]) + (100).to_bytes(2, "little")
    assert MODULE.snappy_decompress(compressed) == literal + literal[:10]


def test_snappy_rejects_truncated_or_inconsistent_input():
    with pytest.raises(ValueError):
        MODULE.snappy_decompress(bytes([12, (4 - 1) << 2]) + b"ab")
    with pytest.raises(ValueError):
        MODULE.snappy_decompress(bytes([5, (4 - 1) << 2]) + b"abcd")  # declares 5, yields 4
    with pytest.raises(ValueError):
        MODULE.snappy_decompress(bytes([8, (4 - 1) << 2]) + b"abcd" + bytes([((4 - 4) << 2) | 1, 9]))  # offset > output


@pytest.mark.parametrize("shard", GRETEL_SHARDS)
def test_parquet_reader_matches_the_fixture(shard):
    expected = json.loads((FIXTURES / "gretel_expected.json").read_text(encoding="utf-8"))[shard]
    columns = list(expected[0])
    assert MODULE.read_parquet_columns(FIXTURES / shard, columns) == expected


def test_parquet_reader_keeps_nulls_and_rejects_unknown_columns():
    rows = MODULE.read_parquet_columns(FIXTURES / "gretel_v2_test.parquet", ["document_type"])
    assert rows[3] == {"document_type": None}
    assert sum(row["document_type"] is None for row in rows) == 1
    with pytest.raises(ValueError, match="no_such_column"):
        MODULE.read_parquet_columns(FIXTURES / "gretel_v1_test.parquet", ["no_such_column"])


def test_parquet_reader_rejects_non_parquet_files(tmp_path):
    path = tmp_path / "broken.parquet"
    path.write_bytes(b"PAR1 not really parquet")
    with pytest.raises(ValueError):
        MODULE.read_parquet_columns(path, ["language"])


@pytest.mark.parametrize("shard", GRETEL_SHARDS)
def test_parquet_reader_agrees_with_pyarrow_when_installed(shard):
    pq = pytest.importorskip("pyarrow.parquet")
    columns = ["document_type", "expanded_type", "language", "generated_text", "pii_spans"]
    assert MODULE.read_parquet_columns(FIXTURES / shard, columns) == pq.read_table(
        FIXTURES / shard, columns=columns
    ).to_pylist()


@pytest.mark.skipif(not os.environ.get("ARK_L1_CORPUS_SOURCES"), reason="needs the pinned Gretel shards")
def test_parquet_reader_agrees_with_pyarrow_on_the_pinned_gretel_shards():
    # ARK_L1_CORPUS_SOURCES points at a --sources directory of prepare_corpora.py.
    pq = pytest.importorskip("pyarrow.parquet")
    corpus = MODULE.load_manifest()[GRETEL]
    columns = ["language", "expanded_type", "generated_text", "pii_spans"]
    for entry in corpus["verified_files"]:
        path = Path(os.environ["ARK_L1_CORPUS_SOURCES"]) / GRETEL / entry["path"]
        assert MODULE.read_parquet_columns(path, columns) == pq.read_table(path, columns=columns).to_pylist()


# ── sources ──────────────────────────────────────────────────────────────────


def test_source_urls_are_pinned_to_the_manifest_revisions():
    manifest = MODULE.load_manifest()
    urls = {corpus: [source.url for source in MODULE.source_files(manifest[corpus])] for corpus in MODULE.CORPORA}
    assert urls[OPENPII] == [
        "https://huggingface.co/datasets/ai4privacy/openpii-masking-nano-1k/resolve/"
        "421ebabbfdd9cc55c1a936fdc8f51cb384a6d0a1/data/train.jsonl"
    ]
    assert urls[TAB] == [
        "https://raw.githubusercontent.com/NorskRegnesentral/text-anonymization-benchmark/"
        "558e09e26d6b36f5f78440074e6a233946d98bd9/echr_test.json"
    ]
    assert len(urls[GRETEL]) == 6
    assert urls[GRETEL][1] == (
        "https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual/resolve/"
        "7b844d16738527a04264f50214cb426a4cea0897/data/English_test-00000-of-00001.parquet"
    )
    assert all(len(source.sha256) == 64 for corpus in MODULE.CORPORA for source in MODULE.source_files(manifest[corpus]))


# ── end to end on synthetic sources ──────────────────────────────────────────


def openpii_rows(count: int = 40) -> bytes:
    lines = []
    for index in range(count):
        text = f"Kontakt {index}: mail{index}@example.test, IBAN DE89370400440532013000."
        email = f"mail{index}@example.test"
        start = text.index(email)
        iban = text.index("DE89")
        lines.append(
            json.dumps(
                {
                    "uid": f"openpii-synthetic-{index:03d}",
                    "language": "de" if index % 2 else "en",
                    "source_text": text,
                    "privacy_mask": [
                        {"label": "EMAIL", "start": start, "end": start + len(email), "value": email},
                        {"label": "IBAN", "start": iban, "end": iban + 22, "value": text[iban : iban + 22]},
                    ],
                }
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def tab_documents(count: int = 30) -> bytes:
    template = json.loads((EXTERNAL_FIXTURES / "tab-standoff.json").read_text(encoding="utf-8"))[0]
    documents = []
    for index in range(count):
        document = copy.deepcopy(template)
        document["doc_id"] = f"tab-synthetic-{index:03d}"
        documents.append(document)
    return json.dumps(documents).encode("utf-8")


@pytest.fixture
def sources(tmp_path):
    """A --sources directory with synthetic files and a manifest pinning their SHA-256."""
    payloads = {
        (GRETEL, shard): (FIXTURES / shard).read_bytes() for shard in GRETEL_SHARDS
    }
    payloads[(OPENPII, "data/train.jsonl")] = openpii_rows()
    payloads[(TAB, "echr_test.json")] = tab_documents()
    manifest = json.loads(MODULE.MANIFEST_PATH.read_text(encoding="utf-8"))
    for corpus in manifest["corpora"]:
        if corpus["id"] == GRETEL:
            corpus["verified_files"] = [
                {"path": shard, "sha256": sha256(payloads[(GRETEL, shard)])} for shard in GRETEL_SHARDS
            ]
        elif corpus["id"] == OPENPII:
            corpus["verified_sha256"] = sha256(payloads[(OPENPII, "data/train.jsonl")])
        else:
            corpus["verified_sha256"] = sha256(payloads[(TAB, "echr_test.json")])
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    source_dir = tmp_path / "sources"
    for (corpus, path), payload in payloads.items():
        target = source_dir / corpus / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return {"manifest": manifest_path, "dir": source_dir, "payloads": payloads, "tmp": tmp_path}


def prepare(sources, **overrides):
    tmp = sources["tmp"]
    options = {
        "dev_out": tmp / "dev",
        "holdout_out": tmp / "holdout",
        "source_dir": sources["dir"],
        "manifest_path": sources["manifest"],
        "offline": True,
    }
    options.update(overrides)
    return MODULE.prepare(**options)


def read_split(directory: Path) -> dict[str, list[dict]]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    return {
        corpus["id"]: [json.loads(line) for line in (directory / corpus["file"]).read_text(encoding="utf-8").splitlines()]
        for corpus in manifest["corpora"]
    }


def test_prepare_writes_disjoint_group_atomic_splits_with_manifests(sources):
    assert prepare(sources) == 0
    tmp = sources["tmp"]
    dev, holdout = read_split(tmp / "dev"), read_split(tmp / "holdout")
    assert set(dev) == set(holdout) == set(MODULE.CORPORA)
    for corpus in MODULE.CORPORA:
        dev_ids = {row["id"] for row in dev[corpus]}
        holdout_ids = {row["id"] for row in holdout[corpus]}
        assert dev_ids and holdout_ids, corpus
        assert not dev_ids & holdout_ids
        assert not {row["group_id"] for row in dev[corpus]} & {row["group_id"] for row in holdout[corpus]}
        assert all(row["corpus"] == corpus for row in dev[corpus] + holdout[corpus])
    # Every source row lands in exactly one split.
    assert len(dev[OPENPII]) + len(holdout[OPENPII]) == 40
    assert len(dev[TAB]) + len(holdout[TAB]) == 30
    assert len(dev[GRETEL]) + len(holdout[GRETEL]) == 24

    for split in ("dev", "holdout"):
        directory = tmp / split
        manifest_bytes = (directory / "manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        assert manifest["schema"] == MODULE.SCHEMA
        assert manifest["split"] == split
        assert manifest["seed"] == MODULE.SPLIT_SEED
        assert manifest["holdout_fraction"] == MODULE.HOLDOUT_FRACTION
        for corpus in manifest["corpora"]:
            data = (directory / corpus["file"]).read_bytes()
            assert corpus["sha256"] == sha256(data)
            assert corpus["bytes"] == len(data)
            assert corpus["rows"] == len(data.splitlines())
            assert all(len(source["sha256"]) == 64 for source in corpus["sources"])
        assert (directory / ".ready").read_text(encoding="utf-8") == f"{sha256(manifest_bytes)}  manifest.json\n"
        assert MODULE.check_split(directory) == []


def test_split_follows_the_frozen_seed_and_fraction(sources):
    assert prepare(sources) == 0
    holdout = read_split(sources["tmp"] / "holdout")
    for corpus, rows in holdout.items():
        for row in rows:
            assert MODULE.split_of(corpus, row["group_id"]) == "holdout"
    # A different seed moves groups: the split is a function of the seed, not of the row order.
    moved = [
        group
        for group in (f"group-{index}" for index in range(200))
        if MODULE.split_of(TAB, group) != MODULE.split_of(TAB, group, seed="other-seed")
    ]
    assert moved
    share = sum(MODULE.split_of(TAB, f"group-{index}") == "holdout" for index in range(2000)) / 2000
    assert abs(share - MODULE.HOLDOUT_FRACTION) < 0.05


def test_prepare_is_byte_identical_and_a_frozen_rerun_is_a_no_op(sources, tmp_path):
    assert prepare(sources) == 0
    first = {path.relative_to(tmp_path): path.read_bytes() for path in (tmp_path / "dev").rglob("*")}
    assert prepare(sources) == 0
    assert {path.relative_to(tmp_path): path.read_bytes() for path in (tmp_path / "dev").rglob("*")} == first
    assert prepare(sources, dev_out=tmp_path / "dev2", holdout_out=tmp_path / "holdout2") == 0
    for name in ("manifest.json", ".ready", f"{TAB}.jsonl"):
        assert (tmp_path / "dev2" / name).read_bytes() == (tmp_path / "dev" / name).read_bytes()


def test_prepare_refuses_to_change_a_frozen_split(sources, tmp_path):
    assert prepare(sources) == 0
    before = (tmp_path / "holdout" / "manifest.json").read_bytes()
    assert prepare(sources, seed="another-seed") == 1
    assert (tmp_path / "holdout" / "manifest.json").read_bytes() == before
    assert prepare(sources, seed="another-seed", force=True) == 0
    assert (tmp_path / "holdout" / "manifest.json").read_bytes() != before


def test_prepare_refuses_a_tampered_frozen_split(sources, tmp_path):
    assert prepare(sources) == 0
    with (tmp_path / "dev" / f"{TAB}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{}\n")
    assert MODULE.check_split(tmp_path / "dev")
    assert prepare(sources) == 1


def test_source_hash_mismatch_writes_nothing(sources, tmp_path):
    (sources["dir"] / TAB / "echr_test.json").write_bytes(tab_documents(29))
    assert prepare(sources) == 1
    assert not (tmp_path / "dev" / ".ready").exists()
    assert not (tmp_path / "holdout" / ".ready").exists()


def test_offline_without_sources_fails(sources, tmp_path):
    assert prepare(sources, source_dir=tmp_path / "empty") == 1
    assert not (tmp_path / "holdout" / ".ready").exists()


def test_download_verifies_and_caches_sources(sources, tmp_path):
    corpora = MODULE.load_manifest(sources["manifest"])
    by_url = {}
    for corpus in MODULE.CORPORA:
        for source in MODULE.source_files(corpora[corpus]):
            name = source.path if corpus != GRETEL else source.path.split("/")[-1]
            by_url[source.url] = sources["payloads"][(corpus, name)]
    requested = []

    def fetch(url):
        requested.append(url)
        return by_url[url]

    cache = tmp_path / "cache"
    assert prepare(sources, source_dir=cache, offline=False, fetch=fetch) == 0
    assert sorted(requested) == sorted(by_url)
    requested.clear()
    assert prepare(sources, source_dir=cache, offline=False, fetch=fetch) == 0
    assert requested == []  # verified cache, no second download

    def corrupt(url):
        return b"tampered"

    assert prepare(
        sources, source_dir=tmp_path / "cache2", offline=False, fetch=corrupt,
        dev_out=tmp_path / "dev3", holdout_out=tmp_path / "holdout3",
    ) == 1
    assert not (tmp_path / "holdout3" / ".ready").exists()
    assert not list((tmp_path / "cache2").rglob("*.parquet"))


def test_prepare_refuses_overlapping_directories(sources, tmp_path):
    assert prepare(sources, holdout_out=tmp_path / "dev") == 1
    assert prepare(sources, holdout_out=tmp_path / "dev" / "holdout") == 1
    # Raw sources contain holdout text and must never land in the dev directory.
    assert prepare(sources, source_dir=tmp_path / "dev" / "sources") == 1
    assert not (tmp_path / "dev" / ".ready").exists()


def test_default_source_cache_lives_in_the_holdout_directory(tmp_path):
    assert MODULE.default_source_dir(tmp_path / "holdout") == tmp_path / "holdout" / ".sources"


def test_cli_offline_run(sources, tmp_path):
    proc = subprocess.run(
        [
            sys.executable, str(SCRIPT),
            "--dev-out", str(tmp_path / "dev"), "--holdout-out", str(tmp_path / "holdout"),
            "--sources", str(sources["dir"]), "--manifest", str(sources["manifest"]), "--offline",
        ],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "dev" / ".ready").exists() and (tmp_path / "holdout" / ".ready").exists()
    # The summary names the dev split only; holdout sizes stay out of agent-visible logs.
    assert "dev" in proc.stdout
    check = subprocess.run(
        [sys.executable, str(SCRIPT), "--check", str(tmp_path / "dev")], capture_output=True, text=True, check=False
    )
    assert check.returncode == 0, check.stderr


# ── presidio_favored family ──────────────────────────────────────────────────

EVALUATOR = "presidio-evaluator-synth-v2"
RECOGNIZER_TESTS = "presidio-analyzer-recognizer-tests"

# A recognizer test file in the shape of presidio-analyzer 2.2.364 (written for this test).
CARD_TESTS = '''\
import pytest
import does_not_exist  # never imported: the file is only parsed

raise SystemExit("never executed")

VALID = "4012888888881881"
LABEL = "Card"


def _make(value):
    return value + "0"


@pytest.fixture(scope="module")
def recognizer():
    return CreditCardRecognizer()


@pytest.fixture(scope="module")
def strict_recognizer():
    return CreditCardRecognizer(strict=True)


@pytest.fixture(scope="module")
def entities():
    return ["CREDIT_CARD"]


@pytest.mark.parametrize(
    "text, expected_len, expected_positions, expected_score_ranges",
    [
        ("4012888888881881 4012-8888-8888-1881", 2, ((0, 16), (17, 36),), ((0.5, 1.0),) * 2),
        (f"{LABEL}: {VALID}", 1, [(6, 22)], [(1.0, 1.0)]),
        ("my card is 4012-8888-8888-1882", 0, (), ()),
        (_make("401288888888188"), 1, ((0, 16),), ()),
        ("4012888888881881", 2, ((0, 16),), ()),
        ("4012888888881881", 1, ((0, 99),), ()),
        ("4111111111111111", 1, ((0, 16),), ()),
        ("4111111111111111", 1, ((0, 16),), ()),
        pytest.param("5555555555554444", 1, ((0, 16),), (), id="param"),
    ],
)
def test_when_cards_then_succeed(text, expected_len, expected_positions, expected_score_ranges, recognizer, entities, max_score):
    pass


@pytest.mark.parametrize(
    "text, expected_len, expected_position, expected_score",
    [
        ("5555555555554444", 1, (0, 16), 1),
        ("no card here", 0, (0, 12), 0),
    ],
)
def test_single_position(text, expected_len, expected_position, expected_score, recognizer, entities):
    pass


@pytest.mark.parametrize("text, expected_len", [("378282246310005", 1), ("Amex 378282246310005", 1), ("12345", 0)])
def test_count_only(text, expected_len, recognizer, entities):
    pass


@pytest.mark.parametrize("text, expected_len", [("4111111111111111", 0)])
def test_strict_mode(text, expected_len, strict_recognizer, entities):
    pass


@pytest.mark.parametrize("text, expected_len, leniency", [("4111111111111111", 0, 3)])
def test_leniency(text, expected_len, leniency, recognizer, entities):
    pass


@pytest.mark.parametrize("number, expected", [("4111111111111111", True)])
def test_validate(number, expected, recognizer):
    pass
'''

PHONE_TESTS = '''\
@pytest.fixture(scope="module")
def recognizer():
    return PhoneRecognizer(supported_regions=PhoneRecognizer.DEFAULT_SUPPORTED_REGIONS + ("JP",))


@pytest.mark.parametrize(
    "text, expected_len, entities, expected_positions, score",
    [
        ("call (415) 555-0132 or +1 415 555 0132", 2, ["PHONE_NUMBER", "PHONE_NUMBER"], ((5, 19), (23, 38)), 0.4),
        ("4111111111111111", 1, ["PHONE_NUMBER"], ((0, 16),), 0.4),
    ],
)
def test_phones(spacy_nlp_engine, text, expected_len, entities, expected_positions, score, recognizer):
    pass
'''

DE_TESTS = '''\
@pytest.fixture(scope="module")
def recognizer():
    return DeTaxIdRecognizer()


@pytest.fixture(scope="module")
def entities():
    return ["DE_TAX_ID"]


@pytest.mark.parametrize(
    "text, expected_len, expected_positions",
    [
        ("Steuer-ID: 12345678903.", 1, ((11, 22),)),
        ("12345678901", 0, ()),
    ],
)
def test_tax_ids(text, expected_len, expected_positions, recognizer, entities):
    pass
'''

DATE_TESTS = '''\
@pytest.fixture(scope="module")
def recognizer():
    return DateRecognizer()


@pytest.fixture(scope="module")
def entities():
    return ["DATE_TIME"]


@pytest.mark.parametrize("text, expected_len, expected_positions", [("on 2024-01-02", 1, ((3, 13),))])
def test_dates(text, expected_len, expected_positions, recognizer, entities):
    pass
'''

RECOGNIZER_FILES = {
    "test_credit_card_recognizer.py": CARD_TESTS,
    "test_phone_recognizer.py": PHONE_TESTS,
    "test_de_tax_id_recognizer.py": DE_TESTS,
    "test_date_recognizer.py": DATE_TESTS,
}


def test_recognizer_cases_are_read_without_running_the_test_file():
    cases, skipped = MODULE.recognizer_test_cases(CARD_TESTS, "test_credit_card_recognizer.py")
    by_test = {case.test.split("::")[1]: case for case in cases}
    assert by_test["test_when_cards_then_succeed[0]"].spans == (("CREDIT_CARD", 0, 16), ("CREDIT_CARD", 17, 36))
    # Module constants and f-strings of them resolve; calls do not.
    assert by_test["test_when_cards_then_succeed[1]"].text == "Card: 4012888888881881"
    assert by_test["test_when_cards_then_succeed[1]"].spans == (("CREDIT_CARD", 6, 22),)
    negative = by_test["test_when_cards_then_succeed[2]"]
    assert negative.spans == () and negative.entities == ("CREDIT_CARD",)
    assert "test_when_cards_then_succeed[3]" not in by_test
    # Spans that disagree with the expected count or leave the text are skipped.
    assert "test_when_cards_then_succeed[4]" not in by_test and "test_when_cards_then_succeed[5]" not in by_test
    assert "test_when_cards_then_succeed[8]" not in by_test  # pytest.param
    # A single (start, end) pair, and a negative whose positions are ignored.
    assert by_test["test_single_position[0]"].spans == (("CREDIT_CARD", 0, 16),)
    assert by_test["test_single_position[1]"].spans == ()
    # Count-only positives are taken only when the whole text is the bare value.
    assert by_test["test_count_only[0]"].spans == (("CREDIT_CARD", 0, 15),)
    assert "test_count_only[1]" not in by_test
    assert by_test["test_count_only[2]"].spans == ()
    # Variant recognizers, call arguments and validator tests yield nothing.
    assert not any(name.startswith(("test_strict_mode", "test_leniency", "test_validate")) for name in by_test)
    assert skipped == {
        "value is not a literal": 1,
        "spans do not match the expected count": 1,
        "span outside the text": 1,
        "case is not a plain tuple": 1,
        "positive without spans": 1,
        "fixture strict_recognizer is not the default recognizer": 1,
        "argument leniency changes the recognizer call": 1,
        "first argument is not the analyzed text": 1,
    }


def test_recognizer_cases_with_per_row_entities_and_a_widened_fixture():
    cases, skipped = MODULE.recognizer_test_cases(PHONE_TESTS, "test_phone_recognizer.py")
    assert [case.spans for case in cases] == [
        (("PHONE_NUMBER", 5, 19), ("PHONE_NUMBER", 23, 38)), (("PHONE_NUMBER", 0, 16),)
    ]
    assert not skipped
    # The same fixture in another file is not on the hand-checked list.
    cases, skipped = MODULE.recognizer_test_cases(PHONE_TESTS, "test_other_recognizer.py")
    assert cases == [] and skipped == {"fixture recognizer is not the default recognizer": 2}


def test_recognizer_test_language_follows_the_file_prefix():
    assert MODULE.recognizer_test_language("test_de_tax_id_recognizer.py") == "de"
    assert MODULE.recognizer_test_language("test_kr_rrn_recognizer.py") == "ko"
    assert MODULE.recognizer_test_language("test_se_personnummer_recognizer.py") == "sv"
    assert MODULE.recognizer_test_language("test_uk_nino_recognizer.py") == "en"
    assert MODULE.recognizer_test_language("test_credit_card_recognizer.py") == "en"


def recognizer_corpus(files=RECOGNIZER_FILES):
    corpus = copy.deepcopy(MODULE.load_manifest()[RECOGNIZER_TESTS])
    corpus["verified_files"] = [{"path": name, "sha256": sha256(text.encode())} for name, text in files.items()]
    return corpus


def write_recognizer_files(root, files=RECOGNIZER_FILES):
    root.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    return root


def test_recognizer_test_rows(tmp_path):
    rows = MODULE.load_recognizer_tests(write_recognizer_files(tmp_path / "tests"), recognizer_corpus())
    by_id = {row["id"]: row for row in rows}
    positive = by_id["test_credit_card_recognizer:test_when_cards_then_succeed:0"]
    assert positive["entities"] == [
        {"entity_type": "pii.credit_card.pan", "start": 0, "end": 16},
        {"entity_type": "pii.credit_card.pan", "start": 17, "end": 36},
    ]
    assert positive["scored_entities"] == ["pii.credit_card.pan"]
    assert positive["source_test"] == "test_credit_card_recognizer.py::test_when_cards_then_succeed[0]"
    assert positive["corpus"] == RECOGNIZER_TESTS and positive["language"] == "en"
    assert positive["group_id"] == "text:" + sha256(positive["text"].encode())
    assert "hard_negatives" not in positive
    negative = by_id["test_credit_card_recognizer:test_when_cards_then_succeed:2"]
    assert negative["entities"] == []
    assert negative["hard_negatives"] == [
        {"start": 0, "end": 30, "kind": "presidio_recognizer_negative", "entity_type": "pii.credit_card.pan"}
    ]
    assert by_id["test_de_tax_id_recognizer:test_tax_ids:0"]["language"] == "de"
    # Repeated cases count once.
    assert "test_credit_card_recognizer:test_when_cards_then_succeed:6" in by_id
    assert "test_credit_card_recognizer:test_when_cards_then_succeed:7" not in by_id
    # DATE_TIME has no L1 benchmark id.
    assert not any(row["id"].startswith("test_date_recognizer") for row in rows)
    # "4111111111111111" is a card in one test and a phone number in another: different ids, both kept.
    phone = by_id["test_phone_recognizer:test_phones:1"]
    assert phone["scored_entities"] == ["pii.phone"] and phone["text"] == "4111111111111111"


def test_contradicting_recognizer_cases_are_dropped(tmp_path):
    files = {
        "test_credit_card_recognizer.py": CARD_TESTS,
        "test_extra_recognizer.py": CARD_TESTS.replace(
            '("my card is 4012-8888-8888-1882", 0, (), ()),', '("my card is 4012-8888-8888-1882", 1, ((11, 30),), ()),'
        ),
    }
    rows = MODULE.load_recognizer_tests(write_recognizer_files(tmp_path / "tests", files), recognizer_corpus(files))
    assert not any(row["text"] == "my card is 4012-8888-8888-1882" for row in rows)
    assert any(row["text"] == "Card: 4012888888881881" for row in rows)


def evaluator_samples(count: int = 30) -> list[dict]:
    samples = []
    for index in range(count):
        email = f"user{index}@mail{index}.de"
        text = f"Hi Ana, write to {email} today. ZIP 1234"
        samples.append({
            "full_text": text,
            "masked": "Hi {{PERSON}}, write to {{EMAIL_ADDRESS}} today. ZIP {{ZIP_CODE}}",
            "spans": [
                {"entity_type": "EMAIL_ADDRESS", "entity_value": email, "start_position": 17, "end_position": 17 + len(email)},
                {"entity_type": "PERSON", "entity_value": "Ana", "start_position": 3, "end_position": 6},
                {"entity_type": "ZIP_CODE", "entity_value": "1234", "start_position": len(text) - 4, "end_position": len(text)},
            ],
            "template_id": index % 12,
            "metadata": None,
        })
    return samples


def test_presidio_evaluator_rows(tmp_path):
    corpus = MODULE.load_manifest()[EVALUATOR]
    path = tmp_path / "synth.json"
    path.write_text(json.dumps(evaluator_samples(3)), encoding="utf-8")
    rows = MODULE.load_presidio_evaluator(path, corpus)
    assert [row["id"] for row in rows] == ["synth_dataset_v2:0", "synth_dataset_v2:1", "synth_dataset_v2:2"]
    assert rows[1]["group_id"] == "template:1" and rows[1]["language"] == "en" and rows[1]["corpus"] == EVALUATOR
    # ZIP_CODE has no benchmark id; PERSON stays as a semantic id (not L1 scope in the scoreboard).
    assert rows[0]["entities"] == [
        {"entity_type": "entity.person_name", "start": 3, "end": 6},
        {"entity_type": "pii.email", "start": 17, "end": 17 + len("user0@mail0.de")},
    ]
    broken = evaluator_samples(1)
    broken[0]["spans"][0]["start_position"] += 1
    path.write_text(json.dumps(broken), encoding="utf-8")
    with pytest.raises(ValueError, match="entity_value"):
        MODULE.load_presidio_evaluator(path, corpus)


def test_presidio_favored_sources_are_pinned():
    manifest = MODULE.load_manifest()
    evaluator, tests = manifest[EVALUATOR], manifest[RECOGNIZER_TESTS]
    assert evaluator["license"] == tests["license"] == "MIT"
    assert [source.url for source in MODULE.source_files(evaluator)] == [
        "https://raw.githubusercontent.com/microsoft/presidio-research/"
        "7f568b6da8a5a403ce199d656f6baefc3e87acbb/data/synth_dataset_v2.json"
    ]
    assert tests["release"] == "2.2.364" and tests["revision"] == "779dbd286d5ef4d1fbe2514275fb1bce358f2417"
    urls = [source.url for source in MODULE.source_files(tests)]
    assert len(urls) >= 70
    assert "https://raw.githubusercontent.com/microsoft/presidio/779dbd286d5ef4d1fbe2514275fb1bce358f2417/" \
        "presidio-analyzer/tests/test_credit_card_recognizer.py" in urls
    assert all(len(source.sha256) == 64 for source in MODULE.source_files(tests))
    assert MODULE.FAMILIES["presidio_favored"].corpora == (EVALUATOR, RECOGNIZER_TESTS)
    assert MODULE.FAMILIES["neutral"].corpora == MODULE.CORPORA


@pytest.fixture
def favored_sources(tmp_path):
    payloads = {(EVALUATOR, "data/synth_dataset_v2.json"): json.dumps(evaluator_samples()).encode()}
    payloads.update({(RECOGNIZER_TESTS, name): text.encode() for name, text in RECOGNIZER_FILES.items()})
    manifest = json.loads(MODULE.MANIFEST_PATH.read_text(encoding="utf-8"))
    for corpus in manifest["corpora"]:
        if corpus["id"] == EVALUATOR:
            corpus["verified_sha256"] = sha256(payloads[(EVALUATOR, "data/synth_dataset_v2.json")])
        elif corpus["id"] == RECOGNIZER_TESTS:
            corpus["verified_files"] = recognizer_corpus()["verified_files"]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    source_dir = tmp_path / "sources"
    for (corpus, path), payload in payloads.items():
        target = source_dir / corpus / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return {"manifest": manifest_path, "dir": source_dir, "payloads": payloads, "tmp": tmp_path}


def test_prepare_presidio_favored_family(favored_sources):
    tmp = favored_sources["tmp"]
    assert prepare(favored_sources, family="presidio_favored") == 0
    dev, holdout = read_split(tmp / "dev"), read_split(tmp / "holdout")
    assert set(dev) == set(holdout) == {EVALUATOR, RECOGNIZER_TESTS}
    for corpus in (EVALUATOR, RECOGNIZER_TESTS):
        assert not {row["group_id"] for row in dev[corpus]} & {row["group_id"] for row in holdout[corpus]}
        for row in holdout[corpus]:
            assert MODULE.split_of(corpus, row["group_id"]) == "holdout"
    assert len(dev[EVALUATOR]) + len(holdout[EVALUATOR]) == 30
    assert dev[EVALUATOR] and holdout[EVALUATOR]
    for split in ("dev", "holdout"):
        manifest = json.loads((tmp / split / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["family"] == "presidio_favored"
        assert "presidio-evaluator template_id" in manifest["grouping"]
        assert MODULE.check_split(tmp / split) == []
    # Byte-identical rerun; the frozen family directory is a no-op.
    before = (tmp / "holdout" / "manifest.json").read_bytes()
    assert prepare(favored_sources, family="presidio_favored") == 0
    assert (tmp / "holdout" / "manifest.json").read_bytes() == before


def test_neutral_manifest_keeps_the_frozen_e04_layout(sources):
    assert prepare(sources) == 0
    manifest = json.loads((sources["tmp"] / "dev" / "manifest.json").read_text(encoding="utf-8"))
    assert "family" not in manifest
    assert manifest["grouping"] == (
        "holdout iff sha256(seed:corpus:group_id)[:8] < fraction * 2^64; "
        "group_id is Gretel expanded_type, otherwise the document id"
    )


def test_cli_presidio_favored_family_offline(favored_sources, tmp_path):
    proc = subprocess.run(
        [
            sys.executable, str(SCRIPT), "--family", "presidio_favored",
            "--dev-out", str(tmp_path / "dev" / "presidio_favored"),
            "--holdout-out", str(tmp_path / "holdout" / "presidio_favored"),
            "--sources", str(favored_sources["dir"]), "--manifest", str(favored_sources["manifest"]), "--offline",
        ],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert f"dev {RECOGNIZER_TESTS}:" in proc.stdout
    assert (tmp_path / "holdout" / "presidio_favored" / ".ready").exists()


@pytest.mark.skipif(not os.environ.get("ARK_L1_CORPUS_SOURCES"), reason="needs the pinned presidio_favored sources")
def test_pinned_presidio_favored_sources_load():
    # ARK_L1_CORPUS_SOURCES points at a --sources directory of prepare_corpora.py --family presidio_favored.
    manifest = MODULE.load_manifest()
    root = Path(os.environ["ARK_L1_CORPUS_SOURCES"])
    evaluator = MODULE.load_presidio_evaluator(root / EVALUATOR / "data" / "synth_dataset_v2.json", manifest[EVALUATOR])
    assert len(evaluator) == 1500
    tests = MODULE.load_recognizer_tests(root / RECOGNIZER_TESTS, manifest[RECOGNIZER_TESTS])
    ids = {entity for row in tests for entity in row["scored_entities"]}
    assert {"pii.credit_card.pan", "pii.iban", "pii.email", "pii.phone", "pii.us.social_security_number"} <= ids
    assert sum(bool(row["entities"]) for row in tests) > 500 and sum(not row["entities"] for row in tests) > 300
