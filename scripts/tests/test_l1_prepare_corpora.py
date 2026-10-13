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
