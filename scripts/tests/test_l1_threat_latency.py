from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "latency.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_latency", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def paragraph(index: int, size: int = 900) -> str:
    """A distinct German paragraph of about size characters (with umlauts)."""
    words = f"Absatz {index}: Die Gemeinde prüft den Haushalt, die Straßenplanung und Änderungen. "
    return (words * (size // len(words) + 1))[:size].strip()


def documents(count: int, per_doc: int = 40, start: int = 0) -> list[dict]:
    return [
        {"id": f"src:doc{d}", "text": "\n\n".join(paragraph(start + d * per_doc + p) for p in range(per_doc))}
        for d in range(count)
    ]


def write_corpus(directory: Path, windows: list[dict]) -> None:
    data = "".join(json.dumps(w, ensure_ascii=False, sort_keys=True) + "\n" for w in windows).encode()
    manifest = {"schema": MODULE.CORPUS_SCHEMA, "window_bytes": MODULE.WINDOW_BYTES, "windows": len(windows),
                "file": MODULE.WINDOWS_FILE, "sha256": MODULE.PII_LATENCY.sha256_bytes(data)}
    directory.mkdir(parents=True, exist_ok=True)
    (directory / MODULE.WINDOWS_FILE).write_bytes(data)
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (directory / MODULE.READY).write_text("", encoding="utf-8")


def windows_for(count: int) -> list[dict]:
    items = MODULE.unique_paragraphs(documents(count * 3))
    windows = MODULE.pack_windows(items, limit=count)
    assert len(windows) == count
    return windows


def test_paragraphs_drop_short_and_letterless_blocks():
    text = "Kurz.\n\n" + "a" * 50 + "\r\n\r\n" + "1234 " * 20 + "\n \n" + "Ein längerer Absatz über den Rhein und seine Ufer."
    assert MODULE.paragraphs(text) == ["a" * 50, "Ein längerer Absatz über den Rhein und seine Ufer."]


def test_unique_paragraphs_skip_repeats_across_documents_case_and_space_insensitive():
    first = "Die Bundesregierung beschließt den Haushalt für das kommende Jahr."
    docs = [{"id": "a", "text": first + "\n\n" + paragraph(1)},
            {"id": "b", "text": "die  bundesregierung beschließt den Haushalt\nfür das kommende Jahr.\n\n" + paragraph(2)}]
    assert MODULE.unique_paragraphs(docs) == [("a", first), ("a", paragraph(1)), ("b", paragraph(2))]


def test_pack_windows_are_exact_size_and_never_repeat_a_paragraph():
    items = MODULE.unique_paragraphs(documents(12))
    windows = MODULE.pack_windows(items)
    assert len(windows) >= 3
    seen = set()
    for window in windows:
        raw = window["text"].encode("utf-8")
        assert len(raw) == MODULE.WINDOW_BYTES == window["bytes"]
        assert window["sha256"] == MODULE.PII_LATENCY.sha256_bytes(raw)
        for part in MODULE.paragraphs(window["text"]):
            key = MODULE.paragraph_key(part)
            assert key not in seen
            seen.add(key)
    # The first window starts with the first paragraph; the cut paragraph's rest is not reused.
    assert windows[0]["text"].startswith(items[0][1])
    assert windows[0]["documents"][0] == "src:doc0"


def test_pack_windows_pads_a_cut_inside_a_multibyte_character():
    items = [("d", "ä" * 70_000)]
    [window] = MODULE.pack_windows(items, size=10_001)
    assert window["bytes"] == 10_001
    assert window["text"] == "ä" * 5_000 + " "


def test_pack_windows_stops_at_the_limit_and_drops_an_unfilled_tail():
    items = MODULE.unique_paragraphs(documents(12))
    assert len(MODULE.pack_windows(items, limit=2)) == 2
    assert MODULE.pack_windows(items[:3]) == []


def test_check_corpus_accepts_an_intact_corpus(tmp_path):
    write_corpus(tmp_path / "c", windows_for(MODULE.MIN_WINDOWS))
    assert MODULE.check_corpus(tmp_path / "c") == []


def test_check_corpus_rejects_too_few_windows_repeats_and_missing_ready(tmp_path):
    windows = windows_for(MODULE.MIN_WINDOWS)
    write_corpus(tmp_path / "few", windows[:-1])
    assert any("at least" in problem for problem in MODULE.check_corpus(tmp_path / "few"))

    repeated = [dict(w) for w in windows]
    repeated[1]["text"] = repeated[0]["text"]
    repeated[1]["sha256"] = repeated[0]["sha256"]
    write_corpus(tmp_path / "rep", repeated)
    assert any("repeated" in problem for problem in MODULE.check_corpus(tmp_path / "rep"))

    write_corpus(tmp_path / "open", windows)
    (tmp_path / "open" / MODULE.READY).unlink()
    assert any(MODULE.READY in problem for problem in MODULE.check_corpus(tmp_path / "open"))


def test_check_corpus_detects_a_modified_windows_file(tmp_path):
    write_corpus(tmp_path / "c", windows_for(MODULE.MIN_WINDOWS))
    path = tmp_path / "c" / MODULE.WINDOWS_FILE
    path.write_bytes(path.read_bytes().replace(b"Gemeinde", b"Gemeinden", 1))
    assert any("sha256" in problem for problem in MODULE.check_corpus(tmp_path / "c"))


def test_corpus_sources_are_pinned_licensed_german_dev_sources():
    sources = MODULE.corpus_sources()
    assert [s["id"] for s in sources][: len(MODULE.SOURCE_IDS)] == list(MODULE.SOURCE_IDS)
    assert len(sources) > len(MODULE.SOURCE_IDS)
    for source in sources:
        assert (source["lang"], source["split"]) == ("de", "dev")
        assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"] or "")
        assert MODULE.BENIGN_DOCS.is_open_content_license(source["license"])


def test_extra_sources_repeat_no_page_of_the_dlp_list():
    dlp = MODULE.BENIGN_DOCS.load_sources()
    pages = {(s["site"], p["title"]) for s in dlp if s["type"] == "mediawiki" for p in s["pages"]}
    revids = {p["revid"] for s in dlp if s["type"] == "mediawiki" for p in s["pages"]}
    for source in MODULE.BENIGN_DOCS.load_sources(MODULE.EXTRA_SOURCES_PATH):
        for page in source["pages"]:
            assert (source["site"], page["title"]) not in pages
            assert page["revid"] not in revids


def test_corpus_sources_reject_an_extra_list_reusing_a_dlp_source_id(tmp_path):
    extra = json.loads(MODULE.EXTRA_SOURCES_PATH.read_text(encoding="utf-8"))
    extra["sources"][0]["id"] = MODULE.SOURCE_IDS[0]
    path = tmp_path / "extra.json"
    path.write_text(json.dumps(extra), encoding="utf-8")
    with pytest.raises(MODULE.LatencyError, match="both"):
        MODULE.corpus_sources(extra_path=path)


def fake_build_source(docs_by_source: dict[str, list[dict]], pins: dict[str, str] | None = None):
    def build_source(source, cache, offline=False):
        data = "".join(json.dumps(d, ensure_ascii=False) + "\n" for d in docs_by_source[source["id"]]).encode()
        sha = (pins or {}).get(source["id"], source["sha256"])
        return data, {"id": source["id"], "license": source["license"], "genre": source["genre"], "sha256": sha,
                      "documents": len(docs_by_source[source["id"]]), "bytes": len(data)}
    return build_source


def test_prepare_writes_a_frozen_corpus_and_keeps_it(tmp_path, monkeypatch):
    ids = [s["id"] for s in MODULE.corpus_sources()]
    docs = {source_id: documents(10, start=i * 1000) for i, source_id in enumerate(ids)}
    # Every source repeats the first source's documents too: the repeats must be skipped.
    docs = {source_id: docs[source_id] + docs[ids[0]] for source_id in ids}
    monkeypatch.setattr(MODULE.BENIGN_DOCS, "build_source", fake_build_source(docs))
    monkeypatch.setattr(MODULE, "MIN_WINDOWS", 5)
    out = tmp_path / "corpus"
    assert MODULE.prepare(out, tmp_path / "cache") == 0
    manifest, windows = MODULE.load_corpus(out)
    assert manifest["windows"] == len(windows) >= 5
    assert manifest["sources"][0]["id"] == ids[0]
    assert MODULE.check_corpus(out) == []
    assert MODULE.prepare(out, tmp_path / "cache") == 0  # unchanged


def test_prepare_refuses_a_source_off_its_pin_and_too_few_windows(tmp_path, monkeypatch, capsys):
    ids = [s["id"] for s in MODULE.corpus_sources()]
    docs = {source_id: documents(1, start=i * 100) for i, source_id in enumerate(ids)}
    monkeypatch.setattr(MODULE.BENIGN_DOCS, "build_source", fake_build_source(docs, {ids[0]: "0" * 64}))
    assert MODULE.prepare(tmp_path / "a", tmp_path / "cache") == 2
    assert "differs from the pin" in capsys.readouterr().err
    monkeypatch.setattr(MODULE.BENIGN_DOCS, "build_source", fake_build_source(docs))
    assert MODULE.prepare(tmp_path / "b", tmp_path / "cache") == 2
    assert "at least" in capsys.readouterr().err
    assert not (tmp_path / "b").exists()


def test_profiles_name_categories_the_gateway_parses():
    names = set(re.findall(r'"([a-z_-]+)" (?:\|[^=]*)?=> Ok\(SecurityCategory::',
                           (ROOT / "ark-core" / "src" / "types.rs").read_text(encoding="utf-8")))
    assert {"unsafe_action", "injection"} <= names
    assert "threat" not in names
    for categories in MODULE.PROFILES.values():
        assert set(categories) <= names
    assert set(MODULE.PROFILES["threat"]) | set(MODULE.PROFILES["injection"]) <= set(MODULE.PROFILES["all"])


def test_jobs_carry_the_profile_categories_and_split_the_budget():
    windows = [{"id": "de-000", "text": "x"}, {"id": "de-001", "text": "y"}]
    jobs = MODULE.jobs(windows, "all", 5, 10.0)
    assert [job["id"] for job in jobs] == ["all:de-000", "all:de-001"]
    assert all(job["categories"] == list(MODULE.PROFILES["all"]) for job in jobs)
    assert jobs[0]["budget_ms"] == 5000.0 and jobs[0]["samples"] == 5 and jobs[0]["min_samples"] == 1


def profile_result(p95: float, profile: str = "threat") -> dict:
    return {"categories": list(MODULE.PROFILES[profile]), "init_ms": 1.0, "loadavg_1m": [0.0, 0.0], "spans": 0,
            "summary": {"samples": 250, "p50_ms": p95 / 2, "p95_ms": p95, "p99_ms": p95, "mean_ms": p95 / 2,
                        "max_ms": p95}}


def report(p95s: dict[str, float]) -> dict:
    manifest = {"sha256": "a" * 64, "windows": 50, "window_bytes": MODULE.WINDOW_BYTES}
    run = {profile: profile_result(p95, profile) for profile, p95 in p95s.items()}
    return MODULE.combine(manifest, [run], "b" * 64)


def test_combine_keeps_the_median_run_per_profile():
    manifest = {"sha256": "a" * 64, "windows": 50, "window_bytes": MODULE.WINDOW_BYTES}
    runs = [{"threat": profile_result(p95)} for p95 in (3.0, 1.0, 2.0)]
    combined = MODULE.combine(manifest, runs, "b" * 64)
    assert combined["profiles"]["threat"]["summary"]["p95_ms"] == 2.0
    assert combined["profiles"]["threat"]["runs_p95_ms"] == [3.0, 1.0, 2.0]
    assert combined["samples_per_window"] == 5 and combined["runs"] == 3


def test_compare_flags_a_profile_above_the_tolerance():
    base = report({"threat": 2.0, "injection": 1.0, "all": 8.0})
    ok = MODULE.compare(base, report({"threat": 2.09, "injection": 0.9, "all": 8.0}))
    assert not ok["regression"]
    slow = MODULE.compare(base, report({"threat": 2.0, "injection": 1.0, "all": 8.5}))
    assert slow["regression"]
    assert [row["profile"] for row in slow["rows"] if row["regression"]] == ["all"]
    assert MODULE.compare_lines(slow)[-1] == "RESULT: REGRESSION"


def test_compare_refuses_different_corpora_or_missing_profiles():
    base = report({"threat": 2.0})
    other = report({"threat": 2.0})
    other["corpus"]["sha256"] = "c" * 64
    with pytest.raises(MODULE.LatencyError, match="corpora"):
        MODULE.compare(base, other)
    with pytest.raises(MODULE.LatencyError, match="threat"):
        MODULE.compare(base, report({"injection": 2.0}))


def test_compare_cli_exit_codes(tmp_path):
    base, head = tmp_path / "base.json", tmp_path / "head.json"
    base.write_text(json.dumps(report({"threat": 2.0})), encoding="utf-8")
    head.write_text(json.dumps(report({"threat": 3.0})), encoding="utf-8")
    assert MODULE.main(["compare", "--base", str(base), "--head", str(base)]) == 0
    assert MODULE.main(["compare", "--base", str(base), "--head", str(head)]) == 1
    head.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    assert MODULE.main(["compare", "--base", str(base), "--head", str(head)]) == 2


def test_compare_limits_the_verdict_to_the_given_profile(tmp_path):
    base, head = tmp_path / "base.json", tmp_path / "head.json"
    base.write_text(json.dumps(report({"threat": 2.0, "injection": 1.0})), encoding="utf-8")
    head.write_text(json.dumps(report({"threat": 3.0, "injection": 1.0})), encoding="utf-8")
    assert MODULE.main(["compare", "--base", str(base), "--head", str(head), "--profile", "injection"]) == 0
    assert MODULE.main(["compare", "--base", str(base), "--head", str(head), "--profile", "threat"]) == 1
    assert MODULE.main(["compare", "--base", str(base), "--head", str(head), "--profile", "all"]) == 2


def test_markdown_names_corpus_and_profiles():
    text = MODULE.markdown(report({"threat": 2.0, "injection": 1.0, "all": 8.0}))
    assert "50 distinct windows of 102400 bytes" in text
    assert f"| all | injection, dlp, pii, {', '.join(MODULE.THREAT_CATEGORIES)}, shell_command |" in text
