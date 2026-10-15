from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "scoreboard.py"
SPEC = importlib.util.spec_from_file_location("scoreboard", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules.setdefault("scoreboard", MODULE)
SPEC.loader.exec_module(MODULE)

EMAP = MODULE.entity_map_module.load()
GRETEL = "gretel-synthetic-pii-finance"
SYNTH = "ark-synthetic-de-eu"


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def gold(row_id, entities, corpus=SYNTH, language="de", hard_negatives=None):
    row = {
        "id": row_id,
        "corpus": corpus,
        "language": language,
        "text": "x" * 200,
        "entities": [{"entity_type": label, "start": start, "end": end} for label, start, end in entities],
    }
    if hard_negatives is not None:
        row["hard_negatives"] = [{"start": start, "end": end, "kind": "case_number"} for start, end in hard_negatives]
    return row


def pred(row_id, spans):
    return {
        "id": row_id,
        "language": "de",
        "evidence_spans": [{"label": label, "start_char": start, "end_char": end, "score": 1.0} for label, start, end in spans],
    }


# ── scoring ──────────────────────────────────────────────────────────────


def test_exact_and_overlap_counts():
    rows = [gold("a", [("pii.email", 0, 10), ("pii.phone", 20, 30), ("pii.iban", 40, 60)])]
    preds = [pred("a", [("pii.email", 0, 10), ("pii.phone", 18, 30), ("pii.iban", 70, 80)])]
    result = MODULE.score_rows(rows, preds, EMAP, "t")
    counts = result["buckets"]["all"]
    assert counts == {"gold": 3, "predicted": 3, "exact": 1, "gold_found": 2, "predicted_correct": 2}
    metrics = MODULE.metrics(counts)
    assert metrics["exact"]["f1"] == pytest.approx(1 / 3)
    assert metrics["overlap"]["f1"] == pytest.approx(2 / 3)
    assert result["buckets"]["entity/pii.phone"]["gold_found"] == 1
    assert result["buckets"]["entity/pii.phone"]["exact"] == 0
    assert result["buckets"]["language/de"] == counts


def test_overlap_needs_the_same_label():
    rows = [gold("a", [("pii.email", 0, 10)])]
    preds = [pred("a", [("pii.phone", 0, 10)])]
    counts = MODULE.score_rows(rows, preds, EMAP)["buckets"]["all"]
    assert counts["gold_found"] == 0 and counts["predicted_correct"] == 0


def test_semantic_entities_are_not_l1_scope():
    rows = [gold("a", [("entity.person_name", 0, 10), ("pii.email", 20, 30)])]
    preds = [pred("a", [("pii.email", 20, 30)])]
    result = MODULE.score_rows(rows, preds, EMAP)
    assert result["buckets"]["all"]["gold"] == 1
    assert not any("person_name" in key for key in result["buckets"])


def test_corpus_ontology_from_entity_map():
    # Gretel does not annotate German tax ids: a prediction there is neither TP nor FP.
    rows = [gold("a", [("pii.email", 0, 10)], corpus=GRETEL, language="en")]
    preds = [pred("a", [("pii.email", 0, 10), ("pii.de.tax_id", 20, 31)])]
    result = MODULE.score_rows(rows, preds, EMAP)
    assert result["buckets"]["all"]["predicted"] == 1
    # A corpus without map entry (the synthetic set) is scored on every L1 id.
    rows = [gold("a", [("pii.email", 0, 10)])]
    result = MODULE.score_rows(rows, preds, EMAP)
    assert result["buckets"]["all"]["predicted"] == 2
    assert result["buckets"]["entity/pii.de.tax_id"]["predicted"] == 1


def test_language_buckets_de_en_other():
    rows = [
        gold("a", [("pii.email", 0, 10)], language="de"),
        gold("b", [("pii.email", 0, 10)], language="en"),
        gold("c", [("pii.email", 0, 10)], language="fr"),
    ]
    preds = [pred("a", [("pii.email", 0, 10)]), pred("b", []), pred("c", [])]
    buckets = MODULE.score_rows(rows, preds, EMAP)["buckets"]
    assert buckets["language/de"]["exact"] == 1
    assert buckets["language/en"]["exact"] == 0
    assert buckets["language/other"]["gold"] == 1
    assert buckets["language_entity/de/pii.email"]["exact"] == 1


def test_resolve_label_reads_ark_and_presidio_fields():
    assert MODULE.resolve_label({"label": "pii.email"}, EMAP) == "pii.email"
    assert MODULE.resolve_label({"label": "ark.STEUERID", "ark_label": "EMAIL"}, EMAP) == "pii.email"
    assert MODULE.resolve_label({"label": "presidio.X", "presidio_entity": "EMAIL_ADDRESS"}, EMAP) == "pii.email"
    assert MODULE.resolve_label({"label": "ark.UNKNOWN", "ark_label": "UNKNOWN"}, EMAP) is None


def test_hard_negative_predictions_are_recorded():
    rows = [gold("a", [("pii.email", 0, 10)], hard_negatives=[(50, 60)])]
    preds = [pred("a", [("pii.email", 0, 10), ("pii.phone", 55, 70), ("pii.iban", 80, 90)])]
    result = MODULE.score_rows(rows, preds, EMAP, "synthetic/x.jsonl")
    assert result["hard_negative_fp"] == [["synthetic/x.jsonl", "a", "pii.phone", 55, 70]]


def test_predictions_must_match_gold_ids():
    rows = [gold("a", [])]
    with pytest.raises(MODULE.ScoreboardError):
        MODULE.score_rows(rows, [], EMAP)
    with pytest.raises(MODULE.ScoreboardError):
        MODULE.score_rows(rows, [pred("a", []), pred("b", [])], EMAP)


def test_compare_flags_f1_losses_above_tolerance():
    rows = [gold(f"r{i}", [("pii.email", 0, 10)]) for i in range(1000)]
    base = MODULE.score_rows(rows, [pred(f"r{i}", [("pii.email", 0, 10)]) for i in range(1000)], EMAP)
    # 4 of 1000 lost: recall 99.6 %, F1 -0.2 pp → within tolerance.
    small = MODULE.score_rows(rows, [pred(f"r{i}", [("pii.email", 0, 10)] if i >= 4 else []) for i in range(1000)], EMAP)
    assert MODULE.compare(base, small)["regressions"] == []
    # 20 of 1000 lost: F1 -1.0 pp → regression for the entity, all L1 and DE, exact and overlap.
    large = MODULE.score_rows(rows, [pred(f"r{i}", [("pii.email", 0, 10)] if i >= 20 else []) for i in range(1000)], EMAP)
    regressions = MODULE.compare(base, large)["regressions"]
    assert {(item["bucket"], item["metric"]) for item in regressions} == {
        (bucket, metric)
        for bucket in ("all", "language/de", "entity/pii.email")
        for metric in ("exact", "overlap")
    }
    assert all(item["delta_pp"] < -0.5 for item in regressions)
    # Improvements never count.
    assert MODULE.compare(large, base)["regressions"] == []


def test_compare_flags_boundary_regressions_in_exact_only():
    rows = [gold(f"r{i}", [("pii.phone", 10, 20)]) for i in range(10)]
    base = MODULE.score_rows(rows, [pred(f"r{i}", [("pii.phone", 10, 20)]) for i in range(10)], EMAP)
    head = MODULE.score_rows(rows, [pred(f"r{i}", [("pii.phone", 9, 20)]) for i in range(10)], EMAP)
    regressions = MODULE.compare(base, head)["regressions"]
    assert {item["metric"] for item in regressions} == {"exact"}


def test_compare_flags_only_new_hard_negative_fp():
    rows = [gold("a", [], hard_negatives=[(0, 10), (20, 30)])]
    base = MODULE.score_rows(rows, [pred("a", [("pii.phone", 0, 10)])], EMAP)
    same = MODULE.score_rows(rows, [pred("a", [("pii.phone", 0, 10)])], EMAP)
    assert MODULE.compare(base, same)["new_hard_negative_fp"] == []
    fewer = MODULE.score_rows(rows, [pred("a", [])], EMAP)
    assert MODULE.compare(base, fewer)["new_hard_negative_fp"] == []
    more = MODULE.score_rows(rows, [pred("a", [("pii.phone", 0, 10), ("pii.iban", 20, 30)])], EMAP)
    assert MODULE.compare(base, more)["new_hard_negative_fp"] == [["", "a", "pii.iban", 20, 30]]


def test_merge_sums_buckets():
    one = MODULE.score_rows([gold("a", [("pii.email", 0, 10)])], [pred("a", [("pii.email", 0, 10)])], EMAP, "x")
    two = MODULE.score_rows([gold("a", [("pii.email", 0, 10)])], [pred("a", [])], EMAP, "y")
    merged = MODULE.merge([one, two])
    assert merged["rows"] == 2
    assert merged["buckets"]["all"]["gold"] == 2 and merged["buckets"]["all"]["exact"] == 1


# ── data discovery ───────────────────────────────────────────────────────


def test_discover_reads_frozen_directories_only(tmp_path):
    write_jsonl(tmp_path / "a.jsonl", [gold("a", [])])
    (tmp_path / ".ready").write_text("x")
    write_jsonl(tmp_path / "synthetic" / "s.jsonl", [gold("s", [])])
    (tmp_path / "synthetic" / ".ready").write_text("x")
    write_jsonl(tmp_path / "unfrozen" / "u.jsonl", [gold("u", [])])
    write_jsonl(tmp_path / ".sources" / "raw.jsonl", [gold("r", [])])
    (tmp_path / ".sources" / ".ready").write_text("x")
    datasets = MODULE.discover("dev", tmp_path)
    assert [d.name for d in datasets] == ["a.jsonl", "synthetic/s.jsonl"]
    assert all(len(d.sha256) == 64 and d.split == "dev" for d in datasets)


def test_discover_without_frozen_data_fails(tmp_path):
    write_jsonl(tmp_path / "a.jsonl", [gold("a", [])])
    with pytest.raises(MODULE.ScoreboardError):
        MODULE.discover("dev", tmp_path)


# ── git sources ──────────────────────────────────────────────────────────


FAKE_RUN_ARK = """\
import argparse, json
# Fake run_ark.py: predicts every gold entity except those whose id is in DROP.
DROP = {drop!r}
p = argparse.ArgumentParser()
p.add_argument("--input"); p.add_argument("--output"); p.add_argument("--meta")
a = p.parse_args()
with open(a.input) as src, open(a.output, "w") as out:
    for line in src:
        row = json.loads(line)
        spans = [] if row["id"] in DROP else [
            {{"label": e["entity_type"], "start_char": e["start"], "end_char": e["end"], "score": 1.0}}
            for e in row["entities"]
        ]
        out.write(json.dumps({{"id": row["id"], "language": row["language"], "evidence_spans": spans}}) + "\\n")
open(a.meta, "w").write("{{}}")
"""


def run_git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(repo)}
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True, env=env).stdout.strip()


def commit_files(repo, files, message):
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", message)
    return run_git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "-q", "-b", "main")
    commit_files(repo, {
        "Cargo.toml": "[workspace]\n",
        "rust/src/lib.rs": "// v1\n",
        "python/patronus_ark/__init__.py": "",
        "scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop=[]),
        "README.md": "v1\n",
    }, "base")
    return repo


def test_source_key_tracks_build_inputs_only(repo):
    base = MODULE.source_key(repo, "HEAD")
    commit_files(repo, {"README.md": "v2\n", "research/x.md": "x\n"}, "docs")
    assert MODULE.source_key(repo, "HEAD") == base
    commit_files(repo, {"rust/src/lib.rs": "// v2\n"}, "rust")
    assert MODULE.source_key(repo, "HEAD") != base
    assert MODULE.source_key(repo, "HEAD~2") == base


def test_is_clean_checks_build_inputs(repo):
    assert MODULE.is_clean(repo)
    (repo / "README.md").write_text("dirty\n")
    assert MODULE.is_clean(repo)
    (repo / "rust" / "src" / "new.rs").write_text("// untracked\n")
    assert not MODULE.is_clean(repo)


def test_commit_sha_rejects_unknown_revisions(repo):
    assert MODULE.commit_sha(repo, "HEAD") == run_git(repo, "rev-parse", "HEAD")
    for rev in ("", "0" * 40):
        with pytest.raises(MODULE.ScoreboardError):
            MODULE.commit_sha(repo, rev)


# ── gate ─────────────────────────────────────────────────────────────────


def frozen_split(root, rows_by_file):
    for name, rows in rows_by_file.items():
        write_jsonl(root / name, rows)
        (root / name).parent.joinpath(".ready").write_text("x")
    return root


@pytest.fixture
def data(tmp_path):
    dev = frozen_split(tmp_path / "dev", {
        "synthetic/s.jsonl": [gold(f"d{i}", [("pii.email", 0, 10)], hard_negatives=[(50, 60)]) for i in range(10)],
    })
    holdout = frozen_split(tmp_path / "holdout", {
        "c.jsonl": [gold(f"h{i}", [("pii.iban", 0, 22)], corpus=GRETEL, language="en") for i in range(10)],
    })
    return {"dev": dev, "holdout": holdout}


class Builds:
    """Fake build factories that run the committed fake run_ark.py and count builds."""

    def __init__(self, repo, tmp_path):
        self.repo, self.tmp_path = repo, tmp_path
        self.head_builds = 0
        self.base_builds = []

    def head(self):
        self.head_builds += 1
        return MODULE.ArkBuild(sys.executable, self.repo / "scripts" / "l1_presidio" / "run_ark.py", {}, None)

    def base(self, sha, key):
        self.base_builds.append(sha)
        script = self.tmp_path / f"run_ark_{sha}.py"
        script.write_text(run_git(self.repo, "show", f"{sha}:scripts/l1_presidio/run_ark.py") + "\n")
        return MODULE.ArkBuild(sys.executable, script, {}, None)

    def gate(self, base_rev, data, cache):
        return MODULE.gate(self.repo, base_rev, data, cache, emap=EMAP,
                           head_factory=self.head, base_factory=self.base)


def test_gate_same_sources_reuses_head_predictions(repo, data, tmp_path):
    base = run_git(repo, "rev-parse", "HEAD")
    commit_files(repo, {"README.md": "docs only\n"}, "docs")
    builds = Builds(repo, tmp_path)
    lines, regressed, report = builds.gate(base, data, tmp_path / "cache")
    assert not regressed
    assert builds.head_builds == 1 and builds.base_builds == []
    assert lines[-1] == "RESULT: PASS"
    assert "(same Ark sources)" in lines[0]
    assert set(report["splits"]) == {"dev", "holdout"}
    # Results are stored per commit, predictions per source key.
    results = tmp_path / "cache" / "scoreboard" / "results"
    assert {p.stem for p in results.iterdir()} == {base, run_git(repo, "rev-parse", "HEAD")}
    # A second gate is served from the cache.
    builds = Builds(repo, tmp_path)
    builds.gate(base, data, tmp_path / "cache")
    assert builds.head_builds == 0 and builds.base_builds == []


def test_gate_detects_regression_on_holdout(repo, data, tmp_path):
    base = run_git(repo, "rev-parse", "HEAD")
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop=["h0", "h1"])}, "worse")
    builds = Builds(repo, tmp_path)
    lines, regressed, report = builds.gate(base, data, tmp_path / "cache")
    assert regressed
    assert builds.base_builds == [base]
    assert lines[-1] == "RESULT: REGRESSION"
    assert any(line.startswith("  holdout entity/pii.iban exact F1 100.0 -> ") for line in lines)
    assert report["splits"]["dev"]["compare"]["regressions"] == []
    # Holdout row ids never reach stdout.
    assert not any("h0" in line or "h1" in line for line in lines)
    # Per-entity tables are printed for dev only.
    assert not any("pii.iban" in line for line in lines if not line.startswith("  holdout"))


def test_gate_detects_new_hard_negative_fp(repo, data, tmp_path):
    base = run_git(repo, "rev-parse", "HEAD")
    noisy = FAKE_RUN_ARK.format(drop=[]).replace(
        "for e in row[\"entities\"]\n        ]",
        "for e in row[\"entities\"]\n        ] + [{\"label\": \"pii.phone\", \"start_char\": 50, \"end_char\": 60}]",
    )
    assert noisy != FAKE_RUN_ARK.format(drop=[])
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": noisy}, "noisy")
    lines, regressed, report = Builds(repo, tmp_path).gate(base, data, tmp_path / "cache")
    assert regressed
    assert len(report["splits"]["dev"]["compare"]["new_hard_negative_fp"]) == 10
    assert "  dev new hard-negative FP: pii.phone 10" in lines


def test_gate_improvement_passes_and_base_is_cached_per_source(repo, data, tmp_path):
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop=["d0", "h0"])}, "weak")
    weak = run_git(repo, "rev-parse", "HEAD")
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop=[])}, "better")
    builds = Builds(repo, tmp_path)
    lines, regressed, _ = builds.gate(weak, data, tmp_path / "cache")
    assert not regressed and builds.base_builds == [weak]
    # A commit that only touches the backlog on top of weak (the runner's done commit) hits the cache.
    run_git(repo, "checkout", "-q", "-b", "done", weak)
    commit_files(repo, {"research/backlog.yaml": "done\n"}, "done")
    done = run_git(repo, "rev-parse", "HEAD")
    run_git(repo, "checkout", "-q", "main")
    builds = Builds(repo, tmp_path)
    builds.gate(done, data, tmp_path / "cache")
    assert builds.base_builds == [] and builds.head_builds == 0


def test_gate_dirty_head_is_not_cached(repo, data, tmp_path):
    base = run_git(repo, "rev-parse", "HEAD")
    (repo / "rust" / "src" / "lib.rs").write_text("// uncommitted\n")
    builds = Builds(repo, tmp_path)
    lines, regressed, report = builds.gate(base, data, tmp_path / "cache")
    assert not regressed and report["head_source_key"] is None
    assert "(uncommitted changes)" in lines[0]
    assert builds.base_builds == [base]
    # Only the committed base lands in the prediction cache.
    assert [p.name for p in (tmp_path / "cache" / "scoreboard" / "predictions").iterdir()] == [report["base_source_key"]]


def test_main_reports_infrastructure_errors_with_exit_2(repo, data, tmp_path, capsys):
    code = MODULE.main(["gate", "--head", str(repo), "--base-sha", "0" * 40, "--dev", str(data["dev"]),
                        "--cache", str(tmp_path / "cache")])
    assert code == 2
    assert "scoreboard error" in capsys.readouterr().err


def test_head_build_requires_the_head_package(repo):
    with pytest.raises(MODULE.ScoreboardError):
        MODULE.head_build(repo, sys.executable)


def test_main_score_subcommand(tmp_path, capsys):
    write_jsonl(tmp_path / "g.jsonl", [gold("a", [("pii.email", 0, 10)])])
    write_jsonl(tmp_path / "p.jsonl", [{"id": "a", "evidence_spans": [
        {"label": "pii.email", "presidio_entity": "EMAIL_ADDRESS", "start_char": 0, "end_char": 10, "score": 0.9}]}])
    assert MODULE.main(["score", "--gold", str(tmp_path / "g.jsonl"), "--predictions", str(tmp_path / "p.jsonl"),
                        "--json", str(tmp_path / "out.json")]) == 0
    out = capsys.readouterr().out
    assert "L1 exact P/R/F1 100.0/100.0/100.0" in out
    assert json.loads((tmp_path / "out.json").read_text())["buckets"]["all"]["exact"] == 1


# ── offline base build ───────────────────────────────────────────────────


FAKE_CARGO = """\
#!{python}
import os, sys, pathlib
log = pathlib.Path(os.environ["FAKE_CARGO_LOG"])
log.write_text(log.read_text() + " ".join(sys.argv[1:]) + "\\n" if log.exists() else " ".join(sys.argv[1:]) + "\\n")
out = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / "debug"
out.mkdir(parents=True, exist_ok=True)
(out / "lib_patronus_ark.so").write_bytes(b"native " + os.environ["PYO3_PYTHON"].encode())
"""


def test_build_base_stages_package_and_is_reused(repo, tmp_path, monkeypatch):
    commit_files(repo, {"python/Cargo.toml": "[package]\n", "python/patronus_ark/benchmark_data/big.jsonl": "{}\n"},
                 "python crate")
    sha = run_git(repo, "rev-parse", "HEAD")
    cargo = tmp_path / "cargo"
    cargo.write_text(FAKE_CARGO.format(python=sys.executable))
    cargo.chmod(cargo.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "cargo.log"
    monkeypatch.setenv("FAKE_CARGO_LOG", str(log))
    cache = tmp_path / "cache"
    key = MODULE.source_key(repo, sha)
    build = MODULE.build_base(repo, sha, key, cache, "/venv/bin/python", str(cargo))
    stage = cache / "builds" / key
    assert build.env == {"PYTHONPATH": str(stage)}
    assert build.native == stage / "patronus_ark" / "_patronus_ark.abi3.so"
    assert build.native.read_bytes() == b"native /venv/bin/python"
    assert (stage / "patronus_ark" / "__init__.py").exists()
    assert not (stage / "patronus_ark" / "benchmark_data").exists()
    assert build.run_ark.read_text() == FAKE_RUN_ARK.format(drop=[])
    assert "--offline --locked --lib --manifest-path" in log.read_text()
    assert not (cache / "src" / key).exists()
    MODULE.build_base(repo, sha, key, cache, "/venv/bin/python", str(cargo))
    assert len(log.read_text().splitlines()) == 1


def test_build_base_failure_is_an_infrastructure_error(repo, tmp_path):
    sha = run_git(repo, "rev-parse", "HEAD")
    cargo = tmp_path / "cargo"
    cargo.write_text(textwrap.dedent("""\
        #!/bin/sh
        echo "error: no matching package" >&2
        exit 101
    """))
    cargo.chmod(cargo.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(MODULE.ScoreboardError, match="no matching package"):
        MODULE.build_base(repo, sha, "k", tmp_path / "cache", sys.executable, str(cargo))
    assert not (tmp_path / "cache" / "builds" / "k" / ".ready").exists()
