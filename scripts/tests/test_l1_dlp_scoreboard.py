from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "scoreboard.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_scoreboard", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
CORPORA = MODULE.CORPORA
TAXONOMY = MODULE.load_taxonomy(ROOT / "research" / "dlp" / "entity_map.yaml")

# Placeholder values only: the scoreboard never reads secret text, it scores offsets.
FILLER = "x" * 40


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gold(start: int, end: int, label: str, entity: str, rule_id: str) -> dict:
    return {"start": start, "end": end, "label": label, "entity": entity, "rule_id": rule_id, "encoding": []}


def carrier(row_id: str, entities: list[dict], variant: str = "positive", content: list[str] | None = None,
            language: str = "en") -> dict:
    return {
        "id": row_id, "text": FILLER, "case_type": "positive" if variant == "positive" else "hard_negative",
        "variant": variant, "entities": entities, "content_labels": content or [], "language": language,
        "family": "env.test", "format": "env", "rule_id": entities[0]["rule_id"] if entities else "dlp_openai_key",
        "split": "dev",
    }


def span(start: int, end: int, rule_id: str, group: str, entities: list[str]) -> dict:
    return {"start_char": start, "end_char": end, "rule_id": rule_id, "label": f"ark.{rule_id}", "group": group,
            "entities": entities, "groups": [group], "score": 1.0, "normalization": []}


OPENAI = ("dlp_openai_key", "API_KEY", ["llm.openai.api_key"])
ANTHROPIC = ("dlp_anthropic_key", "API_KEY", ["llm.anthropic.api_key"])
PASSWORD = ("dlp_password_assignment", "CREDENTIAL", ["credential.password_assignment"])
SQL = ("dlp_sql_statement", "dlp.content.sql", ["content.sql"])


def ark(start: int, end: int, rule: tuple[str, str, list[str]]) -> dict:
    return span(start, end, *rule)


def carrier_rows() -> list[dict]:
    return [
        carrier("openai-1", [gold(10, 30, "API_KEY", "llm.openai.api_key", "dlp_openai_key")]),
        carrier("openai-2", [gold(5, 25, "API_KEY", "llm.openai.api_key", "dlp_openai_key")]),
        carrier("anthropic-1", [gold(0, 20, "API_KEY", "llm.anthropic.api_key", "dlp_anthropic_key")]),
        carrier("password-1", [gold(8, 16, "CREDENTIAL", "credential.password_assignment", "dlp_password_assignment")],
                content=["content.sql"]),
        carrier("openai-placeholder", [], variant="placeholder"),
        carrier("openai-env-ref", [], variant="env_ref", language="de"),
    ]


def base_predictions() -> list[dict]:
    return [
        {"id": "openai-1", "evidence_spans": [ark(10, 30, OPENAI)]},           # exact, attributed
        {"id": "openai-2", "evidence_spans": [ark(5, 22, OPENAI)]},            # overlap only
        {"id": "anthropic-1", "evidence_spans": [ark(0, 20, OPENAI)]},         # exact span, wrong provider
        {"id": "password-1", "evidence_spans": []},                            # missed
        {"id": "openai-placeholder", "evidence_spans": [ark(2, 9, PASSWORD)]}, # hard-negative FP
    ]


# ── metrics ──────────────────────────────────────────────────────────────────


def test_synthetic_groups_are_scored_on_exact_and_overlapping_value_spans():
    report = MODULE.score_synthetic(carrier_rows(), base_predictions(), TAXONOMY)
    api = report["groups"]["API_KEY"]
    assert api["gold"] == 3 and api["predicted"] == 3
    assert api["exact"]["tp"] == 2 and api["exact"]["precision"] == pytest.approx(2 / 3)
    assert api["exact"]["recall"] == pytest.approx(2 / 3) and api["exact"]["f1"] == pytest.approx(2 / 3)
    assert api["overlap"]["recall"] == 1.0 and api["overlap"]["precision"] == 1.0
    credential = report["groups"]["CREDENTIAL"]
    # The only CREDENTIAL prediction sits on a hard negative: precision 0, recall 0.
    assert credential["gold"] == 1 and credential["predicted"] == 1
    assert credential["exact"]["f1"] == 0.0 and credential["overlap"]["f1"] == 0.0
    # Untyped: any value span, whatever its group.
    overall = report["overall"]
    assert overall["gold"] == 4 and overall["predicted"] == 4
    assert overall["exact"]["tp"] == 2 and overall["overlap"]["recall"] == pytest.approx(3 / 4)


def test_providers_report_recall_and_attribution_to_the_right_rule():
    report = MODULE.score_synthetic(carrier_rows(), base_predictions(), TAXONOMY)
    anthropic = report["providers"]["llm.anthropic.api_key"]
    # Found on the exact value span, but attributed to the OpenAI rule.
    assert anthropic["found"] == 1 and anthropic["attributed"] == 0 and anthropic["rule_attributed"] == 0
    assert anthropic["exact"]["recall"] == 0.0 and anthropic["attribution"] == 0.0
    openai = report["providers"]["llm.openai.api_key"]
    assert openai["gold"] == 2 and openai["predicted"] == 3
    assert openai["found"] == 1 and openai["attributed"] == 1 and openai["rule_attributed"] == 1
    assert openai["exact"]["precision"] == pytest.approx(1 / 3) and openai["overlap"]["recall"] == 1.0
    assert report["attribution"] == {"found": 2, "attributed": 1, "rule_attributed": 1, "rate": 0.5}


def test_hard_negatives_count_every_value_span_as_fp_per_variant():
    report = MODULE.score_synthetic(carrier_rows(), base_predictions(), TAXONOMY)
    negatives = report["hard_negatives"]
    assert negatives["rows"] == 2 and negatives["rows_with_fp"] == 1 and negatives["fp"] == 1
    assert negatives["by_variant"]["placeholder"] == {"rows": 1, "rows_with_fp": 1, "fp": 1}
    assert negatives["by_variant"]["env_ref"] == {"rows": 1, "rows_with_fp": 0, "fp": 0}
    assert negatives["by_language"]["de"]["fp"] == 0
    assert negatives["spans"] == [["openai-placeholder", 2, 9]]


def test_content_classes_are_scored_per_document_and_kept_out_of_span_metrics():
    extended = [
        {"id": "password-1", "evidence_spans": [ark(0, 12, SQL)]},
        {"id": "openai-1", "evidence_spans": [ark(0, 8, SQL), ark(10, 20, SQL)]},
    ]
    default = base_predictions() + [{"id": "anthropic-1", "evidence_spans": [ark(0, 5, SQL)]}]
    report = MODULE.score_synthetic(carrier_rows(), default, TAXONOMY, extended)
    assert "dlp.content.sql" not in report["groups"]
    assert report["overall"]["predicted"] == 4
    sql = report["documents"]["content.sql"]
    # One document per class: password-1 is a TP, openai-1 a FP (two spans, one document).
    assert sql["gold"] == 1 and sql["predicted"] == 2 and sql["tp"] == 1
    assert sql["precision"] == 0.5 and sql["recall"] == 1.0 and sql["f1"] == pytest.approx(2 / 3)
    # Without an extended run, document classes are not scored at all.
    assert MODULE.score_synthetic(carrier_rows(), default, TAXONOMY)["documents"] == {}


def test_baseline_predictions_use_their_mapped_groups_and_entities():
    rows = carrier_rows()[:1]
    preds = [{"id": "openai-1", "evidence_spans": [
        {"start_char": 10, "end_char": 30, "rule_id": "openai-api-key", "label": "gitleaks.openai-api-key",
         "entities": ["llm.openai.api_key"], "groups": ["API_KEY"], "normalization": []},
        {"start_char": 0, "end_char": 4, "rule_id": "generic-api-key", "label": "gitleaks.generic-api-key",
         "entities": [], "groups": [], "normalization": []},
    ]}]
    report = MODULE.score_synthetic(rows, preds, TAXONOMY)
    assert report["groups"]["API_KEY"]["exact"]["f1"] == 1.0
    assert report["providers"]["llm.openai.api_key"]["attributed"] == 1
    # An unmapped baseline rule still counts as a predicted value span (untyped precision).
    assert report["overall"]["predicted"] == 2 and report["groups"]["(unmapped)"]["predicted"] == 1


def test_baseline_entities_without_an_ark_rule_are_scored_for_every_tool():
    # GOLD-D2: gold of an entity only baselines detect has rule_id None; a lookalike row is
    # a hard negative of its own variant.
    telegram = gold(4, 50, "SECRET_TOKEN", "comm.telegram.bot_token", None)
    rows = [dict(carrier("telegram-1", [telegram]), rule_id=None),
            dict(carrier("telegram-lookalike", [], variant="lookalike"), rule_id=None)]
    gitleaks = [{"id": "telegram-1", "evidence_spans": [
        {"start_char": 4, "end_char": 50, "rule_id": "telegram-bot-api-token", "label": "gitleaks.telegram-bot-api-token",
         "entities": ["comm.telegram.bot_token"], "groups": ["SECRET_TOKEN"], "normalization": []}]}]
    report = MODULE.score_synthetic(rows, gitleaks, TAXONOMY)
    entity = report["providers"]["comm.telegram.bot_token"]
    assert entity["gold"] == 1 and entity["exact"]["f1"] == 1.0 and entity["attributed"] == 1
    assert entity["rule_attributed"] == 0  # no ARK rule to attribute to
    ark_report = MODULE.score_synthetic(rows, [{"id": "telegram-lookalike", "evidence_spans": [ark(0, 9, PASSWORD)]}],
                                        TAXONOMY)
    assert ark_report["providers"]["comm.telegram.bot_token"]["exact"]["recall"] == 0.0
    assert ark_report["hard_negatives"]["by_variant"]["lookalike"] == {"rows": 1, "rows_with_fp": 1, "fp": 1}


def test_predictions_for_unknown_rows_are_rejected():
    with pytest.raises(ValueError, match="unknown"):
        MODULE.score_synthetic(carrier_rows(), [{"id": "nope", "evidence_spans": []}], TAXONOMY)


def test_opt_in_identifier_spans_come_from_the_extended_run_only():
    rows = [carrier("order-1", [gold(3, 12, "dlp.record.order_id", "identifier.record.order", "dlp_record_order_id")])]
    order = ("dlp_record_order_id", "dlp.record.order_id", ["identifier.record.order"])
    extended = [{"id": "order-1", "evidence_spans": [ark(3, 12, order), ark(20, 30, OPENAI)]}]
    report = MODULE.score_synthetic(rows, [{"id": "order-1", "evidence_spans": []}], TAXONOMY, extended)
    assert report["groups"]["dlp.record.order_id"]["exact"]["f1"] == 1.0
    # Secret spans of the extended run do not leak into the default-profile metrics.
    assert "API_KEY" not in report["groups"] and report["overall"]["predicted"] == 1


def scored(start: int, end: int, rule: tuple[str, str, list[str]], score: float) -> dict:
    return {**ark(start, end, rule), "score": score}


def test_curves_score_the_spans_that_reach_each_threshold():
    # K04: recall-mode predictions with model scores; every threshold keeps the spans scoring at least it.
    predictions = [
        {"id": "openai-1", "evidence_spans": [scored(10, 30, OPENAI, 0.7)]},
        {"id": "openai-2", "evidence_spans": [scored(5, 25, OPENAI, 0.4)]},
        {"id": "anthropic-1", "evidence_spans": [scored(0, 20, ANTHROPIC, 1.0)]},
        {"id": "password-1", "evidence_spans": [scored(8, 16, PASSWORD, 0.6)]},
        {"id": "openai-placeholder", "evidence_spans": [scored(2, 9, PASSWORD, 0.3)]},
    ]
    curves = MODULE.score_curves(carrier_rows(), predictions, TAXONOMY)
    assert curves["mode"] == "recall"
    points = {point["threshold"]: point for point in curves["points"]}
    assert tuple(points) == MODULE.CURVE_THRESHOLDS
    assert MODULE.CURVE_THRESHOLDS[:3] == (0.3, 0.4, 0.5)
    # 0.3: everything, incl. the hard-negative FP; precision 4/5, recall 4/4.
    low = points[0.3]["overall"]["exact"]
    assert (points[0.3]["hard_negative_fp"], low["precision"], low["recall"]) == (1, 0.8, 1.0)
    # 0.5 (balanced): the FP and the 0.4 span are gone.
    mid = points[0.5]["overall"]["exact"]
    assert (points[0.5]["hard_negative_fp"], mid["precision"], mid["recall"]) == (0, 1.0, 0.75)
    assert points[0.5]["groups"]["API_KEY"]["exact"]["recall"] == pytest.approx(2 / 3)
    # 1.0: only the span scoring 1.0.
    assert points[1.0]["overall"]["exact"]["recall"] == 0.25 and points[1.0]["overall"]["predicted"] == 1
    # Recall falls monotonically with the threshold.
    recalls = [point["overall"]["exact"]["recall"] for point in curves["points"]]
    assert recalls == sorted(recalls, reverse=True)
    # Spans without a score (a build without the scored mode) count as 1.0.
    flat = MODULE.score_curves(carrier_rows(), base_predictions(), TAXONOMY)
    assert len({json.dumps(point["overall"]) for point in flat["points"]}) == 1


def test_curves_are_reported_only_with_recall_predictions_and_never_gated(splits):
    dev, _ = splits
    split = MODULE.load_split(dev)
    without = MODULE.score_split(split, [], TAXONOMY)
    assert without["curves"] is None
    recall = [{"id": row["id"], "evidence_spans": []} for row in split.carriers]
    report = MODULE.score_split(split, [], TAXONOMY, recall_predictions=recall)
    assert [point["threshold"] for point in report["curves"]["points"]] == list(MODULE.CURVE_THRESHOLDS)
    # Curves add no checks: a head that loses all curve points still passes.
    base = dict(report)
    head = dict(report, curves={"mode": "recall", "points": []})
    assert all(check["ok"] for check in MODULE.compare(base, head))
    assert not any("curve" in check["check"] for check in MODULE.compare(base, head))


def test_recall_profile_scans_carriers_in_the_scored_mode_with_its_own_cache_key(splits):
    dev, _ = splits
    split = MODULE.load_split(dev)
    build = MODULE.Build(commit="c" * 40, key="k" * 64, package=Path("/nonexistent"), entity_map=ROOT / "x")
    shas = {path: sha256(path.read_bytes()) for paths in split.files.values() for path in paths}
    jobs = MODULE.plan_jobs(build, split, TAXONOMY, Path("/cache"), shas)
    recall = [job for job in jobs if job.profile == "recall"]
    assert recall and {job.component for job in recall} == {"synthetic"}
    assert {job.mode for job in recall} == {"recall"} and not recall[0].rules
    assert {job.mode for job in jobs if job.profile != "recall"} == {"strict"}
    default = next(job for job in jobs if job.profile == "default" and job.source == recall[0].source)
    assert default.key != recall[0].key
    # Strict keys are unchanged by the scored profile: cached strict predictions stay valid.
    expected = sha256(json.dumps([MODULE.PREDICTION_VERSION, build.key, MODULE._predictor_sha(), [],
                                  shas[default.source]]).encode())
    assert default.key == expected


def test_predict_file_passes_the_dlp_mode_only_when_scored(monkeypatch, tmp_path):
    calls = []

    class Done:
        returncode = 0

    monkeypatch.setattr(MODULE.subprocess, "run", lambda cmd, **_: calls.append(cmd) or Done())
    build = MODULE.Build(commit="c" * 40, key="k", package=tmp_path, entity_map=tmp_path / "map.yaml")
    MODULE.predict_file(build, tmp_path / "in.jsonl", [], tmp_path / "out.jsonl")
    MODULE.predict_file(build, tmp_path / "in.jsonl", [], tmp_path / "out.jsonl", mode="recall")
    assert "--dlp-mode" not in calls[0]
    assert calls[1][calls[1].index("--dlp-mode") + 1] == "recall"


def test_taxonomy_lists_opt_in_rules_from_the_entity_map():
    # Default on: secret families only (docs/reference/l1-rule-catalog.md); everything else is opt-in.
    assert {"dlp_sql_statement", "dlp_record_order_id", "dlp_de_vat_id"} <= set(TAXONOMY.opt_in_rules)
    assert "dlp_openai_key" not in TAXONOMY.opt_in_rules and "dlp_password_hash" not in TAXONOMY.opt_in_rules
    assert TAXONOMY.is_content("dlp.content.sql") and not TAXONOMY.is_content("dlp.record.order_id")
    assert TAXONOMY.is_opt_in("dlp.record.order_id") and not TAXONOMY.is_opt_in("API_KEY")
    assert not TAXONOMY.is_opt_in(MODULE.UNMAPPED)
    assert "content.sql" in TAXONOMY.content_classes and "content.sql" in TAXONOMY.opt_in_classes
    assert "identifier.record.order" not in TAXONOMY.content_classes


# ── comparison ───────────────────────────────────────────────────────────────


def split_report(code_fp: int = 3, docs_fp: int = 1, docs_flagged: int = 0, f1: float = 0.9,
                 overlap_f1: float = 0.95, hn: list | None = None, doc_f1: float = 0.8,
                 opt_in_classes: tuple[str, ...] = ("content.sql",)) -> dict:
    prf = lambda value: {"tp": 0, "precision": value, "recall": value, "f1": value}  # noqa: E731
    return {
        "schema": MODULE.REPORT_SCHEMA,
        "opt_in_classes": list(opt_in_classes),
        "synthetic": {
            "overall": {"gold": 10, "predicted": 10, "exact": prf(f1), "overlap": prf(overlap_f1)},
            "groups": {
                "API_KEY": {"gold": 10, "predicted": 10, "exact": prf(f1), "overlap": prf(overlap_f1)},
                "dlp.record.order_id": {"gold": 0, "predicted": 2, "exact": prf(0.0), "overlap": prf(0.0)},
            },
            "documents": {"content.sql": {"gold": 4, "predicted": 4, **prf(doc_f1)}},
            "hard_negatives": {"rows": 5, "rows_with_fp": len(hn or []), "fp": len(hn or []), "spans": hn or []},
        },
        "benign_code": {"bytes": 2_000_000, "fp": code_fp, "fp_per_mb": code_fp / 2},
        "benign_docs": {
            "default": {"bytes": 1_000_000, "fp": docs_fp, "fp_per_mb": float(docs_fp)},
            "extended": {"by_class": {"content.sql": {"documents_flagged": docs_flagged}}},
        },
    }


def failed(checks: list[dict]) -> list[str]:
    return [check["check"] for check in checks if not check["ok"]]


def test_identical_reports_pass_every_check():
    checks = MODULE.compare(split_report(), split_report())
    assert checks and failed(checks) == []
    names = {check["check"] for check in checks}
    assert {"f1.exact:API_KEY", "f1.overlap:API_KEY", "f1.exact:overall", "f1.document:content.sql",
            "fp:benign_code", "fp:benign_docs", "hard_negatives:new_fp"} <= names
    # Groups without gold spans are reported, not gated.
    assert "f1.exact:dlp.record.order_id" not in names


def test_f1_loss_above_half_a_point_is_a_regression():
    assert failed(MODULE.compare(split_report(f1=0.9), split_report(f1=0.896))) == []
    assert failed(MODULE.compare(split_report(f1=0.9), split_report(f1=0.894))) == [
        "f1.exact:overall", "f1.exact:API_KEY"]
    assert failed(MODULE.compare(split_report(overlap_f1=0.95), split_report(overlap_f1=0.9))) == [
        "f1.overlap:overall", "f1.overlap:API_KEY"]
    assert failed(MODULE.compare(split_report(doc_f1=0.8), split_report(doc_f1=0.79))) == ["f1.document:content.sql"]
    # Gains never fail.
    assert failed(MODULE.compare(split_report(f1=0.5, doc_f1=0.1), split_report(f1=0.99, doc_f1=1.0))) == []


def test_more_fp_on_benign_corpora_is_a_regression():
    assert failed(MODULE.compare(split_report(code_fp=3), split_report(code_fp=4))) == ["fp:benign_code"]
    assert failed(MODULE.compare(split_report(code_fp=3), split_report(code_fp=2))) == []
    assert failed(MODULE.compare(split_report(docs_fp=1), split_report(docs_fp=2))) == ["fp:benign_docs"]
    assert failed(MODULE.compare(split_report(docs_flagged=0), split_report(docs_flagged=1))) == [
        "flagged:benign_docs:content.sql"]


def test_new_opt_in_classes_are_not_gated_on_benign_documents_until_the_base_has_them():
    base = split_report(opt_in_classes=())
    head = split_report(docs_flagged=2)
    assert "flagged:benign_docs:content.sql" not in {check["check"] for check in MODULE.compare(base, head)}


def test_a_moved_hard_negative_fp_is_new_even_if_the_count_is_equal():
    base = split_report(hn=[["neg-1", 0, 10]])
    assert failed(MODULE.compare(base, split_report(hn=[["neg-1", 5, 12]]))) == []      # same FP, wider span
    assert failed(MODULE.compare(base, split_report(hn=[["neg-2", 0, 10]]))) == ["hard_negatives:new_fp"]
    assert failed(MODULE.compare(split_report(hn=[["neg-1", 0, 10], ["neg-2", 0, 4]]), base)) == []


# ── corpora and gate ─────────────────────────────────────────────────────────


def write_split(directory: Path, split: str, carriers: list[dict], code: list[dict], docs: list[dict]) -> Path:
    """A frozen split directory in the layout of prepare_corpora.py (only what check() verifies)."""
    def jsonl(rows):
        return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()

    def freeze(path: Path, manifest: dict) -> None:
        data = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
        (path / "manifest.json").write_bytes(data)
        (path / ".ready").write_text(f"{sha256(data)}  manifest.json\n")

    for name in CORPORA.COMPONENTS:
        (directory / name).mkdir(parents=True)
    data = jsonl(code)
    (directory / "benign_code" / "alpha.jsonl").write_bytes(data)
    freeze(directory / "benign_code", {"schema": CORPORA.BENIGN_CODE.SCHEMA, "repos": [
        {"id": "alpha", "file": "alpha.jsonl", "sha256": sha256(data)}]})
    data = jsonl(docs)
    (directory / "benign_docs" / "wiki.jsonl").write_bytes(data)
    freeze(directory / "benign_docs", {"schema": CORPORA.BENIGN_DOCS.SCHEMA, "sources": [
        {"id": "wiki", "file": "wiki.jsonl", "sha256": sha256(data)}]})
    data = jsonl(carriers)
    (directory / "synthetic" / "carriers.jsonl").write_bytes(data)
    freeze(directory / "synthetic", {"schema": CORPORA.SYNTHETIC_SCHEMA, "sha256": sha256(data)})
    manifest = CORPORA.top_manifest(directory, split)
    (directory / "manifest.json").write_bytes(manifest)
    (directory / ".ready").write_bytes(CORPORA._ready(manifest))
    assert CORPORA.check(directory) == []
    return directory


def code_docs() -> list[dict]:
    return [{"id": "alpha:src/a.py", "repo": "alpha", "path": "src/a.py", "kind": "code", "text": "print(1)\n" * 50}]


def text_docs() -> list[dict]:
    return [{"id": f"wiki:{lang}", "source": "wiki", "lang": lang, "genre": "prose", "text": "Text. " * 60}
            for lang in ("de", "en")]


@pytest.fixture
def splits(tmp_path):
    dev = write_split(tmp_path / "dev", "dev", carrier_rows(), code_docs(), text_docs())
    holdout_rows = [dict(row, id="h-" + row["id"]) for row in carrier_rows()]
    holdout = write_split(tmp_path / "holdout", "holdout", holdout_rows, code_docs(), text_docs())
    return dev, holdout


def test_load_split_rejects_a_modified_frozen_split(splits):
    dev, _ = splits
    assert len(MODULE.load_split(dev).carriers) == len(carrier_rows())
    with (dev / "synthetic" / "carriers.jsonl").open("a") as handle:
        handle.write("\n")
    with pytest.raises(ValueError, match="does not match"):
        MODULE.load_split(dev)


def make_repo(path: Path) -> list[str]:
    """Commits: base, head with a detector change, and a docs-only commit on top."""
    env = {"GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(path), "PATH": os.environ["PATH"]}

    def git(*args):
        return subprocess.run(["git", *args], cwd=path, env=env, check=True, capture_output=True, text=True).stdout.strip()

    path.mkdir()
    git("init", "--quiet", "-b", "main")
    commits = []
    for name, content in (("rust/src/lib.rs", "// base\n"), ("rust/src/lib.rs", "// head\n"),
                          ("research/dlp/backlog.yaml", "status: done\n")):
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(content)
        if not (path / "research/dlp/entity_map.yaml").exists():
            (path / "research/dlp").mkdir(parents=True, exist_ok=True)
            (path / "research/dlp/entity_map.yaml").write_text("schema: test\n")
        git("add", "-A")
        git("commit", "--quiet", "-m", f"change {name}")
        commits.append(git("rev-parse", "HEAD"))
    return commits


def test_build_key_follows_detector_sources_only(tmp_path):
    repo = tmp_path / "repo"
    base, head, docs_only = make_repo(repo)
    assert MODULE.resolve_commit(repo, "HEAD") == docs_only
    keys = [MODULE.build_key(repo, commit) for commit in (base, head, docs_only)]
    assert keys[0] != keys[1] and keys[1] == keys[2]


def test_extracted_trees_get_fresh_mtimes(tmp_path):
    repo = tmp_path / "repo"
    base, _, _ = make_repo(repo)
    before = time.time() - 1
    target = tmp_path / "src"
    MODULE.extract_tree(repo, base, target)
    source = target / "rust" / "src" / "lib.rs"
    # cargo compares mtimes: an old commit time would reuse artifacts of a newer build.
    assert source.read_text() == "// base\n" and source.stat().st_mtime >= before
    (target / "stale.txt").write_text("left over")
    MODULE.extract_tree(repo, base, target)
    assert not (target / "stale.txt").exists()


class FakeEngine:
    """Stands in for ensure_build/predict_file: the head adds one FP per benign code document."""

    def __init__(self, repo: Path, head: str, regress: str | None = None):
        self.repo, self.head, self.regress, self.calls, self.modes = repo, head, regress, [], []

    def ensure_build(self, tree: Path, commit: str, cache: Path) -> MODULE.Build:
        key = MODULE.build_key(tree, commit)
        return MODULE.Build(commit=commit, key=key, package=cache / key, entity_map=ROOT / "research/dlp/entity_map.yaml")

    def predict_file(self, build: MODULE.Build, source: Path, rules: list[str], output: Path,
                     mode: str = "strict") -> None:
        self.calls.append((build.commit, source.name, tuple(rules)))
        self.modes.append((build.commit, source.name, mode))
        head = build.commit == self.head
        rows = []
        for line in source.read_text().splitlines():
            row = json.loads(line)
            spans = []
            if "entities" in row and not rules:
                spans = [{"start_char": e["start"], "end_char": e["end"], "rule_id": e["rule_id"],
                          "group": e["label"], "entities": [e["entity"]], "groups": [e["label"]]}
                         for e in row["entities"]]
                if head and self.regress == "recall":
                    spans = spans[1:]
            if head and self.regress == "fp" and row.get("kind") == "code" and not rules:
                spans.append({"start_char": 0, "end_char": 5, "rule_id": "dlp_generic", "group": "SECRET_TOKEN"})
            rows.append({"id": row["id"], "evidence_spans": spans})
        output.write_text("".join(json.dumps(row) + "\n" for row in rows))


class FakeLatency:
    """Stands in for latency_check: fixed 100 KiB p95 of base and head, records its calls."""

    def __init__(self, base_ms: float = 5.0, head_ms: float = 5.0):
        self.base_ms, self.head_ms, self.calls = base_ms, head_ms, []

    def __call__(self, builds: dict, dev: Path, cache: Path) -> dict:
        self.calls.append(dev)
        side = {name: {"100k": {"p95_ms": ms}, "repo": {"mib_per_s": 6.0}}
                for name, ms in (("base", self.base_ms), ("head", self.head_ms))}
        return {"schema": MODULE.LATENCY.SCHEMA, "attempts": 1, **side,
                "checks": MODULE.LATENCY.latency_checks(side["base"], side["head"])}


def run_gate(monkeypatch, capsys, tmp_path, splits, regress: str | None = None, holdout_only: bool = False,
             latency: FakeLatency | None = None):
    repo = tmp_path / "repo"
    base, head, _ = make_repo(repo)
    engine = FakeEngine(repo, head, regress)
    monkeypatch.setattr(MODULE, "ensure_build", engine.ensure_build)
    monkeypatch.setattr(MODULE, "predict_file", engine.predict_file)
    engine.latency = latency or FakeLatency()
    monkeypatch.setattr(MODULE, "latency_check", engine.latency)
    dev, holdout = splits
    subprocess.run(["git", "checkout", "--quiet", head], cwd=repo, check=True)
    if holdout_only:  # the regression only shows on the holdout
        dev = write_split(tmp_path / "dev-clean", "dev", carrier_rows(), [], text_docs())
    code = MODULE.main(["gate", "--head", str(repo), "--base-sha", base, "--dev", str(dev),
                        "--holdout", str(holdout), "--cache", str(tmp_path / "cache")])
    run_gate.base = base
    return code, capsys.readouterr().out, engine


def test_gate_passes_without_regression_and_reports_dev_only(monkeypatch, capsys, tmp_path, splits):
    code, out, engine = run_gate(monkeypatch, capsys, tmp_path, splits)
    assert code == 0
    assert "dev" in out and "holdout: no regression" in out and out.rstrip().endswith("PASS")
    # The holdout appears only as a verdict, never with numbers or row ids.
    holdout_lines = [line for line in out.splitlines() if "holdout" in line]
    assert holdout_lines and all(not any(ch.isdigit() for ch in line.replace("holdout", "")) for line in holdout_lines)
    assert "h-openai" not in out
    reports = list((tmp_path / "cache" / "scoreboard" / "reports").rglob("*.json"))
    assert {path.name for path in reports} == {"dev.json", "holdout.json", "latency.json"}
    # Latency is timed once, on the dev workloads only, and reported for dev.
    assert engine.latency.calls == [splits[0]]
    assert "dev latency: 100 KiB p95 5.00 → 5.00 ms" in out
    # Default and extended profile per build and file; extended only on carriers and benign docs.
    profiles = {(name, bool(rules)) for _, name, rules in engine.calls}
    assert ("alpha.jsonl", True) not in profiles and ("carriers.jsonl", True) in profiles
    # The recall profile (P/R curves) scans the carriers only, for head and base.
    recall = {(commit, name) for commit, name, mode in engine.modes if mode == "recall"}
    assert {name for _, name in recall} == {"carriers.jsonl"} and len(recall) == 2
    assert "P/R curve (recall mode, exact spans)" in out
    dev_report = json.loads(next((tmp_path / "cache" / "scoreboard" / "reports").rglob("dev.json")).read_text())
    assert [point["threshold"] for point in dev_report["head"]["curves"]["points"]] == list(MODULE.CURVE_THRESHOLDS)
    assert not any("curve" in check["check"] for check in dev_report["checks"])


def test_gate_fails_on_a_dev_fp_regression_and_names_it(monkeypatch, capsys, tmp_path, splits):
    code, out, _ = run_gate(monkeypatch, capsys, tmp_path, splits, regress="fp")
    assert code == 1
    assert "fp:benign_code" in out and out.rstrip().endswith("FAIL")


def test_gate_fails_on_a_holdout_only_regression_without_details(monkeypatch, capsys, tmp_path, splits):
    code, out, _ = run_gate(monkeypatch, capsys, tmp_path, splits, regress="fp", holdout_only=True)
    assert code == 1
    assert "holdout: regression" in out and "fp:benign_code" not in out
    report = json.loads(next((tmp_path / "cache" / "scoreboard" / "reports").rglob("holdout.json")).read_text())
    assert [check["check"] for check in report["checks"] if not check["ok"]] == ["fp:benign_code"]


def test_gate_fails_on_a_recall_regression(monkeypatch, capsys, tmp_path, splits):
    code, out, _ = run_gate(monkeypatch, capsys, tmp_path, splits, regress="recall")
    assert code == 1 and "f1.exact:API_KEY" in out


def test_gate_fails_on_a_slower_head_and_names_the_latency_check(monkeypatch, capsys, tmp_path, splits):
    code, out, _ = run_gate(monkeypatch, capsys, tmp_path, splits, latency=FakeLatency(5.0, 6.0))
    assert code == 1
    assert "dev: REGRESSION latency:100k_p95_ms: 5.0 → 6.0" in out and "holdout: no regression" in out
    report = json.loads(next((tmp_path / "cache" / "scoreboard" / "reports").rglob("dev.json")).read_text())
    assert [check["check"] for check in report["checks"] if not check["ok"]] == ["latency:100k_p95_ms"]
    holdout = json.loads(next((tmp_path / "cache" / "scoreboard" / "reports").rglob("holdout.json")).read_text())
    assert not any(check["check"].startswith("latency:") for check in holdout["checks"])


def test_gate_fails_when_the_head_leaves_the_latency_budget(monkeypatch, capsys, tmp_path, splits):
    code, out, _ = run_gate(monkeypatch, capsys, tmp_path, splits, latency=FakeLatency(9.5, 10.3))
    assert code == 1 and "latency:budget_100k_p95_ms" in out and "latency:100k_p95_ms" not in out


def test_gate_reuses_cached_predictions(monkeypatch, capsys, tmp_path, splits):
    code, _, engine = run_gate(monkeypatch, capsys, tmp_path, splits)
    assert code == 0 and engine.calls
    # Same cache, same builds: the second run scans nothing.
    repo = tmp_path / "repo"
    second = FakeEngine(repo, engine.head)
    monkeypatch.setattr(MODULE, "predict_file", second.predict_file)
    monkeypatch.setattr(MODULE, "latency_check", FakeLatency())
    dev, holdout = splits
    assert MODULE.main(["gate", "--head", str(repo), "--base-sha", run_gate.base, "--dev", str(dev),
                        "--holdout", str(holdout), "--cache", str(tmp_path / "cache")]) == 0
    assert second.calls == []


def test_same_build_for_head_and_base_scans_once(monkeypatch, capsys, tmp_path, splits):
    repo = tmp_path / "repo"
    _, head, docs_only = make_repo(repo)
    engine = FakeEngine(repo, docs_only)
    monkeypatch.setattr(MODULE, "ensure_build", engine.ensure_build)
    monkeypatch.setattr(MODULE, "predict_file", engine.predict_file)
    dev, _ = splits
    assert MODULE.main(["gate", "--head", str(repo), "--base-sha", head, "--dev", str(dev),
                        "--cache", str(tmp_path / "cache")]) == 0
    # carriers in all three profiles, benign docs in default and extended, benign code in default only
    assert len(engine.calls) == 6
    # one build: the real latency check measures nothing
    assert "dev latency: not measured (head and base share one build)" in capsys.readouterr().out


def test_prune_keeps_recent_and_current_builds_and_fresh_predictions(tmp_path):
    cache = tmp_path / "cache"
    now = time.time()
    for index in range(MODULE.KEEP_BUILDS + 3):
        ready = cache / "builds" / f"key{index:02d}" / ".ready"
        ready.parent.mkdir(parents=True)
        ready.write_text("x")
        os.utime(ready, (now - index * 60, now - index * 60))
    (cache / "predictions").mkdir()
    fresh, stale = cache / "predictions" / "fresh.jsonl", cache / "predictions" / "stale.jsonl"
    fresh.write_text("")
    stale.write_text("")
    old = now - (MODULE.KEEP_PREDICTIONS_DAYS + 1) * 86400
    os.utime(stale, (old, old))
    oldest = f"key{MODULE.KEEP_BUILDS + 2:02d}"
    MODULE.prune(cache, keep={oldest}, now=now)
    left = sorted(path.name for path in (cache / "builds").iterdir())
    assert left == [f"key{index:02d}" for index in range(MODULE.KEEP_BUILDS)] + [oldest]
    assert fresh.exists() and not stale.exists()


def test_gate_without_base_sha_or_with_a_broken_split_is_an_error(monkeypatch, capsys, tmp_path, splits):
    repo = tmp_path / "repo"
    make_repo(repo)
    dev, _ = splits
    cache = str(tmp_path / "cache")
    assert MODULE.main(["gate", "--head", str(repo), "--base-sha", "", "--dev", str(dev), "--cache", cache]) == 2
    (dev / ".ready").unlink()
    assert MODULE.main(["gate", "--head", str(repo), "--base-sha", "HEAD", "--dev", str(dev), "--cache", cache]) == 2


def test_score_command_scores_any_tool_on_one_split(tmp_path, splits, capsys):
    dev, _ = splits
    predictions = tmp_path / "gitleaks.jsonl"
    predictions.write_text("".join(json.dumps(row) + "\n" for row in base_predictions()))
    output = tmp_path / "report.json"
    assert MODULE.main(["score", "--split", str(dev), "--predictions", str(predictions), "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["synthetic"]["groups"]["API_KEY"]["gold"] == 3
    assert report["benign_code"]["fp"] == 0 and report["benign_docs"]["default"]["fp"] == 0


def test_compare_command_exits_one_on_regression(tmp_path, capsys):
    base, head = tmp_path / "base.json", tmp_path / "head.json"
    base.write_text(json.dumps(split_report()))
    head.write_text(json.dumps(split_report(code_fp=9)))
    assert MODULE.main(["compare", "--base", str(base), "--head", str(base)]) == 0
    assert MODULE.main(["compare", "--base", str(base), "--head", str(head)]) == 1
    assert "fp:benign_code" in capsys.readouterr().out


def test_loads_without_native_module_or_yaml_free_imports():
    # The gate runs the scoreboard with the baseline venv: standard library, PyYAML and git only.
    code = ("import importlib.util, sys; spec = importlib.util.spec_from_file_location('s', sys.argv[1]); "
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
            "assert 'patronus_ark' not in sys.modules")
    subprocess.run([sys.executable, "-c", code, str(SCRIPT)], check=True)


# ── external content goldens (dev only) ──────────────────────────────────────

EXTERNAL = MODULE.EXTERNAL


def external_rows() -> list[dict]:
    """gitleaks-like Go/Markdown documents and one SchemaPile-like SQL file with two statements."""
    def row(row_id, corpus, kind, labels, judged, span_judged=(), scope_end=200, entities=()):
        return {"id": row_id, "corpus": corpus, "path": row_id.split(":")[-1], "kind": kind, "text": "y" * 200,
                "document_labels": labels, "judged": judged, "span_judged": list(span_judged),
                "scope": [0, scope_end], "entities": [
                    {"start": s, "end": e, "entity": "content.sql", "label": "dlp.content.sql"} for s, e in entities]}

    go = ["content.source_code", "content.sql"]
    return [
        row(f"{EXTERNAL.GITLEAKS}:main.go", EXTERNAL.GITLEAKS, "go", ["content.source_code"], go),
        row(f"{EXTERNAL.GITLEAKS}:README.md", EXTERNAL.GITLEAKS, "markdown", [], ["content.source_code"]),
        row(f"{EXTERNAL.SCHEMAPILE}:a.sql", EXTERNAL.SCHEMAPILE, "sql", ["content.sql"], ["content.sql"],
            ["content.sql"], 120, [(0, 50), (51, 120)]),
    ]


def write_external(directory: Path, rows: list[dict] | None = None) -> Path:
    rows = external_rows() if rows is None else rows
    files = {}
    corpora = []
    for corpus_id, name in EXTERNAL.FILES.items():
        data = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows if row["corpus"] == corpus_id).encode()
        files[name] = data
        corpora.append({"id": corpus_id, "file": name, "sha256": sha256(data)})
    manifest = json.dumps({"schema": EXTERNAL.SCHEMA, "split": "dev", "corpora": corpora}).encode()
    files["manifest.json"] = manifest
    files[".ready"] = f"{sha256(manifest)}  manifest.json\n".encode()
    MODULE.BENIGN_CODE._write(directory / "external", files)
    assert EXTERNAL.check(directory / "external") == []
    return directory


def sql_predictions(spans: list[tuple[int, int]], go_source: bool = True) -> list[dict]:
    return [
        {"id": f"{EXTERNAL.GITLEAKS}:main.go",
         "evidence_spans": [ark(0, 9, ("dlp_source_code_declaration", "dlp.content.source_code",
                                       ["content.source_code"]))] if go_source else []},
        {"id": f"{EXTERNAL.SCHEMAPILE}:a.sql", "evidence_spans": [ark(s, e, SQL) for s, e in spans]},
    ]


def test_external_component_is_loaded_on_dev_and_refused_on_the_holdout(splits):
    dev, holdout = splits
    assert MODULE.load_split(dev).external is None
    split = MODULE.load_split(write_external(dev))
    assert len(split.external) == 3 and all("text" not in row for row in split.external)
    assert [path.name for path in split.files["external"]] == ["gitleaks-go.jsonl", "schemapile-sql.jsonl"]
    # The top-level manifest of an already frozen dev split stays valid.
    assert CORPORA.check(dev) == []
    with pytest.raises(ValueError, match="dev only"):
        MODULE.load_split(write_external(holdout))


def test_external_goldens_are_scored_from_the_extended_run(splits):
    dev, _ = splits
    split = MODULE.load_split(write_external(dev))
    # Second statement missed, one span after the scope end: ignored.
    report = MODULE.score_split(split, base_predictions(), TAXONOMY, sql_predictions([(0, 50), (130, 150)]))
    external = report["external"]
    assert external["spans"]["content.sql"]["exact"]["recall"] == 0.5
    assert external["spans"]["content.sql"]["exact"]["precision"] == 1.0
    assert external["spans"]["content.sql"]["out_of_scope"] == 1
    assert external["documents"]["content.source_code"]["f1"] == 1.0
    assert external["documents"]["content.sql"]["f1"] == 1.0
    # Without an extended run there is nothing to score; a split without the component reports None.
    assert MODULE.score_split(split, base_predictions(), TAXONOMY)["external"] is None


def test_external_f1_losses_are_regressions():
    def report(spans, go_source=True):
        rows = [dict(row, bytes=200) for row in external_rows()]
        return dict(split_report(), external=EXTERNAL.score(rows, sql_predictions(spans, go_source)))

    base = report([(0, 50), (51, 120)])
    checks = MODULE.compare(base, base)
    names = {check["check"] for check in checks}
    assert {"f1.external.document:content.source_code", "f1.external.document:content.sql",
            "f1.external.exact:content.sql", "f1.external.overlap:content.sql"} <= names
    assert failed(checks) == []
    assert failed(MODULE.compare(base, report([(0, 50), (52, 120)]))) == ["f1.external.exact:content.sql"]
    assert failed(MODULE.compare(base, report([(0, 50), (51, 120)], go_source=False))) == [
        "f1.external.document:content.source_code"]
    # Reports without the component (older base, or no external/ on the split) add no checks.
    assert not any(check["check"].startswith("f1.external") for check in MODULE.compare(split_report(), split_report()))


class ExternalEngine(FakeEngine):
    """FakeEngine that also predicts the external Gold in the extended profile; the head can miss a statement."""

    def predict_file(self, build, source, rules, output, mode="strict"):
        if not source.name.startswith(("gitleaks", "schemapile")):
            return super().predict_file(build, source, rules, output, mode)
        self.calls.append((build.commit, source.name, tuple(rules)))
        drop = build.commit == self.head and self.regress == "external"
        rows = []
        for line in source.read_text().splitlines():
            row = json.loads(line)
            entities = row["entities"][1:] if drop else row["entities"]
            rows.append({"id": row["id"], "evidence_spans": [
                {"start_char": e["start"], "end_char": e["end"], "rule_id": "dlp_sql_statement",
                 "group": "dlp.content.sql", "entities": ["content.sql"]} for e in entities]})
        output.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_gate_scores_external_goldens_on_dev_in_the_extended_profile(monkeypatch, capsys, tmp_path, splits):
    dev, holdout = splits
    write_external(dev)
    repo = tmp_path / "repo"
    base, head, _ = make_repo(repo)
    for regress, expected in ((None, 0), ("external", 1)):
        engine = ExternalEngine(repo, head, regress)
        monkeypatch.setattr(MODULE, "ensure_build", engine.ensure_build)
        monkeypatch.setattr(MODULE, "predict_file", engine.predict_file)
        monkeypatch.setattr(MODULE, "latency_check", FakeLatency())
        subprocess.run(["git", "checkout", "--quiet", head], cwd=repo, check=True)
        code = MODULE.main(["gate", "--head", str(repo), "--base-sha", base, "--dev", str(dev),
                            "--holdout", str(holdout), "--cache", str(tmp_path / f"cache-{regress}")])
        out = capsys.readouterr().out
        assert code == expected
        external_calls = {(name, bool(rules)) for _, name, rules in engine.calls if name.endswith("sql.jsonl")}
        assert external_calls == {("schemapile-sql.jsonl", True)}
        assert "external span content.sql" in out
        if regress:
            assert "dev: REGRESSION f1.external.exact:content.sql" in out and "holdout: no regression" in out
