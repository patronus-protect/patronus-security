from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "external_content.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_external_content", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

SQL_A = "-- schema\nCREATE TABLE a (v text);\nALTER TABLE a ADD w int;\n"
SQL_B = "/*!40101 SET NAMES utf8 */;\nCREATE TABLE b (s text default 'x;y');\nDROP TABLE c;\ntrailing"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def sources(tmp_path):
    """A gitleaks-like checkout, a SchemaPile-like archive and an adapter manifest pinning both."""
    repo = tmp_path / "cache" / "gitleaks"
    repo.mkdir(parents=True)
    (repo / "LICENSE").write_text("MIT fixture\n")
    (repo / "main.go").write_text("package main\n\nfunc main() {}\n")
    (repo / "cmd").mkdir()
    (repo / "cmd" / "root.go").write_text("package cmd\n")
    (repo / "README.md").write_text("Documentation only.\n")
    env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), *env, "commit", "-qm", "fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    (repo / ".git" / "ark-complete").write_text(revision)

    archive = tmp_path / "cache" / MODULE.ARCHIVE
    members = tmp_path / "members"
    members.mkdir()
    with tarfile.open(archive, "w:gz") as handle:
        for name, text in (("000001_a.sql", SQL_A), ("000002_b.sql", SQL_B)):
            (members / name).write_text(text)
            handle.add(members / name, arcname=f"sqlfiles_permissive/{name}")
    data = archive.read_bytes()
    manifest = {"schema": "ark-external-dlp-manifest-v1", "corpora": [
        {"id": MODULE.GITLEAKS, "admission_status": "admitted", "adapter": "git_tree_content_v1",
         "source": "https://example.invalid/gitleaks", "revision": revision, "license": "MIT",
         "license_file_sha256": sha256((repo / "LICENSE").read_bytes()),
         "positive": {"entity_type": "dlp.content.source_code", "extensions": [".go"], "expected_documents": 2},
         "negative": {"extensions": [".md"], "expected_minimum_documents": 1}},
        {"id": MODULE.SCHEMAPILE, "admission_status": "admitted", "adapter": "tar_sql_statement_v1",
         "source": "https://example.invalid/schemapile.tar.gz", "license": "permissive subset",
         "verified_sha256": sha256(data), "published_md5": hashlib.md5(data).hexdigest(),  # noqa: S324
         # Four statements: all of a.sql, the first two of b.sql.
         "positive": {"entity_type": "dlp.content.sql", "target_cap": 4}},
    ]}
    path = tmp_path / "external_dlp_manifest.json"
    path.write_text(json.dumps(manifest))
    return tmp_path / "cache", path


def rows_by_path(directory: Path) -> dict[str, dict]:
    return {row["path"]: row for row in MODULE.load(directory, keep_text=True)}


# ── build and freeze ─────────────────────────────────────────────────────────


def test_gitleaks_rows_carry_document_labels_and_judged_classes(tmp_path, sources):
    cache, manifest = sources
    assert MODULE.prepare(tmp_path / "out", cache, offline=True, manifest_path=manifest, pins={}) == 0
    rows = rows_by_path(tmp_path / "out")
    go, md = rows["main.go"], rows["README.md"]
    assert go["id"] == f"{MODULE.GITLEAKS}:main.go" and go["kind"] == "go"
    assert go["document_labels"] == ["content.source_code"]
    # Go files are SQL negatives; Markdown files are judged for source code only.
    assert go["judged"] == ["content.source_code", "content.sql"] and md["judged"] == ["content.source_code"]
    assert md["document_labels"] == [] and go["span_judged"] == [] and go["entities"] == []
    assert go["scope"] == [0, len(go["text"])]


def test_schemapile_rows_hold_exact_statements_and_end_their_scope_at_the_cap(tmp_path, sources):
    cache, manifest = sources
    assert MODULE.prepare(tmp_path / "out", cache, offline=True, manifest_path=manifest, pins={}) == 0
    rows = rows_by_path(tmp_path / "out")
    a, b = rows["sqlfiles_permissive/000001_a.sql"], rows["sqlfiles_permissive/000002_b.sql"]
    assert a["document_labels"] == ["content.sql"] and a["judged"] == a["span_judged"] == ["content.sql"]

    def spans(row):
        return [row["text"][e["start"]:e["end"]] for e in row["entities"]]

    # Leading comments belong to the statement; MySQL conditional comments are statements.
    assert spans(a) == ["-- schema\nCREATE TABLE a (v text);", "ALTER TABLE a ADD w int;"]
    assert spans(b) == ["/*!40101 SET NAMES utf8 */;", "CREATE TABLE b (s text default 'x;y');"]
    assert all(e["entity"] == "content.sql" and e["label"] == "dlp.content.sql" for e in a["entities"])
    # a.sql is fully selected; the cap stops in b.sql, so its scope ends after the last selected statement.
    assert a["scope"] == [0, len(a["text"])]
    assert b["scope"] == [0, b["entities"][-1]["end"]] and b["scope"][1] < b["text"].index("DROP")


def test_prepare_writes_a_pinned_manifest_and_reruns_byte_identically(tmp_path, sources, capsys):
    cache, manifest = sources
    out = tmp_path / "out"
    assert MODULE.prepare(out, cache, offline=True, manifest_path=manifest, pins={}) == 0
    meta = json.loads((out / "manifest.json").read_text())
    assert meta["schema"] == MODULE.SCHEMA and meta["split"] == "dev" and meta["contract"] == MODULE.CONTRACT
    corpora = {corpus["id"]: corpus for corpus in meta["corpora"]}
    assert corpora[MODULE.GITLEAKS]["documents"] == 3 and corpora[MODULE.GITLEAKS]["document_labels"] == {
        "content.source_code": 2}
    assert corpora[MODULE.SCHEMAPILE]["evidence_spans"] == 4
    assert corpora[MODULE.SCHEMAPILE]["pins"]["verified_sha256"] == json.loads(manifest.read_text())[
        "corpora"][1]["verified_sha256"]
    assert MODULE.check(out) == []
    before = {path.name: path.read_bytes() for path in out.iterdir()}
    assert MODULE.prepare(out, cache, offline=True, manifest_path=manifest, pins={}) == 0
    assert "unchanged (frozen)" in capsys.readouterr().out
    assert {path.name: path.read_bytes() for path in out.iterdir()} == before


def test_output_that_misses_its_pin_is_not_written(tmp_path, sources, capsys):
    cache, manifest = sources
    assert MODULE.prepare(tmp_path / "out", cache, offline=True, manifest_path=manifest,
                          pins={MODULE.GITLEAKS: "0" * 64}) == 1
    assert "pinned SHA-256" in capsys.readouterr().err and not (tmp_path / "out").exists()


def test_the_checked_in_pins_are_set():
    assert set(MODULE.PINNED_SHA256) == {MODULE.GITLEAKS, MODULE.SCHEMAPILE}
    assert all(len(value) == 64 for value in MODULE.PINNED_SHA256.values())


def test_a_modified_frozen_component_is_not_overwritten_without_force(tmp_path, sources, capsys):
    cache, manifest = sources
    out = tmp_path / "out"
    assert MODULE.prepare(out, cache, offline=True, manifest_path=manifest, pins={}) == 0
    with (out / MODULE.FILES[MODULE.SCHEMAPILE]).open("a") as handle:
        handle.write("\n")
    assert any("does not match" in problem for problem in MODULE.check(out))
    with pytest.raises(ValueError, match="does not match"):
        MODULE.load(out)
    assert MODULE.prepare(out, cache, offline=True, manifest_path=manifest, pins={}) == 1
    assert "--force" in capsys.readouterr().err
    assert MODULE.prepare(out, cache, offline=True, force=True, manifest_path=manifest, pins={}) == 0
    assert MODULE.check(out) == []


def test_offline_without_cached_sources_fails_without_network(tmp_path, sources, capsys):
    _, manifest = sources
    assert MODULE.prepare(tmp_path / "out", tmp_path / "empty", offline=True, manifest_path=manifest, pins={}) == 1
    assert "not cached (--offline)" in capsys.readouterr().err


def test_a_tampered_archive_is_rejected(tmp_path, sources, capsys):
    cache, manifest = sources
    with (cache / MODULE.ARCHIVE).open("ab") as handle:
        handle.write(b"\0")
    assert MODULE.prepare(tmp_path / "out", cache, offline=True, manifest_path=manifest, pins={}) == 1
    assert "not cached" in capsys.readouterr().err


def test_sources_inside_the_output_are_rejected(tmp_path, sources, capsys):
    _, manifest = sources
    out = tmp_path / "out"
    assert MODULE.prepare(out, out / "cache", offline=True, manifest_path=manifest, pins={}) == 1
    assert "--sources" in capsys.readouterr().err


def test_load_drops_text_unless_asked(tmp_path, sources):
    cache, manifest = sources
    MODULE.prepare(tmp_path / "out", cache, offline=True, manifest_path=manifest, pins={})
    rows = MODULE.load(tmp_path / "out")
    assert rows and all("text" not in row and row["bytes"] > 0 for row in rows)
    assert [path.name for path in MODULE.files(tmp_path / "out")] == ["gitleaks-go.jsonl", "schemapile-sql.jsonl"]


def test_script_loads_without_the_native_module():
    code = ("import importlib.util, sys; spec = importlib.util.spec_from_file_location('m', sys.argv[1]); "
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
            "assert '_patronus_ark' not in str(sys.modules) and 'patronus_ark' not in sys.modules")
    subprocess.run([sys.executable, "-c", code, str(SCRIPT)], check=True)


# ── attach/scope contract ────────────────────────────────────────────────────


def doc(row_id, corpus, labels, judged, span_judged=(), scope=(0, 100), entities=()):
    return {"id": row_id, "corpus": corpus, "document_labels": list(labels), "judged": list(judged),
            "span_judged": list(span_judged), "scope": list(scope), "bytes": 100,
            "entities": [{"start": s, "end": e, "entity": "content.sql", "label": "dlp.content.sql"}
                         for s, e in entities]}


def ark(start, end, entity, rule="dlp_rule"):
    group = MODULE.GROUPS.get(entity, "API_KEY")
    return {"start_char": start, "end_char": end, "rule_id": rule, "group": group, "entities": [entity],
            "groups": [group]}


GO = ["content.source_code", "content.sql"]


def contract_rows():
    return [
        doc("go-1", "g", ["content.source_code"], GO),
        doc("go-2", "g", ["content.source_code"], GO),
        doc("md-1", "g", [], ["content.source_code"]),
        doc("sql-1", "s", ["content.sql"], ["content.sql"], ["content.sql"], (0, 60), [(0, 20), (21, 40), (41, 60)]),
    ]


def test_document_labels_attach_through_in_scope_evidence_spans_of_judged_classes():
    predictions = [
        {"id": "go-1", "evidence_spans": [ark(0, 10, "content.source_code"), ark(20, 30, "content.sql")]},
        # A SQL span on a Markdown file is unjudged there, not a SQL false positive.
        {"id": "md-1", "evidence_spans": [ark(0, 5, "content.sql"), ark(0, 9, "content.source_code")]},
        {"id": "sql-1", "evidence_spans": [ark(0, 20, "content.sql"), ark(0, 9, "content.source_code")]},
    ]
    report = MODULE.score(contract_rows(), predictions)
    source = report["documents"]["content.source_code"]
    assert source["documents"] == 3 and source["gold"] == 2 and source["predicted"] == 2 and source["tp"] == 1
    assert source["precision"] == 0.5 and source["recall"] == 0.5
    sql = report["documents"]["content.sql"]
    # go-1 is a SQL negative with a SQL span: one FP document; sql-1 is the TP.
    assert sql["documents"] == 3 and sql["gold"] == 1 and sql["predicted"] == 2 and sql["tp"] == 1
    assert report["documents_by_corpus"]["g"]["content.sql"]["predicted"] == 1
    assert report["documents_by_corpus"]["s"]["content.sql"]["f1"] == 1.0
    assert report["unjudged"] == {"content.source_code": 1, "content.sql": 1}


def test_secret_spans_are_not_counted_as_unjudged_when_classes_are_given():
    predictions = [{"id": "go-1", "evidence_spans": [ark(0, 10, "llm.openai.api_key")]}]
    assert MODULE.score(contract_rows(), predictions)["unjudged"] == {"llm.openai.api_key": 1}
    assert MODULE.score(contract_rows(), predictions, ["content.sql"])["unjudged"] == {}


def test_sql_evidence_spans_are_scored_exactly_inside_the_scope_only():
    predictions = [{"id": "sql-1", "evidence_spans": [
        ark(0, 20, "content.sql"),                          # exact
        ark(0, 20, "content.sql", "dlp_sql_multiline_statement"),  # same span, second rule: counted once
        ark(22, 40, "content.sql"),                         # overlap only
        ark(55, 70, "content.sql"),                         # straddles the scope end: scored
        ark(61, 80, "content.sql"),                         # after the scope: ignored
        ark(60, 60, "content.sql"),                         # empty span at the scope end: ignored
    ]}]
    spans = MODULE.score(contract_rows(), predictions)["spans"]["content.sql"]
    assert spans["gold"] == 3 and spans["predicted"] == 3 and spans["out_of_scope"] == 2
    assert spans["exact"]["tp"] == 1 and spans["exact"]["precision"] == pytest.approx(1 / 3)
    assert spans["exact"]["recall"] == pytest.approx(1 / 3)
    assert spans["overlap"]["tp"] == 3 and spans["overlap"]["precision"] == 1.0 and spans["overlap"]["recall"] == 1.0


def test_a_document_without_in_scope_evidence_is_not_predicted():
    rows = contract_rows()
    predictions = [
        {"id": "sql-1", "evidence_spans": [ark(70, 90, "content.sql")], "document_labels": ["content.sql"]},
        {"id": "go-2", "evidence_spans": [], "document_labels": ["content.source_code"]},
    ]
    report = MODULE.score(rows, predictions)
    assert report["documents"]["content.sql"]["predicted"] == 0
    assert report["documents"]["content.source_code"]["predicted"] == 0
    assert report["labels_without_evidence"] == {"content.source_code": 1, "content.sql": 1}
    assert report["spans"]["content.sql"]["out_of_scope"] == 1


def test_baseline_spans_attach_through_their_mapped_group():
    span = {"start_char": 0, "end_char": 20, "rule_id": "x", "groups": ["dlp.content.sql"], "entities": []}
    assert MODULE.span_classes(span) == {"content.sql"}
    assert MODULE.span_classes({"start_char": 0, "end_char": 1, "groups": ["API_KEY"]}) == set()


def test_predictions_for_unknown_rows_are_rejected():
    with pytest.raises(ValueError, match="unknown"):
        MODULE.score(contract_rows(), [{"id": "nope", "evidence_spans": []}])


def test_cli_scores_a_prepared_component(tmp_path, sources, capsys):
    cache, manifest = sources
    out = tmp_path / "out"
    MODULE.prepare(out, cache, offline=True, manifest_path=manifest, pins={})
    rows = MODULE.load(out, keep_text=True)
    predictions = []
    for row in rows:
        spans = [{"start_char": e["start"], "end_char": e["end"], "rule_id": "dlp_sql_statement",
                  "group": "dlp.content.sql", "entities": ["content.sql"]} for e in row["entities"]]
        predictions.append({"id": row["id"], "evidence_spans": spans})
    path = tmp_path / "pred.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in predictions))
    assert MODULE.main(["score", "--corpus", str(out), "--predictions", str(path), "--output",
                        str(tmp_path / "r.json")]) == 0
    report = json.loads((tmp_path / "r.json").read_text())
    assert report["spans"]["content.sql"]["exact"]["f1"] == 1.0
    assert report["documents"]["content.sql"]["f1"] == 1.0 and report["documents"]["content.source_code"]["f1"] == 0.0
    assert report["corpora"][MODULE.SCHEMAPILE]["documents"] == 2
