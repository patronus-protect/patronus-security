from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


MODULE = _load("l1_dlp_baseline_report", ROOT / "scripts" / "l1_dlp" / "baseline_report.py")
# Fixtures of the scoreboard tests: carrier rows with placeholder text, a frozen split writer.
SB_TESTS = _load("l1_dlp_scoreboard_tests", Path(__file__).resolve().parent / "test_l1_dlp_scoreboard.py")
TAXONOMY = MODULE.SCOREBOARD.load_taxonomy(ROOT / "research" / "dlp" / "entity_map.yaml")
ark, gold, carrier = SB_TESTS.ark, SB_TESTS.gold, SB_TESTS.carrier
OPENAI, PASSWORD = SB_TESTS.OPENAI, SB_TESTS.PASSWORD
VAT = ("dlp_de_vat_id", "dlp.de.vat_id", ["identifier.de.vat_id"])


def rows() -> list[dict]:
    return [
        carrier("openai-1", [gold(10, 30, "API_KEY", "llm.openai.api_key", "dlp_openai_key")]),
        carrier("openai-2", [gold(5, 25, "API_KEY", "llm.openai.api_key", "dlp_openai_key")]),
        dict(carrier("password-1", [gold(8, 16, "CREDENTIAL", "credential.password_assignment",
                                         "dlp_password_assignment")]), format="json"),
        carrier("vat-1", [gold(0, 11, "dlp.de.vat_id", "identifier.de.vat_id", "dlp_de_vat_id")]),
        carrier("openai-example", [], variant="doc_example"),
        carrier("openai-test", [], variant="test_key"),
    ]


def ark_default() -> list[dict]:
    return [
        {"id": "openai-1", "evidence_spans": [ark(10, 30, OPENAI), ark(35, 39, PASSWORD)]},  # exact + extra
        {"id": "openai-2", "evidence_spans": [ark(5, 22, OPENAI)]},                           # boundary
        {"id": "password-1", "evidence_spans": []},                                           # missed
        {"id": "openai-example", "evidence_spans": [ark(0, 20, OPENAI), ark(0, 20, OPENAI)]},  # one FP
        {"id": "openai-test", "evidence_spans": [ark(0, 20, OPENAI), ark(25, 30, PASSWORD)]},
    ]


def test_error_buckets_split_fp_missed_boundary_and_extra_spans_by_rule():
    buckets = MODULE.error_buckets(rows(), ark_default(), TAXONOMY)
    assert buckets["hard_negative_fp"] == [
        {"rule_id": "dlp_openai_key", "variant": "doc_example", "fp": 1},
        {"rule_id": "dlp_openai_key", "variant": "test_key", "fp": 1},
        {"rule_id": "dlp_password_assignment", "variant": "test_key", "fp": 1},
    ]
    assert buckets["missed"] == {"dlp_password_assignment": 1}  # the opt-in VAT gold is not counted
    assert buckets["missed_by_format"] == {"json": 1}
    assert buckets["boundary"] == {"dlp_openai_key": 1}
    assert buckets["extra_on_positives"] == {"dlp_password_assignment": 1}


def test_error_buckets_ignore_content_spans_and_unknown_rows():
    sql = ark(0, 30, SB_TESTS.SQL)
    predictions = [{"id": "openai-example", "evidence_spans": [sql]}, {"id": "elsewhere", "evidence_spans": [sql]}]
    buckets = MODULE.error_buckets(rows(), predictions, TAXONOMY)
    assert buckets["hard_negative_fp"] == [] and buckets["extra_on_positives"] == {}


def write_predictions(directory: Path, name: str, predictions: list[dict]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text("".join(json.dumps(row) + "\n" for row in predictions))


def write_run(directory: Path, prefix: str, components: tuple[str, ...], **predictions: list[dict]) -> None:
    """Every component file of one tool profile; components not given are empty runs."""
    for component in components:
        write_predictions(directory, f"{prefix}.{component}.jsonl", predictions.get(component, []))


def write_default(directory: Path, tool: str, **predictions: list[dict]) -> None:
    write_run(directory, tool, MODULE.COMPONENTS, **predictions)


def write_extended(directory: Path, tool: str, **predictions: list[dict]) -> None:
    write_run(directory, f"{tool}.extended", MODULE.EXTENDED_COMPONENTS, **predictions)


def test_load_predictions_merges_components_and_skips_missing_tools(tmp_path):
    write_default(tmp_path, "ark", synthetic=ark_default(), benign_code=[{"id": "alpha:src/a.py", "evidence_spans": []}])
    write_extended(tmp_path, "ark", synthetic=[{"id": "vat-1", "evidence_spans": [ark(0, 11, VAT)]}])
    write_default(tmp_path, "gitleaks")
    loaded = MODULE.load_predictions(tmp_path)
    assert list(loaded) == ["ark", "gitleaks"]
    assert len(loaded["ark"]["default"]) == len(ark_default()) + 1
    assert loaded["ark"]["extended"] == [{"id": "vat-1", "evidence_spans": [ark(0, 11, VAT)]}]
    assert loaded["gitleaks"]["extended"] is None


@pytest.mark.parametrize("missing", ["gitleaks.benign_code.jsonl", "ark.extended.external.jsonl"])
def test_load_predictions_rejects_incomplete_component_sets(tmp_path, missing):
    write_default(tmp_path, "ark")
    write_extended(tmp_path, "ark")
    write_default(tmp_path, "gitleaks")
    (tmp_path / missing).unlink()
    with pytest.raises(ValueError, match=f"incomplete component set.*missing {missing}"):
        MODULE.load_predictions(tmp_path)


def test_load_predictions_rejects_extended_run_without_default_run(tmp_path):
    write_extended(tmp_path, "ark")
    with pytest.raises(ValueError, match="without a default run"):
        MODULE.load_predictions(tmp_path)


@pytest.fixture
def dev(tmp_path):
    return SB_TESTS.write_split(tmp_path / "dev", "dev", rows(), SB_TESTS.code_docs(), SB_TESTS.text_docs())


def test_main_writes_reports_and_renders_secret_and_opt_in_tables(tmp_path, dev, capsys):
    predictions, output = tmp_path / "pred", tmp_path / "out"
    write_default(predictions, "ark", synthetic=ark_default())
    write_extended(predictions, "ark", synthetic=[{"id": "vat-1", "evidence_spans": [ark(0, 11, VAT)]}])
    gitleaks = [{"id": "openai-1", "evidence_spans": [dict(ark(10, 30, OPENAI), rule_id="openai-api-key", group=None)]}]
    write_default(predictions, "gitleaks", synthetic=gitleaks)
    assert MODULE.main(["--dev", str(dev), "--predictions", str(predictions), "--output-dir", str(output)]) == 0
    out = capsys.readouterr().out
    assert sorted(path.name for path in output.iterdir()) == [
        "ark.buckets.json", "ark.extended.json", "ark.json", "gitleaks.json"]
    extended_report = json.loads((output / "ark.extended.json").read_text())
    assert extended_report["synthetic"]["groups"]["dlp.de.vat_id"]["exact"]["recall"] == 1.0
    # The default report, like the baselines', holds the default run only: no opt-in spans.
    ark_report = json.loads((output / "ark.json").read_text())
    assert ark_report["synthetic"]["groups"]["dlp.de.vat_id"]["exact"]["recall"] == 0.0
    assert ark_report["synthetic"]["overall"]["predicted"] == len(
        {(row["id"], s["start_char"], s["end_char"]) for row in ark_default() for s in row["evidence_spans"]})
    assert ark_report["benign_docs"].get("extended") is None
    secret_table = out.split("### F1 je Secret-Gruppe")[1].split("###")[0]
    assert "| API_KEY | 2 |" in secret_table and "dlp.de.vat_id" not in secret_table
    opt_in_table = out.split("### Opt-in-Gruppen")[1].split("###")[0]
    assert "| dlp.de.vat_id | 1 | 100.0 / 100.0 |" in opt_in_table
    assert "| llm.openai.api_key | shared | 2 | 50.0 (100.0) | 50.0 (50.0) |" in out
    assert "| dlp_openai_key | doc_example | 1 |" in out


def test_default_tables_ignore_ark_opt_in_spans(tmp_path, dev, capsys):
    """Opt-in spans of the extended run change neither ARK's default row nor its hard-negative FP."""
    outputs = []
    for name, extended in (("plain", None), ("with-extended", [
        {"id": "vat-1", "evidence_spans": [ark(0, 11, VAT)]},
        {"id": "openai-example", "evidence_spans": [ark(40, 51, VAT)]},  # opt-in span on a hard negative
    ])):
        predictions = tmp_path / name
        write_default(predictions, "ark", synthetic=ark_default())
        write_default(predictions, "gitleaks")
        if extended is not None:
            write_extended(predictions, "ark", synthetic=extended)
        assert MODULE.main(["--dev", str(dev), "--predictions", str(predictions)]) == 0
        outputs.append(capsys.readouterr().out)
    plain, combined = outputs
    default_part = lambda out: out.split("### Opt-in-Gruppen")[0].split("### Fehler-Buckets")[0]
    assert default_part(plain) == default_part(combined)
    assert "### Opt-in-Gruppen" not in plain
    # The hard-negative opt-in span counts against the extended run only: one TP, one FP.
    assert "| dlp.de.vat_id | 1 | 66.7 / 66.7 |" in combined.split("### Opt-in-Gruppen")[1]


def test_main_without_predictions_is_an_error(tmp_path, dev, capsys):
    (tmp_path / "empty").mkdir()
    assert MODULE.main(["--dev", str(dev), "--predictions", str(tmp_path / "empty")]) == 2
    assert "no predictions" in capsys.readouterr().err
