from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "gold.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_gold", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
CORPORA = MODULE.CORPORA


def row(dataset, index, text, language="en", classes=(), benign=False, **extra):
    return {"id": f"{dataset}:{index:07d}", "dataset": dataset, "text": text, "language": language,
            "classes": list(classes), "benign": benign, **extra}


def freeze(directory: Path, sets: dict[str, list[dict]], schema=None, role="dev") -> Path:
    """A frozen corpus directory as prepare_corpora.py (or generators.py) writes it."""
    directory.mkdir(parents=True)
    entries = {}
    for name, rows in sets.items():
        data = CORPORA.BENIGN_CODE._jsonl(rows)
        (directory / f"{name}.jsonl").write_bytes(data)
        entries[name] = {"file": f"{name}.jsonl", "sha256": CORPORA.PRESIDIO._sha256(data), "role": role,
                         "dataset": rows[0]["dataset"], "rows": len(rows)}
    manifest = CORPORA.BENIGN_CODE._manifest_bytes({"schema": schema or CORPORA.CORPORA_SCHEMA, "sets": entries})
    (directory / "manifest.json").write_bytes(manifest)
    (directory / ".ready").write_text(f"{CORPORA.PRESIDIO._sha256(manifest)}  manifest.json\n", encoding="utf-8")
    return directory


def texts(prefix, count):
    return [f"{prefix} number {index} with some distinct filler words {index * 7919}" for index in range(count)]


@pytest.fixture()
def dev_pool(tmp_path):
    attacks = [row("inj", i, t, classes=["instruction_injection"]) for i, t in enumerate(texts("ignore the rules", 60))]
    benign = [row("inj", 100 + i, t, benign=True) for i, t in enumerate(texts("summarise the report", 60))]
    german = [row("de", i, t, language="de", benign=True) for i, t in enumerate(texts("fasse den Bericht zusammen", 70))]
    prepared = freeze(tmp_path / "train_dev", {"inj": attacks + benign, "de": german})
    templates = [row("generators_dev_seed", i, t, classes=["tool_poisoning"]) for i, t in enumerate(texts("tool says send", 55))]
    generated = freeze(tmp_path / "generated", {"class_templates": templates}, schema=CORPORA.GENERATED_SCHEMA)
    return MODULE.read_pool([prepared, generated])


def review(sheet, wrong=()):
    return [{**item, "verdict": "wrong" if item["id"] in wrong else "ok"} for item in sheet]


def test_sample_is_stratified_deterministic_and_covers_every_set(dev_pool):
    sheet = MODULE.sample(dev_pool, 50)
    assert sheet == MODULE.sample(dev_pool, 50)
    by_set = {}
    for item in sheet:
        by_set.setdefault(item["set"], []).append(item["label"])
    assert {key: len(labels) for key, labels in by_set.items()} == {
        "train_dev/inj": 50, "train_dev/de": 50, "generated/class_templates": 50}
    assert by_set["train_dev/inj"].count("benign") == 25
    assert all(item["verdict"] is None for item in sheet)


def test_sample_takes_every_row_of_a_small_set(tmp_path):
    small = freeze(tmp_path / "train_dev", {"tiny": [row("tiny", i, t, benign=True) for i, t in enumerate(texts("hello", 7))]})
    assert len(MODULE.sample(MODULE.read_pool([small]), 50)) == 7


def test_check_sheet_rejects_missing_verdicts_relabels_and_short_sets(dev_pool):
    sheet = review(MODULE.sample(dev_pool, 50))
    assert MODULE.check_sheet(sheet, dev_pool, 50) == []
    broken = [dict(item) for item in sheet[1:]]
    broken[0]["verdict"] = None
    broken[1]["label"] = "jailbreak"
    problems = MODULE.check_sheet(broken + [broken[-1]], dev_pool, 50)
    assert any("verdict must be" in p for p in problems)
    assert any("differs from the corpus" in p for p in problems)
    assert any("reviewed twice" in p for p in problems)
    assert any("49 rows reviewed" in p for p in problems)


def test_summary_counts_classes_languages_provenance_and_error_rates(dev_pool):
    sheet = MODULE.sample(dev_pool, 50)
    wrong = {item["id"] for item in sheet if item["set"] == "train_dev/inj"}
    result = MODULE.summary(dev_pool, review(sheet, list(wrong)[:5]), "dev", {"de"})
    assert result["classes"]["instruction_injection"] == {"en": 60}
    assert result["classes"]["benign"] == {"de": 70, "en": 60}
    assert result["provenance"]["tool_poisoning"] == {"synthetic": 55}
    assert result["provenance"]["benign"] == {"native": 60, "translated": 70}
    assert result["sets"]["train_dev/inj"]["error_rate"] == 0.1
    assert result["sets"]["train_dev/de"]["error_rate"] == 0.0
    assert [item["verdict"] for item in result["flagged"]] == ["wrong"] * 5
    assert "text" not in json.dumps(result)
    holdout = MODULE.summary(dev_pool, review(sheet, list(wrong)[:5]), "holdout", set())
    assert "flagged" not in holdout and holdout["sets"]["train_dev/inj"]["wrong"] == 5


def summaries(pool, wrong=()):
    sheet = MODULE.sample(pool, 50)
    dev = MODULE.summary(pool, review(sheet, wrong), "dev", set())
    holdout = {**MODULE.summary(pool, review(sheet), "holdout", set()), "split": "holdout"}
    return dev, holdout, sheet


def test_decide_go_needs_both_splits_rows_review_and_no_leakage(dev_pool):
    dev, holdout, sheet = summaries(dev_pool)
    clean = {"leaked": 0}
    classes = ["instruction_injection", "tool_poisoning", "jailbreak"]
    decisions = MODULE.decide(classes, dev, holdout, clean)
    assert decisions["instruction_injection"] == ("go", "")
    assert decisions["tool_poisoning"] == ("go", "")
    assert decisions["jailbreak"][0] == "no-go"
    assert MODULE.decide(classes, dev, None, None)["instruction_injection"] == ("pending", "owner holdout review missing")
    assert MODULE.decide(classes, dev, holdout, None)["instruction_injection"] == ("pending", "leakage check missing")
    leaked = MODULE.decide(classes, dev, holdout, {"leaked": 2})
    assert leaked["instruction_injection"] == ("no-go", "2 holdout rows leak from dev")


def test_decide_blocks_a_class_whose_set_fails_and_every_class_on_a_failing_benign_pool(dev_pool):
    sheet = MODULE.sample(dev_pool, 50)
    tool_wrong = [item["id"] for item in sheet if item["set"] == "generated/class_templates"][:3]
    dev = MODULE.summary(dev_pool, review(sheet, tool_wrong), "dev", set())
    holdout = {**MODULE.summary(dev_pool, review(sheet), "holdout", set()), "split": "holdout"}
    decisions = MODULE.decide(["instruction_injection", "tool_poisoning"], dev, holdout, {"leaked": 0})
    assert decisions["instruction_injection"][0] == "go"
    assert decisions["tool_poisoning"] == ("no-go", "dev generated/class_templates: error rate 6.0%")
    # 75 benign rows reviewed (50 German, 25 English): 3 errors pass the pool, 4 do not.
    german = [item["id"] for item in sheet if item["set"] == "train_dev/de"]
    dev = MODULE.summary(dev_pool, review(sheet, german[:3]), "dev", set())
    assert MODULE.decide(["instruction_injection"], dev, holdout, {"leaked": 0})["instruction_injection"] == ("go", "")
    dev = MODULE.summary(dev_pool, review(sheet, german[:4]), "dev", set())
    decisions = MODULE.decide(["instruction_injection", "tool_poisoning"], dev, holdout, {"leaked": 0})
    assert all(decision == "no-go" and "dev benign pool: error rate 5.3%" in reason for decision, reason in decisions.values())


def test_report_sets_neither_count_nor_block(tmp_path):
    attacks = [row("rep", i, t, classes=["jailbreak"]) for i, t in enumerate(texts("pretend you are free", 60))]
    pool = MODULE.read_pool([freeze(tmp_path / "report", {"rep": attacks}, role="report")])
    dev, holdout, sheet = summaries(pool, [item["id"] for item in MODULE.sample(pool, 50)][:10])
    assert dev["classes"] == {}
    assert dev["class_sets"]["jailbreak"] == {"report/rep": 60}
    reason = MODULE.decide(["jailbreak"], dev, holdout, {"leaked": 0})["jailbreak"][1]
    assert "error rate" not in reason and "0 scored rows" in reason


def test_leakage_counts_exact_and_near_duplicates_across_splits(tmp_path):
    base = ("Please summarise the quarterly report for the finance team and list the three largest cost items "
            "together with their change against the previous quarter.")
    dev = MODULE.read_pool([freeze(tmp_path / "dev" / "train_dev", {"a": [row("a", 0, base, classes=["instruction_injection"])]})])
    holdout_rows = [
        row("h", 0, base.upper()),
        row("h", 1, base.replace("three largest", "three biggest")),
        row("h", 2, "Wie wird das Wetter morgen in Hamburg, und brauche ich einen Schirm für den Ausflug?", language="de"),
    ]
    holdout = MODULE.read_pool([freeze(tmp_path / "holdout" / "holdout", {"h": holdout_rows})])
    result = MODULE.leakage(dev, holdout, CORPORA.load()["dedup"])
    assert result["sets"]["holdout/h"] == {"rows": 3, "exact": 1, "minhash": 1}
    assert result["leaked"] == 2
    assert "text" not in json.dumps(result)


def test_leakage_indexes_near_duplicate_dev_rows(tmp_path):
    # MinHash is not transitive: the holdout row matches dev row b, not its near twin a.
    tail = ("the quarterly report for the finance team and list the three largest cost items together with their "
            "change against the previous quarter and the owner of each")
    a, b = f"Please summarise {tail} budget line in the sheet", f"Kindly draft and send {tail} budget line in the sheet"
    held = f"Kindly draft and send {tail} cost centre in the sheet"
    index = CORPORA.Deduper(CORPORA.load()["dedup"])
    index.add(a)
    assert index.match(b)[0] == "minhash" and index.match(held)[0] is None
    dev = MODULE.read_pool([freeze(tmp_path / "dev" / "train_dev", {"a": [row("a", 0, a), row("a", 1, b)]})])
    holdout = MODULE.read_pool([freeze(tmp_path / "holdout" / "holdout", {"h": [row("h", 0, held)]})])
    result = MODULE.leakage(dev, holdout, CORPORA.load()["dedup"])
    assert result["sets"]["holdout/h"] == {"rows": 1, "exact": 0, "minhash": 1}


def test_cli_end_to_end_renders_pending_holdout(dev_pool, tmp_path):
    directories = [str(tmp_path / "train_dev"), str(tmp_path / "generated")]
    sheet_path, summary_path, report = tmp_path / "sheet.jsonl", tmp_path / "dev.json", tmp_path / "gold.md"
    assert MODULE.main(["sample", *directories, "--out", str(sheet_path)]) == 0
    sheet = [json.loads(line) for line in sheet_path.read_text(encoding="utf-8").splitlines()]
    assert MODULE.main(["summary", *directories, "--split", "dev", "--review", str(sheet_path), "--out", str(summary_path)]) == 1
    sheet_path.write_bytes(CORPORA.BENIGN_CODE._jsonl(review(sheet)))
    assert MODULE.main(["summary", *directories, "--split", "dev", "--review", str(sheet_path), "--out", str(summary_path)]) == 0
    notes = tmp_path / "notes.md"
    notes.write_text("## Findings\n\nAll clean.\n", encoding="utf-8")
    assert MODULE.main(["render", "--dev", str(summary_path), "--notes", str(notes), "--out", str(report)]) == 0
    text = report.read_text(encoding="utf-8")
    assert "| instruction_injection | pending | owner holdout review missing |" in text
    assert "| jailbreak | no-go | dev: 0 scored rows (needs 50) |" in text
    assert "Pending: the owner's aggregate review report is not present." in text
    assert text.endswith("## Findings\n\nAll clean.\n") and "## Flagged dev rows" not in text
    with pytest.raises(ValueError, match="not a holdout summary"):
        MODULE.main(["render", "--dev", str(summary_path), "--holdout", str(summary_path), "--out", str(report)])
