from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "harmful_subclass.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_harmful_subclass", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def label(row_id, subclass="nonviolent_crime", reason="drug_acquisition"):
    return {"id": row_id, "subclass": subclass, "reason": reason}


def write_dev(root: Path) -> None:
    rows = {
        "train_dev/a.jsonl": [
            {"id": "a:1", "classes": ["harmful_content"], "language": "en", "text": "x", "labels": []},
            {"id": "a:2", "classes": [], "benign": True, "language": "en", "text": "y"},
            {"id": "a:3", "classes": ["harmful_content"], "language": "de", "text": "z",
             "labels": ["category = Violence (AILuminate vcr)"]},
        ],
        "report/r.jsonl": [{"id": "r:1", "classes": ["harmful_content"], "language": "en", "text": "q"}],
    }
    for name, items in rows.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(item) + "\n" for item in items))


def test_taxonomy_has_twelve_hazards_and_other():
    assert len(MODULE.PATTERN_SUBCLASSES) == 7 and len(MODULE.MODEL_ONLY_SUBCLASSES) == 5
    assert set(MODULE.MODEL_ONLY_SUBCLASSES) == {"specialized_advice", "ip", "defamation", "elections", "privacy"}
    assert MODULE.SUBCLASSES[-1] == MODULE.OTHER


def test_validate_rejects_text_unknown_subclasses_and_duplicates():
    assert MODULE.validate([label("a:1")]) == {"a:1": {"subclass": "nonviolent_crime", "reason": "drug_acquisition"}}
    with pytest.raises(ValueError, match="keys"):
        MODULE.validate([{**label("a:1"), "text": "row text"}])
    with pytest.raises(ValueError, match="unknown subclass"):
        MODULE.validate([label("a:1", subclass="hate")])
    with pytest.raises(ValueError, match="snake_case"):
        MODULE.validate([label("a:1", reason="How do I steal a car?")])
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.validate([label("a:1"), label("a:1")])


def test_sample_is_a_fixed_five_percent():
    ids = [f"set:{i:07d}" for i in range(4000)]
    picked = [i for i in ids if MODULE.in_sample(i)]
    assert 0.04 < len(picked) / len(ids) < 0.06
    assert picked == [i for i in ids if MODULE.in_sample(i)]


def test_dev_positives_skip_report_sets_and_check_names_missing_and_extra(tmp_path):
    write_dev(tmp_path)
    positives = MODULE.dev_positives(tmp_path)
    assert [row["id"] for row in positives] == ["a:1", "a:3"]
    labels = MODULE.validate([label("a:1"), label("r:1")])
    assert MODULE.check(labels, positives) == ["unlabelled positive a:3",
                                               "label of a row that is no dev positive: r:1"]


def test_merge_writes_sorted_labels_without_text_and_coverage_names_gaps(tmp_path, capsys):
    write_dev(tmp_path / "dev")
    batch = tmp_path / "labels0.jsonl"
    batch.write_text(json.dumps(label("a:3", "violent_crime", "assault_plan")) + "\n" + json.dumps(label("a:1")) + "\n")
    out = tmp_path / "labels.jsonl"
    assert MODULE.main(["--labels", str(out), "merge", "--dev", str(tmp_path / "dev"), str(batch)]) == 0
    assert [json.loads(line)["id"] for line in out.read_text().splitlines()] == ["a:1", "a:3"]
    assert "text" not in out.read_text()
    labels = MODULE.load(out)
    table = MODULE.coverage(labels, MODULE.dev_positives(tmp_path / "dev"))
    assert table["violent_crime"] == {"all": 1, "de": 1, "en": 0}
    assert ("violent_crime", "de") in MODULE.gaps(table) and all(sub != MODULE.OTHER for sub, _ in MODULE.gaps(table))
    # A label set that misses a positive is not written.
    batch.write_text(json.dumps(label("a:1")) + "\n")
    assert MODULE.main(["--labels", str(tmp_path / "x.jsonl"), "merge", "--dev", str(tmp_path / "dev"), str(batch)]) == 1
    assert not (tmp_path / "x.jsonl").exists()


def test_agree_lists_the_rows_the_two_passes_label_differently():
    rows, diffs = MODULE.agree({"a": "privacy", "b": "cbrne", "c": "ip"}, {"a": "privacy", "b": "violent_crime"})
    assert rows == 2 and diffs == [("b", "cbrne", "violent_crime")]


def test_missing_label_file_loads_empty(tmp_path):
    assert MODULE.load(tmp_path / "none.jsonl") == {}


def test_features_hash_into_the_buckets_of_the_category_model():
    counts = MODULE.feature_counts("Wie Wie", buckets=64)
    # Two words, one bigram, the char n-grams of "<wie>" twice: every feature counted.
    expected = [MODULE.fnv1a_32(f) % 64 for f in MODULE.fasttext_features("Wie Wie", (), *MODULE.CHAR_NGRAMS)]
    assert sum(counts.values()) == len(expected) and counts == __import__("collections").Counter(expected)
    assert MODULE.feature_counts("", buckets=64) == {}


def test_quantize_rounds_and_clamps_to_i16():
    assert MODULE.quantize([0.0014, -0.0016, 40.0, -40.0], scale=1000) == [1, -2, 32767, -32768]


def test_train_and_predict_toy_subclasses():
    texts = ["steal the car", "steal a wallet", "hack the server", "hack an account"] * 3
    targets = [0, 0, 1, 1] * 3
    weights, bias = MODULE.fit(texts, targets, 2, buckets=256, epochs=100)
    model = MODULE.model_document(["nonviolent_crime", "cyber_harm"], weights, bias, buckets=256)
    assert model["weights"] and len(model["weights"][0]) == 256
    subclass, numerators, total = MODULE.predict(model, "how to hack a server")
    assert subclass == "cyber_harm" and numerators[1] > numerators[0] and total > 0
    assert MODULE.predict(model, "steal it")[0] == "nonviolent_crime"
    # A text without features counts as one feature: the numerators are the biases.
    assert MODULE.predict(model, "") [1:] == (model["bias"], 1)


def test_ties_go_to_the_first_class_and_folds_are_stratified():
    model = {"buckets": 8, "char_ngram_range": [3, 5], "classes": ["a", "b"], "bias": [0, 0],
             "weights": [[0] * 8, [0] * 8]}
    assert MODULE.predict(model, "x")[0] == "a"
    assert MODULE.folds([0, 0, 1, 0, 1], count=2) == [0, 1, 0, 0, 1]


def test_parity_file_matches_the_built_in_model():
    model = json.loads(MODULE.MODEL_PATH.read_text(encoding="utf-8"))
    for line in MODULE.PARITY_PATH.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        assert MODULE.predict(model, case["text"]) == (case["subclass"], case["numerators"], case["total"])
