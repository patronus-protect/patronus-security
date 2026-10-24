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
EVALUATOR = "presidio-evaluator-synth-v2"
RECOGNIZER_TESTS = "presidio-analyzer-recognizer-tests"


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


def test_buckets_per_source_family():
    rows = [
        gold("a", [("pii.email", 0, 10)]),
        gold("b", [("pii.email", 0, 10)], corpus=GRETEL, language="en"),
        gold("c", [("pii.email", 0, 10)], corpus=EVALUATOR, language="en"),
    ]
    preds = [pred("a", [("pii.email", 0, 10)]), pred("b", []), pred("c", [("pii.email", 0, 10)])]
    buckets = MODULE.score_rows(rows, preds, EMAP)["buckets"]
    assert buckets["family/ark_authored"]["exact"] == 1
    assert buckets["family/neutral"] == {"gold": 1, "predicted": 0, "exact": 0, "gold_found": 0, "predicted_correct": 0}
    assert buckets["family/presidio_favored"]["exact"] == 1
    assert buckets["family_entity/neutral/pii.email"]["gold"] == 1
    assert buckets["family_language/presidio_favored/en"]["exact"] == 1
    assert buckets["family_language_entity/ark_authored/de/pii.email"]["exact"] == 1


def test_every_gold_corpus_needs_a_source_family():
    rows = [gold("a", [("pii.email", 0, 10)], corpus="unknown-corpus")]
    with pytest.raises(MODULE.ScoreboardError, match="source family"):
        MODULE.score_rows(rows, [pred("a", [])], EMAP)


def recognizer_case(row_id, entities, scored, negative=False):
    row = gold(row_id, entities, corpus=RECOGNIZER_TESTS, language="en")
    row["scored_entities"] = scored
    if negative:
        row["hard_negatives"] = [
            {"start": 0, "end": 200, "kind": "presidio_recognizer_negative", "entity_type": label} for label in scored
        ]
    return row


def test_scored_entities_restrict_a_row_to_its_recognizer():
    # A credit card test case says nothing about the e-mail address next to the card number.
    rows = [recognizer_case("a", [("pii.credit_card.pan", 0, 16)], ["pii.credit_card.pan"])]
    preds = [pred("a", [("pii.credit_card.pan", 0, 16), ("pii.email", 20, 30)])]
    result = MODULE.score_rows(rows, preds, EMAP)
    assert result["buckets"]["all"] == {"gold": 1, "predicted": 1, "exact": 1, "gold_found": 1, "predicted_correct": 1}
    assert "entity/pii.email" not in result["buckets"]
    rows[0]["scored_entities"] = "pii.credit_card.pan"
    with pytest.raises(MODULE.ScoreboardError, match="scored_entities"):
        MODULE.score_rows(rows, preds, EMAP)


def test_typed_hard_negative_only_forbids_its_entity():
    rows = [recognizer_case("a", [], ["pii.us.social_security_number"], negative=True)]
    preds = [pred("a", [("pii.us.social_security_number", 0, 11), ("pii.phone", 0, 11)])]
    result = MODULE.score_rows(rows, preds, EMAP, "presidio_favored/t.jsonl")
    assert result["hard_negative_fp"] == [["presidio_favored/t.jsonl", "a", "pii.us.social_security_number", 0, 11]]
    assert result["buckets"]["entity/pii.us.social_security_number"]["predicted"] == 1
    assert "entity/pii.phone" not in result["buckets"]


def test_compare_gates_source_families():
    favored = [gold(f"f{i}", [("pii.email", 0, 10)], corpus=EVALUATOR, language="en") for i in range(100)]
    neutral = [gold(f"n{i}", [("pii.email", 0, 10)], corpus=GRETEL, language="en") for i in range(900)]
    rows = favored + neutral
    base = MODULE.score_rows(rows, [pred(row["id"], [("pii.email", 0, 10)]) for row in rows], EMAP)
    # 4 presidio_favored rows lost: -0.2 pp overall, but -2 pp in the family.
    head = MODULE.score_rows(
        rows, [pred(row["id"], [] if row["id"] in {"f0", "f1", "f2", "f3"} else [("pii.email", 0, 10)]) for row in rows], EMAP
    )
    assert {item["bucket"] for item in MODULE.compare(base, head)["regressions"]} == {"family/presidio_favored"}


def m1_rows():
    rows, ark, presidio = [], [], []
    for family, corpus in (("neutral", GRETEL), ("favored", EVALUATOR), ("ark", SYNTH)):
        for i in range(10):
            row_id = f"{family}-{i}"
            rows.append(gold(row_id, [("pii.email", 0, 10), ("pii.phone", 20, 30)], corpus=corpus, language="en"))
            # Ark finds every e-mail; it misses phones in neutral rows 0-4 and in all ark_authored rows.
            ark_spans = [("pii.email", 0, 10)]
            if not ((family == "neutral" and i < 5) or family == "ark"):
                ark_spans.append(("pii.phone", 20, 30))
            ark.append(pred(row_id, ark_spans))
            presidio.append(pred(row_id, [("pii.email", 0, 10), ("pii.phone", 20, 30)] if i else [("pii.phone", 20, 30)]))
    return rows, ark, presidio


def test_m1_must_hold_on_neutral_and_presidio_favored_separately():
    rows, ark, presidio = m1_rows()
    report = MODULE.m1_report(MODULE.score_rows(rows, ark, EMAP), MODULE.score_rows(rows, presidio, EMAP), EMAP)
    families = report["families"]
    assert families["presidio_favored"]["holds"]
    assert not families["neutral"]["holds"]
    assert families["neutral"]["entities"]["pii.phone"]["holds"] is False
    assert families["neutral"]["entities"]["pii.email"]["holds"] is True
    # ark_authored is reported, never decides: Ark is worse there and M1 does not care.
    assert not families["ark_authored"]["decides"] and not families["ark_authored"]["holds"]
    assert report["met"] is False
    # Ark perfect on neutral: M1 met although ark_authored still fails.
    ark = [pred(row["id"], [(e["entity_type"], e["start"], e["end"]) for e in row["entities"]])
           if row["corpus"] == GRETEL else p for row, p in zip(rows, ark)]
    report = MODULE.m1_report(MODULE.score_rows(rows, ark, EMAP), MODULE.score_rows(rows, presidio, EMAP), EMAP)
    assert report["met"] is True and not report["families"]["ark_authored"]["holds"]
    lines = MODULE.m1_lines(report)
    assert lines[-1] == "M1: MET (neutral holds, presidio_favored holds)"
    assert any(line.startswith("ark_authored: NOT MET") and "decides no milestone" in line for line in lines)


def test_m1_needs_data_in_both_families_and_counts_only_shared_ids():
    rows = [gold(f"n{i}", [("pii.email", 0, 10), ("pii.swift_bic", 20, 31)], corpus=GRETEL, language="en") for i in range(5)]
    ark = [pred(row["id"], [("pii.email", 0, 10)]) for row in rows]
    report = MODULE.m1_report(MODULE.score_rows(rows, ark, EMAP), MODULE.score_rows(rows, ark, EMAP), EMAP)
    assert report["families"]["neutral"]["holds"] and set(report["families"]["neutral"]["entities"]) == {"pii.email"}
    assert report["families"]["presidio_favored"] == {"decides": True, "holds": False, "entities": {}}
    assert report["met"] is False
    assert "presidio_favored: NO DATA, 0/0 shared ids" in MODULE.m1_lines(report)


def test_m1_is_english_by_default():
    rows = [gold("de", [("pii.email", 0, 10)], corpus=GRETEL, language="de"),
            gold("en", [("pii.email", 0, 10)], corpus=GRETEL, language="en")]
    ark = [pred("de", []), pred("en", [("pii.email", 0, 10)])]
    presidio = [pred("de", [("pii.email", 0, 10)]), pred("en", [("pii.email", 0, 10)])]
    scored = MODULE.score_rows(rows, ark, EMAP), MODULE.score_rows(rows, presidio, EMAP)
    assert MODULE.m1_report(*scored, EMAP)["families"]["neutral"]["holds"]
    assert not MODULE.m1_report(*scored, EMAP, language="all")["families"]["neutral"]["holds"]


BY_CORPUS = {GRETEL: "g.jsonl", EVALUATOR: "presidio_favored/e.jsonl", SYNTH: "synthetic/s.jsonl"}


def write_tree(tmp_path, rows, engines):
    """Gold rows in three frozen directories plus one prediction directory per engine."""
    for root, predictions in (("gold", None), *engines.items()):
        for corpus, name in BY_CORPUS.items():
            selected = [i for i, row in enumerate(rows) if row["corpus"] == corpus]
            write_jsonl(tmp_path / root / name, [rows[i] if predictions is None else predictions[i] for i in selected])
            if predictions is None:
                (tmp_path / root / name).parent.joinpath(".ready").write_text("x")
    return {name: tmp_path / name for name in engines}


def perfect(rows):
    return [pred(row["id"], [(e["entity_type"], e["start"], e["end"]) for e in row["entities"]]) for row in rows]


def test_main_m1_subcommand_prints_every_mode_and_decides_on_balanced(tmp_path, capsys):
    rows, ark, presidio = m1_rows()
    dirs = write_tree(tmp_path, rows, {"weak": ark, "perfect": perfect(rows), "presidio": presidio})
    base = ["m1", "--gold", str(tmp_path / "gold"), "--presidio", str(dirs["presidio"])]
    args = base + ["--ark", f"strict={dirs['weak']}", "--ark", f"balanced={dirs['perfect']}"]
    assert MODULE.main(args + ["--json", str(tmp_path / "m1.json")]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert "== Ark strict (reported, decides no milestone)" in lines and "== Ark balanced (milestone mode)" in lines
    strict = lines[lines.index("== Ark strict (reported, decides no milestone)"):lines.index("== Ark balanced (milestone mode)")]
    assert "neutral: NOT MET, 1/2 shared ids" in strict
    assert "M1 strict: NOT MET (neutral not met, presidio_favored holds)" in lines
    assert "M1 balanced: MET (neutral holds, presidio_favored holds)" in lines
    assert lines[-1] == "M1: MET (balanced: neutral holds, presidio_favored holds)"
    report = json.loads((tmp_path / "m1.json").read_text())
    assert report["milestone_mode"] == "balanced" and report["met"] is True
    assert report["modes"]["strict"]["met"] is False and report["modes"]["balanced"]["met"] is True
    assert MODULE.main(args + ["--check"]) == 0
    # Swapped: strict meets M1, balanced does not, so M1 is not met.
    swapped = base + ["--ark", f"strict={dirs['perfect']}", "--ark", f"balanced={dirs['weak']}"]
    assert MODULE.main(swapped + ["--check"]) == 1
    assert capsys.readouterr().out.strip().endswith("M1: NOT MET (balanced: neutral not met, presidio_favored holds)")
    # Balanced is required; modes are named once and must exist.
    assert MODULE.main(base + ["--ark", f"strict={dirs['perfect']}"]) == 2
    assert MODULE.main(base + ["--ark", f"balanced={dirs['weak']}"]) == 0
    for bad in (str(dirs["weak"]), f"fast={dirs['weak']}"):
        assert MODULE.main(base + ["--ark", f"balanced={dirs['weak']}", "--ark", bad]) == 2
    assert MODULE.main(swapped + ["--ark", f"balanced={dirs['weak']}"]) == 2
    (dirs["weak"] / "g.jsonl").unlink()
    assert MODULE.main(swapped) == 2


# ── M2 per source family ─────────────────────────────────────────────────


def m2_rows(neutral_phones=5, favored_phones=10):
    """DE rows: Gretel (neutral) and presidio-evaluator (presidio_favored), each with e-mail and phone gold,
    plus postal-code recognizer cases (presidio_only). Presidio finds every e-mail, phones only in
    presidio_favored rows and every postal code; Ark finds every e-mail, the first neutral_phones
    neutral and favored_phones favored phones, and no postal code."""
    rows, ark, presidio = [], [], []
    for family, corpus, found in (("neutral", GRETEL, neutral_phones), ("favored", EVALUATOR, favored_phones)):
        for i in range(10):
            row_id = f"{family}-{i}"
            rows.append(gold(row_id, [("pii.email", 0, 10), ("pii.phone", 20, 30)], corpus=corpus))
            ark.append(pred(row_id, [("pii.email", 0, 10)] + ([("pii.phone", 20, 30)] if i < found else [])))
            presidio.append(pred(row_id, [("pii.email", 0, 10)] + ([("pii.phone", 20, 30)] if family == "favored" else [])))
    for i in range(3):
        row = recognizer_case(f"plz-{i}", [("pii.de.postal_code", 0, 5)], ["pii.de.postal_code"])
        row["language"] = "de"
        rows.append(row)
        ark.append(pred(row["id"], []))
        presidio.append(pred(row["id"], [("pii.de.postal_code", 0, 5)]))
    return rows, ark, presidio


def m2(rows, ark, presidio, emap=EMAP, **kwargs):
    return MODULE.m2_report(MODULE.score_rows(rows, ark, emap), MODULE.score_rows(rows, presidio, emap), emap, **kwargs)


def test_m2_neutral_needs_tuned_plus_15_pp_and_presidio_favored_parity():
    # neutral: Presidio macro (100 + 0) / 2 = 50, target 65; Ark (100 + 66.7) / 2 = 83.3.
    report = m2(*m2_rows())
    neutral, favored = report["families"]["neutral"], report["families"]["presidio_favored"]
    assert neutral["margin_pp"] == 15.0 and favored["margin_pp"] == 0.0
    assert neutral["ids"] == ["pii.email", "pii.phone"]
    assert neutral["ark_macro_f1"] == pytest.approx((1 + 2 / 3) / 2)
    assert neutral["presidio_macro_f1"] == pytest.approx(0.5) and neutral["target"] == pytest.approx(0.65)
    assert neutral["holds"] is True
    # presidio_favored: both perfect on e-mail and phone; parity is enough, no margin.
    assert favored["ark_macro_f1"] == pytest.approx(1.0) and favored["presidio_macro_f1"] == pytest.approx(1.0)
    assert favored["holds"] is True and report["met"] is True
    # One neutral phone: Ark 59.1 is 9 pp ahead of Presidio but below the +15 pp target.
    report = m2(*m2_rows(neutral_phones=1))
    assert report["families"]["neutral"]["ark_macro_f1"] == pytest.approx((1 + 2 / 11) / 2)
    assert report["families"]["neutral"]["holds"] is False and report["met"] is False
    # Exactly at the target still holds (two phones: (100 + 33.3) / 2 = 66.7 >= 65).
    assert m2(*m2_rows(neutral_phones=2))["families"]["neutral"]["holds"] is True
    # presidio_favored below parity fails although neutral holds.
    report = m2(*m2_rows(favored_phones=9))
    assert report["families"]["neutral"]["holds"] and not report["families"]["presidio_favored"]["holds"]
    assert report["met"] is False


def test_m2_neutral_target_is_tuned_macro_f1_plus_15_pp():
    rows = [gold(f"n{i}", [("pii.email", 0, 10)], corpus=GRETEL) for i in range(20)]
    # Presidio finds 10 of 20 e-mails (F1 66.7, target 81.7); Ark 14 of 20 gives 82.4, 13 gives 78.8.
    presidio = [pred(row["id"], [("pii.email", 0, 10)] if i < 10 else []) for i, row in enumerate(rows)]
    for found, holds in ((16, True), (14, True), (13, False)):
        ark = [pred(row["id"], [("pii.email", 0, 10)] if i < found else []) for i, row in enumerate(rows)]
        assert m2(rows, ark, presidio)["families"]["neutral"]["holds"] is holds, found


def test_m2_keeps_presidio_only_ids_out_unless_the_map_marks_them_shared():
    rows, ark, presidio = m2_rows()
    favored = m2(rows, ark, presidio)["families"]["presidio_favored"]
    # Presidio finds every postal code, Ark none; the id stays out and is listed as excluded.
    assert "pii.de.postal_code" not in favored["ids"] and "pii.de.postal_code" not in favored["entities"]
    assert favored["excluded"] == {"pii.de.postal_code": {"gold": 3, "scope": "presidio_only"}}
    assert favored["holds"] is True
    # Once the map marks the id shared (an Ark label exists), it counts and pulls Ark below parity.
    entities = [entity._replace(scope="shared", ark=("POSTAL_CODE_DE",)) if entity.id == "pii.de.postal_code" else entity
                for entity in EMAP.entities.values()]
    emap = MODULE.entity_map_module.EntityMap(EMAP.presidio_version, entities, EMAP.families)
    favored = m2(rows, ark, presidio, emap=emap)["families"]["presidio_favored"]
    assert favored["ids"] == ["pii.de.postal_code", "pii.email", "pii.phone"] and favored["excluded"] == {}
    assert favored["ark_macro_f1"] == pytest.approx(2 / 3) and favored["holds"] is False


def test_m2_counts_ark_only_ids_and_ignores_semantic_ones():
    rows = [gold(f"n{i}", [("pii.email", 0, 10), ("pii.swift_bic", 20, 31), ("entity.person", 40, 50)], corpus=GRETEL)
            for i in range(5)]
    ark = perfect(rows)
    presidio = [pred(row["id"], [("pii.email", 0, 10)]) for row in rows]
    neutral = m2(rows, ark, presidio)["families"]["neutral"]
    # Presidio has no recognizer for the BIC (ark_only): F1 0 there, macro 50.
    assert neutral["ids"] == ["pii.email", "pii.swift_bic"]
    assert neutral["entities"]["pii.swift_bic"] == {"gold": 5, "scope": "ark_only", "ark_f1": 1.0, "presidio_f1": 0.0}
    assert neutral["presidio_macro_f1"] == pytest.approx(0.5) and neutral["holds"]


def test_m2_is_german_by_default_and_needs_data_in_both_families():
    rows = [gold("de", [("pii.email", 0, 10)], corpus=GRETEL, language="de"),
            gold("en", [("pii.phone", 20, 30)], corpus=GRETEL, language="en")]
    ark = [pred("de", [("pii.email", 0, 10)]), pred("en", [])]
    presidio = [pred("de", []), pred("en", [("pii.phone", 20, 30)])]
    report = m2(rows, ark, presidio)
    assert report["language"] == "de" and report["families"]["neutral"]["ids"] == ["pii.email"]
    assert report["families"]["neutral"]["holds"]
    # No German gold in presidio_favored: that family does not hold and M2 is not met.
    assert report["families"]["presidio_favored"]["ids"] == [] and not report["families"]["presidio_favored"]["holds"]
    assert report["met"] is False
    assert not m2(rows, ark, presidio, language="all")["families"]["neutral"]["holds"]
    lines = MODULE.m2_lines(report)
    assert "presidio_favored: NO DATA, 0 ids" in lines
    assert lines[-1] == "M2: NOT MET (neutral holds, presidio_favored not met)"


def test_m2_lines_print_macro_f1_target_and_excluded_ids():
    lines = MODULE.m2_lines(m2(*m2_rows()))
    assert lines[0].startswith("ark-l1-scoreboard-v1 M2 (de, exact F1 in %")
    assert "neutral: HOLDS, macro-F1 Ark  83.3 >= target  65.0 (Presidio  50.0 + 15.0 pp), 2 ids" in lines
    assert "presidio_favored: HOLDS, macro-F1 Ark 100.0 >= target 100.0 (Presidio 100.0 + 0.0 pp), 2 ids" in lines
    assert "  pii.phone                            gold    10  Ark  66.7  Presidio   0.0" in lines
    assert "  excluded pii.de.postal_code (presidio_only, gold 3)" in lines
    assert any(line.startswith("ark_authored: NO DATA") and "decides no milestone" in line for line in lines)
    assert lines[-1] == "M2: MET (neutral holds, presidio_favored holds)"


def test_main_m2_subcommand_prints_every_mode_and_exits_1_unless_balanced_holds(tmp_path, capsys):
    # write_tree has no recognizer-test file; the postal-code rows stay out (covered above).
    rows, weak, presidio = m2_rows(neutral_phones=1)
    dirs = write_tree(tmp_path, rows, {"weak": weak, "perfect": perfect(rows), "presidio": presidio})
    base = ["m2", "--gold", str(tmp_path / "gold"), "--presidio", str(dirs["presidio"])]
    args = base + ["--ark", f"strict={dirs['weak']}", "--ark", f"balanced={dirs['perfect']}"]
    assert MODULE.main(args + ["--json", str(tmp_path / "m2.json")]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert "== Ark strict (reported, decides no milestone)" in lines and "== Ark balanced (milestone mode)" in lines
    strict = lines[lines.index("== Ark strict (reported, decides no milestone)"):lines.index("== Ark balanced (milestone mode)")]
    assert any(line.startswith("neutral: NOT MET, macro-F1 Ark  59.1 < target  65.0") for line in strict)
    assert "M2 strict: NOT MET (neutral not met, presidio_favored holds)" in lines
    assert "M2 balanced: MET (neutral holds, presidio_favored holds)" in lines
    assert lines[-1] == "M2: MET (balanced: neutral holds, presidio_favored holds)"
    report = json.loads((tmp_path / "m2.json").read_text())
    assert report["milestone_mode"] == "balanced" and report["met"] is True and report["language"] == "de"
    assert report["modes"]["strict"]["met"] is False
    assert report["modes"]["balanced"]["families"]["neutral"]["margin_pp"] == 15.0
    # Swapped: balanced misses the rule, so m2 exits 1 without any extra flag.
    swapped = base + ["--ark", f"strict={dirs['perfect']}", "--ark", f"balanced={dirs['weak']}"]
    assert MODULE.main(swapped) == 1
    assert capsys.readouterr().out.strip().endswith("M2: NOT MET (balanced: neutral not met, presidio_favored holds)")
    # Balanced is required; modes are named once and must exist.
    assert MODULE.main(base + ["--ark", f"strict={dirs['perfect']}"]) == 2
    assert MODULE.main(base + ["--ark", f"balanced={dirs['perfect']}"]) == 0
    assert MODULE.main(base + ["--ark", f"balanced={dirs['perfect']}", "--ark", f"fast={dirs['weak']}"]) == 2
    (dirs["weak"] / "g.jsonl").unlink()
    assert MODULE.main(swapped) == 2


# ── baseline report ──────────────────────────────────────────────────────


def write_report_tree(tmp_path):
    """Gold in three frozen directories plus Ark strict/balanced and Presidio default/tuned predictions."""
    rows, ark, tuned = m1_rows()
    rows.append(gold("ark-hn", [], corpus=SYNTH, language="de", hard_negatives=[(40, 50)]))
    ark.append(pred("ark-hn", []))
    tuned.append(pred("ark-hn", [("pii.phone", 40, 50)]))
    default = [pred(row["id"], []) for row in rows]
    return write_tree(tmp_path, rows, {"ark": ark, "balanced": perfect(rows), "default": default, "tuned": tuned})


def test_report_scores_every_engine_per_family_corpus_and_entity(tmp_path):
    engines = write_report_tree(tmp_path)
    ark = {"strict": engines["ark"], "balanced": engines["balanced"]}
    report = MODULE.baseline_report(tmp_path / "gold", ark, {"presidio-tuned": engines["tuned"]}, EMAP)
    assert list(report["engines"]) == ["ark-strict", "ark-balanced", "presidio-tuned"]
    strict, tuned = report["engines"]["ark-strict"], report["engines"]["presidio-tuned"]
    assert strict["buckets"]["family/neutral"] == {"gold": 20, "predicted": 15, "exact": 15, "gold_found": 15,
                                                   "predicted_correct": 15}
    assert strict["buckets"][f"corpus/{GRETEL}"] == strict["buckets"]["family/neutral"]
    assert report["engines"]["ark-balanced"]["buckets"]["family/neutral"]["exact"] == 20
    # Hard-negative hits are attributed to the family of their row.
    assert report["hard_negative_fp"] == {"ark-strict": {}, "ark-balanced": {}, "presidio-tuned": {"ark_authored": 1}}
    assert tuned["buckets"]["family/ark_authored"]["predicted"] == 20
    # M1 compares every Ark mode with every Presidio profile; the milestone is read from balanced.
    assert report["milestone_mode"] == "balanced"
    assert list(report["m1"]) == ["presidio-tuned"]
    m1 = report["m1"]["presidio-tuned"]
    assert m1["modes"]["strict"]["families"]["presidio_favored"]["holds"] and not m1["modes"]["strict"]["met"]
    assert m1["modes"]["balanced"]["met"] and m1["met"]
    # M2 likewise per profile and mode; these rows carry no German gold, so no family holds.
    m2 = report["m2"]["presidio-tuned"]
    assert m2["language"] == "de" and m2["met"] is False and set(m2["modes"]) == {"strict", "balanced"}
    with pytest.raises(MODULE.ScoreboardError, match="balanced"):
        MODULE.baseline_report(tmp_path / "gold", {"strict": engines["ark"]}, {"presidio-tuned": engines["tuned"]}, EMAP)
    with pytest.raises(MODULE.ScoreboardError, match="Presidio"):
        MODULE.baseline_report(tmp_path / "gold", ark, {}, EMAP)


def test_report_markdown_tables(tmp_path):
    engines = write_report_tree(tmp_path)
    report = MODULE.baseline_report(
        tmp_path / "gold",
        {"strict": engines["ark"], "balanced": engines["balanced"]},
        {"presidio-default": engines["default"], "presidio-tuned": engines["tuned"]},
        EMAP,
    )
    lines = MODULE.report_lines(report)
    text = "\n".join(lines)
    assert "| Family | Engine | Rows | Gold | Pred | Exact P | Exact R | Exact F1 | Overlap F1 | EN F1 | DE F1 | HN-FP |" in lines
    assert "| neutral | ark-strict | 10 | 20 | 15 | 100.0 | 75.0 | 85.7 | 85.7 | 85.7 | – | 0 |" in lines
    assert "| neutral | ark-balanced | 10 | 20 | 20 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | – | 0 |" in lines
    assert "| ark_authored ¹ | presidio-tuned | 11 | 20 | 20 | 95.0 | 95.0 | 95.0 | 95.0 | 97.4 | 0.0 | 1 |" in lines
    assert (f"| {GRETEL} | neutral | 10 | 20 | 100.0 / 75.0 / 85.7 | 100.0 / 100.0 / **100.0** | 0.0 / 0.0 / 0.0 | "
            "100.0 / 95.0 / 97.4 |") in lines
    # Per entity: exact F1 per engine, the best one in bold, shared ids marked.
    assert "| neutral | pii.phone | shared | 10 | 66.7 | **100.0** | 0.0 | **100.0** |" in lines
    assert "| presidio_favored | pii.email | shared | 10 | **100.0** | **100.0** | 0.0 | 94.7 |" in lines
    # M1 per Ark mode and milestone family against each Presidio profile; balanced decides.
    assert "| Ark mode | Profile | M1 | neutral | presidio_favored | ark_authored ¹ |" in lines
    assert "| balanced | presidio-default | MET | 2/2 | 2/2 | 2/2 |" in lines
    assert "| balanced | presidio-tuned | MET | 2/2 | 2/2 | 2/2 |" in lines
    assert "| strict ² | presidio-tuned | NOT MET | 1/2 (below: pii.phone) | 2/2 | 1/2 (below: pii.phone) |" in lines
    assert "| strict ² | presidio-default | MET | 2/2 | 2/2 | 2/2 |" in lines
    assert lines.index("| balanced | presidio-tuned | MET | 2/2 | 2/2 | 2/2 |") < lines.index(
        "| strict ² | presidio-tuned | NOT MET | 1/2 (below: pii.phone) | 2/2 | 1/2 (below: pii.phone) |")
    assert "¹ ark_authored is reported and decides no milestone." in text
    assert "² reported; milestones are judged on balanced (T15)." in text
    # M2 per Ark mode and profile: DE rows, macro-F1 over shared + ark_only ids; no German gold here.
    assert "| Ark mode | Profile | M2 | neutral | presidio_favored | ark_authored ¹ |" in lines
    assert "| balanced | presidio-tuned | NOT MET | no data | no data | no data |" in lines
    assert "| strict ² | presidio-default | NOT MET | no data | no data | no data |" in lines


def test_report_m2_cells_show_macro_f1_and_target(tmp_path):
    rows, ark, presidio = m2_rows()
    dirs = write_tree(tmp_path, rows, {"ark": ark, "tuned": presidio})
    report = MODULE.baseline_report(tmp_path / "gold", {"balanced": dirs["ark"]}, {"presidio-tuned": dirs["tuned"]}, EMAP)
    assert ("| balanced | presidio-tuned | MET | 83.3 vs 65.0 (50.0 + 15), 2 ids | 100.0 vs 100.0 (100.0 + 0), 2 ids "
            "| no data |") in MODULE.report_lines(report)


def test_main_report_subcommand(tmp_path, capsys):
    engines = write_report_tree(tmp_path)
    args = ["report", "--gold", str(tmp_path / "gold"), "--ark", f"strict={engines['ark']}",
            "--ark", f"balanced={engines['balanced']}", "--engine", f"presidio-tuned={engines['tuned']}"]
    assert MODULE.main(args + ["--json", str(tmp_path / "report.json")]) == 0
    out = capsys.readouterr().out
    assert out.startswith("## ") and "| neutral | ark-strict |" in out and "## Gold gaps" in out
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["m1"]["presidio-tuned"]["met"] is True
    assert report["m1"]["presidio-tuned"]["modes"]["strict"]["met"] is False
    assert MODULE.main(args + ["--engine", "broken"]) == 2
    assert MODULE.main(args + ["--engine", f"presidio-tuned={engines['default']}"]) == 2
    assert MODULE.main(args + ["--engine", f"ark-strict={engines['default']}"]) == 2
    assert MODULE.main(args + ["--ark", f"balanced={engines['default']}"]) == 2
    (engines["tuned"] / "g.jsonl").unlink()
    assert MODULE.main(args) == 2


# ── gold gaps (T16) ──────────────────────────────────────────────────────


def annotated(row_id, text, items, corpus=GRETEL, language="en"):
    """A gold row with real text; items are (label, value, occurrence) and annotate that occurrence."""
    entities = []
    for label, value, occurrence in items:
        start = -1
        for _ in range(occurrence + 1):
            start = text.index(value, start + 1)
        entities.append({"entity_type": label, "start": start, "end": start + len(value)})
    return {"id": row_id, "corpus": corpus, "language": language, "text": text, "entities": entities}


def spans_of(row_id, text, items):
    """Prediction row for (label, value, occurrence) items."""
    spans = []
    for label, value, occurrence in items:
        start = -1
        for _ in range(occurrence + 1):
            start = text.index(value, start + 1)
        spans.append((label, start, start + len(value)))
    return pred(row_id, spans)


MAIL_TEXT = "Contact [ann@bank.example](mailto:ann@bank.example), cc ann@bank.example or bob@bank.example."
LINK_TEXT = "Write to [cy@bank.example](mailto:cy@bank.example) today."
CARD_TEXT = "Cards 4111 1111 1111 1111 and 4111 1111 1111 1112, IBAN DE89370400440532013000 / DE89370400440532013001."


def gap_rows():
    rows = [
        # Gretel annotates one copy of the markdown mail link only.
        annotated("mail", MAIL_TEXT, [("pii.email", "ann@bank.example", 0)]),
        # Gretel's span includes the link bracket: the inner value is a boundary error, the mailto copy a gap.
        annotated("link", LINK_TEXT, [("pii.email", "[cy@bank.example]", 0)]),
        annotated("card", CARD_TEXT, [("pii.credit_card.pan", "4111 1111 1111 1111", 0),
                                      ("pii.credit_card.pan", "4111 1111 1111 1112", 0),
                                      ("pii.iban", "DE89370400440532013000", 0),
                                      ("pii.iban", "DE89370400440532013001", 0)]),
    ]
    ark = [
        spans_of("mail", MAIL_TEXT, [("pii.email", "ann@bank.example", i) for i in range(3)]
                 + [("pii.email", "bob@bank.example", 0), ("pii.phone", "ann@bank.example", 1)]),
        spans_of("link", LINK_TEXT, [("pii.email", "cy@bank.example", i) for i in range(2)]),
        spans_of("card", CARD_TEXT, [("pii.credit_card.pan", "4111 1111 1111 1111", 0),
                                     ("pii.iban", "DE89370400440532013000", 0)]),
    ]
    presidio = [
        spans_of("mail", MAIL_TEXT, [("pii.email", "ann@bank.example", 1)]),
        spans_of("link", LINK_TEXT, [("pii.email", "[cy@bank.example]", 0)]),
        spans_of("card", CARD_TEXT, [("pii.credit_card.pan", "4111 1111 1111 1112", 0),
                                     ("pii.iban", "DE89370400440532013001", 0)]),
    ]
    return rows, ark, presidio


def test_gold_gaps_count_duplicate_values_and_checksum_invalid_gold():
    rows, ark, presidio = gap_rows()
    gaps = MODULE.gold_gaps(rows, ark, EMAP)[GRETEL]
    # Two further copies of the annotated value count, and the mailto copy of the bracketed link value;
    # bob@ is an ordinary FP, the value inside the gold bracket a boundary error, and a phone span on
    # the e-mail value is another id.
    assert gaps["pii.email"] == {"gold": 2, "gold_invalid": None, "invalid_found": None, "duplicate_fp": 3}
    assert gaps["pii.credit_card.pan"] == {"gold": 2, "gold_invalid": 1, "invalid_found": 0, "duplicate_fp": 0}
    assert gaps["pii.iban"] == {"gold": 2, "gold_invalid": 1, "invalid_found": 0, "duplicate_fp": 0}
    assert "pii.phone" not in gaps
    # Gold on the mailto copy: the bracketed copy is the gap.
    text = "Mail [dee@bank.example](mailto:dee@bank.example)"
    mailto = [annotated("m", text, [("pii.email", "mailto:dee@bank.example", 0)])]
    gaps = MODULE.gold_gaps(mailto, [spans_of("m", text, [("pii.email", "dee@bank.example", i) for i in range(2)])], EMAP)
    assert gaps[GRETEL]["pii.email"]["duplicate_fp"] == 1
    gaps = MODULE.gold_gaps(rows, presidio, EMAP)[GRETEL]
    assert gaps["pii.email"]["duplicate_fp"] == 1
    assert gaps["pii.credit_card.pan"]["invalid_found"] == 1 and gaps["pii.iban"]["invalid_found"] == 1


def test_gold_gaps_follow_the_scored_ids_of_a_row():
    text = "Card 4111 1111 1111 1112 for ann@bank.example and ann@bank.example"
    row = annotated("r", text, [("pii.credit_card.pan", "4111 1111 1111 1112", 0), ("pii.email", "ann@bank.example", 0)],
                    corpus=RECOGNIZER_TESTS)
    row["scored_entities"] = ["pii.credit_card.pan"]
    gaps = MODULE.gold_gaps([row], [spans_of("r", text, [("pii.email", "ann@bank.example", 1)])], EMAP)
    assert gaps == {RECOGNIZER_TESTS: {"pii.credit_card.pan": {"gold": 1, "gold_invalid": 1, "invalid_found": 0,
                                                               "duplicate_fp": 0}}}


def test_gold_gaps_change_no_metric(tmp_path):
    rows, ark, presidio = gap_rows()
    dirs = write_tree(tmp_path, rows, {"strict": ark, "balanced": ark, "tuned": presidio})
    report = MODULE.baseline_report(tmp_path / "gold", {"strict": dirs["strict"], "balanced": dirs["balanced"]},
                                    {"presidio-tuned": dirs["tuned"]}, EMAP)
    assert report["engines"]["ark-strict"] == MODULE.score_rows(rows, ark, EMAP, "g.jsonl")
    assert report["engines"]["presidio-tuned"] == MODULE.score_rows(rows, presidio, EMAP, "g.jsonl")
    gaps = report["gold_gaps"]
    assert gaps["validators"]["pii.iban"] == ["mod97"]
    email = gaps["corpora"][GRETEL]["pii.email"]
    assert email["gold"] == 2 and email["gold_invalid"] is None
    assert email["engines"] == {"ark-strict": {"duplicate_fp": 3, "invalid_found": None},
                                "ark-balanced": {"duplicate_fp": 3, "invalid_found": None},
                                "presidio-tuned": {"duplicate_fp": 1, "invalid_found": None}}
    lines = MODULE.report_lines(report)
    assert "## Gold gaps (reported only; no metric changes, T16)" in lines
    assert "| Corpus | Entity | Gold | ark-strict | ark-balanced | presidio-tuned |" in lines
    assert f"| {GRETEL} | pii.email | 2 | 3 | 3 | 1 |" in lines
    assert "| Corpus | Entity | Validator | Gold | Invalid | ark-strict | ark-balanced | presidio-tuned |" in lines
    assert f"| {GRETEL} | pii.credit_card.pan | payment_card | 2 | 1 | 0 | 0 | 1 |" in lines
    assert f"| {GRETEL} | pii.iban | mod97 | 2 | 1 | 0 | 0 | 1 |" in lines


def test_gold_validators_cover_every_checksum_validator():
    validators = MODULE.gold_validators(EMAP)
    assert validators["pii.iban"] == ("mod97",)
    assert validators["pii.credit_card.pan"] == ("payment_card",)
    assert validators["pii.de.tax_id"] == ("steuer_id", "steuer_id_issued")
    assert validators["pii.de.vat_id"] == ("de_vat_id",)
    assert validators["pii.it.vat_code"] == ("it_vat_id",)
    assert validators["entity.passport_number"] == ("de_passport_number",)
    assert validators["pii.identity_card_number"] == ("de_identity_card_number",)
    rules = MODULE.count_validated_module().load_rules()
    checksum = {name for name, rule in rules.ark.items() if rule is not None}
    # A task that adds a checksum validator ports it to CHECKSUM_PORTS for the gold-gap report.
    assert checksum <= set(MODULE.CHECKSUM_PORTS), sorted(checksum - set(MODULE.CHECKSUM_PORTS))
    assert {v for ids in validators.values() for v in ids} <= checksum


@pytest.mark.parametrize("name,valid,invalid", [
    ("luhn", ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"],
     ["4111111111111112", "4111 1111 1111 1112", "49 89 2019 4401", "0151 2345 6789 02", "00000000000000", "4242"]),
    # B-PAN: Luhn plus IIN prefix and length per brand; birth-date IDs and stamps are no card.
    ("payment_card", ["4111111111111111", "4111 1111 1111 1111", "3773 149258 60736", "36731492586076",
                      "507314925862", "2200731492586072", "6273149258607314922", "122000000000003",
                      "4047737215142"],
     ["4111111111111112", "44 20 1234 5678", "1748503543012", "3473149258607313", "2721731492586072",
      "4506095123081", "470312-1081835", "202201010800", "199912312359596", "0157-09-316-8811", "4242"]),
    ("mod97", ["DE89370400440532013000", "DE89 3704 0044 0532 0130 00", "GB82WEST12345698765432"],
     ["DE89370400440532013001", "DE00370400440532013000", "DE18 4306 0967 1234 5678 01", "GB82WEST12345698765433",
      "DE8"]),
    ("steuer_id", ["86095742719", "86 095 742 719", "12345678903"],
     ["86095742718", "06095742719", "8609574271", "860957427190"]),
    ("steuer_id_issued", ["86095742719", "86 095 742 719"],
     ["86095742718", "12345678903", "47110815008", "86555742194", "11111111111"]),
    # B01: VAT IDs per country (rust/tests/pii_vat_id.rs).
    ("de_vat_id", ["DE136695976", "DE 136 695 976", "DE.136.695.976", "DE123456788"],
     ["DE136695977", "DE987654321", "DE100000001", "DE036695976", "DE13669597", "ATU13585627"]),
    ("at_vat_id", ["ATU13585627", "ATU 13585627", "ATU68044369"],
     ["ATU13585626", "ATU00000000", "AT13585627", "DE136695976"]),
    ("ch_vat_id", ["CHE-100.155.212", "CHE100155212", "CHE 100 155 212", "CHE-712.368.516"],
     ["CHE-100.155.213", "CHE-000.000.001", "CHE-100.155.21"]),
    ("fr_vat_id", ["FR40303265045", "FR 40 303 265 045", "FR78610357972"],
     ["FR41303265045", "FR40303265046", "FR43303265046", "FR12345678901"]),
    ("nl_vat_id", ["NL004495445B01", "NL000099998B57", "NL434938713B02"],
     ["NL004495446B01", "NL004495445B00", "NL000000000B01", "NL004495445X01"]),
    ("be_vat_id", ["BE0403019261", "BE 0403.019.261", "BE0776091951"],
     ["BE0403019262", "BE1403019261", "BE0000000097", "BE2403019261"]),
    ("it_vat_id", ["IT00743110157", "00743110157", "01333550323", "IT24442930335"],
     ["IT00743110158", "IT00000000000", "IT12345670009", "IT12345675008", "0074311015"]),
    ("es_vat_id", ["ESA13585625", "ESX5253868R", "ES54362315K", "ESB58378431", "ESM1234567L"],
     ["ESA13585626", "ESX5253868Q", "ES54362315L", "ESI1234567L"]),
    # B02: VAT IDs part 2 (rust/tests/pii_vat_id_part2.rs).
    ("bg_vat_id", ["BG175074752", "BG 175074752", "BG436687597", "BG9111146569", "BG2852728877", "BG0326991023"],
     ["BG175074751", "BG436687598", "BG9111146566", "BG000000000", "BG17507475", "CY10259033P"]),
    ("cy_vat_id", ["CY10259033P", "CY-10259033P", "CY 10259033P", "CY18715842G"],
     ["CY10259033Z", "CY12945807E", "CY00000000E", "CY102590331", ""]),
    ("cz_vat_id", ["CZ25123891", "CZ 25123891", "CZ640903926", "CZ7103192745", "CZ69170100"],
     ["CZ25123890", "CZ92193081", "CZ640903927", "CZ7103192746", "CZ4538323647", "CZ401231123"]),
    ("dk_vat_id", ["DK13585628", "DK 13 58 56 28", "DK77384235"], ["DK13585627", "DK02061597", "DK00000000"]),
    ("ee_vat_id", ["EE100931558", "EE 100931558", "EE100594102"], ["EE100931559", "EE347140694", "EE000000000"]),
    ("el_vat_id", ["EL094259216", "EL 094259216", "GR094259216", "EL009331143"],
     ["EL094259217", "EL123456781", "EL000000000", "ES094259216"]),
    ("fi_vat_id", ["FI20774740", "FI 20774740", "FI58392596"], ["FI20774741", "FI00000000", "FI2077474"]),
    ("hr_vat_id", ["HR33392005961", "HR 33392005961", "HR93154366775"], ["HR33392005962", "HR00000000000"]),
    ("hu_vat_id", ["HU12892312", "HU-12892312", "HU 12892312"], ["HU12892313", "HU00000000"]),
    ("ie_vat_id", ["IE6433435F", "IE 6433435F", "IE6433435OA", "IE8D79739I", "IE2710022OH",
                   "IE8*79739I", "IE 8+79739I"],
     ["IE6433435E", "IE6433435OB", "IE8D79739J", "IE0000000W", "IE6433435", "IE6433435FX", "IE8*79739J",
      "IE8+7973I", "IE6433435*", "IE64334+5F"]),
    ("lt_vat_id", ["LT119511515", "LT 119511515", "LT500326715", "LT100001919017", "LT100004801610"],
     ["LT119511516", "LT018800102", "LT100001919018", "LT1195115150"]),
    # B16: VAT IDs part 3 (rust/tests/pii_vat_id.rs).
    ("lu_vat_id", ["LU15027442", "LU 15027442", "LU08424551"], ["LU15027443", "LU00000001", "LU1502744"]),
    ("lv_vat_id", ["LV40003521600", "LV 40003521600", "LV71890053205"],
     ["LV40003521601", "LV16117519997", "LV4000352160"]),
    ("mt_vat_id", ["MT11679112", "MT 1167-9112", "MT33016035"], ["MT11679113", "MT09722003", "MT1167911"]),
    ("pl_vat_id", ["PL8567346215", "PL 856-734-62-15", "PL 856-73-46-215"],
     ["PL8567346216", "PL5709301372", "PL856734621"]),
    ("pt_vat_id", ["PT501964843", "PT 501 964 843", "PT392644339"], ["PT501964842", "PT006132677", "PT50196484"]),
    ("ro_vat_id", ["RO18547290", "RO 18547290", "RO1590082"],
     ["RO18547291", "RO0185472", "RO1630615123457", "RO1"]),
    ("se_vat_id", ["SE123456789701", "SE556677889901", "SE 556677-889901"],
     ["SE123456789101", "SE123456789702", "SE1234567897"]),
    ("si_vat_id", ["SI50223054", "SI 5022 3054", "SI73570800"], ["SI50223055", "SI37315871", "SI07978707"]),
    ("sk_vat_id", ["SK2022749619", "SK 202 274 96 19", "SK3387441728"],
     ["SK2022749618", "SK8110629857", "SK202274961"]),
    ("no_vat_id", ["NO995525828MVA", "NO 995 525 828 MVA", "NO911887517MVA"],
     ["NO995525829MVA", "NO995525828", "NO99552582MVA"]),
    ("gb_vat_id", ["GB980780684", "GB 980 7806 84", "GB 980 7806 84 001", "XI 980 7806 84", "GB218960684"],
     ["GB802311781", "GB980780685", "GB009537909", "GB447009415", "GBGD001", "XI98078068"]),
    # F08: German passport and identity card, ICAO 9303 7-3-1 (rust/tests/pii_document_numbers.rs).
    ("de_passport_number", ["C01X00T41", "F12345671", "c01234565", "C01X00T478", "CF21823027", "1220001297"],
     ["C01X00T42", "C01X00T47", "L01X00T44", "C01X00T479", "1220001298", "0000000000", "B01X00T41",
      "C01A00T41", "C01x00T41", "C01X00T4", "122000129"]),
    ("de_identity_card_number", ["L01X00T44", "l01x00t44", "X12345677", "T220001293", "L01X00T471", "1220001297"],
     ["L01X00T45", "T22000129", "C01X00T41", "T220001294", "1220001298", "0000000000", "D12345675",
      "L01x00T44", "L01X00T4", "L01X00T4711"]),
    # B-UK: NHS number, weighted mod 11 (rust/tests/pii_uk.rs).
    ("uk_nhs_number", ["9434765919", "943 476 5919", "943-476-5919", "4526018155", "6351819091"],
     ["9434765918", "4526018156", "1234567890", "0000000000", "4444444444", "943476591", "94347659190",
      "943 476 591X", "943/476/5919"]),
])
def test_checksum_ports_match_the_rust_vectors(name, valid, invalid):
    check = MODULE.CHECKSUM_PORTS[name]
    assert all(check(value) for value in valid), [v for v in valid if not check(v)]
    assert not any(check(value) for value in invalid), [v for v in invalid if check(v)]


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
        for bucket in ("all", "language/de", "entity/pii.email", "family/ark_authored")
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
# Fake run_ark.py: predicts every gold entity except those whose id is in DROP (a list for every
# PII mode or a mapping mode -> list) and records the mode like run_ark.py.
DROP = {drop!r}
p = argparse.ArgumentParser()
p.add_argument("--input"); p.add_argument("--output"); p.add_argument("--meta")
p.add_argument("--pii-mode", default="strict")
a = p.parse_args()
drop = DROP.get(a.pii_mode, []) if isinstance(DROP, dict) else DROP
with open(a.input) as src, open(a.output, "w") as out:
    for line in src:
        row = json.loads(line)
        spans = [] if row["id"] in drop else [
            {{"label": e["entity_type"], "start_char": e["start"], "end_char": e["end"], "score": 1.0}}
            for e in row["entities"]
        ]
        out.write(json.dumps({{"id": row["id"], "language": row["language"], "evidence_spans": spans}}) + "\\n")
engine = {{}} if a.pii_mode == "strict" else {{"pii_mode": a.pii_mode}}
open(a.meta, "w").write(json.dumps({{"engine": engine}}))
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
    # Both PII modes are scored for both splits; milestones are read from balanced (T15).
    assert report["milestone_mode"] == "balanced"
    assert list(report["modes"]) == ["strict", "balanced"]
    assert all(set(splits) == {"dev", "holdout"} for splits in report["modes"].values())
    # Results are stored per commit (both modes), predictions per source key and mode.
    results = tmp_path / "cache" / "scoreboard" / "results"
    assert {p.stem for p in results.iterdir()} == {base, run_git(repo, "rev-parse", "HEAD")}
    stored = json.loads((results / f"{base}.json").read_text())
    assert set(stored["modes"]) == {"strict", "balanced"} and set(stored["modes"]["balanced"]) == {"dev", "holdout"}
    predictions = tmp_path / "cache" / "scoreboard" / "predictions" / report["head_source_key"]
    # strict keeps the layout from before T15, so cached strict predictions stay valid.
    assert len(list(predictions.glob("*.jsonl"))) == 2 and len(list((predictions / "balanced").glob("*.jsonl"))) == 2
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
    for mode in ("strict", "balanced"):
        assert any(line.startswith(f"  {mode} holdout entity/pii.iban exact F1 100.0 -> ") for line in lines)
        assert report["modes"][mode]["dev"]["compare"]["regressions"] == []
    # Holdout row ids never reach stdout.
    assert not any("h0" in line or "h1" in line for line in lines)
    # Per-entity tables are printed for dev only, one per mode.
    assert not any("pii.iban" in line for line in lines if not line.startswith(("  strict holdout", "  balanced holdout")))
    assert "dev per entity, strict (head; Δ vs base in pp):" in lines
    assert "dev per entity, balanced (head; Δ vs base in pp):" in lines
    # Aggregates per mode and source family for both splits; the family regression is named, the rows are not.
    assert any(line.startswith("  strict dev ark_authored") and "decides no milestone" in line for line in lines)
    assert any(line.startswith("  balanced holdout neutral") and "L1 F1 88.9/88.9 (-11.1/-11.1)" in line for line in lines)
    assert any(line.startswith("  balanced holdout family/neutral exact F1 100.0 -> ") for line in lines)
    assert any(line.startswith("balanced holdout rows    10") for line in lines)


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
    for mode in ("strict", "balanced"):
        assert len(report["modes"][mode]["dev"]["compare"]["new_hard_negative_fp"]) == 10
        assert f"  {mode} dev new hard-negative FP: pii.phone 10" in lines


@pytest.mark.parametrize("mode", ["strict", "balanced"])
def test_gate_fails_on_a_regression_in_either_mode(repo, data, tmp_path, mode):
    base = run_git(repo, "rev-parse", "HEAD")
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop={mode: ["h0", "h1"]})}, "worse")
    lines, regressed, report = Builds(repo, tmp_path).gate(base, data, tmp_path / "cache")
    assert regressed and lines[-1] == "RESULT: REGRESSION"
    other = "balanced" if mode == "strict" else "strict"
    assert report["modes"][mode]["holdout"]["compare"]["regressions"]
    assert report["modes"][other]["holdout"]["compare"]["regressions"] == []
    assert any(line.startswith(f"  {mode} holdout entity/pii.iban") for line in lines)
    assert not any(line.startswith(f"  {other} holdout entity/") for line in lines)


def test_gate_balanced_gain_does_not_hide_a_strict_loss(repo, data, tmp_path):
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop={"balanced": ["h0", "h1"]})}, "weak")
    weak = run_git(repo, "rev-parse", "HEAD")
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": FAKE_RUN_ARK.format(drop={"strict": ["h0"]})}, "trade")
    lines, regressed, report = Builds(repo, tmp_path).gate(weak, data, tmp_path / "cache")
    assert regressed
    assert report["modes"]["strict"]["holdout"]["compare"]["regressions"]
    assert report["modes"]["balanced"]["holdout"]["compare"]["regressions"] == []


def test_gate_rejects_a_runner_that_ignores_the_pii_mode(repo, data, tmp_path):
    # A run_ark.py without --pii-mode support (meta without engine.pii_mode) must not pass as balanced.
    legacy = FAKE_RUN_ARK.format(drop=[]).replace('engine = {} if a.pii_mode == "strict" else {"pii_mode": a.pii_mode}',
                                                  "engine = {}")
    assert legacy != FAKE_RUN_ARK.format(drop=[])
    base = run_git(repo, "rev-parse", "HEAD")
    commit_files(repo, {"scripts/l1_presidio/run_ark.py": legacy}, "legacy")
    with pytest.raises(MODULE.ScoreboardError, match="balanced"):
        Builds(repo, tmp_path).gate(base, data, tmp_path / "cache")


def test_run_predictions_passes_the_pii_mode(tmp_path):
    script = tmp_path / "run_ark.py"
    script.write_text(FAKE_RUN_ARK.format(drop={"balanced": ["a"]}))
    write_jsonl(tmp_path / "g.jsonl", [gold("a", [("pii.email", 0, 10)])])
    build = MODULE.ArkBuild(sys.executable, script, {}, None)
    for mode, spans in (("strict", 1), ("balanced", 0)):
        output = tmp_path / f"{mode}.jsonl"
        MODULE.run_predictions(build, tmp_path / "g.jsonl", output, mode)
        assert len(MODULE.read_jsonl(output)[0]["evidence_spans"]) == spans


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
    # One build per side serves both modes.
    assert builds.base_builds == [base] and builds.head_builds == 1
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
