from __future__ import annotations

import copy
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "entity_map.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_entity_map", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

CLASSES = MODULE.taxonomy.CLASSES
TAXONOMY = {"classes": {name: {"families": [{"id": "fam_a"}, {"id": "fam_b"}]} for name in CLASSES}}
INVENTORY = {
    "sources": [{"id": "src"}],
    "rules": [
        {"source": "src", "id": "r1", "class": "jailbreak", "mapping": "hint"},
        {"source": "src", "id": "r2", "class": None, "mapping": "out_of_scope"},
        {"source": "src", "id": "r3", "class": None, "mapping": "handoff"},
    ],
}


def dataset(dataset_id, **overrides):
    entry = {
        "id": dataset_id,
        "name": dataset_id,
        "source": f"hf:example/{dataset_id}",
        "licence": "MIT",
        "languages": ["de", "en"],
        "split": "holdout",
        "family": "neutral",
        "labels": [
            {"label": "attack", "classes": list(CLASSES)},
            {"label": "benign", "benign": True},
        ],
    }
    entry.update(overrides)
    return entry


def minimal_map():
    baselines = [{"id": name, "kind": "heuristic", "rules": "src"} for name in MODULE.taxonomy.BASELINES]
    for baseline in baselines:
        if baseline["id"] == "protectai_v2":
            baseline.clear()
            baseline.update(
                {
                    "id": "protectai_v2",
                    "kind": "reference",
                    "model": "protectai-v2/onnx",
                    "labels": [
                        {"label": "INJECTION", "classes": ["instruction_injection"]},
                        {"label": "SAFE", "benign": True},
                    ],
                    "trained_on": [],
                }
            )
    return {"schema": MODULE.SCHEMA, "baselines": baselines, "datasets": [dataset("pub")], "gaps": []}


def problems(entity_map, inventory=INVENTORY):
    return MODULE.check(entity_map, inventory=inventory, tax=TAXONOMY)


def test_minimal_map_is_clean():
    assert problems(minimal_map()) == []


def test_repository_map_is_clean():
    entity_map = MODULE.load()
    assert MODULE.check(entity_map, inventory=MODULE.oss_inventory.load(), tax=MODULE.taxonomy.load()) == []


def test_repository_map_ark_blind_decides_only_without_neutral_data():
    decided = MODULE.decisions(MODULE.load())
    assert decided[("instruction_injection", "en")][0] == "neutral"
    assert decided[("instruction_injection", "de")][0] == "ark_blind"
    assert decided[("toxic_language", "de")][0] == "neutral"
    assert decided[("memory_poisoning", "en")][0] == "ark_blind"
    # The CyberSecEval leak slice is reported only; the Tensor Trust extraction benchmark
    # is the neutral set that decides EN extraction.
    assert decided[("prompt_extraction", "en")][0] == "neutral"


def test_repository_map_keeps_toxicity_out_of_harmful_content():
    # harmful_content.md §2: hate, insults and profanity belong to toxic_language, not to harm requests.
    datasets = {entry["id"]: entry for entry in MODULE.load()["datasets"]}
    ptp = {label["label"]: label.get("classes") for label in datasets["ptp_wildchat_de"]["labels"]}
    assert ptp["prompt toxicity (Perspective) >= 0.5"] == ["toxic_language"]
    for label in datasets["aya_redteaming"]["labels"]:
        if "harmful_content" in label.get("classes", []):
            for toxic in ("Hate Speech", "Profanity", "Bullying & Harassment"):
                assert toxic not in label["label"]


def test_neutral_wins_over_ark_blind():
    entity_map = minimal_map()
    entity_map["datasets"].append(dataset("blind", family="ark_blind"))
    assert problems(entity_map) == []
    assert MODULE.decisions(entity_map)[("jailbreak", "de")] == ("neutral", ["pub"])


def test_ark_blind_decides_where_neutral_lacks_the_language():
    entity_map = minimal_map()
    entity_map["datasets"] = [
        dataset("pub", languages=["en"]),
        dataset("blind", family="ark_blind", languages=["de"]),
        dataset("wiki", languages=["de"], labels=[{"label": "article", "benign": True}]),
    ]
    assert problems(entity_map) == []
    assert MODULE.decisions(entity_map)[("jailbreak", "de")] == ("ark_blind", ["blind"])
    assert MODULE.decisions(entity_map)[("jailbreak", "en")] == ("neutral", ["pub"])


def test_train_dev_and_report_data_never_decide():
    entity_map = minimal_map()
    entity_map["datasets"] = [
        dataset("pub", languages=["en"]),
        dataset("dev", languages=["de"], split="train_dev"),
        dataset("noisy", languages=["de"], split="report", family="report_only"),
    ]
    found = problems(entity_map)
    assert "jailbreak/de: no neutral or ark_blind holdout data and no gap entry" in found
    assert "language de: no neutral benign pool" in found


def test_gap_entry_covers_undecided_pair_and_fails_when_decided():
    entity_map = minimal_map()
    entity_map["datasets"][0]["labels"][0]["classes"] = [name for name in CLASSES if name != "memory_poisoning"]
    assert problems(entity_map) == [
        "memory_poisoning/de: no neutral or ark_blind holdout data and no gap entry",
        "memory_poisoning/en: no neutral or ark_blind holdout data and no gap entry",
    ]
    entity_map["gaps"] = [
        {"class": "memory_poisoning", "language": "de", "reason": "no data"},
        {"class": "memory_poisoning", "language": "en", "reason": "no data"},
        {"class": "jailbreak", "language": "en", "reason": "stale"},
    ]
    assert problems(entity_map) == ["gap jailbreak/en is decided by neutral (pub)"]


def test_decides_false_keeps_a_label_reported_only():
    entity_map = minimal_map()
    entity_map["datasets"][0]["labels"].append(
        {"label": "small", "classes": ["jailbreak"], "decides": False, "reason": "too small"}
    )
    entity_map["datasets"][0]["labels"][0]["classes"].remove("jailbreak")
    found = problems(entity_map)
    assert "jailbreak/de: no neutral or ark_blind holdout data and no gap entry" in found
    entity_map["datasets"][0]["labels"][-1].pop("reason")
    assert "dataset pub [small]: decides: false needs a reason" in problems(entity_map)


def test_label_needs_exactly_one_outcome():
    entity_map = minimal_map()
    labels = entity_map["datasets"][0]["labels"]
    labels.append({"label": "both", "benign": True, "out_of_scope": "x"})
    labels.append({"label": "none"})
    labels.append({"label": "empty reason", "out_of_scope": ""})
    labels.append({"label": "bad handoff", "handoff": "dlp"})
    found = problems(entity_map)
    assert "dataset pub [both]: needs exactly one of classes, benign, out_of_scope, handoff, has benign, out_of_scope" in found
    assert "dataset pub [none]: needs exactly one of classes, benign, out_of_scope, handoff, has none" in found
    assert "dataset pub [empty reason]: out_of_scope needs a reason" in found
    assert "dataset pub [bad handoff]: handoff 'dlp' is not one of shell_command" in found


def test_unknown_class_and_family_fail():
    entity_map = minimal_map()
    labels = entity_map["datasets"][0]["labels"]
    labels.append({"label": "old", "classes": ["prompt_injection"]})
    labels.append({"label": "fam", "classes": ["jailbreak"], "family": "nope"})
    labels.append({"label": "two", "classes": ["jailbreak", "exfiltration"], "family": "fam_a"})
    labels.append({"label": "ok", "classes": ["jailbreak"], "family": "fam_a"})
    assert problems(entity_map) == [
        "dataset pub [old]: unknown class prompt_injection",
        "dataset pub [fam]: nope is not a family of jailbreak in taxonomy.yaml",
        "dataset pub [two]: family needs exactly one class",
    ]


def test_restricted_licence_needs_report_only():
    entity_map = minimal_map()
    entity_map["datasets"].append(dataset("nc", licence="CC-BY-NC-4.0", split="report"))
    entity_map["datasets"].append(dataset("gpl", licence="GPL-3.0", split="report"))
    entity_map["datasets"].append(dataset("ok", licence="CC-BY-NC-4.0", split="report", family="report_only"))
    assert problems(entity_map) == [
        "dataset nc: licence CC-BY-NC-4.0 needs family report_only",
        "dataset gpl: licence GPL-3.0 needs family report_only",
    ]


def test_family_and_split_constraints():
    entity_map = minimal_map()
    entity_map["datasets"].append(dataset("blind_dev", family="ark_blind", split="train_dev"))
    entity_map["datasets"].append(dataset("golden", family="ark_authored"))
    entity_map["datasets"].append(dataset("odd", family="mine", split="test", languages=["xx"]))
    assert problems(entity_map) == [
        "dataset blind_dev: ark_blind data belongs to the holdout",
        "dataset golden: ark_authored data cannot be holdout",
        "dataset odd: split 'test' is not one of holdout, train_dev, report",
        "dataset odd: family 'mine' is not one of neutral, ark_blind, ark_authored, baseline_trained, report_only",
        "dataset odd: unknown language xx",
    ]


def test_duplicate_dataset_and_unknown_keys_fail():
    entity_map = minimal_map()
    entity_map["datasets"].append(dataset("pub", extra=1))
    found = problems(entity_map)
    assert "dataset pub is defined 2 times" in found
    assert "dataset pub: unknown key extra" in found


def test_baselines_must_match_the_taxonomy():
    entity_map = minimal_map()
    entity_map["baselines"] = [b for b in entity_map["baselines"] if b["id"] != "atr"]
    entity_map["baselines"].append({"id": "lakera", "kind": "heuristic", "rules": "src"})
    assert problems(entity_map) == [
        "taxonomy baseline atr has no entry",
        f"baseline lakera: not a taxonomy baseline ({', '.join(MODULE.taxonomy.BASELINES)})",
    ]


def test_heuristic_baseline_needs_inventory_source_with_mapped_rules():
    entity_map = minimal_map()
    inventory = copy.deepcopy(INVENTORY)
    inventory["rules"].append({"source": "src", "id": "r4", "class": None, "mapping": "default"})
    found = problems(entity_map, inventory)
    assert "baseline atr: inventory rule r4 has no class, handoff or out_of_scope" in found
    entity_map["baselines"][0]["rules"] = "missing"
    assert f"baseline {entity_map['baselines'][0]['id']}: rules source 'missing' is not in oss_rules.yaml" in problems(entity_map)


def test_reference_baseline_needs_model_class_and_benign_label():
    entity_map = minimal_map()
    reference = next(b for b in entity_map["baselines"] if b["id"] == "protectai_v2")
    reference.pop("model")
    reference["labels"] = [{"label": "INJECTION", "classes": ["instruction_injection"]}]
    reference["trained_on"] = ["unregistered"]
    assert problems(entity_map) == [
        "baseline protectai_v2: reference baseline without model",
        "baseline protectai_v2: needs at least one class label and one benign label",
        "baseline protectai_v2: trained_on unregistered is not a registered dataset",
    ]


def test_baseline_trained_dataset_must_be_named_by_a_baseline():
    entity_map = minimal_map()
    entity_map["datasets"].append(dataset("train", split="train_dev", family="baseline_trained"))
    assert problems(entity_map) == ["dataset train: baseline_trained but no baseline names it in trained_on"]
    next(b for b in entity_map["baselines"] if b["id"] == "protectai_v2")["trained_on"] = ["train"]
    assert problems(entity_map) == []


def test_table_lists_deciding_family_per_class_and_language():
    entity_map = minimal_map()
    entity_map["datasets"] = [dataset("pub", languages=["en"]), dataset("blind", family="ark_blind", languages=["de"])]
    rendered = MODULE.table(entity_map)
    assert "| `jailbreak` | ark_blind: blind | neutral: pub |" in rendered
    assert "| neutral | 1 | 0 | 0 |" in rendered


def test_cli_check_passes_on_repository_map(capsys):
    assert MODULE.main(["check"]) == 0
    assert "entity map ok" in capsys.readouterr().out
