# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("l1_threat_real_agent", ROOT / "scripts/l1_threat/real_agent.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REGISTRY = {"datasets": [{"id": "real_x", "source": "https://github.com/o/r", "revision": "a" * 40}]}


def _row(key: str, family: str = "agent_config", label: str = "benign", **extra):
    return {"dataset": "real_x", "sha256": key, "source": f"https://github.com/o/r/blob/{'a' * 40}/f.md",
            "family": family, "label": label, "reason": "coding_guidance", **extra}


def _families(count: int):
    return [_row(f"{family[:1]}{number:063x}"[:64].replace("a", "0").replace("t", "1").replace("m", "2"), family)
            for family in MODULE.FAMILIES for number in range(count)]


def test_checked_in_labels_cover_registered_sets_and_families():
    rows = MODULE.load()
    registry = yaml.safe_load(MODULE.REGISTRY_PATH.read_text(encoding="utf-8"))
    assert MODULE.check(rows, registry) == []
    assert all("text" not in row for row in rows)


def test_check_flags_bad_rows_duplicates_and_thin_families(monkeypatch):
    monkeypatch.setattr(MODULE, "MIN_BENIGN_PER_FAMILY", 2)
    rows = _families(2)
    assert MODULE.check(rows, REGISTRY) == []
    assert any("labelled 2 times" in p for p in MODULE.check(rows + [rows[0]], REGISTRY))
    wrong_source = {**rows[0], "source": "https://github.com/o/r/blob/main/f.md"}
    assert any("pinned" in p or "at " in p for p in MODULE.check([wrong_source] + rows[1:], REGISTRY))
    assert any("label in" in p for p in MODULE.check([{**rows[0], "label": "jailbreak"}] + rows[1:], REGISTRY))
    assert any("text" in p or "keys" in p for p in MODULE.check([_row(rows[0]["sha256"], text="x")] + rows[1:], REGISTRY))
    assert any("family memory_write" in p for p in MODULE.check([r for r in rows if r["family"] != "memory_write"], REGISTRY))


def test_sample_is_fixed_and_agree_names_disagreements():
    keys = [f"{number:064x}" for number in range(200)]
    sample = [key for key in keys if MODULE.in_sample(key)]
    assert sample == [key for key in keys if MODULE.in_sample(key)] and 5 <= len(sample) <= 40
    rows = [_row(key) for key in keys]
    second = [{"sha256": key, "label": "benign"} for key in sample]
    second[0]["label"] = "agent_config_tampering"
    result = MODULE.agree(rows, second)
    assert result["sample"] == result["checked"] == len(sample) and result["missing"] == []
    assert result["disagreements"] == [{"sha256": sample[0], "first": "benign", "second": "agent_config_tampering"}]
    assert MODULE.agree(rows, second[1:])["missing"] == [sample[0]]
