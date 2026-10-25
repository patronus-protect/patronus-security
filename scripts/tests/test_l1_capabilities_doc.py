from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("_ark_generate_docs_capabilities", ROOT / "scripts" / "generate_docs.py")
GENERATE_DOCS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = GENERATE_DOCS
SPEC.loader.exec_module(GENERATE_DOCS)

sys.path.insert(0, str(ROOT / "scripts"))
import l1_capabilities_doc  # noqa: E402

PAGE = ROOT / "docs" / "reference" / "l1-capabilities.md"


def test_page_is_up_to_date():
    assert PAGE.read_text(encoding="utf-8") == GENERATE_DOCS.generate_l1_capabilities_doc(), (
        "docs/reference/l1-capabilities.md is stale; run python3 scripts/generate_docs.py"
    )


def test_every_registry_label_and_rule_appears():
    page = PAGE.read_text(encoding="utf-8")
    pii = GENERATE_DOCS.parse_native_patterns(ROOT / "ark-core/src/detectors/pii/pii.rs", "PiiPattern")
    dlp = GENERATE_DOCS.parse_dlp_patterns()
    for rule in pii + dlp:
        assert f"`{rule['entity_group']}`" in page, rule["entity_group"]
        assert f"`{rule['id']}`" in page, rule["id"]
    for rule_id, _, _ in GENERATE_DOCS.DLP_RELATIONSHIP_RULES:
        assert f"`{rule_id}`" in page, rule_id


def test_snapshot_is_documented_and_used():
    path, snapshot = l1_capabilities_doc.latest_snapshot()
    assert path.parent == ROOT / "research" / "scoreboard"
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == "ark-l1-scoreboard-snapshot-v1"
    page = PAGE.read_text(encoding="utf-8")
    assert f"{snapshot['date']} on `main` {snapshot['commit']}" in page
    for programme in ("pii", "dlp"):
        for milestone in snapshot[programme]["milestones"]:
            assert milestone["value"] in page
