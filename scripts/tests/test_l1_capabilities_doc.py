from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("_ark_generate_docs_capabilities", ROOT / "scripts" / "generate_docs.py")
GENERATE_DOCS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = GENERATE_DOCS
SPEC.loader.exec_module(GENERATE_DOCS)

sys.path.insert(0, str(ROOT / "scripts"))
import l1_capabilities_doc  # noqa: E402
import scoreboard_snapshot  # noqa: E402

PAGE = ROOT / "docs" / "reference" / "l1-capabilities.md"
FIXTURES = ROOT / "scripts" / "tests" / "fixtures" / "scoreboard_snapshot"


def _row(page: str, entity_id: str, after: str) -> str:
    """The first table row of `entity_id` below the heading `after`."""
    section = page[page.index(after):]
    return next(line for line in section.splitlines() if line.startswith(f"| `{entity_id}` |"))


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
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "ark-l1-scoreboard-snapshot-v1"
    assert data["schema_version"] == scoreboard_snapshot.SCHEMA_VERSION
    page = PAGE.read_text(encoding="utf-8")
    assert f"{snapshot['date']} on `main` {snapshot['commit']}" in page
    for programme in ("pii", "dlp"):
        for milestone in snapshot[programme]["milestones"]:
            assert milestone["value"] in page


def test_every_measured_pii_id_with_gold_shows_its_f1():
    _, snapshot = l1_capabilities_doc.latest_snapshot()
    pii = snapshot["pii"]
    page = PAGE.read_text(encoding="utf-8")
    entity_ids = {e["id"] for e in yaml.safe_load(l1_capabilities_doc.PII_ENTITY_MAP_PATH.read_text())["entities"]}
    with_gold = [i for i, entry in pii["entities"].items() if any(v.get("gold") for v in entry.values())]
    assert len(with_gold) >= 60
    for entity_id in with_gold:
        if entity_id not in entity_ids:
            continue
        row = _row(page, entity_id, "### F1 per entity")
        for family, values in pii["entities"][entity_id].items():
            if values.get("gold"):
                expected = f"ARK {values['f1']['ark-balanced']:.1f} / Presidio {values['f1']['presidio-tuned']:.1f}"
                assert expected in row, (entity_id, family)
            else:
                assert "no gold" in row, (entity_id, family)


def test_every_measured_dlp_entity_with_gold_shows_its_f1():
    _, snapshot = l1_capabilities_doc.latest_snapshot()
    page = PAGE.read_text(encoding="utf-8")
    entity_ids = {e["id"] for e in yaml.safe_load(l1_capabilities_doc.DLP_ENTITY_MAP_PATH.read_text())["entities"]}
    entities = snapshot["dlp"]["entities"]
    assert sum(bool(entry["gold"]) for entry in entities.values()) >= 40
    for entity_id, entry in entities.items():
        if entity_id not in entity_ids:
            continue
        row = _row(page, entity_id, "#### F1 and recall per entity")
        if not entry["gold"]:
            assert "no gold" in row, entity_id
        elif "extended" in entry:
            assert f"ARK {entry['extended']['ark']['f1']:.1f} (opt-in profile)" in row, entity_id
        else:
            assert f"ARK {entry['default']['ark']['f1']:.1f} / " in row, entity_id


def test_cells_distinguish_no_gold_from_not_measured():
    measured = {"neutral": {"gold": 0}, "presidio_favored": {"gold": 3, "f1": {"ark-balanced": 50.0, "presidio-tuned": 100.0}}}
    assert l1_capabilities_doc.pii_f1_cell(measured, "neutral", "ark-balanced", "presidio-tuned") == "no gold"
    assert (l1_capabilities_doc.pii_f1_cell(measured, "presidio_favored", "ark-balanced", "presidio-tuned")
            == "ARK 50.0 / Presidio 100.0")
    assert l1_capabilities_doc.pii_f1_cell(None, "neutral", "ark-balanced", "presidio-tuned") == "–"
    assert l1_capabilities_doc.pii_gold_cell(measured) == "0 / 3 / 0"
    assert l1_capabilities_doc.dlp_cell({"gold": 0}) == "no gold"
    assert l1_capabilities_doc.dlp_cell(None) == "–"
    entry = {"gold": 4, "default": {"ark": {"f1": 90.0}, "gitleaks": {"f1": 40.0}, "trufflehog": {"f1": 60.0}}}
    assert l1_capabilities_doc.dlp_cell(entry) == "ARK 90.0 / best baseline 60.0 (TruffleHog)"
    assert l1_capabilities_doc.dlp_cell({"gold": 4, "default": {"ark": {"f1": 90.0}}}) == "ARK 90.0 / no baseline"
    opt_in = {"gold": 8, "profile": "extended", "extended": {"ark": {"f1": 50.0, "recall": 37.5}}}
    assert l1_capabilities_doc.dlp_cell(opt_in, "recall") == "ARK 37.5 (opt-in profile)"


def test_converter_round_trip(tmp_path):
    output = tmp_path / "snapshot.json"
    code = scoreboard_snapshot.main([
        "from-reports", "--snapshot", str(FIXTURES / "snapshot.json"),
        "--pii-report", str(FIXTURES / "pii_report.json"),
        "--dlp-reports", str(FIXTURES / "dlp"), "--dlp-entity-map", str(FIXTURES / "entity_map.yaml"),
        "--output", str(output),
    ])
    assert code == 0
    snapshot = json.loads(output.read_text(encoding="utf-8"))
    assert snapshot["schema"] == "ark-l1-scoreboard-snapshot-v1" and snapshot["schema_version"] == "1.1"
    pii = snapshot["pii"]
    assert pii["overall_f1"] == {"neutral": 66.7, "presidio_favored": 100.0}
    assert pii["entities"]["pii.email"]["neutral"] == {"gold": 10, "f1": {"ark-balanced": 66.7, "presidio-tuned": 50.0}}
    assert pii["entities"]["pii.email"]["presidio_favored"] == {"gold": 0}
    assert pii["entities"]["pii.iban"]["presidio_favored"]["f1"] == {"ark-balanced": 100.0, "presidio-tuned": 0.0}
    assert pii["entities"]["pii.iban"]["ark_authored"] == {"gold": 0}
    assert set(pii["entities"]) == {"pii.email", "pii.iban", "pii.us.itin"}

    dlp = snapshot["dlp"]
    assert "group_f1" not in dlp and dlp["tools"] == ["ark", "gitleaks"]
    assert dlp["entities"]["llm.openai.api_key"] == {"gold": 40, "default": {
        "ark": {"f1": 90.0, "precision": 90.0, "recall": 90.0},
        "gitleaks": {"f1": 50.0, "precision": 50.0, "recall": 25.0}}}
    assert dlp["entities"]["saas.misc.api_token"] == {"gold": 0}
    assert dlp["entities"]["identifier.de.vat_id"] == {
        "gold": 8, "profile": "extended", "extended": {"ark": {"f1": 50.0, "precision": 75.0, "recall": 37.5}}}
    assert dlp["entities"]["content.sql"]["level"] == "document"
    assert dlp["entities"]["content.sql"]["extended"]["ark"]["f1"] == 90.9
    assert "document.hr" not in dlp["entities"] and "action.secret_transfer" not in dlp["entities"]
    assert dlp["groups"]["API_KEY"]["default"]["gitleaks"]["f1"] == 50.0
    assert dlp["groups"]["dlp.de.vat_id"]["extended"]["ark"]["f1"] == 50.0
    assert "dlp.document.hr" not in dlp["groups"]
    # A second run over its own output yields the same snapshot.
    again = tmp_path / "again.json"
    assert scoreboard_snapshot.main([
        "from-reports", "--snapshot", str(output), "--pii-report", str(FIXTURES / "pii_report.json"),
        "--dlp-reports", str(FIXTURES / "dlp"), "--dlp-entity-map", str(FIXTURES / "entity_map.yaml"),
        "--output", str(again),
    ]) == 0
    assert again.read_text(encoding="utf-8") == output.read_text(encoding="utf-8")
    assert l1_capabilities_doc.dlp_cell(dlp["entities"]["llm.openai.api_key"], "recall") == (
        "ARK 90.0 / best baseline 25.0 (gitleaks)")


def test_converter_without_opt_in_run_leaves_opt_in_families_unmeasured(tmp_path):
    reports = tmp_path / "dlp"
    reports.mkdir()
    for name in ("ark.json", "gitleaks.json"):
        (reports / name).write_text((FIXTURES / "dlp" / name).read_text(encoding="utf-8"), encoding="utf-8")
    output = tmp_path / "snapshot.json"
    assert scoreboard_snapshot.main([
        "from-reports", "--snapshot", str(FIXTURES / "snapshot.json"),
        "--dlp-reports", str(reports), "--dlp-entity-map", str(FIXTURES / "entity_map.yaml"),
        "--output", str(output),
    ]) == 0
    dlp = json.loads(output.read_text(encoding="utf-8"))["dlp"]
    assert "identifier.de.vat_id" not in dlp["entities"] and "content.sql" not in dlp["entities"]
    assert "dlp.de.vat_id" not in dlp["groups"] and "dlp.content.sql" not in dlp["groups"]
    assert l1_capabilities_doc.dlp_cell(dlp["entities"].get("identifier.de.vat_id")) == "–"
    assert dlp["entities"]["llm.openai.api_key"]["gold"] == 40


def test_shared_wolf_metadata_is_resolved_in_asset_docs():
    assets = GENERATE_DOCS.parse_assets()
    wolf = [asset for asset in assets if asset.category == "Injection"]
    assert wolf and all(asset.repo == "patronus-studio/wolf-defender-prompt-injection-small" for asset in wolf)
    package = next(p for p in GENERATE_DOCS.parse_ntdb_packages() if p.category == "Injection")
    assert package.revision == "142fadc5474163d4c483cb761d5a6b02e3aa1741"
    assert "patronus_ark_core::warmup::" not in GENERATE_DOCS.generate_assets_doc(assets, GENERATE_DOCS.load_snapshot())
