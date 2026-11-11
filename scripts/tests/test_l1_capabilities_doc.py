from __future__ import annotations

import importlib.util
import re
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


def _section(page: str, heading: str) -> str:
    """The text below `heading` up to the next heading of the same or a higher level."""
    level = heading.split(" ")[0]
    start = page.index(f"\n{heading}\n") + 1
    rest = page[start + len(heading):]
    ends = [m.start() for m in re.finditer(r"^#{1,%d} " % len(level), rest, flags=re.M)]
    return rest[: ends[0]] if ends else rest


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


def test_report_number_reads_english_and_german_notation():
    assert l1_capabilities_doc.report_number("91.3") == 91.3
    assert l1_capabilities_doc.report_number("91,3") == 91.3
    assert l1_capabilities_doc.report_number("1 731") == 1731
    assert l1_capabilities_doc.report_number("1134") == 1134
    assert l1_capabilities_doc.report_number("0,053") == 0.053


def test_report_table_reads_the_first_matching_table(tmp_path):
    report = tmp_path / "report.md"
    report.write_text(
        "Intro\n\n| Tool | P |\n|---|---:|\n| other | 1 |\n\n"
        "| Family | Engine | F1 |\n|---|---|---:|\n| neutral ¹ | ark | **88,3** |\n| neutral | presidio | 1,430 ¹ |\n\n"
        "| Family | Engine | F1 |\n|---|---|---:|\n| later | x | 0 |\n",
        encoding="utf-8",
    )
    rows = l1_capabilities_doc.report_table(report, "| Family | Engine |")
    assert rows == [
        {"Family": "neutral", "Engine": "ark", "F1": "88,3"},
        {"Family": "neutral", "Engine": "presidio", "F1": "1,430"},
    ]


def test_page_shows_the_final_pii_results():
    page = PAGE.read_text(encoding="utf-8")
    overall = l1_capabilities_doc.report_table(l1_capabilities_doc.PII_FINAL_PATH, "| Family | Engine |")
    by_key = {(row["Family"], row["Engine"]): row["Exact F1"] for row in overall}
    accuracy = _section(page, "### Accuracy")
    for family, name in l1_capabilities_doc.PII_TEST_DATA.items():
        row = next(line for line in accuracy.splitlines() if line.startswith(f"| {name} |"))
        for engine in l1_capabilities_doc.PII_ENGINES:
            assert by_key[(family, engine)] in row, (family, engine)
    per_identifier = _section(page, "### Accuracy per identifier")
    entities = l1_capabilities_doc.report_table(l1_capabilities_doc.PII_FINAL_PATH, "| Family | Entity | Scope | Gold |")
    assert len(entities) >= 60
    for entity in entities:
        assert f"| `{entity['Entity']}` |" in per_identifier, entity["Entity"]


def test_page_shows_the_final_dlp_results():
    page = PAGE.read_text(encoding="utf-8")
    tools = l1_capabilities_doc.report_table(l1_capabilities_doc.DLP_FINAL_PATH, "| Tool | P |")
    assert [row["Tool"] for row in tools] == ["ark", "gitleaks", "trufflehog", "detect-secrets"]
    assert "| **Ark L1** ² | **91.3** | **85.5** | **88.3** | **144** | **0.053** |" in page
    assert "| detect-secrets 1.5.0 | 33.9 | 51.6 | 40.9 | 1,731 | 36.283 ⁴ |" in page
    assert "| `CREDENTIAL` | 320 | **100.0** | 23.7 | 11.4 | 11.9 |" in page


def test_page_uses_no_internal_research_jargon():
    page = PAGE.read_text(encoding="utf-8")
    for pattern in (r"\b(M[1-4]|T[0-9]{2}|H0[0-9]|E[0-9]{2}|K0[0-9])\b", r"milestone", r"raw gold", r"dev split",
                    r"presidio_favored", r"ark_authored", r"\bgold\b", r"source family", r"D-BARE"):
        assert not re.search(pattern, page, flags=re.I), pattern


def test_shared_wolf_metadata_is_resolved_in_asset_docs():
    assets = GENERATE_DOCS.parse_assets()
    wolf = [asset for asset in assets if asset.category == "Injection"]
    assert wolf and all(asset.repo == "patronus-studio/wolf-defender-prompt-injection-small" for asset in wolf)
    package = next(p for p in GENERATE_DOCS.parse_ntdb_packages() if p.category == "Injection")
    assert package.revision == "142fadc5474163d4c483cb761d5a6b02e3aa1741"
    assert "patronus_ark_core::warmup::" not in GENERATE_DOCS.generate_assets_doc(assets, GENERATE_DOCS.load_snapshot())


def test_pii_default_names_the_opt_in_bare_form():
    rule = {"id": "pii_sin_ca", "scored_only": False}
    scored = {"id": "pii_sin_ca_context_free", "scored_only": True}
    bare = {"id": "pii_sin_ca_bare", "scored_only": False}
    assert l1_capabilities_doc._pii_default([rule]) == "on"
    assert l1_capabilities_doc._pii_default([rule, bare]) == "on, bare form opt-in"
    assert (
        l1_capabilities_doc._pii_default([rule, scored, bare])
        == "on (1 of 2 rules `balanced`/`recall` only), bare form opt-in"
    )


def test_pii_default_names_the_opt_in_compatibility_form():
    rule = {"id": "pii_ssn_us", "scored_only": False}
    bare = {"id": "pii_ssn_us_bare", "scored_only": False}
    compat = {"id": "pii_ssn_us_unassigned_compat", "scored_only": False}
    assert l1_capabilities_doc._pii_default([rule, compat]) == "on, compatibility form opt-in"
    assert (
        l1_capabilities_doc._pii_default([rule, bare, compat])
        == "on, bare form opt-in, compatibility form opt-in"
    )
