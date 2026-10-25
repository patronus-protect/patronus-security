"""Generate docs/reference/l1-capabilities.md (called by scripts/generate_docs.py).

Sources: the PII and DLP rule registries (parsed by generate_docs.py, as for the rule catalog),
research/l1-pii/entity_map.yaml, research/dlp/entity_map.yaml, the checksum count of
scripts/l1_presidio/count_validated.py and the newest milestone snapshot in research/scoreboard/.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[1]
PII_ENTITY_MAP_PATH = ROOT / "research/l1-pii/entity_map.yaml"
DLP_ENTITY_MAP_PATH = ROOT / "research/dlp/entity_map.yaml"
SCOREBOARD_DIR = ROOT / "research/scoreboard"
COUNT_VALIDATED_PATH = ROOT / "scripts/l1_presidio/count_validated.py"

PII_STRENGTH_ORDER = ["checksum", "format", "none"]
DLP_STRENGTH_ORDER = ["checksum", "structure", "format", "none"]
SCOPE_ORDER_PII = ["shared", "ark_only", "presidio_only", "semantic"]
SCOPE_ORDER_DLP = ["shared", "ark_only", "baseline_only", "out_of_scope"]
SPLIT_NAMES = {"neutral": "neutral", "presidio_favored": "presidio_favored"}

CONFIG_PYTHON = """```python
scanner.set_execution_gates({
    "levels": {"l1": True, "l2": False, "l3": False},
    "models": {"native:mcp_runtime_risk": False, "external:internal_token": False},
    "rules": {"pii_email": False, "dlp_password_assignment": False},
})
```"""

CONFIG_RUST = """```rust
scanner.set_execution_gates(
    ScanGateMatrix::levels(true, false, false)
        .with_model("native:mcp_runtime_risk", false)
        .with_rule("pii_email", false),
);
```"""

CONFIG_YAML = """```yaml
gates:
  l1: true
  l2: false
  l3: false
  pii_mode: strict
  dlp_mode: strict
  rules:
    pii_employee_id: true
    dlp_sql_statement: false
  models:
    native:mcp_runtime_risk: false
```"""


def latest_snapshot(directory: Path = SCOREBOARD_DIR) -> tuple[Path, dict[str, Any]]:
    """The newest `YYYY-MM-DD.json` milestone snapshot."""
    paths = sorted(directory.glob("????-??-??.json"))
    if not paths:
        raise ValueError(f"No milestone snapshot in {directory}")
    return paths[-1], json.loads(paths[-1].read_text(encoding="utf-8"))


def checksum_counts() -> tuple[int, int]:
    """ARK and Presidio checksum-validated units of the current registry (count rule T03)."""
    spec = importlib.util.spec_from_file_location("_ark_count_validated", COUNT_VALIDATED_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    counts = module.count(module.ENTITY_MAP_MODULE.load(), module.load_rules())
    return len(counts.ark), len(counts.presidio)


def _code(values: list[str] | None) -> str:
    return ", ".join(f"`{value}`" for value in values or []) or "–"


def _strongest(strengths: list[str | None], order: list[str]) -> str:
    present = [strength or "none" for strength in strengths]
    for strength in order:
        if strength in present:
            return strength
    return "–"


def _pii_check(rules: list[dict]) -> str:
    strength = _strongest([rule["strength"] for rule in rules], PII_STRENGTH_ORDER)
    if strength != "none":
        return strength
    bound = all(rule["field_context"] or rule["requires_context"] for rule in rules)
    return "context" if bound else "pattern"


def _pii_default(rules: list[dict]) -> str:
    if not rules:
        return "–"
    scored = [rule for rule in rules if rule["scored_only"]]
    if len(scored) == len(rules):
        return "on (`balanced`/`recall` only)"
    if scored:
        return f"on ({len(scored)} of {len(rules)} rules `balanced`/`recall` only)"
    return "on"


NOT_MEASURED = "–"
NO_GOLD = "no gold"
PLANNED = "planned / not implemented"
PII_FAMILIES = ["neutral", "presidio_favored", "ark_authored"]
DLP_TOOL_NAMES = {"ark": "ARK", "gitleaks": "gitleaks", "trufflehog": "TruffleHog", "detect-secrets": "detect-secrets"}


def _engine(name: str) -> str:
    """Report engine key of a display name (`Presidio tuned` -> `presidio-tuned`)."""
    return name.strip().lower().replace(" ", "-")


def pii_gold_cell(entry: dict | None) -> str:
    if not entry:
        return NOT_MEASURED
    return " / ".join(str(entry.get(family, {}).get("gold", 0)) for family in PII_FAMILIES)


def pii_f1_cell(entry: dict | None, family: str, ark_engine: str, baseline_engine: str) -> str:
    """`ARK x / Presidio y` (exact F1), `no gold`, or `–` for an id outside the measurement."""
    values = (entry or {}).get(family)
    if not values:
        return NOT_MEASURED
    if not values.get("gold"):
        return NO_GOLD
    f1 = values["f1"]
    return f"ARK {f1[ark_engine]:.1f} / Presidio {f1[baseline_engine]:.1f}"


def dlp_cell(entry: dict | None, metric: str = "f1") -> str:
    """`ARK x / best baseline y (name)`, `ARK x (opt-in profile)`, `no gold` or `–`."""
    if entry is None:
        return NOT_MEASURED
    if not entry.get("gold"):
        return NO_GOLD
    if "extended" in entry:
        return f"ARK {entry['extended']['ark'][metric]:.1f} (opt-in profile)"
    default = entry["default"]
    ark = f"ARK {default['ark'][metric]:.1f}"
    baselines = [(values[metric], tool) for tool, values in default.items() if tool != "ark"]
    if not baselines:
        return f"{ark} / no baseline"
    best = max(value for value, _ in baselines)
    names = ", ".join(DLP_TOOL_NAMES.get(tool, tool) for value, tool in baselines if value == best)
    return f"{ark} / best baseline {best:.1f} ({names})"


def dlp_gold_cell(entry: dict | None) -> str:
    if entry is None:
        return NOT_MEASURED
    if entry.get("level") == "document":
        return f"{entry['gold']} documents"
    return str(entry["gold"])


def _baseline_rules(entity: dict) -> str:
    parts = [
        f"{name}: {_code(entity.get(key))}"
        for key, name in (("gitleaks", "gitleaks"), ("trufflehog", "TruffleHog"), ("detect_secrets", "detect-secrets"))
        if entity.get(key)
    ]
    return "; ".join(parts) or "–"


def _met(flag: bool) -> str:
    return "met" if flag else "not met"


def generate(
    pii_rules: list[dict],
    dlp_rules: list[dict],
    credential_groups: set[str],
    relationship_rules: list[tuple[str, str, bool]],
) -> str:
    pii_map = yaml.safe_load(PII_ENTITY_MAP_PATH.read_text(encoding="utf-8"))
    dlp_map = yaml.safe_load(DLP_ENTITY_MAP_PATH.read_text(encoding="utf-8"))
    snapshot_path, snapshot = latest_snapshot()
    ark_units, presidio_units = checksum_counts()
    date, commit, splits = snapshot["date"], snapshot["commit"], snapshot["splits"]
    pii, dlp = snapshot["pii"], snapshot["dlp"]
    snapshot_rel = snapshot_path.relative_to(ROOT).as_posix()

    pii_labels = list(dict.fromkeys(rule["entity_group"] for rule in pii_rules))
    dlp_labels = list(dict.fromkeys(rule["entity_group"] for rule in dlp_rules))
    pii_by_label: dict[str, list[dict]] = {}
    for rule in pii_rules:
        pii_by_label.setdefault(rule["entity_group"], []).append(rule)
    dlp_by_id = {rule["id"]: rule for rule in dlp_rules}

    lines = [
        "# L1 capabilities",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "What ARK L1 detects (PII and DLP), how it compares with Presidio and the secret scanners "
        "gitleaks, TruffleHog and detect-secrets, how fast it is and how it is configured. Rule data "
        "comes from the rule registries (as in the [L1 rule catalog](l1-rule-catalog.md)), coverage "
        "from `research/l1-pii/entity_map.yaml` and `research/dlp/entity_map.yaml`, measurements from "
        f"`{snapshot_rel}`.",
        "",
        f"!!! note \"Measurements\"\n    All F1, latency and milestone values are from the milestone measurement of {date} "
        f"on `main` {commit} ({splits} splits). Rule counts, labels and coverage reflect the current "
        "registries and entity maps, so they can be ahead of the measurement.",
        "",
        "## Summary",
        "",
        "| | PII | DLP |",
        "| --- | --- | --- |",
        f"| Result labels (entity groups) | {len(pii_labels)} | {len(dlp_labels)} |",
        f"| Regex rules | {len(pii_rules)} | {len(dlp_rules)} (+{len(relationship_rules)} relationship rules) |",
        f"| Checksum-validated units (count rule T03) | {ark_units} (Presidio 2.2.364: {presidio_units}) | – |",
        f"| Rules with a `checksum` or `structure` check | "
        f"{sum(rule['strength'] == 'checksum' for rule in pii_rules)} | "
        f"{sum(rule['validator_strength'] in ('checksum', 'structure') for rule in dlp_rules)} |",
        f"| Default state | all rules on | credential/secret groups on, broader families opt-in |",
        f"| Compared with | Presidio {pii_map['presidio_version']} (tuned) | "
        + ", ".join(
            f"{name} {dlp_map['baselines'][key]['version']}"
            for key, name in (("gitleaks", "gitleaks"), ("trufflehog", "TruffleHog"), ("detect_secrets", "detect-secrets"))
        )
        + " |",
        f"| Overall F1 ({date}) | `{pii['decision_mode']}`: neutral {pii['overall_f1']['neutral']:.1f}, "
        f"presidio_favored {pii['overall_f1']['presidio_favored']:.1f} | "
        f"{dlp['decision_profile']} profile: {dlp['overall']['f1']:.1f} (P {dlp['overall']['precision']:.1f}, "
        f"R {dlp['overall']['recall']:.1f}) |",
        "",
        "### Milestone status",
        "",
        "| Programme | Milestone | Value | Target | Status | Measured |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for programme, data in (("PII", pii), ("DLP", dlp)):
        for milestone in data["milestones"]:
            status = _met(milestone["met"])
            if milestone.get("note"):
                status += f" ({milestone['note']})"
            lines.append(
                f"| {programme} | {milestone['id']} {milestone['name']} | {milestone['value']} "
                f"| {milestone['target']} | {status} | {date} |"
            )

    # ── PII ──
    entities = pii_map["entities"]
    lines.extend([
        "",
        "## PII",
        "",
        "One row per benchmark entity of `research/l1-pii/entity_map.yaml`. Scope: `shared` (ARK and "
        "Presidio match it by pattern), `ark_only`, `presidio_only` (a gap in ARK L1), `semantic` "
        "(NER entities; L1 never reports them, see [Dynamic PII](configuration.md#dynamic-pii)). "
        "Check: the strongest validator of the entity's rules (`checksum`: check digits computed; "
        "`format`: length, alphabet, range or date; `pattern`: regex shape only; `context`: regex shape "
        "plus a field name or nearby term).",
        "",
        "### Coverage",
        "",
        "| Benchmark id | Scope | ARK label(s) | Rule ID(s) | Check | Default | Presidio entities |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for scope in SCOPE_ORDER_PII:
        for entity in (e for e in entities if e["scope"] == scope):
            rules = [rule for label in entity.get("ark") or [] for rule in pii_by_label.get(label, [])]
            lines.append(
                f"| `{entity['id']}` | {scope} | {_code(entity.get('ark'))} "
                f"| {_code([rule['id'] for rule in rules])} | {_pii_check(rules) if rules else '–'} "
                f"| {_pii_default(rules)} | {_code(entity.get('presidio'))} |"
            )
    counts = {scope: sum(e["scope"] == scope for e in entities) for scope in SCOPE_ORDER_PII}
    lines.extend([
        "",
        f"Entities: {counts['shared']} shared, {counts['ark_only']} ARK only, "
        f"{counts['presidio_only']} Presidio only, {counts['semantic']} semantic. Hard-negative false "
        f"positives ({date}): ARK {pii['hard_negative_fp']['ark']}, Presidio {pii['hard_negative_fp']['presidio']}.",
    ])

    ark_engine, baseline_engine = f"ark-{pii['decision_mode']}", _engine(pii["baseline"])
    measured = pii["entities"]
    lines.extend([
        "",
        "### F1 per entity",
        "",
        f"Exact F1 in percent on the {splits} split, measured {date}, per source family: ARK in "
        f"`{pii['decision_mode']}` vs {pii['baseline']}, over all rows of the family (EN and DE; M1 counts "
        "EN rows only). Gold: gold spans in neutral / presidio_favored / ark_authored.",
        "",
        f"Legend: `ARK x / Presidio y` = exact F1 of both; `{NO_GOLD}` = measured, but the family has no "
        f"gold span for the id; `{NOT_MEASURED}` = the id was not part of the measurement (added later, or "
        "`semantic`).",
        "",
        "| Benchmark id | Scope | Gold | F1 neutral | F1 presidio_favored | F1 ark_authored ¹ |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for scope in SCOPE_ORDER_PII:
        for entity in (e for e in entities if e["scope"] == scope):
            entry = measured.get(entity["id"])
            lines.append(
                f"| `{entity['id']}` | {scope} | {pii_gold_cell(entry)} | "
                + " | ".join(pii_f1_cell(entry, family, ark_engine, baseline_engine) for family in PII_FAMILIES)
                + " |"
            )
    with_gold = sum(any(v.get("gold") for v in entry.values()) for entry in measured.values())
    lines.extend([
        "",
        f"¹ `ark_authored` (ARK's own synthetic DE/EU goldset) is reported and decides no milestone. "
        f"Measured ids: {len(measured)}, {with_gold} with gold in at least one family, "
        f"{len(measured) - with_gold} without gold.",
    ])

    # ── DLP ──
    taxonomy = dlp_map["taxonomy"]
    dlp_entities = dlp_map["entities"]
    lines.extend([
        "",
        "## DLP",
        "",
        "### Groups",
        "",
        "Credential/secret groups are on by default; business identifiers, metrics and content classes "
        "are opt-in per rule. Exact F1 in percent on the "
        f"{splits} split, measured {date}: default-on groups in the {dlp['decision_profile']} profile against "
        "the best of " + ", ".join(DLP_TOOL_NAMES[tool] for tool in dlp["tools"] if tool != "ark")
        + f"; default-off groups with their rules switched on (ARK's `{dlp['opt_in_profile']}` profile, "
        "marked `opt-in profile`; no baseline has these classes). Content classes are judged per document "
        "on external corpora.",
        "",
        f"Legend: `ARK x / best baseline y (name)` = exact F1 of ARK and of the best baseline; `{NO_GOLD}` = "
        f"measured, but no gold for it; `{NOT_MEASURED}` = not part of the measurement; `{PLANNED}` = "
        "planned class without rules.",
        "",
        "| Result label | Family | Default | Rules | Entities | Gold | F1 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    groups = list(dict.fromkeys(list(taxonomy) + dlp_labels))
    for group in groups:
        family = (taxonomy.get(group) or {}).get("family", "–")
        planned = (taxonomy.get(group) or {}).get("planned")
        if planned:
            family += " (planned)"
        rule_count = sum(rule["entity_group"] == group for rule in dlp_rules)
        entity_count = sum(e.get("group") == group and e["scope"] in ("shared", "ark_only") for e in dlp_entities)
        entry = dlp["groups"].get(group)
        lines.append(
            f"| `{group}` | {family} | {'on' if group in credential_groups else 'off'} | {rule_count} "
            f"| {entity_count} | {PLANNED if planned and not rule_count else dlp_gold_cell(entry)} "
            f"| {PLANNED if planned and not rule_count else dlp_cell(entry)} |"
        )

    lines.extend([
        "",
        "### Entities",
        "",
        "One row per entity of `research/dlp/entity_map.yaml`. Scope: `shared` (ARK and at least one "
        "baseline), `ark_only`, `baseline_only` (a gap in ARK L1), `out_of_scope` (action or policy "
        "rules, not a secret value). Structure check: the strongest `validator_strength` of the "
        "entity's rules (`checksum`, `structure`: decoded or parsed, `format`, `none`). Baseline rules: "
        "the gitleaks, TruffleHog and detect-secrets rules mapped to the entity.",
        "",
        "#### Coverage",
        "",
        "| Entity | Scope | Group | Rule ID(s) | Structure check | Default | Baseline rules |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    relationship_defaults = {rule_id: default for rule_id, _, default in relationship_rules}
    for scope in SCOPE_ORDER_DLP:
        for entity in (e for e in dlp_entities if e["scope"] == scope):
            ark = entity.get("ark") or []
            regex = [dlp_by_id[rule_id] for rule_id in ark if rule_id in dlp_by_id]
            check = _strongest([rule["validator_strength"] for rule in regex], DLP_STRENGTH_ORDER) if regex else "–"
            if regex:
                default = "on" if any(rule["entity_group"] in credential_groups for rule in regex) else "off"
            elif ark:
                default = "on" if any(relationship_defaults.get(rule_id) for rule_id in ark) else "off"
            else:
                default = "–"
            lines.append(
                f"| `{entity['id']}` | {scope} | {_code([entity['group']] if entity.get('group') else [])} "
                f"| {_code(ark)} | {check} | {default} | {_baseline_rules(entity)} |"
            )
    dlp_counts = {scope: sum(e["scope"] == scope for e in dlp_entities) for scope in SCOPE_ORDER_DLP}
    lines.extend([
        "",
        f"Entities: {dlp_counts['shared']} shared, {dlp_counts['ark_only']} ARK only, "
        f"{dlp_counts['baseline_only']} baseline only, {dlp_counts['out_of_scope']} out of scope.",
    ])

    measured_dlp = dlp["entities"]
    lines.extend([
        "",
        "#### F1 and recall per entity",
        "",
        f"Exact F1 and recall in percent on the {splits} split, measured {date}; same cells and legend as the "
        "group table (M1 judges recall). A baseline counts for an entity when it reported a typed span for it. "
        "`out_of_scope` entities are not measured and not listed.",
        "",
        "| Entity | Scope | Group | Gold | F1 | Recall |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for scope in SCOPE_ORDER_DLP[:-1]:
        for entity in (e for e in dlp_entities if e["scope"] == scope):
            group = entity.get("group")
            if (taxonomy.get(group or "") or {}).get("planned") and not entity.get("ark"):
                gold = f1_cell = recall_cell = PLANNED
            else:
                entry = measured_dlp.get(entity["id"])
                gold, f1_cell, recall_cell = dlp_gold_cell(entry), dlp_cell(entry), dlp_cell(entry, "recall")
            lines.append(
                f"| `{entity['id']}` | {scope} | {_code([group] if group else [])} | {gold} | {f1_cell} "
                f"| {recall_cell} |"
            )
    dlp_with_gold = sum(bool(entry.get("gold")) for entry in measured_dlp.values())
    lines.extend([
        "",
        f"Measured entities: {len(measured_dlp)}, {dlp_with_gold} with gold, "
        f"{len(measured_dlp) - dlp_with_gold} without gold.",
    ])

    # ── Latency ──
    pii_latency, dlp_latency = pii["latency"], dlp["latency"]
    lines.extend([
        "",
        "## Latency",
        "",
        f"Measured {date} on `main` {commit}.",
        "",
        "| Programme | Measurement | Value | Target |",
        "| --- | --- | --- | --- |",
        f"| PII | {pii_latency['size']} p95, Python bindings | {pii_latency['p95_ms']['bindings']:.1f} ms "
        f"| ≤ {pii_latency['target_p95_ms']:.0f} ms |",
        f"| PII | {pii_latency['size']} p95, native (DE {pii_latency['p95_ms']['native_de']:.0f} ms, "
        f"EN {pii_latency['p95_ms']['native_en']:.0f} ms) | {pii_latency['p95_ms']['native']:.1f} ms "
        f"| ≤ {pii_latency['target_p95_ms']:.0f} ms |",
        f"| DLP | {dlp_latency['size']} p95 | {dlp_latency['p95_ms']:.1f} ms | {dlp_latency['target']} |",
        f"| DLP | scan throughput | {dlp_latency['throughput_mib_s']:.2f} MiB/s "
        f"(gitleaks {dlp_latency['gitleaks_throughput_mib_s']:.2f} MiB/s) | ≥ gitleaks |",
        "",
        f"PII latency is not yet at target ({pii_latency['note']}).",
    ])

    # ── Configuration ──
    lines.extend([
        "",
        "## Configuration",
        "",
        "Every rule above can be switched on or off on its own with the `rules` execution gate; missing "
        "IDs inherit the shared defaults (all PII rules on; credential/secret DLP rules on, broader DLP "
        "families opt-in). `levels` (`l1`, `l2`, `l3`) switch layers, `models` switch whole producers "
        "(`native:pii`, `native:dlp`, …). `pii_mode` and `dlp_mode` choose the output mode: `strict` "
        "(default; every finding scores `1.0`), `balanced` or `recall` (model scores with thresholds "
        "0.50 and 0.30).",
        "",
        "Python:",
        "",
        CONFIG_PYTHON,
        "",
        "Rust:",
        "",
        CONFIG_RUST,
        "",
        "Ark API YAML:",
        "",
        CONFIG_YAML,
        "",
        "See the [configuration reference](configuration.md#execution-gates) for all gates and the "
        "[L1 rule catalog](l1-rule-catalog.md) for every rule ID, score and default.",
    ])
    return "\n".join(lines) + "\n"
