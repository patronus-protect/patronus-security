"""Generate docs/reference/l1-capabilities.md (called by scripts/generate_docs.py).

Sources: the PII and DLP rule registries (parsed by generate_docs.py, as for the rule catalog),
research/l1-pii/entity_map.yaml, research/dlp/entity_map.yaml, the checksum count of
scripts/l1_presidio/count_validated.py and the final reports of the L1 evaluation: the overall and
per-identifier tables of research/l1-pii/scoreboard/final-raw.md and the tool and group tables of
research/dlp/scoreboard/final.md. Speed and the name/place results are written here from
research/l1-pii/scoreboard/latency.md, research/dlp/scoreboard/latency.md and
research/l1-pii/scoreboard/2026-11-05.md, with the same numbers as the README section "How L1 compares".
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PII_ENTITY_MAP_PATH = ROOT / "research/l1-pii/entity_map.yaml"
DLP_ENTITY_MAP_PATH = ROOT / "research/dlp/entity_map.yaml"
PII_FINAL_PATH = ROOT / "research/l1-pii/scoreboard/final-raw.md"
DLP_FINAL_PATH = ROOT / "research/dlp/scoreboard/final.md"
COUNT_VALIDATED_PATH = ROOT / "scripts/l1_presidio/count_validated.py"

PII_STRENGTH_ORDER = ["checksum", "format", "none"]
DLP_STRENGTH_ORDER = ["checksum", "structure", "format", "none"]
PII_SCOPES = {
    "shared": "Ark and Presidio",
    "ark_only": "Ark only",
    "presidio_only": "Presidio only",
    "semantic": "names etc. (L3 model)",
}
DLP_SCOPES = {
    "shared": "Ark and scanners",
    "ark_only": "Ark only",
    "baseline_only": "scanners only",
    "out_of_scope": "not a value (policy)",
}
# Test data sets of the PII evaluation (report key -> plain name).
PII_TEST_DATA = {
    "neutral": "Public PII corpora (Gretel finance, ai4privacy)",
    "presidio_favored": "Presidio's own evaluator and recognizer test data",
    "ark_authored": "Our German/EU synthetic set ¹",
}
PII_ENGINES = {
    "ark-strict": "Ark `strict` (default)",
    "ark-balanced": "Ark `balanced`",
    "ark-balanced-bare": "Ark balanced + bare formats",
    "presidio-default": "Presidio default",
    "presidio-tuned": "Presidio tuned",
}
DLP_TOOLS = {"ark": "**Ark L1** ²", "gitleaks": "gitleaks 8.30.1", "trufflehog": "TruffleHog 3.97.9 ³",
             "detect-secrets": "detect-secrets 1.5.0"}

CONFIG_PYTHON = """```python
scanner.set_execution_gates({
    "l1": True, "l2": False, "l3": False,
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

METHOD = """## How we measured

- **Test data.** PII: three sets, each with labelled values and look-alike values that are not PII
  (order numbers, hashes, version strings and similar): public PII corpora (Gretel finance,
  ai4privacy), Presidio's own evaluator and recognizer test data, and a German/EU synthetic set
  that we wrote ourselves. Secrets: synthetic files (.env, YAML, JSON, code, logs, command lines,
  German and English prose) with generated secret values, 37.8 MB of normal code from 8
  repositories and 7.5 MB of normal documents.
- **Scoring.** A finding counts only when its span matches the labelled span exactly. Every
  labelled value counts, including ones Ark skips on purpose (see *Where Presidio is ahead*).
  F1, precision and recall are in percent.
- **Ark modes.** The default PII mode `strict` reports rule matches only. `balanced`
  (`pii_mode: balanced`) also scores matches by their context and reports checksum-valid numbers
  without a field name. *Balanced + bare formats* adds the opt-in
  [bare-format rules](../how-to/pii-bare-formats.gates.json) (tax IDs, LANR, BSNR, SIN, NPI and
  similar numbers without a field name next to them). Secrets are measured in the default profile.
- **Other tools.** Presidio 2.2.364, once with its default recognizers and once with a tuned
  profile (German recognizers and context words added). gitleaks 8.30.1, TruffleHog 3.97.9 (run
  with `--no-verification`, so it checks formats only, like the other tools) and detect-secrets
  1.5.0 in their default configuration.

¹ Written by us for German and EU identifiers; shown for completeness, not used for our own
conclusions."""

PII_NOTES = """- **Checksums:** Ark validates check digits for {ark_units} identifier types, Presidio for {presidio_units}.
- **Where Presidio is ahead:** on some identifiers of Presidio's own data (IP addresses, US SSNs,
  Indian GSTIN, Singapore NRIC/FIN, UK NINO) Presidio scores higher, because that data labels
  loopback addresses such as `127.0.0.1`, numbers with an invalid check digit and a NINO with a
  leading space. Ark does not report these on purpose; the opt-in
  [compatibility profile](../how-to/pii-presidio-compat.gates.json) reports loopback addresses and
  never-issued SSNs. On the German rows of Presidio's data, Presidio tuned leads unless the
  bare-format rules are on, and with them Ark loses some US SSN precision on the public corpora
  (bare nine-digit numbers). Presidio default also leads on passport and bank account numbers of
  its own data, which it matches without a field name, and Presidio tuned on some licence plate
  forms. The table [per identifier](#accuracy-per-identifier) shows every case.
- **`strict` vs. `balanced`:** `strict` misses identifiers that Presidio's data shows without a
  field name, mostly phone numbers, US SSNs, national IDs and German numbers; `balanced` finds
  them by context and checksum."""

NAMES = """### Names, places, organisations

Names, places and organisations are not part of L1; Ark finds them with the optional L3 model
(`dynamic-pii`, GLiNER, `max_level="l3"`), compared with Presidio's spaCy NER (`en_core_web_lg`;
tuned adds `de_core_news_lg`). F1 in % over PERSON, LOCATION and ORGANIZATION, measured on
2026-11-05:

| Test data | Language | Ark L1 + GLiNER | Presidio default | Presidio tuned |
| --- | --- | ---: | ---: | ---: |
| Public PII corpora | English | **54.7** | 30.2 | 30.2 |
| Public PII corpora | German | **44.0** | 7.4 | 27.5 |
| Presidio's evaluator data | English | **65.4** | 58.8 | 58.8 |
| Our German/EU synthetic set ¹ | English | **70.0** | 54.0 | 54.0 |
| Our German/EU synthetic set ¹ | German | **69.9** | 31.0 | 42.9 |

Presidio 2.2.364 reports no organisations by default. The L3 model takes several times longer per
text than Presidio's spaCy model; L1 alone is unaffected."""

DLP_NOTES = """² Includes the opt-in business-identifier rules (German VAT IDs, commercial register numbers,
BSNR, case, contract, order, invoice, project and organisation IDs), which cause all false positives
on look-alikes; the default rules have none. These opt-in rules are still weak (F1 50.0 for
commercial register numbers, 28.6 for BSNR, 18.2 for the others), and no scanner has them.

³ Run with `--no-verification`, so it checks formats only, like the other tools.

⁴ From an earlier run (2026-11-02) on the same data and versions.

On generic credentials (passwords, tokens and connection strings in config files, command lines
and prose) the scanners are weakest. **Where gitleaks is ahead:** it knows more provider formats.
Ark covers 91 of its 222 default rules and 139 secret formats in total; per provider and coverage
matrix: [DLP coverage and comparison](dlp-comparison.md)."""

SPEED = """## Speed

95th percentile per 100 KiB text on the same 6-vCPU machine, one call per text:

| Detection | Tool | 100 KiB p95 | Throughput (10 MiB repository) | Measured |
| --- | --- | ---: | ---: | --- |
| PII | Ark L1, Rust | 9.8 ms | – | 2026-11-05 |
| PII | Ark L1, Python | 15.0 ms | – | 2026-11-05 |
| PII | Presidio default | 13.6 s | – | 2026-11-02 |
| PII | Presidio tuned | 12.0 s | – | 2026-11-02 |
| Secrets | Ark L1, Rust | 8.0 ms | – | 2026-11-10 |
| Secrets | Ark L1, Python | 8.6 ms | – | 2026-11-10 |
| Secrets | Ark L1, Python, including the first scan in a new process ⁵ | 16.6 ms | 10.37 MiB/s | 2026-11-10 |
| Secrets | gitleaks 8.30.1 (one process per text) | 918 ms | 5.11 MiB/s | 2026-11-10 |

The machine is shared, so single runs spread: five later runs of PII in Rust measured 9.6–10.8 ms
(median 10.3 ms). See also [Performance & memory](../concepts/performance.md).

⁵ The first scan in a new process builds the regex state."""


def checksum_counts() -> tuple[int, int]:
    """Ark and Presidio identifier types with check-digit validation in the current registry."""
    spec = importlib.util.spec_from_file_location("_ark_count_validated", COUNT_VALIDATED_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    counts = module.count(module.ENTITY_MAP_MODULE.load(), module.load_rules())
    return len(counts.ark), len(counts.presidio)


def report_table(path: Path, header_start: str) -> list[dict[str, str]]:
    """Rows of the first Markdown table in `path` whose header line starts with `header_start`;
    cells are stripped of bold markers and footnote marks."""
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(header_start))
    header = _cells(lines[start])
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        rows.append(dict(zip(header, _cells(line))))
    return rows


def _cells(line: str) -> list[str]:
    return [cell.strip().replace("**", "").rstrip("¹²³⁴ ").strip() for cell in line.strip().strip("|").split("|")]


def report_number(cell: str) -> float:
    """A number of a report cell, in English (`91.3`, `1134`) or German (`91,3`, `1 731`) notation."""
    cell = cell.replace(" ", "").replace(" ", "").replace(" ", "")
    if "," in cell and "." not in cell:
        cell = cell.replace(",", ".")
    return float(cell)


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
    bare = any(rule["id"].endswith("_bare") for rule in rules)
    compat = any(rule["id"].endswith("_compat") for rule in rules)
    rules = [rule for rule in rules if not rule["id"].endswith(("_bare", "_compat"))]
    scored = [rule for rule in rules if rule["scored_only"]]
    if len(scored) == len(rules):
        state = "on (`balanced`/`recall` only)"
    elif scored:
        state = f"on ({len(scored)} of {len(rules)} rules `balanced`/`recall` only)"
    else:
        state = "on"
    # The bare form of an id is off until the `rules` gate enables it, and so is its compatibility form.
    state = f"{state}, bare form opt-in" if bare else state
    return f"{state}, compatibility form opt-in" if compat else state


def _f1_cells(values: list[float]) -> list[str]:
    """F1 values with one decimal, the best of the row in bold."""
    best = max(values)
    return [f"**{value:.1f}**" if value == best else f"{value:.1f}" for value in values]


def pii_overall_lines(rows: list[dict[str, str]]) -> list[str]:
    """Overall F1 per test data set (and its English and German rows) and false positives on
    look-alikes, from the overall table of the PII final report."""
    by_key = {(row["Family"], row["Engine"]): row for row in rows}
    engines = list(PII_ENGINES)
    lines = [
        "| Test data | " + " | ".join(PII_ENGINES.values()) + " |",
        "| --- |" + " ---: |" * len(engines),
    ]
    for family, name in PII_TEST_DATA.items():
        for column, label in (("Exact F1", name), ("EN F1", "— of which English"), ("DE F1", "— of which German")):
            values = [report_number(by_key[(family, engine)][column]) for engine in engines]
            lines.append(f"| {label} | " + " | ".join(_f1_cells(values)) + " |")
    lines.extend([
        "",
        "False positives on look-alike values that are not PII (count of wrongly reported values):",
        "",
        "| Test data | " + " | ".join(PII_ENGINES.values()) + " |",
        "| --- |" + " ---: |" * len(engines),
    ])
    for family, name in PII_TEST_DATA.items():
        values = [int(report_number(by_key[(family, engine)]["HN-FP"])) for engine in engines]
        lines.append(f"| {name} | " + " | ".join(f"{value:,}" for value in values) + " |")
    return lines


def pii_entity_lines(rows: list[dict[str, str]], entity_order: list[str]) -> list[str]:
    """F1 per identifier and test data set, from the per-entity appendix of the PII final report."""
    order = {entity_id: index for index, entity_id in enumerate(entity_order)}
    families = list(PII_TEST_DATA)
    rows = sorted(rows, key=lambda row: (order.get(row["Entity"], len(order)), families.index(row["Family"])))
    engines = list(PII_ENGINES)
    lines = [
        "| Identifier type | Test data | Labelled values | " + " | ".join(PII_ENGINES.values()) + " |",
        "| --- | --- | ---: |" + " ---: |" * len(engines),
    ]
    short = {"neutral": "public corpora", "presidio_favored": "Presidio's data"}
    for row in rows:
        values = [report_number(row[engine]) for engine in engines]
        lines.append(
            f"| `{row['Entity']}` | {short[row['Family']]} | {row['Gold']} | " + " | ".join(_f1_cells(values)) + " |"
        )
    return lines


def dlp_result_lines(tools: list[dict[str, str]], groups: list[dict[str, str]]) -> list[str]:
    """Tool and group tables of the DLP final report."""
    lines = [
        "| Tool | Precision | Recall | F1 | False positives on look-alikes | False positives per MB of normal code |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    # (report column, higher is better, format); the best value of each column is bold.
    columns = [("P", True, "{:.1f}"), ("R", True, "{:.1f}"), ("F1", True, "{:.1f}"),
               ("HN-FP (Spans)", False, "{:,.0f}"), ("Code-FP/MB", False, "{:.3f}")]
    best = {column: (max if higher else min)(report_number(row[column]) for row in tools)
            for column, higher, _ in columns}
    for row in tools:
        cells = []
        for column, _, fmt in columns:
            value = report_number(row[column])
            cells.append(f"**{fmt.format(value)}**" if value == best[column] else fmt.format(value))
        if row["Tool"] not in ("ark", "gitleaks"):
            cells[-1] += " ⁴"
        lines.append(f"| {DLP_TOOLS[row['Tool']]} | " + " | ".join(cells) + " |")
    scanners = ["gitleaks", "TruffleHog", "detect-secrets"]
    lines.extend([
        "",
        "F1 per secret group, default rules:",
        "",
        "| Group | Labelled values | Ark | " + " | ".join(scanners) + " |",
        "| --- | ---: | ---: |" + " ---: |" * len(scanners),
    ])
    for row in groups:
        values = [report_number(row[column]) for column in ["ARK", *scanners]]
        lines.append(f"| {row['Gruppe']} | {row['Gold']} | " + " | ".join(_f1_cells(values)) + " |")
    return lines


def _baseline_rules(entity: dict) -> str:
    parts = [
        f"{name}: {_code(entity.get(key))}"
        for key, name in (("gitleaks", "gitleaks"), ("trufflehog", "TruffleHog"), ("detect_secrets", "detect-secrets"))
        if entity.get(key)
    ]
    return "; ".join(parts) or "–"


def generate(
    pii_rules: list[dict],
    dlp_rules: list[dict],
    default_on_groups: set[str],
    relationship_rules: list[tuple[str, str, str, bool]],
) -> str:
    pii_map = yaml.safe_load(PII_ENTITY_MAP_PATH.read_text(encoding="utf-8"))
    dlp_map = yaml.safe_load(DLP_ENTITY_MAP_PATH.read_text(encoding="utf-8"))
    ark_units, presidio_units = checksum_counts()

    pii_labels = list(dict.fromkeys(rule["entity_group"] for rule in pii_rules))
    dlp_labels = list(dict.fromkeys(rule["entity_group"] for rule in dlp_rules))
    pii_by_label: dict[str, list[dict]] = {}
    for rule in pii_rules:
        pii_by_label.setdefault(rule["entity_group"], []).append(rule)
    dlp_by_id = {rule["id"]: rule for rule in dlp_rules}
    scanners = ", ".join(
        f"{name} {dlp_map['baselines'][key]['version']}"
        for key, name in (("gitleaks", "gitleaks"), ("trufflehog", "TruffleHog"), ("detect_secrets", "detect-secrets"))
    )

    lines = [
        "# L1 capabilities",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "What Ark L1 (rules and validators, no model) detects for personal data (PII) and secrets "
        "(DLP), how accurate and how fast it is compared with Presidio and the secret scanners "
        "gitleaks, TruffleHog and detect-secrets, and how it is configured. Accuracy and speed are our "
        "own measurements on public and synthetic test data (PII on 2026-11-08, secrets on 2026-11-10); "
        "rule counts and coverage come from the current code. Every rule is listed in the "
        "[L1 rule catalog](l1-rule-catalog.md).",
        "",
        "## Summary",
        "",
        "| | PII | Secrets (DLP) |",
        "| --- | --- | --- |",
        f"| Result labels | {len(pii_labels)} | {len(dlp_labels)} |",
        f"| Regex rules | {len(pii_rules)} | {len(dlp_rules)} (+{len(relationship_rules)} relationship rules) |",
        f"| Identifier types with check-digit validation | {ark_units} (Presidio "
        f"{pii_map['presidio_version']}: {presidio_units}) | – |",
        f"| Rules with a `checksum` or `structure` check | "
        f"{sum(rule['strength'] == 'checksum' for rule in pii_rules)} | "
        f"{sum(rule['validator_strength'] in ('checksum', 'structure') for rule in dlp_rules)} |",
        "| Default state | all rules on except the opt-in bare and compatibility forms | credential/secret "
        "groups and classification markings on, broader families opt-in |",
        f"| Compared with | Presidio {pii_map['presidio_version']} (default and tuned) | {scanners} |",
        "",
        METHOD,
    ]

    # ── PII ──
    lines.extend([
        "",
        "## PII",
        "",
        "### Accuracy",
        "",
        "F1 in %, best of each row in bold. Names, places and organisations are not part of L1 "
        "(see below).",
        "",
        *pii_overall_lines(report_table(PII_FINAL_PATH, "| Family | Engine |")),
        "",
        PII_NOTES.format(ark_units=ark_units, presidio_units=presidio_units),
        "",
        NAMES,
    ])

    entities = pii_map["entities"]
    lines.extend([
        "",
        "### Coverage",
        "",
        "One row per identifier type. Covered by: whether Ark, Presidio or both match it by pattern; "
        "names, places and organisations are found only by the optional L3 model (see "
        "[Dynamic PII](configuration.md#dynamic-pii)). Check: the strongest validator of its rules "
        "(`checksum`: check digits computed; `format`: length, alphabet, range or date; `pattern`: "
        "regex shape only; `context`: regex shape plus a field name or nearby term).",
        "",
        "| Identifier type | Covered by | Ark label(s) | Rule ID(s) | Check | Default | Presidio entities |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for scope, scope_name in PII_SCOPES.items():
        for entity in (e for e in entities if e["scope"] == scope):
            rules = [rule for label in entity.get("ark") or [] for rule in pii_by_label.get(label, [])]
            lines.append(
                f"| `{entity['id']}` | {scope_name} | {_code(entity.get('ark'))} "
                f"| {_code([rule['id'] for rule in rules])} | {_pii_check(rules) if rules else '–'} "
                f"| {_pii_default(rules)} | {_code(entity.get('presidio'))} |"
            )
    counts = {scope: sum(e["scope"] == scope for e in entities) for scope in PII_SCOPES}
    lines.extend([
        "",
        f"Identifier types: {counts['shared']} covered by Ark and Presidio, {counts['ark_only']} by Ark only, "
        f"{counts['presidio_only']} by Presidio only, {counts['semantic']} names and similar entities.",
        "",
        "### Accuracy per identifier",
        "",
        "F1 in % per identifier type on the public PII corpora and on Presidio's own data, best of each "
        "row in bold. Labelled values: how many values of the type the test data holds; with only a few, "
        "one value moves the F1 a lot. Our synthetic set is not broken down per identifier.",
        "",
        *pii_entity_lines(report_table(PII_FINAL_PATH, "| Family | Entity | Scope | Gold |"),
                          [entity["id"] for scope in PII_SCOPES for entity in entities if entity["scope"] == scope]),
    ])

    # ── DLP ──
    taxonomy = dlp_map["taxonomy"]
    dlp_entities = dlp_map["entities"]
    lines.extend([
        "",
        "## Secrets (DLP)",
        "",
        "### Accuracy",
        "",
        *dlp_result_lines(report_table(DLP_FINAL_PATH, "| Tool | P |"),
                          report_table(DLP_FINAL_PATH, "| Gruppe | Gold |")),
        "",
        DLP_NOTES,
        "",
        "### Groups",
        "",
        "Credential/secret groups are on by default; business identifiers, metrics and content classes "
        "are opt-in per rule.",
        "",
        "| Result label | Kind | Default | Rules | Entities |",
        "| --- | --- | --- | --- | --- |",
    ])
    groups = list(dict.fromkeys(list(taxonomy) + dlp_labels))
    for group in groups:
        kind = (taxonomy.get(group) or {}).get("family", "–").replace("_", " ")
        if (taxonomy.get(group) or {}).get("planned"):
            kind += " (planned)"
        rule_count = sum(rule["entity_group"] == group for rule in dlp_rules)
        entity_count = sum(e.get("group") == group and e["scope"] in ("shared", "ark_only") for e in dlp_entities)
        lines.append(
            f"| `{group}` | {kind} | {'on' if group in default_on_groups else 'off'} | {rule_count} "
            f"| {entity_count} |"
        )

    lines.extend([
        "",
        "### Coverage",
        "",
        "One row per secret or content type. Covered by: Ark, at least one scanner, or both; \"not a "
        "value\" marks action or policy rules. Structure check: the strongest validator of its rules "
        "(`checksum`, `structure`: decoded or parsed, `format`, `none`). Scanner rules: the gitleaks, "
        "TruffleHog and detect-secrets rules for the same type.",
        "",
        "| Type | Covered by | Group | Rule ID(s) | Structure check | Default | Scanner rules |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    relationship_defaults = {rule_id: default for rule_id, _, _, default in relationship_rules}
    for scope, scope_name in DLP_SCOPES.items():
        for entity in (e for e in dlp_entities if e["scope"] == scope):
            ark = entity.get("ark") or []
            regex = [dlp_by_id[rule_id] for rule_id in ark if rule_id in dlp_by_id]
            check = _strongest([rule["validator_strength"] for rule in regex], DLP_STRENGTH_ORDER) if regex else "–"
            if regex:
                default = "on" if any(rule["entity_group"] in default_on_groups for rule in regex) else "off"
            elif ark:
                default = "on" if any(relationship_defaults.get(rule_id) for rule_id in ark) else "off"
            else:
                default = "–"
            lines.append(
                f"| `{entity['id']}` | {scope_name} | {_code([entity['group']] if entity.get('group') else [])} "
                f"| {_code(ark)} | {check} | {default} | {_baseline_rules(entity)} |"
            )
    dlp_counts = {scope: sum(e["scope"] == scope for e in dlp_entities) for scope in DLP_SCOPES}
    lines.extend([
        "",
        f"Types: {dlp_counts['shared']} covered by Ark and scanners, {dlp_counts['ark_only']} by Ark only, "
        f"{dlp_counts['baseline_only']} by scanners only, {dlp_counts['out_of_scope']} not a value.",
        "",
        SPEED,
    ])

    # ── Configuration ──
    lines.extend([
        "",
        "## Configuration",
        "",
        "Every rule above can be switched on or off on its own with the `rules` execution gate; missing "
        "IDs inherit the shared defaults (all PII rules on except the opt-in bare and compatibility forms; "
        "credential/secret DLP rules and classification markings on, broader DLP families opt-in). "
        "`levels` (`l1`, `l2`, `l3`) switch layers, `models` switch whole producers "
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
