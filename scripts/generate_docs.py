#!/usr/bin/env python3
"""Generate public Markdown docs from source comments and asset metadata."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
SNAPSHOT_PATH = DOCS_DIR / "asset-size-snapshot.json"

INJECTION_CATALOG_PATHS = [
    ROOT / "ark-core/src/detectors/injection/rules/skillspector_0_1_7.json",
    ROOT / "ark-core/src/detectors/injection/rules/prompt_armor_95e532e.json",
    ROOT / "ark-core/src/detectors/injection/rules/source_derived_p0_0_1_6.json",
    ROOT / "ark-core/src/detectors/injection/rules/source_derived_coverage_0_1_6.json",
    ROOT / "ark-core/src/detectors/injection/rules/prompt_armor_canonical_lexicons_0_1_6.json",
]
INJECTION_NATIVE_REGISTRY_PATH = (
    ROOT / "ark-core/src/detectors/injection/rules/ark_native_71ff48e.json"
)

CATEGORY_NAMES = {
    "Injection": "injection",
    "Dlp": "dlp",
    "Pii": "pii",
    "DynamicPii": "dynamic-pii",
    "SensitiveDocument": "sensitive_document",
    "ToolClass": "tool_class",
    "ToolAction": "tool_action",
    "ToolTags": "tool_tags",
    "Routing": "routing",
    "Threat": "threat",
    "ShellCommand": "shell_command",
}

CATEGORY_ORDER = [
    "Injection",
    "Dlp",
    "Pii",
    "DynamicPii",
    "SensitiveDocument",
    "ToolClass",
    "ToolAction",
    "ToolTags",
    "Routing",
    "Threat",
    "ShellCommand",
]


@dataclass(frozen=True)
class Asset:
    category: str
    level: str
    repo: str
    source_path: str
    destination_path: str
    required: bool
    # Pipeline model bundles are cached relative to the model root rather than
    # below the category directory.
    bundle: bool = False


def parse_assets() -> list[Asset]:
    full_source = (ROOT / "rust/src/assets/specs.rs").read_text()
    source = full_source.split("pub const ASSET_MANIFEST", 1)[1]
    source = source.split("pub const NTDB_L2_PACKAGE_MANIFEST", 1)[0]
    assets: list[Asset] = []
    for block in re.findall(r"\bAssetSpec\s*\{(.*?)\}", source, flags=re.S):
        category = _field(block, "category").replace("SecurityCategory::", "")
        level = _field(block, "level").replace("SecurityLevel::", "")
        assets.append(
            Asset(
                category=category,
                level=level,
                repo=_field(block, "repo").strip('"'),
                source_path=_field(block, "source_path").strip('"'),
                destination_path=_field(block, "destination_path").strip('"'),
                required=_field(block, "required") == "true",
            )
        )
    for const_name, level in (("DYNAMIC_PII_ASSET", "L3"), ("SHELL_COMMAND_ASSET", "L1")):
        assets.extend(_pipeline_bundle_assets(full_source, const_name, level))
    return assets


def _pipeline_bundle_assets(full_source: str, const_name: str, level: str) -> list[Asset]:
    block = full_source.split(f"pub const {const_name}", 1)[1].split("};", 1)[0]
    category = _field(block, "category").replace("SecurityCategory::", "")
    repo = _field(block, "repo").strip('"')
    destination = _field(block, "destination_path").strip('"')
    files_block = block.split("files: &[", 1)[1].split("],", 1)[0]
    return [
        Asset(
            category=category,
            level=level,
            repo=repo,
            source_path=filename,
            destination_path=f"{destination}/{filename}",
            required=True,
            bundle=True,
        )
        for filename in re.findall(r'"([^"]+)"', files_block)
    ]


@dataclass(frozen=True)
class NtdbPackage:
    category: str
    model: str
    repo: str
    revision: str
    source_prefix: str
    destination_path: str


def parse_ntdb_packages() -> list[NtdbPackage]:
    source = (ROOT / "rust/src/assets/specs.rs").read_text()
    source = source.split("pub const NTDB_L2_PACKAGE_MANIFEST", 1)[1]
    packages: list[NtdbPackage] = []
    for block in re.findall(r"\bNtdbL2PackageAssetSpec\s*\{(.*?)\}", source, flags=re.S):
        packages.append(
            NtdbPackage(
                category=_field(block, "category").replace("SecurityCategory::", ""),
                model=_field(block, "model").strip('"'),
                repo=_field(block, "repo").strip('"'),
                revision=_field(block, "revision").strip('"'),
                source_prefix=_field(block, "source_prefix").strip('"'),
                destination_path=_field(block, "destination_path").strip('"'),
            )
        )
    return packages


def _field(block: str, name: str) -> str:
    match = re.search(rf"{name}:\s*([^,\n]+)", block)
    if not match:
        raise ValueError(f"Missing {name} in AssetSpec block")
    value = match.group(1).strip()
    # Runtime and documentation use the same official model metadata.
    if "patronus_ark_core::warmup::" in value:
        constants = (ROOT / "ark-core/src/warmup.rs").read_text()
        for constant, literal in re.findall(r'pub const (WOLF_\w+): &str\s*=\s*"([^"\n]+)";', constants):
            value = value.replace(f"patronus_ark_core::warmup::{constant}", json.dumps(literal))
    return value


def parse_native_patterns(
    path: Path, struct_name: str, registry: str = r"\w+"
) -> list[dict[str, str]]:
    """Rules of the static `struct_name` registry in `path`, in registry order.

    Entries are inline struct literals or `module::CONST` references to
    `const CONST: Struct = Struct { ... };` items in the sibling `module.rs`.
    """
    source = path.read_text()
    static_start = re.search(
        rf"pub(?:\(\w+\))? (?:static|const) {registry}:\s*&\[{struct_name}\]\s*=\s*&\[",
        source,
    )
    if not static_start:
        raise ValueError(f"Missing static {struct_name} registry in {path}")
    source = source[static_start.end():]
    body = source[:re.search(r"^\}?\];", source, flags=re.M).end()]
    reference = r"^\s*(\w+)::(\w+),\s*$"
    if re.search(reference, body, flags=re.M):
        blocks = []
        entry = rf"\b{struct_name}\s*\{{(.*?)\n\s*\}},|{reference}"
        for match in re.finditer(entry, body, flags=re.S | re.M):
            if match.group(1) is not None:
                blocks.append(match.group(1))
            else:
                blocks.append(_native_pattern_const(path.parent, struct_name, *match.group(2, 3)))
    else:
        blocks = re.findall(rf"\b{struct_name}\s*\{{(.*?)\n\s*\}}(?:,|\];)", body, flags=re.S)
    patterns = []
    for block in blocks:
        name = re.search(r'\bname:\s*"([^"]+)"', block)
        entity_group = re.search(r'\bentity_group:\s*"([^"]+)"', block)
        if name and entity_group:
            validator = re.search(r"Some\((?:\w+::)*(\w+)\)", _field(block, "validator"))
            strength = re.search(r"\bstrength:\s*(?:\w+::)*(\w+),", block)
            base_score = re.search(r"\bbase_score:\s*(\d+),", block)
            pattern = {
                "id": name.group(1),
                "entity_group": entity_group.group(1),
                "validated": validator is not None,
                "validator": validator.group(1) if validator else None,
                "strength": strength.group(1).lower() if strength else None,
                "base_score": int(base_score.group(1)) if base_score else None,
                "field_context": re.search(r"\bcaptured_value:\s*true\b", block) is not None,
                "requires_context": re.search(r"\brequires_context:\s*true\b", block) is not None,
                "scored_only": re.search(r"\bscored_only:\s*true\b", block) is not None,
                "span_group": re.search(r"\bspan_group:\s*Some\(", block) is not None,
            }
            meta = re.search(r'\bmeta:\s*RuleMeta::new\(\s*ValidatorStrength::(\w+),\s*"([^"]+)"', block)
            if meta:
                provider = re.search(r'\.with_provider\(\s*"([^"]+)"\s*\)', block)
                subtype = re.search(r"\.with_subtype\(\s*SecretSubtype::(\w+)\s*\)", block)
                pattern.update(
                    validator_strength=meta.group(1).lower(),
                    source_ref=meta.group(2),
                    provider=provider.group(1) if provider else None,
                    subtype=re.sub(r"(?<!^)(?=[A-Z])", "_", subtype.group(1)).lower() if subtype else None,
                )
            patterns.append(pattern)
    return patterns


def parse_dlp_patterns() -> list[dict[str, str]]:
    """DLP rules from the family modules, in the registry order of `rules/mod.rs`."""
    rules_dir = ROOT / "ark-core/src/detectors/dlp/rules"
    parts = re.search(r"const PARTS:[^=]*=\s*&\[(.*?)\];", (rules_dir / "mod.rs").read_text(), re.S)
    if not parts:
        raise ValueError(f"Missing DLP rule registry in {rules_dir / 'mod.rs'}")
    patterns = []
    for module, registry in re.findall(r"(\w+)::(\w+)", parts.group(1)):
        patterns.extend(parse_native_patterns(rules_dir / f"{module}.rs", "DlpPattern", registry))
    for pattern in patterns:
        if "validator_strength" not in pattern:
            raise ValueError(f"Missing RuleMeta for {pattern['id']}")
    return patterns


def _source_ref_cell(source_ref: str) -> str:
    if source_ref.startswith("https://"):
        return f"[{source_ref.removeprefix('https://').split('/')[0]}]({source_ref})"
    return f"`{source_ref}`"


def _native_pattern_const(directory: Path, struct_name: str, module: str, const: str) -> str:
    path = directory / f"{module}.rs"
    source = path.read_text() if path.is_file() else ""
    match = re.search(
        rf"\bconst {const}:\s*{struct_name}\s*=\s*{struct_name}\s*\{{(.*?)\n\}};",
        source,
        flags=re.S,
    )
    if not match:
        raise ValueError(f"Missing {struct_name} {module}::{const} in {path}")
    return match.group(1)


def pii_score_points(path: Path = ROOT / "ark-core/src/detectors/pii/score.rs") -> tuple[dict[str, int], int, list[int], int]:
    """Validator strength, field bonus, proximity tiers and counter-context penalty of the PII score model."""
    source = path.read_text()
    body = re.search(r"pub const fn points\(self\) -> u8 \{(.*?)\n    \}", source, flags=re.S)
    context = re.search(r"pub const FIELD_CONTEXT_POINTS: u8 = (\d+);", source)
    proximity = re.search(r"pub const PROXIMITY_CONTEXT_POINTS: \[\(usize, u8\); \d+\] = \[(.*?)\];", source)
    counter = re.search(r"pub const COUNTER_CONTEXT_POINTS: u8 = (\d+);", source)
    if not body or not context or not proximity or not counter:
        raise ValueError(f"Missing PII score points in {path}")
    strength = {name.lower(): int(points) for name, points in re.findall(r"Self::(\w+) => (\d+),", body.group(1))}
    tiers = [int(points) for _, points in re.findall(r"\((\d+), (\d+)\)", proximity.group(1))]
    return strength, int(context.group(1)), tiers, int(counter.group(1))


def pii_competing_labels(path: Path = ROOT / "ark-core/src/detectors/pii/overlap.rs") -> list[str]:
    """Labels whose overlapping findings `balanced` and `recall` resolve to one (K07)."""
    match = re.search(r"pub const COMPETING_LABELS: \[&str; \d+\] = \[(.*?)\];", path.read_text(), re.S)
    if not match:
        raise ValueError(f"Missing COMPETING_LABELS in {path}")
    return re.findall(r'"([A-Z_]+)"', match.group(1))


def pii_secondary_labels(path: Path = ROOT / "ark-core/src/detectors/pii/overlap.rs") -> list[str]:
    """Labels whose findings inside a reported IBAN `strict` marks as secondary evidence (T07)."""
    match = re.search(r"pub const SECONDARY_IN_IBAN: \[&str; \d+\] = \[(.*?)\];", path.read_text(), re.S)
    if not match:
        raise ValueError(f"Missing SECONDARY_IN_IBAN in {path}")
    return re.findall(r'"([A-Z_]+)"', match.group(1))


def pii_spelled_out_penalty(path: Path = ROOT / "ark-core/src/detectors/pii/score.rs") -> int:
    """Points a finding loses when only the `recall` obfuscation normalization reveals it (K06)."""
    match = re.search(r"pub const SPELLED_OUT_PENALTY_POINTS: u8 = (\d+);", path.read_text())
    if not match:
        raise ValueError(f"Missing SPELLED_OUT_PENALTY_POINTS in {path}")
    return int(match.group(1))


PII_LEXICON_PATH = ROOT / "ark-core/src/detectors/anchor_lexicons/pii.json"
PII_CONTEXT_PATH = ROOT / "ark-core/src/detectors/pii/context.rs"


def pii_context_lexicon(path: Path = PII_CONTEXT_PATH) -> tuple[dict[str, list[str]], list[str]]:
    """Support lexicon ids per PII label and the counter-context ids of the PII context engine."""
    source = path.read_text()
    support = re.search(r"pub static SUPPORT_LEXICON: .*? = &\[(.*?)\n\];", source, flags=re.S)
    counter = re.search(r"pub static COUNTER_LEXICON: &\[&str\] = &\[(.*?)\];", source, flags=re.S)
    if not support or not counter:
        raise ValueError(f"Missing PII context lexicon in {path}")
    labels = {
        label: re.findall(r'"(pii\.\w+)"', ids)
        for label, ids in re.findall(r'\(\s*"(\w+)",\s*&\[(.*?)\],?\s*\)', support.group(1), flags=re.S)
    }
    return labels, re.findall(r'"(pii\.\w+)"', counter.group(1))


def pii_context_lexicon_lines(labels: list[str], path: Path = PII_LEXICON_PATH) -> list[str]:
    """Catalog section: support lexicon ids per PII label and the counter-context terms."""
    entries = {entry["id"]: entry for entry in json.loads(path.read_text())}
    support, counter = pii_context_lexicon()
    lines = [
        "",
        "### PII context lexicon",
        "",
        "The context engine reads these DE/EN entries of `ark-core/src/detectors/anchor_lexicons/pii.json` "
        "(with their FR/ES/IT/NL field names where an entry lists them, T26); "
        "`ark-core/src/detectors/pii/context.rs` maps them to labels. Support terms of a label count for "
        "rules without a field name of their own, a counter-context term counts for every label when it "
        "is nearer than every support term. As a structural key (a JSON key, CSV or table header, XML "
        "element), a term of either kind names the value it holds; keys are compared lowercased, with "
        "`_`, `-`, `.` and camelCase boundaries as spaces, optionally followed by `no`, `nr`, `number` "
        "or `nummer`. The key `iban` names no account number.",
        "",
        "| Result entity group | Support anchors |",
        "| --- | --- |",
    ]
    for label in labels:
        anchors = ", ".join(f"`{anchor}`" for anchor in support.get(label, [])) or "—"
        lines.append(f"| `{label}` | {anchors} |")
    lines.extend(["", "| Counter-context anchor | DE | EN |", "| --- | --- | --- |"])
    for anchor in counter:
        entry = entries[anchor]
        de = ", ".join(f"`{word}`" for word in entry["de"] + entry["shared"])
        en = ", ".join(f"`{word}`" for word in entry["en"] + entry["shared"])
        lines.append(f"| `{anchor}` | {de} | {en} |")
    return lines


def pii_rule_score(rule: dict, strength_points: dict[str, int], context_points: int) -> float:
    points = rule["base_score"] + strength_points[rule["strength"]]
    points += context_points if rule["field_context"] else 0
    return min(points, 100) / 100


def pii_rule_context(rule: dict) -> str:
    if rule["field_context"]:
        return "field or key"
    if rule["scored_only"]:
        return "key or proximity, `balanced`/`recall` only"
    return "key or proximity (required)" if rule["requires_context"] else "key or proximity"


def pii_rule_score_range(rule: dict, strength_points: dict[str, int], context_points: int, tiers: list[int]) -> str:
    """Score without and with the best proximity context; context-bound rules need the weakest tier."""
    if rule["field_context"]:
        return f"{pii_rule_score(rule, strength_points, context_points):.2f}"
    points = rule["base_score"] + strength_points[rule["strength"]]
    low = points + min(tiers) if rule["requires_context"] else points
    return f"{min(low, 100) / 100:.2f}–{min(points + max(tiers), 100) / 100:.2f}"


def dlp_strength_points(path: Path = ROOT / "ark-core/src/detectors/dlp/score.rs") -> dict[str, int]:
    """Validator strength points of the DLP score model (K04)."""
    body = re.search(r"pub const fn points\(self\) -> u8 \{(.*?)\n    \}", path.read_text(), flags=re.S)
    if not body:
        raise ValueError(f"Missing DLP strength points in {path}")
    return {name.lower(): int(points) for name, points in re.findall(r"Self::(\w+) => (\d+),", body.group(1))}


def dlp_context_lexicon(path: Path = ROOT / "ark-core/src/detectors/dlp/context.rs") -> tuple[list[str], list[str]]:
    """Support and counter-context lexicon IDs of the DLP score model (K04)."""
    source = path.read_text()
    lists = []
    for name in ("SUPPORT_LEXICON", "COUNTER_LEXICON"):
        body = re.search(rf"pub static {name}: &\[&str\] = &\[(.*?)\];", source, flags=re.S)
        if not body:
            raise ValueError(f"Missing {name} in {path}")
        lists.append(re.findall(r'"([^"]+)"', body.group(1)))
    return lists[0], lists[1]


def dlp_rule_context(rule: dict, credential_groups: set[str]) -> str:
    """Context source of a DLP rule, as `detectors::dlp::context::source` decides it."""
    if rule["entity_group"].startswith(("dlp.content.", "dlp.internal.")):
        return "none"
    if rule["span_group"]:
        return "field"
    return "proximity" if rule["entity_group"] in credential_groups else "none"


def dlp_rule_score_range(rule: dict, context: str, strength_points: dict[str, int], context_points: int) -> str:
    points = rule["base_score"] + strength_points[rule["validator_strength"]]
    if context == "field":
        return f"{min(points + context_points, 100) / 100:.2f}"
    if context == "proximity":
        return f"{min(points, 100) / 100:.2f}–{min(points + context_points, 100) / 100:.2f}"
    return f"{min(points, 100) / 100:.2f}"


DLP_CREDENTIAL_GROUPS = {
    "API_KEY", "CLOUD_KEY", "CREDENTIAL", "CRYPTO_KEY", "PASSWORD_HASH",
    "PAYMENT_KEY", "PRIVATE_KEY", "SECRET_TOKEN",
}

# (rule ID, model gate, default on) of the DLP relationship rules.
DLP_RELATIONSHIP_RULES = [
    ("dlp_sensitive_material", "native:sensitive_material", True),
    ("dlp_secret_transfer", "native:secret_transfer", True),
    ("dlp_mcp_runtime_risk", "native:mcp_runtime_risk", False),
    ("dlp_mcp_policy", "native:mcp_policy", False),
    ("dlp_destructive_operation", "native:destructive_operation", False),
]


def generate_l1_rule_catalog_doc() -> str:
    pii = parse_native_patterns(ROOT / "ark-core/src/detectors/pii/pii.rs", "PiiPattern")
    strength_points, context_points, proximity_tiers, counter_points = pii_score_points()
    dlp = parse_dlp_patterns()
    dlp_points = dlp_strength_points()
    dlp_support, dlp_counter = dlp_context_lexicon()
    credential_groups = DLP_CREDENTIAL_GROUPS

    injection: dict[str, dict[str, str]] = {}
    for path in INJECTION_CATALOG_PATHS:
        payload = json.loads(path.read_text())
        for rule in payload["rules"]:
            rule_id = rule.get("canonical_id") or rule["id"]
            injection.setdefault(
                rule_id,
                {
                    "family": rule["family"],
                    "description": rule["description"],
                    "source": payload["catalog_id"],
                },
            )
    native_registry = json.loads(INJECTION_NATIVE_REGISTRY_PATH.read_text())
    for rule in native_registry["rules"]:
        injection.setdefault(
            rule["id"],
            {
                "family": rule["family"],
                "description": f"Native producer gate for {rule['model']}.",
                "source": native_registry["registry_id"],
            },
        )
    injection.setdefault(
        "ark.injection.structure.override_sensitive_disclosure",
        {
            "family": "instruction_override",
            "description": "Structural override plus sensitive-disclosure relationship.",
            "source": "native structural producer",
        },
    )

    lines = [
        "# L1 Rule Catalog",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "These are the stable rule IDs accepted by execution-gate `rules`. Missing IDs inherit the shared Rust/Python/API defaults below. Model gates such as `native:pii`, `native:dlp`, `native:injection_l1`, and `native:threat_l1` control complete producers; rule gates control individual entries below.",
        "",
        "For coverage per benchmark entity, the comparison with Presidio and the secret scanners, and latency, see [L1 capabilities](l1-capabilities.md).",
        "",
        f"## PII rules ({len(pii)})",
        "",
        "All PII rules are eligible by default when PII L1 is enabled.",
        "",
        "In the default `strict` PII mode every finding scores `1.0`. In `balanced` and `recall` "
        "a finding scores the rule base plus the validator strength "
        f"(checksum {strength_points['checksum']}, format {strength_points['format']}, none {strength_points['none']}) "
        f"plus its context, capped at 100 and divided by 100: {context_points} when the rule binds the value "
        f"to a field name, otherwise {'/'.join(str(points) for points in proximity_tiers)} for a support term "
        f"of the label near the value and -{counter_points} when a counter-context term is nearer "
        "(see [PII score and modes](result-schema.md#pii-score-and-modes), "
        "[PII context lexicon](#pii-context-lexicon)). "
        "Rules marked `proximity (required)` report only with a support term, in every mode. "
        "Rules marked `balanced`/`recall` only (K05) report a checksum value without a field name "
        "and never run in `strict`; the value must stand alone, not inside a longer number. "
        "Structure (K04): a JSON key, a `key: value`/`key=value` line, an XML element or attribute, a CSV "
        "header or a Markdown/HTML table header that a `field` rule accepts as its field name binds the value "
        "it holds to the rule in every mode, if the value matches the rule's value form in full; for the "
        "other rules a key of the label (or a counter-context key) that names exactly the value is its context "
        f"(+{context_points} or -{counter_points}) instead of proximity. "
        "Obfuscation (K06): every rule also sees values behind zero-width characters, full-width forms "
        "and defanged separators (`[.]`, `(@)`) in every mode, and in `recall` also spelled-out e-mail "
        "separators (`[at]`, `ät`, `dot`, `punkt`) and numbers spaced character by character "
        f"(-{pii_spelled_out_penalty()}); the span is the original text and the validator decides on the "
        "normalized value. "
        "Overlaps (K07): in `balanced` and `recall` overlapping findings of two different labels among "
        f"{', '.join(f'`{label}`' for label in pii_competing_labels())} resolve to one: an IBAN wins, then the "
        "longer value, context that supports its own label, a checksum, the higher score, the earlier rule; a "
        "finding inside a printed IBAN form (`DE64 7172 …`) yields even when its check digits fail. "
        "`strict` keeps both labels and lists "
        f"{' and '.join(f'`{label}`' for label in pii_secondary_labels())} findings inside a reported IBAN "
        "under `details.secondary_evidence` (T07); evaluations score primary findings only.",
        "",
        "| Rule ID | Result entity group | Extra validator | Validator strength | Base | Context | Score (`balanced`/`recall`) |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for rule in pii:
        lines.append(
            f"| `{rule['id']}` | `{rule['entity_group']}` | {'yes' if rule['validated'] else 'no'} "
            f"| {rule['strength']} | {rule['base_score']} | {pii_rule_context(rule)} "
            f"| {pii_rule_score_range(rule, strength_points, context_points, proximity_tiers)} |"
        )
    lines.extend(pii_context_lexicon_lines(list(dict.fromkeys(rule["entity_group"] for rule in pii))))

    lines.extend([
        "",
        f"## DLP regex rules ({len(dlp)})",
        "",
        "Rust, Python, and the Ark API enable only credential/secret entity groups by default. Set a rule to `true` to opt into a broader family. Low-level detector `evaluate()` calls bypass gateway execution gates and evaluate the full detector inventory.",
        "",
        "Every credential/secret rule drops documented example and test values: a marker word (`EXAMPLE`, `SAMPLE`, `BEISPIEL` or `MUSTER` at the start or end of a word, not inside one such as `resampler`; `TEST`/`TESTKEY`, `FAKE` or `DUMMY` as a whole word; any marker repeated). Values mostly made of repeated chunks or same-character runs are dropped for fixed-format provider, key, hash, JWT, signed-URL and session-ID rules, also when a generic rule captures such a provider-shaped value. Values that need a single sequential run (`AKIA1234567890ABCDEF`) to count as low-variety, and low-variety values of generic credential assignments, are dropped only when the same or one of the three lines above calls the value an example, sample, dummy, fixture or documentation value (DE/EN).",
        "",
        "Value-capturing credential rules (assignments, URL parameters and userinfo, signatures, auth headers, cookies, CSRF tokens, connection strings) also drop placeholders (`<…>`, masks, `TODO`, `CHANGEME`, `REPLACE_ME`, `BITTE_AENDERN`, all-upper or all-lower word sequences such as `YOUR_…_HERE`, `HIER_…_EINTRAGEN`, `YOUR-API-TOKEN`) and references (`$VAR`, `${…}`, `%VAR%`, `{{var}}`, Terraform `var.x`, `os.environ[…]`, `os.Getenv`, `System.getenv`, `Environment.GetEnvironmentVariable`, `ENV.fetch`, `process.env.X` and similar environment accessors). They also drop template syntaxes (`%(name)s`, `{name}`, `%{name}`, `@name@`, `__NAME__`, `!NAME!`, `((name))`, YAML tags such as `!secret` and CloudFormation `!Ref`), secret-manager references (`op://`, `ref+…://`, `@Microsoft.KeyVault(…)`, AWS Secrets Manager/SSM ARNs, GCP `projects/…/secrets/…`, `/run/secrets/…`), `null`/`None`, `changeit`, redaction words (`REDACTED`, `***REMOVED***`, `***ENTFERNT***`) and values that only name the credential (`my-access-token`, `SECRET_PASSWORD`).",
        "",
        "Every credential/secret rule also drops the vendor-documented example values of `research/dlp/documented_values.yaml` (stored as SHA-256 of the normalized value) and JWTs with the documented example claims of jwt.io and RFC 7519; publicly known test keys listed there (Hardhat/Anvil default accounts) stay findings with `severity` `test`.",
        "",
        "Each rule carries metadata v2, and every entry of `matched_rules` in the layer details reports it: `provider` for provider-bound formats, `validator_strength` (`checksum`: check digits verified; `structure`: decoded or parsed structure verified; `format`: fixed prefix, alphabet, length or syntax shape; `none`: keyword or context only), `source_ref` (`gitleaks:<rule-id>`, vendor or specification URL, or `ark` for in-house rules; see `research/dlp/rule_sources.yaml`) and, for credential/secret rules, `severity` (`test` for provider test/sandbox credentials such as Stripe `sk_test_`, otherwise `live`) and `subtype` (taxonomy v2, K09: what the value is within its group, see [DLP taxonomy](result-schema.md#dlp-taxonomy)). Provider, key and JWT rules drop values whose Shannon entropy is below 3.0 bits per character.",
        "",
        "Prefix rules (provider tokens, `dlp_eth_private_key`, `dlp_btc_wif`, `dlp_jwt_token`) report a value only as a whole token (T01): the characters right before and after it are no `[A-Za-z0-9_]` and none of the provider alphabet (`-` for base64url-style tokens), so a prefix inside an identifier (`load_hf_…`) or a hex run (Cargo.lock checksum, sha256 digest) is no finding. A value with a `+` or `/` neighbour inside a base64 run of at least 16 characters with upper case, lower case and digits (go.sum hash, npm integrity, data URI) is part of the blob. Escapes that end in a letter or digit (`\\n`, `\\t`, `\\uHHHH`, `\\xHH`, URL `%HH`) still delimit a token.",
        "",
        "`dlp_eth_private_key` also needs a key context (F01): `0x` and 64 hex digits is as often a transaction or block hash, a state or Merkle root, an event topic or a CREATE2 salt, so the value counts only next to a key term (private key, privkey, secret key, signing key, mnemonic, keystore, privater/geheimer Schlüssel; on its own line also wallet, signer, accounts, pk, key, Schlüssel), and not where a hash, root, ID or chain-data term (tx hash, transactionHash, blockHash, Transaktionshash, checksum, Prüfsumme, root, Zustandswurzel, topic, salt, nonce, public key …) labels it. The context is the value's line and up to five lines above it, back to the previous hex value; a term after the value counts on its line within a short gap unless it names the next field. A label (only separators between term and value, also across line breaks) decides; without one, a key term proper anywhere in the context supports the value (chat replies, mail bodies), otherwise the nearest term decides. Wallet and signer terms count only on the value's line or as its label. The value must also be a secp256k1 scalar (1 ≤ k < n). The gate applies in every DLP mode.",
        "",
        "`dlp_btc_wif` verifies Base58Check (F02): the version byte of mainnet (`0x80`; `5…` uncompressed, `K…`/`L…` compressed) or of testnet, signet and regtest (`0xef`; `9…`, `c…`), a secp256k1 scalar (1 ≤ k < n) and the `0x01` flag of compressed keys. Testnet keys have severity `test`. The rule scores at `checksum` strength, so a bare WIF key stays in `balanced`; a nearer checksum, hash or ID term still drops it there.",
        "",
        "`dlp_github_token` verifies the CRC32 of GitHub tokens (F03): `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` and exactly 36 base62 characters, of which the last six are the CRC32 of the first 30 as base62 digits; `dlp_github_pat` takes `github_pat_` and exactly 82 characters. A longer or shorter body is no token. The rule scores at `checksum` strength, so a bare token stays in `balanced`, also next to a counter term. A generic assignment, URL or header rule does not report a value that starts with a whole `gh…_` token shape whose CRC32 fails.",
        "",
        "`dlp_npm_token` verifies the CRC32 of npm tokens (F04): `npm_` and exactly 36 base62 characters, of which the last six are the CRC32 of the first 30, as for GitHub tokens; it scores at `checksum` strength, and a generic rule does not report an `npm_` token shape whose CRC32 fails. `dlp_gitlab_pat` takes `glpat-` and exactly 20 characters or the routable form (payload, `.`, a two-character version and a seven-character base36 check value, which is not verified; or the current form with `.01.`, the payload length as two base36 digits and a seven-digit base36 CRC32). `dlp_gitlab_token` takes the other documented GitLab prefixes with the lengths of the gitleaks rules: deploy (`gldt-`), runner (`glrt-`, or `glrtr-` when created through a registration token; also routable), workspace (`glwt-`, routable only), runner registration (`GR1348941`), pipeline trigger (`glptt-`, 40 lower-case hex digits), feed (`glft-`), incoming mail (`glimt-`), Kubernetes agent (`glagent-`), CI/CD job (`glcbt-`), SCIM (`glsoat-`) and feature flag client tokens (`glffct-`); `dlp_gitlab_oauth_secret` takes OAuth application secrets (`gloas-` and 64 characters) as `API_KEY` with subtype `secret_key`.",
        "",
        "DevOps and package-registry tokens (P05) are `SECRET_TOKEN` with subtype `access_token`: `dlp_dockerhub_token` takes Docker Hub personal (`dckr_pat_`) and organization (`dckr_oat_`) access tokens with 27 base64url characters; `dlp_pypi_token` takes `pypi-` and the base64url of a Macaroon V2 for `pypi.org` or `test.pypi.org` (severity `test`) and parses it completely (version, header with location and identifier, caveat sections, 32-byte signature) at `structure` strength; `dlp_rubygems_token` takes `rubygems_` and 48 lower-case hex digits; `dlp_cratesio_token` takes `cio` and 32 alphanumerics with upper- and lower-case letters; `dlp_packagist_token` takes the Private Packagist prefixes `packagist_ort_`, `packagist_out_`, `packagist_uut_` and `packagist_cut_`, 60 hex digits and the CRC32 of prefix and random part as eight hex digits at `checksum` strength (a generic rule does not report a Packagist token shape whose CRC32 fails); `dlp_jfrog_token` takes Artifactory API keys (`AKCp` and 69 alphanumerics) and reference tokens (`cmVmd` and 59); `dlp_terraform_cloud_token` takes HCP Terraform tokens (14 alphanumerics, `.atlasv1.`, 60 to 70 characters); `dlp_pulumi_token` takes `pul-` and 40 hex digits; `dlp_vault_token` takes Vault service (`hvs.`, 90 to 120 characters) and batch tokens (`hvb.`, 138 to 300); `dlp_vault_legacy_token` takes pre-1.10 service tokens (`s.` and 24 alphanumerics with both cases) only with `vault` on the value's line or up to five lines above it; `dlp_doppler_token` takes the documented Doppler prefixes (`dp.pt.`, `dp.ct.`, `dp.st.` with an optional scope, `dp.sa.`, `dp.said.`, `dp.scim.`, `dp.audit.`) with 40 to 44 alphanumerics.",
        "",
        "CI and hosting tokens (P06) carry the provider's entity group and subtype. Prefix rules with a token boundary: `dlp_azure_devops_pat` takes Azure DevOps PATs since 2024 (84 alphanumerics with the signature `AZDO` at positions 76 to 80, upper- and lower-case letters); `dlp_circleci_token` takes CircleCI personal (`CCIPAT_`) and project (`CCIPRJ_`) API tokens (a base58 UUID, `_` and 40 hex digits); `dlp_vercel_token` takes the Vercel prefixes `vcp_`, `vci_`, `vca_`, `vcr_` and `vck_` with 56 alphanumerics of both cases; `dlp_netlify_token` takes `nfp_` and 36 characters; `dlp_flyio_token` takes Fly.io OAuth tokens (`fo1_` and 43 characters); `dlp_heroku_api_key` takes `HRKU-AA` and 58 characters; `dlp_render_api_key` takes `rnd_` and 24 to 64 alphanumerics of both cases only with `render` on the value's line or up to five lines above it (Render documents no length); `dlp_cloudflare_origin_ca_key` takes `v1.0-`, 24 and 146 hex digits; `dlp_digitalocean_token` takes `dop_v1_`, `doo_v1_` and `dor_v1_` with 64 hex digits. `dlp_flyio_macaroon_token` takes Fly.io macaroon tokens (`fm1a_`, `fm1r_`, `fm2_` and 100 to 4096 base64 characters) without a token boundary, since `/` and `+` belong to the token. Key-anchored rules report the value under a key that names the provider and ends in a credential noun right before the separator (`TRAVIS_API_TOKEN=`, `\"netlify_auth_token\":`, `Heroku-API-Schlüssel:`, `Circle-Token:`): `dlp_bitbucket_client_secret` (64 characters, `API_KEY` with subtype `secret_key`), `dlp_azure_devops_legacy_pat` (52 lower-case alphanumerics under `azure devops`, `azdo` or `vsts`), `dlp_circleci_legacy_token` (40 hex digits), `dlp_travis_token` (22 alphanumerics), `dlp_vercel_legacy_token` (24 alphanumerics), `dlp_netlify_legacy_token` (40 to 46 characters), `dlp_heroku_legacy_api_key` and `dlp_railway_token` (UUIDs) and `dlp_cloudflare_api_key` (API tokens with 40 characters, Global API Keys with 37 hex digits). IDs under provider keys without a credential noun (`HEROKU_APP_ID`, `CIRCLE_SHA1`, `RAILWAY_PROJECT_ID`, `CLOUDFLARE_ZONE_ID`) are no credentials.",
        "",
        "Observability tokens and keys (P07): tokens are `SECRET_TOKEN` with subtype `access_token`, keys `API_KEY` with subtype `api_key`. Prefix rules with a token boundary: `dlp_newrelic_user_api_key` takes `NRAK-` and 27 alphanumerics; `dlp_newrelic_insert_key` takes `NRII-` and 32 or 25 characters; `dlp_newrelic_license_key` takes 32 hex digits, or `eu01xx` and 26, and the suffix `FFFFNRAL`; `dlp_sentry_user_token` takes `sntryu_` and 64 hex digits; `dlp_grafana_service_account_token` takes `glsa_`, 32 alphanumerics, `_` and the CRC32 of everything before that `_` as the hex of its little-endian bytes at `checksum` strength (a generic rule does not report a `glsa_` shape whose CRC32 fails); `dlp_dynatrace_token` takes `dt0c01` or `dt0s01` to `dt0s16`, the 24-character public and the 64-character secret portion. Base64 tokens, without a token boundary since `/` and `+` belong to them, are decoded and parsed at `structure` strength: `dlp_sentry_org_token` (`sntrys_`, the base64 of a JSON payload with a numeric `iat`, `_` and 43 base64 characters), `dlp_grafana_api_key` (the base64 of `{\"k\",\"n\",\"id\"}`, starting with `eyJrIjoi`) and `dlp_grafana_cloud_token` (`glc_` and the base64 of a JSON object with the key in `k`). Key-anchored rules report a value under a key that names the provider and ends in a credential noun right before the separator: `dlp_datadog_api_key` (32 hex digits or 40 characters under `datadog` or a leading `dd_`/`dd-`/`ddApi`/`ddApp`; the public client token `pub` and 32 hex digits is no secret for any rule), `dlp_newrelic_legacy_license_key` (40 hex digits), `dlp_sentry_auth_token` (64 hex digits), `dlp_splunk_hec_token` (a GUID, also after `Authorization: Splunk`), `dlp_elastic_api_key` (`id:api_key` with 20 and 22 base64url characters or its base64, also after `Authorization: ApiKey`; decoded and split at `structure` strength), `dlp_honeycomb_api_key` (22 alphanumerics with both cases or 32 hex digits, also in the `x-honeycomb-team` header and `OTEL_EXPORTER_OTLP_HEADERS`) and `dlp_pagerduty_api_key` (20 characters with both cases or a 32-hex integration key; in the `Token token=` scheme, which Rails shares, only with `pagerduty` on the value's line or up to five lines above it). `dlp_sentry_dsn_secret` reports the secret key of a legacy DSN (`https://<public key>:<secret key>@host/<project id>`, `API_KEY` with subtype `secret_key`); a DSN with the public key only is safe to expose and no finding.",
        "",
        "`dlp_aws_access_key` takes the credential prefixes of the IAM unique-ID table (F05): `AKIA` (long-term), `ASIA` (temporary), `ABIA` (STS service bearer token), `ACCA` (context-specific credential) or legacy `A3T` and one more character, then exactly 16 Base32 characters (`A-Z`, `2-7`). Group, user, role, policy and other unique IDs (`AGPA`, `AIDA`, `AROA`, `ANPA` …) are no credentials. `dlp_aws_secret_key` takes 40 base64 characters with upper and lower case letters as a whole run, only in structural AWS context: after an AWS key name or label (`aws_secret_access_key`, `AwsSecretAccessKey`, `aws.secretKey`, `AWS-Secret-Access-Key`, `SecretAccessKey`; in prose up to two lines on), right after an access key ID (SDK call, IAM credentials CSV, CLI), or after a generic `secret_key`, `secret-key` or `secretKey` with AWS context within five lines above or two below (an access key ID or `access_key` key, Terraform `provider \"aws\"` or `backend \"s3\"`, `amazonaws.com`, `aws` as a name part). Hex digests, longer base64 runs and single-case values are no secret key.",
        "",
        "The generic credential rules need password likeness (F-GEN1). `dlp_password_assignment` and `dlp_generic_credential_assignment` drop a value that is a code expression (call, index or member access, `Token::…` path, type annotation such as `str`, `string|null`, `Option<&str>`, `Arc<…>`, format placeholder `%s`, ABNF repetition), a key or label ending in `:`, a file path, or that follows a shell variable used as key (`$PWD:/work`); a quoted value is a string literal and only checked for paths and stand-ins. A value of letters and `_`/`-`/`.` only is dropped if it is a DE/EN dictionary word sequence or word form (`falsch`, `abgelaufen`, `stored`, `case-sensitive`), names a credential in one naming convention (`GIT_PASSWORD`, `passwordGenerator`, `clientSecret`) or is a test stand-in (`password`, `pass`, `topSecret`, `realtoken`, `foo001`). A value with a digit or another symbol is never a word, so weak but real passwords (`hunter2`, `Sommer2026!`, `P@ssw0rd`, `letmein`, `abcabcabcabc`) stay findings. `dlp_url_userinfo_password` reads the password percent-decoded (`p%40ss` is `p@ss`) and drops stand-ins and credential names as passwords, also masked with leetspeak digits and symbols (`user:pass`, `user:secret`, `user:p%40ssw%24rd`, `token:MY_GITHUB_TOKEN`), and the pseudo-password `x-oauth-basic`; a chosen password keeps its encoded span; `dlp_url_userinfo_token` reports the token in the username of `https://<token>:x-oauth-basic@…` as `SECRET_TOKEN` (subtype `access_token`) if it has two character classes, at least 3 bits of entropy per character and no sequential or repeated runs.",
        "",
        "Connection strings report the password per scheme (G01). `dlp_connection_string_password` (subtype `connection_string`, `structure` strength) takes the `password`/`pwd` key of a `;`-separated key/value string with a server, data source, address, host, DSN, driver or provider key or after a `jdbc:` URL (ADO.NET, ODBC with `{…}` values, OLE DB, JDBC SQL Server and DB2 properties), of a libpq keyword/value string with a host and a database, user or port (`host=db dbname=app user=app password=…`; keyword arguments of a call such as `connect(host=\"db\", password=…)` are no libpq string), the `password`/`pwd` query parameter of a database or broker URL (`jdbc:mysql://db/app?user=app&password=…`, also `&amp;` in XML; a web URL stays with `dlp_credential_in_url`) and the password of an Oracle thin/OCI URL (`jdbc:oracle:thin:user/…@host`). A bare value runs to the `;`, a quote, the line end or the next libpq `key=` and may hold spaces. `dlp_ldap_bind_password` (subtype `password`) takes the LDAP simple-bind password of `ldapsearch`/`ldapmodify`/`ldapadd`/`ldapdelete`/`ldappasswd`/`ldapwhoami`/`ldapcompare`/`ldapmodrdn`/`ldapexop` `-w`, of `bindpw`/`bind_pw`/`bindCredential` keys, of SSSD `ldap_default_authtok` and of the Apache `AuthLDAPBindPassword` directive (a directive without `=` or `:` only at the start of its line); `-W` prompts and has no value. Both drop stand-ins and credential names, also in leetspeak (`Password=password;`, `Pwd=s3cr3t;`, `-w secret`, `Password=myPassword;`), and win the overlap against the generic assignment and URL parameter matches of the same value. `dlp_url_userinfo_password` also takes a userinfo without a username (`redis://:…@host`).",
        "",
        "Passwords on CLI command lines (G03). `dlp_cli_password` (subtype `password`, `format` strength, structural credential tier) takes the password of `curl -u`/`--user user:…`, of the MySQL/MariaDB clients `-p…` (attached; `-p db` prompts) and `--password=…`, of a shell `PGPASSWORD=…`, `sshpass -p`, `docker`/`podman login -p`/`--password` (not `--password-stdin`), `htpasswd` in batch mode (`-b`: the last argument), PowerShell `ConvertTo-SecureString` with a quoted literal and `-AsPlainText` (also piped), and `net use \\\\server\\share` with a password before or after `/user:`. The option may follow the tool within its line or `\\`-continued lines, not past `|`, `;` or `&`. Prompts (`curl -u user`, `mysql -p db`, `net use … *`), `sshpass -e`/`-f`, shell, CI and template references and stand-ins are no findings.",
        "",
        "Before any regex runs, one Aho-Corasick pass finds the prefilter keywords of all rules (ASCII case-insensitive); a rule whose keywords are absent is skipped. The two rules without a literal have a structural prefilter instead: `dlp_discord_token` needs a run of 24 alphanumerics, `dlp_btc_wif` a run of 51 Base58 characters. Where every match starts a bounded number of bytes before a keyword (for example `dlp_generic_credential_assignment`), the rule is only tried at those positions, in text order. Every gate is proven from the rule's regex, so the findings are the same as a full scan; a text with LONG S or KELVIN SIGN, which case-insensitive rules match for `s` and `k`, runs every rule on the whole text (K07, `rust/tests/dlp_rule_prefilter.rs`).",
        "",
        "Overlapping credential/secret findings keep one span (K08): a span that only adds quotes or a trailing `;`/`,` to a tighter span of the same tier gives way to it; a fixed-format match strictly inside a longer fixed-format value of another rule, or a match of a keywordless rule inside a longer secret value, is a substring artefact; then the tier decides — provider and key-material rules > platform-format tokens (JWT, bearer, CSRF, session cookie, URL signature) > password hashes > structural credentials (URL userinfo and parameters, Basic auth, connection strings, LDAP bind and CLI passwords) > generic assignments —, within a tier the stronger validator, then the registry order. A generic key that is the userinfo of a URL (`https://token:…@host`) belongs to the URL credential. Suppressed matches stay in `matched_rules` with `suppressed_by`; identifier and content classes keep overlapping spans (see [Evidence spans](result-schema.md#evidence-spans)).",
        "",
        "In the default `strict` DLP mode every finding scores `1.0`. In `balanced` and `recall` (K04, "
        "thresholds 0.50 and 0.30 as for PII) a finding scores the rule base plus the validator strength "
        f"(checksum {dlp_points['checksum']}, structure {dlp_points['structure']}, format {dlp_points['format']}, "
        f"none {dlp_points['none']}) plus its context, capped at 100 and divided by 100: {context_points} for a "
        "`field` rule, which captures the value behind a field name of its own; for a `proximity` rule "
        f"{'/'.join(str(points) for points in proximity_tiers)} for a credential term near the value "
        f"({', '.join(f'`{lexicon_id}`' for lexicon_id in dlp_support)}) and -{counter_points} when a "
        f"digest, hash or ID term ({', '.join(f'`{lexicon_id}`' for lexicon_id in dlp_counter)}) is nearer; "
        "`none` rules score without context. A scored mode keeps the `strict` spans whose score reaches the "
        "threshold (see [DLP score and modes](result-schema.md#dlp-score-and-modes)). The score column "
        "shows the score without counter-context.",
        "",
        "| Rule ID | Result entity group | Subtype | Provider | Validator | Source | Extra validator | Default | Base | Context | Score (`balanced`/`recall`) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for rule in dlp:
        provider = f"`{rule['provider']}`" if rule["provider"] else "–"
        subtype = f"`{rule['subtype']}`" if rule["subtype"] else "–"
        context = dlp_rule_context(rule, credential_groups)
        score_range = dlp_rule_score_range(rule, context, dlp_points, context_points)
        lines.append(
            f"| `{rule['id']}` | `{rule['entity_group']}` | {subtype} | {provider} | `{rule['validator_strength']}` | {_source_ref_cell(rule['source_ref'])} | {'yes' if rule['validated'] else 'no'} | {'on' if rule['entity_group'] in credential_groups else 'off'} | {rule['base_score']} | {context} | {score_range} |"
        )

    lines.extend([
        "",
        f"## DLP relationship rules ({len(DLP_RELATIONSHIP_RULES)})",
        "",
        "These rules use the shared source-bound component contract and emit finding spans. Their evidence includes action/target relations or MCP tool/argument components.",
        "",
        "| Rule ID | Model gate | Default |",
        "| --- | --- | --- |",
        *(
            f"| `{rule_id}` | `{gate}` | {'on' if default else 'off'} |"
            for rule_id, gate, default in DLP_RELATIONSHIP_RULES
        ),
        "",
        f"## Injection rules ({len(injection)})",
        "",
        "Injection rule IDs gate versioned catalog entries, native evidence producers, and the structural producer. Several source rules can intentionally share one canonical ID; the table lists each effective gate once.",
        "",
        "| Rule ID | Family | Description | Source |",
        "| --- | --- | --- | --- |",
    ])
    for rule_id, rule in sorted(injection.items()):
        description = rule["description"].replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{rule_id}` | `{rule['family']}` | {description} | `{rule['source']}` |"
        )
    threat = json.loads((ROOT / "rust/src/detectors/threat/rules.json").read_text())["rules"]
    lines.extend([
        "", f"## Threat rules ({len(threat)})", "",
        "Enabled by default when Threat L1 is configured. Matches report risky operations, not proof of malicious intent. See [Threat L1](threat-l1.md) for context and coverage limits.", "",
        "| Rule ID | Threat class | SkillSpector reference groups |", "| --- | --- | --- |",
    ])
    for rule in threat:
        lines.append(f"| `{rule['id']}` | `{rule['class_name']}` | {', '.join(rule['upstream_groups'])} |")
    return "\n".join(lines) + "\n"


def fetch_asset_snapshot(assets: list[Asset]) -> dict:
    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "https://huggingface.co/api/models/{repo}?blobs=true",
        "repos": {},
    }
    for repo in sorted({asset.repo for asset in assets}):
        url = f"https://huggingface.co/api/models/{repo}?blobs=true"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            snapshot["repos"][repo] = {
                "error": f"HTTP {exc.code}",
                "files": {},
            }
            continue
        except urllib.error.URLError as exc:
            snapshot["repos"][repo] = {
                "error": str(exc.reason),
                "files": {},
            }
            continue
        needed = {asset.source_path for asset in assets if asset.repo == repo}
        files = {
            sibling["rfilename"]: sibling.get("size")
            for sibling in payload.get("siblings", [])
            if sibling.get("rfilename") in needed
        }
        snapshot["repos"][repo] = {
            "sha": payload.get("sha"),
            "last_modified": payload.get("lastModified"),
            "files": files,
        }
    return snapshot


def load_snapshot() -> dict:
    if SNAPSHOT_PATH.exists():
        return json.loads(SNAPSHOT_PATH.read_text())
    return {"generated_at": None, "repos": {}}


def asset_size(asset: Asset, snapshot: dict) -> int | None:
    repo = snapshot.get("repos", {}).get(asset.repo, {})
    value = repo.get("files", {}).get(asset.source_path)
    return value if isinstance(value, int) else None


def format_size(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "unknown"
    if num_bytes == 0:
        return "0 B"
    mib = num_bytes / (1024 * 1024)
    if mib >= 1:
        return f"{mib:.1f} MiB"
    kib = num_bytes / 1024
    return f"{kib:.1f} KiB"


def ntdb_package_table(packages: list[NtdbPackage]) -> list[str]:
    lines = [
        "## NTDB L2 Packages",
        "",
        "NTDB L2 packages are manifest-first and revision-pinned: the runtime downloads `manifest.json` and every runtime file it references from the immutable Hugging Face commit listed below. The current official packages use Package v4 with mmBERT and the Joint-v3 actionable-benefit promoter; the deprecated Package-v2 runtime remains available for older local overrides.",
        "",
        "For mmBERT packages, the Security Lib generates `tokenizer.mmbpe` locally after the verified asset download. The former `.kit` runtime is no longer supported. The original `tokenizer.json` remains the canonical fallback.",
        "",
        "| Category | Model | Repository | Revision | Source prefix | Cache path |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for package in packages:
        lines.append(
            f"| {package.category} | `{package.model}` | `{package.repo}` | `{package.revision}` | `{package.source_prefix}` | `{package.destination_path}` |"
        )
    lines.append("")
    return lines


def generate_assets_doc(assets: list[Asset], snapshot: dict) -> str:
    lines = [
        "# Asset Downloads",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "Patronus Ark does not bundle model assets in the Rust crate or Python wheel. Rust-native rule-based scanners run without downloads. Model-backed categories load their manifest assets from the Hugging Face repositories declared in `rust/src/assets/specs.rs`.",
        "",
        "## Cache Location",
        "",
        "If `model_dir` is set, that directory is used as the asset root. Otherwise the library uses the platform cache directory and appends `patronus_ark`:",
        "",
        "| Platform | Typical default cache root |",
        "| --- | --- |",
        "| macOS | `~/Library/Caches/patronus_ark` |",
        "| Linux | `~/.cache/patronus_ark` |",
        "| Windows | `%LOCALAPPDATA%\\patronus_ark` |",
        "",
        "Category assets are stored below that root, for example `injection/`, `sensitive_document/`, `tool_class/`, or `dynamic_pii/`.",
        "",
        "## Offline And Missing-Asset Behavior",
        "",
        "- `download_files=False` disables network downloads even when `download_categories` is set.",
        "- Existing cached assets are still used in offline mode.",
        "- `prepare_assets()` downloads and verifies configured model assets without initializing model runtimes.",
        "- `asset_readiness()` verifies the local cache without downloading or warming models.",
        "- `warmup_from_local_assets()` initializes configured runtimes strictly from the local cache and has no download path.",
        "- `warmup()` remains the combined compatibility operation: asset preparation followed by offline runtime warmup.",
        "- If required assets are missing and downloads are disabled for that category, asset preparation fails; native scanners still run where available.",
        "- Failed downloads for required assets return an error from `prepare_assets()` and therefore from compatibility `warmup()`.",
        "- Missing optional assets do not block asset preparation.",
        "- Optional assets are skipped by default during downloads. Set `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS=1` to download optional full ONNX files and sidecar data.",
        "- Set `PATRONUS_L3_PRECISION=fp16` to select pinned FP16 ONNX files where available; Linux `x86_64` production deployments use this validated mode, including Dynamic PII/GLiNER.",
        "- PII is native L1-only and has no model assets.",
        "- `dynamic-pii` is L3-only and requires the revision-pinned `gliner_small-v2.5-edge` bundle below the regular `model_dir` asset root.",
        "- L3 ONNX sessions are lazy-loaded on first L3 inference and are evicted after `PATRONUS_L3_TTL_SECS` seconds of idleness. The default TTL is `300` seconds; set `-1` to keep loaded sessions resident.",
        "- Set `HF_TOKEN` when a model repository requires authenticated or rate-limited Hugging Face access.",
        "",
        "## L3 Strategy",
        "",
        "`dedicated` loads the configured per-pipeline L3 bundles. `multi` loads only the revision-pinned `patronus-studio/lion-warden-ai-security-classifier` classifier bundle at revision `30ea449339d1075a31fcffa9199ebee4f2cfaf9a`; GLiNER remains separate in both strategies.",
        "",
        "The default shared ONNX artifact is `onnx/int8_int4_embeddings/model.onnx`; set `PATRONUS_L3_PRECISION=fp16` to select `onnx/onnx_fp16/model_fp16.onnx`. Dynamic PII selects `onnx/fp16/model_fp16.onnx` from its separate GLiNER bundle. Linux `x86_64` production deployments use FP16 for validated inference parity. See [Models & the NTDB format](concepts/models-and-ntdb.md) for the current tensor and runtime contracts.",
        "",
    ]
    lines.extend(ntdb_package_table(parse_ntdb_packages()))
    lines.extend([
        "## Download Size Snapshot",
        "",
    ])
    if snapshot.get("generated_at"):
        lines.append(f"Snapshot generated: `{snapshot['generated_at']}`.")
    else:
        lines.append("No size snapshot is available. Run `python scripts/generate_docs.py --fetch-asset-sizes` to refresh it.")
    lines.extend(
        [
            "",
            "The sizes below show required cold-cache downloads for the selected maximum level. Each maximum level includes lower-level required manifest assets for that category. Optional assets are listed in the manifest detail table.",
            "",
            "| Category | L1 required | L2 required | L3 required | Repositories |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for category in CATEGORY_ORDER:
        category_assets = [asset for asset in assets if asset.category == category]
        repos = ", ".join(sorted({asset.repo for asset in category_assets})) or "none"
        required_assets = [asset for asset in category_assets if asset.required]
        l1_assets = [asset for asset in required_assets if asset.level == "L1"]
        l2_assets = [asset for asset in required_assets if asset.level in {"L1", "L2"}]
        l3_assets = [asset for asset in required_assets if asset.level in {"L1", "L2", "L3"}]
        l1_size = _sum_size(l1_assets, snapshot)
        l2_size = _sum_size(l2_assets, snapshot)
        l3_size = _sum_size(l3_assets, snapshot)
        lines.append(
            f"| `{CATEGORY_NAMES[category]}` | {format_size(l1_size)} | {format_size(l2_size)} | {format_size(l3_size)} | {repos} |"
        )
    active_repos = {asset.repo for asset in assets}
    repo_errors = [
        f"- `{repo}`: {data['error']}"
        for repo, data in sorted(snapshot.get("repos", {}).items())
        if repo in active_repos and data.get("error")
    ]
    if repo_errors:
        lines.extend(
            [
                "",
                "The following repositories were not accessible when the snapshot was generated, so their sizes are listed as `unknown`:",
                "",
                *repo_errors,
            ]
        )
    lines.extend(
        [
            "",
            "## Manifest Detail",
            "",
            "| Category | Level | Required | Source | Cache path | Size |",
            "| --- | --- | --- | --- | --- | ---: |",
        ]
    )
    for asset in assets:
        required = "yes" if asset.required else "optional"
        source = f"`{asset.repo}/{asset.source_path}`"
        cache_path = f"`{asset.destination_path}`" if asset.bundle else f"`{CATEGORY_NAMES[asset.category]}/{asset.destination_path}`"
        lines.append(
            f"| `{CATEGORY_NAMES[asset.category]}` | `{asset.level}` | {required} | {source} | {cache_path} | {format_size(asset_size(asset, snapshot))} |"
        )
    return "\n".join(lines) + "\n"


def _sum_size(assets: list[Asset], snapshot: dict) -> int | None:
    total = 0
    for asset in assets:
        size = asset_size(asset, snapshot)
        if size is None:
            return None
        total += size
    return total


def generate_python_api_doc() -> str:
    source_path = ROOT / "python/patronus_ark/__init__.py"
    tree = ast.parse(source_path.read_text())
    lines = [
        "# Python API Reference",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "Import from `patronus_ark` after installing the wheel or running `maturin develop`.",
        "",
    ]
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "SecurityGateway":
            lines.extend(_python_class_doc(node))
    return "\n".join(lines).rstrip() + "\n"


def _python_class_doc(node: ast.ClassDef) -> list[str]:
    lines = [f"## `{node.name}`", ""]
    lines.extend(_doc_lines(ast.get_docstring(node)))
    for item in node.body:
        if isinstance(item, ast.FunctionDef) and not item.name.startswith("_"):
            lines.extend(_python_function_doc(item, heading_level=3))
    return lines


def _python_function_doc(node: ast.FunctionDef, heading_level: int) -> list[str]:
    heading = "#" * heading_level
    lines = [f"{heading} `{node.name}{_python_signature(node)}`", ""]
    lines.extend(_doc_lines(ast.get_docstring(node)))
    return lines


def _python_signature(node: ast.FunctionDef) -> str:
    args = node.args.args
    defaults = [None] * (len(args) - len(node.args.defaults)) + list(node.args.defaults)
    parts = []
    for arg, default in zip(args, defaults):
        if arg.arg == "self":
            continue
        text = arg.arg
        if arg.annotation is not None:
            text += f": {ast.unparse(arg.annotation)}"
        if default is not None:
            text += f" = {ast.unparse(default)}"
        parts.append(text)
    returns = f" -> {ast.unparse(node.returns)}" if node.returns is not None else ""
    return f"({', '.join(parts)}){returns}"


def _doc_lines(doc: str | None) -> list[str]:
    if not doc:
        return ["No public documentation is available yet.", ""]
    return [textwrap.dedent(doc).strip(), ""]


def generate_rust_api_doc() -> str:
    lines = [
        "# Rust API Reference",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "Import public items from the `patronus_ark` crate.",
        "",
        "## Public Exports",
        "",
        "```rust",
        (ROOT / "rust/src/lib.rs").read_text().strip(),
        "```",
        "",
    ]
    sections = [
        ("Core Gateway", ROOT / "rust/src/pipeline/security.rs"),
        ("Asset And Runtime Lifecycle", ROOT / "rust/src/pipeline/security/warmup.rs"),
        ("Queued Request API", ROOT / "rust/src/pipeline/security/request_queue.rs"),
        ("External L1 API", ROOT / "rust/src/external_l1.rs"),
        ("Dynamic PII Types", ROOT / "rust/src/dynamic_pii.rs"),
        ("Result And Category Types", ROOT / "rust/src/types.rs"),
        ("Synchronous Core API", ROOT / "ark-core/src/scanner.rs"),
        ("Shared Native Engine", ROOT / "ark-core/src/native/engine.rs"),
        ("Native Policy", ROOT / "ark-core/src/native/policy.rs"),
        ("Native Producer Descriptors", ROOT / "ark-core/src/native/registry.rs"),
        ("Wolf Execution Options", ROOT / "ark-core/src/wolf_options.rs"),
        ("Core ONNX Classification", ROOT / "ark-core/src/ml/text_classifier.rs"),
        ("Core Asset Preparation And Warmup", ROOT / "ark-core/src/warmup.rs"),
        ("Core Asset Cache", ROOT / "ark-core/src/warmup/cache.rs"),
        ("Core Cancellation And Deadlines", ROOT / "ark-core/src/control.rs"),
        ("Shared Native Types", ROOT / "ark-core/src/types.rs"),
        ("Wolf Defender Runtime", ROOT / "ark-core/src/wolf.rs"),
        ("Asset Manifest Helpers", ROOT / "rust/src/assets/specs.rs"),
        ("Asset Download Helpers", ROOT / "rust/src/assets/download.rs"),
    ]
    for title, path in sections:
        lines.extend([f"## {title}", ""])
        for signature, doc in rust_public_items(path):
            lines.extend(["```rust", signature, "```", ""])
            lines.extend(_doc_lines(doc))
    return "\n".join(lines).rstrip() + "\n"


def rust_public_items(path: Path) -> list[tuple[str, str | None]]:
    items: list[tuple[str, str | None]] = []
    lines = path.read_text().splitlines()
    index = 0
    pending_docs: list[str] = []
    hidden_item = False
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if stripped.startswith("///"):
            pending_docs.append(stripped.removeprefix("///").strip())
            index += 1
            continue
        if stripped == "#[doc(hidden)]":
            hidden_item = True
            index += 1
            continue
        if _is_public_rust_item(stripped):
            signature, index = _collect_rust_signature(lines, index)
            if not hidden_item:
                doc = "\n".join(pending_docs) if pending_docs else None
                items.append((signature, doc))
            pending_docs = []
            hidden_item = False
            continue
        if stripped and not stripped.startswith("#["):
            pending_docs = []
            hidden_item = False
        index += 1
    return items


def _is_public_rust_item(stripped: str) -> bool:
    return (
        stripped.startswith("pub struct ")
        or stripped.startswith("pub enum ")
        or stripped.startswith("pub trait ")
        or stripped.startswith("pub type ")
        or stripped.startswith("pub fn ")
    )


def _collect_rust_signature(lines: list[str], start: int) -> tuple[str, int]:
    first = lines[start].strip()
    if (
        first.startswith("pub struct ")
        or first.startswith("pub enum ")
        or first.startswith("pub trait ")
    ) and "{" in first:
        collected = []
        depth = 0
        index = start
        while index < len(lines):
            current = lines[index]
            collected.append(current)
            depth += current.count("{")
            depth -= current.count("}")
            if depth == 0:
                break
            index += 1
        return textwrap.dedent("\n".join(collected)).strip(), index + 1

    collected: list[str] = []
    index = start
    while index < len(lines):
        current = lines[index]
        collected.append(current)
        if "{" in current or current.rstrip().endswith(";"):
            break
        index += 1
    signature = "\n".join(collected)
    signature = re.sub(r"\s*\{\s*$", ";", signature, flags=re.S)
    signature = textwrap.dedent(signature).strip()
    return signature, index + 1


def generate_l1_capabilities_doc() -> str:
    sys.path.insert(0, str(ROOT / "scripts"))
    import l1_capabilities_doc

    return l1_capabilities_doc.generate(
        parse_native_patterns(ROOT / "ark-core/src/detectors/pii/pii.rs", "PiiPattern"),
        parse_dlp_patterns(),
        DLP_CREDENTIAL_GROUPS,
        DLP_RELATIONSHIP_RULES,
    )


def write_or_check(path: Path, content: str, check: bool) -> bool:
    if check:
        if not path.exists() or path.read_text() != content:
            print(f"{path.relative_to(ROOT)} is not up to date", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if generated docs are stale.")
    parser.add_argument(
        "--fetch-asset-sizes",
        action="store_true",
        help="Refresh docs/asset-size-snapshot.json from Hugging Face.",
    )
    args = parser.parse_args()

    assets = parse_assets()
    if args.fetch_asset_sizes:
        DOCS_DIR.mkdir(parents=True, exist_ok=True)
        snapshot = fetch_asset_snapshot(assets)
        SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    else:
        snapshot = load_snapshot()

    outputs = {
        DOCS_DIR / "assets.md": generate_assets_doc(assets, snapshot),
        DOCS_DIR / "reference/l1-rule-catalog.md": generate_l1_rule_catalog_doc(),
        DOCS_DIR / "reference/l1-capabilities.md": generate_l1_capabilities_doc(),
        DOCS_DIR / "python-api.md": generate_python_api_doc(),
        DOCS_DIR / "rust-api.md": generate_rust_api_doc(),
    }
    ok = True
    for path, content in outputs.items():
        ok = write_or_check(path, content, args.check) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
