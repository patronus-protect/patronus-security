#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build and check the OSS rule inventory (research/l1-threat/oss_rules.yaml).

The inventory lists every rule of the open heuristic detectors the L1 threat classes may harvest
from (ATR, pipelock, Cisco mcp-scanner YARA, seojoonkim/prompt-guard, Vigil, NeMo Guardrails YARA,
LlamaFirewall regex, SkillSpector static YARA, sentinel-ai, citadel): upstream id and category,
licence, mapped class and family of ``taxonomy.yaml``, languages and a harvest decision. The file
never holds rule bodies (regexes, YARA strings), only a short SHA-256 of each body, so an upstream
change is visible on the next build.

    python3 scripts/l1_threat/oss_inventory.py build --src DIR   # DIR holds one clone per source
    python3 scripts/l1_threat/oss_inventory.py check             # exit code 1 on any problem
    python3 scripts/l1_threat/oss_inventory.py summary           # counts per class and language
    python3 scripts/l1_threat/oss_inventory.py harvest --class exfiltration

``build`` keeps the hand-maintained head of the file (sources with pinned commit, licence, paths,
category map, hints) and regenerates ``rules`` and ``counts`` from the clones under DIR (directory
``<owner>_<repo>`` per source, checked out at the pinned commit). Mapping per rule: the first
``category_map`` entry matching the upstream category either ends the mapping (``out_of_scope``,
``handoff``) or names the classes the rule may take; then the first hint matching
``category id title`` inside those classes gives class and family; else the entry's ``family`` or
the class default family. Harvest is yes only for an allowed licence, a mapped class, a
deterministic text matcher, a regex that compiles without lookaround or backreferences (Rust
``regex``), an active rule and the first copy of a body within the source.

Problems reported by ``check``: schema errors, a commit that is not a 40-hex SHA, a source licence
outside the known set, a harvested rule of a source whose licence is not allowed, a rule carrying a
body key, an unknown class or family, a harvested rule without class and family, a rule of an
unknown source, duplicate rule ids and counts that do not match the rules.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import taxonomy  # noqa: E402

INVENTORY_PATH = taxonomy.ROOT / "research" / "l1-threat" / "oss_rules.yaml"
SCHEMA = "ark-l1-threat-oss-rules-v1"
HARVEST_LICENCES = ("MIT", "Apache-2.0")
LICENCES = HARVEST_LICENCES + ("AGPL-3.0", "GPL-3.0", "Elastic-2.0", "unknown")
EXTRACTORS = ("atr", "yara", "pipelock_go", "citadel_go", "prompt_guard", "python_re")
KINDS = ("regex", "text", "hex", "semantic")
REASONS = (
    "licence",
    "out_of_scope",
    "handoff",
    "semantic",
    "inactive",
    "not_portable",
    "duplicate",
    "unmapped",
)
LANGUAGES = ("any", "en", "de", "fr", "es", "pt", "it", "nl", "ru", "zh", "ja", "ko", "vi", "ar", "hi", "other")
RULE_KEYS = {
    "source",
    "id",
    "title",
    "category",
    "path",
    "kind",
    "class",
    "family",
    "mapping",
    "languages",
    "harvest",
    "reason",
    "sha",
}
BODY_KEYS = {"pattern", "regex", "body", "value", "strings", "condition", "patterns"}
MAPPINGS = ("hint", "category", "default", "out_of_scope", "handoff")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TITLE_MAX = 120

HEADER = """\
# L1 threat OSS rule inventory (M02). Generated rules and counts; the head (sources, category
# maps, hints, default families) is maintained by hand.
#
# Rebuild: clone each source to <DIR>/<owner>_<repo> at its pinned commit, then
#   python3 scripts/l1_threat/oss_inventory.py build --src <DIR>
# Check:   python3 scripts/l1_threat/oss_inventory.py check
#
# No rule bodies: each rule carries upstream id, title, category, file, kind, mapped class and
# family (taxonomy.yaml), languages, harvest decision and a 12-hex SHA-256 of its body. Harvest is
# yes only for MIT/Apache-2.0 sources, a mapped class, a deterministic text matcher that compiles
# in Rust regex (no lookaround or backreferences), an active rule and the first copy of a body.
# Harvested rules enter a class catalog default off and stay only if they hold dev precision.
# Mapping is a first pass for the M04 review: `mapping: default` marks rules whose family is the
# class default and needs a look.
"""


# --- body analysis ---------------------------------------------------------------------------

_NON_PORTABLE = re.compile(r"\(\?<?[=!]|\(\?>|\(\?\(|\\[1-9]|[*+?}][+]")
_ESCAPE = re.compile(r"\\(?:x\{?[0-9a-fA-F]+\}?|u[0-9a-fA-F]{4}|[pP]\{[^}]*\}|[a-zA-Z])")
_RANGE_CLASS = re.compile(r"\[[^\]]*-[^\]]*\]")
_FLAGS = re.compile(r"\(\?[a-zA-Z-]+[:)]")
_WORD = re.compile(r"[^\W\d_]{2,}")

_SCRIPTS = (
    ("ko", re.compile(r"[\uac00-\ud7af]")),
    ("ja", re.compile(r"[\u3040-\u30ff]")),
    ("zh", re.compile(r"[\u4e00-\u9fff]")),
    ("ru", re.compile(r"[\u0400-\u04ff]")),
    ("ar", re.compile(r"[\u0600-\u06ff]")),
    ("hi", re.compile(r"[\u0900-\u097f]")),
    ("vi", re.compile(r"[ơưđạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]", re.IGNORECASE)),
)
# Distinctive words (or stems, marked with a trailing *) per Latin-script language. Words shared
# with English or between the Romance languages are left out.
_MARKERS = {
    "de": (
        "ignorier* vergiss vergessen anweisung* befehl* regel* vorherig* früher* bisherig* "
        "obig* du bist sie ihr jetzt nun sofort zeig* gib verrat* alle* deine* dein ihre* nicht "
        "keine* und oder mit ohne für über sende schick* lösch* passwort* geheim* schlüssel* "
        "befolg* umgeh* sicherheit* zugangsdaten daten datei* einschränk* beschränk* neue* "
        "ausgab* mir mich uns wie ist sind werden wird soll* muss* darf* kannst "
        "systemanweisung* entwickler* modus anleitung* hinweis* wichtig*"
    ),
    "fr": (
        "ignorez oubliez oublie précédent* vous êtes maintenant règle* système montre* affiche* "
        "révèle* votre vos toutes tous sans avec développeur consignes désormais"
    ),
    "es": (
        "olvida* instrucciones anteriores ahora eres muestra* revela* tus reglas desarrollador "
        "sistema"
    ),
    "pt": "esqueça instruções você voce agora regras mostre revele suas desenvolvedor",
    "it": "dimentica* istruzioni precedenti regole rivela* modalità sviluppatore",
    "nl": "negeer* vergeet instructies eerdere regels",
}
_MARKER_WORDS = {
    lang: (
        {w for w in words.split() if not w.endswith("*")},
        tuple(w[:-1] for w in words.split() if w.endswith("*")),
    )
    for lang, words in _MARKERS.items()
}
_ENGLISH = set(
    (
        "the you your all any ignore previous prior above earlier instructions instruction rules "
        "system prompt now are is do not never from on of to and or with without act as pretend "
        "reveal show print tell me what forget disregard override bypass mode developer secret "
        "password key token send upload file data user assistant tool call execute run delete must "
        "should will can new hidden important note following this that these those into "
        "for please also before after when then here there output repeat respond say write give"
    ).split()
)


def body_sha(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]


def portable(body: str, kind: str) -> bool:
    """True when a regex body has no construct the Rust ``regex`` crate rejects."""
    return kind != "regex" or not _NON_PORTABLE.search(body)


def _words(body: str) -> list[str]:
    text = _FLAGS.sub(" ", body)
    text = _ESCAPE.sub(" ", text)
    text = _RANGE_CLASS.sub(" ", text)
    return [w.lower() for w in _WORD.findall(text)]


def languages(body: str, declared: str | None = None) -> list[str]:
    """Natural languages a rule body is written for; ``any`` for purely structural bodies.

    ``declared`` is a language the upstream file states for the rule (e.g. a per-language list).
    """
    found = [lang for lang, script in _SCRIPTS if script.search(body)]
    if declared in LANGUAGES:
        found.append(declared)
    words = _words(body)
    for lang, (exact, stems) in _MARKER_WORDS.items():
        if any(w in exact or (stems and w.startswith(stems)) for w in words):
            found.append(lang)
    if any(w in _ENGLISH for w in words):
        found.append("en")
    if not found:
        latin = [w for w in words if w.isascii()]
        found.append("en" if latin else "any")
    return sorted(set(found), key=LANGUAGES.index)


# --- extractors ------------------------------------------------------------------------------
# Each extractor yields raw rules: id, title, category, path, kind, bodies, active.


def _raw(
    rule_id: str,
    title: str,
    category: str,
    path: str,
    kind: str,
    bodies: list[str],
    active: bool = True,
    language: str | None = None,
):
    return {
        "id": rule_id,
        "title": " ".join(title.split())[:TITLE_MAX],
        "category": category,
        "path": path,
        "kind": kind,
        "bodies": bodies,
        "active": active,
        "language": language,
    }


def _files(root: Path, patterns: Iterable[str]) -> list[Path]:
    out: list[Path] = []
    for pattern in patterns:
        out.extend(sorted(p for p in root.glob(pattern) if p.is_file()))
    return out


def _detection_values(node: Any) -> Iterable[tuple[str, str]]:
    if isinstance(node, dict):
        operator = str(node.get("operator", ""))
        value = node.get("value")
        if isinstance(value, str):
            yield operator, value
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            for v in value:
                yield operator, v
        for key, child in node.items():
            if key not in ("value", "false_positives", "description"):
                yield from _detection_values(child)
    elif isinstance(node, list):
        for child in node:
            yield from _detection_values(child)


def extract_atr(root: Path, paths: list[str]) -> Iterable[dict[str, Any]]:
    for path in _files(root, paths):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        tags = doc.get("tags") or {}
        category = f"{path.parent.name}/{tags.get('subcategory') or ''}"
        values = list(_detection_values(doc.get("detection") or {}))
        semantic = doc.get("detection_tier") == "semantic" or not values
        kind = "semantic" if semantic else ("regex" if any("regex" in op for op, _ in values) else "text")
        active = doc.get("status") not in ("deprecated", "draft")
        yield _raw(str(doc["id"]), str(doc.get("title", "")), category, str(path.relative_to(root)), kind,
                   [v for _, v in values], active)


_YARA_RULE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)", re.M)
_YARA_META = re.compile(r'^\s*(description|threat_type)\s*=\s*"([^"]*)"', re.M)
_YARA_STRING = re.compile(r"^\s*(\$\w*)\s*=\s*(.+?)\s*$", re.M)


def _yara_kind(value: str) -> tuple[str, str]:
    if value.startswith("/"):
        return "regex", value[1:value.rfind("/")]
    if value.startswith("{"):
        return "hex", value
    end = value.rfind('"')
    return "text", value[1:end] if end > 0 else value


def extract_yara(root: Path, paths: list[str]) -> Iterable[dict[str, Any]]:
    """One rule per YARA string, id ``<rule>.<$string>``; category is the YARA rule name."""
    for path in _files(root, paths):
        text = path.read_text(encoding="utf-8", errors="replace")
        heads = list(_YARA_RULE.finditer(text))
        for i, head in enumerate(heads):
            block = text[head.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
            meta = dict(_YARA_META.findall(block))
            title = meta.get("description") or meta.get("threat_type") or head.group(1)
            strings = block.split("strings:", 1)[1].split("condition:", 1)[0] if "strings:" in block else ""
            seen: Counter[str] = Counter()
            for name, value in _YARA_STRING.findall(strings):
                if value.startswith("//"):
                    continue
                kind, body = _yara_kind(value)
                seen[name] += 1
                suffix = f"#{seen[name]}" if seen[name] > 1 else ""
                yield _raw(f"{head.group(1)}.{name}{suffix}", title, head.group(1), str(path.relative_to(root)),
                           kind, [body])


_GO_STRING = re.compile(r"`([^`]*)`|\"((?:[^\"\\]|\\.)*)\"")
_GO_ENTRY = re.compile(r'\{\s*Name:\s*"([^"]+)",\s*Regex:\s*([^}\n]+)|\bname:\s*"([^"]+)",')
_GO_CONST = re.compile(r"^\s*(?:const\s+|var\s+)?(\w+)\s*=\s*(.+)$", re.M)


def _go_literals(expr: str) -> str:
    return " ".join(a or b for a, b in _GO_STRING.findall(expr))


def extract_pipelock_go(root: Path, paths: list[str]) -> Iterable[dict[str, Any]]:
    """Named Go pattern entries (``{Name: .., Regex: ..}`` and ``name: .., re: ..``)."""
    files = _files(root, paths)
    consts: dict[str, str] = {}
    for path in files:
        for name, expr in _GO_CONST.findall(path.read_text(encoding="utf-8")):
            consts.setdefault(name, expr)
    for path in files:
        text = path.read_text(encoding="utf-8")
        seen: Counter[str] = Counter()
        group = path.stem
        for match in _GO_ENTRY.finditer(text):
            name = match.group(1) or match.group(3)
            if match.group(1):
                expr = match.group(2)
            else:
                expr = text[match.end(): text.find("\n\t},", match.end())]
            body = _go_literals(expr)
            for ident in re.findall(r"\b([A-Z]\w+Regex|\w+Keywords|\w+Pattern)\b", expr):
                body += " " + _go_literals(consts.get(ident, ""))
            seen[name] += 1
            suffix = f"#{seen[name]}" if seen[name] > 1 else ""
            yield _raw(f"{group}.{name}{suffix}", name, group, str(path.relative_to(root)), "regex", [body])


_CITADEL_REGISTER = re.compile(r'r\.register\(\s*"([^"]+)",\s*(`[^`]*`|"(?:[^"\\]|\\.)*")\s*,\s*cat\s*,\s*\d+\s*,\s*"([^"]*)"')
_CITADEL_CAT = re.compile(r"cat\s*:?=\s*Category(\w+)")
_CITADEL_STRUCT = re.compile(r"Pattern:\s*regexp\.MustCompile\((`[^`]*`|\"(?:[^\"\\]|\\.)*\")\),\s*\n\s*Category:\s*\"([^\"]+)\"")


def extract_citadel_go(root: Path, paths: list[str]) -> Iterable[dict[str, Any]]:
    for path in _files(root, paths):
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(root))
        cats = [(m.start(), m.group(1)) for m in _CITADEL_CAT.finditer(text)]
        for match in _CITADEL_REGISTER.finditer(text):
            category = next((c for pos, c in reversed(cats) if pos < match.start()), "")
            yield _raw(match.group(1), match.group(3), category, rel, "regex", [_go_literals(match.group(2))])
        index: Counter[str] = Counter()
        for match in _CITADEL_STRUCT.finditer(text):
            category = match.group(2)
            index[category] += 1
            yield _raw(f"{path.stem}.{category}.{index[category]}", category.replace("_", " "), category, rel,
                       "regex", [_go_literals(match.group(1))])


def _module_constants(path: Path) -> Iterable[tuple[str, Any]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    try:
                        yield target.id, ast.literal_eval(node.value)
                    except ValueError:
                        continue


_PG_LANGUAGE = re.compile(r"^PATTERNS_([A-Z]{2})\.|\.([a-z]{2})$")


def extract_prompt_guard(root: Path, paths: list[str]) -> Iterable[dict[str, Any]]:
    """``prompt_guard/patterns.py`` lists and per-language dicts; tier YAML ``patterns/*.yaml``."""
    for path in _files(root, paths):
        rel = str(path.relative_to(root))
        if path.suffix == ".py":
            for name, value in _module_constants(path):
                groups: list[tuple[str, Any]] = []
                if isinstance(value, list):
                    groups = [(name, value)]
                elif isinstance(value, dict):
                    groups = [(f"{name}.{key}", sub) for key, sub in value.items() if isinstance(sub, list)]
                for group, items in groups:
                    declared = _PG_LANGUAGE.search(group)
                    language = (declared.group(1) or declared.group(2)).lower() if declared else None
                    for i, item in enumerate(items):
                        if isinstance(item, str):
                            yield _raw(f"{group}[{i}]", group.lower().replace("_", " "), group, rel, "regex", [item],
                                       language=language)
        else:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for group, items in (doc.get("patterns") or {}).items():
                for i, item in enumerate(items or []):
                    if isinstance(item, dict) and isinstance(item.get("pattern"), str):
                        category = f"{group}/{item.get('category', '')}"
                        yield _raw(f"{path.stem}.{group}[{i}]", group.replace("_", " "), category, rel, "regex",
                                   [item["pattern"]])


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _call_name(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    child: ast.AST = node
    parent = parents.get(child)
    while parent is not None:
        if isinstance(parent, ast.Tuple):
            first = parent.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and first is not child:
                return first.value
        if isinstance(parent, ast.Dict):
            key = parent.keys[parent.values.index(child)] if child in parent.values else None
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                return key.value
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            target = parent.targets[0] if isinstance(parent, ast.Assign) else parent.target
            if isinstance(target, ast.Name):
                return target.id
        if isinstance(parent, (ast.FunctionDef, ast.ClassDef, ast.Module)):
            break
        child, parent = parent, parents.get(parent)
    return f"L{node.lineno}"


def extract_python_re(root: Path, paths: list[str]) -> Iterable[dict[str, Any]]:
    """Every ``re.compile`` with a literal pattern, plus module-level ``{name: pattern}`` dicts."""
    for path in _files(root, paths):
        rel = str(path.relative_to(root))
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = _parents(tree)
        seen: Counter[str] = Counter()

        def emit(name: str, body: str) -> dict[str, Any]:
            seen[name] += 1
            suffix = f"#{seen[name]}" if seen[name] > 1 else ""
            return _raw(f"{path.stem}.{name}{suffix}", name.strip("_").lower().replace("_", " "), path.stem, rel,
                        "regex", [body])

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "compile"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                yield emit(_call_name(node, parents), node.args[0].value)
        for name, value in _module_constants(path):
            if isinstance(value, dict) and value and all(isinstance(v, str) for v in value.values()):
                if name.endswith("PATTERNS"):
                    for key, body in value.items():
                        yield emit(str(key), body)


EXTRACT: dict[str, Callable[[Path, list[str]], Iterable[dict[str, Any]]]] = {
    "atr": extract_atr,
    "yara": extract_yara,
    "pipelock_go": extract_pipelock_go,
    "citadel_go": extract_citadel_go,
    "prompt_guard": extract_prompt_guard,
    "python_re": extract_python_re,
}


# --- mapping and harvest ---------------------------------------------------------------------


def _match(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def map_rule(raw: dict[str, Any], source: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    """Class, family and mapping basis of one raw rule (see module docstring)."""
    entry = next((e for e in source.get("category_map", []) if _match(e["match"], raw["category"])), None)
    if entry is None:
        return {"class": None, "family": None, "mapping": "default"}
    if "out_of_scope" in entry:
        return {"class": None, "family": None, "mapping": "out_of_scope"}
    if "handoff" in entry:
        return {"class": None, "family": None, "mapping": "handoff"}
    allowed = entry["classes"]
    text = f"{raw['category']} {raw['id']} {raw['title']}"
    for hint in inventory.get("hints", []):
        if not _match(hint["match"], text):
            continue
        if "handoff" in hint:
            return {"class": None, "family": None, "mapping": "handoff"}
        if "out_of_scope" in hint:
            return {"class": None, "family": None, "mapping": "out_of_scope"}
        if hint["class"] in allowed or "*" in allowed:
            return {"class": hint["class"], "family": hint["family"], "mapping": "hint"}
    cls = allowed[0]
    if cls == "*":
        return {"class": None, "family": None, "mapping": "default"}
    if entry.get("family"):
        return {"class": cls, "family": entry["family"], "mapping": "category"}
    return {"class": cls, "family": inventory["default_families"][cls], "mapping": "default"}


def harvest_reason(rule: dict[str, Any], raw: dict[str, Any], licence: str, duplicate: bool) -> str | None:
    """Why a rule is not harvested, or None when it is."""
    if licence not in HARVEST_LICENCES:
        return "licence"
    if rule["mapping"] in ("out_of_scope", "handoff"):
        return rule["mapping"]
    if rule["class"] is None:
        return "unmapped"
    if raw["kind"] in ("semantic", "hex"):
        return "semantic"
    if not raw["active"]:
        return "inactive"
    if not all(portable(body, raw["kind"]) for body in raw["bodies"]):
        return "not_portable"
    if duplicate:
        return "duplicate"
    return None


def inventory_rules(source: dict[str, Any], raws: Iterable[dict[str, Any]], inventory: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    shas: set[str] = set()
    for raw in raws:
        sha = body_sha("\n".join(raw["bodies"]))
        mapped = map_rule(raw, source, inventory)
        reason = harvest_reason(mapped, raw, source["licence"], sha in shas)
        shas.add(sha)
        rule = {
            "source": source["id"],
            "id": raw["id"],
            "title": raw["title"],
            "category": raw["category"],
            "path": raw["path"],
            "kind": raw["kind"],
            **mapped,
            "languages": languages(" ".join(raw["bodies"]), raw["language"]),
            "harvest": reason is None,
            "sha": sha,
        }
        if reason is not None:
            rule["reason"] = reason
        rules.append(rule)
    return rules


def counts(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Rules and harvested rules per class and language, and per source."""
    by_class: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: {"rules": 0, "harvest": 0}))
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: {"rules": 0, "harvest": 0})
    for rule in rules:
        cls = rule["class"] or f"({rule.get('reason') or rule['mapping']})"
        for lang in rule["languages"]:
            cell = by_class[cls][lang]
            cell["rules"] += 1
            cell["harvest"] += int(rule["harvest"])
        by_source[rule["source"]]["rules"] += 1
        by_source[rule["source"]]["harvest"] += int(rule["harvest"])
    order = {c: i for i, c in enumerate(taxonomy.CLASSES)}
    return {
        "by_class": {
            cls: {lang: dict(by_class[cls][lang]) for lang in sorted(by_class[cls], key=LANGUAGES.index)}
            for cls in sorted(by_class, key=lambda c: (order.get(c, len(order)), c))
        },
        "by_source": {src: dict(cell) for src, cell in by_source.items()},
    }


def git_head(path: Path) -> str:
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True,
                          text=True).stdout.strip()


def build(inventory: dict[str, Any], src: Path) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for source in inventory["sources"]:
        clone = src / source["clone"]
        head = git_head(clone)
        if head != source["commit"]:
            raise SystemExit(f"{source['id']}: clone at {head}, inventory pins {source['commit']}")
        raws = EXTRACT[source["extractor"]](clone, source["paths"])
        rules.extend(inventory_rules(source, raws, inventory))
    head = {k: v for k, v in inventory.items() if k not in ("rules", "counts")}
    return {**head, "counts": counts(rules), "rules": rules}


# --- check -----------------------------------------------------------------------------------


def _check_source(source: dict[str, Any]) -> list[str]:
    where = f"source {source.get('id')}"
    problems = []
    for key in ("id", "name", "repo", "commit", "licence", "extractor", "clone", "paths"):
        if key not in source:
            problems.append(f"{where}: missing {key}")
    if "commit" in source and not SHA_RE.match(str(source["commit"])):
        problems.append(f"{where}: commit {source['commit']!r} is not a pinned 40-hex SHA")
    if source.get("licence") not in LICENCES:
        problems.append(f"{where}: unknown licence {source.get('licence')!r}")
    if source.get("extractor") not in EXTRACTORS:
        problems.append(f"{where}: unknown extractor {source.get('extractor')!r}")
    for entry in source.get("category_map", []):
        terminal = [k for k in ("classes", "out_of_scope", "handoff") if k in entry]
        if "match" not in entry or len(terminal) != 1:
            problems.append(f"{where}: category_map entry {entry} needs match and one of classes/out_of_scope/handoff")
    return problems


def check(inventory: dict[str, Any], tax: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if inventory.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    families = {cls: {f["id"] for f in spec["families"]} for cls, spec in tax["classes"].items()}

    def known(cls: Any, family: Any, where: str) -> None:
        if cls not in families:
            problems.append(f"{where}: unknown class {cls!r}")
        elif family not in families[cls]:
            problems.append(f"{where}: unknown family {cls}.{family}")

    for cls in taxonomy.CLASSES:
        if cls not in (inventory.get("default_families") or {}):
            problems.append(f"default_families: missing {cls}")
    for cls, family in (inventory.get("default_families") or {}).items():
        known(cls, family, "default_families")
    for i, hint in enumerate(inventory.get("hints") or []):
        if "class" in hint:
            known(hint["class"], hint.get("family"), f"hint {i} {hint.get('match')!r}")
        elif not ("handoff" in hint or "out_of_scope" in hint):
            problems.append(f"hint {i}: needs class/family, handoff or out_of_scope")
    sources = {}
    for source in inventory.get("sources") or []:
        problems.extend(_check_source(source))
        if source.get("id") in sources:
            problems.append(f"source {source.get('id')}: declared twice")
        sources[source.get("id")] = source
        for entry in source.get("category_map", []):
            for cls in entry.get("classes", []):
                if cls != "*" and cls not in families:
                    problems.append(f"source {source.get('id')}: unknown class {cls!r} in category_map")
            if entry.get("family"):
                known(entry["classes"][0], entry["family"], f"source {source.get('id')} category_map")
    seen: set[tuple[str, str]] = set()
    rules = inventory.get("rules") or []
    for rule in rules:
        where = f"rule {rule.get('source')}/{rule.get('id')}"
        if BODY_KEYS & set(rule):
            problems.append(f"{where}: carries a rule body ({', '.join(sorted(BODY_KEYS & set(rule)))})")
        if set(rule) - RULE_KEYS - BODY_KEYS:
            problems.append(f"{where}: unknown keys {sorted(set(rule) - RULE_KEYS - BODY_KEYS)}")
        key = (rule.get("source"), rule.get("id"))
        if key in seen:
            problems.append(f"{where}: duplicate rule id")
        seen.add(key)
        source = sources.get(rule.get("source"))
        if source is None:
            problems.append(f"{where}: unknown source")
            continue
        if rule.get("kind") not in KINDS:
            problems.append(f"{where}: unknown kind {rule.get('kind')!r}")
        if rule.get("mapping") not in MAPPINGS:
            problems.append(f"{where}: unknown mapping {rule.get('mapping')!r}")
        if len(str(rule.get("title", ""))) > TITLE_MAX:
            problems.append(f"{where}: title longer than {TITLE_MAX}")
        langs = rule.get("languages") or []
        if not langs or any(lang not in LANGUAGES for lang in langs):
            problems.append(f"{where}: languages {langs} not in {LANGUAGES}")
        if rule.get("class") is not None:
            known(rule["class"], rule.get("family"), where)
        if rule.get("harvest") is True:
            if source.get("licence") not in HARVEST_LICENCES:
                problems.append(f"{where}: harvested from a {source.get('licence')} source")
            if rule.get("class") is None or rule.get("family") is None:
                problems.append(f"{where}: harvested without class and family")
            if "reason" in rule:
                problems.append(f"{where}: harvested rule with a reason")
        elif rule.get("harvest") is False:
            if rule.get("reason") not in REASONS:
                problems.append(f"{where}: not harvested, reason {rule.get('reason')!r} not in {REASONS}")
        else:
            problems.append(f"{where}: harvest must be true or false")
    if not problems and inventory.get("counts") != counts(rules):
        problems.append("counts do not match the rules; rerun build")
    return problems


def harvest_list(inventory: dict[str, Any], cls: str) -> list[dict[str, Any]]:
    """Harvested rules of one class, the input of the class catalogs."""
    return [r for r in inventory["rules"] if r["harvest"] and r["class"] == cls]


def summary(inventory: dict[str, Any]) -> str:
    table = inventory["counts"]["by_class"]
    langs = [lang for lang in LANGUAGES if any(lang in row for row in table.values())]
    lines = ["class".ljust(26) + "".join(lang.rjust(10) for lang in langs) + "     (harvest/rules)"]
    for cls, row in table.items():
        cells = "".join((f"{row[lang]['harvest']}/{row[lang]['rules']}" if lang in row else "-").rjust(10) for lang in langs)
        lines.append(cls.ljust(26) + cells)
    lines.append("")
    for src, cell in inventory["counts"]["by_source"].items():
        lines.append(f"{src.ljust(26)}{cell['harvest']:>6} harvested of {cell['rules']}")
    return "\n".join(lines)


def load(path: Path = INVENTORY_PATH) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class _Dumper(yaml.SafeDumper):
    pass


def _represent_dict(dumper: yaml.SafeDumper, data: dict[str, Any]) -> yaml.Node:
    flow = "sha" in data or ("rules" in data and "harvest" in data and len(data) == 2)
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items(), flow_style=flow)


_Dumper.add_representer(dict, _represent_dict)


def dump(inventory: dict[str, Any]) -> str:
    return HEADER + "\n" + yaml.dump(inventory, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=10000)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build", help="regenerate rules and counts from local clones")
    build_cmd.add_argument("--src", type=Path, required=True)
    sub.add_parser("check", help="check the inventory against the schema and taxonomy")
    sub.add_parser("summary", help="counts per class and language")
    harvest_cmd = sub.add_parser("harvest", help="harvested rules of one class")
    harvest_cmd.add_argument("--class", dest="cls", required=True, choices=taxonomy.CLASSES)
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    args = parser.parse_args(argv)

    inventory = load(args.inventory)
    if args.command == "build":
        args.inventory.write_text(dump(build(inventory, args.src)), encoding="utf-8")
        inventory = load(args.inventory)
    if args.command in ("build", "check"):
        problems = check(inventory, taxonomy.load())
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            return 1
        print(f"ok: {len(inventory['rules'])} rules from {len(inventory['sources'])} sources")
        return 0
    if args.command == "summary":
        print(summary(inventory))
        return 0
    for rule in harvest_list(inventory, args.cls):
        print(f"{rule['source']}/{rule['id']}\t{rule['family']}\t{','.join(rule['languages'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
