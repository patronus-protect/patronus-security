#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run gitleaks, TruffleHog and detect-secrets on DLP JSONL; write one prediction format.

Input is JSONL with ``id`` and ``text`` (DLP goldens, carrier rows, benign-code or
benign-document corpora). Every row becomes one file in a scratch directory, named after
its ``path`` or its carrier ``format``, because the tools allowlist and parse by file
name. One pinned tool scans the directory in its default profile; TruffleHog runs with
``--no-verification`` and nothing talks to a network.

Each output row carries ``id`` and ``evidence_spans`` with code-point
``start_char``/``end_char`` on the **value** only (README: span normalization per tool),
``rule_id`` (the tool's own rule, detector or plugin), ``label`` (``<tool>.<rule_id>``),
and ``entities``/``groups`` from ``research/dlp/entity_map.yaml``. No secret text is
written. ``<output>.meta.json`` records version, binary SHA-256, entity-map and I/O
digests and counts of unlocated findings, without timestamps; reruns are byte-identical.

    python3 scripts/l1_dlp/run_baselines.py versions
    python3 scripts/l1_dlp/run_baselines.py check-entity-map
    python3 scripts/l1_dlp/run_baselines.py run --tool gitleaks --input gold.jsonl --output gl.jsonl
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENTITY_MAP_PATH = ROOT / "research" / "dlp" / "entity_map.yaml"
BASELINES_DIR = Path.home() / "ark-dlp" / "baselines"
DETECT_SECRETS_PYTHON = Path.home() / "ark-dlp" / "baselines-venv" / "bin" / "python"
SCHEMA = "ark-l1-dlp-baseline-predictions-v1"
WORKER = "_detect-secrets-worker"

# Pinned in research/dlp/backlog.yaml S01 and ~/ark-dlp/baselines/VERSIONS. The binaries
# are the unmodified release builds; TruffleHog (AGPL) is only executed, never vendored.
PINS: dict[str, dict[str, str]] = {
    "gitleaks": {
        "version": "8.30.1",
        "sha256": "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
    },
    "trufflehog": {
        "version": "3.97.9",
        "sha256": "2e0a09c37d104c2f3069021f0c1ab33cf07287b6aca4d59eb4684d7d73fb89b4",
    },
    "detect-secrets": {"version": "1.5.0"},
}
TOOLS = tuple(PINS)
# Field of an entity in entity_map.yaml that lists the tool's rule ids.
ENTITY_MAP_FIELDS = {"gitleaks": "gitleaks", "trufflehog": "trufflehog", "detect-secrets": "detect_secrets"}

COMMANDS = {
    "gitleaks": [
        "dir", "{root}", "--report-format", "json", "--report-path", "{report}",
        "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error",
    ],
    "trufflehog": [
        "filesystem", "{root}", "--json", "--no-verification", "--no-update", "--no-color",
        "--log-level=-1",
    ],
}

# Carrier ``format`` / ``code_language`` -> file name, so path- and extension-based
# behaviour (detect-secrets YAML/INI transformers, gitleaks path allowlists) applies.
FORMAT_FILENAMES = {
    "env": ".env", "yaml": "config.yaml", "json": "config.json", "toml": "config.toml",
    "hcl": "main.tf", "xml": "config.xml", "properties": "application.properties",
    "shell": "run.sh", "dockerfile": "Dockerfile", "ci_yaml": ".gitlab-ci.yml",
    "jupyter": "notebook.ipynb", "log": "app.log", "http": "request.http", "chat": "chat.txt",
    "ticket": "ticket.txt", "mail": "mail.eml",
}
CODE_FILENAMES = {
    "python": "main.py", "javascript": "index.js", "typescript": "index.ts", "go": "main.go",
    "java": "Main.java", "ruby": "main.rb", "rust": "main.rs", "csharp": "Program.cs",
}
DEFAULT_FILENAME = "document.txt"

# detect-secrets' JWT regex ends in a lazy ``[…]*?`` and so always stops before the
# signature; the value continues over the plugin's own final character class.
TAIL_RULES = {("detect-secrets", "JwtTokenDetector"): re.compile(r"[A-Za-z0-9_\-.+/=]+")}
# Rules whose reported secret is ``user:password``; the value is the password.
USERPASS_RULES = {("gitleaks", "curl-auth-user")}
QUOTES = ("\"", "'", "`")
LEADING_TRIM = " \t\r\n\"'`=:"
TRAILING_TRIM = " \t\r\n\"'`"
URL_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/@:]*:([^\s/@]+)@")
PEM_HEADER = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")


@dataclass
class Finding:
    """One tool finding before locating: document index, rule and reported secret."""

    doc: int
    rule_id: str
    secret: str
    line: int = 0  # 1-based; 0 = unknown
    end_line: int = 0
    column: int | None = None  # code-point offset within ``line``, a hint only
    match: str | None = None  # gitleaks: full rule match that contains ``secret``
    alternatives: tuple[str, ...] = ()
    extra: dict[str, str] = field(default_factory=dict)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Input ─────────────────────────────────────────────────────────────────


def read_rows(path: Path) -> list[dict[str, Any]]:
    rows, seen = [], set()
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON") from exc
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id or row_id in seen:
            raise ValueError(f"{path}:{number}: every row requires a unique non-empty id")
        if not isinstance(row.get("text"), str):
            raise ValueError(f"{path}:{number}: row {row_id!r} requires text")
        seen.add(row_id)
        rows.append(row)
    return rows


def document_filename(row: dict[str, Any]) -> str:
    """Relative file name for a row: its safe ``path``, else from carrier format."""
    path = row.get("path")
    if isinstance(path, str) and path:
        parts = PurePosixPath(path).parts
        if (
            not path.startswith("/")
            and "\\" not in path
            and "\0" not in path
            and all(part not in ("", ".", "..") for part in parts)
        ):
            return str(PurePosixPath(*parts))
    if row.get("format") == "code":
        return CODE_FILENAMES.get(str(row.get("code_language")), DEFAULT_FILENAME)
    return FORMAT_FILENAMES.get(str(row.get("format")), DEFAULT_FILENAME)


def materialize(rows: list[dict[str, Any]], root: Path) -> None:
    """Write row ``i`` as ``root/<i:06d>/<document_filename>`` in UTF-8, bytes unchanged."""
    for index, row in enumerate(rows):
        target = root / f"{index:06d}" / document_filename(row)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(row["text"].encode("utf-8"))


def document_index(file: str, root: Path) -> tuple[int, str]:
    """Map a reported file path back to its row index and relative name."""
    path = Path(file)
    if not path.is_absolute():
        path = root / path
    relative = path.resolve().relative_to(root.resolve())
    return int(relative.parts[0]), str(PurePosixPath(*relative.parts[1:]))


# ── Tool adapters ─────────────────────────────────────────────────────────


def tool_env(home: Path) -> dict[str, str]:
    """Minimal environment: no user config (GITLEAKS_CONFIG …), no proxies, own HOME."""
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8"}


class Lines:
    """Line starts of a text in code points; lines end at ``\\n`` like in the tools."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def start(self, line: int) -> int:
        return self.starts[min(max(line, 1), len(self.starts)) - 1]

    def end(self, line: int) -> int:
        line = min(max(line, 1), len(self.starts))
        return self.starts[line] - 1 if line < len(self.starts) else len(self.text)

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


def byte_to_char_column(line_text: str, byte_column: int) -> int:
    return len(line_text.encode("utf-8")[: max(byte_column, 0)].decode("utf-8", "ignore"))


def parse_gitleaks(report: list[dict[str, Any]], root: Path, texts: list[str]) -> list[Finding]:
    """gitleaks JSON report -> findings.

    ``Secret`` is the rule's secret group, ``Match`` the full match. Columns are UTF-8
    byte based: ``StartColumn`` is the 0-based byte offset + 1 on line 1 and + 2 on later
    lines (8.30.1), so they only serve as a hint for the nearest occurrence.
    """
    findings, cache = [], {}
    for item in report:
        doc, _ = document_index(item["File"], root)
        line = int(item.get("StartLine") or 0)
        column = None
        if line and item.get("StartColumn"):
            if doc not in cache:
                cache[doc] = Lines(texts[doc])
            lines = cache[doc]
            line_text = texts[doc][lines.start(line) : lines.end(line)]
            offset = 1 if line == 1 else 2
            column = byte_to_char_column(line_text, int(item["StartColumn"]) - offset)
        findings.append(
            Finding(
                doc=doc,
                rule_id=str(item["RuleID"]),
                secret=str(item.get("Secret") or item.get("Match") or ""),
                line=line,
                end_line=int(item.get("EndLine") or line),
                column=column,
                match=item.get("Match") or None,
                extra=_gitleaks_decoder(item.get("Tags") or []),
            )
        )
    return findings


def _gitleaks_decoder(tags: list[str]) -> dict[str, str]:
    """``decoded:base64`` tag -> ``{"decoder": "base64"}``; such secrets are decoded text."""
    decoders = [tag.split(":", 1)[1] for tag in tags if tag.startswith("decoded:")]
    return {"decoder": "+".join(decoders)} if decoders else {}


def parse_trufflehog(stdout: str, root: Path) -> list[Finding]:
    """TruffleHog JSON lines -> findings (``Raw``, then ``RawV2``; line only, no column)."""
    findings = []
    for raw_line in stdout.splitlines():
        if not raw_line.strip():
            continue
        item = json.loads(raw_line)
        if "DetectorName" not in item:
            continue  # log line
        meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        doc, _ = document_index(meta["file"], root)
        raw = str(item.get("Raw") or "")
        raw_v2 = str(item.get("RawV2") or "")
        findings.append(
            Finding(
                doc=doc,
                rule_id=str(item["DetectorName"]),
                secret=raw,
                line=int(meta.get("line") or 0),
                alternatives=(raw_v2,) if raw_v2 and raw_v2 != raw else (),
                extra={"decoder": str(item.get("DecoderName") or "PLAIN")},
            )
        )
    return findings


def parse_detect_secrets(stdout: str, root: Path) -> list[Finding]:
    """Worker JSON lines -> findings (plugin class, value, line)."""
    findings = []
    for raw_line in stdout.splitlines():
        if raw_line.strip():
            item = json.loads(raw_line)
            doc = int(PurePosixPath(item["path"]).parts[0])
            findings.append(
                Finding(doc=doc, rule_id=item["plugin"], secret=item["value"], line=int(item["line"]))
            )
    return findings


def scan_with_tool(
    tool: str, rows: list[dict[str, Any]], bin_dir: Path, detect_secrets_python: Path
) -> list[Finding]:
    """Materialize ``rows`` and run the pinned tool once over all of them."""
    texts = [row["text"] for row in rows]
    with tempfile.TemporaryDirectory(prefix="ark-dlp-baseline-") as tmp:
        work = Path(tmp)
        root = work / "docs"
        root.mkdir()
        materialize(rows, root)
        env = tool_env(work)
        if tool == "detect-secrets":
            result = subprocess.run(
                [str(detect_secrets_python), "-I", str(Path(__file__).resolve()), WORKER, str(root)],
                cwd=work, env=env, capture_output=True, text=True, check=False,
            )
            _check(tool, result)
            return parse_detect_secrets(result.stdout, root)
        report = work / "report.json"
        command = [str(bin_dir / tool)] + [
            part.format(root=root, report=report) for part in COMMANDS[tool]
        ]
        result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True, check=False)
        _check(tool, result)
        if tool == "gitleaks":
            return parse_gitleaks(json.loads(report.read_text(encoding="utf-8") or "[]"), root, texts)
        return parse_trufflehog(result.stdout, root)


def _check(tool: str, result: subprocess.CompletedProcess) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{tool} exited {result.returncode}: {result.stderr.strip()[-2000:]}")


# ── Pins ──────────────────────────────────────────────────────────────────


def installed_version(tool: str, bin_dir: Path, detect_secrets_python: Path) -> str | None:
    try:
        if tool == "detect-secrets":
            command = [
                str(detect_secrets_python), "-I", "-c",
                "from detect_secrets.__version__ import VERSION; print(VERSION)",
            ]
        else:
            command = [str(bin_dir / tool), "version" if tool == "gitleaks" else "--version"]
        result = subprocess.run(command, capture_output=True, text=True, check=False, env=tool_env(bin_dir))
    except OSError:
        return None
    found = re.search(r"\d+\.\d+\.\d+", result.stdout + result.stderr)
    return found.group(0) if result.returncode == 0 and found else None


def check_pins(
    tools: Iterable[str],
    bin_dir: Path,
    detect_secrets_python: Path,
    version_of: Callable[[str, Path, Path], str | None] = installed_version,
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Return ``{tool: {version, sha256?}}`` as installed and a list of pin violations."""
    installed, problems = {}, []
    for tool in tools:
        pin = PINS[tool]
        version = version_of(tool, bin_dir, detect_secrets_python)
        info = {"version": version or "none"}
        if version != pin["version"]:
            problems.append(f"{tool}: pinned {pin['version']}, installed {version or 'none'}")
        if "sha256" in pin:
            binary = bin_dir / tool
            digest = sha256_bytes(binary.read_bytes()) if binary.is_file() else "none"
            info["sha256"] = digest
            if digest != pin["sha256"]:
                problems.append(f"{tool}: binary sha256 {digest[:12]} differs from pin {pin['sha256'][:12]}")
        installed[tool] = info
    return installed, problems


# ── Locating and value normalization ──────────────────────────────────────


def _occurrences(text: str, needle: str, lo: int = 0, hi: int | None = None) -> Iterator[tuple[int, int]]:
    """Exact occurrences of ``needle`` starting in ``[lo, hi)``."""
    hi = len(text) if hi is None else hi
    start = text.find(needle, lo) if needle else -1
    while 0 <= start < hi:
        yield start, start + len(needle)
        start = text.find(needle, start + 1)


def _flexible_occurrences(text: str, needle: str, lo: int = 0, hi: int | None = None) -> Iterator[tuple[int, int]]:
    """Like ``_occurrences``, but whitespace in ``needle`` matches whitespace or ``\\n``-style escapes."""
    tokens = needle.split()
    if len(tokens) < 2:
        return
    hi = len(text) if hi is None else hi
    pattern = re.compile(r"(?:\s|\\[nrt])+".join(re.escape(token) for token in tokens))
    match = pattern.search(text, lo)
    while match and match.start() < hi:
        yield match.start(), match.end()
        match = pattern.search(text, match.start() + 1)


def locate(text: str, finding: Finding, lines: Lines | None = None) -> tuple[int, int, list[str]] | None:
    """Find the reported secret in the document; return span and normalization steps.

    Preference: an occurrence starting on the reported lines (nearest to the column hint,
    else the first), then the first anywhere in the document (step ``relocated``). Exact
    text before whitespace-tolerant text (``whitespace``, e.g. re-wrapped PEM bodies),
    ``Raw`` before ``RawV2`` (``raw_v2``).
    """
    lines = lines or Lines(text)
    window = None
    if finding.line:
        window = (lines.start(finding.line), lines.end(max(finding.end_line, finding.line)) + 1)
    anchor = None if finding.column is None or window is None else window[0] + finding.column

    def pick(finder: Callable[..., Iterator[tuple[int, int]]], needle: str) -> tuple[tuple[int, int], bool] | None:
        if window is not None:
            inside = list(finder(text, needle, *window))
            if inside:
                if anchor is not None:
                    return min(inside, key=lambda span: (abs(span[0] - anchor), span[0])), False
                return inside[0], False
        first = next(finder(text, needle), None)
        return (first, window is not None) if first else None

    candidates = [(finding.secret, [])] + [(alt, ["raw_v2"]) for alt in finding.alternatives]
    for needle, base_steps in candidates:
        if not needle:
            continue
        if finding.match and finding.match != needle:
            picked = pick(_occurrences, finding.match)
            if picked:
                (start, end), relocated = picked
                inner = text.rfind(needle, start, end)
                if inner >= 0:
                    return inner, inner + len(needle), base_steps + (["relocated"] if relocated else [])
        for finder, steps in ((_occurrences, []), (_flexible_occurrences, ["whitespace"])):
            picked = pick(finder, needle)
            if picked:
                (start, end), relocated = picked
                return start, end, base_steps + steps + (["relocated"] if relocated else [])
    return None


def refine(text: str, start: int, end: int, tool: str, rule_id: str) -> tuple[int, int, list[str]]:
    """Narrow or widen a located span to the value span ARK goldens use."""
    steps = []
    located = (start, end)
    while start < end and text[start] in LEADING_TRIM:
        start += 1
    while end > start and (
        text[end - 1] in TRAILING_TRIM or (text[end - 1] == "\\" and text[end : end + 1] in QUOTES)
    ):
        end -= 1
    if (start, end) != located:
        steps.append("trim")
    if (tool, rule_id) in TAIL_RULES:
        tail = TAIL_RULES[(tool, rule_id)].match(text, end)
        if tail and tail.end() > end:
            end = tail.end()
            steps.append("regex_tail")
    value = text[start:end]
    userinfo = URL_USERINFO.match(value)
    if userinfo:
        start, end = start + userinfo.start(1), start + userinfo.end(1)
        steps.append("url_password")
    elif (tool, rule_id) in USERPASS_RULES and ":" in value:
        start += value.index(":") + 1
        steps.append("user_password")
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    line_end = len(text) if line_end < 0 else line_end
    for header in PEM_HEADER.finditer(text, line_start, line_end):
        if header.start() <= start < header.end():
            footer = re.compile(r"-----END " + re.escape(header.group(1)) + r"-----").search(text, header.end())
            new_end = footer.end() if footer else header.end()
            if (header.start(), new_end) != (start, end):
                steps.append("pem_block" if footer else "pem_header")
            start, end = header.start(), new_end
            break
    return start, end, steps


# ── Entity map ────────────────────────────────────────────────────────────


def load_entity_index(path: Path = ENTITY_MAP_PATH) -> dict[str, dict[str, tuple[list[str], list[str]]]]:
    """``{tool: {rule_id: (entity ids, groups)}}`` from entity_map.yaml (sorted, unique)."""
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    index: dict[str, dict[str, tuple[set[str], set[str]]]] = {tool: {} for tool in TOOLS}
    for entity in data["entities"]:
        for tool, key in ENTITY_MAP_FIELDS.items():
            for rule_id in entity.get(key) or []:
                entities, groups = index[tool].setdefault(str(rule_id), (set(), set()))
                entities.add(entity["id"])
                if entity.get("group"):
                    groups.add(str(entity["group"]))
    return {
        tool: {rule: (sorted(e), sorted(g)) for rule, (e, g) in sorted(rules.items())}
        for tool, rules in index.items()
    }


def map_rule(index: dict[str, dict[str, tuple[list[str], list[str]]]], tool: str, rule_id: str):
    return index.get(tool, {}).get(rule_id, ([], []))


def unknown_trufflehog_detectors(names: Iterable[str], bin_dir: Path) -> list[str]:
    """Names the pinned binary rejects in ``--include-detectors`` (its own registry)."""

    def accepted(selection: list[str]) -> bool:
        with tempfile.TemporaryDirectory(prefix="ark-dlp-th-") as tmp:
            result = subprocess.run(
                [str(bin_dir / "trufflehog"), "filesystem", tmp, "--json", "--no-verification",
                 "--no-update", "--include-detectors=" + ",".join(selection)],
                capture_output=True, text=True, check=False, env=tool_env(Path(tmp)),
            )
        return result.returncode == 0 and "unrecognized detector" not in result.stdout + result.stderr

    names = sorted(set(names))
    if not names or accepted(names):
        return []
    return [name for name in names if not accepted([name])]


def detect_secrets_plugins(detect_secrets_python: Path) -> list[str]:
    script = (
        "import json; from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class as m; "
        "print(json.dumps(sorted(c.__name__ for c in m().values())))"
    )
    result = subprocess.run(
        [str(detect_secrets_python), "-I", "-c", script],
        capture_output=True, text=True, check=True, env=tool_env(detect_secrets_python.parent),
    )
    return json.loads(result.stdout)


def check_entity_map(
    bin_dir: Path, detect_secrets_python: Path, path: Path = ENTITY_MAP_PATH
) -> list[str]:
    """Problems with baseline names in entity_map.yaml against the installed tools."""
    index = load_entity_index(path)
    problems = [
        f"trufflehog: unknown detector {name!r}"
        for name in unknown_trufflehog_detectors(index["trufflehog"], bin_dir)
    ]
    plugins = set(detect_secrets_plugins(detect_secrets_python))
    problems += [
        f"detect-secrets: unknown plugin {name!r}" for name in sorted(set(index["detect-secrets"]) - plugins)
    ]
    return problems


# ── Predictions ───────────────────────────────────────────────────────────


def predict(
    tool: str,
    rows: list[dict[str, Any]],
    findings: Iterable[Finding],
    index: dict[str, dict[str, tuple[list[str], list[str]]]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Locate and normalize findings; one prediction row per input row, input order."""
    spans: list[dict[tuple[int, int, str], dict[str, Any]]] = [{} for _ in rows]
    stats: dict[str, Counter] = {
        "findings": Counter(), "unlocated": Counter(), "normalization": Counter(), "unmapped": Counter(),
    }
    lines: dict[int, Lines] = {}
    for finding in findings:
        text = rows[finding.doc]["text"]
        stats["findings"][finding.rule_id] += 1
        if finding.doc not in lines:
            lines[finding.doc] = Lines(text)
        located = locate(text, finding, lines[finding.doc])
        if located is None:
            reason = finding.extra.get("decoder", "PLAIN")
            stats["unlocated"][f"{finding.rule_id}:{reason}"] += 1
            continue
        start, end, steps = located
        start, end, more = refine(text, start, end, tool, finding.rule_id)
        steps = steps + more
        if end <= start:
            stats["unlocated"][f"{finding.rule_id}:empty"] += 1
            continue
        entities, groups = map_rule(index, tool, finding.rule_id)
        if not entities:
            stats["unmapped"][finding.rule_id] += 1
        for step in steps:
            stats["normalization"][step] += 1
        key = (start, end, finding.rule_id)
        span = spans[finding.doc].get(key)
        if span is None:
            span = {
                "start_char": start,
                "end_char": end,
                "rule_id": finding.rule_id,
                "label": f"{tool}.{finding.rule_id}",
                "entities": entities,
                "groups": groups,
                "normalization": sorted(set(steps)),
            }
            spans[finding.doc][key] = span
        else:
            span["normalization"] = sorted(set(span["normalization"]) | set(steps))
    predictions = []
    for row, row_spans in zip(rows, spans):
        ordered = [row_spans[key] for key in sorted(row_spans)]
        predictions.append({"id": row["id"], "tool": tool, "evidence_spans": ordered})
    summary = {name: dict(sorted(counter.items())) for name, counter in stats.items()}
    summary["spans"] = sum(len(row["evidence_spans"]) for row in predictions)
    return predictions, summary


def run(
    tool: str,
    input_path: Path,
    output_path: Path,
    meta_path: Path,
    scan: Callable[[str, list[dict[str, Any]]], list[Finding]],
    installed: dict[str, str],
    entity_map_path: Path = ENTITY_MAP_PATH,
) -> dict[str, Any]:
    """Write predictions plus a timestamp-free metadata sidecar; return the metadata."""
    source = input_path.read_bytes()
    rows = read_rows(input_path)
    findings = scan(tool, rows) if rows else []
    predictions, summary = predict(tool, rows, findings, load_entity_index(entity_map_path))
    encoded = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in predictions
    ).encode("utf-8")
    output_path.write_bytes(encoded)
    meta = {
        "schema": SCHEMA,
        "tool": tool,
        "pinned": PINS[tool],
        "installed": installed,
        "command": COMMANDS.get(tool, ["detect_secrets.core.scan.scan_file", "default_settings()"]),
        "entity_map_sha256": sha256_bytes(entity_map_path.read_bytes()),
        "input_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(encoded),
        "rows": len(predictions),
        "span_unit": "unicode_code_point",
        **summary,
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


# ── detect-secrets worker (runs inside the baselines venv) ────────────────


def detect_secrets_worker(root: Path) -> int:
    """Scan every file with all plugins and default filters; print JSON lines.

    Equivalent to ``detect-secrets scan --all-files`` per file, but keeps the plain
    value the plugin reported. Regex plugins that capture only the token prefix
    (``(ghp|…)_…``, ``glpat``) report the whole match instead, so the value is the token.
    """
    from detect_secrets.__version__ import VERSION
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import default_settings, get_plugins

    if VERSION != PINS["detect-secrets"]["version"]:
        print(f"detect-secrets {VERSION} differs from pin {PINS['detect-secrets']['version']}", file=sys.stderr)
        return 2
    classes = get_mapping_from_secret_type_to_class()
    with default_settings() as settings:
        if any("verification" in name for name in settings.filters):
            print("detect-secrets verification must stay off", file=sys.stderr)
            return 2
        plugins = {type(plugin).__name__: plugin for plugin in get_plugins()}
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
            found = set()
            for secret in scan_file(str(path)):
                plugin = classes[secret.type].__name__
                value = secret.secret_value or ""
                line = lines[secret.line_number - 1] if 0 < secret.line_number <= len(lines) else ""
                value = _full_regex_match(plugins.get(plugin), line, value)
                found.add((secret.line_number, plugin, value))
            relative = str(PurePosixPath(*path.relative_to(root).parts))
            for line_number, plugin, value in sorted(found):
                print(json.dumps({"path": relative, "line": line_number, "plugin": plugin, "value": value}))
    return 0


def _full_regex_match(plugin: Any, line: str, value: str) -> str:
    """Widen a prefix-only capture group (``ghp``) to its regex match (``ghp_…``)."""
    for regex in getattr(plugin, "denylist", ()) or ():
        for match in regex.finditer(line):
            for group in range(1, (regex.groups or 0) + 1):
                if (
                    match.group(group) == value
                    and match.start(group) == match.start(0)
                    and match.end(0) > match.end(group)
                ):
                    return match.group(0)
    return value


# ── CLI ───────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == [WORKER]:
        return detect_secrets_worker(Path(argv[1]))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin-dir", type=Path, default=BASELINES_DIR / "bin")
    parser.add_argument("--detect-secrets-python", type=Path, default=DETECT_SECRETS_PYTHON)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("versions", help="check the installed tools against the pins")
    commands.add_parser(
        "check-entity-map", help="check TruffleHog/detect-secrets names in entity_map.yaml against the tools"
    )
    run_parser = commands.add_parser("run", help="scan an input JSONL with one tool")
    run_parser.add_argument("--tool", choices=TOOLS, required=True)
    run_parser.add_argument("--input", type=Path, required=True, help="JSONL with id and text")
    run_parser.add_argument("--output", type=Path, required=True, help="prediction JSONL")
    run_parser.add_argument("--meta", type=Path, help="metadata JSON (default: OUTPUT with .meta.json)")
    args = parser.parse_args(argv)

    tools = (args.tool,) if args.command == "run" else TOOLS
    installed, problems = check_pins(tools, args.bin_dir, args.detect_secrets_python)
    if args.command == "versions":
        print(json.dumps(installed, indent=2, sort_keys=True))
    if problems:
        print("installed baselines differ from the pins:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 2
    if args.command == "versions":
        return 0
    if args.command == "check-entity-map":
        problems = check_entity_map(args.bin_dir, args.detect_secrets_python)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0

    meta_path = args.meta or args.output.with_name(args.output.stem + ".meta.json")
    meta = run(
        args.tool,
        args.input,
        args.output,
        meta_path,
        lambda tool, rows: scan_with_tool(tool, rows, args.bin_dir, args.detect_secrets_python),
        installed[args.tool],
    )
    print(
        f"{args.tool}: {meta['rows']} rows, {meta['spans']} spans, "
        f"{sum(meta['unlocated'].values())} unlocated -> {args.output} (sha256 {meta['output_sha256'][:12]})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
