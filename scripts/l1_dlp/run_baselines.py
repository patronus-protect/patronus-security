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
digests, counts of unlocated findings and the files a tool failed on (``errors``: a
detect-secrets plugin raised; the scan goes on), without timestamps; reruns are byte-identical.

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
# Rules whose reported secret starts with the cookie name; the value is the cookie value.
COOKIE_RULES = {("gitleaks", "gitlab-session-cookie"): "_gitlab_session="}
QUOTES = ("\"", "'", "`")
LEADING_TRIM = " \t\r\n\"'`=:"
TRAILING_TRIM = " \t\r\n\"'`"
URL_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/@:]*:([^\s/@]+)@")
PEM_HEADER = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
# URI credentials inside a (possibly normalized) TruffleHog value; the host stops before a
# port, so ``user:password@host`` can be searched in a source that omits the default port.
URI_CREDENTIALS = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<user>[^\s/@:]*):(?P<password>[^\s/@]+)@(?P<host>[^\s/?#:;,@]+)"
)
# JDBC connection strings (pinned TruffleHog 3.97.9 ``jdbc`` detector): userinfo after a
# nested scheme (``jdbc:postgresql://user:pw@host``), ``?password=``/``&password=`` query
# parameters, ``;password=`` properties (SQL Server style) and Oracle ``thin:user/pw@``.
JDBC_PASSWORD_PARAM = re.compile(r"[;?&]\s*password\s*=\s*([^;&\s\"'`]+)", re.IGNORECASE)
JDBC_ORACLE = re.compile(r"jdbc:oracle:[A-Za-z0-9]+:@?[^\s/@:;]+/([^\s@;]+)@", re.IGNORECASE)
# Multi-part TruffleHog secrets: ``Raw`` holds only the first part, the other parts are
# entries of ``SecretParts`` and ``RawV2`` is their concatenation (dedup key). Each part is
# classified by its shape and emitted as its own finding with its own entity.
AWS_KEY_ID = re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}")
AWS_SECRET_KEY = re.compile(r"[A-Za-z0-9+/]{40}")
TRUFFLEHOG_PARTS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "AWS": (("access_key_id", AWS_KEY_ID), ("secret_access_key", AWS_SECRET_KEY)),
}
# (tool, rule_id, part) -> the one entity of ``map_rule`` that part stands for.
PART_ENTITIES = {
    ("trufflehog", "AWS", "access_key_id"): "cloud.aws.access_key_id",
    ("trufflehog", "AWS", "secret_access_key"): "cloud.aws.secret_access_key",
}


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
    # Last-resort needles (needle, value start, value end, step): the span is the value
    # slice of an exact occurrence of the needle, e.g. ``user:password@host``.
    fallbacks: tuple[tuple[str, int, int, str], ...] = ()
    part: str | None = None  # multi-part secret: which part (selects the entity)
    # Span already located by the producer (detect-secrets worker), or None.
    located: tuple[int, int, tuple[str, ...]] | None = None


@dataclass(frozen=True)
class ScanError:
    """A document the tool failed on (exception class only; messages may quote the text)."""

    doc: int
    error: str


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
    """TruffleHog JSON lines -> findings (``Raw``, then ``RawV2``; line only, no column).

    Multi-part results (``TRUFFLEHOG_PARTS``, e.g. AWS key id + secret key) become one
    finding per part. Connection strings get ``user:password@host`` fallbacks, because
    TruffleHog normalizes them (``Postgres`` adds the default port ``:5432``).
    """
    findings = []
    for raw_line in stdout.splitlines():
        if not raw_line.strip():
            continue
        item = json.loads(raw_line)
        if "DetectorName" not in item:
            continue  # log line
        meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        doc, _ = document_index(meta["file"], root)
        rule_id = str(item["DetectorName"])
        raw = str(item.get("Raw") or "")
        raw_v2 = str(item.get("RawV2") or "")
        parts = item.get("SecretParts")
        parts = {str(k): str(v) for k, v in parts.items() if v} if isinstance(parts, dict) else {}
        line = int(meta.get("line") or 0)
        extra = {"decoder": str(item.get("DecoderName") or "PLAIN")}
        split = trufflehog_parts(rule_id, raw, raw_v2, parts)
        if split:
            findings.extend(
                Finding(doc=doc, rule_id=rule_id, secret=value, line=line, extra=dict(extra), part=name)
                for name, value in split
            )
            continue
        findings.append(
            Finding(
                doc=doc,
                rule_id=rule_id,
                secret=raw,
                line=line,
                alternatives=(raw_v2,) if raw_v2 and raw_v2 != raw else (),
                extra=extra,
                fallbacks=uri_fallbacks((raw, raw_v2), parts),
            )
        )
    return findings


def trufflehog_parts(rule_id: str, raw: str, raw_v2: str, parts: dict[str, str]) -> list[tuple[str, str]]:
    """``[(part, value)]`` of a multi-part result; ``[]`` for single-value detectors.

    Values come from ``SecretParts``; without it, ``RawV2 = Raw + rest`` is split. A part
    is named by the first shape it matches; values matching no shape are not secrets
    (account ids, ARNs …) and are dropped.
    """
    shapes = TRUFFLEHOG_PARTS.get(rule_id)
    if not shapes:
        return []
    values = [parts[key] for key in sorted(parts)]
    if not values and raw and raw_v2.startswith(raw) and len(raw_v2) > len(raw):
        values = [raw, raw_v2[len(raw):]]
    split = []
    for value in dict.fromkeys(values):
        name = next((name for name, shape in shapes if shape.fullmatch(value)), None)
        if name is not None:
            split.append((name, value))
    return split


def uri_fallbacks(values: Iterable[str], parts: dict[str, str]) -> tuple[tuple[str, int, int, str], ...]:
    """Needles for a password whose reported URI is not literal source text.

    For ``scheme://user:password@host[:port]…`` the needles are the URI up to the host
    (no port), ``user:password@host`` and ``user:password@``; a ``SecretParts`` password
    is the last resort. Each needle carries the password slice within it.
    """
    fallbacks: dict[tuple[str, int, int, str], None] = {}
    for value in values:
        match = URI_CREDENTIALS.search(value or "")
        if not match:
            continue
        user, password, host = match["user"], match["password"], match["host"]
        prefix = f"{match['scheme']}://"
        for head, tail in ((prefix + user + ":", "@" + host), (user + ":", "@" + host), (user + ":", "@")):
            fallbacks[(head + password + tail, len(head), len(head) + len(password), "uri_password")] = None
    for key in sorted(parts):
        if "password" in key.lower():
            fallbacks[(parts[key], 0, len(parts[key]), "secret_part")] = None
    return tuple(fallbacks)


def parse_detect_secrets(stdout: str, root: Path) -> tuple[list[Finding], list[ScanError]]:
    """Worker JSON lines -> findings (plugin class, line, span located by the worker) and errors.

    The worker never prints the secret value, only its code-point span in the file (or
    ``null`` when the value is not in the text); such findings count as ``unlocated``.
    A line with ``error`` names a file a plugin raised on.
    """
    findings = []
    errors = []
    for raw_line in stdout.splitlines():
        if raw_line.strip():
            item = json.loads(raw_line)
            doc = int(PurePosixPath(item["path"]).parts[0])
            if "error" in item:
                errors.append(ScanError(doc=doc, error=str(item["error"])))
                continue
            located = None
            if item.get("start") is not None and item.get("end") is not None:
                located = (int(item["start"]), int(item["end"]), tuple(item.get("normalization") or ()))
            findings.append(
                Finding(doc=doc, rule_id=item["plugin"], secret="", line=int(item["line"]), located=located)
            )
    return findings, errors


def scan_with_tool(
    tool: str, rows: list[dict[str, Any]], bin_dir: Path, detect_secrets_python: Path
) -> tuple[list[Finding], list[ScanError]]:
    """Materialize ``rows`` and run the pinned tool once over all of them; findings and errors."""
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
            return parse_gitleaks(json.loads(report.read_text(encoding="utf-8") or "[]"), root, texts), []
        return parse_trufflehog(result.stdout, root), []


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
    ``Raw`` before ``RawV2`` (``raw_v2``), then the exact ``fallbacks`` narrowed to their
    value slice (``uri_password``/``secret_part``).
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
    for needle, value_start, value_end, step in finding.fallbacks:
        picked = pick(_occurrences, needle) if needle and value_end > value_start else None
        if picked:
            (start, _), relocated = picked
            return start + value_start, start + value_end, [step] + (["relocated"] if relocated else [])
    return None


def jdbc_password(value: str) -> tuple[int, int] | None:
    """Password span within a JDBC connection string, or None if it carries none."""
    offset = 5 if value[:5].lower() == "jdbc:" else 0
    userinfo = URL_USERINFO.match(value, offset)
    if userinfo:
        return userinfo.start(1), userinfo.end(1)
    for pattern in (JDBC_PASSWORD_PARAM, JDBC_ORACLE):
        found = pattern.search(value)
        if found:
            return found.start(1), found.end(1)
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
    jdbc = value[:5].lower() == "jdbc:" or (tool, rule_id) == ("trufflehog", "JDBC")
    if userinfo:
        start, end = start + userinfo.start(1), start + userinfo.end(1)
        steps.append("url_password")
    elif jdbc and (password := jdbc_password(value)) is not None:
        start, end = start + password[0], start + password[1]
        steps.append("jdbc_password")
    elif (tool, rule_id) in USERPASS_RULES and ":" in value:
        start += value.index(":") + 1
        steps.append("user_password")
    elif (tool, rule_id) in COOKIE_RULES and value.startswith(COOKIE_RULES[(tool, rule_id)]):
        start += len(COOKIE_RULES[(tool, rule_id)])
        steps.append("cookie_name")
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


def load_entity_index(
    path: Path = ENTITY_MAP_PATH, fields: dict[str, str] = ENTITY_MAP_FIELDS
) -> dict[str, dict[str, tuple[list[str], list[str]]]]:
    """``{tool: {rule_id: (entity ids, groups)}}`` from entity_map.yaml (sorted, unique).

    ``fields`` maps each tool to its entity field (``run_ark.py`` passes ``{"ark": "ark"}``).
    """
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    index: dict[str, dict[str, tuple[set[str], set[str]]]] = {tool: {} for tool in fields}
    for entity in data["entities"]:
        for tool, key in fields.items():
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
        if finding.located is not None:
            start, end, pre_steps = finding.located
            valid = 0 <= start < end <= len(text)
            located = (start, end, list(pre_steps)) if valid else None
        else:
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
        label = f"{tool}.{finding.rule_id}"
        if finding.part is not None:
            label += f".{finding.part}"
            entity = PART_ENTITIES.get((tool, finding.rule_id, finding.part))
            if entity in entities:
                entities = [entity]  # the parts of one detector share their group
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
                "label": label,
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
    scan: Callable[[str, list[dict[str, Any]]], tuple[list[Finding], list[ScanError]]],
    installed: dict[str, str],
    entity_map_path: Path = ENTITY_MAP_PATH,
) -> dict[str, Any]:
    """Write predictions plus a timestamp-free metadata sidecar; return the metadata."""
    source = input_path.read_bytes()
    rows = read_rows(input_path)
    findings, errors = scan(tool, rows) if rows else ([], [])
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
        # Files the tool failed on; their rows have no spans (the CLI would have aborted).
        "errors": [
            {"id": rows[e.doc]["id"], "file": document_filename(rows[e.doc]), "error": e.error}
            for e in sorted(errors, key=lambda e: (e.doc, e.error))
        ],
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
    Unlike the CLI, a file a plugin raises on does not abort the scan (``worker_lines``).
    """
    from detect_secrets.__version__ import VERSION
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import default_settings, get_plugins

    if VERSION != PINS["detect-secrets"]["version"]:
        print(f"detect-secrets {VERSION} is not the pinned release", file=sys.stderr)
        return 2
    classes = get_mapping_from_secret_type_to_class()
    with default_settings() as settings:
        if any("verification" in name for name in settings.filters):
            print("detect-secrets verification must stay off", file=sys.stderr)
            return 2
        plugins = {type(plugin).__name__: plugin for plugin in get_plugins()}

        def secrets(path: Path) -> list[tuple[int, str, str]]:
            return [
                (secret.line_number, classes[secret.type].__name__, secret.secret_value or "")
                for secret in scan_file(str(path))
            ]

        for line in worker_lines(root, secrets, plugins):
            print(line)
    return 0


def worker_lines(
    root: Path, scan: Callable[[Path], list[tuple[int, str, str]]], plugins: dict[str, Any]
) -> Iterator[str]:
    """JSON lines for every file under ``root``: one per located secret, one per failed file.

    The detect-secrets CLI aborts the whole scan when a plugin raises on one file (a YAML
    date its transformer cannot parse); here that file yields ``{"path", "error"}`` with the
    exception class only (the message may quote the text), its partial findings are dropped
    and the scan goes on, as in ``latency.py``.
    """
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = str(PurePosixPath(*path.relative_to(root).parts))
        try:
            secrets = scan(path)
        except Exception as exc:  # noqa: BLE001 - listed in the meta, like a file the CLI fails on
            yield json.dumps({"path": relative, "error": type(exc).__name__}, sort_keys=True)
            continue
        # Same code points as the row text (materialize wrote it verbatim; no newline
        # translation), so the offsets below index the row directly.
        text = path.read_bytes().decode("utf-8", errors="replace")
        for record in worker_records(text, secrets, plugins):
            yield json.dumps({"path": relative, **record}, sort_keys=True)


def worker_records(
    text: str, secrets: Iterable[tuple[int, str, str]], plugins: dict[str, Any]
) -> list[dict[str, Any]]:
    """Locate each ``(line, plugin, value)`` in ``text``; records carry spans, never values.

    The worker's stdout is a log stream to the parent, so the value is reduced to its
    code-point span here (``null`` when it is not in the text).
    """
    lines = text.split("\n")
    index = Lines(text)
    found: set[tuple[int, str, int | None, int | None, tuple[str, ...]]] = set()
    for line_number, plugin, value in secrets:
        line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
        value = _full_regex_match(plugins.get(plugin), line, value)
        located = locate(text, Finding(doc=0, rule_id=plugin, secret=value, line=line_number), index)
        if located is None:
            found.add((line_number, plugin, None, None, ()))
        else:
            found.add((line_number, plugin, located[0], located[1], tuple(located[2])))
    def order(item: tuple[int, str, int | None, int | None, tuple[str, ...]]) -> tuple:
        line_number, plugin, start, end, steps = item
        return line_number, plugin, -1 if start is None else start, -1 if end is None else end, steps

    return [
        {"line": line_number, "plugin": plugin, "start": start, "end": end, "normalization": list(steps)}
        for line_number, plugin, start, end, steps in sorted(found, key=order)
    ]


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
        f"{sum(meta['unlocated'].values())} unlocated, {len(meta['errors'])} errors -> {args.output} (sha256 {meta['output_sha256'][:12]})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
