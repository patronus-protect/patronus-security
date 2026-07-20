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
]


@dataclass(frozen=True)
class Asset:
    category: str
    level: str
    repo: str
    source_path: str
    destination_path: str
    required: bool


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
    dynamic_block = full_source.split("pub const DYNAMIC_PII_ASSET", 1)[1].split("};", 1)[0]
    dynamic_repo = _field(dynamic_block, "repo").strip('"')
    dynamic_destination = _field(dynamic_block, "destination_path").strip('"')
    files_block = dynamic_block.split("files: &[", 1)[1].split("],", 1)[0]
    for filename in re.findall(r'"([^"]+)"', files_block):
        assets.append(
            Asset(
                category="DynamicPii",
                level="L3",
                repo=dynamic_repo,
                source_path=filename,
                destination_path=f"{dynamic_destination}/{filename}",
                required=True,
            )
        )
    return assets


@dataclass(frozen=True)
class NtdbPackage:
    category: str
    model: str
    repo: str
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
                source_prefix=_field(block, "source_prefix").strip('"'),
                destination_path=_field(block, "destination_path").strip('"'),
            )
        )
    return packages


def _field(block: str, name: str) -> str:
    match = re.search(rf"{name}:\s*([^,\n]+)", block)
    if not match:
        raise ValueError(f"Missing {name} in AssetSpec block")
    return match.group(1).strip()


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
        "NTDB v2 L2 packages are manifest-first: the runtime downloads `manifest.json` and every file it references. Sizes therefore depend on the published package contents.",
        "",
        "For supported Granite/ModernBERT packages, the Security Lib generates a compact `tokenizer.kit` locally after the verified asset download. Existing official caches are migrated during warmup, while local environment overrides are left untouched. The original `tokenizer.json` remains the canonical fallback. Generated files are written atomically under a cross-process lock and invalidated by source hash, compact hash, converter version, and format version.",
        "",
        "| Category | Model | Repository | Source prefix | Cache path |",
        "| --- | --- | --- | --- | --- |",
    ]
    for package in packages:
        lines.append(
            f"| {package.category} | `{package.model}` | `{package.repo}` | `{package.source_prefix}` | `{package.destination_path}` |"
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
        "If `model_dir` is set, that directory is used as the asset root. Otherwise the library uses the platform cache directory and appends `patronus_security`:",
        "",
        "| Platform | Typical default cache root |",
        "| --- | --- |",
        "| macOS | `~/Library/Caches/patronus_security` |",
        "| Linux | `~/.cache/patronus_security` |",
        "| Windows | `%LOCALAPPDATA%\\patronus_security` |",
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
        "- Required L3 assets prefer fp16 ONNX files where available.",
        "- PII is native L1-only and has no model assets.",
        "- `dynamic-pii` is L3-only and requires the revision-pinned `gliner_small-v2.5-edge` bundle below the regular `model_dir` asset root.",
        "- L3 ONNX sessions are lazy-loaded on first L3 inference and are evicted after `PATRONUS_L3_TTL_SECS` seconds of idleness. The default TTL is `300` seconds.",
        "- Set `HF_TOKEN` when a model repository requires authenticated or rate-limited Hugging Face access.",
        "",
        "## L3 Strategy",
        "",
        "`dedicated` loads the configured per-pipeline L3 bundles. `multi` loads only the revision-pinned `patronus-studio/lion-warden-ai-security-classifier` classifier bundle at revision `5711c4169442da12f0f4ec20e32f90d940684d20`; GLiNER remains separate in both strategies.",
        "",
        "The shared ONNX artifact is `onnx/int8_int4_embeddings/model.onnx`. See `docs/unified-multitask-l3-plan.md` for its seven-head tensor contract and the request-local worker coalescing contract.",
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
        cache_path = f"`{asset.destination_path}`" if asset.category == "DynamicPii" else f"`{CATEGORY_NAMES[asset.category]}/{asset.destination_path}`"
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
    source_path = ROOT / "python/patronus_security/__init__.py"
    tree = ast.parse(source_path.read_text())
    lines = [
        "# Python API Reference",
        "",
        "<!-- Generated by scripts/generate_docs.py. Do not edit by hand. -->",
        "",
        "Import from `patronus_security` after installing the wheel or running `maturin develop`.",
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
        "Import public items from the `patronus_security` crate.",
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
        DOCS_DIR / "python-api.md": generate_python_api_doc(),
        DOCS_DIR / "rust-api.md": generate_rust_api_doc(),
    }
    ok = True
    for path, content in outputs.items():
        ok = write_or_check(path, content, args.check) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
