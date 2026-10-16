#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Freeze the L1-DLP dev and holdout corpora (gate step ``prepare-corpora``).

Each output directory gets three components, one subdirectory each:

* ``benign_code/``: benign-code corpus split by repository (``benign_code.py``, FP/MB);
* ``benign_docs/``: DE/EN benign-document corpus split by source (``benign_docs.py``);
* ``synthetic/``: synthetic carrier rows (``patronus_ark.dlp_synth.carriers``) of the
  split's own template families. Dev uses the public ``DEV_SEED``; the holdout seed is
  secret and lives in a seed file (default ``HOLDOUT/.seed``), created from ``secrets``
  on first use with mode 0600.

    python3 scripts/l1_dlp/prepare_corpora.py --dev-out DIR --holdout-out DIR
    python3 scripts/l1_dlp/prepare_corpora.py --check DIR

Every component directory has its JSONL files, ``manifest.json`` with SHA-256 and
``.ready``. The top-level ``manifest.json`` pins the SHA-256 of every component manifest
and file; ``.ready`` with its SHA-256 is written last, after all components. A directory
with ``.ready`` is frozen: a rerun must reproduce it byte for byte, otherwise nothing is
written and the exit code is 1 (``--force`` replaces it, reusing the seed file). The
runner calls this once in the gate while ``HOLDOUT/.ready`` is missing; afterwards no
agent branch gets write access to the holdout, and the agent sandbox cannot read it.
Git and HTTP caches live in ``--sources`` (default ``HOLDOUT/.sources``), never in the
dev directory; stdout names only dev numbers. Only the standard library and the git CLI
are needed (the gate runs this with the baseline venv, without the native module).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import secrets
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DLP_SYNTH_DIR = ROOT / "python" / "patronus_ark" / "dlp_synth"


def _load_file(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_package(name: str, directory: Path) -> ModuleType:
    """Load ``directory`` as package ``name`` without ``patronus_ark/__init__`` (native module)."""
    spec = importlib.util.spec_from_file_location(
        name, directory / "__init__.py", submodule_search_locations=[str(directory)]
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {directory}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BENIGN_CODE = _load_file("_ark_l1_dlp_benign_code", HERE / "benign_code.py")
BENIGN_DOCS = _load_file("_ark_l1_dlp_benign_docs", HERE / "benign_docs.py")
_load_package("_ark_dlp_synth", DLP_SYNTH_DIR)
CARRIERS = importlib.import_module("_ark_dlp_synth.carriers")

SCHEMA = "ark-dlp-corpora-v1"
SYNTHETIC_SCHEMA = "ark-dlp-synthetic-carriers-v1"
SPLITS = ("dev", "holdout")
COMPONENTS = ("benign_code", "benign_docs", "synthetic")
READY = ".ready"
SEED_FILE = ".seed"
SYNTHETIC_FILE = "carriers.jsonl"
# Public seed of the dev carrier rows; the holdout seed is secret.
DEV_SEED = 20261011
# Files that define the synthetic rows; their SHA-256 goes into the synthetic manifest.
GENERATOR_FILES = ("carrier_templates.py", "carriers.py", "generators.json", "recipes.py", "rules.json", "rules.py")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ready(manifest: bytes) -> bytes:
    return f"{_sha256(manifest)}  manifest.json\n".encode("utf-8")


# ── synthetic carriers ───────────────────────────────────────────────────────


def seed_value(token: str) -> int:
    """Unsigned 64-bit carrier seed derived from the secret seed-file token."""
    return int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big")


def holdout_seed(path: Path) -> str:
    """Read the secret holdout seed token, creating it (mode 0600) on first use."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(secrets.token_hex(32) + "\n")
    token = path.read_text(encoding="utf-8").strip()
    if len(token) < 16:
        raise ValueError(f"{path}: holdout seed must have at least 16 characters")
    if token == str(DEV_SEED) or seed_value(token) == DEV_SEED:
        raise ValueError(f"{path}: holdout seed must differ from the dev seed")
    return token


def _counts(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row[field]) for row in rows).items()))


def build_synthetic(split: str, seed: int, seed_commitment: dict[str, Any]) -> dict[str, bytes]:
    """``{file name: content}`` of the synthetic component of one split."""
    families = CARRIERS.families(split)
    rows = CARRIERS.build(split, seed)
    foreign = sorted({row["family"] for row in rows if row["split"] != split})
    if foreign:
        raise ValueError(f"synthetic {split} rows from families of another split: {', '.join(foreign)}")
    data = BENIGN_CODE._jsonl(rows)
    manifest = BENIGN_CODE._manifest_bytes(
        {
            "schema": SYNTHETIC_SCHEMA,
            "split": split,
            "split_rule": "disjoint carrier template families (field split of dlp_synth.carrier_templates) and seed",
            "carrier_version": CARRIERS.CARRIER_VERSION,
            "generator_files": {
                name: _sha256((DLP_SYNTH_DIR / name).read_bytes()) for name in GENERATOR_FILES
            },
            "families": [
                {"id": family.id, "format": family.format, "language": family.language} for family in families
            ],
            "file": SYNTHETIC_FILE,
            "sha256": _sha256(data),
            "bytes": len(data),
            "rows": len(rows),
            "entities": sum(len(row["entities"]) for row in rows),
            "offsets": "code points (Python str indices)",
            "variants": _counts(rows, "variant"),
            "languages": _counts(rows, "language"),
            "formats": _counts(rows, "format"),
            "rules": _counts(rows, "rule_id"),
            **seed_commitment,
        }
    )
    return {SYNTHETIC_FILE: data, "manifest.json": manifest, READY: _ready(manifest)}


def check_synthetic(directory: Path) -> list[str]:
    """Problems of a written synthetic component (empty list: ready and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_bytes() != _ready(manifest_bytes):
        problems.append(f"{directory}: {READY} does not match manifest.json")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return problems + [f"{directory}: manifest.json is not JSON"]
    if manifest.get("schema") != SYNTHETIC_SCHEMA:
        problems.append(f"{directory}: manifest schema is not {SYNTHETIC_SCHEMA}")
    path = directory / SYNTHETIC_FILE
    if not path.is_file():
        problems.append(f"{path} is missing")
    elif _sha256(path.read_bytes()) != manifest.get("sha256"):
        problems.append(f"{path} does not match its SHA-256 in manifest.json")
    return problems


def write_synthetic(directory: Path, files: dict[str, bytes], force: bool, split: str) -> tuple[int, str]:
    """Freeze one synthetic split like the benign corpora: (exit code, state)."""
    if (directory / READY).exists():
        manifest = (directory / "manifest.json").read_bytes() if (directory / "manifest.json").is_file() else b""
        if not check_synthetic(directory) and manifest == files["manifest.json"]:
            return 0, "unchanged (frozen)"
        if not force:
            print(
                f"synthetic: {split} split in {directory} is frozen and differs from this run "
                "(or was modified); nothing written. Use --force to replace it.",
                file=sys.stderr,
            )
            return 1, ""
    BENIGN_CODE._write(directory, files)
    return 0, "written"


# ── top level ────────────────────────────────────────────────────────────────


def _component_entry(directory: Path) -> dict[str, Any]:
    manifest_bytes = (directory / "manifest.json").read_bytes()
    files = {
        path.name: _sha256(path.read_bytes())
        for path in sorted(directory.iterdir())
        if path.is_file() and path.suffix == ".jsonl"
    }
    return {
        "dir": directory.name,
        "schema": json.loads(manifest_bytes)["schema"],
        "manifest_sha256": _sha256(manifest_bytes),
        "files": files,
    }


def top_manifest(directory: Path, split: str) -> bytes:
    return BENIGN_CODE._manifest_bytes(
        {
            "schema": SCHEMA,
            "split": split,
            "components": {name: _component_entry(directory / name) for name in COMPONENTS},
            "excluded": "gitleaks/detect-secrets fixtures are dev smoke tests only, never holdout",
        }
    )


def check(directory: Path) -> list[str]:
    """Problems of a prepared output directory (empty list: frozen and intact)."""
    ready, manifest_path = directory / READY, directory / "manifest.json"
    if not ready.is_file() or not manifest_path.is_file():
        return [f"{directory}: no {READY} or manifest.json"]
    manifest_bytes = manifest_path.read_bytes()
    problems = []
    if ready.read_bytes() != _ready(manifest_bytes):
        problems.append(f"{directory}: {READY} does not match manifest.json")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return problems + [f"{directory}: manifest.json is not JSON"]
    if manifest.get("schema") != SCHEMA:
        problems.append(f"{directory}: manifest schema is not {SCHEMA}")
    checkers = {
        "benign_code": BENIGN_CODE.check_split,
        "benign_docs": BENIGN_DOCS.check_split,
        "synthetic": check_synthetic,
    }
    components = manifest.get("components", {})
    for name in COMPONENTS:
        component = directory / name
        if name not in components:
            problems.append(f"{directory}: manifest.json has no component {name}")
            continue
        found = checkers[name](component)
        if found:
            problems.extend(found)
        elif _component_entry(component) != components[name]:
            problems.append(f"{component} does not match its entry in {manifest_path}")
    return problems


def prepare(
    dev_out: Path,
    holdout_out: Path,
    source_dir: Path | None = None,
    seed_file: Path | None = None,
    code_repos: Path = BENIGN_CODE.REPOS_PATH,
    doc_sources: Path = BENIGN_DOCS.SOURCES_PATH,
    offline: bool = False,
    force: bool = False,
) -> int:
    """Build and freeze both splits; 0 on success or unchanged frozen splits, 1 on any problem."""
    source_dir = holdout_out / ".sources" if source_dir is None else source_dir
    seed_file = holdout_out / SEED_FILE if seed_file is None else seed_file
    dev, holdout = dev_out.resolve(), holdout_out.resolve()
    try:
        if dev == holdout or dev.is_relative_to(holdout) or holdout.is_relative_to(dev):
            raise ValueError("--dev-out and --holdout-out must be separate, non-nested directories")
        if source_dir.resolve().is_relative_to(dev):
            raise ValueError("--sources must not be inside --dev-out: the caches hold holdout data")
        if seed_file.resolve().is_relative_to(dev):
            raise ValueError("--holdout-seed-file must not be inside --dev-out")
        token = holdout_seed(seed_file)
        synthetic = {
            "dev": build_synthetic("dev", DEV_SEED, {"seed": DEV_SEED}),
            # The holdout seed is secret; its manifest only commits to it.
            "holdout": build_synthetic("holdout", seed_value(token), {"seed_sha256": _sha256(token.encode("utf-8"))}),
        }
    except (ValueError, OSError) as error:
        print(f"prepare_corpora: {error}", file=sys.stderr)
        return 1

    frozen = {split: (directory / READY).exists() for split, directory in (("dev", dev), ("holdout", holdout))}
    if not force:
        for split, directory in (("dev", dev), ("holdout", holdout)):
            if frozen[split] and check(directory):
                print(
                    f"prepare_corpora: {split} corpora in {directory} were modified; nothing written. "
                    "Use --force to replace them.",
                    file=sys.stderr,
                )
                return 1
    # Components freeze themselves; each refuses to overwrite a differing frozen split.
    sources = source_dir.resolve()
    if BENIGN_CODE.prepare(
        dev / "benign_code", holdout / "benign_code", sources / "benign_code", code_repos, offline, force
    ):
        return 1
    if BENIGN_DOCS.prepare(
        dev / "benign_docs", holdout / "benign_docs", sources / "benign_docs", doc_sources, offline, force
    ):
        return 1
    for split, directory in (("dev", dev), ("holdout", holdout)):
        code, state = write_synthetic(directory / "synthetic", synthetic[split], force, split)
        if code:
            return code
        if split == "dev":
            manifest = json.loads(synthetic[split]["manifest.json"])
            print(f"dev synthetic: {manifest['rows']} rows, {manifest['entities']} spans, seed {DEV_SEED}")
        print(f"{split} synthetic: {state} in {directory / 'synthetic'}")

    for split, directory in (("dev", dev), ("holdout", holdout)):
        manifest = top_manifest(directory, split)
        current = (directory / "manifest.json").read_bytes() if (directory / "manifest.json").is_file() else b""
        if frozen[split] and current == manifest and not check(directory):
            state = "unchanged (frozen)"
        elif frozen[split] and not force:
            print(
                f"prepare_corpora: {split} corpora in {directory} are frozen and differ from this run; "
                "nothing written. Use --force to replace them.",
                file=sys.stderr,
            )
            return 1
        else:
            (directory / READY).unlink(missing_ok=True)
            for name, content in (("manifest.json", manifest), (READY, _ready(manifest))):
                partial = directory / f"{name}.part"
                partial.write_bytes(content)
                os.replace(partial, directory / name)
            state = "written"
        print(f"{split}: {state} in {directory}, manifest sha256 {_sha256(manifest)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dev-out", type=Path, help="dev corpora directory (visible to agents)")
    parser.add_argument("--holdout-out", type=Path, help="holdout corpora directory (gate only)")
    parser.add_argument("--sources", type=Path, help="git and HTTP caches (default: HOLDOUT/.sources)")
    parser.add_argument(
        "--holdout-seed-file", type=Path, help=f"secret holdout seed (default: HOLDOUT/{SEED_FILE}, created if missing)"
    )
    parser.add_argument("--code-repos", type=Path, default=BENIGN_CODE.REPOS_PATH, help="pinned benign-code repositories")
    parser.add_argument("--doc-sources", type=Path, default=BENIGN_DOCS.SOURCES_PATH, help="pinned benign-document sources")
    parser.add_argument("--offline", action="store_true", help="never fetch; caches must be complete")
    parser.add_argument("--force", action="store_true", help="replace frozen corpora that differ")
    parser.add_argument("--check", type=Path, metavar="DIR", help="only verify a prepared directory")
    args = parser.parse_args(argv)
    if args.check is not None:
        problems = check(args.check)
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{args.check}: corpora ok")
        return 1 if problems else 0
    if args.dev_out is None or args.holdout_out is None:
        parser.error("--dev-out and --holdout-out are required (or use --check DIR)")
    return prepare(
        args.dev_out,
        args.holdout_out,
        args.sources,
        args.holdout_seed_file,
        args.code_repos,
        args.doc_sources,
        args.offline,
        args.force,
    )


if __name__ == "__main__":
    sys.exit(main())
