from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "prepare_corpora.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_prepare_corpora", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
CODE = MODULE.BENIGN_CODE
DOCS = MODULE.BENIGN_DOCS

# A few value rules keep the synthetic component small; the full build is covered by E04.
RULES = ("dlp_github_pat", "dlp_openai_key", "dlp_password_assignment")
DATA_URI = "data:image/png;base64," + "QUJD" * 30
MINIFIED = "var a=1;" + ";".join(f"function f{i}(x){{return x+{i}}}" for i in range(80)) + "\n"
PARAGRAPH = {
    "de": "Die Verwaltung bewahrt Unterlagen nach den gesetzlichen Fristen auf und informiert die Beschäftigten. ",
    "en": "The agency keeps records for the statutory periods and informs its staff in good time about changes. ",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(cwd: Path, *args: str) -> str:
    env = {**CODE.GIT_ENV, "GIT_AUTHOR_DATE": "2026-01-02T03:04:05Z", "GIT_COMMITTER_DATE": "2026-01-02T03:04:05Z"}
    result = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, check=True)
    return result.stdout.decode().strip()


def make_repo(path: Path, files: dict[str, str]) -> str:
    """Local git repository usable as a partial-fetch source; returns the head commit."""
    path.mkdir(parents=True)
    run_git(path, "init", "--quiet", "-b", "main")
    for key, value in (
        ("user.name", "Fixture Author"),
        ("user.email", "author@example.invalid"),
        ("uploadpack.allowFilter", "true"),
        ("uploadpack.allowAnySHA1InWant", "true"),
    ):
        run_git(path, "config", key, value)
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    run_git(path, "add", "-A")
    run_git(path, "commit", "--quiet", "-m", "Add fixture files")
    return run_git(path, "rev-parse", "HEAD")


def code_files(prefix: str) -> dict[str, str]:
    return {
        "LICENSE": "MIT License\n",
        "src/app.py": f"def {prefix}_main():\n    return 'hello'\n",
        "package-lock.json": '{"lockfileVersion": 3, "packages": {}}\n',
        "dist/bundle.js": MINIFIED,
        "icons/star.svg": '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h1v1z"/></svg>\n',
        "styles/inline.css": f".logo {{ background: url({DATA_URI}); }}\n",
    }


@pytest.fixture
def lists(tmp_path):
    """Pinned benign-code and benign-docs lists over local git fixtures (both splits)."""
    repos = []
    for repo_id, split in (("alpha", "dev"), ("beta", "holdout")):
        source = tmp_path / "upstream" / repo_id
        commit = make_repo(source, code_files(repo_id))
        repos.append({"id": repo_id, "url": source.as_uri(), "commit": commit, "license": "MIT", "split": split})
    code_list = tmp_path / "repos.json"
    code_list.write_text(json.dumps({"schema": CODE.LIST_SCHEMA, "repos": repos}))
    assert CODE.pin(tmp_path / "pin-cache" / "code", code_list, write=True) == 0

    files = {"LICENSE": "This is free and unencumbered software released into the public domain.\n"}
    for split in DOCS.SPLITS:
        for lang in DOCS.LANGS:
            for genre in DOCS.GENRES:
                files[f"{split}/{lang}/{genre}/text.md"] = f"# {split} {lang} {genre}\n\n" + PARAGRAPH[lang] * 3
    texts = tmp_path / "upstream" / "texts"
    commit = make_repo(texts, files)
    sources = [
        {"id": f"{lang}-{genre}-{split}", "type": "git", "url": texts.as_uri(), "commit": commit,
         "paths": [f"{split}/{lang}/{genre}/*.md"], "license": "Unlicense", "lang": lang, "genre": genre,
         "split": split}
        for split in DOCS.SPLITS for lang in DOCS.LANGS for genre in DOCS.GENRES
    ]  # fmt: skip
    doc_list = tmp_path / "sources.json"
    doc_list.write_text(json.dumps({"schema": DOCS.LIST_SCHEMA, "sources": sources}))
    assert DOCS.pin(tmp_path / "pin-cache" / "docs", doc_list, write=True) == 0
    return code_list, doc_list


@pytest.fixture(autouse=True)
def few_rules(monkeypatch):
    build = MODULE.CARRIERS.build
    monkeypatch.setattr(MODULE.CARRIERS, "build", lambda split, seed: build(split, seed, RULES))


def prepare(tmp_path: Path, lists, **kwargs) -> int:
    code_list, doc_list = lists
    return MODULE.prepare(
        tmp_path / "dev", tmp_path / "holdout", code_repos=code_list, doc_sources=doc_list, **kwargs
    )


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def snapshot(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file() and ".sources" not in path.parts
    }


# ── prepare ──────────────────────────────────────────────────────────────────


def test_prepare_freezes_every_component_under_a_sha256_manifest(tmp_path, lists, capsys):
    assert prepare(tmp_path, lists) == 0
    for split in MODULE.SPLITS:
        directory = tmp_path / split
        manifest_bytes = (directory / "manifest.json").read_bytes()
        assert (directory / ".ready").read_text() == f"{sha256(manifest_bytes)}  manifest.json\n"
        manifest = json.loads(manifest_bytes)
        assert manifest["schema"] == MODULE.SCHEMA and manifest["split"] == split
        assert sorted(manifest["components"]) == sorted(MODULE.COMPONENTS)
        for name, entry in manifest["components"].items():
            component = directory / name
            assert entry["manifest_sha256"] == sha256((component / "manifest.json").read_bytes())
            assert entry["files"] and all(
                sha256((component / file).read_bytes()) == digest for file, digest in entry["files"].items()
            )
            assert (component / ".ready").is_file()
        assert MODULE.check(directory) == []
    assert sorted((tmp_path / "dev" / "benign_code").glob("*.jsonl")) == [tmp_path / "dev" / "benign_code" / "alpha.jsonl"]
    assert sorted((tmp_path / "holdout" / "benign_code").glob("*.jsonl")) == [
        tmp_path / "holdout" / "benign_code" / "beta.jsonl"
    ]
    # Caches live with the holdout, never in the dev directory.
    assert (tmp_path / "holdout" / ".sources" / "benign_code").is_dir()
    assert not any(".sources" in path.parts for path in (tmp_path / "dev").rglob("*"))
    # stdout names only dev numbers.
    out = capsys.readouterr().out
    counted = [line for line in out.splitlines() if "documents" in line or "rows" in line]
    assert counted and all(line.startswith("dev ") for line in counted)
    assert "beta" not in out


def test_synthetic_splits_use_disjoint_families_and_a_secret_holdout_seed(tmp_path, lists, capsys):
    assert prepare(tmp_path, lists) == 0
    seed_file = tmp_path / "holdout" / ".seed"
    assert stat.S_IMODE(seed_file.stat().st_mode) == 0o600
    token = seed_file.read_text().strip()
    rows = {split: read_jsonl(tmp_path / split / "synthetic" / "carriers.jsonl") for split in MODULE.SPLITS}
    manifests = {
        split: json.loads((tmp_path / split / "synthetic" / "manifest.json").read_text()) for split in MODULE.SPLITS
    }
    families = {split: {row["family"] for row in rows[split]} for split in MODULE.SPLITS}
    assert families["dev"] and families["holdout"] and not families["dev"] & families["holdout"]
    assert all(row["split"] == split for split in MODULE.SPLITS for row in rows[split])
    assert {row["rule_id"] for row in rows["holdout"]} == set(RULES)
    assert {row["variant"] for row in rows["holdout"]} == set(MODULE.CARRIERS.VARIANTS)
    assert {row["language"] for row in rows["holdout"]} == {"de", "en"}
    assert manifests["dev"]["seed"] == MODULE.DEV_SEED and "seed_sha256" not in manifests["dev"]
    assert manifests["holdout"]["seed_sha256"] == sha256(token.encode()) and "seed" not in manifests["holdout"]
    assert manifests["holdout"]["rows"] == len(rows["holdout"])
    # The holdout values come from the secret seed, not from the public dev seed.
    public = {row["id"]: row["text"] for row in MODULE.CARRIERS.build("holdout", MODULE.DEV_SEED)}
    secret = {row["id"]: row["text"] for row in rows["holdout"] if row["variant"] == "positive"}
    assert secret and all(public[key] != text for key, text in secret.items())
    out = capsys.readouterr().out
    assert token not in out and str(MODULE.seed_value(token)) not in out
    assert token not in (tmp_path / "holdout" / "manifest.json").read_text()


def test_rerun_is_byte_identical_offline_and_keeps_the_seed(tmp_path, lists, capsys):
    assert prepare(tmp_path, lists) == 0
    before = {split: snapshot(tmp_path / split) for split in MODULE.SPLITS}
    seed = (tmp_path / "holdout" / ".seed").read_bytes()
    capsys.readouterr()
    assert prepare(tmp_path, lists, offline=True) == 0
    assert {split: snapshot(tmp_path / split) for split in MODULE.SPLITS} == before
    assert (tmp_path / "holdout" / ".seed").read_bytes() == seed
    out = capsys.readouterr().out
    assert "dev: unchanged (frozen)" in out and "holdout: unchanged (frozen)" in out


def test_modified_holdout_is_not_overwritten_without_force(tmp_path, lists, capsys):
    assert prepare(tmp_path, lists) == 0
    target = tmp_path / "holdout" / "synthetic" / "carriers.jsonl"
    target.write_bytes(target.read_bytes() + b"{}\n")
    assert MODULE.check(tmp_path / "holdout")
    tampered = snapshot(tmp_path / "holdout")
    assert prepare(tmp_path, lists, offline=True) == 1
    assert "were modified" in capsys.readouterr().err
    assert snapshot(tmp_path / "holdout") == tampered
    assert prepare(tmp_path, lists, offline=True, force=True) == 0
    assert MODULE.check(tmp_path / "holdout") == []


def test_tampered_top_level_manifest_is_detected(tmp_path, lists):
    assert prepare(tmp_path, lists) == 0
    manifest = tmp_path / "dev" / "manifest.json"
    data = json.loads(manifest.read_text())
    data["components"]["synthetic"]["manifest_sha256"] = "0" * 64
    manifest.write_text(json.dumps(data))
    assert any(".ready does not match" in problem for problem in MODULE.check(tmp_path / "dev"))
    (tmp_path / "dev" / ".ready").write_text(f"{sha256(manifest.read_bytes())}  manifest.json\n")
    assert any("does not match its entry" in problem for problem in MODULE.check(tmp_path / "dev"))


def test_failing_component_leaves_no_top_level_ready(tmp_path, lists, capsys):
    code_list, doc_list = lists
    data = json.loads(code_list.read_text())
    data["repos"][1]["sha256"] = "0" * 64
    code_list.write_text(json.dumps(data))
    assert prepare(tmp_path, lists) == 1
    assert "pinned" in capsys.readouterr().err
    assert not (tmp_path / "holdout" / ".ready").exists() and not (tmp_path / "dev" / ".ready").exists()


@pytest.mark.parametrize(
    "dev, holdout",
    [("corpora", "corpora"), ("corpora", "corpora/holdout"), ("corpora/dev", "corpora")],
)
def test_nested_output_directories_are_rejected(tmp_path, lists, dev, holdout, capsys):
    code_list, doc_list = lists
    assert MODULE.prepare(tmp_path / dev, tmp_path / holdout, code_repos=code_list, doc_sources=doc_list) == 1
    assert "non-nested" in capsys.readouterr().err


def test_seed_file_and_caches_inside_dev_are_rejected(tmp_path, lists, capsys):
    assert prepare(tmp_path, lists, seed_file=tmp_path / "dev" / "seed") == 1
    assert prepare(tmp_path, lists, source_dir=tmp_path / "dev" / "cache") == 1
    err = capsys.readouterr().err
    assert "--holdout-seed-file must not be inside --dev-out" in err and "--sources must not be inside" in err
    assert not (tmp_path / "dev" / "seed").exists()


@pytest.mark.parametrize("token", ["short", str(MODULE.DEV_SEED) * 2])
def test_weak_or_public_holdout_seeds_are_rejected(tmp_path, lists, token, monkeypatch, capsys):
    seed_file = tmp_path / "seed"
    seed_file.write_text(token + "\n")
    if len(token) >= 16:
        monkeypatch.setattr(MODULE, "seed_value", lambda value: MODULE.DEV_SEED)
    assert prepare(tmp_path, lists, seed_file=seed_file) == 1
    assert "holdout seed must" in capsys.readouterr().err
    assert not (tmp_path / "holdout").exists()


def test_explicit_seed_file_reproduces_the_holdout(tmp_path, lists):
    seed_file = tmp_path / "seed"
    seed_file.write_text("a" * 32 + "\n")
    assert prepare(tmp_path, lists, seed_file=seed_file) == 0
    assert not (tmp_path / "holdout" / ".seed").exists()
    first = (tmp_path / "holdout" / "synthetic" / "carriers.jsonl").read_bytes()
    rows = MODULE.build_synthetic("holdout", MODULE.seed_value("a" * 32), {})[MODULE.SYNTHETIC_FILE]
    assert rows == first


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_check_reports_missing_and_intact_directories(tmp_path, lists, capsys):
    assert MODULE.main(["--check", str(tmp_path / "dev")]) == 1
    assert prepare(tmp_path, lists) == 0
    capsys.readouterr()
    assert MODULE.main(["--check", str(tmp_path / "dev")]) == 0
    assert "corpora ok" in capsys.readouterr().out
    (tmp_path / "dev" / "benign_docs" / "de-prose-dev.jsonl").write_text("")
    assert MODULE.main(["--check", str(tmp_path / "dev")]) == 1


def test_cli_requires_both_output_directories(capsys):
    with pytest.raises(SystemExit):
        MODULE.main(["--dev-out", "dev"])
    assert "--holdout-out" in capsys.readouterr().err


def test_script_loads_without_the_native_module():
    """The gate runs this with the baseline venv, which has no patronus_ark extension."""
    code = (
        "import runpy, sys; "
        f"module = runpy.run_path({str(SCRIPT)!r}); "
        "assert not any(name == 'patronus_ark' or name.startswith('patronus_ark.') for name in sys.modules); "
        "print(len(module['CARRIERS'].families('holdout')))"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout) > 0
