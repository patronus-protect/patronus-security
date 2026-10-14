from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "benign_code.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_benign_code", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

# Synthetic, not decodable to anything meaningful: 120 base64 characters after a data URI.
DATA_URI = "data:image/png;base64," + "QUJD" * 30
MINIFIED = "var a=1;" + ";".join(f"function f{i}(x){{return x+{i}}}" for i in range(80)) + "\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(cwd: Path, *args: str) -> str:
    env = {**MODULE.GIT_ENV, "GIT_AUTHOR_DATE": "2026-01-02T03:04:05Z", "GIT_COMMITTER_DATE": "2026-01-02T03:04:05Z"}
    result = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, check=True)
    return result.stdout.decode().strip()


def make_repo(path: Path, files: dict[str, bytes | str], extra_commits: int = 2) -> str:
    """Local git repository usable as a fetch source; returns the head commit."""
    path.mkdir(parents=True)
    run_git(path, "init", "--quiet", "-b", "main")
    for key, value in (
        ("user.name", "Fixture Author"),
        ("user.email", "author@example.invalid"),
        ("uploadpack.allowFilter", "true"),
        ("uploadpack.allowAnySHA1InWant", "true"),
    ):
        run_git(path, "config", key, value)
    for number in range(extra_commits):
        (path / "CHANGES.txt").write_text(f"change {number}\n")
        run_git(path, "add", "-A")
        run_git(path, "commit", "--quiet", "-m", f"Change number {number}")
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    run_git(path, "add", "-A")
    run_git(path, "commit", "--quiet", "-m", "Add fixture files")
    return run_git(path, "rev-parse", "HEAD")


def full_files(prefix: str) -> dict[str, bytes | str]:
    return {
        "LICENSE": "MIT License\n",
        "src/app.py": f"def {prefix}_main():\n    return 'hello'\n",
        "package-lock.json": '{"lockfileVersion": 3, "packages": {}}\n',
        "dist/app.min.js": "var x=1;\n",
        "dist/bundle.js": MINIFIED,
        "icons/star.svg": '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h1v1z"/></svg>\n',
        "styles/inline.css": f".logo {{ background: url({DATA_URI}); }}\n",
        "keys/server.pem": "fixture key file, excluded by suffix\n",
        ".env.example": "API_URL=http://localhost\n",
        "assets/blob.bin": b"\x00\x01binary",
        "docs/latin1.txt": "caf\xe9\n".encode("latin-1"),
        "empty.txt": "",
    }


@pytest.fixture
def fixture_repos(tmp_path):
    repos = []
    for repo_id, split in (("alpha", "dev"), ("beta", "holdout")):
        source = tmp_path / "upstream" / repo_id
        commit = make_repo(source, full_files(repo_id))
        repos.append(
            {"id": repo_id, "url": source.as_uri(), "commit": commit, "license": "MIT", "split": split, "sha256": None}
        )
    return repos


def write_list(path: Path, repos: list[dict]) -> Path:
    path.write_text(json.dumps({"schema": MODULE.LIST_SCHEMA, "repos": repos}, indent=2) + "\n")
    return path


def pinned_list(tmp_path: Path, repos: list[dict]) -> Path:
    path = write_list(tmp_path / "repos.json", repos)
    assert MODULE.pin(tmp_path / "pin-cache", path, write=True) == 0
    return path


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ── licenses, scanner exclusion, repository list ─────────────────────────────


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("MIT", True),
        ("Apache-2.0", True),
        ("Unlicense OR MIT", True),
        ("GPL-3.0-only OR MIT", True),
        ("MIT AND BSD-3-Clause", True),
        ("MIT AND GPL-3.0-only", False),
        ("GPL-3.0-only", False),
        ("AGPL-3.0-only", False),
        ("", False),
    ],
)
def test_permissive_license_expressions(expression, expected):
    assert MODULE.is_permissive(expression) is expected


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/gitleaks/gitleaks",
        "https://github.com/trufflesecurity/trufflehog",
        "https://github.com/Yelp/detect-secrets",
        "https://github.com/mongodb/kingfisher",
        "https://github.com/praetorian-inc/noseyparker",
        "https://github.com/secretlint/secretlint",
    ],
)
def test_secret_scanner_repositories_are_rejected(tmp_path, url):
    repo = {"id": "tool", "url": url, "commit": "a" * 40, "license": "MIT", "split": "dev", "sha256": None}
    with pytest.raises(ValueError, match="secret-scanner"):
        MODULE.load_repos(write_list(tmp_path / "repos.json", [repo]))


@pytest.mark.parametrize(
    "change, message",
    [
        ({"license": "GPL-3.0-only"}, "not permissive"),
        ({"commit": "abc123"}, "40-hex"),
        ({"split": "test"}, "split"),
        ({"id": "Bad Id"}, "invalid repo id"),
        ({"sha256": "XYZ"}, "sha256"),
    ],
)
def test_invalid_repository_entries_are_rejected(tmp_path, change, message):
    repo = {"id": "lib", "url": "https://example.invalid/lib", "commit": "a" * 40, "license": "MIT", "split": "dev"}
    with pytest.raises(ValueError, match=message):
        MODULE.load_repos(write_list(tmp_path / "repos.json", [{**repo, **change}]))


def test_duplicate_repositories_are_rejected(tmp_path):
    repo = {"id": "lib", "url": "https://example.invalid/lib", "commit": "a" * 40, "license": "MIT", "split": "dev"}
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.load_repos(write_list(tmp_path / "repos.json", [repo, {**repo, "split": "holdout"}]))
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.load_repos(write_list(tmp_path / "repos.json", [repo, {**repo, "id": "lib2"}]))


def test_committed_repository_list_is_pinned_and_split_by_repository():
    repos = MODULE.load_repos()
    for repo in repos:
        assert repo["sha256"], repo["id"]
        assert repo["url"].startswith("https://github.com/"), repo["id"]
    by_split = {split: [repo for repo in repos if repo["split"] == split] for split in MODULE.SPLITS}
    assert all(len(members) >= 5 for members in by_split.values())
    ids = [repo["id"] for repo in repos]
    commits = [repo["commit"] for repo in repos]
    assert len(set(ids)) == len(ids) and len(set(commits)) == len(commits)


# ── classification ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path, text, kind",
    [
        ("package-lock.json", "{}", "lockfile"),
        ("crates/x/Cargo.lock", "[[package]]", "lockfile"),
        ("go.sum", "github.com/a/b v1.0.0 h1:abc=", "lockfile"),
        ("poetry.lock", "[[package]]", "lockfile"),
        ("Gemfile.lock", "GEM", "lockfile"),
        ("composer.lock", "{}", "lockfile"),
        ("dist/app.min.js", "var x=1;", "minified_js"),
        ("dist/bundle.js", MINIFIED, "minified_js"),
        ("src/app.js", "function f() {\n  return 1;\n}\n", "code"),
        ("icons/star.svg", "<svg/>", "svg"),
        ("styles/inline.css", f"a {{ background: url({DATA_URI}) }}", "base64"),
        ("notes.ipynb", '{"image/png": "' + "iVBORw0K" * 30 + '"}', "base64"),
        ("README.md", "plain text", "code"),
    ],
)
def test_classify(path, text, kind):
    assert MODULE.classify(path, text) == kind


@pytest.mark.parametrize(
    "path",
    ["keys/server.pem", "tls/ca.KEY", "certs/client.p12", ".env", ".env.production", "home/.npmrc", "ssh/id_rsa",
     "ssh/id_ed25519.pub", "node_modules/x/index.js", "aws/credentials"],
)  # fmt: skip
def test_key_material_and_credential_files_are_excluded(path):
    assert MODULE.excluded(path)


@pytest.mark.parametrize("path", ["src/keyboard.py", "docs/environment.md", "src/credentials_form.tsx", "key.txt"])
def test_ordinary_files_are_not_excluded(path):
    assert not MODULE.excluded(path)


def test_binary_and_non_utf8_content_is_skipped():
    assert MODULE.decode_text(b"\x00\x01") is None
    assert MODULE.decode_text("caf\xe9".encode("latin-1")) is None
    assert MODULE.decode_text("﻿a = 1\n".encode("utf-8")) == "a = 1\n"


# ── building and freezing splits ─────────────────────────────────────────────


def test_prepare_writes_both_splits_with_manifest_license_and_sha256(tmp_path, fixture_repos, capsys):
    repos_path = pinned_list(tmp_path, fixture_repos)
    capsys.readouterr()
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.prepare(dev, holdout, repos_path=repos_path) == 0
    out = capsys.readouterr().out
    assert "dev alpha:" in out and "beta" not in out.replace(str(holdout), "")
    for split, directory, repo in (("dev", dev, fixture_repos[0]), ("holdout", holdout, fixture_repos[1])):
        assert MODULE.check_split(directory) == []
        manifest = json.loads((directory / "manifest.json").read_text())
        assert manifest["schema"] == MODULE.SCHEMA and manifest["split"] == split
        [entry] = manifest["repos"]
        assert entry["id"] == repo["id"] and entry["commit"] == repo["commit"]
        assert entry["license"] == "MIT" and entry["license_file"] == "LICENSE"
        data = (directory / entry["file"]).read_bytes()
        assert entry["sha256"] == sha256(data)
        assert entry["bytes"] == sum(stat["bytes"] for stat in entry["kinds"].values())
        assert (directory / ".ready").read_text() == f"{sha256((directory / 'manifest.json').read_bytes())}  manifest.json\n"
        documents = {doc["path"]: doc for doc in read_jsonl(directory / entry["file"])}
        assert {path: doc["kind"] for path, doc in documents.items()} == {
            "CHANGES.txt": "code",
            "LICENSE": "code",
            "dist/app.min.js": "minified_js",
            "dist/bundle.js": "minified_js",
            "icons/star.svg": "svg",
            "package-lock.json": "lockfile",
            "src/app.py": "code",
            "styles/inline.css": "base64",
            "@git-log": "git_log",
        }
        assert all(doc["id"] == f"{repo['id']}:{doc['path']}" and doc["repo"] == repo["id"] for doc in documents.values())
        log = documents["@git-log"]["text"]
        assert log.count("\ncommit ") + log.startswith("commit ") == 3
        assert f"commit {repo['commit']}" in log and "Change number 1" in log and "A\tsrc/app.py" in log
    assert not (dev / ".sources").exists()
    assert (holdout / ".sources" / "benign_code" / "beta" / "files.git").is_dir()


def test_rerun_is_byte_identical_and_offline(tmp_path, fixture_repos):
    repos_path = pinned_list(tmp_path, fixture_repos)
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.prepare(dev, holdout, repos_path=repos_path) == 0
    before = {path.name: path.read_bytes() for path in dev.iterdir()}
    assert MODULE.prepare(dev, holdout, repos_path=repos_path, offline=True) == 0
    assert {path.name: path.read_bytes() for path in dev.iterdir()} == before
    other = tmp_path / "again"
    assert MODULE.prepare(other / "dev", other / "holdout", tmp_path / "fresh-cache", repos_path) == 0
    assert (other / "dev" / "manifest.json").read_bytes() == before["manifest.json"]


def test_offline_without_cache_fails(tmp_path, fixture_repos):
    repos_path = pinned_list(tmp_path, fixture_repos)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", repos_path=repos_path, offline=True) == 1


def test_pin_mismatch_and_missing_pin_fail(tmp_path, fixture_repos, capsys):
    unpinned = write_list(tmp_path / "unpinned.json", fixture_repos)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", repos_path=unpinned) == 1
    assert "no pinned sha256" in capsys.readouterr().err
    wrong = write_list(tmp_path / "wrong.json", [{**repo, "sha256": "0" * 64} for repo in fixture_repos])
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", repos_path=wrong) == 1
    assert "pinned 000" in capsys.readouterr().err
    assert not (tmp_path / "dev" / ".ready").exists()


def test_pin_reports_changes_without_writing(tmp_path, fixture_repos):
    path = write_list(tmp_path / "repos.json", fixture_repos)
    assert MODULE.pin(tmp_path / "cache", path) == 1
    assert json.loads(path.read_text())["repos"][0]["sha256"] is None
    assert MODULE.pin(tmp_path / "cache", path, write=True) == 0
    assert MODULE.pin(tmp_path / "cache", path, offline=True) == 0


def test_frozen_split_is_not_overwritten_without_force(tmp_path, fixture_repos):
    repos_path = pinned_list(tmp_path, fixture_repos)
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.prepare(dev, holdout, repos_path=repos_path) == 0
    (dev / "alpha.jsonl").write_text("tampered\n")
    assert MODULE.check_split(dev)
    assert MODULE.prepare(dev, holdout, repos_path=repos_path) == 1
    assert (dev / "alpha.jsonl").read_text() == "tampered\n"
    assert MODULE.prepare(dev, holdout, repos_path=repos_path, force=True) == 0
    assert MODULE.check_split(dev) == []


def test_nested_output_directories_are_rejected(tmp_path, fixture_repos):
    repos_path = pinned_list(tmp_path, fixture_repos)
    assert MODULE.prepare(tmp_path / "out", tmp_path / "out" / "holdout", repos_path=repos_path) == 1
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", tmp_path / "dev" / "src", repos_path) == 1


def test_split_without_a_required_kind_fails(tmp_path, fixture_repos, capsys):
    source = tmp_path / "upstream" / "gamma"
    commit = make_repo(source, {"LICENSE": "MIT License\n", "main.go": "package main\n"})
    gamma = {"id": "gamma", "url": source.as_uri(), "commit": commit, "license": "MIT", "split": "holdout", "sha256": None}
    repos_path = pinned_list(tmp_path, [fixture_repos[0], gamma])
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", repos_path=repos_path) == 1
    assert "holdout split has no lockfile, minified_js, svg, base64" in capsys.readouterr().err


def test_repository_without_license_file_fails(tmp_path):
    source = tmp_path / "upstream" / "nolicense"
    commit = make_repo(source, {"main.go": "package main\n"})
    repo = {"id": "nolicense", "url": source.as_uri(), "commit": commit, "license": "MIT", "split": "dev"}
    with pytest.raises(ValueError, match="no license file"):
        MODULE.build_repo(repo, tmp_path / "cache")


def test_kind_budget_and_log_limits(tmp_path, monkeypatch):
    files = {"LICENSE": "MIT License\n", **{f"src/m{i}.py": f"value_{i} = {i}\n" + "x = 1\n" * 50 for i in range(10)}}
    source = tmp_path / "upstream" / "budget"
    commit = make_repo(source, files, extra_commits=6)
    repo = {"id": "budget", "url": source.as_uri(), "commit": commit, "license": "MIT", "split": "dev"}
    monkeypatch.setitem(MODULE.KIND_BUDGET_BYTES, "code", 1000)
    monkeypatch.setattr(MODULE, "LOG_COMMITS", 4)
    monkeypatch.setattr(MODULE, "LOG_MAX_BYTES", 700)
    data, entry = MODULE.build_repo(repo, tmp_path / "cache")
    assert 0 < entry["kinds"]["code"]["bytes"] <= 1000
    log = [doc for doc in map(json.loads, data.decode().splitlines()) if doc["kind"] == "git_log"][0]["text"]
    assert 0 < len(log.encode()) <= 700 and log.startswith(f"commit {commit}\n")
    full = MODULE.git(["log", "-n4", "--format=%H", commit], tmp_path / "cache" / "budget" / "log.git").decode().split()
    kept = re.findall(r"(?m)^commit ([0-9a-f]{40})$", log)
    assert 1 <= len(kept) < 4 and kept == full[: len(kept)]  # cut at a commit boundary
    again, _ = MODULE.build_repo(repo, tmp_path / "cache")
    assert again == data


# ── FP/MB ────────────────────────────────────────────────────────────────────


DOCUMENTS = {
    "a:x.py": {"repo": "a", "kind": "code", "bytes": 600_000},
    "a:package-lock.json": {"repo": "a", "kind": "lockfile", "bytes": 250_000},
    "b:@git-log": {"repo": "b", "kind": "git_log", "bytes": 150_000},
}


def test_fp_per_mb_counts_distinct_spans_per_document():
    predictions = [
        {"id": "a:x.py", "evidence_spans": [
            {"rule_id": "dlp_generic_token", "start_char": 0, "end_char": 10},
            {"rule_id": "dlp_password_assignment", "start_char": 0, "end_char": 10},
            {"rule_id": "dlp_generic_token", "start_char": 20, "end_char": 30},
        ]},
        {"id": "a:package-lock.json", "evidence_spans": [{"label": "dlp_npm_token", "start_char": 5, "end_char": 9}]},
        {"id": "b:@git-log", "evidence_spans": []},
    ]  # fmt: skip
    report = MODULE.fp_per_mb(DOCUMENTS, predictions)
    assert report["bytes"] == 1_000_000 and report["documents"] == 3
    assert report["fp"] == 3 and report["fp_per_mb"] == 3.0 and report["documents_with_fp"] == 2
    assert report["by_kind"]["code"] == {"bytes": 600_000, "documents": 1, "fp": 2, "fp_per_mb": 3.3333}
    assert report["by_kind"]["lockfile"]["fp_per_mb"] == 4.0
    assert report["by_kind"]["git_log"]["fp"] == 0
    assert report["by_repo"]["a"]["fp"] == 3 and report["by_repo"]["b"]["fp_per_mb"] == 0.0
    assert report["by_rule"] == {
        "dlp_generic_token": {"fp": 2, "fp_per_mb": 2.0},
        "dlp_npm_token": {"fp": 1, "fp_per_mb": 1.0},
        "dlp_password_assignment": {"fp": 1, "fp_per_mb": 1.0},
    }


def test_fp_per_mb_without_predictions_is_zero_and_rejects_unknown_ids():
    assert MODULE.fp_per_mb(DOCUMENTS, [])["fp_per_mb"] == 0.0
    with pytest.raises(ValueError, match="unknown document"):
        MODULE.fp_per_mb(DOCUMENTS, [{"id": "c:missing", "evidence_spans": []}])


def test_fp_per_mb_cli_on_a_prepared_split(tmp_path, fixture_repos):
    repos_path = pinned_list(tmp_path, fixture_repos)
    dev = tmp_path / "dev"
    assert MODULE.prepare(dev, tmp_path / "holdout", repos_path=repos_path) == 0
    documents = MODULE.load_corpus(dev)
    assert set(documents) >= {"alpha:src/app.py", "alpha:@git-log"}
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text(
        json.dumps({"id": "alpha:src/app.py", "evidence_spans": [{"rule_id": "r", "start_char": 0, "end_char": 3}]}) + "\n"
    )
    output = tmp_path / "report.json"
    assert MODULE.main(["fp-per-mb", "--corpus", str(dev), "--predictions", str(predictions), "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["fp"] == 1 and report["bytes"] == sum(doc["bytes"] for doc in documents.values())
    assert report["by_kind"]["code"]["fp"] == 1
    (dev / "alpha.jsonl").write_text("tampered\n")
    assert MODULE.main(["fp-per-mb", "--corpus", str(dev), "--predictions", str(predictions)]) == 1
