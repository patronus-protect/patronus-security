from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import urllib.parse
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "benign_docs.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_benign_docs", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

SITE = "https://wiki.example.invalid"
LAW = """---
Title: Beispielgesetz
layout: default
---

# Beispielgesetz (BspG)

### § 1 Zweck

Dieses Gesetz regelt die Aufbewahrung von Unterlagen in der öffentlichen Verwaltung. Die Behörde
bestimmt die Fristen nach pflichtgemäßem Ermessen und unterrichtet die Beschäftigten rechtzeitig.
"""
GUIDE = """# Working with partner agencies

Our team works in the open. Every project starts with a kickoff meeting, a shared project brief and
a short discovery phase in which we interview the people who use the service every day.
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(cwd: Path, *args: str) -> str:
    env = {**MODULE.GIT_ENV, "GIT_AUTHOR_DATE": "2026-01-02T03:04:05Z", "GIT_COMMITTER_DATE": "2026-01-02T03:04:05Z"}
    result = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, check=True)
    return result.stdout.decode().strip()


def make_repo(path: Path, files: dict[str, bytes | str]) -> str:
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
        target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    run_git(path, "add", "-A")
    run_git(path, "commit", "--quiet", "-m", "Add fixture documents")
    return run_git(path, "rev-parse", "HEAD")


def page_text(lang: str, genre: str, number: int) -> str:
    """Wikitext of a synthetic page; long enough to pass the minimum document length."""
    if lang == "de":
        body = (
            f"Die '''Musterstadt {number}''' liegt am [[Fluss|Rhein]] und gehört zum Bereich {genre}. "
            "Sie hat rund 50.000 Einwohner und ein historisches Rathaus.<ref>Statistisches Amt, 2024.</ref>\n\n"
            "== Geschichte ==\nDie Stadt wurde im Mittelalter gegründet und wuchs mit dem Handel entlang des Flusses. "
            "{{Infobox Ort|Name=Musterstadt|Einwohner=50000}}\n"
        )
    else:
        body = (
            f"'''Sample Town {number}''' is a town on the [[River Thames|Thames]] in the {genre} section. "
            "It has about 50,000 residents and a historic town hall.<ref>Office for Statistics, 2024.</ref>\n\n"
            "== History ==\nThe town was founded in the Middle Ages and grew with the river trade. "
            "{{Infobox settlement|name=Sample Town|population=50000}}\n"
        )
    return body * 2


class FakeWiki:
    """Stands in for ``fetch_url``: serves ``action=raw`` revisions and ``action=query`` titles."""

    def __init__(self) -> None:
        self.revisions: dict[int, tuple[str, str]] = {}
        self.calls: list[str] = []

    def add(self, revid: int, title: str, text: str) -> dict:
        self.revisions[revid] = (title, text)
        return {"title": title, "revid": revid}

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        assert f"{parsed.scheme}://{parsed.netloc}" == SITE
        if parsed.path == "/w/index.php":
            assert query["action"] == ["raw"]
            revid = int(query["oldid"][0])
            if revid not in self.revisions:
                raise ValueError(f"HTTP 404 for {url}")
            return self.revisions[revid][1].encode("utf-8")
        assert parsed.path == "/w/api.php" and query["action"] == ["query"]
        pages, bad = [], {}
        for revid in map(int, query["revids"][0].split("|")):
            if revid in self.revisions:
                pages.append({"title": self.revisions[revid][0], "revisions": [{"revid": revid}]})
            else:
                bad[str(revid)] = {"revid": revid, "missing": True}
        result = {"query": {"pages": pages}}
        if bad:
            result["query"]["badrevids"] = bad
        return json.dumps(result).encode("utf-8")


@pytest.fixture
def wiki(monkeypatch):
    fake = FakeWiki()
    monkeypatch.setattr(MODULE, "fetch_url", fake)
    monkeypatch.setattr(MODULE, "REQUEST_DELAY_SECONDS", 0)
    return fake


@pytest.fixture
def fixture_sources(tmp_path, wiki):
    """Every language x genre in both splits; government DE via git, everything else via a wiki."""
    laws = tmp_path / "upstream" / "laws"
    laws_commit = make_repo(
        laws,
        {
            "LICENSE": "This is free and unencumbered software released into the public domain.\n",
            "a/bspg/index.md": LAW,
            "b/bspv/index.md": LAW.replace("Beispielgesetz", "Beispielverordnung").replace("BspG", "BspV"),
            "c/other/index.md": LAW.replace("Beispielgesetz", "Anderes Gesetz"),
            "img/logo.png": b"\x89PNG\x00\x01",
        },
    )
    sources = []
    revid = 100
    for split in MODULE.SPLITS:
        for lang in MODULE.LANGS:
            for genre in MODULE.GENRES:
                if (lang, genre) == ("de", "government"):
                    paths = ["a/*/index.md"] if split == "dev" else ["b/*/index.md"]
                    sources.append(
                        {"id": f"laws-{split}", "type": "git", "url": laws.as_uri(), "commit": laws_commit,
                         "paths": paths, "license": "Unlicense", "lang": "de", "genre": "government",
                         "split": split, "sha256": None}
                    )  # fmt: skip
                    continue
                pages = []
                for number in range(2):
                    revid += 1
                    pages.append(wiki.add(revid, f"{split} {lang} {genre} {number}", page_text(lang, genre, revid)))
                sources.append(
                    {"id": f"{lang}-{genre}-{split}", "type": "mediawiki", "site": SITE, "pages": pages,
                     "license": "CC-BY-SA-4.0", "lang": lang, "genre": genre, "split": split, "sha256": None}
                )  # fmt: skip
    return sources


def write_list(path: Path, sources: list[dict]) -> Path:
    path.write_text(json.dumps({"schema": MODULE.LIST_SCHEMA, "sources": sources}, indent=2) + "\n")
    return path


def pinned_list(tmp_path: Path, sources: list[dict]) -> Path:
    path = write_list(tmp_path / "sources.json", sources)
    assert MODULE.pin(tmp_path / "pin-cache", path, write=True) == 0
    return path


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line]


def mediawiki_source(**change) -> dict:
    source = {
        "id": "wiki", "type": "mediawiki", "site": SITE, "pages": [{"title": "A", "revid": 1}],
        "license": "CC-BY-SA-4.0", "lang": "de", "genre": "prose", "split": "dev",
    }  # fmt: skip
    return {**source, **change}


# ── licenses and source list ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "license_id, expected",
    [
        ("CC0-1.0", True),
        ("CC-BY-4.0", True),
        ("CC-BY-SA-4.0", True),
        ("CC-BY-SA-3.0", True),
        ("Unlicense", True),
        ("CC-BY-NC-4.0", False),
        ("CC-BY-ND-4.0", False),
        ("CC-BY-NC-SA-4.0", False),
        ("MIT", False),
        ("GPL-3.0-only", False),
        ("", False),
    ],
)
def test_only_public_domain_and_cc_licenses_are_accepted(license_id, expected):
    assert MODULE.is_open_content_license(license_id) is expected


@pytest.mark.parametrize(
    "change, message",
    [
        ({"license": "CC-BY-NC-4.0"}, "not public domain or CC"),
        ({"split": "test"}, "split"),
        ({"lang": "fr"}, "lang"),
        ({"genre": "fiction"}, "genre"),
        ({"type": "http"}, "type"),
        ({"id": "Bad Id"}, "invalid source id"),
        ({"sha256": "XYZ"}, "sha256"),
        ({"site": "http://wiki.example.invalid"}, "https"),
        ({"pages": []}, "pages"),
        ({"pages": [{"title": "A", "revid": 0}]}, "revid"),
        ({"pages": [{"title": "", "revid": 1}]}, "title"),
        ({"pages": [{"title": "A", "revid": 1}, {"title": "B", "revid": 1}]}, "duplicate"),
    ],
)
def test_invalid_mediawiki_sources_are_rejected(tmp_path, change, message):
    with pytest.raises(ValueError, match=message):
        MODULE.load_sources(write_list(tmp_path / "sources.json", [mediawiki_source(**change)]))


@pytest.mark.parametrize(
    "change, message",
    [
        ({"commit": "abc123"}, "40-hex"),
        ({"paths": []}, "paths"),
        ({"paths": ["/etc/passwd"]}, "relative"),
        ({"paths": ["docs/../x.md"]}, "relative"),
    ],
)
def test_invalid_git_sources_are_rejected(tmp_path, change, message):
    source = {
        "id": "laws", "type": "git", "url": "https://example.invalid/laws", "commit": "a" * 40,
        "paths": ["a/*.md"], "license": "Unlicense", "lang": "de", "genre": "government", "split": "dev",
    }  # fmt: skip
    with pytest.raises(ValueError, match=message):
        MODULE.load_sources(write_list(tmp_path / "sources.json", [{**source, **change}]))


def test_a_page_in_two_sources_is_rejected(tmp_path):
    first = mediawiki_source()
    second = mediawiki_source(id="wiki2", split="holdout", pages=[{"title": "Other", "revid": 1}])
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.load_sources(write_list(tmp_path / "sources.json", [first, second]))
    third = mediawiki_source(id="wiki3", split="holdout", pages=[{"title": "A", "revid": 2}])
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.load_sources(write_list(tmp_path / "sources.json", [first, third]))
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.load_sources(write_list(tmp_path / "sources.json", [first, {**first}]))


def test_committed_source_list_is_pinned_split_by_source_and_covers_every_language_and_genre():
    sources = MODULE.load_sources()
    assert {source["type"] for source in sources} == {"git", "mediawiki"}
    for source in sources:
        assert source["sha256"], source["id"]
        if source["type"] == "git":
            assert source["url"].startswith("https://github.com/"), source["id"]
        else:
            assert source["site"].endswith((".wikipedia.org", ".wikimedia.org")), source["id"]
            assert len(source["pages"]) >= 20, source["id"]
    for split in MODULE.SPLITS:
        covered = {(source["lang"], source["genre"]) for source in sources if source["split"] == split}
        assert covered == {(lang, genre) for lang in MODULE.LANGS for genre in MODULE.GENRES}, split
    titles = [(source["site"], page["title"]) for source in sources if source["type"] == "mediawiki" for page in source["pages"]]
    assert len(set(titles)) == len(titles)


# ── wikitext and markdown to text ────────────────────────────────────────────


def test_wikitext_to_text_keeps_prose_and_drops_markup():
    wikitext = (
        "<languages />\n{{Infobox|name={{lang|de|Ort}}|x=1}}\n"
        "= <translate><!--T:1--> Main heading</translate> =\n"
        "The '''town''' lies on the [[River Thames|Thames]] near [[London]].<ref name=a>Source, p. 1.</ref>"
        "<ref name=a /> See [https://example.invalid/history the history] and [{{FULLURL:Page|oldid=1}} 2003].\n"
        "[[File:Map.png|thumb|A map with a [[link]].]]\n"
        "{| class=\"wikitable\"\n|-\n| cell || cell\n|}\n"
        "* first item with <span lang=\"de\">Wort</span>&nbsp;&amp; more\n"
        "<!-- hidden comment -->\n\n\n\n"
        "== Section ==\nUse the [<tvar name=\"x\">https://example.invalid</tvar> archive].<br />End.\n"
        "<gallery>\nA.jpg|caption\n</gallery>\n__NOTOC__\n[[Category:Towns]]\n[[de:Stadt]]\n"
    )
    assert MODULE.wikitext_to_text(wikitext) == (
        "Main heading\n"
        "The town lies on the Thames near London. See the history and 2003.\n\n"
        "first item with Wort & more\n\n"
        "Section\nUse the archive.\nEnd.\n"
    )


def test_wikitext_to_text_is_deterministic_on_unbalanced_markup():
    text = "Start {{broken template [[unclosed link and '''bold\n"
    assert MODULE.wikitext_to_text(text) == MODULE.wikitext_to_text(text)
    assert "Start" in MODULE.wikitext_to_text(text)


def test_markdown_front_matter_is_removed():
    assert MODULE.markdown_text(LAW).startswith("# Beispielgesetz (BspG)\n")
    assert MODULE.markdown_text(GUIDE) == GUIDE
    assert MODULE.markdown_text("---\nno closing marker\n") == "---\nno closing marker\n"


# ── building and freezing splits ─────────────────────────────────────────────


def test_prepare_writes_both_splits_with_manifest_license_and_sha256(tmp_path, fixture_sources, capsys):
    sources_path = pinned_list(tmp_path, fixture_sources)
    capsys.readouterr()
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.prepare(dev, holdout, sources_path=sources_path) == 0
    out = capsys.readouterr().out
    assert "dev laws-dev:" in out and "laws-holdout:" not in out
    for split, directory in (("dev", dev), ("holdout", holdout)):
        assert MODULE.check_split(directory) == []
        manifest = json.loads((directory / "manifest.json").read_text())
        assert manifest["schema"] == MODULE.SCHEMA and manifest["split"] == split
        entries = {entry["id"]: entry for entry in manifest["sources"]}
        assert set(entries) == {source["id"] for source in fixture_sources if source["split"] == split}
        for entry in entries.values():
            data = (directory / entry["file"]).read_bytes()
            assert entry["sha256"] == sha256(data) and entry["license"] in ("CC-BY-SA-4.0", "Unlicense")
            documents = read_jsonl(directory / entry["file"])
            assert entry["documents"] == len(documents) == (2 if entry["type"] == "mediawiki" else 1)
            assert entry["bytes"] == sum(len(doc["text"].encode("utf-8")) for doc in documents)
            for doc in documents:
                assert doc["source"] == entry["id"] and doc["lang"] == entry["lang"] and doc["genre"] == entry["genre"]
                assert doc["license"] == entry["license"] and doc["url"]
        assert set(manifest["by_lang_genre"]) == {f"{lang}/{genre}" for lang in MODULE.LANGS for genre in MODULE.GENRES}
        assert manifest["bytes"] == sum(entry["bytes"] for entry in entries.values())
        assert (directory / ".ready").read_text() == f"{sha256((directory / 'manifest.json').read_bytes())}  manifest.json\n"

    laws = json.loads((dev / "manifest.json").read_text())["sources"]
    [git_entry] = [entry for entry in laws if entry["type"] == "git"]
    laws_source = next(source for source in fixture_sources if source["id"] == "laws-dev")
    assert git_entry["commit"] == laws_source["commit"] and git_entry["license_file"] == "LICENSE"
    [law] = read_jsonl(dev / "laws-dev.jsonl")
    assert law["id"] == "laws-dev:a/bspg/index.md" and law["path"] == "a/bspg/index.md"
    assert law["text"].startswith("# Beispielgesetz (BspG)") and "layout:" not in law["text"]
    page = read_jsonl(dev / "de-prose-dev.jsonl")[0]
    assert page["id"] == "de-prose-dev:dev de prose 0" and page["title"] == "dev de prose 0"
    assert page["url"] == f"{SITE}/w/index.php?oldid={page['revid']}"
    assert "Musterstadt" in page["text"] and "[[" not in page["text"] and "Statistisches Amt" not in page["text"]
    assert not (dev / ".sources").exists()
    assert (holdout / ".sources" / "benign_docs" / "de-prose-holdout").is_dir()


def test_rerun_is_byte_identical_and_offline(tmp_path, fixture_sources, wiki):
    sources_path = pinned_list(tmp_path, fixture_sources)
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.prepare(dev, holdout, sources_path=sources_path) == 0
    before = {path.name: path.read_bytes() for path in dev.iterdir()}
    calls = len(wiki.calls)
    assert MODULE.prepare(dev, holdout, sources_path=sources_path, offline=True) == 0
    assert len(wiki.calls) == calls
    assert {path.name: path.read_bytes() for path in dev.iterdir()} == before
    other = tmp_path / "again"
    assert MODULE.prepare(other / "dev", other / "holdout", tmp_path / "fresh-cache", sources_path) == 0
    assert (other / "dev" / "manifest.json").read_bytes() == before["manifest.json"]


def test_offline_without_cache_fails(tmp_path, fixture_sources):
    sources_path = pinned_list(tmp_path, fixture_sources)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", sources_path=sources_path, offline=True) == 1


def test_pin_mismatch_and_missing_pin_fail(tmp_path, fixture_sources, capsys):
    unpinned = write_list(tmp_path / "unpinned.json", fixture_sources)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", sources_path=unpinned) == 1
    assert "no pinned sha256" in capsys.readouterr().err
    wrong = write_list(tmp_path / "wrong.json", [{**source, "sha256": "0" * 64} for source in fixture_sources])
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", sources_path=wrong) == 1
    assert "pinned 000" in capsys.readouterr().err
    assert not (tmp_path / "dev" / ".ready").exists()


def test_pin_reports_changes_without_writing(tmp_path, fixture_sources):
    path = write_list(tmp_path / "sources.json", fixture_sources)
    assert MODULE.pin(tmp_path / "cache", path) == 1
    assert json.loads(path.read_text())["sources"][0]["sha256"] is None
    assert MODULE.pin(tmp_path / "cache", path, write=True) == 0
    assert MODULE.pin(tmp_path / "cache", path, offline=True) == 0


def test_frozen_split_is_not_overwritten_without_force(tmp_path, fixture_sources):
    sources_path = pinned_list(tmp_path, fixture_sources)
    dev, holdout = tmp_path / "dev", tmp_path / "holdout"
    assert MODULE.prepare(dev, holdout, sources_path=sources_path) == 0
    (dev / "laws-dev.jsonl").write_text("tampered\n")
    assert MODULE.check_split(dev)
    assert MODULE.prepare(dev, holdout, sources_path=sources_path) == 1
    assert (dev / "laws-dev.jsonl").read_text() == "tampered\n"
    assert MODULE.prepare(dev, holdout, sources_path=sources_path, force=True) == 0
    assert MODULE.check_split(dev) == []


def test_nested_output_directories_are_rejected(tmp_path, fixture_sources):
    sources_path = pinned_list(tmp_path, fixture_sources)
    assert MODULE.prepare(tmp_path / "out", tmp_path / "out" / "holdout", sources_path=sources_path) == 1
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", tmp_path / "dev" / "src", sources_path) == 1


def test_split_without_a_language_genre_pair_fails(tmp_path, fixture_sources, capsys):
    sources = [source for source in fixture_sources if source["id"] != "en-corporate-holdout"]
    sources_path = pinned_list(tmp_path, sources)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", sources_path=sources_path) == 1
    assert "holdout split has no en/corporate documents" in capsys.readouterr().err


def test_documents_shared_between_splits_are_rejected(tmp_path, fixture_sources, capsys):
    sources = [
        {**source, "paths": ["*/*/index.md"]} if source["id"] == "laws-holdout" else source for source in fixture_sources
    ]
    sources_path = pinned_list(tmp_path, sources)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", sources_path=sources_path) == 1
    assert "a/bspg/index.md is in more than one source" in capsys.readouterr().err


def test_identical_text_in_both_splits_is_rejected(tmp_path, fixture_sources, wiki, capsys):
    holdout_page = next(source for source in fixture_sources if source["id"] == "en-prose-holdout")["pages"][0]
    dev_page = next(source for source in fixture_sources if source["id"] == "en-prose-dev")["pages"][0]
    wiki.revisions[holdout_page["revid"]] = (holdout_page["title"], wiki.revisions[dev_page["revid"]][1])
    sources_path = pinned_list(tmp_path, fixture_sources)
    assert MODULE.prepare(tmp_path / "dev", tmp_path / "holdout", sources_path=sources_path) == 1
    assert "same text in dev and holdout" in capsys.readouterr().err


def test_git_source_without_license_file_or_without_matches_fails(tmp_path):
    source = tmp_path / "upstream" / "nolicense"
    commit = make_repo(source, {"docs/a.md": GUIDE})
    entry = {
        "id": "guides", "type": "git", "url": source.as_uri(), "commit": commit, "paths": ["docs/*.md"],
        "license": "CC0-1.0", "lang": "en", "genre": "government", "split": "dev",
    }  # fmt: skip
    with pytest.raises(ValueError, match="no license file"):
        MODULE.build_source(entry, tmp_path / "cache")
    licensed = tmp_path / "upstream" / "licensed"
    commit = make_repo(licensed, {"LICENSE.md": "CC0 1.0 Universal\n", "docs/a.md": GUIDE})
    entry = {**entry, "url": licensed.as_uri(), "commit": commit, "paths": ["missing/*.md"]}
    with pytest.raises(ValueError, match="matches no file"):
        MODULE.build_source(entry, tmp_path / "cache2")


def test_git_source_fetches_only_selected_blobs(tmp_path):
    files = {"LICENSE.md": "CC0 1.0 Universal\n", "docs/a.md": GUIDE, "docs/b.md": GUIDE.replace("kickoff", "planning")}
    files.update({f"assets/big{i}.txt": "unrelated " * 5000 for i in range(3)})
    upstream = tmp_path / "upstream" / "guides"
    commit = make_repo(upstream, files)
    entry = {
        "id": "guides", "type": "git", "url": upstream.as_uri(), "commit": commit, "paths": ["docs/*.md"],
        "license": "CC0-1.0", "lang": "en", "genre": "government", "split": "dev",
    }  # fmt: skip
    data, manifest_entry = MODULE.build_source(entry, tmp_path / "cache")
    assert [doc["path"] for doc in map(json.loads, data.decode().splitlines())] == ["docs/a.md", "docs/b.md"]
    assert manifest_entry["license_file"] == "LICENSE.md"
    git_dir = tmp_path / "cache" / "guides" / "files.git"
    big = run_git(upstream, "rev-parse", f"{commit}:assets/big0.txt")
    present = MODULE.git(["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], git_dir).decode().split()
    assert big not in present and len(present) == 7  # commit, 3 trees, license and the two selected blobs
    lazy = subprocess.run(["git", "--git-dir", str(git_dir), "cat-file", "-e", big], env=MODULE.GIT_ENV, capture_output=True)
    assert lazy.returncode != 0  # no promisor remote left: missing blobs are never fetched lazily


def test_mediawiki_revision_with_wrong_title_or_missing_revision_fails(tmp_path, wiki):
    wiki.add(7, "Real title", page_text("en", "prose", 7))
    entry = mediawiki_source(pages=[{"title": "Expected title", "revid": 7}], lang="en")
    with pytest.raises(ValueError, match="Real title"):
        MODULE.build_source(entry, tmp_path / "cache")
    entry = mediawiki_source(pages=[{"title": "Gone", "revid": 8}])
    with pytest.raises(ValueError, match="revision 8"):
        MODULE.build_source(entry, tmp_path / "cache2")


def test_short_and_oversized_documents_are_skipped(tmp_path, wiki, monkeypatch):
    monkeypatch.setattr(MODULE, "MAX_DOC_BYTES", 2000)
    pages = [
        wiki.add(1, "Short", "Too short."),
        wiki.add(2, "Normal", page_text("en", "prose", 2)),
        wiki.add(3, "Huge", page_text("en", "prose", 3) * 10),
    ]
    data, entry = MODULE.build_source(mediawiki_source(pages=pages, lang="en"), tmp_path / "cache")
    assert [doc["title"] for doc in map(json.loads, data.decode().splitlines())] == ["Normal"]
    assert entry["documents"] == 1 and entry["skipped"] == 2


def test_fetch_retries_rate_limits(monkeypatch):
    responses = iter([MODULE.RetryableError("HTTP 429"), MODULE.RetryableError("HTTP 503"), b"ok"])

    def fake_open(url):
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    sleeps = []
    monkeypatch.setattr(MODULE, "_open_url", fake_open)
    monkeypatch.setattr(MODULE.time, "sleep", sleeps.append)
    assert MODULE.fetch_url("https://wiki.example.invalid/w/index.php?action=raw&oldid=1") == b"ok"
    assert len(sleeps) == 2 and sleeps[0] < sleeps[1]


# ── FP report ────────────────────────────────────────────────────────────────


DOCUMENTS = {
    "de-wiki:A": {"source": "de-wiki", "lang": "de", "genre": "prose", "bytes": 400_000},
    "de-wiki:B": {"source": "de-wiki", "lang": "de", "genre": "prose", "bytes": 100_000},
    "en-corp:C": {"source": "en-corp", "lang": "en", "genre": "corporate", "bytes": 500_000},
}


def test_fp_report_counts_spans_and_flagged_documents_per_rule_language_genre_and_source():
    predictions = [
        {"id": "de-wiki:A", "evidence_spans": [
            {"rule_id": "dlp_business_metric", "start_char": 0, "end_char": 10},
            {"rule_id": "dlp_business_metric", "start_char": 20, "end_char": 30},
            {"rule_id": "dlp_password_assignment", "start_char": 0, "end_char": 10},
        ]},
        {"id": "de-wiki:B", "evidence_spans": []},
        {"id": "en-corp:C", "evidence_spans": [{"label": "dlp_hr_document", "start_char": 5, "end_char": 9}]},
    ]  # fmt: skip
    report = MODULE.fp_report(DOCUMENTS, predictions)
    assert report["bytes"] == 1_000_000 and report["documents"] == 3
    assert report["fp"] == 3 and report["fp_per_mb"] == 3.0
    assert report["documents_flagged"] == 2 and report["flagged_rate"] == 0.6667
    assert report["by_lang"]["de"] == {
        "bytes": 500_000, "documents": 2, "documents_flagged": 1, "flagged_rate": 0.5, "fp": 2, "fp_per_mb": 4.0,
    }  # fmt: skip
    assert report["by_genre"]["corporate"]["fp_per_mb"] == 2.0
    assert report["by_source"]["de-wiki"]["documents_flagged"] == 1
    assert report["by_rule"] == {
        "dlp_business_metric": {"documents_flagged": 1, "flagged_rate": 0.3333, "fp": 2, "fp_per_mb": 2.0},
        "dlp_hr_document": {"documents_flagged": 1, "flagged_rate": 0.3333, "fp": 1, "fp_per_mb": 1.0},
        "dlp_password_assignment": {"documents_flagged": 1, "flagged_rate": 0.3333, "fp": 1, "fp_per_mb": 1.0},
    }


def test_document_level_labels_flag_documents_without_spans():
    predictions = [{"id": "en-corp:C", "evidence_spans": [], "document_labels": ["dlp_hr_document"]}]
    report = MODULE.fp_report(DOCUMENTS, predictions)
    assert report["fp"] == 0 and report["documents_flagged"] == 1
    assert report["by_rule"]["dlp_hr_document"] == {"documents_flagged": 1, "flagged_rate": 0.3333, "fp": 0, "fp_per_mb": 0.0}


def test_fp_report_without_predictions_is_zero_and_rejects_unknown_ids():
    report = MODULE.fp_report(DOCUMENTS, [])
    assert report["fp_per_mb"] == 0.0 and report["flagged_rate"] == 0.0 and report["by_rule"] == {}
    with pytest.raises(ValueError, match="unknown document"):
        MODULE.fp_report(DOCUMENTS, [{"id": "x:missing", "evidence_spans": []}])


def test_fp_report_cli_on_a_prepared_split(tmp_path, fixture_sources):
    sources_path = pinned_list(tmp_path, fixture_sources)
    dev = tmp_path / "dev"
    assert MODULE.prepare(dev, tmp_path / "holdout", sources_path=sources_path) == 0
    documents = MODULE.load_corpus(dev)
    assert "laws-dev:a/bspg/index.md" in documents
    assert {doc["lang"] for doc in documents.values()} == set(MODULE.LANGS)
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text(
        json.dumps({"id": "laws-dev:a/bspg/index.md", "evidence_spans": [{"rule_id": "r", "start_char": 0, "end_char": 3}]})
        + "\n"
    )
    output = tmp_path / "report.json"
    assert MODULE.main(["fp-report", "--corpus", str(dev), "--predictions", str(predictions), "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["fp"] == 1 and report["bytes"] == sum(doc["bytes"] for doc in documents.values())
    assert report["by_genre"]["government"]["fp"] == 1 and report["by_lang"]["de"]["documents_flagged"] == 1
    (dev / "laws-dev.jsonl").write_text("tampered\n")
    assert MODULE.main(["fp-report", "--corpus", str(dev), "--predictions", str(predictions)]) == 1
