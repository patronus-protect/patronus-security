"""Checks for the packaged legal files verified before a release."""

from pathlib import Path
import importlib.util
import shutil


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_legal_files", ROOT / "scripts" / "release_legal_files.py")
LEGAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEGAL)

RULE = LEGAL.RULE


def section(number: int, title: str, body: str) -> str:
    return f"{RULE}\n{number}. {title}\n{RULE}\n{body}\n"


def write_tree(root: Path, notice: str, core_notice: str) -> None:
    files = {source for source, _ in LEGAL.COPIES} - {"NOTICE", LEGAL.CORE_NOTICE}
    for path in files:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(f"{path}\n")
    (root / "NOTICE").write_text(notice)
    (root / LEGAL.CORE_NOTICE).write_text(core_notice)
    for source, copy in LEGAL.COPIES:
        (root / copy).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, root / copy)


NOTICE = "Ark\n\n" + section(1, "Ark only  (rust/src/x.rs)", "Ark body\n") + "\n" + section(
    2, "Core part  (ark-core/src/y.rs)", "Core body\n"
)
CORE_NOTICE = "Core\n\n" + section(1, "Core part  (ark-core/src/y.rs)", "Core body\n")


def test_repository_legal_files_are_current():
    assert LEGAL.problems() == []


def test_consistent_files_pass(tmp_path):
    write_tree(tmp_path, NOTICE, CORE_NOTICE)
    assert LEGAL.problems(tmp_path) == []


def test_stale_package_copy_is_reported(tmp_path):
    write_tree(tmp_path, NOTICE, CORE_NOTICE)
    (tmp_path / "python/NOTICE").write_text("old\n")
    assert LEGAL.problems(tmp_path) == ["python/NOTICE differs from NOTICE"]


def test_core_section_must_match_the_root_notice(tmp_path):
    changed = CORE_NOTICE.replace("Core body", "Other body")
    write_tree(tmp_path, NOTICE, changed)
    assert LEGAL.problems(tmp_path) == [
        "ark-core/NOTICE section 'Core part  (ark-core/src/y.rs)' is missing from NOTICE or differs"
    ]


def test_root_section_on_core_sources_must_be_in_the_core_notice(tmp_path):
    extra = NOTICE + "\n" + section(3, "New Core part  (ark-core/src/z.rs)", "New body\n")
    write_tree(tmp_path, extra, CORE_NOTICE)
    assert LEGAL.problems(tmp_path) == [
        "NOTICE section 'New Core part  (ark-core/src/z.rs)' covers ark-core/ but is missing from ark-core/NOTICE"
    ]
