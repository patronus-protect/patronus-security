from pathlib import Path
import importlib.util
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("check_release_source", ROOT / "scripts/check_release_source.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_builds_allow_unpublished_feature_branches():
    MODULE.validate_release_source("build", "refs/heads/feature", "0.1.12", "abc", None, None)


@pytest.mark.parametrize("channel", ["testpypi", "production"])
def test_matching_release_branch_and_tag_are_required(channel):
    MODULE.validate_release_source(channel, "refs/tags/v0.1.12", "0.1.12", "abc", "abc", "abc")
    for ref, tag, branch in [
        ("refs/heads/main", "abc", "abc"),
        ("refs/heads/release/0.1.12", "abc", "abc"),
        ("refs/tags/v0.1.11", "abc", "abc"),
        ("refs/tags/v0.1.12", None, "abc"),
        ("refs/tags/v0.1.12", "abc", None),
        ("refs/tags/v0.1.12", "def", "abc"),
        ("refs/tags/v0.1.12", "abc", "def"),
    ]:
        with pytest.raises(ValueError):
            MODULE.validate_release_source(channel, ref, "0.1.12", "abc", tag, branch)
