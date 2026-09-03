"""Keep CI bootstrap aligned with the toolchain required by plain cargo/rustc."""
from pathlib import Path
import re
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("workflow", ["ci.yml", "release.yml"])
def test_toolchain_actions_install_all_repository_components(workflow):
    required = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]
    text = (ROOT / ".github" / "workflows" / workflow).read_text()
    steps = re.findall(
        r"(?m)^      - uses: dtolnay/rust-toolchain@([^\n]+)\n((?:        [^\n]*\n)*)",
        text,
    )
    assert steps, f"no Rust toolchain setup found in {workflow}"
    for version, options in steps:
        assert version == required["channel"]
        components = re.search(r"(?m)^          components: ([^\n]+)$", options)
        assert components, f"{workflow}: install components explicitly before running cargo/rustc"
        installed = {value.strip() for value in components.group(1).split(",")}
        assert set(required["components"]) <= installed
