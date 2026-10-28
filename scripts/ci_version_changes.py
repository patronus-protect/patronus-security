"""Remove release-only version changes from the existing CI path selections."""
import json
import os
from pathlib import Path
import posixpath
import subprocess
import tomllib

from release_version import CARGO_MANIFESTS


ROOT = Path(__file__).resolve().parents[1]
VERSION_FILES = {"Cargo.lock", *CARGO_MANIFESTS, *(str(Path(p).with_name("pyproject.toml")) for p in CARGO_MANIFESTS)}


def normalize(path, text, manifests):
    data = tomllib.loads(text)
    names = {value["package"]["name"]: value["package"]["version"] for value in manifests.values()}
    if path == "Cargo.lock":
        references = {f"{name} {version}": name for name, version in names.items()}
        for package in data["package"]:
            if package.get("version") == names.get(package["name"]) and "source" not in package:
                package["version"] = "<release>"
            package["dependencies"] = [
                references.get(dep, dep)
                for dep in package.get("dependencies", [])
            ]
    elif path in manifests:
        data["package"]["version"] = "<release>"
        for table in [data, *data.get("target", {}).values()]:
            for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
                for dependency in table.get(kind, {}).values():
                    if not isinstance(dependency, dict) or "path" not in dependency:
                        continue
                    target = posixpath.normpath(f"{Path(path).parent}/{dependency['path']}/Cargo.toml")
                    if target in manifests and dependency.get("version") == manifests[target]["package"]["version"]:
                        dependency["version"] = "<release>"
    elif path in VERSION_FILES and path.endswith("pyproject.toml"):
        data["project"]["version"] = "<release>"
    return data


def version_only(path, before, after, old_manifests, new_manifests):
    return path in VERSION_FILES and normalize(path, before, old_manifests) == normalize(path, after, new_manifests)


def read_base(base, path):
    return subprocess.check_output(["git", "show", f"{base}:{path}"], cwd=ROOT, text=True)


def main():
    selections = json.loads(os.environ["CI_PATH_SELECTIONS"])
    base = os.environ["CI_BASE"]
    paths = {path for key, value in selections.items() if key.endswith("_files") for path in json.loads(value)}
    ignored = set()
    try:
        old = {p: tomllib.loads(read_base(base, p)) for p in CARGO_MANIFESTS}
        new = {p: tomllib.loads((ROOT / p).read_text()) for p in CARGO_MANIFESTS}
        for path in paths:
            if path in VERSION_FILES and version_only(path, read_base(base, path), (ROOT / path).read_text(), old, new):
                ignored.add(path)
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError):
        # New branches, missing files and invalid manifests retain the full path-based checks.
        ignored.clear()
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in selections.items():
            if key.endswith("_files"):
                selected = bool(set(json.loads(value)) - ignored)
                print(f"{key[:-6]}={str(selected).lower()}", file=output)
    print("Version-only files excluded from build jobs:", ", ".join(sorted(ignored)) or "none")


if __name__ == "__main__":
    main()
