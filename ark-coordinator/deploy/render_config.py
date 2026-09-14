#!/usr/bin/env python3
"""Render root-supplied Coordinator secrets without printing their values."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit


TOKEN = re.compile(r"[0-9a-f]{64}")


def read_secret(path: Path) -> str:
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        raise ValueError("secret input must be root-owned and mode 0600 or stricter")
    value = path.read_text().strip()
    if not TOKEN.fullmatch(value):
        raise ValueError("secret must contain exactly 64 lowercase hexadecimal characters")
    return value


def validate_redis_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "rediss"
        or not parsed.hostname
        or not parsed.username
        or not parsed.password
        or parsed.port is None
        or not re.fullmatch(r"/[0-9]+", parsed.path)
        or parsed.query
        or parsed.fragment
        or any(char in value for char in "\r\n\t ")
    ):
        raise ValueError("Managed Redis URL must be an authenticated rediss:// URL")
    return value


def read_redis_url(path: Path) -> str:
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        raise ValueError("Redis input must be root-owned and mode 0600 or stricter")
    return validate_redis_url(path.read_text().strip())


def read_cube_origins(path: Path) -> list[str]:
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        raise ValueError("Cube origins file must be root-owned and mode 0600 or stricter")
    return validate_cube_origins(path.read_text().splitlines())


def validate_cube_origins(lines: list[str]) -> list[str]:
    origins = [
        line.strip().rstrip("/")
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(origins) != 12 or len(set(origins)) != 12:
        raise ValueError("Cube origins file must contain exactly 12 unique origins")
    for origin in origins:
        parsed = urlsplit(origin)
        try:
            parsed.port
        except ValueError as error:
            raise ValueError("Cube origin contains an invalid port") from error
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or any(character.isspace() for character in origin)
        ):
            raise ValueError("Cube origins must be HTTP(S) origins without credentials or paths")
    return origins


def render_cubes(origins: list[str]) -> str:
    return "\n".join(
        (
            f"    - name: cube-{index:02d}\n"
            f"      url: {json.dumps(origin)}\n"
            "      max_in_flight: 3"
        )
        for index, origin in enumerate(origins, 1)
    )


def replace_private(path: Path, contents: str, owner: int = 10001) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".secret-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(contents)
            os.fchown(handle.fileno(), owner, owner)
            os.fchmod(handle.fileno(), 0o400)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def render(
    directory: Path,
    api_key_files: list[Path],
    cube_key_file: Path,
    redis_url_file: Path,
    cube_origins_file: Path,
) -> None:
    api_keys = [read_secret(path) for path in api_key_files]
    if not api_keys or len(set(api_keys)) != len(api_keys):
        raise ValueError("API key inputs must be present and distinct")
    cube_key = read_secret(cube_key_file)
    redis_url = read_redis_url(redis_url_file)
    cubes_yaml = render_cubes(read_cube_origins(cube_origins_file))
    key_yaml = "\n".join(
        f'    - key_hash: "{hashlib.sha256(key.encode()).hexdigest()}"'
        for key in api_keys
    )
    template = (directory / "config.template.yaml").read_text()
    rendered = template.replace("__API_KEYS_YAML__", key_yaml).replace(
        "__CUBES_YAML__", cubes_yaml
    )
    if "__API_KEYS_YAML__" in rendered or "__CUBES_YAML__" in rendered:
        raise ValueError("configuration template was not rendered")
    replace_private(directory / "config.yaml", rendered)
    replace_private(directory / "cube.token", cube_key + "\n")
    replace_private(directory / "redis.url", redis_url + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--api-key-file", type=Path, action="append", required=True)
    parser.add_argument("--cube-key-file", type=Path, required=True)
    parser.add_argument("--redis-url-file", type=Path, required=True)
    parser.add_argument("--cube-origins-file", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Run as root.\n")
    try:
        render(
            args.directory,
            args.api_key_file,
            args.cube_key_file,
            args.redis_url_file,
            args.cube_origins_file,
        )
    except (OSError, ValueError):
        parser.exit(1, "Invalid private Coordinator configuration; inspect root-only input files.\n")


if __name__ == "__main__":
    main()
