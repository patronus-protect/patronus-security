"""Render private Cube runtime configuration; never emit credential values."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from urllib.parse import unquote, urlsplit


def read_secret(path):
    """Require a root-owned, private regular file, without following symlinks."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                raise ValueError
            value = handle.read(4097).removesuffix("\n")
        if not value or len(value) > 4096 or any(ord(c) < 33 for c in value):
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError):
        raise ValueError("Secret input must be a root-owned, private regular file containing one nonempty line.") from None


def validate_token(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("API/worker keys must contain exactly 64 lowercase hexadecimal characters.")
    return value


def validate_redis_url(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"redis", "rediss"} or not parsed.hostname
                or parsed.fragment or parsed.query or parsed.port is None
                or not 1 <= parsed.port <= 65535
                or not re.fullmatch(r"/[0-9]+", parsed.path)
                or not parsed.username or not parsed.password
                or any(c in value for c in "\r\n\t ")
                or re.search(r"%(?![0-9a-fA-F]{2})", value)):
            raise ValueError
        # External credentials must be explicit, and TLS verification cannot be bypassed.
        for part in (parsed.username, parsed.password):
            if any(ord(c) < 32 for c in unquote(part)):
                raise ValueError
        host = parsed.hostname
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
                raise ValueError
        else:
            if not address.is_private or address.is_loopback or address.is_unspecified:
                raise ValueError
        return value
    except ValueError:
        raise ValueError("External Redis requires redis[s]://user:password@private-host:port/database, without query or fragment.") from None


def write_private(path, contents, owner=0, mode=0o600):
    """Replace atomically; credentials never follow an existing destination symlink."""
    fd, temporary = tempfile.mkstemp(prefix=".secret-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(contents)
            os.fchown(handle.fileno(), owner, owner)
            os.fchmod(handle.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configure(root, key_file=None, redis_file=None, additional_key_files=None):
    public_path, worker_path = root / "public-api.key", root / "worker.key"
    redis_path = root / "redis.url"
    public = validate_token(read_secret(key_file or public_path)) if key_file or public_path.exists() else secrets.token_hex(32)
    public_keys = [public] + [validate_token(read_secret(path)) for path in (additional_key_files or [])]
    if len(set(public_keys)) != len(public_keys):
        raise ValueError("Entrypoint key files must contain distinct values.")
    worker = validate_token(read_secret(worker_path)) if worker_path.exists() else secrets.token_hex(32)
    external = redis_file is not None or redis_path.exists()
    redis_url = validate_redis_url(read_secret(redis_file or redis_path)) if external else "redis://redis:6379/0"
    public_key_yaml = "\n".join(
        f'    - name: public-client-{index}\n      key_hash: "{hashlib.sha256(value.encode()).hexdigest()}"'
        for index, value in enumerate(public_keys, start=1)
    )
    replacements = {
        "__PUBLIC_KEYS_YAML__": public_key_yaml,
        "__WORKER_HASH__": hashlib.sha256(worker.encode()).hexdigest(),
        "__WORKER_TOKEN__": worker,
        "__REDIS_URL_JSON__": json.dumps(redis_url),
    }
    rendered = {}
    for name in ("worker", "entrypoint"):
        contents = (root / f"{name}.template.yaml").read_text()
        for key, value in replacements.items():
            contents = contents.replace(key, value)
        rendered[name] = contents
    # Validate all inputs and read templates before changing any runtime file.
    write_private(public_path, public + "\n")
    write_private(worker_path, worker + "\n")
    if external:
        write_private(redis_path, redis_url + "\n")
    for name, contents in rendered.items():
        write_private(root / f"{name}.yaml", contents, owner=10001, mode=0o400)
    write_private(root / "redis-mode", "external\n" if external else "local\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--entrypoint-key-file", type=Path)
    parser.add_argument("--additional-entrypoint-key-file", type=Path, action="append", default=[])
    parser.add_argument("--redis-url-file", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Run as root.\n")
    try:
        configure(args.directory, args.entrypoint_key_file, args.redis_url_file, args.additional_entrypoint_key_file)
    except (OSError, ValueError):
        # Neither parser tracebacks nor file/URL representations may disclose credentials.
        parser.exit(1, "Invalid private runtime configuration; check root-only input files, key format, Redis URL, and templates.\n")


if __name__ == "__main__":
    main()
