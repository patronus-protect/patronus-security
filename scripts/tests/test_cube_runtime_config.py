"""Check offline Cube bootstrap addressing and private runtime rendering."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest
import yaml


DEPLOY = Path(__file__).resolve().parents[2] / "ark-api" / "deploy"
spec = importlib.util.spec_from_file_location("bootstrap_config", DEPLOY / "bootstrap_config.py")
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


@pytest.fixture
def root_files(monkeypatch):
    """Model root ownership on a developer machine; keep real permissions and I/O."""
    original_stat = os.fstat

    def root_stat(fd):
        values = list(original_stat(fd))
        values[4] = 0
        return os.stat_result(values)

    monkeypatch.setattr(config.os, "fstat", root_stat)
    monkeypatch.setattr(config.os, "fchown", lambda *_: None)


def private_file(path, value):
    path.write_text(value + "\n")
    path.chmod(0o600)
    return path


def cube_root(path):
    path.mkdir(mode=0o700)
    for name in ("worker", "entrypoint"):
        (path / f"{name}.template.yaml").write_text((DEPLOY / f"{name}.template.yaml").read_text())
    return path


@pytest.mark.parametrize("address", ["10.20.0.11", "10.20.0.12", "10.20.0.23", "10.20.0.254"])
def test_cube_ip_validation_accepts_other_cubes_without_host_actions(address):
    functions = (DEPLOY / "bootstrap.sh").read_text().split("phase=${1:-help}")[0]
    result = subprocess.run(["bash", "-c", functions + '\nCUBE_IP=$1; validate_cube_ip', "test", address],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("address", ["10.20.0.0", "10.20.0.1", "10.20.0.255", "10.20.0.999",
                                     "10.20.0.012", "10.21.0.12", "10.20.0.12/24", "invalid"])
def test_invalid_cube_ip_fails_before_any_host_actions(address):
    result = subprocess.run(["bash", str(DEPLOY / "bootstrap.sh"), "network", "--cube-ip", address],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "Cube IP must" in result.stderr
    assert "Run with sudo" not in result.stderr


def test_external_redis_and_shared_key_keep_worker_credentials_cube_local(tmp_path, root_files, capsys):
    shared = private_file(tmp_path / "shared.key", "ab" * 32)
    # URL metacharacters remain data even when embedded in YAML.
    url = 'rediss://patronus:s%23e%22cr%3Aet@redis.internal:6379/0'
    redis = private_file(tmp_path / "redis-input", url)
    roots = [cube_root(tmp_path / name) for name in ("cube1", "cube2")]
    workers = []
    for root in roots:
        config.configure(root, shared, redis)
        rendered = yaml.safe_load((root / "entrypoint.yaml").read_text())
        assert rendered["gateway"]["redis_url"] == url
        assert rendered["auth"]["keys"][0]["key_hash"] == hashlib.sha256(("ab" * 32).encode()).hexdigest()
        workers.append(rendered["gateway"]["worker_token"])
        assert (root / "public-api.key").read_text() == shared.read_text()
        assert (root / "redis-mode").read_text() == "external\n"
        for name in ("public-api.key", "public-api.keys", "worker.key", "redis.url", "redis-mode"):
            assert stat.S_IMODE((root / name).stat().st_mode) == 0o600
        assert stat.S_IMODE((root / "entrypoint.yaml").stat().st_mode) == 0o400
        first_worker = (root / "worker.key").read_text()
        config.configure(root)
        assert (root / "worker.key").read_text() == first_worker
        assert yaml.safe_load((root / "entrypoint.yaml").read_text())["gateway"]["redis_url"] == url
    assert workers[0] != workers[1]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_additional_entrypoint_key_renders_distinct_hashes_without_storing_raw_value(tmp_path, root_files):
    root = cube_root(tmp_path / "cube")
    primary = private_file(tmp_path / "primary.key", "ab" * 32)
    additional = private_file(tmp_path / "additional.key", "cd" * 32)
    config.configure(root, primary, additional_key_files=[additional])
    rendered = yaml.safe_load((root / "entrypoint.yaml").read_text())
    assert [item["name"] for item in rendered["auth"]["keys"]] == ["public-client-1", "public-client-2"]
    assert [item["key_hash"] for item in rendered["auth"]["keys"]] == [
        hashlib.sha256(("ab" * 32).encode()).hexdigest(),
        hashlib.sha256(("cd" * 32).encode()).hexdigest(),
    ]
    assert (root / "public-api.key").read_text() == primary.read_text()
    assert "cd" * 32 not in (root / "entrypoint.yaml").read_text()
    assert (root / "public-api.keys").read_text() == primary.read_text() + additional.read_text()
    assert stat.S_IMODE((root / "public-api.keys").stat().st_mode) == 0o600

    # A later deploy with omitted key arguments must preserve the overlap.
    config.configure(root)
    rerendered = yaml.safe_load((root / "entrypoint.yaml").read_text())
    assert [item["key_hash"] for item in rerendered["auth"]["keys"]] == [
        hashlib.sha256(("ab" * 32).encode()).hexdigest(),
        hashlib.sha256(("cd" * 32).encode()).hexdigest(),
    ]


def test_explicit_primary_key_without_additions_finishes_rotation(tmp_path, root_files):
    root = cube_root(tmp_path / "cube")
    old = private_file(tmp_path / "old.key", "ab" * 32)
    new = private_file(tmp_path / "new.key", "cd" * 32)
    config.configure(root, old, additional_key_files=[new])

    config.configure(root, new)

    rendered = yaml.safe_load((root / "entrypoint.yaml").read_text())
    assert [item["key_hash"] for item in rendered["auth"]["keys"]] == [
        hashlib.sha256(("cd" * 32).encode()).hexdigest(),
    ]
    assert (root / "public-api.keys").read_text() == new.read_text()


def test_interrupted_keyring_update_is_resumed_without_explicit_key_files(tmp_path, root_files, monkeypatch):
    root = cube_root(tmp_path / "cube")
    old = private_file(tmp_path / "old.key", "ab" * 32)
    new = private_file(tmp_path / "new.key", "cd" * 32)
    config.configure(root, old, additional_key_files=[new])
    original_write = config.write_private

    def interrupt_after_keyring(path, contents, owner=0, mode=0o600):
        if path == root / "public-api.key":
            raise OSError("simulated interruption")
        original_write(path, contents, owner, mode)

    monkeypatch.setattr(config, "write_private", interrupt_after_keyring)
    with pytest.raises(OSError, match="simulated interruption"):
        config.configure(root, new)
    assert (root / "public-api.keys").read_text() == new.read_text()
    assert (root / "public-api.key").read_text() == old.read_text()

    monkeypatch.setattr(config, "write_private", original_write)
    config.configure(root)
    assert (root / "public-api.key").read_text() == new.read_text()
    rendered = yaml.safe_load((root / "entrypoint.yaml").read_text())
    assert len(rendered["auth"]["keys"]) == 1


def test_entrypoint_keyring_has_a_bounded_size(tmp_path, root_files):
    root = cube_root(tmp_path / "cube")
    primary = private_file(tmp_path / "primary.key", "00" * 32)
    additions = [private_file(tmp_path / f"key-{index}", f"{index:064x}") for index in range(1, 65)]
    with pytest.raises(ValueError, match="At most 64"):
        config.configure(root, primary, additional_key_files=additions)
    assert not (root / "public-api.keys").exists()


def test_duplicate_entrypoint_rotation_key_is_rejected_before_runtime_files_change(tmp_path, root_files):
    root = cube_root(tmp_path / "cube")
    primary = private_file(tmp_path / "primary.key", "ab" * 32)
    duplicate = private_file(tmp_path / "duplicate.key", "ab" * 32)
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with pytest.raises(ValueError, match="distinct"):
        config.configure(root, primary, additional_key_files=[duplicate])
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before


def test_local_redis_compatibility(tmp_path, root_files):
    root = cube_root(tmp_path / "cube")
    config.configure(root)
    assert not (root / "redis.url").exists()
    assert (root / "redis-mode").read_text() == "local\n"
    assert yaml.safe_load((root / "entrypoint.yaml").read_text())["gateway"]["redis_url"] == "redis://redis:6379/0"
    compose = yaml.safe_load((DEPLOY / "compose.yaml").read_text())
    assert compose["services"]["redis"]["profiles"] == ["local-redis"]
    assert compose["services"]["entrypoint"]["depends_on"]["redis"] == {
        "condition": "service_healthy", "required": False,
    }


@pytest.mark.parametrize("problem", ["world-readable", "symlink", "hardlink", "multiple-lines", "directory"])
def test_unsafe_secret_files_are_rejected(tmp_path, root_files, problem):
    secret = private_file(tmp_path / "secret", "ab" * 32)
    if problem == "world-readable":
        secret.chmod(0o644)
    elif problem == "symlink":
        (tmp_path / "link").symlink_to(secret)
        secret = tmp_path / "link"
    elif problem == "hardlink":
        os.link(secret, tmp_path / "link")
    elif problem == "multiple-lines":
        secret.write_text("secret\nsecond-line\n")
    elif problem == "directory":
        secret = tmp_path
    with pytest.raises(ValueError, match="root-owned, private regular file"):
        config.read_secret(secret)


def test_non_root_owned_secret_rejected(tmp_path, monkeypatch):
    secret = private_file(tmp_path / "secret", "ab" * 32)
    original_stat = os.fstat

    def user_stat(fd):
        values = list(original_stat(fd))
        values[4] = 1000
        return os.stat_result(values)

    monkeypatch.setattr(config.os, "fstat", user_stat)
    with pytest.raises(ValueError, match="root-owned"):
        config.read_secret(secret)


@pytest.mark.parametrize("url", [
    "rediss://patronus:secret@db.internal:6379/0#insecure",
    "redis://patronus:secret@8.8.8.8:6379/0",
    "redis://patronus:secret@127.0.0.1:6379/0",
    "redis://db.internal:6379/0", "rediss://patronus:secret@db.internal/0",
    "rediss://patronus:secret@db.internal:6379/0?insecure=true",
    "https://patronus:secret@db.internal:6379/0",
    "rediss://patronus:secret%0A@db.internal:6379/0",
    "rediss://patronus:secret%XX@db.internal:6379/0",
])
def test_bad_redis_url_rejected_without_disclosing_credentials(url):
    with pytest.raises(ValueError) as error:
        config.validate_redis_url(url)
    assert "secret" not in str(error.value)
    assert url not in str(error.value)


def test_invalid_input_leaves_existing_config_unchanged(tmp_path, root_files):
    root = cube_root(tmp_path / "cube")
    config.configure(root)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    redis = private_file(tmp_path / "redis-input", "rediss://user:secret@host:6379/0#insecure")
    with pytest.raises(ValueError):
        config.configure(root, redis_file=redis)
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


def test_cli_error_is_redacted(tmp_path, root_files, monkeypatch, capsys):
    root = cube_root(tmp_path / "cube")
    redis = private_file(tmp_path / "redis-input", "rediss://user:DO-NOT-PRINT@host:6379/0#insecure")
    monkeypatch.setattr(config.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", ["bootstrap_config.py", str(root), "--redis-url-file", str(redis)])
    with pytest.raises(SystemExit) as error:
        config.main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert "DO-NOT-PRINT" not in output.err + output.out
    assert "Invalid private runtime configuration" in output.err


@pytest.mark.parametrize("fail_readiness", [False, True])
def test_same_image_deployment_refreshes_mounts_before_removing_local_redis(tmp_path, fail_readiness):
    functions = (DEPLOY / "bootstrap.sh").read_text().split("phase=${1:-help}")[0]
    # Model Compose's same-image mount reuse; no Docker or host commands run.
    harness = r'''
DEPLOY_DIR=$1
STATE_DIR=$1
FAIL_READINESS=$2
RELEASE_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ARK_IMAGE=ghcr.io/patronus-protect/ark-api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
printf 'previous-boot\n' > "$STATE_DIR/network-boot-before"
printf 'local Redis is still running\n' > "$STATE_DIR/old-redis"
boot_id() { printf 'current-boot\n'; }
network_check() { :; }
install_docker() { :; }
fetch_config() { :; }
redis_mode() { printf 'external\n'; }
docker() {
    if [[ $1 == pull ]]; then return; fi
    case "$4" in
        *image.version*) printf '0.1.6\n' ;;
        *image.revision*) printf '%s\n' "$RELEASE_COMMIT" ;;
        *) return 1 ;;
    esac
}
revision=0
configure_secrets() {
    revision=$((revision + 1))
    printf 'runtime secret revision %s\n' "$revision" > "$DEPLOY_DIR/new.yaml"
    mv "$DEPLOY_DIR/new.yaml" "$DEPLOY_DIR/entrypoint.yaml"
}
compose() {
    printf '%s\n' "$*" >> "$STATE_DIR/compose-calls"
    case "$1" in
        config) return ;;
        up)
            [[ $* == *'--wait'* ]] || return 1
            if [[ ! -e $STATE_DIR/mounted-config || $* == *'--force-recreate'* ]]; then
                cp "$DEPLOY_DIR/entrypoint.yaml" "$STATE_DIR/mounted-config"
            fi
            cmp "$DEPLOY_DIR/entrypoint.yaml" "$STATE_DIR/mounted-config" || return 1
            [[ $FAIL_READINESS == false ]] || return 1
            printf 'ready\n' >> "$STATE_DIR/compose-calls"
            ;;
        --profile)
            [[ $* == '--profile local-redis rm --stop --force redis' ]] || return 1
            rm -f "$STATE_DIR/old-redis"
            ;;
        *) return 1 ;;
    esac
}
stack_check() { cmp "$DEPLOY_DIR/entrypoint.yaml" "$STATE_DIR/mounted-config"; }
deploy
deploy
'''
    result = subprocess.run(["bash", "-c", functions + harness, "test", str(tmp_path),
                             str(fail_readiness).lower()], capture_output=True, text=True)
    calls = (tmp_path / "compose-calls").read_text().splitlines()
    if fail_readiness:
        assert result.returncode != 0
        assert (tmp_path / "old-redis").exists()
        assert not any("rm --stop" in call for call in calls)
        return
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "mounted-config").read_text() == "runtime secret revision 2\n"
    assert not (tmp_path / "old-redis").exists()
    assert calls.count("ready") == 2
    for index, call in enumerate(calls):
        if "rm --stop" in call:
            assert calls[index - 1] == "ready"
