"""Static checks for the downloadable model-free Coordinator deployment."""

from pathlib import Path
import importlib.util
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "ark-coordinator" / "deploy"
SPEC = importlib.util.spec_from_file_location("coordinator_render", DEPLOY / "render_config.py")
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)


def test_compose_contains_only_hardened_coordinator():
    config = yaml.safe_load((DEPLOY / "compose.yaml").read_text())
    assert set(config["services"]) == {"coordinator"}
    service = config["services"]["coordinator"]
    assert "build" not in service
    assert service["image"].startswith("${COORDINATOR_IMAGE")
    assert service["stop_grace_period"] == "310s"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["user"] == "10001:10001"
    assert service["ports"] == [
        "${COORDINATOR_IP:?Set the private Coordinator IP}:8090:8090",
        "127.0.0.1:8090:8090",
    ]


def test_template_renders_exactly_twelve_private_cube_origins():
    origins = [f"http://cube-{index:02d}.example.invalid:8080" for index in range(1, 13)]
    assert RENDER.validate_cube_origins(origins) == origins
    rendered = (DEPLOY / "config.template.yaml").read_text()
    rendered = rendered.replace(
        "__API_KEYS_YAML__", '    - key_hash: "' + "0" * 64 + '"'
    ).replace("__CUBES_YAML__", RENDER.render_cubes(origins))
    config = yaml.safe_load(rendered)
    cubes = config["gateway"]["cubes"]
    assert config["server"]["max_upload_mb"] == 2
    assert [cube["url"] for cube in cubes] == origins
    assert len(cubes) == 12
    assert all(cube["max_in_flight"] == 3 for cube in cubes)
    assert config["gateway"]["chunk_bytes"] == 4096
    assert config["gateway"]["chunks_per_batch"] == 4
    assert config["gateway"]["parent_deadline_ms"] == 300000
    assert config["gateway"]["retention_secs"] == 900
    assert config["gateway"]["redis_url_file"].startswith("/run/ark-coordinator/")
    assert config["gateway"]["cube_token_file"].startswith("/run/ark-coordinator/")


def test_cube_origin_input_rejects_wrong_count_duplicates_and_non_origins():
    valid = [f"https://cube-{index:02d}.example.invalid" for index in range(1, 13)]
    for invalid in (
        valid[:-1],
        valid[:-1] + [valid[0]],
        valid[:-1] + ["https://user@cube-12.example.invalid"],
        valid[:-1] + ["https://cube-12.example.invalid/path"],
    ):
        try:
            RENDER.validate_cube_origins(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid Cube origins were accepted")


def test_runtime_image_contains_only_coordinator_binary():
    dockerfile = (ROOT / "ark-coordinator" / "Dockerfile").read_text()
    runtime = dockerfile.split("FROM debian:trixie-slim AS runtime", 1)[1]
    assert "/target/release/ark-coordinator /usr/local/bin/ark-coordinator" in runtime
    assert "ark-api-entrypoint" not in runtime
    assert "/target/release/ark-api " not in runtime
    assert "/data/models" not in runtime


def test_bootstrap_help_is_side_effect_free():
    result = subprocess.run(
        ["bash", str(DEPLOY / "bootstrap.sh"), "--help"],
        text=True,
        capture_output=True,
        check=True,
    )
    assert "--coordinator-ip" in result.stdout
    assert "--cube-origins-file" in result.stdout
    assert "Secret values are never printed" in result.stdout


def test_managed_redis_url_must_be_tls_authenticated_and_bounded():
    assert RENDER.validate_redis_url("rediss://patronus:secret@redis.example:6379/0")
    for value in (
        "redis://patronus:secret@redis.example:6379/0",
        "rediss://redis.example:6379/0",
        "rediss://patronus:secret@redis.example/0",
        "rediss://patronus:secret@redis.example:6379/0?insecure=true",
    ):
        try:
            RENDER.validate_redis_url(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid Redis URL: {value}")
