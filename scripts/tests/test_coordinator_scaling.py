"""Explicit fleet sizes preserve origin validation and the legacy default."""

import importlib.util
from pathlib import Path

import pytest
import yaml


DEPLOY = Path(__file__).resolve().parents[2] / "ark-coordinator" / "deploy"
SPEC = importlib.util.spec_from_file_location("coordinator_scaling", DEPLOY / "render_config.py")
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)


@pytest.mark.parametrize("count", [1, 6, 12, 13])
def test_explicit_fleet_size_renders_three_slots_per_cube(count):
    origins = [f"http://cube-{n}.example.invalid:8080" for n in range(count)]
    validated = RENDER.validate_cube_origins(origins, expected_count=count)
    cubes = yaml.safe_load("cubes:\n" + RENDER.render_cubes(validated))["cubes"]
    assert len(cubes) == count
    assert [cube["url"] for cube in cubes] == origins
    assert all(cube["max_in_flight"] == 3 for cube in cubes)


@pytest.mark.parametrize("count", [0, -1, True, None])
def test_invalid_requested_fleet_sizes_are_rejected(count):
    with pytest.raises(ValueError):
        RENDER.validate_cube_origins(["http://cube.example.invalid"], count)


def test_explicit_size_keeps_duplicate_and_origin_checks():
    valid = [f"http://cube-{n}.example.invalid" for n in range(13)]
    for origins in ([], valid[:-1], valid[:-1] + [valid[0]],
                    valid[:-1] + ["http://cube.example.invalid/path"]):
        with pytest.raises(ValueError):
            RENDER.validate_cube_origins(origins, 13)


def test_legacy_default_still_rejects_unrequested_size():
    with pytest.raises(ValueError):
        RENDER.validate_cube_origins(["http://cube.example.invalid"])
