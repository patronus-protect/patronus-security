"""Fleet ownership includes the declared worker network security groups."""

import importlib.util
from pathlib import Path

import pytest


PATH = Path(__file__).resolve().parents[2] / "ark-api" / "deploy" / "fleet.py"
SPEC = importlib.util.spec_from_file_location("fleet_groups", PATH)
FLEET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLEET)


def identity(n):
    return f"00000000-0000-4000-8000-{n:012d}"


def inputs():
    config = {"datacenter_id": identity(99), "private_lan_id": 3,
              "minimum_cubes": 1, "minimum_cores": 8, "minimum_ram_mb": 16384,
              "worker_security_group_ids": [identity(98)],
              "slots": [{"name": "cube-1", "private_ip": "192.0.2.1", "server_id": identity(1)}]}
    inventory = {"datacenter_id": identity(99), "servers": [
        {"id": identity(1), "name": "cube-1", "type": "CUBE", "cores": 8, "ram_mb": 16384,
         "state": "RUNNING", "resource_state": "AVAILABLE", "security_group_ids": [identity(98)],
         "nics": [{"lan": 3, "ips": ["192.0.2.1"]}]}]}
    return config, inventory


def test_inventory_keeps_group_identity_without_group_metadata():
    server = {"id": identity(1), "properties": {"type": "CUBE"}, "entities": {
        "securitygroups": {"items": [{"id": identity(98), "metadata": {"createdBy": "private-account"}}]}}}
    row = FLEET.summarize(server)
    assert row["security_group_ids"] == [identity(98)]
    assert "private-account" not in str(row)


def test_declared_group_allows_capacity_plan():
    config, inventory = inputs()
    assert FLEET.plan(config, inventory, 1)["target_workers"] == 3


@pytest.mark.parametrize("groups", [[], [identity(97)], None])
def test_default_or_missing_group_cannot_satisfy_declared_membership(groups):
    config, inventory = inputs()
    if groups is None:
        inventory["servers"][0].pop("security_group_ids")
    else:
        inventory["servers"][0]["security_group_ids"] = groups
    with pytest.raises(ValueError, match="required worker security group"):
        FLEET.plan(config, inventory, 1)


@pytest.mark.parametrize("groups", [[], [identity(98), identity(98)], "ark-workers"])
def test_group_configuration_is_explicit_and_unique(groups):
    config, inventory = inputs()
    config["worker_security_group_ids"] = groups
    with pytest.raises(ValueError):
        FLEET.plan(config, inventory, 1)
