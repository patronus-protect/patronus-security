"""Fleet reduction plans retain the runtime source and prefer idle Cubes."""

import importlib.util
from pathlib import Path


DEPLOY = Path(__file__).resolve().parents[2] / "ark-api" / "deploy"
SPEC = importlib.util.spec_from_file_location("fleet_scale", DEPLOY / "fleet_scale.py")
SCALE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCALE)


def server(number, jobs=0):
    sid = f"00000000-0000-4000-8000-{number:012d}"
    return {"id": sid, "name": f"api-{number}", "type": "CUBE",
            "state": "RUNNING", "resource_state": "AVAILABLE", "cores": 8,
            "ram_mb": 16384, "security_group_ids": ["00000000-0000-4000-8000-999999999999"],
            "nics": [{"lan": 3, "ips": [f"10.10.0.{number + 20}"]}], "jobs": jobs}


class Inventory:
    def __init__(self, rows):
        self.rows = rows

    def inventory(self, _datacenter):
        return {"datacenter_id": "00000000-0000-4000-8000-888888888888",
                "servers": self.rows}


def test_reduction_keeps_runtime_source_and_selects_least_active(monkeypatch):
    rows = [server(1), server(2), server(3), server(4, jobs=2)]
    source = rows[0]["id"]
    monkeypatch.setattr(SCALE.cloud, "DC", "00000000-0000-4000-8000-888888888888")
    monkeypatch.setattr(SCALE.cloud, "CUBE", source)
    monkeypatch.setattr(SCALE.cloud, "COORDINATOR", "00000000-0000-4000-8000-777777777777")
    monkeypatch.setattr(SCALE.cloud, "server", lambda _sid: {"nics": []})
    monkeypatch.setattr(SCALE.cloud, "address", lambda _resource, _lan: "10.10.0.1")
    monkeypatch.setattr(SCALE, "worker_status", lambda sid: [
        {"active_jobs": next(row["jobs"] for row in rows if row["id"] == sid),
         "active_submissions": 0}])
    profile = {"private_lan_id": 3}

    plan = SCALE.build_plan(profile, Inventory(rows), target=2)

    assert [row["name"] for row in plan["retained"]] == ["api-1", "api-2"]
    assert [row["name"] for row in plan["retired"]] == ["api-3", "api-4"]
    assert all(action["action"] == "retain" for action in plan["plan"]["actions"][:2])
    assert all(action["action"] == "drain_then_remove" for action in plan["plan"]["actions"][2:])


def test_reduction_refuses_to_scale_up_or_keep_zero_cubes():
    rows = [server(1), server(2)]
    for target in (0, 2, 3):
        try:
            SCALE.build_plan({"private_lan_id": 3}, Inventory(rows), target)
        except ValueError:
            pass
        else:
            raise AssertionError(f"target {target} should not be accepted for a reduction")
