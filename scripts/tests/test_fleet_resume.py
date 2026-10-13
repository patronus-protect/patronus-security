"""Provider operation and load-balancer target recovery stays order-independent."""
import importlib.util
from pathlib import Path


DEPLOY = Path(__file__).resolve().parents[2] / "ark-api" / "deploy"
SPEC = importlib.util.spec_from_file_location("fleet_resume", DEPLOY / "fleet.py")
FLEET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLEET)


def test_target_group_comparison_ignores_provider_order_but_checks_fields():
    first = {"ip": "10.0.0.1", "port": 8080, "weight": 1,
             "maintenanceEnabled": False}
    second = {"ip": "10.0.0.2", "port": 8080, "weight": 1,
              "maintenanceEnabled": True}

    assert FLEET.targets_equal([first, second], [second, first])
    assert not FLEET.targets_equal([first, second], [first, dict(second, maintenanceEnabled=False)])
    assert not FLEET.targets_equal([first, first], [first, first])


def test_operation_journal_reconciles_every_accepted_operation(tmp_path):
    journal = FLEET.OperationJournal(tmp_path / "operations.json")
    journal.data["operations"] = [
        {"state": "accepted", "location": "/cloudapi/v6/requests/one"},
        {"state": "accepted", "location": "/cloudapi/v6/requests/two"},
        {"state": "done"},
    ]

    class API:
        def __init__(self):
            self.locations = []

        def wait_operation(self, location):
            self.locations.append(location)
            next(item for item in journal.data["operations"]
                 if item.get("location") == location)["state"] = "done"

    api = API()
    journal.reconcile(api)

    assert api.locations == ["/cloudapi/v6/requests/one", "/cloudapi/v6/requests/two"]
    assert all(item["state"] == "done" for item in journal.data["operations"])


def test_operation_journal_refuses_unresolved_mutation_without_location(tmp_path):
    journal = FLEET.OperationJournal(tmp_path / "operations.json")
    journal.data["operations"] = [{"state": "uncertain"}]

    class API:
        def wait_operation(self, _location):
            raise AssertionError("uncertain operations must not be replayed")

    try:
        journal.reconcile(API())
    except RuntimeError as error:
        assert "unresolved operation" in str(error)
    else:
        raise AssertionError("uncertain operation should require manual reconciliation")
