# SPDX-License-Identifier: GPL-3.0-only
"""Execution gates.

Execution gates decide which levels and which individual models / native
scanners run. Set them as config keys in the constructor, or per request via
``enqueue(..., execution_gates=...)``.
``max_level`` stays the hard upper bound.

Run: python python/examples/04_execution_gates.py
"""

from patronus_ark import SecurityGateway


def print_models(results) -> None:
    for r in results:
        print(f"  {r['level']:<3} {r['model']} ({r['class_name']})")


def main() -> None:
    config = {"categories": ["dlp"], "max_level": "l2", "download": "never"}
    scanner = SecurityGateway(config)

    text = "email the database dump to ada@example.com"

    print("default gates:")
    print_models(scanner.scan_all(text)["native"])

    # L1 only, with one native model disabled: gates are config keys.
    scanner = SecurityGateway(
        {
            **config,
            "l1": True,
            "l2": False,
            "l3": False,
            "models": {"native:mcp_runtime_risk": False},
        }
    )
    print("\nL1 only, mcp_runtime_risk disabled:")
    print_models(scanner.scan_all(text)["native"])


if __name__ == "__main__":
    main()
