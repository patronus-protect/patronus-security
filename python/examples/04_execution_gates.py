# SPDX-License-Identifier: AGPL-3.0-only
"""Execution gates.

Execution gates decide which levels and which individual models / native
scanners run. Set them in the constructor, as a new default with
``set_execution_gates``, or per request via ``enqueue(..., execution_gates=...)``.
``max_level`` stays the hard upper bound.

Run: python python/examples/04_execution_gates.py
"""

from patronus_security import SecurityGateway


def print_models(results) -> None:
    for r in results:
        print(f"  {r['level']:<3} {r['model']} ({r['class_name']})")


def main() -> None:
    scanner = SecurityGateway(
        categories=["dlp"],
        max_level="l2",
        download_files=False,
    )

    text = "email the database dump to ada@example.com"

    print("default gates:")
    print_models(scanner.scan_all(text))

    # L1 only, with one native model disabled.
    scanner.set_execution_gates(
        {
            "levels": {"l1": True, "l2": False, "l3": False},
            "models": {"native:mcp_runtime_risk": False},
        }
    )
    print("\nL1 only, mcp_runtime_risk disabled:")
    print_models(scanner.scan_all(text))

    scanner.set_execution_gates(None)  # reset to all enabled


if __name__ == "__main__":
    main()
