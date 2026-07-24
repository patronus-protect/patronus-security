# SPDX-License-Identifier: GPL-3.0-only
"""Fresh-process worker for one complete local benchmark strategy."""

import json
import sys

from . import SecurityGateway
from .benchmark import _run_local_benchmark_for_strategy


def main():
    payload = json.load(sys.stdin)
    gateway = SecurityGateway(**payload["gateway"])
    gateway.warmup()
    result = _run_local_benchmark_for_strategy(
        gateway,
        payload["output_dir"],
        limit_per_pipeline=payload["limit_per_pipeline"],
        load_requests=payload["load_requests"],
        print_summary=False,
        native_l1_iterations=payload["native_l1_iterations"],
    )
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
