# SPDX-License-Identifier: AGPL-3.0-only
"""Fresh-process worker for isolated Injection L2/L3 plus GLiNER benchmarks."""

import json
import sys

from . import SecurityGateway
from .benchmark import (
    GLINER_LABELS,
    _benchmark_dynamic_config,
    _process_peak_rss_mb,
    _run_l2_l3_gliner_latency,
)


def main():
    payload = json.load(sys.stdin)
    config = payload["gateway"]
    process_start_peak_rss_mb = _process_peak_rss_mb()
    gateway = SecurityGateway(
        categories=["injection", "dynamic-pii"],
        max_level="l3",
        model_dir=config["model_dir"],
        download_files=False,
        onnx_batch_mode=config["onnx_batch_mode"],
        execution_backend=config["execution_backend"],
        ntdb_operating_point=config["ntdb_operating_point"],
    )
    gateway.warmup()

    labels = GLINER_LABELS[:30]
    gateway.set_dynamic_pii_config(_benchmark_dynamic_config(labels))
    warmup_text = payload["samples"][0]["text"] + " isolated-memory-warmup"
    for _ in range(2):
        gateway.scan_categories(["injection", "dynamic-pii"], warmup_text)

    result = _run_l2_l3_gliner_latency(
        gateway,
        payload["samples"],
        process_start_peak_rss_mb,
    )
    result["memory"]["scope"] = ["injection", "dynamic-pii"]
    result["memory"]["fresh_process"] = True
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
