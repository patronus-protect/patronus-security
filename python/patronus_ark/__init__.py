# SPDX-License-Identifier: GPL-3.0-only
from ._patronus_ark import SecurityGateway as RustSecurityGateway
from ._patronus_ark import normalize_text as _rust_normalize_text
from copy import deepcopy
import json
import math

from patronus_ark_core import ScanControl, ScanGates, ScannerConfig, ScanReport


def _failure_to_dict(failure):
    return {
        "stage": failure.stage,
        "level": failure.level,
        "detector_id": failure.detector_id,
        "kind": failure.kind,
        "retryable": failure.retryable,
        "message": failure.message,
    }


def _event_to_dict(event):
    output = {
        "event_type": event.event_type,
        "request_id": event.request_id,
    }
    if event.event_type in ("result", "provisional"):
        output["result"] = event.result
    elif event.event_type == "progress":
        output["progress"] = event.progress
    else:
        output["completion"] = event.completion
        output["failures"] = [_failure_to_dict(failure) for failure in event.failures]
    return output


def _request_state_to_dict(state):
    return {
        "state": state.state,
        "completion": state.completion,
        "failures": [_failure_to_dict(failure) for failure in state.failures],
    }


def _level_readiness_to_dict(readiness):
    return {
        "state": readiness.state,
        "failures": [_failure_to_dict(failure) for failure in readiness.failures],
    }


def _execution_gates_json(execution_gates):
    """Gates in the one gate schema; the native extension validates them."""
    if execution_gates is None:
        return None
    if not isinstance(execution_gates, dict):
        raise ValueError("execution_gates must be a dict")
    return json.dumps(execution_gates)


def _normalization_configs_json(configs):
    if configs is None:
        return None
    if not isinstance(configs, dict):
        raise ValueError("configs must be a dict")
    return json.dumps(configs)


def _unix_ms_from_ts(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("until_ts must be a Unix timestamp")
    if not math.isfinite(value) or value < 0:
        raise ValueError("until_ts must be a non-negative finite Unix timestamp")
    if value >= 1_000_000_000_000:
        return int(value)
    return int(value * 1000)


def normalize_text(text: str, configs: dict | None = None) -> str:
    """Return canonical_security_text_v1-style normalized text.

    `configs` gates individual normalization steps. Supported keys are
    `html_entities`, `nfkc`, `confusables`, `format_characters`, `whitespace`,
    and `trim`; omitted steps default to enabled.
    """
    return _rust_normalize_text(text, _normalization_configs_json(configs))


class GatewayConfig(ScannerConfig, total=False):
    """`SecurityGateway(config)`: Ark Core's `Scanner` config (`categories`,
    `max_level`, the gate keys, `cascade`, `cache_root`, `download`,
    `download_categories`, `download_timeout_ms`, `execution_backend`,
    `onnx_runtime`, `wolf`, `shell`) with the same meaning, plus Ark's keys.
    Unknown keys raise `ValueError`."""

    l3_strategy: str
    ntdb_operating_point: str
    ntdb_decision_threshold_point: str
    onnx_batch_mode: str
    dynamic_pii: dict[str, object]
    cache: dict[str, object]


class SecurityGateway:
    """Python gateway for Patronus Ark scanners.

    Args:
        config: The gateway config, a dict (see `GatewayConfig`): the keys of
            Ark Core's `Scanner` config with the same meaning, plus Ark's own.

            Core keys: `categories` (any Ark category), `max_level` (`l1`,
            `l2` or `l3`; default `l3`), the gate keys at the top level
            (`l1`/`l2`/`l3`, `rules`, `models`, `pii_mode`, `dlp_mode`, one
            `<category>_mode` per attack class, `explain`, `conditional`, the
            L3 worker policy `l3_policy` and the opt-in `cascade`
            (`{"modules": {...}}`: L1 early exit with per-category
            `detect_threshold`/`clear_threshold`; scan reports then carry
            `decision`, one entry per module)), `cache_root` (the model cache root; default the
            platform cache directory plus `patronus_ark`), `download`
            (`never`, the default; `missing` lets `warmup()` download missing
            model assets), `download_categories` (unset: every category),
            `download_timeout_ms`, `execution_backend` (`auto`, `cpu`, `gpu`,
            `coreml`, `cuda`, `directml`, `tensorrt`) and `onnx_runtime`
            (`intra_threads`, `inter_threads`, `spinning`) of every ONNX
            model, Wolf included, `wolf` (the
            dedicated injection L3: `model` `base`, `small` (default) or
            `edge`; `precision` `auto` (default), `fp32`, `fp16`, `mixed`,
            `mixed_x86`, `int8_int4` or `int8_int4_x86`; `execution` with
            `window_tokens`, `overlap_tokens`, `batch_size`, unset values
            retaining 256/0/1) and `shell` (`policy_dirs` and `allowlist` of
            the `shell_command` verdict).

            Ark keys: `l3_strategy` (`dedicated` or `multi`),
            `ntdb_operating_point`, `ntdb_decision_threshold_point` (`best_f1`
            (default), `best_promote`, `best_fpr_in_f1`, `best_fnr_in_f1`,
            `best_latency_in_f1`), `onnx_batch_mode` (`lazy_batches` or
            `tensor_batch`; unset follows the backend), `dynamic_pii` (labels, result gates, thresholds,
            chunking, text limit and timeout of the L3-only `dynamic-pii`
            category) and `cache` (`storage_location`, `encryption_key_hex`,
            `entry_ttl_seconds`, `memory_max_entries`, `memory_max_bytes`;
            without a storage location the cache stays in memory).
    """

    def __init__(self, config: GatewayConfig):
        if not isinstance(config, dict):
            raise ValueError("config must be a dict")
        self._config = deepcopy(config)
        self.rust_gateway = RustSecurityGateway(json.dumps(config))

    def warmup(self):
        """Initialize model-backed scanners and download allowed missing assets.

        Native scanners are available without calling `warmup()`. Model-backed
        L2/L3 scanners are initialized only when their required assets are
        already cached or, with `download: "missing"`, can be downloaded.
        L3 ONNX sessions are lazy-loaded on first L3 inference, not during
        `warmup()`.

        Raises:
            ValueError: If an allowed required asset download or model
                initialization fails.
        """
        self.rust_gateway.warmup()

    def stop_l3_models(self):
        """Unload resident L3 model sessions while preserving gateway configuration."""
        self.rust_gateway.stop_l3_models()

    def flush_cache(self):
        """Wait until all queued persistent cache writes are durable."""
        self.rust_gateway.flush_cache()

    def reset_cache_connections(self):
        """Flush and close persistent cache handles.

        The cache database file is preserved. A configured persistent cache is
        reopened lazily on the next cache access.
        """
        self.rust_gateway.reset_cache_connections()

    def reset_cache(self, until_ts: int | float) -> int:
        """Delete cache records created before `until_ts`.

        `until_ts` accepts Unix seconds or Unix milliseconds. The cache database
        file is preserved.
        """
        return self.rust_gateway.reset_cache(_unix_ms_from_ts(until_ts))

    def scan_all(self, text: str, *, control: ScanControl | None = None) -> ScanReport:
        """Scan text with every category configured on this gateway.

        Returns Ark Core's report shape: `input_bytes`, the per-category
        results in `native`, `wolf` (the dedicated injection L3's Wolf result
        when it ran, else `None`) and, with the opt-in `cascade`, `decision`
        (one final answer per module).

        `control` is Ark Core's `ScanControl`, as in Core's `Scanner.scan`:
        its timeout or `cancel()` stops the scan wherever it is and raises
        `TimeoutError` or `patronus_ark_core.CancelledError`.
        """
        self._require_loaded_dynamic_pii(self.rust_gateway.categories)
        return self.rust_gateway.scan_all(text, control)

    def _require_loaded_dynamic_pii(self, categories: list[str]):
        """Raise instead of silently returning no `dynamic-pii` result when its model is not loaded."""
        if "dynamic-pii" not in categories:
            return
        l3 = self.runtime_readiness()["l3"]
        if l3["state"] == "not_ready":
            reasons = "; ".join(failure["message"] for failure in l3["failures"])
            raise RuntimeError(
                f"dynamic-pii needs its L3 model loaded; call warmup() before scanning ({reasons})"
            )

    def scan_category(
        self, category: str, text: str, *, control: ScanControl | None = None
    ) -> ScanReport:
        """Scan text with a single category; the report and `control` as in `scan_all`."""
        self._require_loaded_dynamic_pii([category])
        return self.rust_gateway.scan_category(category, text, control)

    def scan_categories(
        self, categories: list[str], text: str, *, control: ScanControl | None = None
    ) -> ScanReport:
        """Scan text with a caller-provided category subset; the report and
        `control` as in `scan_all`."""
        self._require_loaded_dynamic_pii(categories)
        return self.rust_gateway.scan_categories(categories, text, control)

    def enqueue(
        self,
        text: str,
        categories: list[str] | None = None,
        execution_gates: ScanGates | None = None,
        metadata: dict | None = None,
        ntdb_operating_point: str | None = None,
        chunk_overlap_tokens: int = 0,
    ) -> str:
        """Queue one scan request and return its request id.

        This method does not return scan results. A background gateway worker
        executes L1/L2 and a separate worker executes promoted L3 jobs.
        `consume_events()` yields result and terminal events from the shared
        queue. Every event includes its `request_id`. `execution_gates`, when
        provided, applies only to this request. `ntdb_operating_point`, when
        provided, overrides the gateway final-decision threshold profile for this
        request and does not change L3 promotion.
        `chunk_overlap_tokens` controls classifier chunk overlap for this request
        and must be between 0 and 64.
        """
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict")
        return self.rust_gateway.enqueue(
            text,
            categories,
            _execution_gates_json(execution_gates),
            None if metadata is None else json.dumps(metadata),
            ntdb_operating_point,
            chunk_overlap_tokens,
        )

    def consume_events(self, timeout: float | None = None):
        """Yield result and terminal events from the shared queue until timeout."""
        while True:
            event = self.consume_next_event(timeout)
            if event is None:
                return
            yield event

    def consume_next_event(self, timeout: float | None = None) -> dict | None:
        """Return the next result or terminal event from the shared queue."""
        event = self.rust_gateway.consume_next_event(timeout)
        return None if event is None else _event_to_dict(event)

    def has_request(self, request_id: str) -> bool:
        """Return whether work or an unconsumed terminal event exists for a request."""
        return self.rust_gateway.has_request(request_id)

    def request_state(self, request_id: str) -> dict | None:
        """Return lifecycle state until the terminal event is consumed."""
        state = self.rust_gateway.request_state(request_id)
        return None if state is None else _request_state_to_dict(state)

    def is_finished(self, request_id: str) -> bool | None:
        """Return whether a known request is terminal."""
        return self.rust_gateway.is_finished(request_id)

    def runtime_readiness(self) -> dict:
        """Return L1/L2/L3 readiness using the request failure schema."""
        readiness = self.rust_gateway.runtime_readiness()
        return {
            "l1": _level_readiness_to_dict(readiness.l1),
            "l2": _level_readiness_to_dict(readiness.l2),
            "l3": _level_readiness_to_dict(readiness.l3),
        }

    def run_local_benchmark(
        self,
        output_dir: str = "benchmark",
        limit_per_pipeline: int | None = None,
        load_requests: int = 200,
        print_summary: bool = True,
        native_l1_iterations: int = 200,
    ) -> dict:
        """Benchmark this gateway against the sample data shipped with the package.

        Runs every benchmark phase once with `dedicated` L3 and once with
        `multi` L3. Each strategy gets its own subdirectory below
        `output_dir`, plus a combined root `BENCHMARK.md` and
        `benchmark_result.json`:
        one complete queued response (`example_result.json`), benign false
        positives (`benign_result.json`), labelled classifier
        validation (`classifier_result.json`), exact-span GLiNER NER quality
        by document/tool context and joint L2/L3/GLiNER latency plus process
        peak RSS (`dynamic_pii_result.json`), native L1
        scans on exact 10 KiB texts (`native_l1_result.json`), and queue load tests where one
        producer enqueues texts as a burst and at a paced 10 req/s while one consumer drains
        the shared result queue (`load_result.json`). Injection L2/L3 plus GLiNER latency and
        peak RSS run in a fresh process containing only those two categories. Only pipelines whose
        category is configured on this gateway are evaluated; the L3 load
        scenario runs only when `max_level` is `l3`. Call `warmup()` first.

        Note: the classifier and native L1 phases temporarily replace the
        execution gate matrix to isolate individual scanners and reset it to
        the shared default matrix afterwards.
        """
        from . import benchmark

        return benchmark.run_local_benchmark(
            self,
            output_dir=output_dir,
            limit_per_pipeline=limit_per_pipeline,
            load_requests=load_requests,
            native_l1_iterations=native_l1_iterations,
            print_summary=print_summary,
        )
