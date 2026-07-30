# SPDX-License-Identifier: GPL-3.0-only
from ._patronus_ark import SecurityGateway as RustSecurityGateway
from ._patronus_ark import normalize_text as _rust_normalize_text
from copy import deepcopy
import json
import math


def _decode_json_object(value):
    try:
        decoded = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _to_dict(result):
    output = {
        "category": result.category,
        "class_name": result.class_name,
        "confidence": result.confidence,
        "level": result.level,
        "model": result.model,
        "duration_ms": result.duration_ms,
        "layers": [
            {
                "level": layer.level,
                "layer_type": layer.layer_type,
                "class_name": layer.class_name,
                "confidence": layer.confidence,
                "matched": layer.matched,
                "duration_ms": layer.duration_ms,
                "thresholds": _decode_json_object(layer.thresholds_json),
                "details": _decode_json_object(layer.details_json),
            }
            for layer in result.layers
        ],
        "evidence_spans": [
            {
                "label": span.label,
                "text": span.text,
                "score": span.score,
                "start_byte": span.start_byte,
                "end_byte": span.end_byte,
                "start_char": span.start_char,
                "end_char": span.end_char,
            }
            for span in result.evidence_spans
        ],
        "label_scores": [
            {
                "label": score.label,
                "confidence": score.confidence,
                "matched": score.matched,
            }
            for score in result.label_scores
        ],
    }
    request_id = getattr(result, "request_id", None)
    if request_id is not None:
        output["request_id"] = request_id
    decision = _decode_json_object(getattr(result, "decision_json", None))
    if decision:
        output["decision"] = decision
    return output


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
        output["result"] = _to_dict(event.result)
    elif event.event_type == "progress":
        output["progress"] = _decode_json_object(getattr(event, "progress_json", None))
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
    if execution_gates is None:
        return None
    if not isinstance(execution_gates, dict):
        raise ValueError("execution_gates must be a dict")

    normalized = {"levels": {}, "models": {}}
    levels = execution_gates.get("levels", {})
    models = execution_gates.get("models", execution_gates.get("model_areas", {}))
    l3_policy = execution_gates.get("l3")
    conditional = execution_gates.get("conditional")

    if not isinstance(levels, dict):
        raise ValueError("execution_gates['levels'] must be a dict")
    if not isinstance(models, dict):
        raise ValueError("execution_gates['models'] must be a dict")
    levels = dict(levels)
    models = dict(models)

    for key, value in execution_gates.items():
        lowered = str(key).lower()
        if lowered in {"l1", "l2"} or (lowered == "l3" and isinstance(value, bool)):
            levels[key] = value

    for key, value in levels.items():
        if not isinstance(value, bool):
            raise ValueError(f"execution_gates level {key!r} must be a bool")
        normalized["levels"][str(key).lower()] = value
    for key, value in models.items():
        if not isinstance(value, bool):
            raise ValueError(f"execution_gates model {key!r} must be a bool")
        normalized["models"][str(key)] = value
    if l3_policy is not None and not isinstance(l3_policy, bool):
        if not isinstance(l3_policy, dict):
            raise ValueError("execution_gates['l3'] must be a dict or bool")
        normalized["l3"] = l3_policy
    if conditional is not None:
        if not isinstance(conditional, list):
            raise ValueError("execution_gates['conditional'] must be a list")
        normalized["conditional"] = conditional

    return json.dumps(normalized)


def _dynamic_pii_config_json(config):
    if config is None:
        return None
    if not isinstance(config, dict):
        raise ValueError("dynamic_pii_config must be a dict")
    return json.dumps(config)


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


class SecurityGateway:
    """Python gateway for Patronus Ark scanners.

    Args:
        categories: Scanner categories to use for `scan_all`.
        max_level: Maximum scanner level: `l1`, `l2`, or `l3`.
        model_dir: Optional asset cache root. Defaults to the platform cache
            directory plus `patronus_ark`.
        download_files: Whether `warmup()` may download missing model assets.
        download_categories: Optional category allowlist for asset downloads.
            When omitted, every configured category may download if
            `download_files` is true.
        execution_gates: Optional scan execution matrix. Use
            `{"levels": {"l1": True, "l2": False, "l3": False},
            "models": {"native:mcp_runtime_risk": False}}` to disable
            levels or model/native scanner areas for subsequent scan calls.
            New classifier pipelines can be gated independently through
            `models`, for example `{"models": {"tool_action": False}}`.
        onnx_batch_mode: `lazy_batches` keeps per-text ONNX execution;
            `tensor_batch` executes L3 fallbacks as one ONNX tensor batch
            when using batch APIs.
        execution_backend: `auto`, `cpu`, `gpu`, `coreml`, `cuda`,
            `directml`, or `tensorrt`. Backend defaults choose lazy L3 on
            CPU/auto and tensor batches on accelerator backends unless
            `onnx_batch_mode` is explicitly set.
        ntdb_operating_point: Calibrated NTDB final-decision threshold set. One of
            `best_f1` (default), `best_promote`, `best_fpr_in_f1`,
            `best_fnr_in_f1`, or `best_latency_in_f1`. This does not change
            L3 promote thresholds.
        l3_strategy: `dedicated` for one L3 model per classifier pipeline or
            `multi` for the shared unified multi-head ONNX model.
        dynamic_pii_config: Pipeline-specific labels, result gates,
            thresholds, chunking, text limit, and timeout for the L3-only
            `dynamic-pii` category.
        cache_storage_location: Optional path to the persistent cache database.
            If omitted, caching remains memory-only.
        cache_encryption_key_hex: Optional 64-character hex-encoded persistent
            cache encryption key. Ignored when `cache_storage_location` is omitted.
        cache_entry_ttl_seconds: Cache entry TTL shared by hot and persistent tiers.
        cache_memory_max_entries: Maximum entries retained by a hot cache tier.
        cache_memory_max_bytes: Maximum bytes retained by a hot cache tier.
    """

    def __init__(
        self,
        categories: list[str],
        max_level: str = "l2",
        model_dir: str = None,
        download_files: bool = True,
        download_categories: list[str] | None = None,
        execution_gates: dict | None = None,
        onnx_batch_mode: str = "backend_default",
        execution_backend: str = "auto",
        ntdb_operating_point: str = "best_f1",
        l3_strategy: str = "dedicated",
        dynamic_pii_config: dict | None = None,
        cache_storage_location: str | None = None,
        cache_encryption_key_hex: str | None = None,
        cache_entry_ttl_seconds: int = 30 * 24 * 60 * 60,
        cache_memory_max_entries: int = 100_000,
        cache_memory_max_bytes: int = 128 * 1024 * 1024,
    ):
        self._categories = list(categories)
        self._max_level = max_level
        self._l3_strategy = l3_strategy
        self._execution_gates = deepcopy(execution_gates)
        self._dynamic_pii_config = deepcopy(dynamic_pii_config or {})
        self._benchmark_gateway_config = {
            "categories": list(categories),
            "max_level": max_level,
            "model_dir": model_dir,
            "download_files": download_files,
            "download_categories": deepcopy(download_categories),
            "execution_gates": deepcopy(execution_gates),
            "onnx_batch_mode": onnx_batch_mode,
            "execution_backend": execution_backend,
            "ntdb_operating_point": ntdb_operating_point,
            "l3_strategy": l3_strategy,
            "dynamic_pii_config": deepcopy(dynamic_pii_config),
            "cache_storage_location": cache_storage_location,
            "cache_encryption_key_hex": cache_encryption_key_hex,
            "cache_entry_ttl_seconds": cache_entry_ttl_seconds,
            "cache_memory_max_entries": cache_memory_max_entries,
            "cache_memory_max_bytes": cache_memory_max_bytes,
        }
        self._benchmark_worker_config = {
            "model_dir": model_dir,
            "onnx_batch_mode": onnx_batch_mode,
            "execution_backend": execution_backend,
            "ntdb_operating_point": ntdb_operating_point,
            "l3_strategy": l3_strategy,
        }
        self.rust_gateway = RustSecurityGateway(
            categories,
            max_level,
            model_dir=model_dir,
            download_files=download_files,
            download_categories=download_categories,
            execution_gates_json=_execution_gates_json(execution_gates),
            onnx_batch_mode=onnx_batch_mode,
            execution_backend=execution_backend,
            ntdb_operating_point=ntdb_operating_point,
            l3_strategy=l3_strategy,
            dynamic_pii_config_json=_dynamic_pii_config_json(dynamic_pii_config),
            cache_storage_location=cache_storage_location,
            cache_encryption_key_hex=cache_encryption_key_hex,
            cache_entry_ttl_seconds=cache_entry_ttl_seconds,
            cache_memory_max_entries=cache_memory_max_entries,
            cache_memory_max_bytes=cache_memory_max_bytes,
        )

    @property
    def categories(self) -> list[str]:
        """Categories configured for `scan_all`."""
        return list(self._categories)

    @property
    def max_level(self) -> str:
        """Maximum scanner level configured for this gateway."""
        return self._max_level

    @property
    def l3_strategy(self) -> str:
        """Active global L3 model strategy."""
        return self._l3_strategy

    def warmup(self):
        """Initialize model-backed scanners and download allowed missing assets.

        Native scanners are available without calling `warmup()`. Model-backed
        L2/L3 scanners are initialized only when their required assets are
        already cached or can be downloaded according to the download settings.
        L3 ONNX sessions are lazy-loaded on first L3 inference, not during
        `warmup()`.

        Raises:
            ValueError: If an allowed required asset download or model
                initialization fails.
        """
        self.rust_gateway.warmup()

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

    def scan_all(self, text: str) -> list[dict]:
        """Scan text with every category configured on this gateway."""
        results = self.rust_gateway.scan_all(text)
        return [_to_dict(r) for r in results]

    def set_execution_gates(self, execution_gates: dict | None):
        """Replace the gate matrix used by subsequent scan calls.

        Pass `None` to reset to the default all-enabled matrix. The matrix
        accepts `levels` and `models` dictionaries; model keys match result
        `model` values such as `native:mcp_runtime_risk`.
        """
        self.rust_gateway.set_execution_gates(_execution_gates_json(execution_gates))
        self._execution_gates = deepcopy(execution_gates)
        self._benchmark_gateway_config["execution_gates"] = deepcopy(execution_gates)

    def set_onnx_batch_mode(self, mode: str):
        """Replace the ONNX batch mode for subsequent batch calls.

        `lazy_batches` preserves the per-text ONNX execution path.
        `tensor_batch` executes L3 fallbacks as one ONNX tensor batch when
        pipelines can batch their fallback texts.
        """
        self.rust_gateway.set_onnx_batch_mode(mode)
        self._benchmark_worker_config["onnx_batch_mode"] = mode
        self._benchmark_gateway_config["onnx_batch_mode"] = mode

    def set_execution_backend(self, backend: str):
        """Replace execution backend and apply its default L3 mode.

        `auto` and `cpu` default to lazy L3 execution. `gpu`, `coreml`,
        `cuda`, `directml`, and `tensorrt` default to tensor batches. Call
        `set_onnx_batch_mode` afterwards to override.
        """
        self.rust_gateway.set_execution_backend(backend)
        self._benchmark_worker_config["execution_backend"] = backend
        self._benchmark_gateway_config["execution_backend"] = backend

    def set_ntdb_operating_point(self, point: str):
        """Select the calibrated NTDB final-decision threshold set for subsequent scans."""
        self.rust_gateway.set_ntdb_operating_point(point)
        self._benchmark_worker_config["ntdb_operating_point"] = point
        self._benchmark_gateway_config["ntdb_operating_point"] = point

    def set_l3_strategy(self, strategy: str):
        """Select `dedicated` per-pipeline L3 models or the shared `multi` model."""
        self.rust_gateway.set_l3_strategy(strategy)
        self._l3_strategy = self.rust_gateway.l3_strategy
        self._benchmark_worker_config["l3_strategy"] = strategy
        self._benchmark_gateway_config["l3_strategy"] = strategy

    def set_dynamic_pii_config(self, config: dict):
        """Replace labels, result gates, thresholds, limits, and timeout for `dynamic-pii`."""
        self.rust_gateway.set_dynamic_pii_config(_dynamic_pii_config_json(config))
        self._dynamic_pii_config = deepcopy(config)
        self._benchmark_gateway_config["dynamic_pii_config"] = deepcopy(config)

    def _new_benchmark_gateway(self, l3_strategy: str):
        """Create an isolated gateway for one benchmark strategy."""
        config = deepcopy(self._benchmark_gateway_config)
        config["l3_strategy"] = l3_strategy
        return type(self)(**config)

    def scan_category(self, category: str, text: str) -> list[dict]:
        """Scan text with a single category."""
        results = self.rust_gateway.scan_category(category, text)
        return [_to_dict(r) for r in results]

    def scan_categories(self, categories: list[str], text: str) -> list[dict]:
        """Scan text with a caller-provided category subset."""
        results = self.rust_gateway.scan_categories(categories, text)
        return [_to_dict(r) for r in results]

    def enqueue(
        self,
        text: str,
        categories: list[str] | None = None,
        execution_gates: dict | None = None,
        metadata: dict | None = None,
        ntdb_operating_point: str | None = None,
    ) -> str:
        """Queue one scan request and return its request id.

        This method does not return scan results. A background gateway worker
        executes L1/L2 and a separate worker executes promoted L3 jobs.
        `consume_events()` yields result and terminal events from the shared
        queue. Every event includes its `request_id`. `execution_gates`, when
        provided, applies only to this request. `ntdb_operating_point`, when
        provided, overrides the gateway final-decision threshold profile for this
        request and does not change L3 promotion.
        """
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict")
        return self.rust_gateway.enqueue(
            text,
            categories,
            _execution_gates_json(execution_gates),
            None if metadata is None else json.dumps(metadata),
            ntdb_operating_point,
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
        the default all-enabled matrix afterwards.
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
