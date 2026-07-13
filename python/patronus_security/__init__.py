from ._patronus_security import SecurityGateway as RustSecurityGateway
import json


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
    }
    request_id = getattr(result, "request_id", None)
    if request_id is not None:
        output["request_id"] = request_id
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
    if event.event_type == "result":
        output["result"] = _to_dict(event.result)
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
    tool_classifier = execution_gates.get("tool_classifier", {})
    l3_policy = execution_gates.get("l3")

    if not isinstance(levels, dict):
        raise ValueError("execution_gates['levels'] must be a dict")
    if not isinstance(models, dict):
        raise ValueError("execution_gates['models'] must be a dict")
    if tool_classifier and not isinstance(tool_classifier, dict):
        raise ValueError("execution_gates['tool_classifier'] must be a dict")
    levels = dict(levels)
    models = dict(models)
    tool_classifier = dict(tool_classifier)

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
    for key, value in tool_classifier.items():
        if not isinstance(value, bool):
            raise ValueError(f"execution_gates tool_classifier {key!r} must be a bool")
        lowered = str(key).lower()
        valid_areas = {
            "description",
            "descriptions",
            "execution",
            "executions",
            "prompt",
            "prompts",
        }
        if lowered not in valid_areas:
            raise ValueError(
                "execution_gates['tool_classifier'] keys must be description, execution, or prompt"
            )
        canonical = {
            "descriptions": "description",
            "executions": "execution",
            "prompts": "prompt",
        }.get(lowered, lowered)
        normalized["models"][f"tool_classifier.{canonical}"] = value
    if l3_policy is not None and not isinstance(l3_policy, bool):
        if not isinstance(l3_policy, dict):
            raise ValueError("execution_gates['l3'] must be a dict or bool")
        normalized["l3"] = l3_policy

    return json.dumps(normalized)


class SecurityGateway:
    """Python gateway for Patronus Security scanners.

    Args:
        categories: Scanner categories to use for `scan_all`.
        max_level: Maximum scanner level: `l1`, `l2`, or `l3`.
        model_dir: Optional asset cache root. Defaults to the platform cache
            directory plus `patronus_security`.
        download_files: Whether `warmup()` may download missing model assets.
        download_categories: Optional category allowlist for asset downloads.
            When omitted, every configured category may download if
            `download_files` is true.
        execution_gates: Optional scan execution matrix. Use
            `{"levels": {"l1": True, "l2": False, "l3": False},
            "models": {"native:mcp_runtime_risk": False}}` to disable
            levels or model/native scanner areas for subsequent scan calls.
            For `tool_classifier`, use
            `{"tool_classifier": {"description": False, "execution": True,
            "prompt": False}}` to gate its subpipelines. Unspecified gates
            default to enabled.
        onnx_batch_mode: `lazy_batches` keeps per-text ONNX execution;
            `tensor_batch` executes L3 fallbacks as one ONNX tensor batch
            when using batch APIs.
        execution_backend: `auto`, `cpu`, `gpu`, `coreml`, `cuda`,
            `directml`, or `tensorrt`. Backend defaults choose lazy L3 on
            CPU/auto and tensor batches on accelerator backends unless
            `onnx_batch_mode` is explicitly set.
        ntdb_operating_point: Calibrated NTDB threshold set. One of
            `best_promote` (default), `best_f1`, `best_fpr_in_f1`,
            `best_fnr_in_f1`, or `best_latency_in_f1`.
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
        ntdb_operating_point: str = "best_promote",
    ):
        self._categories = list(categories)
        self._max_level = max_level
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
        )

    @property
    def categories(self) -> list[str]:
        """Categories configured for `scan_all`."""
        return list(self._categories)

    @property
    def max_level(self) -> str:
        """Maximum scanner level configured for this gateway."""
        return self._max_level

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

    def set_onnx_batch_mode(self, mode: str):
        """Replace the ONNX batch mode for subsequent batch calls.

        `lazy_batches` preserves the per-text ONNX execution path.
        `tensor_batch` executes L3 fallbacks as one ONNX tensor batch when
        pipelines can batch their fallback texts.
        """
        self.rust_gateway.set_onnx_batch_mode(mode)

    def set_execution_backend(self, backend: str):
        """Replace execution backend and apply its default L3 mode.

        `auto` and `cpu` default to lazy L3 execution. `gpu`, `coreml`,
        `cuda`, `directml`, and `tensorrt` default to tensor batches. Call
        `set_onnx_batch_mode` afterwards to override.
        """
        self.rust_gateway.set_execution_backend(backend)

    def set_ntdb_operating_point(self, point: str):
        """Select the calibrated NTDB threshold set for subsequent scans."""
        self.rust_gateway.set_ntdb_operating_point(point)

    def set_long_text_policy(
        self,
        enabled: bool = True,
        no_full_l2_byte_limit: int = 1024,
        chunk_size_bytes: int = 256,
        overlap_bytes: int = 96,
        verify_non_benign_l2: bool = True,
    ):
        """Replace the long-text policy used for L3 chunked verification.

        NTDB L2 always scans the full text; the model packages chunk
        internally and aggregate across chunks. When a scan is promoted to
        L3, the L3 worker splits the full text into overlapping
        `chunk_size_bytes`/`overlap_bytes` windows and verifies them by
        priority. `verify_non_benign_l2` keeps non-benign L2 chunk decisions
        subject to L3 verification during aggregation.
        """
        self.rust_gateway.set_long_text_policy(
            enabled,
            no_full_l2_byte_limit,
            chunk_size_bytes,
            overlap_bytes,
            verify_non_benign_l2,
        )

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
    ) -> str:
        """Queue one scan request and return its request id.

        This method does not return scan results. A background gateway worker
        executes L1/L2 and a separate worker executes promoted L3 jobs.
        `consume_events()` yields result and terminal events from the shared
        queue. Every event includes its `request_id`. `execution_gates`, when
        provided, applies only to this request.
        """
        return self.rust_gateway.enqueue(
            text,
            categories,
            _execution_gates_json(execution_gates),
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

        Runs benchmark phases and writes a readable `BENCHMARK.md` plus JSON into `output_dir`:
        one complete queued response (`example_result.json`), benign false
        positives (`benign_result.json`), labelled classifier
        validation (`classifier_result.json`), native L1 scans on exact 10 KiB
        texts (`native_l1_result.json`), and a queue load test where one
        producer enqueues texts while one consumer drains the shared result queue
        (`load_result.json`). Only pipelines whose
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
